//! A TCP connection lasts no longer than its use: a session that ended and
//! a handshake nobody answered leave no socket behind. This is alone in its
//! file because it counts the sockets of the whole process.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use cardinal_crypto::{HybridKeyPair, SigningKey};
use cardinal_link::{
    Bind, CarrierKind, Endpoint, EndpointConfig, LocalIdentity, MemoryDirectory, Target,
};

fn sockets() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .flatten()
        .filter(|e| {
            std::fs::read_link(e.path()).is_ok_and(|p| p.to_string_lossy().starts_with("socket:"))
        })
        .count()
}

struct Device {
    key: Arc<HybridKeyPair>,
    id: LocalIdentity,
}

fn device(n: u8) -> Device {
    Device {
        key: Arc::new(HybridKeyPair::from_seed(&[n; 32])),
        id: LocalIdentity {
            identity: [0xaa; 32],
            signing_key: Arc::new(SigningKey::from_seed(&[n; 32])),
        },
    }
}

async fn endpoint(d: &Device, dir: Arc<MemoryDirectory>) -> Endpoint {
    let mut c = EndpointConfig::new(d.key.clone(), dir);
    c.identity = Some(d.id.clone());
    c.connect_timeout = Duration::from_millis(200);
    let tcp: SocketAddr = "127.0.0.1:0".parse().unwrap();
    Endpoint::bind(
        c,
        Bind {
            udp: None,
            tcp: Some(tcp),
        },
    )
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn connections_close_when_they_are_done_with() {
    let (a, b) = (device(1), device(2));
    let dir = MemoryDirectory::new();
    for d in [&a, &b] {
        dir.add_device(
            d.id.identity,
            d.id.signing_key.public_key(),
            d.key.public_key().clone(),
        );
    }
    let (ea, eb) = (endpoint(&a, dir.clone()).await, endpoint(&b, dir).await);
    let at = eb.tcp_addr().unwrap();
    let before = sockets();

    // The wrong key: whoever listens stays silent.
    let other = HybridKeyPair::from_seed(&[9; 32]);
    for _ in 0..10 {
        let t = Target::new(at, CarrierKind::Tcp, other.public_key());
        assert!(ea.connect(t).await.is_err());
    }

    // Sessions that end.
    for _ in 0..10 {
        let t = Target::new(at, CarrierKind::Tcp, b.key.public_key());
        let (sa, sb) = tokio::join!(ea.connect(t), eb.accept());
        let (sa, sb) = (sa.unwrap(), sb.unwrap());
        sa.close("done");
        tokio::time::timeout(Duration::from_secs(5), sb.closed())
            .await
            .unwrap();
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    while sockets() > before {
        assert!(
            Instant::now() < deadline,
            "{} sockets left open",
            sockets() - before
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
