//! Sessions over a stream another carrier opened (`carriers/ble.md`): here
//! an in-memory pipe stands in for an L2CAP channel.

use std::sync::Arc;
use std::time::Duration;

use cardinal_crypto::{HybridKeyPair, SigningKey};
use cardinal_link::{
    Bind, CarrierKind, Endpoint, EndpointConfig, LocalIdentity, MemoryDirectory, Priority, Service,
    Target,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Device {
    key: Arc<HybridKeyPair>,
    id: LocalIdentity,
}

fn device(n: u8, identity: u8) -> Device {
    Device {
        key: Arc::new(HybridKeyPair::from_seed(&[n; 32])),
        id: LocalIdentity {
            identity: [identity; 32],
            signing_key: Arc::new(SigningKey::from_seed(&[n; 32])),
        },
    }
}

/// An endpoint that listens on nothing: its only carrier is what is
/// attached to it.
async fn endpoint(d: &Device, dir: Arc<MemoryDirectory>) -> Endpoint {
    let mut c = EndpointConfig::new(d.key.clone(), dir);
    c.identity = Some(d.id.clone());
    c.connect_timeout = Duration::from_secs(2);
    Endpoint::bind(c, Bind::default()).await.unwrap()
}

#[tokio::test]
async fn a_session_over_an_attached_stream_tries_every_key_at_once() {
    let (a, b, other) = (device(1, 0xaa), device(2, 0xbb), device(3, 0xbb));
    let dir = MemoryDirectory::new();
    for d in [&a, &b, &other] {
        dir.add_device(
            d.id.identity,
            d.id.signing_key.public_key(),
            d.key.public_key().clone(),
        );
    }
    let ea = endpoint(&a, dir.clone()).await;
    let eb = endpoint(&b, dir).await;
    assert!(ea.udp_addr().is_none() && ea.tcp_addr().is_none());
    let (near, far) = tokio::io::duplex(64 * 1024);
    let on = ea.attach(near, CarrierKind::Ble, "radio:b");
    let _ = eb.attach(far, CarrierKind::Ble, "radio:a");
    // Bo has two devices, and the advertisement does not say which this
    // is: both are tried on the one channel, and only the one there answers.
    let unused = "0.0.0.0:0".parse().unwrap();
    let to = |d: &Device| Target::new(unused, CarrierKind::Ble, d.key.public_key());
    let (wrong, right, accepted) = tokio::join!(
        ea.connect_on(&on, to(&other).within(Duration::from_millis(800))),
        ea.connect_on(&on, to(&b)),
        eb.accept()
    );
    assert!(wrong.is_err(), "the other device is not at this end");
    let (sa, sb) = (right.unwrap(), accepted.unwrap());
    assert!(
        !on.is_closed(),
        "a failed try leaves the stream to the others"
    );
    assert_eq!(sa.peer_static(), *b.key.public_key().x25519());
    assert_eq!(sa.carrier(), Some(CarrierKind::Ble));
    assert_eq!(sb.carrier(), Some(CarrierKind::Ble));
    assert!(sa.remote_addr().is_none(), "a radio has no socket address");

    let mut st = sa
        .open_stream(Service::BLOB, Priority::Interactive)
        .unwrap();
    let payload: Vec<u8> = (0..100_000u32).map(|i| i as u8).collect();
    st.write_all(&payload).await.unwrap();
    st.shutdown().await.unwrap();
    let mut got = Vec::new();
    let mut rb = sb.accept_stream().await.unwrap();
    rb.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, payload);

    // A target that names no attached stream cannot be dialled by address.
    assert!(ea.connect(to(&b)).await.is_err());
}
