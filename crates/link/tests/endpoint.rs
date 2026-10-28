//! Endpoints talking over loopback TCP and UDP.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use cardinal_crypto::{HybridKeyPair, SigningKey};
use cardinal_link::{
    Admission, Bind, CarrierKind, CloseReason, CookiePolicy, Endpoint, EndpointConfig,
    ExpectedPeer, LocalIdentity, MemoryDirectory, Priority, SecretEntry, Service, SessionConfig,
    Target,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

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

fn register(dir: &MemoryDirectory, d: &Device) {
    dir.add_device(
        d.id.identity,
        d.id.signing_key.public_key(),
        d.key.public_key().clone(),
    );
}

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

async fn endpoint_with(
    d: &Device,
    dir: Arc<MemoryDirectory>,
    f: impl FnOnce(&mut EndpointConfig),
) -> Endpoint {
    let mut c = EndpointConfig::new(d.key.clone(), dir);
    c.identity = Some(d.id.clone());
    c.connect_timeout = Duration::from_secs(3);
    c.handshake_retry = Duration::from_millis(200);
    f(&mut c);
    Endpoint::bind(
        c,
        Bind {
            udp: Some(loopback()),
            tcp: Some(loopback()),
        },
    )
    .await
    .unwrap()
}

async fn two(f: impl Fn(&mut EndpointConfig) + Copy) -> (Endpoint, Endpoint, Device, Device) {
    let a = device(1, 0xaa);
    let b = device(2, 0xaa); // Two devices of one identity.
    let dir = MemoryDirectory::new();
    register(&dir, &a);
    register(&dir, &b);
    let ea = endpoint_with(&a, dir.clone(), f).await;
    let eb = endpoint_with(&b, dir, f).await;
    (ea, eb, a, b)
}

#[tokio::test]
async fn tcp_session_streams_and_datagrams() {
    let (ea, eb, _a, b) = two(|_| {}).await;
    let target = Target::new(eb.tcp_addr().unwrap(), CarrierKind::Tcp, b.key.public_key());
    let (sa, sb) = tokio::join!(ea.connect(target), eb.accept());
    let sa = sa.unwrap();
    let sb = sb.unwrap();
    assert_eq!(sa.peer_static(), *b.key.public_key().x25519());
    assert_eq!(sa.peer_identity().unwrap().identity, [0xaa; 32]);
    assert!(sa.peer_identity().unwrap().verified_by_log);
    assert_eq!(
        sb.peer_identity().unwrap().signing_key,
        _a.id.signing_key.public_key()
    );
    assert_eq!(sa.handshake_hash(), sb.handshake_hash());
    assert!(sa.stats().rekeys >= 1, "mandatory rekey done");
    assert!(sb.stats().rekeys >= 1);
    assert_eq!(sa.admission(), Admission::Known);

    // A stream with messages.
    let mut st = sa
        .open_stream(Service::SYNC, Priority::Interactive)
        .unwrap();
    st.send_message(&cardinal_encoding::Value::from("hello"))
        .await
        .unwrap();
    let mut rs = sb.accept_stream().await.unwrap();
    assert_eq!(rs.service(), Service::SYNC);
    assert_eq!(rs.priority(), Priority::Interactive);
    let m = rs.recv_message().await.unwrap().unwrap();
    assert_eq!(m.as_text(), Some("hello"));
    rs.send_message(&cardinal_encoding::Value::from(42u64))
        .await
        .unwrap();
    rs.shutdown().await.unwrap();
    assert_eq!(
        st.recv_message().await.unwrap().unwrap().as_uint(),
        Some(42)
    );
    assert!(st.recv_message().await.unwrap().is_none());

    // Datagrams on a channel.
    let label = [5u8; 16];
    let mut cb = sb.channel(label, Priority::RealTime);
    let ca = sa.channel(label, Priority::RealTime);
    for i in 0..10u8 {
        ca.send(vec![i; 100]).unwrap();
    }
    for i in 0..10u8 {
        let d = tokio::time::timeout(Duration::from_secs(2), cb.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&d[..], &[i; 100][..]);
    }
    assert!(ca
        .send(vec![0; cardinal_link::MAX_DATAGRAM_PAYLOAD + 1])
        .is_err());

    // Observed addresses.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(sa.observed_addr().is_some());

    sa.close("bye");
    let r = tokio::time::timeout(Duration::from_secs(2), sb.closed())
        .await
        .unwrap();
    assert_eq!(r, CloseReason::Remote("bye".into()));
}

#[tokio::test]
async fn udp_session() {
    let (ea, eb, _a, b) = two(|_| {}).await;
    let target = Target::new(eb.udp_addr().unwrap(), CarrierKind::Udp, b.key.public_key());
    let (sa, sb) = tokio::join!(ea.connect(target), eb.accept());
    let (sa, sb) = (sa.unwrap(), sb.unwrap());
    let mut st = sa.open_stream(Service::BLOB, Priority::Background).unwrap();
    let data: Vec<u8> = (0..4_000_000u32).map(|i| (i % 251) as u8).collect();
    let d2 = data.clone();
    let w = tokio::spawn(async move {
        st.write_all(&d2).await.unwrap();
        st.shutdown().await.unwrap();
        st
    });
    let mut rs = sb.accept_stream().await.unwrap();
    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(60), rs.read_to_end(&mut got))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.len(), data.len());
    assert!(got == data);
    drop(w.await.unwrap());
}

/// Transfers 1 GiB through one stream over loopback TCP and prints the
/// rate: `cargo test --release -p cardinal-link --test endpoint
/// tcp_throughput -- --nocapture`. Set CARDINAL_THROUGHPUT_MIB to change
/// the size.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_throughput() {
    let mib: usize = std::env::var("CARDINAL_THROUGHPUT_MIB")
        .ok()
        .and_then(|v| v.parse().ok())
        // 1 GiB in release builds; a smaller amount in debug builds, where
        // this crate is unoptimized.
        .unwrap_or(if cfg!(debug_assertions) { 8 } else { 1024 });
    let (ea, eb, _a, b) = two(|_| {}).await;
    let target = Target::new(eb.tcp_addr().unwrap(), CarrierKind::Tcp, b.key.public_key());
    let (sa, sb) = tokio::join!(ea.connect(target), eb.accept());
    let (sa, sb) = (sa.unwrap(), sb.unwrap());
    let total = mib * 1024 * 1024;
    let mut st = sa.open_stream(Service::BLOB, Priority::Background).unwrap();
    let start = Instant::now();
    let writer = tokio::spawn(async move {
        let chunk = vec![0x5au8; 256 * 1024];
        let mut left = total;
        while left > 0 {
            let n = left.min(chunk.len());
            st.write_all(&chunk[..n]).await.unwrap();
            left -= n;
        }
        st.shutdown().await.unwrap();
        st
    });
    let mut rs = sb.accept_stream().await.unwrap();
    let mut buf = vec![0u8; 256 * 1024];
    let mut got = 0usize;
    loop {
        let n = rs.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        got += n;
    }
    let secs = start.elapsed().as_secs_f64();
    drop(writer.await.unwrap());
    assert_eq!(got, total);
    let rate = total as f64 / secs / 1e6;
    println!(
        "link throughput over loopback TCP: {mib} MiB in {secs:.2} s = {rate:.1} MB/s ({} packets sent, {} rekeys)",
        sa.stats().packets_sent,
        sa.stats().rekeys
    );
}

#[tokio::test]
async fn strangers_get_silence() {
    let (_ea, eb, _a, b) = two(|_| {}).await;
    // A device unknown to b's directory.
    let s = device(9, 0x99);
    let es = endpoint_with(&s, MemoryDirectory::new(), |c| {
        c.connect_timeout = Duration::from_millis(800)
    })
    .await;
    let target = Target::new(eb.tcp_addr().unwrap(), CarrierKind::Tcp, b.key.public_key());
    assert!(matches!(
        es.connect(target).await,
        Err(cardinal_link::LinkError::Timeout)
    ));
    let target = Target::new(eb.udp_addr().unwrap(), CarrierKind::Udp, b.key.public_key());
    assert!(es.connect(target).await.is_err());

    // Raw: a valid-looking initiation from a stranger, and garbage with a
    // bad mac1, get no bytes back at all.
    let init = {
        let p = cardinal_link::handshake::InitiationParams {
            local: &s.key,
            remote_x25519: *b.key.public_key().x25519(),
            remote_kem: Some(b.key.public_key().kem()),
            secret: None,
            counter: u64::MAX >> 4,
            sender_index: 7,
        };
        cardinal_link::handshake::initiate(&p, &[1; 32], [0; 3], |k| k.encapsulate())
            .unwrap()
            .packet()
            .to_vec()
    };
    let mut garbage = init.clone();
    garbage[1200] ^= 1;
    garbage[100] ^= 1;
    for pkt in [&init, &garbage] {
        let mut tcp = TcpStream::connect(eb.tcp_addr().unwrap()).await.unwrap();
        tcp.write_all(&(pkt.len() as u16).to_le_bytes())
            .await
            .unwrap();
        tcp.write_all(pkt).await.unwrap();
        let mut b1 = [0u8; 1];
        let r = tokio::time::timeout(Duration::from_millis(500), tcp.read(&mut b1)).await;
        assert!(r.is_err(), "no reply over TCP");
        let udp = UdpSocket::bind(loopback()).await.unwrap();
        udp.send_to(pkt, eb.udp_addr().unwrap()).await.unwrap();
        let mut buf = [0u8; 2048];
        let r = tokio::time::timeout(Duration::from_millis(500), udp.recv_from(&mut buf)).await;
        assert!(r.is_err(), "no reply over UDP");
    }
}

#[tokio::test]
async fn invitation_without_kem_uses_secret() {
    // The invitee is unknown to the inviter and has only its X25519 key.
    let inviter = device(3, 0x33);
    let invitee = device(4, 0x44);
    let ei = endpoint_with(&inviter, MemoryDirectory::new(), |_| {}).await;
    let ee = endpoint_with(&invitee, MemoryDirectory::new(), |c| {
        c.connect_timeout = Duration::from_millis(800)
    })
    .await;
    let secret = [0x5e; 16];
    // Wrong secret first: silence.
    let id = ei.add_secret(SecretEntry {
        expected: ExpectedPeer {
            identity: Some([0x44; 32]),
            ..Default::default()
        },
        ..SecretEntry::new(&secret)
    });
    let wrong = Target::invitation(
        ei.tcp_addr().unwrap(),
        CarrierKind::Tcp,
        *inviter.key.public_key().x25519(),
        &[0x11; 16],
    );
    assert!(ee.connect(wrong).await.is_err());
    // Without a secret and without a KEM ciphertext: silence too.
    let mut no_secret = Target::new(
        ei.tcp_addr().unwrap(),
        CarrierKind::Tcp,
        inviter.key.public_key(),
    );
    no_secret.peer_kem = None;
    assert!(ee.connect(no_secret).await.is_err());

    let t = Target::invitation(
        ei.tcp_addr().unwrap(),
        CarrierKind::Tcp,
        *inviter.key.public_key().x25519(),
        &secret,
    )
    .expect(ExpectedPeer {
        identity: Some([0x33; 32]),
        ..Default::default()
    });
    let (se, si) = tokio::join!(ee.connect(t.clone()), ei.accept());
    let (se, si) = (se.unwrap(), si.unwrap());
    let pi = si.peer_identity().unwrap();
    assert_eq!(pi.identity, [0x44; 32]);
    assert!(!pi.verified_by_log, "provisional until the log is known");
    assert!(matches!(si.admission(), Admission::Secret { id: i, .. } if i == id));
    assert!(se.peer_link_key().is_none());
    assert!(si.peer_link_key().is_none());
    assert!(se.stats().rekeys >= 1, "post-quantum rekey follows at once");
    // Single use: a second session with the same invitation is refused.
    assert!(ee.connect(t).await.is_err());
}

#[tokio::test]
async fn cookie_reply_then_mac2() {
    let (ea, eb, _a, b) = two(|c| c.cookies = CookiePolicy::Always).await;
    for carrier in [CarrierKind::Udp, CarrierKind::Tcp] {
        let addr = match carrier {
            CarrierKind::Udp => eb.udp_addr().unwrap(),
            CarrierKind::Tcp => eb.tcp_addr().unwrap(),
        };
        let target = Target::new(addr, carrier, b.key.public_key());
        let (sa, sb) = tokio::join!(ea.connect(target), eb.accept());
        sa.unwrap();
        sb.unwrap();
    }
}

#[tokio::test]
async fn periodic_rekey_under_traffic() {
    let (ea, eb, _a, b) = two(|c| {
        c.session = SessionConfig {
            rekey_interval: Duration::from_millis(100),
            ..SessionConfig::default()
        }
    })
    .await;
    let target = Target::new(eb.tcp_addr().unwrap(), CarrierKind::Tcp, b.key.public_key());
    let (sa, sb) = tokio::join!(ea.connect(target), eb.accept());
    let (sa, sb) = (sa.unwrap(), sb.unwrap());
    let mut st = sa.open_stream(Service::SYNC, Priority::Background).unwrap();
    let mut rs = None;
    let mut sent = 0u64;
    let mut got = 0u64;
    let start = Instant::now();
    while start.elapsed() < Duration::from_millis(1200) {
        let chunk: Vec<u8> = (0..10_000u32).map(|i| (i as u64 + sent) as u8).collect();
        st.write_all(&chunk).await.unwrap();
        sent += chunk.len() as u64;
        if rs.is_none() {
            rs = sb.accept_stream().await;
        }
        let r = rs.as_mut().unwrap();
        let mut buf = vec![0u8; chunk.len()];
        r.read_exact(&mut buf).await.unwrap();
        for (i, b) in buf.iter().enumerate() {
            assert_eq!(*b, (got + i as u64) as u8);
        }
        got += buf.len() as u64;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let ra = sa.stats().rekeys;
    let rb = sb.stats().rekeys;
    assert!(ra >= 5, "initiator rekeys: {ra}");
    assert!(rb + 1 >= ra, "responder rekeys: {rb}");
}

/// A UDP relay standing in for a NAT: client packets go out from one
/// socket, then from another, as if the client roamed.
struct Nat {
    addr: SocketAddr,
    switch: tokio::sync::watch::Sender<usize>,
    first_initiation: Arc<std::sync::Mutex<Option<Vec<u8>>>>,
    outer: [Arc<UdpSocket>; 2],
}

async fn nat(server: SocketAddr) -> Nat {
    let front = Arc::new(UdpSocket::bind(loopback()).await.unwrap());
    let outer = [
        Arc::new(UdpSocket::bind(loopback()).await.unwrap()),
        Arc::new(UdpSocket::bind(loopback()).await.unwrap()),
    ];
    let (switch, rx) = tokio::sync::watch::channel(0usize);
    let client: Arc<std::sync::Mutex<Option<SocketAddr>>> = Default::default();
    let first_initiation: Arc<std::sync::Mutex<Option<Vec<u8>>>> = Default::default();
    {
        let (front, outer, rx, client, fi) = (
            front.clone(),
            outer.clone(),
            rx.clone(),
            client.clone(),
            first_initiation.clone(),
        );
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                let (n, from) = front.recv_from(&mut buf).await.unwrap();
                *client.lock().unwrap() = Some(from);
                if buf[0] == 1 {
                    fi.lock().unwrap().get_or_insert_with(|| buf[..n].to_vec());
                }
                let i = *rx.borrow();
                let _ = outer[i].send_to(&buf[..n], server).await;
            }
        });
    }
    for o in outer.iter() {
        let (front, o, client) = (front.clone(), o.clone(), client.clone());
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                let (n, _) = o.recv_from(&mut buf).await.unwrap();
                let c = *client.lock().unwrap();
                if let Some(c) = c {
                    let _ = front.send_to(&buf[..n], c).await;
                }
            }
        });
    }
    Nat {
        addr: front.local_addr().unwrap(),
        switch,
        first_initiation,
        outer,
    }
}

#[tokio::test]
async fn udp_roaming_keeps_the_session() {
    let (ea, eb, _a, b) = two(|_| {}).await;
    let n = nat(eb.udp_addr().unwrap()).await;
    let target = Target::new(n.addr, CarrierKind::Udp, b.key.public_key());
    let (sa, sb) = tokio::join!(ea.connect(target), eb.accept());
    let (sa, sb) = (sa.unwrap(), sb.unwrap());
    assert_eq!(sb.remote_addr(), Some(n.outer[0].local_addr().unwrap()));
    let mut st = sa
        .open_stream(Service::SYNC, Priority::Interactive)
        .unwrap();
    st.write_all(b"before").await.unwrap();
    let mut rs = sb.accept_stream().await.unwrap();
    let mut buf = [0u8; 6];
    rs.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"before");

    // The client "moves": its packets now come from another address.
    n.switch.send(1).unwrap();
    st.write_all(b"after!").await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), rs.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf, b"after!");
    // Replies flow on the new path once it validated.
    rs.write_all(b"reply").await.unwrap();
    let mut b5 = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(5), st.read_exact(&mut b5))
        .await
        .unwrap()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while sb.remote_addr() != Some(n.outer[1].local_addr().unwrap()) {
        assert!(Instant::now() < deadline, "server moved the session");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Replaying the first initiation (counter now confirmed) gets nothing.
    let init = n.first_initiation.lock().unwrap().clone().unwrap();
    let probe = UdpSocket::bind(loopback()).await.unwrap();
    probe.send_to(&init, eb.udp_addr().unwrap()).await.unwrap();
    let mut rb = [0u8; 2048];
    let r = tokio::time::timeout(Duration::from_millis(400), probe.recv_from(&mut rb)).await;
    assert!(r.is_err(), "replayed initiation answered");
    assert!(eb
        .confirmed_counter(&_a.key.public_key().x25519().clone())
        .is_some());
}

#[tokio::test]
async fn reconnect_replaces_and_simultaneous_resolves() {
    let (ea, eb, a, b) = two(|_| {}).await;
    let ta = Target::new(eb.tcp_addr().unwrap(), CarrierKind::Tcp, b.key.public_key());
    let tb = Target::new(ea.tcp_addr().unwrap(), CarrierKind::Tcp, a.key.public_key());
    // Simultaneous: both initiate.
    let (r1, r2) = tokio::join!(ea.connect(ta.clone()), eb.connect(tb));
    let (s1, s2) = (r1.unwrap(), r2.unwrap());
    tokio::time::sleep(Duration::from_millis(200)).await;
    let a_smaller = a.key.public_key().x25519() < b.key.public_key().x25519();
    let (survivor, loser) = if a_smaller { (&s1, &s2) } else { (&s2, &s1) };
    assert!(!survivor.is_closed());
    assert_eq!(loser.close_reason(), Some(CloseReason::Replaced));
    assert_eq!(ea.sessions().iter().filter(|s| !s.is_closed()).count(), 1);
    assert_eq!(eb.sessions().iter().filter(|s| !s.is_closed()).count(), 1);
}

/// Many request/reply streams at once, as blob fetching does: every
/// request must be answered promptly (a flow-control credit leak used to
/// starve the session after a while).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_request_streams() {
    let (ea, eb, _a, b) = two(|_| {}).await;
    let target = Target::new(eb.tcp_addr().unwrap(), CarrierKind::Tcp, b.key.public_key());
    let (sa, sb) = tokio::join!(ea.connect(target), eb.accept());
    let (sa, sb) = (sa.unwrap(), sb.unwrap());
    let sb2 = sb.clone();
    // Server: reads a request (a length), answers that many bytes.
    let server = tokio::spawn(async move {
        while let Some(mut st) = sb.accept_stream().await {
            tokio::spawn(async move {
                let mut len = [0u8; 4];
                if st.read_exact(&mut len).await.is_err() {
                    return;
                }
                let n = u32::from_le_bytes(len) as usize;
                let _ = st.write_all(&vec![7u8; n]).await;
                let _ = st.shutdown().await;
            });
        }
    });
    let total = if cfg!(debug_assertions) { 300 } else { 2000 };
    let mut set = tokio::task::JoinSet::new();
    let mut done = 0;
    let mut i = 0u32;
    while done < total {
        while set.len() < 8 && i < total as u32 {
            let s = sa.clone();
            // Some requests are abandoned after part of the reply, as a
            // timed-out request is.
            let abandon = i % 5 == 3;
            let n = 300_000 + (i % 7) * 50_000;
            i += 1;
            set.spawn(async move {
                let mut st = s.open_stream(Service::BLOB, Priority::Background).unwrap();
                st.write_all(&n.to_le_bytes()).await.unwrap();
                if abandon {
                    // drop after part of the reply, the rest in flight
                    let mut part = vec![0u8; 100_000];
                    st.read_exact(&mut part).await.unwrap();
                    return;
                }
                st.shutdown().await.unwrap();
                let mut got = Vec::new();
                st.read_to_end(&mut got).await.unwrap();
                assert_eq!(got.len(), n as usize);
            });
        }
        let Ok(r) = tokio::time::timeout(Duration::from_secs(10), set.join_next()).await else {
            panic!(
                "a request stalled\nclient:\n{}\nserver:\n{}",
                sa.debug_flow(),
                sb2.debug_flow()
            );
        };
        r.unwrap().unwrap();
        done += 1;
    }
    server.abort();
}
