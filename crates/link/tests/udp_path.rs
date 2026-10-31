//! Sessions over real UDP sockets, through a bottleneck that queues, delays,
//! and drops as a real one does: congestion control as a session sees it.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cardinal_crypto::{HybridKeyPair, SigningKey};
use cardinal_link::{
    Bind, CarrierKind, Endpoint, EndpointConfig, LocalIdentity, MemoryDirectory, Priority, Service,
    Session, Target,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

const MBIT: f64 = 1e6 / 8.0;

#[derive(Clone, Copy)]
struct Link {
    /// Bytes per second, each way.
    rate: f64,
    /// Round trip with an empty queue.
    rtt: Duration,
    /// Bytes the queue holds.
    queue: usize,
    /// One packet in this many is lost, if not 0.
    lose_one_in: u64,
}

/// One direction of a link: what comes in at `from` leaves from `out` to
/// wherever `to` says, at the link's rate and after its delay.
async fn pipe(
    from: Arc<UdpSocket>,
    out: Arc<UdpSocket>,
    to: Arc<Mutex<Option<SocketAddr>>>,
    link: Link,
    learn: Option<Arc<Mutex<Option<SocketAddr>>>>,
    dropped: Arc<AtomicU64>,
) {
    let queue: Arc<Mutex<VecDeque<(Instant, Vec<u8>)>>> = Default::default();
    let q = queue.clone();
    tokio::spawn(async move {
        loop {
            let next = q.lock().await.front().map(|(t, _)| *t);
            let Some(t) = next else {
                tokio::time::sleep(Duration::from_micros(200)).await;
                continue;
            };
            tokio::time::sleep_until(t.into()).await;
            let due = Instant::now();
            let mut q = q.lock().await;
            while q.front().is_some_and(|(t, _)| *t <= due) {
                let (_, p) = q.pop_front().unwrap();
                if let Some(a) = *to.lock().await {
                    let _ = out.try_send_to(&p, a);
                }
            }
        }
    });
    let mut free_at = Instant::now();
    let mut seen = 0u64;
    let mut buf = vec![0u8; 2048];
    loop {
        let (n, src) = from.recv_from(&mut buf).await.unwrap();
        if let Some(l) = &learn {
            *l.lock().await = Some(src);
        }
        seen += 1;
        let now = Instant::now();
        let backlog = free_at.saturating_duration_since(now);
        let queued = (backlog.as_secs_f64() * link.rate) as usize;
        let random = link.lose_one_in != 0 && seen % link.lose_one_in == 0;
        if queued + n > link.queue || random {
            dropped.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        free_at = free_at.max(now) + Duration::from_secs_f64(n as f64 / link.rate);
        queue
            .lock()
            .await
            .push_back((free_at + link.rtt / 2, buf[..n].to_vec()));
    }
}

struct Pair {
    client: Session,
    server: Session,
    dropped: Arc<AtomicU64>,
    _keep: (Endpoint, Endpoint),
}

/// A session between two endpoints across `link`.
async fn across(link: Link) -> Pair {
    let dir = MemoryDirectory::new();
    let device = |n: u8| {
        let key = Arc::new(HybridKeyPair::from_seed(&[n; 32]));
        let id = LocalIdentity {
            identity: [0xaa; 32],
            signing_key: Arc::new(SigningKey::from_seed(&[n; 32])),
        };
        dir.add_device(
            id.identity,
            id.signing_key.public_key(),
            key.public_key().clone(),
        );
        (key, id)
    };
    let (ka, ia) = device(1);
    let (kb, ib) = device(2);
    let bind = |key: Arc<HybridKeyPair>, id: LocalIdentity| {
        let dir = dir.clone();
        async move {
            let mut c = EndpointConfig::new(key, dir);
            c.identity = Some(id);
            let loopback: SocketAddr = "127.0.0.1:0".parse().unwrap();
            Endpoint::bind(
                c,
                Bind {
                    udp: Some(loopback),
                    tcp: None,
                },
            )
            .await
            .unwrap()
        }
    };
    let (ea, eb) = (bind(ka, ia).await, bind(kb.clone(), ib).await);
    let front = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let back = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let client_addr: Arc<Mutex<Option<SocketAddr>>> = Default::default();
    let server_addr = Arc::new(Mutex::new(eb.udp_addr()));
    let dropped: Arc<AtomicU64> = Default::default();
    tokio::spawn(pipe(
        front.clone(),
        back.clone(),
        server_addr,
        link,
        Some(client_addr.clone()),
        dropped.clone(),
    ));
    tokio::spawn(pipe(
        back,
        front.clone(),
        client_addr,
        link,
        None,
        dropped.clone(),
    ));
    let at = front.local_addr().unwrap();
    let target = Target::new(at, CarrierKind::Udp, kb.public_key());
    let (a, b) = tokio::join!(ea.connect(target), eb.accept());
    Pair {
        client: a.unwrap(),
        server: b.unwrap(),
        dropped,
        _keep: (ea, eb),
    }
}

/// Sends `bytes` at `priority`, and returns them as they arrived and how
/// long that took.
async fn transfer(p: &Pair, bytes: &[u8], priority: Priority) -> (Vec<u8>, Duration) {
    let t0 = Instant::now();
    let mut out = p.client.open_stream(Service::BLOB, priority).unwrap();
    let data = bytes.to_vec();
    let send = tokio::spawn(async move {
        out.write_all(&data).await.unwrap();
        out.shutdown().await.unwrap();
    });
    let mut rx = p.server.accept_stream().await.unwrap();
    let mut got = Vec::with_capacity(bytes.len());
    rx.read_to_end(&mut got).await.unwrap();
    send.await.unwrap();
    (got, t0.elapsed())
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n as u32)
        .map(|i| (i.wrapping_mul(31) >> 3) as u8)
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_transfer_uses_most_of_the_link() {
    let link = Link {
        rate: 40.0 * MBIT,
        rtt: Duration::from_millis(20),
        queue: 2 << 20,
        lose_one_in: 0,
    };
    let p = across(link).await;
    let data = pattern(16 << 20);
    let (got, took) = transfer(&p, &data, Priority::Background).await;
    assert!(got == data);
    let used = data.len() as f64 / took.as_secs_f64() / link.rate;
    eprintln!(
        "MEASURE clean link: {took:?}, {used:.2} of the link, {} packets dropped, window {:?}",
        p.dropped.load(Ordering::Relaxed),
        p.client.stats().window,
    );
    assert!(used > 0.6, "used {used:.2}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_transfer_over_a_lossy_link_arrives_whole() {
    let link = Link {
        rate: 40.0 * MBIT,
        rtt: Duration::from_millis(20),
        queue: 2 << 20,
        lose_one_in: 200,
    };
    let p = across(link).await;
    let data = pattern(8 << 20);
    let (got, took) = tokio::time::timeout(
        Duration::from_secs(30),
        transfer(&p, &data, Priority::Interactive),
    )
    .await
    .unwrap();
    assert!(got == data);
    eprintln!(
        "MEASURE 0.5% loss: {took:?}, {:.1} Mbit/s, {} lost by the session",
        data.len() as f64 / took.as_secs_f64() / MBIT,
        p.client.stats().packets_lost,
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_message_gets_through_beside_a_big_transfer() {
    let link = Link {
        rate: 40.0 * MBIT,
        rtt: Duration::from_millis(20),
        queue: 8 << 20,
        lose_one_in: 0,
    };
    let p = Arc::new(across(link).await);
    let big = pattern(32 << 20);
    let bulk = {
        let p = p.clone();
        tokio::spawn(async move {
            let mut out = p
                .client
                .open_stream(Service::BLOB, Priority::Background)
                .unwrap();
            out.write_all(&big).await.unwrap();
            out.shutdown().await.unwrap();
        })
    };
    let mut rx = p.server.accept_stream().await.unwrap();
    let drain = tokio::spawn(async move {
        let mut sink = Vec::new();
        rx.read_to_end(&mut sink).await.unwrap();
        sink.len()
    });
    tokio::time::sleep(Duration::from_secs(2)).await;

    let mut times = Vec::new();
    for _ in 0..20 {
        let (got, took) = {
            let t0 = Instant::now();
            let mut out = p
                .client
                .open_stream(Service::SYNC, Priority::Interactive)
                .unwrap();
            out.write_all(b"news").await.unwrap();
            out.shutdown().await.unwrap();
            let mut rx = p.server.accept_stream().await.unwrap();
            let mut got = Vec::new();
            rx.read_to_end(&mut got).await.unwrap();
            (got, t0.elapsed())
        };
        assert_eq!(got, b"news");
        times.push(took);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    times.sort();
    let median = times[times.len() / 2];
    eprintln!(
        "MEASURE beside a transfer: median {median:?}, worst {:?}",
        times[times.len() - 1]
    );
    assert!(median < Duration::from_millis(90), "median {median:?}");
    drop(bulk);
    drop(drain);
}

/// How fast a bulk transfer goes on loopback, on either carrier. Not a test
/// of anything: run with `--ignored --nocapture` in a release build.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn measure_raw_speed() {
    for carrier in [CarrierKind::Tcp, CarrierKind::Udp] {
        let dir = MemoryDirectory::new();
        let device = |n: u8| {
            let key = Arc::new(HybridKeyPair::from_seed(&[n; 32]));
            let id = LocalIdentity {
                identity: [0xaa; 32],
                signing_key: Arc::new(SigningKey::from_seed(&[n; 32])),
            };
            dir.add_device(
                id.identity,
                id.signing_key.public_key(),
                key.public_key().clone(),
            );
            (key, id)
        };
        let (ka, ia) = device(1);
        let (kb, ib) = device(2);
        let loopback: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let bind = |key: Arc<HybridKeyPair>, id: LocalIdentity| {
            let dir = dir.clone();
            async move {
                let mut c = EndpointConfig::new(key, dir);
                c.identity = Some(id);
                let b = Bind {
                    udp: Some(loopback),
                    tcp: Some(loopback),
                };
                Endpoint::bind(c, b).await.unwrap()
            }
        };
        let (ea, eb) = (bind(ka, ia).await, bind(kb.clone(), ib).await);
        let at = match carrier {
            CarrierKind::Tcp => eb.tcp_addr().unwrap(),
            _ => eb.udp_addr().unwrap(),
        };
        let target = Target::new(at, carrier, kb.public_key());
        let (a, b) = tokio::join!(ea.connect(target), eb.accept());
        let p = Pair {
            client: a.unwrap(),
            server: b.unwrap(),
            dropped: Default::default(),
            _keep: (ea, eb),
        };
        let data = pattern(256 << 20);
        let (got, took) = transfer(&p, &data, Priority::Background).await;
        assert!(got == data);
        eprintln!(
            "MEASURE {carrier:?}: {:.0} MiB/s, lost {}, window {:?}, srtt {:?}",
            256.0 / took.as_secs_f64(),
            p.client.stats().packets_lost,
            p.client.stats().window,
            p.client.stats().srtt,
        );
    }
}
