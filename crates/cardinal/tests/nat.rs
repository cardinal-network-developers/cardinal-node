//! Devices behind NATs, finding each other through a host
//! (`hosts.md#rendezvous`, `hosts.md#relay`). A device here sends all its UDP
//! through a simulated NAT and takes nothing else in, so nothing reaches it
//! that a real router would not let through.
//!
//! Skipped (with a message) when `/dev/fuse` or `fusermount3` is missing.

mod common;

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use common::*;
use tokio::net::UdpSocket;

const HEADER: usize = 6;

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    /// One public port for the device, open to whoever it has sent to. Most
    /// home routers do this, and two of them can be punched through.
    PortRestricted,
    /// A new public port for each address it sends to, as many carrier NATs
    /// do. What a host sees says nothing about what a peer would.
    Symmetric,
}

struct Nat {
    gateway: SocketAddr,
    _runtime: tokio::runtime::Runtime,
}

struct Mapping {
    public: Arc<UdpSocket>,
    opened: Arc<Mutex<HashSet<SocketAddr>>>,
}

impl Nat {
    fn new(kind: Kind) -> Nat {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let inner = runtime.block_on(UdpSocket::bind("127.0.0.1:0")).unwrap();
        let gateway = inner.local_addr().unwrap();
        runtime.spawn(run(Arc::new(inner), kind));
        Nat {
            gateway,
            _runtime: runtime,
        }
    }
}

async fn run(inner: Arc<UdpSocket>, kind: Kind) {
    let mut maps: HashMap<Option<SocketAddr>, Mapping> = HashMap::new();
    let device: Arc<Mutex<Option<SocketAddr>>> = Default::default();
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, from) = inner.recv_from(&mut buf).await.unwrap();
        if n < HEADER {
            continue;
        }
        *device.lock().unwrap() = Some(from);
        let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
        let to = SocketAddr::from((ip, u16::from_le_bytes([buf[4], buf[5]])));
        let key = (kind == Kind::Symmetric).then_some(to);
        let m = match maps.entry(key) {
            Entry::Occupied(m) => m.into_mut(),
            Entry::Vacant(v) => {
                let public = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
                let opened: Arc<Mutex<HashSet<SocketAddr>>> = Default::default();
                tokio::spawn(back(
                    public.clone(),
                    opened.clone(),
                    inner.clone(),
                    device.clone(),
                ));
                v.insert(Mapping { public, opened })
            }
        };
        m.opened.lock().unwrap().insert(to);
        let _ = m.public.send_to(&buf[HEADER..n], to).await;
    }
}

/// What comes in on a public port goes to the device, if it sent there first.
async fn back(
    public: Arc<UdpSocket>,
    opened: Arc<Mutex<HashSet<SocketAddr>>>,
    inner: Arc<UdpSocket>,
    device: Arc<Mutex<Option<SocketAddr>>>,
) {
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, from) = public.recv_from(&mut buf[HEADER..]).await.unwrap();
        if !opened.lock().unwrap().contains(&from) {
            continue;
        }
        if let SocketAddr::V4(a) = from {
            buf[..4].copy_from_slice(&a.ip().octets());
            buf[4..6].copy_from_slice(&a.port().to_le_bytes());
        }
        let to = *device.lock().unwrap();
        if let Some(to) = to {
            let _ = inner.send_to(&buf[..HEADER + n], to).await;
        }
    }
}

fn carrier(from: &Dev, name: &str) -> String {
    let v = from.status();
    let d = v["devices"].as_array().unwrap();
    let d = d.iter().find(|d| d["name"] == name).unwrap();
    if d["online"] == true {
        d["carrier"].as_str().unwrap_or_default().to_owned()
    } else {
        String::new()
    }
}

fn put_behind(d: &mut Dev, nat: &Nat) {
    d.stop();
    d.env.retain(|(k, _)| k != "CARDINAL_TEST_UDP_GATEWAY");
    d.env
        .push(("CARDINAL_TEST_UDP_GATEWAY".into(), nat.gateway.to_string()));
    d.start();
    d.wait_mounted();
}

/// A host, and two devices that know of it, not yet behind anything.
fn three(root: &std::path::Path) -> (Dev, Dev, Dev) {
    let mut host = Dev::new(root, "host", free_port());
    let mut x = Dev::new(root, "ex", free_port());
    let mut y = Dev::new(root, "why", free_port());
    host.start();
    host.cli(&["init", "--yes", "--name", "host"]);
    host.wait_mounted();
    x.start();
    pair(&host, &x);
    y.start();
    pair(&host, &y);
    x.wait_mounted();
    y.wait_mounted();
    let shown = host.cli(&["host", "--address", &format!("127.0.0.1:{}", host.port)]);
    let key = shown
        .lines()
        .find_map(|l| l.trim().strip_prefix("Key:"))
        .unwrap()
        .trim()
        .to_owned();
    for d in [&x, &y] {
        wait("it knows of the host", 20, || {
            d.cli(&["recovery", "sheet"]).contains(&key)
        });
    }
    (host, x, y)
}

#[test]
fn two_devices_behind_nats_reach_each_other_directly() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (mut host, mut x, mut y) = three(root.path());
    let (nx, ny) = (
        Nat::new(Kind::PortRestricted),
        Nat::new(Kind::PortRestricted),
    );
    put_behind(&mut x, &nx);
    put_behind(&mut y, &ny);

    wait("they reach each other directly", 30, || {
        carrier(&x, "why") == "UDP" && carrier(&y, "ex") == "UDP"
    });

    // It really is direct: the host can go.
    host.stop();
    std::fs::write(x.p("from-x.txt"), "x\n").unwrap();
    x.cli(&["flush"]);
    wait("y has it with no host", 15, || {
        std::fs::read(y.p("from-x.txt")).is_ok_and(|b| b == b"x\n")
    });

    // One moves: a new NAT, a new address, the same keys, and no name.
    host.start();
    wait("the host is back", 30, || carrier(&x, "host") == "UDP");
    let moved = Nat::new(Kind::PortRestricted);
    put_behind(&mut y, &moved);
    wait("they find each other again", 40, || {
        carrier(&x, "why") == "UDP" && carrier(&y, "ex") == "UDP"
    });
    std::fs::write(y.p("from-y.txt"), "y\n").unwrap();
    y.cli(&["flush"]);
    wait("x has it", 15, || {
        std::fs::read(x.p("from-y.txt")).is_ok_and(|b| b == b"y\n")
    });
}

#[test]
fn devices_that_cannot_punch_through_go_through_the_host() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (mut host, mut x, mut y) = three(root.path());
    let (nx, ny) = (Nat::new(Kind::Symmetric), Nat::new(Kind::Symmetric));
    put_behind(&mut x, &nx);
    put_behind(&mut y, &ny);

    wait("they meet through the host", 40, || {
        carrier(&x, "why") == "relay" && carrier(&y, "ex") == "relay"
    });

    // A file big enough for chunks, each way.
    let big: Vec<u8> = (0..3_000_000u32).map(|n| (n * 7 % 251) as u8).collect();
    std::fs::write(x.p("big.bin"), &big).unwrap();
    x.cli(&["flush"]);
    wait("y has it", 40, || {
        std::fs::read(y.p("big.bin")).is_ok_and(|b| b == big)
    });
    std::fs::write(y.p("back.txt"), "back\n").unwrap();
    y.cli(&["flush"]);
    wait("x has y's file", 20, || {
        std::fs::read(x.p("back.txt")).is_ok_and(|b| b == b"back\n")
    });

    // Without the host they have no way to each other.
    host.stop();
    std::fs::write(x.p("after.txt"), "after\n").unwrap();
    x.cli(&["flush"]);
    std::thread::sleep(std::time::Duration::from_secs(3));
    assert!(!y.p("after.txt").exists());
}
