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
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;
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
    /// One public port, known ahead and open to anyone: a forwarded port.
    Forwarded,
    /// As PortRestricted, with 80 ms on the way out.
    Slow,
}

struct Nat {
    gateway: SocketAddr,
    /// The public address, for a forwarded port.
    public: Option<SocketAddr>,
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
        let open = runtime
            .block_on(UdpSocket::bind("127.0.0.1:0"))
            .ok()
            .filter(|_| kind == Kind::Forwarded)
            .map(Arc::new);
        let public = open.as_ref().map(|s| s.local_addr().unwrap());
        runtime.spawn(run(Arc::new(inner), kind, open));
        Nat {
            gateway,
            public,
            _runtime: runtime,
        }
    }
}

async fn run(inner: Arc<UdpSocket>, kind: Kind, forwarded: Option<Arc<UdpSocket>>) {
    let mut maps: HashMap<Option<SocketAddr>, Mapping> = HashMap::new();
    let device: Arc<Mutex<Option<SocketAddr>>> = Default::default();
    if let Some(public) = forwarded {
        let opened: Arc<Mutex<HashSet<SocketAddr>>> = Default::default();
        tokio::spawn(back(public.clone(), None, inner.clone(), device.clone()));
        maps.insert(None, Mapping { public, opened });
    }
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
                    Some(opened.clone()),
                    inner.clone(),
                    device.clone(),
                ));
                v.insert(Mapping { public, opened })
            }
        };
        m.opened.lock().unwrap().insert(to);
        if kind == Kind::Slow {
            let public = m.public.clone();
            let data = buf[HEADER..n].to_vec();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(80)).await;
                let _ = public.send_to(&data, to).await;
            });
        } else {
            let _ = m.public.send_to(&buf[HEADER..n], to).await;
        }
    }
}

/// What comes in on a public port goes to the device, if it sent there first.
async fn back(
    public: Arc<UdpSocket>,
    opened: Option<Arc<Mutex<HashSet<SocketAddr>>>>,
    inner: Arc<UdpSocket>,
    device: Arc<Mutex<Option<SocketAddr>>>,
) {
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, from) = public.recv_from(&mut buf[HEADER..]).await.unwrap();
        if opened
            .as_ref()
            .is_some_and(|o| !o.lock().unwrap().contains(&from))
        {
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
    let listed = x.status();
    let devices = listed["devices"].as_array().unwrap();
    let why = devices.iter().find(|d| d["name"] == "why").unwrap();
    assert_eq!(why["through"], "host", "{why}");
    assert!(why["addr"].is_null(), "{why}");

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

/// Three devices, none of them a host.
fn three_plain(root: &std::path::Path) -> (Dev, Dev, Dev) {
    let mut plain = Dev::new(root, "plain", free_port());
    let mut x = Dev::new(root, "ex", free_port());
    let mut y = Dev::new(root, "why", free_port());
    plain.start();
    plain.cli(&["init", "--yes", "--name", "plain"]);
    plain.wait_mounted();
    x.start();
    pair(&plain, &x);
    y.start();
    pair(&plain, &y);
    x.wait_mounted();
    y.wait_mounted();
    assert!(plain
        .cli(&["recovery", "sheet"])
        .contains("no always-on device"));
    (plain, x, y)
}

/// `hosts.md#help-from-a-persons-own-devices`: any device with a session to
/// two others introduces them, and they stay connected when it goes.
#[test]
fn a_device_that_is_no_host_introduces_two_others() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (mut plain, mut x, mut y) = three_plain(root.path());
    let (nx, ny) = (
        Nat::new(Kind::PortRestricted),
        Nat::new(Kind::PortRestricted),
    );
    put_behind(&mut x, &nx);
    put_behind(&mut y, &ny);
    wait("it introduces them", 30, || {
        carrier(&x, "why") == "UDP" && carrier(&y, "ex") == "UDP"
    });
    plain.stop();
    std::fs::write(x.p("direct.txt"), "x\n").unwrap();
    x.cli(&["flush"]);
    wait("y has it with the other gone", 15, || {
        std::fs::read(y.p("direct.txt")).is_ok_and(|b| b == b"x\n")
    });
}

#[test]
fn a_device_that_is_no_host_relays_for_two_others() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (_plain, mut x, mut y) = three_plain(root.path());
    let (nx, ny) = (Nat::new(Kind::Symmetric), Nat::new(Kind::Symmetric));
    put_behind(&mut x, &nx);
    put_behind(&mut y, &ny);
    wait("they meet through it", 40, || {
        carrier(&x, "why") == "relay" && carrier(&y, "ex") == "relay"
    });
    std::fs::write(x.p("relayed.txt"), "r\n").unwrap();
    x.cli(&["flush"]);
    wait("y has it", 15, || {
        std::fs::read(y.p("relayed.txt")).is_ok_and(|b| b == b"r\n")
    });
}

/// The helper need not be out in the open: here it too is behind a router, one
/// with a forwarded port. And a device that comes back needs only it, not a
/// host and not a mailbox, to catch up.
#[test]
fn a_device_behind_a_forwarded_port_helps_and_catches_others_up() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (mut plain, mut x, mut y) = three_plain(root.path());
    let forwarded = Nat::new(Kind::Forwarded);
    let public = forwarded.public.unwrap().to_string();
    x.cli(&["peer", "add", &public]);
    y.cli(&["peer", "add", &public]);
    put_behind(&mut plain, &forwarded);
    let (nx, ny) = (
        Nat::new(Kind::PortRestricted),
        Nat::new(Kind::PortRestricted),
    );
    put_behind(&mut x, &nx);
    put_behind(&mut y, &ny);
    wait("it introduces them", 40, || {
        carrier(&x, "why") == "UDP" && carrier(&y, "ex") == "UDP"
    });

    // X is away while Y writes, and comes back to find only the helper.
    x.stop();
    std::fs::write(y.p("while-away.txt"), "news\n").unwrap();
    y.cli(&["flush"]);
    wait("the helper has it", 15, || {
        std::fs::read(plain.p("while-away.txt")).is_ok_and(|b| b == b"news\n")
    });
    y.stop();
    x.start();
    x.wait_mounted();
    wait("x catches up from the helper", 20, || {
        std::fs::read(x.p("while-away.txt")).is_ok_and(|b| b == b"news\n")
    });
}

fn ask(d: &Dev, req: Value) -> Value {
    let mut s = UnixStream::connect(d.home.join("control.sock")).unwrap();
    writeln!(s, "{req}").unwrap();
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).unwrap();
    let reply: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(reply["ok"], true, "{req} got {reply}");
    reply
}

/// The one contact a device has, as it lists them.
fn the_contact(d: &Dev) -> Value {
    ask(d, json!({"cmd": "contacts"}))["contacts"][0].clone()
}

fn standing(d: &Dev) -> Value {
    ask(d, json!({"cmd": "call"}))["call"]["state"].clone()
}

/// Ana, with a host and a laptop, and Bo, with a laptop and no host, who have
/// met through an invitation from Ana's laptop. Nothing is behind anything yet.
fn two_people(root: &std::path::Path) -> (Dev, Dev, Dev) {
    two_people_from(root, false)
}

/// The same, with the invitation from Ana's host, the one device of hers that
/// anyone can reach.
fn two_people_from(root: &std::path::Path, from_host: bool) -> (Dev, Dev, Dev) {
    let mut host = Dev::new(root, "host", free_port());
    let mut ana = Dev::new(root, "ana", free_port());
    let mut bo = Dev::new(root, "bo", free_port());
    host.start();
    host.cli(&["init", "--yes", "--name", "host"]);
    host.wait_mounted();
    ana.start();
    pair(&host, &ana);
    ana.wait_mounted();
    let shown = host.cli(&["host", "--address", &format!("127.0.0.1:{}", host.port)]);
    let key = shown
        .lines()
        .find_map(|l| l.trim().strip_prefix("Key:"))
        .unwrap()
        .trim()
        .to_owned();
    wait("ana's laptop knows of the host", 20, || {
        ana.cli(&["recovery", "sheet"]).contains(&key)
    });
    bo.start();
    bo.cli(&["init", "--yes", "--name", "bo"]);
    bo.wait_mounted();
    let inviter = if from_host { &host } else { &ana };
    let at = format!("127.0.0.1:{}", inviter.port);
    let code = inviter.cli(&["invite", "--address", &at, "--name", "Ana"]);
    bo.cli(&["accept", code.trim(), "--name", "Ana"]);
    wait("each lists the other", 30, || {
        the_contact(&ana)["name"] == "bo" && the_contact(&bo)["name"] == "Ana"
    });
    (host, ana, bo)
}

/// The case of two people where only one has a host, and neither laptop can
/// be reached or punched through: they meet through the one host, and can
/// call each other.
#[test]
fn a_contact_behind_a_nat_is_reached_through_their_host() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (_host, mut ana, mut bo) = two_people(root.path());
    let (na, nb) = (Nat::new(Kind::Symmetric), Nat::new(Kind::Symmetric));
    put_behind(&mut ana, &na);
    put_behind(&mut bo, &nb);

    wait("they meet through ana's host", 60, || {
        let (a, b) = (the_contact(&ana), the_contact(&bo));
        a["connected"] == true && b["connected"] == true && b["relayed"] == true
    });
    bo.cli(&["say", "Ana", "through your host"]);
    wait("ana reads it", 20, || {
        ana.cli(&["messages", "bo"]).contains("through your host")
    });

    // Ana rings Bo, who has no host: the session Bo keeps is how.
    ask(&ana, json!({"cmd": "call-start", "who": "bo"}));
    wait("bo's laptop rings", 15, || standing(&bo) == "ringing");
    ask(&bo, json!({"cmd": "call-answer"}));
    wait("ana hears the answer", 10, || standing(&ana) == "live");

    let mut lines = [&ana, &bo].map(|d| {
        let mut w = UnixStream::connect(d.home.join("control.sock")).unwrap();
        writeln!(w, "{}", json!({"cmd": "call-media"})).unwrap();
        w.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        let r = BufReader::new(w.try_clone().unwrap());
        (w, r)
    });
    std::thread::sleep(Duration::from_millis(300));
    for n in 0..50u32 {
        for (i, (w, _)) in lines.iter_mut().enumerate() {
            let frame = hex::encode((n + 1000 * i as u32).to_be_bytes());
            writeln!(w, "{}", json!({"audio": frame})).unwrap();
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut heard = [0, 0];
    for _ in 0..100 {
        for (i, (_, r)) in lines.iter_mut().enumerate() {
            let mut line = String::new();
            if r.read_line(&mut line).is_ok() && line.contains("audio") {
                heard[i] += 1;
            }
        }
        if heard == [50, 50] {
            break;
        }
    }
    assert!(heard[0] >= 45 && heard[1] >= 45, "heard {heard:?}");
    ask(&bo, json!({"cmd": "call-end"}));
    wait("it ends for ana", 10, || standing(&ana).is_null());
}

/// Ordinary NATs on both sides: the host introduces them, and the session is
/// direct.
#[test]
fn a_contact_is_met_directly_when_their_nat_allows() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (_host, mut ana, mut bo) = two_people(root.path());
    let (na, nb) = (
        Nat::new(Kind::PortRestricted),
        Nat::new(Kind::PortRestricted),
    );
    put_behind(&mut ana, &na);
    put_behind(&mut bo, &nb);
    wait("they meet directly", 60, || {
        let (a, b) = (the_contact(&ana), the_contact(&bo));
        a["connected"] == true
            && b["connected"] == true
            && a["relayed"] == false
            && b["relayed"] == false
    });
}

/// Ana reaches Bo through hosts only. Bo's device still asks Ana's host, but
/// Ana's laptop says no, so the host names nothing and relays nothing.
#[test]
fn a_contact_not_trusted_back_is_not_reached_through_a_host() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (_host, mut ana, mut bo) = two_people(root.path());
    ana.cli(&["contact", "bo", "hosts-only"]);
    let (na, nb) = (Nat::new(Kind::Symmetric), Nat::new(Kind::Symmetric));
    put_behind(&mut ana, &na);
    put_behind(&mut bo, &nb);
    wait("ana's host answers bo", 40, || {
        bo.log().contains("host named 0 of their devices")
    });
    std::thread::sleep(Duration::from_secs(5));
    assert!(
        !bo.log().contains("host named 1"),
        "the host named ana's laptop"
    );
    assert_eq!(the_contact(&bo)["connected"], false);
    assert_eq!(the_contact(&ana)["connected"], false);
}

/// Bo met Ana through her host and keeps a session with it, but a call has to
/// ring her laptop: Bo still looks for that, and finds it through the host.
#[test]
fn a_contact_with_a_session_to_the_host_still_finds_the_laptop() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (_host, mut ana, mut bo) = two_people_from(root.path(), true);
    let (na, nb) = (Nat::new(Kind::Symmetric), Nat::new(Kind::Symmetric));
    put_behind(&mut ana, &na);
    put_behind(&mut bo, &nb);
    wait("bo reaches ana's laptop through her host", 60, || {
        the_contact(&ana)["connected"] == true && the_contact(&ana)["relayed"] == true
    });
    ask(&ana, json!({"cmd": "call-start", "who": "bo"}));
    wait("bo's laptop rings", 15, || standing(&bo) == "ringing");
    ask(&bo, json!({"cmd": "call-answer"}));
    wait("ana's laptop hears the answer", 10, || {
        standing(&ana) == "live"
    });
}

/// A stranger with Ana's token times the host's answer to `connect`, with her
/// laptop far enough away that its answer would show. Nobody agrees, so nobody
/// is named, and the answer takes as long whether the laptop is there or not.
#[test]
fn the_hosts_reply_time_says_nothing_of_who_is_there() {
    use cardinal_crypto::{derive, HybridKeyPair, Purpose};
    use cardinal_encoding::Record;
    use cardinal_link::{
        Bind, CarrierKind, Endpoint, EndpointConfig, MemoryDirectory, Priority, Service, Target,
    };
    use tokio::io::AsyncWriteExt;
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (host, mut ana, _bo) = two_people(root.path());
    ana.cli(&["contact", "bo", "hosts-only"]);
    let na = Nat::new(Kind::Slow);
    put_behind(&mut ana, &na);

    let state = std::fs::read(host.home.join("mailbox/state.json")).unwrap();
    let state: Value = serde_json::from_slice(&state).unwrap();
    let token: [u8; 16] = hex::decode(state["active"][0].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let sheet = host.cli(&["recovery", "sheet"]);
    let key = sheet.lines().find(|l| l.contains("Key:")).unwrap();
    let key = key.split_whitespace().last().unwrap();
    let host_key = cardinald::host::read_sheet_key(key).unwrap();
    let addr: SocketAddr = format!("127.0.0.1:{}", host.port).parse().unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let measure = |rt: &tokio::runtime::Runtime| -> Vec<Duration> {
        rt.block_on(async {
            let kp = std::sync::Arc::new(HybridKeyPair::generate());
            let mut config = EndpointConfig::new(kp, MemoryDirectory::new());
            config.connect_timeout = Duration::from_secs(3);
            let bind = Bind {
                udp: Some("127.0.0.1:0".parse().unwrap()),
                tcp: None,
            };
            let endpoint = Endpoint::bind(config, bind).await.unwrap();
            let secret = derive(Purpose::Token, &token);
            let target = Target::invitation(addr, CarrierKind::Udp, host_key, &secret[..]);
            let s = endpoint.connect(target).await.expect("the token opens");
            let mut times = Vec::new();
            while times.len() < 6 {
                tokio::time::sleep(Duration::from_millis(1100)).await;
                let start = std::time::Instant::now();
                let mut st = s
                    .open_stream(Service::RENDEZVOUS, Priority::Interactive)
                    .unwrap();
                let ask = Record::new().with(0, 2u64).with(1, token);
                st.send_message(&cardinal_encoding::Value::Record(ask))
                    .await
                    .unwrap();
                st.shutdown().await.unwrap();
                let v = st.recv_message_max(1 << 20).await.unwrap().unwrap();
                let took = start.elapsed();
                let r = v.as_record().unwrap().clone();
                if r.get(0).and_then(|v| v.as_uint()) != Some(2) {
                    continue; // busy: someone else asked within the second
                }
                assert_eq!(r.record_list(1).unwrap_or_default().len(), 0, "named");
                times.push(took);
            }
            times.sort();
            times
        })
    };
    std::thread::sleep(Duration::from_secs(5));
    let present = measure(&rt);
    ana.stop();
    std::thread::sleep(Duration::from_secs(3));
    let absent = measure(&rt);
    eprintln!("present: {present:?}\nabsent: {absent:?}");
    assert!(
        present[0] <= absent[absent.len() - 1],
        "the reply time tells whether ana's laptop is present"
    );
}
