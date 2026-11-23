//! Hosting a trusted contact (D87, `hosts.md#hosting-a-contact`): Daniel's
//! anchor, a device anyone can reach, hosts Grandma, whose phone sits behind
//! a router and has no host of her own. Ben, another contact of hers and
//! nobody to Daniel, leaves her messages there while her phone is off, finds
//! her phone through it, and is relayed through it where no direct way
//! opens. The NATs here are simulated, as in `nat.rs`: a device behind one
//! sends all its UDP through it and takes nothing else in.
//!
//! Skipped (with a message) when `/dev/fuse` or `fusermount3` is missing.

mod common;

use common::*;
use serde_json::{json, Value};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
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

#[allow(dead_code)]
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

fn behind(d: &mut Dev, nat: &Nat) {
    d.stop();
    d.env.retain(|(k, _)| k != "CARDINAL_TEST_UDP_GATEWAY");
    d.env
        .push(("CARDINAL_TEST_UDP_GATEWAY".into(), nat.gateway.to_string()));
    d.start();
    d.wait_mounted();
}

fn ask(d: &Dev, req: Value) -> Value {
    let reply = common::reply(d, &req);
    assert_eq!(reply["ok"], true, "{req} got {reply}");
    reply
}

fn contact(d: &Dev, who: &str) -> Value {
    let all = ask(d, json!({"cmd": "contacts"}))["contacts"].clone();
    let all = all.as_array().cloned().unwrap_or_default();
    all.into_iter()
        .find(|c| c["name"] == who)
        .unwrap_or(Value::Null)
}

fn hosting(d: &Dev) -> Vec<Value> {
    let v = ask(d, json!({"cmd": "hosting"}));
    v["hosting"].as_array().cloned().unwrap_or_default()
}

/// `inviter` invites `invitee`, who calls them `name`; both trust each
/// other, as an invitation makes them.
fn meet(inviter: &Dev, invitee: &Dev, name: &str) {
    let at = format!("127.0.0.1:{}", inviter.port);
    let code = inviter.cli(&["invite", "--address", &at, "--name", name]);
    invitee.cli(&["accept", code.trim(), "--name", name]);
    wait("each lists the other", 30, || {
        !contact(inviter, invitee.name).is_null() && !contact(invitee, name).is_null()
    });
}

/// Daniel, whose one device can be reached and is plugged in; Grandma; and
/// Ben, who knows Grandma and not Daniel. Nothing is behind anything yet.
fn three(root: &std::path::Path) -> (Dev, Dev, Dev) {
    let mut daniel = Dev::new(root, "daniel", free_port());
    let mut grandma = Dev::new(root, "grandma", free_port());
    let mut ben = Dev::new(root, "ben", free_port());
    for (d, name) in [
        (&mut daniel, "daniel"),
        (&mut grandma, "grandma"),
        (&mut ben, "ben"),
    ] {
        d.start();
        d.cli(&["init", "--yes", "--name", name]);
        d.wait_mounted();
    }
    ask(
        &daniel,
        json!({"cmd": "conditions", "plugged_in": true, "metered": false}),
    );
    let at = format!("127.0.0.1:{}", daniel.port);
    daniel.cli(&["host", "--address", &at]);
    meet(&daniel, &grandma, "Daniel");
    meet(&ben, &grandma, "Ben");
    (daniel, grandma, ben)
}

/// Daniel offers, Grandma accepts, and her devices name his anchor where
/// her hosts are named.
fn host_grandma(daniel: &Dev, grandma: &Dev) {
    let said = daniel.cli(&["hosting", "offer", "grandma"]);
    assert!(said.contains("never what anything says"), "{said}");
    wait("grandma hears of the offer", 30, || {
        hosting(grandma).iter().any(|h| h["mine"] == false)
    });
    grandma.cli(&["hosting", "accept", "Daniel"]);
    wait("daniel hosts grandma", 30, || {
        hosting(daniel).iter().any(|h| h["accepted"] == true)
    });
    wait("grandma names daniel's anchor to ben", 60, || {
        grandma.log().contains("device as a host of this person's")
    });
}

/// How often `d` pings the device of `who`'s it is in touch with, in
/// seconds (null for none); `None` if it is in touch with none.
fn kept_alive(d: &Dev, who: &str) -> Option<Value> {
    let v = ask(d, json!({"cmd": "contact-status", "who": who}));
    let all = v["devices"].as_array().cloned().unwrap_or_default();
    all.into_iter()
        .find(|x| x["online"] == true)
        .map(|x| x["kept_alive_s"].clone())
}

fn waiting_at(daniel: &Dev) -> u64 {
    let all = hosting(daniel);
    all.iter().find_map(|h| h["waiting"].as_u64()).unwrap_or(0)
}

/// The whole of step 1, as Daniel and Grandma would live it.
#[test]
fn a_contacts_anchor_hosts_grandma() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (daniel, mut grandma, mut ben) = three(root.path());
    host_grandma(&daniel, &grandma);
    std::thread::sleep(Duration::from_secs(5));

    // Grandma's phone is off; Ben, behind a router that cannot be punched
    // through, writes to her. It waits at Daniel's anchor.
    let (ng, nb) = (Nat::new(Kind::PortRestricted), Nat::new(Kind::Symmetric));
    grandma.stop();
    behind(&mut ben, &nb);
    ben.cli(&["say", "Grandma", "while you were away"]);
    wait("the envelope waits at daniel's anchor", 60, || {
        waiting_at(&daniel) >= 1
    });

    // Her phone wakes behind a router, on battery: it collects what waited.
    // Nobody is turned to for long, so only the anchor keeps it in touch.
    grandma
        .env
        .push(("CARDINAL_TEST_IN_USE_SECS".into(), "4".into()));
    behind(&mut grandma, &ng);
    ask(
        &grandma,
        json!({"cmd": "conditions", "plugged_in": false, "metered": false}),
    );
    wait("grandma reads it", 60, || {
        grandma
            .cli(&["messages", "Ben"])
            .contains("while you were away")
    });
    assert!(
        grandma.log().contains("envelopes left with"),
        "it did not come from the mailbox"
    );

    // D86 with D87: her host is her anchor. It keeps her phone's session
    // alive, and the phone, on battery, sends it no pings of its own.
    wait("the host keeps grandma's phone in touch", 60, || {
        kept_alive(&daniel, "grandma").is_some_and(|k| k.is_u64())
            && kept_alive(&grandma, "Daniel").is_some_and(|k| k.is_null())
    });

    // Ben finds her phone through the anchor, and is relayed through it.
    ben.cli(&["say", "Grandma", "are you there?"]);
    wait("ben reaches grandma's phone through the anchor", 60, || {
        let c = contact(&ben, "grandma");
        c["connected"] == true && c["relayed"] == true
    });
    assert!(
        daniel
            .log()
            .contains("a token holder looks for 1 devices here"),
        "the anchor did not introduce them"
    );
    wait("grandma reads it", 30, || {
        grandma.cli(&["messages", "Ben"]).contains("are you there?")
    });
    wait(
        "the phone still leaves the keepalives to its host",
        30,
        || {
            kept_alive(&grandma, "Daniel").is_some_and(|k| k.is_null())
                && kept_alive(&daniel, "grandma").is_some_and(|k| k.is_u64())
        },
    );

    // Grandma ends it: her devices stop naming the anchor, and it serves
    // her no longer.
    grandma.cli(&["hosting", "end", "Daniel"]);
    wait("grandma stops naming the anchor", 60, || {
        grandma.log().contains("no longer names a contact's host")
    });
    wait("daniel hosts nobody", 30, || hosting(&daniel).is_empty());
}

/// Daniel changes the quota on the host: one envelope at a time. A second
/// one from Ben while Grandma is away is refused, as a full mailbox
/// refuses: it never absorbs.
#[test]
fn a_full_mailbox_refuses() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (daniel, mut grandma, ben) = three(root.path());
    host_grandma(&daniel, &grandma);
    daniel.cli(&["hosting", "offer", "grandma", "--envelopes", "1"]);
    wait("the quota reaches daniel's list", 30, || {
        hosting(&daniel).iter().any(|h| h["envelopes"] == 1)
    });
    std::thread::sleep(Duration::from_secs(5));
    grandma.stop();
    ben.cli(&["say", "Grandma", "one"]);
    wait("one waits", 60, || waiting_at(&daniel) == 1);
    ben.cli(&["say", "Grandma", "two"]);
    wait("the second is refused", 60, || {
        daniel
            .log()
            .contains("mailbox here is full under one token")
    });
    assert_eq!(waiting_at(&daniel), 1);
    grandma.start();
    wait("grandma gets the first", 60, || {
        grandma.cli(&["messages", "Ben"]).contains("one")
    });
}

/// Only a trusted contact can be hosted, and nobody else can use what is
/// offered: someone Daniel keeps to hosts is refused an offer, and a host
/// offered and not accepted serves nobody.
#[test]
fn only_a_trusted_contact_is_hosted() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (daniel, grandma, _ben) = three(root.path());
    ask(
        &daniel,
        json!({"cmd": "contact", "who": "grandma", "setting": "hosts-only"}),
    );
    let refused = common::reply(&daniel, &json!({"cmd": "host-offer", "who": "grandma"}));
    assert_eq!(refused["ok"], false, "{refused}");
    ask(
        &daniel,
        json!({"cmd": "contact", "who": "grandma", "setting": "trust"}),
    );
    daniel.cli(&["hosting", "offer", "grandma"]);
    wait("grandma hears of the offer", 30, || {
        hosting(&grandma).iter().any(|h| h["mine"] == false)
    });
    std::thread::sleep(Duration::from_secs(15));
    assert!(
        !grandma.log().contains("device as a host of this person's"),
        "named before accepting"
    );
}
