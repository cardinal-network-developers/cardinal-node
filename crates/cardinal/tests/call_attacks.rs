//! Review tests: calls against someone who means harm, with a real contact's
//! keys, and calls across a person's several devices.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cardinal_encoding::{Record, Value};
use cardinal_link::{
    Bind, CarrierKind, Endpoint, EndpointConfig, LocalIdentity, MemoryDirectory, Priority, Service,
    Session, Target,
};
use cardinald::keys::Keys;
use common::*;
use serde_json::{json, Value as Json};
use tokio::io::AsyncWriteExt;

const RING: u64 = 1;
const ANSWER: u64 = 2;
const END: u64 = 3;

fn person(root: &std::path::Path, name: &'static str) -> Dev {
    let mut d = Dev::new(root, name, free_port());
    d.start();
    d.cli(&["init", "--yes", "--name", name]);
    d.wait_mounted();
    d
}

fn try_ask(d: &Dev, req: Json) -> Json {
    let mut s = UnixStream::connect(d.home.join("control.sock")).unwrap();
    writeln!(s, "{req}").unwrap();
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

fn ask(d: &Dev, req: Json) -> Json {
    let reply = try_ask(d, req.clone());
    assert_eq!(reply["ok"], true, "{req} got {reply}");
    reply
}

fn standing(d: &Dev) -> Json {
    ask(d, json!({"cmd": "call"}))["call"]["state"].clone()
}

fn unhex<const N: usize>(s: &str) -> [u8; N] {
    let byte = |i: usize| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    std::array::from_fn(byte)
}

fn spaces(d: &Dev) -> Vec<[u8; 32]> {
    let dir = std::fs::read_dir(d.home.join("spaces")).unwrap();
    let names = dir.flatten().map(|e| e.file_name());
    names.map(|n| unhex(n.to_str().unwrap())).collect()
}

/// `invitee` accepts `inviter`'s invitation, in the ordinary way.
fn contacts(inviter: &Dev, invitee: &Dev, inviter_named: &str) {
    let at = format!("127.0.0.1:{}", inviter.port);
    let code = inviter.cli(&["invite", "--address", &at, "--name", inviter_named]);
    invitee.cli(&["accept", code.trim()]);
    wait("the inviter lists them", 30, || {
        inviter.cli(&["contacts"]).contains(invitee.name)
    });
}

fn other_person(d: &Dev) -> [u8; 32] {
    let mut names = std::fs::read_dir(d.home.join("others")).unwrap().flatten();
    let name = names.next().unwrap().file_name();
    let name = name.to_str().unwrap();
    unhex(name.split('.').next().unwrap())
}

struct Modified {
    keys: Keys,
    identity: [u8; 32],
    peer: Keys,
    peer_identity: [u8; 32],
    addr: SocketAddr,
}

impl Modified {
    /// Before `peer` knows anyone else.
    fn of(who: &Dev, peer: &Dev) -> Modified {
        Modified {
            keys: Keys::load_or_create(&who.home.join("device.key")).unwrap(),
            identity: other_person(peer),
            peer: Keys::load_or_create(&peer.home.join("device.key")).unwrap(),
            peer_identity: other_person(who),
            addr: format!("127.0.0.1:{}", peer.port).parse().unwrap(),
        }
    }

    async fn open(&self) -> Option<(Endpoint, Session)> {
        let directory = MemoryDirectory::new();
        let link = self.peer.link.public_key();
        directory.add_device(self.peer_identity, self.peer.key(), link.clone());
        let mut config = EndpointConfig::new(self.keys.link.clone(), directory);
        config.identity = Some(LocalIdentity {
            identity: self.identity,
            signing_key: self.keys.signing.clone(),
        });
        config.connect_timeout = Duration::from_secs(3);
        let bind = Bind {
            udp: Some("127.0.0.1:0".parse().unwrap()),
            tcp: None,
        };
        let endpoint = Endpoint::bind(config, bind).await.unwrap();
        let target = Target::new(self.addr, CarrierKind::Udp, link);
        let session = endpoint.connect(target).await.ok()?;
        Some((endpoint, session))
    }
}

async fn signal(s: &Session, kind: u64, space: [u8; 32], id: [u8; 16]) {
    let Ok(mut st) = s.open_stream(Service::EPHEMERAL, Priority::RealTime) else {
        return;
    };
    let r = Record::new().with(0, kind).with(1, space).with(2, id);
    let _ = st.send_message(&Value::Record(r)).await;
    let _ = st.shutdown().await;
}

/// The next signal this session hears.
async fn heard(s: &Session, within: Duration) -> Option<(u64, [u8; 32], [u8; 16])> {
    let wait = async {
        loop {
            let mut st = s.accept_stream().await?;
            if st.service() != Service::EPHEMERAL {
                continue;
            }
            let Ok(Some(v)) = st.recv_message_max(256).await else {
                continue;
            };
            let r = v.as_record()?;
            let kind = r.get(0)?.as_uint()?;
            let space: [u8; 32] = r.get(1)?.as_bytes()?.try_into().ok()?;
            let id: [u8; 16] = r.get(2)?.as_bytes()?.try_into().ok()?;
            return Some((kind, space, id));
        }
    };
    tokio::time::timeout(within, wait).await.ok()?
}

fn label_of(space: &[u8; 32], id: &[u8; 16]) -> [u8; 16] {
    let mut h = blake3::Hasher::new();
    h.update(space);
    h.update(id);
    let mut label = [0; 16];
    label.copy_from_slice(&h.finalize().as_bytes()[..16]);
    label
}

struct Line {
    r: BufReader<UnixStream>,
}

impl Line {
    fn open(d: &Dev) -> Line {
        let mut w = UnixStream::connect(d.home.join("control.sock")).unwrap();
        writeln!(w, "{}", json!({"cmd": "call-media"})).unwrap();
        w.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        Line {
            r: BufReader::new(w),
        }
    }

    fn heard(&mut self) -> Option<Vec<u8>> {
        let mut line = String::new();
        self.r.read_line(&mut line).ok()?;
        let v: Json = serde_json::from_str(&line).ok()?;
        hex::decode(v["audio"].as_str()?).ok()
    }
}

fn resident(pid: u32) -> u64 {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let line = status.lines().find(|l| l.starts_with("VmRSS:")).unwrap();
    let kib = line.split_whitespace().nth(1).unwrap();
    kib.parse::<u64>().unwrap() * 1024
}

/// Ticks of CPU a process has used.
fn cpu_ticks(pid: u32) -> u64 {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let after = stat.rsplit(") ").next().unwrap();
    let f: Vec<&str> = after.split_whitespace().collect();
    f[11].parse::<u64>().unwrap() + f[12].parse::<u64>().unwrap()
}

fn seq_now(d: &Dev) -> u64 {
    let mut s = UnixStream::connect(d.home.join("control.sock")).unwrap();
    writeln!(s, "{}", json!({"cmd": "watch"})).unwrap();
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).unwrap();
    let v: Json = serde_json::from_str(&line).unwrap();
    v["seq"].as_u64().unwrap()
}

/// One device of two says no. The caller's call ends, and the other device,
/// told nothing, goes on ringing. If it answers it is live with nobody, and
/// stays so, and is busy to everyone meanwhile.
#[test]
fn saying_no_on_one_device_stops_the_others_ringing() {
    if !fuse_available() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let a = person(root.path(), "ana");
    let b = person(root.path(), "bo");
    contacts(&a, &b, "Ana");
    let mut b2 = Dev::new(root.path(), "bophone", free_port());
    b2.start();
    pair(&b, &b2);
    wait("the phone knows ana", 60, || {
        b2.cli(&["contacts"]).contains("Ana")
    });
    // Own devices share only each other's addresses.
    b2.stop();
    std::fs::copy(b.home.join("peers.json"), b2.home.join("peers.json")).unwrap();
    b2.start();
    b2.wait_mounted();
    wait("ana reaches the phone", 60, || {
        ask(&b2, json!({"cmd": "contacts"}))["contacts"][0]["connected"] == true
    });

    ask(&a, json!({"cmd": "call-start", "who": "bo"}));
    wait("both ring", 10, || {
        standing(&b) == "ringing" && standing(&b2) == "ringing"
    });
    ask(&b, json!({"cmd": "call-end"}));
    wait("ana hears no", 10, || standing(&a).is_null());
    std::thread::sleep(Duration::from_secs(3));
    let phone = standing(&b2);
    eprintln!("MEASURE 3 s after the call ended, the phone is {phone}");
    if phone == "ringing" {
        ask(&b2, json!({"cmd": "call-answer"}));
        std::thread::sleep(Duration::from_secs(50));
        let state = standing(&b2);
        eprintln!("MEASURE 50 s after answering nobody, the phone is {state}");
        eprintln!(
            "MEASURE and ana says {}",
            ask(&a, json!({"cmd": "call"}))["call"]
        );
    }
    assert!(phone.is_null(), "the phone goes on ringing: {phone}");
}

/// A contact who rings keeps this person from calling anyone else, and the
/// moment they hang up rings again.
#[test]
fn a_ring_gives_way_to_a_call_this_person_makes() {
    if !fuse_available() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let ana = person(root.path(), "ana");
    let mut bo = person(root.path(), "bo");
    contacts(&ana, &bo, "Ana");
    let theirs = spaces(&bo);
    let space = spaces(&ana)
        .into_iter()
        .find(|s| theirs.contains(s))
        .unwrap();
    let hostile = Modified::of(&bo, &ana);
    bo.stop();
    let cy = person(root.path(), "cy");
    contacts(&ana, &cy, "Ana");
    wait("ana sees cy", 30, || {
        let c = ask(&ana, json!({"cmd": "contacts"}));
        c["contacts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["name"] == "cy" && c["connected"] == true)
    });

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (_e, s) = hostile.open().await.expect("a contact connects");
        tokio::time::sleep(Duration::from_millis(500)).await;
        let mut refused = 0;
        for n in 0u8..5 {
            signal(&s, RING, space, [n; 16]).await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert_eq!(standing(&ana), "ringing");
            let tried = try_ask(&ana, json!({"cmd": "call-start", "who": "cy"}));
            eprintln!("MEASURE ana calls cy: {tried}");
            if tried["ok"] == false {
                refused += 1;
            }
            ask(&ana, json!({"cmd": "call-end"}));
            let (kind, ..) = heard(&s, Duration::from_secs(3)).await.unwrap();
            assert_eq!(kind, END);
        }
        assert_eq!(refused, 0, "ana could not call cy");
    });
}

/// The call already ringing, rung again over another session (one made
/// since, or another found): it goes on ringing, nobody is told it is busy,
/// and it is answered on the newer session.
#[test]
fn a_ring_rung_again_over_another_session_is_the_same_call() {
    if !fuse_available() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let ana = person(root.path(), "ana");
    let mut bo = person(root.path(), "bo");
    contacts(&ana, &bo, "Ana");
    let theirs = spaces(&bo);
    let space = spaces(&ana)
        .into_iter()
        .find(|s| theirs.contains(s))
        .unwrap();
    let caller = Modified::of(&bo, &ana);
    bo.stop();

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (_e1, first) = caller.open().await.expect("a contact connects");
        tokio::time::sleep(Duration::from_millis(500)).await;
        let id = [7u8; 16];
        signal(&first, RING, space, id).await;
        wait("ana rings", 10, || standing(&ana) == "ringing");
        let (_e2, second) = caller.open().await.expect("and again");
        tokio::time::sleep(Duration::from_millis(500)).await;
        signal(&second, RING, space, id).await;
        let said = heard(&second, Duration::from_secs(2)).await;
        assert!(said.is_none(), "the same call was answered {said:?}");
        assert_eq!(standing(&ana), "ringing");
        ask(&ana, json!({"cmd": "call-answer"}));
        let (kind, _, got) = heard(&second, Duration::from_secs(5))
            .await
            .expect("an answer");
        assert_eq!((kind, got), (ANSWER, id), "answered on the newer session");
    });
}

/// A contact rings and hangs up as fast as a session lets them. Each ring
/// leaves a task asleep for 45 seconds.
#[test]
#[ignore = "a measurement, of a minute"]
fn rings_pile_up() {
    if !fuse_available() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let ana = person(root.path(), "ana");
    let mut bo = person(root.path(), "bo");
    contacts(&ana, &bo, "Ana");
    let theirs = spaces(&bo);
    let space = spaces(&ana)
        .into_iter()
        .find(|s| theirs.contains(s))
        .unwrap();
    let hostile = Modified::of(&bo, &ana);
    bo.stop();
    let pid = ana.child.as_ref().unwrap().id();

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (_e, s) = hostile.open().await.expect("a contact connects");
        tokio::time::sleep(Duration::from_secs(2)).await;
        let (rss0, cpu0, seq0) = (resident(pid), cpu_ticks(pid), seq_now(&ana));
        let start = Instant::now();
        let secs = 30;
        let mut n = 0u64;
        while start.elapsed() < Duration::from_secs(secs) {
            let id: [u8; 16] = cardinal_crypto::random_bytes();
            signal(&s, RING, space, id).await;
            tokio::time::sleep(Duration::from_micros(1500)).await;
            signal(&s, END, space, id).await;
            n += 2;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
        let (rss1, cpu1, seq1) = (resident(pid), cpu_ticks(pid), seq_now(&ana));
        eprintln!(
            "MEASURE {n} signals sent in {secs} s: seq rose {}, rss grew {} MiB, cpu {} ticks of {}",
            seq1 - seq0,
            (rss1.saturating_sub(rss0)) >> 20,
            cpu1 - cpu0,
            secs * 100,
        );
        tokio::time::sleep(Duration::from_secs(50)).await;
        eprintln!(
            "MEASURE 50 s later rss is {} MiB over the start",
            (resident(pid).saturating_sub(rss0)) >> 20
        );
    });
    assert!(ana.status()["devices"].is_array());
}

/// A contact on a call floods its channel when it ends. If the end falls
/// between two turns of the audio loop the loop never hears of it, goes on
/// after the call, and whatever the contact sends reaches this person's client
/// in the next call, with someone else.
#[test]
fn a_call_that_ended_stops_hearing() {
    if !fuse_available() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let ana = person(root.path(), "ana");
    let mut bo = person(root.path(), "bo");
    contacts(&ana, &bo, "Ana");
    let theirs = spaces(&bo);
    let space = spaces(&ana)
        .into_iter()
        .find(|s| theirs.contains(s))
        .unwrap();
    let hostile = Modified::of(&bo, &ana);
    bo.stop();
    let cy = person(root.path(), "cy");
    contacts(&ana, &cy, "Ana");
    wait("ana sees cy", 30, || {
        let c = ask(&ana, json!({"cmd": "contacts"}));
        c["contacts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["name"] == "cy" && c["connected"] == true)
    });

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let (_e, s) = hostile.open().await.expect("a contact connects");
        tokio::time::sleep(Duration::from_millis(500)).await;
        let attempts = 40u32;
        let mut labels = Vec::new();
        for attempt in 0..attempts {
            // Ana calls Bo, and Bo answers: all it takes, once.
            ask(&ana, json!({"cmd": "call-start", "who": "bo"}));
            // The call before may still have its end to say: on a busy
            // machine that comes after the drain below, and it is not this
            // call's ring.
            let (sp, id) = loop {
                let (kind, sp, id) = heard(&s, Duration::from_secs(5)).await.expect("a ring");
                if kind == RING {
                    break (sp, id);
                }
                assert_eq!(kind, END, "neither a ring nor a late end");
            };
            assert_eq!(sp, space);
            let label = label_of(&space, &id);
            labels.push(label);
            signal(&s, ANSWER, sp, id).await;
            wait("live", 10, || standing(&ana) == "live");

            let flooding = Arc::new(AtomicBool::new(true));
            let sent = Arc::new(AtomicU64::new(0));
            let (s2, f2, n2) = (s.clone(), flooding.clone(), sent.clone());
            let flood = tokio::spawn(async move {
                while f2.load(Ordering::Relaxed) {
                    let _ = s2.send_datagram(label, Priority::RealTime, vec![0u8; 4]);
                    n2.fetch_add(1, Ordering::Relaxed);
                    if n2.load(Ordering::Relaxed) % 16 == 0 {
                        tokio::task::yield_now().await;
                    }
                }
            });
            tokio::time::sleep(Duration::from_millis(30)).await;
            if attempt % 2 == 0 {
                signal(&s, END, sp, id).await;
            } else {
                ask(&ana, json!({"cmd": "call-end"}));
            }
            wait("ended", 10, || standing(&ana).is_null());
            flooding.store(false, Ordering::Relaxed);
            let _ = flood.await;
            // Drain what ana said to us.
            while heard(&s, Duration::from_millis(5)).await.is_some() {}
        }

        // Now Ana is on a call with someone else altogether.
        ask(&ana, json!({"cmd": "call-start", "who": "cy"}));
        wait("cy rings", 10, || standing(&cy) == "ringing");
        ask(&cy, json!({"cmd": "call-answer"}));
        wait("live with cy", 10, || standing(&ana) == "live");
        let mut line = Line::open(&ana);
        tokio::time::sleep(Duration::from_millis(200)).await;
        for (n, label) in labels.iter().enumerate() {
            let mut frame = b"not cy ".to_vec();
            frame.push(n as u8);
            for _ in 0..3 {
                let _ = s.send_datagram(*label, Priority::RealTime, frame.clone());
            }
        }
        let mut injected = Vec::new();
        for _ in 0..40 {
            if let Some(f) = line.heard() {
                if f.starts_with(b"not cy ") {
                    injected.push(f[7]);
                }
            }
        }
        injected.sort_unstable();
        injected.dedup();
        let who = ask(&ana, json!({"cmd": "call"}));
        eprintln!(
            "MEASURE on a call with {}, ana's client heard bo on {} of {attempts} old channels: {injected:?}",
            who["call"]["name"],
            injected.len()
        );
        assert!(injected.is_empty(), "bo was heard in ana's call with cy");
    });
}

/// Negative controls: what ends a live call by itself.
#[test]
fn refusing_ends_a_live_call() {
    if !fuse_available() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let ana = person(root.path(), "ana");
    let mut bo = person(root.path(), "bo");
    contacts(&ana, &bo, "Ana");
    let theirs = spaces(&bo);
    let space = spaces(&ana)
        .into_iter()
        .find(|s| theirs.contains(s))
        .unwrap();
    let hostile = Modified::of(&bo, &ana);
    bo.stop();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (_e, s) = hostile.open().await.expect("a contact connects");
        tokio::time::sleep(Duration::from_millis(500)).await;
        ask(&ana, json!({"cmd": "call-start", "who": "bo"}));
        let (_, sp, id) = heard(&s, Duration::from_secs(5)).await.expect("a ring");
        signal(&s, ANSWER, sp, id).await;
        wait("live", 10, || standing(&ana) == "live");
        assert_eq!(sp, space);
        ask(
            &ana,
            json!({"cmd": "contact", "who": "bo", "setting": "refuse"}),
        );
        let took = wait("the call ends", 10, || standing(&ana).is_null());
        eprintln!("MEASURE refused during a call: ended after {took:?}");
    });
}

/// A contact goes without a word while live.
#[test]
fn a_silent_contact_ends_a_live_call_eventually() {
    if !fuse_available() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let ana = person(root.path(), "ana");
    let mut bo = person(root.path(), "bo");
    contacts(&ana, &bo, "Ana");
    let hostile = Modified::of(&bo, &ana);
    bo.stop();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (_e, s) = hostile.open().await.expect("a contact connects");
        tokio::time::sleep(Duration::from_millis(500)).await;
        ask(&ana, json!({"cmd": "call-start", "who": "bo"}));
        let (_, sp, id) = heard(&s, Duration::from_secs(5)).await.expect("a ring");
        signal(&s, ANSWER, sp, id).await;
        wait("live", 10, || standing(&ana) == "live");
        s.abandon();
        let took = wait("the call ends", 150, || standing(&ana).is_null());
        eprintln!("MEASURE a silent contact: call ended after {took:?}");
    });
}

/// Two hostile contacts: with the real id and label of a call between Ana and
/// Cy, Bo can still neither answer, end nor speak in it.
#[test]
fn a_contact_with_the_call_id_cannot_touch_someone_elses_call() {
    if !fuse_available() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let ana = person(root.path(), "ana");
    let mut bo = person(root.path(), "bo");
    contacts(&ana, &bo, "Ana");
    let theirs = spaces(&bo);
    let bo_space = spaces(&ana)
        .into_iter()
        .find(|s| theirs.contains(s))
        .unwrap();
    let as_bo = Modified::of(&bo, &ana);
    bo.stop();
    let mut cy = person(root.path(), "cy");
    contacts(&ana, &cy, "Ana");
    let theirs = spaces(&cy);
    let cy_space = spaces(&ana)
        .into_iter()
        .find(|s| theirs.contains(s))
        .unwrap();
    let names: Vec<[u8; 32]> = std::fs::read_dir(ana.home.join("others"))
        .unwrap()
        .flatten()
        .map(|e| {
            let n = e.file_name();
            unhex(n.to_str().unwrap().split('.').next().unwrap())
        })
        .collect();
    let cy_identity = *names.iter().find(|n| **n != as_bo.identity).unwrap();
    let as_cy = Modified {
        keys: Keys::load_or_create(&cy.home.join("device.key")).unwrap(),
        identity: cy_identity,
        peer: Keys::load_or_create(&ana.home.join("device.key")).unwrap(),
        peer_identity: other_person(&cy),
        addr: as_bo.addr,
    };
    cy.stop();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (_e1, b) = as_bo.open().await.expect("bo connects");
        let (_e2, c) = as_cy.open().await.expect("cy connects");
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Bo rings naming Cy's space.
        signal(&b, RING, cy_space, [9; 16]).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            standing(&ana).is_null(),
            "a ring named someone else's space"
        );

        ask(&ana, json!({"cmd": "call-start", "who": "cy"}));
        let (kind, sp, id) = heard(&c, Duration::from_secs(5)).await.expect("a ring");
        assert_eq!((kind, sp), (RING, cy_space));
        for space in [bo_space, cy_space] {
            signal(&b, ANSWER, space, id).await;
            signal(&b, END, space, id).await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(standing(&ana), "calling", "bo changed a call to cy");

        signal(&c, ANSWER, sp, id).await;
        wait("live", 10, || standing(&ana) == "live");
        for space in [bo_space, cy_space] {
            signal(&b, END, space, id).await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(standing(&ana), "live", "bo ended a call with cy");

        let mut line = Line::open(&ana);
        tokio::time::sleep(Duration::from_millis(200)).await;
        let label = label_of(&cy_space, &id);
        let mut from_bo = 0;
        let mut from_cy = 0;
        for _ in 0..10 {
            let _ = b.send_datagram(label, Priority::RealTime, b"bo".to_vec());
            let _ = c.send_datagram(label, Priority::RealTime, b"cy".to_vec());
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        for _ in 0..40 {
            match line.heard().as_deref() {
                Some(b"bo") => from_bo += 1,
                Some(b"cy") => from_cy += 1,
                _ => {}
            }
        }
        eprintln!("MEASURE on cy's label: {from_cy} frames from cy, {from_bo} from bo");
        assert!(from_cy > 0);
        assert_eq!(from_bo, 0, "bo was heard on cy's channel");
        ask(&ana, json!({"cmd": "call-end"}));
    });
}

/// A device of the person being called, not the one on the call, has no say in
/// it: it could only end the call for one side.
#[test]
fn a_device_not_on_a_call_cannot_end_it() {
    if !fuse_available() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let a = person(root.path(), "ana");
    let b = person(root.path(), "bo");
    contacts(&a, &b, "Ana");
    let mut b2 = Dev::new(root.path(), "bophone", free_port());
    b2.start();
    pair(&b, &b2);
    wait("the phone knows ana", 60, || {
        b2.cli(&["contacts"]).contains("Ana")
    });
    let hostile = Modified::of(&b2, &a);
    b2.stop();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (_e, s) = hostile.open().await.expect("the phone connects");
        tokio::time::sleep(Duration::from_millis(500)).await;
        ask(&a, json!({"cmd": "call-start", "who": "bo"}));
        let (kind, sp, id) = heard(&s, Duration::from_secs(5)).await.expect("a ring");
        assert_eq!(kind, RING);
        wait("the laptop rings", 10, || standing(&b) == "ringing");
        ask(&b, json!({"cmd": "call-answer"}));
        wait("live", 10, || standing(&a) == "live");
        // Ana told the phone to stop; it says no anyway, a moment too late.
        signal(&s, END, sp, id).await;
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(standing(&a), "live");
        assert_eq!(standing(&b), "live");
    });
}

/// Someone with only a delivery token cannot ring.
#[test]
fn a_token_cannot_ring() {
    if !fuse_available() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let ana = person(root.path(), "ana");
    let at = format!("127.0.0.1:{}", ana.port);
    ana.cli(&["host", "--address", &at]);
    let bo = person(root.path(), "bo");
    let bo_at = format!("127.0.0.1:{}", bo.port);
    bo.cli(&["host", "--address", &bo_at]);
    let args = ["invite", "--address", &at, "--name", "Ana", "--hosts-only"];
    let code = ana.cli(&args).trim().to_owned();
    bo.cli(&["accept", &code, "--hosts-only"]);
    wait("ana lists bo", 20, || ana.cli(&["contacts"]).contains("bo"));
    let state = std::fs::read(ana.home.join("mailbox/state.json")).unwrap();
    let state: Json = serde_json::from_slice(&state).unwrap();
    let token: [u8; 16] = unhex(state["active"][0].as_str().unwrap());
    let theirs = spaces(&bo);
    let space = spaces(&ana)
        .into_iter()
        .find(|s| theirs.contains(s))
        .unwrap();
    let sheet = ana.cli(&["recovery", "sheet"]);
    let key = sheet.lines().find(|l| l.contains("Key:")).unwrap();
    let key = key.split_whitespace().last().unwrap();
    let host = cardinald::host::read_sheet_key(key).unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let key = Arc::new(cardinal_crypto::HybridKeyPair::generate());
        let mut config = EndpointConfig::new(key, MemoryDirectory::new());
        config.connect_timeout = Duration::from_secs(3);
        let bind = Bind {
            udp: Some("127.0.0.1:0".parse().unwrap()),
            tcp: None,
        };
        let endpoint = Endpoint::bind(config, bind).await.unwrap();
        let secret = cardinal_crypto::derive(cardinal_crypto::Purpose::Token, &token);
        let addr: SocketAddr = at.parse().unwrap();
        let target = Target::invitation(addr, CarrierKind::Udp, host, &secret[..]);
        let s = endpoint.connect(target).await.expect("a good token opens");
        signal(&s, RING, space, [7; 16]).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(standing(&ana).is_null(), "a token rang");
    });
}

/// A contact can ring only so often. Past five rings in two minutes, a ring
/// finds this person busy, hears `end` at once, and nothing rings here.
#[test]
fn a_contact_rings_only_so_often() {
    if !fuse_available() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let ana = person(root.path(), "ana");
    let mut bo = person(root.path(), "bo");
    contacts(&ana, &bo, "Ana");
    let theirs = spaces(&bo);
    let space = spaces(&ana)
        .into_iter()
        .find(|s| theirs.contains(s))
        .unwrap();
    let hostile = Modified::of(&bo, &ana);
    bo.stop();

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (_e, s) = hostile.open().await.expect("a contact connects");
        for n in 0..5 {
            let id: [u8; 16] = cardinal_crypto::random_bytes();
            signal(&s, RING, space, id).await;
            wait(&format!("ring {n} rings"), 5, || {
                standing(&ana) == "ringing"
            });
            signal(&s, END, space, id).await;
            wait(&format!("ring {n} stops"), 5, || standing(&ana).is_null());
        }
        let id: [u8; 16] = cardinal_crypto::random_bytes();
        signal(&s, RING, space, id).await;
        let told = heard(&s, Duration::from_secs(3)).await;
        assert_eq!(
            told,
            Some((END, space, id)),
            "the sixth ring is not told it is busy"
        );
        assert!(standing(&ana).is_null(), "the sixth ring rang");
    });
}
