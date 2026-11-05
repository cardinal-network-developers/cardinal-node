//! Group calls with no centre (`profiles.md#calls`), between real daemons:
//! a device that helps others carries a call its own person is not on, a
//! group where everyone knows everyone settles into a tree, someone who left
//! comes back to the same call, and a link that went quiet while a device's
//! network was gone is made again when it comes back.

mod common;

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::*;
use serde_json::{json, Value};
use tokio::net::UdpSocket;

fn reply(d: &Dev, req: &Value) -> Value {
    let mut s = UnixStream::connect(d.home.join("control.sock")).unwrap();
    writeln!(s, "{req}").unwrap();
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

fn ask(d: &Dev, req: Value) -> Value {
    let r = reply(d, &req);
    assert_eq!(r["ok"], true, "{req} got {r}");
    r
}

fn start(mut d: Dev) -> Dev {
    d.start_with(&["--no-mount"]);
    d.cli(&["init", "--yes", "--name", d.name]);
    d
}

fn person(root: &std::path::Path, name: &'static str) -> Dev {
    start(Dev::new(root, name, free_port()))
}

/// What someone is called by those who know them.
fn called(d: &Dev) -> String {
    let mut c = d.name.chars();
    c.next()
        .map(|f| f.to_uppercase().chain(c).collect())
        .unwrap_or_default()
}

/// `a` invites `b`; each calls the other by name.
fn meet(a: &Dev, b: &Dev) {
    let at = format!("127.0.0.1:{}", a.port);
    let code = a.cli(&["invite", "--address", &at, "--name", &called(a)]);
    b.cli(&["accept", code.trim(), "--name", &called(a)]);
    wait("they meet", 30, || a.cli(&["contacts"]).contains(b.name));
    ask(
        a,
        json!({"cmd": "contact", "who": b.name, "name": called(b)}),
    );
}

fn plugged_in(d: &Dev, yes: bool) {
    ask(
        d,
        json!({"cmd": "conditions", "plugged_in": yes, "metered": false}),
    );
}

/// A group `admin` makes with the others, who join it.
fn group(admin: &Dev, others: &[&Dev]) -> String {
    let people: Vec<String> = others.iter().map(|d| called(d)).collect();
    let made = ask(
        admin,
        json!({"cmd": "group-create", "name": "Family", "people": people}),
    );
    let g = made["group"].as_str().unwrap().to_owned();
    for d in others {
        wait("offered", 30, || {
            let v = ask(d, json!({"cmd": "groups"}));
            !v["offers"].as_array().unwrap().is_empty()
        });
        ask(d, json!({"cmd": "group-join", "group": g}));
    }
    let all = others.len() + 1;
    wait("everyone sees everyone", 30, || {
        others.iter().chain([&admin]).all(|d| {
            let m = reply(d, &json!({"cmd": "group-members", "group": g}));
            m["members"].as_array().is_some_and(|m| m.len() == all)
        })
    });
    g
}

fn call(d: &Dev) -> Value {
    ask(d, json!({"cmd": "call"}))["call"].clone()
}

fn standing(d: &Dev) -> String {
    call(d)["state"].as_str().unwrap_or_default().to_owned()
}

fn linked(d: &Dev) -> u64 {
    call(d)["linked"].as_u64().unwrap_or(0)
}

fn carrying(d: &Dev) -> u64 {
    d.status()["carrying_calls"].as_u64().unwrap_or(0)
}

/// A call's sound, as a client has it.
struct Line {
    w: UnixStream,
    r: BufReader<UnixStream>,
    tag: u8,
    n: u32,
}

impl Line {
    fn open(d: &Dev, tag: u8) -> Line {
        let mut w = UnixStream::connect(d.home.join("control.sock")).unwrap();
        writeln!(w, "{}", json!({"cmd": "call-media"})).unwrap();
        w.set_read_timeout(Some(Duration::from_millis(5))).unwrap();
        let r = BufReader::new(w.try_clone().unwrap());
        Line { w, r, tag, n: 0 }
    }

    fn say(&mut self) {
        let mut frame = self.n.to_be_bytes().to_vec();
        frame.extend_from_slice(&[self.tag; 20]);
        self.n += 1;
        writeln!(self.w, "{}", json!({"audio": hex::encode(frame)})).unwrap();
    }

    /// The tags heard so far.
    fn heard(&mut self, into: &mut HashSet<u8>) {
        loop {
            let mut line = String::new();
            match self.r.read_line(&mut line) {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
            let Ok(v) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            if let Some(audio) = v["audio"].as_str() {
                let bytes = hex::decode(audio).unwrap();
                into.insert(bytes[4]);
            }
        }
    }
}

/// Those in `talking` speak for `frames` frames of 20 ms; what each line
/// heard.
fn talk(lines: &mut [Line], talking: &[bool], frames: u32) -> Vec<HashSet<u8>> {
    let mut heard = vec![HashSet::new(); lines.len()];
    for _ in 0..frames {
        for (l, t) in lines.iter_mut().zip(talking) {
            if *t {
                l.say();
            }
        }
        std::thread::sleep(Duration::from_millis(20));
        for (l, h) in lines.iter_mut().zip(heard.iter_mut()) {
            l.heard(h);
        }
    }
    for _ in 0..25 {
        std::thread::sleep(Duration::from_millis(10));
        for (l, h) in lines.iter_mut().zip(heard.iter_mut()) {
            l.heard(h);
        }
    }
    heard
}

/// Carol made the group, and Ana and Ben do not know each other. Carol does
/// not take the call, but her device is plugged in, so it carries it for
/// them, and goes on after she says no. Unplugged, it stops.
#[test]
fn a_device_that_helps_carries_a_call_its_person_is_not_on() {
    let root = tempfile::tempdir().unwrap();
    let carol = person(root.path(), "carol");
    let ana = person(root.path(), "ana");
    let ben = person(root.path(), "ben");
    plugged_in(&carol, true);
    plugged_in(&ana, false);
    plugged_in(&ben, false);
    meet(&carol, &ana);
    meet(&carol, &ben);
    let g = group(&carol, &[&ana, &ben]);

    ask(&ana, json!({"cmd": "call-start", "group": g}));
    wait("ben is rung, through carol's device", 20, || {
        standing(&ben) == "ringing"
    });
    wait("carol's device carries it", 20, || carrying(&carol) == 1);
    ask(&ben, json!({"cmd": "call-answer"}));
    wait("ana hears that ben took it", 20, || {
        standing(&ana) == "live"
    });
    assert_eq!(standing(&carol), "ringing", "carol herself is not on it");

    let mut lines = [Line::open(&ana, 1), Line::open(&ben, 2)];
    let heard = talk(&mut lines, &[true, true], 60);
    assert!(heard[0].contains(&2), "ana heard {:?}", heard[0]);
    assert!(heard[1].contains(&1), "ben heard {:?}", heard[1]);
    wait("both count two", 15, || {
        call(&ana)["people"] == 2 && call(&ben)["people"] == 2
    });

    // Carol says no: that is hers to say, and her device carries on.
    ask(&carol, json!({"cmd": "call-end"}));
    let heard = talk(&mut lines, &[true, true], 40);
    assert!(heard[0].contains(&2) && heard[1].contains(&1), "{heard:?}");
    assert_eq!(carrying(&carol), 1);

    // On battery it helps no more.
    plugged_in(&carol, false);
    wait("carol's device lets go", 10, || {
        linked(&ana) == 0 && linked(&ben) == 0
    });
    assert_eq!(carrying(&carol), 0);
}

/// Four who all know each other: each frame at first comes to a device on
/// every link, and once each takes a voice from two links only, every frame
/// comes about twice.
#[test]
fn a_group_where_everyone_knows_everyone_settles_into_a_tree() {
    let root = tempfile::tempdir().unwrap();
    let all: Vec<Dev> = ["ana", "bo", "cy", "dee"]
        .into_iter()
        .map(|n| person(root.path(), n))
        .collect();
    for d in &all {
        plugged_in(d, false);
    }
    for i in 0..all.len() {
        for j in i + 1..all.len() {
            meet(&all[i], &all[j]);
        }
    }
    let (ana, rest) = all.split_first().unwrap();
    let others: Vec<&Dev> = rest.iter().collect();
    let g = group(ana, &others);
    ask(ana, json!({"cmd": "call-start", "group": g}));
    for d in rest {
        wait("rung", 20, || standing(d) == "ringing");
        ask(d, json!({"cmd": "call-answer"}));
    }
    wait("each links with the three others", 30, || {
        all.iter().all(|d| linked(d) == 3)
    });

    let dee = &all[3];
    let mut lines = [Line::open(ana, 1), Line::open(dee, 4)];
    let start = call(dee)["frames"].clone();
    talk(&mut lines, &[true, false], 50);
    let before = call(dee)["frames"].clone();
    let heard = talk(&mut lines, &[true, false], 150);
    let after = call(dee)["frames"].clone();
    assert!(heard[1].contains(&1), "dee heard {:?}", heard[1]);
    let n = |v: &Value, k: &str| v[k].as_u64().unwrap() as f64;
    let new = n(&after, "new") - n(&before, "new");
    let extra = n(&after, "in") - n(&before, "in") - new;
    let first_new = n(&before, "new") - n(&start, "new");
    let first_extra = n(&before, "in") - n(&start, "in") - first_new;
    eprintln!("at first {first_extra} extra for {first_new} new; then {extra} for {new}");
    assert!(new >= 140.0, "{before} {after}");
    // On every link it would be two more of each; on two, one.
    assert!(
        (0.7..1.3).contains(&(extra / new)),
        "{extra} extra for {new} new"
    );
}

/// Bo leaves; pressing Call everyone again takes him back into the call
/// Ana and Cy are still on, not a new one ringing them.
#[test]
fn a_person_who_left_a_group_call_can_join_it_again() {
    let root = tempfile::tempdir().unwrap();
    let ana = person(root.path(), "ana");
    let bo = person(root.path(), "bo");
    let cy = person(root.path(), "cy");
    for d in [&ana, &bo, &cy] {
        plugged_in(d, false);
    }
    meet(&ana, &bo);
    meet(&ana, &cy);
    let g = group(&ana, &[&bo, &cy]);
    ask(&ana, json!({"cmd": "call-start", "group": g}));
    for d in [&bo, &cy] {
        wait("rung", 20, || standing(d) == "ringing");
        ask(d, json!({"cmd": "call-answer"}));
    }
    wait("ana links both", 20, || linked(&ana) == 2);

    ask(&bo, json!({"cmd": "call-end"}));
    wait("ana lets bo go", 10, || linked(&ana) == 1);
    assert_eq!(call(&bo), Value::Null);
    ask(&bo, json!({"cmd": "call-start", "group": g}));
    wait("bo is back on the same call", 15, || {
        standing(&bo) == "live" && linked(&ana) == 2
    });
    assert_eq!(standing(&ana), "live");
    assert_eq!(standing(&cy), "live");

    let mut lines = [Line::open(&bo, 2), Line::open(&cy, 3)];
    let heard = talk(&mut lines, &[true, true], 60);
    assert!(heard[0].contains(&3) && heard[1].contains(&2), "{heard:?}");
    wait("bo counts three", 15, || call(&bo)["people"] == 3);
}

/// Everything a device sends over UDP goes through here, and nothing comes
/// back but through here: switched off, its network is gone.
struct Gateway {
    addr: SocketAddr,
    down: Arc<AtomicBool>,
    _runtime: tokio::runtime::Runtime,
}

/// Before what a device sends through the gateway: where to, as four bytes
/// of address and two of port, little-endian.
const HEADER: usize = 6;

impl Gateway {
    fn new() -> Gateway {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let inner = Arc::new(runtime.block_on(UdpSocket::bind("127.0.0.1:0")).unwrap());
        let public = Arc::new(runtime.block_on(UdpSocket::bind("127.0.0.1:0")).unwrap());
        let addr = inner.local_addr().unwrap();
        let down = Arc::new(AtomicBool::new(false));
        let device: Arc<Mutex<Option<SocketAddr>>> = Default::default();
        let (i, p, dn, dv) = (inner.clone(), public.clone(), down.clone(), device.clone());
        runtime.spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let (n, from) = i.recv_from(&mut buf).await.unwrap();
                *dv.lock().unwrap() = Some(from);
                if n < HEADER || dn.load(Ordering::SeqCst) {
                    continue;
                }
                let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                let to = SocketAddr::from((ip, u16::from_le_bytes([buf[4], buf[5]])));
                let _ = p.send_to(&buf[HEADER..n], to).await;
            }
        });
        let (i, p, dn) = (inner, public, down.clone());
        runtime.spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let (n, from) = p.recv_from(&mut buf[HEADER..]).await.unwrap();
                if dn.load(Ordering::SeqCst) {
                    continue;
                }
                if let SocketAddr::V4(a) = from {
                    buf[..4].copy_from_slice(&a.ip().octets());
                    buf[4..6].copy_from_slice(&a.port().to_le_bytes());
                }
                let to = *device.lock().unwrap();
                if let Some(to) = to {
                    let _ = i.send_to(&buf[..HEADER + n], to).await;
                }
            }
        });
        Gateway {
            addr,
            down,
            _runtime: runtime,
        }
    }

    fn set_down(&self, down: bool) {
        self.down.store(down, Ordering::SeqCst);
    }
}

/// Ana, Bo and Cy, Bo behind a gateway that can be switched off, on a call
/// where Bo hears Cy only through Ana.
fn bo_behind(root: &std::path::Path, gw: &Gateway) -> (Dev, Dev, Dev, Vec<Line>) {
    let ana = person(root, "ana");
    let mut bo = Dev::new(root, "bo", free_port());
    bo.env
        .push(("CARDINAL_TEST_UDP_GATEWAY".into(), gw.addr.to_string()));
    let bo = start(bo);
    let cy = person(root, "cy");
    for d in [&ana, &bo, &cy] {
        plugged_in(d, false);
    }
    meet(&ana, &bo);
    meet(&ana, &cy);
    let g = group(&ana, &[&bo, &cy]);
    ask(&ana, json!({"cmd": "call-start", "group": g}));
    for d in [&bo, &cy] {
        wait("rung", 20, || standing(d) == "ringing");
        ask(d, json!({"cmd": "call-answer"}));
    }
    wait("ana links both", 20, || linked(&ana) == 2);
    let mut lines = vec![Line::open(&bo, 2), Line::open(&cy, 3)];
    let heard = talk(&mut lines, &[true, true], 50);
    assert!(heard[0].contains(&3) && heard[1].contains(&2), "{heard:?}");
    (ana, bo, cy, lines)
}

/// Bo's network goes for long enough that the link is taken for gone, not
/// so long that the session ends: when it comes back, the link is made
/// again on the same session.
#[test]
fn a_link_that_went_quiet_is_made_again_when_it_comes_back() {
    let root = tempfile::tempdir().unwrap();
    let gw = Gateway::new();
    let (ana, bo, _cy, mut lines) = bo_behind(root.path(), &gw);

    gw.set_down(true);
    wait("ana lets bo's link go", 20, || linked(&ana) == 1);
    gw.set_down(false);
    wait("bo is linked again", 20, || {
        linked(&ana) == 2 && linked(&bo) == 1
    });
    let heard = talk(&mut lines, &[true, true], 50);
    assert!(heard[0].contains(&3) && heard[1].contains(&2), "{heard:?}");
}

/// Bo's network goes for long enough that his sessions end. Back, his
/// device finds Ana again, as she is on a call with him, and the new
/// session is linked.
#[test]
fn a_device_back_after_its_sessions_ended_is_linked_again() {
    let root = tempfile::tempdir().unwrap();
    let gw = Gateway::new();
    let (ana, bo, _cy, mut lines) = bo_behind(root.path(), &gw);

    gw.set_down(true);
    wait("ana lets bo's link go", 20, || linked(&ana) == 1);
    // Past the link's keepalive and its wait for an answer: the sessions end.
    std::thread::sleep(Duration::from_secs(35));
    gw.set_down(false);
    // As a phone's app says when its network changes.
    ask(&bo, json!({"cmd": "network-changed"}));
    wait("bo is linked again", 60, || linked(&ana) == 2);
    let heard = talk(&mut lines, &[true, true], 50);
    assert!(heard[0].contains(&3) && heard[1].contains(&2), "{heard:?}");
}
