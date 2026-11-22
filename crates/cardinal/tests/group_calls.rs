//! Group calls with no centre (`profiles.md#calls`), between real daemons:
//! a device that helps others carries a call its own person is not on, a
//! group where everyone knows everyone settles into a tree, someone who left
//! comes back to the same call, and a link that went quiet while a device's
//! network was gone is made again when it comes back. Pictures go only
//! where they were asked for, in the size asked or smaller
//! (`basics/video.md#groups`).

mod common;

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::*;
use serde_json::{json, Value};
use tokio::net::UdpSocket;

fn reply(d: &Dev, req: &Value) -> Value {
    common::reply(d, req)
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
    m: Media,
    tag: u8,
    n: u32,
}

impl Line {
    fn open(d: &Dev, tag: u8) -> Line {
        Line {
            m: Media::open(d, Duration::from_millis(5)),
            tag,
            n: 0,
        }
    }

    fn say(&mut self) {
        let mut frame = self.n.to_be_bytes().to_vec();
        frame.extend_from_slice(&[self.tag; 20]);
        self.n += 1;
        self.m.send(&json!({"audio": hex::encode(frame)}));
    }

    /// The tags heard so far, and how often.
    fn heard(&mut self, into: &mut HashMap<u8, u32>) {
        loop {
            let Some(v) = self.m.next() else {
                return;
            };
            if let Some(audio) = v["audio"].as_str() {
                let bytes = hex::decode(audio).unwrap();
                *into.entry(bytes[4]).or_default() += 1;
            }
        }
    }
}

/// Those in `talking` speak for `frames` frames of 20 ms; what each line
/// heard of each.
fn talk(lines: &mut [Line], talking: &[bool], frames: u32) -> Vec<HashMap<u8, u32>> {
    let mut heard = vec![HashMap::new(); lines.len()];
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

/// Whether most of what `tag` said in `frames` frames was heard: a call that
/// works loses little, and one frame getting through shows nothing.
fn heard_most(h: &HashMap<u8, u32>, tag: u8, frames: u32) -> bool {
    h.get(&tag).copied().unwrap_or(0) * 10 >= frames * 9
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
    assert!(heard_most(&heard[0], 2, 60), "ana heard {:?}", heard[0]);
    assert!(heard_most(&heard[1], 1, 60), "ben heard {:?}", heard[1]);
    wait("both count two", 15, || {
        call(&ana)["people"] == 2 && call(&ben)["people"] == 2
    });

    // Carol says no: that is hers to say, and her device carries on.
    ask(&carol, json!({"cmd": "call-end"}));
    let heard = talk(&mut lines, &[true, true], 40);
    assert!(
        heard_most(&heard[0], 2, 40) && heard_most(&heard[1], 1, 40),
        "{heard:?}"
    );
    assert_eq!(carrying(&carol), 1);

    // On battery it helps no more.
    plugged_in(&carol, false);
    wait("carol's device lets go", 10, || {
        linked(&ana) == 0 && linked(&ben) == 0
    });
    assert_eq!(carrying(&carol), 0);
}

/// A person with two devices rung for a group call: answered on one, it is
/// not missed on the other.
#[test]
fn a_group_call_answered_on_another_device_is_not_missed() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let ana = person(root.path(), "ana");
    let ben = person(root.path(), "ben");
    plugged_in(&ana, false);
    plugged_in(&ben, false);
    meet(&ana, &ben);
    let g = group(&ana, &[&ben]);
    let phone = start_paired(root.path(), &ben);
    plugged_in(&phone, false);
    wait("ben's phone has the group", 60, || {
        let v = reply(&phone, &json!({"cmd": "groups"}));
        v["groups"].as_array().is_some_and(|g| !g.is_empty())
    });
    wait("ben's phone reaches ana", 60, || {
        reply(&phone, &json!({"cmd": "contacts"}))["contacts"][0]["connected"] == true
    });

    ask(&ana, json!({"cmd": "call-start", "group": g}));
    wait("both of ben's devices ring", 20, || {
        standing(&ben) == "ringing" && standing(&phone) == "ringing"
    });
    let id = call(&ben)["id"].clone();
    ask(&ben, json!({"cmd": "call-answer"}));
    wait("the phone stops ringing", 20, || {
        standing(&phone).is_empty()
    });
    let e = ask(&phone, json!({"cmd": "call"}))["ended"].clone();
    assert_eq!(e["id"], id, "{e}");
    assert_eq!(e["how"], "answered_elsewhere", "{e}");
    assert_eq!(e["group"], g, "{e}");
}

/// A device of `of`'s, paired to it. (Pairing waits for its files to be
/// mounted.)
fn start_paired(root: &std::path::Path, of: &Dev) -> Dev {
    let mut d = Dev::new(root, "phone", free_port());
    d.start();
    pair(of, &d);
    d
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
    assert!(heard_most(&heard[1], 1, 150), "dee heard {:?}", heard[1]);
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
    {
        let mut lines = [Line::open(&bo, 2), Line::open(&cy, 3)];
        let heard = talk(&mut lines, &[true, true], 60);
        assert!(heard_most(&heard[1], 2, 60), "{heard:?}");
    }

    ask(&bo, json!({"cmd": "call-end"}));
    wait("ana lets bo go", 10, || linked(&ana) == 1);
    assert_eq!(call(&bo), Value::Null);
    ask(&bo, json!({"cmd": "call-start", "group": g}));
    wait("bo is back on the same call", 15, || {
        standing(&bo) == "live" && linked(&ana) == 2
    });
    assert_eq!(standing(&ana), "live");
    assert_eq!(standing(&cy), "live");

    // Back, Bo is heard at once, not taken for the frames he sent before.
    let mut lines = [Line::open(&bo, 2), Line::open(&cy, 3)];
    let heard = talk(&mut lines, &[true, true], 60);
    assert!(
        heard_most(&heard[0], 3, 60) && heard_most(&heard[1], 2, 60),
        "{heard:?}"
    );
    wait("bo counts three", 15, || call(&bo)["people"] == 3);
}

/// Everything a device sends over UDP goes through here, and nothing comes
/// back but through here: switched off, its network is gone.
struct Gateway {
    addr: SocketAddr,
    /// 0 up, 1 down both ways, 2 down only towards the device.
    down: Arc<AtomicU8>,
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
        let down = Arc::new(AtomicU8::new(0));
        let device: Arc<Mutex<Option<SocketAddr>>> = Default::default();
        let (i, p, dn, dv) = (inner.clone(), public.clone(), down.clone(), device.clone());
        runtime.spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let (n, from) = i.recv_from(&mut buf).await.unwrap();
                *dv.lock().unwrap() = Some(from);
                if n < HEADER || dn.load(Ordering::SeqCst) == 1 {
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
                if dn.load(Ordering::SeqCst) != 0 {
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
        self.down.store(u8::from(down), Ordering::SeqCst);
    }

    /// What the device sends still goes; nothing comes back.
    fn set_deaf(&self) {
        self.down.store(2, Ordering::SeqCst);
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
    assert!(
        heard_most(&heard[0], 3, 50) && heard_most(&heard[1], 2, 50),
        "{heard:?}"
    );
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
    assert!(
        heard_most(&heard[0], 3, 50) && heard_most(&heard[1], 2, 50),
        "{heard:?}"
    );
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
    assert!(
        heard_most(&heard[0], 3, 50) && heard_most(&heard[1], 2, 50),
        "{heard:?}"
    );
}

/// Only Bo's way in goes. With nothing acknowledged his session soon sends
/// nothing either, so both ends of the link fall silent and are let go, as
/// when the network goes both ways; when it comes back they link again.
#[test]
fn a_link_cut_one_way_is_made_again() {
    let root = tempfile::tempdir().unwrap();
    let gw = Gateway::new();
    let (ana, bo, _cy, mut lines) = bo_behind(root.path(), &gw);

    gw.set_deaf();
    wait("bo lets his link to ana go", 20, || linked(&bo) == 0);
    gw.set_down(false);
    wait("bo is linked again", 20, || {
        linked(&bo) == 1 && linked(&ana) == 2
    });
    let heard = talk(&mut lines, &[true, true], 50);
    assert!(
        heard_most(&heard[0], 3, 50) && heard_most(&heard[1], 2, 50),
        "{heard:?}"
    );
}

/// In a group each sender needs every receiver's viewport
/// (`basics/video.md`): Ben's reaches Ana through Carol's device, which only
/// carries the call, with the voice it is, as his sound has it, and is said
/// again every five seconds.
#[test]
fn a_viewport_is_passed_on_to_everyone_on_a_group_call() {
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
    wait("ben is rung", 20, || standing(&ben) == "ringing");
    ask(&ben, json!({"cmd": "call-answer"}));
    wait("live", 20, || standing(&ana) == "live");

    let mut lines = [Line::open(&ana, 1), Line::open(&ben, 2)];
    lines[1].m.send(&json!({"width": 3, "height": 4}));
    let (mut views, mut voice) = (Vec::new(), None);
    let until = std::time::Instant::now() + Duration::from_secs(8);
    while std::time::Instant::now() < until {
        lines[1].say();
        if let Some(v) = lines[0].m.next() {
            if v.get("width").is_some() {
                views.push(v);
            } else if let Some(from) = v["from"].as_str() {
                voice = Some(from.to_owned());
            }
        }
        if let Some(v) = lines[1].m.next() {
            assert!(v.get("width").is_none(), "ben is not told his own: {v}");
        }
    }
    let voice = voice.expect("ana heard ben");
    assert!(views.len() >= 2, "said now and again: {views:?}");
    for v in &views {
        assert_eq!(*v, json!({"width": 3, "height": 4, "from": voice}));
    }
}

/// The draft name of video, as a window gives it (`basics/video.md`).
fn video_format() -> String {
    hex::encode(blake3::hash(b"cardinal draft format: video vp8 1").as_bytes())
}

/// What a window was given on a group video call.
#[derive(Default)]
struct Given {
    /// The voice of each tag it heard.
    voices: HashMap<u8, String>,
    /// The numbers of the pictures it was given, by tag and size.
    pictures: HashMap<(u8, u64), Vec<u32>>,
    /// The sizes it was told are asked of it: small, large.
    asked: Vec<(bool, bool)>,
    /// The sizes of its own it was asked for key pictures of.
    keys: Vec<u64>,
}

impl Given {
    fn count(&self, tag: u8, size: u64) -> usize {
        self.pictures.get(&(tag, size)).map_or(0, Vec::len)
    }

    fn clear_pictures(&mut self) {
        self.pictures.clear();
    }
}

/// A window on a group call with video: its sound, which tells the others
/// its voice, synthetic pictures of two sizes, and the levels it asks for.
struct Window {
    line: Line,
}

impl Window {
    fn open(d: &Dev, tag: u8) -> Window {
        Window {
            line: Line::open(d, tag),
        }
    }

    /// A picture: an RTP-like header, then its tag, size and number, and
    /// something of the size of a packet of video.
    fn show(&mut self, size: u8, n: u32) {
        let mut b = vec![0x80, 96, self.line.tag, size];
        b.extend_from_slice(&n.to_be_bytes());
        b.extend_from_slice(&[0x55; 600]);
        self.line.m.send(&json!({
            "frame": hex::encode(b),
            "format": video_format(),
            "size": size,
        }));
    }

    fn level(&mut self, from: &str, level: u8) {
        self.line.m.send(&json!({"level": level, "from": from}));
    }

    fn key(&mut self, from: &str, size: u8) {
        self.line.m.send(&json!({"from": from, "size": size}));
    }

    /// Takes everything that came so far.
    fn take(&mut self, g: &mut Given) {
        while let Some(v) = self.line.m.next() {
            if let Some(audio) = v["audio"].as_str() {
                let b = hex::decode(audio).unwrap();
                if let Some(from) = v["from"].as_str() {
                    g.voices.insert(b[4], from.to_owned());
                }
            } else if let Some(frame) = v["frame"].as_str() {
                let b = hex::decode(frame).unwrap();
                let size = v["size"].as_u64().expect("a picture in a group has a size");
                assert_eq!(u64::from(b[3]), size, "given as the size it was sent");
                assert!(v["from"].is_string(), "{v}");
                let n = u32::from_be_bytes(b[4..8].try_into().unwrap());
                g.pictures.entry((b[2], size)).or_default().push(n);
            } else if v.get("small").is_some() {
                g.asked.push((v["small"] == true, v["large"] == true));
            } else if v.get("size").is_some() {
                g.keys.push(v["size"].as_u64().unwrap());
            }
        }
    }
}

fn take_all(w: &mut [Window], given: &mut [Given]) {
    for (w, g) in w.iter_mut().zip(given.iter_mut()) {
        w.take(g);
    }
}

/// Each window speaks for a moment, so that each learns the others' voices.
fn learn_voices(w: &mut [Window], given: &mut [Given]) {
    let all = w.len();
    let until = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < until {
        for x in w.iter_mut() {
            x.line.say();
        }
        std::thread::sleep(Duration::from_millis(20));
        take_all(w, given);
        if given.iter().all(|g| g.voices.len() == all - 1) {
            return;
        }
    }
    panic!("not every window heard every other");
}

/// Senders `send` show large pictures for a moment, so that large is had
/// wherever it is asked for before small comes; then both sizes, numbered
/// `from..from + n`, or with `small_only` small alone. What each window was
/// given of the second part.
fn show_pictures(
    w: &mut [Window],
    given: &mut [Given],
    send: &[usize],
    from: u32,
    n: u32,
    small_only: bool,
) {
    if !small_only {
        for i in 0..5 {
            for s in send {
                w[*s].show(2, from + 1000 + i);
            }
            std::thread::sleep(Duration::from_millis(40));
        }
    }
    take_all(w, given);
    for g in given.iter_mut() {
        g.clear_pictures();
    }
    for i in from..from + n {
        for s in send {
            if !small_only {
                w[*s].show(2, i);
            }
            w[*s].show(1, i);
        }
        std::thread::sleep(Duration::from_millis(33));
        take_all(w, given);
    }
    for _ in 0..30 {
        std::thread::sleep(Duration::from_millis(20));
        take_all(w, given);
    }
}

/// No picture is given twice.
fn given_once(given: &[Given]) {
    for g in given {
        for (k, list) in &g.pictures {
            let mut l = list.clone();
            l.sort();
            l.dedup();
            assert_eq!(l.len(), list.len(), "{k:?} given twice: {list:?}");
        }
    }
}

/// Ana, Ben, Cy and Dee know only Carol, whose device carries the call.
/// Ana asks Ben for large, Cy asks him for small, and Dee for nothing:
/// Carol's device asks Ben for both and gives each what they asked, never
/// more, and Dee none of his. When Ben sends small alone, Ana gets that.
/// A key picture is asked of Ben for those who asked for his pictures.
#[test]
fn a_relay_gives_each_the_pictures_they_asked_for() {
    let root = tempfile::tempdir().unwrap();
    let carol = person(root.path(), "carol");
    let ana = person(root.path(), "ana");
    let ben = person(root.path(), "ben");
    let cy = person(root.path(), "cy");
    let dee = person(root.path(), "dee");
    plugged_in(&carol, true);
    for d in [&ana, &ben, &cy, &dee] {
        plugged_in(d, false);
        meet(&carol, d);
    }
    let g = group(&carol, &[&ana, &ben, &cy, &dee]);
    ask(&ana, json!({"cmd": "call-start", "group": g}));
    for d in [&ben, &cy, &dee] {
        wait("rung", 20, || standing(d) == "ringing");
        ask(d, json!({"cmd": "call-answer"}));
    }
    wait("carol's device carries it for all four", 30, || {
        carrying(&carol) == 1 && [&ana, &ben, &cy, &dee].iter().all(|d| linked(d) == 1)
    });

    let mut w = vec![
        Window::open(&ana, 1),
        Window::open(&ben, 2),
        Window::open(&cy, 3),
        Window::open(&dee, 4),
    ];
    let mut given: Vec<Given> = (0..4).map(|_| Given::default()).collect();
    learn_voices(&mut w, &mut given);
    let ben_v = given[0].voices[&2].clone();
    let ana_v = given[3].voices[&1].clone();
    w[0].level(&ben_v, 2);
    w[2].level(&given[2].voices[&2].clone(), 1);
    w[3].level(&given[3].voices[&2].clone(), 0);
    w[3].level(&ana_v, 2);
    wait("ben is asked for both sizes, ana for large", 10, || {
        take_all(&mut w, &mut given);
        given[1].asked.last() == Some(&(true, true))
            && given[0].asked.last() == Some(&(false, true))
    });

    show_pictures(&mut w, &mut given, &[0, 1], 0, 60, false);
    given_once(&given);
    let most = 54;
    let (a, b, c, d) = (&given[0], &given[1], &given[2], &given[3]);
    eprintln!(
        "ana {:?}, cy {:?}, dee {:?}",
        a.pictures.keys().collect::<Vec<_>>(),
        c.pictures.keys().collect::<Vec<_>>(),
        d.pictures.keys().collect::<Vec<_>>()
    );
    assert!(
        a.count(2, 2) >= most,
        "ana has ben large: {}",
        a.count(2, 2)
    );
    // Small is within what she asked, before large is had; no more.
    assert!(a.count(2, 1) <= 2, "ana has ben small: {}", a.count(2, 1));
    assert!(c.count(2, 1) >= most, "cy has ben small: {}", c.count(2, 1));
    assert_eq!(c.count(2, 2), 0, "cy asked for small: never large");
    assert_eq!(
        d.count(2, 1) + d.count(2, 2),
        0,
        "dee asked for none of ben"
    );
    assert!(
        d.count(1, 2) >= most,
        "dee has ana large: {}",
        d.count(1, 2)
    );
    assert_eq!(b.pictures.len(), 0, "ben asked for nothing");
    assert_eq!(c.count(1, 1) + c.count(1, 2), 0, "cy asked for none of ana");

    // Ben's large goes: Ana is given his small, the best there is up to large.
    show_pictures(&mut w, &mut given, &[1], 100, 60, true);
    given_once(&given);
    let (a, c, d) = (&given[0], &given[2], &given[3]);
    assert!(
        a.count(2, 1) >= 25,
        "ana falls back to small: {}",
        a.count(2, 1)
    );
    assert_eq!(a.count(2, 2), 0);
    assert!(c.count(2, 1) >= most, "{}", c.count(2, 1));
    assert_eq!(d.count(2, 1), 0, "dee still asked for none");

    // Dee asked for none of Ben's: her ask for a key picture goes nowhere.
    w[3].key(&given[3].voices[&2].clone(), 2);
    std::thread::sleep(Duration::from_millis(1500));
    take_all(&mut w, &mut given);
    assert!(given[1].keys.is_empty(), "{:?}", given[1].keys);
    w[0].key(&ben_v, 2);
    wait("ben is asked for a key picture", 5, || {
        take_all(&mut w, &mut given);
        given[1].keys == [2]
    });
}

/// Four who all know each other, each sending both sizes: every window is
/// given each sender's pictures in the size it asked for, from that sender's
/// own device, once; a window that asks for nothing is given nothing, and
/// each sender is told which sizes are asked of it.
#[test]
fn in_a_mesh_each_window_gets_the_sizes_it_asked_for() {
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
    let (first, rest) = all.split_first().unwrap();
    let others: Vec<&Dev> = rest.iter().collect();
    let g = group(first, &others);
    ask(first, json!({"cmd": "call-start", "group": g}));
    for d in rest {
        wait("rung", 20, || standing(d) == "ringing");
        ask(d, json!({"cmd": "call-answer"}));
    }
    wait("each links with the three others", 30, || {
        all.iter().all(|d| linked(d) == 3)
    });
    let mut w: Vec<Window> = all
        .iter()
        .enumerate()
        .map(|(i, d)| Window::open(d, i as u8 + 1))
        .collect();
    let mut given: Vec<Given> = (0..4).map(|_| Given::default()).collect();
    learn_voices(&mut w, &mut given);
    // What each window asks of each sender, by tag: Dee asks for nothing.
    let want: [[u8; 4]; 4] = [[0, 2, 1, 0], [1, 0, 2, 2], [1, 1, 0, 1], [0, 0, 0, 0]];
    for (r, row) in want.iter().enumerate() {
        for (s, level) in row.iter().enumerate() {
            if *level > 0 {
                let v = given[r].voices[&(s as u8 + 1)].clone();
                w[r].level(&v, *level);
            }
        }
    }
    let told = [(true, false), (true, true), (true, true), (true, true)];
    wait("each sender is told the sizes asked of it", 10, || {
        take_all(&mut w, &mut given);
        (0..4).all(|i| given[i].asked.last() == Some(&told[i]))
    });

    show_pictures(&mut w, &mut given, &[0, 1, 2, 3], 0, 60, false);
    given_once(&given);
    for (r, row) in want.iter().enumerate() {
        for (s, level) in row.iter().enumerate() {
            let tag = s as u8 + 1;
            let (small, large) = (given[r].count(tag, 1), given[r].count(tag, 2));
            match level {
                0 => assert_eq!(small + large, 0, "{r} asked none of {tag}"),
                1 => assert!(small >= 54 && large == 0, "{r} of {tag}: {small} {large}"),
                _ => assert!(large >= 54 && small <= 2, "{r} of {tag}: {small} {large}"),
            }
        }
    }
    assert!(given[3].pictures.is_empty(), "dee asked for nothing");
}

/// Who is on a group call, by voice, as `call` gives it: `voice` to
/// `(name, identity, contact, you)`.
fn voices(d: &Dev) -> HashMap<String, (String, String, bool, bool)> {
    let c = call(d);
    let Some(l) = c["voices"].as_array() else {
        return HashMap::new();
    };
    l.iter()
        .map(|v| {
            let s = |k: &str| v[k].as_str().unwrap_or_default().to_owned();
            (
                s("voice"),
                (
                    s("name"),
                    s("identity"),
                    v["contact"] == true,
                    v["you"] == true,
                ),
            )
        })
        .collect()
}

/// This person's name for each member of a group, by the start of their id.
fn names_in(d: &Dev, g: &str) -> HashMap<String, (String, bool)> {
    let m = ask(d, json!({"cmd": "group-members", "group": g}));
    m["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            let s = |k: &str| m[k].as_str().unwrap_or_default().to_owned();
            (s("id"), (s("name"), m["contact"] == true))
        })
        .collect()
}

/// Four on a group call: Carol knows everyone, Ana knows Carol and Dee but
/// not Ben. Each window is told, for every voice it hears, whose it is:
/// a contact by this person's name for them, someone else by the group's,
/// and the `from` of a voice's sound is one of them.
#[test]
fn a_group_call_says_whose_each_voice_is() {
    let root = tempfile::tempdir().unwrap();
    let carol = person(root.path(), "carol");
    let ana = person(root.path(), "ana");
    let ben = person(root.path(), "ben");
    let dee = person(root.path(), "dee");
    plugged_in(&carol, true);
    for d in [&ana, &ben, &dee] {
        plugged_in(d, false);
    }
    meet(&carol, &ana);
    meet(&carol, &ben);
    meet(&carol, &dee);
    meet(&ana, &dee);
    let g = group(&carol, &[&ana, &ben, &dee]);
    ask(&carol, json!({"cmd": "call-start", "group": g}));
    for d in [&ana, &ben, &dee] {
        wait("rung", 20, || standing(d) == "ringing");
        ask(d, json!({"cmd": "call-answer"}));
    }
    let all = [&carol, &ana, &ben, &dee];
    wait("each hears the three others", 30, || {
        all.iter().all(|d| voices(d).len() == 3)
    });
    for d in all {
        let names = names_in(d, &g);
        let v = voices(d);
        let mut ids: Vec<&String> = v.values().map(|w| &w.1).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 3, "{}: three people, {v:?}", d.name);
        for (name, id, contact, you) in v.values() {
            assert!(!you, "{}: no device of its own on it", d.name);
            let (n, c) = &names[id];
            assert_eq!((name, contact), (n, c), "{}: {v:?} {names:?}", d.name);
            assert_ne!(name, "You");
        }
        let contacts = v.values().filter(|w| w.2).count();
        let want = match d.name {
            "carol" => 3,
            "ana" | "dee" => 2,
            _ => 1,
        };
        assert_eq!(contacts, want, "{}: {v:?}", d.name);
    }
    let named = |d: &Dev, who: &str| voices(d).values().any(|w| w.0 == who && w.2);
    assert!(
        named(&ana, "Carol") && named(&ana, "Dee"),
        "{:?}",
        voices(&ana)
    );
    let ben_to_ana = voices(&ana).into_values().find(|w| !w.2).unwrap();
    assert_eq!(ben_to_ana.0, names_in(&ana, &g)[&ben_to_ana.1].0);

    // what Ben says comes to Ana from the voice named as his
    let mut lines = [Line::open(&ana, 1), Line::open(&ben, 2)];
    for _ in 0..50 {
        lines[1].say();
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut from = None;
    while let Some(f) = lines[0].m.next() {
        if f["audio"].is_string() {
            from = f["from"].as_str().map(str::to_owned);
            break;
        }
    }
    let from = from.expect("ana heard ben");
    assert_eq!(voices(&ana)[&from].1, ben_to_ana.1, "{:?}", voices(&ana));
}

/// Ben is on a group call on two devices: the phone's voice is his own,
/// named as he is, and Ana sees both as Ben.
#[test]
fn a_group_call_says_a_voice_is_another_device_of_ones_own() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let ana = person(root.path(), "ana");
    let ben = person(root.path(), "ben");
    let cy = person(root.path(), "cy");
    plugged_in(&ana, false);
    plugged_in(&ben, false);
    plugged_in(&cy, false);
    meet(&ana, &ben);
    meet(&ana, &cy);
    let g = group(&ana, &[&ben, &cy]);
    let phone = start_paired(root.path(), &ben);
    plugged_in(&phone, false);
    wait("ben's phone has the group", 60, || {
        let v = reply(&phone, &json!({"cmd": "groups"}));
        v["groups"].as_array().is_some_and(|g| !g.is_empty())
    });
    wait("ben's phone reaches ana", 60, || {
        reply(&phone, &json!({"cmd": "contacts"}))["contacts"][0]["connected"] == true
    });

    ask(&ana, json!({"cmd": "call-start", "group": g}));
    wait("ben and cy ring", 20, || {
        standing(&ben) == "ringing" && standing(&cy) == "ringing"
    });
    ask(&ben, json!({"cmd": "call-answer"}));
    ask(&cy, json!({"cmd": "call-answer"}));
    wait("the phone stops ringing", 20, || {
        standing(&phone).is_empty()
    });
    // and Ben joins it from the phone as well
    ask(&phone, json!({"cmd": "call-start", "group": g}));
    wait("ana hears three voices", 40, || voices(&ana).len() == 3);
    wait("ben hears his phone", 40, || {
        voices(&ben).values().any(|w| w.3)
    });
    let mine = voices(&ben);
    let own: Vec<_> = mine.values().filter(|w| w.3).collect();
    assert_eq!(own.len(), 1, "{mine:?}");
    assert_eq!(own[0].0, "You");
    assert!(!own[0].2, "his own is not a contact");
    let at_ana = voices(&ana);
    let bens: Vec<_> = at_ana.values().filter(|w| w.0 == "Ben").collect();
    assert_eq!(bens.len(), 2, "{at_ana:?}");
    assert_eq!(bens[0].1, bens[1].1, "one person");
    assert!(bens.iter().all(|w| w.2 && !w.3));
    assert_eq!(own[0].1, bens[0].1, "the same person, as each names them");
}
