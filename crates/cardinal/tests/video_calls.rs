//! Calls that say what they hold: a ring offers formats, an answer takes
//! some, and a format other than voice (video) has its own channel.
//!
//! Skipped (with a message) when `/dev/fuse` or `fusermount3` is missing.

mod common;

use common::*;
use serde_json::{json, Value};
use std::time::Duration;

fn person(root: &std::path::Path, name: &'static str) -> Dev {
    let mut d = Dev::new(root, name, free_port());
    d.start();
    d.cli(&["init", "--yes", "--name", name]);
    d.wait_mounted();
    d
}

fn try_ask(d: &Dev, req: Value) -> Value {
    common::reply(d, &req)
}

fn ask(d: &Dev, req: Value) -> Value {
    let reply = try_ask(d, req.clone());
    assert_eq!(reply["ok"], true, "{req} got {reply}");
    reply
}

fn standing(d: &Dev) -> Value {
    ask(d, json!({"cmd": "call"}))["call"]["state"].clone()
}

fn met(root: &std::path::Path) -> (Dev, Dev, String) {
    let (a, b) = (person(root, "ana"), person(root, "bo"));
    let at = format!("127.0.0.1:{}", a.port);
    let code = a.cli(&["invite", "--address", &at, "--name", "Ana"]);
    b.cli(&["accept", code.trim(), "--name", "Ana"]);
    let bo = wait_name(&a);
    wait("they are connected", 30, || {
        let c = ask(&a, json!({"cmd": "contacts"}));
        c["contacts"][0]["connected"] == true
    });
    (a, b, bo)
}

fn wait_name(a: &Dev) -> String {
    let mut name = String::new();
    wait("listed", 30, || {
        let c = ask(a, json!({"cmd": "conversations"}));
        name = c["conversations"][0]["name"]
            .as_str()
            .unwrap_or("")
            .to_owned();
        !name.is_empty()
    });
    name
}

/// A client's line of audio.
struct Line {
    m: Media,
}

impl Line {
    fn open(d: &Dev) -> Line {
        Line {
            m: Media::open(d, Duration::from_millis(50)),
        }
    }

    fn say(&mut self, n: u32) {
        let frame = hex::encode(n.to_be_bytes());
        self.m.send(&json!({"audio": frame}));
    }

    fn show(&mut self, format: &str, n: u32) {
        let frame = hex::encode(n.to_be_bytes());
        self.m.send(&json!({"frame": frame, "format": format}));
    }

    /// What came, as (kind, number): `audio`, or a format's hex.
    fn got(&mut self) -> Option<(String, u32)> {
        let v = self.m.next()?;
        let (kind, h) = match v["audio"].as_str() {
            Some(h) => ("audio".to_owned(), h),
            None => (v["format"].as_str()?.to_owned(), v["frame"].as_str()?),
        };
        let b = hex::decode(h).ok()?;
        Some((kind, u32::from_be_bytes(b.try_into().ok()?)))
    }
}

fn video_hex(d: &Dev) -> String {
    let call = ask(d, json!({"cmd": "call"}))["call"].clone();
    call["taken"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f.as_str().unwrap().to_owned())
        .find(|f| *f != call["taken"][0].as_str().unwrap())
        .unwrap()
}

/// What one side got: kind and number.
type Got = Vec<(String, u32)>;

fn exchange(a: &Dev, b: &Dev, video: &str) -> (Got, Got) {
    let (mut la, mut lb) = (Line::open(a), Line::open(b));
    std::thread::sleep(Duration::from_millis(200));
    for n in 0..30 {
        la.say(n);
        la.show(video, 500 + n);
        lb.show(video, 900 + n);
        std::thread::sleep(Duration::from_millis(5));
    }
    let (mut at_a, mut at_b) = (Vec::new(), Vec::new());
    for _ in 0..200 {
        if let Some(x) = la.got() {
            at_a.push(x);
        }
        if let Some(x) = lb.got() {
            at_b.push(x);
        }
    }
    (at_a, at_b)
}

#[test]
fn video_goes_on_its_own_channel_when_both_take_it() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (a, b, bo) = met(root.path());
    let both = json!(["voice 1", "video vp8 1"]);
    ask(
        &a,
        json!({"cmd": "call-start", "who": bo, "format_names": both}),
    );
    wait("bo's device rings", 10, || standing(&b) == "ringing");
    let offered = ask(&b, json!({"cmd": "call"}))["call"]["offered"].clone();
    assert_eq!(offered.as_array().map(Vec::len), Some(2), "{offered}");
    ask(&b, json!({"cmd": "call-answer", "format_names": both}));
    wait("ana hears the answer", 10, || standing(&a) == "live");
    let taken = ask(&a, json!({"cmd": "call"}))["call"]["taken"].clone();
    assert_eq!(taken, offered, "both formats taken");
    let video = video_hex(&a);
    let (at_a, at_b) = exchange(&a, &b, &video);
    let of = |l: &[(String, u32)], k: &str| l.iter().filter(|(x, _)| x == k).count();
    assert_eq!(of(&at_b, "audio"), 30, "{at_b:?}");
    assert_eq!(of(&at_b, &video), 30, "{at_b:?}");
    assert_eq!(of(&at_a, &video), 30, "{at_a:?}");
    assert!(at_b.iter().any(|(k, n)| *k == video && *n == 500));
    ask(&a, json!({"cmd": "call-end"}));
}

/// Answered with voice only: no video is sent either way, and a ring that
/// names nothing is the voice call it always was.
#[test]
fn voice_only_answers_get_no_video() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (a, b, bo) = met(root.path());
    ask(
        &a,
        json!({"cmd": "call-start", "who": bo, "format_names": ["voice 1", "video vp8 1"]}),
    );
    wait("bo's device rings", 10, || standing(&b) == "ringing");
    let offered = ask(&b, json!({"cmd": "call"}))["call"]["offered"].clone();
    let video = offered[1].as_str().unwrap().to_owned();
    ask(
        &b,
        // A window that names nothing, as one from before formats: voice only.
        json!({"cmd": "call-answer"}),
    );
    wait("ana hears the answer", 10, || standing(&a) == "live");
    let taken = ask(&a, json!({"cmd": "call"}))["call"]["taken"].clone();
    assert_eq!(taken.as_array().map(Vec::len), Some(1), "{taken}");
    let (at_a, at_b) = exchange(&a, &b, &video);
    assert!(
        at_a.iter().chain(&at_b).all(|(k, _)| k == "audio"),
        "{at_a:?} {at_b:?}"
    );
    assert_eq!(at_b.len(), 30);
    ask(&a, json!({"cmd": "call-end"}));
    wait("over", 10, || standing(&b).is_null());

    ask(&a, json!({"cmd": "call-start", "who": bo}));
    wait("rings", 10, || standing(&b) == "ringing");
    assert!(ask(&b, json!({"cmd": "call"}))["call"]["offered"].is_null());
    ask(&b, json!({"cmd": "call-answer"}));
    wait("live", 10, || standing(&a) == "live");
    assert!(ask(&a, json!({"cmd": "call"}))["call"]["taken"].is_null());
}

/// How many formats `key` (`taken` or `they_take`) of a device's call names.
fn named(d: &Dev, key: &str) -> Option<usize> {
    ask(d, json!({"cmd": "call"}))["call"][key]
        .as_array()
        .map(Vec::len)
}

/// Receiving video is each side's own choice, during the call too
/// (`basics/video.md`): answered with voice only, no video comes; a new
/// answer taking video starts it coming, to that side alone, and one with
/// voice only stops it. The other side is told each time.
#[test]
fn answering_again_turns_video_on_and_off() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (a, b, bo) = met(root.path());
    let both = json!(["voice 1", "video vp8 1"]);
    let voice = json!(["voice 1"]);
    ask(
        &a,
        json!({"cmd": "call-start", "who": bo, "format_names": both}),
    );
    wait("bo's device rings", 10, || standing(&b) == "ringing");
    let video = ask(&b, json!({"cmd": "call"}))["call"]["offered"][1]
        .as_str()
        .unwrap()
        .to_owned();
    ask(&b, json!({"cmd": "call-answer", "format_names": voice}));
    wait("ana hears the answer", 10, || standing(&a) == "live");
    let of = |l: &[(String, u32)], k: &str| l.iter().filter(|(x, _)| x == k).count();

    // Voice only: no video either way, though both windows send it.
    let (at_a, at_b) = exchange(&a, &b, &video);
    assert_eq!(of(&at_b, "audio"), 30, "{at_b:?}");
    assert_eq!(
        of(&at_b, &video) + of(&at_a, &video),
        0,
        "{at_a:?} {at_b:?}"
    );

    // Bo takes video: Ana's device is told, and sends him hers; she still
    // takes none of his.
    ask(&b, json!({"cmd": "call-answer", "format_names": both}));
    assert_eq!(named(&b, "taken"), Some(2));
    wait("ana is told bo takes video", 10, || {
        named(&a, "they_take") == Some(2)
    });
    assert_eq!(named(&a, "taken"), Some(1));
    let (at_a, at_b) = exchange(&a, &b, &video);
    assert_eq!(of(&at_b, &video), 30, "{at_b:?}");
    assert_eq!(of(&at_a, &video), 0, "{at_a:?}");

    // Ana takes it too, the caller answering again.
    ask(&a, json!({"cmd": "call-answer", "format_names": both}));
    wait("bo is told", 10, || named(&b, "they_take") == Some(2));
    let (at_a, at_b) = exchange(&a, &b, &video);
    assert_eq!(of(&at_a, &video), 30, "{at_a:?}");
    assert_eq!(of(&at_b, &video), 30, "{at_b:?}");

    // Bo goes back to voice only: his video stops; Ana's goes on.
    ask(&b, json!({"cmd": "call-answer"}));
    wait("ana is told bo takes voice only", 10, || {
        named(&a, "they_take") == Some(1)
    });
    let (at_a, at_b) = exchange(&a, &b, &video);
    assert_eq!(of(&at_b, &video), 0, "{at_b:?}");
    assert_eq!(of(&at_b, "audio"), 30, "{at_b:?}");
    assert_eq!(of(&at_a, &video), 30, "{at_a:?}");
    assert_eq!(standing(&a), "live");
    assert_eq!(standing(&b), "live");
    ask(&a, json!({"cmd": "call-end"}));
    wait("over", 10, || standing(&b).is_null());

    // A voice call that offered nothing else has nothing to answer again.
    ask(&a, json!({"cmd": "call-start", "who": bo}));
    wait("rings", 10, || standing(&b) == "ringing");
    ask(&b, json!({"cmd": "call-answer"}));
    wait("live", 10, || standing(&a) == "live");
    let again = try_ask(&b, json!({"cmd": "call-answer", "format_names": both}));
    assert_eq!(again["ok"], false, "{again}");
    assert_eq!(standing(&b), "live");
}

/// The viewports that came on a line within `secs` seconds.
fn viewports(l: &mut Line, secs: u64) -> Vec<Value> {
    let until = std::time::Instant::now() + Duration::from_secs(secs);
    let mut out = Vec::new();
    while std::time::Instant::now() < until {
        if let Some(v) = l.m.next() {
            if v.get("width").is_some() {
                out.push(v);
            }
        }
    }
    out
}

/// A window tells the service the shape of its viewport; the other side's
/// window has it, apart from the video, again every five seconds, and as
/// soon as it changes (`basics/video.md`).
#[test]
fn a_viewport_reaches_the_one_sending_video() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (a, b, bo) = met(root.path());
    let both = json!(["voice 1", "video vp8 1"]);
    ask(
        &a,
        json!({"cmd": "call-start", "who": bo, "format_names": both}),
    );
    wait("bo's device rings", 10, || standing(&b) == "ringing");
    ask(&b, json!({"cmd": "call-answer", "format_names": both}));
    wait("ana hears the answer", 10, || standing(&a) == "live");
    let (mut la, mut lb) = (Line::open(&a), Line::open(&b));
    std::thread::sleep(Duration::from_millis(200));
    lb.m.send(&json!({"width": 9, "height": 16}));
    let tall = json!({"width": 9, "height": 16});
    let got = viewports(&mut la, 7);
    assert!(got.len() >= 2, "said now and again: {got:?}");
    assert!(got.iter().all(|v| *v == tall), "{got:?}");
    lb.m.send(&json!({"width": 16, "height": 9}));
    let got = viewports(&mut la, 2);
    assert_eq!(got, vec![json!({"width": 16, "height": 9})]);
    assert!(viewports(&mut lb, 1).is_empty(), "not given back");
    ask(&a, json!({"cmd": "call-end"}));
}
