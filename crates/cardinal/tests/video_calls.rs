//! Calls that say what they hold: a ring offers formats, an answer takes
//! some, and a format other than voice (video) has its own channel.
//!
//! Skipped (with a message) when `/dev/fuse` or `fusermount3` is missing.

mod common;

use common::*;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

fn person(root: &std::path::Path, name: &'static str) -> Dev {
    let mut d = Dev::new(root, name, free_port());
    d.start();
    d.cli(&["init", "--yes", "--name", name]);
    d.wait_mounted();
    d
}

fn try_ask(d: &Dev, req: Value) -> Value {
    let mut s = UnixStream::connect(d.home.join("control.sock")).unwrap();
    writeln!(s, "{req}").unwrap();
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
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
    w: UnixStream,
    r: BufReader<UnixStream>,
}

impl Line {
    fn open(d: &Dev) -> Line {
        let mut w = UnixStream::connect(d.home.join("control.sock")).unwrap();
        writeln!(w, "{}", json!({"cmd": "call-media"})).unwrap();
        w.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        let r = BufReader::new(w.try_clone().unwrap());
        Line { w, r }
    }

    fn say(&mut self, n: u32) {
        let frame = hex::encode(n.to_be_bytes());
        writeln!(self.w, "{}", json!({"audio": frame})).unwrap();
    }

    fn show(&mut self, format: &str, n: u32) {
        let frame = hex::encode(n.to_be_bytes());
        writeln!(self.w, "{}", json!({"frame": frame, "format": format})).unwrap();
    }

    /// What came, as (kind, number): `audio`, or a format's hex.
    fn got(&mut self) -> Option<(String, u32)> {
        let mut line = String::new();
        self.r.read_line(&mut line).ok()?;
        let v: Value = serde_json::from_str(&line).ok()?;
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
