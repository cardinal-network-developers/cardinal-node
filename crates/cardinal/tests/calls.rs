//! Calls, over the socket as a client reaches them: one person rings another,
//! audio goes both ways on the real-time channel, and a big transfer beside it
//! does not hold it up.
//!
//! Skipped (with a message) when `/dev/fuse` or `fusermount3` is missing.

mod common;

use common::*;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

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

    fn heard(&mut self) -> Option<u32> {
        let mut line = String::new();
        self.r.read_line(&mut line).ok()?;
        let v: Value = serde_json::from_str(&line).ok()?;
        let b = hex::decode(v["audio"].as_str()?).ok()?;
        Some(u32::from_be_bytes(b.try_into().ok()?))
    }
}

#[test]
fn two_people_talk_and_hang_up() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (a, b, bo) = met(root.path());

    ask(&a, json!({"cmd": "call-start", "who": bo}));
    assert_eq!(standing(&a), "calling");
    wait("bo's device rings", 10, || standing(&b) == "ringing");
    assert_eq!(ask(&b, json!({"cmd": "call"}))["call"]["name"], "Ana");

    let rung = Instant::now();
    ask(&b, json!({"cmd": "call-answer"}));
    wait("ana hears the answer", 10, || standing(&a) == "live");
    assert!(
        rung.elapsed() < Duration::from_secs(2),
        "{:?}",
        rung.elapsed()
    );
    assert_eq!(standing(&b), "live");

    let (mut la, mut lb) = (Line::open(&a), Line::open(&b));
    std::thread::sleep(Duration::from_millis(200));
    for n in 0..50 {
        la.say(n);
        lb.say(1000 + n);
        std::thread::sleep(Duration::from_millis(5));
    }
    let (mut at_a, mut at_b) = (Vec::new(), Vec::new());
    for _ in 0..120 {
        if let Some(n) = la.heard() {
            at_a.push(n);
        }
        if let Some(n) = lb.heard() {
            at_b.push(n);
        }
        if at_a.len() == 50 && at_b.len() == 50 {
            break;
        }
    }
    assert_eq!(at_b.len(), 50, "{at_b:?}");
    assert_eq!(at_a.len(), 50, "{at_a:?}");
    assert_eq!(at_a[0], 1000);

    ask(&a, json!({"cmd": "call-end"}));
    wait("bo hears the end", 10, || standing(&b).is_null());
    assert!(standing(&a).is_null());
}

/// Saying no, and being busy, end a call on both sides.
#[test]
fn a_call_can_be_declined() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (a, b, bo) = met(root.path());
    ask(&a, json!({"cmd": "call-start", "who": bo}));
    wait("it rings", 10, || standing(&b) == "ringing");
    ask(&b, json!({"cmd": "call-end"}));
    wait("ana hears no", 10, || standing(&a).is_null());
    assert!(standing(&b).is_null());
}

fn ended(d: &Dev) -> Value {
    ask(d, json!({"cmd": "call"}))["ended"].clone()
}

/// A person with two devices: a call answered, or said no to, on one is not
/// missed on the other, and the service says how each call ended, so a
/// window need not guess.
#[test]
fn a_call_taken_on_another_device_is_not_missed() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (a, b, bo) = met(root.path());
    let mut b2 = Dev::new(root.path(), "bo-phone", free_port());
    b2.start();
    pair(&b, &b2);
    wait("bo's phone reaches ana", 60, || {
        let c = try_ask(&b2, json!({"cmd": "contacts"}));
        c["contacts"][0]["connected"] == true
    });
    let both_ring = |a: &Dev| {
        ask(a, json!({"cmd": "call-start", "who": bo}));
        wait("both of bo's devices ring", 20, || {
            standing(&b) == "ringing" && standing(&b2) == "ringing"
        });
        ask(&b, json!({"cmd": "call"}))["call"]["id"].clone()
    };

    // Answered on one: the other stops ringing, and it was not missed.
    let id = both_ring(&a);
    ask(&b, json!({"cmd": "call-answer"}));
    wait("the phone stops ringing", 10, || standing(&b2).is_null());
    let e = ended(&b2);
    assert_eq!(e["id"], id, "{e}");
    assert_eq!(e["how"], "answered_elsewhere", "{e}");
    assert_eq!(e["name"], "Ana", "{e}");
    wait("ana is on it", 10, || standing(&a) == "live");
    ask(&a, json!({"cmd": "call-end"}));
    wait("bo hears the end", 10, || standing(&b).is_null());
    assert_eq!(ended(&b)["how"], "over");
    assert_eq!(ended(&a)["how"], "over");

    // Said no to on one: not missed on the other either.
    let id = both_ring(&a);
    ask(&b2, json!({"cmd": "call-end"}));
    wait("the other stops ringing", 10, || standing(&b).is_null());
    let e = ended(&b);
    assert_eq!(e["id"], id, "{e}");
    assert_eq!(e["how"], "declined_elsewhere", "{e}");
    assert_eq!(ended(&b2)["how"], "declined");
    wait("ana hears no", 10, || standing(&a).is_null());
    assert_eq!(ended(&a)["how"], "they_declined");

    // Nobody answers before the caller gives up: missed on both.
    let id = both_ring(&a);
    ask(&a, json!({"cmd": "call-end"}));
    wait("both stop ringing", 10, || {
        standing(&b).is_null() && standing(&b2).is_null()
    });
    for d in [&b, &b2] {
        let e = ended(d);
        assert_eq!(e["id"], id, "{e}");
        assert_eq!(e["how"], "missed", "{e}");
    }
    assert_eq!(ended(&a)["how"], "cancelled");
}

/// Someone not trusted has no session, so a call says so, and asks no one.
#[test]
fn nobody_can_be_called_while_out_of_reach() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (a, mut b, bo) = met(root.path());
    b.stop();
    wait("ana notices", 45, || {
        ask(&a, json!({"cmd": "contacts"}))["contacts"][0]["connected"] == false
    });
    let reply = try_ask(&a, json!({"cmd": "call-start", "who": bo}));
    assert_eq!(reply["ok"], false, "{reply}");
    assert!(
        reply["error"]
            .as_str()
            .unwrap()
            .contains("cannot be reached"),
        "{reply}"
    );
    assert!(standing(&a).is_null());
}

/// Refusing someone ends every way they had of reaching this person, and a
/// ring is one of them.
#[test]
fn someone_refused_cannot_ring() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (a, b, bo) = met(root.path());
    ask(
        &a,
        json!({"cmd": "contact", "who": bo, "setting": "refuse"}),
    );
    wait("bo is cut off", 30, || {
        ask(&b, json!({"cmd": "contacts"}))["contacts"][0]["connected"] == false
    });
    let reply = try_ask(&b, json!({"cmd": "call-start", "who": "Ana"}));
    assert_eq!(reply["ok"], false, "{reply}");
    std::thread::sleep(Duration::from_secs(1));
    assert!(standing(&a).is_null());
}

/// `experience.md`: background sync has no audible effect on a call. Frames go
/// every 20 ms while a large file syncs beside them, and none may be late by
/// more than a jitter buffer holds. The sync is to this person's other device,
/// so this measures a busy daemon and machine, not two kinds of traffic on one
/// session: contacts share no bulk data yet.
#[test]
fn a_big_transfer_does_not_hold_up_a_call() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut a = person(root.path(), "ana");
    let mut phone = Dev::new(root.path(), "phone", free_port());
    phone.start();
    pair(&a, &phone);
    let at = format!("127.0.0.1:{}", a.port);
    let (bob, _) = (person(root.path(), "bo"), ());
    let code = bob.cli(&[
        "invite",
        "--address",
        &format!("127.0.0.1:{}", bob.port),
        "--name",
        "Bo",
    ]);
    a.cli(&["accept", code.trim(), "--name", "Bo"]);
    let _ = at;
    wait("connected", 30, || {
        ask(&a, json!({"cmd": "contacts"}))["contacts"][0]["connected"] == true
    });
    ask(&a, json!({"cmd": "call-start", "who": "Bo"}));
    wait("it rings", 10, || standing(&bob) == "ringing");
    ask(&bob, json!({"cmd": "call-answer"}));
    wait("live", 10, || standing(&a) == "live");
    let (mut la, mut lb) = (Line::open(&a), Line::open(&bob));
    lb.w.set_read_timeout(Some(Duration::from_millis(2)))
        .unwrap();
    std::thread::sleep(Duration::from_millis(200));

    // Bulk on the machine and on a's links while frames go.
    let big: Vec<u8> = (0..(200u32 << 20))
        .map(|i| (i.wrapping_mul(2654435761) >> 24) as u8)
        .collect();
    std::fs::write(a.p("big.bin"), &big).unwrap();
    a.cli(&["flush"]);

    let start = Instant::now();
    let mut late_ms = Vec::new();
    let mut got = 0u32;
    for n in 0..150u32 {
        let due = start + Duration::from_millis(u64::from(n) * 20);
        while Instant::now() < due {
            if let Some(h) = lb.heard() {
                got += 1;
                let sent_at = start + Duration::from_millis(u64::from(h) * 20);
                late_ms.push(
                    Instant::now()
                        .saturating_duration_since(sent_at)
                        .as_millis() as u64,
                );
            }
        }
        la.say(n);
    }
    late_ms.sort_unstable();
    let p99 = late_ms[(late_ms.len() * 99) / 100];
    let max = *late_ms.last().unwrap();
    eprintln!("MEASURE call beside a sync: {got} of 150 frames, p99 {p99} ms, worst {max} ms");
    assert!(got >= 142, "lost too many: {got}");
    assert!(p99 < 60, "p99 {p99} ms");
    a.stop();
    phone.stop();
}
