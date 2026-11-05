//! A device told its network changed finds the sessions that went with the old
//! one in seconds, then looks again: a phone asleep runs no timers of its own,
//! so whatever sees the change (Android, for the app) says so.

mod common;

use common::*;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

fn ask(d: &Dev, req: Value) -> Value {
    let mut s = UnixStream::connect(d.home.join("control.sock")).unwrap();
    writeln!(s, "{req}").unwrap();
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).unwrap();
    let r: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(r["ok"], true, "{req} got {r}");
    r
}

fn person(root: &std::path::Path, name: &'static str) -> Dev {
    let mut d = Dev::new(root, name, free_port());
    d.start_with(&["--no-mount"]);
    d.cli(&["init", "--yes", "--name", name]);
    d
}

fn connected(d: &Dev) -> bool {
    ask(d, json!({"cmd": "conversations"}))["conversations"][0]["connected"] == true
}

fn signal(d: &Dev, sig: &str) {
    let pid = d.child.as_ref().unwrap().id().to_string();
    let ok = std::process::Command::new("kill")
        .args([sig, &pid])
        .status()
        .unwrap();
    assert!(ok.success());
}

#[test]
fn a_changed_network_finds_dead_sessions_in_seconds() {
    let root = tempfile::tempdir().unwrap();
    let a = person(root.path(), "ana");
    let b = person(root.path(), "bo");
    let at = format!("127.0.0.1:{}", a.port);
    let code = a.cli(&["invite", "--address", &at, "--name", "Ana"]);
    b.cli(&["accept", code.trim(), "--name", "Ana"]);
    wait("connected", 30, || connected(&a));

    // Bo's device stops answering, as one left behind on the old network does.
    signal(&b, "-STOP");
    let r = ask(&a, json!({"cmd": "network-changed"}));
    assert!(r["checking"].as_u64().unwrap() >= 1, "{r}");
    let t = Instant::now();
    wait("the dead session ends", 20, || !connected(&a));
    let took = t.elapsed();
    signal(&b, "-CONT");
    // A keepalive would have taken up to 30 s.
    assert!(took < Duration::from_secs(15), "took {took:?}");
    wait("together again", 60, || connected(&a));
}
