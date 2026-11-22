//! A device told its network changed finds the sessions that went with the old
//! one in seconds, then looks again: a phone asleep runs no timers of its own,
//! so whatever sees the change (Android, for the app) says so.

mod common;

use common::*;
use serde_json::{json, Value};
use std::time::{Duration, Instant};

fn ask(d: &Dev, req: Value) -> Value {
    let r = common::reply(d, &req);
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

/// Whether every thread of `d`'s daemon is stopped, as the kernel says.
fn all_stopped(d: &Dev) -> bool {
    let pid = d.child.as_ref().unwrap().id();
    let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
        return false;
    };
    tasks.flatten().all(|t| {
        let stat = std::fs::read_to_string(t.path().join("stat")).unwrap_or_default();
        // The state follows the command name, which is in parentheses.
        let state = stat.rsplit_once(") ").map(|(_, rest)| rest.chars().next());
        state == Some(Some('T'))
    })
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
    // `kill` returns before every thread of it has stopped, and one still
    // running could answer what Ana asks next.
    signal(&b, "-STOP");
    wait("bo's device has stopped", 5, || all_stopped(&b));
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
