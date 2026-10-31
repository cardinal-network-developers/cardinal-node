//! Removing a device (`spaces.md#when-to-rotate`, `spaces.md#authors`):
//! every remaining device moves to keys it never held at once, and what is
//! written after that reaches them all. A device that was retired keeps its
//! work and one that was lost does not. The news spreads from device to
//! device, and a device that has not heard it goes on trusting the one
//! removed until it meets one that has.
//!
//! Skipped (with a message) when `/dev/fuse` or `fusermount3` is missing.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

use common::*;
use serde_json::{json, Value};

fn request(d: &Dev, req: Value) -> Value {
    let mut s = UnixStream::connect(d.home.join("control.sock")).unwrap();
    s.write_all(format!("{req}\n").as_bytes()).unwrap();
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

/// The current epoch of the files space.
fn epoch(d: &Dev) -> String {
    let t = request(d, json!({"cmd": "debug-tree"}));
    t["epoch"].as_str().unwrap_or_default().to_owned()
}

#[test]
fn a_removal_moves_the_other_devices_to_new_keys_at_once() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut a = Dev::new(root.path(), "alpha", free_port());
    let mut b = Dev::new(root.path(), "beta", free_port());
    let mut c = Dev::new(root.path(), "gamma", free_port());
    a.start();
    a.cli(&["init", "--yes", "--name", "alpha"]);
    a.wait_mounted();
    b.start();
    pair(&a, &b);
    c.start();
    pair(&a, &c);
    b.wait_mounted();
    c.wait_mounted();
    std::fs::write(a.p("before.txt"), "before\n").unwrap();
    a.cli(&["flush"]);
    wait("gamma has the file", 30, || {
        std::fs::read(c.p("before.txt")).is_ok_and(|x| x == b"before\n")
    });
    let old = epoch(&a);
    assert!(!old.is_empty());
    assert_eq!(epoch(&c), old);

    a.cli(&["remove-device", "gamma"]);

    // Nobody has written anything.
    assert_ne!(epoch(&a), old, "the device that removed it");
    wait("beta is on the new keys", 20, || epoch(&b) == epoch(&a));
    assert_ne!(epoch(&b), old);

    // Beta is not an admin device, and what it writes reaches alpha.
    std::fs::write(b.p("after.txt"), "after\n").unwrap();
    b.cli(&["flush"]);
    wait("alpha has beta's file", 20, || {
        std::fs::read(a.p("after.txt")).is_ok_and(|x| x == b"after\n")
    });

    // Gamma hears that it is gone, and of nothing after that.
    assert_eq!(c.status()["removed"], true);
    assert_eq!(epoch(&c), old);
    assert!(!c.p("after.txt").exists());
}

/// Three devices with a file in common. Beta also knows how to reach gamma
/// by itself.
fn three(root: &std::path::Path) -> (Dev, Dev, Dev) {
    let mut a = Dev::new(root, "alpha", free_port());
    let mut b = Dev::new(root, "beta", free_port());
    let mut c = Dev::new(root, "gamma", free_port());
    a.start();
    a.cli(&["init", "--yes", "--name", "alpha"]);
    a.wait_mounted();
    b.start();
    pair(&a, &b);
    c.start();
    pair(&a, &c);
    b.wait_mounted();
    c.wait_mounted();
    std::fs::write(a.p("base.txt"), "base\n").unwrap();
    a.cli(&["flush"]);
    wait("all have the file", 30, || {
        has(&b, "base.txt") && has(&c, "base.txt")
    });
    b.cli(&["peer", "add", &format!("127.0.0.1:{}", c.port)]);
    wait("beta reaches gamma itself", 30, || online(&b, "gamma"));
    (a, b, c)
}

fn has(d: &Dev, file: &str) -> bool {
    d.p(file).exists()
}

fn listed(d: &Dev, name: &str) -> bool {
    let v = d.status();
    let all = v["devices"].as_array().unwrap();
    all.iter().any(|x| x["name"] == name)
}

fn online(d: &Dev, name: &str) -> bool {
    let v = d.status();
    let all = v["devices"].as_array().unwrap();
    all.iter().any(|x| x["name"] == name && x["online"] == true)
}

#[test]
fn a_retired_device_keeps_what_it_wrote_last() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (a, b, c) = three(root.path());
    std::fs::write(c.p("last.txt"), "last\n").unwrap();
    c.cli(&["flush"]);
    wait("everyone has it", 30, || {
        has(&a, "last.txt") && has(&b, "last.txt")
    });

    a.cli(&["remove-device", "gamma"]);
    wait("beta knows", 20, || !listed(&b, "gamma"));
    std::thread::sleep(std::time::Duration::from_secs(1));
    assert!(has(&a, "last.txt") && has(&b, "last.txt"));
}

/// Written a moment before the removal: only the device itself has it, and
/// the removal fetches it.
#[test]
fn a_retired_device_gives_up_what_nobody_has_yet() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (a, _b, mut c) = three(root.path());
    std::fs::write(c.p("note.txt"), "just now\n").unwrap();
    c.cli(&["flush"]);
    a.cli(&["remove-device", "gamma"]);
    c.stop();
    wait("alpha has it", 20, || has(&a, "note.txt"));
    assert_eq!(std::fs::read(a.p("note.txt")).unwrap(), b"just now\n");
}

#[test]
fn a_lost_device_keeps_nothing_nobody_built_on() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (a, b, c) = three(root.path());
    std::fs::write(c.p("thief.txt"), "theirs\n").unwrap();
    c.cli(&["flush"]);
    wait("everyone has it", 30, || {
        has(&a, "thief.txt") && has(&b, "thief.txt")
    });

    let told = a.cli(&["remove-device", "gamma", "--lost"]);
    assert!(told.contains("not kept:"), "{told}");
    assert!(!told.contains("not kept: 0"), "{told}");
    wait("alpha drops it", 20, || !has(&a, "thief.txt"));
    wait("beta drops it", 20, || !has(&b, "thief.txt"));
    assert!(has(&a, "base.txt") && has(&b, "base.txt"));
}

#[test]
fn a_device_back_from_offline_hears_as_soon_as_it_meets_one_that_knows() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (a, mut b, mut c) = three(root.path());
    b.stop();
    a.cli(&["remove-device", "gamma"]);
    c.stop();
    b.start();
    wait("beta heard", 30, || !listed(&b, "gamma"));
    wait("beta is on the new keys", 20, || epoch(&b) == epoch(&a));
}

/// Gamma was told, so it is a way for the news to travel: alpha is gone by
/// the time beta comes back.
#[test]
fn the_removed_device_itself_can_carry_the_news() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (mut a, mut b, c) = three(root.path());
    b.stop();
    a.cli(&["remove-device", "gamma"]);
    wait("gamma was told", 10, || c.status()["removed"] == true);
    a.stop();
    b.start();
    wait("beta heard from gamma", 30, || !listed(&b, "gamma"));

    // And it gets nothing for it.
    std::fs::write(b.p("after.txt"), "after\n").unwrap();
    b.cli(&["flush"]);
    std::thread::sleep(std::time::Duration::from_secs(2));
    assert!(!has(&c, "after.txt"));
}

/// What cannot be helped: beta can reach only gamma, neither knows, so they
/// go on as before. What beta built on stays, because beta still trusted
/// gamma; the rest goes when beta hears.
#[test]
fn a_device_that_has_not_heard_goes_on_trusting_the_one_removed() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (mut a, mut b, mut c) = three(root.path());
    b.stop();
    c.stop();
    a.cli(&["remove-device", "gamma"]);
    a.stop();
    b.start();
    c.start();

    std::fs::write(c.p("built-on.txt"), "1\n").unwrap();
    c.cli(&["flush"]);
    wait("beta has it", 40, || has(&b, "built-on.txt"));
    std::fs::write(b.p("by-beta.txt"), "2\n").unwrap();
    b.cli(&["flush"]);
    wait("gamma has beta's", 30, || has(&c, "by-beta.txt"));
    std::fs::write(c.p("not-built-on.txt"), "3\n").unwrap();
    c.cli(&["flush"]);
    wait("beta has that too", 30, || has(&b, "not-built-on.txt"));
    assert!(listed(&b, "gamma"));

    a.start();
    wait("beta heard", 60, || !listed(&b, "gamma"));
    wait("what nothing built on goes", 20, || {
        !has(&a, "not-built-on.txt") && !has(&b, "not-built-on.txt")
    });
    wait("the rest stays", 20, || {
        has(&a, "built-on.txt") && has(&a, "by-beta.txt") && has(&b, "built-on.txt")
    });

    // Gamma is cut off from here on.
    std::fs::write(b.p("later.txt"), "4\n").unwrap();
    b.cli(&["flush"]);
    std::thread::sleep(std::time::Duration::from_secs(2));
    assert!(!has(&c, "later.txt"));
}
