//! Removing a device (`spaces.md#when-to-rotate`): every remaining device
//! moves to keys it never held at once, before anyone writes, and what is
//! written after that reaches them all.
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

    // Gamma is cut off: it hears none of this.
    assert_eq!(epoch(&c), old);
    assert!(!c.p("after.txt").exists());
}
