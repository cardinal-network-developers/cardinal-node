//! News passes through devices (`sync.md#notices`): with alpha between
//! beta and gamma, which cannot reach each other, what one writes reaches
//! the other at once, not at the next periodic reconcile. Small changes go
//! as objects, large ones as heads.
//!
//! Skipped (with a message) when `/dev/fuse` or `fusermount3` is missing.

mod common;

use common::*;

/// Far less than the periodic reconcile (three minutes).
const SOON: u64 = 15;

#[test]
fn news_passes_through_a_device_between_two_others() {
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
    assert!(pair_as(&a, &b, true, None).contains("Added"));
    c.start();
    pair(&a, &c);
    b.wait_mounted();
    c.wait_mounted();

    // A small change, each way.
    std::fs::write(b.p("from-beta.txt"), "beta\n").unwrap();
    b.cli(&["flush"]);
    wait("gamma has beta's file", SOON, || {
        std::fs::read(c.p("from-beta.txt")).is_ok_and(|x| x == b"beta\n")
    });
    std::fs::write(c.p("from-gamma.txt"), "gamma\n").unwrap();
    c.cli(&["flush"]);
    wait("beta has gamma's file", SOON, || {
        std::fs::read(b.p("from-gamma.txt")).is_ok_and(|x| x == b"gamma\n")
    });

    // A large one: too big for a notice to carry.
    std::fs::create_dir(b.p("many")).unwrap();
    for n in 0..60 {
        std::fs::write(b.p(&format!("many/{n}.txt")), format!("file {n}\n")).unwrap();
    }
    b.cli(&["flush"]);
    wait("gamma has beta's files", SOON, || {
        std::fs::read_dir(c.p("many")).is_ok_and(|d| d.count() == 60)
    });

    // The identity log too: what beta changes there reaches gamma.
    let mut d = Dev::new(root.path(), "delta", free_port());
    d.start();
    pair(&b, &d);
    wait("gamma knows of delta", SOON, || {
        c.status()["devices"]
            .as_array()
            .is_some_and(|v| v.len() == 4)
    });
}
