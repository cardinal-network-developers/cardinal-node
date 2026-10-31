//! Devices talk over UDP, and over TCP with one that does not listen there:
//! an older device, or a network that blocks UDP.
//!
//! Skipped (with a message) when `/dev/fuse` or `fusermount3` is missing.

mod common;

use common::*;

/// What `from` says its session with `name` runs over.
fn carrier(from: &Dev, name: &str) -> String {
    let v = from.status();
    let d = v["devices"].as_array().unwrap();
    let d = d.iter().find(|d| d["name"] == name).unwrap();
    d["carrier"].as_str().unwrap_or_default().to_owned()
}

#[test]
fn udp_where_it_works_and_tcp_where_it_does_not() {
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
    c.start_with(&["--no-udp"]);
    pair(&a, &c);
    b.wait_mounted();
    c.wait_mounted();

    wait("alpha reaches beta over UDP", 20, || {
        carrier(&a, "beta") == "UDP"
    });
    wait("alpha reaches gamma over TCP", 20, || {
        carrier(&a, "gamma") == "TCP"
    });

    // A file big enough for chunks, each way.
    let big: Vec<u8> = (0..4_000_000u32).map(|n| (n * 13 % 251) as u8).collect();
    std::fs::write(a.p("big.bin"), &big).unwrap();
    a.cli(&["flush"]);
    wait("beta has it, over UDP", 30, || {
        std::fs::read(b.p("big.bin")).is_ok_and(|x| x == big)
    });
    wait("gamma has it, over TCP", 30, || {
        std::fs::read(c.p("big.bin")).is_ok_and(|x| x == big)
    });
    std::fs::write(b.p("back.txt"), "back\n").unwrap();
    b.cli(&["flush"]);
    wait("alpha has beta's file", 20, || {
        std::fs::read(a.p("back.txt")).is_ok_and(|x| x == b"back\n")
    });
}
