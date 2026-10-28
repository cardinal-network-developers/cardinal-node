//! Three devices on one machine: alpha holds a set of files, beta (on
//! demand) only part of them, both answer slowly, and gamma joins with
//! full retention and fetches from both at once. Gamma must not stall on what
//! beta lacks or on beta's slowness, and must end with every file intact.
//!
//! Skipped (with a message) when `/dev/fuse` or `fusermount3` is missing.

mod common;

use common::*;
use std::time::{Duration, Instant};

fn content(i: usize) -> Vec<u8> {
    let len = 300 * 1024 + (i * 97 * 1024) % (900 * 1024);
    let mut x: u64 = 0x9e3779b97f4a7c15 ^ (i as u64 + 1);
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.extend_from_slice(&x.to_le_bytes());
    }
    out.truncate(len);
    out
}

#[test]
fn fetch_from_several_devices() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    const FILES: usize = 40;
    let root = tempfile::tempdir().unwrap();
    let mut a = Dev::new(root.path(), "alpha", free_port());
    let mut b = Dev::new(root.path(), "beta", free_port());
    let mut c = Dev::new(root.path(), "gamma", free_port());

    // Both others serve slowly (about 5 MB/s each), so gamma is still
    // fetching when it reaches beta.
    a.env
        .push(("CARDINAL_TEST_BLOB_DELAY_MS".into(), "200".into()));
    a.start();
    let out = a.cli(&["init", "--yes", "--name", "alpha"]);
    assert!(out.contains("Set up"), "{out}");
    a.wait_mounted();
    std::fs::create_dir_all(a.p("photos")).unwrap();
    let mut total = 0u64;
    for i in 0..FILES {
        let data = content(i);
        total += data.len() as u64;
        std::fs::write(a.p(&format!("photos/{i:02}.bin")), data).unwrap();
    }
    a.cli(&["flush"]);
    wait("alpha committed", 60, || {
        a.status()["pending_changes"].as_bool() == Some(false)
    });

    // Beta keeps only what is opened, and serves slowly.
    std::fs::write(
        b.home.join("config.toml"),
        "[daemon]\nretention = \"on-demand\"\n",
    )
    .unwrap();
    b.env
        .push(("CARDINAL_TEST_BLOB_DELAY_MS".into(), "200".into()));
    b.start();
    pair(&a, &b);
    b.wait_mounted();
    wait("beta sees the files", 30, || {
        std::fs::read_dir(b.p("photos")).is_ok_and(|d| d.count() == FILES)
    });
    for i in (0..FILES).step_by(2) {
        let got = std::fs::read(b.p(&format!("photos/{i:02}.bin"))).unwrap();
        assert_eq!(got, content(i), "beta read {i}");
    }

    // Gamma reaches both.
    std::fs::write(
        c.home.join("config.toml"),
        format!(
            "[daemon]\npeers = [\"127.0.0.1:{}\", \"127.0.0.1:{}\"]\n",
            a.port, b.port
        ),
    )
    .unwrap();
    c.start();
    pair(&a, &c);
    let t0 = Instant::now();
    let mut line = String::new();
    wait("gamma has everything", 60, || {
        let s = c.status();
        let p = &s["progress"];
        if p["files_pending"].as_u64().unwrap_or(0) > 0 && line.is_empty() {
            line = c.cli(&["status"]);
        }
        p["bytes_wanted"].as_u64() == Some(total)
            && p["files_pending"].as_u64() == Some(0)
            && p["bytes_pending"].as_u64() == Some(0)
            && p["last_error"].is_null()
    });
    let took = t0.elapsed();
    let s = c.status();
    let online = s["devices"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|d| d["this"].as_bool() != Some(true) && d["online"].as_bool() == Some(true))
        .count();
    assert_eq!(online, 2, "gamma reached alpha and beta: {s}");
    let replies = |name: &str| {
        s["devices"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["name"] == name)
            .and_then(|d| d["fetch"]["replies"].as_u64())
            .unwrap_or(0)
    };
    assert!(
        replies("alpha") > 0 && replies("beta") > 0,
        "gamma fetched from both: {s}"
    );
    eprintln!(
        "MEASURE three devices: {} MiB fetched by gamma in {took:?}",
        total >> 20
    );
    if !line.is_empty() {
        assert!(line.contains("Sync: fetching"), "{line}");
    }

    // Everything is on gamma: readable with both others stopped.
    a.stop();
    b.stop();
    c.wait_mounted();
    for i in 0..FILES {
        let got = std::fs::read(c.p(&format!("photos/{i:02}.bin"))).unwrap();
        assert_eq!(got, content(i), "gamma file {i}");
    }
    assert!(took < Duration::from_secs(45), "took {took:?}");
}
