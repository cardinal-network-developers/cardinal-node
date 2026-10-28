//! Two devices fetch new content from a slow third at the same time.
//! Alpha holds the data and serves slowly (a laptop on Wi-Fi); beta and
//! gamma (full retention, fast between them) are connected to alpha and to
//! each other. Each fetches in its own order, so they pull different parts
//! from alpha and find much of the rest at each other: alpha should send
//! the data about once, not once per device (as it did when both fetched
//! in the same order).
//!
//! Skipped (with a message) when `/dev/fuse` or `fusermount3` is missing.

mod common;

use common::*;
use std::time::{Duration, Instant};

/// Distinct, incompressible content of `len` bytes.
fn content(seed: u64, len: usize) -> Vec<u8> {
    let mut x: u64 = 0x9e3779b97f4a7c15 ^ seed.wrapping_mul(0x2545f4914f6cdd1d);
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

/// The files: one large file (decorrelated within) and many medium ones.
fn files() -> Vec<(String, Vec<u8>)> {
    let mut v = vec![("big.bin".to_owned(), content(1000, 40 << 20))];
    for i in 0..20 {
        let len = (1 << 20) + (i * 211 * 1024) % (3 << 20);
        v.push((format!("photos/{i:02}.bin"), content(i as u64, len)));
    }
    v
}

/// What `of` reports about `name` as a blob source: bytes received.
fn received(of: &serde_json::Value, name: &str) -> u64 {
    of["devices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"] == name)
        .and_then(|d| d["fetch"]["received"].as_u64())
        .unwrap_or(0)
}

fn complete(d: &Dev, total: u64) -> bool {
    let s = d.status();
    let p = &s["progress"];
    p["bytes_wanted"].as_u64() == Some(total)
        && p["files_pending"].as_u64() == Some(0)
        && p["bytes_pending"].as_u64() == Some(0)
        && p["last_error"].is_null()
}

fn online_others(d: &Dev) -> usize {
    d.status()["devices"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|d| d["this"].as_bool() != Some(true) && d["online"].as_bool() == Some(true))
        .count()
}

#[test]
fn slow_source_sends_once() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut a = Dev::new(root.path(), "alpha", free_port());
    let mut b = Dev::new(root.path(), "beta", free_port());
    let mut c = Dev::new(root.path(), "gamma", free_port());

    // Alpha sends 1 MiB per 80 ms, to everyone together.
    a.env
        .push(("CARDINAL_TEST_BLOB_DELAY_MS".into(), "80".into()));
    a.start();
    let out = a.cli(&["init", "--yes", "--name", "alpha"]);
    assert!(out.contains("Set up"), "{out}");
    a.wait_mounted();

    // Beta and gamma know each other's address (and alpha's).
    for (d, other) in [(&b, c.port), (&c, b.port)] {
        std::fs::write(
            d.home.join("config.toml"),
            format!(
                "[daemon]\npeers = [\"127.0.0.1:{}\", \"127.0.0.1:{other}\"]\n",
                a.port
            ),
        )
        .unwrap();
    }
    b.start();
    pair(&a, &b);
    c.start();
    pair(&a, &c);
    for d in [&a, &b, &c] {
        wait(&format!("{} reaches both others", d.name), 30, || {
            online_others(d) == 2
        });
    }

    // The new content arrives while beta and gamma are off, so they start
    // fetching together when they come back.
    b.stop();
    c.stop();
    let files = files();
    std::fs::create_dir_all(a.p("photos")).unwrap();
    let mut total = 0u64;
    for (name, data) in &files {
        total += data.len() as u64;
        std::fs::write(a.p(name), data).unwrap();
    }
    a.cli(&["flush"]);
    wait("alpha committed", 60, || {
        a.status()["pending_changes"].as_bool() == Some(false)
    });

    let t0 = Instant::now();
    b.start();
    c.start();
    let (mut done_b, mut done_c) = (None, None);
    wait("beta and gamma have everything", 90, || {
        if done_b.is_none() && complete(&b, total) {
            done_b = Some(t0.elapsed());
        }
        if done_c.is_none() && complete(&c, total) {
            done_c = Some(t0.elapsed());
        }
        done_b.is_some() && done_c.is_some()
    });
    let (sb, sc) = (b.status(), c.status());
    let from_alpha = received(&sb, "alpha") + received(&sc, "alpha");
    let ratio = from_alpha as f64 / total as f64;
    let (b_from_c, c_from_b) = (received(&sb, "gamma"), received(&sc, "beta"));
    eprintln!(
        "MEASURE fetch order: {} MiB to two devices; alpha sent {ratio:.2}x the data \
         (beta {:.2}, gamma {:.2}); beta got {:.2} from gamma, gamma {:.2} from beta; \
         done in {:?} and {:?}",
        total >> 20,
        received(&sb, "alpha") as f64 / total as f64,
        received(&sc, "alpha") as f64 / total as f64,
        b_from_c as f64 / total as f64,
        c_from_b as f64 / total as f64,
        done_b.unwrap(),
        done_c.unwrap(),
    );

    // Everything is on each: readable with the others stopped.
    a.stop();
    c.stop();
    let verify = |d: &Dev| {
        d.wait_mounted();
        for (name, data) in &files {
            let got = std::fs::read(d.p(name)).unwrap();
            assert!(got == *data, "{} {name}", d.name);
        }
    };
    verify(&b);
    b.stop();
    c.start();
    verify(&c);

    assert!(ratio < 1.5, "alpha sent {ratio:.2}x the data");
    // One of them usually leads and takes more from alpha; each still
    // gets a good part from the other.
    for (who, got) in [("beta", b_from_c), ("gamma", c_from_b)] {
        assert!(
            got as f64 > 0.1 * total as f64,
            "{who} got only {got} of {total} bytes from the other fast device"
        );
    }
    let took = done_b.unwrap().max(done_c.unwrap());
    assert!(took < Duration::from_secs(40), "took {took:?}");
}
