//! Counting copies (`blobs.md#counting-copies`) and the speed test, with
//! two daemons on one machine that both keep everything. Checks run
//! every 1.5 s and count content older than 2 s, so the rules play out in
//! seconds: a lone device warns; a second device is counted once it
//! passes checks; one that loses its disk fails checks while it fetches
//! everything again, and comes back once it has. Alpha serves pieces
//! slowly (3 s per MiB), so the fetch takes seconds and a check sees it.
//!
//! Skipped (with a message) when `/dev/fuse` or `fusermount3` is missing.

mod common;

use common::*;
use serde_json::Value;
use std::time::Duration;

fn content(len: usize, seed: u64) -> Vec<u8> {
    let mut x: u64 = 0x9e3779b97f4a7c15 ^ seed;
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

fn copies(d: &Dev) -> Value {
    d.status()["copies"].clone()
}

fn state_of(d: &Dev, name: &str) -> String {
    copies(d)["holders"]
        .as_array()
        .and_then(|a| a.iter().find(|h| h["name"] == name).cloned())
        .and_then(|h| h["state"].as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// Stops a device, deletes its chunks (a lost disk), and starts it again:
/// it fetches everything again.
fn lose_disk(d: &mut Dev) {
    d.stop();
    std::fs::remove_dir_all(d.home.join("blobs")).unwrap();
    d.start();
}

#[test]
fn copies_and_speedtest() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut a = Dev::new(root.path(), "alpha", free_port());
    let mut b = Dev::new(root.path(), "beta", free_port());
    for d in [&mut a, &mut b] {
        for (k, v) in [
            ("CARDINAL_TEST_CHECK_INTERVAL_MS", "1500"),
            ("CARDINAL_TEST_CHECK_MIN_AGE_MS", "2000"),
            ("CARDINAL_TEST_SPEEDTEST_MS", "1000"),
        ] {
            d.env.push((k.into(), v.into()));
        }
    }
    a.env
        .push(("CARDINAL_TEST_BLOB_DELAY_MS".into(), "3000".into()));
    a.start();
    let out = a.cli(&["init", "--yes", "--name", "alpha"]);
    assert!(out.contains("Set up"), "{out}");
    a.wait_mounted();
    // About 32 chunks and an index.
    std::fs::write(a.p("photo.bin"), content(2 << 20, 1)).unwrap();
    a.cli(&["flush"]);

    // Alone, alpha says its files are only here.
    wait("alpha counts itself", 20, || {
        let c = copies(&a);
        c["count"] == 1 && c["blobs"] == 1
    });
    let st = a.cli(&["status"]);
    eprintln!("---- alpha alone ----\n{st}");
    assert!(st.contains("Copies: 1 — this device"), "{st}");
    assert!(
        st.contains(
            "Your files are only on this device. Keep a copy on another device: run \
             `cardinal pair` on it."
        ),
        "{st}"
    );

    // Beta joins and fetches the file; both devices see two copies.
    b.start();
    pair(&a, &b);
    wait("alpha counts beta", 40, || copies(&a)["count"] == 2);
    wait("beta counts alpha", 40, || copies(&b)["count"] == 2);
    let st = a.cli(&["status"]);
    eprintln!("---- alpha with beta ----\n{st}");
    assert!(
        st.contains("Copies: 2 — this device, beta (checked "),
        "{st}"
    );
    assert!(!st.contains("only on this device"), "{st}");
    let full = a.status();
    eprintln!(
        "---- alpha copies (json) ----\n{}",
        serde_json::to_string_pretty(&full["copies"]).unwrap()
    );

    // A restart remembers what was seen: beta is never "not checked".
    a.stop();
    a.start();
    wait("alpha's copies after a restart", 20, || {
        !copies(&a).is_null()
    });
    assert_ne!(state_of(&a, "beta"), "unchecked");

    // Both devices reconnect after the restart; wait for the session to
    // settle (duplicate sessions can churn briefly).
    let beta_online = |a: &Dev| {
        a.status()["devices"]
            .as_array()
            .is_some_and(|d| d.iter().any(|d| d["name"] == "beta" && d["online"] == true))
    };
    wait("beta online after alpha's restart", 30, || {
        beta_online(&a) && {
            std::thread::sleep(Duration::from_secs(2));
            beta_online(&a)
        }
    });

    // The speed test, to every online device and to one by name.
    let out = a.cli(&["speedtest"]);
    eprintln!("---- speedtest ----\n{out}");
    assert!(out.starts_with("beta: receive "), "{out}");
    assert!(
        out.contains("/s, send ") && out.contains(", round trip "),
        "{out}"
    );
    let j: Value = serde_json::from_str(&b.cli(&["speedtest", "alpha", "--json"])).unwrap();
    assert_eq!(j[0]["device"], "alpha", "{j}");
    assert!(j[0]["receive"].as_u64().unwrap() > 0, "{j}");
    assert!(j[0]["send"].as_u64().unwrap() > 0, "{j}");
    assert!(j[0]["rtt_min_ms"].as_f64().unwrap() > 0.0, "{j}");
    let o = a.try_cli(&["speedtest", "alpha"]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("this device"));

    // Beta loses its disk, twice: alpha's checks find pieces missing while
    // beta fetches everything again, and count it once it has. Nothing is
    // declared, and fetching, however often, is not held against it.
    for round in 0..2 {
        lose_disk(&mut b);
        wait("alpha finds pieces missing on beta", 40, || {
            state_of(&a, "beta") == "failed"
        });
        let st = a.cli(&["status"]);
        eprintln!("---- beta rebuilding ({round}) ----\n{st}");
        assert!(st.contains("beta: not counted — did not have "), "{st}");
        assert!(
            st.contains(
                "Your files are only on this device until another device passes its checks."
            ),
            "{st}"
        );
        wait("beta counted again", 40, || copies(&a)["count"] == 2);
    }

    // A device without the speed test (0.1.3 and earlier) says so.
    b.env
        .push(("CARDINAL_TEST_NO_SPEEDTEST".into(), "1".into()));
    b.stop();
    b.start();
    wait("beta online again", 30, || {
        a.status()["devices"]
            .as_array()
            .is_some_and(|d| d.iter().any(|d| d["name"] == "beta" && d["online"] == true))
    });
    let out = a.cli(&["speedtest"]);
    assert_eq!(out.trim(), "beta runs an older version without speedtest");
}
