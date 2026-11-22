//! Freeing deleted files and old versions (`cleanup.rs`), with two
//! daemons that keep everything. Passes run every second and nothing is
//! too new to free, so the rules play out in seconds: old versions are
//! kept within the keep period; `free-space` frees them now; a version
//! freed here is restored from the other device; one freed everywhere is
//! refused; `keep-old 0` frees at the next pass.
//!
//! Skipped (with a message) when `/dev/fuse` or `fusermount3` is missing.

mod common;

use common::*;
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

/// Version `n`'s line of `cardinal history`.
fn version_line(d: &Dev, path: &str, n: usize) -> String {
    let h = d.cli(&["history", &d.p(path).display().to_string()]);
    h.lines()
        .find(|l| l.trim_start().starts_with(&format!("{n} ")))
        .unwrap_or_else(|| panic!("no version {n}:\n{h}"))
        .to_owned()
}

fn old_bytes(d: &Dev) -> u64 {
    d.status()["old"]["bytes"].as_u64().unwrap_or(0)
}

#[test]
fn old_versions_are_kept_then_freed() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut a = Dev::new(root.path(), "alpha", free_port());
    let mut b = Dev::new(root.path(), "beta", free_port());
    for d in [&mut a, &mut b] {
        d.env
            .push(("CARDINAL_TEST_FREE_INTERVAL_MS".into(), "1000".into()));
        d.env
            .push(("CARDINAL_TEST_FREE_MIN_AGE_MS".into(), "0".into()));
    }
    a.start();
    a.cli(&["init", "--yes", "--name", "alpha"]);
    a.wait_mounted();
    b.start();
    pair(&a, &b);

    let (va, vb, vg) = (
        content(600 << 10, 1),
        content(600 << 10, 2),
        content(300 << 10, 3),
    );
    let synced = |d: &Dev, name: &str, want: &[u8]| {
        wait(&format!("{} has {name}", d.name), 40, || {
            std::fs::read(d.p(name)).ok().as_deref() == Some(want)
        });
    };
    // Version 1, then 2, of a.bin; g.bin written and deleted.
    std::fs::write(a.p("a.bin"), &va).unwrap();
    a.cli(&["flush"]);
    synced(&b, "a.bin", &va);
    std::fs::write(a.p("a.bin"), &vb).unwrap();
    std::fs::write(a.p("g.bin"), &vg).unwrap();
    a.cli(&["flush"]);
    synced(&b, "a.bin", &vb);
    synced(&b, "g.bin", &vg);
    std::fs::remove_file(a.p("g.bin")).unwrap();
    a.cli(&["flush"]);
    wait("beta sees g.bin deleted", 40, || !b.p("g.bin").exists());

    // Passes run, but within 30 days nothing old is freed.
    wait("alpha counts the old versions", 20, || {
        old_bytes(&a) > 900 << 10
    });
    std::thread::sleep(Duration::from_secs(3));
    assert!(old_bytes(&a) > 900 << 10);
    assert!(!version_line(&a, "a.bin", 1).contains("not on this device"));
    let st = a.cli(&["status"]);
    eprintln!("---- alpha keeps old versions ----\n{st}");
    assert!(st.contains("Old versions: "), "{st}");
    assert!(
        st.contains("kept 30 days (`cardinal free-space` frees them now)"),
        "{st}"
    );

    // Free them now, on alpha only.
    let before = dir_size(&a.home.join("blobs"));
    let out = a.cli(&["free-space", "--yes"]);
    eprintln!("---- free-space ----\n{out}");
    assert!(out.starts_with("This frees "), "{out}");
    assert!(out.contains("Freed "), "{out}");
    assert!(dir_size(&a.home.join("blobs")) + (800 << 10) < before);
    assert_eq!(old_bytes(&a), 0);
    assert!(!a.cli(&["status"]).contains("Old versions:"));
    assert!(version_line(&a, "a.bin", 1).contains("(not on this device)"));
    assert!(a
        .cli(&["free-space", "--yes"])
        .contains("Nothing to free now."));

    // Version 1 comes back from beta, which still keeps it.
    a.cli(&[
        "restore",
        &a.p("a.bin").display().to_string(),
        "--version",
        "1",
    ]);
    synced(&a, "a.bin", &va);
    synced(&b, "a.bin", &va);

    // Version 2 is now old on both; freed on both, it cannot come back.
    for d in [&a, &b] {
        d.cli(&["free-space", "--yes"]);
    }
    let o = a.try_cli(&[
        "restore",
        &a.p("a.bin").display().to_string(),
        "--version",
        "2",
    ]);
    let err = String::from_utf8_lossy(&o.stderr).into_owned();
    assert!(!o.status.success());
    assert!(
        err.contains("version 2 of a.bin is no longer kept"),
        "{err}"
    );
    assert_eq!(std::fs::read(a.p("a.bin")).unwrap(), va, "unchanged");

    // Keeping nothing: the next pass frees what is replaced.
    assert!(!a.try_cli(&["keep-old", "soon"]).status.success());
    let out = a.cli(&["keep-old", "0"]);
    assert!(
        out.contains("now keeps deleted files and old versions for 0 days"),
        "{out}"
    );
    std::fs::write(a.p("a.bin"), content(600 << 10, 4)).unwrap();
    a.cli(&["flush"]);
    wait("alpha frees version 3 by itself", 20, || {
        version_line(&a, "a.bin", 3).contains("(not on this device)")
    });
    let out = a.cli(&["keep-old", "forever"]);
    assert!(
        out.contains("keeps deleted files and old versions forever"),
        "{out}"
    );
}

/// The files space's line of `space-usage`.
fn files_usage(d: &Dev) -> serde_json::Value {
    let r = ask(d, &serde_json::json!({"cmd": "space-usage"}));
    let all = r["spaces"].as_array().cloned().unwrap_or_default();
    all.into_iter()
        .find(|s| s["name"] == "files" || s["name"] == "Cardinal")
        .unwrap_or_else(|| panic!("no files space in {r}"))
}

/// What history costs, and emptying it (D85): each space held is counted
/// as live chunks, history-only chunks and its log, for what this device
/// holds; a device that keeps old versions for some days says so, in the
/// account placement too; and "empty now" drops the history-only chunks
/// of a space at once, with no copy check, leaving what is current.
#[test]
fn history_is_counted_and_emptied_at_once() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut a = Dev::new(root.path(), "alpha", free_port());
    a.env
        .push(("CARDINAL_TEST_FREE_MIN_AGE_MS".into(), "0".into()));
    a.start();
    a.cli(&["init", "--yes", "--name", "alpha"]);
    a.wait_mounted();
    let (v1, v2) = (content(600 << 10, 11), content(300 << 10, 12));
    std::fs::write(a.p("h.bin"), &v1).unwrap();
    a.cli(&["flush"]);
    let first = files_usage(&a);
    assert!(
        first["live_bytes"].as_u64().unwrap() >= 600 << 10,
        "{first}"
    );
    assert_eq!(first["history_bytes"], 0, "{first}");
    assert!(first["log_bytes"].as_u64().unwrap() > 0, "{first}");
    assert_eq!(first["full"], true);
    // by convention old versions are kept 30 days: history for 30 days
    assert_eq!(first["retention"], "history-days", "{first}");
    assert_eq!(first["history_days"], 30, "{first}");

    // a new version: the first is history only
    std::fs::write(a.p("h.bin"), &v2).unwrap();
    a.cli(&["flush"]);
    let second = files_usage(&a);
    let history = second["history_bytes"].as_u64().unwrap();
    assert!(history >= 600 << 10, "{second}");
    assert!(
        second["live_bytes"].as_u64().unwrap() >= 300 << 10,
        "{second}"
    );
    assert!(
        second["live_bytes"].as_u64().unwrap() < 600 << 10,
        "{second}"
    );

    // empty now, for that space alone
    let space = second["space"].as_str().unwrap().to_owned();
    let out = ask(
        &a,
        &serde_json::json!({"cmd": "history-empty", "space": space}),
    );
    assert!(out["bytes"].as_u64().unwrap() >= 600 << 10, "{out}");
    let after = files_usage(&a);
    assert_eq!(after["history_bytes"], 0, "{after}");
    assert_eq!(
        after["live_bytes"], second["live_bytes"],
        "the current file stays"
    );
    assert_eq!(std::fs::read(a.p("h.bin")).unwrap(), v2);
    assert!(version_line(&a, "h.bin", 1).contains("(not on this device)"));

    // kept forever is history; kept for no days is full
    a.cli(&["keep-old", "forever"]);
    assert_eq!(files_usage(&a)["retention"], "history");
    a.cli(&["keep-old", "0"]);
    let none = files_usage(&a);
    assert_eq!(none["retention"], "full");
    assert!(none["history_days"].is_null(), "{none}");
    // a space that is not held is refused
    let r = reply(
        &a,
        &serde_json::json!({"cmd": "history-empty", "space": "zz"}),
    );
    assert_eq!(r["ok"], false, "{r}");

    // One space's period in place of the device's: history kept forever,
    // but none of the files space's old versions kept.
    a.cli(&["keep-old", "forever"]);
    std::fs::write(a.p("h.bin"), content(200 << 10, 13)).unwrap();
    a.cli(&["flush"]);
    assert!(files_usage(&a)["history_bytes"].as_u64().unwrap() > 0);
    let out = ask(
        &a,
        &serde_json::json!({"cmd": "keep-old", "keep": "7", "space": space}),
    );
    assert_eq!(out["keep"], "7 days", "{out}");
    let files = files_usage(&a);
    assert_eq!(files["retention"], "history-days", "{files}");
    assert_eq!(files["history_days"], 7, "{files}");
    let r = ask(&a, &serde_json::json!({"cmd": "space-usage"}));
    let others: Vec<serde_json::Value> = r["spaces"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s["space"] != space.as_str())
        .cloned()
        .collect();
    assert!(!others.is_empty(), "{r}");
    for o in &others {
        assert_eq!(o["retention"], "history", "{o}");
    }
    let o = a.cli(&["keep-old", "0", "--space", &space]);
    assert!(o.contains("for 0 days"), "{o}");
    wait("the files space's old version is freed", 20, || {
        files_usage(&a)["history_bytes"] == 0
    });
    assert_eq!(files_usage(&a)["retention"], "full");
    let r = ask(&a, &serde_json::json!({"cmd": "space-usage"}));
    for o in r["spaces"].as_array().unwrap() {
        if o["space"] != space.as_str() {
            assert_eq!(o["retention"], "history", "{o}");
        }
    }
    // a space that is not held is refused
    let r = reply(
        &a,
        &serde_json::json!({"cmd": "keep-old", "keep": "7", "space": "zz"}),
    );
    assert_eq!(r["ok"], false, "{r}");
}
