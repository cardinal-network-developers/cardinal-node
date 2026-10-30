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
