//! A device over its on-demand budget drops a file's pieces only once a
//! device that keeps everything produces them, and says what it could not
//! free (`blobs.md#dropping-a-chunk`, core D54).

mod common;

use common::*;

fn content(len: usize, seed: u64) -> Vec<u8> {
    let mut x = 0x9e37_79b9_7f4a_7c15 ^ seed;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

#[test]
fn a_device_over_its_budget_keeps_what_no_full_holder_has() {
    if !fuse_available() {
        eprintln!("no FUSE here; skipped");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut a = Dev::new(root.path(), "alpha", free_port());
    let mut b = Dev::new(root.path(), "beta", free_port());
    std::fs::write(
        b.home.join("config.toml"),
        "[daemon]\nretention = \"on-demand\"\non_demand_budget = 1\n",
    )
    .unwrap();
    b.env
        .push(("CARDINAL_TEST_FREE_MIN_AGE_MS".into(), "0".into()));
    a.start();
    a.cli(&["init", "--yes", "--name", "alpha"]);
    a.wait_mounted();
    b.start();
    pair(&a, &b);
    b.wait_mounted();

    // Beta writes while alpha, which keeps everything, is away.
    a.stop();
    let data = content(3 << 20, 1);
    std::fs::write(b.p("video.bin"), &data).unwrap();
    b.cli(&["flush"]);
    wait("beta committed", 30, || {
        b.status()["pending_changes"].as_bool() == Some(false)
    });
    let blobs = b.home.join("blobs");
    let held = dir_size(&blobs);
    let out = b.cli(&["free-space", "--yes"]);
    assert!(out.contains("cannot be reached now"), "{out}");
    assert!(dir_size(&blobs) >= held, "nothing of it was dropped");
    assert_eq!(b.status()["old"]["unchecked"], true);

    // Once alpha has it, beta can drop its pieces, and still read the file.
    a.start();
    a.wait_mounted();
    wait("alpha has the file", 60, || {
        std::fs::read(a.p("video.bin")).is_ok_and(|got| got == data)
    });
    wait("beta drops what alpha keeps", 60, || {
        let out = b.cli(&["free-space", "--yes"]);
        !out.contains("not on your other devices yet")
    });
    assert!(
        dir_size(&blobs) + (2 << 20) < held,
        "{} of {held}",
        dir_size(&blobs)
    );
    assert_eq!(b.status()["old"]["only_here"]["files"], 0);
    assert_eq!(b.status()["old"]["unchecked"], false);
    // read on demand again, and flushed into place soon after, not left in tmp
    assert_eq!(std::fs::read(b.p("video.bin")).unwrap(), data);
    wait("what was read is flushed", 10, || {
        std::fs::read_dir(blobs.join("tmp")).is_ok_and(|d| d.count() == 0)
    });
}
