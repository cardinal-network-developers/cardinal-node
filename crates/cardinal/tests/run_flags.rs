//! Flags for one run stay with that run: `--no-mount` holds however the
//! settings are read again, and whatever saves them does not make it
//! permanent.
//!
//! Skipped (with a message) when `/dev/fuse` or `fusermount3` is missing.

mod common;

use common::*;

#[test]
fn no_mount_lasts_one_run() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut d = Dev::new(root.path(), "alpha", free_port());
    d.start_with(&["--no-mount"]);
    // Setting up reads the settings again, and hosting saves them.
    d.cli(&["init", "--yes", "--name", "alpha"]);
    d.cli(&["host", "--address", &format!("127.0.0.1:{}", d.port)]);
    std::thread::sleep(std::time::Duration::from_secs(2));
    assert!(d.status()["mounted"].is_null(), "{}", d.status());
    assert!(!std::fs::read_to_string(d.home.join("daemon.log"))
        .unwrap()
        .contains("mounted your files"));

    d.stop();
    d.start();
    d.wait_mounted();
}
