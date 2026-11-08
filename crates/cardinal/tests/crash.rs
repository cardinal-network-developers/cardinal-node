//! A daemon killed in the middle of things, as a crash would (`kill -9`),
//! keeps what an application flushed, and commits it when it starts again
//! (`profiles.md#mapping-to-a-disk-guidance`, core D54).

mod common;

use std::io::Write;

use common::*;

fn kill(d: &mut Dev) {
    if let Some(mut c) = d.child.take() {
        c.kill().unwrap(); // SIGKILL
        c.wait().unwrap();
    }
    let _ = std::process::Command::new("fusermount3")
        .args(["-u", "-z"])
        .arg(&d.mount)
        .status();
}

#[test]
fn what_an_application_flushed_survives_a_kill() {
    if !fuse_available() {
        eprintln!("no FUSE here; skipped");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut a = Dev::new(root.path(), "ana", free_port());
    a.start();
    a.cli(&["init", "--yes", "--name", "ana"]);
    a.wait_mounted();
    std::fs::create_dir(a.p("drafts")).unwrap();
    // flushed, and killed well inside the 200 ms the folder waits to commit
    let mut f = std::fs::File::create(a.p("drafts/letter.txt")).unwrap();
    f.write_all(b"flushed before the crash").unwrap();
    f.sync_all().unwrap();
    kill(&mut a);
    drop(f);
    a.start();
    a.wait_mounted();
    wait("the flushed file is back", 30, || {
        read(&a.p("drafts/letter.txt")).as_deref() == Some("flushed before the crash")
    });
    assert!(a.log().contains("taking up 1 flushed files"), "{}", a.log());
    // and it is committed, not only staged again
    wait("it is committed", 30, || a.status()["pending_changes"] == false);
    a.stop();
    a.start();
    a.wait_mounted();
    assert_eq!(
        read(&a.p("drafts/letter.txt")).as_deref(),
        Some("flushed before the crash")
    );
}
