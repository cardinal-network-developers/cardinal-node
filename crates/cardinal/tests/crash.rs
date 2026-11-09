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
    wait("it is committed", 30, || {
        a.status()["pending_changes"] == false
    });
    a.stop();
    a.start();
    a.wait_mounted();
    assert_eq!(
        read(&a.p("drafts/letter.txt")).as_deref(),
        Some("flushed before the crash")
    );
}

#[test]
fn a_stop_while_saving_fails_keeps_what_was_written() {
    use std::os::unix::fs::PermissionsExt;
    if !fuse_available() {
        eprintln!("no FUSE here; skipped");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut a = Dev::new(root.path(), "ana", free_port());
    a.start();
    a.cli(&["init", "--yes", "--name", "ana"]);
    a.wait_mounted();
    // saving fails, as on a full disk
    let tmp = a.home.join("blobs").join("tmp");
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o555)).unwrap();
    let mut f = std::fs::File::create(a.p("kept.txt")).unwrap();
    f.write_all(&vec![b'x'; 100_000]).unwrap();
    f.sync_all().unwrap();
    drop(f);
    wait("a commit fails", 20, || {
        a.log().contains("cannot save changes")
    });
    a.stop();
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).unwrap();
    a.start();
    a.wait_mounted();
    wait("the file is back", 30, || {
        std::fs::read(a.p("kept.txt")).is_ok_and(|b| b.len() == 100_000)
    });
    wait("it is committed", 30, || {
        a.status()["pending_changes"] == false
    });
}

#[test]
fn an_edit_taken_up_after_a_crash_keeps_one_made_elsewhere_meanwhile() {
    if !fuse_available() {
        eprintln!("no FUSE here; skipped");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut a = Dev::new(root.path(), "alpha", free_port());
    let mut b = Dev::new(root.path(), "beta", free_port());
    a.start();
    a.cli(&["init", "--yes", "--name", "alpha"]);
    a.wait_mounted();
    b.start();
    pair(&a, &b);
    b.wait_mounted();
    std::fs::write(a.p("doc.txt"), b"first").unwrap();
    a.cli(&["flush"]);
    wait("beta has it", 30, || {
        read(&b.p("doc.txt")).as_deref() == Some("first")
    });
    // beta edits and flushes, and dies before it commits
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(b.p("doc.txt"))
        .unwrap();
    f.write_all(b"beta's edit").unwrap();
    f.sync_all().unwrap();
    kill(&mut b);
    drop(f);
    // alpha edits it meanwhile
    std::fs::write(a.p("doc.txt"), b"alpha's edit").unwrap();
    a.cli(&["flush"]);
    wait("alpha committed", 30, || {
        a.status()["pending_changes"] == false
    });
    // beta hears of alpha's edit before it takes its own up again, at mount
    b.start_with(&["--no-mount"]);
    let history = |d: &Dev| d.cli(&["history", "doc.txt"]);
    wait("beta has alpha's edit", 30, || history(&b) == history(&a));
    b.cli(&["mount", b.mount.to_str().unwrap()]);
    b.wait_mounted();
    let versions = |d: &Dev| -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(&d.mount)
            .map(|rd| {
                rd.flatten()
                    .filter(|e| e.file_name().to_string_lossy().starts_with("doc"))
                    .filter_map(|e| read(&e.path()))
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    };
    wait("both edits are kept, on both devices", 60, || {
        let want = vec!["alpha's edit".to_owned(), "beta's edit".to_owned()];
        versions(&a) == want && versions(&b) == want
    });
}
