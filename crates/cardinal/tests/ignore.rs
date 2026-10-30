//! `.cardinalignore` (`fs/local.rs`), with two daemons: what it names
//! stays on alpha, survives a restart, and never reaches beta; moving
//! across the line syncs or unsyncs; changing a line syncs what it no
//! longer names; a folder deleted on beta that holds local items on alpha
//! stays on alpha.
//!
//! Skipped (with a message) when `/dev/fuse` or `fusermount3` is missing.

mod common;

use common::*;
use std::path::Path;

fn read(p: &Path) -> Option<Vec<u8>> {
    std::fs::read(p).ok()
}

fn pending(d: &Dev) -> bool {
    d.status()["pending_changes"].as_bool().unwrap_or(true)
}

#[test]
fn ignored_paths_stay_on_this_device() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
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
    let synced = |d: &Dev, p: &str, want: &[u8]| {
        wait(&format!("{} has {p}", d.name), 40, || {
            read(&d.p(p)).as_deref() == Some(want)
        });
    };

    // Lines at the top and in a project; files on both sides of them.
    std::fs::write(a.p(".cardinalignore"), "target/\n*.tmp\n*.swp\n").unwrap();
    std::fs::create_dir_all(a.p("proj/src")).unwrap();
    std::fs::write(a.p("proj/.cardinalignore"), "!keep.tmp\n").unwrap();
    std::fs::write(a.p("proj/src/main.rs"), "fn main() {}\n").unwrap();
    std::fs::write(a.p("proj/keep.tmp"), "kept\n").unwrap();
    std::fs::write(a.p("notes.tmp"), "only here\n").unwrap();
    std::fs::create_dir_all(a.p("proj/target/debug")).unwrap();
    std::fs::write(a.p("proj/target/debug/app"), vec![7u8; 300_000]).unwrap();
    // A build's churn: many files, renames, deletes.
    for n in 0..200 {
        let p = a.p(&format!("proj/target/debug/o{n}.tmp-part"));
        std::fs::write(&p, format!("object {n}")).unwrap();
        if n % 2 == 0 {
            std::fs::rename(&p, a.p(&format!("proj/target/debug/o{n}.o"))).unwrap();
        } else {
            std::fs::remove_file(&p).unwrap();
        }
    }
    a.cli(&["flush"]);
    synced(&b, "proj/src/main.rs", b"fn main() {}\n");
    synced(&b, "proj/keep.tmp", b"kept\n");
    synced(&b, ".cardinalignore", b"target/\n*.tmp\n*.swp\n");
    assert!(!b.p("proj/target").exists());
    assert!(!b.p("notes.tmp").exists());
    assert_eq!(read(&a.p("notes.tmp")).unwrap(), b"only here\n");
    assert_eq!(
        read(&a.p("proj/target/debug/app")).unwrap(),
        vec![7u8; 300_000]
    );
    assert_eq!(read(&a.p("proj/target/debug/o4.o")).unwrap(), b"object 4");
    assert!(!a.p("proj/target/debug/o5.tmp-part").exists());
    assert!(!pending(&a), "local items are not pending changes");

    // A restart keeps them.
    a.stop();
    a.start();
    a.wait_mounted();
    assert_eq!(read(&a.p("notes.tmp")).unwrap(), b"only here\n");
    assert_eq!(
        read(&a.p("proj/target/debug/app")).unwrap(),
        vec![7u8; 300_000]
    );
    let n = std::fs::read_dir(a.p("proj/target/debug")).unwrap().count();
    assert_eq!(n, 101, "app and 100 objects");

    // Moving across the line: local to synced, and synced to local.
    std::fs::rename(a.p("notes.tmp"), a.p("notes.txt")).unwrap();
    std::fs::rename(a.p("proj/src/main.rs"), a.p("proj/src/main.tmp")).unwrap();
    a.cli(&["flush"]);
    synced(&b, "notes.txt", b"only here\n");
    wait("beta loses main.rs", 40, || {
        !b.p("proj/src/main.rs").exists()
    });
    assert!(!b.p("proj/src/main.tmp").exists());
    assert_eq!(read(&a.p("proj/src/main.tmp")).unwrap(), b"fn main() {}\n");

    // An editor's save: write a local temporary, rename it over the file.
    std::fs::write(a.p("doc.txt"), "draft 1\n").unwrap();
    a.cli(&["flush"]);
    synced(&b, "doc.txt", b"draft 1\n");
    std::fs::write(a.p(".doc.txt.swp"), "draft 2\n").unwrap();
    std::fs::rename(a.p(".doc.txt.swp"), a.p("doc.txt")).unwrap();
    a.cli(&["flush"]);
    synced(&b, "doc.txt", b"draft 2\n");
    let h = a.cli(&["history", &a.p("doc.txt").display().to_string()]);
    assert!(h.contains("  2 "), "an edit, not a new file: {h}");

    // A line no longer there: what it named syncs.
    std::fs::write(a.p(".cardinalignore"), "target/\n*.swp\n").unwrap();
    a.cli(&["flush"]);
    synced(&b, "proj/src/main.tmp", b"fn main() {}\n");
    assert!(!b.p("proj/target").exists());

    // Beta deletes the project; alpha keeps what is local in it.
    std::fs::remove_dir_all(b.p("proj")).unwrap();
    b.cli(&["flush"]);
    wait("alpha loses proj/src", 40, || !a.p("proj/src").exists());
    assert_eq!(
        read(&a.p("proj/target/debug/app")).unwrap(),
        vec![7u8; 300_000]
    );
    assert!(!a.p("proj/keep.tmp").exists());
    std::thread::sleep(std::time::Duration::from_secs(2));
    a.cli(&["flush"]);
    assert!(!b.p("proj").exists(), "not created again on beta");
    // ...across a restart too.
    a.stop();
    a.start();
    a.wait_mounted();
    assert_eq!(read(&a.p("proj/target/debug/o8.o")).unwrap(), b"object 8");
    assert!(!b.p("proj").exists());
}
