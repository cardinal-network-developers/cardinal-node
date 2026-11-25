//! The one folder as a mount (`profiles.md#one-folder-for-everything-guidance`):
//! each relationship's shared folder beside the person's own files, used the
//! way a file manager uses it.
//!
//! Skipped (with a message) when `/dev/fuse` or `fusermount3` is missing.

mod common;

use common::*;
use std::io::ErrorKind;

fn person(root: &std::path::Path, name: &'static str) -> Dev {
    let mut d = Dev::new(root, name, free_port());
    d.start();
    d.cli(&["init", "--yes", "--name", name]);
    d.wait_mounted();
    d
}

/// Ana and Bo, who call each other Ana and Bo.
fn met(root: &std::path::Path) -> (Dev, Dev) {
    let (a, b) = (person(root, "ana"), person(root, "bo"));
    let at = format!("127.0.0.1:{}", a.port);
    let code = a.cli(&["invite", "--address", &at, "--name", "Ana"]);
    b.cli(&["accept", code.trim(), "--name", "Ana"]);
    wait("Ana's folder for the other", 30, || a.p("People").is_dir());
    let them = std::fs::read_dir(a.p("People"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .file_name();
    // Ana names the other Bo, which renames the folder.
    std::fs::rename(a.p("People").join(&them), a.p("People/Bo")).unwrap();
    wait("Bo's folder at Ana's", 30, || a.p("People/Bo").is_dir());
    wait("Ana's folder at Bo's", 30, || b.p("People/Ana").is_dir());
    (a, b)
}

fn names(dir: &std::path::Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

#[test]
fn a_shared_folder_is_beside_my_files() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (a, b) = met(root.path());
    assert_eq!(names(&a.mount), ["People"]);
    assert_eq!(names(&a.p("People")), ["Bo"]);
    let c = a.cli(&["contacts"]);
    assert!(
        c.contains("Bo"),
        "renaming the folder renamed the contact: {c}"
    );

    // Written at Ana's, read at Bo's: fetched from her devices when opened.
    let plan: Vec<u8> = (0..300_000u32).map(|n| (n * 7 % 251) as u8).collect();
    std::fs::write(a.p("People/Bo/plan.bin"), &plan).unwrap();
    std::fs::create_dir(a.p("People/Bo/trip")).unwrap();
    std::fs::write(a.p("People/Bo/trip/list.txt"), "eggs").unwrap();
    a.cli(&["flush"]);
    wait("at Bo's", 30, || {
        read(&b.p("People/Ana/trip/list.txt")).as_deref() == Some("eggs")
    });
    wait("the plan at Bo's", 30, || {
        std::fs::read(b.p("People/Ana/plan.bin")).ok() == Some(plan.clone())
    });

    // Bo changes it; Ana sees the change.
    std::fs::write(b.p("People/Ana/trip/list.txt"), "eggs, milk").unwrap();
    b.cli(&["flush"]);
    wait("back at Ana's", 30, || {
        read(&a.p("People/Bo/trip/list.txt")).as_deref() == Some("eggs, milk")
    });

    // Moving between spaces is a copy: a file manager does that on EXDEV.
    std::fs::write(a.p("notes.txt"), "mine").unwrap();
    let err = std::fs::rename(a.p("notes.txt"), a.p("People/Bo/notes.txt")).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::CrossesDevices, "{err}");
    std::fs::copy(a.p("notes.txt"), a.p("People/Bo/notes.txt")).unwrap();
    std::fs::remove_file(a.p("notes.txt")).unwrap();
    a.cli(&["flush"]);
    wait("the copy at Bo's", 30, || {
        read(&b.p("People/Ana/notes.txt")).as_deref() == Some("mine")
    });

    // Nothing goes in a category except people, and people stay.
    assert!(std::fs::write(a.p("People/stray.txt"), "x").is_err());
    assert!(std::fs::create_dir(a.p("People/Somebody")).is_err());
    assert!(std::fs::remove_dir_all(a.p("People/Bo")).is_err());
    assert!(std::fs::create_dir(a.p("People")).is_err());
}

#[test]
fn my_folder_named_like_a_category_is_shown_beside_it() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let a = person(root.path(), "ana");
    std::fs::create_dir(a.p("People")).unwrap();
    std::fs::write(a.p("People/old.txt"), "mine").unwrap();
    a.cli(&["flush"]);
    let b = person(root.path(), "bo");
    let at = format!("127.0.0.1:{}", a.port);
    let code = a.cli(&["invite", "--address", &at, "--name", "Ana"]);
    b.cli(&["accept", code.trim(), "--name", "Ana"]);
    wait("the category at Ana's", 30, || a.p("People (2)").is_dir());
    assert_eq!(names(&a.mount), ["People", "People (2)"]);
    assert_eq!(read(&a.p("People (2)/old.txt")).as_deref(), Some("mine"));
    // and it is still hers to change
    std::fs::write(a.p("People (2)/new.txt"), "also").unwrap();
    std::fs::rename(a.p("People (2)"), a.p("Folk")).unwrap();
    assert_eq!(names(&a.p("Folk")), ["new.txt", "old.txt"]);
}

/// A group's folder in the mount (D88): `Groups/<name>`, renamed only by
/// an admin or the owner, and refused to anyone else with a permission
/// error.
#[test]
fn a_groups_folder_is_renamed_only_by_its_admins() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (a, b) = met(root.path());
    let ask = |d: &Dev, req: serde_json::Value| {
        let r = reply(d, &req);
        assert_eq!(r["ok"], true, "{req} got {r}");
        r
    };
    let made = ask(
        &a,
        serde_json::json!({"cmd": "group-create", "name": "Family", "people": ["Bo"]}),
    );
    let g = made["group"].as_str().unwrap().to_owned();
    wait("bo is offered it", 30, || {
        let r = ask(&b, serde_json::json!({"cmd": "groups"}));
        r["offers"].as_array().is_some_and(|o| !o.is_empty())
    });
    assert_eq!(names(&b.mount), ["People"]);
    ask(&b, serde_json::json!({"cmd": "group-join", "group": g}));
    wait("bo's folder for the group", 30, || {
        b.p("Groups/Family").is_dir()
    });
    assert_eq!(names(&b.mount), ["Groups", "People"]);
    std::fs::write(b.p("Groups/Family/plan.txt"), "picnic").unwrap();
    wait("ana has bo's plan", 30, || {
        std::fs::read_to_string(a.p("Groups/Family/plan.txt"))
            .ok()
            .as_deref()
            == Some("picnic")
    });

    // Bo may not rename it; nobody removes it.
    let err = std::fs::rename(b.p("Groups/Family"), b.p("Groups/Kin")).unwrap_err();
    // EACCES: this person lacks the right, where EPERM is for nobody
    assert_eq!(err.raw_os_error(), Some(13), "{err}");
    assert!(b.p("Groups/Family").is_dir());
    // (only the folder itself: what is in it is removed as in any folder)
    let err = std::fs::remove_dir(b.p("Groups/Family")).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::PermissionDenied, "{err}");
    assert!(std::fs::rename(b.p("Groups/Family"), b.p("People/Family")).is_err());
    // Ana, its owner, may: the group is renamed, and Bo's folder follows.
    std::fs::rename(a.p("Groups/Family"), a.p("Groups/Kin")).unwrap();
    wait("bo's folder follows", 30, || b.p("Groups/Kin").is_dir());
    assert!(!b.p("Groups/Family").exists());
    assert_eq!(
        std::fs::read_to_string(b.p("Groups/Kin/plan.txt")).unwrap(),
        "picnic"
    );
    // Leaving takes it away.
    ask(&b, serde_json::json!({"cmd": "group-leave", "group": g}));
    wait("bo's Groups goes", 30, || !b.p("Groups").exists());
}

/// A file manager's trash at the top of the one folder is refused (D91):
/// `.Trash` and `.Trash-<uid>` cannot be made there, nor anything put in
/// one already there, so that a file manager offers to delete for good,
/// which `deleted` then lists. One already there stays, to be emptied by
/// moving out what is in it, and deleted.
#[test]
fn a_file_managers_trash_is_refused_at_the_top() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let a = person(root.path(), "ana");
    let refused = |r: std::io::Result<()>, what: &str| {
        let e = r.expect_err(what);
        assert_eq!(e.raw_os_error(), Some(libc::EPERM), "{what}: {e}");
    };
    refused(std::fs::create_dir(a.p(".Trash-1000")), "mkdir .Trash-1000");
    refused(std::fs::create_dir(a.p(".Trash")), "mkdir .Trash");
    refused(std::fs::write(a.p(".Trash-x"), "x"), "file .Trash-x");
    std::fs::write(a.p("notes.txt"), "mine").unwrap();
    refused(
        std::fs::rename(a.p("notes.txt"), a.p(".Trash-1000")),
        "rename to .Trash-1000",
    );
    // elsewhere, and other names, are anyone's
    std::fs::create_dir(a.p(".Trashcan")).unwrap();
    std::fs::create_dir_all(a.p("docs/.Trash-1000")).unwrap();
    a.cli(&["flush"]);

    // One made before, elsewhere: nothing more goes in, what is there
    // comes out.
    let ok = |r: serde_json::Value| assert_eq!(r["ok"], true, "{r}");
    for p in [".Trash-1000", ".Trash-1000/files"] {
        ok(reply(&a, &serde_json::json!({"cmd": "mkdir", "path": p})));
    }
    let old = root.path().join("old.txt");
    std::fs::write(&old, "from before").unwrap();
    ok(reply(
        &a,
        &serde_json::json!({"cmd": "put", "from": old, "to": ".Trash-1000/files"}),
    ));
    wait("the old trash in the mount", 30, || {
        a.p(".Trash-1000/files/old.txt").exists()
    });
    refused(
        std::fs::rename(a.p("notes.txt"), a.p(".Trash-1000/files/notes.txt")),
        "move into the old trash",
    );
    refused(
        std::fs::create_dir(a.p(".Trash-1000/info")),
        "mkdir in the old trash",
    );
    refused(
        std::fs::write(a.p(".Trash-1000/files/new.txt"), "x"),
        "file in the old trash",
    );
    std::fs::rename(a.p(".Trash-1000/files/old.txt"), a.p("old.txt")).unwrap();
    assert_eq!(read(&a.p("old.txt")).as_deref(), Some("from before"));
    std::fs::remove_dir_all(a.p(".Trash-1000")).unwrap();

    // Deleting for good is a delete, listed and brought back.
    std::fs::remove_file(a.p("notes.txt")).unwrap();
    a.cli(&["flush"]);
    let gone = reply(&a, &serde_json::json!({"cmd": "deleted", "path": ""}));
    let names: Vec<&str> = gone["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"notes.txt"), "{gone}");
    assert!(
        !names.contains(&".Trash-1000"),
        "hidden unless asked: {gone}"
    );
    a.cli(&["undelete", "notes.txt"]);
    wait("notes.txt back", 30, || {
        read(&a.p("notes.txt")).as_deref() == Some("mine")
    });
}
