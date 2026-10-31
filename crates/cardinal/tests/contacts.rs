//! Two people, each with their own identity (`contact.md`): one invites the
//! other, and they can talk. What each has that they do not share stays
//! their own.
//!
//! Skipped (with a message) when `/dev/fuse` or `fusermount3` is missing.

mod common;

use common::*;

/// Someone with one device.
fn person(root: &std::path::Path, name: &'static str) -> Dev {
    let mut d = Dev::new(root, name, free_port());
    d.start();
    d.cli(&["init", "--yes", "--name", name]);
    d.wait_mounted();
    d
}

fn invitation(from: &Dev, name: &str) -> String {
    let at = format!("127.0.0.1:{}", from.port);
    from.cli(&["invite", "--address", &at, "--name", name])
        .trim()
        .to_owned()
}

#[test]
fn two_people_connect_and_talk() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut ana = person(root.path(), "ana");
    let mut bo = person(root.path(), "bo");

    // Each has something private.
    std::fs::write(ana.p("private.txt"), "ana's\n").unwrap();
    ana.cli(&["flush"]);

    let code = invitation(&ana, "Ana");
    assert!(code.starts_with("cardinal:"), "{code}");
    let done = bo.cli(&["accept", &code]);
    assert!(done.contains("Connected to Ana"), "{done}");
    wait("ana sees bo", 20, || ana.cli(&["contacts"]).contains("bo"));
    assert!(bo.cli(&["contacts"]).contains("Ana"));

    // An invitation works once.
    let cy = person(root.path(), "cy");
    let again = cy.try_cli(&["accept", &code]);
    assert!(!again.status.success(), "{again:?}");
    assert!(cy.cli(&["contacts"]).trim().is_empty());

    bo.cli(&["say", "Ana", "hello"]);
    wait("ana reads it", 20, || {
        ana.cli(&["messages", "bo"]).contains("bo: hello")
    });
    ana.cli(&["say", "bo", "hello yourself"]);
    wait("bo reads it", 20, || {
        bo.cli(&["messages", "Ana"]).contains("Ana: hello yourself")
    });

    // In the same order on both.
    let (a, b) = (ana.cli(&["messages", "bo"]), bo.cli(&["messages", "Ana"]));
    assert_eq!(a.lines().count(), 2, "{a}");
    assert_eq!(b.lines().count(), 2, "{b}");
    assert!(a.find("hello\n") < a.find("hello yourself"), "{a}");
    assert!(b.find("hello\n") < b.find("hello yourself"), "{b}");

    // Nothing else crossed: bo holds no other space of ana's, and has none of
    // ana's files.
    assert!(!bo.p("private.txt").exists());
    std::fs::write(ana.p("later.txt"), "later\n").unwrap();
    ana.cli(&["flush"]);
    std::thread::sleep(std::time::Duration::from_secs(1));
    assert!(!bo.p("later.txt").exists());
    let spaces = |d: &Dev| std::fs::read_dir(d.home.join("spaces")).unwrap().count();
    assert_eq!(spaces(&bo), 3, "bo's own two, and the one they share");

    // It survives a restart, and they find each other again.
    bo.stop();
    ana.cli(&["say", "bo", "while you were out"]);
    bo.start();
    bo.wait_mounted();
    wait("bo catches up", 20, || {
        bo.cli(&["messages", "Ana"]).contains("while you were out")
    });
    ana.stop();
    bo.cli(&["say", "Ana", "and you?"]);
    ana.start();
    ana.wait_mounted();
    wait("ana catches up", 20, || {
        ana.cli(&["messages", "bo"]).contains("and you?")
    });
}

/// A person's other devices are in the conversation too.
#[test]
fn a_conversation_reaches_all_of_a_persons_devices() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let ana = person(root.path(), "ana");
    let bo = person(root.path(), "bo");
    let code = invitation(&ana, "Ana");
    bo.cli(&["accept", &code]);
    wait("ana sees bo", 20, || ana.cli(&["contacts"]).contains("bo"));
    bo.cli(&["say", "Ana", "first"]);
    wait("ana reads it", 20, || {
        ana.cli(&["messages", "bo"]).contains("first")
    });

    let mut phone = Dev::new(root.path(), "phone", free_port());
    phone.start();
    pair(&ana, &phone);
    wait("the phone reads the conversation", 30, || {
        phone
            .try_cli(&["messages", "bo"])
            .stdout
            .windows(5)
            .any(|w| w == b"first")
    });
    phone.cli(&["say", "bo", "from my phone"]);
    wait("bo reads it", 20, || {
        bo.cli(&["messages", "Ana"]).contains("from my phone")
    });
}
