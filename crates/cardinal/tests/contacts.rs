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

/// What `from` lists for the contact called `name`.
fn listing(from: &Dev, name: &str) -> String {
    let all = from.cli(&["contacts", "--all"]);
    let line = all.lines().find(|l| l.starts_with(name));
    line.unwrap_or_default().to_owned()
}

fn connected(from: &Dev, name: &str) -> bool {
    listing(from, name).contains("  connected")
}

/// Waits long enough that anything sent would have arrived.
fn settle() {
    std::thread::sleep(std::time::Duration::from_secs(3));
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

/// Trust runs one way and is never sent, so being moved down looks like the
/// other device being off (`contact.md#who-a-person-knows`).
#[test]
fn someone_no_longer_trusted_gets_silence() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let ana = person(root.path(), "ana");
    let bo = person(root.path(), "bo");
    let code = invitation(&ana, "Ana");
    bo.cli(&["accept", &code]);
    wait("they connect", 20, || {
        connected(&ana, "bo") && connected(&bo, "Ana")
    });

    ana.cli(&["contact", "bo", "hosts-only"]);
    assert!(listing(&ana, "bo").contains("through hosts only"));
    assert!(!connected(&ana, "bo"));

    // Bo is told nothing: a closed session would have shown at once.
    assert!(connected(&bo, "Ana"), "bo heard about it");
    wait("bo finds ana gone", 35, || !connected(&bo, "Ana"));

    // Nothing bo sends gets through, however it tries.
    bo.cli(&["say", "Ana", "anyone there?"]);
    settle();
    assert!(!connected(&bo, "Ana"));
    assert!(!ana.cli(&["messages", "bo"]).contains("anyone there?"));
    // Dropped at the handshake: a session that opened and was then closed
    // would have told bo that something is there.
    assert!(!ana.log().contains("unknown device"), "{}", ana.log());
    let kept = ana.cli(&["say", "bo", "not yet"]);
    assert!(kept.contains("Kept here"), "{kept}");

    ana.cli(&["contact", "bo", "trust"]);
    wait("they connect again", 30, || {
        connected(&ana, "bo") && connected(&bo, "Ana")
    });
    wait("ana reads it", 20, || {
        ana.cli(&["messages", "bo"]).contains("anyone there?")
    });
    wait("bo reads it", 20, || {
        bo.cli(&["messages", "Ana"]).contains("not yet")
    });
}

/// A connection takes both, so either can keep the other to hosts.
#[test]
fn either_side_of_an_invitation_can_choose_hosts_only() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let ana = person(root.path(), "ana");
    let bo = person(root.path(), "bo");
    let cy = person(root.path(), "cy");

    // The one who invites.
    let at = format!("127.0.0.1:{}", ana.port);
    let args = ["invite", "--address", &at, "--name", "Ana", "--hosts-only"];
    let code = ana.cli(&args).trim().to_owned();
    bo.cli(&["accept", &code]);
    wait("ana lists bo", 20, || {
        listing(&ana, "bo").contains("hosts only")
    });
    assert!(listing(&bo, "Ana").contains("  trusted"));
    wait("their session ends", 35, || {
        !connected(&ana, "bo") && !connected(&bo, "Ana")
    });

    // The one who answers.
    let code = invitation(&ana, "Ana");
    cy.cli(&["accept", &code, "--hosts-only", "--no-introductions"]);
    wait("ana lists cy", 20, || {
        listing(&ana, "cy").contains("  trusted")
    });
    let theirs = listing(&cy, "Ana");
    assert!(theirs.contains("hosts only"), "{theirs}");
    assert!(theirs.contains("no introductions"), "{theirs}");
    wait("their session ends", 35, || {
        !connected(&ana, "cy") && !connected(&cy, "Ana")
    });

    // Each has the conversation, and nothing crosses.
    bo.cli(&["say", "Ana", "hello?"]);
    settle();
    assert!(!ana.cli(&["messages", "bo"]).contains("hello?"));
    assert!(!connected(&ana, "bo"));
}

/// Refusing someone ends everything with them, and a new invitation does not
/// bring them back.
#[test]
fn someone_refused_is_gone_until_the_refusal_is_taken_back() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let ana = person(root.path(), "ana");
    let bo = person(root.path(), "bo");
    let code = invitation(&ana, "Ana");
    bo.cli(&["accept", &code]);
    wait("they connect", 20, || {
        connected(&ana, "bo") && connected(&bo, "Ana")
    });
    bo.cli(&["say", "Ana", "before"]);
    wait("ana reads it", 20, || {
        ana.cli(&["messages", "bo"]).contains("before")
    });

    ana.cli(&["contact", "bo", "refuse"]);
    assert!(!ana.cli(&["contacts"]).contains("bo"));
    assert!(listing(&ana, "bo").contains("refused"));
    assert!(!connected(&ana, "bo"));
    assert!(!ana.try_cli(&["say", "bo", "no"]).status.success());
    assert!(!ana.try_cli(&["messages", "bo"]).status.success());

    let code = invitation(&ana, "Ana");
    assert!(!bo.try_cli(&["accept", &code]).status.success());
    assert_eq!(ana.cli(&["contacts", "--all"]).lines().count(), 1);

    // As they were before.
    ana.cli(&["contact", "bo", "unrefuse"]);
    assert!(listing(&ana, "bo").contains("  trusted"));
    assert!(ana.cli(&["messages", "bo"]).contains("before"));
    wait("they connect again", 40, || {
        connected(&ana, "bo") && connected(&bo, "Ana")
    });
}

/// How a person regards someone holds on all of their devices.
#[test]
fn a_persons_other_devices_follow_how_they_regard_someone() {
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

    let mut phone = Dev::new(root.path(), "phone", free_port());
    phone.start();
    pair(&ana, &phone);
    wait("the phone knows of bo", 30, || {
        listing(&phone, "bo").contains("trusted")
    });
    // Own devices share only each other's addresses, so the phone has none
    // for bo unless it is given one.
    phone.stop();
    std::fs::copy(ana.home.join("peers.json"), phone.home.join("peers.json")).unwrap();
    phone.start();
    phone.wait_mounted();
    wait("the phone reaches bo", 40, || connected(&phone, "bo"));

    ana.cli(&["contact", "bo", "hosts-only"]);
    wait("the phone lets go too", 20, || {
        listing(&phone, "bo").contains("hosts only") && !connected(&phone, "bo")
    });
}
