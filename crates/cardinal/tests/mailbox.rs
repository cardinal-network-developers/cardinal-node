//! People who do not connect directly, reaching each other through their
//! hosts (`hosts.md#mailbox`, `contact.md#who-a-person-knows`).
//!
//! Skipped (with a message) when `/dev/fuse` or `fusermount3` is missing.

mod common;

use common::*;

/// Someone with one device, which is their host.
fn hosted(root: &std::path::Path, name: &'static str) -> Dev {
    let mut d = Dev::new(root, name, free_port());
    d.start();
    d.cli(&["init", "--yes", "--name", name]);
    d.wait_mounted();
    let at = format!("127.0.0.1:{}", d.port);
    d.cli(&["host", "--address", &at]);
    d
}

/// Bo accepts Ana's invitation, and each keeps the other to hosts.
fn through_hosts(ana: &Dev, bo: &Dev) {
    let at = format!("127.0.0.1:{}", ana.port);
    let args = ["invite", "--address", &at, "--name", "Ana", "--hosts-only"];
    let code = ana.cli(&args).trim().to_owned();
    bo.cli(&["accept", &code, "--hosts-only"]);
    wait("ana lists bo", 20, || ana.cli(&["contacts"]).contains("bo"));
}

fn connected(from: &Dev) -> bool {
    from.cli(&["contacts"]).contains("  connected")
}

fn has_read(from: &Dev, who: &str, text: &str) -> bool {
    from.cli(&["messages", who]).contains(text)
}

#[test]
fn people_through_hosts_only_can_talk() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let ana = hosted(root.path(), "ana");
    let bo = hosted(root.path(), "bo");
    through_hosts(&ana, &bo);

    let said = bo.cli(&["say", "Ana", "hello"]);
    assert!(said.trim().is_empty(), "{said}");
    wait("ana reads it", 20, || has_read(&ana, "bo", "bo: hello"));
    ana.cli(&["say", "bo", "hello yourself"]);
    wait("bo reads it", 20, || {
        has_read(&bo, "Ana", "Ana: hello yourself")
    });

    // They never had a session of their own for any of it.
    assert!(!connected(&ana), "{}", ana.cli(&["contacts"]));
    assert!(!connected(&bo), "{}", bo.cli(&["contacts"]));
    let (a, b) = (ana.cli(&["messages", "bo"]), bo.cli(&["messages", "Ana"]));
    assert_eq!(a.lines().count(), 2, "{a}");
    assert_eq!(b.lines().count(), 2, "{b}");
}

/// A message waits for the host it is going to, and survives a restart.
#[test]
fn a_message_goes_when_a_host_comes_back() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut ana = hosted(root.path(), "ana");
    let mut bo = hosted(root.path(), "bo");
    through_hosts(&ana, &bo);

    ana.stop();
    bo.cli(&["say", "Ana", "while you were out"]);
    bo.stop();
    ana.start();
    ana.wait_mounted();
    bo.start();
    bo.wait_mounted();
    wait("ana reads it", 45, || {
        has_read(&ana, "bo", "while you were out")
    });

    // Once: it is not sent again on the next look.
    ana.cli(&["say", "bo", "got it"]);
    wait("bo reads it", 45, || has_read(&bo, "Ana", "got it"));
    let lines = ana.cli(&["messages", "bo"]);
    assert_eq!(lines.lines().count(), 2, "{lines}");
}

/// What reaches a host reaches all of its person's devices.
#[test]
fn a_persons_other_devices_get_what_reached_their_host() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let ana = hosted(root.path(), "ana");
    let bo = hosted(root.path(), "bo");
    through_hosts(&ana, &bo);
    let mut phone = Dev::new(root.path(), "phone", free_port());
    phone.start();
    pair(&ana, &phone);
    phone.wait_mounted();

    bo.cli(&["say", "Ana", "for all of you"]);
    wait("the phone reads it", 30, || {
        phone
            .try_cli(&["messages", "bo"])
            .stdout
            .windows(14)
            .any(|w| w == b"for all of you")
    });
}

/// Refusing someone ends their token too, and taking it back gives them a
/// new one.
#[test]
fn a_refused_persons_token_stops_working() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let ana = hosted(root.path(), "ana");
    let bo = hosted(root.path(), "bo");
    through_hosts(&ana, &bo);
    bo.cli(&["say", "Ana", "first"]);
    wait("ana reads it", 20, || has_read(&ana, "bo", "first"));

    ana.cli(&["contact", "bo", "refuse"]);
    bo.cli(&["say", "Ana", "second"]);
    std::thread::sleep(std::time::Duration::from_secs(5));
    ana.cli(&["contact", "bo", "unrefuse"]);
    assert!(!has_read(&ana, "bo", "second"), "it got through");

    wait("it arrives once they may", 60, || {
        has_read(&ana, "bo", "second")
    });
}

/// A message too long for an envelope is fetched from the writer's host, on
/// the strength of a notice.
#[test]
fn a_long_message_is_fetched_from_the_writers_host() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let ana = hosted(root.path(), "ana");
    let bo = hosted(root.path(), "bo");
    through_hosts(&ana, &bo);
    let text = "x".repeat(3000);
    bo.cli(&["say", "Ana", &text]);
    wait("ana reads it", 20, || has_read(&ana, "bo", &text));
    assert!(!connected(&ana), "{}", ana.cli(&["contacts"]));
}

/// Someone with no host cannot be told anything, so they look at their
/// contact's. What they write can only be short, and they are told so.
#[test]
fn someone_with_no_host_fetches_from_a_contacts() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let ana = hosted(root.path(), "ana");
    let mut bo = Dev::new(root.path(), "bo", free_port());
    bo.env.push(("CARDINAL_TEST_PULL_SECS".into(), "1".into()));
    bo.start();
    bo.cli(&["init", "--yes", "--name", "bo"]);
    bo.wait_mounted();
    through_hosts(&ana, &bo);

    ana.cli(&["say", "bo", "are you there?"]);
    wait("bo reads it", 20, || has_read(&bo, "Ana", "are you there?"));
    bo.cli(&["say", "Ana", "I am"]);
    wait("ana reads it", 20, || has_read(&ana, "bo", "I am"));

    let told = bo.cli(&["say", "Ana", &"x".repeat(3000)]);
    assert!(told.contains("Kept here"), "{told}");
    assert!(!connected(&ana), "{}", ana.cli(&["contacts"]));
}

/// Fetching from someone's host brings what the two share and nothing else.
#[test]
fn fetching_from_a_host_brings_only_what_is_shared() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let ana = hosted(root.path(), "ana");
    let mut bo = Dev::new(root.path(), "bo", free_port());
    bo.env.push(("CARDINAL_TEST_PULL_SECS".into(), "1".into()));
    bo.start();
    bo.cli(&["init", "--yes", "--name", "bo"]);
    bo.wait_mounted();
    std::fs::write(ana.p("private.txt"), "ana's\n").unwrap();
    ana.cli(&["flush"]);
    through_hosts(&ana, &bo);
    ana.cli(&["say", "bo", "hello"]);
    wait("bo reads it", 20, || has_read(&bo, "Ana", "hello"));

    // Bo fetched from ana's host time and again, and holds only what they
    // share: bo's own two spaces and that one.
    let spaces = std::fs::read_dir(bo.home.join("spaces")).unwrap().count();
    assert_eq!(spaces, 3);
    assert!(!bo.p("private.txt").exists());
}
