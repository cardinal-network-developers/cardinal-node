//! A person updates one device at a time, so a release has to work beside
//! the one before it. `CARDINAL_OLD_BIN` names that release's binary.
//!
//! Skipped (with a message) without it, or when `/dev/fuse` or `fusermount3`
//! is missing.

mod common;

use std::path::{Path, PathBuf};

use common::*;

fn old_bin() -> Option<PathBuf> {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return None;
    }
    let old = std::env::var_os("CARDINAL_OLD_BIN").map(PathBuf::from);
    if old.is_none() {
        eprintln!("skipping: CARDINAL_OLD_BIN is not set");
    }
    old
}

fn old_device(root: &Path, name: &'static str, old: &Path) -> Dev {
    let mut d = Dev::new(root, name, free_port());
    d.bin = old.to_owned();
    // Another build: a release, or the one before, while the version is
    // not yet raised.
    let version = d.cli(&["version"]);
    let this = std::process::Command::new(BIN)
        .arg("version")
        .output()
        .unwrap();
    let this = String::from_utf8_lossy(&this.stdout).into_owned();
    assert_ne!(version, this, "the old binary is this one");
    d
}

fn first(d: &mut Dev) {
    d.start();
    d.cli(&["init", "--yes", "--name", d.name]);
    d.wait_mounted();
}

fn write(d: &Dev, name: &str, text: &str) {
    std::fs::write(d.p(name), text).unwrap();
    d.cli(&["flush"]);
}

fn arrives(d: &Dev, name: &str, text: &str) {
    wait(&format!("{name} on {}", d.name), 60, || {
        read(&d.p(name)).as_deref() == Some(text)
    });
}

fn both_ways(a: &Dev, b: &Dev, round: &str) {
    let name = format!("from-{}-{round}.txt", a.name);
    write(a, &name, round);
    arrives(b, &name, round);
    let name = format!("from-{}-{round}.txt", b.name);
    write(b, &name, round);
    arrives(a, &name, round);
}

fn update(d: &mut Dev) {
    d.stop();
    d.bin = BIN.into();
    d.start();
    d.wait_mounted();
}

fn no_panic(d: &Dev) {
    let log = d.log();
    assert!(!log.contains("panicked"), "{log}");
    let lines = log.lines();
    for l in lines.filter(|l| l.contains("WARN") || l.contains("ERROR")) {
        eprintln!("{}: {l}", d.name);
    }
}

#[test]
fn updating_one_device_leaves_both_syncing() {
    let Some(old) = old_bin() else { return };
    let root = tempfile::tempdir().unwrap();
    let mut a = old_device(root.path(), "alpha", &old);
    let mut b = old_device(root.path(), "beta", &old);
    first(&mut a);
    b.start();
    pair(&a, &b);
    both_ways(&a, &b, "before");

    update(&mut b);
    assert_eq!(read(&b.p("from-alpha-before.txt")).unwrap(), "before");
    both_ways(&a, &b, "after");

    // Each in turn has to find the other again.
    a.stop();
    a.start();
    a.wait_mounted();
    both_ways(&a, &b, "old-restarted");
    b.stop();
    b.start();
    b.wait_mounted();
    both_ways(&a, &b, "new-restarted");

    update(&mut a);
    both_ways(&a, &b, "both-updated");
    no_panic(&a);
    no_panic(&b);
}

#[test]
fn pairing_works_across_versions() {
    let Some(old) = old_bin() else { return };
    let root = tempfile::tempdir().unwrap();

    let mut new = Dev::new(root.path(), "new", free_port());
    let mut joins = old_device(root.path(), "joins-old", &old);
    first(&mut new);
    joins.start();
    pair(&new, &joins);
    both_ways(&new, &joins, "old-joined");

    let mut older = old_device(root.path(), "older", &old);
    let mut joins = Dev::new(root.path(), "joins-new", free_port());
    first(&mut older);
    joins.start();
    pair(&older, &joins);
    both_ways(&older, &joins, "new-joined");
}

#[test]
fn an_old_device_lives_beside_contacts() {
    let Some(old) = old_bin() else { return };
    let root = tempfile::tempdir().unwrap();
    let mut ana = Dev::new(root.path(), "ana", free_port());
    let mut phone = old_device(root.path(), "phone", &old);
    let mut bo = Dev::new(root.path(), "bo", free_port());
    first(&mut ana);
    phone.start();
    pair(&ana, &phone);
    first(&mut bo);

    let at = format!("127.0.0.1:{}", ana.port);
    let code = ana.cli(&["invite", "--address", &at, "--name", "Ana"]);
    let done = bo.cli(&["accept", code.trim()]);
    assert!(done.contains("Connected to Ana"), "{done}");
    wait("ana lists bo", 20, || ana.cli(&["contacts"]).contains("bo"));
    ana.cli(&["say", "bo", "hello bo"]);
    wait("bo reads it", 30, || {
        bo.cli(&["messages", "Ana"]).contains("hello bo")
    });

    // The phone has been sent records and a space it knows nothing about.
    both_ways(&ana, &phone, "with-a-contact");
    phone.stop();
    phone.start();
    phone.wait_mounted();
    both_ways(&ana, &phone, "phone-restarted");
    no_panic(&phone);

    update(&mut phone);
    both_ways(&ana, &phone, "phone-updated");
    wait("the phone lists bo", 30, || {
        phone.cli(&["contacts"]).contains("bo")
    });
    wait("the phone reads the conversation", 30, || {
        phone.cli(&["messages", "bo"]).contains("hello bo")
    });
}

#[test]
fn a_new_device_with_an_old_host() {
    let Some(old) = old_bin() else { return };
    let root = tempfile::tempdir().unwrap();
    let mut ana = Dev::new(root.path(), "ana", free_port());
    let mut host = old_device(root.path(), "host", &old);
    let mut bo = Dev::new(root.path(), "bo", free_port());
    first(&mut ana);
    host.start();
    pair(&ana, &host);
    let at = format!("127.0.0.1:{}", host.port);
    let made = host.cli(&["host", "--address", &at]);
    eprintln!("host says: {made}");
    both_ways(&ana, &host, "host-named");
    first(&mut bo);

    let at = format!("127.0.0.1:{}", ana.port);
    let code = ana.cli(&["invite", "--address", &at, "--name", "Ana", "--hosts-only"]);
    let done = bo.cli(&["accept", code.trim(), "--hosts-only"]);
    assert!(done.contains("Connected to Ana"), "{done}");
    wait("ana lists bo", 20, || ana.cli(&["contacts"]).contains("bo"));
    let said = ana.cli(&["say", "bo", "through hosts"]);
    eprintln!("say: {said}");
    both_ways(&ana, &host, "after-a-hosts-only-contact");
    no_panic(&host);
    no_panic(&ana);
}

/// What `contacts` on `d` lists for the one contact it has, as JSON.
fn only_contact(d: &Dev) -> serde_json::Value {
    let v = control(d, serde_json::json!({"cmd": "contacts"}));
    v["contacts"][0].clone()
}

fn control(d: &Dev, req: serde_json::Value) -> serde_json::Value {
    common::ask(d, &req)
}

/// An account made before the self node (D71) has none: its person is
/// suggested by the device's name until they set theirs, and `me` then
/// makes the node, on any of their devices, old or new.
#[test]
fn an_old_account_gets_a_name_of_its_own() {
    let Some(old) = old_bin() else { return };
    // Only a version from before D71 (0.1.15 and earlier) makes an account
    // with no name of its own; one that has `cardinal me` already names it.
    let knows_names = std::process::Command::new(&old)
        .args(["me", "--help"])
        .output()
        .is_ok_and(|o| o.status.success());
    if knows_names {
        eprintln!("skipping: the old version already keeps the person's name");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut ana = old_device(root.path(), "ana-laptop", &old);
    let mut phone = old_device(root.path(), "ana-phone", &old);
    first(&mut ana);
    phone.start();
    pair(&ana, &phone);
    update(&mut ana);
    let me = control(&ana, serde_json::json!({"cmd": "me"}));
    assert_eq!(me["name"], "ana-laptop", "{me}");
    assert_eq!(me["set"], false, "{me}");

    let mut bo = Dev::new(root.path(), "bo", free_port());
    first(&mut bo);
    let at = format!("127.0.0.1:{}", ana.port);
    let code = ana.cli(&["invite", "--address", &at]);
    bo.cli(&["accept", code.trim()]);
    assert_eq!(only_contact(&bo)["suggested"], "ana-laptop");

    // Set on the updated device: the old one keeps syncing beside it.
    let set = control(&ana, serde_json::json!({"cmd": "me", "name": "Ana"}));
    assert_eq!(set["set"], true);
    both_ways(&ana, &phone, "after-a-self-node");
    let mut cy = Dev::new(root.path(), "cy", free_port());
    first(&mut cy);
    let code = ana.cli(&["invite", "--address", &at]);
    cy.cli(&["accept", code.trim()]);
    assert_eq!(only_contact(&cy)["suggested"], "Ana");
    // The phone, updated, has it from the account.
    update(&mut phone);
    wait("the phone has the name", 30, || {
        control(&phone, serde_json::json!({"cmd": "me"}))["name"] == "Ana"
    });
    no_panic(&phone);
    no_panic(&ana);
}
