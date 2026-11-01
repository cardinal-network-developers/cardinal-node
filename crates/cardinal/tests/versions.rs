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
    let version = d.cli(&["version"]);
    assert!(!version.contains(env!("CARGO_PKG_VERSION")), "{version}");
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
