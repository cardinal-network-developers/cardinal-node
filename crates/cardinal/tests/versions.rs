//! A person updates one device at a time, so a release has to work beside
//! the one before it. `CARDINAL_OLD_BIN` names that release's binary.
//!
//! Skipped (with a message) without it, or when `/dev/fuse` or `fusermount3`
//! is missing.
//!
//! 0.1.19 does not work beside 0.1.18: pairing, the sync turns and the
//! link's reset frame all changed, so against 0.1.18 only
//! `data_written_by_the_old_version_opens` and the two that check the
//! person is told (`an_old_device_that_cannot_be_read_is_named`,
//! `an_old_contact_that_cannot_be_read_is_named`) pass. The rest hold
//! again against 0.1.19 and later.

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
        skipping("CARDINAL_OLD_BIN is not set");
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

/// One device, updated on its own: what the old version wrote opens, and
/// the new one goes on writing beside it.
#[test]
fn data_written_by_the_old_version_opens() {
    let Some(old) = old_bin() else { return };
    let root = tempfile::tempdir().unwrap();
    let mut a = old_device(root.path(), "alpha", &old);
    first(&mut a);
    write(&a, "old.txt", "written by the old version");
    update(&mut a);
    assert_eq!(read(&a.p("old.txt")).unwrap(), "written by the old version");
    write(&a, "new.txt", "written by the new one");
    a.stop();
    a.start();
    a.wait_mounted();
    assert_eq!(read(&a.p("old.txt")).unwrap(), "written by the old version");
    assert_eq!(read(&a.p("new.txt")).unwrap(), "written by the new one");
    no_panic(&a);
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

/// What `status` on `d` says of its device `name` that it cannot read, if
/// anything.
fn unreadable_device(d: &Dev, name: &str) -> Option<serde_json::Value> {
    let st = d.status();
    let devices = st["devices"].as_array().cloned().unwrap_or_default();
    let dv = devices.into_iter().find(|x| x["name"] == name)?;
    dv["unreadable"]
        .is_object()
        .then(|| dv["unreadable"].clone())
}

fn count(log: &str, all: &[&str]) -> usize {
    log.lines()
        .filter(|l| all.iter().all(|w| l.contains(w)))
        .count()
}

/// A release this one cannot read (0.1.18 beside 0.1.19): two of a
/// person's devices, one updated, do not sync, and the updated one says so
/// in `status`, at WARN once, and dials the other less often. Against a
/// release it reads, they sync and nothing is said.
#[test]
fn an_old_device_that_cannot_be_read_is_named() {
    let Some(old) = old_bin() else { return };
    let root = tempfile::tempdir().unwrap();
    let mut a = old_device(root.path(), "alpha", &old);
    let mut b = old_device(root.path(), "beta", &old);
    first(&mut a);
    b.start();
    pair(&a, &b);
    both_ways(&a, &b, "before");
    update(&mut b);

    write(&a, "after.txt", "after");
    let mut said = None;
    wait("beta syncs with alpha, or says why not", 90, || {
        if read(&b.p("after.txt")).as_deref() == Some("after") {
            return true;
        }
        said = unreadable_device(&b, "alpha");
        said.is_some()
    });
    let Some(said) = said else {
        assert!(unreadable_device(&b, "alpha").is_none());
        eprintln!("the old version is read: nothing to say");
        return;
    };
    let says = said["says"].as_str().unwrap().to_owned();
    eprintln!("beta says: {says} ({})", said["reason"]);
    assert!(says.starts_with("alpha "), "{says}");
    assert!(says.contains("Update"), "{says}");
    assert!(b.cli(&["status"]).contains(&says));

    // Sessions keep closing, alpha dialling as it always did; beta says it
    // once and dials alpha twice at most in the first 45 s.
    let dialled = count(&b.log(), &["connected to alpha", "outgoing"]);
    std::thread::sleep(std::time::Duration::from_secs(45));
    let log = b.log();
    let more = count(&log, &["connected to alpha", "outgoing"]) - dialled;
    assert!(more <= 2, "beta dialled alpha {more} times in 45 s");
    assert_eq!(count(&log, &["WARN", &says]), 1, "{log}");
    assert!(unreadable_device(&b, "alpha").is_some());

    // Updated, alpha syncs, and nothing is said any more.
    update(&mut a);
    both_ways(&a, &b, "both-updated");
    wait("beta reads alpha again", 60, || {
        unreadable_device(&b, "alpha").is_none()
    });
    no_panic(&a);
    no_panic(&b);
}

/// The same with a contact: their device, on the release this one cannot
/// read, is named in `contacts` and `contacts <name>`.
#[test]
fn an_old_contact_that_cannot_be_read_is_named() {
    let Some(old) = old_bin() else { return };
    let root = tempfile::tempdir().unwrap();
    let mut ana = old_device(root.path(), "ana", &old);
    let mut bo = old_device(root.path(), "bo", &old);
    first(&mut ana);
    first(&mut bo);
    let at = format!("127.0.0.1:{}", ana.port);
    let code = ana.cli(&["invite", "--address", &at, "--name", "Ana"]);
    let done = bo.cli(&["accept", code.trim()]);
    assert!(done.contains("Connected to Ana"), "{done}");
    wait("ana lists bo", 20, || ana.cli(&["contacts"]).contains("bo"));
    ana.cli(&["say", "bo", "before"]);
    wait("bo reads it", 30, || {
        bo.cli(&["messages", "Ana"]).contains("before")
    });

    update(&mut bo);
    bo.cli(&["say", "Ana", "after"]);
    ana.cli(&["say", "bo", "after"]);
    // Messages may still come through a mailbox; the sessions cannot.
    let mut said = None;
    for _ in 0..90 {
        said = only_contact(&bo)["unreadable"].as_str().map(str::to_owned);
        if said.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    let Some(says) = said else {
        eprintln!("the old version is read: nothing to say");
        assert!(bo.cli(&["messages", "Ana"]).contains("after"));
        return;
    };
    eprintln!("bo says: {says}");
    assert!(says.starts_with("One of Ana's devices "), "{says}");
    assert!(bo.cli(&["contacts"]).contains(&says));
    let status = control(
        &bo,
        serde_json::json!({"cmd": "contact-status", "who": "Ana"}),
    );
    let devices = status["devices"].as_array().cloned().unwrap_or_default();
    assert!(
        devices
            .iter()
            .any(|d| d["unreadable"]["says"] == says.as_str()),
        "{status}"
    );
    assert!(bo.cli(&["contacts", "Ana"]).contains(&says));
    no_panic(&bo);
}

/// D92, D93: a device on the release before groups made for a call sees
/// one as an ordinary group. Offered it and rung there, it drops the ring
/// and shows the offer; joined, it syncs both ways, and goes on syncing
/// after the mark is set false ("Keep this group").
#[test]
fn an_old_device_in_a_call_group_sees_an_ordinary_group() {
    let Some(old) = old_bin() else { return };
    use serde_json::json;
    let root = tempfile::tempdir().unwrap();
    let mut ana = Dev::new(root.path(), "ana", free_port());
    ana.start_with(&["--no-mount"]);
    ana.cli(&["init", "--yes", "--name", "ana"]);
    let mut bo = old_device(root.path(), "bo", &old);
    bo.start_with(&["--no-mount"]);
    bo.cli(&["init", "--yes", "--name", "bo"]);
    let at = format!("127.0.0.1:{}", ana.port);
    let code = ana.cli(&["invite", "--address", &at, "--name", "Ana"]);
    bo.cli(&["accept", code.trim(), "--name", "Ana"]);
    wait("they meet", 30, || ana.cli(&["contacts"]).contains("bo"));
    common::ask(&ana, &json!({"cmd": "contact", "who": "bo", "name": "Bo"}));
    let made = common::ask(
        &ana,
        &json!({"cmd": "group-create", "name": "Call", "people": ["Bo"], "for_call": true}),
    );
    let g = made["group"].as_str().unwrap().to_owned();
    let offered = |d: &Dev| {
        let v = common::ask(d, &json!({"cmd": "groups"}));
        v["offers"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|o| o["group"] == g.as_str())
    };
    wait("bo is offered it", 30, || offered(&bo));
    // rung there, only offered: the old device drops the ring
    common::ask(
        &ana,
        &json!({"cmd": "call-start", "group": g, "ring": ["Bo"]}),
    );
    for _ in 0..8 {
        let c = common::ask(&bo, &json!({"cmd": "call"}));
        assert!(c["call"].is_null(), "{c}");
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    common::ask(&ana, &json!({"cmd": "call-end"}));
    assert!(offered(&bo));
    common::ask(&bo, &json!({"cmd": "group-join", "group": g}));
    let says = |d: &Dev, text: &str| {
        common::ask(d, &json!({"cmd": "say", "group": g, "text": text}));
    };
    let reads = |d: &Dev, text: &str| {
        wait(&format!("{} reads {text}", d.name), 30, || {
            common::ask(d, &json!({"cmd": "messages", "group": g}))
                .to_string()
                .contains(text)
        });
    };
    says(&ana, "from ana");
    reads(&bo, "from ana");
    says(&bo, "from bo");
    reads(&ana, "from bo");
    let listed = common::ask(&bo, &json!({"cmd": "groups"}));
    let mine = listed["groups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["group"] == g.as_str())
        .cloned()
        .unwrap();
    assert!(
        mine.get("for_call").is_none(),
        "an old device knows no mark: {mine}"
    );
    common::ask(
        &ana,
        &json!({"cmd": "group-set", "group": g, "for_call": false}),
    );
    says(&ana, "kept");
    reads(&bo, "kept");
    says(&bo, "still here");
    reads(&ana, "still here");
    no_panic(&bo);
    no_panic(&ana);
}
