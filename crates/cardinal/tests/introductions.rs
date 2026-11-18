//! Introductions (`contact.md#introductions`): Carol, who knows Ana and Ben,
//! introduces them, and both say yes. And in a group Carol made, Ana asks
//! to meet Ben, and Carol's device introduces them unasked
//! (`profiles.md#group`). Each remembers how they met.

mod common;

use common::*;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

fn reply(d: &Dev, req: &Value) -> Value {
    let mut s = UnixStream::connect(d.home.join("control.sock")).unwrap();
    writeln!(s, "{req}").unwrap();
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

fn ask(d: &Dev, req: Value) -> Value {
    let r = reply(d, &req);
    assert_eq!(r["ok"], true, "{req} got {r}");
    r
}

/// Someone whose device is `name`, and who calls themselves the same with a
/// capital: what an introduction says they are called (D71: a petname is
/// its person's own, and never passed on).
fn person(root: &std::path::Path, name: &'static str) -> Dev {
    let mut d = Dev::new(root, name, free_port());
    d.start_with(&["--no-mount"]);
    let mut called = name.to_owned();
    called[..1].make_ascii_uppercase();
    d.cli(&["init", "--yes", "--name", &called]);
    d
}

/// Carol invites `them`, who calls her Carol, and she calls them `called`.
fn meet(carol: &Dev, them: &Dev, called: &str) {
    let at = format!("127.0.0.1:{}", carol.port);
    let code = carol.cli(&["invite", "--address", &at, "--name", "Carol"]);
    them.cli(&["accept", code.trim(), "--name", "Carol"]);
    wait("carol lists them", 30, || {
        carol.cli(&["contacts"]).to_lowercase().contains(them.name)
    });
    ask(
        carol,
        json!({"cmd": "contact", "who": them.name, "name": called}),
    );
}

fn waiting(d: &Dev) -> Vec<Value> {
    ask(d, json!({"cmd": "introductions"}))["introductions"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

/// The contact called `name`, as a device lists it.
fn contact(d: &Dev, name: &str) -> Option<Value> {
    let all = ask(d, json!({"cmd": "contacts"}))["contacts"].clone();
    all.as_array()?.iter().find(|c| c["name"] == name).cloned()
}

#[test]
fn an_introduction_makes_two_contacts_of_two_strangers() {
    let root = tempfile::tempdir().unwrap();
    let carol = person(root.path(), "carol");
    let ana = person(root.path(), "ana");
    let ben = person(root.path(), "ben");
    meet(&carol, &ana, "Ana");
    meet(&carol, &ben, "Ben");

    ask(
        &carol,
        json!({"cmd": "introduce", "who": "Ana", "to": "Ben", "note": "you both garden"}),
    );
    wait("ben is asked", 30, || {
        waiting(&ben)
            .iter()
            .any(|i| i["kind"] == "meet" && i["name"] == "Ana" && i["from"] == "Carol")
    });
    let i = waiting(&ben)[0].clone();
    assert_eq!(i["note"], "you both garden");
    assert!(
        waiting(&ana).is_empty(),
        "ana was asked before ben said yes"
    );
    ask(&ben, json!({"cmd": "introduction-accept", "id": i["id"]}));
    // His own yes is not his to answer again.
    std::thread::sleep(std::time::Duration::from_millis(500));
    assert!(waiting(&ben).is_empty(), "{:?}", waiting(&ben));

    wait("ana hears ben said yes", 30, || {
        waiting(&ana)
            .iter()
            .any(|i| i["kind"] == "introduced" && i["name"] == "Ben")
    });
    let i = waiting(&ana)[0].clone();
    ask(&ana, json!({"cmd": "introduction-accept", "id": i["id"]}));
    wait("ben lists ana", 30, || contact(&ben, "Ana").is_some());
    let b = contact(&ana, "Ben").expect("ana lists ben");
    assert_eq!(b["met"]["how"], "introduced", "{b}");
    assert_eq!(b["met"]["by"], "Carol", "{b}");
    let a = contact(&ben, "Ana").unwrap();
    assert_eq!(a["met"]["how"], "introduced", "{a}");
    assert_eq!(a["met"]["by"], "Carol", "{a}");
    // Those met by invitation say so.
    assert_eq!(
        contact(&ana, "Carol").unwrap()["met"]["how"],
        "their invitation"
    );
    assert_eq!(
        contact(&carol, "Ana").unwrap()["met"]["how"],
        "your invitation"
    );

    ask(
        &ana,
        json!({"cmd": "say", "who": "Ben", "text": "hello from ana"}),
    );
    wait("ben reads it", 30, || {
        ben.cli(&["messages", "ana"]).contains("hello from ana")
    });
}

#[test]
fn a_group_introduces_its_members() {
    let root = tempfile::tempdir().unwrap();
    let carol = person(root.path(), "carol");
    let ana = person(root.path(), "ana");
    let ben = person(root.path(), "ben");
    meet(&carol, &ana, "Ana");
    meet(&carol, &ben, "Ben");
    let made = ask(
        &carol,
        json!({"cmd": "group-create", "name": "Garden", "people": ["Ana", "Ben"]}),
    );
    let g = made["group"].as_str().unwrap().to_owned();
    for d in [&ana, &ben] {
        wait("offered", 30, || {
            let v = ask(d, json!({"cmd": "groups"}));
            !v["offers"].as_array().unwrap().is_empty()
        });
        ask(d, json!({"cmd": "group-join", "group": g}));
    }

    // Ana asks; Carol's device introduces her to Ben without Carol.
    wait("ana sees ben in it", 30, || {
        let m = reply(&ana, &json!({"cmd": "group-members", "group": g}));
        m["members"].as_array().is_some_and(|m| m.len() == 3)
    });
    ask(
        &ana,
        json!({"cmd": "group-connect", "group": g, "who": "Ben"}),
    );
    // Asking again while it is under way is the same ask.
    let again = ask(
        &ana,
        json!({"cmd": "group-connect", "group": g, "who": "Ben"}),
    );
    assert_eq!(again["asked"], true, "{again}");
    wait("ben is asked, through the group", 30, || {
        waiting(&ben)
            .iter()
            .any(|i| i["name"] == "Ana" && i["group"] == "Garden")
    });
    let i = waiting(&ben)[0].clone();
    ask(&ben, json!({"cmd": "introduction-accept", "id": i["id"]}));
    // Ana asked, so her device connects of itself.
    wait("they are contacts", 30, || {
        contact(&ana, "Ben").is_some() && contact(&ben, "Ana").is_some()
    });
    let b = contact(&ana, "Ben").unwrap();
    assert_eq!(b["met"]["group"], "Garden", "{b}");
    assert_eq!(b["met"]["by"], "Carol", "{b}");
}

#[test]
fn a_group_that_does_not_introduce_says_no() {
    let root = tempfile::tempdir().unwrap();
    let carol = person(root.path(), "carol");
    let ana = person(root.path(), "ana");
    let ben = person(root.path(), "ben");
    meet(&carol, &ana, "Ana");
    meet(&carol, &ben, "Ben");
    let made = ask(
        &carol,
        json!({"cmd": "group-create", "name": "Clinic", "people": ["Ana", "Ben"]}),
    );
    let g = made["group"].as_str().unwrap().to_owned();
    // Ben is there under another name, and not to be introduced.
    ask(
        &carol,
        json!({"cmd": "group-member", "group": g, "who": "Ben", "shown": "A patient", "introduce": false}),
    );
    for d in [&ana, &ben] {
        wait("offered", 30, || {
            let v = ask(d, json!({"cmd": "groups"}));
            !v["offers"].as_array().unwrap().is_empty()
        });
        ask(d, json!({"cmd": "group-join", "group": g}));
    }
    wait("ana sees the name carol chose", 30, || {
        let m = reply(&ana, &json!({"cmd": "group-members", "group": g}));
        m["members"]
            .as_array()
            .is_some_and(|m| m.iter().any(|x| x["name"] == "A patient"))
    });
    let no = reply(
        &ana,
        &json!({"cmd": "group-connect", "group": g, "who": "A patient"}),
    );
    assert_eq!(no["ok"], false, "{no}");
    std::thread::sleep(std::time::Duration::from_secs(2));
    assert!(waiting(&ben).is_empty());
}
