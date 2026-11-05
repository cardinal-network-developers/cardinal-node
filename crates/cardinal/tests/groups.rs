//! Groups (`profiles.md#group`): Ana makes one with Bo and Cy, who know her
//! but not each other. Each is offered it through the relationship they have
//! with her, joins, and reads what the others write, Bo and Cy through Ana,
//! who passes it on. Cy, taken out, reads nothing written after.

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

fn person(root: &std::path::Path, name: &'static str) -> Dev {
    let mut d = Dev::new(root, name, free_port());
    d.start_with(&["--no-mount"]);
    d.cli(&["init", "--yes", "--name", name]);
    d
}

/// Ana invites `them`, who calls her Ana, and she calls them `called`.
fn meet(ana: &Dev, them: &Dev, called: &str) {
    let at = format!("127.0.0.1:{}", ana.port);
    let code = ana.cli(&["invite", "--address", &at, "--name", "Ana"]);
    them.cli(&["accept", code.trim(), "--name", "Ana"]);
    wait("ana lists them", 30, || {
        ana.cli(&["contacts"]).contains(them.name)
    });
    ask(
        ana,
        json!({"cmd": "contact", "who": them.name, "name": called}),
    );
}

fn offers(d: &Dev) -> Vec<Value> {
    ask(d, json!({"cmd": "groups"}))["offers"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

fn groups(d: &Dev) -> Vec<Value> {
    ask(d, json!({"cmd": "groups"}))["groups"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

/// What a group's conversation holds here, as `from: text`, or nothing yet.
fn said(d: &Dev, group: &str) -> Vec<String> {
    let r = reply(d, &json!({"cmd": "messages", "group": group}));
    let all = r["messages"].as_array().cloned().unwrap_or_default();
    all.iter()
        .map(|m| {
            format!(
                "{}: {}",
                m["from"].as_str().unwrap_or(""),
                m["text"].as_str().unwrap_or("")
            )
        })
        .collect()
}

#[test]
fn a_group_is_offered_joined_and_read_by_all() {
    let root = tempfile::tempdir().unwrap();
    let ana = person(root.path(), "ana");
    let bo = person(root.path(), "bo");
    let cy = person(root.path(), "cy");
    meet(&ana, &bo, "Bo");
    meet(&ana, &cy, "Cy");

    let made = ask(
        &ana,
        json!({"cmd": "group-create", "name": "Family", "people": ["Bo", "Cy"]}),
    );
    let g = made["group"].as_str().unwrap().to_owned();
    for d in [&bo, &cy] {
        wait("the offer arrives", 30, || {
            offers(d)
                .iter()
                .any(|o| o["name"] == "Family" && o["from"] == "Ana")
        });
        assert!(groups(d).is_empty(), "listed before joining");
        ask(d, json!({"cmd": "group-join", "group": g}));
        wait("joined", 10, || {
            groups(d).iter().any(|x| x["name"] == "Family")
        });
    }

    ask(&ana, json!({"cmd": "say", "group": g, "text": "hello all"}));
    for d in [&bo, &cy] {
        wait("ana's message arrives", 30, || {
            said(d, &g).contains(&"Ana: hello all".to_owned())
        });
    }
    // Cy does not know Bo: Ana passes what he writes on, and Cy sees the name
    // Ana gave him.
    ask(&bo, json!({"cmd": "say", "group": g, "text": "hi from bo"}));
    wait("bo's message reaches cy through ana", 30, || {
        said(&cy, &g).contains(&"Bo: hi from bo".to_owned())
    });
    assert!(said(&ana, &g).contains(&"Bo: hi from bo".to_owned()));
    let unread = groups(&cy)[0]["unread"].as_u64().unwrap();
    assert_eq!(unread, 2, "{:?}", groups(&cy));
    ask(&cy, json!({"cmd": "mark-read", "group": g}));
    assert_eq!(groups(&cy)[0]["unread"], 0);

    let members = ask(&cy, json!({"cmd": "group-members", "group": g}))["members"].clone();
    let mut names: Vec<&str> = members
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["name"].as_str().unwrap())
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["Ana", "Bo", "You"], "{members}");

    // Only an admin takes people out, and then the rest get a new key.
    let no = reply(
        &bo,
        &json!({"cmd": "group-remove", "group": g, "who": "Ana"}),
    );
    assert_eq!(no["ok"], false, "{no}");
    ask(
        &ana,
        json!({"cmd": "group-remove", "group": g, "who": "Cy"}),
    );
    wait("bo sees cy gone", 30, || {
        let m = ask(&bo, json!({"cmd": "group-members", "group": g}));
        m["members"].as_array().unwrap().len() == 2
    });
    ask(&bo, json!({"cmd": "say", "group": g, "text": "after cy"}));
    wait("ana reads it", 30, || {
        said(&ana, &g).contains(&"Bo: after cy".to_owned())
    });
    std::thread::sleep(std::time::Duration::from_secs(3));
    assert!(
        !said(&cy, &g).iter().any(|m| m.contains("after cy")),
        "cy read what came after: {:?}",
        said(&cy, &g)
    );
}

#[test]
fn a_group_can_be_declined() {
    let root = tempfile::tempdir().unwrap();
    let ana = person(root.path(), "ana");
    let bo = person(root.path(), "bo");
    meet(&ana, &bo, "Bo");
    let made = ask(
        &ana,
        json!({"cmd": "group-create", "name": "Trip", "people": ["Bo"]}),
    );
    let g = made["group"].as_str().unwrap().to_owned();
    wait("the offer arrives", 30, || !offers(&bo).is_empty());
    ask(&bo, json!({"cmd": "group-decline", "group": g}));
    wait("and is gone", 10, || offers(&bo).is_empty());
    assert!(groups(&bo).is_empty());
    // Nothing of Bo's went into it.
    std::thread::sleep(std::time::Duration::from_secs(2));
    let m = ask(&ana, json!({"cmd": "group-members", "group": g}));
    assert_eq!(m["members"].as_array().unwrap().len(), 2);
    let no = reply(&bo, &json!({"cmd": "say", "group": g, "text": "hi"}));
    assert_eq!(no["ok"], false, "{no}");
}
