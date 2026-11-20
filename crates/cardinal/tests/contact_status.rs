//! `contact-status`: how a device reaches one contact, as `cardinal contacts
//! NAME` shows it. Two people on loopback: the session with each other's
//! device, its opening noted, a look and its steps, and a reach node naming
//! a host by name, which is shown as not tried.
//!
//! Skipped (with a message) when `/dev/fuse` or `fusermount3` is missing.

mod common;

use common::*;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

fn person(root: &std::path::Path, name: &'static str) -> Dev {
    let mut d = Dev::new(root, name, free_port());
    d.start();
    d.cli(&["init", "--yes", "--name", name]);
    d.wait_mounted();
    d
}

fn ask(d: &Dev, req: Value) -> Value {
    let mut s = UnixStream::connect(d.home.join("control.sock")).unwrap();
    writeln!(s, "{req}").unwrap();
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).unwrap();
    let reply: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(reply["ok"], true, "{req} got {reply}");
    reply
}

#[test]
fn a_contact_shows_its_route_its_reach_and_how_it_was_looked_for() {
    if !fuse_available() {
        eprintln!("skipped: no FUSE");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (a, b) = (person(root.path(), "ana"), person(root.path(), "bo"));
    let at = format!("127.0.0.1:{}", a.port);
    let code = a.cli(&["invite", "--address", &at, "--name", "Ana"]);
    b.cli(&["accept", code.trim(), "--name", "Ana"]);
    wait("they are connected", 30, || {
        let c = ask(&b, json!({"cmd": "contacts"}));
        c["contacts"][0]["connected"] == true
    });

    // Ana becomes a host, by a name and by an address: Bo's device tries
    // only the address.
    a.cli(&[
        "host",
        "--address",
        &format!("localhost:{}", a.port),
        "--address",
        &at,
    ]);
    let mut v = Value::Null;
    wait("Ana's reach node arrives", 30, || {
        v = ask(&b, json!({"cmd": "contact-status", "who": "Ana"}));
        v["their_reach"][0]["endpoints"]
            .as_array()
            .is_some_and(|e| e.len() == 2)
    });
    assert_eq!(v["name"], "Ana", "{v:#}");
    assert_eq!(v["direct_sessions"], true);
    let device = &v["devices"][0];
    assert_eq!(device["online"], true, "{v:#}");
    assert_eq!(device["route"], "direct", "{v:#}");
    assert!(
        device["addr"].as_str().unwrap().starts_with("127.0.0.1:"),
        "{v:#}"
    );
    assert!(device["bytes_received"].as_u64().unwrap() > 0, "{v:#}");
    let entry = &v["their_reach"][0];
    assert_eq!(
        entry["device"], device["key"],
        "the host is Ana's device: {v:#}"
    );
    let eps = entry["endpoints"].as_array().unwrap();
    let named = eps
        .iter()
        .find(|e| e["endpoint"].as_str().unwrap().starts_with("localhost"))
        .unwrap();
    assert_eq!(named["tried"], false, "{v:#}");
    assert!(named["why_not"].as_str().unwrap().contains("name"), "{v:#}");
    let addr = eps.iter().find(|e| e["endpoint"] == at.as_str()).unwrap();
    assert_eq!(addr["tried"], true, "{v:#}");
    assert_eq!(addr["local"], true, "loopback is local: {v:#}");
    let opened = v["sessions"].as_array().unwrap();
    assert!(
        opened
            .iter()
            .any(|s| s["ok"] == true && s["text"].as_str().unwrap().contains("opened: direct")),
        "{v:#}"
    );

    // Looking now, with every device reached, says so.
    let v = ask(
        &b,
        json!({"cmd": "contact-status", "who": "Ana", "look": true}),
    );
    let look = v["last_look"].as_array().unwrap();
    assert!(
        look[0]["text"]
            .as_str()
            .unwrap()
            .starts_with("looking for them"),
        "{v:#}"
    );
    assert!(
        look.iter().any(|s| s["text"]
            .as_str()
            .unwrap()
            .contains("every device of theirs reached")),
        "{v:#}"
    );
    assert!(v["looked_s_ago"].as_u64().is_some(), "{v:#}");

    // Ana stops: the session's end is noted with why.
    drop(a);
    wait("the session's end is noted", 240, || {
        let v = ask(&b, json!({"cmd": "contact-status", "who": "Ana"}));
        v["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["ok"] == false && s["text"].as_str().unwrap().contains("closed after"))
    });

    // Looking for her now that she is off: her host does not answer, and
    // Bo has no other device to ask. Both are said.
    // A look within 5 s of the last is not repeated.
    std::thread::sleep(std::time::Duration::from_secs(6));
    let v = ask(
        &b,
        json!({"cmd": "contact-status", "who": "Ana", "look": true}),
    );
    let look = v["last_look"].as_array().unwrap();
    let said = |what: &str, ok: Value| {
        look.iter()
            .any(|s| s["ok"] == ok && s["text"].as_str().unwrap().contains(what))
    };
    assert!(
        said("no other device of yours to ask", Value::Null),
        "{v:#}"
    );
    assert!(said(&format!("their host at {at}"), json!(false)), "{v:#}");
    assert_eq!(v["devices"][0]["online"], false, "{v:#}");

    // The words: the view a person reads.
    let text = b.cli(&["contacts", "Ana"]);
    assert!(text.contains("Where they say to find them"), "{text}");
    assert!(text.contains("not tried: a name"), "{text}");
    assert!(text.contains("closed after"), "{text}");
}
