//! The local interface a client uses (`apps.md#the-local-interface`), over
//! the socket as a client reaches it: news arrives by itself, a conversation
//! says what can be said of each message, and read markers travel.
//!
//! Skipped (with a message) when `/dev/fuse` or `fusermount3` is missing.

mod common;

use common::*;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

fn person(root: &std::path::Path, name: &'static str) -> Dev {
    let mut d = Dev::new(root, name, free_port());
    d.start();
    d.cli(&["init", "--yes", "--name", name]);
    d.wait_mounted();
    d
}

fn socket(d: &Dev) -> std::path::PathBuf {
    d.home.join("control.sock")
}

/// One request and its reply, as a client makes them.
fn ask(d: &Dev, req: Value) -> Value {
    let mut s = UnixStream::connect(socket(d)).unwrap();
    writeln!(s, "{req}").unwrap();
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).unwrap();
    let reply: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(reply["ok"], true, "{req} got {reply}");
    reply
}

/// Two people who have met, and each other's names.
fn met(root: &std::path::Path) -> (Dev, Dev) {
    let (a, b) = (person(root, "ana"), person(root, "bo"));
    let at = format!("127.0.0.1:{}", a.port);
    let code = a.cli(&["invite", "--address", &at, "--name", "Ana"]);
    b.cli(&["accept", code.trim(), "--name", "Ana"]);
    wait("each lists the other", 30, || {
        let listed = |d: &Dev| ask(d, json!({"cmd": "conversations"}))["conversations"].clone();
        listed(&a).as_array().is_some_and(|c| c.len() == 1)
            && listed(&b).as_array().is_some_and(|c| c.len() == 1)
    });
    (a, b)
}

fn only(d: &Dev) -> Value {
    ask(d, json!({"cmd": "conversations"}))["conversations"][0].clone()
}

fn said(d: &Dev, who: &str) -> Vec<Value> {
    let v = ask(d, json!({"cmd": "messages", "who": who}));
    v["messages"].as_array().unwrap().clone()
}

#[test]
fn says_which_version_it_speaks() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let a = person(root.path(), "ana");
    assert_eq!(ask(&a, json!({"cmd": "hello"}))["api"], 1);
}

/// A message arrives, and the client hears without asking. It then reads the
/// message, and the other side sees that it was read.
#[test]
fn news_comes_by_itself_and_read_travels_back() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (a, b) = met(root.path());
    let bo = only(&a)["name"].as_str().unwrap().to_owned();

    let mut news = UnixStream::connect(socket(&a)).unwrap();
    news.set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    writeln!(news, "{}", json!({"cmd": "watch"})).unwrap();
    let mut news = BufReader::new(news);
    let mut first = String::new();
    news.read_line(&mut first).unwrap();
    let first: Value = serde_json::from_str(&first).unwrap();
    assert_eq!(first["event"], "changed", "{first}");

    b.cli(&["say", "Ana", "hello from bo"]);
    wait("the message arrives", 30, || {
        let mut line = String::new();
        news.read_line(&mut line).unwrap();
        only(&a)["unread"] == 1
    });
    let c = only(&a);
    assert_eq!(c["last"]["text"], "hello from bo");
    assert_eq!(c["last"]["mine"], false);

    wait("bo hears it got there", 30, || {
        said(&b, "Ana")[0]["state"] == "sent"
    });
    assert_eq!(said(&b, "Ana")[0]["mine"], true);

    ask(&a, json!({"cmd": "mark-read", "who": bo}));
    assert_eq!(only(&a)["unread"], 0);
    wait("bo sees it was read", 30, || {
        said(&b, "Ana")[0]["state"] == "read"
    });

    // Reading again changes nothing: there is nothing to tell anyone.
    let before = a.status()["spaces"].to_string();
    ask(&a, json!({"cmd": "mark-read", "who": bo}));
    assert_eq!(a.status()["spaces"].to_string(), before);

    // A newer message is unread again, and what was read stays read.
    b.cli(&["say", "Ana", "and another"]);
    wait("the second arrives", 30, || only(&a)["unread"] == 1);
    ask(&a, json!({"cmd": "mark-read", "who": bo}));
    wait("both are read", 30, || {
        said(&b, "Ana").iter().all(|m| m["state"] == "read")
    });
}

/// With no way to reach someone, a message says so, and stops saying so once
/// it has got there.
#[test]
fn a_message_waits_while_nobody_can_be_reached() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (a, mut b) = met(root.path());
    b.stop();
    wait("ana notices", 45, || only(&a)["connected"] == false);
    let bo = only(&a)["name"].as_str().unwrap().to_owned();
    a.cli(&["say", &bo, "are you there?"]);
    assert_eq!(said(&a, &bo)[0]["state"], "waiting");
    b.start();
    wait("it gets there", 60, || said(&a, &bo)[0]["state"] == "sent");
}

/// A message that got there stays sent, whatever happens to the session after.
#[test]
fn a_message_stays_sent_after_the_session_ends() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (a, mut b) = met(root.path());
    let bo = only(&a)["name"].as_str().unwrap().to_owned();
    a.cli(&["say", &bo, "before you go"]);
    wait("it is confirmed", 30, || {
        said(&a, &bo)[0]["state"] == "sent"
    });
    b.stop();
    wait("ana notices", 45, || only(&a)["connected"] == false);
    assert_eq!(said(&a, &bo)[0]["state"], "sent");
}

/// A person with no command line sets up through a client: the service makes
/// the identity, shows the words once, and saves nothing until they are
/// proved.
#[test]
fn a_client_can_set_up_a_first_device() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut a = Dev::new(root.path(), "ana", free_port());
    a.start();
    assert!(a.status()["identity"].is_null());
    let begun = ask(&a, json!({"cmd": "setup-begin"}));
    let words: Vec<String> = serde_json::from_value(begun["words"].clone()).unwrap();
    assert_eq!(words.len(), 24);
    let at: Vec<usize> = serde_json::from_value(begun["ask"].clone()).unwrap();
    assert_ne!(at[0], at[1]);

    // Wrong words save nothing, and leave the same identity on offer.
    let mut s = UnixStream::connect(socket(&a)).unwrap();
    let wrong = json!({"cmd": "setup-finish", "name": "Ana", "answers": ["no", "no"]});
    writeln!(s, "{wrong}").unwrap();
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).unwrap();
    let reply: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(reply["ok"], false, "{reply}");
    assert!(a.status()["identity"].is_null());

    let answers = json!([words[at[0]].to_uppercase(), format!(" {} ", words[at[1]])]);
    ask(
        &a,
        json!({"cmd": "setup-finish", "name": "Ana", "answers": answers}),
    );
    wait("set up", 20, || !a.status()["identity"].is_null());
    // `name` is the person's; the device keeps its own (D71).
    assert_eq!(ask(&a, json!({"cmd": "me"}))["name"], "Ana");
    assert_eq!(a.status()["name"], "ana");
    wait("mounted", 20, || !a.status()["mounted"].is_null());
    std::fs::write(a.p("hello.txt"), "works").unwrap();
    assert_eq!(read(&a.p("hello.txt")).unwrap(), "works");
}

/// A client can walk a person's files: folders first, sizes as they are.
#[test]
fn lists_a_folder() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let a = person(root.path(), "ana");
    std::fs::create_dir(a.p("recipes")).unwrap();
    std::fs::write(a.p("recipes/bread.md"), "flour").unwrap();
    std::fs::write(a.p("notes.txt"), "hello").unwrap();
    a.cli(&["flush"]);
    wait("committed", 30, || {
        a.status()["pending_changes"].as_bool() == Some(false)
    });
    let top = ask(&a, json!({"cmd": "files"}));
    let names: Vec<&str> = top["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["name"].as_str().unwrap())
        .collect();
    let at = |n: &str| names.iter().position(|x| *x == n).unwrap();
    assert!(at("recipes") < at("notes.txt"), "{names:?}");
    let inside = ask(&a, json!({"cmd": "files", "path": "recipes"}));
    assert_eq!(inside["files"][0]["name"], "bread.md");
    assert_eq!(inside["files"][0]["size"], 5);
    assert_eq!(inside["files"][0]["folder"], false);
}

/// The reason a request was turned down.
fn turned_down(d: &Dev, req: Value) -> String {
    let mut s = UnixStream::connect(socket(d)).unwrap();
    writeln!(s, "{req}").unwrap();
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).unwrap();
    let reply: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(reply["ok"], false, "{req} got {reply}");
    reply["error"].as_str().unwrap_or_default().to_owned()
}

/// Whoever invited was never asked what to call the other, so either side can
/// change it afterwards. The other is told nothing, and no two contacts share
/// a name.
#[test]
fn a_contact_can_be_renamed() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (a, b) = met(root.path());
    // Bo gave the name he suggests for himself, and that is all Ana has to
    // go on.
    assert_eq!(only(&a)["name"], "bo");
    let bo = only(&a)["id"].as_str().unwrap().to_owned();

    ask(
        &a,
        json!({"cmd": "contact", "who": bo, "name": " Bo Smith "}),
    );
    assert_eq!(only(&a)["name"], "Bo Smith");
    let listed = ask(&a, json!({"cmd": "contacts"}));
    assert_eq!(listed["contacts"][0]["name"], "Bo Smith");
    ask(
        &a,
        json!({"cmd": "say", "who": "bo smith", "text": "found you"}),
    );
    assert_eq!(only(&b)["name"], "Ana");

    // An empty name is no name: Ana sees what Bo calls himself, as his.
    let cleared = ask(&a, json!({"cmd": "contact", "who": bo, "name": "  "}));
    assert_eq!(
        (&cleared["name"], &cleared["own"]),
        (&json!("bo"), &json!(false))
    );
    assert_eq!(only(&a)["own"], false);
    ask(&a, json!({"cmd": "contact", "who": bo, "name": "Bo Smith"}));

    let c = person(root.path(), "cy");
    let at = format!("127.0.0.1:{}", a.port);
    let code = a.cli(&["invite", "--address", &at]);
    c.cli(&["accept", code.trim(), "--name", "Ana"]);
    wait("Ana lists Cy", 30, || {
        let listed = ask(&a, json!({"cmd": "conversations"}))["conversations"].clone();
        listed.as_array().is_some_and(|c| c.len() == 2)
    });
    let taken = turned_down(
        &a,
        json!({"cmd": "contact", "who": "cy", "name": "bo SMITH"}),
    );
    assert!(taken.contains("already"), "{taken}");
    // Changing only the case of one's own name is no clash.
    ask(&a, json!({"cmd": "contact", "who": bo, "name": "bo smith"}));
    assert_eq!(
        a.cli(&["contacts"])
            .lines()
            .filter(|l| l.starts_with("bo smith"))
            .count(),
        1
    );
}

/// A conversation is more than text: a reply names what it answers, an edit
/// and a delete reach the other side, and each person reacts for themselves.
/// What someone else wrote is not theirs to change.
#[test]
fn messages_can_be_answered_changed_and_reacted_to() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (a, b) = met(root.path());
    let bo = only(&a)["name"].as_str().unwrap().to_owned();
    ask(&a, json!({"cmd": "say", "who": bo, "text": "helo"}));
    wait("bo has it", 20, || said(&b, "Ana").len() == 1);
    let id = said(&b, "Ana")[0]["id"].as_str().unwrap().to_owned();

    ask(
        &a,
        json!({"cmd": "edit-message", "who": bo, "id": id, "text": "hello"}),
    );
    wait("bo sees the edit", 20, || {
        said(&b, "Ana")[0]["text"] == "hello"
    });
    assert_eq!(said(&b, "Ana")[0]["edited"], true);

    ask(
        &b,
        json!({"cmd": "say", "who": "Ana", "text": "hi", "reply_to": id}),
    );
    wait("ana has the reply", 20, || said(&a, &bo).len() == 2);
    assert_eq!(said(&a, &bo)[1]["reply_to"], id.as_str());

    ask(
        &b,
        json!({"cmd": "react", "who": "Ana", "id": id, "text": "👍"}),
    );
    ask(
        &a,
        json!({"cmd": "react", "who": bo, "id": id, "text": "👍"}),
    );
    wait("both reactions", 20, || {
        said(&a, &bo)[0]["reactions"][0]["count"] == 2
    });
    assert_eq!(said(&a, &bo)[0]["reactions"][0]["mine"], true);
    ask(
        &b,
        json!({"cmd": "react", "who": "Ana", "id": id, "text": ""}),
    );
    wait("bo's is gone", 20, || {
        said(&a, &bo)[0]["reactions"][0]["count"] == 1
    });

    let theirs = turned_down(
        &b,
        json!({"cmd": "edit-message", "who": "Ana", "id": id, "text": "x"}),
    );
    assert!(theirs.contains("only what you wrote"), "{theirs}");
    let theirs = turned_down(&b, json!({"cmd": "delete-message", "who": "Ana", "id": id}));
    assert!(theirs.contains("only what you wrote"), "{theirs}");

    ask(&a, json!({"cmd": "delete-message", "who": bo, "id": id}));
    wait("gone for bo", 20, || said(&b, "Ana").len() == 1);
    assert_eq!(said(&b, "Ana")[0]["text"], "hi");
}

/// A file goes with a message. The other person sees what it is, and saves it
/// whole, fetched from the sender's device, which serves it to them and
/// nothing else of its own.
#[test]
fn a_file_goes_with_a_message() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (a, b) = met(root.path());
    let bo = only(&a)["name"].as_str().unwrap().to_owned();
    let photo: Vec<u8> = (0..700_000u32).map(|n| (n * 31 % 251) as u8).collect();
    let path = root.path().join("photo.jpg");
    std::fs::write(&path, &photo).unwrap();
    let attach = json!([path.to_str().unwrap()]);
    ask(
        &a,
        json!({"cmd": "say", "who": bo, "text": "a photo", "attach": attach}),
    );
    wait("bo has it", 20, || said(&b, "Ana").len() == 1);
    let m = said(&b, "Ana")[0].clone();
    assert_eq!(m["attachments"][0]["name"], "photo.jpg");
    assert_eq!(m["attachments"][0]["type"], "image/jpeg");
    assert_eq!(m["attachments"][0]["size"], 700_000);

    let to = root.path().join("saved.jpg");
    let req = json!({"cmd": "save-attachment", "who": "Ana", "id": m["id"], "index": 0, "to": to});
    ask(&b, req.clone());
    assert_eq!(std::fs::read(&to).unwrap(), photo);
    let again = turned_down(&b, req);
    assert!(again.contains("already"), "{again}");

    // The same from the command line.
    let listed = b.cli(&["messages", "Ana"]);
    let line = listed
        .lines()
        .find(|l| l.contains("photo.jpg"))
        .unwrap_or_default();
    assert!(line.contains("cardinal save Ana"), "{listed}");
    let id = m["id"].as_str().unwrap();
    let to = root.path().join("by-hand.jpg");
    b.cli(&["save", "Ana", id, "1", to.to_str().unwrap()]);
    assert_eq!(std::fs::read(&to).unwrap(), photo);
}
