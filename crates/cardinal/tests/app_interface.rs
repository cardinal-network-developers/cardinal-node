//! The local interface a client uses (`apps.md#the-local-interface`), over
//! the socket as a client reaches it: news arrives by itself, a conversation
//! says what can be said of each message, and read markers travel.
//!
//! Skipped (with a message) when `/dev/fuse` or `fusermount3` is missing.

mod common;

use common::*;
use serde_json::{json, Value};
use std::time::Duration;

fn person(root: &std::path::Path, name: &'static str) -> Dev {
    let mut d = Dev::new(root, name, free_port());
    d.start();
    d.cli(&["init", "--yes", "--name", name]);
    d.wait_mounted();
    d
}

/// One request and its reply, as a client makes them.
fn ask(d: &Dev, req: Value) -> Value {
    let reply = common::reply(d, &req);
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
    assert_eq!(ask(&a, json!({"cmd": "hello"}))["api"], 2);
}

/// The messages themselves (`apps.md#the-local-interface`): one record
/// each, a request by its number and its arguments by theirs, and a reply
/// with its status in key 0. What is not a request is answered with an
/// error, and the connection goes on.
#[test]
fn the_interface_is_records_with_numbers() {
    use cardinal_encoding::{Record, Value as V};
    let root = tempfile::tempdir().unwrap();
    let mut a = Dev::new(root.path(), "ana", free_port());
    a.start_with(&["--no-mount"]);
    let mut c = a.connect();
    let mut answer = |msg: &[u8]| {
        c.send_raw(msg).unwrap();
        Record::decode(&c.recv_raw().unwrap().unwrap()).unwrap()
    };
    // hello is 1: status 0, then api (2) and version (3)
    let r = answer(&Record::new().with(0, 1u64).encode());
    assert_eq!(r.uint(0).unwrap(), 0);
    assert_eq!(r.uint(2).unwrap(), 2);
    assert!(r.text(3).is_ok(), "{r}");
    // not one record: malformed (2), and why in key 1
    let r = answer(&[0x1d, 0x00]);
    assert_eq!(r.uint(0).unwrap(), 2, "{r}");
    assert!(!r.text(1).unwrap().is_empty());
    let r = answer(&[0x08, 0x08]);
    assert_eq!(r.uint(0).unwrap(), 2, "trailing bytes: {r}");
    // a number nobody gave: unknown (3)
    let r = answer(&Record::new().with(0, 9999u64).encode());
    assert_eq!(r.uint(0).unwrap(), 3, "{r}");
    // an argument of the wrong type: malformed
    let r = answer(&Record::new().with(0, 10u64).with(1, 5u64).encode());
    assert_eq!(r.uint(0).unwrap(), 2, "{r}");
    // larger than a message may be: malformed, and nothing else is read
    let big = Record::new()
        .with(0, 105u64)
        .with(1, "x".repeat(300 * 1024))
        .encode();
    let r = answer(&big);
    assert_eq!(r.uint(0).unwrap(), 2, "{r}");
    // and the connection still answers
    let r = answer(&Record::new().with(0, 1u64).encode());
    assert_eq!(r.uint(0).unwrap(), 0);
    // a failure is 1, with why
    let say = Record::new().with(0, 35u64).with(1, "nobody").with(2, "hi");
    let r = answer(&say.encode());
    assert_eq!(r.uint(0).unwrap(), 1, "no identity yet: {r}");
    assert!(!r.text(1).unwrap().is_empty(), "{r}");

    // watch: a reply, then only events, the first at once
    let mut w = a.connect();
    w.send_raw(&Record::new().with(0, 3u64).encode()).unwrap();
    let ok = Record::decode(&w.recv_raw().unwrap().unwrap()).unwrap();
    assert_eq!(ok.uint(0).unwrap(), 0);
    let e = Record::decode(&w.recv_raw().unwrap().unwrap()).unwrap();
    assert_eq!(e.uint(0).unwrap(), 1, "changed: {e}");
    assert!(matches!(e.get(1), Some(V::Int(_))), "{e}");
    assert_eq!(e.len(), 2, "an event carries nothing else: {e}");

    // no call: call-media says so
    let r = answer(&Record::new().with(0, 104u64).encode());
    assert_eq!(r.uint(0).unwrap(), 1, "{r}");
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

    let mut news = a.connect();
    news.set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let watching = news.ask(&json!({"cmd": "watch"})).unwrap();
    assert_eq!(watching["ok"], true, "{watching}");
    let first = news.event().unwrap().unwrap();
    assert_eq!(first["event"], "changed", "{first}");

    b.cli(&["say", "Ana", "hello from bo"]);
    wait("the message arrives", 30, || {
        news.event().unwrap().unwrap();
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

/// Read markers are the person's to give (`profiles.md#relationship`):
/// turned off, in the account, `mark-read` moves no marker and says so,
/// and the other side sees the message as sent and no more. What was
/// read is kept privately in the account instead (field 6 of the space's
/// node), so another device of the person's counts it read too. Turned
/// on again, reading marks it read.
#[test]
fn read_markers_turned_off_tell_nobody_what_was_read() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (a, b) = met(root.path());
    let mut phone = Dev::new(root.path(), "phone", free_port());
    phone.start();
    pair(&a, &phone);
    wait("her phone has the conversation", 60, || {
        ask(&phone, json!({"cmd": "conversations"}))["conversations"]
            .as_array()
            .is_some_and(|c| c.len() == 1)
    });
    let bo = only(&a)["name"].as_str().unwrap().to_owned();
    assert_eq!(ask(&a, json!({"cmd": "read-markers"}))["on"], true);
    assert_eq!(a.status()["read_markers"], true);
    assert_eq!(
        ask(&a, json!({"cmd": "read-markers", "on": false}))["on"],
        false
    );
    assert_eq!(ask(&a, json!({"cmd": "read-markers"}))["on"], false);
    assert_eq!(a.status()["read_markers"], false);
    wait("off on her phone too", 30, || {
        phone.status()["read_markers"] == false
    });
    b.cli(&["say", "Ana", "do you read me"]);
    wait("the message arrives", 30, || only(&a)["unread"] == 1);
    wait("and on her phone", 30, || only(&phone)["unread"] == 1);
    wait("bo hears it got there", 30, || {
        said(&b, "Ana")[0]["state"] == "sent"
    });
    let r = ask(&a, json!({"cmd": "mark-read", "who": bo}));
    assert_eq!(
        (&r["marked"], &r["kept"]),
        (&json!(false), &json!(true)),
        "{r}"
    );
    assert!(r["why"].as_str().unwrap_or("").contains("off"), "{r}");
    assert_eq!(only(&a)["unread"], 0);
    wait("her phone counts it read", 30, || {
        only(&phone)["unread"] == 0
    });
    // Reading again keeps nothing more.
    let r = ask(&a, json!({"cmd": "mark-read", "who": bo}));
    assert_eq!(r["kept"], false, "{r}");
    std::thread::sleep(Duration::from_secs(3));
    assert_eq!(
        said(&b, "Ana")[0]["state"],
        "sent",
        "bo learned it was read"
    );
    ask(&a, json!({"cmd": "read-markers", "on": true}));
    b.cli(&["say", "Ana", "and now?"]);
    wait("the second arrives", 30, || only(&a)["unread"] == 1);
    let r = ask(&a, json!({"cmd": "mark-read", "who": bo}));
    assert_eq!(r["marked"], true, "{r}");
    wait("bo sees it was read", 30, || {
        said(&b, "Ana").iter().any(|m| m["state"] == "read")
    });
}

/// At the command line: `cardinal messages` alone shows what is new, and
/// reading a conversation marks it read.
#[test]
fn the_command_line_shows_what_is_new_and_reading_marks_it_read() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (a, b) = met(root.path());
    let bo = only(&a)["name"].as_str().unwrap().to_owned();
    assert!(a.cli(&["messages"]).contains("nothing said yet"));

    b.cli(&["say", "Ana", "hello from bo"]);
    wait("the message arrives", 30, || only(&a)["unread"] == 1);
    let all = a.cli(&["messages"]);
    assert!(all.contains(&format!("● {bo}")), "{all}");
    assert!(all.contains("1 new"), "{all}");
    assert!(all.contains("hello from bo"), "{all}");
    assert!(all.contains(&format!("1 new message from {bo}.")), "{all}");
    assert!(!all.contains('\x1b'), "no color when not a terminal: {all}");

    assert!(a.cli(&["messages", &bo]).contains("hello from bo"));
    assert_eq!(only(&a)["unread"], 0);
    wait("bo sees it was read", 30, || {
        said(&b, "Ana")[0]["state"] == "read"
    });
    assert!(a.cli(&["messages"]).contains("Nothing new."));
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
    let wrong = json!({"cmd": "setup-finish", "name": "Ana", "answers": ["no", "no"]});
    let reply = common::reply(&a, &wrong);
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

/// A conversation longer than one message holds comes in pages, back from
/// the newest, each under the cap; the cursor is a message's id, and one
/// taken back keeps its place (`apps.md`, Pages). The command line pages
/// through it all, as before.
#[test]
fn a_long_conversation_comes_in_pages() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (a, _b) = met(root.path());
    let bo = only(&a)["name"].as_str().unwrap().to_owned();
    // forty of eight thousand bytes: more than a message carries
    let text = |i: usize| format!("{i:02} {}", "x".repeat(8000));
    for i in 0..40 {
        ask(&a, json!({"cmd": "say", "who": bo, "text": text(i)}));
    }
    let texts = |v: &Value| -> Vec<String> {
        let list = v["messages"].as_array().unwrap().iter();
        list.map(|m| m["text"].as_str().unwrap().to_owned())
            .collect()
    };
    let first = ask(&a, json!({"cmd": "messages", "who": bo}));
    let shown = texts(&first);
    assert!(!shown.is_empty() && shown.len() < 40, "{}", shown.len());
    assert_eq!(shown.last(), Some(&text(39)), "the newest come first");
    assert_eq!(first["more"], true);
    let mut all = shown;
    let mut before = first["next"].clone();
    loop {
        let p = ask(&a, json!({"cmd": "messages", "who": bo, "before": before}));
        let mut older = texts(&p);
        assert!(!older.is_empty());
        older.append(&mut all);
        all = older;
        if p["more"] != true {
            assert!(p.get("next").is_none(), "{}", p["next"]);
            break;
        }
        before = p["next"].clone();
    }
    assert_eq!(all, (0..40).map(text).collect::<Vec<_>>());

    // a limit: the newest so many
    let p = ask(&a, json!({"cmd": "messages", "who": bo, "limit": 3}));
    assert_eq!(texts(&p), [text(37), text(38), text(39)]);
    let id = p["messages"][0]["id"].clone();
    assert_eq!(p["next"], id);
    // taken back, it still marks where the page before it ends
    ask(&a, json!({"cmd": "delete-message", "who": bo, "id": id}));
    let p = ask(
        &a,
        json!({"cmd": "messages", "who": bo, "before": id, "limit": 2}),
    );
    assert_eq!(texts(&p), [text(35), text(36)]);

    // the command line shows every one
    let out = a.cli(&["messages", &bo]);
    for i in (0..40).filter(|i| *i != 37) {
        assert!(out.contains(&format!("you: {i:02} xxx")), "{i} missing");
    }
    assert!(!out.contains("you: 37 "));

    // a folder too, by position
    for n in ["a", "b", "c", "d", "e"] {
        ask(&a, json!({"cmd": "mkdir", "path": n}));
    }
    let mut names = Vec::new();
    let mut after = json!(0);
    loop {
        let p = ask(&a, json!({"cmd": "files", "after": after, "limit": 2}));
        let page = p["files"].as_array().unwrap();
        assert!(page.len() <= 2);
        names.extend(page.iter().map(|f| f["name"].as_str().unwrap().to_owned()));
        if p["more"] != true {
            break;
        }
        after = p["next"].clone();
    }
    let whole = ask(&a, json!({"cmd": "files"}));
    assert_eq!(whole["more"], false);
    let listed: Vec<&str> = whole["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, listed);
    for n in ["a", "b", "c", "d", "e"] {
        assert!(listed.contains(&n), "{listed:?}");
    }
}

/// The reason a request was turned down.
fn turned_down(d: &Dev, req: Value) -> String {
    let reply = common::reply(d, &req);
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

    // Sent as bytes, Bo's id is Bo and nothing else, whatever anyone is
    // called: with Cy named the text of it, that text names both, and the
    // bytes Bo alone. The bytes of a name name nobody.
    ask(&a, json!({"cmd": "contact", "who": "cy", "name": bo}));
    let both = turned_down(&a, json!({"cmd": "messages", "who": bo}));
    assert!(both.contains("more than one"), "{both}");
    let as_bytes = format!("{}{bo}", cardinald::api::EXACT);
    ask(&a, json!({"cmd": "messages", "who": as_bytes}));
    let named = ask(
        &a,
        json!({"cmd": "contact", "who": as_bytes, "name": "Bo by id"}),
    );
    assert_eq!(named["name"], "Bo by id");
    let listed = ask(&a, json!({"cmd": "contacts"}))["contacts"].clone();
    let names: Vec<&str> = listed
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["name"].as_str())
        .collect();
    assert_eq!(names.len(), 2, "{names:?}");
    assert!(
        names.contains(&"Bo by id") && names.contains(&bo.as_str()),
        "{names:?}"
    );
    let name = format!("{}{}", cardinald::api::EXACT, hex::encode("cy"));
    let none = turned_down(&a, json!({"cmd": "messages", "who": name}));
    assert!(none.contains("no contact"), "{none}");
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
