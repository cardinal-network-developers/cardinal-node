//! Groups (`profiles.md#group`): Ana makes one with Bo and Cy, who know her
//! but not each other. Each is offered it through the relationship they have
//! with her, joins, and reads what the others write, Bo and Cy through Ana,
//! who passes it on. Nobody is taken out of it in place.

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
    // A file Bo sends reaches Cy through Ana, who keeps it.
    let photo = root.path().join("photo.bin");
    std::fs::write(&photo, vec![7u8; 300_000]).unwrap();
    ask(
        &bo,
        json!({"cmd": "say", "group": g, "text": "a file", "attach": [photo]}),
    );
    wait("the file's message reaches cy", 30, || {
        said(&cy, &g).contains(&"Bo: a file".to_owned())
    });
    let file_id = {
        let r = ask(&cy, json!({"cmd": "messages", "group": g}));
        let all = r["messages"].as_array().unwrap().clone();
        all.iter().find(|m| m["text"] == "a file").unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let kept = root.path().join("kept.bin");
    wait("cy saves it", 30, || {
        let r = reply(
            &cy,
            &json!({"cmd": "save-attachment", "group": g, "id": file_id, "index": 0, "to": kept}),
        );
        r["ok"] == true
    });
    assert_eq!(std::fs::read(&kept).unwrap(), vec![7u8; 300_000]);
    let unread = groups(&cy)[0]["unread"].as_u64().unwrap();
    assert_eq!(unread, 3, "{:?}", groups(&cy));
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

    // Nobody is taken out of a group in place. That is its owner replacing
    // it with one that leaves them out, which this version cannot do yet: so
    // the command says so, to anyone and to the owner, and changes nothing.
    let no = reply(
        &bo,
        &json!({"cmd": "group-remove", "group": g, "who": "Ana"}),
    );
    assert_eq!(no["ok"], false, "{no}");
    assert!(
        no["error"].as_str().unwrap().contains("only the owner"),
        "{no}"
    );
    let no = reply(
        &ana,
        &json!({"cmd": "group-remove", "group": g, "who": "Cy"}),
    );
    assert_eq!(no["ok"], false, "{no}");
    let why = no["error"].as_str().unwrap();
    assert!(
        why.contains("cannot be taken out") && why.contains("Cy"),
        "{no}"
    );
    ask(
        &bo,
        json!({"cmd": "say", "group": g, "text": "still all of us"}),
    );
    for d in [&ana, &cy] {
        wait("everyone still reads it", 30, || {
            said(d, &g).contains(&"Bo: still all of us".to_owned())
        });
        let m = ask(d, json!({"cmd": "group-members", "group": g}));
        assert_eq!(m["members"].as_array().unwrap().len(), 3, "{m}");
    }
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

fn standing(d: &Dev) -> Value {
    ask(d, json!({"cmd": "call"}))["call"]["state"].clone()
}

/// A call's sound, as a client has it.
struct Line {
    w: UnixStream,
    r: BufReader<UnixStream>,
}

impl Line {
    fn open(d: &Dev) -> Line {
        let mut w = UnixStream::connect(d.home.join("control.sock")).unwrap();
        writeln!(w, "{}", json!({"cmd": "call-media"})).unwrap();
        w.set_read_timeout(Some(std::time::Duration::from_millis(20)))
            .unwrap();
        let r = BufReader::new(w.try_clone().unwrap());
        Line { w, r }
    }

    fn say(&mut self, tag: u8, n: u32) {
        let mut frame = n.to_be_bytes().to_vec();
        frame.extend_from_slice(&[tag; 20]);
        writeln!(self.w, "{}", json!({"audio": hex::encode(frame)})).unwrap();
    }

    /// The voices heard so far, by who, and what each said.
    fn heard(
        &mut self,
        into: &mut std::collections::HashMap<String, std::collections::HashSet<u8>>,
    ) {
        loop {
            let mut line = String::new();
            match self.r.read_line(&mut line) {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
            let Ok(v) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            let (Some(from), Some(audio)) = (v["from"].as_str(), v["audio"].as_str()) else {
                continue;
            };
            let bytes = hex::decode(audio).unwrap();
            into.entry(from.to_owned()).or_default().insert(bytes[4]);
        }
    }
}

#[test]
fn a_group_call_carries_every_voice_through_whoever_links_them() {
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
        wait("offered", 30, || !offers(d).is_empty());
        ask(d, json!({"cmd": "group-join", "group": g}));
    }
    wait("everyone sees everyone", 30, || {
        [&ana, &bo, &cy].iter().all(|d| {
            let m = reply(d, &json!({"cmd": "group-members", "group": g}));
            m["members"].as_array().is_some_and(|m| m.len() == 3)
        })
    });

    ask(&ana, json!({"cmd": "call-start", "group": g}));
    wait("both ring", 15, || {
        standing(&bo) == "ringing" && standing(&cy) == "ringing"
    });
    assert_eq!(ask(&cy, json!({"cmd": "call"}))["call"]["name"], "Family");
    ask(&bo, json!({"cmd": "call-answer"}));
    ask(&cy, json!({"cmd": "call-answer"}));
    wait("all live", 15, || {
        [&ana, &bo, &cy].iter().all(|d| standing(d) == "live")
    });
    // Bo and Cy have no session with each other: Ana links them.
    wait("ana links both", 15, || {
        ask(&ana, json!({"cmd": "call"}))["call"]["linked"] == 2
    });

    let mut lines = [Line::open(&ana), Line::open(&bo), Line::open(&cy)];
    std::thread::sleep(std::time::Duration::from_millis(300));
    let mut heard: [std::collections::HashMap<String, std::collections::HashSet<u8>>; 3] =
        Default::default();
    for n in 0..60u32 {
        for (i, l) in lines.iter_mut().enumerate() {
            l.say(i as u8 + 1, n);
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
        for (i, l) in lines.iter_mut().enumerate() {
            l.heard(&mut heard[i]);
        }
    }
    for _ in 0..20 {
        for (i, l) in lines.iter_mut().enumerate() {
            l.heard(&mut heard[i]);
        }
    }
    for (i, h) in heard.iter().enumerate() {
        let mut said: Vec<u8> = h.values().flatten().copied().collect();
        said.sort_unstable();
        let others: Vec<u8> = (1..=3u8).filter(|t| *t != i as u8 + 1).collect();
        assert_eq!(said, others, "device {i} heard {h:?}");
        assert_eq!(h.len(), 2, "two voices, apart: {h:?}");
    }

    // Bo hears Cy only through Ana, and still counts three on the call.
    assert_eq!(ask(&bo, json!({"cmd": "call"}))["call"]["people"], 3);
    assert_eq!(ask(&ana, json!({"cmd": "call"}))["call"]["people"], 3);

    // Cy leaves; Ana and Bo go on.
    ask(&cy, json!({"cmd": "call-end"}));
    wait("ana links bo alone", 10, || {
        ask(&ana, json!({"cmd": "call"}))["call"]["linked"] == 1
    });
    assert_eq!(standing(&bo), "live");
}
