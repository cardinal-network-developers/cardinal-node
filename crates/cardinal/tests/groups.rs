//! Groups (`profiles.md#group`): Ana makes one with Bo and Cy, who know her
//! but not each other. Each is offered it through the relationship they have
//! with her, joins, and reads what the others write, Bo and Cy through Ana,
//! who passes it on. Nobody is taken out of it in place. Cy leaves, reads
//! nothing written after, and is back when added again.

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
/// capital: what a group is shown for them, unless whoever adds them says
/// otherwise (D71: a petname is its person's own).
fn person(root: &std::path::Path, name: &'static str) -> Dev {
    let mut d = Dev::new(root, name, free_port());
    d.start_with(&["--no-mount"]);
    let mut called = name.to_owned();
    called[..1].make_ascii_uppercase();
    d.cli(&["init", "--yes", "--name", &called]);
    d
}

/// Ana invites `them`, who calls her Ana, and she calls them `called`.
fn meet(ana: &Dev, them: &Dev, called: &str) {
    let at = format!("127.0.0.1:{}", ana.port);
    let code = ana.cli(&["invite", "--address", &at, "--name", "Ana"]);
    them.cli(&["accept", code.trim(), "--name", "Ana"]);
    wait("ana lists them", 30, || {
        ana.cli(&["contacts"]).to_lowercase().contains(them.name)
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

    // Cy leaves. The others see that, and Cy has no group any more.
    let left = |d: &Dev| -> Vec<String> {
        let m = ask(d, json!({"cmd": "group-members", "group": g}));
        let all = m["members"].as_array().unwrap().clone();
        let gone = all.iter().filter(|m| m["left"] == true);
        gone.map(|m| m["name"].as_str().unwrap().to_owned())
            .collect()
    };
    assert!(left(&ana).is_empty());
    ask(&cy, json!({"cmd": "group-leave", "group": g}));
    for d in [&ana, &bo] {
        wait("the others see that cy left", 30, || left(d).len() == 1);
    }
    assert_eq!(left(&ana), ["Cy"]);
    // Whoever has left is no longer counted among those in the group.
    for d in [&ana, &bo] {
        assert_eq!(groups(d)[0]["members"], 2, "{:?}", groups(d));
    }
    assert!(groups(&cy).is_empty() && offers(&cy).is_empty());
    let no = reply(
        &cy,
        &json!({"cmd": "say", "group": g, "text": "still here?"}),
    );
    assert_eq!(no["ok"], false, "{no}");
    // What is written after is under a new key and is not sent to Cy.
    let held = |d: &Dev| {
        let log = d.home.join("spaces").join(&g).join("entries.log");
        std::fs::metadata(log).unwrap().len()
    };
    let before = held(&cy);
    ask(&bo, json!({"cmd": "say", "group": g, "text": "after cy"}));
    wait("ana reads it", 30, || {
        said(&ana, &g).contains(&"Bo: after cy".to_owned())
    });
    std::thread::sleep(std::time::Duration::from_secs(3));
    assert_eq!(held(&cy), before, "cy was sent what came after");
    assert_eq!(left(&bo), ["Cy"]);

    // Added again, Cy is offered it again, and on joining reads what was
    // written meanwhile.
    ask(
        &ana,
        json!({"cmd": "group-add", "group": g, "people": ["Cy"]}),
    );
    wait("cy is offered it again", 30, || {
        offers(&cy).iter().any(|o| o["name"] == "Family")
    });
    assert!(groups(&cy).is_empty(), "back without being asked");
    ask(&cy, json!({"cmd": "group-join", "group": g}));
    wait("cy reads what was written meanwhile", 30, || {
        said(&cy, &g).contains(&"Bo: after cy".to_owned())
    });
    for d in [&ana, &bo] {
        wait("nobody has left any more", 30, || left(d).is_empty());
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

/// What a group or an offer says of this person's reach node there.
fn reach_in(d: &Dev, group: &str) -> Value {
    let all = ask(d, json!({"cmd": "groups"}));
    let both = ["groups", "offers"].map(|k| all[k].as_array().cloned().unwrap_or_default());
    let found = both.iter().flatten().find(|g| g["group"] == group);
    found.unwrap_or_else(|| panic!("no group {group} in {all}"))["reach"].clone()
}

/// A reach node tells every member where its person's hosts are
/// (`hosts.md#telling-others-where-to-reach-you`). Ana makes a group of Bo
/// and Cy, who are not each other's contacts. Bo has no host, so there is
/// nothing to ask him. Cy has one: his software asks before it tells Bo
/// where it is, and does as he says.
#[test]
fn nobody_learns_where_a_host_is_unasked() {
    let root = tempfile::tempdir().unwrap();
    let ana = person(root.path(), "ana");
    let bo = person(root.path(), "bo");
    let cy = person(root.path(), "cy");
    let at = format!("127.0.0.1:{}", cy.port);
    cy.cli(&["host", "--address", &at]);
    meet(&ana, &bo, "Bo");
    meet(&ana, &cy, "Cy");
    let made = ask(
        &ana,
        json!({"cmd": "group-create", "name": "Club", "people": ["Bo", "Cy"]}),
    );
    let g = made["group"].as_str().unwrap().to_owned();
    for d in [&bo, &cy] {
        wait("the offer arrives", 30, || {
            offers(d).iter().any(|o| o["name"] == "Club")
        });
    }

    // Bo has nothing to tell: he joins, and his list is left unset (D75).
    let r = reach_in(&bo, &g);
    assert_eq!(r["ask"], false, "{r}");
    assert_eq!(r["who"], json!(["Cy"]), "{r}");
    assert_eq!(r["what"], json!([]), "{r}");
    ask(&bo, json!({"cmd": "group-join", "group": g}));
    wait("bo joined", 10, || {
        groups(&bo).iter().any(|x| x["name"] == "Club")
    });
    let r = reach_in(&bo, &g);
    assert_eq!(
        (&r["shared"], &r["set"]),
        (&json!(false), &json!(false)),
        "{r}"
    );
    assert_eq!(r["said_no"], false, "{r}");

    // Cy is asked: who would learn, and what.
    let r = reach_in(&cy, &g);
    assert_eq!(r["ask"], true, "{r}");
    assert_eq!(r["who"], json!(["Bo"]), "{r}");
    assert_eq!(r["what"], json!([at]), "{r}");
    assert_eq!(r["shared"], false, "{r}");
    let no = reply(&cy, &json!({"cmd": "group-join", "group": g}));
    assert_eq!(no["ok"], false, "{no}");
    let why = no["error"].as_str().unwrap_or("");
    assert!(why.contains("Bo") && why.contains(&at), "{no}");
    assert!(groups(&cy).is_empty(), "joined without an answer");
    assert!(offers(&cy).iter().any(|o| o["name"] == "Club"));
    // Nothing of Cy's went into it.
    std::thread::sleep(std::time::Duration::from_secs(2));
    assert!(groups(&cy).is_empty());

    // He says no, and joins: the others have no host of his from the group.
    ask(
        &cy,
        json!({"cmd": "group-join", "group": g, "reach": false}),
    );
    wait("cy joined", 10, || {
        groups(&cy).iter().any(|x| x["name"] == "Club")
    });
    let r = reach_in(&cy, &g);
    assert_eq!(
        (&r["shared"], &r["ask"]),
        (&json!(false), &json!(false)),
        "{r}"
    );
    assert_eq!(
        (&r["set"], &r["said_no"]),
        (&json!(true), &json!(true)),
        "{r}"
    );
    // What his devices do unasked leaves it so.
    ask(&cy, json!({"cmd": "say", "group": g, "text": "hello"}));
    wait("cy's message reaches bo through ana", 30, || {
        said(&bo, &g).contains(&"Cy: hello".to_owned())
    });
    std::thread::sleep(std::time::Duration::from_secs(3));
    assert_eq!(reach_in(&cy, &g)["shared"], false);

    // He changes his mind, and back.
    ask(
        &cy,
        json!({"cmd": "group-reach", "group": g, "share": true}),
    );
    assert_eq!(reach_in(&cy, &g)["shared"], true);
    ask(
        &cy,
        json!({"cmd": "group-reach", "group": g, "share": false}),
    );
    assert_eq!(reach_in(&cy, &g)["shared"], false);
    // Bo has no host to tell anyone of. There is nothing to share, and it
    // says so: nothing is kept for when he has one.
    let no = reply(
        &bo,
        &json!({"cmd": "group-reach", "group": g, "share": true}),
    );
    assert_eq!(no["ok"], false, "{no}");
    let why = no["error"].as_str().unwrap_or("");
    assert!(why.contains("nothing is kept for later"), "{no}");
    assert_eq!(reach_in(&bo, &g)["shared"], false);

    // He shares it, leaves, and is added again. The offer is a new one and
    // asks afresh: what he answered before does not stand for a group
    // that may have changed while he was out of it.
    ask(
        &cy,
        json!({"cmd": "group-reach", "group": g, "share": true}),
    );
    ask(&cy, json!({"cmd": "group-leave", "group": g}));
    wait("ana sees that cy left", 30, || {
        let m = ask(&ana, json!({"cmd": "group-members", "group": g}));
        let all = m["members"].as_array().cloned().unwrap_or_default();
        all.iter().any(|x| x["name"] == "Cy" && x["left"] == true)
    });
    ask(
        &ana,
        json!({"cmd": "group-add", "group": g, "people": ["Cy"]}),
    );
    wait("cy is offered it again", 30, || {
        offers(&cy).iter().any(|o| o["name"] == "Club")
    });
    assert_eq!(reach_in(&cy, &g)["ask"], true);
    let no = reply(&cy, &json!({"cmd": "group-join", "group": g}));
    assert_eq!(no["ok"], false, "{no}");
    ask(
        &cy,
        json!({"cmd": "group-join", "group": g, "reach": false}),
    );
    wait("cy joined again", 10, || {
        groups(&cy).iter().any(|x| x["name"] == "Club")
    });
    let r = reach_in(&cy, &g);
    assert_eq!(
        (&r["shared"], &r["ask"]),
        (&json!(false), &json!(false)),
        "{r}"
    );

    // Ana's contacts have a host of hers already, if she has one: nothing
    // is asked of her. She may say no all the same, among contacts too.
    let r = reach_in(&ana, &g);
    assert_eq!((&r["ask"], &r["who"]), (&json!(false), &json!([])), "{r}");
    ask(
        &ana,
        json!({"cmd": "group-reach", "group": g, "share": false}),
    );
    assert_eq!(reach_in(&ana, &g)["shared"], false);
    // Nothing made here is public, and every group and offer says so.
    for d in [&ana, &bo, &cy] {
        assert!(groups(d).iter().all(|x| x["public"] == false));
    }
}

/// The answer about hosts is the person's, and the list is where it is
/// kept (`hosts.md#telling-others-where-to-reach-you`). Among contacts
/// Bo's host is named without asking when he joins. He says no, and
/// nothing fills it in again. And when Cy, whom Bo does not know, is added
/// to a group where Bo's host is named, Bo is told, and offered to stop.
/// When he refuses Ana, who is there already, he is asked then, and not
/// again.
#[test]
fn an_answer_about_hosts_is_kept_and_a_later_arrival_is_told_of() {
    let root = tempfile::tempdir().unwrap();
    let ana = person(root.path(), "ana");
    let bo = person(root.path(), "bo");
    let cy = person(root.path(), "cy");
    let at = format!("127.0.0.1:{}", bo.port);
    bo.cli(&["host", "--address", &at]);
    meet(&ana, &bo, "Bo");
    meet(&ana, &cy, "Cy");
    let made = ask(
        &ana,
        json!({"cmd": "group-create", "name": "Choir", "people": ["Bo"]}),
    );
    let g = made["group"].as_str().unwrap().to_owned();
    wait("the offer arrives", 30, || {
        offers(&bo).iter().any(|o| o["name"] == "Choir")
    });
    // Everyone there is Bo's contact: nothing to ask. He may say no all
    // the same, and the empty list a join sets is the answer: nothing
    // names his host there afterwards, whatever his devices do unasked.
    let offer = offers(&bo)[0].clone();
    assert_eq!(offer["reach"]["ask"], false, "{offer}");
    assert_eq!(offer["public"], false, "{offer}");
    ask(
        &bo,
        json!({"cmd": "group-join", "group": g, "reach": false}),
    );
    wait("bo joined", 10, || {
        groups(&bo).iter().any(|x| x["name"] == "Choir")
    });
    ask(&bo, json!({"cmd": "say", "group": g, "text": "here"}));
    wait("bo's message reaches ana", 30, || {
        said(&ana, &g).contains(&"Bo: here".to_owned())
    });
    std::thread::sleep(std::time::Duration::from_secs(4));
    assert_eq!(reach_in(&bo, &g)["shared"], false);

    // Leaving leaves no answer behind. Added again and joining with
    // nothing said, among contacts, his host is named.
    ask(&bo, json!({"cmd": "group-leave", "group": g}));
    wait("ana sees that bo left", 30, || {
        let m = ask(&ana, json!({"cmd": "group-members", "group": g}));
        let all = m["members"].as_array().cloned().unwrap_or_default();
        all.iter().any(|x| x["name"] == "Bo" && x["left"] == true)
    });
    ask(
        &ana,
        json!({"cmd": "group-add", "group": g, "people": ["Bo"]}),
    );
    wait("bo is offered it again", 30, || {
        offers(&bo).iter().any(|o| o["name"] == "Choir")
    });
    ask(&bo, json!({"cmd": "group-join", "group": g}));
    wait("bo's host is named", 10, || {
        groups(&bo).iter().any(|x| x["name"] == "Choir") && reach_in(&bo, &g)["shared"] == true
    });
    assert_eq!(reach_in(&bo, &g)["added"], json!([]));

    // He says no, among contacts. It stays so, whatever his devices do
    // unasked: the empty list is the answer.
    ask(
        &bo,
        json!({"cmd": "group-reach", "group": g, "share": false}),
    );
    assert_eq!(reach_in(&bo, &g)["shared"], false);
    ask(&bo, json!({"cmd": "say", "group": g, "text": "hello"}));
    wait("bo's message reaches ana", 30, || {
        said(&ana, &g).contains(&"Bo: hello".to_owned())
    });
    std::thread::sleep(std::time::Duration::from_secs(4));
    assert_eq!(reach_in(&bo, &g)["shared"], false);
    // And yes again.
    ask(
        &bo,
        json!({"cmd": "group-reach", "group": g, "share": true}),
    );
    assert_eq!(reach_in(&bo, &g)["shared"], true);

    // Ana adds Cy, who is not Bo's contact, and who now reads where Bo's
    // host is. Bo is told who, and what they can see.
    ask(
        &ana,
        json!({"cmd": "group-add", "group": g, "people": ["Cy"]}),
    );
    wait("bo is told that cy was added", 30, || {
        reach_in(&bo, &g)["added"] == json!(["Cy"])
    });
    let r = reach_in(&bo, &g);
    assert_eq!(
        (&r["shared"], &r["ask"]),
        (&json!(true), &json!(false)),
        "{r}"
    );
    assert_eq!(r["what"], json!([at]), "{r}");
    let listed = bo.cli(&["groups"]);
    assert!(
        listed.contains("Cy was added to Choir and is not a contact of yours"),
        "{listed}"
    );
    assert!(listed.contains(&at), "{listed}");
    // Nothing waits for him meanwhile, and nothing answers for him.
    std::thread::sleep(std::time::Duration::from_secs(3));
    assert_eq!(reach_in(&bo, &g)["added"], json!(["Cy"]));
    // He keeps it: told once, and not again.
    ask(
        &bo,
        json!({"cmd": "group-reach", "group": g, "share": true}),
    );
    let r = reach_in(&bo, &g);
    assert_eq!(
        (&r["shared"], &r["added"]),
        (&json!(true), &json!([])),
        "{r}"
    );
    std::thread::sleep(std::time::Duration::from_secs(3));
    assert_eq!(reach_in(&bo, &g)["added"], json!([]));
    // Or he empties it, as he was offered.
    ask(
        &bo,
        json!({"cmd": "group-reach", "group": g, "share": false}),
    );
    let r = reach_in(&bo, &g);
    assert_eq!(
        (&r["shared"], &r["added"]),
        (&json!(false), &json!([])),
        "{r}"
    );

    // He names it again, and then refuses Ana, who is there and reads it.
    // He is asked as part of refusing, with the group and what she sees.
    // Nothing tracks it afterwards: she did not come, so she is not
    // listed as someone added.
    ask(
        &bo,
        json!({"cmd": "group-reach", "group": g, "share": true}),
    );
    let r = reach_in(&bo, &g);
    assert_eq!(
        (&r["shared"], &r["added"]),
        (&json!(true), &json!([])),
        "{r}"
    );
    let told = bo.cli(&["contact", "Ana", "refuse"]);
    assert!(
        told.contains("Ana is in Choir and can still see your host's address there"),
        "{told}"
    );
    assert!(told.contains(&at), "{told}");
    let r = reach_in(&bo, &g);
    assert_eq!(
        (&r["shared"], &r["added"]),
        (&json!(true), &json!([])),
        "{r}"
    );
    assert_eq!(r["who"].as_array().map(Vec::len), Some(2), "{r}");
    assert!(!bo.cli(&["groups"]).contains("not a contact of yours"));
    // Refusing her again asks again, as the service tells a client: the
    // group, its name, and what is seen there.
    ask(
        &bo,
        json!({"cmd": "contact", "who": "Ana", "setting": "unrefuse"}),
    );
    let again = ask(
        &bo,
        json!({"cmd": "contact", "who": "Ana", "setting": "refuse"}),
    );
    assert_eq!(
        again["reach"],
        json!([{"group": g, "name": "Choir", "what": [at]}]),
        "{again}"
    );
    // He stops sharing it there, as he was offered. Refusing her now has
    // nothing to ask about.
    ask(
        &bo,
        json!({"cmd": "group-reach", "group": g, "share": false}),
    );
    assert_eq!(reach_in(&bo, &g)["shared"], false);
    ask(
        &bo,
        json!({"cmd": "contact", "who": "Ana", "setting": "unrefuse"}),
    );
    let again = ask(
        &bo,
        json!({"cmd": "contact", "who": "Ana", "setting": "refuse"}),
    );
    assert_eq!(again["reach"], json!([]), "{again}");
}

/// `hosts.md`, "An act that cannot be finished is finished later, by the
/// same device". Bo's phone joins a group among contacts while his host is
/// off. Naming the host takes a token registered with it, so the list is
/// set empty and the phone keeps his yes to itself, through a restart, and
/// names the host once it is back.
#[test]
fn a_yes_given_while_the_host_is_away_is_finished_when_it_is_back() {
    // pairing waits for the new device's files to be mounted
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let ana = person(root.path(), "ana");
    let mut bo = person(root.path(), "bo");
    let at = format!("127.0.0.1:{}", bo.port);
    bo.cli(&["host", "--address", &at]);
    meet(&ana, &bo, "Bo");
    let mut phone = Dev::new(root.path(), "phone", free_port());
    phone.start();
    pair(&bo, &phone);
    let made = ask(
        &ana,
        json!({"cmd": "group-create", "name": "Choir", "people": ["Bo"]}),
    );
    let g = made["group"].as_str().unwrap().to_owned();
    wait(
        "the offer reaches the phone, with what it would share",
        60,
        || {
            let all = reply(&phone, &json!({"cmd": "groups"}));
            let offers = all["offers"].as_array().cloned().unwrap_or_default();
            let offer = offers.iter().find(|o| o["name"] == "Choir");
            offer.is_some_and(|o| {
                o["reach"]["what"] == json!([at]) && o["reach"]["who"] == json!([])
            })
        },
    );
    bo.stop();
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Among contacts nothing is asked, and joining shares. The host is
    // away: nothing is named yet, and the yes waits here.
    let joined = ask(&phone, json!({"cmd": "group-join", "group": g}));
    assert_eq!(
        (&joined["shared"], &joined["waiting"]),
        (&json!(false), &json!(true)),
        "{joined}"
    );
    let r = reach_in(&phone, &g);
    assert_eq!(
        (&r["shared"], &r["waiting"]),
        (&json!(false), &json!(true)),
        "{r}"
    );
    // Said again, it waits as before: no error, and nothing new.
    let again = ask(
        &phone,
        json!({"cmd": "group-reach", "group": g, "share": true}),
    );
    assert_eq!(
        (&again["shared"], &again["waiting"]),
        (&json!(false), &json!(true)),
        "{again}"
    );
    // The phone is restarted, and still knows.
    phone.stop();
    phone.start();
    wait("the phone is back", 30, || {
        reply(&phone, &json!({"cmd": "groups"}))["ok"] == true
    });
    let r = reach_in(&phone, &g);
    assert_eq!(
        (&r["shared"], &r["waiting"]),
        (&json!(false), &json!(true)),
        "{r}"
    );
    // The host comes back: the phone registers a token and names it.
    bo.start_with(&["--no-mount"]);
    wait("the phone names the host", 90, || {
        let r = reach_in(&phone, &g);
        r["shared"] == true && r["waiting"] == false
    });
}

/// `hosts.md`, "What software does on its own": a host that serves the
/// person no longer is taken out of the lists that name it.
#[test]
fn a_host_that_stops_serving_is_taken_out_of_the_list() {
    let root = tempfile::tempdir().unwrap();
    let ana = person(root.path(), "ana");
    let bo = person(root.path(), "bo");
    let at = format!("127.0.0.1:{}", bo.port);
    bo.cli(&["host", "--address", &at]);
    meet(&ana, &bo, "Bo");
    let made = ask(
        &ana,
        json!({"cmd": "group-create", "name": "Choir", "people": ["Bo"]}),
    );
    let g = made["group"].as_str().unwrap().to_owned();
    wait("the offer arrives", 30, || {
        offers(&bo).iter().any(|o| o["name"] == "Choir")
    });
    let joined = ask(&bo, json!({"cmd": "group-join", "group": g}));
    assert_eq!(
        (&joined["shared"], &joined["waiting"]),
        (&json!(true), &json!(false)),
        "{joined}"
    );
    bo.cli(&["host", "--off"]);
    wait("the list names it no longer", 30, || {
        reach_in(&bo, &g)["shared"] == false
    });
    // With no host there is nothing to share, and nothing waits.
    let no = reply(
        &bo,
        &json!({"cmd": "group-reach", "group": g, "share": true}),
    );
    assert_eq!(no["ok"], false, "{no}");
    assert_eq!(reach_in(&bo, &g)["waiting"], false);
}

/// `hosts.md`: an entry stays "until that device, or the person, takes it
/// out". Removing a device is the person saying so: a host that was lost,
/// and so never takes itself out, leaves every list when it is removed, or
/// contacts would go on leaving messages with whoever holds it.
#[test]
fn a_removed_host_leaves_the_lists_that_name_it() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let ana = person(root.path(), "ana");
    let mut bo = Dev::new(root.path(), "bo", free_port());
    bo.start();
    bo.cli(&["init", "--yes", "--name", "Bo"]);
    bo.wait_mounted();
    let mut shelf = Dev::new(root.path(), "shelf", free_port());
    shelf.start();
    pair(&bo, &shelf);
    shelf.wait_mounted();
    let at = format!("127.0.0.1:{}", shelf.port);
    shelf.cli(&["host", "--address", &at]);
    wait("bo knows of his host", 30, || {
        ask(&bo, json!({"cmd": "status"}))["hosts"] == 1
    });
    meet(&ana, &bo, "Bo");
    let made = ask(
        &ana,
        json!({"cmd": "group-create", "name": "Choir", "people": ["Bo"]}),
    );
    let g = made["group"].as_str().unwrap().to_owned();
    wait("the offer arrives", 30, || {
        offers(&bo).iter().any(|o| o["name"] == "Choir")
    });
    let joined = ask(&bo, json!({"cmd": "group-join", "group": g}));
    assert_eq!(joined["shared"], true, "{joined}");
    let shared_at = |d: &Dev| {
        ask(d, json!({"cmd": "groups"}))["groups"]
            .as_array()
            .and_then(|all| all.iter().find(|x| x["group"] == g.as_str()).cloned())
            .is_some_and(|x| x["reach"]["shared"] == true)
    };
    wait("the host names itself there", 30, || {
        shared_at(&bo) && shared_at(&shelf)
    });

    // The shelf is lost: it never takes itself out.
    shelf.stop();
    bo.cli(&["remove-device", "shelf", "--lost"]);
    wait("the list names it no longer", 30, || {
        reach_in(&bo, &g)["shared"] == false
    });
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

/// The tokens a host has active, from where it keeps them.
fn active_tokens(d: &Dev) -> usize {
    let kept = std::fs::read(d.home.join("mailbox/state.json")).unwrap_or_default();
    let v: Value = serde_json::from_slice(&kept).unwrap_or_default();
    v["active"].as_array().map_or(0, Vec::len)
}

/// P14 (`hosts.md#delivery-tokens`, `spaces.md#members-and-roles`). A
/// token is what lets a space's members use a person's host. When the
/// person stops naming the host there, by saying no or by leaving, the
/// token they gave out there is ended, and not only left out of the node.
#[test]
fn a_token_ends_when_its_space_no_longer_names_the_host() {
    let root = tempfile::tempdir().unwrap();
    let ana = person(root.path(), "ana");
    let bo = person(root.path(), "bo");
    let at = format!("127.0.0.1:{}", bo.port);
    bo.cli(&["host", "--address", &at]);
    meet(&ana, &bo, "Bo");
    let made = ask(
        &ana,
        json!({"cmd": "group-create", "name": "Choir", "people": ["Bo"]}),
    );
    let g = made["group"].as_str().unwrap().to_owned();
    wait("the offer arrives", 30, || {
        offers(&bo).iter().any(|o| o["name"] == "Choir")
    });
    std::thread::sleep(std::time::Duration::from_secs(2));
    let without = active_tokens(&bo);
    ask(&bo, json!({"cmd": "group-join", "group": g}));
    wait("bo's host is named", 10, || {
        groups(&bo).iter().any(|x| x["name"] == "Choir") && reach_in(&bo, &g)["shared"] == true
    });
    assert_eq!(active_tokens(&bo), without + 1);
    // He says no: the node is emptied, and the token ended.
    ask(
        &bo,
        json!({"cmd": "group-reach", "group": g, "share": false}),
    );
    wait("the token ends with the no", 10, || {
        active_tokens(&bo) == without
    });
    // He shares again, with a new token, and leaves.
    ask(
        &bo,
        json!({"cmd": "group-reach", "group": g, "share": true}),
    );
    assert_eq!(active_tokens(&bo), without + 1);
    ask(&bo, json!({"cmd": "group-leave", "group": g}));
    wait("the token ends with the leave", 10, || {
        active_tokens(&bo) == without
    });
}
