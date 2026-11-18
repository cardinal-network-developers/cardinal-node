//! Who a person says they are is theirs, once, in the account's self node;
//! a device's name is only which machine it is; and what a person calls
//! others, and the picture they see for them, are their own (D71,
//! `profiles.md#account`).
//!
//! Skipped (with a message) when `/dev/fuse` or `fusermount3` is missing,
//! since pairing waits for the new device's folder.

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

/// What `devices` calls each device, this one first.
fn device_names(d: &Dev) -> Vec<String> {
    let v = ask(d, json!({"cmd": "devices"}));
    let mut all: Vec<(bool, String)> = v["devices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            let name = x["name"].as_str().unwrap_or_default().to_owned();
            (x["this"] != true, name)
        })
        .collect();
    all.sort();
    all.into_iter().map(|(_, n)| n).collect()
}

fn me(d: &Dev) -> String {
    let v = ask(d, json!({"cmd": "me"}));
    v["name"].as_str().unwrap_or_default().to_owned()
}

/// The contact `who` (by identity prefix or name) as `contacts` lists it.
fn contact(d: &Dev, who: &str) -> Option<Value> {
    let v = ask(d, json!({"cmd": "contacts"}));
    let all = v["contacts"].as_array().cloned().unwrap_or_default();
    all.into_iter()
        .find(|c| c["identity"].as_str() == Some(who) || c["name"].as_str() == Some(who))
}

fn identity(d: &Dev) -> String {
    d.status()["identity"].as_str().unwrap().to_owned()
}

/// Someone with one device, set up with `person` as their name.
fn person(root: &std::path::Path, device: &'static str, person: &str) -> Dev {
    let mut d = Dev::new(root, device, free_port());
    d.start();
    d.cli(&["init", "--yes", "--name", person]);
    d.wait_mounted();
    d
}

/// `from` invites, suggesting whatever its person's name is, and `to`
/// accepts.
fn meet(from: &Dev, to: &Dev) {
    let at = format!("127.0.0.1:{}", from.port);
    let code = from.cli(&["invite", "--address", &at]).trim().to_owned();
    to.cli(&["accept", &code]);
    let (a, b) = (identity(from), identity(to));
    wait("both are contacts", 30, || {
        contact(from, &b).is_some() && contact(to, &a).is_some()
    });
}

fn skip() -> bool {
    let no = !fuse_available();
    if no {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
    }
    no
}

/// `init` names the person, and the device after its machine or as told;
/// pairing names the new device and leaves the person's name as it was;
/// a window's `setup-finish` takes the person's name and the device's.
#[test]
fn the_person_and_the_device_are_named_apart() {
    if skip() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut a = Dev::new(root.path(), "alpha", free_port());
    let mut b = Dev::new(root.path(), "beta", free_port());
    a.start();
    b.start();
    let said = a.cli(&[
        "init",
        "--yes",
        "--name",
        "Ana Lima",
        "--device-name",
        "Laptop",
    ]);
    assert!(
        said.contains("Ana Lima") && said.contains("Laptop"),
        "{said}"
    );
    a.wait_mounted();
    assert_eq!(me(&a), "Ana Lima");
    assert_eq!(ask(&a, json!({"cmd": "me"}))["set"], true);
    assert_eq!(device_names(&a), ["Laptop"]);
    assert_eq!(a.cli(&["me"]).trim(), "Ana Lima");

    // The new device names itself; the one typing may name it instead.
    pair_with(&a, &b, false, None, &["--device-name", "Tablet"], &[]);
    wait("both list both", 60, || {
        device_names(&a).len() == 2 && device_names(&b).len() == 2
    });
    assert_eq!(device_names(&a), ["Laptop", "Tablet"]);
    assert_eq!(device_names(&b), ["Tablet", "Laptop"]);
    wait("the new device knows its person's name", 30, || {
        me(&b) == "Ana Lima"
    });
    assert_eq!(me(&a), "Ana Lima");

    let mut c = Dev::new(root.path(), "gamma", free_port());
    c.start();
    pair_with(&a, &c, false, None, &[], &["--device-name", "Phone"]);
    wait("all list all", 60, || device_names(&c).len() == 3);
    assert_eq!(device_names(&c), ["Phone", "Laptop", "Tablet"]);
    assert_eq!(me(&c), "Ana Lima");

    // A window sets up: the person's name, and the device's from the phone.
    let mut w = Dev::new(root.path(), "delta", free_port());
    w.start();
    let begun = ask(&w, json!({"cmd": "setup-begin"}));
    let words: Vec<String> = serde_json::from_value(begun["words"].clone()).unwrap();
    let at: Vec<usize> = serde_json::from_value(begun["ask"].clone()).unwrap();
    let answers: Vec<&str> = at.iter().map(|i| words[*i].as_str()).collect();
    let done = ask(
        &w,
        json!({"cmd": "setup-finish", "name": " Bo ", "device": "Bo's phone", "answers": answers}),
    );
    assert_eq!(done["name"], "Bo");
    assert_eq!(done["device"], "Bo's phone");
    w.wait_mounted();
    assert_eq!(me(&w), "Bo");
    assert_eq!(device_names(&w), ["Bo's phone"]);
    // Without `device`, the machine's name, which a test cannot know: but
    // never the person's.
    let mut v = Dev::new(root.path(), "epsilon", free_port());
    v.start();
    let begun = ask(&v, json!({"cmd": "setup-begin"}));
    let words: Vec<String> = serde_json::from_value(begun["words"].clone()).unwrap();
    let at: Vec<usize> = serde_json::from_value(begun["ask"].clone()).unwrap();
    let answers: Vec<&str> = at.iter().map(|i| words[*i].as_str()).collect();
    ask(
        &v,
        json!({"cmd": "setup-finish", "name": "Cy", "answers": answers}),
    );
    v.wait_mounted();
    assert_eq!(me(&v), "Cy");
    assert_eq!(device_names(&v), ["epsilon"], "the name it runs with");

    // Renaming a device leaves the person's name; setting it leaves the
    // devices'.
    ask(
        &b,
        json!({"cmd": "device-rename", "device": "Laptop", "name": "Desk"}),
    );
    ask(&b, json!({"cmd": "me", "name": "Ana"}));
    wait("each device has both", 30, || {
        [&a, &b, &c].iter().all(|d| me(d) == "Ana")
            && device_names(&a) == ["Desk", "Phone", "Tablet"]
    });
    for d in [&mut a, &mut b, &mut c, &mut w, &mut v] {
        d.stop();
    }
}

/// An invitation, the hello and an introduction suggest the name in the
/// self node, set from any of the person's devices; a contact made records
/// it as theirs; a petname cleared shows it, marked as theirs; a picture is
/// set from a file in the one folder or on the disk, reaches the person's
/// other devices, and is cleared.
#[test]
fn contacts_hear_the_persons_name_and_keep_their_own() {
    if skip() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    // Ana has two devices, named nothing like her.
    let mut a1 = person(root.path(), "laptop", "Ana");
    let mut a2 = Dev::new(root.path(), "phone", free_port());
    a2.start();
    pair(&a1, &a2);
    let mut cy = person(root.path(), "desk", "Cy");
    let mut cy2 = Dev::new(root.path(), "pocket", free_port());
    cy2.start();
    pair(&cy, &cy2);
    let mut dee = person(root.path(), "tower", "Dee");

    // The invitation carries Ana's name, and the hello Cy's.
    meet(&a1, &cy);
    let ana_id = identity(&a1);
    let cy_id = identity(&cy);
    let ana = contact(&cy, &ana_id).unwrap();
    assert_eq!(ana["name"], "Ana", "{ana}");
    assert_eq!(ana["suggested"], "Ana", "{ana}");
    assert_eq!(
        ana["own"], true,
        "a name accepted is the person's own: {ana}"
    );
    let cy_there = contact(&a1, &cy_id).unwrap();
    assert_eq!(cy_there["name"], "Cy", "{cy_there}");
    assert_eq!(cy_there["suggested"], "Cy", "{cy_there}");

    // Ana changes her name on her phone: the next invitation, made on the
    // laptop, carries it.
    ask(&a2, json!({"cmd": "me", "name": "Ana Lima"}));
    wait("the laptop has the new name", 30, || me(&a1) == "Ana Lima");
    meet(&a1, &dee);
    let seen = contact(&dee, &ana_id).unwrap();
    assert_eq!(seen["suggested"], "Ana Lima", "{seen}");
    let made = ask(&a1, json!({"cmd": "invitations"}));
    let mut names: Vec<String> = made["invitations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["name"].as_str().unwrap_or_default().to_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["Ana", "Ana Lima"]);

    // Dee meets Cy too, and introduces Cy to someone as Cy suggests, never
    // by what Dee calls Cy.
    meet(&cy, &dee);
    ask(
        &dee,
        json!({"cmd": "contact", "who": cy_id, "name": "Cousin"}),
    );
    let mut fresh = person(root.path(), "box", "Eve");
    meet(&dee, &fresh);
    ask(
        &dee,
        json!({"cmd": "introduce", "who": "Cousin", "to": "Eve"}),
    );
    wait("Eve hears of Cy", 30, || {
        let v = ask(&fresh, json!({"cmd": "introductions"}));
        v["introductions"]
            .as_array()
            .is_some_and(|a| a.iter().any(|i| i["name"] == "Cy"))
    });
    let v = ask(&fresh, json!({"cmd": "introductions"}));
    assert!(!v.to_string().contains("Cousin"), "{v}");

    // Cy calls Ana something else, and then clears it: Ana's own name is
    // shown, as hers.
    ask(&cy, json!({"cmd": "contact", "who": "Ana", "name": "Sis"}));
    let sis = contact(&cy, &ana_id).unwrap();
    assert_eq!((&sis["name"], &sis["own"]), (&json!("Sis"), &json!(true)));
    let cleared = ask(&cy, json!({"cmd": "contact", "who": "Sis", "name": ""}));
    assert_eq!(cleared["own"], false, "{cleared}");
    let theirs = contact(&cy, &ana_id).unwrap();
    assert_eq!(theirs["name"], "Ana", "{theirs}");
    assert_eq!(theirs["own"], false, "{theirs}");
    assert_eq!(theirs["suggested"], "Ana", "{theirs}");
    let line = cy.cli(&["contacts"]);
    assert!(line.contains("Ana (their name)"), "{line}");
    wait("Cy's other device shows it too", 30, || {
        contact(&cy2, &ana_id).is_some_and(|c| c["own"] == false && c["name"] == "Ana")
    });
    // The conversation is listed the same way.
    let convs = ask(&cy, json!({"cmd": "conversations"}));
    let conv = convs["conversations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == json!(ana_id))
        .cloned()
        .unwrap();
    assert_eq!(
        (&conv["name"], &conv["own"]),
        (&json!("Ana"), &json!(false))
    );

    // A picture from the disk.
    let png = |n: u8| {
        let mut b = b"\x89PNG\r\n\x1a\n".to_vec();
        b.extend(std::iter::repeat_n(n, 4000));
        b
    };
    let on_disk = root.path().join("ana.png");
    std::fs::write(&on_disk, png(1)).unwrap();
    let set = ask(
        &cy,
        json!({"cmd": "contact", "who": "Ana", "picture": on_disk.display().to_string()}),
    );
    let shown = set["picture"].as_str().unwrap().to_owned();
    assert!(shown.ends_with(".png"), "{shown}");
    assert_eq!(std::fs::read(&shown).unwrap(), png(1));
    // The file can go: the picture is a copy.
    std::fs::remove_file(&on_disk).unwrap();
    let listed = contact(&cy, &ana_id).unwrap();
    assert_eq!(listed["picture"], json!(shown));
    let line = cy.cli(&["contacts"]);
    assert!(line.contains("picture"), "{line}");
    // It reaches Cy's other device, as a file there.
    wait("the picture on Cy's other device", 60, || {
        contact(&cy2, &ana_id)
            .and_then(|c| c["picture"].as_str().map(str::to_owned))
            .and_then(|p| std::fs::read(p).ok())
            == Some(png(1))
    });

    // A picture Ana sent, from the folder Cy shares with her.
    let sent = root.path().join("me.png");
    std::fs::write(&sent, png(2)).unwrap();
    ask(
        &a1,
        json!({"cmd": "say", "who": "Cy", "text": "me", "attach": [sent.display().to_string()]}),
    );
    wait("the picture arrives", 60, || {
        let v = reply(&cy, &json!({"cmd": "files", "path": "People/Ana"}));
        v.to_string().contains("me.png")
    });
    let set = ask(
        &cy,
        json!({"cmd": "contact", "who": "Ana", "picture": "People/Ana/me.png"}),
    );
    let p = set["picture"].as_str().unwrap().to_owned();
    assert_eq!(std::fs::read(&p).unwrap(), png(2));
    wait("the new picture on Cy's other device", 60, || {
        contact(&cy2, &ana_id)
            .and_then(|c| c["picture"].as_str().map(str::to_owned))
            .and_then(|p| std::fs::read(p).ok())
            == Some(png(2))
    });
    // Ana's devices know nothing of it.
    let cy_there = contact(&a1, &cy_id).unwrap();
    assert!(cy_there["picture"].is_null(), "{cy_there}");

    // Cleared, on both.
    ask(&cy2, json!({"cmd": "contact", "who": "Ana", "picture": ""}));
    wait("no picture on either", 30, || {
        [&cy, &cy2]
            .iter()
            .all(|d| contact(d, &ana_id).is_some_and(|c| c["picture"].is_null()))
    });
    for d in [&mut a1, &mut a2, &mut cy, &mut cy2, &mut dee, &mut fresh] {
        d.stop();
    }
}
