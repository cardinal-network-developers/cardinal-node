//! The one folder and each relationship's shared folder
//! (`profiles.md#one-folder-for-everything-guidance`, `profiles.md#shared-folder`),
//! through the local interface a window uses. These daemons mount nothing:
//! what is tested is what every client sees, whatever shows the files.

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

fn refused(d: &Dev, req: Value) -> String {
    let r = reply(d, &req);
    assert_eq!(r["ok"], false, "{req} got {r}");
    r["error"].as_str().unwrap_or_default().to_owned()
}

fn person(root: &std::path::Path, name: &'static str, args: &[&str]) -> Dev {
    let mut d = Dev::new(root, name, free_port());
    d.start_with(&[&["--no-mount"], args].concat());
    d.cli(&["init", "--yes", "--name", name]);
    wait(&format!("{name}'s files"), 30, || {
        reply(&d, &json!({"cmd": "files"}))["ok"] == true
    });
    d
}

/// Ana and Bo, who call each other Ana and Bo.
fn met(root: &std::path::Path, bo_args: &[&str]) -> (Dev, Dev) {
    let a = person(root, "ana", &[]);
    let b = person(root, "bo", bo_args);
    let at = format!("127.0.0.1:{}", a.port);
    let code = a.cli(&["invite", "--address", &at, "--name", "Ana"]);
    b.cli(&["accept", code.trim(), "--name", "Ana"]);
    wait("each lists the other", 30, || {
        let n = |d: &Dev| {
            ask(d, json!({"cmd": "conversations"}))["conversations"]
                .as_array()
                .map(Vec::len)
        };
        n(&a) == Some(1) && n(&b) == Some(1)
    });
    let theirs = ask(&a, json!({"cmd": "conversations"}))["conversations"][0]["id"].clone();
    ask(&a, json!({"cmd": "contact", "who": theirs, "name": "Bo"}));
    (a, b)
}

fn names(d: &Dev, path: &str) -> Vec<String> {
    let v = ask(d, json!({"cmd": "files", "path": path}));
    v["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["name"].as_str().unwrap().to_owned())
        .collect()
}

fn entry(d: &Dev, path: &str, name: &str) -> Value {
    let v = ask(d, json!({"cmd": "files", "path": path}));
    let found = v["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == name)
        .cloned();
    found.unwrap_or(Value::Null)
}

fn said(d: &Dev, who: &str) -> Vec<Value> {
    ask(d, json!({"cmd": "messages", "who": who}))["messages"]
        .as_array()
        .unwrap()
        .clone()
}

fn bytes(n: u32, seed: u32) -> Vec<u8> {
    (0..n)
        .map(|i| (i.wrapping_mul(31).wrapping_add(seed) % 251) as u8)
        .collect()
}

/// Saves a file of the one folder to disk and reads it back.
fn saved(d: &Dev, root: &std::path::Path, path: &str) -> Vec<u8> {
    let to = root.join(format!("saved-{}-{}", d.name, path.replace('/', "_")));
    let _ = std::fs::remove_file(&to);
    ask(d, json!({"cmd": "save", "path": path, "to": to}));
    std::fs::read(&to).unwrap()
}

#[test]
fn a_file_sent_is_in_the_folder_both_share() {
    let root = tempfile::tempdir().unwrap();
    let (a, b) = met(root.path(), &[]);
    let photo = bytes(700_000, 1);
    let path = root.path().join("photo.jpg");
    std::fs::write(&path, &photo).unwrap();
    ask(
        &a,
        json!({"cmd": "say", "who": "Bo", "text": "a photo", "attach": [path]}),
    );
    wait("Bo has the message", 20, || said(&b, "Ana").len() == 1);
    wait("in Bo's folder for Ana", 20, || {
        names(&b, "People/Ana") == ["photo.jpg"]
    });

    assert_eq!(names(&a, ""), ["People"]);
    assert_eq!(names(&a, "People"), ["Bo"]);
    assert_eq!(entry(&a, "People", "Bo")["folder"], true);
    assert!(entry(&a, "People", "Bo")["who"].is_string());
    assert_eq!(names(&a, "People/Bo"), ["photo.jpg"]);
    assert_eq!(entry(&a, "People/Bo", "photo.jpg")["mine"], true);
    assert_eq!(entry(&b, "People/Ana", "photo.jpg")["mine"], false);
    assert_eq!(entry(&b, "People/Ana", "photo.jpg")["size"], 700_000);
    // stored once: the message and the folder name the same content
    assert_eq!(saved(&b, root.path(), "People/Ana/photo.jpg"), photo);
}

#[test]
fn files_go_between_my_files_and_a_shared_folder() {
    let root = tempfile::tempdir().unwrap();
    let (a, b) = met(root.path(), &[]);
    let plans = bytes(300_000, 2);
    std::fs::write(root.path().join("plans.pdf"), &plans).unwrap();
    std::fs::write(root.path().join("note.txt"), "small").unwrap();

    // Ana's own files first, from her disk.
    ask(&a, json!({"cmd": "mkdir", "path": "work"}));
    ask(
        &a,
        json!({"cmd": "put", "from": root.path().join("plans.pdf"), "to": "work"}),
    );
    ask(
        &a,
        json!({"cmd": "put", "from": root.path().join("note.txt"), "to": "work"}),
    );
    assert_eq!(names(&a, "work"), ["note.txt", "plans.pdf"]);

    // Shared without a word: in the folder, and nothing in the conversation.
    ask(
        &a,
        json!({"cmd": "share", "who": "Bo", "paths": ["work/plans.pdf"]}),
    );
    wait("in Bo's folder", 20, || {
        names(&b, "People/Ana") == ["plans.pdf"]
    });
    assert!(said(&b, "Ana").is_empty());
    assert_eq!(saved(&b, root.path(), "People/Ana/plans.pdf"), plans);

    // Shared with a word: a message carrying it, and the folder too.
    ask(
        &a,
        json!({"cmd": "share", "who": "Bo", "paths": ["work/note.txt"], "text": "and this"}),
    );
    wait("the message", 20, || said(&b, "Ana").len() == 1);
    let m = &said(&b, "Ana")[0];
    assert_eq!(m["text"], "and this");
    assert_eq!(m["attachments"][0]["name"], "note.txt");
    wait("both in the folder", 20, || {
        names(&b, "People/Ana") == ["note.txt", "plans.pdf"]
    });
    assert_eq!(saved(&b, root.path(), "People/Ana/note.txt"), b"small");

    // Bo keeps one in his own files; it is his to change from then on.
    ask(
        &b,
        json!({"cmd": "copy", "from": "People/Ana/plans.pdf", "to": ""}),
    );
    assert!(
        names(&b, "").contains(&"plans.pdf".to_owned()),
        "{:?}",
        names(&b, "")
    );
    assert_eq!(saved(&b, root.path(), "plans.pdf"), plans);

    // And puts one of his own in the folder they share: Ana's devices may
    // fetch what Bo put there.
    let drawing = bytes(200_000, 3);
    std::fs::write(root.path().join("drawing.png"), &drawing).unwrap();
    ask(
        &b,
        json!({"cmd": "put", "from": root.path().join("drawing.png"), "to": ""}),
    );
    ask(
        &b,
        json!({"cmd": "copy", "from": "drawing.png", "to": "People/Ana"}),
    );
    wait("Ana sees it", 20, || {
        names(&a, "People/Bo").contains(&"drawing.png".to_owned())
    });
    assert_eq!(saved(&a, root.path(), "People/Bo/drawing.png"), drawing);

    // Moving between spaces copies and removes.
    ask(
        &a,
        json!({"cmd": "move", "from": "People/Bo/drawing.png", "to": "work/drawing.png"}),
    );
    assert_eq!(saved(&a, root.path(), "work/drawing.png"), drawing);
    wait("gone from what they share", 20, || {
        !names(&b, "People/Ana").contains(&"drawing.png".to_owned())
    });
}

#[test]
fn a_shared_folder_is_a_folder() {
    let root = tempfile::tempdir().unwrap();
    let (a, b) = met(root.path(), &[]);
    std::fs::write(root.path().join("list.txt"), "eggs").unwrap();
    ask(&a, json!({"cmd": "mkdir", "path": "People/Bo/trip"}));
    ask(
        &a,
        json!({"cmd": "put", "from": root.path().join("list.txt"), "to": "People/Bo/trip"}),
    );
    wait("Bo sees the folder", 20, || {
        names(&b, "People/Ana/trip") == ["list.txt"]
    });
    ask(
        &b,
        json!({"cmd": "move", "from": "People/Ana/trip/list.txt", "to": "People/Ana/trip/packing.txt"}),
    );
    wait("Ana sees the rename", 20, || {
        names(&a, "People/Bo/trip") == ["packing.txt"]
    });
    ask(
        &b,
        json!({"cmd": "copy", "from": "People/Ana/trip", "to": ""}),
    );
    assert_eq!(names(&b, "trip"), ["packing.txt"]);
    ask(&a, json!({"cmd": "remove", "path": "People/Bo/trip"}));
    wait("gone for Bo", 20, || names(&b, "People/Ana").is_empty());
    // Bo's own copy stays.
    assert_eq!(saved(&b, root.path(), "trip/packing.txt"), b"eggs");

    let no = refused(&a, json!({"cmd": "remove", "path": "People/Bo"}));
    assert!(no.contains("refuse"), "{no}");
    let no = refused(&a, json!({"cmd": "mkdir", "path": "People/somebody"}));
    assert!(no.contains("People"), "{no}");
    let no = refused(&a, json!({"cmd": "mkdir", "path": "People"}));
    assert!(no.contains("People"), "{no}");
}

#[test]
fn a_folder_follows_what_someone_is_called() {
    let root = tempfile::tempdir().unwrap();
    let (a, _b) = met(root.path(), &[]);
    let who = entry(&a, "People", "Bo")["who"]
        .as_str()
        .unwrap()
        .to_owned();

    // Renaming the folder renames the contact, and the other way round.
    ask(
        &a,
        json!({"cmd": "move", "from": "People/Bo", "to": "People/Bobby"}),
    );
    assert_eq!(names(&a, "People"), ["Bobby"]);
    let c = &ask(&a, json!({"cmd": "contacts"}))["contacts"][0];
    assert_eq!(c["name"], "Bobby");
    ask(&a, json!({"cmd": "contact", "who": who, "name": "Bo"}));
    assert_eq!(names(&a, "People"), ["Bo"]);

    // Listed under another category, they move to its folder.
    ask(
        &a,
        json!({"cmd": "contact", "who": who, "category": "Family"}),
    );
    assert_eq!(names(&a, ""), ["Family"]);
    assert_eq!(names(&a, "Family"), ["Bo"]);

    // Ana's own folder named like a category is shown beside it.
    ask(&a, json!({"cmd": "mkdir", "path": "Notes"}));
    ask(
        &a,
        json!({"cmd": "contact", "who": who, "category": "Notes"}),
    );
    assert_eq!(names(&a, ""), ["Notes", "Notes (2)"]);
    assert_eq!(names(&a, "Notes"), ["Bo"]);
    assert!(names(&a, "Notes (2)").is_empty());
}

#[test]
fn a_phone_keeps_pictures_and_fetches_the_rest_when_opened() {
    let root = tempfile::tempdir().unwrap();
    let (mut a, b) = met(root.path(), &[]);
    ask(&b, json!({"cmd": "retention", "mode": "on-demand"}));
    let photo = bytes(400_000, 4);
    let film = bytes(400_000, 5);
    std::fs::write(root.path().join("photo.jpg"), &photo).unwrap();
    std::fs::write(root.path().join("film.mp4"), &film).unwrap();
    let attach = json!([root.path().join("photo.jpg"), root.path().join("film.mp4")]);
    ask(
        &a,
        json!({"cmd": "say", "who": "Bo", "text": "two", "attach": attach}),
    );
    wait("in Bo's folder", 20, || names(&b, "People/Ana").len() == 2);
    // The picture comes by itself; the film waits to be opened.
    std::thread::sleep(std::time::Duration::from_secs(6));
    a.stop();
    assert_eq!(saved(&b, root.path(), "People/Ana/photo.jpg"), photo);
    let to = root.path().join("film-copy.mp4");
    let no = refused(
        &b,
        json!({"cmd": "save", "path": "People/Ana/film.mp4", "to": to}),
    );
    assert!(no.contains("fetched"), "{no}");
}

#[test]
fn a_computer_keeps_what_it_is_sent() {
    let root = tempfile::tempdir().unwrap();
    let (mut a, b) = met(root.path(), &[]);
    let film = bytes(400_000, 6);
    std::fs::write(root.path().join("film.mp4"), &film).unwrap();
    ask(
        &a,
        json!({"cmd": "put", "from": root.path().join("film.mp4"), "to": "People/Bo"}),
    );
    wait("in Bo's folder", 20, || {
        names(&b, "People/Ana") == ["film.mp4"]
    });
    std::thread::sleep(std::time::Duration::from_secs(6));
    a.stop();
    assert_eq!(saved(&b, root.path(), "People/Ana/film.mp4"), film);
}

#[test]
fn the_command_line_does_the_same() {
    let root = tempfile::tempdir().unwrap();
    let (a, b) = met(root.path(), &[]);
    assert!(a.cli(&["files"]).contains("People/"));
    assert!(a.cli(&["files", "People"]).contains("Bo/"));
    std::fs::write(root.path().join("list.txt"), "eggs").unwrap();
    a.cli(&["put", root.path().join("list.txt").to_str().unwrap()]);
    a.cli(&["share", "Bo", "list.txt", "--message", "for the trip"]);
    wait("at Bo's", 20, || names(&b, "People/Ana") == ["list.txt"]);
    assert!(b.cli(&["files", "People/Ana"]).contains("Shared with Ana"));
    let got = root.path().join("got.txt");
    b.cli(&["get", "People/Ana/list.txt", got.to_str().unwrap()]);
    assert_eq!(std::fs::read(&got).unwrap(), b"eggs");
    let who = entry(&a, "People", "Bo")["who"]
        .as_str()
        .unwrap()
        .to_owned();
    a.cli(&["contact", &who, "category", "Family"]);
    assert!(a.cli(&["files"]).contains("Family/"));
}
