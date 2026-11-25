//! The history of the one folder's files through the local interface and
//! the command line: what was deleted from a folder and bringing it back
//! (`deleted`, `undelete`), the versions of a file and bringing one back
//! (`history`, `restore`), and copying an earlier version out without
//! bringing it back (`save` with `version`). Each works in the person's own
//! files, in a contact's folder in `People` and in a group's in `Groups`.
//! These daemons mount nothing.

mod common;

use std::path::Path;

use common::*;
use serde_json::{json, Value};

fn ask(d: &Dev, req: Value) -> Value {
    let r = common::reply(d, &req);
    assert_eq!(r["ok"], true, "{req} got {r}");
    r
}

fn refused(d: &Dev, req: Value) -> String {
    let r = common::reply(d, &req);
    assert_eq!(r["ok"], false, "{req} got {r}");
    r["error"].as_str().unwrap_or_default().to_owned()
}

fn person(root: &Path, name: &'static str) -> Dev {
    let mut d = Dev::new(root, name, free_port());
    d.start_with(&["--no-mount"]);
    let mut called = name.to_owned();
    called[..1].make_ascii_uppercase();
    d.cli(&["init", "--yes", "--name", &called]);
    wait(&format!("{name}'s files"), 30, || {
        common::reply(&d, &json!({"cmd": "files"}))["ok"] == true
    });
    d
}

fn names(d: &Dev, path: &str) -> Vec<String> {
    let v = common::reply(d, &json!({"cmd": "files", "path": path}));
    if v["ok"] != true {
        return Vec::new();
    }
    let all = v["files"].as_array().cloned().unwrap_or_default();
    all.iter()
        .map(|f| f["name"].as_str().unwrap().to_owned())
        .collect()
}

fn deleted(d: &Dev, path: &str) -> Vec<Value> {
    let v = ask(d, json!({"cmd": "deleted", "path": path}));
    v["files"].as_array().cloned().unwrap_or_default()
}

/// Puts a file holding `text` at `path` in the one folder (`put`, where it
/// is new; `write`, a new version, where it is there).
fn put(d: &Dev, root: &Path, path: &str, text: &str) {
    let local = root.join(format!("in-{}-{}", d.name, path.replace('/', "_")));
    std::fs::write(&local, text).unwrap();
    ask(d, json!({"cmd": "write", "from": local, "path": path}));
}

fn saved(d: &Dev, root: &Path, path: &str, version: Option<u64>) -> String {
    let to = root.join(format!("saved-{}-{}", d.name, path.replace('/', "_")));
    let _ = std::fs::remove_file(&to);
    let mut req = json!({"cmd": "save", "path": path, "to": to});
    if let Some(n) = version {
        req["version"] = json!(n);
    }
    ask(d, req);
    std::fs::read_to_string(&to).unwrap()
}

fn versions(d: &Dev, path: &str) -> Vec<Value> {
    let v = ask(d, json!({"cmd": "history", "path": path}));
    v["versions"].as_array().cloned().unwrap_or_default()
}

#[test]
fn own_files_deleted_and_brought_back() {
    let root = tempfile::tempdir().unwrap();
    let r = root.path();
    let ana = person(r, "ana");
    ask(&ana, json!({"cmd": "mkdir", "path": "Notes"}));
    put(&ana, r, "Notes/a.txt", "one");
    put(&ana, r, "Notes/a.txt", "two");
    assert!(deleted(&ana, "Notes").is_empty());

    // An earlier version copied out leaves the file as it is.
    assert_eq!(saved(&ana, r, "Notes/a.txt", Some(1)), "one");
    assert_eq!(saved(&ana, r, "Notes/a.txt", None), "two");
    assert_eq!(versions(&ana, "Notes/a.txt").len(), 2);
    let no = refused(
        &ana,
        json!({"cmd": "save", "path": "Notes/a.txt", "to": r.join("x"), "version": 3}),
    );
    assert!(no.contains("versions 1 to 2"), "{no}");
    let out = r.join("cli-v1.txt");
    ana.cli(&[
        "get",
        "Notes/a.txt",
        out.to_str().unwrap(),
        "--version",
        "1",
    ]);
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "one");

    // Deleted, it is listed with when, by which device, and its size.
    ask(&ana, json!({"cmd": "remove", "path": "Notes/a.txt"}));
    assert!(names(&ana, "Notes").is_empty());
    let gone = deleted(&ana, "Notes");
    assert_eq!(gone.len(), 1, "{gone:?}");
    let g = &gone[0];
    assert_eq!(g["name"], "a.txt");
    assert_eq!(g["folder"], false);
    assert_eq!(g["size"], 3);
    assert_eq!(g["mine"], true);
    assert!(g["time"].as_u64().is_some(), "{g}");
    let me = ana.status();
    let device = me["devices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["this"] == true)
        .unwrap()["name"]
        .clone();
    assert_eq!(g["by"], device, "{g}");
    let listed = ana.cli(&["deleted", "Notes"]);
    assert!(
        listed.contains("a.txt") && listed.contains("undelete"),
        "{listed}"
    );
    // History is of what is there: a deleted file is undeleted first.
    refused(&ana, json!({"cmd": "history", "path": "Notes/a.txt"}));

    // Brought back, with its versions.
    let back = ana.cli(&["undelete", "Notes/a.txt"]);
    assert!(back.contains("Notes/a.txt"), "{back}");
    assert_eq!(names(&ana, "Notes"), ["a.txt"]);
    assert_eq!(saved(&ana, r, "Notes/a.txt", None), "two");
    assert_eq!(versions(&ana, "Notes/a.txt").len(), 2);
    assert!(deleted(&ana, "Notes").is_empty());
    let no = refused(&ana, json!({"cmd": "undelete", "path": "Notes/a.txt"}));
    assert!(no.contains("nothing named a.txt"), "{no}");

    // Back beside a new file of its name, the two are shown as the folder
    // shows any two of one name: the one made first keeps it.
    ask(&ana, json!({"cmd": "remove", "path": "Notes/a.txt"}));
    put(&ana, r, "Notes/a.txt", "newer");
    let v = ask(&ana, json!({"cmd": "undelete", "path": "Notes/a.txt"}));
    assert_eq!(v["path"], "Notes/a.txt", "{v}");
    assert_eq!(names(&ana, "Notes"), ["a (2).txt", "a.txt"]);
    assert_eq!(saved(&ana, r, "Notes/a.txt", None), "two");
    assert_eq!(saved(&ana, r, "Notes/a (2).txt", None), "newer");

    // Two deleted of one name: which is the person's to say, by id.
    ask(&ana, json!({"cmd": "remove", "path": "Notes/a (2).txt"}));
    ask(&ana, json!({"cmd": "remove", "path": "Notes/a.txt"}));
    let gone = deleted(&ana, "Notes");
    assert_eq!(gone.len(), 2, "{gone:?}");
    let no = refused(&ana, json!({"cmd": "undelete", "path": "Notes/a.txt"}));
    assert!(no.contains("2 deleted items"), "{no}");
    let listed = ana.cli(&["deleted", "Notes"]);
    assert!(listed.contains("--id"), "{listed}");
    let older = gone.iter().find(|g| g["size"] == 3).unwrap();
    let id = older["id"].as_str().unwrap();
    ana.cli(&["undelete", "Notes/a.txt", "--id", &id[..12]]);
    assert_eq!(names(&ana, "Notes"), ["a.txt"]);
    assert_eq!(saved(&ana, r, "Notes/a.txt", None), "two");
    let no = refused(
        &ana,
        json!({"cmd": "undelete", "path": "Notes/a.txt", "id": "ffffffffffff"}),
    );
    assert!(no.contains("that id"), "{no}");

    // A folder comes back with what was in it; what is in it is not
    // listed on its own.
    ask(&ana, json!({"cmd": "remove", "path": "Notes"}));
    let gone = deleted(&ana, "");
    assert_eq!(gone.len(), 1, "{gone:?}");
    assert_eq!(gone[0]["name"], "Notes");
    assert_eq!(gone[0]["folder"], true);
    ana.cli(&["undelete", "Notes"]);
    assert_eq!(names(&ana, "Notes"), ["a.txt"]);
    // the copy deleted on its own before stays deleted
    assert_eq!(deleted(&ana, "Notes").len(), 1);
}

#[test]
fn shared_folders_have_their_history() {
    let root = tempfile::tempdir().unwrap();
    let r = root.path();
    let ana = person(r, "ana");
    let bo = person(r, "bo");
    let at = format!("127.0.0.1:{}", ana.port);
    let code = ana.cli(&["invite", "--address", &at, "--name", "Ana"]);
    bo.cli(&["accept", code.trim(), "--name", "Ana"]);
    wait("ana lists bo", 30, || {
        ana.cli(&["contacts"]).to_lowercase().contains("bo")
    });
    ask(&ana, json!({"cmd": "contact", "who": "bo", "name": "Bo"}));
    wait("bo's folder", 30, || names(&ana, "People") == ["Bo"]);
    wait("ana's folder", 30, || names(&bo, "People") == ["Ana"]);

    let made = ask(
        &ana,
        json!({"cmd": "group-create", "name": "Family", "people": ["Bo"]}),
    );
    let g = made["group"].as_str().unwrap().to_owned();
    wait("the offer arrives", 30, || {
        let v = ask(&bo, json!({"cmd": "groups"}));
        v["offers"]
            .as_array()
            .is_some_and(|o| o.iter().any(|o| o["name"] == "Family"))
    });
    ask(&bo, json!({"cmd": "group-join", "group": g}));
    wait("bo's group folder", 30, || {
        names(&bo, "Groups") == ["Family"]
    });

    for (mine, theirs) in [
        ("People/Bo", "People/Ana"),
        ("Groups/Family", "Groups/Family"),
    ] {
        let (af, bf) = (format!("{mine}/list.txt"), format!("{theirs}/list.txt"));
        // Ana writes it, and Bo a second version.
        put(&ana, r, &af, "eggs");
        wait("bo has it", 30, || names(&bo, theirs) == ["list.txt"]);
        put(&bo, r, &bf, "eggs, milk");
        wait("ana has bo's version", 30, || {
            saved(&ana, r, &af, None) == "eggs, milk"
        });
        let vs = versions(&ana, &af);
        assert_eq!(vs.len(), 2, "{vs:?}");
        assert!(vs[0].get("by").is_none(), "{vs:?}");
        assert_eq!(vs[1]["by"], "Bo", "{vs:?}");
        assert_eq!(vs[1]["current"], true, "{vs:?}");
        let h = ana.cli(&["history", &af]);
        assert!(h.contains("  1  ") && h.contains("  2  "), "{h}");
        // the first copied out, as it was
        assert_eq!(saved(&ana, r, &af, Some(1)), "eggs");
        assert_eq!(saved(&bo, r, &bf, Some(1)), "eggs");

        // Ana brings back her version, on the command line, for both.
        ana.cli(&["restore", &af, "--version", "1"]);
        wait("bo has the restored version", 30, || {
            saved(&bo, r, &bf, None) == "eggs"
        });
        assert_eq!(versions(&bo, &bf).len(), 3);

        // Bo deletes it; Ana sees who did, and brings it back.
        ask(&bo, json!({"cmd": "remove", "path": bf}));
        wait("gone for ana", 30, || names(&ana, mine).is_empty());
        let gone = deleted(&ana, mine);
        assert_eq!(gone.len(), 1, "{gone:?}");
        assert_eq!(gone[0]["name"], "list.txt");
        assert_eq!(gone[0]["by"], "Bo", "{gone:?}");
        assert_eq!(gone[0]["mine"], false, "{gone:?}");
        assert_eq!(gone[0]["size"], 4, "{gone:?}");
        let listed = ana.cli(&["deleted", mine]);
        assert!(
            listed.contains("list.txt") && listed.contains("Bo"),
            "{listed}"
        );
        let back = ana.cli(&["undelete", &af]);
        assert!(back.contains(&af), "{back}");
        wait("back for bo", 30, || names(&bo, theirs) == ["list.txt"]);
        assert_eq!(saved(&bo, r, &bf, None), "eggs");
        assert!(deleted(&bo, theirs).is_empty());
    }
    // A category has no history of its own.
    refused(&ana, json!({"cmd": "deleted", "path": "People"}));
    refused(&ana, json!({"cmd": "history", "path": "Groups"}));
}
