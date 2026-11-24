//! Each group's folder in the one folder (D88,
//! `profiles.md#one-folder-for-everything-guidance`): `Groups/<name>`, through
//! the local interface a window uses. These daemons mount nothing; the mount
//! is tested in `shared_mount.rs`.
//!
//! Ana makes Family with Bo and Cy, who know her and not each other. The
//! folder appears for each on joining, holds what is sent there, follows
//! the group's name, and is renamed only by Ana. A second Family is
//! `Family (2)`. Cy's own folder named Groups moves aside, and so does Ana's
//! contact category typed as Groups. Ana takes Cy out: Bo's folder goes on in
//! the successor, Cy's goes. Bo leaves, and his goes too.

mod common;

use common::*;
use serde_json::{json, Value};

fn reply(d: &Dev, req: &Value) -> Value {
    common::reply(d, req)
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

fn person(root: &std::path::Path, name: &'static str) -> Dev {
    let mut d = Dev::new(root, name, free_port());
    d.start_with(&["--no-mount"]);
    let mut called = name.to_owned();
    called[..1].make_ascii_uppercase();
    d.cli(&["init", "--yes", "--name", &called]);
    wait(&format!("{name}'s files"), 30, || {
        reply(&d, &json!({"cmd": "files"}))["ok"] == true
    });
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

fn offered(d: &Dev, name: &str) -> bool {
    let r = ask(d, json!({"cmd": "groups"}));
    let all = r["offers"].as_array().cloned().unwrap_or_default();
    all.iter().any(|o| o["name"] == name)
}

fn group_name(d: &Dev, g: &str) -> Option<String> {
    let r = ask(d, json!({"cmd": "groups"}));
    let all = r["groups"].as_array().cloned().unwrap_or_default();
    all.iter()
        .find(|x| x["group"] == g)
        .and_then(|x| x["name"].as_str().map(str::to_owned))
}

fn names(d: &Dev, path: &str) -> Vec<String> {
    let v = reply(d, &json!({"cmd": "files", "path": path}));
    if v["ok"] != true {
        return Vec::new();
    }
    let all = v["files"].as_array().cloned().unwrap_or_default();
    all.iter()
        .map(|f| f["name"].as_str().unwrap().to_owned())
        .collect()
}

fn entry(d: &Dev, path: &str, name: &str) -> Value {
    let v = ask(d, json!({"cmd": "files", "path": path}));
    let all = v["files"].as_array().cloned().unwrap_or_default();
    all.into_iter()
        .find(|f| f["name"] == name)
        .unwrap_or(Value::Null)
}

fn saved(d: &Dev, root: &std::path::Path, path: &str) -> Vec<u8> {
    let to = root.join(format!("saved-{}-{}", d.name, path.replace('/', "_")));
    let _ = std::fs::remove_file(&to);
    ask(d, json!({"cmd": "save", "path": path, "to": to}));
    std::fs::read(&to).unwrap()
}

#[test]
fn each_group_has_its_folder_in_groups() {
    let root = tempfile::tempdir().unwrap();
    let ana = person(root.path(), "ana");
    let bo = person(root.path(), "bo");
    let cy = person(root.path(), "cy");
    meet(&ana, &bo, "Bo");
    meet(&ana, &cy, "Cy");
    // Cy has a folder of his own called Groups, from before.
    ask(&cy, json!({"cmd": "mkdir", "path": "Groups"}));
    std::fs::write(root.path().join("old.txt"), "mine").unwrap();
    ask(
        &cy,
        json!({"cmd": "put", "from": root.path().join("old.txt"), "to": "Groups"}),
    );

    let made = ask(
        &ana,
        json!({"cmd": "group-create", "name": "Family", "people": ["Bo", "Cy"]}),
    );
    let g = made["group"].as_str().unwrap().to_owned();
    assert_eq!(names(&ana, "Groups"), ["Family"]);
    for d in [&bo, &cy] {
        wait("the offer arrives", 30, || offered(d, "Family"));
    }
    // Offered is not joined: no folder yet. Cy's Groups is his own.
    assert_eq!(names(&bo, ""), ["People"]);
    assert_eq!(names(&cy, ""), ["Groups", "People"]);
    assert_eq!(names(&cy, "Groups"), ["old.txt"]);
    for d in [&bo, &cy] {
        ask(d, json!({"cmd": "group-join", "group": g}));
    }
    wait("bo's folder for the group", 30, || {
        names(&bo, "") == ["Groups", "People"] && names(&bo, "Groups") == ["Family"]
    });
    let f = entry(&bo, "Groups", "Family");
    assert_eq!(f["folder"], true);
    assert_eq!(f["group"], g.as_str(), "{f}");
    assert!(f.get("who").is_none(), "{f}");
    // Cy's own Groups moves aside, as a files space entry named as a
    // category does.
    wait("cy's folder for the group", 30, || {
        names(&cy, "") == ["Groups", "Groups (2)", "People"]
    });
    assert_eq!(names(&cy, "Groups"), ["Family"]);
    assert_eq!(names(&cy, "Groups (2)"), ["old.txt"]);
    assert!(refused(&cy, json!({"cmd": "mkdir", "path": "Groups"})).contains("choose another"));

    // A file sent in the group is in its folder, for everyone.
    let photo: Vec<u8> = (0..400_000u32).map(|i| (i % 251) as u8).collect();
    let at = root.path().join("photo.jpg");
    std::fs::write(&at, &photo).unwrap();
    ask(
        &ana,
        json!({"cmd": "say", "group": g, "text": "a photo", "attach": [at]}),
    );
    for d in [&bo, &cy] {
        wait("the photo is in the group's folder", 30, || {
            names(d, "Groups/Family") == ["photo.jpg"]
        });
    }
    let listing = ask(&bo, json!({"cmd": "files", "path": "Groups/Family"}));
    assert_eq!(listing["place"]["kind"], "shared", "{listing}");
    assert_eq!(listing["place"]["group"], g.as_str(), "{listing}");
    assert_eq!(listing["place"]["name"], "Family", "{listing}");
    assert_eq!(entry(&bo, "Groups/Family", "photo.jpg")["added_by"], "Ana");
    assert_eq!(saved(&bo, root.path(), "Groups/Family/photo.jpg"), photo);
    // and Cy, who does not know Bo, gets what Bo puts there through Ana
    std::fs::write(root.path().join("list.txt"), "eggs").unwrap();
    ask(
        &bo,
        json!({"cmd": "put", "from": root.path().join("list.txt"), "to": "Groups/Family"}),
    );
    wait("bo's list reaches cy", 30, || {
        names(&cy, "Groups/Family").contains(&"list.txt".to_owned())
    });
    assert_eq!(saved(&cy, root.path(), "Groups/Family/list.txt"), b"eggs");

    // The folder itself is not removed: leaving is what takes it away.
    let no = refused(&bo, json!({"cmd": "remove", "path": "Groups/Family"}));
    assert!(no.contains("leave"), "{no}");
    // A group's folder stays in Groups, and a contact's does not go there.
    refused(
        &bo,
        json!({"cmd": "move", "from": "Groups/Family", "to": "People/Family"}),
    );
    refused(
        &bo,
        json!({"cmd": "move", "from": "People/Ana", "to": "Groups/Ana"}),
    );

    // Bo is an ordinary member: renaming the folder is refused, and says so.
    let no = refused(
        &bo,
        json!({"cmd": "move", "from": "Groups/Family", "to": "Groups/Kin"}),
    );
    assert!(no.contains("admin"), "{no}");
    assert_eq!(group_name(&bo, &g).as_deref(), Some("Family"));
    assert_eq!(names(&bo, "Groups"), ["Family"]);
    // Ana, its owner, renames it so, and the folder follows everywhere.
    ask(
        &ana,
        json!({"cmd": "move", "from": "Groups/Family", "to": "Groups/Kin"}),
    );
    assert_eq!(group_name(&ana, &g).as_deref(), Some("Kin"));
    for d in [&ana, &bo, &cy] {
        wait("the folder follows the name", 30, || {
            names(d, "Groups") == ["Kin"]
        });
    }
    assert_eq!(names(&bo, "Groups/Kin"), ["list.txt", "photo.jpg"]);

    // Two groups of one name: the second by id is `Kin (2)`.
    let other = ask(
        &ana,
        json!({"cmd": "group-create", "name": "Kin", "people": ["Bo"]}),
    );
    let g2 = other["group"].as_str().unwrap().to_owned();
    wait("bo is offered the other", 30, || offered(&bo, "Kin"));
    ask(&bo, json!({"cmd": "group-join", "group": g2}));
    let (first, second) = if g < g2 { (&g, &g2) } else { (&g2, &g) };
    for d in [&ana, &bo] {
        wait("both are listed", 30, || {
            names(d, "Groups") == ["Kin", "Kin (2)"]
        });
        assert_eq!(entry(d, "Groups", "Kin")["group"], first.as_str());
        assert_eq!(entry(d, "Groups", "Kin (2)")["group"], second.as_str());
    }

    // A contact category typed as Groups is shown beside the groups'.
    ask(
        &ana,
        json!({"cmd": "contact", "who": "Bo", "category": "Groups"}),
    );
    wait("bo is listed aside", 10, || {
        names(&ana, "") == ["Groups", "Groups (2)", "People"]
    });
    assert_eq!(names(&ana, "Groups (2)"), ["Bo"]);
    assert_eq!(names(&ana, "People"), ["Cy"]);
    assert_eq!(names(&ana, "Groups (2)/Bo"), names(&bo, "People/Ana"));
    // moved back, he is in People again
    ask(
        &ana,
        json!({"cmd": "move", "from": "Groups (2)/Bo", "to": "People/Bo"}),
    );
    let c = ask(&ana, json!({"cmd": "contacts"}));
    let bo_c = c["contacts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["name"] == "Bo")
        .cloned()
        .unwrap();
    assert_eq!(bo_c["category"], "People", "{bo_c}");
    assert_eq!(names(&ana, ""), ["Groups", "People"]);

    // Ana takes Cy out of Kin: a successor stands in its place. Bo's folder
    // goes on there under the same name, with what came across.
    let out = ask(
        &ana,
        json!({"cmd": "group-remove", "group": g, "who": "Cy"}),
    );
    let g3 = out["group"].as_str().unwrap().to_owned();
    assert_ne!(g3, g);
    let at = |d: &Dev, name: &str| entry(d, "Groups", name)["group"].clone();
    for d in [&ana, &bo] {
        wait("the folder is the successor's", 60, || {
            let n = if g < g2 { "Kin" } else { "Kin (2)" };
            at(d, n) == g3.as_str()
        });
        assert_eq!(names(d, "Groups"), ["Kin", "Kin (2)"]);
    }
    let n = if g < g2 { "Kin" } else { "Kin (2)" };
    let there = format!("Groups/{n}");
    wait("what came across is there", 60, || {
        names(&bo, &there) == ["list.txt", "photo.jpg"]
    });
    assert_eq!(
        saved(&bo, root.path(), &format!("{there}/photo.jpg")),
        photo
    );
    // Cy is left out: the group has ended for him, and so has its folder.
    wait("cy's folder goes", 60, || {
        names(&cy, "") == ["Groups", "People"] && names(&cy, "Groups") == ["old.txt"]
    });

    // Bo leaves the other: its folder goes, and his for Kin stays.
    ask(&bo, json!({"cmd": "group-leave", "group": g2}));
    wait("bo's folder for it goes", 10, || {
        names(&bo, "Groups") == ["Kin"]
    });
    assert_eq!(entry(&bo, "Groups", "Kin")["group"], g3.as_str());
    ask(&bo, json!({"cmd": "group-leave", "group": g3}));
    wait("and with no group, no Groups", 10, || {
        names(&bo, "") == ["People"]
    });
}
