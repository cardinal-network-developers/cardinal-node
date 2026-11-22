//! Inspection (`cardinald/src/inspect.rs`): off until the person turns it
//! on, only for the token that gave, read-only, and never a key or a secret.

mod common;

use common::*;
use serde_json::{json, Value};

fn raw(d: &Dev, req: Value) -> Value {
    common::reply(d, &req)
}

/// The request for one view of inspection, named by `what`, as the
/// explorer asks: `inspect` for the overview, else `inspect-<what>`.
fn view(mut req: Value, token: &str) -> Value {
    let what = req.as_object_mut().unwrap().remove("what");
    let cmd = match what.as_ref().and_then(Value::as_str) {
        None | Some("overview") => "inspect".to_owned(),
        Some(w) => format!("inspect-{w}"),
    };
    req["cmd"] = json!(cmd);
    req["token"] = json!(token);
    req
}

fn ok(d: &Dev, req: Value) -> Value {
    let r = raw(d, req.clone());
    assert_eq!(r["ok"], true, "{req} got {r}");
    r
}

#[test]
fn inspection_is_granted_read_only_and_keeps_secrets() {
    let root = tempfile::tempdir().unwrap();
    let mut d = Dev::new(root.path(), "ana", free_port());
    d.start_with(&["--no-mount"]);
    d.cli(&["init", "--yes", "--name", "Ana"]);
    wait("the account", 30, || {
        d.status()["spaces"]
            .as_array()
            .is_some_and(|s| s.len() >= 2)
    });

    // Off until the person turns it on.
    let r = raw(&d, json!({"cmd": "inspect"}));
    assert_eq!(r["ok"], false);
    assert_eq!(d.status()["inspection"]["on"], false);

    let token = d.cli(&["inspect", "on", "--yes", "--quiet", "--minutes", "5"]);
    let token = token.trim().to_string();
    assert_eq!(token.len(), 64);
    assert_eq!(d.status()["inspection"]["on"], true);
    let wrong = raw(&d, json!({"cmd": "inspect", "token": "00".repeat(32)}));
    assert_eq!(wrong["ok"], false);

    let ask = |req: Value| ok(&d, view(req, &token));
    let o = ask(json!({"what": "overview"}));
    let me = o["identity"]["id"].as_str().unwrap().to_string();
    let spaces = o["spaces"].as_array().unwrap().clone();
    let account = spaces
        .iter()
        .find(|s| s["account"] == true)
        .expect("the account");
    let acc = account["id"].as_str().unwrap();
    ask(json!({"what": "identity"}));
    ask(json!({"what": "identity", "who": me}));

    // Every space, every entry, every node can be read.
    let mut seen = String::new();
    for s in &spaces {
        let id = s["id"].as_str().unwrap();
        ask(json!({"what": "space", "space": id}));
        let sealed = ask(json!({"what": "entries", "space": id, "view": "sealed"}));
        assert_eq!(sealed["total"], s["sealed"]);
        let opened = ask(json!({"what": "entries", "space": id}));
        // a page at a time, the same entries
        let ids = |v: &Value| -> Vec<Value> {
            let list = v["entries"].as_array().unwrap().iter();
            list.map(|e| e["entry"].clone()).collect()
        };
        let mut paged = Vec::new();
        let mut after = 0;
        loop {
            let p = ask(json!({"what": "entries", "space": id, "after": after, "limit": 3}));
            assert!(ids(&p).len() <= 3);
            paged.extend(ids(&p));
            if p["more"] != true {
                break;
            }
            after = p["next"].as_u64().unwrap();
        }
        assert_eq!(paged, ids(&opened));
        for e in opened["entries"].as_array().unwrap() {
            let full = ask(
                json!({"what": "entry", "space": id, "entry": e["entry"], "value_bytes": 300000}),
            );
            seen.push_str(&full.to_string());
        }
        let nodes = ask(json!({"what": "nodes", "space": id}));
        for n in nodes["nodes"].as_array().unwrap() {
            let full =
                ask(json!({"what": "node", "space": id, "node": n["id"], "value_bytes": 300000}));
            seen.push_str(&full.to_string());
        }
    }
    // The account's secret node shows that it holds a secret, and how long,
    // and nothing leads to its value.
    let nodes = ask(json!({"what": "nodes", "space": acc, "kind": 5}));
    let secret = &nodes["nodes"][0];
    let n = ask(json!({"what": "node", "space": acc, "node": secret["id"], "value_bytes": 300000}));
    let v = n["values"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["k"] == 2)
        .unwrap();
    assert_eq!(v["values"][0]["v"]["t"], "secret");
    let by_path = raw(
        &d,
        json!({"cmd": "inspect-node", "token": token, "space": acc,
        "node": secret["id"], "path": [2, 0]}),
    );
    assert_eq!(by_path["ok"], false);
    let made_in = n["created_in"].as_str().unwrap();
    for path in [
        json!(["entry"]),
        json!(["entry", 5]),
        json!(["signed"]),
        json!(["signed", 1, "inner"]),
    ] {
        let r = raw(
            &d,
            json!({"cmd": "inspect-entry", "token": token, "space": acc,
            "entry": made_in, "path": path, "value_bytes": 300000}),
        );
        assert_eq!(r["ok"], false, "{path} gave {r}");
    }
    assert!(seen.contains("\"t\":\"secret\""));

    // Nothing was written: the account holds what it held.
    let after = ask(json!({"what": "overview"}));
    assert_eq!(after["spaces"], o["spaces"]);

    // Off ends the token.
    d.cli(&["inspect", "off"]);
    assert_eq!(
        raw(&d, json!({"cmd": "inspect", "token": token}))["ok"],
        false
    );
    assert_eq!(d.status()["inspection"]["on"], false);
}

/// The presence secret a person gives a trusted contact (D74) is a secret
/// in the relationship's reach node too: shown as one, and no path leads
/// to its value.
#[test]
fn a_presence_secret_in_a_reach_node_is_kept_secret() {
    let root = tempfile::tempdir().unwrap();
    let mut ana = Dev::new(root.path(), "ana", free_port());
    let mut bo = Dev::new(root.path(), "bo", free_port());
    ana.start_with(&["--no-mount"]);
    bo.start_with(&["--no-mount"]);
    ana.cli(&["init", "--yes", "--name", "Ana"]);
    bo.cli(&["init", "--yes", "--name", "Bo"]);
    let at = format!("127.0.0.1:{}", ana.port);
    let code = ana.cli(&["invite", "--address", &at, "--name", "Ana"]);
    bo.cli(&["accept", code.trim(), "--name", "Ana"]);
    wait("Ana gives Bo her presence secret", 60, || {
        let v = raw(&ana, json!({"cmd": "contact-status", "who": "Bo"}));
        v["nearby"]["you_give_secret"] == true
    });
    let token = ana.cli(&["inspect", "on", "--yes", "--quiet", "--minutes", "5"]);
    let token = token.trim().to_string();
    let ask = |req: Value| raw(&ana, view(req, &token));
    let o = ask(json!({"what": "overview"}));
    let me = o["identity"]["id"].as_str().unwrap().to_string();
    let mut found = false;
    for s in o["spaces"].as_array().unwrap() {
        let id = s["id"].as_str().unwrap();
        let sp = ask(json!({"what": "space", "space": id}));
        let members = sp["members"].as_array().cloned().unwrap_or_default();
        let Some(mine) = members.iter().find(|m| m["identity"] == me.as_str()) else {
            continue;
        };
        let node = mine["reach_node"].clone();
        let n = ask(json!({"what": "node", "space": id, "node": node, "value_bytes": 300000}));
        if n["ok"] != true {
            continue;
        }
        let Some(v) = n["values"]
            .as_array()
            .and_then(|vs| vs.iter().find(|f| f["k"] == 2))
        else {
            continue;
        };
        found = true;
        assert_eq!(v["values"][0]["v"]["t"], "secret", "{v}");
        let by_path = ask(json!({"what": "node", "space": id, "node": node, "path": [2, 0]}));
        assert_eq!(by_path["ok"], false, "{by_path}");
        // and in the entries that set it, each shown as a secret
        let opened = ask(json!({"what": "entries", "space": id}));
        let mut shown = String::new();
        for e in opened["entries"].as_array().unwrap() {
            let full = ask(
                json!({"what": "entry", "space": id, "entry": e["entry"], "value_bytes": 300000}),
            );
            shown.push_str(&full.to_string());
        }
        assert!(shown.contains("\"t\":\"secret\""), "{shown}");
    }
    assert!(found, "no reach node gives a presence secret");
    ana.stop();
    bo.stop();
}
