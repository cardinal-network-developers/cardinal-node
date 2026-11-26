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

/// Every view, asked every way a client may ask it: pages, paths, ids as
/// bytes and typed, values cut short, what is not there. Where the tests
/// run the service answers each typed and by name too, and fails one that
/// differs, so this is also the comparison of the two.
#[test]
fn every_view_is_answered_every_way() {
    let root = tempfile::tempdir().unwrap();
    let mut d = Dev::new(root.path(), "ana", free_port());
    d.start_with(&["--no-mount"]);
    d.cli(&["init", "--yes", "--name", "Ana"]);
    wait("the account", 30, || {
        d.status()["spaces"]
            .as_array()
            .is_some_and(|s| s.len() >= 2)
    });
    let token = d.cli(&["inspect", "on", "--yes", "--quiet", "--minutes", "5"]);
    let token = token.trim().to_string();
    // an id as bytes, as a client that holds it sends it
    let exact = |h: &Value| json!(format!("\u{0}{}", h.as_str().unwrap()));
    let answered = |req: Value| {
        let r = raw(&d, view(req.clone(), &token));
        // never the comparison's failure
        let why = r["error"].as_str().unwrap_or_default();
        assert!(!why.contains("internal"), "{req} got {r}");
        r
    };
    let ok = |req: Value| {
        let r = answered(req.clone());
        assert_eq!(r["ok"], true, "{req} got {r}");
        r
    };
    let refused = |req: Value| {
        let r = answered(req.clone());
        assert_eq!(r["ok"], false, "{req} got {r}");
    };
    let pages = |req: Value| {
        for (after, limit) in [
            (None, Some(1)),
            (Some(1), Some(2)),
            (Some(3), None),
            (Some(999), None),
        ] {
            let mut r = req.clone();
            if let Some(a) = after {
                r["after"] = json!(a);
            }
            if let Some(l) = limit {
                r["limit"] = json!(l);
            }
            ok(r);
        }
    };

    // the token as bytes, and typed in capitals
    ok(json!({"what": "overview", "token": exact(&json!(token))}));
    ok(json!({"what": "overview", "token": token.to_uppercase()}));
    let o = ok(json!({"what": "overview"}));
    pages(json!({"what": "overview"}));
    let me = o["identity"]["id"].clone();
    let spaces = o["spaces"].as_array().unwrap().clone();
    let acc = spaces.iter().find(|s| s["account"] == true).unwrap()["id"].clone();

    // ---- an identity log ----
    let log = ok(json!({"what": "identity", "who": exact(&me)}));
    pages(json!({"what": "identity"}));
    refused(json!({"what": "identity", "who": "00"}));
    refused(json!({"what": "identity", "who": "11".repeat(32)}));
    let first = log["entries"][0]["id"].clone();
    for path in [
        json!([]),
        json!([1]),
        json!([1, 0]),
        json!([1, "inner"]),
        json!([99]),
        json!([-1]),
        json!(["inner"]),
    ] {
        answered(json!({"what": "identity", "entry": first, "path": path}));
    }
    ok(json!({"what": "identity", "entry": exact(&first), "value_bytes": 4, "items": 1}));
    refused(json!({"what": "identity", "entry": "00"}));

    // ---- each space, its entries and its nodes ----
    for s in &spaces {
        let id = s["id"].clone();
        ok(json!({"what": "space", "space": exact(&id), "value_bytes": 2, "items": 1}));
        pages(json!({"what": "space", "space": id}));
        let sealed = ok(json!({"what": "entries", "space": id, "view": "sealed"}));
        pages(json!({"what": "entries", "space": id, "view": "sealed"}));
        pages(json!({"what": "entries", "space": exact(&id)}));
        ok(json!({"what": "entries", "space": id, "limit": 0}));
        let opened = ok(json!({"what": "entries", "space": id}));
        if let Some(e) = opened["entries"].as_array().and_then(|l| l.last()) {
            let eid = e["entry"].clone();
            ok(json!({"what": "entry", "space": id, "entry": exact(&eid)}));
            pages(json!({"what": "entry", "space": id, "entry": eid}));
            for path in [
                json!(["sealed"]),
                json!(["sealed", 5]),
                json!(["sealed", 1]),
                json!(["signed"]),
                json!(["signed", 0]),
                json!(["signed", 1]),
                json!(["entry"]),
                json!(["entry", 5]),
                json!(["entry", 5, 0]),
                json!(["entry", 5, 0, 1]),
                json!([]),
                json!(["nope"]),
                json!([7]),
            ] {
                answered(
                    json!({"what": "entry", "space": id, "entry": eid, "path": path,
                    "value_bytes": 3, "items": 1}),
                );
            }
        }
        if let Some(e) = sealed["entries"].as_array().and_then(|l| l.first()) {
            let sid = e["sealed_id"].clone();
            ok(json!({"what": "entry", "space": id, "sealed_id": sid}));
            ok(json!({"what": "entry", "space": id, "sealed_id": exact(&sid)}));
            answered(json!({"what": "entry", "space": id, "sealed_id": sid, "path": ["sealed"]}));
        }
        refused(json!({"what": "entry", "space": id}));
        refused(json!({"what": "entry", "space": id, "entry": "00"}));
        let nodes = ok(json!({"what": "nodes", "space": id}));
        pages(json!({"what": "nodes", "space": id}));
        ok(json!({"what": "nodes", "space": id, "parent": "00".repeat(16)}));
        ok(json!({"what": "nodes", "space": id, "parent": exact(&json!("00".repeat(16)))}));
        refused(json!({"what": "nodes", "space": id, "parent": "00"}));
        ok(json!({"what": "nodes", "space": id, "kind": 1, "limit": 2}));
        ok(json!({"what": "nodes", "space": id, "kind": "11".repeat(32)}));
        for n in nodes["nodes"].as_array().unwrap().iter().take(6) {
            let nid = n["id"].clone();
            ok(
                json!({"what": "node", "space": id, "node": exact(&nid), "value_bytes": 2, "items": 1}),
            );
            pages(json!({"what": "node", "space": id, "node": nid}));
            for path in [
                json!([1, 0]),
                json!([1]),
                json!([2, 0]),
                json!([1, 0, "inner"]),
                json!([1, -1]),
                json!([-1]),
                json!(["x"]),
            ] {
                answered(json!({"what": "node", "space": id, "node": nid, "path": path}));
            }
        }
        ok(json!({"what": "node", "space": id, "node": "00".repeat(16)}));
        refused(json!({"what": "node", "space": id, "node": "ff".repeat(16)}));
    }
    refused(json!({"what": "space"}));
    refused(json!({"what": "space", "space": "00"}));
    refused(json!({"what": "space", "space": "22".repeat(32)}));
    refused(json!({"what": "nodes", "space": exact(&json!("22".repeat(32)))}));
    let _ = acc;
    d.stop();
}
