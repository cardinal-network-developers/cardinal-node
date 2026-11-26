//! The typed requests send the same bytes as they did by name: for the same
//! data, the reply the service gives now (`control::typed`) is compared
//! byte for byte with the one the handler kept by name gives, cut and
//! encoded by the tables at the edge as before.

use std::sync::Arc;

use serde_json::{json, Value as Json};

use super::typed::{read_reply, Ask, Fields, Wire};
use super::*;
use crate::daemon::Daemon;

/// The reply the way by name gives to `req`.
fn by_name(d: &Arc<Daemon>, req: &Json) -> Vec<u8> {
    let (_, msg) = encode_request(req).unwrap();
    let (spec, args) = match decode_request(&msg) {
        Ok(x) => x,
        Err(r) => return error_reply(r.status, &r.why),
    };
    let s = |k: &str| args.get(k).and_then(Json::as_str);
    let answer = match spec.name {
        "files" => crate::onefolder::list_by_name(d, s("path").unwrap_or("")),
        "messages" if args.get("group").is_some() => {
            crate::groups::messages_by_name(d, s("group").unwrap(), s("before"))
        }
        "messages" => match s("who") {
            Some(who) => crate::contacts::messages_by_name(d, who, s("before")),
            None => Err(anyhow::anyhow!("missing argument who")),
        },
        "call" => Ok(crate::calls::current_by_name(d)),
        other => panic!("{other} is not typed"),
    };
    match answer {
        Ok(v) => match page(spec, &args, v) {
            Ok(v) => encode_reply(spec, Ok(&v)),
            Err((st, why, item)) => error_reply_with(st, &why, &item),
        },
        Err(e) => error_reply(status::FAILED, &format!("{e:#}")),
    }
}

/// The reply the service gives to `req` now, typed.
fn typed(d: &Arc<Daemon>, req: &Json) -> Vec<u8> {
    let (_, msg) = encode_request(req).unwrap();
    crate::control::typed::reply_to(d, &msg).expect("a typed request")
}

/// Both ways give `req` the same bytes; and the reply, read typed, is
/// what it says.
fn same(d: &Arc<Daemon>, req: Json) -> Vec<u8> {
    let old = by_name(d, &req);
    let new = typed(d, &req);
    assert_eq!(
        old,
        new,
        "{req}\n by name {}\n typed   {}",
        render_reply(&REQUESTS[0], &old),
        render_reply(&REQUESTS[0], &new)
    );
    new
}

fn files_of(msg: &[u8]) -> FilesReply {
    read_reply::<FilesArgs>(msg).unwrap().unwrap()
}

fn messages_of(msg: &[u8]) -> MessagesReply {
    read_reply::<MessagesArgs>(msg).unwrap().unwrap()
}

#[tokio::test]
async fn typed_replies_are_the_bytes_they_were_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let (paths, config) = crate::testing::set_up(dir.path());
    let d = Daemon::start(paths, config).await.unwrap();

    // ---- files ----
    let local = dir.path().join("a-file");
    std::fs::write(&local, b"some bytes").unwrap();
    let local = local.to_str().unwrap();
    crate::onefolder::mkdir(&d, "Docs").unwrap();
    crate::onefolder::mkdir(&d, "Docs/inner").unwrap();
    for name in ["b.txt", "B.txt", "a.txt", "Zed", "ünïcode", "c.txt"] {
        crate::onefolder::write(&d, local, &format!("Docs/{name}"))
            .await
            .unwrap();
    }
    // a second version
    crate::onefolder::write(&d, local, "Docs/a.txt")
        .await
        .unwrap();
    let g = crate::groups::create(&d, "Kin", &[], false, true).unwrap();
    let group = g["group"].as_str().unwrap().to_owned();
    for path in ["", "Docs", "Docs/inner", "Groups", "Groups/Kin"] {
        same(&d, json!({"cmd": "files", "path": path}));
    }
    same(&d, json!({"cmd": "files"}));
    let all = files_of(&same(&d, json!({"cmd": "files", "path": "Docs"})));
    assert_eq!(all.files.len(), 7);
    assert_eq!(all.files[0].name, "inner");
    assert!(all.files[0].folder);
    assert_eq!(all.place.kind, "mine");
    let page = files_of(&same(
        &d,
        json!({"cmd": "files", "path": "Docs", "after": 2, "limit": 3}),
    ));
    assert_eq!((page.files.len(), page.more, page.next), (3, true, Some(5)));
    for (after, limit) in [(0, 0), (6, 0), (7, 0), (9, 2), (0, 100)] {
        same(
            &d,
            json!({"cmd": "files", "path": "Docs", "after": after, "limit": limit}),
        );
    }
    // errors, and what is refused before any handler
    same(&d, json!({"cmd": "files", "path": "Nowhere"}));
    same(&d, json!({"cmd": "files", "path": "Docs/a.txt"}));
    let wrong = Record::new().with(0, 120u64).with(1, vec![1u8, 2]).encode();
    assert_eq!(
        crate::control::typed::reply_to(&d, &wrong),
        Some(error_reply(status::MALFORMED, "files.path should be text"))
    );
    let groups = files_of(&same(&d, json!({"cmd": "files", "path": "Groups"})));
    assert_eq!(groups.files[0].group.map(hex::encode), Some(group.clone()));
    let shared = files_of(&same(&d, json!({"cmd": "files", "path": "Groups/Kin"})));
    assert_eq!(shared.place.kind, "shared");

    // ---- messages ----
    let by_id = format!("{EXACT}{group}");
    same(&d, json!({"cmd": "messages", "group": by_id}));
    for i in 0..30 {
        let text = format!("message {i} {}", "word ".repeat(i));
        crate::groups::say(&d, &group, &text, None, &[])
            .await
            .unwrap();
    }
    let all = messages_of(&same(&d, json!({"cmd": "messages", "group": by_id})));
    assert_eq!(all.messages.len(), 30);
    let first = hex::encode(all.messages[0].id);
    let tenth = hex::encode(all.messages[10].id);
    crate::groups::say(&d, &group, "an answer", Some(&first), &[])
        .await
        .unwrap();
    crate::groups::react(&d, &group, &tenth, "👍").unwrap();
    crate::groups::edit_message(&d, &group, &tenth, "said again").unwrap();
    crate::groups::say(&d, &group, "with a file", None, &[local.to_owned()])
        .await
        .unwrap();
    let all = messages_of(&same(&d, json!({"cmd": "messages", "group": "Kin"})));
    assert_eq!(all.messages.len(), 32);
    assert_eq!(all.messages[30].reply_to, Some(all_first(&all)));
    assert_eq!(all.messages[10].reactions.len(), 1);
    assert!(all.messages[10].edited);
    assert_eq!(all.messages[31].attachments.len(), 1);
    for req in [
        json!({"cmd": "messages", "group": by_id, "limit": 5}),
        json!({"cmd": "messages", "group": by_id, "before": format!("{EXACT}{tenth}")}),
        json!({"cmd": "messages", "group": by_id, "before": tenth}),
        json!({"cmd": "messages", "group": by_id, "before": &tenth[..6], "limit": 2}),
        json!({"cmd": "messages", "group": by_id, "before": "nothing"}),
        json!({"cmd": "messages", "group": by_id, "before": format!("{EXACT}00ff")}),
        json!({"cmd": "messages", "group": "No such group"}),
        json!({"cmd": "messages", "group": format!("{EXACT}0011")}),
        json!({"cmd": "messages", "who": "Nobody"}),
        json!({"cmd": "messages", "who": format!("{EXACT}0011223344556677")}),
        json!({"cmd": "messages"}),
    ] {
        same(&d, req);
    }
    let page = messages_of(&same(
        &d,
        json!({"cmd": "messages", "group": by_id, "limit": 5}),
    ));
    assert!(page.more);
    assert_eq!(page.next, Some(page.messages[0].id));
    // more than a message holds: cut by size, and one too large alone
    let long = "x".repeat(60_000);
    for _ in 0..5 {
        crate::groups::say(&d, &group, &long, None, &[])
            .await
            .unwrap();
    }
    let page = messages_of(&same(&d, json!({"cmd": "messages", "group": by_id})));
    assert!(
        page.more && page.messages.len() == 4,
        "{}",
        page.messages.len()
    );
    // a ref sent as text that begins as an id given as bytes is held
    let nul = Record::new()
        .with(0, 34u64)
        .with(2, format!("{EXACT}{group}"))
        .encode();
    assert_eq!(
        crate::control::typed::reply_to(&d, &nul),
        Some(error_reply(
            status::MALFORMED,
            "messages.group is text that begins with NUL"
        ))
    );

    // ---- call ----
    same(&d, json!({"cmd": "call"}));
    *d.call_ended.lock().unwrap() = Some(CallEnded {
        group: Some([7; 32]),
        how: "declined".into(),
        id: [1; 16],
        name: "Kin".into(),
        who: [2; 8],
        at: 1_790_000_000_000,
    });
    same(&d, json!({"cmd": "call"}));
    *d.call_ended.lock().unwrap() = Some(CallEnded {
        group: None,
        how: "ended".into(),
        id: [3; 16],
        name: "Ann".into(),
        who: [4; 8],
        at: 5,
    });
    let msg = same(&d, json!({"cmd": "call"}));
    let r = read_reply::<CallArgs>(&msg).unwrap().unwrap();
    assert_eq!(r.ended.unwrap().name, "Ann");
}

fn all_first(r: &MessagesReply) -> [u8; 16] {
    r.messages[0].id
}

/// A call as full as it may be, typed, is the record the tables gave its
/// JSON tree by name; and read back, it is itself. A call under way is not
/// made here: its handler is driven by `tests/calls.rs` and the group
/// calls' tests, which read it by name.
#[test]
fn a_full_call_is_what_its_tree_was() {
    let member = |n: u8| Member {
        contact: true,
        id: [n; 8],
        introduce: false,
        left: false,
        name: format!("m{n}"),
        own: Some(true),
        picture: Some("/p".into()),
        role: "admin".into(),
        shown: Some("M".into()),
        suggested: None,
        taken_out: None,
        you: n == 1,
        reach: None,
        reaches_you: None,
        through: None,
    };
    let call = Call {
        frames: Some(CallFrames { r#in: 9, new: 3 }),
        group: Some([5; 32]),
        id: [6; 16],
        linked: Some(2),
        name: "Kin".into(),
        offered: Some(vec![[1; 32], [2; 32]]),
        people: Some(3),
        picture: None,
        seconds: Some(61),
        state: "live".into(),
        taken: Some(vec![]),
        who: [8; 8],
        voices: Some(vec![Voice {
            contact: true,
            identity: [9; 8],
            name: "Ann".into(),
            picture: Some("/a".into()),
            voice: [10; 8],
            you: false,
            camera: true,
        }]),
        they_take: None,
        camera: Some(false),
        caller: Some(member(2)),
        admins: Some(vec![member(1), member(3)]),
        joins: Some(true),
        reach: Some(GroupReach {
            added: vec!["A".into()],
            ask: true,
            public: false,
            said_no: false,
            set: true,
            shared: false,
            waiting: false,
            what: vec!["1.2.3.4:5".into()],
            who: vec!["B".into(), "C".into()],
            named: None,
        }),
        for_call: Some(true),
    };
    let member_json = |n: u8| {
        json!({"contact": true, "id": hex::encode([n; 8]), "introduce": false, "left": false,
               "name": format!("m{n}"), "own": true, "picture": "/p", "role": "admin",
               "shown": "M", "you": n == 1})
    };
    let tree = json!({
        "call": {
            "frames": {"in": 9, "new": 3},
            "group": hex::encode([5; 32]),
            "id": hex::encode([6; 16]),
            "linked": 2,
            "name": "Kin",
            "offered": [hex::encode([1; 32]), hex::encode([2; 32])],
            "people": 3,
            "seconds": 61,
            "state": "live",
            "taken": [],
            "who": hex::encode([8; 8]),
            "voices": [{"contact": true, "identity": hex::encode([9; 8]), "name": "Ann",
                        "picture": "/a", "voice": hex::encode([10; 8]), "you": false,
                        "camera": true}],
            "camera": false,
            "caller": member_json(2),
            "admins": [member_json(1), member_json(3)],
            "joins": true,
            "reach": {"added": ["A"], "ask": true, "public": false, "said_no": false,
                      "set": true, "shared": false, "waiting": false, "what": ["1.2.3.4:5"],
                      "who": ["B", "C"]},
            "for_call": true,
        },
    });
    let reply = CallReply {
        call: Some(call),
        ended: None,
    };
    let spec = CallArgs::REQUEST;
    let msg = typed::reply_message(&reply);
    assert_eq!(msg, encode_reply(spec, Ok(&tree)));
    assert_eq!(read_reply::<CallArgs>(&msg).unwrap().unwrap(), reply);
    // the reply's record: its count, then status 0 and `call` by their keys
    assert_eq!(reply.call.as_ref().unwrap().encoded_len() + 4, msg.len());
    // and the tables' rows are the typed declarations
    assert!(std::ptr::eq(
        match &CallReply::FIELDS[0].ty {
            Ty::Rec(r) => *r,
            _ => panic!(),
        },
        &table::CALL
    ));
}

/// A typed record read back is strict: a field of the wrong type, bytes of
/// the wrong length, or a field it always has missing are errors, never a
/// value half read. Fields it does not know are passed over.
#[test]
fn typed_records_are_read_strictly() {
    let at = typed::At::Top("t");
    let file = |r: Record| <File as Wire>::take(Value::Record(r), &at);
    let ok = Record::new().with(3, true).with(5, "n");
    assert_eq!(file(ok.clone()).unwrap().name, "n");
    assert!(file(ok.clone().with(99, "later")).is_ok());
    assert_eq!(
        file(Record::new().with(3, true)).unwrap_err(),
        "t.name is missing"
    );
    assert_eq!(
        file(ok.clone().with(9, vec![1u8; 7])).unwrap_err(),
        "t.who should be 8 bytes"
    );
    assert_eq!(
        file(ok.clone().with(6, "big")).unwrap_err(),
        "t.size should be an unsigned integer"
    );
    let list = Value::List(vec![Value::Record(ok.clone()), Value::from(3u64)]);
    assert_eq!(
        <Vec<File> as Wire>::take(list, &at).unwrap_err(),
        "t[1] should be a record"
    );
}

/// An item too large for a message alone is error 4 both ways, naming it
/// by its place and its id; a message cannot be written that large here,
/// so the pages are cut from answers made up for it.
#[test]
fn an_item_too_large_alone_is_named_the_same_way() {
    let message = |n: u8, text: String| Message {
        id: [n; 16],
        mine: true,
        text,
        state: Some("sent".into()),
        ..Message::default()
    };
    let as_tree = |m: &Message| {
        json!({"id": hex::encode(m.id), "mine": m.mine, "text": m.text, "state": m.state,
               "attachments": [], "reactions": [], "edited": false})
    };
    let big = "y".repeat(300_000);
    for texts in [
        vec!["a".to_owned(), big.clone(), "b".to_owned()],
        vec![big.clone()],
        vec!["a".to_owned(), "b".to_owned(), big.clone()],
        vec![
            "z".repeat(100_000),
            "z".repeat(100_000),
            "z".repeat(100_000),
        ],
    ] {
        let messages: Vec<Message> = texts
            .into_iter()
            .enumerate()
            .map(|(i, t)| message(i as u8, t))
            .collect();
        let tree = json!({"messages": messages.iter().map(as_tree).collect::<Vec<_>>()});
        let args = MessagesArgs::default();
        let reply = MessagesReply {
            messages,
            ..MessagesReply::default()
        };
        let spec = MessagesArgs::REQUEST;
        let old = match page(spec, &json!({}), tree) {
            Ok(v) => encode_reply(spec, Ok(&v)),
            Err((st, why, item)) => error_reply_with(st, &why, &item),
        };
        let new = crate::control::typed::messages_reply(&args, reply);
        assert_eq!(old, new, "{}", render_reply(spec, &new));
    }
    let file = |name: String| File {
        name,
        folder: false,
        versions: Some(1),
        ..File::default()
    };
    for names in [
        vec!["a".to_owned(), big.clone()],
        vec![big.clone(), "a".to_owned()],
    ] {
        let tree = json!({"path": "", "place": {"kind": "mine"}, "files": names.iter()
            .map(|n| json!({"name": n, "folder": false, "versions": 1})).collect::<Vec<_>>()});
        let reply = FilesReply {
            files: names.into_iter().map(file).collect(),
            place: Place {
                kind: "mine".into(),
                ..Place::default()
            },
            ..FilesReply::default()
        };
        for after in [0u64, 1] {
            let args = FilesArgs {
                after: Some(after),
                ..FilesArgs::default()
            };
            let spec = FilesArgs::REQUEST;
            let old = match page(spec, &json!({"after": after}), tree.clone()) {
                Ok(v) => encode_reply(spec, Ok(&v)),
                Err((st, why, item)) => error_reply_with(st, &why, &item),
            };
            let new = crate::control::typed::files_reply(&args, reply.clone());
            assert_eq!(old, new, "{}", render_reply(spec, &new));
        }
    }
}
