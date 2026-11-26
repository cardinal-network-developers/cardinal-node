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

// ---- Twins: for the requests that change what they find ----

/// Copies a folder, all of it.
fn copy_all(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let to = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_all(&e.path(), &to);
        } else {
            std::fs::copy(e.path(), to).unwrap();
        }
    }
}

/// Two services on copies of one device, set up as `cardinal init` leaves
/// it: one to be asked by name, one typed. What either is asked, the other
/// is asked too, so they hold the same; only what each makes since (a
/// group's id, a message's) differs, which [`Twins::same`] is told.
struct Twins {
    old: Arc<Daemon>,
    new: Arc<Daemon>,
    /// What the old one made, beside what the new one made in its place.
    swap: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Twins {
    async fn start(dir: &std::path::Path) -> Twins {
        let (paths, config) = crate::testing::set_up(&dir.join("old"));
        copy_all(&dir.join("old"), &dir.join("new"));
        let twin = crate::paths::Paths::at(&dir.join("new"));
        let new = Daemon::start(twin, config.clone()).await.unwrap();
        let old = Daemon::start(paths, config).await.unwrap();
        Twins {
            old,
            new,
            swap: Vec::new(),
        }
    }

    /// `old` and `new` are the same, made apart.
    fn alike(&mut self, old: &[u8], new: &[u8]) {
        assert_eq!(old.len(), new.len());
        self.swap.push((old.to_vec(), new.to_vec()));
        let (o, n) = (hex::encode(old), hex::encode(new));
        self.swap.push((o.into_bytes(), n.into_bytes()));
    }

    /// The old one's message, its ids as the new one's.
    fn swapped(&self, mut msg: Vec<u8>) -> Vec<u8> {
        for (o, n) in &self.swap {
            let mut i = 0;
            while i + o.len() <= msg.len() {
                if msg[i..i + o.len()] == o[..] {
                    msg[i..i + o.len()].copy_from_slice(n);
                    i += o.len();
                } else {
                    i += 1;
                }
            }
        }
        msg
    }

    /// The request, by name to the old one and typed to the new one, is
    /// answered with the same bytes: the reply typed.
    async fn same(&self, req: Json) -> Vec<u8> {
        self.same_as(req.clone(), req).await
    }

    /// As [`Twins::same`], each its own request: `old` names what the old
    /// one made, and `new` the new one's.
    async fn same_as(&self, old: Json, new: Json) -> Vec<u8> {
        let (_, msg) = encode_request(&old).unwrap();
        let by_name = self.swapped(crate::control::by_name(&self.old, &msg).await);
        let (_, msg) = encode_request(&new).unwrap();
        let typed = crate::control::typed::reply(&self.new, &msg)
            .await
            .expect("a typed request");
        let spec = by_name_or_first(&new);
        assert_eq!(
            by_name,
            typed,
            "{new}\n by name {}\n typed   {}",
            render_reply(spec, &by_name),
            render_reply(spec, &typed)
        );
        typed
    }

    /// A message, not by name, to both: the same bytes back.
    async fn same_message(&self, msg: &[u8]) -> Vec<u8> {
        let by_name = crate::control::by_name(&self.old, msg).await;
        let typed = crate::control::typed::reply(&self.new, msg)
            .await
            .expect("a typed request");
        assert_eq!(by_name, typed);
        typed
    }
}

fn by_name_or_first(req: &Json) -> &'static Request {
    req.get("cmd")
        .and_then(Json::as_str)
        .and_then(super::by_name)
        .unwrap_or(&REQUESTS[0])
}

/// What a reply says, typed.
fn typed_of<A: Ask>(msg: &[u8]) -> A::Reply {
    read_reply::<A>(msg).unwrap().unwrap()
}

/// How a reply failed.
fn failed_of<A: Ask>(msg: &[u8]) -> typed::Failed
where
    A::Reply: std::fmt::Debug,
{
    read_reply::<A>(msg).unwrap().unwrap_err()
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

/// The frames of `call-media`, the events of `watch` and an error's
/// fields, typed, are the bytes the service built by hand (frames, by their
/// numbers) or by name (events, errors) before; and the frames are those
/// the tables give them by name.
#[test]
fn frames_events_and_errors_are_the_bytes_they_were() {
    use super::typed::Streamed;
    let voice = Some([9u8; 8]);
    let bytes = bytes::Bytes::from_static(&[1, 2, 3, 250]);
    for from in [None, voice] {
        // as `calls.rs` wrote them by hand
        let old = Record::new()
            .with(0, frame::AUDIO)
            .with(1, bytes.to_vec())
            .with_opt(3, from.map(|v| v.to_vec()))
            .encode();
        let new = AudioFrame {
            audio: bytes.clone(),
            from,
        }
        .message();
        assert_eq!(old, new);
        let named = json!({"audio": hex::encode(&bytes), "from": from.map(hex::encode)});
        assert_eq!(frame_message(&named).unwrap(), new);
        for size in [None, Some(0u64), Some(3)] {
            let old = Record::new()
                .with(0, frame::OTHER)
                .with(1, bytes.to_vec())
                .with(2, [7u8; 32].to_vec())
                .with_opt(3, from.map(|v| v.to_vec()))
                .with_opt(4, size)
                .encode();
            let new = OtherFrame {
                frame: bytes.clone(),
                format: [7; 32],
                from,
                size,
            }
            .message();
            assert_eq!(old, new);
            let named = json!({"frame": hex::encode(&bytes), "format": hex::encode([7u8; 32]),
                               "from": from.map(hex::encode), "size": size});
            assert_eq!(frame_message(&named).unwrap(), new);
        }
        for (width, height) in [(0u64, 0u64), (640, 480), (65535, 1)] {
            let old = Record::new()
                .with(0, frame::VIEWPORT)
                .with(1, width)
                .with(2, height)
                .with_opt(3, from.map(|v| v.to_vec()))
                .encode();
            let new = ViewportFrame {
                width,
                height,
                from,
            }
            .message();
            assert_eq!(old, new);
        }
    }
    for (small, large) in [(false, false), (true, false), (false, true), (true, true)] {
        let old = Record::new()
            .with(0, frame::ASKED)
            .with(1, small)
            .with(2, large)
            .encode();
        assert_eq!(old, AskedFrame { small, large }.message());
        let named = json!({"small": small, "large": large});
        assert_eq!(frame_message(&named).unwrap(), old);
    }
    for size in [0u64, 1, 2, 255] {
        let old = Record::new().with(0, frame::KEY).with(4, size).encode();
        assert_eq!(old, KeyFrame { from: None, size }.message());
    }
    // what a window sends, as the service reads it
    let level = LevelFrame {
        level: 2,
        from: voice,
    }
    .message();
    assert_eq!(
        level,
        frame_message(&json!({"level": 2, "from": hex::encode([9u8; 8])})).unwrap()
    );
    for camera in [false, true] {
        let msg = CameraFrame { camera }.message();
        assert_eq!(msg, frame_message(&json!({"camera": camera})).unwrap());
    }
    // the rows are the frames' and events' declarations, in the tables
    assert_eq!(FRAMES.len(), 7);
    for (row, n) in FRAMES.iter().zip(1u64..) {
        assert_eq!(row.n, n);
    }

    // ---- events ----
    for seq in [0u64, 1, 127, 128, 1 << 40] {
        let old = encode_stream(EVENTS, "changed", &json!({ "seq": seq })).unwrap();
        assert_eq!(event_message(seq), old);
        assert_eq!(old, Changed { seq }.message());
    }

    // ---- errors ----
    let id = [7u8; 16];
    for (why, at, id) in [
        ("", None, None),
        ("too large", Some(0u64), None),
        ("too large", Some(3), Some(&id[..])),
        ("an id alone", None, Some(&id[..8])),
    ] {
        for st in [status::FAILED, status::TOO_LARGE, status::NEEDS_WORDS] {
            let tree = json!({"at": at, "id": id.map(hex::encode)});
            let old = error_reply_with_by_name(st, why, &tree);
            let more = ErrorMore {
                at,
                id: id.map(bytes::Bytes::copy_from_slice),
            };
            assert_eq!(old, error_reply_with(st, why, &more));
            if more == ErrorMore::default() {
                assert_eq!(old, error_reply(st, why));
            }
        }
    }
    // an id not in hex was left out, `at` with it
    let old = error_reply_with_by_name(4, "w", &json!({"at": 1, "id": "not hex"}));
    assert_eq!(old, error_reply(4, "w"));
}

/// The requests of the service, this device and the person's devices.
#[tokio::test]
async fn this_device_is_answered_the_same() {
    let dir = tempfile::tempdir().unwrap();
    let t = Twins::start(dir.path()).await;

    // ---- me ----
    let r = typed_of::<MeArgs>(&t.same(json!({"cmd": "me"})).await);
    assert_eq!((r.name.as_str(), r.set), ("Me", true));
    for name in ["", "  ", "a\nb", "Ann", "  Ann Lee  "] {
        t.same(json!({"cmd": "me", "name": name})).await;
    }
    let r = typed_of::<MeArgs>(&t.same(json!({"cmd": "me"})).await);
    assert_eq!((r.name.as_str(), r.set), ("Ann Lee", true));
    let wrong = Record::new().with(0, 10u64).with(1, 5u64).encode();
    let f = failed_of::<MeArgs>(&t.same_message(&wrong).await);
    assert_eq!(
        (f.status, f.why.as_str()),
        (status::MALFORMED, "me.name should be text")
    );

    // ---- conditions ----
    t.same(json!({"cmd": "conditions"})).await;
    for req in [
        json!({"cmd": "conditions", "metered": true}),
        json!({"cmd": "conditions", "plugged_in": true}),
        json!({"cmd": "conditions", "plugged_in": true, "metered": true}),
        json!({"cmd": "conditions"}),
        json!({"cmd": "conditions", "plugged_in": false, "metered": false}),
        json!({"cmd": "conditions", "plugged_in": true, "metered": false}),
    ] {
        t.same(req).await;
    }
    let r = typed_of::<ConditionsArgs>(&t.same(json!({"cmd": "conditions"})).await);
    assert_eq!(
        (r.plugged_in, r.metered, r.helps),
        (Some(true), false, true)
    );
    let wrong = Record::new().with(0, 6u64).with(1, 2u64).encode();
    t.same_message(&wrong).await;

    // ---- network-changed and wake ----
    t.same(json!({"cmd": "network-changed"})).await;
    t.same(json!({"cmd": "network-changed", "why": "wifi"}))
        .await;
    let r = typed_of::<WakeArgs>(&t.same(json!({"cmd": "wake"})).await);
    assert_eq!(r.checking, 0);
    t.same_message(&Record::new().with(0, 7u64).with(1, true).encode())
        .await;

    // ---- device-rename ----
    let key = t.old.keys.key();
    assert_eq!(key, t.new.keys.key());
    let full = format!("{EXACT}{}", hex::encode(key));
    let short = format!("{EXACT}{}", hex::encode(&key[..8]));
    for req in [
        json!({"cmd": "device-rename"}),
        json!({"cmd": "device-rename", "device": full}),
        json!({"cmd": "device-rename", "name": "Laptop"}),
        json!({"cmd": "device-rename", "device": "Nobody", "name": "Laptop"}),
        json!({"cmd": "device-rename", "device": format!("{EXACT}0011"), "name": "Laptop"}),
        json!({"cmd": "device-rename", "device": full, "name": ""}),
        json!({"cmd": "device-rename", "device": full, "name": "a\tb"}),
        json!({"cmd": "device-rename", "device": full, "name": " Laptop "}),
        json!({"cmd": "device-rename", "device": short, "name": "Desk"}),
        json!({"cmd": "device-rename", "device": "desk", "name": "Desk 2"}),
        json!({"cmd": "device-rename", "device": &hex::encode(key)[..6], "name": "Desk 3"}),
        json!({"cmd": "device-rename", "device": "", "name": "Desk 4"}),
    ] {
        t.same(req).await;
    }
    let r = typed_of::<DeviceRenameArgs>(
        &t.same(json!({"cmd": "device-rename", "device": "Desk 3", "name": "Mine"}))
            .await,
    );
    assert_eq!((r.key, r.name.as_str()), (short_id(&key), "Mine"));
    // text that begins as an id given as bytes does
    let nul = Record::new()
        .with(0, 12u64)
        .with(1, format!("{EXACT}{}", hex::encode(key)))
        .with(2, "X")
        .encode();
    t.same_message(&nul).await;
}

/// Pairing and the clipboard.
#[tokio::test]
async fn pairing_and_the_clipboard_are_answered_the_same() {
    use crate::daemon::PairState;
    let dir = tempfile::tempdir().unwrap();
    let t = Twins::start(dir.path()).await;

    // ---- pair-show: this device belongs to someone already ----
    for req in [
        json!({"cmd": "pair-show"}),
        json!({"cmd": "pair-show", "device": "  "}),
        json!({"cmd": "pair-show", "device": "a\nb"}),
        json!({"cmd": "pair-show", "device": " Kitchen "}),
    ] {
        t.same(req).await;
    }
    assert_eq!(t.new.config().name, "Kitchen");
    // a number no longer used is passed over
    let gone = Record::new().with(0, 14u64).with(1, "anything").encode();
    t.same_message(&gone).await;

    // ---- pair-status, in each state ----
    let power = [
        None,
        Some(cardinal_identity::Power::Admin),
        Some(cardinal_identity::Power::Device),
    ];
    let mut states = vec![
        PairState::Idle,
        PairState::Showing {
            code: "ab12-cd34".into(),
        },
        PairState::Failed("the code timed out".into()),
    ];
    for power in power {
        states.push(PairState::Joining {
            identity: [1; 32],
            admin_static: [2; 32],
            admin_name: "Desk".into(),
            admin_key: [3; 32],
            admin_addr: None,
            power,
        });
        states.push(PairState::Joined {
            admin_name: "Desk".into(),
            power,
        });
    }
    for st in states {
        for d in [&t.old, &t.new] {
            *d.pairing.lock().unwrap() = st.clone();
        }
        t.same(json!({"cmd": "pair-status"})).await;
    }

    // ---- pair-type: what is refused before any device is looked for ----
    for req in [
        json!({"cmd": "pair-type"}),
        json!({"cmd": "pair-type", "admin": true}),
        json!({"cmd": "pair-type", "code": "x", "at": "not an address"}),
        json!({"cmd": "pair-type", "code": "x", "at": "127.0.0.1:1", "device": "a\nb"}),
    ] {
        t.same(req).await;
    }
    let wrong = Record::new()
        .with(0, 16u64)
        .with(1, "x")
        .with(3, "yes")
        .encode();
    t.same_message(&wrong).await;

    // ---- the clipboard ----
    let r = typed_of::<ClipArgs>(&t.same(json!({"cmd": "clip"})).await);
    assert_eq!(r, ClipReply::default());
    for req in [
        json!({"cmd": "clip-copy"}),
        json!({"cmd": "clip-copy", "text": ""}),
        json!({"cmd": "clip-copy", "text": "x".repeat(crate::clipboard::MAX_TEXT + 1)}),
        json!({"cmd": "clip-copy", "text": "to paste"}),
    ] {
        t.same(req).await;
    }
    let r = typed_of::<ClipArgs>(&t.same(json!({"cmd": "clip"})).await);
    assert_eq!(r.text.as_deref(), Some("to paste"));
    assert_eq!((r.here, r.seconds), (Some(true), Some(0)));
    let r = typed_of::<ClipCopyArgs>(
        &t.same(json!({"cmd": "clip-copy", "text": "x".repeat(crate::clipboard::MAX_TEXT)}))
            .await,
    );
    assert_eq!(r.devices, 0);
}

/// What pair-show answers, typed, is the record its tree was by name: the
/// code a device shows cannot be the same on twins, so it is made up here.
#[test]
fn a_shown_code_is_what_its_tree_was() {
    for addrs in [
        vec![],
        vec!["192.168.1.20:7171".to_owned(), "[::1]:7171".into()],
    ] {
        let reply = PairShowReply {
            addrs: addrs.clone(),
            code: "ab12-cd34".into(),
        };
        let tree = json!({"code": "ab12-cd34", "addrs": addrs});
        assert_eq!(
            typed::reply_message(&reply),
            encode_reply(PairShowArgs::REQUEST, Ok(&tree))
        );
    }
}

/// The one folder's requests that are not listings.
#[tokio::test]
async fn the_one_folder_is_changed_the_same() {
    let dir = tempfile::tempdir().unwrap();
    let mut t = Twins::start(dir.path()).await;
    let local = dir.path().join("local.txt");
    std::fs::write(&local, b"some bytes").unwrap();
    let local = local.to_str().unwrap().to_owned();

    // ---- mkdir, write, move, copy, put, remove ----
    for req in [
        json!({"cmd": "mkdir"}),
        json!({"cmd": "mkdir", "path": "Docs"}),
        json!({"cmd": "mkdir", "path": "Docs"}),
        json!({"cmd": "mkdir", "path": "Docs/inner/"}),
        json!({"cmd": "mkdir", "path": ""}),
        json!({"cmd": "mkdir", "path": "Nowhere/x"}),
        json!({"cmd": "write"}),
        json!({"cmd": "write", "from": local}),
        json!({"cmd": "write", "path": "Docs/a.txt"}),
        json!({"cmd": "write", "from": "/no/such/file", "path": "Docs/a.txt"}),
        json!({"cmd": "write", "from": local, "path": "Docs/a.txt"}),
        json!({"cmd": "write", "from": local, "path": "Docs/a.txt"}),
        json!({"cmd": "write", "from": local, "path": "Docs"}),
        json!({"cmd": "move", "from": "Docs/a.txt"}),
        json!({"cmd": "move", "to": "Docs/b.txt"}),
        json!({"cmd": "move", "from": "Docs/none.txt", "to": "Docs/b.txt"}),
        json!({"cmd": "move", "from": "Docs/a.txt", "to": "Docs/b.txt"}),
        json!({"cmd": "copy", "from": "Docs/b.txt", "to": "Docs/inner"}),
        json!({"cmd": "copy", "from": "Docs/b.txt", "to": "Docs/inner/"}),
        json!({"cmd": "copy", "from": "Docs/none.txt", "to": "Docs"}),
        json!({"cmd": "copy", "from": "Docs/b.txt"}),
        json!({"cmd": "put", "from": local, "to": "Docs"}),
        json!({"cmd": "put", "from": local, "to": ""}),
        json!({"cmd": "put", "from": "/no/such/file", "to": "Docs"}),
        json!({"cmd": "put", "to": "Docs"}),
        json!({"cmd": "remove"}),
        json!({"cmd": "remove", "path": "Docs/none.txt"}),
        json!({"cmd": "remove", "path": "local.txt"}),
    ] {
        t.same(req).await;
    }
    let r = typed_of::<CopyArgs>(
        &t.same(json!({"cmd": "copy", "from": "Docs/b.txt", "to": "Docs"}))
            .await,
    );
    assert_eq!(r.path, "Docs/b.txt");
    let wrong = Record::new()
        .with(0, 122u64)
        .with(1, "a")
        .with(2, 3u64)
        .encode();
    t.same_message(&wrong).await;

    // ---- save: each twin to a file of its own ----
    let out = |who: &str, n: u8| dir.path().join(format!("{who}-out-{n}.txt"));
    for (n, path, version) in [
        (1u8, "Docs/b.txt", None),
        (2, "Docs/b.txt", Some(1u64)),
        (3, "Docs/b.txt", Some(99)),
        (4, "Docs", None),
        (5, "Docs/none.txt", None),
        (1, "Docs/b.txt", None),
    ] {
        let (o, n) = (out("old", n), out("new", n));
        t.alike(
            o.to_str().unwrap().as_bytes(),
            n.to_str().unwrap().as_bytes(),
        );
        let req = |to: &std::path::Path| json!({"cmd": "save", "path": path, "to": to.to_str().unwrap(), "version": version});
        t.same_as(req(&o), req(&n)).await;
    }
    assert_eq!(std::fs::read(out("new", 1)).unwrap(), b"some bytes");
    t.same(json!({"cmd": "save", "path": "Docs/b.txt"})).await;
    t.same(json!({"cmd": "save", "to": "/tmp/x"})).await;

    // ---- restore ----
    for req in [
        json!({"cmd": "restore"}),
        json!({"cmd": "restore", "path": "Docs/b.txt"}),
        json!({"cmd": "restore", "path": "Docs/b.txt", "version": 99}),
        json!({"cmd": "restore", "path": "Docs", "version": 1}),
        json!({"cmd": "restore", "path": "Docs/b.txt", "version": 1}),
    ] {
        t.same(req).await;
    }

    // ---- share, with a group made on each twin ----
    let made = |d: &Arc<Daemon>| {
        let g = crate::groups::create(d, "Kin", &[], false, true).unwrap();
        hex::decode(g["group"].as_str().unwrap()).unwrap()
    };
    let (go, gn) = (made(&t.old), made(&t.new));
    t.alike(&go, &gn);
    for req in [
        json!({"cmd": "share"}),
        json!({"cmd": "share", "paths": ["Docs/b.txt"]}),
        json!({"cmd": "share", "who": "Nobody", "paths": ["Docs/b.txt"]}),
        json!({"cmd": "share", "who": "Kin", "group": "Kin", "paths": ["Docs/b.txt"]}),
        json!({"cmd": "share", "group": "Kin"}),
        json!({"cmd": "share", "group": "Kin", "paths": ["Docs/none.txt"]}),
        json!({"cmd": "share", "group": "Kin", "paths": [""]}),
        json!({"cmd": "share", "who": "Kin", "paths": ["Docs/b.txt"]}),
        json!({"cmd": "share", "group": "Kin", "paths": ["Docs/inner"], "text": "  "}),
        json!({"cmd": "share", "group": "Nobody", "paths": ["Docs/b.txt"]}),
    ] {
        t.same(req).await;
    }
    let by_id = |g: &[u8]| {
        json!({"cmd": "share", "group": format!("{EXACT}{}", hex::encode(g)),
               "paths": ["Docs/b.txt"], "text": "for you"})
    };
    let r = typed_of::<ShareArgs>(&t.same_as(by_id(&go), by_id(&gn)).await);
    assert_eq!((r.path.as_str(), r.message), ("Groups/Kin", true));
    let by_id = |g: &[u8]| {
        json!({"cmd": "share", "who": format!("{EXACT}{}", hex::encode(&g[..8])),
               "paths": ["Docs/b.txt"]})
    };
    t.same_as(by_id(&go), by_id(&gn)).await;
    t.same(json!({"cmd": "share", "who": format!("{EXACT}0011"), "paths": ["Docs/b.txt"]}))
        .await;

    // ---- mount (refused only: a test mounts nothing), unmount, flush ----
    let wrong = Record::new().with(0, 129u64).with(1, true).encode();
    t.same_message(&wrong).await;
    t.same(json!({"cmd": "unmount"})).await;
    let r = typed_of::<FlushArgs>(&t.same(json!({"cmd": "flush"})).await);
    assert_eq!(r.entries, 0);

    // ---- pin, unpin, retention ----
    for req in [
        json!({"cmd": "pin"}),
        json!({"cmd": "pin", "path": "/Docs/"}),
        json!({"cmd": "pin", "path": "Docs/b.txt"}),
        json!({"cmd": "unpin", "path": "Docs/none.txt"}),
        json!({"cmd": "retention"}),
        json!({"cmd": "retention", "mode": "some"}),
        json!({"cmd": "retention", "mode": "on-demand"}),
        json!({"cmd": "pin", "path": "Docs/inner"}),
        json!({"cmd": "unpin", "path": "/Docs"}),
        json!({"cmd": "unpin"}),
        json!({"cmd": "retention", "mode": "full"}),
    ] {
        t.same(req).await;
    }
    let r = typed_of::<PinArgs>(&t.same(json!({"cmd": "pin", "path": "Docs"})).await);
    assert_eq!((r.path.as_str(), r.on_demand), ("Docs", false));
}
