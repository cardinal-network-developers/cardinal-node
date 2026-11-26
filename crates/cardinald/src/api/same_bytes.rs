//! The typed requests send the same bytes as they did by name: for the same
//! data, the reply the service gives now (`control::typed`) is compared
//! byte for byte with the one the handler kept by name gives, cut and
//! encoded by the tables at the edge as before.

use std::sync::Arc;

use serde_json::{json, Value as Json};

use super::typed::{read_reply, Ask, Fields, Wire};
use super::*;
use crate::daemon::Daemon;

/// The reply the way by name gives to `req`: as the service answered it
/// before its request was typed, by main's handler.
async fn by_name(d: &Arc<Daemon>, req: &Json) -> Vec<u8> {
    let (_, msg) = encode_request(req).unwrap();
    crate::control::by_name(d, &msg).await
}

/// The reply the service gives to `req` now, typed.
async fn typed(d: &Arc<Daemon>, req: &Json) -> Vec<u8> {
    let (_, msg) = encode_request(req).unwrap();
    crate::control::typed::reply(d, &msg)
        .await
        .expect("a typed request")
}

/// Both ways give `req` the same bytes; and the reply, read typed, is
/// what it says.
async fn same(d: &Arc<Daemon>, req: Json) -> Vec<u8> {
    let old = by_name(d, &req).await;
    let new = typed(d, &req).await;
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

    /// `old` and `new` are the same time, made apart: their encodings,
    /// after the key of `time` in a message record (12).
    fn alike_time(&mut self, old: u64, new: u64) {
        let enc = |n: u64| {
            let mut v = vec![12u8];
            n.encode_into(&mut v);
            v
        };
        let (o, n) = (enc(old), enc(new));
        assert_eq!(o.len(), n.len());
        self.swap.push((o, n));
    }

    /// The old one's message, its ids as the new one's: every swap at
    /// once, the longest first where two begin at one place, so that one
    /// swapped is never swapped again.
    fn swapped(&self, msg: Vec<u8>) -> Vec<u8> {
        let mut swaps: Vec<&(Vec<u8>, Vec<u8>)> = self.swap.iter().collect();
        swaps.sort_by_key(|(o, _)| std::cmp::Reverse(o.len()));
        let mut out = Vec::with_capacity(msg.len());
        let mut i = 0;
        'at: while i < msg.len() {
            for (o, n) in &swaps {
                if msg[i..].starts_with(o) {
                    out.extend_from_slice(n);
                    i += o.len();
                    continue 'at;
                }
            }
            out.push(msg[i]);
            i += 1;
        }
        out
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

    /// As [`Twins::same_as`], for a request each twin answers with what it
    /// makes its own of (a group's id): `made` reads those from a reply,
    /// and they are told alike before the two are compared.
    async fn same_made<A: Ask>(
        &mut self,
        old: Json,
        new: Json,
        made: impl Fn(&A::Reply) -> Vec<Vec<u8>>,
    ) -> Vec<u8> {
        let (_, msg) = encode_request(&old).unwrap();
        let by_name = crate::control::by_name(&self.old, &msg).await;
        let (_, msg) = encode_request(&new).unwrap();
        let typed = crate::control::typed::reply(&self.new, &msg)
            .await
            .expect("a typed request");
        if let (Ok(Ok(o)), Ok(Ok(n))) = (read_reply::<A>(&by_name), read_reply::<A>(&typed)) {
            for (o, n) in made(&o).into_iter().zip(made(&n)) {
                if o != n {
                    self.alike(&o, &n);
                }
            }
        }
        let by_name = self.swapped(by_name);
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
    let group = hex::encode(g.group);
    for path in ["", "Docs", "Docs/inner", "Groups", "Groups/Kin"] {
        same(&d, json!({"cmd": "files", "path": path})).await;
    }
    same(&d, json!({"cmd": "files"})).await;
    let all = files_of(&same(&d, json!({"cmd": "files", "path": "Docs"})).await);
    assert_eq!(all.files.len(), 7);
    assert_eq!(all.files[0].name, "inner");
    assert!(all.files[0].folder);
    assert_eq!(all.place.kind, "mine");
    let page = files_of(
        &same(
            &d,
            json!({"cmd": "files", "path": "Docs", "after": 2, "limit": 3}),
        )
        .await,
    );
    assert_eq!((page.files.len(), page.more, page.next), (3, true, Some(5)));
    for (after, limit) in [(0, 0), (6, 0), (7, 0), (9, 2), (0, 100)] {
        same(
            &d,
            json!({"cmd": "files", "path": "Docs", "after": after, "limit": limit}),
        )
        .await;
    }
    // errors, and what is refused before any handler
    same(&d, json!({"cmd": "files", "path": "Nowhere"})).await;
    same(&d, json!({"cmd": "files", "path": "Docs/a.txt"})).await;
    let wrong = Record::new().with(0, 120u64).with(1, vec![1u8, 2]).encode();
    assert_eq!(
        crate::control::typed::reply(&d, &wrong).await,
        Some(error_reply(status::MALFORMED, "files.path should be text"))
    );
    let groups = files_of(&same(&d, json!({"cmd": "files", "path": "Groups"})).await);
    assert_eq!(groups.files[0].group.map(hex::encode), Some(group.clone()));
    let shared = files_of(&same(&d, json!({"cmd": "files", "path": "Groups/Kin"})).await);
    assert_eq!(shared.place.kind, "shared");

    // ---- messages ----
    let by_id = format!("{EXACT}{group}");
    same(&d, json!({"cmd": "messages", "group": by_id})).await;
    for i in 0..30 {
        let text = format!("message {i} {}", "word ".repeat(i));
        crate::groups::say(&d, Ref::Typed(&group), &text, None, &[])
            .await
            .unwrap();
    }
    let all = messages_of(&same(&d, json!({"cmd": "messages", "group": by_id})).await);
    assert_eq!(all.messages.len(), 30);
    let first = hex::encode(all.messages[0].id);
    let tenth = hex::encode(all.messages[10].id);
    crate::groups::say(
        &d,
        Ref::Typed(&group),
        "an answer",
        Some(Ref::Typed(&first)),
        &[],
    )
    .await
    .unwrap();
    crate::groups::react(&d, Ref::Typed(&group), Ref::Typed(&tenth), "👍").unwrap();
    crate::groups::edit_message(&d, Ref::Typed(&group), Ref::Typed(&tenth), "said again").unwrap();
    crate::groups::say(
        &d,
        Ref::Typed(&group),
        "with a file",
        None,
        &[local.to_owned()],
    )
    .await
    .unwrap();
    let all = messages_of(&same(&d, json!({"cmd": "messages", "group": "Kin"})).await);
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
        same(&d, req).await;
    }
    let page = messages_of(&same(&d, json!({"cmd": "messages", "group": by_id, "limit": 5})).await);
    assert!(page.more);
    assert_eq!(page.next, Some(page.messages[0].id));
    // more than a message holds: cut by size, and one too large alone
    let long = "x".repeat(60_000);
    for _ in 0..5 {
        crate::groups::say(&d, Ref::Typed(&group), &long, None, &[])
            .await
            .unwrap();
    }
    let page = messages_of(&same(&d, json!({"cmd": "messages", "group": by_id})).await);
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
        crate::control::typed::reply(&d, &nul).await,
        Some(error_reply(
            status::MALFORMED,
            "messages.group is text that begins with NUL"
        ))
    );

    // ---- call ----
    same(&d, json!({"cmd": "call"})).await;
    *d.call_ended.lock().unwrap() = Some(CallEnded {
        group: Some([7; 32]),
        how: "declined".into(),
        id: [1; 16],
        name: "Kin".into(),
        who: [2; 8],
        at: 1_790_000_000_000,
    });
    same(&d, json!({"cmd": "call"})).await;
    *d.call_ended.lock().unwrap() = Some(CallEnded {
        group: None,
        how: "ended".into(),
        id: [3; 16],
        name: "Ann".into(),
        who: [4; 8],
        at: 5,
    });
    let msg = same(&d, json!({"cmd": "call"})).await;
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
    let msg = typed::reply_message("call", &reply);
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
        attachments: vec![],
        edited: false,
        reactions: vec![],
        from: None,
        picture: None,
        read_by: None,
        reply_to: None,
        time: None,
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
        let args = MessagesArgs::new();
        let reply = MessagesReply {
            messages,
            group: None,
            name: None,
            more: false,
            next: None,
        };
        let spec = MessagesArgs::REQUEST;
        let old = match page(spec, &json!({}), tree) {
            Ok(v) => encode_reply(spec, Ok(&v)),
            Err((st, why, item)) => error_reply_with(st, &why, &item),
        };
        let new = args.reply_bytes(reply);
        assert_eq!(old, new, "{}", render_reply(spec, &new));
    }
    let file = |name: String| File {
        name,
        folder: false,
        versions: Some(1),
        added_by: None,
        category: None,
        mine: None,
        size: None,
        time: None,
        who: None,
        group: None,
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
                name: None,
                who: None,
                group: None,
            },
            path: String::new(),
            more: false,
            next: None,
        };
        for after in [0u64, 1] {
            let args = FilesArgs {
                after: Some(after),
                path: None,
                limit: None,
            };
            let spec = FilesArgs::REQUEST;
            let old = match page(spec, &json!({"after": after}), tree.clone()) {
                Ok(v) => encode_reply(spec, Ok(&v)),
                Err((st, why, item)) => error_reply_with(st, &why, &item),
            };
            let new = args.reply_bytes(reply.clone());
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
            if more == ErrorMore::new() {
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
    assert_eq!(r, ClipReply::new());
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
            typed::reply_message("pair-show", &reply),
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
        g.group.to_vec()
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

/// A contact named by name, by the start of their id and by their id as
/// bytes, and `before` in each form, typed against main's handlers; with
/// the two old oddities kept to the byte (DEVIATIONS.md, Old oddities
/// kept): a refused contact named by bytes is named NUL first, and
/// `before` as text that is NUL and an id once trimmed finds that id. The
/// contact's conversation is not held here (a relationship needs the
/// other's identity); a group's is, and takes `before` the same way.
#[tokio::test]
async fn a_contact_and_before_are_the_bytes_they_were() {
    let dir = tempfile::tempdir().unwrap();
    let mut t = Twins::start(dir.path()).await;
    let them = [9u8; 32];
    for d in [&t.old, &t.new] {
        let acc = d.core().account_id().unwrap();
        let op = cardinal_space::account::create_contact(
            &them,
            "Ann",
            &[7; 32],
            cardinal_space::account::Regard::default(),
        );
        d.write_and_push(&acc, vec![op]).unwrap();
    }
    let short = format!("{EXACT}{}", hex::encode(&them[..8]));
    let whole = format!("{EXACT}{}", hex::encode(them));
    let forms = [
        "Ann",
        "ann",
        &hex::encode(&them[..8]),
        &short,
        &whole,
        "Bob",
    ];
    for who in forms {
        t.same(json!({"cmd": "messages", "who": who})).await;
        t.same(json!({"cmd": "messages", "who": who, "before": "00"}))
            .await;
    }
    // refused, and named by bytes: NUL first in the words, as before
    for d in [&t.old, &t.new] {
        crate::contacts::set(d, "Ann", "refuse").unwrap();
    }
    for who in forms {
        let msg = t.same(json!({"cmd": "messages", "who": who})).await;
        if who.starts_with(EXACT) {
            let why = failed_of::<MessagesArgs>(&msg).why;
            assert!(why.starts_with("you have refused \u{0}"), "{why:?}");
        }
    }

    // `before`, in a group's conversation
    let made = |d: &Arc<Daemon>| {
        let g = crate::groups::create(d, "Kin", &[], false, true).unwrap();
        g.group.to_vec()
    };
    let (go, gn) = (made(&t.old), made(&t.new));
    t.alike(&go, &gn);
    for i in 0..3 {
        for d in [&t.old, &t.new] {
            crate::groups::say(d, Ref::Typed("Kin"), &format!("m{i}"), None, &[])
                .await
                .unwrap();
        }
    }
    let ids = |d: &Arc<Daemon>| {
        let r = crate::control::typed::messages(
            d,
            &MessagesArgs {
                who: None,
                group: Some(typed::Reference::Typed("Kin".into())),
                before: None,
                limit: None,
            },
        )
        .unwrap();
        r.messages
            .iter()
            .map(|m| (m.id, m.time.unwrap()))
            .collect::<Vec<_>>()
    };
    let (io, inew) = (ids(&t.old), ids(&t.new));
    for ((o, ot), (n, nt)) in io.iter().zip(&inew) {
        t.alike(o, n);
        t.alike_time(*ot, *nt);
    }
    let (o, n) = (io[2].0, inew[2].0);
    // what an error names of them: their starts
    t.alike(&o[..8], &n[..8]);
    t.alike(&o[..5], &n[..5]);
    let forms: [fn([u8; 16]) -> String; 7] = [
        |id| format!("{EXACT}{}", hex::encode(id)),
        |id| hex::encode(id),
        |id| format!("  {}  ", hex::encode(id)),
        |id| hex::encode(&id[..5]),
        // the oddity: a space, then NUL and the id
        |id| format!(" {EXACT}{}", hex::encode(id)),
        |id| format!(" {EXACT}{}", hex::encode(&id[..5])),
        |id| format!("{EXACT}{}", hex::encode(&id[..8])),
    ];
    for (i, form) in forms.iter().enumerate() {
        let req = |id| json!({"cmd": "messages", "group": "Kin", "before": form(id)});
        let msg = t.same_as(req(o), req(n)).await;
        if i == 4 {
            assert_eq!(typed_of::<MessagesArgs>(&msg).messages.len(), 2);
        }
    }
}

/// A uint the encoding cannot hold is the error it was by name, wherever
/// it is: in a debug build the request fails, `internal: ...`, naming it
/// by its place; a list's are checked as a field's are; and a client's
/// arguments are refused before they are sent.
#[test]
fn a_uint_too_large_is_the_error_it_was() {
    let too = 1u64 << 60;
    let file = |size| File {
        added_by: None,
        category: None,
        folder: false,
        mine: None,
        name: "a".into(),
        size: Some(size),
        time: None,
        versions: None,
        who: None,
        group: None,
    };
    for sizes in [vec![too], vec![1, too + 5], vec![u64::MAX, 2]] {
        let reply = FilesReply {
            files: sizes.iter().map(|s| file(*s)).collect(),
            path: "p".into(),
            place: Place::new("mine".into()),
            more: false,
            next: None,
        };
        let tree = json!({"path": "p", "place": {"kind": "mine"}, "more": false,
            "files": sizes.iter().map(|s| json!({"name": "a", "folder": false, "size": s}))
                .collect::<Vec<_>>()});
        let spec = FilesArgs::REQUEST;
        assert_eq!(
            typed::reply_message(spec.name, &reply),
            encode_reply(spec, Ok(&tree))
        );
    }
    let at = typed::At::Top("t");
    assert_eq!(
        Wire::check(&vec![1u64, too], &at).unwrap_err(),
        format!("t[1] should be below 2^60, not {too}")
    );
    let args = FilesArgs {
        path: None,
        after: Some(too),
        limit: None,
    };
    let old = encode_request(&json!({"cmd": "files", "after": too})).unwrap_err();
    assert_eq!(args.encode().unwrap_err().to_string(), old.to_string());
    // an i64 as an int is
    assert!(Wire::check(&(-(1i64 << 60)), &at).is_ok());
    assert!(Wire::check(&(1i64 << 60), &at).is_err());
}

/// The kinds, ints and int-or-text values encode as the base encoding's
/// values do, and read back as themselves.
#[test]
fn the_other_types_are_the_base_encodings() {
    let at = typed::At::Top("t");
    for n in [
        0i64,
        1,
        -1,
        23,
        -24,
        1 << 40,
        -(1 << 59),
        (1 << 60) - 1,
        -(1 << 60),
    ] {
        let mut out = Vec::new();
        n.encode_into(&mut out);
        let v = Value::from(cardinal_encoding::Int::new(n).unwrap());
        assert_eq!(out, v.encode(), "{n}");
        assert_eq!(out.len(), n.encoded_len());
        assert_eq!(i64::take(v, &at).unwrap(), n);
    }
    for k in [
        typed::Kind::Number(4),
        typed::Kind::Named(vec![7u8; 32].into()),
    ] {
        let mut out = Vec::new();
        k.encode_into(&mut out);
        let v = cardinal_encoding::decode(&out).unwrap();
        assert_eq!(typed::Kind::take(v, &at).unwrap(), k);
    }
    for x in [typed::Scalar::Int(-3), typed::Scalar::Text("x".into())] {
        let mut out = Vec::new();
        x.encode_into(&mut out);
        let v = cardinal_encoding::decode(&out).unwrap();
        assert_eq!(typed::Scalar::take(v, &at).unwrap(), x);
    }
}

/// What a message that is not a request's arguments by name says: key 0,
/// the request's number, and `fields` under their numbers.
fn message_of(n: u64, fields: Vec<(u64, Value)>) -> Vec<u8> {
    let mut r = Record::new().with(0, n);
    for (k, v) in fields {
        r.insert(k, v);
    }
    r.encode()
}

/// The router, Bluetooth, the network, hosting this person's devices, and
/// the peers asked by address.
#[tokio::test]
async fn networks_hosts_and_peers_are_answered_the_same() {
    let dir = tempfile::tempdir().unwrap();
    let mut t = Twins::start(dir.path()).await;
    // what each listens on, which an error or a warning names
    let port = |d: &Arc<Daemon>| d.endpoint.tcp_addr().unwrap().port().to_string();
    let (po, pn) = (port(&t.old), port(&t.new));
    t.alike(po.as_bytes(), pn.as_bytes());

    // ---- router: without a mapping, refused, and given one ----
    for req in [
        json!({"cmd": "router"}),
        json!({"cmd": "router", "this_device": true}),
        json!({"cmd": "router", "on": true, "this_device": true}),
        json!({"cmd": "router", "on": false, "this_device": true}),
        json!({"cmd": "router", "on": true}),
        json!({"cmd": "router", "on": false}),
        json!({"cmd": "router", "on": false, "this_device": false}),
    ] {
        t.same(req).await;
    }
    let at = std::time::Instant::now();
    for state in [
        crate::portmap::State {
            mapping: None,
            why_not: Some("the router said no".into()),
            running: false,
        },
        crate::portmap::State {
            mapping: Some((
                crate::portmap::Mapping {
                    protocol: crate::portmap::Protocol::NatPmp,
                    external: "203.0.113.9:40000".parse().unwrap(),
                    internal_port: 7171,
                    lifetime: 7200,
                },
                at,
            )),
            why_not: Some("ignored beside a mapping".into()),
            running: false,
        },
    ] {
        for d in [&t.old, &t.new] {
            *d.portmap.lock().unwrap() = state.clone();
        }
        let r = typed_of::<RouterArgs>(&t.same(json!({"cmd": "router"})).await);
        assert!(r.error.is_some() || r.protocol.as_deref() == Some("NAT-PMP"));
    }
    t.same_message(&message_of(180, vec![(1, Value::from("yes"))]))
        .await;

    // ---- network: what this device's network is, and the person's answer ----
    let r = typed_of::<NetworkArgs>(&t.same(json!({"cmd": "network"})).await);
    for req in [
        json!({"cmd": "network", "mine": true}),
        json!({"cmd": "network", "mine": true, "name": "  Home  "}),
        json!({"cmd": "network", "mine": false, "name": ""}),
        json!({"cmd": "network", "name": "only a name"}),
        json!({"cmd": "network"}),
    ] {
        t.same(req).await;
    }
    // which of the two this machine shows, both are compared above
    let _ = r.known;
    t.same_message(&message_of(182, vec![(2, Value::from(true))]))
        .await;

    // ---- bluetooth: asked, set off and open, refused ----
    for req in [
        json!({"cmd": "bluetooth"}),
        json!({"cmd": "bluetooth", "mode": "off"}),
        json!({"cmd": "bluetooth", "mode": "sometimes"}),
        json!({"cmd": "bluetooth", "mode": ""}),
        json!({"cmd": "bluetooth", "mode": "open"}),
        json!({"cmd": "bluetooth"}),
        json!({"cmd": "bluetooth", "mode": "off"}),
    ] {
        t.same(req).await;
    }
    let r = typed_of::<BluetoothArgs>(&t.same(json!({"cmd": "bluetooth"})).await);
    assert_eq!(r.mode, "off");
    t.same_message(&message_of(181, vec![(1, Value::from(3u64))]))
        .await;

    // ---- host and host-off ----
    for req in [
        json!({"cmd": "host"}),
        json!({"cmd": "host", "addresses": []}),
        json!({"cmd": "host", "addresses": ["not an address"]}),
        json!({"cmd": "host", "addresses": ["203.0.113.5:7171", "nowhere"]}),
        json!({"cmd": "host-off"}),
        json!({"cmd": "host", "addresses": ["127.0.0.1:7171"]}),
        json!({"cmd": "host", "addresses": ["203.0.113.5:7171", "host.example.org:7171"]}),
        json!({"cmd": "host", "addresses": ["host.example.org:7171"]}),
        json!({"cmd": "host-off"}),
        json!({"cmd": "host-off"}),
    ] {
        t.same(req).await;
    }
    let r = typed_of::<HostArgs>(
        &t.same(json!({"cmd": "host", "addresses": ["203.0.113.5:7171"]}))
            .await,
    );
    assert_eq!(r.hosts.len(), 1);
    assert_eq!(r.hosts[0].addresses, ["203.0.113.5:7171"]);
    t.same_message(&message_of(183, vec![(1, Value::from("203.0.113.5:7171"))]))
        .await;
    t.same_message(&message_of(
        183,
        vec![(1, Value::List(vec![Value::from(true)]))],
    ))
    .await;
    let r = typed_of::<HostOffArgs>(&t.same(json!({"cmd": "host-off"})).await);
    assert!(r.hosts.is_empty());
    t.same_message(&message_of(184, vec![(1, Value::from(true))]))
        .await;

    // ---- peer-add and peer-remove ----
    for req in [
        json!({"cmd": "peer-add"}),
        json!({"cmd": "peer-add", "addr": "no-port"}),
        json!({"cmd": "peer-add", "addr": "  192.0.2.1:7171  "}),
        json!({"cmd": "peer-add", "addr": "192.0.2.1:7171"}),
        json!({"cmd": "peer-remove"}),
        json!({"cmd": "peer-remove", "addr": "192.0.2.2:7171"}),
        json!({"cmd": "peer-remove", "addr": " 192.0.2.1:7171"}),
        json!({"cmd": "peer-remove", "addr": "192.0.2.1:7171"}),
        json!({"cmd": "peer-remove", "addr": "192.0.2.1:7171"}),
    ] {
        t.same(req).await;
    }
    t.same_message(&message_of(185, vec![(1, Value::from(5u64))]))
        .await;
    t.same_message(&message_of(186, vec![(1, Value::from(false))]))
        .await;
}

/// A contact on both twins, as `a_contact_and_before_are_the_bytes_they_were`
/// makes one: its identity.
fn a_contact(t: &Twins, name: &str, n: u8) -> [u8; 32] {
    let them = [n; 32];
    for d in [&t.old, &t.new] {
        let acc = d.core().account_id().unwrap();
        let op = cardinal_space::account::create_contact(
            &them,
            name,
            &[n.wrapping_add(1); 32],
            cardinal_space::account::Regard::default(),
        );
        d.write_and_push(&acc, vec![op]).unwrap();
    }
    them
}

/// A group made on each twin, the two told alike: the old one's id and the
/// new one's.
fn a_group(t: &mut Twins, name: &str) -> (Vec<u8>, Vec<u8>) {
    let made = |d: &Arc<Daemon>| {
        let g = crate::groups::create(d, name, &[], false, true).unwrap();
        g.group.to_vec()
    };
    let (go, gn) = (made(&t.old), made(&t.new));
    t.alike(&go, &gn);
    (go, gn)
}

/// A `ref` given as bytes, as the way by name holds it.
fn exact(b: &[u8]) -> String {
    format!("{EXACT}{}", hex::encode(b))
}

/// Starting, answering and ending a call, where nobody can be reached:
/// every refusal before a call is made.
#[tokio::test]
async fn calls_are_started_answered_and_ended_the_same() {
    let dir = tempfile::tempdir().unwrap();
    let mut t = Twins::start(dir.path()).await;
    let ann = a_contact(&t, "Ann", 9);
    let (go, gn) = a_group(&mut t, "Kin");
    let me = t.old.core().identity.as_ref().unwrap().id();
    let format = hex::encode([5u8; 32]);
    for req in [
        json!({"cmd": "call-end"}),
        json!({"cmd": "call-answer"}),
        json!({"cmd": "call-answer", "reach": true, "join": false}),
        json!({"cmd": "call-answer", "formats": [format]}),
        json!({"cmd": "call-answer", "formats": ["0011"]}),
        json!({"cmd": "call-answer", "format_names": ["voice"]}),
        json!({"cmd": "call-start"}),
        json!({"cmd": "call-start", "who": "Nobody"}),
        json!({"cmd": "call-start", "who": exact(&[1; 8])}),
        json!({"cmd": "call-start", "who": "Ann", "formats": []}),
        json!({"cmd": "call-start", "who": "Ann", "formats": ["0011"]}),
        json!({"cmd": "call-start", "who": "Ann", "formats": vec![format.clone(); 40]}),
        json!({"cmd": "call-start", "who": "Nobody", "formats": ["0011"]}),
        json!({"cmd": "call-start", "who": "Ann", "format_names": []}),
        json!({"cmd": "call-start", "ring": []}),
        json!({"cmd": "call-start", "ring": ["Ann"], "who": "Ann"}),
        json!({"cmd": "call-start", "ring": ["Ann"]}),
        json!({"cmd": "call-start", "ring": ["Ann"], "group": "Nobody"}),
        json!({"cmd": "call-start", "ring": ["Ann"], "group": "Kin"}),
        json!({"cmd": "call-start", "ring": [exact(&ann)], "group": "Kin"}),
        json!({"cmd": "call-start", "ring": [exact(&ann[..8])], "group": "Kin"}),
        json!({"cmd": "call-start", "ring": ["Me"], "group": "Kin"}),
        json!({"cmd": "call-start", "ring": [exact(&me)], "group": "Kin"}),
        json!({"cmd": "call-start", "ring": [exact(&me[..8]), "Ann"], "group": "Kin"}),
        json!({"cmd": "call-start", "group": "Kin"}),
        json!({"cmd": "call-start", "group": "Nobody", "who": "Ann"}),
        json!({"cmd": "call-start", "group": exact(&[3; 32])}),
    ] {
        t.same(req).await;
    }
    let by_id = |g: &[u8]| json!({"cmd": "call-start", "group": exact(g)});
    t.same_as(by_id(&go), by_id(&gn)).await;
    let by_id = |g: &[u8]| json!({"cmd": "call-start", "group": exact(g), "ring": ["Ann"]});
    t.same_as(by_id(&go), by_id(&gn)).await;
    // nobody to reach: Ann, by name, by the start of her id, as bytes
    for who in [
        "Ann",
        &hex::encode(&ann[..8]),
        &exact(&ann[..8]),
        &exact(&ann),
    ] {
        let msg = t.same(json!({"cmd": "call-start", "who": who})).await;
        let why = failed_of::<CallStartArgs>(&msg).why;
        assert_eq!(why, "Ann cannot be reached right now");
    }
    // refused: named NUL first where given as bytes, as before
    for d in [&t.old, &t.new] {
        crate::contacts::set(d, "Ann", "refuse").unwrap();
    }
    for who in ["Ann", &exact(&ann[..8])] {
        t.same(json!({"cmd": "call-start", "who": who})).await;
    }
    let msg = t
        .same(json!({"cmd": "call-start", "who": exact(&ann[..8])}))
        .await;
    assert!(failed_of::<CallStartArgs>(&msg)
        .why
        .starts_with("you have refused \u{0}"));
    // what is refused before any handler
    t.same_message(&message_of(101, vec![(5, Value::from("Ann"))]))
        .await;
    t.same_message(&message_of(102, vec![(3, Value::from(2u64))]))
        .await;
    t.same_message(&message_of(103, vec![(1, Value::from(true))]))
        .await;
    t.same(json!({"cmd": "call-end"})).await;
}

/// Making an invitation and taking one up: refused, made (each twin's code
/// its own, told alike), and taken up from a third device, one invitation
/// of its for each twin.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invitations_are_made_and_taken_up_the_same() {
    let dir = tempfile::tempdir().unwrap();
    let mut t = Twins::start(dir.path()).await;
    let ann = a_contact(&t, "Ann", 9);

    // ---- invite ----
    for req in [
        json!({"cmd": "invite", "address": "not an address"}),
        json!({"cmd": "invite", "address": ""}),
    ] {
        t.same(req).await;
    }
    for req in [
        json!({"cmd": "invite"}),
        json!({"cmd": "invite", "address": "203.0.113.9:7171", "name": "Dan"}),
        json!({"cmd": "invite", "hosts_only": true, "no_introductions": false}),
        json!({"cmd": "invite", "hosts_only": false, "no_introductions": true, "name": ""}),
    ] {
        let (_, msg) = encode_request(&req).unwrap();
        let old = crate::control::by_name(&t.old, &msg).await;
        let new = crate::control::typed::reply(&t.new, &msg).await.unwrap();
        let (o, n) = (
            typed_of::<InviteArgs>(&old).code,
            typed_of::<InviteArgs>(&new).code,
        );
        // the secret is each one's own: the rest of the code is the same
        assert_ne!(o, n);
        t.alike(o.as_bytes(), n.as_bytes());
        assert_eq!(t.swapped(old), new, "{req}");
    }
    t.same_message(&message_of(42, vec![(3, Value::from("yes"))]))
        .await;

    // ---- accept: refused ----
    let own = typed_of::<InviteArgs>(
        &crate::control::typed::reply(
            &t.new,
            &encode_request(&json!({"cmd": "invite"})).unwrap().1,
        )
        .await
        .unwrap(),
    )
    .code;
    for req in [
        json!({"cmd": "accept"}),
        json!({"cmd": "accept", "code": "not a code"}),
        json!({"cmd": "accept", "code": "  "}),
        json!({"cmd": "accept", "code": own}),
        json!({"cmd": "accept", "code": own, "for": "Nobody"}),
        json!({"cmd": "accept", "for": "Nobody"}),
        json!({"cmd": "accept", "for": exact(&[4; 8])}),
        json!({"cmd": "accept", "code": "x", "for": "Ann"}),
        json!({"cmd": "accept", "code": "x", "for": exact(&ann)}),
        json!({"cmd": "accept", "code": "x", "for": exact(&ann[..8])}),
        json!({"cmd": "accept", "code": "x", "for": hex::encode(&ann[..8])}),
    ] {
        t.same(req).await;
    }
    t.same_message(&message_of(43, vec![(6, Value::from(5u64))]))
        .await;
    t.same_message(&message_of(
        43,
        vec![
            (1, Value::from("x")),
            (6, Value::from(format!("{EXACT}00"))),
        ],
    ))
    .await;

    // ---- accept: taken up from other devices, one for each twin (two
    // sessions of one device's keys are one session to whoever answers),
    // new ones for each case ----
    let cases: [(Option<&str>, Option<&str>, Option<bool>); 3] = [
        (Some("Bea"), None, None),
        (None, Some("a QR code"), Some(true)),
        (Some(" "), Some(""), Some(false)),
    ];
    for (i, (name, via, hosts_only)) in cases.into_iter().enumerate() {
        let mut inviters = Vec::new();
        for twin in ["old", "new"] {
            let (paths, config) =
                crate::testing::set_up(&dir.path().join(format!("inviter-{twin}-{i}")));
            let inviter = Daemon::start(paths, config).await.unwrap();
            // it answers its invitations: sessions are taken
            tokio::spawn(inviter.clone().run());
            inviters.push(inviter);
        }
        let code = |inviter: &Arc<Daemon>, name: &str| {
            crate::contacts::invite(inviter, None, Some(name), Default::default())
                .unwrap()
                .code
        };
        let req = |code: String| {
            json!({"cmd": "accept", "code": code, "name": name, "via": via,
                   "hosts_only": hosts_only, "no_introductions": hosts_only})
        };
        let (a, b) = (&inviters[0], &inviters[1]);
        let msg = t
            .same_as(req(code(a, "Inviter")), req(code(b, "Inviter")))
            .await;
        let r = typed_of::<AcceptArgs>(&msg);
        assert_eq!(r.name, name.unwrap_or("Inviter"));
        assert_eq!(r.recovery_of, None);
        // taken up already: the same person again
        t.same_as(req(code(a, "Again")), req(code(b, "Again")))
            .await;
        // refused, by their id as bytes
        for (d, inviter) in [(&t.old, a), (&t.new, b)] {
            let them = inviter.core().identity.as_ref().unwrap().id();
            crate::contacts::set(d, &exact(&them), "refuse").unwrap();
        }
        t.same_as(req(code(a, "Refused")), req(code(b, "Refused")))
            .await;
        for d in inviters {
            let _ = d.stopping.send(true);
        }
    }
}

/// Waits until `now` holds, a few seconds at most.
async fn until(what: &str, now: impl Fn() -> bool) {
    for _ in 0..300 {
        if now() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("{what} did not happen");
}

/// For each twin a device of someone else's, a contact of that twin's
/// called `name` (they call the twin "Me"), made by an invitation taken up:
/// both running, with the twins, so that what they offer comes. Their
/// identities are told alike.
async fn befriended(t: &mut Twins, dir: &std::path::Path, name: &str) -> [Arc<Daemon>; 2] {
    let mut them = Vec::new();
    for (twin, d) in [("old", t.old.clone()), ("new", t.new.clone())] {
        let (paths, config) = crate::testing::set_up(&dir.join(format!("{name}-{twin}")));
        let x = Daemon::start(paths, config).await.unwrap();
        tokio::spawn(x.clone().run());
        let code = crate::contacts::invite(&x, None, None, Default::default())
            .unwrap()
            .code;
        let met = cardinal_space::account::Met {
            how: cardinal_space::account::MET_THEIR_INVITATION,
            ..Default::default()
        };
        crate::contacts::accept(&d, &code, Some(name), Default::default(), met, true)
            .await
            .unwrap();
        them.push(x);
    }
    let id = |d: &Arc<Daemon>| d.core().identity.as_ref().unwrap().id();
    t.alike(&id(&them[0]), &id(&them[1]));
    t.alike(&id(&them[0])[..8], &id(&them[1])[..8]);
    [them[0].clone(), them[1].clone()]
}

/// A group of `x`'s, offered to the twin they know as "Me", once it is
/// on that twin: its id.
async fn offered(x: &Arc<Daemon>, twin: &Arc<Daemon>, name: &str) -> [u8; 32] {
    let me = vec![typed::Reference::Typed("Me".into())];
    let g = crate::groups::create(x, name, &me, false, true).unwrap();
    until(&format!("the offer of {name}"), || {
        let list = crate::groups::list(twin);
        let offers = list["offers"].as_array().cloned().unwrap_or_default();
        offers.iter().any(|o| o["name"] == name)
            && twin
                .core()
                .spaces
                .get(&g.group)
                .is_some_and(|h| h.space.is_some())
    })
    .await;
    g.group
}

/// The groups' requests that are not listings: made, offered, joined,
/// declined, changed, left and come back to; with every refusal before
/// them, a ref as text, as the start of an id and as bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn groups_are_changed_the_same() {
    let dir = tempfile::tempdir().unwrap();
    let mut t = Twins::start(dir.path()).await;
    tokio::spawn(t.old.clone().run());
    tokio::spawn(t.new.clone().run());
    let bea = befriended(&mut t, dir.path(), "Bea").await;
    let bea_id = |i: usize| bea[i].core().identity.as_ref().unwrap().id();
    let g32 = |r: &GroupCreateReply| vec![r.group.to_vec()];

    // ---- group-create ----
    for req in [
        json!({"cmd": "group-create"}),
        json!({"cmd": "group-create", "name": "  "}),
        json!({"cmd": "group-create", "name": "X", "people": ["Nobody"]}),
        json!({"cmd": "group-create", "name": "X", "people": [exact(&[1; 8])]}),
        json!({"cmd": "group-create", "people": ["Bea"]}),
    ] {
        t.same(req).await;
    }
    let made = |name: &str, extra: Json| {
        let mut r = json!({"cmd": "group-create", "name": name});
        for (k, v) in extra.as_object().unwrap() {
            r[k] = v.clone();
        }
        r
    };
    t.same_made::<GroupCreateArgs>(made("Alone", json!({})), made("Alone", json!({})), g32)
        .await;
    t.same_made::<GroupCreateArgs>(
        made(" Call ", json!({"for_call": true, "history": false})),
        made(" Call ", json!({"for_call": true, "history": false})),
        g32,
    )
    .await;
    let mine = |i: usize| {
        made(
            "Mine",
            json!({"people": [if i == 0 { exact(&bea_id(0)[..8]) } else { exact(&bea_id(1)[..8]) }], "for_call": false}),
        )
    };
    t.same_made::<GroupCreateArgs>(mine(0), mine(1), g32).await;
    t.same_made::<GroupCreateArgs>(
        made("Theirs", json!({"people": ["Bea"], "history": true})),
        made("Theirs", json!({"people": ["Bea"], "history": true})),
        g32,
    )
    .await;
    t.same_message(&message_of(
        71,
        vec![(1, Value::from("X")), (2, Value::from("Bea"))],
    ))
    .await;
    t.same_message(&message_of(
        71,
        vec![
            (1, Value::from("X")),
            (2, Value::List(vec![Value::from(1u64)])),
        ],
    ))
    .await;

    // ---- group-add, group-set, group-member, group-role ----
    for req in [
        json!({"cmd": "group-add"}),
        json!({"cmd": "group-add", "group": "Nobody", "people": ["Bea"]}),
        json!({"cmd": "group-add", "group": "Call", "people": ["Bea"]}),
        json!({"cmd": "group-add", "group": "Mine", "people": ["Nobody"]}),
        json!({"cmd": "group-add", "group": "Mine"}),
        json!({"cmd": "group-add", "group": "Mine", "people": ["Bea"], "shown": "B"}),
        json!({"cmd": "group-add", "group": "Mine", "people": ["Bea"]}),
        json!({"cmd": "group-set"}),
        json!({"cmd": "group-set", "group": "Nobody"}),
        json!({"cmd": "group-set", "group": "Mine", "for_call": true}),
        json!({"cmd": "group-set", "group": "Mine"}),
        json!({"cmd": "group-set", "group": "Mine", "name": "  "}),
        json!({"cmd": "group-set", "group": "Mine", "introductions": false}),
        json!({"cmd": "group-set", "group": "Call", "for_call": false}),
        json!({"cmd": "group-set", "group": "Alone", "name": " Lone ", "introductions": true, "for_call": false}),
        json!({"cmd": "group-member"}),
        json!({"cmd": "group-member", "group": "Mine"}),
        json!({"cmd": "group-member", "group": "Mine", "who": "Nobody"}),
        json!({"cmd": "group-member", "group": "Mine", "who": "Bea", "shown": "Bee"}),
        json!({"cmd": "group-member", "group": "Mine", "who": "Bee", "introduce": false}),
        json!({"cmd": "group-member", "group": "Mine", "who": "Bea", "shown": "B2", "introduce": true}),
        json!({"cmd": "group-role"}),
        json!({"cmd": "group-role", "group": "Mine", "who": "Bea"}),
        json!({"cmd": "group-role", "group": "Mine", "who": "Bea", "role": "owner"}),
        json!({"cmd": "group-role", "group": "Mine", "who": "Bea", "role": "boss"}),
        json!({"cmd": "group-role", "group": "Mine", "who": "Nobody", "role": "admin"}),
        json!({"cmd": "group-role", "group": "Mine", "who": "Me", "role": "admin"}),
        json!({"cmd": "group-role", "group": "Mine", "who": "Bea", "role": "member"}),
        json!({"cmd": "group-role", "group": "Mine", "who": "Bea", "role": "admin"}),
        json!({"cmd": "group-role", "group": "Lone", "who": "Bea", "role": "admin"}),
    ] {
        t.same(req).await;
    }
    // by the member's id, whole and its start, as bytes and typed
    for (o, n) in [
        (exact(&bea_id(0)), exact(&bea_id(1))),
        (exact(&bea_id(0)[..8]), exact(&bea_id(1)[..8])),
        (hex::encode(&bea_id(0)[..8]), hex::encode(&bea_id(1)[..8])),
    ] {
        let req = |who: &str| json!({"cmd": "group-member", "group": "Mine", "who": who, "introduce": true});
        t.same_as(req(&o), req(&n)).await;
        let req =
            |who: &str| json!({"cmd": "group-role", "group": "Mine", "who": who, "role": "admin"});
        t.same_as(req(&o), req(&n)).await;
    }
    // a member without a node of their own is shown by the ref as given
    let me = t.old.core().identity.as_ref().unwrap().id();
    t.same(json!({"cmd": "group-member", "group": "Lone", "who": exact(&me)}))
        .await;
    t.same(json!({"cmd": "group-member", "group": "Lone", "who": exact(&[2; 32])}))
        .await;
    let ids = |r: &GroupRoleReply| {
        let mut v = vec![r.group.to_vec()];
        v.extend(r.was.map(|w| w.to_vec()));
        v
    };
    // lowered: the group goes on under a new id
    let req = json!({"cmd": "group-role", "group": "Mine", "who": "Bea", "role": "reader"});
    t.same_made::<GroupRoleArgs>(req.clone(), req, ids).await;
    t.same(json!({"cmd": "group-role", "group": exact(&[7; 32]), "who": "Bea", "role": "member"}))
        .await;
    t.same_message(&message_of(82, vec![(3, Value::from(true))]))
        .await;

    // ---- group-remove ----
    for req in [
        json!({"cmd": "group-remove"}),
        json!({"cmd": "group-remove", "group": "Mine"}),
        json!({"cmd": "group-remove", "group": "Mine", "who": "Nobody"}),
        json!({"cmd": "group-remove", "group": "Mine", "who": "Me"}),
        json!({"cmd": "group-remove", "group": "Lone", "who": "Bea"}),
    ] {
        t.same(req).await;
    }
    let ids = |r: &GroupRemoveReply| vec![r.group.to_vec(), r.was.to_vec()];
    let msg = t
        .same_made::<GroupRemoveArgs>(
            json!({"cmd": "group-remove", "group": "Theirs", "who": exact(&bea_id(0))}),
            json!({"cmd": "group-remove", "group": "Theirs", "who": exact(&bea_id(1))}),
            ids,
        )
        .await;
    assert_eq!(typed_of::<GroupRemoveArgs>(&msg).left_out.len(), 1);
    // taken out already: named as given, NUL first as bytes
    t.same_as(
        json!({"cmd": "group-remove", "group": "Theirs", "who": exact(&bea_id(0))}),
        json!({"cmd": "group-remove", "group": "Theirs", "who": exact(&bea_id(1))}),
    )
    .await;

    // ---- offered: group-join, group-reach, group-decline ----
    let club = [
        offered(&bea[0], &t.old, "Club").await,
        offered(&bea[1], &t.new, "Club").await,
    ];
    t.alike(&club[0], &club[1]);
    let other = [
        offered(&bea[0], &t.old, "Other").await,
        offered(&bea[1], &t.new, "Other").await,
    ];
    t.alike(&other[0], &other[1]);
    for req in [
        json!({"cmd": "group-reach", "group": "Club", "share": true}),
        json!({"cmd": "group-join"}),
        json!({"cmd": "group-join", "group": "Nobody"}),
        json!({"cmd": "group-join", "group": "Alone"}),
        json!({"cmd": "group-join", "group": "Club", "reach": true}),
        json!({"cmd": "group-join", "group": "Club"}),
        json!({"cmd": "group-reach"}),
        json!({"cmd": "group-reach", "share": true}),
        json!({"cmd": "group-reach", "group": "Club"}),
        json!({"cmd": "group-reach", "group": "Club", "share": true}),
        json!({"cmd": "group-reach", "group": "Club", "share": true, "host": "Desk"}),
        json!({"cmd": "group-reach", "group": "Club", "share": false, "host": "Desk"}),
        json!({"cmd": "group-reach", "group": "Club", "share": false}),
        json!({"cmd": "group-reach", "group": "Nobody", "share": false}),
        json!({"cmd": "group-decline"}),
        json!({"cmd": "group-decline", "group": "Club"}),
        json!({"cmd": "group-decline", "group": "Nobody"}),
    ] {
        t.same(req).await;
    }
    // what the above did: joined, said no to sharing, refused declining
    let r = typed_of::<GroupJoinArgs>(&t.same(json!({"cmd": "group-join", "group": "Club"})).await);
    assert_eq!(r, GroupJoinReply::new(), "joined already");
    let by_id = |g: &[u8]| json!({"cmd": "group-decline", "group": exact(g)});
    let r = t.same_as(by_id(&other[0]), by_id(&other[1])).await;
    typed_of::<GroupDeclineArgs>(&r);
    t.same_as(by_id(&other[0]), by_id(&other[1])).await;
    t.same(json!({"cmd": "group-join", "group": "Other"})).await;

    // ---- group-leave and group-rejoin ----
    for req in [
        json!({"cmd": "group-leave"}),
        json!({"cmd": "group-leave", "group": "Nobody"}),
        json!({"cmd": "group-leave", "group": "Mine"}),
        json!({"cmd": "group-leave", "group": "Mine", "admins": ["Nobody"]}),
        json!({"cmd": "group-leave", "group": "Mine", "admins": ["Me"]}),
        json!({"cmd": "group-leave", "group": "Club", "admins": ["Bea"]}),
        json!({"cmd": "group-rejoin"}),
        json!({"cmd": "group-rejoin", "group": "Nobody"}),
        json!({"cmd": "group-rejoin", "group": "Mine"}),
        json!({"cmd": "group-leave", "group": "Club", "anyway": false}),
        json!({"cmd": "group-rejoin", "group": "Club"}),
        json!({"cmd": "group-leave", "group": "Mine", "admins": ["Bea", "Bea"], "anyway": true}),
        json!({"cmd": "group-rejoin", "group": "Mine"}),
        json!({"cmd": "group-leave", "group": "Alone"}),
        json!({"cmd": "group-rejoin", "group": "Lone"}),
        json!({"cmd": "group-rejoin", "group": exact(&[6; 32])}),
    ] {
        t.same(req).await;
    }
    t.same_as(
        json!({"cmd": "group-rejoin", "group": exact(&club[0])}),
        json!({"cmd": "group-rejoin", "group": exact(&club[1])}),
    )
    .await;
    // Mine was left and come back to, by its owner
    let r = typed_of::<GroupLeaveArgs>(
        &t.same(json!({"cmd": "group-leave", "group": "Mine", "admins": ["Bea"]}))
            .await,
    );
    assert_eq!(r.admins, ["Bea"]);
    let r = typed_of::<GroupRejoinArgs>(
        &t.same(json!({"cmd": "group-rejoin", "group": "Mine"}))
            .await,
    );
    assert_eq!(r.name, "Mine");
    t.same_message(&message_of(
        74,
        vec![(1, Value::from("Mine")), (3, Value::from("yes"))],
    ))
    .await;
    t.same_message(&message_of(87, vec![(1, Value::from(1u64))]))
        .await;
    for d in [&t.old, &t.new] {
        let _ = d.stopping.send(true);
    }
    for d in bea {
        let _ = d.stopping.send(true);
    }
}

/// The ids and times of the messages of a conversation, oldest first.
fn said_in(d: &Arc<Daemon>, who: Option<&str>, group: Option<&str>) -> Vec<([u8; 16], u64)> {
    let r = crate::control::typed::messages(
        d,
        &MessagesArgs {
            who: who.map(|w| typed::Reference::Typed(w.into())),
            group: group.map(|g| typed::Reference::Typed(g.into())),
            before: None,
            limit: None,
        },
    )
    .unwrap();
    r.messages
        .iter()
        .map(|m| (m.id, m.time.unwrap_or(0)))
        .collect()
}

/// Writing, saving what came with a message, changing and taking back
/// what was said, reacting and marking read: with a contact (a device of
/// someone else's for each twin) and in a group.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn messages_are_written_the_same() {
    let dir = tempfile::tempdir().unwrap();
    let mut t = Twins::start(dir.path()).await;
    tokio::spawn(t.old.clone().run());
    tokio::spawn(t.new.clone().run());
    let bea = befriended(&mut t, dir.path(), "Bea").await;
    let (go, gn) = a_group(&mut t, "Kin");
    let local = dir.path().join("note.txt");
    std::fs::write(&local, b"a note").unwrap();
    let local = local.to_str().unwrap().to_owned();

    // ---- say: refused, then said ----
    for req in [
        json!({"cmd": "say"}),
        json!({"cmd": "say", "who": "Bea"}),
        json!({"cmd": "say", "text": "hi"}),
        json!({"cmd": "say", "who": "Nobody", "text": "hi"}),
        json!({"cmd": "say", "who": exact(&[3; 8]), "text": "hi"}),
        json!({"cmd": "say", "group": "Kin"}),
        json!({"cmd": "say", "group": "Nobody", "text": "hi"}),
        json!({"cmd": "say", "group": "Kin", "text": "hi", "reply_to": "nothing"}),
        json!({"cmd": "say", "group": "Kin", "text": "hi", "reply_to": exact(&[1; 16])}),
        json!({"cmd": "say", "group": "Kin", "text": "hi", "reply_to": exact(&[1; 15])}),
        json!({"cmd": "say", "who": "Bea", "text": "hi", "reply_to": hex::encode([1; 16])}),
        json!({"cmd": "say", "group": "Kin", "text": "hi", "attach": ["/no/such/file"]}),
        json!({"cmd": "say", "group": "Kin", "text": "hi", "attach": [dir.path().to_str().unwrap()]}),
        json!({"cmd": "say", "group": "Kin", "text": "first"}),
        json!({"cmd": "say", "group": "Kin", "who": "Nobody", "text": "to the group"}),
        json!({"cmd": "say", "group": "Kin", "text": "with a note", "attach": [local]}),
        json!({"cmd": "say", "who": "Bea", "text": "hello"}),
        json!({"cmd": "say", "who": "bea", "text": "with a note", "attach": [local]}),
    ] {
        t.same(req).await;
    }
    let by_id = |g: &[u8]| json!({"cmd": "say", "group": exact(g), "text": "by its id"});
    t.same_as(by_id(&go), by_id(&gn)).await;
    let bea_id = |i: usize| bea[i].core().identity.as_ref().unwrap().id();
    for short in [false, true] {
        let req = |id: [u8; 32]| {
            let id = if short { exact(&id[..8]) } else { exact(&id) };
            json!({"cmd": "say", "who": id, "text": "by hers"})
        };
        t.same_as(req(bea_id(0)), req(bea_id(1))).await;
    }
    // what each twin said, told alike
    let (ko, kn) = (
        said_in(&t.old, None, Some("Kin")),
        said_in(&t.new, None, Some("Kin")),
    );
    let (bo, bn) = (
        said_in(&t.old, Some("Bea"), None),
        said_in(&t.new, Some("Bea"), None),
    );
    assert_eq!((ko.len(), bo.len()), (kn.len(), bn.len()));
    for ((o, ot), (n, nt)) in ko.iter().chain(&bo).zip(kn.iter().chain(&bn)) {
        t.alike(o, n);
        t.alike_time(*ot, *nt);
    }
    // in reply, by an id as bytes and typed
    for (o, n) in [(ko[0].0, kn[0].0), (bo[0].0, bn[0].0)] {
        for form in [exact as fn(&[u8]) -> String, |b: &[u8]| hex::encode(b)] {
            let req = |id: [u8; 16], g: bool| {
                if g {
                    json!({"cmd": "say", "group": "Kin", "text": "yes", "reply_to": form(&id)})
                } else {
                    json!({"cmd": "say", "who": "Bea", "text": "yes", "reply_to": form(&id)})
                }
            };
            t.same_as(req(o, true), req(n, true)).await;
            t.same_as(req(o, false), req(n, false)).await;
        }
    }
    t.same_message(&message_of(
        35,
        vec![(1, Value::from("Bea")), (2, Value::from(1u64))],
    ))
    .await;

    // ---- save-attachment ----
    let note = |list: &[([u8; 16], u64)], at: usize| list[at].0;
    for (i, (o, n, group)) in [
        (note(&ko, 2), note(&kn, 2), true),
        (note(&bo, 1), note(&bn, 1), false),
    ]
    .into_iter()
    .enumerate()
    {
        let to = |who: &str| dir.path().join(format!("saved-{who}-{i}.txt"));
        let (to_o, to_n) = (to("old"), to("new"));
        t.alike(
            to_o.to_str().unwrap().as_bytes(),
            to_n.to_str().unwrap().as_bytes(),
        );
        let req = |id: [u8; 16], to: &std::path::Path, index: Option<u64>| {
            let mut r = json!({"cmd": "save-attachment", "id": exact(&id), "to": to.to_str().unwrap(), "index": index});
            if group {
                r["group"] = json!("Kin");
            } else {
                r["who"] = json!("Bea");
            }
            r
        };
        t.same_as(req(o, &to_o, Some(1)), req(n, &to_n, Some(1)))
            .await;
        let msg = t.same_as(req(o, &to_o, None), req(n, &to_n, None)).await;
        assert_eq!(typed_of::<SaveAttachmentArgs>(&msg).size, 6);
        // there already
        t.same_as(req(o, &to_o, Some(0)), req(n, &to_n, Some(0)))
            .await;
    }
    for req in [
        json!({"cmd": "save-attachment"}),
        json!({"cmd": "save-attachment", "who": "Bea"}),
        json!({"cmd": "save-attachment", "who": "Bea", "id": "00"}),
        json!({"cmd": "save-attachment", "who": "Bea", "id": "00", "to": "/tmp/x"}),
        json!({"cmd": "save-attachment", "group": "Kin", "to": "/tmp/x"}),
        json!({"cmd": "save-attachment", "group": "Nobody", "id": "00", "to": "/tmp/x"}),
        json!({"cmd": "save-attachment", "group": "Kin", "id": exact(&[1; 16]), "to": "/tmp/x"}),
    ] {
        t.same(req).await;
    }

    // ---- what Bea says comes, and is not this person's to change ----
    for (i, d) in bea.iter().enumerate() {
        let twin = if i == 0 { &t.old } else { &t.new };
        let had = said_in(twin, Some("Bea"), None).len();
        crate::contacts::say(d, Ref::Typed("Me"), "from Bea", None, &[])
            .await
            .unwrap();
        until("Bea's message", || {
            said_in(twin, Some("Bea"), None).len() > had
        })
        .await;
    }
    let (bo, bn) = (
        said_in(&t.old, Some("Bea"), None),
        said_in(&t.new, Some("Bea"), None),
    );
    let (theirs_o, theirs_n) = (bo.last().unwrap(), bn.last().unwrap());
    t.alike(&theirs_o.0, &theirs_n.0);
    t.alike_time(theirs_o.1, theirs_n.1);

    // ---- edit-message, react, delete-message, mark-read ----
    let (mo, mn) = (ko[0].0, kn[0].0);
    let (co, cn) = (bo[0].0, bn[0].0);
    let pairs: Vec<(Json, Json)> = {
        let mut v = Vec::new();
        for (field, place) in [("group", "Kin"), ("who", "Bea")] {
            let (o, n) = if field == "group" { (mo, mn) } else { (co, cn) };
            let with = |id: String, rest: Json| {
                let mut r = rest;
                r[field] = json!(place);
                r["id"] = json!(id);
                r
            };
            for (id_o, id_n) in [(exact(&o), exact(&n)), (hex::encode(o), hex::encode(n))] {
                for rest in [
                    json!({"cmd": "edit-message", "text": "said again"}),
                    json!({"cmd": "edit-message", "text": "  "}),
                    json!({"cmd": "react", "text": "👍"}),
                    json!({"cmd": "react", "text": " 👍 "}),
                    json!({"cmd": "react", "text": "x".repeat(17)}),
                    json!({"cmd": "react", "text": "🎉"}),
                    json!({"cmd": "react", "text": ""}),
                    json!({"cmd": "react", "text": ""}),
                ] {
                    v.push((with(id_o.clone(), rest.clone()), with(id_n.clone(), rest)));
                }
            }
            v.push((
                with(exact(&o), json!({"cmd": "edit-message"})),
                with(exact(&n), json!({"cmd": "edit-message"})),
            ));
            v.push((
                with(exact(&o), json!({"cmd": "react"})),
                with(exact(&n), json!({"cmd": "react"})),
            ));
        }
        // Bea's: reacted to, not changed
        for rest in [
            json!({"cmd": "react", "text": "👋"}),
            json!({"cmd": "edit-message", "text": "mine now"}),
            json!({"cmd": "delete-message"}),
        ] {
            let with = |id: [u8; 16]| {
                let mut r = rest.clone();
                r["who"] = json!("Bea");
                r["id"] = json!(exact(&id));
                r
            };
            v.push((with(theirs_o.0), with(theirs_n.0)));
        }
        v
    };
    for (o, n) in pairs {
        t.same_as(o, n).await;
    }
    for req in [
        json!({"cmd": "edit-message"}),
        json!({"cmd": "edit-message", "who": "Bea", "text": "x"}),
        json!({"cmd": "edit-message", "group": "Kin", "id": "zz", "text": "x"}),
        json!({"cmd": "delete-message"}),
        json!({"cmd": "delete-message", "group": "Kin"}),
        json!({"cmd": "delete-message", "who": "Nobody", "id": "00"}),
        json!({"cmd": "react"}),
        json!({"cmd": "react", "group": "Kin", "id": exact(&[2; 16]), "text": "x"}),
        json!({"cmd": "mark-read"}),
        json!({"cmd": "mark-read", "who": "Nobody"}),
        json!({"cmd": "mark-read", "group": "Nobody"}),
        json!({"cmd": "mark-read", "who": "Bea"}),
        json!({"cmd": "mark-read", "who": "Bea"}),
        json!({"cmd": "mark-read", "group": "Kin"}),
    ] {
        t.same(req).await;
    }
    for d in [&t.old, &t.new] {
        crate::settings::read_markers(d, Some(false)).unwrap();
    }
    for (i, d) in bea.iter().enumerate() {
        let twin = if i == 0 { &t.old } else { &t.new };
        let had = said_in(twin, Some("Bea"), None).len();
        crate::contacts::say(d, Ref::Typed("Me"), "again", None, &[])
            .await
            .unwrap();
        until("Bea's second message", || {
            said_in(twin, Some("Bea"), None).len() > had
        })
        .await;
    }
    let (bo, bn) = (
        said_in(&t.old, Some("Bea"), None),
        said_in(&t.new, Some("Bea"), None),
    );
    t.alike(&bo.last().unwrap().0, &bn.last().unwrap().0);
    t.alike_time(bo.last().unwrap().1, bn.last().unwrap().1);
    let msg = t.same(json!({"cmd": "mark-read", "who": "Bea"})).await;
    assert!(typed_of::<MarkReadArgs>(&msg).why.is_some());
    t.same(json!({"cmd": "mark-read", "who": "Bea"})).await;
    for (field, o, n) in [("group", mo, mn), ("who", co, cn)] {
        let place = if field == "group" { "Kin" } else { "Bea" };
        let req = |id: [u8; 16]| {
            let mut r = json!({"cmd": "delete-message", "id": exact(&id)});
            r[field] = json!(place);
            r
        };
        t.same_as(req(o), req(n)).await;
        t.same_as(req(o), req(n)).await;
    }
    // refused, by her id as bytes: named NUL first, as before
    for d in [&t.old, &t.new] {
        crate::contacts::set(d, "Bea", "refuse").unwrap();
    }
    for req in [
        |id: [u8; 32]| json!({"cmd": "say", "who": exact(&id[..8]), "text": "hi"}),
        |id: [u8; 32]| json!({"cmd": "react", "who": exact(&id), "id": "00", "text": "hi"}),
        |id: [u8; 32]| json!({"cmd": "mark-read", "who": exact(&id)}),
        |id: [u8; 32]| json!({"cmd": "edit-message", "who": exact(&id), "id": "00", "text": "x"}),
        |id: [u8; 32]| json!({"cmd": "save-attachment", "who": exact(&id), "id": "00", "to": "/x"}),
    ] {
        let msg = t.same_as(req(bea_id(0)), req(bea_id(1))).await;
        let why = failed_of::<SayArgs>(&msg).why;
        assert!(why.starts_with("you have refused \u{0}"), "{why:?}");
    }
    for d in [&t.old, &t.new] {
        let _ = d.stopping.send(true);
    }
    for d in bea {
        let _ = d.stopping.send(true);
    }
}
