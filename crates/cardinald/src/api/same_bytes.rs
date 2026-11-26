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
    // the clock held still, as the service holds it to compare the two;
    // and, as the service does (`control::typed::beside`), the two asked
    // in turn a few times, until one answer is the other's before it, for
    // what changes between two asks (a live session's counts)
    let (old, new) = crate::control::clock::still(async {
        let mut old = by_name(d, &req).await;
        let mut new = typed(d, &req).await;
        for _ in 0..8 {
            if old == new {
                break;
            }
            old = by_name(d, &req).await;
            if old == new {
                break;
            }
            new = typed(d, &req).await;
        }
        (old, new)
    })
    .await;
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
        Twins::start_words(dir).await.0
    }

    /// [`Twins::start`], and their recovery words.
    async fn start_words(dir: &std::path::Path) -> (Twins, String) {
        let (paths, config, words) = crate::testing::set_up_words(&dir.join("old"));
        copy_all(&dir.join("old"), &dir.join("new"));
        let twin = crate::paths::Paths::at(&dir.join("new"));
        let new = Daemon::start(twin, config.clone()).await.unwrap();
        let old = Daemon::start(paths, config).await.unwrap();
        let t = Twins {
            old,
            new,
            swap: Vec::new(),
        };
        (t, words)
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

    /// A request that changes nothing, asked of the new one both ways: for
    /// what the twins hold in an order of their own (members of a group by
    /// identity, where each has a contact of its own).
    async fn same_here(&self, req: Json) -> Vec<u8> {
        same(&self.new, req).await
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
        at: Some(1_790_000_000_000),
    });
    same(&d, json!({"cmd": "call"})).await;
    *d.call_ended.lock().unwrap() = Some(CallEnded {
        group: None,
        how: "ended".into(),
        id: [3; 16],
        name: "Ann".into(),
        who: [4; 8],
        at: Some(5),
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
        crate::contacts::set_by_name(d, "Ann", "refuse").unwrap();
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
        crate::contacts::set_by_name(d, "Ann", "refuse").unwrap();
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
            crate::contacts::set_by_name(d, &exact(&them), "refuse").unwrap();
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
        list.offers.iter().any(|o| o.name == name)
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

    // ---- group-members: a listing, compared beside too wherever asked ----
    for req in [
        json!({"cmd": "group-members"}),
        json!({"cmd": "group-members", "group": "Nobody"}),
        json!({"cmd": "group-members", "group": "Mine"}),
        json!({"cmd": "group-members", "group": "Theirs"}),
        json!({"cmd": "group-members", "group": "Club"}),
        json!({"cmd": "group-members", "group": "Club", "limit": 1}),
        json!({"cmd": "group-members", "group": "Club", "after": 1, "limit": 1}),
        json!({"cmd": "group-members", "group": "Club", "after": 9}),
        json!({"cmd": "group-members", "group": "Lone", "limit": 0}),
    ] {
        t.same_here(req).await;
    }
    t.same_here(json!({"cmd": "group-members", "group": exact(&club[1])}))
        .await;
    let r = typed_of::<GroupMembersArgs>(
        &t.same(json!({"cmd": "group-members", "group": "Theirs"}))
            .await,
    );
    assert!(r.members.iter().any(|m| m.taken_out == Some(true)), "{r:?}");

    // ---- groups: joined, offered and left, through its three lists ----
    let groups = || {
        let mut v = Vec::new();
        for (after, limit) in [
            (None, None),
            (None, Some(1)),
            (Some(1), Some(2)),
            (Some(3), None),
            (Some(4), Some(1)),
            (Some(40), None),
        ] {
            v.push(json!({"cmd": "groups", "after": after, "limit": limit}));
        }
        v
    };
    for req in groups() {
        t.same_here(req).await;
    }

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
    for req in groups() {
        t.same_here(req).await;
    }
    let r = typed_of::<GroupsArgs>(&t.same_here(json!({"cmd": "groups"})).await);
    assert!(!r.groups.is_empty() && r.rejoin.is_some(), "{r:?}");
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
    // the listings of contacts and conversations, on one twin both ways
    let lists = || {
        let mut v = Vec::new();
        for cmd in ["contacts", "conversations"] {
            for (after, limit) in [
                (None, None),
                (None, Some(1)),
                (Some(1), None),
                (Some(5), Some(2)),
            ] {
                let mut r = json!({"cmd": cmd, "after": after, "limit": limit});
                if cmd == "contacts" {
                    v.push(r.clone());
                    r["all"] = json!(true);
                }
                v.push(r);
            }
        }
        v
    };
    for req in lists() {
        t.same_here(req).await;
    }
    let r = typed_of::<ConversationsArgs>(&t.same_here(json!({"cmd": "conversations"})).await);
    assert!(r.conversations.iter().any(|c| c.last.is_some()));
    // refused, by her id as bytes: named NUL first, as before
    for d in [&t.old, &t.new] {
        crate::contacts::set_by_name(d, "Bea", "refuse").unwrap();
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
    // refused: listed with `all` alone
    let r = typed_of::<ContactsArgs>(&t.same_here(json!({"cmd": "contacts", "all": true})).await);
    assert!(r.contacts.iter().any(|c| c.refused));
    for req in lists() {
        t.same_here(req).await;
    }
    for d in [&t.old, &t.new] {
        let _ = d.stopping.send(true);
    }
    for d in bea {
        let _ = d.stopping.send(true);
    }
}

/// Listings of one device, typed against main's handlers on the same data:
/// invitations, introductions, peers, space usage, a file's versions and
/// what was deleted, with their pages.
#[tokio::test]
async fn listings_are_the_bytes_they_were() {
    let dir = tempfile::tempdir().unwrap();
    let (paths, config) = crate::testing::set_up(dir.path());
    let d = Daemon::start(paths, config).await.unwrap();
    let pages = |cmd: &str, rest: Json| {
        let mut out = Vec::new();
        for (after, limit) in [
            (None, None),
            (None, Some(1)),
            (Some(1), Some(1)),
            (Some(2), None),
            (Some(9), Some(0)),
        ] {
            let mut r = rest.clone();
            r["cmd"] = json!(cmd);
            if let Some(a) = after {
                r["after"] = json!(a);
            }
            if let Some(l) = limit {
                r["limit"] = json!(l);
            }
            out.push(r);
        }
        out
    };
    for cmd in [
        "invitations",
        "introductions",
        "peer-list",
        "space-usage",
        "devices",
        "conflicts",
    ] {
        for req in pages(cmd, json!({})) {
            same(&d, req).await;
        }
    }
    for (name, hosts_only) in [(Some("Ann"), false), (None, true), (Some(""), false)] {
        crate::contacts::invite(
            &d,
            None,
            name,
            cardinal_space::account::Regard {
                trusted: !hosts_only,
                introductions: true,
            },
        )
        .unwrap();
    }
    let all = typed_of::<InvitationsArgs>(&same(&d, json!({"cmd": "invitations"})).await);
    crate::contacts::cancel_invitation(&d, Ref::Typed(&hex::encode(all.invitations[0].id)))
        .unwrap();
    {
        let mut c = d.config();
        c.peers = vec!["192.0.2.1:7171".into(), "host.example.org:7171".into()];
    }
    d.book
        .lock()
        .unwrap()
        .manual
        .insert("192.0.2.1:7171".into(), hex::encode(d.keys.key()));
    let local = dir.path().join("a.txt");
    std::fs::write(&local, b"one").unwrap();
    let local = local.to_str().unwrap();
    crate::onefolder::mkdir(&d, "Docs").unwrap();
    for name in ["a.txt", "b.txt", ".lock", "a.txt", "a.txt"] {
        crate::onefolder::write(&d, local, &format!("Docs/{name}"))
            .await
            .unwrap();
    }
    crate::onefolder::mkdir(&d, "Docs/inner").unwrap();
    for gone in ["Docs/b.txt", "Docs/.lock", "Docs/inner"] {
        crate::onefolder::remove(&d, gone).unwrap();
    }
    crate::onefolder::write(&d, local, "Docs/b.txt")
        .await
        .unwrap();
    crate::onefolder::remove(&d, "Docs/b.txt").unwrap();
    for cmd in [
        "invitations",
        "peer-list",
        "space-usage",
        "devices",
        "conflicts",
    ] {
        for req in pages(cmd, json!({})) {
            same(&d, req).await;
        }
    }
    for req in pages("history", json!({"path": "Docs/a.txt"})) {
        same(&d, req).await;
    }
    for rest in [
        json!({"path": "Docs"}),
        json!({"path": "Docs", "hidden": true}),
        json!({}),
        json!({"hidden": false}),
    ] {
        for req in pages("deleted", rest) {
            same(&d, req).await;
        }
    }
    for req in [
        json!({"cmd": "history"}),
        json!({"cmd": "history", "path": "Docs"}),
        json!({"cmd": "history", "path": "Nowhere/x"}),
        json!({"cmd": "deleted", "path": "Docs/a.txt"}),
        json!({"cmd": "deleted", "path": "Nowhere"}),
    ] {
        same(&d, req).await;
    }
    let r = typed_of::<DeletedArgs>(
        &same(
            &d,
            json!({"cmd": "deleted", "path": "Docs", "hidden": true}),
        )
        .await,
    );
    assert_eq!(r.files.len(), 4, "{r:?}");
    let r =
        typed_of::<HistoryArgs>(&same(&d, json!({"cmd": "history", "path": "Docs/a.txt"})).await);
    assert_eq!(r.versions.len(), 3);
}

/// The pages of `cmd`, as `after` and `limit` cut them: the whole, a page
/// of one, the second of one, from the third, and past the end.
fn pages_of(cmd: &str, rest: Json) -> Vec<Json> {
    let mut out = Vec::new();
    for (after, limit) in [
        (None, None),
        (None, Some(1)),
        (Some(1), Some(1)),
        (Some(2), None),
        (Some(3), Some(2)),
        (Some(40), Some(0)),
    ] {
        let mut r = rest.clone();
        r["cmd"] = json!(cmd);
        if let Some(a) = after {
            r["after"] = json!(a);
        }
        if let Some(l) = limit {
            r["limit"] = json!(l);
        }
        out.push(r);
    }
    out
}

/// `status` and `contact-status`, paged through their lists in turn, on a
/// running service with a contact connected, one known only by their node,
/// and one refused: by name and typed beside on one twin, and what looks
/// or tries an address on both, where that does nothing that differs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn status_and_reaching_are_the_bytes_they_were() {
    let dir = tempfile::tempdir().unwrap();
    let mut t = Twins::start(dir.path()).await;
    // before it runs: no copies counted yet, nothing set aside
    for req in pages_of("status", json!({})) {
        t.same_here(req).await;
    }
    tokio::spawn(t.old.clone().run());
    tokio::spawn(t.new.clone().run());
    let bea = befriended(&mut t, dir.path(), "Bea").await;
    let bea_id = bea[1].core().identity.as_ref().unwrap().id();
    let cy = a_contact(&t, "Cy", 7);
    let dee = a_contact(&t, "Dee", 9);
    for d in [&t.old, &t.new] {
        crate::contacts::set_by_name(d, "Dee", "refuse").unwrap();
    }
    {
        let mut c = t.new.config();
        c.peers = vec!["192.0.2.1:7171".into(), "host.example.org:7171".into()];
        c.this_run.left_behind = vec!["Docs/x.txt".into()];
    }
    crate::groups::create(&t.new, "Kin", &[], false, true).unwrap();
    until("Bea's devices in a session", || {
        t.new
            .core()
            .others
            .get(&bea_id)
            .is_some_and(|o| !o.log.state().keys.is_empty())
    })
    .await;
    for req in pages_of("status", json!({})) {
        t.same_here(req).await;
    }
    let st = typed_of::<StatusArgs>(&t.same_here(json!({"cmd": "status"})).await);
    assert_eq!(st.peers.len(), 2, "{st:?}");
    assert!(st.spaces.len() >= 3, "{st:?}");
    assert!(st.copies.is_some(), "{st:?}");
    let short = |id: &[u8; 32]| hex::encode(&id[..8]);
    for who in [
        json!("Bea"),
        json!("bea"),
        json!(short(&bea_id)),
        json!(exact(&bea_id)),
        json!(exact(&bea_id[..8])),
        json!("Cy"),
        json!("Dee"),
    ] {
        for req in pages_of("contact-status", json!({"who": who})) {
            t.same_here(req).await;
        }
    }
    let r = typed_of::<ContactStatusArgs>(
        &t.same_here(json!({"cmd": "contact-status", "who": "Bea"}))
            .await,
    );
    assert_eq!(r.name, "Bea");
    assert!(!r.devices.is_empty(), "{r:?}");
    // refused, missing and malformed, the same on both
    for req in [
        json!({"cmd": "contact-status"}),
        json!({"cmd": "contact-status", "who": "Nobody"}),
        json!({"cmd": "contact-status", "who": exact(&[3; 32])}),
        json!({"cmd": "contact-status", "who": "Bea", "at": "nowhere"}),
        json!({"cmd": "contact-status", "at": "nowhere"}),
        json!({"cmd": "contact-status", "who": "Dee", "at": "192.0.2.9:7171"}),
        json!({"cmd": "contact-status", "who": exact(&dee), "at": "192.0.2.9:7171"}),
        json!({"cmd": "contact-status", "who": exact(&dee[..8]), "look": true}),
        json!({"cmd": "contact-status", "who": "Dee", "look": false}),
        json!({"cmd": "contact-status", "who": "Dee", "look": true, "after": 1}),
        json!({"cmd": "contact-status", "who": "Cy", "at": "nowhere", "after": 2}),
    ] {
        t.same(req).await;
    }
    let _ = cy;
    for x in bea {
        let _ = x.stopping.send(true);
    }
}

/// The introductions this person may answer, by id, oldest first.
fn waiting_ids(d: &Arc<Daemon>) -> Vec<[u8; 16]> {
    crate::introductions::list(d)
        .introductions
        .iter()
        .map(|i| i.id)
        .collect()
}

/// The rest of the requests outside the families: `hello`, read markers,
/// cancelling an invitation, introducing, answering an introduction, and
/// the groups' asking to meet, posting again, moves and leaving. Each
/// refusal, a missing and a malformed argument, a ref as text, as the
/// start of an id and as bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_rest_are_answered_the_same() {
    let dir = tempfile::tempdir().unwrap();
    let mut t = Twins::start(dir.path()).await;
    tokio::spawn(t.old.clone().run());
    tokio::spawn(t.new.clone().run());

    // ---- hello, read-markers ----
    t.same_here(json!({"cmd": "hello"})).await;
    for req in [
        json!({"cmd": "read-markers"}),
        json!({"cmd": "read-markers", "on": false}),
        json!({"cmd": "read-markers"}),
        json!({"cmd": "read-markers", "on": true}),
        json!({"cmd": "read-markers", "on": true}),
    ] {
        t.same(req).await;
    }
    t.same_message(&message_of(41, vec![(1, Value::from("yes"))]))
        .await;

    // ---- cancel-invitation ----
    let made = |d: &Arc<Daemon>| {
        crate::contacts::invite(d, None, Some("Ann"), Default::default()).unwrap();
        let list = crate::contacts::invitations(d).invitations;
        list.last().unwrap().id
    };
    let (io, inew) = (made(&t.old), made(&t.new));
    t.alike(&io, &inew);
    let (jo, jnew) = (made(&t.old), made(&t.new));
    t.alike(&jo, &jnew);
    for req in [
        json!({"cmd": "cancel-invitation"}),
        json!({"cmd": "cancel-invitation", "id": "zz"}),
        json!({"cmd": "cancel-invitation", "id": "00112233"}),
        json!({"cmd": "cancel-invitation", "id": hex::encode([7; 16])}),
        json!({"cmd": "cancel-invitation", "id": exact(&[7; 16])}),
        json!({"cmd": "cancel-invitation", "id": exact(&[7; 3])}),
    ] {
        t.same(req).await;
    }
    t.same_as(
        json!({"cmd": "cancel-invitation", "id": hex::encode(io).to_uppercase()}),
        json!({"cmd": "cancel-invitation", "id": hex::encode(inew).to_uppercase()}),
    )
    .await;
    t.same_as(
        json!({"cmd": "cancel-invitation", "id": exact(&jo)}),
        json!({"cmd": "cancel-invitation", "id": exact(&jnew)}),
    )
    .await;
    // cancelled already: cancelled again
    t.same_as(
        json!({"cmd": "cancel-invitation", "id": hex::encode(jo)}),
        json!({"cmd": "cancel-invitation", "id": hex::encode(jnew)}),
    )
    .await;
    t.same_message(&message_of(45, vec![(1, Value::from(7u64))]))
        .await;

    // ---- introduce ----
    let bea = befriended(&mut t, dir.path(), "Bea").await;
    let cy = befriended(&mut t, dir.path(), "Cy").await;
    let id = |d: &Arc<Daemon>| d.core().identity.as_ref().unwrap().id();
    let (bea_o, bea_n) = (id(&bea[0]), id(&bea[1]));
    let dee = a_contact(&t, "Dee", 9);
    for d in [&t.old, &t.new] {
        crate::contacts::set_by_name(d, "Dee", "refuse").unwrap();
    }
    let eve = a_contact(&t, "Eve", 11);
    for d in [&t.old, &t.new] {
        crate::contacts::set_by_name(d, "Eve", "no-introductions").unwrap();
    }
    for req in [
        json!({"cmd": "introduce"}),
        json!({"cmd": "introduce", "who": "Bea"}),
        json!({"cmd": "introduce", "to": "Bea"}),
        json!({"cmd": "introduce", "who": "Nobody", "to": "Bea"}),
        json!({"cmd": "introduce", "who": "Bea", "to": "Nobody"}),
        json!({"cmd": "introduce", "who": "Bea", "to": "bea"}),
        json!({"cmd": "introduce", "who": "Dee", "to": "Bea"}),
        json!({"cmd": "introduce", "who": exact(&dee), "to": "Bea"}),
        json!({"cmd": "introduce", "who": "Bea", "to": exact(&dee[..8])}),
        json!({"cmd": "introduce", "who": "Eve", "to": "Bea"}),
        json!({"cmd": "introduce", "who": "Bea", "to": hex::encode(&eve[..8])}),
        json!({"cmd": "introduce", "who": exact(&[5; 32]), "to": "Bea"}),
        json!({"cmd": "introduce", "who": "Bea", "to": "Cy", "note": "you two"}),
        json!({"cmd": "introduce", "who": "Cy", "to": "Bea"}),
    ] {
        t.same(req).await;
    }
    t.same_as(
        json!({"cmd": "introduce", "who": exact(&bea_o), "to": "Cy", "note": ""}),
        json!({"cmd": "introduce", "who": exact(&bea_n), "to": "Cy", "note": ""}),
    )
    .await;
    t.same_message(&message_of(47, vec![(1, Value::from(3u64))]))
        .await;

    // ---- introduction-accept, introduction-decline ----
    for cmd in ["introduction-accept", "introduction-decline"] {
        for req in [
            json!({"cmd": cmd}),
            json!({"cmd": cmd, "id": "zz"}),
            json!({"cmd": cmd, "id": hex::encode([4; 16])}),
            json!({"cmd": cmd, "id": exact(&[4; 16])}),
            json!({"cmd": cmd, "id": exact(&[4; 2])}),
        ] {
            t.same(req).await;
        }
    }
    // Bea introduces each twin to someone, twice: one to say yes to and
    // one to say no to
    let twin = [t.old.clone(), t.new.clone()];
    for (i, x) in bea.iter().enumerate() {
        let me = id(&twin[i]);
        let space = crate::contacts::find(x, "Me").unwrap().space;
        for (n, name) in [(21u8, "Fay"), (22, "Gus")] {
            let op = cardinal_space::relationship::create_introduction(
                &id(x),
                &[n; 32],
                name,
                Some("a friend"),
                None,
                None,
            );
            x.write_and_push(&space, vec![op]).unwrap();
        }
        let _ = me;
    }
    until("Bea's introductions", || {
        twin.iter().all(|d| waiting_ids(d).len() == 2)
    })
    .await;
    let names = |d: &Arc<Daemon>| {
        let mut v: Vec<(String, [u8; 16])> = crate::introductions::list(d)
            .introductions
            .into_iter()
            .map(|i| (i.name, i.id))
            .collect();
        v.sort();
        v
    };
    let (wo, wn) = (names(&t.old), names(&t.new));
    for ((_, o), (_, n)) in wo.iter().zip(&wn) {
        t.alike(o, n);
    }
    // Fay: as text, upper case (not an id here), then as bytes
    t.same_as(
        json!({"cmd": "introduction-accept", "id": hex::encode(wo[0].1).to_uppercase()}),
        json!({"cmd": "introduction-accept", "id": hex::encode(wn[0].1).to_uppercase()}),
    )
    .await;
    t.same_as(
        json!({"cmd": "introduction-accept", "id": exact(&wo[0].1)}),
        json!({"cmd": "introduction-accept", "id": exact(&wn[0].1)}),
    )
    .await;
    // Gus: no, as text
    t.same_as(
        json!({"cmd": "introduction-decline", "id": hex::encode(wo[1].1)}),
        json!({"cmd": "introduction-decline", "id": hex::encode(wn[1].1)}),
    )
    .await;
    t.same_as(
        json!({"cmd": "introduction-decline", "id": hex::encode(wo[1].1)}),
        json!({"cmd": "introduction-decline", "id": hex::encode(wn[1].1)}),
    )
    .await;

    // ---- the groups' ----
    let (go, gn) = a_group(&mut t, "Kin");
    for req in [
        json!({"cmd": "group-connect"}),
        json!({"cmd": "group-connect", "group": "Kin"}),
        json!({"cmd": "group-connect", "who": "Bea"}),
        json!({"cmd": "group-connect", "group": "Nowhere", "who": "Bea"}),
        json!({"cmd": "group-connect", "group": exact(&[6; 32]), "who": "Bea"}),
        json!({"cmd": "group-connect", "group": "Kin", "who": "Bea"}),
        json!({"cmd": "group-post-again"}),
        json!({"cmd": "group-post-again", "group": "Nowhere"}),
        json!({"cmd": "group-post-again", "group": "Kin"}),
        json!({"cmd": "group-post-again", "group": exact(&[6; 32])}),
        json!({"cmd": "group-moved-seen"}),
        json!({"cmd": "group-moved-seen", "group": "Nowhere"}),
        json!({"cmd": "group-moved-seen", "group": "Kin"}),
        json!({"cmd": "group-confirm-move"}),
        json!({"cmd": "group-confirm-move", "group": "Kin"}),
        json!({"cmd": "group-confirm-move", "group": "Kin", "moves": []}),
        json!({"cmd": "group-confirm-move", "group": "Kin", "moves": [hex::encode([1; 3])]}),
        json!({"cmd": "group-confirm-move", "group": "Kin", "moves": [hex::encode([1; 32])]}),
        json!({"cmd": "group-confirm-move", "group": "Kin", "moves": [hex::encode([1; 32])],
            "to": [hex::encode([2; 32]), hex::encode([3; 32])]}),
        json!({"cmd": "group-confirm-move", "group": "Kin", "moves": [hex::encode([1; 32])],
            "to": [hex::encode([2; 5])]}),
        json!({"cmd": "group-confirm-move", "group": "Kin", "moves": [hex::encode([1; 32])],
            "to": [hex::encode([2; 32])]}),
        json!({"cmd": "group-leaving"}),
        json!({"cmd": "group-leaving", "group": "Nowhere"}),
    ] {
        t.same(req).await;
    }
    t.same_as(
        json!({"cmd": "group-connect", "group": "Kin", "who": exact(&bea_o)}),
        json!({"cmd": "group-connect", "group": "Kin", "who": exact(&bea_n)}),
    )
    .await;
    for group in [
        json!("Kin"),
        json!(hex::encode(&gn[..8])),
        json!(exact(&gn)),
    ] {
        t.same_here(json!({"cmd": "group-leaving", "group": group}))
            .await;
    }
    t.same_as(
        json!({"cmd": "group-moved-seen", "group": exact(&go)}),
        json!({"cmd": "group-moved-seen", "group": exact(&gn)}),
    )
    .await;
    t.same_as(
        json!({"cmd": "group-post-again", "group": exact(&go)}),
        json!({"cmd": "group-post-again", "group": exact(&gn)}),
    )
    .await;
    // a group of Bea's, which introduces its members
    let bea_group = |x: &Arc<Daemon>| {
        let me = vec![typed::Reference::Typed("Me".into())];
        crate::groups::create(x, "Club", &me, false, true)
            .unwrap()
            .group
    };
    let (co, cn) = (bea_group(&bea[0]), bea_group(&bea[1]));
    t.alike(&co, &cn);
    until("the offers of Club", || {
        twin.iter().all(|d| {
            crate::groups::list(d)
                .offers
                .iter()
                .any(|o| o.name == "Club")
        })
    })
    .await;
    for req in [
        json!({"cmd": "group-connect", "group": "Club", "who": "Bea"}),
        json!({"cmd": "group-leaving", "group": "Club"}),
        json!({"cmd": "group-post-again", "group": "Club"}),
    ] {
        t.same(req).await;
    }
    for x in bea.iter().chain(&cy) {
        let _ = x.stopping.send(true);
    }
}

/// The guardians' requests: the person's (naming guardians, asking one,
/// objecting) on the twins, and a guardian's (accepting, what they guard,
/// the caution, and every refusal before a recovery) on the two who are
/// asked, Bea of each twin, the one by name and the other typed. What
/// needs a recovery or a change of guardians under way (endorsing,
/// confirming, saying never, confirming a change, an invitation for a
/// helper) is compared up to its refusals here; the whole is asked in
/// `tests/guardians.rs`, where `guardians` and `guarding` are compared
/// beside.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn guardians_are_answered_the_same() {
    let dir = tempfile::tempdir().unwrap();
    let (mut t, words) = Twins::start_words(dir.path()).await;
    tokio::spawn(t.old.clone().run());
    tokio::spawn(t.new.clone().run());
    t.same_here(json!({"cmd": "guardians"})).await;
    t.same_here(json!({"cmd": "guarding"})).await;
    let bea = befriended(&mut t, dir.path(), "Bea").await;
    let bea_id = |i: usize| bea[i].core().identity.as_ref().unwrap().id();
    let cy = a_contact(&t, "Cy", 7);
    for d in [&t.old, &t.new] {
        crate::contacts::set_by_name(d, "Cy", "hosts-only").unwrap();
    }
    let twin = [t.old.clone(), t.new.clone()];

    // ---- the person's, before anyone accepted ----
    for req in [
        json!({"cmd": "guardians-set"}),
        json!({"cmd": "guardians-set", "who": []}),
        json!({"cmd": "guardians-set", "who": ["Nobody"]}),
        json!({"cmd": "guardians-set", "who": ["Cy"]}),
        json!({"cmd": "guardians-set", "who": [exact(&cy)]}),
        json!({"cmd": "guardians-set", "who": ["Bea", "bea"]}),
        json!({"cmd": "guardians-set", "who": ["Bea"], "threshold": 2}),
        json!({"cmd": "guardians-set", "who": ["Bea"], "threshold": 0}),
        json!({"cmd": "guardians-ask"}),
        json!({"cmd": "guardians-ask", "who": "Nobody"}),
        json!({"cmd": "guardians-ask", "who": "Cy"}),
        json!({"cmd": "guardians-object"}),
        json!({"cmd": "guardians-object", "fingerprint": "a b c"}),
    ] {
        t.same(req).await;
    }
    // not accepted yet: asked, and refused
    t.same(json!({"cmd": "guardians-set", "who": ["Bea"]}))
        .await;
    t.same_here(json!({"cmd": "guardians"})).await;
    t.same_as(
        json!({"cmd": "guardians-ask", "who": exact(&bea_id(0))}),
        json!({"cmd": "guardians-ask", "who": exact(&bea_id(1))}),
    )
    .await;
    t.same(json!({"cmd": "guardians-ask", "who": "Bea"})).await;

    // ---- Bea's, each twin's: the old one asked by name ----
    let mut b = Twins {
        old: bea[0].clone(),
        new: bea[1].clone(),
        swap: t.swap.clone(),
    };
    until("the asking of Bea", || {
        bea.iter()
            .all(|x| !crate::guardians::list(x).asked.is_empty())
    })
    .await;
    b.same_here(json!({"cmd": "guarding"})).await;
    for req in [
        json!({"cmd": "guarding-accept"}),
        json!({"cmd": "guarding-accept", "who": "Nobody"}),
        json!({"cmd": "guarding-caution", "who": "Me"}),
        json!({"cmd": "guarding-caution"}),
        json!({"cmd": "guarding-invite", "who": "Me"}),
        json!({"cmd": "guarding-invite"}),
        json!({"cmd": "guarding-never", "who": "Me", "fingerprint": "x"}),
        json!({"cmd": "guarding-endorse", "who": "Me", "fingerprint": "x"}),
        json!({"cmd": "guarding-confirm", "who": "Me", "fingerprint": "x", "understood": true}),
        json!({"cmd": "guarding-confirm-change", "who": "Me"}),
    ] {
        b.same(req).await;
    }
    let persona = |r: &GuardingAcceptReply| vec![r.persona.to_vec()];
    b.same_made::<GuardingAcceptArgs>(
        json!({"cmd": "guarding-accept", "who": "Me"}),
        json!({"cmd": "guarding-accept", "who": "Me"}),
        persona,
    )
    .await;
    let r = typed_of::<GuardingAcceptArgs>(
        &b.same(json!({"cmd": "guarding-accept", "who": "me"})).await,
    );
    assert!(r.already, "{r:?}");
    b.same_here(json!({"cmd": "guarding"})).await;

    // ---- the person's, Bea accepted ----
    until("Bea's persona", || {
        twin.iter()
            .all(|d| crate::guardians::show(d).is_ok_and(|g| g.ready.iter().any(|n| n == "Bea")))
    })
    .await;
    t.swap = b.swap.clone();
    t.same_here(json!({"cmd": "guardians"})).await;
    // the first guardians need the words
    t.same(json!({"cmd": "guardians-set", "who": ["Bea"], "words": "not the words"}))
        .await;
    t.same(json!({"cmd": "guardians-set", "who": ["Bea"]}))
        .await;
    let r = typed_of::<GuardiansSetArgs>(
        &t.same(json!({"cmd": "guardians-set", "who": ["Bea"], "words": words, "delay": 60}))
            .await,
    );
    assert_eq!(r.names, ["Bea"]);
    t.same_here(json!({"cmd": "guardians"})).await;
    // a change under way, of guardians named again
    t.same(json!({"cmd": "guardians-set", "who": ["Bea"], "threshold": 1}))
        .await;
    t.same_here(json!({"cmd": "guardians"})).await;
    t.same(json!({"cmd": "guardians-set", "who": ["Bea"]}))
        .await;
    t.same(json!({"cmd": "guardians-object", "fingerprint": "not it"}))
        .await;
    // ---- Bea's, guarding ----
    until("Bea guards each twin", || {
        bea.iter()
            .all(|x| !crate::guardians::list(x).guarding.is_empty())
    })
    .await;
    b.swap = t.swap.clone();
    b.same_here(json!({"cmd": "guarding"})).await;
    for req in [
        json!({"cmd": "guarding-caution", "who": "Me"}),
        json!({"cmd": "guarding-never", "who": "Me"}),
        json!({"cmd": "guarding-never", "who": "Me", "fingerprint": "x"}),
        json!({"cmd": "guarding-endorse", "who": "Me", "fingerprint": "x"}),
        json!({"cmd": "guarding-endorse", "who": "Me", "fingerprint": "x", "understood": true}),
        json!({"cmd": "guarding-confirm", "who": "Me", "fingerprint": "x", "understood": true}),
        json!({"cmd": "guarding-confirm", "who": "Me"}),
        json!({"cmd": "guarding-confirm-change", "who": "Me"}),
        json!({"cmd": "guarding-confirm-change", "who": "Me", "understood": true}),
        json!({"cmd": "guarding-invite", "who": "Nobody"}),
    ] {
        b.same(req).await;
    }
    for x in &bea {
        let _ = x.stopping.send(true);
    }
}

/// Recovery's requests: on the twins, which belong to someone, and on two
/// devices that do not, each a copy of the other. A recovery under way and
/// its finish make words and a helper of each one's own, so what they
/// answer then is compared up to its refusals here; the whole is asked in
/// `tests/guardians.rs`, where `recovery-sheet` and `recovery-check` are
/// compared beside.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recovery_is_answered_the_same() {
    let dir = tempfile::tempdir().unwrap();
    let (t, words) = Twins::start_words(dir.path()).await;
    let device = t.old.config().name.clone();
    t.same_here(json!({"cmd": "recovery-sheet"})).await;
    for req in [
        json!({"cmd": "recover"}),
        json!({"cmd": "recovery-check"}),
        json!({"cmd": "recovery-check", "words": "not the words"}),
        json!({"cmd": "recovery-check", "words": words}),
        json!({"cmd": "recover-start"}),
        json!({"cmd": "recover-start", "identity": "zz"}),
        json!({"cmd": "recover-invite"}),
        json!({"cmd": "recover-cancel"}),
        json!({"cmd": "recover-finish"}),
        json!({"cmd": "recover-finish", "without_account": true, "lost_at": 5}),
        json!({"cmd": "recover-lost-at"}),
        json!({"cmd": "recover-lost-at", "lost_at": 5}),
        json!({"cmd": "keep-work"}),
        json!({"cmd": "keep-work", "name": "Nobody"}),
        json!({"cmd": "keep-work", "name": device}),
        json!({"cmd": "keep-work", "name": device, "up_to": "soon"}),
        json!({"cmd": "keep-work", "name": device, "up_to": "all"}),
        json!({"cmd": "keep-work", "name": device, "up_to": "17"}),
        json!({"cmd": "restore-from-host"}),
        json!({"cmd": "restore-from-host", "words": words, "at": "nowhere"}),
        json!({"cmd": "restore-from-host", "words": words, "at": "nowhere", "key": hex::encode([1; 32])}),
        json!({"cmd": "recover-undo"}),
        json!({"cmd": "recover-undo", "to": hex::encode([2; 32])}),
        json!({"cmd": "recover-kept-seen"}),
        json!({"cmd": "recover-kept-seen", "to": [hex::encode([2; 32])]}),
        json!({"cmd": "recover-stop-waiting"}),
        json!({"cmd": "recover-stop-waiting", "all": true, "who": "Bea"}),
        json!({"cmd": "recover-stop-waiting", "all": true}),
        json!({"cmd": "recover-stop-waiting", "who": exact(&[4; 32])}),
    ] {
        t.same(req).await;
    }
    t.same_message(&message_of(170, vec![(1, Value::from(5u64))]))
        .await;
    for d in [&t.old, &t.new] {
        let _ = d.stopping.send(true);
    }

    // two devices that belong to nobody
    let fresh = |at: &str| {
        let paths = crate::paths::Paths::at(&dir.path().join(at));
        let mut config = crate::config::Config {
            listen: "127.0.0.1:0".into(),
            ..Default::default()
        };
        config.this_run.no_mount = true;
        config.this_run.no_discovery = true;
        config.this_run.no_udp = true;
        (paths, config)
    };
    let (po, co) = fresh("bare-old");
    let (pn, cn) = fresh("bare-new");
    let u = Twins {
        old: Daemon::start(po, co).await.unwrap(),
        new: Daemon::start(pn, cn).await.unwrap(),
        swap: Vec::new(),
    };
    for req in [
        json!({"cmd": "recover"}),
        json!({"cmd": "recovery-sheet"}),
        json!({"cmd": "recovery-check", "words": words}),
        json!({"cmd": "recover-start", "code": "not a code"}),
        json!({"cmd": "recover-start", "identity": "zz"}),
        json!({"cmd": "recover-start", "identity": " 00ff "}),
        json!({"cmd": "recover-start", "identity": exact(&[3; 5])}),
        json!({"cmd": "recover-invite"}),
        json!({"cmd": "recover-invite", "at": "192.0.2.1:7171"}),
        json!({"cmd": "recover-cancel"}),
        json!({"cmd": "recover-finish"}),
        json!({"cmd": "recover-lost-at", "lost_at": 5}),
        json!({"cmd": "restore-from-host", "words": "not the words", "at": "x", "key": hex::encode([1; 32])}),
        json!({"cmd": "restore-from-host", "words": words, "at": "nowhere", "key": hex::encode([1; 31])}),
        json!({"cmd": "restore-from-host", "words": words, "at": "nowhere", "key": hex::encode([1; 32])}),
        json!({"cmd": "restore-from-host", "words": words, "key": hex::encode([1; 32])}),
        json!({"cmd": "recover-undo", "to": hex::encode([2; 32])}),
        json!({"cmd": "recover-stop-waiting", "all": true}),
    ] {
        u.same(req).await;
    }
}

/// Hosting a contact: offered by each twin to its Bea, taken up by each
/// Bea, the one by name and the other typed, and ended; with every refusal
/// before, a ref as text and as bytes, and `hosting` on both sides.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hosting_is_answered_the_same() {
    let dir = tempfile::tempdir().unwrap();
    let mut t = Twins::start(dir.path()).await;
    tokio::spawn(t.old.clone().run());
    tokio::spawn(t.new.clone().run());
    let bea = befriended(&mut t, dir.path(), "Bea").await;
    let bea_id = |i: usize| bea[i].core().identity.as_ref().unwrap().id();
    let cy = a_contact(&t, "Cy", 7);
    for d in [&t.old, &t.new] {
        crate::contacts::set_by_name(d, "Cy", "hosts-only").unwrap();
    }
    t.same_here(json!({"cmd": "hosting"})).await;
    for req in [
        json!({"cmd": "host-offer"}),
        json!({"cmd": "host-offer", "who": "Nobody"}),
        json!({"cmd": "host-offer", "who": "Cy"}),
        json!({"cmd": "host-offer", "who": exact(&cy)}),
        json!({"cmd": "host-offer", "who": "Bea"}),
        json!({"cmd": "host-accept"}),
        json!({"cmd": "host-accept", "who": "Cy"}),
        json!({"cmd": "host-accept", "who": exact(&cy)}),
        json!({"cmd": "host-accept", "who": "Bea"}),
        json!({"cmd": "host-end"}),
        json!({"cmd": "host-end", "who": "Nobody"}),
        json!({"cmd": "host-end", "who": "Bea"}),
    ] {
        t.same(req).await;
    }
    t.same_as(
        json!({"cmd": "host-accept", "who": exact(&bea_id(0))}),
        json!({"cmd": "host-accept", "who": exact(&bea_id(1))}),
    )
    .await;
    // each twin plugged in on a network not metered: it can host
    for d in [&t.old, &t.new] {
        d.conditions.tell(crate::conditions::Told {
            plugged_in: true,
            metered: false,
        });
    }
    t.same_here(json!({"cmd": "hosting"})).await;
    for req in [
        json!({"cmd": "host-offer", "who": "Bea", "devices": ["Nowhere"]}),
        json!({"cmd": "host-offer", "who": "Bea", "envelopes": 10, "relay_mb": 5}),
        json!({"cmd": "host-offer", "who": "bea", "devices": [], "envelopes": 20}),
        json!({"cmd": "host-offer", "who": "Bea"}),
    ] {
        t.same(req).await;
    }
    t.same_here(json!({"cmd": "hosting"})).await;
    let mut b = Twins {
        old: bea[0].clone(),
        new: bea[1].clone(),
        swap: t.swap.clone(),
    };
    until("the offers to host Bea", || {
        bea.iter()
            .all(|x| !crate::hosting::list(x).hosting.is_empty())
    })
    .await;
    b.same_here(json!({"cmd": "hosting"})).await;
    for req in [
        json!({"cmd": "host-accept", "who": "Me"}),
        json!({"cmd": "host-accept", "who": "me"}),
    ] {
        b.same(req).await;
    }
    b.same_here(json!({"cmd": "hosting"})).await;
    b.same(json!({"cmd": "host-end", "who": "Me"})).await;
    b.same_here(json!({"cmd": "hosting"})).await;
    t.same(json!({"cmd": "host-end", "who": "Bea"})).await;
    b.swap.clear();
    t.same_here(json!({"cmd": "hosting"})).await;
    for x in &bea {
        let _ = x.stopping.send(true);
    }
}

/// Freeing space and the service's own: how long old versions are kept,
/// freeing what is past it or what nothing names, emptying a history, a
/// reload, and stopping; with a space named as text, as the start of its
/// id in any case, and as bytes.
#[tokio::test]
async fn freeing_space_is_answered_the_same() {
    let dir = tempfile::tempdir().unwrap();
    let t = Twins::start(dir.path()).await;
    let files = t.new.core().files_id().unwrap();
    let start = hex::encode(&files[..4]);
    for req in [
        json!({"cmd": "keep-old"}),
        json!({"cmd": "keep-old", "keep": "never ever"}),
        json!({"cmd": "keep-old", "keep": "7d"}),
        json!({"cmd": "keep-old", "keep": "forever", "space": ""}),
        json!({"cmd": "keep-old", "keep": "3 days", "space": start}),
        json!({"cmd": "keep-old", "keep": "3 days", "space": start.to_uppercase()}),
        json!({"cmd": "keep-old", "keep": "3 days", "space": format!(" {start} ")}),
        json!({"cmd": "keep-old", "keep": "1", "space": exact(&files)}),
        json!({"cmd": "keep-old", "keep": "1", "space": exact(&files[..2])}),
        json!({"cmd": "keep-old", "keep": "1", "space": exact(&[])}),
        json!({"cmd": "keep-old", "keep": "1", "space": "ffffffffff"}),
        json!({"cmd": "free-space"}),
        json!({"cmd": "free-space", "dry_run": true}),
        json!({"cmd": "free-space", "dry_run": false}),
        json!({"cmd": "free-space", "unnamed": true}),
        json!({"cmd": "free-space", "unnamed": true, "delete": true}),
        json!({"cmd": "free-space", "unnamed": false, "delete": true}),
        json!({"cmd": "history-empty"}),
        json!({"cmd": "history-empty", "space": ""}),
        json!({"cmd": "history-empty", "space": start}),
        json!({"cmd": "history-empty", "space": exact(&files)}),
        json!({"cmd": "history-empty", "space": "ffffffffff"}),
        json!({"cmd": "reload"}),
    ] {
        t.same(req).await;
    }
    t.same_message(&message_of(138, vec![(1, Value::from(3u64))]))
        .await;
    t.same(json!({"cmd": "stop"})).await;
    assert!(*t.new.stopping.subscribe().borrow());
}

// ---- Setting up, removing a device, contacts, measuring, programs ----

/// Whether a reply says it was done.
fn done(msg: &[u8]) -> bool {
    Record::decode(msg).unwrap().get(0).and_then(Value::as_uint) == Some(status::OK)
}

/// Asks each of `reqs` of both twins, and says which were done.
async fn done_of(t: &Twins, reqs: Vec<Json>) -> Vec<bool> {
    let mut out = Vec::new();
    for req in reqs {
        out.push(done(&t.same(req).await));
    }
    out
}

/// Two services on copies of one device that belongs to nobody yet, as a
/// window finds one before it is set up.
async fn bare_twins(dir: &std::path::Path) -> Twins {
    let start = |at: &str| {
        let paths = crate::paths::Paths::at(&dir.join(at));
        let mut config = crate::config::Config {
            listen: "127.0.0.1:0".into(),
            ..Default::default()
        };
        config.this_run.no_mount = true;
        config.this_run.no_discovery = true;
        config.this_run.no_udp = true;
        (paths, config)
    };
    let (po, co) = start("old");
    let (pn, cn) = start("new");
    let old = Daemon::start(po, co).await.unwrap();
    let new = Daemon::start(pn, cn).await.unwrap();
    let mut t = Twins {
        old,
        new,
        swap: Vec::new(),
    };
    // each one's folder, named in a refusal
    let (o, n) = (
        dir.join("old").display().to_string(),
        dir.join("new").display().to_string(),
    );
    t.swap.push((o.into_bytes(), n.into_bytes()));
    t
}

/// `setup-begin` gives words of its own on each twin, made at random: the
/// replies are compared with the new one's words and places put in the
/// old one's reply, which must then be the new one's bytes, and each is
/// checked for what it holds. `setup-finish` is then compared byte for
/// byte, each twin answered with its own words.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn setting_up_is_answered_the_same() {
    let dir = tempfile::tempdir().unwrap();
    let t = bare_twins(dir.path()).await;
    // before anything is begun
    for req in [
        json!({"cmd": "setup-finish"}),
        json!({"cmd": "setup-finish", "answers": ["a", "b"]}),
    ] {
        t.same(req).await;
    }
    let begun = |t: &Twins| {
        let (o, n) = (t.old.clone(), t.new.clone());
        async move {
            let (_, msg) = encode_request(&json!({"cmd": "setup-begin"})).unwrap();
            let old = crate::control::by_name(&o, &msg).await;
            let new = crate::control::typed::reply(&n, &msg).await.unwrap();
            // one record each, canonical, its words and places as begun
            let (ro, rn) = (Record::decode(&old).unwrap(), Record::decode(&new).unwrap());
            assert_eq!(ro.encode(), old);
            let mut swapped = ro.clone();
            for k in [2, 3] {
                swapped.insert(k, rn.get(k).unwrap().clone());
            }
            assert_eq!(swapped.encode(), new, "setup-begin, the words swapped");
            let words = |r: &Record| -> Vec<String> {
                let l = r.get(3).unwrap().as_list().unwrap();
                l.iter().map(|w| w.as_text().unwrap().to_owned()).collect()
            };
            let ask = |r: &Record| -> Vec<u64> {
                let l = r.get(2).unwrap().as_list().unwrap();
                l.iter().map(|n| n.as_uint().unwrap()).collect()
            };
            for r in [&ro, &rn] {
                assert_eq!(r.len(), 3);
                assert_eq!(r.get(0).and_then(Value::as_uint), Some(0));
                assert_eq!(words(r).len(), 24);
                let a = ask(r);
                assert!(a.len() == 2 && a[0] < a[1] && a[1] < 24, "{a:?}");
            }
            let read = typed_of::<SetupBeginArgs>(&new);
            assert_eq!(read.words, words(&rn));
            let answers = |r: &Record| -> Vec<String> {
                let w = words(r);
                ask(r).iter().map(|&i| w[i as usize].clone()).collect()
            };
            (answers(&ro), answers(&rn))
        }
    };
    let (ao, an) = begun(&t).await;
    for (old, new) in [
        (json!(["no", "no"]), json!(["no", "no"])),
        (json!([ao[0]]), json!([an[0]])),
        (json!([]), json!([])),
    ] {
        t.same_as(
            json!({"cmd": "setup-finish", "answers": old}),
            json!({"cmd": "setup-finish", "answers": new}),
        )
        .await;
    }
    t.same(json!({"cmd": "setup-finish"})).await;
    let up =
        |w: &[String]| -> Vec<String> { vec![format!("  {}", w[0].to_uppercase()), w[1].clone()] };
    // a name or a device's name of two lines, refused before anything
    // is kept
    for (name, device) in [
        (json!("Ann\nB"), json!(null)),
        (json!("Ann"), json!("a\nb")),
    ] {
        t.same_as(
            json!({"cmd": "setup-finish", "answers": up(&ao), "name": name, "device": device}),
            json!({"cmd": "setup-finish", "answers": up(&an), "name": name, "device": device}),
        )
        .await;
    }
    // begun again: the words before go
    let (ao, an) = begun(&t).await;
    t.same_as(
        json!({"cmd": "setup-finish", "answers": up(&ao), "name": "  Ann  ", "device": " Desk "}),
        json!({"cmd": "setup-finish", "answers": up(&an), "name": "  Ann  ", "device": " Desk "}),
    )
    .await;
    // done: nothing is being set up, and the device belongs to someone
    t.same(json!({"cmd": "setup-finish", "answers": ["a", "b"]}))
        .await;
    t.same(json!({"cmd": "setup-begin"})).await;

    // the person's own name, and the device's, as the machine has them
    let dir = tempfile::tempdir().unwrap();
    let t = bare_twins(dir.path()).await;
    let (ao, an) = begun(&t).await;
    t.same_as(
        json!({"cmd": "setup-finish", "answers": ao, "name": " ", "device": ""}),
        json!({"cmd": "setup-finish", "answers": an, "name": " ", "device": ""}),
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let t = bare_twins(dir.path()).await;
    let (ao, an) = begun(&t).await;
    t.same_as(
        json!({"cmd": "setup-finish", "answers": ao}),
        json!({"cmd": "setup-finish", "answers": an}),
    )
    .await;
}

/// A device of this person's, the same on each twin, named `name` in the
/// account where a name is given.
fn a_device(t: &Twins, power: cardinal_identity::Power) -> [u8; 32] {
    let k = cardinal_identity::DeviceKeys::generate();
    for d in [&t.old, &t.new] {
        {
            let mut core = d.core();
            let ident = core.identity.as_mut().unwrap();
            let enc = ident.enc.first().unwrap();
            let enc = cardinal_crypto::HybridKeyPair::from_secret_bytes(&enc.secret_bytes());
            let req = k.request(&ident.id(), power);
            let e = ident
                .log
                .add_key(&d.keys.device.signing, &req, Some(&enc))
                .unwrap();
            ident.record_own(&e).unwrap();
        }
        d.identity_changed();
    }
    k.key()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_is_removed_the_same() {
    let dir = tempfile::tempdir().unwrap();
    let (t, words) = Twins::start_words(dir.path()).await;
    let me = t.new.keys.key();
    let one = a_device(&t, cardinal_identity::Power::Device);
    let two = a_device(&t, cardinal_identity::Power::Device);
    let admin = a_device(&t, cardinal_identity::Power::Admin);
    let short = |k: &[u8; 32]| hex::encode(&k[..8]);
    let reqs = vec![
        json!({"cmd": "remove-device"}),
        json!({"cmd": "remove-device", "lost": true}),
        json!({"cmd": "remove-device", "who": "nobody"}),
        json!({"cmd": "remove-device", "who": ""}),
        json!({"cmd": "remove-device", "who": exact(&[])}),
        json!({"cmd": "remove-device", "who": exact(&one[..4])}),
        json!({"cmd": "remove-device", "who": exact(&me)}),
        json!({"cmd": "remove-device", "who": short(&me)}),
        json!({"cmd": "remove-device", "who": short(&admin)}),
        json!({"cmd": "remove-device", "who": short(&admin), "words": "not the words"}),
        json!({"cmd": "remove-device", "who": short(&one).to_uppercase(), "lost": true}),
        json!({"cmd": "remove-device", "who": exact(&two[..8])}),
        json!({"cmd": "remove-device", "who": exact(&two)}),
        json!({"cmd": "remove-device", "who": short(&admin), "words": words, "lost": false}),
    ];
    let done = done_of(&t, reqs).await;
    // the three removals, and nothing else
    assert_eq!(done.iter().filter(|x| **x).count(), 3, "{done:?}");
    assert!(done[10] && done[11] && done[13], "{done:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_contact_is_changed_the_same() {
    let dir = tempfile::tempdir().unwrap();
    let mut t = Twins::start(dir.path()).await;
    let ann = a_contact(&t, "Ann", 7);
    a_contact(&t, "Bea", 9);
    // a picture on the disk, and one too large for a picture
    let png = dir.path().join("ann.png");
    std::fs::write(&png, b"\x89PNG\r\n\x1a\n a picture").unwrap();
    let big = dir.path().join("big.png");
    std::fs::File::create(&big)
        .unwrap()
        .set_len((16 << 20) + 1)
        .unwrap();
    // each twin's folder of pictures, named in what it shows
    let (o, n) = (
        t.old.paths.pictures().display().to_string(),
        t.new.paths.pictures().display().to_string(),
    );
    t.swap.push((o.into_bytes(), n.into_bytes()));
    let short = hex::encode(&ann[..8]);
    let reqs = vec![
        json!({"cmd": "contact"}),
        json!({"cmd": "contact", "who": "Ann"}),
        json!({"cmd": "contact", "name": "Ann"}),
        json!({"cmd": "contact", "who": "nobody", "name": "x"}),
        json!({"cmd": "contact", "who": exact(&[1, 2]), "name": "x"}),
        json!({"cmd": "contact", "who": "Ann", "name": "Bea"}),
        json!({"cmd": "contact", "who": "Ann", "name": "two\nlines"}),
        json!({"cmd": "contact", "who": "Ann", "name": "  Anna  "}),
        json!({"cmd": "contact", "who": exact(&ann), "name": ""}),
        json!({"cmd": "contact", "who": short, "name": "Ann", "category": "Work"}),
        json!({"cmd": "contact", "who": "Ann", "category": ""}),
        json!({"cmd": "contact", "who": "Ann", "category": "a/b"}),
        json!({"cmd": "contact", "who": "Ann", "category": ".."}),
        json!({"cmd": "contact", "who": exact(&ann[..8]), "category": " Family "}),
        json!({"cmd": "contact", "who": "Ann", "picture": ""}),
        json!({"cmd": "contact", "who": "Ann", "picture": "People/none.png"}),
        json!({"cmd": "contact", "who": "Ann", "picture": big.display().to_string()}),
        json!({"cmd": "contact", "who": "Ann", "picture": png.display().to_string()}),
        json!({"cmd": "contact", "who": "Ann", "name": ""}),
        json!({"cmd": "contact", "who": exact(&ann), "name": "Ann"}),
        json!({"cmd": "contact", "who": "Ann", "picture": " ", "category": "Work"}),
        json!({"cmd": "contact", "who": "Ann", "setting": "bogus"}),
        json!({"cmd": "contact", "setting": "trust"}),
        json!({"cmd": "contact", "who": "Ann", "setting": "trust"}),
        json!({"cmd": "contact", "who": "Ann", "setting": "hosts-only"}),
        json!({"cmd": "contact", "who": "Ann", "setting": "no-introductions"}),
        json!({"cmd": "contact", "who": "Ann", "setting": "introductions"}),
        json!({"cmd": "contact", "who": "Ann", "setting": "name-hosts"}),
        json!({"cmd": "contact", "who": "Ann", "setting": "no-hosts"}),
        json!({"cmd": "contact", "who": "Ann", "setting": "name-hosts"}),
        json!({"cmd": "contact", "who": "Ann", "setting": "no-host"}),
        json!({"cmd": "contact", "who": "Ann", "setting": "no-host", "host": "nowhere"}),
        json!({"cmd": "contact", "who": exact(&ann), "setting": "refuse"}),
        json!({"cmd": "contact", "who": exact(&ann), "setting": "name-hosts"}),
        json!({"cmd": "contact", "who": "Ann", "setting": "no-hosts"}),
        json!({"cmd": "contact", "who": exact(&ann[..8]), "setting": "unrefuse"}),
    ];
    let done = done_of(&t, reqs).await;
    let yes = [
        7, 8, 9, 13, 14, 17, 18, 19, 20, 23, 24, 25, 26, 27, 29, 32, 35,
    ];
    let said: Vec<usize> = (0..done.len()).filter(|i| done[*i]).collect();
    assert_eq!(said, yes);
    // the picture, read back as the contacts give it
    t.same_here(json!({"cmd": "contacts"})).await;
    let _ = &mut t;
}

/// What the files bring back: each twin's deleted file has an id of its
/// own, told alike.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn files_are_brought_back_the_same() {
    let dir = tempfile::tempdir().unwrap();
    let mut t = Twins::start(dir.path()).await;
    let local = dir.path().join("local.txt");
    std::fs::write(&local, b"some bytes").unwrap();
    let local = local.to_str().unwrap().to_owned();
    for req in [
        json!({"cmd": "mkdir", "path": "Docs"}),
        json!({"cmd": "write", "from": local, "path": "Docs/a.txt"}),
        json!({"cmd": "remove", "path": "Docs/a.txt"}),
        json!({"cmd": "write", "from": local, "path": "Docs/a.txt"}),
        json!({"cmd": "remove", "path": "Docs/a.txt"}),
        json!({"cmd": "write", "from": local, "path": "b.txt"}),
        json!({"cmd": "remove", "path": "b.txt"}),
    ] {
        t.same(req).await;
    }
    let ids = |d: &Arc<Daemon>, path: &str| -> Vec<[u8; 16]> {
        let r = crate::file_history::deleted(d, path, false).unwrap();
        r.files.iter().map(|f| f.id).collect()
    };
    let (o, n) = (ids(&t.old, "Docs"), ids(&t.new, "Docs"));
    for (a, b) in o.iter().zip(&n) {
        t.alike(a, b);
    }
    let (ob, nb) = (ids(&t.old, ""), ids(&t.new, ""));
    for (a, b) in ob.iter().zip(&nb) {
        t.alike(a, b);
    }
    for req in [
        json!({"cmd": "undelete"}),
        json!({"cmd": "undelete", "path": "Docs/none.txt"}),
        json!({"cmd": "undelete", "path": "Nowhere/a.txt"}),
        json!({"cmd": "undelete", "path": "Docs/a.txt"}),
        json!({"cmd": "undelete", "path": "Docs/a.txt", "id": ""}),
        json!({"cmd": "undelete", "path": "Docs/a.txt", "id": exact(&[])}),
        json!({"cmd": "undelete", "path": "Docs/a.txt", "id": "ffffffff"}),
        json!({"cmd": "undelete", "path": "Docs/a.txt", "id": exact(&[0xff; 16])}),
    ] {
        t.same(req).await;
    }
    // by the start of its id, typed, and by its id as bytes
    let typed_start = |id: &[u8; 16]| hex::encode(&id[..6]).to_uppercase();
    t.same_as(
        json!({"cmd": "undelete", "path": "Docs/a.txt", "id": exact(&o[0][..8])}),
        json!({"cmd": "undelete", "path": "Docs/a.txt", "id": exact(&n[0][..8])}),
    )
    .await;
    let back = t
        .same_as(
            json!({"cmd": "undelete", "path": "Docs/a.txt", "id": typed_start(&o[0])}),
            json!({"cmd": "undelete", "path": "Docs/a.txt", "id": typed_start(&n[0])}),
        )
        .await;
    assert_eq!(typed_of::<UndeleteArgs>(&back).id, n[0]);
    let back = t
        .same_as(
            json!({"cmd": "undelete", "path": "Docs/a.txt", "id": exact(&o[1])}),
            json!({"cmd": "undelete", "path": "Docs/a.txt", "id": exact(&n[1])}),
        )
        .await;
    // the first is back, so its name is taken: the second comes back
    // beside it
    assert_eq!(typed_of::<UndeleteArgs>(&back).id, n[1]);
    assert!(done(
        &t.same(json!({"cmd": "undelete", "path": "b.txt"})).await
    ));
    assert!(!done(
        &t.same(json!({"cmd": "undelete", "path": "b.txt"})).await
    ));
    // what was brought back is in the folder again
    t.same_here(json!({"cmd": "files", "path": "Docs"})).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn what_programs_ask_is_answered_the_same() {
    let dir = tempfile::tempdir().unwrap();
    let mut t = Twins::start(dir.path()).await;
    let pages = |cmd: &str| {
        [
            json!({"cmd": cmd}),
            json!({"cmd": cmd, "limit": 1}),
            json!({"cmd": cmd, "after": 1, "limit": 1}),
            json!({"cmd": cmd, "after": 9}),
        ]
    };
    for cmd in ["app-questions", "approvals", "app-offers"] {
        for req in pages(cmd) {
            t.same(req).await;
        }
    }
    // questions waiting, alike on both
    let mut waiting = Vec::new();
    for d in [&t.old, &t.new] {
        use crate::apps::Asks;
        waiting.push(crate::apps::ask_for_test(
            d,
            "/usr/bin/cal",
            "Calendar",
            Asks::Family {
                root: [5; 32],
                change: true,
            },
            "see and change your calendars",
        ));
        waiting.push(crate::apps::ask_for_test(
            d,
            "/usr/bin/cal",
            "Calendar",
            Asks::Share {
                space: [6; 32],
                role: cardinal_space::group::WRITER,
            },
            "share Family",
        ));
        waiting.push(crate::apps::ask_for_test(
            d,
            "/usr/bin/notes",
            "Notes",
            Asks::NewSpace {
                root: [7; 32],
                name: "Notes".into(),
            },
            "start a space",
        ));
    }
    for cmd in ["app-questions"] {
        for req in pages(cmd) {
            t.same(req).await;
        }
    }
    // approvals, each twin's node its own, told alike
    for d in [&t.old, &t.new] {
        crate::apps::record_approval(d, "/usr/bin/cal", "Calendar", [5; 32], true).unwrap();
        crate::apps::record_approval(d, "/usr/bin/notes", "Notes", [7; 32], false).unwrap();
    }
    let nodes = |d: &Arc<Daemon>| -> Vec<[u8; 16]> {
        crate::apps::list_approvals(d)
            .iter()
            .map(|a| a.id)
            .collect()
    };
    let (on, nn) = (nodes(&t.old), nodes(&t.new));
    for (a, b) in on.iter().zip(&nn) {
        t.alike(a, b);
    }
    for req in pages("approvals") {
        t.same_here(req).await;
    }
    let reqs = vec![
        json!({"cmd": "app-answer"}),
        json!({"cmd": "app-answer", "id": 99, "yes": true}),
        json!({"cmd": "app-answer", "id": 1, "role": "owner"}),
        json!({"cmd": "app-answer", "id": 2, "yes": true}),
        json!({"cmd": "app-answer", "id": 2, "yes": true, "people": []}),
        json!({"cmd": "app-answer", "id": 1, "yes": true, "role": ""}),
        json!({"cmd": "app-answer", "id": 3, "yes": false}),
        json!({"cmd": "app-answer", "id": 1, "yes": true}),
        json!({"cmd": "approval-revoke"}),
        json!({"cmd": "approval-revoke", "id": ""}),
        json!({"cmd": "approval-revoke", "id": exact(&[])}),
        json!({"cmd": "approval-revoke", "id": "ffffffffff"}),
        json!({"cmd": "approval-revoke", "id": exact(&[0xff; 4])}),
        json!({"cmd": "app-join"}),
        json!({"cmd": "app-join", "space": ""}),
        json!({"cmd": "app-join", "space": "Calendar"}),
        json!({"cmd": "app-join", "space": exact(&[1; 32])}),
        json!({"cmd": "app-join", "space": exact(&[])}),
    ];
    let answered = done_of(&t, reqs).await;
    let said: Vec<usize> = (0..answered.len()).filter(|i| answered[*i]).collect();
    assert_eq!(said, [5, 6]);
    // the share question again, answered with whom and as what, by name
    // and by bytes; what each program was told
    for d in [&t.old, &t.new] {
        use crate::apps::Asks;
        waiting.push(crate::apps::ask_for_test(
            d,
            "/usr/bin/cal",
            "Calendar",
            Asks::Share {
                space: [6; 32],
                role: cardinal_space::group::READER,
            },
            "share Work",
        ));
    }
    let answered = t
        .same(json!({"cmd": "app-answer", "id": 4, "yes": true,
            "people": ["Ann", exact(&[3; 8])], "role": "reader"}))
        .await;
    assert!(done(&answered));
    // asked of the old one, then the new one: three, then one more
    let said: Vec<String> = waiting
        .into_iter()
        .map(|mut w| format!("{:?}", w.try_recv().ok()))
        .collect();
    assert_eq!(said[0..3], said[3..6]);
    assert_eq!(said[6], said[7]);
    assert!(said[7].contains("0303030303030303"), "{said:?}");
    // revoked by the start of its id, typed and as bytes
    t.same_as(
        json!({"cmd": "approval-revoke", "id": hex::encode(&on[0][..5]).to_uppercase()}),
        json!({"cmd": "approval-revoke", "id": hex::encode(&nn[0][..5]).to_uppercase()}),
    )
    .await;
    let revoked = t
        .same_as(
            json!({"cmd": "approval-revoke", "id": exact(&on[1][..3])}),
            json!({"cmd": "approval-revoke", "id": exact(&nn[1][..3])}),
        )
        .await;
    assert!(done(&revoked));
    assert!(crate::apps::list_approvals(&t.new)
        .iter()
        .all(|a| a.revoked));
    for req in pages("approvals") {
        t.same_here(req).await;
    }
}

/// `speedtest` measures, and so is answered once: compared where it is
/// refused, every way, the measuring itself is not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn speedtest_is_refused_the_same() {
    let dir = tempfile::tempdir().unwrap();
    let t = Twins::start(dir.path()).await;
    let me = t.new.keys.key();
    let other = a_device(&t, cardinal_identity::Power::Device);
    for req in [
        json!({"cmd": "speedtest"}),
        json!({"cmd": "speedtest", "device": "nowhere"}),
        json!({"cmd": "speedtest", "device": ""}),
        json!({"cmd": "speedtest", "device": exact(&[])}),
        json!({"cmd": "speedtest", "device": exact(&me)}),
        json!({"cmd": "speedtest", "device": hex::encode(&me[..8])}),
        json!({"cmd": "speedtest", "device": hex::encode(&other[..3]).to_uppercase()}),
        json!({"cmd": "speedtest", "device": exact(&other[..8])}),
        json!({"cmd": "speedtest", "device": exact(&other)}),
    ] {
        t.same(req).await;
    }
}

/// The tree, unmounted where the tests run, and on a device that holds no
/// files space.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_tree_is_answered_the_same() {
    let dir = tempfile::tempdir().unwrap();
    let t = Twins::start(dir.path()).await;
    for req in [
        json!({"cmd": "debug-tree"}),
        json!({"cmd": "debug-tree", "limit": 1}),
        json!({"cmd": "debug-tree", "after": 3}),
    ] {
        t.same_here(req).await;
    }
    let dir = tempfile::tempdir().unwrap();
    let t = bare_twins(dir.path()).await;
    t.same(json!({"cmd": "debug-tree"})).await;
}

/// Inspection turned on and off. The token is random and the time it ends
/// is read off each twin's clock: `inspect-on` is compared with the new
/// one's token and time put in the old one's reply, and the rest byte for
/// byte; what it is asked of the views is compared both ways on one
/// service, as every request that changes nothing is where the tests run.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inspection_is_turned_on_and_off_the_same() {
    let dir = tempfile::tempdir().unwrap();
    let t = Twins::start(dir.path()).await;
    for req in [
        json!({"cmd": "inspect-off"}),
        json!({"cmd": "inspect-on", "minutes": 0}),
        json!({"cmd": "inspect-on", "minutes": 24 * 60 + 1}),
        json!({"cmd": "inspect", "token": "00"}),
        json!({"cmd": "inspect"}),
    ] {
        t.same(req).await;
    }
    let on = |t: &Twins, req: Json| {
        let (o, n) = (t.old.clone(), t.new.clone());
        async move {
            let (_, msg) = encode_request(&req).unwrap();
            let old = crate::control::by_name(&o, &msg).await;
            let new = crate::control::typed::reply(&n, &msg).await.unwrap();
            let (ro, rn) = (Record::decode(&old).unwrap(), Record::decode(&new).unwrap());
            assert_eq!(ro.encode(), old);
            let mut swapped = ro.clone();
            for k in [2, 3] {
                swapped.insert(k, rn.get(k).unwrap().clone());
            }
            assert_eq!(swapped.encode(), new, "{req}, the token and time swapped");
            let read = typed_of::<InspectOnArgs>(&new);
            let until = |r: &Record| r.get(3).unwrap().as_uint().unwrap();
            assert!(until(&ro).abs_diff(until(&rn)) < 5_000);
            let minutes = req["minutes"].as_u64().unwrap_or(60);
            let now = crate::core::now_ms();
            assert!(read.until.abs_diff(now + minutes * 60_000) < 5_000);
            let token = |r: &Record| r.get(2).unwrap().as_bytes().unwrap().to_vec();
            (token(&ro), token(&rn))
        }
    };
    let (to, tn) = on(&t, json!({"cmd": "inspect-on"})).await;
    let (to, tn) = (exact(&to), exact(&tn));
    // each twin's own token, typed in hex or as bytes, and another's
    let typed_hex = |t: &str| t.trim_start_matches(EXACT).to_uppercase();
    for (o, n) in [
        (to.clone(), tn.clone()),
        (typed_hex(&to), typed_hex(&tn)),
        (tn.clone(), to.clone()),
    ] {
        t.same_as(
            json!({"cmd": "inspect-nodes", "token": o, "space": exact(&[0; 32])}),
            json!({"cmd": "inspect-nodes", "token": n, "space": exact(&[0; 32])}),
        )
        .await;
    }
    on(&t, json!({"cmd": "inspect-on", "minutes": 5})).await;
    for req in [
        json!({"cmd": "inspect-off"}),
        json!({"cmd": "inspect-off"}),
        json!({"cmd": "inspect", "token": to}),
    ] {
        t.same(req).await;
    }
}

/// The old pager's answer to `req` by name, as the way by name sent it.
fn paged_by_name(spec: &Request, req: &Json, tree: Json) -> Vec<u8> {
    match page(spec, req, tree) {
        Ok(v) => encode_reply(spec, Ok(&v)),
        Err((st, why, item)) => error_reply_with(st, &why, &item),
    }
}

/// A reply the handler cut itself (`precut`) is paged as the old pager
/// paged one that said `_page_from` and `_page_total`: in every page of
/// made-up answers, of items of every size up to one too large.
#[test]
fn a_reply_cut_by_its_handler_pages_as_it_did() {
    let node = |i: usize, size: usize| NodeBrief {
        bytes: i as u64,
        children: 0,
        created: Some(7),
        created_in: [1; 32],
        creator: [2; 32],
        delete_conflict: false,
        deleted: i % 2 == 0,
        fields: vec![vec![1, 2, 3]],
        id: [i as u8; 16],
        kind: typed::Kind::Number(3),
        name: "n".repeat(size),
        parent: [0; 16],
        position: (i % 3 != 0).then_some(i as u64),
    };
    let as_tree = |n: &NodeBrief| {
        json!({"bytes": n.bytes, "children": n.children, "created": n.created,
            "created_in": hex::encode(n.created_in), "creator": hex::encode(n.creator),
            "delete_conflict": n.delete_conflict, "deleted": n.deleted, "fields": n.fields,
            "id": hex::encode(n.id), "kind": 3, "name": n.name, "parent": hex::encode(n.parent),
            "position": n.position})
    };
    let spec = InspectNodesArgs::REQUEST;
    let mut seed = 7u64;
    let mut next = |n: u64| {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (seed >> 33) % n
    };
    let mut cases = 0;
    for round in 0..400 {
        let len = next(12) as usize;
        let total = len + next(6) as usize;
        let after = next(8);
        let limit = [None, Some(0), Some(1), Some(2), Some(5)][next(5) as usize];
        // now and then an item near or past what a message holds
        let sizes: Vec<usize> = (0..len)
            .map(|_| match next(10) {
                0 => 262_000 + next(300) as usize,
                1 => 90_000,
                _ => next(40) as usize,
            })
            .collect();
        let nodes: Vec<NodeBrief> = sizes.iter().enumerate().map(|(i, s)| node(i, *s)).collect();
        let from = after;
        let mut req = json!({"cmd": "inspect-nodes"});
        if round % 3 != 0 {
            req["after"] = json!(after);
        }
        if let Some(l) = limit {
            req["limit"] = json!(l);
        }
        let given_after = req.get("after").map(|_| after);
        let from = if given_after.is_some() { from } else { 0 };
        let tree = json!({"total": total, PAGE_FROM: from, PAGE_TOTAL: total,
            "nodes": nodes.iter().map(as_tree).collect::<Vec<_>>()});
        let old = paged_by_name(spec, &req, tree);
        let args = InspectNodesArgs {
            token: None,
            space: None,
            kind: None,
            parent: None,
            after: given_after,
            limit,
        };
        let new = args.reply_bytes(typed::Precut {
            reply: InspectNodesReply::new(nodes, total as u64, false),
            from,
            total: total as u64,
        });
        assert_eq!(
            old,
            new,
            "round {round}: {req}\n by name {}\n typed   {}",
            render_reply(spec, &old),
            render_reply(spec, &new)
        );
        cases += 1;
    }
    assert_eq!(cases, 400);
}

/// An item too large alone in a reply paged through several lists in turn
/// is named by its id, where its list's records have one, as the old pager
/// named it; and a list without ids names none.
#[test]
fn an_item_too_large_among_several_lists_is_named_by_its_id() {
    let big = "z".repeat(300_000);
    let space = |n: u8, label: &str| {
        let mut s = InspectSpace::new(false, 1, false, [n; 32], true, 0, 2);
        s.label = Some(label.to_owned());
        s
    };
    let other = |n: u8, name: &str| OtherLog {
        bytes: 1,
        entries: 2,
        id: [n; 32],
        name: Some(name.to_owned()),
    };
    let tree_space = |s: &InspectSpace| {
        json!({"account": s.account, "bytes": s.bytes, "files": s.files, "id": hex::encode(s.id),
            "opened": s.opened, "pending": s.pending, "sealed": s.sealed, "label": s.label})
    };
    let tree_other = |o: &OtherLog| json!({"bytes": o.bytes, "entries": o.entries, "id": hex::encode(o.id), "name": o.name});
    let spec = InspectArgs::REQUEST;
    for (others, spaces) in [
        (vec![other(1, "a")], vec![space(2, "b"), space(3, &big)]),
        (vec![other(1, &big)], vec![space(2, "b")]),
        (vec![other(1, "a"), other(4, "c")], vec![space(5, &big)]),
    ] {
        for after in [None, Some(1), Some(2)] {
            let mut req = json!({"cmd": "inspect"});
            if let Some(a) = after {
                req["after"] = json!(a);
            }
            let tree = json!({
                "device": {"key": hex::encode([9u8; 32]), "link_x25519": hex::encode([8u8; 32])},
                "others": others.iter().map(tree_other).collect::<Vec<_>>(),
                "spaces": spaces.iter().map(tree_space).collect::<Vec<_>>(),
                "store": {"bytes": 1, "objects": 2},
                "version": "x",
            });
            let old = paged_by_name(spec, &req, tree);
            let reply = InspectReply::new(
                InspectDevice {
                    key: [9; 32],
                    link_x25519: [8; 32],
                    name: None,
                },
                others.clone(),
                spaces.clone(),
                StoreShown {
                    bytes: 1,
                    objects: 2,
                },
                "x".into(),
                false,
            );
            let args = InspectArgs {
                token: None,
                after,
                limit: None,
            };
            let new = args.reply_bytes(reply);
            assert_eq!(old, new, "{req}: {}", render_reply(spec, &new));
        }
    }
    // a node's history names nothing: its records have no id
    let spec = InspectNodeArgs::REQUEST;
    let hist = |n: u8| NodeHistory {
        accepted: true,
        author: [n; 32],
        bytes: 1,
        entry: [n; 32],
        index: 0,
        op: Some(1),
        time: None,
        valid: true,
    };
    let mut reply = InspectNodeReply::new(false);
    reply.history = Some(vec![hist(1)]);
    reply.name = Some(big.clone());
    reply.values = Some(vec![]);
    let tree = json!({"history": [{"accepted": true, "author": hex::encode([1u8; 32]),
        "bytes": 1, "entry": hex::encode([1u8; 32]), "index": 0, "op": 1, "valid": true}],
        "name": big, "values": []});
    let old = paged_by_name(spec, &json!({}), tree);
    let new = InspectNodeArgs::new().reply_bytes(reply);
    assert_eq!(old, new, "{}", render_reply(spec, &new));
}

/// An epoch with entries waiting to be opened: an old oddity, kept to the
/// byte (DEVIATIONS.md). By name it said so in a field with no number, so
/// the reply was this build's mistake: in a debug build the request fails,
/// naming the field; and the old pager counted the epoch as no bytes.
#[test]
fn an_epoch_with_entries_waiting_is_the_mistake_it_was() {
    let spec = InspectSpaceArgs::REQUEST;
    let epoch = |n: u8, pending: Option<u64>| EpochShown {
        epoch: InspectEpoch::new(3, true, [n; 16]),
        pending,
    };
    let tree_epoch = |e: &EpochShown| {
        let mut t = json!({"entries": 3, "held": true, "id": hex::encode(e.id)});
        if let Some(p) = e.pending {
            t["pending"] = json!(p);
        }
        t
    };
    for epochs in [
        vec![epoch(1, None), epoch(2, Some(4))],
        vec![epoch(1, Some(1))],
        vec![epoch(1, None)],
    ] {
        for limit in [None, Some(1)] {
            let mut req = json!({"cmd": "inspect-space"});
            if let Some(l) = limit {
                req["limit"] = json!(l);
            }
            let tree = json!({"account": false, "bytes": 1, "files": false,
                "id": hex::encode([7u8; 32]), "opened": true, "pending": 1, "sealed": 2,
                "epochs": epochs.iter().map(tree_epoch).collect::<Vec<_>>(),
                "heads": [hex::encode([5u8; 32])]});
            let old = paged_by_name(spec, &req, tree);
            let mut reply = InspectSpaceReply::new(false, 1, false, [7; 32], true, 1, 2, false);
            reply.epochs = Some(epochs.clone());
            reply.heads = Some(vec![[5; 32]]);
            let args = InspectSpaceArgs {
                token: None,
                space: None,
                value_bytes: None,
                items: None,
                after: None,
                limit,
            };
            let new = args.reply_bytes(reply);
            assert_eq!(old, new, "{req}: {}", render_reply(spec, &new));
        }
    }
}
