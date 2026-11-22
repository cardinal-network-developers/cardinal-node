use super::*;
use std::collections::HashSet;

fn check_fields(fields: &[Field], first: u64, at: &str, seen: &mut HashSet<&'static str>) {
    let mut numbers = HashSet::new();
    let mut names = HashSet::new();
    for f in fields {
        assert!(
            f.n >= first,
            "{at}.{} is numbered {}, below {first}",
            f.name,
            f.n
        );
        assert!(numbers.insert(f.n), "{at} gives {} twice", f.n);
        // a name no longer used may be given again, to a field in use
        if !matches!(f.ty, Ty::Gone(_)) {
            assert!(names.insert(f.name), "{at} names {} twice", f.name);
        }
        check_ty(&f.ty, seen);
    }
}

fn check_ty(ty: &Ty, seen: &mut HashSet<&'static str>) {
    match ty {
        Ty::List(t) | Ty::Gone(t) => check_ty(t, seen),
        Ty::Rec(r) | Ty::Recs(r) if seen.insert(r.name) => check_fields(r.fields, 1, r.name, seen),
        _ => {}
    }
}

#[test]
fn every_number_is_given_once() {
    let mut numbers = HashSet::new();
    let mut names = HashSet::new();
    let mut seen = HashSet::new();
    for r in REQUESTS {
        assert!(r.n > 0, "{} has number 0", r.name);
        assert!(numbers.insert(r.n), "request {} is numbered twice", r.n);
        assert!(names.insert(r.name), "request {} is named twice", r.name);
        check_fields(r.args, 1, r.name, &mut seen);
        check_fields(r.reply, 2, r.name, &mut seen);
    }
    for t in [EVENTS, FRAMES] {
        for e in t {
            check_fields(e.args, 1, e.name, &mut seen);
        }
    }
    // what the program says, and what an error says, are numbered as a
    // reply's fields are
    for r in PROGRAM {
        assert!(
            r.args.is_empty(),
            "{} is an option, with nothing to it",
            r.name
        );
        check_fields(r.reply, 2, r.name, &mut seen);
    }
    check_fields(ERROR_FIELDS, 2, "an error", &mut seen);
    // record names are unique too
    let mut by_name = std::collections::HashMap::new();
    fn walk(ty: &Ty, by_name: &mut std::collections::HashMap<&'static str, *const Rec>) {
        match ty {
            Ty::List(t) | Ty::Gone(t) => walk(t, by_name),
            Ty::Rec(r) | Ty::Recs(r) => {
                let p = *r as *const Rec;
                if let Some(q) = by_name.insert(r.name, p) {
                    assert_eq!(q, p, "two records are called {}", r.name);
                    return;
                }
                for f in r.fields {
                    walk(&f.ty, by_name);
                }
            }
            _ => {}
        }
    }
    for r in REQUESTS.iter().chain(PROGRAM) {
        for f in r.args.iter().chain(r.reply) {
            walk(&f.ty, &mut by_name);
        }
    }
}

#[test]
fn a_request_goes_by_number_and_comes_back_by_name() {
    let req =
        json!({"cmd": "say", "who": "Ana", "text": "hi", "attach": ["/a", "/b"], "reply_to": null});
    let (spec, msg) = encode_request(&req).unwrap();
    assert_eq!(spec.name, "say");
    let r = Record::decode(&msg).unwrap();
    assert_eq!(r.uint(0).unwrap(), 35);
    assert_eq!(r.text(1).unwrap(), "Ana");
    assert_eq!(r.text(2).unwrap(), "hi");
    assert!(r.get(3).is_none(), "nothing for null");
    assert_eq!(
        render_request(&msg),
        r#"{request: say, who: "Ana", text: "hi", attach: ["/a", "/b"]}"#
    );
    let (back, named) = decode_request(&msg).unwrap();
    assert_eq!(back.n, 35);
    assert_eq!(
        named,
        json!({"cmd": "say", "who": "Ana", "text": "hi", "attach": ["/a", "/b"]})
    );
}

/// A ref given as bytes is an id, and never a name or the start of one:
/// the handlers tell it from text, which they read as a person types it.
#[test]
fn a_reference_may_be_bytes_and_is_then_an_id_alone() {
    let msg = Record::new()
        .with(0, 45u64)
        .with(1, vec![0xabu8, 0xcd])
        .encode();
    let (_, named) = decode_request(&msg).unwrap();
    let id = named["id"].as_str().unwrap();
    assert_eq!(reference(id), Ref::Id("abcd"));
    assert_eq!(id_hex(id), "abcd");
    // the same as text is typed
    let typed = Record::new().with(0, 45u64).with(1, "abcd").encode();
    let (_, named) = decode_request(&typed).unwrap();
    assert_eq!(reference(named["id"].as_str().unwrap()), Ref::Typed("abcd"));
    // and nothing typed passes for bytes
    let sly = Record::new().with(0, 45u64).with(1, "\u{0}abcd").encode();
    assert_eq!(decode_request(&sly).unwrap_err().status, status::MALFORMED);
    // it goes back out as bytes, as a client sends it
    let (_, back) = encode_request(&json!({"cmd": "cancel-invitation", "id": id})).unwrap();
    assert_eq!(back, msg);
    // whole, or the first eight bytes the service gives in its place
    let key = [0x11u8; 32];
    let whole = format!("{EXACT}{}", hex::encode(key));
    let short = format!("{EXACT}{}", hex::encode(&key[..8]));
    let start = format!("{EXACT}{}", hex::encode(&key[..4]));
    assert!(reference(&whole).is_id(&key));
    assert!(reference(&short).is_id(&key));
    assert!(
        !reference(&start).is_id(&key),
        "the start of an id is no id"
    );
    assert!(
        !reference(&hex::encode(key)).is_id(&key),
        "text is not an id here"
    );
}

#[test]
fn what_is_not_one_record_or_unknown_is_refused() {
    let e = decode_request(&[0x00]).unwrap_err();
    assert_eq!(e.status, status::MALFORMED);
    let e = decode_request(&Record::new().with(0, 9999u64).encode()).unwrap_err();
    assert_eq!(e.status, status::UNKNOWN);
    let wrong = Record::new().with(0, 35u64).with(1, 7u64).encode();
    assert_eq!(
        decode_request(&wrong).unwrap_err().status,
        status::MALFORMED
    );
    // a key this build does not know is left out, as encoding.md says
    let later = Record::new().with(0, 1u64).with(99, "new").encode();
    assert_eq!(decode_request(&later).unwrap().1, json!({"cmd": "hello"}));
    assert!(encode_request(&json!({"cmd": "say", "nonsense": 1})).is_err());
    assert!(encode_request(&json!({"cmd": "no-such-thing"})).is_err());
}

#[test]
fn replies_carry_status_why_and_fields() {
    let spec = by_name("contacts").unwrap();
    let v = json!({"contacts": [{"identity": "0011223344556677", "name": "Ana", "trusted": true}]});
    let msg = encode_reply(spec, Ok(&v));
    let r = Record::decode(&msg).unwrap();
    assert_eq!(r.uint(0).unwrap(), 0);
    let c = r.record_list(2).unwrap();
    assert_eq!(
        c[0].bytes(3).unwrap(),
        [0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]
    );
    assert_eq!(c[0].uint(14).unwrap(), 1);
    let back = decode_reply(spec, &msg).unwrap();
    assert_eq!(back["ok"], true);
    assert_eq!(back["contacts"][0]["name"], "Ana");
    assert_eq!(back["contacts"][0]["identity"], "0011223344556677");
    assert_eq!(
        render_reply(spec, &msg),
        r#"{status: ok, contacts: [{identity: h'0011223344556677', name: "Ana", trusted: 1}]}"#
    );

    let msg = encode_reply(spec, Err((status::NEEDS_WORDS, "say the words")));
    let back = decode_reply(spec, &msg).unwrap();
    assert_eq!(back["ok"], false);
    assert_eq!(back["error"], "say the words");
    assert_eq!(back["needs_words"], true);
    assert_eq!(
        render_reply(spec, &msg),
        r#"{status: needs words, why: "say the words"}"#
    );
}

#[test]
fn a_reply_field_without_a_number_fails_where_tests_run() {
    let spec = by_name("hello").unwrap();
    let msg = encode_reply(spec, Ok(&json!({"api": 2, "surprise": true})));
    let r = Record::decode(&msg).unwrap();
    assert_eq!(r.uint(0).unwrap(), status::FAILED);
}

#[test]
fn events_and_frames() {
    let e = event_message(7);
    assert_eq!(e, Record::new().with(0, 1u64).with(1, 7u64).encode());
    assert_eq!(
        decode_event(&e).unwrap().unwrap(),
        json!({"event": "changed", "seq": 7})
    );
    let a = frame_message(&json!({"audio": "0102", "from": "ff"})).unwrap();
    assert_eq!(
        a,
        Record::new()
            .with(0, 1u64)
            .with(1, vec![1u8, 2])
            .with(3, vec![0xffu8])
            .encode()
    );
    assert_eq!(
        decode_frame(&a).unwrap().unwrap(),
        json!({"audio": "0102", "from": "ff"})
    );
    let f = frame_message(&json!({"frame": "03", "format": "aa"})).unwrap();
    assert_eq!(
        f,
        Record::new()
            .with(0, 2u64)
            .with(1, vec![3u8])
            .with(2, vec![0xaau8])
            .encode()
    );
    let v = frame_message(&json!({"width": 9, "height": 16})).unwrap();
    assert_eq!(
        v,
        Record::new()
            .with(0, 3u64)
            .with(1, 9u64)
            .with(2, 16u64)
            .encode()
    );
    assert_eq!(
        decode_frame(&v).unwrap().unwrap(),
        json!({"width": 9, "height": 16})
    );
}

#[test]
fn a_request_no_longer_answered_keeps_its_number() {
    let gone = by_number(165).unwrap();
    assert!(gone.gone && gone.name == "recover-keep-succession");
    assert!(by_name("recover-keep-succession").is_none());
    assert!(encode_request(&json!({"cmd": "recover-keep-succession"})).is_err());
    let e = decode_request(&Record::new().with(0, 165u64).encode()).unwrap_err();
    assert_eq!(e.status, status::UNKNOWN);
    // a field no longer used is neither sent nor read
    let spec = by_name("recover").unwrap();
    let msg = encode_reply(
        spec,
        Ok(&json!({"successions": [{"id": "x", "space": "y"}]})),
    );
    assert_eq!(
        Record::decode(&msg).unwrap().uint(0).unwrap(),
        status::FAILED
    );
    let msg = Record::new()
        .with(0, 0u64)
        .with(15, Value::List(vec![]))
        .with(17, true)
        .encode();
    assert_eq!(
        decode_reply(spec, &msg).unwrap(),
        json!({"ok": true, "under_way": true})
    );
}

#[test]
fn a_paged_request_has_its_cursor_and_says_if_there_is_more() {
    let ty = |fields: &[Field], name: &str| {
        fields
            .iter()
            .find(|f| f.name == name)
            .map(|f| ty_text(&f.ty))
    };
    for r in REQUESTS.iter().filter(|r| r.page != Page::Whole) {
        assert_eq!(ty(r.args, "limit").as_deref(), Some("uint"), "{}", r.name);
        assert_eq!(ty(r.reply, "more").as_deref(), Some("bool"), "{}", r.name);
        match r.page {
            Page::After => {
                assert_eq!(ty(r.args, "after").as_deref(), Some("uint"), "{}", r.name);
                assert_eq!(ty(r.reply, "next").as_deref(), Some("uint"), "{}", r.name);
            }
            Page::Before { list } => {
                assert_eq!(ty(r.args, "before").as_deref(), Some("ref"), "{}", r.name);
                assert_eq!(ty(r.reply, "next").as_deref(), Some("bytes"), "{}", r.name);
                let f = r.reply.iter().find(|f| f.name == list).unwrap();
                let Ty::Recs(rec) = f.ty else {
                    panic!("{} pages {list}, which is not a list of records", r.name)
                };
                assert_eq!(ty(rec.fields, "id").as_deref(), Some("bytes"), "{}", r.name);
            }
            Page::Whole => unreachable!(),
        }
    }
    // what grows with what the person holds comes in pages
    for name in [
        "status",
        "devices",
        "contacts",
        "contact-status",
        "conversations",
        "messages",
        "groups",
        "group-members",
        "files",
        "peer-list",
        "inspect",
        "inspect-identity",
        "inspect-space",
        "inspect-entries",
        "inspect-entry",
        "inspect-nodes",
        "inspect-node",
        "debug-tree",
    ] {
        assert_ne!(by_name(name).unwrap().page, Page::Whole, "{name}");
    }
}

fn texts(n: usize, len: usize) -> Vec<String> {
    (0..n).map(|i| format!("{i:0len$}")).collect()
}

#[test]
fn a_page_goes_through_each_list_in_turn() {
    let spec = by_name("groups").unwrap();
    let groups: Vec<Json> = (0..3).map(|i| json!({"name": format!("g{i}")})).collect();
    let offers: Vec<Json> = (0..2).map(|i| json!({"name": format!("o{i}")})).collect();
    let full = json!({"groups": groups, "offers": offers});
    let ask = |after: u64, limit: u64| {
        let req = json!({"cmd": "groups", "after": after, "limit": limit});
        page(spec, &req, full.clone()).unwrap()
    };
    let p = ask(0, 2);
    assert_eq!(p["groups"].as_array().unwrap().len(), 2);
    assert_eq!(p["offers"], json!([]));
    assert_eq!(
        (p["more"].clone(), p["next"].clone()),
        (json!(true), json!(2))
    );
    let p = ask(2, 2);
    assert_eq!(p["groups"][0]["name"], "g2");
    assert_eq!(p["offers"][0]["name"], "o0");
    assert_eq!(p["next"], 4);
    let p = ask(4, 2);
    assert_eq!(p["groups"], json!([]));
    assert_eq!(p["offers"][0]["name"], "o1");
    assert_eq!(p["more"], false);
    assert!(p.get("next").is_none());
    // without a limit, all that fit
    let p = page(spec, &json!({"cmd": "groups"}), full.clone()).unwrap();
    assert_eq!(p["groups"].as_array().unwrap().len(), 3);
    assert_eq!(p["more"], false);
    // a request that is not paged is left as it is
    let spec = by_name("guardians").unwrap();
    let v = json!({"names": texts(3, 4)});
    assert_eq!(page(spec, &json!({}), v.clone()).unwrap(), v);
}

#[test]
fn a_page_never_holds_more_than_a_message() {
    let spec = by_name("peer-list").unwrap();
    let peers: Vec<Json> = texts(400, 1000)
        .into_iter()
        .map(|a| json!({"addr": a}))
        .collect();
    let full = json!({"peers": peers});
    let mut after = 0u64;
    let mut seen = 0;
    loop {
        let req = json!({"cmd": "peer-list", "after": after});
        let p = page(spec, &req, full.clone()).unwrap();
        let msg = encode_reply(spec, Ok(&p));
        assert!(msg.len() <= MAX_MESSAGE, "{} bytes", msg.len());
        let n = p["peers"].as_array().unwrap().len();
        assert!(n > 0);
        assert_eq!(p["peers"][0]["addr"], format!("{seen:01000}"));
        seen += n;
        if p["more"] == false {
            break;
        }
        after = p["next"].as_u64().unwrap();
        assert_eq!(after as usize, seen);
    }
    assert_eq!(seen, 400);
    // an item larger than a message is said to be, not cut
    let big = json!({"peers": [{"addr": "x".repeat(MAX_MESSAGE)}]});
    let e = page(spec, &json!({"cmd": "peer-list"}), big).unwrap_err();
    assert_eq!(e.0, status::TOO_LARGE);
}

/// Error 4 says which item was too large, so that a client can ask for
/// what comes after it: by its place as `after` counts, and by its id
/// where it has one.
#[test]
fn an_item_too_large_is_named_so_that_it_can_be_paged_past() {
    let spec = by_name("peer-list").unwrap();
    let peers = json!({"peers": [
        {"addr": "a"}, {"addr": "x".repeat(MAX_MESSAGE)}, {"addr": "c"}
    ]});
    let p = page(spec, &json!({"limit": 1}), peers.clone()).unwrap();
    assert_eq!(p["next"], 1);
    let (st, why, item) = page(spec, &json!({"after": 1}), peers.clone()).unwrap_err();
    assert_eq!(item, json!({"at": 1, "id": null}));
    let msg = error_reply_with(st, &why, &item);
    let r = Record::decode(&msg).unwrap();
    assert_eq!(r.uint(0).unwrap(), status::TOO_LARGE);
    assert_eq!(r.uint(2).unwrap(), 1);
    assert!(r.get(3).is_none(), "a peer has no id");
    let back = decode_reply(spec, &msg).unwrap();
    assert_eq!(
        (back["ok"].clone(), back["at"].clone()),
        (json!(false), json!(1))
    );
    assert!(
        render_reply(spec, &msg).contains("at: 1"),
        "{}",
        render_reply(spec, &msg)
    );
    // and after it, the rest
    let p = page(spec, &json!({"after": 2}), peers).unwrap();
    assert_eq!(p["peers"][0]["addr"], "c");

    // a message by its id too, which `before` takes
    let spec = by_name("messages").unwrap();
    let id = hex::encode([7u8; 16]);
    let said = json!({"messages": [
        {"id": hex::encode([6u8; 16]), "text": "before it"},
        {"id": id, "text": "x".repeat(MAX_MESSAGE)},
    ]});
    let (st, why, item) = page(spec, &json!({}), said).unwrap_err();
    assert_eq!(item, json!({"at": 1, "id": id}));
    let r = Record::decode(&error_reply_with(st, &why, &item)).unwrap();
    assert_eq!(r.bytes(3).unwrap(), [7u8; 16]);
}

#[test]
fn messages_page_back_from_the_newest() {
    let spec = by_name("messages").unwrap();
    let said: Vec<Json> = (0..5u8)
        .map(|i| json!({"id": hex::encode([i; 16]), "text": format!("m{i}")}))
        .collect();
    let full = json!({"name": "Ana", "messages": said});
    let p = page(spec, &json!({"cmd": "messages", "limit": 2}), full.clone()).unwrap();
    let texts: Vec<&str> = p["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["text"].as_str().unwrap())
        .collect();
    assert_eq!(texts, ["m3", "m4"], "the newest, oldest first");
    assert_eq!(p["more"], true);
    assert_eq!(p["next"], hex::encode([3u8; 16]));
    assert_eq!(p["name"], "Ana");
    // the handler gives those before `before`; the oldest are the last page
    let before: Vec<Json> = full["messages"].as_array().unwrap()[..1].to_vec();
    let p = page(
        spec,
        &json!({"cmd": "messages", "limit": 2}),
        json!({"messages": before}),
    )
    .unwrap();
    assert_eq!(p["messages"][0]["text"], "m0");
    assert_eq!(p["more"], false);
    assert!(p.get("next").is_none());
    // on the wire, `next` is bytes
    let msg = encode_reply(spec, Ok(&page(spec, &json!({"limit": 1}), full).unwrap()));
    assert_eq!(Record::decode(&msg).unwrap().bytes(6).unwrap(), [4u8; 16]);
}

/// The tables as `apps.md` gives them: `CARDINAL_API_TABLES=<file>`
/// writes them there.
#[test]
fn tables_for_the_specification() {
    let Some(path) = std::env::var_os("CARDINAL_API_TABLES") else {
        return;
    };
    std::fs::write(path, markdown()).unwrap();
}

fn ty_text(ty: &Ty) -> String {
    match ty {
        Ty::Text => "text".into(),
        Ty::Bytes => "bytes".into(),
        Ty::Uint => "uint".into(),
        Ty::Int => "int".into(),
        Ty::Bool => "bool".into(),
        Ty::Ref => "ref".into(),
        Ty::Kind => "kind".into(),
        Ty::Scalar => "int or text".into(),
        Ty::List(t) => format!("[{}]", ty_text(t)),
        Ty::Rec(r) => format!("*{}*", r.name),
        Ty::Recs(r) => format!("[*{}*]", r.name),
        Ty::Gone(t) => format!("{} (no longer used)", ty_text(t)),
    }
}

fn fields_text(fields: &[Field]) -> String {
    let parts: Vec<String> = fields
        .iter()
        .map(|f| format!("{} `{}` {}", f.n, f.name, ty_text(&f.ty)))
        .collect();
    parts.join(", ")
}

/// The requests this implementation answers that `apps.md` does not
/// describe in words: marked in its tables.
const NODE_ONLY: &[&str] = &[
    "stop",
    "reload",
    "remove-device",
    "contacts",
    "read-markers",
    "group-role",
    "group-post-again",
    "group-moved-seen",
    "mount",
    "unmount",
    "flush",
    "conflicts",
    "history",
    "restore",
    "pin",
    "unpin",
    "retention",
    "keep-old",
    "free-space",
    "space-usage",
    "history-empty",
    "guardians",
    "guardians-set",
    "guardians-object",
    "guardians-ask",
    "guarding",
    "guarding-invite",
    "guarding-accept",
    "guarding-confirm-change",
    "guarding-never",
    "guarding-caution",
    "guarding-endorse",
    "guarding-confirm",
    "recover",
    "recover-start",
    "recover-invite",
    "recover-lost-at",
    "recover-undo",
    "recover-kept-seen",
    "recover-cancel",
    "recover-finish",
    "keep-work",
    "recovery-check",
    "recovery-sheet",
    "restore-from-host",
    "router",
    "bluetooth",
    "network",
    "host",
    "host-off",
    "peer-add",
    "peer-remove",
    "peer-list",
    "inspect-on",
    "inspect-off",
    "inspect",
    "inspect-identity",
    "inspect-space",
    "inspect-entries",
    "inspect-entry",
    "inspect-nodes",
    "inspect-node",
    "debug-tree",
    "speedtest",
];

fn markdown() -> String {
    let mut out = String::new();
    let groups: &[(u64, u64, &str)] = &[
        (1, 29, "The service, this device, and the person's devices"),
        (30, 69, "People, conversations and invitations"),
        (70, 99, "Groups"),
        (100, 119, "Calls and the clipboard"),
        (120, 149, "The one folder"),
        (150, 179, "Guardians and recovery"),
        (180, 199, "Networks, hosts and peers"),
        (200, 219, "Inspection and measuring"),
        (220, 239, "Applications"),
    ];
    for (lo, hi, title) in groups {
        out += &format!(
            "\n#### {lo}–{hi}: {title}\n\n| # | Request | Arguments | Reply |\n|---|---|---|---|\n"
        );
        for r in REQUESTS.iter().filter(|r| r.n >= *lo && r.n <= *hi) {
            let mark = if r.gone {
                " † (no longer answered)"
            } else if NODE_ONLY.contains(&r.name) {
                " †"
            } else {
                ""
            };
            out += &format!(
                "| {} | `{}`{mark} | {} | {} |\n",
                r.n,
                r.name,
                fields_text(r.args),
                fields_text(r.reply)
            );
        }
    }
    out += "\n#### What the program says\n\n| Asked | Reply |\n|---|---|\n";
    for r in PROGRAM {
        out += &format!("| `{}` | {} |\n", r.name, fields_text(r.reply));
    }
    out += &format!(
        "\n#### What an error says\n\n{}\n",
        fields_text(ERROR_FIELDS)
    );
    let mut seen: Vec<&Rec> = Vec::new();
    fn walk<'a>(ty: &'a Ty, seen: &mut Vec<&'a Rec>) {
        match ty {
            Ty::List(t) | Ty::Gone(t) => walk(t, seen),
            Ty::Rec(r) | Ty::Recs(r) if !seen.iter().any(|s| std::ptr::eq(*s, *r)) => {
                seen.push(r);
                for f in r.fields {
                    walk(&f.ty, seen);
                }
            }
            _ => {}
        }
    }
    for r in REQUESTS.iter().chain(PROGRAM) {
        for f in r.args.iter().chain(r.reply) {
            walk(&f.ty, &mut seen);
        }
    }
    seen.sort_by_key(|r| r.name);
    out += "\n#### Records\n\n| Record | Fields |\n|---|---|\n";
    for r in seen {
        out += &format!("| *{}* | {} |\n", r.name, fields_text(r.fields));
    }
    out
}
