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
        assert!(names.insert(f.name), "{at} names {} twice", f.name);
        check_ty(&f.ty, seen);
    }
}

fn check_ty(ty: &Ty, seen: &mut HashSet<&'static str>) {
    match ty {
        Ty::List(t) => check_ty(t, seen),
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
    // record names are unique too
    let mut by_name = std::collections::HashMap::new();
    fn walk(ty: &Ty, by_name: &mut std::collections::HashMap<&'static str, *const Rec>) {
        match ty {
            Ty::List(t) => walk(t, by_name),
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
    for r in REQUESTS {
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

#[test]
fn a_reference_may_be_bytes() {
    let msg = Record::new()
        .with(0, 45u64)
        .with(1, vec![0xabu8, 0xcd])
        .encode();
    let (_, named) = decode_request(&msg).unwrap();
    assert_eq!(named["id"], "abcd");
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
    "recover-keep-succession",
    "recover-lost-at",
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
    ];
    for (lo, hi, title) in groups {
        out += &format!(
            "\n#### {lo}–{hi}: {title}\n\n| # | Request | Arguments | Reply |\n|---|---|---|---|\n"
        );
        for r in REQUESTS.iter().filter(|r| r.n >= *lo && r.n <= *hi) {
            let mark = if NODE_ONLY.contains(&r.name) {
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
    let mut seen: Vec<&Rec> = Vec::new();
    fn walk<'a>(ty: &'a Ty, seen: &mut Vec<&'a Rec>) {
        match ty {
            Ty::List(t) => walk(t, seen),
            Ty::Rec(r) | Ty::Recs(r) if !seen.iter().any(|s| std::ptr::eq(*s, *r)) => {
                seen.push(r);
                for f in r.fields {
                    walk(&f.ty, seen);
                }
            }
            _ => {}
        }
    }
    for r in REQUESTS {
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
