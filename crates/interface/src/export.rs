//! The interface exported for clients in other languages: every request,
//! record, event and frame of [`crate::table`], as one record in the base
//! encoding, `interface.bin` beside this crate's `Cargo.toml`, and its text
//! rendering with the export's own names, `interface.txt` (one item to a
//! line, for people and for diffs). Both are made from the declarations
//! here, and checked in; [`the_export_is_up_to_date`] fails when they are
//! not what the declarations give, and writes them anew with
//! `CARDINAL_INTERFACE_EXPORT=write cargo test -p cardinal-interface
//! --lib export`.
//!
//! A generator reads `interface.bin` with its language's own reader of the
//! base encoding (every client has one: it is what the local interface
//! speaks), and nothing else. What it holds, by the records below, their
//! fields numbered in the order of their names as the tables' are:
//!
//! - *interface*: `version` (this interface's, as `hello` answers it), and
//!   lists of every `request` by number, the `events` of `watch`, the
//!   `frames` of `call-media`, what the service's `program` says (as
//!   requests: each an option, with only a reply), what an `error` says
//!   besides its status and why (fields), and every `record` the others
//!   hold, by name; every status a reply's key 0 may be, `statuses`, each
//!   its number `n` and `name`; the `layout` of a message, the keys of its
//!   parts (a request's `number` and the key its arguments are numbered
//!   from, `arguments_from`; a reply's `status`, an error's `why`, and
//!   `fields_from`; a stream's message's `kind` and `stream_fields_from`);
//!   the largest message either way, `max_message`, in bytes; the
//!   oldest service a client works with, `min_service` (`hello`'s
//!   `version`, compared as `new_enough` in the crate's lib.rs says); key 1
//!   of an error, `why` (a field: text, always there, so that an error's
//!   reply without it, or with any of its fields of another type, is
//!   unreadable, as a reply that was done is); what a refusal whose `why`
//!   is empty is shown as when its status has no name in `statuses`,
//!   `unnamed_status` (one that has a name is shown by it); and the
//!   version of these records themselves, `schema`, which rises when a
//!   generator must change. Their numbers are only ever added, as the
//!   interface's are; `export-schema.txt` holds every one given, and a test
//!   fails when one is moved, retyped or given again.
//! - *request*: its number `n`, `name`, `args` and `reply` (fields; a
//!   reply's numbered from 2, after the status, 0, and why, 1, as
//!   `apps.md` says), `page` (`whole`, `after`: by position, through the
//!   `lists` in turn, the arguments' `after` and `limit` and the reply's
//!   `more` and `next`; or `before`: back from the newest of its one list,
//!   `before` an id, `next` the oldest given), the `lists` paged, each
//!   with the `id` field of its records that error 4 and `before` name it
//!   by, whether it is a `stream` (the connection carries one after it),
//!   whether it is `gone` (its number no longer answered), whether it
//!   is the node's `own` (not in `apps.md`), and whether it `reads`:
//!   answering it changes nothing, `unless` one of the arguments named
//!   there is given (a request that writes, a stream's, or one no longer
//!   answered does not); of a paged request, `one_page`, the arguments that
//!   ask for one page when any is given (its cursor and `limit`), and
//!   otherwise a client asks page after page. Asking page after page, a
//!   page that adds no item ends the asking; going on past an item too
//!   large for a message, error 4 must name one at or after where the page
//!   began (`at` no less than `after`, or an `id` other than `before`), or
//!   the asking ends with that error; and a listing whose every item is too
//!   large is answered empty, its items left out, as a page past the last
//!   one is.
//! - *message* (an event or a frame): its number `n` (key 0 of the
//!   message), `name` and `fields`, numbered from 1.
//! - *field*: its number `n`, `name`, `type`, whether it is `optional` (it
//!   may be left out, and a reader takes its absence as none; a field not
//!   optional is always sent, and a message without it is unreadable) and
//!   whether it is `gone` (its number no longer used: never sent, passed
//!   over when read; `type` is what it held); of text whose values are a
//!   closed set its declaration names, those values, `known` (it is still
//!   text on the wire, and a client that meets another shows it as text).
//! - *type*: what it `is` (`text`, `bytes`, `uint`, `int`, `bool`, `ref`,
//!   `kind`, `int or text`, `list` or `record`); of `bytes` of one length
//!   only, its `size`; of a list, its `item`; of a record, the `record`'s
//!   name.
//! - *record*: its `name` and `fields`, numbered from 1.
//!
//! The base encoding was chosen over the tables' markdown: the markdown
//! has no place for whether a field is optional, how a request pages or
//! that it is a stream, or the frames and events, and adding marks to its
//! cells would give each generator a grammar of nested types to parse; the
//! base encoding has every client's reader already, with nothing to guess.

use crate::table::{Field, Page, Request, Ty};
use crate::typed::{Ask, Wire};
use crate::{each_request, typed};
use crate::{key, status, MAX_MESSAGE, MIN_SERVICE};
use crate::{ERROR_FIELDS, EVENTS, FRAMES, NODE_ONLY, PROGRAM, REQUESTS, VERSION};

typed!(
    /// A field's type.
    TYPE "type" TypeOf {
        1 is: String,
        2 item: Option<Box<TypeOf>> as {TYPE},
        3 record: Option<String>,
        4 size: Option<u64>,
    }
);
typed!(FIELD "field" FieldOf {
    1 gone: bool,
    2 n: u64,
    3 name: String,
    4 optional: bool,
    5 r#type: TypeOf,
    6 known: Option<Vec<String>>,
});
typed!(LIST "list" ListOf {
    1 id: Option<String>,
    2 name: String,
});
typed!(REQUEST "request" RequestOf {
    1 args: Vec<FieldOf>,
    2 gone: bool,
    3 lists: Vec<ListOf>,
    4 n: u64,
    5 name: String,
    6 own: bool,
    7 page: String,
    8 reply: Vec<FieldOf>,
    9 stream: bool,
    10 reads: bool,
    11 unless: Option<Vec<String>>,
    12 one_page: Option<Vec<String>>,
});
typed!(MESSAGE "message" MessageOf {
    1 fields: Vec<FieldOf>,
    2 n: u64,
    3 name: String,
});
typed!(RECORD "record" RecordOf {
    1 fields: Vec<FieldOf>,
    2 name: String,
});
typed!(STATUS "status" StatusOf {
    1 n: u64,
    2 name: String,
});
typed!(LAYOUT "layout" LayoutOf {
    1 arguments_from: u64,
    2 fields_from: u64,
    3 kind: u64,
    4 number: u64,
    5 status: u64,
    6 stream_fields_from: u64,
    7 why: u64,
});
typed!(INTERFACE "interface" Interface {
    1 error: Vec<FieldOf>,
    2 events: Vec<MessageOf>,
    3 frames: Vec<MessageOf>,
    4 program: Vec<RequestOf>,
    5 records: Vec<RecordOf>,
    6 requests: Vec<RequestOf>,
    7 version: u64,
    8 layout: LayoutOf,
    9 max_message: u64,
    10 statuses: Vec<StatusOf>,
    11 schema: u64,
    12 min_service: String,
    13 unnamed_status: String,
    14 why: FieldOf,
});

/// The version of the export's own records, above: it rises when a
/// generator that reads them must change. Their field numbers are only
/// added, never moved, retyped or given to another field
/// ([`the_exports_own_numbers_are_only_added`], against `export-schema.txt`),
/// so a field added is no change a generator must make.
const SCHEMA: u64 = 1;

fn type_of(ty: &Ty) -> TypeOf {
    let is = |s: &str| crate::new!(TypeOf { is: s.to_owned() });
    match ty {
        Ty::Text => is("text"),
        Ty::Bytes => is("bytes"),
        Ty::BytesOf(n) => TypeOf {
            size: Some(*n as u64),
            ..is("bytes")
        },
        Ty::Uint => is("uint"),
        Ty::Int => is("int"),
        Ty::Bool => is("bool"),
        Ty::Ref => is("ref"),
        Ty::Kind => is("kind"),
        Ty::Scalar => is("int or text"),
        Ty::List(t) => TypeOf {
            item: Some(Box::new(type_of(t))),
            ..is("list")
        },
        Ty::Rec(r) => TypeOf {
            record: Some(r.name.to_owned()),
            ..is("record")
        },
        Ty::Recs(r) => TypeOf {
            item: Some(Box::new(type_of(&Ty::Rec(r)))),
            ..is("list")
        },
        Ty::Gone(_) => unreachable!("a field no longer used is said by the field"),
    }
}

fn fields_of(fields: &[Field]) -> Vec<FieldOf> {
    fields
        .iter()
        .map(|f| {
            let (gone, ty) = match &f.ty {
                Ty::Gone(t) => (true, *t),
                t => (false, t),
            };
            FieldOf {
                known: (!f.known.is_empty())
                    .then(|| f.known.iter().map(|k| (*k).to_owned()).collect()),
                ..crate::new!(FieldOf {
                    gone,
                    n: f.n,
                    name: f.name.to_owned(),
                    optional: f.optional,
                    r#type: type_of(ty)
                })
            }
        })
        .collect()
}

/// What a request's declaration says beyond its row: how it pages, and
/// whether it changes nothing (unless some arguments are given).
type Declared = (
    &'static [(&'static str, Option<&'static str>)],
    bool,
    &'static [&'static str],
    &'static [&'static str],
);

/// [`Declared`], of each request, by its number.
macro_rules! declared {
    ($($how:ident $x:ident,)*) => {
        fn declared_of(n: u64) -> Declared {
            $(if let Some(l) = declared!(@one n $how $x) {
                return l;
            })*
            (&[], false, &[], &[])
        }
    };
    (@one $n:ident gone $row:ident) => { None };
    (@one $n:ident $how:ident $args:ident) => {
        (<crate::$args as Ask>::REQUEST.n == $n).then_some((
            <crate::$args as Ask>::LISTS,
            <crate::$args as Ask>::READS,
            <crate::$args as Ask>::UNLESS,
            <crate::$args as Ask>::ONE_PAGE,
        ))
    };
}
each_request!(declared);

fn request_of(r: &Request, own: bool, (lists, reads, unless, one_page): Declared) -> RequestOf {
    let page = match r.page {
        Page::Whole => "whole",
        Page::After => "after",
        Page::Before { .. } => "before",
    };
    let lists = lists
        .iter()
        .map(|(name, id)| {
            crate::new!(ListOf {
                name: (*name).to_owned()
            })
            .with_id(*id)
        })
        .collect();
    let names = |n: &[&str]| (!n.is_empty()).then(|| n.iter().map(|u| (*u).to_owned()).collect());
    RequestOf {
        unless: names(unless),
        one_page: names(one_page),
        ..crate::new!(RequestOf {
            args: fields_of(r.args),
            gone: r.gone,
            lists,
            n: r.n,
            name: r.name.to_owned(),
            own,
            page: page.to_owned(),
            reply: fields_of(r.reply),
            stream: r.stream,
            reads
        })
    }
}

impl ListOf {
    fn with_id(self, id: Option<&str>) -> Self {
        ListOf {
            id: id.map(str::to_owned),
            ..self
        }
    }
}

fn message_of(m: &Request) -> MessageOf {
    crate::new!(MessageOf {
        fields: fields_of(m.args),
        n: m.n,
        name: m.name.to_owned()
    })
}

/// Every record the tables hold, by name.
fn records() -> Vec<RecordOf> {
    let mut seen: Vec<&'static crate::table::Rec> = Vec::new();
    fn walk(ty: &'static Ty, seen: &mut Vec<&'static crate::table::Rec>) {
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
    let every = REQUESTS.iter().chain(PROGRAM).chain(EVENTS).chain(FRAMES);
    for r in every {
        for f in r.args.iter().chain(r.reply) {
            walk(&f.ty, &mut seen);
        }
    }
    for f in ERROR_FIELDS {
        walk(&f.ty, &mut seen);
    }
    seen.sort_by_key(|r| r.name);
    seen.iter()
        .map(|r| {
            crate::new!(RecordOf {
                fields: fields_of(r.fields),
                name: r.name.to_owned()
            })
        })
        .collect()
}

/// The export, from the declarations.
fn interface() -> Interface {
    crate::new!(Interface {
        error: fields_of(ERROR_FIELDS),
        events: EVENTS.iter().map(message_of).collect(),
        frames: FRAMES.iter().map(message_of).collect(),
        // the program's options are numbered apart from the requests,
        // and declare nothing beyond their rows
        program: PROGRAM
            .iter()
            .map(|r| request_of(r, false, (&[], false, &[], &[])))
            .collect(),
        records: records(),
        requests: REQUESTS
            .iter()
            .map(|r| request_of(r, NODE_ONLY.contains(&r.name), declared_of(r.n)))
            .collect(),
        version: VERSION,
        layout: crate::new!(LayoutOf {
            arguments_from: key::FIRST_ARGUMENT,
            fields_from: key::FIRST_REPLY_FIELD,
            kind: key::KIND,
            number: key::NUMBER,
            status: key::STATUS,
            stream_fields_from: key::FIRST_STREAM_FIELD,
            why: key::WHY,
        }),
        max_message: MAX_MESSAGE as u64,
        statuses: status::ALL
            .iter()
            .map(|n| crate::new!(StatusOf {
                n: *n,
                name: status::name(*n)
                    .expect("every status has its name")
                    .to_owned(),
            }))
            .collect(),
        schema: SCHEMA,
        min_service: MIN_SERVICE.to_owned(),
        unnamed_status: status::UNNAMED.to_owned(),
        why: fields_of(std::slice::from_ref(&crate::typed::WHY_ROW))
            .pop()
            .expect("why's row"),
    })
}

/// `interface.bin`: the export as one record.
fn binary(i: &Interface) -> Vec<u8> {
    let mut out = Vec::new();
    i.encode_into(&mut out);
    out
}

/// `interface.txt`: the export's text rendering, with its names, one item
/// of each list to a line.
fn text(bin: &[u8]) -> String {
    let r = cardinal_encoding::Record::decode(bin).expect("the export is one record");
    let mut out = String::from("{\n");
    for (k, v) in r.iter() {
        let f = crate::field_by_number(INTERFACE.fields, *k).expect("the export's own field");
        match (&f.ty, v) {
            (Ty::List(item), cardinal_encoding::Value::List(items)) => {
                out += &format!("  {}: [\n", f.name);
                for x in items {
                    out += &format!("    {},\n", crate::render_value(item, x));
                }
                out += "  ],\n";
            }
            (Ty::Recs(rec), cardinal_encoding::Value::List(items)) => {
                out += &format!("  {}: [\n", f.name);
                for x in items {
                    out += &format!("    {},\n", crate::render_value(&Ty::Rec(rec), x));
                }
                out += "  ],\n";
            }
            (ty, v) => out += &format!("  {}: {},\n", f.name, crate::render_value(ty, v)),
        }
    }
    out += "}\n";
    out
}

fn path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(name)
}

/// `interface.bin` and `interface.txt` are what the declarations give:
/// `CARDINAL_INTERFACE_EXPORT=write` writes them so.
#[test]
fn the_export_is_up_to_date() {
    let bin = binary(&interface());
    let txt = text(&bin);
    if std::env::var("CARDINAL_INTERFACE_EXPORT").as_deref() == Ok("write") {
        std::fs::write(path("interface.bin"), &bin).unwrap();
        std::fs::write(path("interface.txt"), &txt).unwrap();
    }
    let stale = "is not what the declarations give: write it anew with \
                 CARDINAL_INTERFACE_EXPORT=write cargo test -p cardinal-interface --lib export";
    assert!(
        std::fs::read(path("interface.bin")).is_ok_and(|b| b == bin),
        "interface.bin {stale}"
    );
    assert!(
        std::fs::read_to_string(path("interface.txt")).is_ok_and(|t| t == txt),
        "interface.txt {stale}"
    );
}

/// The export reads back as itself, in the canonical encoding, and holds
/// what a generator needs of the requests the tables have.
#[test]
fn the_export_reads_back_and_holds_every_request() {
    let bin = binary(&interface());
    let back: Interface = crate::typed::record_take(
        cardinal_encoding::decode(&bin).unwrap(),
        &crate::typed::At::Top("export"),
    )
    .unwrap();
    assert_eq!(back, interface());
    assert_eq!(back.requests.len(), REQUESTS.len());
    let by = |name: &str| back.requests.iter().find(|r| r.name == name).unwrap();
    let messages = by("messages");
    assert_eq!(messages.page, "before");
    assert_eq!(
        messages.lists,
        [crate::new!(ListOf {
            name: "messages".into()
        })
        .with_id(Some("id"))]
    );
    let groups = by("groups");
    assert_eq!(groups.page, "after");
    assert!(groups.lists.len() > 1, "groups pages through several lists");
    assert!(by("watch").stream && by("call-media").stream && !by("files").stream);
    assert!(by("recover-keep-succession").gone);
    // the program's options, numbered apart, have nothing of the requests
    // of their numbers
    assert!(back.program.iter().all(|p| p.lists.is_empty() && !p.reads));
    assert!(by("inspect").own && !by("files").own);
    // a field the last release lacked is optional; one always sent is not
    let call = back
        .records
        .iter()
        .find(|r| r.name == "call ended")
        .unwrap();
    let at = call.fields.iter().find(|f| f.name == "at").unwrap();
    assert!(at.optional);
    let files = by("files");
    let more = files.reply.iter().find(|f| f.name == "more").unwrap();
    assert!(!more.optional && more.r#type.is == "bool");
    // ids keep their length
    let file = back.records.iter().find(|r| r.name == "file").unwrap();
    let group = file.fields.iter().find(|f| f.name == "group").unwrap();
    assert_eq!(
        (group.r#type.is.as_str(), group.r#type.size),
        ("bytes", Some(32))
    );
    assert!(back.frames.iter().any(|f| f.name == "audio"));
    assert_eq!(back.version, VERSION);
    // what every message shares
    let st = |n: u64| {
        back.statuses
            .iter()
            .find(|s| s.n == n)
            .map(|s| s.name.as_str())
    };
    assert_eq!(
        (st(0), st(4), st(6)),
        (Some("ok"), Some("too large"), Some("needs for"))
    );
    assert_eq!(
        (back.layout.status, back.layout.why, back.layout.fields_from),
        (0, 1, 2)
    );
    assert_eq!((back.layout.number, back.layout.arguments_from), (0, 1));
    assert_eq!(back.max_message, 256 * 1024);
    // whether a request writes, as it is declared
    assert!(by("files").reads && !by("say").reads && !by("watch").reads);
    let unless = by("contact-status").unless.as_deref().map(|u| u.join(" "));
    assert!(by("contact-status").reads && unless.is_some(), "{unless:?}");
    // the values of text a client compares against
    let call = back.records.iter().find(|r| r.name == "call").unwrap();
    let state = call.fields.iter().find(|f| f.name == "state").unwrap();
    assert_eq!(
        state.known.as_deref(),
        Some(&["calling".into(), "ringing".into(), "live".into()][..])
    );
    let name = call.fields.iter().find(|f| f.name == "name").unwrap();
    assert_eq!(name.known, None);
    // what a client must agree on
    assert_eq!(back.min_service, MIN_SERVICE);
    assert_eq!(
        (back.why.n, back.why.optional, back.why.r#type.is.as_str()),
        (1, false, "text")
    );
    assert_eq!(back.unnamed_status, "failed");
    let one = |r: &str| by(r).one_page.clone().unwrap_or_default().join(" ");
    assert_eq!(
        (one("files"), one("messages"), one("say")),
        ("after limit".into(), "before limit".into(), String::new())
    );
}

/// The export's own records, one field to a line: `<record> <n> <name>
/// <type>`, and `optional` where it may be left out, after the line
/// `schema <n>`.
fn schema_text() -> String {
    let mut held: Vec<&'static crate::table::Rec> = Vec::new();
    fn walk(r: &'static crate::table::Rec, held: &mut Vec<&'static crate::table::Rec>) {
        if held.iter().any(|h| std::ptr::eq(*h, r)) {
            return;
        }
        held.push(r);
        for f in r.fields {
            let mut t = &f.ty;
            while let Ty::List(i) = t {
                t = i;
            }
            if let Ty::Rec(r) | Ty::Recs(r) = t {
                walk(r, held);
            }
        }
    }
    walk(&INTERFACE, &mut held);
    held.sort_by_key(|r| r.name);
    let mut out = format!("schema {SCHEMA}\n");
    for r in held {
        for f in r.fields {
            let optional = if f.optional { " optional" } else { "" };
            out += &format!(
                "{} {} {} {}{optional}\n",
                r.name,
                f.n,
                f.name,
                ty_name(&f.ty)
            );
        }
    }
    out
}

/// A type as the schema's copy writes it.
fn ty_name(ty: &Ty) -> String {
    match ty {
        Ty::List(t) => format!("[{}]", ty_name(t)),
        Ty::Rec(r) => format!("{{{}}}", r.name.replace(' ', "_")),
        Ty::Recs(r) => format!("[{{{}}}]", r.name.replace(' ', "_")),
        Ty::BytesOf(n) => format!("bytes{n}"),
        Ty::Gone(t) => format!("gone:{}", ty_name(t)),
        t => format!("{t:?}").to_lowercase(),
    }
}

/// The export's own numbers are only ever added: every field the
/// checked-in copy (`export-schema.txt`) gives keeps its number, name and
/// type, and the copy gives every field there is (writing it anew, with
/// `CARDINAL_INTERFACE_EXPORT=write`, only adds). A change a generator must
/// make raises [`SCHEMA`], but moves no number either.
#[test]
fn the_exports_own_numbers_are_only_added() {
    // record names may hold a space: the copy's lines split at the number
    let now = schema_text();
    let split = |text: &str| -> Vec<((String, u64), String)> {
        text.lines()
            .skip(1)
            .map(|l| {
                let words: Vec<&str> = l.split(' ').collect();
                let at = words.iter().position(|w| w.parse::<u64>().is_ok()).unwrap();
                let rec = words[..at].join(" ");
                let n = words[at].parse().unwrap();
                ((rec, n), words[at + 1..].join(" "))
            })
            .collect()
    };
    let had = std::fs::read_to_string(path("export-schema.txt")).unwrap_or_default();
    let (old, new) = (split(&had), split(&now));
    let moved: Vec<String> = old
        .iter()
        .filter(|(k, v)| new.iter().find(|(n, _)| n == k).map(|(_, w)| w) != Some(v))
        .map(|((r, n), v)| format!("{r} {n} {v}"))
        .collect();
    assert!(
        moved.is_empty(),
        "the export's own fields given before were moved, retyped or taken away (numbers are \
         only added): {moved:?}"
    );
    if std::env::var("CARDINAL_INTERFACE_EXPORT").as_deref() == Ok("write") {
        std::fs::write(path("export-schema.txt"), &now).unwrap();
        return;
    }
    assert_eq!(
        had.lines().next(),
        Some(format!("schema {SCHEMA}").as_str()),
        "export-schema.txt is of another schema: write it anew with \
         CARDINAL_INTERFACE_EXPORT=write cargo test -p cardinal-interface --lib export"
    );
    assert_eq!(
        old.len(),
        new.len(),
        "export-schema.txt lacks fields the export now has: write it anew with \
         CARDINAL_INTERFACE_EXPORT=write cargo test -p cardinal-interface --lib export"
    );
}
