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
//!   hold, by name.
//! - *request*: its number `n`, `name`, `args` and `reply` (fields; a
//!   reply's numbered from 2, after the status, 0, and why, 1, as
//!   `apps.md` says), `page` (`whole`, `after`: by position, through the
//!   `lists` in turn, the arguments' `after` and `limit` and the reply's
//!   `more` and `next`; or `before`: back from the newest of its one list,
//!   `before` an id, `next` the oldest given), the `lists` paged, each
//!   with the `id` field of its records that error 4 and `before` name it
//!   by, whether it is a `stream` (the connection carries one after it),
//!   whether it is `gone` (its number no longer answered) and whether it
//!   is the node's `own` (not in `apps.md`).
//! - *message* (an event or a frame): its number `n` (key 0 of the
//!   message), `name` and `fields`, numbered from 1.
//! - *field*: its number `n`, `name`, `type`, whether it is `optional` (it
//!   may be left out, and a reader takes its absence as none; a field not
//!   optional is always sent, and a message without it is unreadable) and
//!   whether it is `gone` (its number no longer used: never sent, passed
//!   over when read; `type` is what it held).
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
typed!(INTERFACE "interface" Interface {
    1 error: Vec<FieldOf>,
    2 events: Vec<MessageOf>,
    3 frames: Vec<MessageOf>,
    4 program: Vec<RequestOf>,
    5 records: Vec<RecordOf>,
    6 requests: Vec<RequestOf>,
    7 version: u64,
});

fn type_of(ty: &Ty) -> TypeOf {
    let is = |s: &str| TypeOf::new(s.to_owned());
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
            FieldOf::new(gone, f.n, f.name.to_owned(), f.optional, type_of(ty))
        })
        .collect()
}

/// How each request pages, from its declaration: by its number.
macro_rules! lists {
    ($($how:ident $x:ident,)*) => {
        fn lists_of(n: u64) -> &'static [(&'static str, Option<&'static str>)] {
            $(if let Some(l) = lists!(@one n $how $x) {
                return l;
            })*
            &[]
        }
    };
    (@one $n:ident gone $row:ident) => { None };
    (@one $n:ident $how:ident $args:ident) => {
        (<crate::$args as Ask>::REQUEST.n == $n).then_some(<crate::$args as Ask>::LISTS)
    };
}
each_request!(lists);

fn request_of(r: &Request, own: bool) -> RequestOf {
    let page = match r.page {
        Page::Whole => "whole",
        Page::After => "after",
        Page::Before { .. } => "before",
    };
    let lists = lists_of(r.n)
        .iter()
        .map(|(name, id)| ListOf::new((*name).to_owned()).with_id(*id))
        .collect();
    RequestOf::new(
        fields_of(r.args),
        r.gone,
        lists,
        r.n,
        r.name.to_owned(),
        own,
        page.to_owned(),
        fields_of(r.reply),
        r.stream,
    )
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
    MessageOf::new(fields_of(m.args), m.n, m.name.to_owned())
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
        .map(|r| RecordOf::new(fields_of(r.fields), r.name.to_owned()))
        .collect()
}

/// The export, from the declarations.
fn interface() -> Interface {
    Interface::new(
        fields_of(ERROR_FIELDS),
        EVENTS.iter().map(message_of).collect(),
        FRAMES.iter().map(message_of).collect(),
        PROGRAM.iter().map(|r| request_of(r, false)).collect(),
        records(),
        REQUESTS
            .iter()
            .map(|r| request_of(r, NODE_ONLY.contains(&r.name)))
            .collect(),
        VERSION,
    )
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
        [ListOf::new("messages".into()).with_id(Some("id"))]
    );
    let groups = by("groups");
    assert_eq!(groups.page, "after");
    assert!(groups.lists.len() > 1, "groups pages through several lists");
    assert!(by("watch").stream && by("call-media").stream && !by("files").stream);
    assert!(by("recover-keep-succession").gone);
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
}
