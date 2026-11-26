//! The tables themselves: every number given once, the paged requests
//! paged alike, the markdown `apps.md` holds, and what the last release
//! lacked read back as an `Option`.

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
        Ty::Bytes | Ty::BytesOf(_) => "bytes".into(),
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

/// The tables of the last release (`released-tables.md`, as
/// `CARDINAL_API_TABLES` wrote them from that release's source): what a
/// client newer than a service still running may be answered with.
const RELEASED: &str = include_str!("released-tables.md");

/// A request's arguments and reply, by its name, as numbers.
type Asked = std::collections::HashMap<String, (HashSet<u64>, HashSet<u64>)>;
/// A record's fields, by its name, as numbers.
type Held = std::collections::HashMap<String, HashSet<u64>>;

/// Every request's arguments and reply, and every record's fields, in the
/// tables `RELEASED` gives.
fn released() -> (Asked, Held) {
    fn numbers(cell: &str) -> HashSet<u64> {
        let mut out = HashSet::new();
        for part in cell.split(", ") {
            let part = part.trim();
            if let Some((n, rest)) = part.split_once(' ') {
                if rest.starts_with('`') {
                    out.insert(n.parse().expect("a field's number"));
                }
            }
        }
        out
    }
    let (mut requests, mut records) = (Asked::new(), Held::new());
    let mut in_records = false;
    for line in RELEASED.lines() {
        if line.starts_with("#### ") {
            in_records = line == "#### Records";
            continue;
        }
        let cells: Vec<&str> = line.split(" | ").collect();
        if !line.starts_with("| ")
            || line.starts_with("| # ")
            || line.starts_with("| Record ")
            || line.starts_with("| Asked ")
        {
            continue;
        }
        if in_records {
            let name = cells[0].trim_start_matches("| *").trim_end_matches('*');
            let fields = cells.get(1).map_or("", |c| c.trim_end_matches(" |"));
            records.insert(name.to_owned(), numbers(fields));
        } else if cells.len() == 4 {
            let name = cells[1].split('`').nth(1).expect("a request's name");
            let reply = cells[3].trim_end_matches(" |");
            requests.insert(name.to_owned(), (numbers(cells[2]), numbers(reply)));
        } else if cells.len() == 2 && cells[0].starts_with("| `") {
            // what the program says, by the option that asks it
            let name = cells[0].split('`').nth(1).expect("an option");
            let reply = cells[1].trim_end_matches(" |");
            requests.insert(name.to_owned(), (HashSet::new(), numbers(reply)));
        }
    }
    (requests, records)
}

/// A field added to a record after it was first released is an `Option`
/// for ever (DEVIATIONS.md, Typed records): a newer client reads an older
/// service still running, and a newer service an older client's request.
/// Held against the last release's tables, for the requests and records it
/// had.
#[test]
fn what_the_last_release_lacked_is_an_option() {
    let (requests, records) = released();
    assert!(requests.contains_key("call") && records.contains_key("call ended"));
    let mut wrong = Vec::new();
    let mut held: Vec<&'static Rec> = Vec::new();
    fn walk(ty: &'static Ty, held: &mut Vec<&'static Rec>) {
        match ty {
            Ty::List(t) | Ty::Gone(t) => walk(t, held),
            Ty::Rec(r) | Ty::Recs(r) if !held.iter().any(|h| std::ptr::eq(*h, *r)) => {
                held.push(r);
                for f in r.fields {
                    walk(&f.ty, held);
                }
            }
            _ => {}
        }
    }
    let mut strict = |at: &str, fields: &'static [Field], had: &HashSet<u64>| {
        for f in fields {
            if !had.contains(&f.n) && !f.optional {
                wrong.push(format!("{at}: {} `{}`", f.n, f.name));
            }
        }
    };
    for r in REQUESTS.iter().chain(PROGRAM).filter(|r| !r.gone) {
        for f in r.args.iter().chain(r.reply) {
            walk(&f.ty, &mut held);
        }
        if let Some((args, reply)) = requests.get(r.name) {
            strict(&format!("{} arguments", r.name), r.args, args);
            strict(&format!("{} reply", r.name), r.reply, reply);
        }
    }
    for rec in held {
        if let Some(had) = records.get(rec.name) {
            strict(&format!("*{}*", rec.name), rec.fields, had);
        }
    }
    assert!(
        wrong.is_empty(),
        "fields the last release did not have, read back as required (make each an \
         Option): {wrong:?}"
    );
}
