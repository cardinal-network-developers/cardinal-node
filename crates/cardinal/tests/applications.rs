//! The application interface (`apps.md#the-application-interface`), driven
//! by the command-line calendar (`cardinal-calendar`), which speaks nothing
//! else: Ana starts a calendar and shares it with Ben, and Ben's calendar
//! program, once he approves it, sees her events. A program without an
//! approval sees nothing, and a write of a kind its documents do not
//! declare is refused.
//!
//! The calendar is a binary of its own crate: run with `cargo test
//! --workspace`, which builds it beside `cardinal`.

mod common;

use cardinal_encoding::{Record, Value};
use common::*;
use serde_json::{json, Value as Json};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

fn calendar_bin() -> PathBuf {
    let p = PathBuf::from(BIN).with_file_name("cardinal-calendar");
    assert!(
        p.exists(),
        "{} is not built: run the tests with `cargo test --workspace`",
        p.display()
    );
    p
}

fn person(root: &std::path::Path, name: &'static str) -> Dev {
    let mut d = Dev::new(root, name, free_port());
    d.start_with(&["--no-mount"]);
    let mut called = name.to_owned();
    called[..1].make_ascii_uppercase();
    d.cli(&["init", "--yes", "--name", &called]);
    d
}

fn app_socket(d: &Dev) -> PathBuf {
    d.home.join("control-apps.sock")
}

fn calendar(d: &Dev) -> Command {
    let mut c = Command::new(calendar_bin());
    c.env("CARDINAL_APP_SOCKET", app_socket(d));
    c
}

/// Runs the calendar to the end, which must succeed: what it printed.
fn cal(d: &Dev, args: &[&str]) -> String {
    let o = calendar(d).args(args).output().unwrap();
    assert!(
        o.status.success(),
        "{} cardinal-calendar {args:?}: {}{}",
        d.name,
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).into_owned()
}

/// Starts the calendar, which will wait for its person.
fn cal_waiting(d: &Dev, args: &[&str]) -> Child {
    calendar(d)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn finished(c: Child) -> String {
    let o = c.wait_with_output().unwrap();
    assert!(
        o.status.success(),
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).into_owned()
}

/// The person answers the one question waiting, as `cardinal approve` does.
fn answer(d: &Dev, args: &[&str]) -> Json {
    let mut q = Json::Null;
    wait("a question for the person", 30, || {
        let v = ask(d, &json!({"cmd": "app-questions"}));
        q = v["questions"][0].clone();
        !q.is_null()
    });
    let id = q["id"].as_u64().unwrap().to_string();
    let mut all = vec!["approve", id.as_str()];
    all.extend_from_slice(args);
    d.cli(&all);
    q
}

/// Ana invites Ben, and each calls the other by name.
fn meet(ana: &Dev, ben: &Dev) {
    let at = format!("127.0.0.1:{}", ana.port);
    let code = ana.cli(&["invite", "--address", &at, "--name", "Ana"]);
    ben.cli(&["accept", code.trim(), "--name", "Ana"]);
    wait("ana lists ben", 30, || {
        ana.cli(&["contacts"]).to_lowercase().contains("ben")
    });
    ask(ana, &json!({"cmd": "contact", "who": "ben", "name": "Ben"}));
}

/// A program of the test's own: this test binary, at the application
/// interface, record by record.
struct Raw(Client);

impl Raw {
    fn new(d: &Dev) -> Raw {
        let c = Client::connect(&app_socket(d)).expect("the application interface listens");
        c.set_read_timeout(Some(std::time::Duration::from_secs(60)))
            .unwrap();
        Raw(c)
    }

    fn ask(&mut self, r: Record) -> Record {
        self.0.send_raw(&r.encode()).unwrap();
        Record::decode(&self.0.recv_raw().unwrap().unwrap()).unwrap()
    }

    fn hello(&mut self, doc: &[u8]) -> Record {
        let r = self.ask(
            Record::new()
                .with(0, 1u64)
                .with(1, "Test")
                .with(2, Value::list([Value::from(doc.to_vec())])),
        );
        assert_eq!(r.uint(0).unwrap(), 0, "{r}");
        r
    }
}

#[test]
fn ana_shares_a_calendar_with_ben_whose_program_sees_it() {
    let root = tempfile::tempdir().unwrap();
    let ana = person(root.path(), "ana");
    let ben = person(root.path(), "ben");
    meet(&ana, &ben);

    // Ana starts a calendar: she is asked, and says yes
    let started = cal_waiting(&ana, &["new", "Ana's calendar"]);
    let q = answer(&ana, &[]);
    assert_eq!(q["asks"], "new-space");
    assert!(
        q["what"].as_str().unwrap().contains("Ana's calendar"),
        "{q}"
    );
    let handle = finished(started).trim().to_owned();
    assert_eq!(handle.len(), 32, "{handle}");
    assert!(cal(&ana, &["list"]).contains("Ana's calendar"));
    cal(
        &ana,
        &[
            "add",
            "Ana's calendar",
            "Dentist",
            "20261126T090000",
            "--zone",
            "America/Chicago",
        ],
    );

    // she shares it with Ben, choosing him in Cardinal
    let sharing = cal_waiting(&ana, &["share", "Ana's calendar"]);
    let q = answer(&ana, &["--with", "Ben"]);
    assert_eq!(q["asks"], "share");
    assert_eq!(q["role"], "reader");
    let members = finished(sharing);
    assert!(members.contains("Ben: reader"), "{members}");

    // Ben is offered it, as a calendar, and takes it
    let mut space = String::new();
    wait("ben is offered ana's calendar", 60, || {
        let v = ask(&ben, &json!({"cmd": "app-offers"}));
        let o = &v["offers"][0];
        space = o["space"].as_str().unwrap_or("").to_owned();
        o["application"] == "Calendar"
    });
    assert!(ben
        .cli(&["apps", "offers"])
        .contains("Ana shares a calendar with you: Ana's calendar"));
    ben.cli(&["apps", "join", &space]);

    // his calendar program sees nothing until he approves it
    assert!(cal(&ben, &["list"]).trim().is_empty());
    let approving = cal_waiting(&ben, &["approve"]);
    let q = answer(&ben, &[]);
    assert_eq!(q["asks"], "family");
    finished(approving);
    let listed = cal(&ben, &["list"]);
    assert!(listed.contains("Ana's calendar  (to see)"), "{listed}");
    wait("ben's calendar shows the dentist", 60, || {
        cal(&ben, &["events", "Ana's calendar"]).contains("20261126T090000  Dentist")
    });
    // and what she adds later
    cal(&ana, &["add", "Ana's calendar", "Choir", "20261127T190000"]);
    wait("ben's calendar shows choir", 60, || {
        cal(&ben, &["events", "Ana's calendar"]).contains("Choir")
    });
    // he may see it, not change it
    let o = calendar(&ben)
        .args(["add", "Ana's calendar", "Mine", "20261128"])
        .output()
        .unwrap();
    assert!(!o.status.success());

    // the approvals are in the account, and listed
    let approvals = ben.cli(&["apps", "approvals"]);
    assert!(
        approvals.contains("may see every Calendar, on this device"),
        "{approvals}"
    );

    // a program without an approval, on Ben's device, sees nothing
    let doc = calendar(&ben).arg("document").output().unwrap().stdout;
    let mut other = Raw::new(&ben);
    let hello = other.hello(&doc);
    assert!(hello.list(7).unwrap().is_empty(), "{hello}");
    let spaces = other.ask(Record::new().with(0, 5u64));
    assert_eq!(spaces.uint(0).unwrap(), 0);
    assert!(spaces.list(2).unwrap().is_empty(), "{spaces}");
    // nor by a handle it got hold of
    let h = hex::decode(&handle).unwrap();
    let nodes = other.ask(Record::new().with(0, 7u64).with(1, h.clone()));
    assert_eq!(nodes.uint(0).unwrap(), 5, "{nodes}");
    // and nothing at all before hello
    let mut rude = Raw::new(&ben);
    assert_eq!(rude.ask(Record::new().with(0, 5u64)).uint(0).unwrap(), 5);
}

#[test]
fn a_write_the_documents_do_not_allow_is_refused() {
    let root = tempfile::tempdir().unwrap();
    let ana = person(root.path(), "ana");
    let doc = calendar(&ana).arg("document").output().unwrap().stdout;
    // a malformed document is no document
    let mut bad = Raw::new(&ana);
    let mut broken = doc.clone();
    broken.push(0);
    let r = bad.ask(
        Record::new()
            .with(0, 1u64)
            .with(2, Value::list([Value::from(broken)])),
    );
    assert_ne!(r.uint(0).unwrap(), 0);

    // this test, as a program, asks to start a calendar, and Ana says yes
    let socket = app_socket(&ana);
    let doc2 = doc.clone();
    let started = std::thread::spawn(move || {
        let c = Client::connect(&socket).unwrap();
        c.set_read_timeout(Some(std::time::Duration::from_secs(60)))
            .unwrap();
        let mut p = Raw(c);
        let hello = p.hello(&doc2);
        let root = hello.list(4).unwrap()[0].as_bytes().unwrap().to_vec();
        let r = p.ask(Record::new().with(0, 4u64).with(1, root).with(2, "Tests"));
        assert_eq!(r.uint(0).unwrap(), 0, "{r}");
        (p, r.bytes(2).unwrap().to_vec())
    });
    answer(&ana, &[]);
    let (mut p, space) = started.join().unwrap();
    let write = |p: &mut Raw, op: Record| {
        p.ask(
            Record::new()
                .with(0, 8u64)
                .with(1, space.clone())
                .with(2, Value::list([Value::Record(op)])),
        )
    };
    let create = |kind: u64, fields: Record| {
        Record::new()
            .with(0, 32u64)
            .with(1, kind)
            .with(2, [0u8; 16])
            .with(3, "x")
            .with(4, fields)
    };
    // an event is written
    let ok = write(
        &mut p,
        create(2, Record::new().with(1, "Lunch").with(2, "20261201T120000")),
    );
    assert_eq!(ok.uint(0).unwrap(), 0, "{ok}");
    // a kind the calendar does not declare is refused, and says which op
    let r = write(&mut p, create(9, Record::new()));
    assert_eq!(r.uint(0).unwrap(), 6, "{r}");
    assert_eq!(r.uint(2).unwrap(), 0);
    // so is a title that is not text, and a control op
    let r = write(&mut p, create(2, Record::new().with(1, 5u64)));
    assert_eq!(r.uint(0).unwrap(), 6, "{r}");
    let r = write(&mut p, Record::new().with(0, 4u64));
    assert_eq!(r.uint(0).unwrap(), 6, "{r}");

    // the space holds one document node, the calendar's, whatever was
    // written since
    let nodes = p.ask(Record::new().with(0, 7u64).with(1, space.clone()));
    assert_eq!(
        nodes.list(2).unwrap().len(),
        1,
        "a program is not given document nodes"
    );

    // what changed since a sequence number, and a watch that says so
    let seq = nodes.uint(3).unwrap();
    let since = |p: &mut Raw, seq: u64| {
        let r = p.ask(
            Record::new()
                .with(0, 7u64)
                .with(1, space.clone())
                .with(4, seq),
        );
        assert_eq!(r.uint(0).unwrap(), 0, "{r}");
        (r.list(2).unwrap().len(), r.uint(3).unwrap())
    };
    assert_eq!(since(&mut p, seq), (0, seq));
    let mut watching = Raw::new(&ana);
    watching.hello(&doc);
    assert_eq!(
        watching.ask(Record::new().with(0, 2u64)).uint(0).unwrap(),
        0
    );
    let event = |w: &mut Raw| Record::decode(&w.0.recv_raw().unwrap().unwrap()).unwrap();
    let first = event(&mut watching);
    assert_eq!(first.bytes(1).unwrap(), &space[..]);
    assert_eq!(first.uint(2).unwrap(), seq);
    let ok = write(
        &mut p,
        create(2, Record::new().with(1, "Tea").with(2, "20261202")),
    );
    assert_eq!(ok.uint(0).unwrap(), 0, "{ok}");
    let next = event(&mut watching);
    assert!(next.uint(2).unwrap() > seq, "{next}");
    let (changed, now) = since(&mut p, seq);
    assert_eq!((changed, now), (1, next.uint(2).unwrap()));
    // a number this service never gave is answered whole
    assert_eq!(since(&mut p, 5).0, 2);
    let token = ask(&ana, &json!({"cmd": "inspect-on"}))["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let shown = ask(&ana, &json!({"cmd": "inspect", "token": token}));
    let spaces = shown["spaces"].as_array().cloned().unwrap_or_default();
    let ours = spaces
        .iter()
        .find(|s| s["profile"].as_str().is_some_and(|p| p.len() == 64))
        .expect("the calendar space")["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let docs = ask(
        &ana,
        &json!({"cmd": "inspect-nodes", "token": token, "space": ours, "kind": 0}),
    );
    assert_eq!(docs["nodes"].as_array().unwrap().len(), 1, "{docs}");
}

/// A document that adds guests to the calendar: a guest is a member.
fn guests(calendar: &[u8]) -> Vec<u8> {
    let root = cardinal_space::application::name_of(calendar);
    let field = Record::new().with(1, 1u64).with(2, "who").with(3, 7u64);
    let guest = Record::new()
        .with(1, 1u64)
        .with(2, "guest")
        .with(3, Value::list([Value::from(0u64)]))
        .with(5, Value::list([Value::Record(field)]));
    Record::new()
        .with(0, 14u64)
        .with(1, "Guests")
        .with(2, "Who comes to an event.")
        .with(3, root)
        .with(5, Value::list([Value::Record(guest)]))
        .with(6, "Guests.\n")
        .with(8, "en")
        .encode()
}

/// What a program is given of another application's kinds is typed by
/// the documents the space holds: a member as a handle, never as an
/// identity. A question goes when the program that asked it does.
#[test]
fn another_application_s_members_are_handles_and_a_question_goes_with_its_asker() {
    let root = tempfile::tempdir().unwrap();
    let ana = person(root.path(), "ana");
    let cal_doc = calendar(&ana).arg("document").output().unwrap().stdout;
    let guest_doc = guests(&cal_doc);
    let cal_root = cardinal_space::application::name_of(&cal_doc);
    let connect = |d: &Dev, docs: &[&[u8]]| {
        let mut p = Raw::new(d);
        let docs = Value::List(docs.iter().map(|b| Value::from(b.to_vec())).collect());
        let hello = p.ask(Record::new().with(0, 1u64).with(1, "Test").with(2, docs));
        assert_eq!(hello.uint(0).unwrap(), 0, "{hello}");
        p
    };
    // a program with both documents starts a calendar
    let socket = app_socket(&ana);
    let both = (cal_doc.clone(), guest_doc.clone());
    let started = std::thread::spawn(move || {
        let c = Client::connect(&socket).unwrap();
        c.set_read_timeout(Some(std::time::Duration::from_secs(60)))
            .unwrap();
        let mut p = Raw(c);
        let docs = Value::list([Value::from(both.0), Value::from(both.1)]);
        let hello = p.ask(Record::new().with(0, 1u64).with(1, "Both").with(2, docs));
        assert_eq!(hello.uint(0).unwrap(), 0, "{hello}");
        let r = p.ask(
            Record::new()
                .with(0, 4u64)
                .with(1, cal_root)
                .with(2, "Party"),
        );
        assert_eq!(r.uint(0).unwrap(), 0, "{r}");
        (p, r.bytes(2).unwrap().to_vec())
    });
    answer(&ana, &[]);
    let (mut p, space) = started.join().unwrap();
    // and writes a guest: Ana, by her handle
    let members = p.ask(Record::new().with(0, 6u64).with(1, space.clone()));
    let me = members.list(2).unwrap()[0]
        .as_record()
        .unwrap()
        .bytes(1)
        .unwrap()
        .to_vec();
    let guests = cardinal_space::application::Document::parse(&guest_doc).unwrap();
    let kind = match guests.node_kind(1) {
        cardinal_space::NodeKind::Named(k) => k,
        k => panic!("a child's kind is named: {k:?}"),
    };
    let op = Record::new()
        .with(0, 32u64)
        .with(1, kind)
        .with(2, [0u8; 16])
        .with(3, "ana")
        .with(4, Record::new().with(1, me.clone()));
    let ok = p.ask(
        Record::new()
            .with(0, 8u64)
            .with(1, space.clone())
            .with(2, Value::list([Value::Record(op)])),
    );
    assert_eq!(ok.uint(0).unwrap(), 0, "{ok}");
    // a program with the calendar's document alone is given her handle
    let mut q = connect(&ana, &[&cal_doc]);
    let nodes = q.ask(Record::new().with(0, 7u64).with(1, space.clone()));
    assert_eq!(nodes.uint(0).unwrap(), 0, "{nodes}");
    let all = nodes.list(2).unwrap();
    let guest = all
        .iter()
        .filter_map(Value::as_record)
        .find(|n| n.bytes(2).is_ok_and(|k| k == kind))
        .expect("the guest is listed");
    let field = guest.list(5).unwrap()[0].as_record().unwrap().clone();
    assert_eq!(
        field.bytes(2).unwrap(),
        &me[..],
        "a handle, not an identity: {field}"
    );
    assert!(field.get(4).is_none(), "{field}");

    // a question waits for Ana while its asker is there, and goes with it
    let mut sharing = connect(&ana, &[&cal_doc]);
    sharing
        .0
        .send_raw(&Record::new().with(0, 11u64).with(1, space.clone()).encode())
        .unwrap();
    wait("ana is asked", 30, || {
        ask(&ana, &json!({"cmd": "app-questions"}))["questions"][0]["asks"] == "share"
    });
    drop(sharing);
    wait("the question went with its asker", 30, || {
        ask(&ana, &json!({"cmd": "app-questions"}))["questions"]
            .as_array()
            .is_some_and(|q| q.is_empty())
    });
}
