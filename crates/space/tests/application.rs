//! Application documents in a space (`profiles.md#applications-normative`):
//! the document node of the root in the genesis, a child's written once,
//! on first use; a document node used only when its hash is its name; and
//! the writer's checks of what a program asks to write. State never
//! depends on any of it.

use cardinal_crypto::{HybridKeyPair, RecoveryPhrase};
use cardinal_encoding::{Record, Value};
use cardinal_identity::{Created, DeviceKeys, IdentityLog};
use cardinal_space::application::{self, Document, Family, DOCUMENT_NODE};
use cardinal_space::{NodeKind, Policy, Profile, Space, SpaceOp, ROOT};

fn field(key: u64, name: &str, ty: u64) -> Value {
    Value::Record(Record::new().with(1, key).with(2, name).with(3, ty))
}

fn kind(n: u64, name: &str, under: Value, owned: bool, fields: Vec<Value>) -> Value {
    Value::Record(
        Record::new()
            .with(1, n)
            .with(2, name)
            .with(3, Value::list([under]))
            .with_opt(4, owned.then_some(true))
            .with(5, Value::List(fields)),
    )
}

fn document(title: &str, parent: Option<[u8; 32]>, kinds: Vec<Value>) -> Document {
    let r = Record::new()
        .with(0, 14u64)
        .with(1, title)
        .with(2, "For the tests")
        .with_opt(3, parent)
        .with(4, Record::new().with(1, true).with(2, 1u64))
        .with(5, Value::List(kinds))
        .with(6, "Words.\n")
        .with(8, "en");
    Document::parse(&r.encode()).unwrap()
}

fn root() -> Document {
    document(
        "Notes",
        None,
        vec![
            kind(
                1,
                "note",
                Value::from(0u64),
                false,
                vec![field(1, "text", 1), field(2, "count", 2)],
            ),
            kind(
                2,
                "mark",
                Value::from(1u64),
                true,
                vec![field(1, "text", 1)],
            ),
        ],
    )
}

fn child(root: &Document) -> Document {
    let under = Value::Record(Record::new().with(1, root.name).with(2, 1u64));
    document(
        "Tags",
        Some(root.name),
        vec![kind(1, "tag", under, false, vec![field(1, "text", 1)])],
    )
}

struct Ana {
    log: IdentityLog,
    dev: DeviceKeys,
    space: Space,
}

fn ana(root: &Document) -> Ana {
    let dev = DeviceKeys::generate();
    let Created {
        log, encryption, ..
    } = IdentityLog::create_with(
        RecoveryPhrase::from_entropy(&[3; 32]),
        &dev,
        HybridKeyPair::generate(),
    )
    .unwrap();
    let genesis = vec![
        SpaceOp::add_member(log.id(), cardinal_space::group::OWNER),
        SpaceOp::from_record(application::document_node(root)),
    ];
    let (space, _) = Space::create_with(
        Profile::Named(root.name),
        Policy::default(),
        &log,
        &dev.signing,
        &[encryption.public_key()],
        genesis,
        None,
    )
    .unwrap();
    Ana { log, dev, space }
}

impl Ana {
    fn write(&mut self, ops: Vec<Record>) -> cardinal_identity::EntryId {
        let ops = ops.into_iter().map(SpaceOp::from_record).collect();
        let (id, _) = self
            .space
            .write_entry(&self.log, &self.dev.signing, ops, None)
            .unwrap();
        id
    }

    fn doc_nodes(&self) -> usize {
        self.space
            .state()
            .nodes()
            .filter(|n| n.kind == NodeKind::Uint(DOCUMENT_NODE) && !n.deleted)
            .count()
    }
}

fn create(kind: Value, parent: Value, fields: Record) -> Record {
    Record::new()
        .with(0, 32u64)
        .with(1, kind)
        .with(2, parent)
        .with(3, "n")
        .with(4, fields)
}

#[test]
fn the_root_s_document_is_in_the_genesis_and_used_when_its_hash_matches() {
    let root = root();
    let mut a = ana(&root);
    let held = application::documents_in(a.space.state());
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].name, root.name);
    // a document node whose bytes are not the name it stands for is
    // in the state, and used by nobody
    let other = child(&root);
    let lie = Record::new()
        .with(0, 32u64)
        .with(1, DOCUMENT_NODE)
        .with(2, ROOT)
        .with(3, "lie")
        .with(
            4,
            Record::new()
                .with(1, root.name)
                .with(2, other.bytes.clone()),
        );
    a.write(vec![lie]);
    assert_eq!(a.doc_nodes(), 2, "it is in the state like any node");
    let held = application::documents_in(a.space.state());
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].bytes, root.bytes);
}

#[test]
fn a_child_s_document_node_is_written_once_on_first_use() {
    let root = root();
    let tags = child(&root);
    let family = Family::new(vec![root.clone(), tags.clone()]).unwrap();
    let mut a = ana(&root);
    let me = a.log.id();
    let note = a.write(vec![create(
        Value::from(1u64),
        Value::from(ROOT),
        Record::new().with(1, "hi"),
    )]);
    let note = cardinal_space::entry::derived_id(&note, 0);
    // a note needs no document node of the child
    let ops = vec![create(Value::from(1u64), Value::from(ROOT), Record::new())];
    let ops = application::check(&family, a.space.state(), &me, &ops).unwrap();
    assert!(application::documents_wanted(&family, a.space.state(), &ops).is_empty());
    // the first tag brings the child's document with it
    let NodeKind::Named(tag) = tags.node_kind(1) else {
        panic!("a child's kind is named")
    };
    let ops = vec![create(
        Value::from(tag),
        Value::from(note),
        Record::new().with(1, "red"),
    )];
    let mut all = application::check(&family, a.space.state(), &me, &ops).unwrap();
    let wanted = application::documents_wanted(&family, a.space.state(), &all);
    assert_eq!(wanted.len(), 1);
    assert_eq!(wanted[0].name, tags.name);
    all.extend(wanted.iter().map(application::document_node));
    a.write(all);
    assert_eq!(a.doc_nodes(), 2);
    // and the second does not
    let ops = vec![create(
        Value::from(tag),
        Value::from(note),
        Record::new().with(1, "blue"),
    )];
    let all = application::check(&family, a.space.state(), &me, &ops).unwrap();
    assert!(application::documents_wanted(&family, a.space.state(), &all).is_empty());
}

#[test]
fn the_writer_s_service_refuses_what_its_documents_do_not_allow() {
    let root = root();
    let family = Family::new(vec![root.clone()]).unwrap();
    let mut a = ana(&root);
    let me = a.log.id();
    let check = |a: &Ana, ops: Vec<Record>| application::check(&family, a.space.state(), &me, &ops);
    // a kind no document declares
    let r = check(
        &a,
        vec![create(Value::from(9u64), Value::from(ROOT), Record::new())],
    )
    .unwrap_err();
    assert_eq!(r.at, 0);
    assert!(r.why.contains("kind"), "{}", r.why);
    // a field of the wrong type, and one not declared
    let r = check(
        &a,
        vec![create(
            Value::from(1u64),
            Value::from(ROOT),
            Record::new().with(2, "x"),
        )],
    );
    assert!(r.is_err());
    let r = check(
        &a,
        vec![create(
            Value::from(1u64),
            Value::from(ROOT),
            Record::new().with(7, "x"),
        )],
    );
    assert!(r.is_err());
    // a mark goes under a note, not under the root; and is made the
    // author's own by the service
    assert!(check(
        &a,
        vec![create(Value::from(2u64), Value::from(ROOT), Record::new())]
    )
    .is_err());
    let ops = vec![
        create(
            Value::from(1u64),
            Value::from(ROOT),
            Record::new().with(1, "hi"),
        ),
        create(Value::from(2u64), Value::from(0u64), Record::new()),
    ];
    let ok = check(&a, ops).unwrap();
    assert_eq!(
        ok[1]
            .get(4)
            .and_then(|v| v.as_record())
            .and_then(|r| r.get(15)),
        Some(&Value::from(1u64))
    );
    // the second op names the first by index: only an earlier one
    let r = check(
        &a,
        vec![create(Value::from(2u64), Value::from(0u64), Record::new())],
    )
    .unwrap_err();
    assert_eq!(r.at, 0);
    // a control op is never a program's
    let leave = SpaceOp::leave().record().clone();
    assert!(check(&a, vec![leave]).is_err());
    // a node it does not know: neither set nor deleted
    let odd = a.write(vec![create(
        Value::from(7u64),
        Value::from(ROOT),
        Record::new(),
    )]);
    let odd = cardinal_space::entry::derived_id(&odd, 0);
    let set = Record::new()
        .with(0, 33u64)
        .with(1, odd)
        .with(2, 1u64)
        .with(3, "x");
    assert!(check(&a, vec![set]).is_err());
    let del = Record::new().with(0, 35u64).with(1, odd);
    assert!(check(&a, vec![del]).is_err());
    // the node is in the state all the same, and does not fit
    let n = a.space.state().node(&odd).unwrap().clone();
    assert!(!family.fits(a.space.state(), &n));
}
