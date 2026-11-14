//! A node made in the same entry (`state.md#a-node-made-in-the-same-entry`).
//!
//! A node's id follows from the id of the entry that creates it, so no op
//! can hold the id of a node its own entry creates. Where `create` or `move`
//! holds a parent it may hold an unsigned integer instead: the place, in the
//! entry's op list, of a `create` that comes earlier. A device turns it into
//! the id when it takes the entry, and nothing it keeps holds the index.
//!
//! With it: what a delete takes when an op before it in its own entry moved
//! something beneath the node, the order of values one entry wrote to one
//! field, and what stands where a node id belongs and is not one.

use cardinal_crypto::{HybridKeyPair, RecoveryPhrase};
use cardinal_encoding::{Int, Record, Value};
use cardinal_identity::{Created, DeviceKeys, EntryId, IdentityLog};
use cardinal_space::entry::derived_id;
use cardinal_space::files::{self, Content, Files};
use cardinal_space::{NodeId, NodeKind, Policy, Profile, SealedEntry, Space, SpaceOp, State, ROOT};

struct One {
    log: IdentityLog,
    enc: HybridKeyPair,
    device: DeviceKeys,
    space: Space,
    genesis: SealedEntry,
}

fn one(n: u8) -> One {
    let device = DeviceKeys::generate();
    let Created {
        log, encryption, ..
    } = IdentityLog::create_with(
        RecoveryPhrase::from_entropy(&[n; 32]),
        &device,
        HybridKeyPair::generate(),
    )
    .unwrap();
    let (space, genesis) = Space::create(
        Profile::FILES,
        Policy::default(),
        &log,
        &device.signing,
        &[encryption.public_key()],
        None,
    )
    .unwrap();
    One {
        log,
        enc: encryption,
        device,
        space,
        genesis,
    }
}

impl One {
    fn write(&mut self, ops: Vec<SpaceOp>) -> EntryId {
        let (id, _) = self
            .space
            .write_entry(&self.log, &self.device.signing, ops, None)
            .unwrap();
        id
    }

    /// Writes an entry that is valid, as any op numbered 32 or above by a
    /// writer is, and says whether it was accepted for state.
    fn accepted(&mut self, ops: Vec<SpaceOp>) -> bool {
        let id = self.write(ops);
        assert!(self.space.validity().is_valid(&id), "not valid");
        self.space.state().is_accepted(&id)
    }

    /// The same space on another device, given everything at once, the
    /// newest entry first.
    fn elsewhere(&self) -> Space {
        let mut other =
            Space::open_genesis(&self.genesis, &[&self.enc], Some(self.log.state())).unwrap();
        let mut ids: Vec<EntryId> = self.space.dag().log_order().to_vec();
        ids.reverse();
        for id in ids.iter().filter(|id| **id != self.space.id()) {
            let sealed = self.space.sealed(id).unwrap().clone();
            other.receive(sealed, &[&self.enc]).unwrap();
        }
        other
    }

    /// What every way of working the state out gives: as entries came, on
    /// another device, from scratch, and by the definition of a delete.
    fn agrees(&self) {
        let here = self.space.state().canonical();
        assert_eq!(self.elsewhere().state().canonical(), here, "another device");
        let valid = &self.space.validity().valid;
        let full = State::compute(Profile::FILES, self.space.dag(), valid);
        assert_eq!(full.canonical(), here, "from scratch");
        let plain = State::compute_by_definition(Profile::FILES, self.space.dag(), valid);
        assert_eq!(plain.canonical(), here, "by the definition");
    }

    fn names(&self, path: &str) -> Vec<String> {
        let list = Files::new(&self.space).list_path(path);
        list.unwrap_or_default()
            .into_iter()
            .map(|e| e.name)
            .collect()
    }

    fn parent_of(&self, node: &NodeId) -> NodeId {
        self.space.state().node(node).unwrap().parent
    }

    fn deleted(&self, node: &NodeId) -> (bool, bool) {
        let n = self.space.state().node(node).unwrap();
        (n.deleted, n.delete_conflict)
    }
}

fn folder(parent: NodeId, name: &str) -> SpaceOp {
    files::create_folder(parent, name)
}

fn folder_under(index: u32, name: &str) -> SpaceOp {
    SpaceOp::create_under(NodeKind::Uint(files::FOLDER), index, name, Record::new())
}

/// A `create` of a folder with whatever is put where its parent belongs.
fn folder_with_parent(parent: Option<Value>) -> SpaceOp {
    let r = Record::new().with(0, 32u32).with(1, 1u32).with(3, "x");
    SpaceOp::from_record(r.with_opt(2, parent))
}

/// The record of the node `id` in a canonical state.
fn record_of(space: &Space, id: &NodeId) -> Record {
    let state = space.state().canonical();
    let list = state.get(1).and_then(Value::as_list).unwrap();
    let mut all = list.iter().filter_map(Value::as_record);
    let found = all.find(|r| r.get(1).and_then(Value::as_bytes) == Some(&id[..]));
    found.unwrap().clone()
}

/// The example of the specification: one entry makes a folder under the
/// root and a file in that folder.
#[test]
fn the_folder_and_the_file_in_it() {
    let mut p = one(71);
    let content = Record::new().with(1, Value::from(b"hi".to_vec()));
    let ops = vec![
        SpaceOp::from_record(
            Record::new()
                .with(0, 32u32)
                .with(1, 1u32)
                .with(2, ROOT)
                .with(3, "Trip"),
        ),
        SpaceOp::from_record(
            Record::new()
                .with(0, 32u32)
                .with(1, 2u32)
                .with(2, 0u32)
                .with(3, "plan.txt")
                .with(4, content),
        ),
    ];
    let id = p.write(ops);
    assert!(p.space.validity().is_valid(&id) && p.space.state().is_accepted(&id));
    let (trip, plan) = (derived_id(&id, 0), derived_id(&id, 1));
    // The file is in the folder, and the folder shows it.
    assert_eq!(p.parent_of(&trip), ROOT);
    assert_eq!(p.parent_of(&plan), trip);
    assert_eq!(p.names(""), ["Trip"]);
    assert_eq!(p.names("Trip"), ["plan.txt"]);
    let f = Files::new(&p.space);
    let got = f.content(&plan).pop().and_then(|v| v.content);
    assert_eq!(got, Some(Content::Inline(b"hi".to_vec())));
    // Everything the device keeps holds the id: the op as it reads it, and
    // the canonical state.
    let entry = p.space.entry(&id).unwrap();
    match entry.ops()[1].body() {
        cardinal_space::SpaceOpBody::Create { parent, .. } => assert_eq!(*parent, trip),
        other => panic!("{other:?}"),
    }
    let record = record_of(&p.space, &plan);
    assert_eq!(record.get(3).and_then(Value::as_bytes), Some(&trip[..]));
    // The entry keeps its bytes: the op still holds the integer.
    assert_eq!(entry.ops()[1].record().get(2), Some(&Value::from(0u32)));
    let again = cardinal_space::SpaceEntry::decode(&entry.encode()).unwrap();
    assert_eq!(again.id(), id);
    assert_eq!(again.encode(), entry.encode());
    // What is hashed is the varint of the index, not the integer as the
    // op encodes it: for 1 those are the bytes 01 and 08.
    assert_eq!(Value::from(1u32).encode(), [0x08]);
    let mut h = blake3::Hasher::new();
    h.update(&id);
    h.update(&[0x01]);
    assert_eq!(plan, h.finalize().as_bytes()[..16]);
    p.agrees();
}

/// An index that is not smaller than the place of the op holding it, or at
/// which there is no `create`, names nothing; and so does anything that is
/// neither sixteen bytes nor an unsigned integer. The entry is not accepted
/// for state. It is not malformed, and it is as valid as its author's role
/// makes it.
#[test]
fn what_names_no_parent() {
    let mut p = one(72);
    let existing = p.write(vec![folder(ROOT, "docs")]);
    let docs = derived_id(&existing, 0);
    let before = p.space.state().canonical();
    let int = |v: i64| Some(Value::Int(Int::new(v).unwrap()));
    let named = |r: Record| SpaceOp::from_record(r);
    let cases: Vec<(&str, Vec<SpaceOp>)> = vec![
        ("its own place", vec![folder_under(0, "x")]),
        (
            "its own place, further on",
            vec![folder(ROOT, "a"), folder_under(1, "x")],
        ),
        (
            "a place after it",
            vec![folder_under(1, "x"), folder(ROOT, "a")],
        ),
        (
            "a place past the end",
            vec![folder(ROOT, "a"), folder_under(2, "x")],
        ),
        (
            "a control op",
            vec![
                SpaceOp::set_policy(&Policy::default()),
                folder_under(0, "x"),
            ],
        ),
        (
            "a `set`",
            vec![
                SpaceOp::set(docs, 9, Some(Value::from("v"))),
                folder_under(0, "x"),
            ],
        ),
        (
            "a `move`",
            vec![SpaceOp::mv(docs, ROOT, "docs"), folder_under(0, "x")],
        ),
        (
            "an op the profile does not define",
            vec![
                named(Record::new().with(0, 40u32)),
                folder(ROOT, "a"),
                folder_under(0, "x"),
            ],
        ),
        (
            "a `create` that is not one, for want of a kind",
            vec![
                named(Record::new().with(0, 32u32).with(2, ROOT).with(3, "a")),
                folder_under(0, "x"),
            ],
        ),
        (
            "the largest integer there is",
            vec![folder(ROOT, "a"), folder_with_parent(int((1 << 60) - 1))],
        ),
        (
            "an integer that is 0 in 32 bits",
            vec![folder(ROOT, "a"), folder_with_parent(int(1 << 32))],
        ),
        (
            "an integer that is 0 in 16 bits",
            vec![folder(ROOT, "a"), folder_with_parent(int(1 << 16))],
        ),
        (
            "a negative integer",
            vec![folder(ROOT, "a"), folder_with_parent(int(-1))],
        ),
        (
            "text",
            vec![
                folder(ROOT, "a"),
                folder_with_parent(Some(Value::from("0"))),
            ],
        ),
        (
            "fifteen bytes",
            vec![folder_with_parent(Some(Value::from(vec![0u8; 15])))],
        ),
        (
            "seventeen bytes",
            vec![folder_with_parent(Some(Value::from(vec![0u8; 17])))],
        ),
        (
            "thirty-two bytes",
            vec![folder_with_parent(Some(Value::from(vec![0u8; 32])))],
        ),
        (
            "a list",
            vec![
                folder(ROOT, "a"),
                folder_with_parent(Some(Value::list([Value::from(0u32)]))),
            ],
        ),
        ("nothing at all", vec![folder_with_parent(None)]),
        (
            "a `move` to its own place",
            vec![folder(ROOT, "a"), SpaceOp::mv_under(docs, 1, "docs")],
        ),
        (
            "a `move` under an op that is no `create`",
            vec![
                SpaceOp::set(docs, 9, Some(Value::from("w"))),
                SpaceOp::mv_under(docs, 0, "docs"),
            ],
        ),
    ];
    for (what, ops) in cases {
        assert!(!p.accepted(ops), "accepted: a parent that is {what}");
        assert_eq!(p.space.state().canonical(), before, "{what}");
    }
    // and each of those ops, with a parent that is there, is taken
    assert!(p.accepted(vec![folder(ROOT, "a"), folder_under(0, "x")]));
    assert!(p.accepted(vec![
        SpaceOp::set(docs, 9, Some(Value::from("v"))),
        folder(ROOT, "b"),
        folder_under(1, "y"),
        folder_under(2, "z"),
    ]));
    assert_eq!(p.names("b/y"), ["z"]);
    p.agrees();
}

/// An index is a parent, and nothing else. Field 1 of `set`, `move`,
/// `delete` and `restore` holds an id: an integer there, though a `create`
/// stands at that place, names no node. Nor does anything else that is not
/// sixteen bytes.
#[test]
fn only_a_parent_is_named_by_index() {
    let mut p = one(73);
    let existing = p.write(vec![folder(ROOT, "docs")]);
    let docs = derived_id(&existing, 0);
    let mut before = p.space.state().canonical();
    let target = |number: u32, node: Value| {
        let r = Record::new().with(0, number).with(1, node);
        // what a `set` and a `move` need besides
        let r = match number {
            33 => r.with(2, 9u32).with(3, "v"),
            34 => r.with(2, ROOT).with(3, "moved"),
            _ => r,
        };
        SpaceOp::from_record(r)
    };
    let not_ids = [
        ("an integer", Value::from(0u32)),
        ("text", Value::from("docs")),
        ("fifteen bytes", Value::from(docs[..15].to_vec())),
        ("seventeen bytes", Value::from([&docs[..], &[0]].concat())),
    ];
    for (op, number) in [("set", 33), ("move", 34), ("delete", 35), ("restore", 36)] {
        for (what, value) in &not_ids {
            let ops = vec![folder(ROOT, "a"), target(number, value.clone())];
            assert!(!p.accepted(ops), "accepted: a `{op}` of {what}");
            assert_eq!(p.space.state().canonical(), before, "{op} {what}");
        }
        // with the id of a node that is there, it is taken
        let ops = vec![target(number, Value::from(docs))];
        assert!(p.accepted(ops), "a `{op}` of a node");
        before = p.space.state().canonical();
    }
    p.agrees();
}

/// A node that is there is moved under one the same entry creates.
#[test]
fn a_move_under_a_node_the_same_entry_creates() {
    let mut p = one(74);
    let e = p.write(vec![
        files::create_file(ROOT, "a.txt", &Content::Inline(b"a".to_vec()), 0o644, None),
        folder(ROOT, "old"),
    ]);
    let (a_txt, old) = (derived_id(&e, 0), derived_id(&e, 1));
    let e = p.write(vec![
        folder(ROOT, "new"),
        SpaceOp::mv_under(a_txt, 0, "a.txt"),
        folder_under(0, "inner"),
        SpaceOp::mv_under(old, 2, "old"),
    ]);
    assert!(p.space.state().is_accepted(&e));
    let (new, inner) = (derived_id(&e, 0), derived_id(&e, 2));
    assert_eq!(p.parent_of(&a_txt), new);
    assert_eq!(p.parent_of(&inner), new);
    assert_eq!(p.parent_of(&old), inner);
    assert_eq!(p.names(""), ["new"]);
    assert_eq!(p.names("new"), ["a.txt", "inner"]);
    assert_eq!(p.names("new/inner"), ["old"]);
    // the entry that set the position is the one that moved it
    let record = record_of(&p.space, &a_txt);
    assert_eq!(record.get(3).and_then(Value::as_bytes), Some(&new[..]));
    assert_eq!(record.get(7).and_then(Value::as_bytes), Some(&e[..]));
    p.agrees();
}

/// A move that would make a node its own ancestor is skipped, as always,
/// and the entry is taken all the same: a folder is not moved into a folder
/// the same entry made inside it.
#[test]
fn a_cycle_through_a_node_the_same_entry_creates() {
    let mut p = one(75);
    let e = p.write(vec![folder(ROOT, "outer")]);
    let outer = derived_id(&e, 0);
    let e = p.write(vec![
        folder(outer, "inner"),
        SpaceOp::mv_under(outer, 0, "outer"),
        folder_under(0, "deeper"),
        SpaceOp::mv_under(outer, 2, "outer"),
    ]);
    assert!(p.space.state().is_accepted(&e));
    let (inner, deeper) = (derived_id(&e, 0), derived_id(&e, 2));
    assert_eq!(p.parent_of(&outer), ROOT);
    assert_eq!(p.parent_of(&inner), outer);
    assert_eq!(p.parent_of(&deeper), inner);
    assert_eq!(p.names("outer/inner"), ["deeper"]);
    p.agrees();
}

/// `state.md#deletion-yields-to-concurrent-work`: what is beneath a node is
/// read from the delete's causal past and the ops before it in its own
/// entry. So `[move Photos under G, delete G]` in one entry means what the
/// same two ops in two entries would.
#[test]
fn a_delete_takes_what_an_earlier_op_of_its_entry_put_there() {
    for in_one_entry in [true, false] {
        let mut p = one(76);
        let e = p.write(vec![
            folder(ROOT, "Photos"),
            folder(ROOT, "G"),
            folder(ROOT, "Kept"),
        ]);
        let (photos, g, kept) = (derived_id(&e, 0), derived_id(&e, 1), derived_id(&e, 2));
        let e = p.write(vec![files::create_file(
            photos,
            "beach.jpg",
            &Content::Inline(b"x".to_vec()),
            0o644,
            None,
        )]);
        let beach = derived_id(&e, 0);
        let ops = vec![SpaceOp::mv(photos, g, "Photos"), SpaceOp::delete(g)];
        if in_one_entry {
            p.write(ops);
        } else {
            for op in ops {
                p.write(vec![op]);
            }
        }
        for gone in [g, photos, beach] {
            assert_eq!(p.deleted(&gone), (true, false), "one entry: {in_one_entry}");
        }
        assert_eq!(p.deleted(&kept), (false, false));
        assert_eq!(p.names(""), ["Kept"]);
        p.agrees();
    }
}

/// The other way round: what an earlier op of the entry moved out from
/// under the node is not taken with it.
#[test]
fn a_delete_leaves_what_an_earlier_op_of_its_entry_took_away() {
    let mut p = one(77);
    let e = p.write(vec![folder(ROOT, "G")]);
    let g = derived_id(&e, 0);
    let e = p.write(vec![folder(g, "Photos")]);
    let photos = derived_id(&e, 0);
    // and something made under it in the entry itself goes with it
    let e = p.write(vec![
        SpaceOp::mv(photos, ROOT, "Photos"),
        folder(g, "made here"),
        SpaceOp::delete(g),
        folder(g, "made after"),
    ]);
    let (here, after) = (derived_id(&e, 1), derived_id(&e, 3));
    assert_eq!(p.deleted(&g), (true, false));
    assert_eq!(p.deleted(&photos), (false, false));
    assert_eq!(p.deleted(&here), (true, false));
    // what comes after the delete in the entry was not beneath it then
    assert_eq!(p.deleted(&after), (false, false));
    assert_eq!(p.names(""), ["Photos"]);
    p.agrees();
}

/// What is touched is read the same way: someone else changes a file in
/// Photos while this entry moves Photos under G and deletes G. The file is
/// beneath G by the op before the delete, so the delete yields: G stays,
/// flagged, with Photos and the file, as it would had the move and the
/// delete been two entries.
#[test]
fn a_delete_yields_to_work_on_what_an_earlier_op_put_there() {
    for in_one_entry in [true, false] {
        let mut p = one(78);
        let e = p.write(vec![
            folder(ROOT, "Photos"),
            folder(ROOT, "G"),
            folder(ROOT, "Other"),
        ]);
        let (photos, g, other) = (derived_id(&e, 0), derived_id(&e, 1), derived_id(&e, 2));
        let e = p.write(vec![
            files::create_file(
                photos,
                "beach.jpg",
                &Content::Inline(b"x".to_vec()),
                0o644,
                None,
            ),
            folder(g, "old"),
        ]);
        let (beach, old) = (derived_id(&e, 0), derived_id(&e, 1));
        // another device, which has seen none of what follows, edits it
        let edit = files::set_content(beach, &Content::Inline(b"edited".to_vec()));
        // A delete of something nobody else touches comes first, and takes
        // effect; the delete after the move is read with the move done.
        let ops = vec![
            SpaceOp::delete(other),
            SpaceOp::mv(photos, g, "Photos"),
            SpaceOp::delete(g),
        ];
        let mut written = Vec::new();
        if in_one_entry {
            written.push(p.write(ops));
        } else {
            for op in ops {
                written.push(p.write(vec![op]));
            }
        }
        let (concurrent, _) = p
            .space
            .write_concurrent(&p.log, &p.device.signing, &written, vec![edit], None)
            .unwrap();
        assert!(p.space.state().is_accepted(&concurrent));
        // G stays, flagged; so do Photos and the file, which were touched;
        // what nobody touched beneath it goes
        assert_eq!(p.deleted(&g), (false, true), "one entry: {in_one_entry}");
        assert_eq!(p.deleted(&photos), (false, false));
        assert_eq!(p.deleted(&beach), (false, false));
        assert_eq!(p.deleted(&old), (true, false));
        assert_eq!(p.deleted(&other), (true, false));
        assert_eq!(p.names("G/Photos"), ["beach.jpg"]);
        p.agrees();
    }
}

/// `state.md#canonical-state`: values are sorted by the id of the entry that
/// wrote them, and where one entry wrote several, by the place of the op
/// that wrote each.
#[test]
fn values_one_entry_wrote_are_in_the_order_of_its_ops() {
    let mut p = one(79);
    let e = p.write(vec![folder(ROOT, "docs")]);
    let docs = derived_id(&e, 0);
    // written beside, so that none supersedes another; the later ops hold
    // the values that would sort first
    let values = ["m", "z", "a", "k"];
    let ops: Vec<SpaceOp> = values
        .iter()
        .map(|v| SpaceOp::set_beside(docs, 9, Some(Value::from(*v))))
        .collect();
    let e = p.write(ops);
    let record = record_of(&p.space, &docs);
    let fields = record.get(5).and_then(Value::as_list).unwrap();
    let nine = fields.iter().filter_map(Value::as_record);
    let nine = nine.filter(|f| f.get(1).and_then(Value::as_uint) == Some(9));
    let held: Vec<Record> = nine
        .flat_map(|f| f.get(2).and_then(Value::as_list).unwrap().to_vec())
        .map(|v| v.as_record().unwrap().clone())
        .collect();
    let texts: Vec<&str> = held
        .iter()
        .map(|v| v.get(2).and_then(Value::as_text).unwrap())
        .collect();
    assert_eq!(texts, values);
    assert!(held
        .iter()
        .all(|v| v.get(1).and_then(Value::as_bytes) == Some(&e[..])));
    p.agrees();
}
