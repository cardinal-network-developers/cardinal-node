//! Generates and checks `vectors/state.json`.
//!
//! Run with `CARDINAL_WRITE_VECTORS=1` to rewrite the file after an
//! intentional change; otherwise the test fails if the file differs from
//! what this implementation produces.

use cardinal_crypto::SigningKey;
use cardinal_encoding::{Record, Value};
use cardinal_space::entry::derived_id;
use cardinal_space::{SpaceEntryBuilder, SpaceOp, SpaceOpBody, ROOT};
use serde_json::{json, Value as Json};

fn check_or_write(name: &str, value: Json) {
    let text = serde_json::to_string_pretty(&value).unwrap() + "\n";
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors")
        .join(name);
    if std::env::var_os("CARDINAL_WRITE_VECTORS").is_some() {
        std::fs::write(&path, text).unwrap();
        return;
    }
    let existing = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}; run with CARDINAL_WRITE_VECTORS=1", path.display()));
    assert!(
        existing == text,
        "{} is out of date with the implementation",
        path.display()
    );
}

fn hx(b: impl AsRef<[u8]>) -> String {
    hex::encode(b)
}

/// `BLAKE3("cardinal test vector " || label)`.
fn fixed32(label: &str) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"cardinal test vector ");
    h.update(label.as_bytes());
    *h.finalize().as_bytes()
}

/// The example of `state.md#a-node-made-in-the-same-entry`: one entry of a
/// files space makes a folder under the root and a file in that folder,
/// which it names by the index of the op that makes the folder.
#[test]
fn state_vectors() {
    let seed = fixed32("state signer");
    let key = SigningKey::from_seed(&seed);
    let space = fixed32("state space");
    let parent = fixed32("state parent entry");
    let author = fixed32("state author");
    let head = fixed32("state author log head");
    let epoch: [u8; 16] = fixed32("state epoch")[..16].try_into().unwrap();
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
                .with(4, Record::new().with(1, Value::from(b"hi".to_vec()))),
        ),
    ];
    let op_list = Value::list(ops.iter().map(|o| o.record().clone()));
    let entry = SpaceEntryBuilder::new(space, &[parent], author, head, epoch)
        .ops(ops)
        .time(1_700_000_000_000)
        .sign(&key)
        .unwrap();
    let id = entry.id();
    let (trip, plan) = (derived_id(&id, 0), derived_id(&id, 1));
    // the file's parent, as the device holds it, is the folder's id
    match entry.ops()[1].body() {
        SpaceOpBody::Create { parent, .. } => assert_eq!(*parent, trip),
        other => panic!("{other:?}"),
    }
    let varint_of = |index: u8| -> Vec<u8> {
        // below 128 a varint is the one byte
        assert!(index < 128);
        vec![index]
    };
    let node = |index: u8, name: &str, node_id: [u8; 16], parent: [u8; 16]| {
        let mut h = blake3::Hasher::new();
        h.update(&id);
        h.update(&varint_of(index));
        assert_eq!(node_id, h.finalize().as_bytes()[..16]);
        json!({
            "index": index,
            "name": name,
            "varint_of_the_index": hx(varint_of(index)),
            "the_index_as_an_op_would_encode_it": hx(Value::from(u32::from(index)).encode()),
            "id": hx(node_id),
            "parent": hx(parent),
        })
    };
    let vectors = json!({
        "description": "A node made in the same entry (state.md#a-node-made-in-the-same-entry). \
            One entry of a files space with two ops: a `create` of a folder under the root, and \
            a `create` of a file whose field 2 is the integer 0, the index of the first op. A \
            node's id is the first 16 bytes of BLAKE3(entry id || varint(index)), where the \
            entry id is the id of the signed object (encoding.md#signed-objects). What is \
            hashed is the varint of the index, not the integer as the op encodes it: for index \
            1 those are the bytes 01 and 08. The file's parent is the id of the node made at \
            index 0. Inputs are fixed bytes, not secrets.",
        "signer_seed": hx(seed),
        "ops": op_list.to_string(),
        "ops_encoding": hx(op_list.encode()),
        "entry": hx(entry.encode()),
        "entry_id": hx(id),
        "nodes": [
            node(0, "Trip", trip, ROOT),
            node(1, "plan.txt", plan, trip),
        ],
        "a_restore": restore_vector(&key, author, head, epoch),
    });
    check_or_write("state.json", vectors);
}

/// The example of `state.md#deletion-yields-to-concurrent-work`: a delete
/// flags only what is not already deleted, and a restore clears the flags
/// its delete set, and no others.
fn restore_vector(key: &SigningKey, author: [u8; 32], head: [u8; 32], epoch: [u8; 16]) -> Json {
    use cardinal_identity::dag::Dag;
    use cardinal_space::files::{self, Content};
    use cardinal_space::{Profile, SpaceEntry, State};
    use std::collections::HashSet;

    let mut dag: Dag<SpaceEntry> = Dag::new();
    // a genesis with no ops, whose id is the space's
    let genesis = SpaceEntryBuilder::genesis(author, head, epoch)
        .time(1_700_000_100_000)
        .sign(key)
        .unwrap();
    let space = genesis.id();
    dag.insert(space, Vec::new(), genesis);
    let mut time = 1_700_000_100_000u64;
    let mut write = |dag: &mut Dag<SpaceEntry>, parents: &[[u8; 32]], ops: Vec<SpaceOp>| {
        time += 1000;
        let e = SpaceEntryBuilder::new(space, parents, author, head, epoch)
            .ops(ops)
            .time(time)
            .sign(key)
            .unwrap();
        let id = e.id();
        dag.insert(id, parents.to_vec(), e);
        id
    };
    let e1 = write(&mut dag, &[space], vec![files::create_folder(ROOT, "Trip")]);
    let trip = derived_id(&e1, 0);
    let e2 = write(
        &mut dag,
        &[e1],
        ["a", "b", "c"]
            .iter()
            .map(|n| {
                files::create_file(
                    trip,
                    n,
                    &Content::Inline(n.as_bytes().to_vec()),
                    0o644,
                    None,
                )
            })
            .collect(),
    );
    let [a, b, c] = [0, 1, 2].map(|i| derived_id(&e2, i));
    let e3 = write(&mut dag, &[e2], vec![SpaceOp::delete(c)]);
    let e4 = write(&mut dag, &[e3], vec![SpaceOp::delete(trip)]);
    let state_of = |dag: &Dag<SpaceEntry>| {
        let valid: HashSet<_> = dag.log_order().iter().copied().collect();
        State::compute(Profile::FILES, dag, &valid)
    };
    let flags_of = |st: &State, named: &[(&str, [u8; 16])]| -> Json {
        let mut out = serde_json::Map::new();
        for (name, id) in named {
            let n = st.node(id).unwrap();
            out.insert(
                (*name).into(),
                json!({"id": hx(id), "deleted": n.deleted, "delete_conflict": n.delete_conflict}),
            );
        }
        Json::Object(out)
    };
    let named = [("Trip", trip), ("a", a), ("b", b), ("c", c)];
    let flags = |st: &State| flags_of(st, &named);
    // Two deletes stand after e4: each deleted node's record numbers the
    // delete that took it, from 1 in the order the records list the first
    // node each took.
    let taken = state_of(&dag);
    let taken_canonical = taken.canonical();
    let number_of = |id: [u8; 16]| -> u64 {
        let list = taken_canonical.list(1).unwrap();
        let r = list
            .iter()
            .filter_map(|v| v.as_record())
            .find(|r| r.bytes(1).ok() == Some(&id[..]))
            .unwrap();
        r.uint(6).unwrap()
    };
    let numbers: serde_json::Map<String, Json> = named
        .iter()
        .map(|(name, id)| ((*name).into(), json!(number_of(*id))))
        .collect();
    assert_eq!(number_of(trip), number_of(a));
    assert_eq!(number_of(trip), number_of(b));
    assert_ne!(number_of(trip), number_of(c));
    let in_successor = successor_vector(key, author, head, epoch, &taken, [trip, a, b, c]);
    let e5 = write(&mut dag, &[e4], vec![SpaceOp::restore(trip)]);
    let after_restore = state_of(&dag);
    assert!(after_restore.node(&c).unwrap().deleted);
    assert!(!after_restore.node(&a).unwrap().deleted);
    let then = flags(&after_restore);
    let canonical = after_restore.canonical().encode();
    // then, both on e5: one restores c, the other deletes Trip
    let e6 = write(&mut dag, &[e5], vec![SpaceOp::restore(c)]);
    let e7 = write(&mut dag, &[e5], vec![SpaceOp::delete(trip)]);
    let both = state_of(&dag);
    assert!(!both.node(&trip).unwrap().deleted && !both.node(&c).unwrap().deleted);
    assert!(both.node(&a).unwrap().deleted);
    let entries: Vec<String> = [space, e1, e2, e3, e4, e5, e6, e7]
        .iter()
        .map(|id| hx(dag.get(id).unwrap().encode()))
        .collect();
    json!({
        "description": "A restore clears the flags its delete set, and no others \
            (state.md#deletion-yields-to-concurrent-work). A files space signed as the example \
            above is, whose genesis (the first of `entries`) has no ops, and seven entries \
            after it: e1 makes the folder Trip, e2 the files a, b and c \
            in it, e3 deletes c, e4 deletes Trip, and e5 restores Trip, each after the one \
            before. e4 flags Trip, a and b, and not c, which e3 had flagged. In the canonical \
            state after e4 (`after_deletes_canonical`), field 6 of each deleted node's record \
            is the number of the delete that took it, the same for every node one delete \
            took, counted from 1 in the order the records, sorted by node id, list the first \
            node each delete took, and 0 for a node not deleted: `after_deletes_numbers`. After e5 Trip, \
            a and b are back and c is still deleted: `after_restore` gives each node's flags \
            and `after_restore_canonical` the canonical state's encoding. Then e6 restores c \
            and e7 deletes Trip, both after e5 and so concurrent: the restore names c, which \
            touches c and everything above it, so the delete yields there; `after_both` has \
            Trip and c not deleted, Trip with a delete conflict, and a and b deleted, \
            `after_both_root` the canonical state's BLAKE3.",
        "entries": entries,
        "after_deletes_canonical": hx(taken_canonical.encode()),
        "after_deletes_numbers": Json::Object(numbers),
        "in_a_successor": in_successor,
        "after_restore": then,
        "after_restore_canonical": hx(canonical),
        "after_both": flags(&both),
        "after_both_root": hx(both.root_hash()),
    })
}

/// A restore in a successor undoes exactly one delete: the successor
/// starts from the canonical state after e4, which numbers the two deletes
/// that stand, and its first entry restores Trip, which brings back what
/// the same delete took (a and b) and not c. Then a delete of Trip, a file
/// d made in Trip after it, and a second delete of Trip, which does nothing
/// since Trip is deleted already; a restore of Trip brings back d with it.
fn successor_vector(
    key: &SigningKey,
    author: [u8; 32],
    head: [u8; 32],
    epoch: [u8; 16],
    initial: &cardinal_space::State,
    [trip, a, b, c]: [[u8; 16]; 4],
) -> Json {
    use cardinal_identity::dag::Dag;
    use cardinal_space::files::{self, Content};
    use cardinal_space::{Profile, SpaceEntry, State};
    use std::collections::HashSet;

    let initial = State::from_canonical(Profile::FILES, &initial.canonical()).unwrap();
    let mut dag: Dag<SpaceEntry> = Dag::new();
    let genesis = SpaceEntryBuilder::genesis(author, head, epoch)
        .time(1_700_000_200_000)
        .sign(key)
        .unwrap();
    let space = genesis.id();
    dag.insert(space, Vec::new(), genesis);
    let mut time = 1_700_000_200_000u64;
    let mut last = space;
    let mut write = |dag: &mut Dag<SpaceEntry>, ops: Vec<SpaceOp>| {
        time += 1000;
        let e = SpaceEntryBuilder::new(space, &[last], author, head, epoch)
            .ops(ops)
            .time(time)
            .sign(key)
            .unwrap();
        let id = e.id();
        dag.insert(id, vec![last], e);
        last = id;
        id
    };
    let state_of = |dag: &Dag<SpaceEntry>| {
        let valid: HashSet<_> = dag.log_order().iter().copied().collect();
        State::compute_from(Profile::FILES, Some(&initial), dag, &valid)
    };
    let deleted = |st: &State, n: &[u8; 16]| st.node(n).unwrap().deleted;
    let s1 = write(&mut dag, vec![SpaceOp::restore(trip)]);
    let restored = state_of(&dag);
    assert!(!deleted(&restored, &trip) && !deleted(&restored, &a) && !deleted(&restored, &b));
    assert!(deleted(&restored, &c), "another delete took c");
    let s2 = write(&mut dag, vec![SpaceOp::delete(trip)]);
    let s3 = write(
        &mut dag,
        vec![files::create_file(
            trip,
            "d",
            &Content::Inline(b"d".to_vec()),
            0o644,
            None,
        )],
    );
    let d = derived_id(&s3, 0);
    let s4 = write(&mut dag, vec![SpaceOp::delete(trip)]);
    let twice = state_of(&dag);
    assert!(deleted(&twice, &trip) && !deleted(&twice, &d));
    let s5 = write(&mut dag, vec![SpaceOp::restore(trip)]);
    let back = state_of(&dag);
    assert!([trip, a, b, d].iter().all(|n| !deleted(&back, n)));
    assert!(deleted(&back, &c));
    let entries: Vec<String> = [space, s1, s2, s3, s4, s5]
        .iter()
        .map(|id| hx(dag.get(id).unwrap().encode()))
        .collect();
    let flags = |st: &State| -> Json {
        let named = [("Trip", trip), ("a", a), ("b", b), ("c", c), ("d", d)];
        let mut out = serde_json::Map::new();
        for (name, id) in named {
            if let Some(n) = st.node(&id) {
                out.insert(name.into(), json!({"id": hx(id), "deleted": n.deleted}));
            }
        }
        Json::Object(out)
    };
    json!({
        "description": "A successor whose initial state is `after_deletes_canonical`, and \
            whose genesis (the first of `entries`) has no ops. s1 restores Trip: Trip, a and b \
            are back, and c, which another delete took, is not (`after_s1`). s2 deletes Trip, \
            s3 makes the file d in it, and s4 deletes Trip again, which does nothing, since \
            Trip is deleted already (state.md#deletion-yields-to-concurrent-work): d is not \
            flagged (`after_s4`). s5 restores Trip, and d comes back with it (`after_s5`), \
            whose canonical state's BLAKE3 is `after_s5_root`.",
        "entries": entries,
        "after_s1": flags(&restored),
        "after_s4": flags(&twice),
        "after_s5": flags(&back),
        "after_s5_root": hx(back.root_hash()),
    })
}
