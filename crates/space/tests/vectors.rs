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
    });
    check_or_write("state.json", vectors);
}
