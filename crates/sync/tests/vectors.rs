//! Generates and checks `vectors/sync.json`.
//!
//! Run with `CARDINAL_WRITE_VECTORS=1` to rewrite the file after an
//! intentional change; otherwise the test fails if the file differs from
//! what this implementation produces.

use cardinal_sync::{
    fingerprint, identity_log_label, BlobReply, BlobRequest, Bundle, Id, MemSet, Message, Mode,
    Range, Reconciler, SetStore, Sum,
};
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
fn fixed32(label: &str) -> Id {
    let mut h = blake3::Hasher::new();
    h.update(b"cardinal test vector ");
    h.update(label.as_bytes());
    *h.finalize().as_bytes()
}

#[test]
fn sync_vectors() {
    let ids: Vec<Id> = (0..40).map(|i| fixed32(&format!("sync id {i}"))).collect();
    let set = MemSet::from_unsorted(ids.clone());
    let fp = |n: usize| {
        let s = MemSet::from_unsorted(ids[..n].to_vec());
        json!({
            "ids": n,
            "sum": hx(s.sum(0, n).to_bytes()),
            "fingerprint": hx(s.fingerprint(0, n)),
        })
    };
    let wrap = Sum::of(&[0xff; 32]).plus(Sum::of(&[0x01; 32]));

    // The initiator's first message for 40 ids, and the responder's reply
    // when it holds the first 20 of them.
    let label = fixed32("sync label");
    let mut ra = Reconciler::new(label, &set);
    let first = ra.initiate();
    let half = MemSet::from_unsorted(ids[..20].to_vec());
    let mut rb = Reconciler::new(label, &half);
    let reply = rb.handle(&first).unwrap().unwrap();
    let small = MemSet::from_unsorted(ids[..3].to_vec());
    let list_first = Reconciler::new(label, &small).initiate();

    let objects = Message::Objects {
        label,
        objects: vec![b"object one".to_vec(), b"object two".to_vec()],
    };
    let range_example = Message::Reconcile {
        label,
        ranges: vec![
            Range {
                upper: Some(ids[0]),
                mode: Mode::Skip,
            },
            Range {
                upper: Some(ids[1]),
                mode: Mode::YouLack(vec![ids[0]]),
            },
            Range {
                upper: None,
                mode: Mode::Fingerprint([7; 16]),
            },
        ],
    };
    let request = BlobRequest {
        ids: vec![ids[0], ids[1]],
    };
    let reply_blob = request.serve(|id| (*id == ids[0]).then(|| b"ciphertext".to_vec()));

    check_or_write(
        "sync.json",
        json!({
            "description": "Sync (sync.md). Ids are BLAKE3(\"cardinal test vector \" || \"sync id {i}\"). sum = sum of ids as 256-bit little-endian integers mod 2^256, 32 bytes LE; fingerprint = first16(BLAKE3(sum || varint(count))). Messages are canonical encodings.",
            "fingerprints": [fp(0), fp(1), fp(2), fp(40)],
            "sum_wraps": {
                "a": hx([0xffu8; 32]),
                "b": hx([0x01u8; 32]),
                "sum": hx(wrap.to_bytes()),
                "fingerprint_count_2": hx(fingerprint(wrap, 2)),
            },
            "identity_log_label": {
                "identity": hx(fixed32("identity")),
                "label": hx(identity_log_label(&fixed32("identity"))),
            },
            "messages": {
                "initiate_40_ids": hx(first.encode()),
                "reply_holding_first_20": hx(reply.encode()),
                "initiate_3_ids": hx(list_first.encode()),
                "ranges_example": hx(range_example.encode()),
                "want": hx(Message::Want { label, ids: vec![ids[0], ids[1]] }.encode()),
                "objects": hx(objects.encode()),
                "heads": hx(Message::Heads { label, ids: vec![ids[2]] }.encode()),
                "blob_request": hx(request.encode()),
                "blob_reply": hx(BlobReply::encode(&reply_blob)),
            },
            "bundle_plain": hx(Bundle::plain(vec![objects]).unwrap().encode()),
        }),
    );
}
