//! Generates and checks `vectors/blob.json`.
//!
//! Run with `CARDINAL_WRITE_VECTORS=1` to rewrite the file after an
//! intentional change; otherwise the test fails if the file differs from
//! what this implementation produces.

use cardinal_blob::chunker::{MASK_EASY, MASK_HARD};
use cardinal_blob::{
    chunk_boundaries, encode_bytes, encrypt, gear, ConvergenceSecret, Encrypted, Index,
    IndexBuilder, IndexEntry, MemStore, ObjectStore, AVG_SIZE, MAX_SIZE, MIN_SIZE,
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

/// Deterministic test inputs: `BLAKE3("cardinal test vector " || label)`
/// extended to `n` bytes.
fn fixed(label: &str, n: usize) -> Vec<u8> {
    let mut h = blake3::Hasher::new();
    h.update(b"cardinal test vector ");
    h.update(label.as_bytes());
    let mut out = vec![0u8; n];
    h.finalize_xof().fill(&mut out);
    out
}

fn chunk_vectors(data: &[u8], secret: &ConvergenceSecret) -> Vec<Json> {
    let mut start = 0;
    chunk_boundaries(data)
        .into_iter()
        .map(|end| {
            let pt = &data[start..end];
            let e = encrypt(secret, pt);
            let v = json!({
                "offset": start,
                "length": end - start,
                "plaintext_blake3": hx(blake3::hash(pt).as_bytes()),
                "key": hx(e.key),
                "id": hx(e.id),
            });
            start = end;
            v
        })
        .collect()
}

#[test]
fn blob_vectors() {
    let g = gear();
    let mut table = Vec::with_capacity(256 * 8);
    for v in g.iter() {
        table.extend_from_slice(&v.to_le_bytes());
    }

    let epoch_key: [u8; 32] = fixed("blob epoch key", 32).try_into().unwrap();
    let secret = ConvergenceSecret::from_epoch_key(&epoch_key);

    // Small single chunk, with its full ciphertext.
    let hello = encrypt(&secret, b"hello, cardinal");
    let public = encrypt(&ConvergenceSecret::public(), b"hello, cardinal");
    let empty_store = MemStore::new();
    let empty_ref = encode_bytes(b"", &secret, &empty_store).unwrap();

    // Pseudorandom input of several chunks: boundaries, ids, keys, and the
    // index and reference.
    let data = fixed("blob input", 1_500_000);
    let store = MemStore::new();
    let reference = encode_bytes(&data, &secret, &store).unwrap();
    let boundaries = chunk_boundaries(&data);
    let top = store.get(&reference.id).unwrap().unwrap();
    let index_pt = cardinal_blob::decrypt(&reference.key, &top).unwrap();
    let index = Index::decode(&index_pt).unwrap();
    assert_eq!(index.entries.len(), boundaries.len());

    // Low-entropy input: zeros.
    let zeros = vec![0u8; 700_000];
    let zero_bounds = chunk_boundaries(&zeros);

    // Index tree over 3,001 synthetic chunk entries: two level-0 indexes
    // (3,000 and 1 entries) under one level-1 index.
    let mut b = IndexBuilder::new();
    let mut emitted: Vec<Json> = Vec::new();
    let mut sink = |e: Encrypted| {
        emitted.push(
            json!({ "id": hx(e.id), "key": hx(e.key), "ciphertext_length": e.ciphertext.len() }),
        );
        Ok(())
    };
    for i in 0u64..3001 {
        let id: [u8; 32] = fixed(&format!("synthetic chunk id {i}"), 32)
            .try_into()
            .unwrap();
        let key: [u8; 32] = fixed(&format!("synthetic chunk key {i}"), 32)
            .try_into()
            .unwrap();
        b.push(
            IndexEntry {
                id,
                key,
                len: 65536 + i,
            },
            &secret,
            &mut sink,
        )
        .unwrap();
    }
    let synthetic_ref = b.finish(&secret, &mut sink).unwrap();

    check_or_write(
        "blob.json",
        json!({
            "description": "Blobs (blobs.md). gear[i] = first 8 bytes LE of BLAKE3(\"cardinal 1 gear\" || byte(i)) for i in 0..=255; gear_table_blake3 is BLAKE3 of the 256 entries as consecutive 8-byte little-endian words. Inputs are BLAKE3(\"cardinal test vector \" || label) extended to the given length. convergence secret = derive(\"convergence\", epoch key); key = BLAKE3.keyed_hash(secret, plaintext); ciphertext = ChaCha20-Poly1305(key, zero nonce, empty aad); id = BLAKE3(ciphertext). Index entry length for an index is the blob bytes it covers; an index naming level-L indexes has level L+1.",
            "chunking": {
                "min": MIN_SIZE,
                "avg": AVG_SIZE,
                "max": MAX_SIZE,
                "mask_hard": format!("{MASK_HARD:016x}"),
                "mask_easy": format!("{MASK_EASY:016x}"),
                "gear_first": [format!("{:016x}", g[0]), format!("{:016x}", g[1]), format!("{:016x}", g[2]), format!("{:016x}", g[3])],
                "gear_last": format!("{:016x}", g[255]),
                "gear_table_blake3": hx(blake3::hash(&table).as_bytes()),
            },
            "epoch_key": hx(epoch_key),
            "convergence_secret": hx(secret.as_bytes()),
            "single_chunk": {
                "plaintext": "hello, cardinal",
                "key": hx(hello.key),
                "ciphertext": hx(&hello.ciphertext),
                "id": hx(hello.id),
                "public_key": hx(public.key),
                "public_id": hx(public.id),
            },
            "empty_blob_reference": hx(empty_ref.encode()),
            "pseudorandom": {
                "label": "blob input",
                "length": data.len(),
                "boundaries": boundaries,
                "chunks": chunk_vectors(&data, &secret),
                "index_plaintext_blake3": hx(blake3::hash(&index_pt).as_bytes()),
                "index_plaintext_length": index_pt.len(),
                "reference": {
                    "id": hx(reference.id),
                    "key": hx(reference.key),
                    "size": reference.size,
                    "levels": reference.levels,
                    "encoding": hx(reference.encode()),
                },
            },
            "zeros": {
                "length": zeros.len(),
                "boundaries": zero_bounds,
            },
            "synthetic_tree": {
                "description": "3,001 entries; chunk i has id fixed(\"synthetic chunk id {i}\"), key fixed(\"synthetic chunk key {i}\"), length 65536 + i. Indexes listed in the order they complete.",
                "indexes": emitted,
                "reference": hx(synthetic_ref.encode()),
                "levels": synthetic_ref.levels,
            },
        }),
    );
}
