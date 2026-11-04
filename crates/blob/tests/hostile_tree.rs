//! Index trees a hostile writer could make: the same index or chunk named
//! many times, and entries that cover nothing.

use std::collections::HashSet;
use std::time::Instant;

use cardinal_blob::{
    encrypt, BlobReader, BlobRef, ConvergenceSecret, Encrypted, Index, IndexEntry, MemStore,
    NoFetch, ObjectStore,
};

fn entry(e: &Encrypted, len: u64) -> IndexEntry {
    IndexEntry {
        id: e.id,
        key: e.key,
        len,
    }
}

fn index(
    store: &MemStore,
    secret: &ConvergenceSecret,
    level: u64,
    entries: Vec<IndexEntry>,
) -> Encrypted {
    let e = encrypt(secret, &Index { level, entries }.encode());
    store.put(&e.id, &e.ciphertext).unwrap();
    e
}

/// Three objects, each index naming the one below 3,000 times: a walk of
/// what is held (`contacts::shared_blobs`) should visit three, not nine
/// million. With one more level it is 2.7e10, with five 2.4e17.
#[test]
fn a_walk_visits_each_object_once() {
    let secret = ConvergenceSecret::from_bytes([7; 32]);
    let store = MemStore::new();
    let c = encrypt(&secret, b"x");
    store.put(&c.id, &c.ciphertext).unwrap();
    let z0 = index(&store, &secret, 0, vec![entry(&c, 1); 3000]);
    let z1 = index(&store, &secret, 1, vec![entry(&z0, 3000); 3000]);
    let blob = BlobRef {
        id: z1.id,
        key: z1.key,
        size: 9_000_000,
        levels: 2,
    };
    let mut visits = 0u64;
    let mut distinct = HashSet::new();
    let start = Instant::now();
    BlobReader::new(&store, &NoFetch, blob)
        .for_each_object(|id| {
            visits += 1;
            distinct.insert(*id);
        })
        .unwrap();
    eprintln!(
        "{visits} visits of {} objects in {:?}",
        distinct.len(),
        start.elapsed()
    );
    assert_eq!(visits, distinct.len() as u64, "the walk repeats itself");
}

/// A 20-byte blob whose top index also names, between its two real halves,
/// an index covering nothing that names another 1,000 times, each naming an
/// empty chunk 1,000 times. Reading the 20 bytes should take a few objects'
/// work; it takes a million entries (and with 3,000 and one level more,
/// 2.7e10 entries: some terabytes).
#[test]
fn a_small_blob_reads_with_small_work() {
    let secret = ConvergenceSecret::from_bytes([7; 32]);
    let store = MemStore::new();
    let chunk = |b: &[u8]| {
        let e = encrypt(&secret, b);
        store.put(&e.id, &e.ciphertext).unwrap();
        e
    };
    let (a, b, empty) = (chunk(b"0123456789"), chunk(b"abcdefghij"), chunk(b""));
    let p0 = index(&store, &secret, 0, vec![entry(&a, 10)]);
    let p1 = index(&store, &secret, 1, vec![entry(&p0, 10)]);
    let q0 = index(&store, &secret, 0, vec![entry(&b, 10)]);
    let q1 = index(&store, &secret, 1, vec![entry(&q0, 10)]);
    let z0 = index(&store, &secret, 0, vec![entry(&empty, 0); 1000]);
    let z1 = index(&store, &secret, 1, vec![entry(&z0, 0); 1000]);
    let top = index(
        &store,
        &secret,
        2,
        vec![entry(&p1, 10), entry(&z1, 0), entry(&q1, 10)],
    );
    let blob = BlobRef {
        id: top.id,
        key: top.key,
        size: 20,
        levels: 3,
    };
    let start = Instant::now();
    let got = BlobReader::new(&store, &NoFetch, blob)
        .read_range(0, 1 << 20)
        .unwrap();
    let took = start.elapsed();
    eprintln!("read {} bytes in {took:?}", got.len());
    assert_eq!(got, b"0123456789abcdefghij");
    assert!(
        took.as_millis() < 50,
        "20 bytes took {took:?}: the frontier grew a thousandfold per level"
    );
}
