//! Writing and reading blobs end to end.

use std::cell::Cell;
use std::io::{self, Read, Seek, SeekFrom, Write};

use cardinal_blob::{
    chunk_boundaries, encode_bytes, encode_reader, object_id, BlobError, BlobReader, BlobRef,
    BlobWriter, ConvergenceSecret, Fetch, FsStore, Fsync, Id, MemStore, NoFetch, ObjectStore,
    ReuseMap,
};
use proptest::prelude::*;

fn pseudo(n: usize, seed: u64) -> Vec<u8> {
    let mut out = vec![0u8; n];
    let mut h = blake3::Hasher::new();
    h.update(&seed.to_le_bytes());
    h.finalize_xof().fill(&mut out);
    out
}

fn secret() -> ConvergenceSecret {
    ConvergenceSecret::from_epoch_key(&[3u8; 32])
}

/// Fetches from another store, counting requests and objects.
struct StoreFetch<'a> {
    from: &'a MemStore,
    calls: Cell<usize>,
    objects: Cell<usize>,
    corrupt: bool,
}

impl<'a> StoreFetch<'a> {
    fn new(from: &'a MemStore) -> Self {
        StoreFetch {
            from,
            calls: Cell::new(0),
            objects: Cell::new(0),
            corrupt: false,
        }
    }
}

impl Fetch for StoreFetch<'_> {
    fn fetch(&self, ids: &[Id]) -> io::Result<Vec<(Id, Vec<u8>)>> {
        self.calls.set(self.calls.get() + 1);
        let mut out = Vec::new();
        for id in ids {
            if let Some(mut b) = self.from.get(id)? {
                if self.corrupt {
                    b[0] ^= 1;
                }
                self.objects.set(self.objects.get() + 1);
                out.push((*id, b));
            }
        }
        Ok(out)
    }
}

fn write_with_fanout(data: &[u8], fanout: usize, store: &MemStore) -> BlobRef {
    let mut w = BlobWriter::new(&secret(), store).with_index_fanout(fanout);
    // Uneven writes exercise the buffering.
    for part in data.chunks(77_777) {
        w.write_all(part).unwrap();
    }
    w.finish().unwrap().0
}

#[test]
fn round_trip_sizes() {
    for n in [0usize, 1, 1023, 16 * 1024, 300_000, 3_000_000] {
        let data = pseudo(n, n as u64);
        let store = MemStore::new();
        let r = encode_bytes(&data, &secret(), &store).unwrap();
        assert_eq!(r.size, n as u64);
        let chunks = chunk_boundaries(&data).len().max(1);
        assert_eq!(r.levels, if chunks == 1 { 0 } else { 1 });
        let mut reader = BlobReader::new(&store, &NoFetch, r);
        let mut back = Vec::new();
        reader.read_to_end(&mut back).unwrap();
        assert!(back == data, "size {n}");
        // Re-encoding is deterministic and stores nothing new.
        let before = store.usage();
        let (r2, stats) = encode_reader(&data[..], &secret(), &store).unwrap();
        assert_eq!(r2, r);
        assert_eq!(stats.new_objects, 0);
        assert_eq!(store.usage(), before);
    }
}

#[test]
fn reference_encoding() {
    let store = MemStore::new();
    let r = encode_bytes(&pseudo(500_000, 1), &secret(), &store).unwrap();
    assert_eq!(BlobRef::decode(&r.encode()).unwrap(), r);
}

#[test]
fn deep_trees_read_anywhere() {
    let data = pseudo(4_000_000, 7);
    let chunks = chunk_boundaries(&data).len();
    assert!(chunks > 27, "{chunks}");
    for fanout in [2usize, 3, 5] {
        let store = MemStore::new();
        let r = write_with_fanout(&data, fanout, &store);
        let mut levels = 0;
        let mut n = chunks;
        while n > 1 {
            n = n.div_ceil(fanout);
            levels += 1;
        }
        assert_eq!(r.levels, levels);
        let mut reader = BlobReader::new(&store, &NoFetch, r);
        for (off, len) in [
            (0u64, 10usize),
            (65_000, 200_000),
            (3_999_990, 100),
            (1_234_567, 1),
            (0, 4_000_000),
        ] {
            let got = reader.read_range(off, len).unwrap();
            let end = (off as usize + len).min(data.len());
            assert!(
                got == data[off as usize..end],
                "fanout {fanout} {off}+{len}"
            );
        }
        // Every object is reachable by the walk.
        let mut ids = Vec::new();
        reader.for_each_object(|id| ids.push(*id)).unwrap();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len() as u64, store.usage().objects);
    }
}

#[test]
fn fetches_only_what_is_read() {
    let data = pseudo(5_000_000, 11);
    let remote = MemStore::new();
    let r = write_with_fanout(&data, 4, &remote);
    let local = MemStore::new();
    let fetch = StoreFetch::new(&remote);
    let mut reader = BlobReader::new(&local, &fetch, r);
    let mut buf = vec![0u8; 4096];
    reader.seek(SeekFrom::Start(2_500_000)).unwrap();
    reader.read_exact(&mut buf).unwrap();
    assert!(buf == data[2_500_000..2_504_096]);
    // One fetch per index level plus one for the chunk(s).
    assert_eq!(fetch.calls.get() as u64, r.levels + 1);
    let fetched = fetch.objects.get();
    assert!(fetched <= r.levels as usize + 2, "{fetched}");
    assert_eq!(local.usage().objects as usize, fetched);
    // Reading the same range again fetches nothing.
    reader.read_at(2_500_000, &mut buf).unwrap();
    assert_eq!(fetch.objects.get(), fetched);
    // fetch_all completes the local copy.
    reader.fetch_all().unwrap();
    assert_eq!(local.usage(), remote.usage());
}

#[test]
fn corruption_is_detected() {
    let data = pseudo(1_000_000, 5);
    let remote = MemStore::new();
    let r = encode_bytes(&data, &secret(), &remote).unwrap();
    let local = MemStore::new();
    let mut fetch = StoreFetch::new(&remote);
    fetch.corrupt = true;
    let mut reader = BlobReader::new(&local, &fetch, r);
    match reader.read_range(0, 10) {
        Err(BlobError::Missing(id)) => assert_eq!(id, r.id),
        other => panic!("{other:?}"),
    }
    assert_eq!(local.usage().objects, 0);
    // A wrong key fails to decrypt.
    let mut bad = r;
    bad.key[0] ^= 1;
    let mut reader = BlobReader::new(&remote, &NoFetch, bad);
    assert!(matches!(reader.read_range(0, 10), Err(BlobError::Decrypt)));
    // A wrong size is caught against the index.
    let mut bad = r;
    bad.size += 1;
    let mut reader = BlobReader::new(&remote, &NoFetch, bad);
    assert!(matches!(
        reader.read_range(0, 10),
        Err(BlobError::Corrupt(_))
    ));
}

#[test]
fn edit_moves_few_chunks() {
    let mut data = pseudo(8_000_000, 21);
    let store = MemStore::new();
    let (_, first) = encode_reader(&data[..], &secret(), &store).unwrap();
    data.splice(4_000_000..4_000_000, b"inserted text".iter().copied());
    let (_, second) = encode_reader(&data[..], &secret(), &store).unwrap();
    // The chunk(s) around the edit, plus the one index.
    assert!(second.new_objects <= 4, "{second:?}");
    assert!(second.new_objects >= 2);
    assert!(first.chunks > 50);
}

#[test]
fn reuse_after_rotation() {
    let mut data = pseudo(3_000_000, 31);
    let store = MemStore::new();
    let old_secret = ConvergenceSecret::from_epoch_key(&[1; 32]);
    let new_secret = ConvergenceSecret::from_epoch_key(&[2; 32]);
    let (old, _) = encode_reader(&data[..], &old_secret, &store).unwrap();
    data[1_500_000] ^= 0xff;
    let mut reuse = ReuseMap::new();
    reuse.add_blob(&store, &NoFetch, old).unwrap();
    let mut w = BlobWriter::new(&new_secret, &store).with_reuse(&reuse);
    w.write_all(&data).unwrap();
    let (new, stats) = w.finish().unwrap();
    assert_eq!(stats.reused, stats.chunks - 1);
    // One new chunk, one new index.
    assert_eq!(stats.new_objects, 2);
    let back = BlobReader::new(&store, &NoFetch, new)
        .read_range(0, data.len())
        .unwrap();
    assert!(back == data);
}

#[test]
fn fs_store_end_to_end() {
    let r: [u8; 8] = cardinal_crypto::random_bytes();
    let dir = std::env::temp_dir().join(format!("cardinal-blob-e2e-{}", u64::from_le_bytes(r)));
    let data = pseudo(2_000_000, 41);
    {
        let store = FsStore::open(&dir, Fsync::Deferred).unwrap();
        let reference = encode_bytes(&data, &secret(), &store).unwrap();
        let back = BlobReader::new(&store, &NoFetch, reference)
            .read_range(0, data.len())
            .unwrap();
        assert!(back == data);
        for info in store.list().unwrap() {
            let bytes = store.get(&info.id).unwrap().unwrap();
            assert_eq!(object_id(&bytes), info.id);
        }
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn random_ranges(seed in any::<u64>(), n in 0usize..1_500_000, reads in proptest::collection::vec((any::<u64>(), 0usize..300_000), 1..8)) {
        let data = pseudo(n, seed);
        let store = MemStore::new();
        let r = write_with_fanout(&data, 3, &store);
        let mut reader = BlobReader::new(&store, &NoFetch, r);
        for (off, len) in reads {
            let off = if n == 0 { off % 10 } else { off % (n as u64 + 10) };
            let got = reader.read_range(off, len).unwrap();
            let s = (off as usize).min(n);
            let e = (off as usize + len).min(n);
            prop_assert!(got == data[s..e]);
        }
    }
}
