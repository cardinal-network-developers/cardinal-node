//! Throughput measurements. Ignored by default; run in release:
//!
//! ```text
//! cargo test --release -p cardinal-blob --test throughput -- --ignored --nocapture
//! ```

use std::io::Write;
use std::time::Instant;

use cardinal_blob::{
    chunk_boundaries, encrypt, BlobReader, BlobWriter, ConvergenceSecret, FsStore, Fsync, MemStore,
    NoFetch, ObjectStore,
};

const SIZE: usize = 512 << 20;

fn pseudo(n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    blake3::Hasher::new()
        .update(b"throughput")
        .finalize_xof()
        .fill(&mut out);
    out
}

fn report(what: &str, bytes: usize, start: Instant) {
    let s = start.elapsed().as_secs_f64();
    println!(
        "{what:<44} {:>8.0} MB/s  ({:.2} s)",
        bytes as f64 / s / 1e6,
        s
    );
}

#[test]
#[ignore]
fn throughput() {
    let data = pseudo(SIZE);
    let secret = ConvergenceSecret::from_epoch_key(&[9; 32]);

    let t = Instant::now();
    let bounds = chunk_boundaries(&data);
    report("chunk only", SIZE, t);
    println!(
        "  {} chunks, mean {} bytes",
        bounds.len(),
        SIZE / bounds.len()
    );

    let t = Instant::now();
    let mut s = 0;
    for &e in &bounds {
        std::hint::black_box(encrypt(&secret, &data[s..e]));
        s = e;
    }
    report("encrypt only, 1 thread", SIZE, t);

    for threads in [1usize, 8] {
        let store = MemStore::new();
        let t = Instant::now();
        let mut w = BlobWriter::new(&secret, &store).with_threads(threads);
        for part in data.chunks(1 << 20) {
            w.write_all(part).unwrap();
        }
        let (r, _) = w.finish().unwrap();
        report(
            &format!("chunk+encrypt+store (memory), {threads} thread(s)"),
            SIZE,
            t,
        );
        if threads == 8 {
            let t = Instant::now();
            let mut reader = BlobReader::new(&store, &NoFetch, r);
            let mut buf = vec![0u8; 128 << 10];
            let mut off = 0u64;
            while off < r.size {
                off += reader.read_at(off, &mut buf).unwrap() as u64;
            }
            report("sequential read, 128 KiB reads (memory)", SIZE, t);
        }
    }

    for policy in [Fsync::Never, Fsync::Deferred] {
        let r: [u8; 8] = cardinal_crypto::random_bytes();
        let dir = std::env::temp_dir().join(format!("cardinal-tp-{}", u64::from_le_bytes(r)));
        let store = FsStore::open(&dir, policy).unwrap();
        let t = Instant::now();
        let mut w = BlobWriter::new(&secret, &store);
        for part in data.chunks(1 << 20) {
            w.write_all(part).unwrap();
        }
        w.finish().unwrap();
        report(
            &format!("chunk+encrypt+store (disk, fsync {policy:?})"),
            SIZE,
            t,
        );
        assert!(store.usage().bytes > SIZE as u64);
        drop(store);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
