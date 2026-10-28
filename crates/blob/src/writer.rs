//! Streaming blob encoding: chunk, encrypt, store, and index.

use std::collections::{BTreeMap, HashMap};
use std::io::{self, Read, Write};
use std::sync::{mpsc, Mutex};

use crate::chunker::{cut, MAX_SIZE};
use crate::convergent::{encrypt, ConvergenceSecret, Encrypted};
use crate::index::{IndexBuilder, IndexEntry};
use crate::reader::{BlobReader, Fetch};
use crate::store::ObjectStore;
use crate::{BlobError, BlobRef};

/// How many bytes are buffered before a batch of chunks is cut and
/// encrypted. Chunks of one batch are cut, encrypted, and stored in a
/// pipeline.
const BATCH_BYTES: usize = 64 * MAX_SIZE;

/// What writing a blob did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WriteStats {
    /// Chunks in the blob.
    pub chunks: u64,
    /// Chunks whose existing reference was reused ([`ReuseMap`]).
    pub reused: u64,
    /// Chunks and indexes that were new to the store.
    pub new_objects: u64,
    /// Bytes of those new objects.
    pub new_bytes: u64,
}

/// Chunk references of earlier versions of a file, by plaintext hash, so
/// that after an epoch rotation unchanged chunks keep their old reference
/// instead of being re-encrypted (`blobs.md#encryption`).
#[derive(Clone, Default)]
pub struct ReuseMap {
    map: HashMap<[u8; 32], IndexEntry>,
}

impl ReuseMap {
    /// An empty map.
    pub fn new() -> ReuseMap {
        ReuseMap::default()
    }

    /// Records that `plaintext` is already stored as `entry`.
    pub fn insert(&mut self, plaintext: &[u8], entry: IndexEntry) {
        self.map.insert(*blake3::hash(plaintext).as_bytes(), entry);
    }

    /// Adds every chunk of an existing blob, reading (and if necessary
    /// fetching) all of it.
    pub fn add_blob<S: ObjectStore, F: Fetch + ?Sized>(
        &mut self,
        store: S,
        fetch: &F,
        reference: BlobRef,
    ) -> Result<(), BlobError> {
        let mut reader = BlobReader::new(store, fetch, reference);
        reader.for_each_chunk(|entry, plaintext| {
            self.insert(plaintext, entry);
            Ok(())
        })
    }

    /// Number of chunks known.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether no chunks are known.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    fn get(&self, plaintext: &[u8]) -> Option<IndexEntry> {
        if self.map.is_empty() {
            return None;
        }
        self.map
            .get(blake3::hash(plaintext).as_bytes())
            .filter(|e| e.len == plaintext.len() as u64)
            .copied()
    }
}

/// Writes a blob from a byte stream. Implements [`Write`]; call
/// [`finish`](BlobWriter::finish) for the reference.
///
/// Memory use is bounded by one batch of chunks (16 MiB) plus one partial
/// index per tree level, whatever the blob's size.
pub struct BlobWriter<'r, S: ObjectStore> {
    store: S,
    secret: ConvergenceSecret,
    reuse: Option<&'r ReuseMap>,
    buf: Vec<u8>,
    builder: IndexBuilder,
    stats: WriteStats,
    threads: usize,
}

impl<'r, S: ObjectStore> BlobWriter<'r, S> {
    /// A writer that stores chunks and indexes in `store`.
    pub fn new(secret: &ConvergenceSecret, store: S) -> BlobWriter<'r, S> {
        let threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .min(8);
        BlobWriter {
            store,
            secret: secret.clone(),
            reuse: None,
            // grown on demand: most blobs are small, and a batch-sized
            // buffer per blob costs more than encoding a small one
            buf: Vec::new(),
            builder: IndexBuilder::new(),
            stats: WriteStats::default(),
            threads,
        }
    }

    /// Reuse the references of chunks already known (see [`ReuseMap`]).
    pub fn with_reuse(mut self, reuse: &'r ReuseMap) -> BlobWriter<'r, S> {
        self.reuse = Some(reuse);
        self
    }

    /// Use `n` encryption threads (at least 1), besides the chunking
    /// thread and the calling thread, which stores.
    pub fn with_threads(mut self, n: usize) -> BlobWriter<'r, S> {
        self.threads = n.max(1);
        self
    }

    /// Builds indexes of at most `n` entries instead of 3,000, so tests can
    /// make deep trees from little data. The result is not a valid blob of
    /// the specification unless `n` is 3,000.
    #[doc(hidden)]
    pub fn with_index_fanout(mut self, n: usize) -> BlobWriter<'r, S> {
        assert_eq!(self.builder.size(), 0, "set the fanout before writing");
        self.builder = IndexBuilder::with_fanout(n);
        self
    }

    /// Bytes written so far.
    pub fn size(&self) -> u64 {
        self.builder.size() + self.buf.len() as u64
    }

    /// Cuts and processes every chunk that is complete; at the end of the
    /// content, all of them.
    ///
    /// A pipeline: one thread cuts chunks, worker threads encrypt them, and
    /// this thread stores them and builds the index, in order.
    fn process(&mut self, eof: bool) -> Result<(), BlobError> {
        let buf = &self.buf[..];
        let more = |s: usize| {
            let rest = buf.len() - s;
            rest > 0 && (eof || rest >= MAX_SIZE)
        };
        if !more(0) {
            return Ok(());
        }
        if eof && buf.len() <= MAX_SIZE {
            return self.process_small();
        }
        let reuse = self.reuse;
        let secret = &self.secret;
        let store = &self.store;
        let builder = &mut self.builder;
        let stats = &mut self.stats;
        let workers = self.threads;
        type Job = (usize, usize, usize);
        // (sequence, entry, reused, newly stored bytes)
        type Done = (usize, Result<(IndexEntry, bool, Option<u64>), BlobError>);
        let (job_tx, job_rx) = mpsc::sync_channel::<Job>(workers * 4);
        let job_rx = Mutex::new(job_rx);
        let job_rx = &job_rx;
        let consumed = std::thread::scope(|sc| -> Result<usize, BlobError> {
            let (done_tx, done_rx) = mpsc::channel::<Done>();
            let cutter = sc.spawn(move || {
                let mut s = 0;
                let mut seq = 0;
                while more(s) {
                    let end = (s + MAX_SIZE).min(buf.len());
                    let n = cut(&buf[s..end]);
                    if job_tx.send((seq, s, s + n)).is_err() {
                        break;
                    }
                    seq += 1;
                    s += n;
                }
                s
            });
            for _ in 0..workers {
                let done_tx = done_tx.clone();
                sc.spawn(move || loop {
                    let job = job_rx.lock().unwrap().recv();
                    let Ok((seq, a, b)) = job else { break };
                    let c = &buf[a..b];
                    let r = match reuse.and_then(|r| r.get(c)) {
                        Some(e) => Ok((e, true, None)),
                        None => {
                            let enc = encrypt(secret, c);
                            let entry = IndexEntry {
                                id: enc.id,
                                key: enc.key,
                                len: c.len() as u64,
                            };
                            store
                                .put(&enc.id, &enc.ciphertext)
                                .map(|new| {
                                    (entry, false, new.then_some(enc.ciphertext.len() as u64))
                                })
                                .map_err(BlobError::from)
                        }
                    };
                    if done_tx.send((seq, r)).is_err() {
                        break;
                    }
                });
            }
            drop(done_tx);
            let mut sink = |e: Encrypted| -> Result<(), BlobError> {
                if store.put(&e.id, &e.ciphertext)? {
                    stats.new_objects += 1;
                    stats.new_bytes += e.ciphertext.len() as u64;
                }
                Ok(())
            };
            let mut chunks = 0u64;
            let mut reused = 0u64;
            let mut new_chunks = 0u64;
            let mut new_bytes = 0u64;
            let mut handle = |r: Result<(IndexEntry, bool, Option<u64>), BlobError>| {
                let (entry, was_reused, stored) = r?;
                chunks += 1;
                reused += was_reused as u64;
                if let Some(n) = stored {
                    new_chunks += 1;
                    new_bytes += n;
                }
                builder.push(entry, secret, &mut sink)
            };
            let mut pending = BTreeMap::new();
            let mut next = 0;
            let mut first_err = None;
            for (seq, r) in done_rx {
                pending.insert(seq, r);
                while let Some(r) = pending.remove(&next) {
                    if first_err.is_none() {
                        first_err = handle(r).err();
                    }
                    next += 1;
                }
            }
            let consumed = cutter.join().expect("chunking thread panicked");

            stats.chunks += chunks;
            stats.reused += reused;
            stats.new_objects += new_chunks;
            stats.new_bytes += new_bytes;
            match first_err {
                Some(e) => Err(e),
                None => Ok(consumed),
            }
        })?;
        self.buf.drain(..consumed);
        Ok(())
    }

    /// [`process`](Self::process) for the last bytes of a blob when they
    /// fit one chunk's maximum: on this thread, since starting the
    /// pipeline's threads costs more than the work.
    fn process_small(&mut self) -> Result<(), BlobError> {
        let buf = std::mem::take(&mut self.buf);
        let mut s = 0;
        while s < buf.len() {
            let n = cut(&buf[s..]);
            let c = &buf[s..s + n];
            s += n;
            self.stats.chunks += 1;
            let entry = match self.reuse.and_then(|r| r.get(c)) {
                Some(e) => {
                    self.stats.reused += 1;
                    e
                }
                None => {
                    let enc = encrypt(&self.secret, c);
                    if self.store.put(&enc.id, &enc.ciphertext)? {
                        self.stats.new_objects += 1;
                        self.stats.new_bytes += enc.ciphertext.len() as u64;
                    }
                    IndexEntry {
                        id: enc.id,
                        key: enc.key,
                        len: c.len() as u64,
                    }
                }
            };
            let store = &self.store;
            let stats = &mut self.stats;
            let mut sink = |e: Encrypted| -> Result<(), BlobError> {
                if store.put(&e.id, &e.ciphertext)? {
                    stats.new_objects += 1;
                    stats.new_bytes += e.ciphertext.len() as u64;
                }
                Ok(())
            };
            self.builder.push(entry, &self.secret, &mut sink)?;
        }
        Ok(())
    }

    /// Completes the blob and returns its reference and statistics.
    pub fn finish(mut self) -> Result<(BlobRef, WriteStats), BlobError> {
        self.process(true)?;
        let store = &self.store;
        let stats = &mut self.stats;
        let mut sink = |e: Encrypted| -> Result<(), BlobError> {
            if store.put(&e.id, &e.ciphertext)? {
                stats.new_objects += 1;
                stats.new_bytes += e.ciphertext.len() as u64;
            }
            Ok(())
        };
        let r = self.builder.finish(&self.secret, &mut sink)?;
        self.store.sync()?;
        Ok((r, self.stats))
    }
}

impl<S: ObjectStore> Write for BlobWriter<'_, S> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let want = self.buf.len() + data.len();
        if want > MAX_SIZE && self.buf.capacity() < BATCH_BYTES + MAX_SIZE {
            // a large blob: buffer whole batches
            self.buf
                .reserve_exact(BATCH_BYTES + MAX_SIZE - self.buf.len());
        }
        self.buf.extend_from_slice(data);
        if self.buf.len() >= BATCH_BYTES {
            self.process(false)?;
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Encodes everything `reader` yields as a blob in `store`.
pub fn encode_reader<S: ObjectStore, R: Read>(
    mut reader: R,
    secret: &ConvergenceSecret,
    store: S,
) -> Result<(BlobRef, WriteStats), BlobError> {
    let mut w = BlobWriter::new(secret, store);
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        w.write_all(&buf[..n])?;
    }
    w.finish()
}

/// Encodes `data` as a blob in `store` and returns its reference.
pub fn encode_bytes<S: ObjectStore>(
    data: &[u8],
    secret: &ConvergenceSecret,
    store: S,
) -> Result<BlobRef, BlobError> {
    let mut w = BlobWriter::new(secret, store);
    w.write_all(data)?;
    Ok(w.finish()?.0)
}
