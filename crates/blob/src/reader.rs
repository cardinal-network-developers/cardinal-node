//! Random-access reading of blobs, fetching missing objects on demand.

use std::collections::HashMap;
use std::io::{self, Read, Seek, SeekFrom};
use std::sync::Arc;

use crate::convergent::decrypt;
use crate::index::{Index, IndexEntry};
use crate::store::ObjectStore;
use crate::{object_id, BlobError, BlobRef, Id};

/// Fetches objects (chunks and indexes) by id from elsewhere: peers over
/// the link `blob` service, a host, or a bundle.
///
/// The reader verifies `BLAKE3(ciphertext) == id` for everything returned
/// and stores it, so implementations need not.
pub trait Fetch {
    /// Fetches what it can of `ids`. Objects it cannot obtain are simply
    /// left out of the result. Implementations split large requests as
    /// their transport requires (the `blob` service takes 64 ids).
    fn fetch(&self, ids: &[Id]) -> io::Result<Vec<(Id, Vec<u8>)>>;
}

impl<F: Fetch + ?Sized> Fetch for &F {
    fn fetch(&self, ids: &[Id]) -> io::Result<Vec<(Id, Vec<u8>)>> {
        (**self).fetch(ids)
    }
}

/// A [`Fetch`] that obtains nothing: reads use only the local store.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoFetch;

impl Fetch for NoFetch {
    fn fetch(&self, _ids: &[Id]) -> io::Result<Vec<(Id, Vec<u8>)>> {
        Ok(Vec::new())
    }
}

/// How many decoded indexes a reader keeps.
const INDEX_CACHE: usize = 32;
/// How many chunks a reader loads per fetch while walking a whole blob.
const WALK_BATCH: usize = 64;

/// Reads a blob through its reference. Also implements [`Read`] and
/// [`Seek`] from an internal position.
///
/// Every object read is checked: ids against ciphertexts, AEAD tags,
/// index levels, and that lengths add up to the reference's size.
pub struct BlobReader<'f, S: ObjectStore, F: Fetch + ?Sized> {
    store: S,
    fetch: &'f F,
    reference: BlobRef,
    indexes: HashMap<Id, Arc<Index>>,
    last_chunk: Option<(Id, Arc<Vec<u8>>)>,
    pos: u64,
}

impl<'f, S: ObjectStore, F: Fetch + ?Sized> BlobReader<'f, S, F> {
    /// A reader of `reference`, using `store` and fetching what it lacks
    /// through `fetch`.
    pub fn new(store: S, fetch: &'f F, reference: BlobRef) -> BlobReader<'f, S, F> {
        BlobReader {
            store,
            fetch,
            reference,
            indexes: HashMap::new(),
            last_chunk: None,
            pos: 0,
        }
    }

    /// The blob's plaintext length.
    pub fn size(&self) -> u64 {
        self.reference.size
    }

    /// The reference being read.
    pub fn reference(&self) -> &BlobRef {
        &self.reference
    }

    /// Ciphertexts of `ids`, from the store or fetched (then verified and
    /// stored). Fails with [`BlobError::Missing`] for the first id that
    /// cannot be obtained.
    fn load(&mut self, ids: &[Id]) -> Result<HashMap<Id, Vec<u8>>, BlobError> {
        let mut out = HashMap::with_capacity(ids.len());
        let mut missing = Vec::new();
        for id in ids {
            if out.contains_key(id) {
                continue;
            }
            match self.store.get(id)? {
                Some(b) => {
                    self.store.touch(id)?;
                    out.insert(*id, b);
                }
                None => missing.push(*id),
            }
        }
        if !missing.is_empty() {
            missing.sort();
            missing.dedup();
            for (id, bytes) in self.fetch.fetch(&missing)? {
                if missing.binary_search(&id).is_err() || out.contains_key(&id) {
                    continue;
                }
                if object_id(&bytes) != id {
                    // A bad peer; treat as not obtained.
                    continue;
                }
                self.store.put(&id, &bytes)?;
                out.insert(id, bytes);
            }
            if let Some(id) = missing.iter().find(|id| !out.contains_key(*id)) {
                return Err(BlobError::Missing(*id));
            }
        }
        Ok(out)
    }

    /// The decoded indexes named by `entries`, checked against the level
    /// expected and the length the parent claims.
    fn indexes(
        &mut self,
        entries: &[IndexEntry],
        level: u64,
    ) -> Result<Vec<Arc<Index>>, BlobError> {
        let need: Vec<Id> = entries
            .iter()
            .filter(|e| !self.indexes.contains_key(&e.id))
            .map(|e| e.id)
            .collect();
        let loaded = if need.is_empty() {
            HashMap::new()
        } else {
            self.load(&need)?
        };
        let cached: Vec<Option<Arc<Index>>> = entries
            .iter()
            .map(|e| self.indexes.get(&e.id).cloned())
            .collect();
        let mut out = Vec::with_capacity(entries.len());
        for (e, cached) in entries.iter().zip(cached) {
            let index = match cached {
                Some(i) => i,
                None => {
                    let ct = &loaded[&e.id];
                    let index = Arc::new(Index::decode(&decrypt(&e.key, ct)?)?);
                    if self.indexes.len() >= INDEX_CACHE {
                        self.indexes.clear();
                    }
                    self.indexes.insert(e.id, index.clone());
                    index
                }
            };
            if index.level != level {
                return Err(BlobError::Corrupt(
                    "index level does not match its position",
                ));
            }
            if index.covered()? != e.len {
                return Err(BlobError::Corrupt("index lengths do not match its parent"));
            }
            out.push(index);
        }
        Ok(out)
    }

    fn top(&self) -> IndexEntry {
        IndexEntry {
            id: self.reference.id,
            key: self.reference.key,
            len: self.reference.size,
        }
    }

    /// The chunks overlapping `[lo, hi)`, with their offsets in the blob.
    fn leaves(&mut self, lo: u64, hi: u64) -> Result<Vec<(IndexEntry, u64)>, BlobError> {
        let mut frontier = vec![(self.top(), 0u64)];
        for level in (0..self.reference.levels).rev() {
            let entries: Vec<IndexEntry> = frontier.iter().map(|(e, _)| *e).collect();
            let indexes = self.indexes(&entries, level)?;
            let mut next = Vec::new();
            for ((_, off), index) in frontier.iter().zip(&indexes) {
                let mut o = *off;
                for child in &index.entries {
                    if o >= hi {
                        break;
                    }
                    if o + child.len > lo {
                        next.push((*child, o));
                    }
                    o += child.len;
                }
            }
            frontier = next;
        }
        Ok(frontier)
    }

    fn chunk_plaintexts(&mut self, entries: &[IndexEntry]) -> Result<Vec<Arc<Vec<u8>>>, BlobError> {
        let need: Vec<Id> = entries
            .iter()
            .filter(|e| self.last_chunk.as_ref().map(|(id, _)| id) != Some(&e.id))
            .map(|e| e.id)
            .collect();
        let loaded = if need.is_empty() {
            HashMap::new()
        } else {
            self.load(&need)?
        };
        let mut out = Vec::with_capacity(entries.len());
        for e in entries {
            let pt = match &self.last_chunk {
                Some((id, pt)) if *id == e.id => pt.clone(),
                _ => {
                    let pt = Arc::new(decrypt(&e.key, &loaded[&e.id])?);
                    if pt.len() as u64 != e.len {
                        return Err(BlobError::Corrupt("chunk length does not match its index"));
                    }
                    pt
                }
            };
            out.push(pt);
        }
        if let (Some(e), Some(pt)) = (entries.last(), out.last()) {
            self.last_chunk = Some((e.id, pt.clone()));
        }
        Ok(out)
    }

    /// Reads up to `buf.len()` bytes at `offset`; returns how many were
    /// read (0 at or past the end).
    pub fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, BlobError> {
        let size = self.reference.size;
        if offset >= size || buf.is_empty() {
            return Ok(0);
        }
        let hi = size.min(offset + buf.len() as u64);
        let leaves = self.leaves(offset, hi)?;
        let entries: Vec<IndexEntry> = leaves.iter().map(|(e, _)| *e).collect();
        let pts = self.chunk_plaintexts(&entries)?;
        let mut written = 0usize;
        for ((_, off), pt) in leaves.iter().zip(&pts) {
            let from = offset.max(*off);
            let to = hi.min(off + pt.len() as u64);
            if from >= to {
                continue;
            }
            let src = &pt[(from - off) as usize..(to - off) as usize];
            let dst = (from - offset) as usize;
            buf[dst..dst + src.len()].copy_from_slice(src);
            written = written.max(dst + src.len());
        }
        if written as u64 != hi - offset {
            return Err(BlobError::Corrupt(
                "chunks do not cover the requested range",
            ));
        }
        Ok(written)
    }

    /// Reads `len` bytes at `offset` (fewer at the end of the blob).
    pub fn read_range(&mut self, offset: u64, len: usize) -> Result<Vec<u8>, BlobError> {
        let n = (self.reference.size.saturating_sub(offset)).min(len as u64) as usize;
        let mut out = vec![0u8; n];
        let got = self.read_at(offset, &mut out)?;
        out.truncate(got);
        Ok(out)
    }

    /// Calls `f` with every chunk entry and plaintext, in order, fetching
    /// as needed. Holds one index per level and a batch of chunks.
    pub fn for_each_chunk(
        &mut self,
        mut f: impl FnMut(IndexEntry, &[u8]) -> Result<(), BlobError>,
    ) -> Result<(), BlobError> {
        let top = self.top();
        if self.reference.levels == 0 {
            let pts = self.chunk_plaintexts(&[top])?;
            return f(top, &pts[0]);
        }
        self.walk_chunks(top, self.reference.levels - 1, &mut f)
    }

    fn walk_chunks(
        &mut self,
        entry: IndexEntry,
        level: u64,
        f: &mut impl FnMut(IndexEntry, &[u8]) -> Result<(), BlobError>,
    ) -> Result<(), BlobError> {
        let index = self.indexes(&[entry], level)?.remove(0);
        if level == 0 {
            for group in index.entries.chunks(WALK_BATCH) {
                let pts = self.chunk_plaintexts(group)?;
                for (e, pt) in group.iter().zip(&pts) {
                    f(*e, pt)?;
                }
            }
        } else {
            for child in &index.entries {
                self.walk_chunks(*child, level - 1, f)?;
            }
        }
        Ok(())
    }

    /// Calls `f` with the id of every object of the blob (indexes before
    /// the chunks they name), fetching indexes as needed but not chunks.
    /// This is the set a "full" retention policy keeps for this blob.
    pub fn for_each_object(&mut self, mut f: impl FnMut(&Id)) -> Result<(), BlobError> {
        let top = self.top();
        if self.reference.levels == 0 {
            f(&top.id);
            return Ok(());
        }
        self.walk_objects(top, self.reference.levels - 1, &mut f)
    }

    fn walk_objects(
        &mut self,
        entry: IndexEntry,
        level: u64,
        f: &mut impl FnMut(&Id),
    ) -> Result<(), BlobError> {
        f(&entry.id);
        let index = self.indexes(&[entry], level)?.remove(0);
        for child in &index.entries {
            if level == 0 {
                f(&child.id);
            } else {
                self.walk_objects(*child, level - 1, f)?;
            }
        }
        Ok(())
    }

    /// Ensures every object of the blob is in the store, fetching in
    /// batches. Returns how many objects were fetched.
    pub fn fetch_all(&mut self) -> Result<u64, BlobError> {
        // Indexes are loaded (and so fetched) by the walk itself.
        let mut ids = Vec::new();
        self.for_each_object(|id| ids.push(*id))?;
        let mut missing = Vec::new();
        for id in ids {
            if !self.store.has(&id)? {
                missing.push(id);
            }
        }
        let n = missing.len() as u64;
        for group in missing.chunks(WALK_BATCH) {
            self.load(group)?;
        }
        Ok(n)
    }
}

impl<S: ObjectStore, F: Fetch + ?Sized> Read for BlobReader<'_, S, F> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.read_at(self.pos, buf)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl<S: ObjectStore, F: Fetch + ?Sized> Seek for BlobReader<'_, S, F> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let target = match to {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::End(d) => self.reference.size.checked_add_signed(d),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        };
        match target {
            Some(t) => {
                self.pos = t;
                Ok(t)
            }
            None => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before the start of the blob",
            )),
        }
    }
}
