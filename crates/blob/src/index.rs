//! Blob indexes (`blobs.md#index`) and the deterministic index tree.

use cardinal_encoding::kind::BLOB_INDEX;
use cardinal_encoding::{Kind, Record, SchemaError, Value};

use crate::convergent::{encrypt, ConvergenceSecret, Encrypted};
use crate::{BlobError, BlobRef, Id, Key};

/// The most entries an index may hold.
pub const MAX_ENTRIES: usize = 3000;

/// One entry of an index: a chunk (in a level-0 index) or a lower index.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IndexEntry {
    /// The id of the chunk or index.
    pub id: Id,
    /// Its key.
    pub key: Key,
    /// The plaintext length it covers: the chunk's length, or for an index
    /// the total length of the blob bytes beneath it.
    pub len: u64,
}

impl std::fmt::Debug for IndexEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "IndexEntry {{ id: {}, len: {} }}",
            crate::reference::hex(&self.id),
            self.len
        )
    }
}

/// An index record `{0: 5, 1: level, 2: entries}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Index {
    /// 0 if the entries name chunks; otherwise one more than the level of
    /// the indexes they name.
    pub level: u64,
    /// The entries, in blob order.
    pub entries: Vec<IndexEntry>,
}

impl Index {
    /// The record form.
    pub fn to_record(&self) -> Record {
        let entries: Vec<Value> = self
            .entries
            .iter()
            .map(|e| {
                Record::new()
                    .with(1, e.id)
                    .with(2, e.key)
                    .with(3, e.len)
                    .into()
            })
            .collect();
        Record::new()
            .with(0, BLOB_INDEX)
            .with(1, self.level)
            .with(2, Value::List(entries))
    }

    /// The canonical encoding: the plaintext that is encrypted.
    pub fn encode(&self) -> Vec<u8> {
        self.to_record().encode()
    }

    /// Reads an index, checking its kind and size.
    pub fn from_record(r: &Record) -> Result<Index, BlobError> {
        let kind = r.kind()?;
        if kind != Kind::Core(BLOB_INDEX) {
            return Err(SchemaError::WrongKind {
                expected: Kind::Core(BLOB_INDEX),
                found: kind,
            }
            .into());
        }
        let level = r.uint(1)?;
        let list = r.record_list(2)?;
        if list.is_empty() || list.len() > MAX_ENTRIES {
            return Err(SchemaError::Invalid("index must hold 1 to 3000 entries").into());
        }
        let mut entries = Vec::with_capacity(list.len());
        for e in list {
            entries.push(IndexEntry {
                id: e.bytes_n::<32>(1)?,
                key: e.bytes_n::<32>(2)?,
                len: e.uint(3)?,
            });
        }
        Ok(Index { level, entries })
    }

    /// Decodes an index from its plaintext.
    pub fn decode(bytes: &[u8]) -> Result<Index, BlobError> {
        Index::from_record(&Record::decode(bytes)?)
    }

    /// The total plaintext length the entries cover.
    pub fn covered(&self) -> Result<u64, BlobError> {
        self.entries.iter().try_fold(0u64, |acc, e| {
            acc.checked_add(e.len)
                .ok_or(BlobError::Corrupt("index lengths overflow"))
        })
    }
}

#[derive(Default)]
struct Level {
    pending: Vec<IndexEntry>,
    flushed: u64,
}

/// Builds the index tree of a blob from its chunk entries, in order,
/// holding at most one partial index per level.
///
/// Each level is split into consecutive indexes of exactly 3,000 entries,
/// except the last, which holds the rest; a level of more than one index is
/// named by the level above, split the same way. Full indexes are emitted
/// as soon as they fill, which yields the same tree as splitting the whole
/// level at the end.
pub struct IndexBuilder {
    fanout: usize,
    levels: Vec<Level>,
    total: u64,
}

impl Default for IndexBuilder {
    fn default() -> Self {
        IndexBuilder::new()
    }
}

impl IndexBuilder {
    /// A builder with the specification's 3,000-entry indexes.
    pub fn new() -> IndexBuilder {
        IndexBuilder::with_fanout(MAX_ENTRIES)
    }

    /// A builder with a smaller fanout, for testing deep trees.
    #[doc(hidden)]
    pub fn with_fanout(fanout: usize) -> IndexBuilder {
        assert!(fanout >= 2);
        IndexBuilder {
            fanout,
            levels: vec![Level::default()],
            total: 0,
        }
    }

    /// Total plaintext length pushed so far.
    pub fn size(&self) -> u64 {
        self.total
    }

    /// Appends the next chunk. `sink` receives every index as it is
    /// completed.
    pub fn push<F>(
        &mut self,
        chunk: IndexEntry,
        secret: &ConvergenceSecret,
        sink: &mut F,
    ) -> Result<(), BlobError>
    where
        F: FnMut(Encrypted) -> Result<(), BlobError>,
    {
        self.total += chunk.len;
        self.push_at(0, chunk, secret, sink)
    }

    fn push_at<F>(
        &mut self,
        level: usize,
        entry: IndexEntry,
        secret: &ConvergenceSecret,
        sink: &mut F,
    ) -> Result<(), BlobError>
    where
        F: FnMut(Encrypted) -> Result<(), BlobError>,
    {
        if self.levels.len() <= level {
            self.levels.push(Level::default());
        }
        self.levels[level].pending.push(entry);
        if self.levels[level].pending.len() == self.fanout {
            let up = self.flush(level, secret, sink)?;
            self.push_at(level + 1, up, secret, sink)?;
        }
        Ok(())
    }

    fn flush<F>(
        &mut self,
        level: usize,
        secret: &ConvergenceSecret,
        sink: &mut F,
    ) -> Result<IndexEntry, BlobError>
    where
        F: FnMut(Encrypted) -> Result<(), BlobError>,
    {
        let l = &mut self.levels[level];
        let entries = std::mem::take(&mut l.pending);
        l.flushed += 1;
        let index = Index {
            level: level as u64,
            entries,
        };
        let len = index.covered()?;
        let enc = encrypt(secret, &index.encode());
        let entry = IndexEntry {
            id: enc.id,
            key: enc.key,
            len,
        };
        sink(enc)?;
        Ok(entry)
    }

    /// Completes the tree and returns the blob's reference. A blob with no
    /// chunks at all is given one empty chunk, which goes to `sink` too.
    pub fn finish<F>(
        mut self,
        secret: &ConvergenceSecret,
        sink: &mut F,
    ) -> Result<BlobRef, BlobError>
    where
        F: FnMut(Encrypted) -> Result<(), BlobError>,
    {
        if self.levels[0].pending.is_empty() && self.levels[0].flushed == 0 {
            let enc = encrypt(secret, b"");
            let r = BlobRef {
                id: enc.id,
                key: enc.key,
                size: 0,
                levels: 0,
            };
            sink(enc)?;
            return Ok(r);
        }
        let mut level = 0;
        loop {
            let alone = self.levels[level].flushed == 0 && level + 1 == self.levels.len();
            if alone && self.levels[level].pending.len() == 1 {
                // The single entry at the top: a chunk (level 0) or the top
                // index (named from the level above it).
                let e = self.levels[level].pending[0];
                return Ok(BlobRef {
                    id: e.id,
                    key: e.key,
                    size: self.total,
                    levels: level as u64,
                });
            }
            if !self.levels[level].pending.is_empty() {
                let up = self.flush(level, secret, sink)?;
                if self.levels.len() <= level + 1 {
                    self.levels.push(Level::default());
                }
                // Not push_at: the level above may not flush early here,
                // because it is handled by the next iteration.
                self.levels[level + 1].pending.push(up);
                if self.levels[level + 1].pending.len() == self.fanout {
                    let up2 = self.flush(level + 1, secret, sink)?;
                    self.push_at(level + 2, up2, secret, sink)?;
                }
            }
            level += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds the tree the slow way: split every level, all at once.
    fn batch(
        leaves: &[IndexEntry],
        fanout: usize,
        secret: &ConvergenceSecret,
    ) -> (BlobRef, Vec<Id>) {
        let total: u64 = leaves.iter().map(|e| e.len).sum();
        let mut level = leaves.to_vec();
        let mut ids = Vec::new();
        let mut n = 0u64;
        while level.len() > 1 {
            let mut next = Vec::new();
            for group in level.chunks(fanout) {
                let index = Index {
                    level: n,
                    entries: group.to_vec(),
                };
                let enc = encrypt(secret, &index.encode());
                ids.push(enc.id);
                next.push(IndexEntry {
                    id: enc.id,
                    key: enc.key,
                    len: index.covered().unwrap(),
                });
            }
            level = next;
            n += 1;
        }
        (
            BlobRef {
                id: level[0].id,
                key: level[0].key,
                size: total,
                levels: n,
            },
            ids,
        )
    }

    fn leaf(i: u64) -> IndexEntry {
        let h = blake3::hash(&i.to_le_bytes());
        IndexEntry {
            id: *h.as_bytes(),
            key: *blake3::hash(h.as_bytes()).as_bytes(),
            len: 1000 + i,
        }
    }

    #[test]
    fn streaming_equals_batch() {
        let secret = ConvergenceSecret::from_bytes([5; 32]);
        for fanout in [2usize, 3, 4, 7] {
            for n in 1..=60u64 {
                let leaves: Vec<_> = (0..n).map(leaf).collect();
                let mut b = IndexBuilder::with_fanout(fanout);
                let mut ids = Vec::new();
                let mut sink = |e: Encrypted| {
                    ids.push(e.id);
                    Ok(())
                };
                for l in &leaves {
                    b.push(*l, &secret, &mut sink).unwrap();
                }
                let r = b.finish(&secret, &mut sink).unwrap();
                let (expect, mut expect_ids) = batch(&leaves, fanout, &secret);
                assert_eq!(r, expect, "fanout {fanout} n {n}");
                ids.sort();
                expect_ids.sort();
                assert_eq!(ids, expect_ids, "fanout {fanout} n {n}");
            }
        }
    }

    #[test]
    fn levels() {
        let secret = ConvergenceSecret::from_bytes([5; 32]);
        let build = |n: u64, fanout: usize| {
            let mut b = IndexBuilder::with_fanout(fanout);
            let mut sink = |_e: Encrypted| Ok(());
            for i in 0..n {
                b.push(leaf(i), &secret, &mut sink).unwrap();
            }
            b.finish(&secret, &mut sink).unwrap().levels
        };
        assert_eq!(build(1, 3), 0);
        assert_eq!(build(2, 3), 1);
        assert_eq!(build(3, 3), 1);
        assert_eq!(build(4, 3), 2);
        assert_eq!(build(9, 3), 2);
        assert_eq!(build(10, 3), 3);
        assert_eq!(build(3000, MAX_ENTRIES), 1);
        assert_eq!(build(3001, MAX_ENTRIES), 2);
    }

    #[test]
    fn record_round_trip() {
        let i = Index {
            level: 0,
            entries: (0..5).map(leaf).collect(),
        };
        assert_eq!(Index::decode(&i.encode()).unwrap(), i);
        let empty = Index {
            level: 0,
            entries: vec![],
        };
        assert!(Index::decode(&empty.encode()).is_err());
    }
}
