//! Blobs (`core/spec/blobs.md`): content-defined chunking, convergent
//! encryption, blob indexes, blob references, and the content-addressed
//! object store that holds chunks and indexes.
//!
//! A blob is cut into chunks by FastCDC with the fixed parameters of the
//! specification ([`chunker`]). Each chunk is encrypted under a key derived
//! from its own plaintext and the epoch's convergence secret, and named by
//! the BLAKE3 hash of its ciphertext ([`convergent`]). A blob of more than
//! one chunk gets a tree of [`Index`] records, encrypted the same way. A
//! [`BlobRef`] names the top of the tree and carries the key to read it.
//!
//! Writing streams: [`BlobWriter`] implements [`std::io::Write`] and never
//! holds more than a few chunks and one partial index per tree level.
//! Reading streams too: [`BlobReader`] reads any byte range, fetching the
//! indexes and chunks it lacks through a [`Fetch`] implementation, which is
//! how a FUSE mount fetches on demand.
//!
//! ```
//! use cardinal_blob::{encode_bytes, BlobReader, ConvergenceSecret, MemStore, NoFetch};
//!
//! let store = MemStore::new();
//! let secret = ConvergenceSecret::from_epoch_key(&[7u8; 32]);
//! let data = vec![42u8; 300_000];
//! let reference = encode_bytes(&data, &secret, &store).unwrap();
//! assert_eq!(reference.size, 300_000);
//!
//! let mut reader = BlobReader::new(&store, &NoFetch, reference);
//! let mut buf = [0u8; 10];
//! reader.read_at(299_995, &mut buf).unwrap();
//! assert_eq!(&buf[..5], &[42u8; 5]);
//! ```

pub mod chunker;
pub mod convergent;
mod error;
mod index;
mod reader;
mod reference;
pub mod retention;
mod store;
mod writer;

pub use chunker::{chunk_boundaries, cut, gear, AVG_SIZE, MAX_SIZE, MIN_SIZE};
pub use convergent::{decrypt, encrypt, ConvergenceSecret, Encrypted};
pub use error::BlobError;
pub use index::{Index, IndexBuilder, IndexEntry, MAX_ENTRIES};
pub use reader::{BlobReader, Fetch, NoFetch};
pub use reference::BlobRef;
pub use retention::Retention;
pub use store::{FsStore, Fsync, MemStore, ObjectInfo, ObjectStore, Usage};
pub use writer::{encode_bytes, encode_reader, BlobWriter, ReuseMap, WriteStats};

/// A 32-byte object id: `BLAKE3(ciphertext)` of a chunk or index.
pub type Id = [u8; 32];

/// A 32-byte chunk or index key.
pub type Key = [u8; 32];

/// The id of `bytes`: `BLAKE3(bytes)`.
pub fn object_id(bytes: &[u8]) -> Id {
    *blake3::hash(bytes).as_bytes()
}

/// Content smaller than this SHOULD be stored inline in the space entry
/// rather than as a blob (`blobs.md#chunking`).
pub const INLINE_LIMIT: usize = 1024;
