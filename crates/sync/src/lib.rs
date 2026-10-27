//! Sync (`core/spec/sync.md`): range-based set reconciliation of 32-byte
//! ids, fetching objects with `want` and `objects`, `heads` notices, the
//! `blob` service's messages, and bundles for sneakernet.
//!
//! Everything here is transport-agnostic. A [`Reconciler`] is a state
//! machine over a [`SetStore`]: feed it the ranges of each incoming
//! `reconcile` message and send what it returns. When it reports
//! [`done`](Reconciler::is_done), [`Reconciler::take_wanted`] holds the ids
//! this side lacks; fetch them with [`want_messages`].
//!
//! ```
//! use cardinal_sync::{MemSet, Message, Reconciler};
//!
//! let label = [1u8; 32];
//! let a: MemSet = (0u8..100).map(|i| [i; 32]).collect();
//! let b: MemSet = (50u8..150).map(|i| [i; 32]).collect();
//! let mut ra = Reconciler::new(label, &a);
//! let mut rb = Reconciler::new(label, &b);
//! let mut msg = Some(ra.initiate());
//! let mut to_b = true;
//! while let Some(m) = msg {
//!     let bytes = m.encode();
//!     let Message::Reconcile { ranges, .. } = Message::decode(&bytes).unwrap() else { panic!() };
//!     msg = if to_b { rb.receive(&ranges).unwrap() } else { ra.receive(&ranges).unwrap() };
//!     to_b = !to_b;
//! }
//! assert_eq!(ra.take_wanted().len(), 50);
//! assert_eq!(rb.take_wanted().len(), 50);
//! ```

mod blob;
mod bundle;
mod error;
mod fetch;
mod fingerprint;
mod message;
mod reconcile;
mod set;

pub use blob::{BlobItem, BlobReply, BlobRequest, MAX_BLOB_REQUEST};
pub use bundle::Bundle;
pub use error::SyncError;
pub use fetch::{answer_want, objects_messages, want_messages, MAX_WANT};
pub use fingerprint::{fingerprint, Fingerprint, Sum};
pub use message::{Message, Mode, Range};
pub use reconcile::{Reconciler, Stats, LIST_THRESHOLD, MAX_MESSAGE, SPLIT};
pub use set::{EmptySet, MemSet, SetStore};

/// A 32-byte object id, ordered bytewise.
pub type Id = [u8; 32];

/// A 32-byte set label.
pub type Label = [u8; 32];

/// The label of an identity log's set: `BLAKE3("identity log" || identity id)`.
pub fn identity_log_label(identity: &Id) -> Label {
    let mut h = blake3::Hasher::new();
    h.update(b"identity log");
    h.update(identity);
    *h.finalize().as_bytes()
}
