//! Sync (`core/spec/sync.md`): range-based set reconciliation of 32-byte
//! ids, fetching objects with `want` and `objects`, `heads` notices, the
//! `blob` service's messages, and bundles for sneakernet.
//!
//! Everything here is transport-agnostic. A [`Reconciler`] is a state
//! machine over a [`SetStore`]: feed it each incoming `reconcile` message,
//! and once the peer's turn has ended it returns this side's turn to send.
//! After every message, [`Reconciler::take_wanted`] holds the ids this side
//! has just learned it lacks; fetch them at once with [`want_messages`],
//! spreading them across peers with a [`Spread`]. On a long-delay link a
//! side may open with a summary instead ([`summary_messages`],
//! [`SummaryReader`]).
//!
//! ```
//! use cardinal_sync::{MemSet, Message, Reconciler};
//!
//! let label = [1u8; 32];
//! let a: MemSet = (0u8..100).map(|i| [i; 32]).collect();
//! let b: MemSet = (50u8..150).map(|i| [i; 32]).collect();
//! let mut ra = Reconciler::new(label, &a);
//! let mut rb = Reconciler::new(label, &b);
//! let (mut wa, mut wb) = (0, 0);
//! let mut turn = vec![ra.initiate()];
//! let mut to_b = true;
//! while !turn.is_empty() {
//!     let mut next = Vec::new();
//!     for m in turn {
//!         let m = Message::decode(&m.encode()).unwrap();
//!         let (r, w) = if to_b { (&mut rb, &mut wb) } else { (&mut ra, &mut wa) };
//!         next = r.handle(&m).unwrap();
//!         *w += r.take_wanted().len();
//!     }
//!     turn = next;
//!     to_b = !to_b;
//! }
//! assert_eq!((wa, wb), (50, 50));
//! ```

mod blob;
mod bundle;
mod error;
mod fetch;
mod fingerprint;
mod message;
mod reconcile;
mod set;
mod spread;
mod summary;

pub use blob::{BlobItem, BlobReply, BlobRequest, MAX_BLOB_REQUEST};
pub use bundle::Bundle;
pub use error::SyncError;
pub use fetch::{answer_want, objects_messages, want_messages, MAX_WANT};
pub use fingerprint::{fingerprint, Fingerprint, Sum};
pub use message::{Message, Mode, Range};
pub use reconcile::{Reconciler, Stats, LIST_THRESHOLD, MAX_MESSAGE, MAX_TURN, SPLIT};
pub use set::{EmptySet, MemSet, SetStore};
pub use spread::Spread;
pub use summary::{
    sends_everything, short_id, summary_bits, summary_messages, Summary, SummaryReader,
    ASSUMED_OTHER_BITS,
};

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
