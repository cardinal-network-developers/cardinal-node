//! Identity logs, device powers, and recovery (`spec/identity.md`).
//!
//! - [`entry`]: identity entries (kind 2) and their ops, built, signed,
//!   verified, and decoded with unknown fields preserved.
//! - [`dag`]: the causal graph of entries: parents, ancestors, heads, log
//!   order. Also used for spaces.
//! - [`log`]: an identity log, its evaluated [`IdentityState`], and the
//!   operations a device needs (create, add and remove keys, set the
//!   encryption key, open wraps).
//! - [`datalog`] and [`model`]: validity is decided by executing the
//!   normative `model/rules.md` with an embedded stratified-Datalog
//!   evaluator, over input facts derived from entries exactly as
//!   `model/world.py` derives them. The rules are never re-implemented by
//!   hand, and a differential test checks this crate against the Python
//!   model on its scenarios and fuzzer.

pub mod dag;
pub mod datalog;
pub mod entry;
mod error;
pub mod log;
pub mod model;

#[doc(hidden)]
pub mod testutil;

pub use dag::{Dag, Inserted};
pub use entry::{EntryBuilder, EntryId, IdentityEntry, IdentityOp, KeyId, OpBody, Power, Protocol};
pub use error::Error;
pub use log::{
    Created, DeviceKeys, EncryptionKeyInfo, IdentityLog, IdentityState, KeyInfo, KeyRequest,
};
