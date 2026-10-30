//! Spaces, membership, epochs, and the shared state tree
//! (`spec/spaces.md`, `spec/state.md`, `spec/profiles.md`).
//!
//! - [`entry`]: space entries (kind 4), their ops, and sealed entries
//!   (kind 3): deterministic nonce, AAD binding, wraps hash.
//! - [`epoch`]: epoch keys, ids, entry keys, and wraps.
//! - [`membership`]: validity and membership — natively for spaces whose
//!   only member is their creator, and with the normative rules for any
//!   space.
//! - [`state`]: the state tree CRDT and the canonical state.
//! - [`space`]: a space as a device holds it, kept up to date as entries
//!   arrive.
//! - [`files`], [`account`]: profile helpers.

pub mod account;
pub mod entry;
pub mod epoch;
mod error;
pub mod files;
pub mod grant;
pub mod membership;
pub mod space;
pub mod state;

pub use entry::{
    NodeId, NodeKind, Policy, Profile, SealedEntry, SpaceEntry, SpaceEntryBuilder, SpaceId,
    SpaceOp, SpaceOpBody,
};
pub use epoch::{EpochId, EpochKey, Keyring};
pub use error::Error;
pub use files::Files;
pub use membership::{Membership, Validity};
pub use space::Space;
pub use state::{Node, State, ROOT};
