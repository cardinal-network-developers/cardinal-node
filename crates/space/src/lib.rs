//! Spaces, members, epochs, and the shared state tree
//! (`spec/spaces.md`, `spec/state.md`, `spec/profiles.md`).
//!
//! - [`entry`]: space entries (kind 4), their ops, and sealed entries
//!   (kind 3): deterministic nonce, AAD binding, wraps hash.
//! - [`epoch`]: epoch keys, ids, entry keys, and wraps.
//! - [`validity`]: which entries are valid and who is a member. Every space
//!   is judged natively, each entry once as it arrives; the normative rules
//!   are run only to test that against.
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
pub mod group;
pub mod relationship;
pub mod space;
pub mod state;
pub mod validity;

pub use entry::{
    NodeId, NodeKind, Policy, Profile, SealedEntry, SpaceEntry, SpaceEntryBuilder, SpaceId,
    SpaceOp, SpaceOpBody,
};
pub use epoch::{EpochId, EpochKey, Keyring};
pub use error::Error;
pub use files::Files;
pub use space::Space;
pub use state::{Node, State, ROOT};
pub use validity::{Judge, Member, Validity};
