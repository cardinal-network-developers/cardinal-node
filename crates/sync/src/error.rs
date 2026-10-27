//! Error type.

use std::fmt;

/// Why a sync message or bundle was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncError {
    /// The bytes are not one canonical value.
    Decode(cardinal_encoding::DecodeError),
    /// The value does not match the message's schema.
    Schema(cardinal_encoding::SchemaError),
    /// A message op this implementation does not know.
    UnknownOp(u64),
    /// The ranges of a reconcile message do not cover every id in order.
    BadRanges(&'static str),
    /// A bundle could not be opened or holds something other than objects
    /// messages.
    Bundle(&'static str),
    /// A sealed bundle did not open with the given key.
    Crypto(cardinal_crypto::Error),
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SyncError::Decode(e) => write!(f, "sync message: {e}"),
            SyncError::Schema(e) => write!(f, "sync message: {e}"),
            SyncError::UnknownOp(op) => write!(f, "unknown sync op {op}"),
            SyncError::BadRanges(why) => write!(f, "reconcile ranges: {why}"),
            SyncError::Bundle(why) => write!(f, "bundle: {why}"),
            SyncError::Crypto(e) => write!(f, "bundle: {e}"),
        }
    }
}

impl std::error::Error for SyncError {}

impl From<cardinal_encoding::DecodeError> for SyncError {
    fn from(e: cardinal_encoding::DecodeError) -> SyncError {
        SyncError::Decode(e)
    }
}

impl From<cardinal_encoding::SchemaError> for SyncError {
    fn from(e: cardinal_encoding::SchemaError) -> SyncError {
        SyncError::Schema(e)
    }
}

impl From<cardinal_encoding::Error> for SyncError {
    fn from(e: cardinal_encoding::Error) -> SyncError {
        match e {
            cardinal_encoding::Error::Decode(d) => SyncError::Decode(d),
            cardinal_encoding::Error::Schema(s) => SyncError::Schema(s),
        }
    }
}

impl From<cardinal_crypto::Error> for SyncError {
    fn from(e: cardinal_crypto::Error) -> SyncError {
        SyncError::Crypto(e)
    }
}
