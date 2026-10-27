//! Error type.

use std::fmt;

/// Why a space operation failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The bytes are not a well-formed object.
    Encoding(cardinal_encoding::Error),
    /// A key or sealed record was rejected.
    Crypto(cardinal_crypto::Error),
    /// The entry's signature does not verify.
    BadSignature,
    /// The sealed entry exceeds 256 KiB.
    TooLarge,
    /// A field has the wrong shape.
    Malformed(&'static str),
    /// No key for the entry's epoch is held, and no wrap opened.
    NoEpochKey,
    /// The ciphertext did not decrypt under the epoch key.
    Decrypt,
    /// The sealed entry's nonce, epoch, or wraps do not match the inner
    /// entry (`spaces.md#entries-and-sealed-entries`).
    Mismatch(&'static str),
    /// The entry belongs to another space.
    WrongSpace,
    /// Membership evaluation of a space with more than one member identity
    /// is not implemented natively yet; use the full rules.
    Unsupported(&'static str),
    /// The author's identity log is not known.
    UnknownAuthor,
    /// The operation is not allowed.
    NotAllowed(&'static str),
    /// From the identity crate.
    Identity(cardinal_identity::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Encoding(e) => write!(f, "encoding: {e}"),
            Error::Crypto(e) => write!(f, "crypto: {e}"),
            Error::BadSignature => f.write_str("bad signature"),
            Error::TooLarge => f.write_str("sealed entry exceeds 256 KiB"),
            Error::Malformed(why) => write!(f, "malformed entry: {why}"),
            Error::NoEpochKey => f.write_str("no key for this epoch"),
            Error::Decrypt => f.write_str("entry does not decrypt"),
            Error::Mismatch(why) => write!(f, "sealed entry does not match: {why}"),
            Error::WrongSpace => f.write_str("entry of another space"),
            Error::Unsupported(why) => write!(f, "unsupported: {why}"),
            Error::UnknownAuthor => f.write_str("unknown author"),
            Error::NotAllowed(why) => write!(f, "not allowed: {why}"),
            Error::Identity(e) => write!(f, "identity: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<cardinal_encoding::Error> for Error {
    fn from(e: cardinal_encoding::Error) -> Error {
        Error::Encoding(e)
    }
}

impl From<cardinal_encoding::SchemaError> for Error {
    fn from(e: cardinal_encoding::SchemaError) -> Error {
        Error::Encoding(e.into())
    }
}

impl From<cardinal_encoding::DecodeError> for Error {
    fn from(e: cardinal_encoding::DecodeError) -> Error {
        Error::Encoding(e.into())
    }
}

impl From<cardinal_crypto::Error> for Error {
    fn from(e: cardinal_crypto::Error) -> Error {
        match e {
            cardinal_crypto::Error::Encoding(e) => Error::Encoding(e),
            cardinal_crypto::Error::Decrypt => Error::Decrypt,
            e => Error::Crypto(e),
        }
    }
}

impl From<cardinal_identity::Error> for Error {
    fn from(e: cardinal_identity::Error) -> Error {
        Error::Identity(e)
    }
}
