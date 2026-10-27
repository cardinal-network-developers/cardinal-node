//! Error type.

use std::fmt;

/// Why an identity operation failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The bytes are not a well-formed object.
    Encoding(cardinal_encoding::Error),
    /// A key, sealed record, or ciphertext was rejected.
    Crypto(cardinal_crypto::Error),
    /// The entry's signature does not verify.
    BadSignature,
    /// The entry exceeds 64 KiB.
    TooLarge,
    /// A field has the wrong shape.
    Malformed(&'static str),
    /// The entry belongs to another identity.
    WrongIdentity,
    /// The genesis entry breaks a rule of `identity.md#operations`.
    BadGenesis(&'static str),
    /// The signing key may not write this entry.
    NotAuthorized(&'static str),
    /// The identity has no current encryption key, or this device holds no
    /// wrap of it.
    NoEncryptionKey,
    /// A wrap, key chain, or recovery wrap did not hold the key it claims.
    WrongKey,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Encoding(e) => write!(f, "encoding: {e}"),
            Error::Crypto(e) => write!(f, "crypto: {e}"),
            Error::BadSignature => f.write_str("bad signature"),
            Error::TooLarge => f.write_str("entry exceeds 64 KiB"),
            Error::Malformed(why) => write!(f, "malformed entry: {why}"),
            Error::WrongIdentity => f.write_str("entry of another identity"),
            Error::BadGenesis(why) => write!(f, "bad genesis entry: {why}"),
            Error::NotAuthorized(why) => write!(f, "not authorized: {why}"),
            Error::NoEncryptionKey => f.write_str("no usable encryption key"),
            Error::WrongKey => f.write_str("a sealed key is not the key it claims to be"),
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
            e => Error::Crypto(e),
        }
    }
}
