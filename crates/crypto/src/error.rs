//! Error type.

use std::fmt;

/// Why a cryptographic operation failed.
///
/// Failures that an attacker could provoke (bad tags, bad signatures) carry
/// no detail beyond their category.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// An AEAD tag did not verify: wrong key, nonce, associated data, or a
    /// modified ciphertext. Also returned by `open` for a sealed record
    /// meant for someone else.
    Decrypt,
    /// A signature did not verify under ZIP-215 rules.
    BadSignature,
    /// A public key or ciphertext is not a valid encoding.
    InvalidKey(&'static str),
    /// A record did not have the expected shape.
    Encoding(cardinal_encoding::Error),
    /// CPace aborted: the peer's share was not a valid element or produced
    /// the identity.
    CpaceAbort,
    /// A recovery phrase or pairing code was rejected.
    Mnemonic(MnemonicError),
}

/// Why a mnemonic was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MnemonicError {
    /// The phrase has the wrong number of words.
    WordCount { expected: usize, found: usize },
    /// The word at this zero-based position is not in the BIP-39 English list.
    UnknownWord { position: usize },
    /// The BIP-39 checksum does not match: probably a mistyped word.
    Checksum,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Decrypt => f.write_str("decryption failed"),
            Error::BadSignature => f.write_str("invalid signature"),
            Error::InvalidKey(what) => write!(f, "invalid {what}"),
            Error::Encoding(e) => write!(f, "malformed record: {e}"),
            Error::CpaceAbort => f.write_str("CPace aborted: invalid peer share"),
            Error::Mnemonic(MnemonicError::WordCount { expected, found }) => {
                write!(f, "expected {expected} words, found {found}")
            }
            Error::Mnemonic(MnemonicError::UnknownWord { position }) => {
                write!(f, "word {} is not in the BIP-39 English list", position + 1)
            }
            Error::Mnemonic(MnemonicError::Checksum) => {
                f.write_str("phrase checksum does not match; check for a mistyped word")
            }
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

impl From<MnemonicError> for Error {
    fn from(e: MnemonicError) -> Error {
        Error::Mnemonic(e)
    }
}
