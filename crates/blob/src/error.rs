//! Error type.

use std::fmt;
use std::io;

use crate::Id;

/// Why a blob operation failed.
#[derive(Debug)]
pub enum BlobError {
    /// The object store or the fetcher failed.
    Io(io::Error),
    /// A chunk or index is neither in the store nor obtainable by fetching.
    Missing(Id),
    /// A ciphertext did not decrypt under the key a reference gave.
    Decrypt,
    /// An index or reference is not a valid encoding.
    Encoding(cardinal_encoding::Error),
    /// A blob's structure is inconsistent: a wrong index level, lengths
    /// that do not add up, or a fetched object that does not hash to its id.
    Corrupt(&'static str),
}

impl fmt::Display for BlobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlobError::Io(e) => write!(f, "object store: {e}"),
            BlobError::Missing(id) => {
                write!(f, "object {} not available", crate::reference::hex(id))
            }
            BlobError::Decrypt => f.write_str("chunk did not decrypt"),
            BlobError::Encoding(e) => write!(f, "invalid blob record: {e}"),
            BlobError::Corrupt(why) => write!(f, "corrupt blob: {why}"),
        }
    }
}

impl std::error::Error for BlobError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BlobError::Io(e) => Some(e),
            BlobError::Encoding(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for BlobError {
    fn from(e: io::Error) -> BlobError {
        BlobError::Io(e)
    }
}

impl From<cardinal_encoding::Error> for BlobError {
    fn from(e: cardinal_encoding::Error) -> BlobError {
        BlobError::Encoding(e)
    }
}

impl From<cardinal_encoding::DecodeError> for BlobError {
    fn from(e: cardinal_encoding::DecodeError) -> BlobError {
        BlobError::Encoding(e.into())
    }
}

impl From<cardinal_encoding::SchemaError> for BlobError {
    fn from(e: cardinal_encoding::SchemaError) -> BlobError {
        BlobError::Encoding(e.into())
    }
}

impl From<BlobError> for io::Error {
    fn from(e: BlobError) -> io::Error {
        match e {
            BlobError::Io(e) => e,
            BlobError::Missing(_) => io::Error::new(io::ErrorKind::NotFound, e),
            other => io::Error::new(io::ErrorKind::InvalidData, other),
        }
    }
}
