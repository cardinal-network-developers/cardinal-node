//! Error types.

use std::fmt;

use crate::Kind;

/// Why bytes were rejected by the decoder. `offset` is the byte position in
/// the input where the offending item starts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The input ended inside a value.
    UnexpectedEnd { offset: usize },
    /// A varint was not in its shortest form.
    NonMinimalVarint { offset: usize },
    /// A varint was longer than 9 bytes.
    VarintTooLong { offset: usize },
    /// A header used reserved type 6 or 7.
    ReservedType { offset: usize, t: u8 },
    /// A length or count exceeds the remaining input.
    LengthExceedsInput { offset: usize },
    /// A text value was not valid UTF-8.
    InvalidUtf8 { offset: usize },
    /// A record key was smaller than the key before it.
    UnsortedKeys { offset: usize, key: u64 },
    /// A record key repeated the key before it.
    DuplicateKey { offset: usize, key: u64 },
    /// Lists and records were nested deeper than [`MAX_DEPTH`](crate::MAX_DEPTH).
    TooDeep { offset: usize },
    /// Bytes followed the single top-level value.
    TrailingBytes { offset: usize },
    /// The context required a record and found another type.
    NotARecord { found: &'static str },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use DecodeError::*;
        match self {
            UnexpectedEnd { offset } => write!(f, "unexpected end of input at byte {offset}"),
            NonMinimalVarint { offset } => write!(f, "non-minimal varint at byte {offset}"),
            VarintTooLong { offset } => write!(f, "varint longer than 9 bytes at byte {offset}"),
            ReservedType { offset, t } => write!(f, "reserved type {t} at byte {offset}"),
            LengthExceedsInput { offset } => write!(f, "length exceeds input at byte {offset}"),
            InvalidUtf8 { offset } => write!(f, "invalid UTF-8 text at byte {offset}"),
            UnsortedKeys { offset, key } => {
                write!(f, "record key {key} out of order at byte {offset}")
            }
            DuplicateKey { offset, key } => {
                write!(f, "duplicate record key {key} at byte {offset}")
            }
            TooDeep { offset } => write!(f, "nesting deeper than 32 at byte {offset}"),
            TrailingBytes { offset } => write!(f, "trailing bytes after value at byte {offset}"),
            NotARecord { found } => write!(f, "expected a record, found {found}"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Why a well-formed value does not fit the schema a reader expected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SchemaError {
    /// A required field is absent.
    Missing { key: u64 },
    /// A field has the wrong type.
    WrongType {
        key: u64,
        expected: &'static str,
        found: &'static str,
    },
    /// A fixed-length byte field has the wrong length.
    WrongLength {
        key: u64,
        expected: usize,
        found: usize,
    },
    /// An integer is outside `-2^60 ..= 2^60 - 1`.
    IntegerOutOfRange,
    /// The object is of a different kind than expected.
    WrongKind { expected: Kind, found: Kind },
    /// Any other schema rule, described.
    Invalid(&'static str),
}

impl fmt::Display for SchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use SchemaError::*;
        match self {
            Missing { key } => write!(f, "missing field {key}"),
            WrongType {
                key,
                expected,
                found,
            } => {
                write!(f, "field {key}: expected {expected}, found {found}")
            }
            WrongLength {
                key,
                expected,
                found,
            } => {
                write!(f, "field {key}: expected {expected} bytes, found {found}")
            }
            IntegerOutOfRange => write!(f, "integer outside -2^60 ..= 2^60 - 1"),
            WrongKind { expected, found } => write!(f, "expected {expected:?}, found {found:?}"),
            Invalid(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for SchemaError {}

/// Either kind of failure when reading a typed object from bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The bytes are not one canonical value.
    Decode(DecodeError),
    /// The value does not match the expected schema.
    Schema(SchemaError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Decode(e) => e.fmt(f),
            Error::Schema(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Decode(e) => Some(e),
            Error::Schema(e) => Some(e),
        }
    }
}

impl From<DecodeError> for Error {
    fn from(e: DecodeError) -> Error {
        Error::Decode(e)
    }
}

impl From<SchemaError> for Error {
    fn from(e: SchemaError) -> Error {
        Error::Schema(e)
    }
}
