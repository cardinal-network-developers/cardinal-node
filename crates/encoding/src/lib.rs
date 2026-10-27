//! The canonical binary encoding of the Cardinal protocol
//! (`core/spec/encoding.md`).
//!
//! Every value has exactly one encoding. The encoder produces it, and the
//! decoder rejects anything else: non-minimal varints, record keys out of
//! order or repeated, reserved types 6 and 7, invalid UTF-8, nesting deeper
//! than [`MAX_DEPTH`], and trailing bytes. Because of that, a decoded value
//! re-encodes to exactly its original bytes, and records keep every field,
//! known or not.
//!
//! ```
//! use cardinal_encoding::Record;
//!
//! let r = Record::new().with(0, 6u32).with(1, vec![0x0a, 0x0b]).with(3, "Ana");
//! let bytes = r.encode();
//! assert_eq!(bytes, [0x1d, 0x00, 0x30, 0x01, 0x12, 0x0a, 0x0b, 0x03, 0x1b, 0x41, 0x6e, 0x61]);
//! assert_eq!(r.to_string(), r#"{0: 6, 1: h'0a0b', 3: "Ana"}"#);
//!
//! let back = Record::decode(&bytes).unwrap();
//! assert_eq!(back.uint(0).unwrap(), 6);
//! assert_eq!(back.text(3).unwrap(), "Ana");
//! ```

mod codec;
mod error;
pub mod kind;
mod signed;
mod text;
mod value;
pub mod varint;

pub use codec::{decode, decode_prefix, validate, MAX_DEPTH};
pub use error::{DecodeError, Error, SchemaError};
pub use kind::Kind;
pub use signed::{
    object_id, signing_message, ObjectSignature, SignedObject, SIGNATURE_DOMAIN,
    SIGNING_MESSAGE_LEN,
};
pub use value::{Int, Record, Value};
pub use varint::{read_varint, varint, write_varint};

/// A stored object: its original bytes together with the decoded record.
///
/// Objects are stored and forwarded as their original bytes, never
/// re-encoded (`encoding.md#unknown-fields`). Since decoding is strict, the
/// bytes are always the canonical encoding of the record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Object {
    bytes: Vec<u8>,
    record: Record,
}

impl Object {
    /// Decodes an object; it must be exactly one record.
    pub fn decode(bytes: Vec<u8>) -> Result<Object, DecodeError> {
        let record = Record::decode(&bytes)?;
        Ok(Object { bytes, record })
    }

    /// Wraps a record, encoding it.
    pub fn from_record(record: Record) -> Object {
        Object {
            bytes: record.encode(),
            record,
        }
    }

    /// The original bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The decoded record.
    pub fn record(&self) -> &Record {
        &self.record
    }

    /// The kind in field 0.
    pub fn kind(&self) -> Result<Kind, SchemaError> {
        self.record.kind()
    }

    /// `BLAKE3` of the bytes.
    pub fn hash(&self) -> [u8; 32] {
        *blake3::hash(&self.bytes).as_bytes()
    }

    /// Consumes the object, returning its bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}
