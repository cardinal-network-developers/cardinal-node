//! Blob references (`blobs.md#references`).

use cardinal_encoding::{Record, SchemaError};

use crate::{BlobError, Id, Key};

/// A blob reference `{1: id, 2: key, 3: size, 4: levels}`: both the
/// address of a blob and the permission to read it.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlobRef {
    /// The id of the chunk if the blob is one chunk, else of the top index.
    pub id: Id,
    /// The key of that chunk or index.
    pub key: Key,
    /// Total plaintext length.
    pub size: u64,
    /// 0 for a single chunk; otherwise the top index's level plus one.
    pub levels: u64,
}

impl BlobRef {
    /// The record form.
    pub fn to_record(&self) -> Record {
        Record::new()
            .with(1, self.id)
            .with(2, self.key)
            .with(3, self.size)
            .with(4, self.levels)
    }

    /// Reads the record form. Unknown fields are ignored.
    pub fn from_record(r: &Record) -> Result<BlobRef, BlobError> {
        let levels = r.uint(4)?;
        if levels > 8 {
            // Eight levels of 3,000 entries exceed 2^92 chunks.
            return Err(SchemaError::Invalid("blob reference levels out of range").into());
        }
        Ok(BlobRef {
            id: r.bytes_n::<32>(1)?,
            key: r.bytes_n::<32>(2)?,
            size: r.uint(3)?,
            levels,
        })
    }

    /// The canonical encoding.
    pub fn encode(&self) -> Vec<u8> {
        self.to_record().encode()
    }

    /// Decodes a reference.
    pub fn decode(bytes: &[u8]) -> Result<BlobRef, BlobError> {
        BlobRef::from_record(&Record::decode(bytes)?)
    }
}

impl std::fmt::Debug for BlobRef {
    // The key is a secret; leave it out of logs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BlobRef {{ id: {}, size: {}, levels: {} }}",
            hex(&self.id),
            self.size,
            self.levels
        )
    }
}

pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
