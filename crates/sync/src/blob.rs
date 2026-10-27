//! Messages of the link `blob` service (`sync.md#blob-transfer`).

use cardinal_encoding::{Record, SchemaError, Value};

use crate::{Id, SyncError};

/// The most ids one blob request names.
pub const MAX_BLOB_REQUEST: usize = 64;

/// A request `{0: 1, 1: ids}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobRequest {
    /// Chunk or index ids, at most [`MAX_BLOB_REQUEST`].
    pub ids: Vec<Id>,
}

/// One item of a reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlobItem {
    /// `{1: id, 2: ciphertext}`.
    Held {
        /// The id.
        id: Id,
        /// The object's bytes.
        ciphertext: Vec<u8>,
    },
    /// `{1: id, 3: 1}`: not held.
    NotHeld(Id),
}

/// A reply `{0: 2, 1: list}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobReply {
    /// One item per requested id.
    pub items: Vec<BlobItem>,
}

impl BlobRequest {
    /// Requests for `ids`, at most 64 each.
    pub fn batches(ids: &[Id]) -> Vec<BlobRequest> {
        ids.chunks(MAX_BLOB_REQUEST)
            .map(|c| BlobRequest { ids: c.to_vec() })
            .collect()
    }

    /// The canonical encoding.
    pub fn encode(&self) -> Vec<u8> {
        Record::new()
            .with(0, 1u64)
            .with(
                1,
                Value::List(self.ids.iter().map(|i| Value::from(*i)).collect()),
            )
            .encode()
    }

    /// Decodes a request; more than 64 ids is an error.
    pub fn decode(bytes: &[u8]) -> Result<BlobRequest, SyncError> {
        let r = Record::decode(bytes)?;
        if r.uint(0)? != 1 {
            return Err(SyncError::UnknownOp(r.uint(0)?));
        }
        let list = r.list(1)?;
        if list.len() > MAX_BLOB_REQUEST {
            return Err(SchemaError::Invalid("more than 64 ids in a blob request").into());
        }
        let ids = list
            .iter()
            .map(|v| {
                v.as_bytes()
                    .and_then(|b| <[u8; 32]>::try_from(b).ok())
                    .ok_or(SchemaError::Invalid("ids must be 32 bytes"))
            })
            .collect::<Result<_, _>>()?;
        Ok(BlobRequest { ids })
    }

    /// The reply from a store: `get` returns an object's bytes if held.
    pub fn serve(&self, mut get: impl FnMut(&Id) -> Option<Vec<u8>>) -> BlobReply {
        BlobReply {
            items: self
                .ids
                .iter()
                .map(|id| match get(id) {
                    Some(ciphertext) => BlobItem::Held {
                        id: *id,
                        ciphertext,
                    },
                    None => BlobItem::NotHeld(*id),
                })
                .collect(),
        }
    }
}

impl BlobReply {
    /// The canonical encoding.
    pub fn encode(&self) -> Vec<u8> {
        let items = self
            .items
            .iter()
            .map(|i| match i {
                BlobItem::Held { id, ciphertext } => Record::new()
                    .with(1, *id)
                    .with(2, ciphertext.clone())
                    .into(),
                BlobItem::NotHeld(id) => Record::new().with(1, *id).with(3, 1u64).into(),
            })
            .collect();
        Record::new()
            .with(0, 2u64)
            .with(1, Value::List(items))
            .encode()
    }

    /// Decodes a reply.
    pub fn decode(bytes: &[u8]) -> Result<BlobReply, SyncError> {
        let r = Record::decode(bytes)?;
        if r.uint(0)? != 2 {
            return Err(SyncError::UnknownOp(r.uint(0)?));
        }
        let items = r
            .record_list(1)?
            .into_iter()
            .map(|i| -> Result<BlobItem, SyncError> {
                let id = i.bytes_n::<32>(1)?;
                Ok(match i.opt_bytes(2)? {
                    Some(c) => BlobItem::Held {
                        id,
                        ciphertext: c.to_vec(),
                    },
                    None => BlobItem::NotHeld(id),
                })
            })
            .collect::<Result<_, _>>()?;
        Ok(BlobReply { items })
    }

    /// The held objects whose bytes hash to their id
    /// (`BLAKE3(ciphertext) == id`); everything else is dropped.
    pub fn verified(self) -> Vec<(Id, Vec<u8>)> {
        self.items
            .into_iter()
            .filter_map(|i| match i {
                BlobItem::Held { id, ciphertext }
                    if blake3::hash(&ciphertext).as_bytes() == &id =>
                {
                    Some((id, ciphertext))
                }
                _ => None,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_reply() {
        let good = b"chunk".to_vec();
        let gid = *blake3::hash(&good).as_bytes();
        let req = BlobRequest {
            ids: vec![gid, [1; 32], [2; 32]],
        };
        let req = BlobRequest::decode(&req.encode()).unwrap();
        let reply = req.serve(|id| {
            if *id == gid {
                Some(good.clone())
            } else if *id == [1; 32] {
                Some(b"lies".to_vec())
            } else {
                None
            }
        });
        let reply = BlobReply::decode(&reply.encode()).unwrap();
        assert_eq!(reply.items.len(), 3);
        assert_eq!(reply.items[2], BlobItem::NotHeld([2; 32]));
        assert_eq!(reply.verified(), vec![(gid, good)]);
        assert_eq!(BlobRequest::batches(&[[0; 32]; 130]).len(), 3);
        let too_many = BlobRequest {
            ids: vec![[0; 32]; 65],
        };
        assert!(BlobRequest::decode(&too_many.encode()).is_err());
    }
}
