//! Signed objects (`encoding.md#signed-objects`): structure only.
//!
//! Producing and checking the Ed25519 signatures is the job of
//! `cardinal-crypto`, which works on [`SignedObject::signing_message`].

use crate::kind::SIGNED_OBJECT;
use crate::{Error, Kind, Record, SchemaError, Value};

/// The domain prefix of every object signature.
pub const SIGNATURE_DOMAIN: &[u8; 14] = b"cardinal sig 1";

/// The length of the message each signature covers: the domain and the id.
pub const SIGNING_MESSAGE_LEN: usize = 46;

/// One signature record `{1: key, 2: signature}`, with any unknown fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectSignature {
    /// The Ed25519 public key.
    pub key: [u8; 32],
    /// The Ed25519 signature over [`SignedObject::signing_message`].
    pub signature: [u8; 64],
    /// Fields other than 1 and 2, preserved.
    pub extra: Record,
}

impl ObjectSignature {
    /// A signature with no extra fields.
    pub fn new(key: [u8; 32], signature: [u8; 64]) -> ObjectSignature {
        ObjectSignature {
            key,
            signature,
            extra: Record::new(),
        }
    }

    /// The signature record.
    pub fn to_record(&self) -> Record {
        let mut r = self.extra.clone();
        r.insert(1, self.key);
        r.insert(2, self.signature);
        r
    }

    /// Reads a signature record.
    pub fn from_record(r: &Record) -> Result<ObjectSignature, SchemaError> {
        Ok(ObjectSignature {
            key: r.bytes_n(1)?,
            signature: r.bytes_n(2)?,
            extra: r.without(&[1, 2]),
        })
    }
}

/// A signed object `{0: 1, 1: body, 2: signatures}`.
///
/// The body is kept as its original bytes; the id is `BLAKE3(body)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedObject {
    body: Vec<u8>,
    inner: Record,
    signatures: Vec<ObjectSignature>,
    extra: Record,
}

impl SignedObject {
    /// An unsigned object wrapping `inner`.
    pub fn new(inner: Record) -> SignedObject {
        SignedObject {
            body: inner.encode(),
            inner,
            signatures: Vec::new(),
            extra: Record::new(),
        }
    }

    /// An unsigned object from the canonical bytes of an inner record.
    pub fn from_body(body: Vec<u8>) -> Result<SignedObject, Error> {
        let inner = Record::decode(&body)?;
        Ok(SignedObject {
            body,
            inner,
            signatures: Vec::new(),
            extra: Record::new(),
        })
    }

    /// The canonical bytes of the inner record.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// The inner record.
    pub fn inner(&self) -> &Record {
        &self.inner
    }

    /// The object id, `BLAKE3(body)`.
    pub fn id(&self) -> [u8; 32] {
        object_id(&self.body)
    }

    /// The 46 bytes each signature covers: `"cardinal sig 1" || id`.
    pub fn signing_message(&self) -> [u8; SIGNING_MESSAGE_LEN] {
        signing_message(&self.id())
    }

    /// The signatures, sorted by key.
    pub fn signatures(&self) -> &[ObjectSignature] {
        &self.signatures
    }

    /// Fields of the outer record other than 0, 1, and 2, preserved.
    pub fn extra(&self) -> &Record {
        &self.extra
    }

    /// Adds a signature, replacing any existing one by the same key, and
    /// keeps the list sorted. Does not check the signature.
    pub fn add_signature(&mut self, sig: ObjectSignature) {
        match self.signatures.binary_search_by(|s| s.key.cmp(&sig.key)) {
            Ok(i) => self.signatures[i] = sig,
            Err(i) => self.signatures.insert(i, sig),
        }
    }

    /// The outer record.
    pub fn to_record(&self) -> Record {
        let mut r = self.extra.clone();
        r.insert(0, SIGNED_OBJECT as u32);
        r.insert(1, self.body.clone());
        r.insert(
            2,
            Value::List(
                self.signatures
                    .iter()
                    .map(|s| s.to_record().into())
                    .collect(),
            ),
        );
        r
    }

    /// The canonical encoding of the outer record.
    pub fn encode(&self) -> Vec<u8> {
        self.to_record().encode()
    }

    /// Reads a signed object, checking its structure: kind 1, a body that
    /// is one canonical record, and signatures with unique keys in order.
    pub fn from_record(r: &Record) -> Result<SignedObject, Error> {
        let kind = r.kind()?;
        if kind != Kind::Core(SIGNED_OBJECT) {
            return Err(SchemaError::WrongKind {
                expected: Kind::Core(SIGNED_OBJECT),
                found: kind,
            }
            .into());
        }
        let body = r.bytes(1)?.to_vec();
        let inner = Record::decode(&body)?;
        let mut signatures = Vec::new();
        for s in r.record_list(2)? {
            let sig = ObjectSignature::from_record(s)?;
            if let Some(prev) = signatures.last() {
                let prev: &ObjectSignature = prev;
                if sig.key <= prev.key {
                    return Err(
                        SchemaError::Invalid("signature keys must be sorted and unique").into(),
                    );
                }
            }
            signatures.push(sig);
        }
        Ok(SignedObject {
            body,
            inner,
            signatures,
            extra: r.without(&[0, 1, 2]),
        })
    }

    /// Decodes and checks a signed object from its bytes.
    pub fn decode(bytes: &[u8]) -> Result<SignedObject, Error> {
        SignedObject::from_record(&Record::decode(bytes)?)
    }
}

/// The id of an object whose canonical body is `body`: `BLAKE3(body)`.
pub fn object_id(body: &[u8]) -> [u8; 32] {
    *blake3::hash(body).as_bytes()
}

/// The message signed for object id `id`: `"cardinal sig 1" || id`.
pub fn signing_message(id: &[u8; 32]) -> [u8; SIGNING_MESSAGE_LEN] {
    let mut m = [0u8; SIGNING_MESSAGE_LEN];
    m[..14].copy_from_slice(SIGNATURE_DOMAIN);
    m[14..].copy_from_slice(id);
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_sorting() {
        let inner = Record::new().with(0, 2u32).with(1, "hello");
        let mut obj = SignedObject::new(inner.clone());
        obj.add_signature(ObjectSignature::new([9; 32], [1; 64]));
        obj.add_signature(ObjectSignature::new([3; 32], [2; 64]));
        obj.add_signature(ObjectSignature::new([9; 32], [3; 64]));
        let keys: Vec<u8> = obj.signatures().iter().map(|s| s.key[0]).collect();
        assert_eq!(keys, [3, 9]);
        assert_eq!(obj.signatures()[1].signature, [3; 64]);

        let bytes = obj.encode();
        let back = SignedObject::decode(&bytes).unwrap();
        assert_eq!(back, obj);
        assert_eq!(back.inner(), &inner);
        assert_eq!(back.id(), *blake3::hash(&inner.encode()).as_bytes());
        let m = back.signing_message();
        assert_eq!(&m[..14], b"cardinal sig 1");
        assert_eq!(m[14..], back.id());
    }

    #[test]
    fn signatures_do_not_change_id() {
        let mut obj = SignedObject::new(Record::new().with(0, 2u32));
        let id = obj.id();
        obj.add_signature(ObjectSignature::new([1; 32], [1; 64]));
        assert_eq!(obj.id(), id);
    }

    #[test]
    fn rejects_bad_structure() {
        let sig = |k: u8| Value::from(ObjectSignature::new([k; 32], [0; 64]).to_record());
        let body = Record::new().with(0, 2u32).encode();
        let base = Record::new().with(0, 1u32).with(1, body.clone());

        let unsorted = base.clone().with(2, vec![sig(2), sig(1)]);
        assert!(SignedObject::from_record(&unsorted).is_err());
        let dup = base.clone().with(2, vec![sig(1), sig(1)]);
        assert!(SignedObject::from_record(&dup).is_err());
        let wrong_kind = base.clone().with(0, 3u32).with(2, Vec::<Value>::new());
        assert!(SignedObject::from_record(&wrong_kind).is_err());
        let bad_body = Record::new()
            .with(0, 1u32)
            .with(1, vec![0x06u8])
            .with(2, Vec::<Value>::new());
        assert!(SignedObject::from_record(&bad_body).is_err());
        let short_key = base.clone().with(
            2,
            vec![Value::from(
                Record::new().with(1, [0u8; 31]).with(2, [0u8; 64]),
            )],
        );
        assert!(SignedObject::from_record(&short_key).is_err());
    }

    #[test]
    fn preserves_unknown_fields() {
        let body = Record::new().with(0, 2u32).encode();
        let r = Record::new()
            .with(0, 1u32)
            .with(1, body)
            .with(
                2,
                vec![Value::from(
                    ObjectSignature::new([1; 32], [2; 64])
                        .to_record()
                        .with(9, "x"),
                )],
            )
            .with(5, "future");
        let obj = SignedObject::from_record(&r).unwrap();
        assert_eq!(obj.to_record(), r);
    }
}
