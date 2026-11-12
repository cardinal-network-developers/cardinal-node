//! Signed objects (`encoding.md#signed-objects`): structure only.
//!
//! Producing and checking the Ed25519 signatures is the job of
//! `cardinal-crypto`, which works on [`SignedObject::signing_message`].
//!
//! An id says what was signed, and by whom: it covers the body and the keys
//! of the signatures, in order. So the same body signed by another key is
//! another object, and a key is added to an object only by everyone signing
//! again.

use crate::kind::SIGNED_OBJECT;
use crate::{Error, Kind, Record, SchemaError, Value};

/// The domain prefix of every object signature.
pub const SIGNATURE_DOMAIN: &[u8; 14] = b"cardinal sig 1";

/// The length of the message each signature covers: the domain and the id.
pub const SIGNING_MESSAGE_LEN: usize = 46;

/// One signature record `{1: key, 2: signature}`. It holds nothing else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectSignature {
    /// The Ed25519 public key.
    pub key: [u8; 32],
    /// The Ed25519 signature over [`SignedObject::signing_message`].
    pub signature: [u8; 64],
}

impl ObjectSignature {
    /// A signature record.
    pub fn new(key: [u8; 32], signature: [u8; 64]) -> ObjectSignature {
        ObjectSignature { key, signature }
    }

    /// The signature record.
    pub fn to_record(&self) -> Record {
        Record::new().with(1, self.key).with(2, self.signature)
    }

    /// Reads a signature record. Nothing binds a key other than 1 and 2,
    /// so one that holds any other is rejected.
    pub fn from_record(r: &Record) -> Result<ObjectSignature, SchemaError> {
        if r.keys().any(|k| k != 1 && k != 2) {
            return Err(SchemaError::Invalid(
                "a signature record holds only a key and a signature",
            ));
        }
        Ok(ObjectSignature {
            key: r.bytes_n(1)?,
            signature: r.bytes_n(2)?,
        })
    }
}

/// A signed object `{0: 1, 1: body, 2: signatures}`. It holds nothing else.
///
/// The body is kept as its original bytes. The id is `BLAKE3` of the
/// encoding of `{1: body, 2: keys}`, the keys being those of the
/// signatures, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedObject {
    body: Vec<u8>,
    inner: Record,
    signatures: Vec<ObjectSignature>,
}

impl SignedObject {
    /// An unsigned object wrapping `inner`.
    pub fn new(inner: Record) -> SignedObject {
        SignedObject {
            body: inner.encode(),
            inner,
            signatures: Vec::new(),
        }
    }

    /// An unsigned object from the canonical bytes of an inner record.
    pub fn from_body(body: Vec<u8>) -> Result<SignedObject, Error> {
        let inner = Record::decode(&body)?;
        Ok(SignedObject {
            body,
            inner,
            signatures: Vec::new(),
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

    /// The object id: it covers the body and the keys of the signatures
    /// the object bears now. An object with no signature yet has the id of
    /// the body signed by nobody.
    pub fn id(&self) -> [u8; 32] {
        let keys: Vec<[u8; 32]> = self.signatures.iter().map(|s| s.key).collect();
        object_id(&self.body, &keys)
    }

    /// The 46 bytes each signature covers: `"cardinal sig 1" || id`.
    pub fn signing_message(&self) -> [u8; SIGNING_MESSAGE_LEN] {
        signing_message(&self.id())
    }

    /// The signatures, sorted by key.
    pub fn signatures(&self) -> &[ObjectSignature] {
        &self.signatures
    }

    /// Signs the object by `keys`, replacing whatever signatures it bore:
    /// `sign` is given each key and the message it signs, which names them
    /// all. The id covers the signing keys, so a signer cannot be added to
    /// an object afterwards without the others signing again.
    pub fn sign_with(
        &mut self,
        keys: &[[u8; 32]],
        mut sign: impl FnMut(&[u8; 32], &[u8; SIGNING_MESSAGE_LEN]) -> [u8; 64],
    ) {
        let mut keys = keys.to_vec();
        keys.sort_unstable();
        keys.dedup();
        let message = signing_message(&object_id(&self.body, &keys));
        self.signatures = keys
            .iter()
            .map(|k| ObjectSignature::new(*k, sign(k, &message)))
            .collect();
    }

    /// Puts a signature record in its place, replacing any by the same
    /// key, and keeps the list sorted. Does not check the signature. A key
    /// that was not there changes the id, and with it what every signature
    /// has to cover: this is for reading and for tests, and
    /// [`sign_with`](Self::sign_with) is for signing.
    pub fn add_signature(&mut self, sig: ObjectSignature) {
        match self.signatures.binary_search_by(|s| s.key.cmp(&sig.key)) {
            Ok(i) => self.signatures[i] = sig,
            Err(i) => self.signatures.insert(i, sig),
        }
    }

    /// The outer record.
    pub fn to_record(&self) -> Record {
        let signatures = self.signatures.iter().map(|s| s.to_record().into());
        Record::new()
            .with(0, SIGNED_OBJECT as u32)
            .with(1, self.body.clone())
            .with(2, Value::List(signatures.collect()))
    }

    /// The canonical encoding of the outer record.
    pub fn encode(&self) -> Vec<u8> {
        self.to_record().encode()
    }

    /// Reads a signed object, checking its structure: kind 1, a body that
    /// is one canonical record, signatures with unique keys in order, and
    /// no key but these three. Neither the id nor a signature covers
    /// anything else in the record, so anyone could add to it.
    pub fn from_record(r: &Record) -> Result<SignedObject, Error> {
        let kind = r.kind()?;
        if kind != Kind::Core(SIGNED_OBJECT) {
            return Err(SchemaError::WrongKind {
                expected: Kind::Core(SIGNED_OBJECT),
                found: kind,
            }
            .into());
        }
        if r.keys().any(|k| k > 2) {
            return Err(
                SchemaError::Invalid("a signed object holds only its body and signatures").into(),
            );
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
        })
    }

    /// Decodes and checks a signed object from its bytes.
    pub fn decode(bytes: &[u8]) -> Result<SignedObject, Error> {
        SignedObject::from_record(&Record::decode(bytes)?)
    }
}

/// The id of an object whose canonical body is `body`, signed by `keys`,
/// in the order its signatures are in: `BLAKE3` of the encoding of
/// `{1: body, 2: keys}`.
pub fn object_id(body: &[u8], keys: &[[u8; 32]]) -> [u8; 32] {
    let keys = Value::list(keys.iter().map(|k| Value::from(*k)));
    let covered = Record::new().with(1, body.to_vec()).with(2, keys);
    *blake3::hash(&covered.encode()).as_bytes()
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
        // the id covers the body and the two keys, in order
        let covered = Record::new()
            .with(1, inner.encode())
            .with(2, vec![Value::from([3u8; 32]), Value::from([9u8; 32])]);
        assert_eq!(back.id(), *blake3::hash(&covered.encode()).as_bytes());
        assert_eq!(back.id(), object_id(&inner.encode(), &[[3; 32], [9; 32]]));
        let m = back.signing_message();
        assert_eq!(&m[..14], b"cardinal sig 1");
        assert_eq!(m[14..], back.id());
    }

    #[test]
    fn an_id_says_what_was_signed_and_by_whom() {
        let mut obj = SignedObject::new(Record::new().with(0, 2u32));
        let unsigned = obj.id();
        obj.add_signature(ObjectSignature::new([1; 32], [1; 64]));
        let by_one = obj.id();
        assert_ne!(by_one, unsigned);
        // the signature's bytes are not in the id: only its key is
        obj.add_signature(ObjectSignature::new([1; 32], [7; 64]));
        assert_eq!(obj.id(), by_one);
        // the same body under another key is another object
        let mut other = SignedObject::new(Record::new().with(0, 2u32));
        other.add_signature(ObjectSignature::new([2; 32], [1; 64]));
        assert_ne!(other.id(), by_one);
        // and so is the same body under both
        obj.add_signature(ObjectSignature::new([2; 32], [1; 64]));
        assert_ne!(obj.id(), by_one);
        assert_ne!(obj.id(), other.id());
    }

    #[test]
    fn signers_sign_the_id_that_names_them_all() {
        let mut obj = SignedObject::new(Record::new().with(0, 2u32).with(1, "x"));
        let mut seen = Vec::new();
        obj.sign_with(&[[9; 32], [3; 32], [9; 32]], |key, message| {
            seen.push((*key, *message));
            [key[0]; 64]
        });
        let keys: Vec<u8> = obj.signatures().iter().map(|s| s.key[0]).collect();
        assert_eq!(keys, [3, 9]);
        // each was given the message of the object as it now is
        assert_eq!(seen.len(), 2);
        assert!(seen.iter().all(|(_, m)| *m == obj.signing_message()));
        // signing again by one of them alone replaces both
        obj.sign_with(&[[3; 32]], |_, _| [0; 64]);
        assert_eq!(obj.signatures().len(), 1);
        assert_ne!(obj.signing_message(), seen[0].1);
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
    fn rejects_keys_that_nothing_binds() {
        // Neither the id nor a signature covers anything in the wrapper or a
        // signature record but their own fields, so anyone could add to
        // them: a decoder refuses.
        let body = Record::new()
            .with(0, 2u32)
            .with(40, "an unknown field")
            .encode();
        let sig = ObjectSignature::new([1; 32], [2; 64]).to_record();
        let good = Record::new()
            .with(0, 1u32)
            .with(1, body)
            .with(2, vec![Value::from(sig.clone())]);
        let obj = SignedObject::from_record(&good).unwrap();
        assert_eq!(obj.to_record(), good);
        // what an extension adds goes in the body, and is kept there
        assert_eq!(obj.inner().text(40).unwrap(), "an unknown field");
        let more = good.clone().with(5, "future");
        assert!(SignedObject::from_record(&more).is_err());
        let more = good.clone().with(2, vec![Value::from(sig.with(9, "x"))]);
        assert!(SignedObject::from_record(&more).is_err());
    }
}
