//! Identity entries (kind 2) and their ops (`identity.md#entries`,
//! `identity.md#operations`).
//!
//! An entry is kept as its signed object, whose body bytes are never
//! re-encoded, so unknown fields anywhere in it are preserved and the id
//! never changes. Each op is kept as its record together with a typed
//! reading of the fields this implementation knows.

use cardinal_crypto::{verify, verify_object_signature, HybridPublicKey, Sealed, SigningKey};
use cardinal_encoding::kind::IDENTITY_ENTRY;
use cardinal_encoding::{varint, Kind, Record, SignedObject, Value};

use crate::Error;

/// Entries MUST NOT exceed 64 KiB.
pub const MAX_ENTRY_SIZE: usize = 64 * 1024;

/// An entry id, and an identity id (the id of its genesis entry).
pub type EntryId = [u8; 32];

/// An Ed25519 public key.
pub type KeyId = [u8; 32];

/// The domain of an `add_key` proof of possession.
pub const ADD_KEY_DOMAIN: &[u8] = b"cardinal add key";

/// A key's power.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Power {
    /// May add or remove nothing.
    Device = 1,
    /// May add device and admin keys and remove device keys.
    Admin = 2,
    /// Offline; may replace itself.
    Root = 3,
}

impl Power {
    /// The power with this value.
    pub fn from_u64(v: u64) -> Option<Power> {
        Some(match v {
            1 => Power::Device,
            2 => Power::Admin,
            3 => Power::Root,
            _ => return None,
        })
    }

    /// The value.
    pub fn value(self) -> u64 {
        self as u64
    }
}

/// A protocol record (`evolution.md#declaring-what-you-speak`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Protocol {
    /// The base hash; 32 zero bytes for drafts.
    pub base: [u8; 32],
    /// Extensions this identity uses.
    pub extensions: Vec<[u8; 32]>,
}

impl Protocol {
    /// The draft base with no extensions.
    pub fn draft() -> Protocol {
        Protocol {
            base: [0; 32],
            extensions: Vec::new(),
        }
    }

    /// The record form.
    pub fn to_record(&self) -> Record {
        Record::new().with(1, self.base).with(
            2,
            Value::List(self.extensions.iter().map(|e| Value::from(*e)).collect()),
        )
    }

    /// Reads the record form.
    pub fn from_record(r: &Record) -> Result<Protocol, Error> {
        let mut extensions = Vec::new();
        for v in r.opt_list(2)?.unwrap_or(&[]) {
            extensions.push(bytes32(v)?);
        }
        Ok(Protocol {
            base: r.bytes_n(1)?,
            extensions,
        })
    }
}

/// A wrap `{1: target signing key, 2: fingerprint of the encryption key,
/// 3: sealed record}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Wrap {
    /// The key it is for.
    pub target: KeyId,
    /// The fingerprint of the wrapped encryption public key.
    pub fingerprint: [u8; 32],
    /// The encryption private key material sealed to the target's link key.
    pub sealed: Sealed,
}

impl Wrap {
    /// The record form.
    pub fn to_record(&self) -> Record {
        Record::new()
            .with(1, self.target)
            .with(2, self.fingerprint)
            .with(3, self.sealed.to_record())
    }

    /// Reads the record form.
    pub fn from_record(r: &Record) -> Result<Wrap, Error> {
        Ok(Wrap {
            target: r.bytes_n(1)?,
            fingerprint: r.bytes_n(2)?,
            sealed: Sealed::from_record(r.record(3)?)?,
        })
    }
}

/// The typed reading of an op.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpBody {
    /// 1 `add_key`.
    AddKey {
        /// The signing key.
        key: KeyId,
        /// Its power (as written; may be out of range).
        power: u64,
        /// Its link key (device and admin keys).
        link_key: Option<HybridPublicKey>,
        /// The proof of possession.
        proof: Option<[u8; 64]>,
        /// The recovery public key (roots).
        recovery_key: Option<HybridPublicKey>,
    },
    /// 2 `remove_key`.
    RemoveKey {
        /// The key.
        key: KeyId,
    },
    /// 3 `set_encryption_key`.
    SetEncryptionKey {
        /// The new public key.
        public: HybridPublicKey,
        /// Wraps of the private key to device and admin keys.
        wraps: Vec<Wrap>,
        /// Sealed to recovery public keys and the guardian key.
        recovery_wraps: Vec<Sealed>,
        /// Earlier private keys sealed to the new public key.
        key_chain: Vec<Sealed>,
    },
    /// 4 `wrap`.
    Wrap {
        /// The wraps.
        wraps: Vec<Wrap>,
    },
    /// 5 `set_recovery`.
    SetRecovery {
        /// Guardian commitments.
        commitments: Vec<[u8; 32]>,
        /// The threshold.
        threshold: u64,
        /// The delay in seconds.
        delay: u64,
        /// Sealed guardian records.
        guardian_records: Vec<Sealed>,
        /// The guardian public key.
        guardian_key: Option<HybridPublicKey>,
        /// Recovery wraps of the current encryption key.
        recovery_wraps: Vec<Sealed>,
        /// The policy this changes (absent in genesis).
        changes: Option<EntryId>,
        /// The controller of a policy naming no guardians.
        controller: Option<KeyId>,
    },
    /// 6 `recover`.
    Recover {
        /// The new root key.
        root: KeyId,
        /// Keys to keep.
        keep: Vec<KeyId>,
        /// Link key of the device that receives shares.
        link_key: Option<HybridPublicKey>,
        /// The policy it acts under.
        policy: EntryId,
        /// The new root's recovery public key.
        recovery_key: Option<HybridPublicKey>,
    },
    /// 7 `endorse`, in a guardian's own log.
    Endorse {
        /// The decision.
        decision: EntryId,
        /// Position of the guardian's commitment, from 1.
        position: u64,
        /// Its salt.
        salt: [u8; 32],
    },
    /// 8 `confirm`, in a guardian's own log.
    Confirm {
        /// The decision.
        decision: EntryId,
        /// Position of the guardian's commitment, from 1.
        position: u64,
        /// Its salt.
        salt: [u8; 32],
        /// The sealed share (recoveries only).
        share: Option<Sealed>,
    },
    /// 9 `object`.
    Object {
        /// The decision objected to.
        decision: EntryId,
    },
    /// 10 `set_protocol`.
    SetProtocol {
        /// The protocol record.
        protocol: Protocol,
    },
    /// An extension op: key 0 is the extension's 32-byte name.
    Extension {
        /// The extension's name.
        name: [u8; 32],
    },
    /// An op number this implementation does not define, or an op whose
    /// fields do not have the required types. No key may sign it.
    Malformed,
}

/// One op: its record, preserved, and the typed reading.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityOp {
    record: Record,
    body: OpBody,
}

fn bytes32(v: &Value) -> Result<[u8; 32], Error> {
    v.as_bytes()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or(Error::Malformed("expected 32 bytes"))
}

fn list32(r: &Record, key: u64) -> Result<Vec<[u8; 32]>, Error> {
    r.opt_list(key)?
        .unwrap_or(&[])
        .iter()
        .map(bytes32)
        .collect()
}

fn sealed_list(r: &Record, key: u64) -> Result<Vec<Sealed>, Error> {
    let mut out = Vec::new();
    for v in r.opt_list(key)?.unwrap_or(&[]) {
        let rec = v.as_record().ok_or(Error::Malformed("expected a record"))?;
        out.push(Sealed::from_record(rec)?);
    }
    Ok(out)
}

fn wrap_list(r: &Record, key: u64) -> Result<Vec<Wrap>, Error> {
    let mut out = Vec::new();
    for v in r.opt_list(key)?.unwrap_or(&[]) {
        let rec = v.as_record().ok_or(Error::Malformed("expected a record"))?;
        out.push(Wrap::from_record(rec)?);
    }
    Ok(out)
}

fn opt_hybrid(r: &Record, key: u64) -> Result<Option<HybridPublicKey>, Error> {
    match r.opt_record(key)? {
        Some(k) => Ok(Some(HybridPublicKey::from_record(k)?)),
        None => Ok(None),
    }
}

impl IdentityOp {
    /// Reads an op record. An op whose number is unknown or whose fields
    /// are malformed reads as [`OpBody::Malformed`]; it is kept, and makes
    /// its entry invalid.
    pub fn from_record(record: Record) -> IdentityOp {
        let body = Self::parse(&record).unwrap_or(OpBody::Malformed);
        IdentityOp { record, body }
    }

    fn parse(r: &Record) -> Result<OpBody, Error> {
        let n = match r.get(0).and_then(Kind::from_value) {
            Some(Kind::Core(n)) => n,
            Some(Kind::Named(name)) => return Ok(OpBody::Extension { name }),
            None => return Ok(OpBody::Malformed),
        };
        Ok(match n {
            1 => OpBody::AddKey {
                key: r.bytes_n(1)?,
                power: r.uint(2)?,
                link_key: opt_hybrid(r, 3)?,
                proof: r.opt_bytes_n(5)?,
                recovery_key: opt_hybrid(r, 6)?,
            },
            2 => OpBody::RemoveKey { key: r.bytes_n(1)? },
            3 => OpBody::SetEncryptionKey {
                public: HybridPublicKey::from_record(r.record(1)?)?,
                wraps: wrap_list(r, 2)?,
                recovery_wraps: sealed_list(r, 3)?,
                key_chain: sealed_list(r, 4)?,
            },
            4 => OpBody::Wrap {
                wraps: wrap_list(r, 1)?,
            },
            5 => OpBody::SetRecovery {
                commitments: list32(r, 1)?,
                threshold: r.opt_uint(2)?.unwrap_or(0),
                delay: r.opt_uint(3)?.unwrap_or(0),
                guardian_records: sealed_list(r, 4)?,
                guardian_key: opt_hybrid(r, 5)?,
                recovery_wraps: sealed_list(r, 6)?,
                changes: r.opt_bytes_n(7)?,
                controller: r.opt_bytes_n(8)?,
            },
            6 => OpBody::Recover {
                root: r.bytes_n(1)?,
                keep: list32(r, 2)?,
                link_key: opt_hybrid(r, 3)?,
                policy: r.bytes_n(4)?,
                recovery_key: opt_hybrid(r, 5)?,
            },
            7 => OpBody::Endorse {
                decision: r.bytes_n(1)?,
                position: r.uint(2)?,
                salt: r.bytes_n(3)?,
            },
            8 => OpBody::Confirm {
                decision: r.bytes_n(1)?,
                position: r.uint(2)?,
                salt: r.bytes_n(3)?,
                share: match r.opt_record(4)? {
                    Some(s) => Some(Sealed::from_record(s)?),
                    None => None,
                },
            },
            9 => OpBody::Object {
                decision: r.bytes_n(1)?,
            },
            10 => OpBody::SetProtocol {
                protocol: Protocol::from_record(r.record(1)?)?,
            },
            _ => OpBody::Malformed,
        })
    }

    /// The record, as written.
    pub fn record(&self) -> &Record {
        &self.record
    }

    /// The typed reading.
    pub fn body(&self) -> &OpBody {
        &self.body
    }

    /// `add_key`. `proof` is required except for the genesis root.
    pub fn add_key(
        key: KeyId,
        power: Power,
        link_key: Option<&HybridPublicKey>,
        proof: Option<[u8; 64]>,
        recovery_key: Option<&HybridPublicKey>,
    ) -> IdentityOp {
        let r = Record::new()
            .with(0, 1u32)
            .with(1, key)
            .with(2, power.value() as u32)
            .with_opt(3, link_key.map(|k| k.to_record()))
            .with_opt(5, proof)
            .with_opt(6, recovery_key.map(|k| k.to_record()));
        IdentityOp::from_record(r)
    }

    /// `remove_key`.
    pub fn remove_key(key: KeyId) -> IdentityOp {
        IdentityOp::from_record(Record::new().with(0, 2u32).with(1, key))
    }

    /// `set_encryption_key`.
    pub fn set_encryption_key(
        public: &HybridPublicKey,
        wraps: &[Wrap],
        recovery_wraps: &[Sealed],
        key_chain: &[Sealed],
    ) -> IdentityOp {
        let r = Record::new()
            .with(0, 3u32)
            .with(1, public.to_record())
            .with(2, Value::list(wraps.iter().map(Wrap::to_record)))
            .with(3, Value::list(recovery_wraps.iter().map(Sealed::to_record)))
            .with(4, Value::list(key_chain.iter().map(Sealed::to_record)));
        IdentityOp::from_record(r)
    }

    /// `wrap`.
    pub fn wrap(wraps: &[Wrap]) -> IdentityOp {
        IdentityOp::from_record(
            Record::new()
                .with(0, 4u32)
                .with(1, Value::list(wraps.iter().map(Wrap::to_record))),
        )
    }

    /// `set_recovery` naming no guardians: the policy of a guardian-less
    /// identity. `changes` and `controller` are absent in genesis.
    pub fn set_recovery_unguarded(
        changes: Option<EntryId>,
        controller: Option<KeyId>,
    ) -> IdentityOp {
        let r = Record::new()
            .with(0, 5u32)
            .with(1, Value::List(Vec::new()))
            .with(2, 0u32)
            .with(3, 0u32)
            .with(4, Value::List(Vec::new()))
            .with_opt(7, changes)
            .with_opt(8, controller);
        IdentityOp::from_record(r)
    }

    /// `object`.
    pub fn object(decision: EntryId) -> IdentityOp {
        IdentityOp::from_record(Record::new().with(0, 9u32).with(1, decision))
    }

    /// `set_protocol`.
    pub fn set_protocol(protocol: &Protocol) -> IdentityOp {
        IdentityOp::from_record(Record::new().with(0, 10u32).with(1, protocol.to_record()))
    }
}

/// The message an added key signs to prove possession:
/// `"cardinal add key" || binding || signing key || varint(power) ||
/// encoding of link key`, where `binding` is the identity id, or the root
/// key in the genesis entry. With no link key (roots), the last part is
/// empty.
pub fn add_key_proof_message(
    binding: &[u8; 32],
    key: &KeyId,
    power: u64,
    link_key: Option<&HybridPublicKey>,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(16 + 64 + 9 + 1300);
    m.extend_from_slice(ADD_KEY_DOMAIN);
    m.extend_from_slice(binding);
    m.extend_from_slice(key);
    m.extend_from_slice(&varint(power));
    if let Some(k) = link_key {
        m.extend_from_slice(&k.encode());
    }
    m
}

/// The proof of possession by `key` of joining with `binding` at `power`.
pub fn add_key_proof(
    key: &SigningKey,
    binding: &[u8; 32],
    power: Power,
    link_key: Option<&HybridPublicKey>,
) -> [u8; 64] {
    key.sign(&add_key_proof_message(
        binding,
        &key.public_key(),
        power.value(),
        link_key,
    ))
}

/// Checks an `add_key` proof.
pub fn check_add_key_proof(
    binding: &[u8; 32],
    key: &KeyId,
    power: u64,
    link_key: Option<&HybridPublicKey>,
    proof: &[u8; 64],
) -> bool {
    verify(
        key,
        &add_key_proof_message(binding, key, power, link_key),
        proof,
    )
    .is_ok()
}

/// An identity entry: a signed object with exactly one signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityEntry {
    signed: SignedObject,
    identity: Option<EntryId>,
    parents: Vec<EntryId>,
    ops: Vec<IdentityOp>,
    protocol: Option<Protocol>,
}

impl IdentityEntry {
    /// Decodes and checks an entry: kind 2, exactly one valid signature,
    /// at most 64 KiB, and the field shapes of `identity.md#entries`.
    /// Whether the entry is *valid* in its log is decided by evaluation.
    pub fn decode(bytes: &[u8]) -> Result<IdentityEntry, Error> {
        if bytes.len() > MAX_ENTRY_SIZE {
            return Err(Error::TooLarge);
        }
        Self::from_signed(SignedObject::decode(bytes)?)
    }

    /// Checks a signed object as an identity entry (see [`decode`](Self::decode)).
    pub fn from_signed(signed: SignedObject) -> Result<IdentityEntry, Error> {
        if signed.encode().len() > MAX_ENTRY_SIZE {
            return Err(Error::TooLarge);
        }
        let r = signed.inner();
        if r.kind()? != Kind::Core(IDENTITY_ENTRY) {
            return Err(Error::Malformed("not an identity entry"));
        }
        if signed.signatures().len() != 1 {
            return Err(Error::Malformed("an entry has exactly one signature"));
        }
        verify_object_signature(&signed, &signed.signatures()[0])
            .map_err(|_| Error::BadSignature)?;
        let identity: Option<EntryId> = r.opt_bytes_n(1)?;
        let parents = list32(r, 2)?;
        if r.contains(4) {
            return Err(Error::Malformed("field 4 is reserved"));
        }
        match identity {
            None if r.contains(2) => {
                return Err(Error::Malformed("genesis has no parents"));
            }
            Some(_) if parents.is_empty() => {
                return Err(Error::Malformed("a non-genesis entry has parents"));
            }
            Some(_) if r.contains(5) => {
                return Err(Error::Malformed("protocol is genesis only"));
            }
            _ => {}
        }
        let mut sorted = parents.clone();
        sorted.sort_unstable();
        sorted.dedup();
        if sorted.len() != parents.len() {
            return Err(Error::Malformed("repeated parent"));
        }
        let ops = r
            .opt_list(3)?
            .unwrap_or(&[])
            .iter()
            .map(|v| {
                v.as_record()
                    .cloned()
                    .map(IdentityOp::from_record)
                    .ok_or(Error::Malformed("an op is a record"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let protocol = match r.opt_record(5)? {
            Some(p) => Some(Protocol::from_record(p)?),
            None => None,
        };
        Ok(IdentityEntry {
            signed,
            identity,
            parents,
            ops,
            protocol,
        })
    }

    /// The entry id: the id of the signed object.
    pub fn id(&self) -> EntryId {
        self.signed.id()
    }

    /// The identity this entry belongs to: field 1, or its own id for the
    /// genesis entry.
    pub fn identity(&self) -> EntryId {
        self.identity.unwrap_or_else(|| self.id())
    }

    /// Whether this is a genesis entry.
    pub fn is_genesis(&self) -> bool {
        self.identity.is_none()
    }

    /// The parents.
    pub fn parents(&self) -> &[EntryId] {
        &self.parents
    }

    /// The ops, in order.
    pub fn ops(&self) -> &[IdentityOp] {
        &self.ops
    }

    /// The protocol record (genesis only).
    pub fn protocol(&self) -> Option<&Protocol> {
        self.protocol.as_ref()
    }

    /// The signing key.
    pub fn signer(&self) -> KeyId {
        self.signed.signatures()[0].key
    }

    /// The signed object.
    pub fn signed(&self) -> &SignedObject {
        &self.signed
    }

    /// The inner record, with any unknown fields.
    pub fn record(&self) -> &Record {
        self.signed.inner()
    }

    /// The encoding of the signed object.
    pub fn encode(&self) -> Vec<u8> {
        self.signed.encode()
    }
}

/// Builds and signs an identity entry.
#[derive(Clone, Debug, Default)]
pub struct EntryBuilder {
    identity: Option<EntryId>,
    parents: Vec<EntryId>,
    ops: Vec<IdentityOp>,
    protocol: Option<Protocol>,
    extra: Record,
}

impl EntryBuilder {
    /// A genesis entry speaking `protocol`.
    pub fn genesis(protocol: Protocol) -> EntryBuilder {
        EntryBuilder {
            protocol: Some(protocol),
            ..EntryBuilder::default()
        }
    }

    /// An entry of `identity` following `parents`.
    pub fn new(identity: EntryId, parents: &[EntryId]) -> EntryBuilder {
        let mut parents = parents.to_vec();
        parents.sort_unstable();
        parents.dedup();
        EntryBuilder {
            identity: Some(identity),
            parents,
            ..EntryBuilder::default()
        }
    }

    /// Appends an op.
    pub fn op(mut self, op: IdentityOp) -> EntryBuilder {
        self.ops.push(op);
        self
    }

    /// Adds a field this implementation does not define (for tests of
    /// unknown-field preservation).
    pub fn extra_field(mut self, key: u64, value: impl Into<Value>) -> EntryBuilder {
        self.extra.insert(key, value);
        self
    }

    /// The inner record.
    pub fn record(&self) -> Record {
        self.extra
            .clone()
            .with(0, IDENTITY_ENTRY as u32)
            .with_opt(1, self.identity)
            .with_opt(
                2,
                (!self.parents.is_empty())
                    .then(|| Value::list(self.parents.iter().map(|p| Value::from(*p)))),
            )
            .with(3, Value::list(self.ops.iter().map(|o| o.record.clone())))
            .with_opt(5, self.protocol.as_ref().map(Protocol::to_record))
    }

    /// Signs the entry with `key`.
    pub fn sign(self, key: &SigningKey) -> Result<IdentityEntry, Error> {
        let mut obj = SignedObject::new(self.record());
        key.sign_object(&mut obj);
        IdentityEntry::from_signed(obj)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_preserves_unknown_fields() {
        let root = SigningKey::from_seed(&[1; 32]);
        let op = Record::new()
            .with(0, 2u32)
            .with(1, [5u8; 32])
            .with(9, "later");
        let e = EntryBuilder::new([7; 32], &[[3; 32], [2; 32]])
            .op(IdentityOp::from_record(op.clone()))
            .op(IdentityOp::from_record(Record::new().with(0, 77u32)))
            .op(IdentityOp::from_record(Record::new().with(0, [9u8; 32])))
            .extra_field(12, "future")
            .sign(&root)
            .unwrap();
        let bytes = e.encode();
        let back = IdentityEntry::decode(&bytes).unwrap();
        assert_eq!(back, e);
        assert_eq!(back.encode(), bytes);
        assert_eq!(back.parents(), &[[2; 32], [3; 32]]);
        assert_eq!(back.ops()[0].record(), &op);
        assert_eq!(back.ops()[0].body(), &OpBody::RemoveKey { key: [5; 32] });
        assert_eq!(back.ops()[1].body(), &OpBody::Malformed);
        assert_eq!(back.ops()[2].body(), &OpBody::Extension { name: [9; 32] });
        assert_eq!(back.record().text(12).unwrap(), "future");
        assert_eq!(back.signer(), root.public_key());
        assert_eq!(back.identity(), [7; 32]);
    }

    #[test]
    fn rejects_bad_shapes() {
        let k = SigningKey::from_seed(&[1; 32]);
        // a tampered signature
        let e = EntryBuilder::genesis(Protocol::draft()).sign(&k).unwrap();
        let mut bytes = e.encode();
        let n = bytes.len();
        bytes[n - 1] ^= 1;
        assert_eq!(IdentityEntry::decode(&bytes), Err(Error::BadSignature));
        // two signatures
        let mut obj = e.signed().clone();
        SigningKey::from_seed(&[2; 32]).sign_object(&mut obj);
        assert!(IdentityEntry::from_signed(obj).is_err());
        // a non-genesis entry without parents
        assert!(EntryBuilder::new([1; 32], &[]).sign(&k).is_err());
    }

    #[test]
    fn proof_of_possession() {
        let k = SigningKey::from_seed(&[4; 32]);
        let p = add_key_proof(&k, &[1; 32], Power::Admin, None);
        assert!(check_add_key_proof(&[1; 32], &k.public_key(), 2, None, &p));
        assert!(!check_add_key_proof(&[1; 32], &k.public_key(), 1, None, &p));
        assert!(!check_add_key_proof(&[2; 32], &k.public_key(), 2, None, &p));
    }
}
