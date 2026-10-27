//! Space entries (kind 4), their ops, and sealed entries (kind 3)
//! (`spaces.md#entries-and-sealed-entries`, `spaces.md#control-operations`,
//! `state.md#operations`).
//!
//! Like identity entries, a space entry is kept as its signed object and
//! each op as its record, so unknown fields survive and ids never change.

use cardinal_crypto::aead::{xchacha20poly1305_decrypt, xchacha20poly1305_encrypt};
use cardinal_crypto::{keyed_hash, verify_object_signature, Sealed, SigningKey};
use cardinal_encoding::kind::{SEALED_ENTRY, SPACE_ENTRY};
use cardinal_encoding::{varint, Kind, Record, SignedObject, Value};
use cardinal_identity::{EntryId, KeyId};

use crate::epoch::{EpochId, EpochKey, Keyring};
use crate::Error;

/// A sealed entry MUST NOT exceed 256 KiB.
pub const MAX_SEALED_SIZE: usize = 256 * 1024;

/// A space id: the entry id of the genesis entry.
pub type SpaceId = [u8; 32];
/// An identity id.
pub type IdentityId = [u8; 32];
/// A membership id.
pub type MembershipId = [u8; 16];
/// A node id.
pub type NodeId = [u8; 16];

/// The id derived from an entry and an op position, for memberships and
/// nodes: the first 16 bytes of `BLAKE3(entry id || varint(i))`.
pub fn derived_id(entry: &EntryId, index: usize) -> [u8; 16] {
    let mut h = blake3::Hasher::new();
    h.update(entry);
    h.update(&varint(index as u64));
    h.finalize().as_bytes()[..16].try_into().expect("16 bytes")
}

/// A profile: a core profile number or a 32-byte schema hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Profile {
    /// A core profile (1 account, 2 files, 3 relationship, 4 group, 5 public).
    Core(u64),
    /// An application profile, named by the hash of its schema.
    Named([u8; 32]),
}

impl Profile {
    /// The account profile.
    pub const ACCOUNT: Profile = Profile::Core(1);
    /// The files profile.
    pub const FILES: Profile = Profile::Core(2);

    fn to_value(self) -> Value {
        match self {
            Profile::Core(n) => Value::from(n as u32),
            Profile::Named(h) => Value::from(h),
        }
    }

    fn from_value(v: &Value) -> Option<Profile> {
        match Kind::from_value(v)? {
            Kind::Core(n) => Some(Profile::Core(n)),
            Kind::Named(h) => Some(Profile::Named(h)),
        }
    }
}

/// A node kind: a profile-local uint or a 32-byte name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NodeKind {
    /// A profile-local kind.
    Uint(u64),
    /// A named kind.
    Named([u8; 32]),
}

impl NodeKind {
    /// The value form.
    pub fn to_value(self) -> Value {
        match self {
            NodeKind::Uint(n) => Value::Int(
                cardinal_encoding::Int::from_u64(n).unwrap_or(cardinal_encoding::Int::MAX),
            ),
            NodeKind::Named(h) => Value::from(h),
        }
    }

    fn from_value(v: &Value) -> Option<NodeKind> {
        match Kind::from_value(v)? {
            Kind::Core(n) => Some(NodeKind::Uint(n)),
            Kind::Named(h) => Some(NodeKind::Named(h)),
        }
    }
}

/// The space policy record (`spaces.md#control-operations`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    /// History shared with new members.
    pub history_shared: bool,
    /// Epoch keys are published.
    pub public: bool,
    /// Rotate after this many entries in one epoch.
    pub rotate_after: u64,
}

impl Default for Policy {
    fn default() -> Policy {
        Policy {
            history_shared: true,
            public: false,
            rotate_after: 10000,
        }
    }
}

impl Policy {
    /// The record form.
    pub fn to_record(&self) -> Record {
        Record::new()
            .with(1, self.history_shared)
            .with(2, self.public)
            .with(3, self.rotate_after as u32)
    }

    /// Reads the record form; absent fields take their defaults.
    pub fn from_record(r: &Record) -> Result<Policy, Error> {
        let d = Policy::default();
        Ok(Policy {
            history_shared: r.opt_bool(1)?.unwrap_or(d.history_shared),
            public: r.opt_bool(2)?.unwrap_or(d.public),
            rotate_after: r.opt_uint(3)?.unwrap_or(d.rotate_after),
        })
    }
}

/// The typed reading of a space op.
#[derive(Clone, Debug, PartialEq)]
pub enum SpaceOpBody {
    /// 1 `start` (genesis only).
    Start {
        /// The profile.
        profile: Profile,
        /// The policy.
        policy: Policy,
        /// The space this one succeeds.
        succeeds: Option<SpaceId>,
        /// Initial state: a blob reference to a canonical state.
        initial_state: Option<Record>,
    },
    /// 2 `add_member`.
    AddMember {
        /// The member identity.
        identity: IdentityId,
        /// Role 0 reader .. 3 owner.
        role: u64,
    },
    /// 4 `remove_member`.
    RemoveMember {
        /// The membership.
        membership: MembershipId,
    },
    /// 5 `rotate`: the keys of superseded epochs, if history is shared.
    Rotate {
        /// `(epoch id, key)` pairs.
        previous: Vec<(EpochId, [u8; 32])>,
    },
    /// 6 `set_policy`.
    SetPolicy {
        /// The policy.
        policy: Policy,
    },
    /// 7 `keep`.
    Keep {
        /// A removed signing key of the author.
        key: KeyId,
        /// Entries by that key.
        entries: Vec<EntryId>,
    },
    /// 8 `succeed`.
    Succeed {
        /// The successor space.
        successor: SpaceId,
    },
    /// 9 `set_protocol`.
    SetProtocol,
    /// 32 `create`.
    Create {
        /// The node kind.
        kind: NodeKind,
        /// The parent node.
        parent: NodeId,
        /// The name.
        name: String,
        /// Initial fields.
        fields: Record,
    },
    /// 33 `set` (value absent to clear).
    Set {
        /// The node.
        node: NodeId,
        /// The field key.
        key: u64,
        /// The value.
        value: Option<Value>,
    },
    /// 34 `move`.
    Move {
        /// The node.
        node: NodeId,
        /// The new parent.
        parent: NodeId,
        /// The new name.
        name: String,
    },
    /// 35 `delete`.
    Delete {
        /// The node.
        node: NodeId,
    },
    /// 36 `restore`.
    Restore {
        /// The node.
        node: NodeId,
    },
    /// 37 `checkpoint`.
    Checkpoint,
    /// An op this implementation does not know, or with malformed fields.
    /// Control ops (1-31) and malformed ops make an entry invalid; unknown
    /// profile ops make it not accepted for state.
    Unknown {
        /// The op number, if it has one.
        number: Option<u64>,
    },
}

impl SpaceOpBody {
    /// Whether this is a control op (1-31) or an unknown op below 32.
    pub fn is_control(&self) -> bool {
        match self {
            SpaceOpBody::Unknown { number } => number.is_none_or(|n| n < 32),
            SpaceOpBody::Create { .. }
            | SpaceOpBody::Set { .. }
            | SpaceOpBody::Move { .. }
            | SpaceOpBody::Delete { .. }
            | SpaceOpBody::Restore { .. }
            | SpaceOpBody::Checkpoint => false,
            _ => true,
        }
    }
}

/// One op: its record, preserved, and the typed reading.
#[derive(Clone, Debug, PartialEq)]
pub struct SpaceOp {
    record: Record,
    body: SpaceOpBody,
}

fn id16(r: &Record, key: u64) -> Result<[u8; 16], Error> {
    Ok(r.bytes_n::<16>(key)?)
}

impl SpaceOp {
    /// Reads an op record.
    pub fn from_record(record: Record) -> SpaceOp {
        let body = Self::parse(&record).unwrap_or_else(|_| SpaceOpBody::Unknown {
            number: record.get(0).and_then(|v| v.as_uint()),
        });
        SpaceOp { record, body }
    }

    fn parse(r: &Record) -> Result<SpaceOpBody, Error> {
        let Some(n) = r.get(0).and_then(|v| v.as_uint()) else {
            return Ok(SpaceOpBody::Unknown { number: None });
        };
        Ok(match n {
            1 => SpaceOpBody::Start {
                profile: r
                    .get(1)
                    .and_then(Profile::from_value)
                    .ok_or(Error::Malformed("profile"))?,
                policy: match r.opt_record(2)? {
                    Some(p) => Policy::from_record(p)?,
                    None => Policy::default(),
                },
                succeeds: r.opt_bytes_n(3)?,
                initial_state: r.opt_record(4)?.cloned(),
            },
            2 => SpaceOpBody::AddMember {
                identity: r.bytes_n(1)?,
                role: r.uint(2)?,
            },
            4 => SpaceOpBody::RemoveMember {
                membership: id16(r, 1)?,
            },
            5 => {
                let mut previous = Vec::new();
                for v in r.opt_list(1)?.unwrap_or(&[]) {
                    let e = v.as_record().ok_or(Error::Malformed("rotate"))?;
                    previous.push((e.bytes_n::<16>(1)?, e.bytes_n::<32>(2)?));
                }
                SpaceOpBody::Rotate { previous }
            }
            6 => SpaceOpBody::SetPolicy {
                policy: Policy::from_record(r.record(1)?)?,
            },
            7 => SpaceOpBody::Keep {
                key: r.bytes_n(1)?,
                entries: r
                    .opt_list(2)?
                    .unwrap_or(&[])
                    .iter()
                    .map(|v| {
                        v.as_bytes()
                            .and_then(|b| <[u8; 32]>::try_from(b).ok())
                            .ok_or(Error::Malformed("keep"))
                    })
                    .collect::<Result<_, _>>()?,
            },
            8 => SpaceOpBody::Succeed {
                successor: r.bytes_n(1)?,
            },
            9 => SpaceOpBody::SetProtocol,
            32 => SpaceOpBody::Create {
                kind: r
                    .get(1)
                    .and_then(NodeKind::from_value)
                    .ok_or(Error::Malformed("kind"))?,
                parent: id16(r, 2)?,
                name: r.opt_text(3)?.unwrap_or("").to_owned(),
                fields: r.opt_record(4)?.cloned().unwrap_or_default(),
            },
            33 => SpaceOpBody::Set {
                node: id16(r, 1)?,
                key: r.uint(2)?,
                value: r.get(3).cloned(),
            },
            34 => SpaceOpBody::Move {
                node: id16(r, 1)?,
                parent: id16(r, 2)?,
                name: r.opt_text(3)?.unwrap_or("").to_owned(),
            },
            35 => SpaceOpBody::Delete { node: id16(r, 1)? },
            36 => SpaceOpBody::Restore { node: id16(r, 1)? },
            37 => SpaceOpBody::Checkpoint,
            n => SpaceOpBody::Unknown { number: Some(n) },
        })
    }

    /// The record, as written.
    pub fn record(&self) -> &Record {
        &self.record
    }

    /// The typed reading.
    pub fn body(&self) -> &SpaceOpBody {
        &self.body
    }

    /// `start`.
    pub fn start(profile: Profile, policy: &Policy) -> SpaceOp {
        SpaceOp::from_record(
            Record::new()
                .with(0, 1u32)
                .with(1, profile.to_value())
                .with(2, policy.to_record()),
        )
    }

    /// `add_member`.
    pub fn add_member(identity: IdentityId, role: u64) -> SpaceOp {
        SpaceOp::from_record(
            Record::new()
                .with(0, 2u32)
                .with(1, identity)
                .with(2, role as u32),
        )
    }

    /// `remove_member`.
    pub fn remove_member(membership: MembershipId) -> SpaceOp {
        SpaceOp::from_record(Record::new().with(0, 4u32).with(1, membership))
    }

    /// `rotate`, carrying superseded epoch keys.
    pub fn rotate(previous: &[&EpochKey]) -> SpaceOp {
        SpaceOp::from_record(
            Record::new().with(0, 5u32).with(
                1,
                Value::list(
                    previous
                        .iter()
                        .map(|k| Record::new().with(1, k.id()).with(2, *k.bytes())),
                ),
            ),
        )
    }

    /// `keep`.
    pub fn keep(key: KeyId, entries: &[EntryId]) -> SpaceOp {
        SpaceOp::from_record(
            Record::new()
                .with(0, 7u32)
                .with(1, key)
                .with(2, Value::list(entries.iter().map(|e| Value::from(*e)))),
        )
    }

    /// `succeed`.
    pub fn succeed(successor: SpaceId) -> SpaceOp {
        SpaceOp::from_record(Record::new().with(0, 8u32).with(1, successor))
    }

    /// `create`.
    pub fn create(kind: NodeKind, parent: NodeId, name: &str, fields: Record) -> SpaceOp {
        SpaceOp::from_record(
            Record::new()
                .with(0, 32u32)
                .with(1, kind.to_value())
                .with(2, parent)
                .with(3, name)
                .with(4, fields),
        )
    }

    /// `set`; `None` clears the field.
    pub fn set(node: NodeId, key: u64, value: Option<Value>) -> SpaceOp {
        SpaceOp::from_record(
            Record::new()
                .with(0, 33u32)
                .with(1, node)
                .with(2, key as u32)
                .with_opt(3, value),
        )
    }

    /// `move`.
    pub fn mv(node: NodeId, parent: NodeId, name: &str) -> SpaceOp {
        SpaceOp::from_record(
            Record::new()
                .with(0, 34u32)
                .with(1, node)
                .with(2, parent)
                .with(3, name),
        )
    }

    /// `delete`.
    pub fn delete(node: NodeId) -> SpaceOp {
        SpaceOp::from_record(Record::new().with(0, 35u32).with(1, node))
    }

    /// `restore`.
    pub fn restore(node: NodeId) -> SpaceOp {
        SpaceOp::from_record(Record::new().with(0, 36u32).with(1, node))
    }
}

/// A space entry: a signed object with exactly one signature.
#[derive(Clone, Debug, PartialEq)]
pub struct SpaceEntry {
    signed: SignedObject,
    space: Option<SpaceId>,
    parents: Vec<EntryId>,
    author: IdentityId,
    author_head: EntryId,
    ops: Vec<SpaceOp>,
    time: Option<u64>,
    epoch: EpochId,
    wraps_hash: Option<[u8; 32]>,
    membership: Option<MembershipId>,
}

impl SpaceEntry {
    /// Checks a signed object as a space entry: kind 4, exactly one valid
    /// signature, and the field shapes of `spaces.md`.
    pub fn from_signed(signed: SignedObject) -> Result<SpaceEntry, Error> {
        let r = signed.inner();
        if r.kind()? != Kind::Core(SPACE_ENTRY) {
            return Err(Error::Malformed("not a space entry"));
        }
        if signed.signatures().len() != 1 {
            return Err(Error::Malformed("an entry has exactly one signature"));
        }
        verify_object_signature(&signed, &signed.signatures()[0])
            .map_err(|_| Error::BadSignature)?;
        let space: Option<SpaceId> = r.opt_bytes_n(1)?;
        let mut parents = Vec::new();
        for v in r.opt_list(2)?.unwrap_or(&[]) {
            parents.push(
                v.as_bytes()
                    .and_then(|b| <[u8; 32]>::try_from(b).ok())
                    .ok_or(Error::Malformed("parent"))?,
            );
        }
        match space {
            None if r.contains(2) => return Err(Error::Malformed("genesis has no parents")),
            Some(_) if parents.is_empty() => {
                return Err(Error::Malformed("a non-genesis entry has parents"))
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
            .opt_list(5)?
            .unwrap_or(&[])
            .iter()
            .map(|v| {
                v.as_record()
                    .cloned()
                    .map(SpaceOp::from_record)
                    .ok_or(Error::Malformed("an op is a record"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(SpaceEntry {
            space,
            parents,
            author: r.bytes_n(3)?,
            author_head: r.bytes_n(4)?,
            ops,
            time: r.opt_uint(6)?,
            epoch: r.bytes_n(7)?,
            wraps_hash: r.opt_bytes_n(8)?,
            membership: r.opt_bytes_n(9)?,
            signed,
        })
    }

    /// Decodes a signed object's bytes as a space entry.
    pub fn decode(bytes: &[u8]) -> Result<SpaceEntry, Error> {
        Self::from_signed(SignedObject::decode(bytes)?)
    }

    /// The entry id.
    pub fn id(&self) -> EntryId {
        self.signed.id()
    }

    /// The space id: field 1, or this entry's id for genesis.
    pub fn space(&self) -> SpaceId {
        self.space.unwrap_or_else(|| self.id())
    }

    /// Whether this is the genesis entry.
    pub fn is_genesis(&self) -> bool {
        self.space.is_none()
    }

    /// The parents.
    pub fn parents(&self) -> &[EntryId] {
        &self.parents
    }

    /// The author identity.
    pub fn author(&self) -> IdentityId {
        self.author
    }

    /// The cited head of the author's identity log.
    pub fn author_head(&self) -> EntryId {
        self.author_head
    }

    /// The ops.
    pub fn ops(&self) -> &[SpaceOp] {
        &self.ops
    }

    /// The author's clock, display only.
    pub fn time(&self) -> Option<u64> {
        self.time
    }

    /// The epoch this entry is encrypted under.
    pub fn epoch(&self) -> EpochId {
        self.epoch
    }

    /// The hash of the sealed entry's wraps, if it carries any.
    pub fn wraps_hash(&self) -> Option<[u8; 32]> {
        self.wraps_hash
    }

    /// The membership this entry is written under.
    pub fn membership(&self) -> Option<MembershipId> {
        self.membership
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

    /// Whether this entry starts an epoch (genesis or `rotate`).
    pub fn starts_epoch(&self) -> bool {
        self.is_genesis()
            || self
                .ops
                .iter()
                .any(|o| matches!(o.body(), SpaceOpBody::Rotate { .. }))
    }

    /// The membership created by the genesis `start` op.
    pub fn genesis_membership(&self) -> Option<MembershipId> {
        let i = self
            .ops
            .iter()
            .position(|o| matches!(o.body(), SpaceOpBody::Start { .. }))?;
        Some(derived_id(&self.id(), i))
    }

    /// The profile named by the genesis `start` op.
    pub fn profile(&self) -> Option<Profile> {
        self.ops.iter().find_map(|o| match o.body() {
            SpaceOpBody::Start { profile, .. } => Some(*profile),
            _ => None,
        })
    }
}

/// The hash bound by field 8: `BLAKE3` of the encoded list of wraps.
pub fn wraps_hash(wraps: &[Sealed]) -> [u8; 32] {
    *blake3::hash(&Value::list(wraps.iter().map(Sealed::to_record)).encode()).as_bytes()
}

/// Builds and signs a space entry.
#[derive(Clone, Debug)]
pub struct SpaceEntryBuilder {
    space: Option<SpaceId>,
    parents: Vec<EntryId>,
    author: IdentityId,
    author_head: EntryId,
    ops: Vec<SpaceOp>,
    time: Option<u64>,
    epoch: EpochId,
    wraps_hash: Option<[u8; 32]>,
    membership: Option<MembershipId>,
    extra: Record,
}

impl SpaceEntryBuilder {
    /// A genesis entry.
    pub fn genesis(author: IdentityId, author_head: EntryId, epoch: EpochId) -> SpaceEntryBuilder {
        SpaceEntryBuilder {
            space: None,
            parents: Vec::new(),
            author,
            author_head,
            ops: Vec::new(),
            time: None,
            epoch,
            wraps_hash: None,
            membership: None,
            extra: Record::new(),
        }
    }

    /// An entry of `space` after `parents`, under `membership`.
    pub fn new(
        space: SpaceId,
        parents: &[EntryId],
        author: IdentityId,
        author_head: EntryId,
        epoch: EpochId,
        membership: Option<MembershipId>,
    ) -> SpaceEntryBuilder {
        let mut parents = parents.to_vec();
        parents.sort_unstable();
        parents.dedup();
        SpaceEntryBuilder {
            space: Some(space),
            parents,
            author,
            author_head,
            ops: Vec::new(),
            time: None,
            epoch,
            wraps_hash: None,
            membership,
            extra: Record::new(),
        }
    }

    /// Appends an op.
    pub fn op(mut self, op: SpaceOp) -> SpaceEntryBuilder {
        self.ops.push(op);
        self
    }

    /// Appends ops.
    pub fn ops(mut self, ops: impl IntoIterator<Item = SpaceOp>) -> SpaceEntryBuilder {
        self.ops.extend(ops);
        self
    }

    /// Sets the display time.
    pub fn time(mut self, ms: u64) -> SpaceEntryBuilder {
        self.time = Some(ms);
        self
    }

    /// Binds the wraps the sealed entry will carry.
    pub fn wraps(mut self, wraps: &[Sealed]) -> SpaceEntryBuilder {
        self.wraps_hash = Some(wraps_hash(wraps));
        self
    }

    /// Adds a field this implementation does not define.
    pub fn extra_field(mut self, key: u64, value: impl Into<Value>) -> SpaceEntryBuilder {
        self.extra.insert(key, value);
        self
    }

    /// Signs with a device or admin key of the author.
    pub fn sign(self, key: &SigningKey) -> Result<SpaceEntry, Error> {
        let r = self
            .extra
            .with(0, SPACE_ENTRY as u32)
            .with_opt(1, self.space)
            .with_opt(
                2,
                (!self.parents.is_empty())
                    .then(|| Value::list(self.parents.iter().map(|p| Value::from(*p)))),
            )
            .with(3, self.author)
            .with(4, self.author_head)
            .with(5, Value::list(self.ops.iter().map(|o| o.record.clone())))
            .with_opt(
                6,
                self.time
                    .and_then(|t| cardinal_encoding::Int::from_u64(t).map(Value::Int)),
            )
            .with(7, self.epoch)
            .with_opt(8, self.wraps_hash)
            .with_opt(9, self.membership);
        let mut obj = SignedObject::new(r);
        key.sign_object(&mut obj);
        SpaceEntry::from_signed(obj)
    }
}

/// A sealed entry: what is stored and transferred.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedEntry {
    record: Record,
    epoch: EpochId,
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
    wraps: Option<Vec<Sealed>>,
    open_key: Option<[u8; 32]>,
}

fn aad(epoch: &EpochId, nonce: &[u8; 24]) -> Vec<u8> {
    Record::new()
        .with(0, SEALED_ENTRY as u32)
        .with(1, *epoch)
        .with(2, *nonce)
        .encode()
}

fn nonce_for(entry_key: &[u8; 32], entry: &EntryId) -> [u8; 24] {
    keyed_hash(entry_key, entry)[..24]
        .try_into()
        .expect("24 bytes")
}

impl SealedEntry {
    /// Seals a signed entry under `epoch`, carrying `wraps` (which the
    /// entry must bind in field 8) and, for public spaces, the epoch key.
    pub fn seal(
        entry: &SpaceEntry,
        epoch: &EpochKey,
        wraps: Option<Vec<Sealed>>,
        public: bool,
    ) -> Result<SealedEntry, Error> {
        if entry.epoch() != epoch.id() {
            return Err(Error::Mismatch("epoch"));
        }
        if entry.wraps_hash() != wraps.as_deref().map(wraps_hash) {
            return Err(Error::Mismatch("wraps hash"));
        }
        let k = epoch.entry_key();
        let nonce = nonce_for(&k, &entry.id());
        let ciphertext =
            xchacha20poly1305_encrypt(&k, &nonce, &aad(&epoch.id(), &nonce), &entry.encode());
        let open_key = public.then(|| *epoch.bytes());
        let record = Record::new()
            .with(0, SEALED_ENTRY as u32)
            .with(1, epoch.id())
            .with(2, nonce)
            .with(3, ciphertext.clone())
            .with_opt(
                4,
                wraps
                    .as_ref()
                    .map(|w| Value::list(w.iter().map(Sealed::to_record))),
            )
            .with_opt(5, open_key);
        let s = SealedEntry {
            record,
            epoch: epoch.id(),
            nonce,
            ciphertext,
            wraps,
            open_key,
        };
        if s.encode().len() > MAX_SEALED_SIZE {
            return Err(Error::TooLarge);
        }
        Ok(s)
    }

    /// Decodes a sealed entry.
    pub fn decode(bytes: &[u8]) -> Result<SealedEntry, Error> {
        if bytes.len() > MAX_SEALED_SIZE {
            return Err(Error::TooLarge);
        }
        let r = Record::decode(bytes)?;
        if r.kind()? != Kind::Core(SEALED_ENTRY) {
            return Err(Error::Malformed("not a sealed entry"));
        }
        let wraps = match r.opt_list(4)? {
            Some(ws) => Some(
                ws.iter()
                    .map(|v| {
                        v.as_record()
                            .ok_or(Error::Malformed("wrap"))
                            .and_then(|w| Ok(Sealed::from_record(w)?))
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            None => None,
        };
        Ok(SealedEntry {
            epoch: r.bytes_n(1)?,
            nonce: r.bytes_n(2)?,
            ciphertext: r.bytes(3)?.to_vec(),
            wraps,
            open_key: r.opt_bytes_n(5)?,
            record: r,
        })
    }

    /// The encoding.
    pub fn encode(&self) -> Vec<u8> {
        self.record.encode()
    }

    /// The sealed id: `BLAKE3` of the encoding.
    pub fn sealed_id(&self) -> [u8; 32] {
        *blake3::hash(&self.encode()).as_bytes()
    }

    /// The epoch.
    pub fn epoch(&self) -> EpochId {
        self.epoch
    }

    /// The wraps, if this entry distributes an epoch key.
    pub fn wraps(&self) -> Option<&[Sealed]> {
        self.wraps.as_deref()
    }

    /// The epoch key in the clear (public spaces).
    pub fn open_key(&self) -> Option<EpochKey> {
        self.open_key.map(EpochKey::from_bytes)
    }

    /// Opens with `key`, checking the nonce, epoch, and wraps hash.
    pub fn open_with(&self, key: &EpochKey) -> Result<SpaceEntry, Error> {
        if key.id() != self.epoch {
            return Err(Error::NoEpochKey);
        }
        let k = key.entry_key();
        let pt = xchacha20poly1305_decrypt(
            &k,
            &self.nonce,
            &aad(&self.epoch, &self.nonce),
            &self.ciphertext,
        )
        .map_err(|_| Error::Decrypt)?;
        let entry = SpaceEntry::decode(&pt)?;
        if nonce_for(&k, &entry.id()) != self.nonce {
            return Err(Error::Mismatch("nonce"));
        }
        if entry.epoch() != self.epoch {
            return Err(Error::Mismatch("epoch"));
        }
        if entry.wraps_hash() != self.wraps.as_deref().map(wraps_hash) {
            return Err(Error::Mismatch("wraps hash"));
        }
        Ok(entry)
    }

    /// Opens with a key from `keyring`, the open key, or a wrap that one of
    /// `identity_keys` opens. Returns the entry and the epoch key used.
    pub fn open(
        &self,
        keyring: &Keyring,
        identity_keys: &[&cardinal_crypto::HybridKeyPair],
    ) -> Result<(SpaceEntry, EpochKey), Error> {
        let key = keyring
            .get(&self.epoch)
            .cloned()
            .or_else(|| self.open_key().filter(|k| k.id() == self.epoch))
            .or_else(|| {
                self.wraps
                    .as_deref()
                    .and_then(|w| EpochKey::open_wraps(w, &self.epoch, identity_keys))
            })
            .ok_or(Error::NoEpochKey)?;
        Ok((self.open_with(&key)?, key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cardinal_crypto::HybridKeyPair;

    #[test]
    fn seal_open_and_tamper() {
        let device = SigningKey::from_seed(&[1; 32]);
        let member = HybridKeyPair::from_seed(b"member");
        let epoch = EpochKey::from_bytes([7; 32]);
        let wraps = vec![epoch.wrap(member.public_key())];
        let e = SpaceEntryBuilder::genesis([2; 32], [3; 32], epoch.id())
            .op(SpaceOp::start(Profile::FILES, &Policy::default()))
            .wraps(&wraps)
            .time(5)
            .extra_field(20, "future")
            .sign(&device)
            .unwrap();
        let s = SealedEntry::seal(&e, &epoch, Some(wraps.clone()), false).unwrap();
        let bytes = s.encode();
        let back = SealedEntry::decode(&bytes).unwrap();
        assert_eq!(back, s);
        // deterministic: re-sealing gives the same bytes
        assert_eq!(
            SealedEntry::seal(&e, &epoch, Some(wraps.clone()), false)
                .unwrap()
                .encode(),
            bytes
        );
        let (opened, k) = back.open(&Keyring::new(), &[&member]).unwrap();
        assert_eq!(opened, e);
        assert_eq!(k, epoch);
        assert_eq!(opened.record().text(20).unwrap(), "future");
        assert_eq!(opened.space(), e.id());
        assert_ne!(back.sealed_id(), e.id());
        assert_eq!(opened.profile(), Some(Profile::FILES));
        // without a key or a wrap for us
        let stranger = HybridKeyPair::from_seed(b"x");
        assert_eq!(
            back.open(&Keyring::new(), &[&stranger]),
            Err(Error::NoEpochKey)
        );
        // the wraps cannot be swapped
        let mut r = Record::decode(&bytes).unwrap();
        r.insert(
            4,
            Value::list([epoch.wrap(stranger.public_key()).to_record()]),
        );
        let swapped = SealedEntry::decode(&r.encode()).unwrap();
        let mut ring = Keyring::new();
        ring.add(epoch.clone());
        assert_eq!(swapped.open(&ring, &[]), Err(Error::Mismatch("wraps hash")));
        // the ciphertext cannot be changed
        let mut r = Record::decode(&bytes).unwrap();
        let mut ct = r.bytes(3).unwrap().to_vec();
        ct[0] ^= 1;
        r.insert(3, ct);
        assert_eq!(
            SealedEntry::decode(&r.encode()).unwrap().open(&ring, &[]),
            Err(Error::Decrypt)
        );
    }

    #[test]
    fn op_round_trip() {
        let ops = [
            SpaceOp::create(
                NodeKind::Uint(2),
                [0; 16],
                "a.txt",
                Record::new().with(2, 0o644u32),
            ),
            SpaceOp::set([1; 16], 1, Some(Value::from(vec![1u8, 2]))),
            SpaceOp::set([1; 16], 1, None),
            SpaceOp::mv([1; 16], [2; 16], "b"),
            SpaceOp::delete([1; 16]),
            SpaceOp::restore([1; 16]),
            SpaceOp::keep([4; 32], &[[5; 32]]),
            SpaceOp::remove_member([6; 16]),
            SpaceOp::rotate(&[&EpochKey::from_bytes([1; 32])]),
        ];
        for op in ops {
            let back = SpaceOp::from_record(Record::decode(&op.record().encode()).unwrap());
            assert_eq!(back, op);
            assert!(
                !matches!(back.body(), SpaceOpBody::Unknown { .. }),
                "{op:?}"
            );
        }
    }
}
