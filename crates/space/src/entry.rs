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
/// A node id.
pub type NodeId = [u8; 16];

/// The reader role: reads, and writes its own reach node, `keep` and `leave`.
pub const READER: u64 = 0;
/// The writer role: also writes application ops, and `rotate`.
pub const WRITER: u64 = 1;
/// The admin role: also adds readers, writers and admins.
pub const ADMIN: u64 = 2;
/// The owner role: also changes policy and protocol, and succeeds the space.
/// Only a genesis gives it, and only to its own author.
pub const OWNER: u64 = 3;

/// The id of the node an entry's `create` op makes: the first 16 bytes of
/// `BLAKE3(entry id || varint(i))`, where `i` is the op's position.
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
    /// The relationship profile.
    pub const RELATIONSHIP: Profile = Profile::Core(3);

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

/// What a successor's `start` says of the space it succeeds
/// (`spaces.md#the-successor`): fields 3, 4 and 6 to 9.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Succession {
    /// 3: the space this one succeeds.
    pub succeeds: Option<SpaceId>,
    /// 4: the initial state, a blob reference to a canonical state.
    pub initial_state: Option<Record>,
    /// 6: the cut, entries of the space this one succeeds.
    pub cut: Vec<EntryId>,
    /// 7: the keys of that space's current epochs, if history is shared.
    pub old_keys: Vec<(EpochId, [u8; 32])>,
    /// 8: the identity logs the state at the cut was judged with: for each
    /// identity, the heads its writer held.
    pub judged_with: Vec<(IdentityId, Vec<EntryId>)>,
    /// 9: a fresh start: nothing the successor does not carry is to follow.
    pub fresh_start: bool,
}

/// The typed reading of a space op.
#[derive(Clone, Debug, PartialEq)]
pub enum SpaceOpBody {
    /// 1 `start` (genesis only, and exactly one).
    Start {
        /// The profile.
        profile: Profile,
        /// The policy.
        policy: Policy,
        /// 5: the protocol record
        /// (`evolution.md#declaring-what-you-speak`).
        protocol: Option<Record>,
        /// Where the space comes from, if it succeeds another.
        succession: Box<Succession>,
    },
    /// 2 `add_member`.
    AddMember {
        /// The member identity.
        identity: IdentityId,
        /// Role 0 reader .. 3 owner.
        role: u64,
        /// The identity this member acts for; display only.
        agent_of: Option<IdentityId>,
    },
    /// 4 `leave`: a member's own statement that it has stopped. It changes
    /// nothing about what is valid.
    Leave,
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
        /// A signing key of the author, removed or about to be.
        key: KeyId,
        /// Entries by that key.
        entries: Vec<EntryId>,
    },
    /// 8 `succeed`.
    Succeed {
        /// The successor space.
        successor: SpaceId,
        /// The members the successor does not name; display only.
        left_out: Vec<IdentityId>,
        /// The successor's public address, when the space is public.
        address: Option<Record>,
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
        /// The ids this node has had, when the op is posted again in a
        /// successor.
        was: Vec<NodeId>,
    },
    /// 33 `set` (value absent to clear).
    Set {
        /// The node.
        node: NodeId,
        /// The field key.
        key: u64,
        /// The value.
        value: Option<Value>,
        /// Written beside: it supersedes nothing
        /// (`state.md#fields-are-multi-value-registers`).
        beside: bool,
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
        /// Written beside: it deletes nothing, and flags a delete conflict
        /// (`state.md#deletion-yields-to-concurrent-work`).
        beside: bool,
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

/// A list of byte strings of length `N` at `key`; absent reads as empty.
fn ids<const N: usize>(r: &Record, key: u64, what: &'static str) -> Result<Vec<[u8; N]>, Error> {
    r.opt_list(key)?
        .unwrap_or(&[])
        .iter()
        .map(|v| {
            v.as_bytes()
                .and_then(|b| <[u8; N]>::try_from(b).ok())
                .ok_or(Error::Malformed(what))
        })
        .collect()
}

/// A list of `{1: epoch id, 2: key}` at `key`; absent reads as empty.
fn epoch_keys(r: &Record, key: u64) -> Result<Vec<(EpochId, [u8; 32])>, Error> {
    let mut out = Vec::new();
    for v in r.opt_list(key)?.unwrap_or(&[]) {
        let e = v.as_record().ok_or(Error::Malformed("epoch keys"))?;
        out.push((e.bytes_n::<16>(1)?, e.bytes_n::<32>(2)?));
    }
    Ok(out)
}

fn epoch_keys_value(keys: &[(EpochId, [u8; 32])]) -> Value {
    Value::list(
        keys.iter()
            .map(|(id, k)| Record::new().with(1, *id).with(2, *k)),
    )
}

fn id_list<const N: usize>(ids: &[[u8; N]]) -> Value {
    Value::list(ids.iter().map(|x| Value::from(x.to_vec())))
}

/// The parent a `create` or a `move` holds in field 2: the sixteen bytes of
/// an id, or an unsigned integer, the **index** of a `create` earlier in
/// the same entry (`state.md#a-node-made-in-the-same-entry`). `made` turns
/// an index into the id of the node that `create` makes, or says that it
/// names nothing. Anything else names no node. The integer is read at its
/// full width, so a huge one names nothing, and does not wrap round to an
/// op that is there.
fn parent_of(r: &Record, made: &dyn Fn(u64) -> Option<NodeId>) -> Result<NodeId, Error> {
    match r.get(2) {
        Some(Value::Bytes(_)) => id16(r, 2),
        Some(v) => v
            .as_uint()
            .and_then(made)
            .ok_or(Error::Malformed("a parent that names no node")),
        None => Err(Error::Malformed("no parent")),
    }
}

impl SpaceOp {
    /// Reads an op record on its own. Outside an entry an index names
    /// nothing: [`SpaceEntry`] reads the ops of an entry in their places.
    pub fn from_record(record: Record) -> SpaceOp {
        SpaceOp::read(record, &|_| None)
    }

    /// Reads an op record in its place in an entry, where `made` gives the
    /// id of the node that the `create` at an index makes.
    fn read(record: Record, made: &dyn Fn(u64) -> Option<NodeId>) -> SpaceOp {
        let body = Self::parse(&record, made).unwrap_or_else(|_| SpaceOpBody::Unknown {
            number: record.get(0).and_then(|v| v.as_uint()),
        });
        SpaceOp { record, body }
    }

    fn parse(r: &Record, made: &dyn Fn(u64) -> Option<NodeId>) -> Result<SpaceOpBody, Error> {
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
                protocol: r.opt_record(5)?.cloned(),
                succession: Box::new(Succession {
                    succeeds: r.opt_bytes_n(3)?,
                    initial_state: r.opt_record(4)?.cloned(),
                    cut: ids(r, 6, "cut")?,
                    old_keys: epoch_keys(r, 7)?,
                    judged_with: {
                        let mut out = Vec::new();
                        for v in r.opt_list(8)?.unwrap_or(&[]) {
                            let e = v.as_record().ok_or(Error::Malformed("judged with"))?;
                            out.push((e.bytes_n::<32>(1)?, ids(e, 2, "judged with")?));
                        }
                        out
                    },
                    fresh_start: r.opt_bool(9)?.unwrap_or(false),
                }),
            },
            2 => SpaceOpBody::AddMember {
                identity: r.bytes_n(1)?,
                role: r.uint(2)?,
                agent_of: r.opt_bytes_n(3)?,
            },
            4 => SpaceOpBody::Leave,
            5 => SpaceOpBody::Rotate {
                previous: epoch_keys(r, 1)?,
            },
            6 => SpaceOpBody::SetPolicy {
                policy: Policy::from_record(r.record(1)?)?,
            },
            7 => SpaceOpBody::Keep {
                key: r.bytes_n(1)?,
                entries: ids(r, 2, "keep")?,
            },
            8 => SpaceOpBody::Succeed {
                successor: r.bytes_n(1)?,
                left_out: ids(r, 2, "left out")?,
                address: r.opt_record(3)?.cloned(),
            },
            9 => {
                // its one field, which it must have: the protocol record
                r.record(1)?;
                SpaceOpBody::SetProtocol
            }
            32 => SpaceOpBody::Create {
                kind: r
                    .get(1)
                    .and_then(NodeKind::from_value)
                    .ok_or(Error::Malformed("kind"))?,
                parent: parent_of(r, made)?,
                name: r.opt_text(3)?.unwrap_or("").to_owned(),
                fields: r.opt_record(4)?.cloned().unwrap_or_default(),
                was: ids(r, 5, "was")?,
            },
            33 => SpaceOpBody::Set {
                node: id16(r, 1)?,
                key: r.uint(2)?,
                value: r.get(3).cloned(),
                beside: r.opt_bool(4)?.unwrap_or(false),
            },
            34 => SpaceOpBody::Move {
                node: id16(r, 1)?,
                parent: parent_of(r, made)?,
                name: r.opt_text(3)?.unwrap_or("").to_owned(),
            },
            35 => SpaceOpBody::Delete {
                node: id16(r, 1)?,
                beside: r.opt_bool(2)?.unwrap_or(false),
            },
            36 => SpaceOpBody::Restore { node: id16(r, 1)? },
            37 => {
                // Nothing here reads a checkpoint yet, but it is that op
                // only if each field it has is as its table types it
                // (`state.md#checkpoints`): the frontier, the state root
                // and the blob reference to the state.
                ids::<32>(r, 1, "frontier")?;
                r.opt_bytes_n::<32>(2)?;
                if let Some(blob) = r.opt_record(3)? {
                    crate::files::BlobRef::from_record(blob)
                        .ok_or(Error::Malformed("state blob"))?;
                }
                SpaceOpBody::Checkpoint
            }
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

    /// `start` of a space that succeeds another, or that declares its
    /// protocol: every field of the op. Lists that are empty and a fresh
    /// start that is not one are left out.
    pub fn start_with(
        profile: Profile,
        policy: &Policy,
        protocol: Option<Record>,
        from: &Succession,
    ) -> SpaceOp {
        let judged = from.judged_with.iter().map(|(who, heads)| {
            Record::new()
                .with(1, *who)
                .with(2, id_list(heads.as_slice()))
        });
        SpaceOp::from_record(
            Record::new()
                .with(0, 1u32)
                .with(1, profile.to_value())
                .with(2, policy.to_record())
                .with_opt(3, from.succeeds)
                .with_opt(4, from.initial_state.clone())
                .with_opt(5, protocol)
                .with_opt(6, (!from.cut.is_empty()).then(|| id_list(&from.cut)))
                .with_opt(
                    7,
                    (!from.old_keys.is_empty()).then(|| epoch_keys_value(&from.old_keys)),
                )
                .with_opt(
                    8,
                    (!from.judged_with.is_empty()).then(|| Value::list(judged)),
                )
                .with_opt(9, from.fresh_start.then_some(true)),
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

    /// `add_member` of an agent: a member that acts for `agent_of`
    /// (`apps.md#agents-normative-where-marked`).
    pub fn add_agent(identity: IdentityId, role: u64, agent_of: IdentityId) -> SpaceOp {
        SpaceOp::from_record(
            Record::new()
                .with(0, 2u32)
                .with(1, identity)
                .with(2, role as u32)
                .with(3, agent_of),
        )
    }

    /// `leave`.
    pub fn leave() -> SpaceOp {
        SpaceOp::from_record(Record::new().with(0, 4u32))
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

    /// `set_policy`.
    pub fn set_policy(policy: &Policy) -> SpaceOp {
        SpaceOp::from_record(Record::new().with(0, 6u32).with(1, policy.to_record()))
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
        SpaceOp::succeed_with(successor, &[], None)
    }

    /// `succeed`, saying who the successor leaves out and, for a public
    /// space, the successor's public address.
    pub fn succeed_with(
        successor: SpaceId,
        left_out: &[IdentityId],
        address: Option<Record>,
    ) -> SpaceOp {
        SpaceOp::from_record(
            Record::new()
                .with(0, 8u32)
                .with(1, successor)
                .with_opt(2, (!left_out.is_empty()).then(|| id_list(left_out)))
                .with_opt(3, address),
        )
    }

    /// `create`.
    pub fn create(kind: NodeKind, parent: NodeId, name: &str, fields: Record) -> SpaceOp {
        SpaceOp::create_was(kind, parent, name, fields, &[])
    }

    /// `create` posted again in a successor: `was` lists every id the node
    /// has had.
    pub fn create_was(
        kind: NodeKind,
        parent: NodeId,
        name: &str,
        fields: Record,
        was: &[NodeId],
    ) -> SpaceOp {
        SpaceOp::from_record(
            Record::new()
                .with(0, 32u32)
                .with(1, kind.to_value())
                .with(2, parent)
                .with(3, name)
                .with(4, fields)
                .with_opt(5, (!was.is_empty()).then(|| id_list(was))),
        )
    }

    /// `create` of a node under one that an earlier op of the same entry
    /// creates: `index` is that op's place in the entry's op list, counting
    /// every op from 0 (`state.md#a-node-made-in-the-same-entry`). The op
    /// means nothing outside an entry: it is read, and the index turned
    /// into the parent's id, when the entry is built or taken.
    pub fn create_under(kind: NodeKind, index: u32, name: &str, fields: Record) -> SpaceOp {
        SpaceOp::from_record(
            Record::new()
                .with(0, 32u32)
                .with(1, kind.to_value())
                .with(2, index)
                .with(3, name)
                .with(4, fields),
        )
    }

    /// `move` of a node under one that an earlier op of the same entry
    /// creates, by that op's index.
    pub fn mv_under(node: NodeId, index: u32, name: &str) -> SpaceOp {
        SpaceOp::from_record(
            Record::new()
                .with(0, 34u32)
                .with(1, node)
                .with(2, index)
                .with(3, name),
        )
    }

    /// This `create` or `move` with another parent: a node, or the index
    /// of an earlier `create` in the entry the op is to go in. For a writer
    /// that knows where an op will stand only once it has cut its ops into
    /// entries.
    pub fn with_parent(&self, parent: impl Into<Value>) -> SpaceOp {
        SpaceOp::from_record(self.record().clone().with(2, parent))
    }

    /// `set`; `None` clears the field.
    pub fn set(node: NodeId, key: u64, value: Option<Value>) -> SpaceOp {
        SpaceOp::from_record(
            Record::new()
                .with(0, 33u32)
                .with(1, node)
                .with(2, key)
                .with_opt(3, value),
        )
    }

    /// `set` written beside: its value is added to the field's values and
    /// supersedes none of them.
    pub fn set_beside(node: NodeId, key: u64, value: Option<Value>) -> SpaceOp {
        SpaceOp::from_record(
            Record::new()
                .with(0, 33u32)
                .with(1, node)
                .with(2, key)
                .with_opt(3, value)
                .with(4, true),
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

    /// `delete` written beside: it deletes nothing and flags a delete
    /// conflict.
    pub fn delete_beside(node: NodeId) -> SpaceOp {
        SpaceOp::from_record(Record::new().with(0, 35u32).with(1, node).with(2, true))
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
        // An index becomes an id on the way in: the entry's id is known,
        // so each op is read in its place, and a parent given as the index
        // of an earlier `create` is held as the id of the node it makes.
        // Nothing after this knows an index exists. The entry keeps its
        // bytes.
        let id = signed.id();
        let mut ops: Vec<SpaceOp> = Vec::new();
        for v in r.opt_list(5)?.unwrap_or(&[]) {
            let record = v.as_record().cloned();
            let record = record.ok_or(Error::Malformed("an op is a record"))?;
            let at = ops.len() as u64;
            let made = |index: u64| {
                // earlier, and a `create`
                let earlier = index < at;
                let creates = || matches!(ops[index as usize].body(), SpaceOpBody::Create { .. });
                (earlier && creates()).then(|| derived_id(&id, index as usize))
            };
            let op = SpaceOp::read(record, &made);
            ops.push(op);
        }
        Ok(SpaceEntry {
            space,
            parents,
            author: r.bytes_n(3)?,
            author_head: r.bytes_n(4)?,
            ops,
            time: r.opt_uint(6)?,
            epoch: r.bytes_n(7)?,
            wraps_hash: r.opt_bytes_n(8)?,
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
            extra: Record::new(),
        }
    }

    /// An entry of `space` after `parents`.
    pub fn new(
        space: SpaceId,
        parents: &[EntryId],
        author: IdentityId,
        author_head: EntryId,
        epoch: EpochId,
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
            .with_opt(8, self.wraps_hash);
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

/// The nonce of a sealed entry: the first 24 bytes of
/// `BLAKE3.keyed_hash(entry key, plaintext)`, the plaintext being the
/// encoded signed object. So no two plaintexts are ever sealed under one
/// nonce, and a signed entry has exactly one sealed form.
fn nonce_for(entry_key: &[u8; 32], plaintext: &[u8]) -> [u8; 24] {
    keyed_hash(entry_key, plaintext)[..24]
        .try_into()
        .expect("24 bytes")
}

/// The hash a sealed entry's field 4 has to answer to: of the wraps list
/// exactly as the record carries it.
fn carried_wraps_hash(r: &Record) -> Option<[u8; 32]> {
    r.get(4).map(|v| *blake3::hash(&v.encode()).as_bytes())
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
        let plaintext = entry.encode();
        let nonce = nonce_for(&k, &plaintext);
        let ciphertext =
            xchacha20poly1305_encrypt(&k, &nonce, &aad(&epoch.id(), &nonce), &plaintext);
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

    /// Decodes a sealed entry, as any holder does, whether or not it can
    /// open it. A sealed entry holds only the fields of its table: nothing
    /// would bind another, so one that has any is rejected. So is an open
    /// key that is not the key of the epoch the entry names.
    pub fn decode(bytes: &[u8]) -> Result<SealedEntry, Error> {
        if bytes.len() > MAX_SEALED_SIZE {
            return Err(Error::TooLarge);
        }
        let r = Record::decode(bytes)?;
        if r.kind()? != Kind::Core(SEALED_ENTRY) {
            return Err(Error::Malformed("not a sealed entry"));
        }
        if r.keys().any(|k| k > 5) {
            return Err(Error::Malformed("a sealed entry holds only its six fields"));
        }
        let epoch: EpochId = r.bytes_n(1)?;
        let open_key: Option<[u8; 32]> = r.opt_bytes_n(5)?;
        if open_key.is_some_and(|k| EpochKey::from_bytes(k).id() != epoch) {
            return Err(Error::Mismatch("open key"));
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
            epoch,
            nonce: r.bytes_n(2)?,
            ciphertext: r.bytes(3)?.to_vec(),
            wraps,
            open_key,
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

    /// The epoch key in the clear: on every entry of a public space, and
    /// on no other.
    pub fn open_key(&self) -> Option<EpochKey> {
        self.open_key.map(EpochKey::from_bytes)
    }

    /// Opens with `key`, as a member does, and rejects what a member must:
    /// a nonce that is not the one derived from what the entry opens to, a
    /// signature that does not verify, an inner epoch that differs from the
    /// sealed one, wraps without their hash in the entry or the reverse,
    /// and wraps that are not the ones the entry binds. Whether an open key
    /// belongs here is for whoever knows the space's policy
    /// ([`Space::receive`](crate::Space::receive)).
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
        if nonce_for(&k, &pt) != self.nonce {
            return Err(Error::Mismatch("nonce"));
        }
        let entry = SpaceEntry::decode(&pt)?;
        if entry.epoch() != self.epoch {
            return Err(Error::Mismatch("epoch"));
        }
        // the list as it is carried, so that nothing can be added to a wrap
        if entry.wraps_hash() != carried_wraps_hash(&self.record) {
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
            .or_else(|| self.open_key())
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
        // nothing can be added to a wrap either: the entry binds the list
        // as it is carried
        let mut r = Record::decode(&bytes).unwrap();
        let padded = wraps[0].to_record().with(9, "more");
        r.insert(4, Value::list([padded]));
        let padded = SealedEntry::decode(&r.encode()).unwrap();
        assert_eq!(padded.open(&ring, &[]), Err(Error::Mismatch("wraps hash")));
        // wraps with nothing in the entry to bind them, and the reverse
        let bare = SpaceEntryBuilder::genesis([2; 32], [3; 32], epoch.id())
            .op(SpaceOp::start(Profile::FILES, &Policy::default()))
            .sign(&device)
            .unwrap();
        let bare = SealedEntry::seal(&bare, &epoch, None, false).unwrap();
        let mut r = Record::decode(&bare.encode()).unwrap();
        r.insert(4, Value::list([wraps[0].to_record()]));
        let given = SealedEntry::decode(&r.encode()).unwrap();
        assert_eq!(given.open(&ring, &[]), Err(Error::Mismatch("wraps hash")));
        let mut r = Record::decode(&bytes).unwrap();
        r.remove(4);
        let taken = SealedEntry::decode(&r.encode()).unwrap();
        assert_eq!(taken.open(&ring, &[]), Err(Error::Mismatch("wraps hash")));
    }

    #[test]
    fn what_any_holder_rejects() {
        // A holder that cannot open an entry still refuses one that holds a
        // field its table does not define, since nothing would bind it, and
        // an open key that is not the key of the epoch the entry names.
        let device = SigningKey::from_seed(&[1; 32]);
        let epoch = EpochKey::from_bytes([7; 32]);
        let e = SpaceEntryBuilder::genesis([2; 32], [3; 32], epoch.id())
            .op(SpaceOp::start(Profile::FILES, &Policy::default()))
            .sign(&device)
            .unwrap();
        let public = SealedEntry::seal(&e, &epoch, None, true).unwrap();
        assert_eq!(public.open_key(), Some(epoch.clone()));
        let bytes = public.encode();
        SealedEntry::decode(&bytes).unwrap();
        let mut r = Record::decode(&bytes).unwrap();
        r.insert(6, "nothing binds this");
        assert_eq!(
            SealedEntry::decode(&r.encode()),
            Err(Error::Malformed("a sealed entry holds only its six fields"))
        );
        let mut r = Record::decode(&bytes).unwrap();
        r.insert(5, [8u8; 32]);
        assert_eq!(
            SealedEntry::decode(&r.encode()),
            Err(Error::Mismatch("open key"))
        );
        // anyone opens a public entry with the key it carries
        let (opened, _) = public.open(&Keyring::new(), &[]).unwrap();
        assert_eq!(opened, e);
    }

    #[test]
    fn the_nonce_follows_from_what_is_sealed() {
        // The nonce is derived from the whole signed object, so no two
        // plaintexts are sealed under one nonce: the same body under
        // another key, or the same entry signed again, gets another.
        let (a, b) = (
            SigningKey::from_seed(&[1; 32]),
            SigningKey::from_seed(&[2; 32]),
        );
        let epoch = EpochKey::from_bytes([7; 32]);
        let entry = |key: &SigningKey| {
            SpaceEntryBuilder::new([9; 32], &[[8; 32]], [2; 32], [3; 32], epoch.id())
                .op(SpaceOp::leave())
                .sign(key)
                .unwrap()
        };
        let (by_a, by_b) = (entry(&a), entry(&b));
        assert_eq!(by_a.record(), by_b.record());
        assert_ne!(by_a.id(), by_b.id());
        let again = {
            let mut obj = by_a.signed().clone();
            let signature = a.sign_salted(&obj.signing_message(), &[4; 32]);
            obj.add_signature(cardinal_encoding::ObjectSignature::new(
                a.public_key(),
                signature,
            ));
            SpaceEntry::from_signed(obj).unwrap()
        };
        assert_eq!(again.id(), by_a.id());
        let seal = |e: &SpaceEntry| SealedEntry::seal(e, &epoch, None, false).unwrap();
        let nonce = |s: &SealedEntry| s.record.bytes_n::<24>(2).unwrap();
        let (sa, sb, sagain) = (seal(&by_a), seal(&by_b), seal(&again));
        assert!(nonce(&sa) != nonce(&sb) && nonce(&sa) != nonce(&sagain));
        assert_eq!(seal(&by_a).encode(), sa.encode());
        assert_eq!(sagain.open_with(&epoch).unwrap().id(), by_a.id());
        // a nonce that is not the one derived from what the entry opens to:
        // the entry sealed properly under a nonce someone else chose
        let k = epoch.entry_key();
        let chosen = [5u8; 24];
        let ct = xchacha20poly1305_encrypt(&k, &chosen, &aad(&epoch.id(), &chosen), &by_a.encode());
        let r = Record::new()
            .with(0, SEALED_ENTRY as u32)
            .with(1, epoch.id())
            .with(2, chosen)
            .with(3, ct);
        let forged = SealedEntry::decode(&r.encode()).unwrap();
        assert_eq!(forged.open_with(&epoch), Err(Error::Mismatch("nonce")));
    }

    /// V7 (`spaces.md#control-operations`). An op is what its table says
    /// only if it is written as the table says: every field the table
    /// gives it has the type the table gives, a field marked display only
    /// included, and a field it must have is there. One that is not so is
    /// an op nobody defined. Keys the table does not list change nothing.
    #[test]
    fn an_op_is_what_its_table_says_only_if_written_so() {
        let op = |n: u32| Record::new().with(0, n);
        let not_that_op = |r: Record, n: u64, what: &str| {
            let body = SpaceOp::from_record(r).body().clone();
            assert_eq!(body, SpaceOpBody::Unknown { number: Some(n) }, "{what}");
        };
        let who = [7u8; 32];
        let reach = [3u8; 16];
        let add = || op(2).with(1, who).with(2, 1u32);
        not_that_op(add().with(3, "an agent"), 2, "add_member, agent of");
        not_that_op(add().with(3, vec![1u8; 31]), 2, "add_member, agent of");
        not_that_op(op(2).with(1, who), 2, "add_member with no role");
        let succeed = || op(8).with(1, [9u8; 32]);
        not_that_op(succeed().with(2, "left out"), 8, "succeed, left out");
        not_that_op(
            succeed().with(2, Value::list(["x"])),
            8,
            "succeed, left out",
        );
        not_that_op(succeed().with(3, 5u32), 8, "succeed, address");
        let set = || op(33).with(1, reach).with(2, 1u32);
        not_that_op(op(33).with(1, reach).with(2, "key"), 33, "set, key");
        not_that_op(op(33).with(1, reach), 33, "set with no key");
        not_that_op(set().with(4, 2u32), 33, "set, beside");
        not_that_op(op(35).with(1, reach).with(2, "yes"), 35, "delete, beside");
        // S10: `checkpoint` has three fields, typed like any other's.
        let ids = Value::list([Value::from([1u8; 32])]);
        let blob = Record::new()
            .with(1, [2u8; 32])
            .with(2, [3u8; 32])
            .with(3, 10u32)
            .with(4, 0u32);
        let whole = op(37).with(1, ids).with(2, [4u8; 32]).with(3, blob);
        for r in [op(37), whole] {
            assert_eq!(*SpaceOp::from_record(r).body(), SpaceOpBody::Checkpoint);
        }
        not_that_op(op(37).with(1, "x"), 37, "checkpoint, frontier");
        let short = Value::list([Value::from([1u8; 31])]);
        not_that_op(op(37).with(1, short), 37, "checkpoint, frontier");
        not_that_op(op(37).with(2, [4u8; 31]), 37, "checkpoint, state root");
        not_that_op(op(37).with(2, 4u32), 37, "checkpoint, state root");
        not_that_op(op(37).with(3, "a blob"), 37, "checkpoint, state blob");
        let no_key = Record::new().with(1, [2u8; 32]).with(3, 10u32);
        not_that_op(op(37).with(3, no_key), 37, "checkpoint, state blob");
        let start = || op(1).with(1, 2u32);
        not_that_op(start().with(2, "a policy"), 1, "start, policy");
        not_that_op(start().with(5, 7u32), 1, "start, protocol");
        not_that_op(op(1), 1, "start with no profile");
        not_that_op(op(6), 6, "set_policy with no policy");
        not_that_op(op(9), 9, "set_protocol with no record");
        not_that_op(op(9).with(1, "a protocol"), 9, "set_protocol");
        not_that_op(
            op(7).with(2, Value::list([[1u8; 32]])),
            7,
            "keep with no key",
        );
        not_that_op(op(5).with(1, "keys"), 5, "rotate");
        // Written as the table says, each is that op, and a key the table
        // does not list changes nothing.
        let is = |r: Record| !matches!(SpaceOp::from_record(r).body(), SpaceOpBody::Unknown { .. });
        assert!(is(add()) && is(add().with(3, who)) && is(add().with(20, "more")));
        assert!(is(succeed()) && is(succeed().with(2, Value::list([who]))));
        assert!(is(set()) && is(set().with(4, true)) && is(set().with(3, "v").with(9, 1u32)));
        assert!(is(start()) && is(op(9).with(1, Record::new())) && is(op(4).with(1, "x")));
        // An entry is malformed, and rejected, if a parent is listed twice
        // or an item of its op list is not a record.
        let key = SigningKey::from_seed(&[7; 32]);
        let once = SpaceEntryBuilder::new([1; 32], &[[2; 32]], [3; 32], [4; 32], [5; 16])
            .sign(&key)
            .unwrap();
        let signed_with = |field: u64, v: Value| {
            let mut body = once.record().clone();
            body.insert(field, v);
            let mut obj = SignedObject::new(body);
            key.sign_object(&mut obj);
            SpaceEntry::from_signed(obj)
        };
        let parent = Value::from([2u8; 32]);
        assert!(signed_with(2, Value::list([parent.clone()])).is_ok());
        assert!(signed_with(2, Value::list([parent.clone(), parent])).is_err());
        assert!(signed_with(5, Value::list(["not a record"])).is_err());
        assert!(signed_with(5, Value::list([Record::new()])).is_ok());
    }

    /// An index means something only in an entry: it is the place of an
    /// op of that entry. An op read on its own that holds one names no
    /// parent, and is read again in its place when the entry is built.
    #[test]
    fn an_index_names_nothing_outside_an_entry() {
        let under = SpaceOp::create_under(NodeKind::Uint(1), 0, "inner", Record::new());
        assert_eq!(*under.body(), SpaceOpBody::Unknown { number: Some(32) });
        let moved = SpaceOp::mv_under([1; 16], 0, "moved");
        assert_eq!(*moved.body(), SpaceOpBody::Unknown { number: Some(34) });
        let key = SigningKey::from_seed(&[7; 32]);
        let first = SpaceOp::create(NodeKind::Uint(1), [0; 16], "outer", Record::new());
        let e = SpaceEntryBuilder::new([1; 32], &[[2; 32]], [3; 32], [4; 32], [5; 16])
            .ops([first, under.clone(), moved])
            .sign(&key)
            .unwrap();
        let outer = derived_id(&e.id(), 0);
        match (e.ops()[1].body(), e.ops()[2].body()) {
            (SpaceOpBody::Create { parent: a, .. }, SpaceOpBody::Move { parent: b, .. }) => {
                assert_eq!((*a, *b), (outer, outer));
            }
            other => panic!("{other:?}"),
        }
        // the op's record is what was written, index and all
        assert_eq!(e.ops()[1].record(), under.record());
        assert_eq!(e.ops()[1].record().get(2), Some(&Value::from(0u32)));
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
            SpaceOp::leave(),
            SpaceOp::rotate(&[&EpochKey::from_bytes([1; 32])]),
            SpaceOp::add_member([7; 32], WRITER),
            SpaceOp::add_agent([7; 32], READER, [8; 32]),
            SpaceOp::set_policy(&Policy::default()),
            SpaceOp::succeed([9; 32]),
            SpaceOp::succeed_with([9; 32], &[[7; 32]], Some(Record::new().with(0, 10u32))),
            SpaceOp::start(Profile::RELATIONSHIP, &Policy::default()),
            SpaceOp::create_was(NodeKind::Uint(2), [0; 16], "b", Record::new(), &[[3; 16]]),
            SpaceOp::set_beside([1; 16], 1, Some(Value::from("x"))),
            SpaceOp::delete_beside([1; 16]),
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

    #[test]
    fn start_says_where_a_successor_comes_from() {
        let from = Succession {
            succeeds: Some([1; 32]),
            initial_state: Some(Record::new().with(1, 5u32)),
            cut: vec![[2; 32], [3; 32]],
            old_keys: vec![([4; 16], [5; 32])],
            judged_with: vec![([6; 32], vec![[7; 32], [8; 32]]), ([9; 32], vec![])],
            fresh_start: true,
        };
        let protocol = Record::new().with(1, [0u8; 32]);
        let policy = Policy::default();
        let op = SpaceOp::start_with(Profile::Core(4), &policy, Some(protocol.clone()), &from);
        // every field is written under its own key
        for key in 1..=9 {
            assert!(op.record().contains(key), "field {key}");
        }
        let bytes = op.record().encode();
        let back = SpaceOp::from_record(Record::decode(&bytes).unwrap());
        assert_eq!(back.record().encode(), bytes);
        let SpaceOpBody::Start {
            profile,
            protocol: p,
            succession,
            ..
        } = back.body()
        else {
            panic!("{back:?}");
        };
        assert_eq!((*profile, p.as_ref()), (Profile::Core(4), Some(&protocol)));
        assert_eq!(**succession, from);
        // a space that succeeds nothing says none of it
        let plain = SpaceOp::start(Profile::FILES, &policy);
        assert!((3..=9).all(|k| !plain.record().contains(k)));
        let SpaceOpBody::Start { succession, .. } = plain.body() else {
            panic!("{plain:?}");
        };
        assert_eq!(**succession, Succession::default());
        // a cut that is not a list of entry ids is not a `start`
        let mut r = op.record().clone();
        r.insert(6, Value::list([Value::from("x")]));
        let bad = SpaceOp::from_record(r);
        assert_eq!(*bad.body(), SpaceOpBody::Unknown { number: Some(1) });
    }

    #[test]
    fn new_fields_are_read_and_kept() {
        let add = SpaceOp::add_agent([1; 32], READER, [2; 32]);
        assert_eq!(
            *add.body(),
            SpaceOpBody::AddMember {
                identity: [1; 32],
                role: READER,
                agent_of: Some([2; 32]),
            }
        );
        let address = Record::new().with(0, 10u32).with(1, [3u8; 32]);
        let end = SpaceOp::succeed_with([4; 32], &[[5; 32], [6; 32]], Some(address.clone()));
        assert_eq!(
            *end.body(),
            SpaceOpBody::Succeed {
                successor: [4; 32],
                left_out: vec![[5; 32], [6; 32]],
                address: Some(address),
            }
        );
        let again = SpaceOp::create_was(NodeKind::Uint(2), [0; 16], "a", Record::new(), &[[7; 16]]);
        assert!(matches!(again.body(), SpaceOpBody::Create { was, .. } if *was == [[7u8; 16]]));
        let plain = SpaceOp::create(NodeKind::Uint(2), [0; 16], "a", Record::new());
        assert!(!plain.record().contains(5));
        assert!(matches!(
            SpaceOp::set_beside([1; 16], 1, None).body(),
            SpaceOpBody::Set {
                beside: true,
                value: None,
                ..
            }
        ));
        assert!(matches!(
            SpaceOp::set([1; 16], 1, None).body(),
            SpaceOpBody::Set { beside: false, .. }
        ));
        assert!(matches!(
            SpaceOp::delete_beside([1; 16]).body(),
            SpaceOpBody::Delete { beside: true, .. }
        ));
        assert!(!SpaceOp::delete([1; 16]).record().contains(2));
        // `leave` has no fields; one that carries some is still a `leave`,
        // and they are kept (what used to be `remove_member` reads so)
        let old = Record::new().with(0, 4u32).with(1, [6u8; 16]);
        let leave = SpaceOp::from_record(old.clone());
        assert_eq!(*leave.body(), SpaceOpBody::Leave);
        assert_eq!(*leave.record(), old);
        assert_eq!(SpaceOp::leave().record().len(), 1);
    }

    #[test]
    fn field_9_is_reserved() {
        // An entry no longer names a membership. One that carries field 9
        // is an entry with a field this implementation does not know: read,
        // and kept as it was signed.
        let device = SigningKey::from_seed(&[1; 32]);
        let with = SpaceEntryBuilder::new([1; 32], &[[2; 32]], [3; 32], [4; 32], [5; 16])
            .extra_field(9, [6u8; 16])
            .sign(&device)
            .unwrap();
        let back = SpaceEntry::decode(&with.encode()).unwrap();
        assert_eq!(back.id(), with.id());
        assert_eq!(back.record().bytes_n::<16>(9).unwrap(), [6; 16]);
        let without = SpaceEntryBuilder::new([1; 32], &[[2; 32]], [3; 32], [4; 32], [5; 16])
            .sign(&device)
            .unwrap();
        assert!(!without.record().contains(9));
        assert_ne!(without.id(), with.id());
    }
}
