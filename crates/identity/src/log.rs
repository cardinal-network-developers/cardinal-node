//! Identity logs: storage, evaluation, and the operations a device needs
//! (`identity.md`).
//!
//! Evaluation converts the entries to the model's abstract entries
//! ([`crate::model`]) and executes the normative `identity` program. The
//! checks the program leaves to the input facts are made here: proofs of
//! possession, the shape of `add_key`, and guardians revealed by their
//! commitments.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::sync::Mutex;

use cardinal_crypto::{
    keyed_hash_parts, open, seal, HybridKeyPair, HybridPublicKey, RecoveryPhrase, Sealed,
    SigningKey,
};
use zeroize::Zeroizing;

use crate::dag::{Dag, Inserted};
use crate::datalog::Val;
use crate::entry::{
    add_key_proof, check_add_key_proof, EntryBuilder, EntryId, IdentityEntry, IdentityOp, KeyId,
    OpBody, Power, Protocol, Wrap,
};
use crate::model::{self, hex_decode, hex_encode, MembershipNames, Op, World};
use crate::Error;

/// Context prefix of a wrap of the identity encryption key.
pub const WRAP_CONTEXT: &[u8] = b"identity key";
/// Context prefix of a recovery wrap.
pub const RECOVERY_WRAP_CONTEXT: &[u8] = b"recovery wrap";
/// Context prefix of a key chain record.
pub const KEY_CHAIN_CONTEXT: &[u8] = b"key chain";
/// The prefix of a guardian commitment.
pub const GUARDIAN_COMMITMENT: &[u8] = b"cardinal guardian";

fn context(prefix: &[u8], binding: &[u8; 32]) -> Vec<u8> {
    [prefix, binding].concat()
}

/// A device's own keys: its signing key and its link key pair.
pub struct DeviceKeys {
    /// The Ed25519 signing key.
    pub signing: SigningKey,
    /// The hybrid link key pair.
    pub link: HybridKeyPair,
}

impl DeviceKeys {
    /// Fresh keys.
    pub fn generate() -> DeviceKeys {
        DeviceKeys {
            signing: SigningKey::generate(),
            link: HybridKeyPair::generate(),
        }
    }

    /// The signing public key.
    pub fn key(&self) -> KeyId {
        self.signing.public_key()
    }

    /// What this device sends to an admin to be added to `identity` at
    /// `power`: its public keys and proof of possession.
    pub fn request(&self, identity: &EntryId, power: Power) -> KeyRequest {
        KeyRequest {
            key: self.key(),
            power,
            link_key: self.link.public_key().clone(),
            proof: add_key_proof(&self.signing, identity, power, Some(self.link.public_key())),
        }
    }
}

/// A request to add a device or admin key, carrying its proof of
/// possession.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRequest {
    /// The signing key.
    pub key: KeyId,
    /// The power asked for.
    pub power: Power,
    /// The link key.
    pub link_key: HybridPublicKey,
    /// The proof of possession, bound to the identity id.
    pub proof: [u8; 64],
}

/// A key in effect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyInfo {
    /// The signing key.
    pub key: KeyId,
    /// Its power.
    pub power: Power,
    /// Its link key (device and admin keys).
    pub link_key: Option<HybridPublicKey>,
    /// Its recovery public key (roots).
    pub recovery_key: Option<HybridPublicKey>,
    /// The entry that added it, or the recovery that kept it.
    pub added_in: EntryId,
}

/// The current identity encryption key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptionKeyInfo {
    /// The entry whose `set_encryption_key` set it.
    pub entry: EntryId,
    /// The public key.
    pub public: HybridPublicKey,
}

/// What an identity log means: the result of evaluating it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityState {
    /// The identity id.
    pub identity: EntryId,
    /// Whether the identity is frozen.
    pub frozen: bool,
    /// Whether more than one root is in effect.
    pub contested: bool,
    /// Valid entries.
    pub valid: HashSet<EntryId>,
    /// Valid entries using a critical extension this software lacks;
    /// evaluation stopped there.
    pub stalled: Vec<EntryId>,
    /// Device and admin keys in effect.
    pub keys: BTreeMap<KeyId, KeyInfo>,
    /// Roots in effect.
    pub roots: BTreeMap<KeyId, KeyInfo>,
    /// The current encryption key.
    pub encryption_key: Option<EncryptionKeyInfo>,
    /// Recovery policies in effect and not replaced.
    pub current_policies: Vec<EntryId>,
    effective_at: HashSet<(KeyId, EntryId)>,
    removed: HashSet<KeyId>,
    removed_at: HashSet<(KeyId, EntryId)>,
}

impl IdentityState {
    /// Whether entry `e` is valid.
    pub fn is_valid(&self, e: &EntryId) -> bool {
        self.valid.contains(e)
    }

    /// The power of a device, admin, or root key in effect.
    pub fn power(&self, key: &KeyId) -> Option<Power> {
        self.keys
            .get(key)
            .or_else(|| self.roots.get(key))
            .map(|k| k.power)
    }

    /// Whether device or admin key `key` was in effect at `head` (the
    /// `effective_at` of the rules).
    pub fn is_effective_at(&self, key: &KeyId, head: &EntryId) -> bool {
        self.effective_at.contains(&(*key, *head))
    }

    /// Whether `key` was ever removed.
    pub fn is_removed(&self, key: &KeyId) -> bool {
        self.removed.contains(key)
    }

    /// Whether a removal of `key` is `head` or in its causal past.
    pub fn is_removed_at(&self, key: &KeyId, head: &EntryId) -> bool {
        self.removed_at.contains(&(*key, *head))
    }

    /// Pairs `(key, head)` for which `key` was in effect at `head`.
    pub fn effective_at(&self) -> impl Iterator<Item = &(KeyId, EntryId)> {
        self.effective_at.iter()
    }

    /// Removed keys.
    pub fn removed(&self) -> impl Iterator<Item = &KeyId> {
        self.removed.iter()
    }

    /// Pairs `(key, head)` for which a removal of `key` is in `head`'s past.
    pub fn removed_at(&self) -> impl Iterator<Item = &(KeyId, EntryId)> {
        self.removed_at.iter()
    }
}

/// An identity log: the entries of one identity.
pub struct IdentityLog {
    id: EntryId,
    root0: KeyId,
    dag: Dag<IdentityEntry>,
    state: Mutex<Option<Arc<IdentityState>>>,
}

/// The result of creating an identity.
pub struct Created {
    /// The new log, holding its genesis entry.
    pub log: IdentityLog,
    /// The recovery phrase, to show the person once.
    pub phrase: RecoveryPhrase,
    /// The identity encryption key pair.
    pub encryption: HybridKeyPair,
}

fn check_genesis(g: &IdentityEntry) -> Result<KeyId, Error> {
    if !g.is_genesis() {
        return Err(Error::BadGenesis("not a genesis entry"));
    }
    let roots: Vec<&OpBody> = g
        .ops()
        .iter()
        .map(|o| o.body())
        .filter(|b| matches!(b, OpBody::AddKey { power: 3, .. }))
        .collect();
    let [OpBody::AddKey {
        key, recovery_key, ..
    }] = roots[..]
    else {
        return Err(Error::BadGenesis("exactly one root key"));
    };
    if *key != g.signer() {
        return Err(Error::BadGenesis("signed by its root key"));
    }
    if recovery_key.is_none() {
        return Err(Error::BadGenesis("the root names its recovery key"));
    }
    if !g
        .ops()
        .iter()
        .any(|o| matches!(o.body(), OpBody::SetRecovery { changes: None, .. }))
    {
        return Err(Error::BadGenesis("set_recovery"));
    }
    if g.protocol().is_none() {
        return Err(Error::BadGenesis("protocol record"));
    }
    Ok(*key)
}

impl IdentityLog {
    /// A log holding only its genesis entry, which is checked.
    pub fn from_genesis(genesis: IdentityEntry) -> Result<IdentityLog, Error> {
        let root0 = check_genesis(&genesis)?;
        let id = genesis.id();
        let mut dag = Dag::new();
        dag.insert(id, Vec::new(), genesis);
        Ok(IdentityLog {
            id,
            root0,
            dag,
            state: Mutex::new(None),
        })
    }

    /// Creates an identity with a fresh recovery phrase, `device` as its
    /// first admin, a fresh encryption key, a policy naming no guardians,
    /// and the draft protocol.
    pub fn create(device: &DeviceKeys) -> Result<Created, Error> {
        Self::create_with(
            RecoveryPhrase::generate(),
            device,
            HybridKeyPair::generate(),
        )
    }

    /// [`create`](Self::create) with a given phrase and encryption key.
    pub fn create_with(
        phrase: RecoveryPhrase,
        device: &DeviceKeys,
        encryption: HybridKeyPair,
    ) -> Result<Created, Error> {
        let root = phrase.root_signing_key();
        let root_key = root.public_key();
        let recovery = phrase.recovery_key_pair();
        let admin_proof = add_key_proof(
            &device.signing,
            &root_key,
            Power::Admin,
            Some(device.link.public_key()),
        );
        // In genesis the identity id does not exist yet, so the root key
        // stands in for it as the binding of wraps (DEVIATIONS.md).
        let binding = root_key;
        let wrap = make_wrap(
            &encryption,
            &device.key(),
            device.link.public_key(),
            &binding,
        );
        let rwrap = seal(
            recovery.public_key(),
            &encryption.secret_bytes()[..],
            &context(RECOVERY_WRAP_CONTEXT, &binding),
        );
        let genesis = EntryBuilder::genesis(Protocol::draft())
            .op(IdentityOp::add_key(
                root_key,
                Power::Root,
                None,
                None,
                Some(recovery.public_key()),
            ))
            .op(IdentityOp::add_key(
                device.key(),
                Power::Admin,
                Some(device.link.public_key()),
                Some(admin_proof),
                None,
            ))
            .op(IdentityOp::set_recovery_unguarded(None, None))
            .op(IdentityOp::set_encryption_key(
                encryption.public_key(),
                &[wrap],
                &[rwrap],
                &[],
            ))
            .sign(&root)?;
        Ok(Created {
            log: IdentityLog::from_genesis(genesis)?,
            phrase,
            encryption,
        })
    }

    /// The identity id.
    pub fn id(&self) -> EntryId {
        self.id
    }

    /// The genesis root key.
    pub fn genesis_root(&self) -> KeyId {
        self.root0
    }

    /// The entries' graph.
    pub fn dag(&self) -> &Dag<IdentityEntry> {
        &self.dag
    }

    /// An entry.
    pub fn get(&self, id: &EntryId) -> Option<&IdentityEntry> {
        self.dag.get(id)
    }

    /// The current heads.
    pub fn heads(&self) -> Vec<EntryId> {
        self.dag.heads()
    }

    /// The number of entries held (not counting those waiting for
    /// parents).
    pub fn len(&self) -> usize {
        self.dag.len()
    }

    /// Whether the log holds no entries (never true: it holds genesis).
    pub fn is_empty(&self) -> bool {
        self.dag.is_empty()
    }

    /// Entries in log order.
    pub fn entries(&self) -> impl Iterator<Item = &IdentityEntry> {
        self.dag.iter().map(|(_, e)| e)
    }

    /// Adds an entry received from anyone. It is held until its parents
    /// arrive.
    pub fn insert(&mut self, entry: IdentityEntry) -> Result<Inserted, Error> {
        if entry.is_genesis() {
            return if entry.id() == self.id {
                Ok(Inserted::Duplicate)
            } else {
                Err(Error::WrongIdentity)
            };
        }
        if entry.identity() != self.id {
            return Err(Error::WrongIdentity);
        }
        let r = self.dag.insert(entry.id(), entry.parents().to_vec(), entry);
        if matches!(r, Inserted::Added(_)) {
            *self.state.get_mut().expect("lock") = None;
        }
        Ok(r)
    }

    /// Decodes and adds an entry.
    pub fn insert_bytes(&mut self, bytes: &[u8]) -> Result<Inserted, Error> {
        self.insert(IdentityEntry::decode(bytes)?)
    }

    /// The evaluated state of this log alone.
    pub fn state(&self) -> Arc<IdentityState> {
        let mut cache = self.state.lock().expect("state lock");
        if let Some(s) = cache.as_ref() {
            return s.clone();
        }
        let s = Arc::new(self.evaluate(&[]));
        *cache = Some(s.clone());
        s
    }

    /// Evaluates this log, with other identities' logs (guardians, and
    /// the logs those confirmations depend on) for confirmations.
    pub fn evaluate(&self, others: &[&IdentityLog]) -> IdentityState {
        let mut logs: Vec<&IdentityLog> = vec![self];
        logs.extend(others.iter().copied().filter(|l| l.id != self.id));
        let conv = Conversion::new(&logs);
        conv.state(self)
    }

    /// Appends an entry signed by `author`, with the current heads as
    /// parents.
    pub fn append(
        &mut self,
        author: &SigningKey,
        ops: Vec<IdentityOp>,
    ) -> Result<IdentityEntry, Error> {
        let mut b = EntryBuilder::new(self.id, &self.heads());
        for op in ops {
            b = b.op(op);
        }
        let e = b.sign(author)?;
        self.insert(e.clone())?;
        Ok(e)
    }

    fn require(&self, author: &SigningKey, min: Power) -> Result<Arc<IdentityState>, Error> {
        let st = self.state();
        match st.power(&author.public_key()) {
            Some(p) if p >= min => Ok(st),
            Some(_) => Err(Error::NotAuthorized("the key's power is too low")),
            None => Err(Error::NotAuthorized("the key is not in effect")),
        }
    }

    /// Adds a device or admin key. If `encryption` is the current
    /// encryption key pair, the same entry wraps it for the new key.
    pub fn add_key(
        &mut self,
        author: &SigningKey,
        request: &KeyRequest,
        encryption: Option<&HybridKeyPair>,
    ) -> Result<IdentityEntry, Error> {
        let need = if request.power == Power::Device {
            Power::Admin
        } else {
            Power::Admin.max(request.power)
        };
        if request.power == Power::Root {
            return Err(Error::NotAuthorized("roots are added only by replacement"));
        }
        self.require(author, need)?;
        if !check_add_key_proof(
            &self.id,
            &request.key,
            request.power.value(),
            Some(&request.link_key),
            &request.proof,
        ) {
            return Err(Error::Malformed("bad proof of possession"));
        }
        let mut ops = vec![IdentityOp::add_key(
            request.key,
            request.power,
            Some(&request.link_key),
            Some(request.proof),
            None,
        )];
        if let Some(enc) = encryption {
            ops.push(IdentityOp::wrap(&[make_wrap(
                enc,
                &request.key,
                &request.link_key,
                &self.id,
            )]));
        }
        self.append(author, ops)
    }

    /// Removes a device or admin key. The author must have strictly more
    /// power. Afterwards an admin MUST set a fresh encryption key
    /// ([`set_encryption_key`](Self::set_encryption_key)).
    pub fn remove_key(&mut self, author: &SigningKey, key: &KeyId) -> Result<IdentityEntry, Error> {
        let st = self.state();
        let target = st
            .power(key)
            .ok_or(Error::NotAuthorized("the key is not in effect"))?;
        let mine = st
            .power(&author.public_key())
            .ok_or(Error::NotAuthorized("the author is not in effect"))?;
        if mine <= target || mine < Power::Admin {
            return Err(Error::NotAuthorized("removals go strictly down in power"));
        }
        self.append(author, vec![IdentityOp::remove_key(*key)])
    }

    /// Sets `new` as the encryption key: wraps for every device and admin
    /// key in effect, recovery wraps to every root's recovery key, and a
    /// key chain carrying `current`, the current key pair, which the
    /// author must hold if there is one.
    pub fn set_encryption_key(
        &mut self,
        author: &SigningKey,
        new: &HybridKeyPair,
        current: Option<&HybridKeyPair>,
    ) -> Result<IdentityEntry, Error> {
        let st = self.require(author, Power::Admin)?;
        let mut wraps = Vec::new();
        for k in st.keys.values() {
            if let Some(link) = &k.link_key {
                wraps.push(make_wrap(new, &k.key, link, &self.id));
            }
        }
        let mut recovery_wraps = Vec::new();
        for r in st.roots.values() {
            if let Some(rk) = &r.recovery_key {
                recovery_wraps.push(seal(
                    rk,
                    &new.secret_bytes()[..],
                    &context(RECOVERY_WRAP_CONTEXT, &self.id),
                ));
            }
        }
        let mut chain = Vec::new();
        if let Some(cur) = &st.encryption_key {
            let held = current.ok_or(Error::NoEncryptionKey)?;
            if held.public_key() != &cur.public {
                return Err(Error::WrongKey);
            }
            chain.push(seal(
                new.public_key(),
                &held.secret_bytes()[..],
                &context(KEY_CHAIN_CONTEXT, &self.id),
            ));
        }
        self.append(
            author,
            vec![IdentityOp::set_encryption_key(
                new.public_key(),
                &wraps,
                &recovery_wraps,
                &chain,
            )],
        )
    }

    fn binding_of(&self, entry: &IdentityEntry) -> [u8; 32] {
        if entry.is_genesis() {
            self.root0
        } else {
            self.id
        }
    }

    /// Opens the current encryption key with a device's link key, from a
    /// wrap in any valid entry.
    pub fn open_encryption_key(&self, device: &DeviceKeys) -> Result<HybridKeyPair, Error> {
        let st = self.state();
        let cur = st.encryption_key.as_ref().ok_or(Error::NoEncryptionKey)?;
        let fp = cur.public.fingerprint();
        let me = device.key();
        for e in self.entries() {
            if !st.is_valid(&e.id()) {
                continue;
            }
            for op in e.ops() {
                let wraps = match op.body() {
                    OpBody::SetEncryptionKey { wraps, .. } | OpBody::Wrap { wraps } => wraps,
                    _ => continue,
                };
                for w in wraps {
                    if w.target != me || w.fingerprint != fp {
                        continue;
                    }
                    let ctx = context(WRAP_CONTEXT, &self.binding_of(e));
                    if let Ok(kp) = open_key(&device.link, &w.sealed, &ctx) {
                        if kp.public_key() == &cur.public {
                            return Ok(kp);
                        }
                        return Err(Error::WrongKey);
                    }
                }
            }
        }
        Err(Error::NoEncryptionKey)
    }

    /// Opens the current encryption key with the recovery phrase, from the
    /// latest recovery wrap made to its recovery key.
    pub fn open_with_phrase(&self, phrase: &RecoveryPhrase) -> Result<HybridKeyPair, Error> {
        let st = self.state();
        let cur = st.encryption_key.as_ref().ok_or(Error::NoEncryptionKey)?;
        let rk = phrase.recovery_key_pair();
        let e = self.get(&cur.entry).ok_or(Error::NoEncryptionKey)?;
        for op in e.ops() {
            if let OpBody::SetEncryptionKey { recovery_wraps, .. } = op.body() {
                let ctx = context(RECOVERY_WRAP_CONTEXT, &self.binding_of(e));
                for s in recovery_wraps {
                    if let Ok(kp) = open_key(&rk, s, &ctx) {
                        if kp.public_key() == &cur.public {
                            return Ok(kp);
                        }
                    }
                }
            }
        }
        Err(Error::NoEncryptionKey)
    }

    /// Every earlier encryption key reachable from `key` through key
    /// chains, `key` included, newest first.
    pub fn key_chain(&self, key: HybridKeyPair) -> Vec<HybridKeyPair> {
        let mut out = vec![key];
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        seen.insert(out[0].public_key().fingerprint());
        let mut i = 0;
        while i < out.len() {
            let fp = out[i].public_key().fingerprint();
            let mut found = Vec::new();
            for e in self.entries() {
                for op in e.ops() {
                    if let OpBody::SetEncryptionKey {
                        public, key_chain, ..
                    } = op.body()
                    {
                        if public.fingerprint() != fp {
                            continue;
                        }
                        let ctx = context(KEY_CHAIN_CONTEXT, &self.binding_of(e));
                        for s in key_chain {
                            if let Ok(kp) = open_key(&out[i], s, &ctx) {
                                if seen.insert(kp.public_key().fingerprint()) {
                                    found.push(kp);
                                }
                            }
                        }
                    }
                }
            }
            out.extend(found);
            i += 1;
        }
        out
    }
}

fn make_wrap(
    enc: &HybridKeyPair,
    target: &KeyId,
    link: &HybridPublicKey,
    binding: &[u8; 32],
) -> Wrap {
    Wrap {
        target: *target,
        fingerprint: enc.public_key().fingerprint(),
        sealed: seal(
            link,
            &enc.secret_bytes()[..],
            &context(WRAP_CONTEXT, binding),
        ),
    }
}

fn open_key(with: &HybridKeyPair, sealed: &Sealed, ctx: &[u8]) -> Result<HybridKeyPair, Error> {
    let pt = open(with, sealed, ctx)?;
    let secret: Zeroizing<[u8; cardinal_crypto::hybrid::SECRET_LEN]> = Zeroizing::new(
        pt[..]
            .try_into()
            .map_err(|_| Error::Malformed("sealed key material has the wrong length"))?,
    );
    Ok(HybridKeyPair::from_secret_bytes(&secret))
}

/// The commitment to guardian `guardian` with `salt`.
pub fn guardian_commitment(salt: &[u8; 32], guardian: &EntryId) -> [u8; 32] {
    keyed_hash_parts(salt, &[GUARDIAN_COMMITMENT, guardian])
}

/// The model world of several identity logs, with real membership names,
/// to which a space's entries can be added for evaluation by the `space`
/// program. Symbols are the lowercase hex of ids and keys.
pub fn model_world(logs: &[&IdentityLog]) -> World {
    Conversion::new(logs).world
}

/// Real entries of several logs, converted to the model's world.
struct Conversion<'a> {
    world: World,
    logs: HashMap<EntryId, &'a IdentityLog>,
}

impl<'a> Conversion<'a> {
    fn new(logs: &[&'a IdentityLog]) -> Conversion<'a> {
        let mut world = World::new(MembershipNames::Real);
        let all: HashMap<EntryId, (&'a IdentityLog, &'a IdentityEntry)> = logs
            .iter()
            .flat_map(|l| l.entries().map(move |e| (e.id(), (*l, e))))
            .collect();
        // which policy each decision acts under
        let mut under: HashMap<EntryId, EntryId> = HashMap::new();
        for (id, (_, e)) in &all {
            if e.is_genesis() {
                continue;
            }
            for op in e.ops() {
                match op.body() {
                    OpBody::Recover { policy, .. } => {
                        under.insert(*id, *policy);
                    }
                    OpBody::SetRecovery {
                        changes: Some(p), ..
                    } => {
                        under.insert(*id, *p);
                    }
                    _ => {}
                }
            }
        }
        // guardians revealed by their commitments: policy -> identities
        let mut revealed: HashMap<EntryId, BTreeSet<EntryId>> = HashMap::new();
        for (l, e) in all.values() {
            for op in e.ops() {
                let (d, pos, salt) = match op.body() {
                    OpBody::Endorse {
                        decision,
                        position,
                        salt,
                    }
                    | OpBody::Confirm {
                        decision,
                        position,
                        salt,
                        ..
                    } => (decision, *position, salt),
                    _ => continue,
                };
                let Some(p) = under.get(d) else { continue };
                let Some((_, pe)) = all.get(p) else { continue };
                for pop in pe.ops() {
                    if let OpBody::SetRecovery { commitments, .. } = pop.body() {
                        let ok = pos >= 1
                            && (pos as usize) <= commitments.len()
                            && commitments[pos as usize - 1] == guardian_commitment(salt, &l.id);
                        if ok {
                            revealed.entry(*p).or_default().insert(l.id);
                        }
                    }
                }
            }
        }
        // insert in an order that puts parents and confirmed decisions
        // first
        let mut queues: Vec<Vec<&IdentityEntry>> = logs
            .iter()
            .map(|l| {
                let mut v: Vec<&IdentityEntry> = l.entries().collect();
                v.reverse();
                v
            })
            .collect();
        let mut placed: HashSet<EntryId> = HashSet::new();
        loop {
            let mut progress = false;
            for (li, q) in queues.iter_mut().enumerate() {
                while let Some(e) = q.last() {
                    let waits = e.ops().iter().any(|o| match o.body() {
                        OpBody::Confirm { decision, .. } => {
                            all.contains_key(decision) && !placed.contains(decision)
                        }
                        _ => false,
                    });
                    if waits {
                        break;
                    }
                    let e = q.pop().expect("entry");
                    let entry = convert(&mut world, logs[li], e, &all, &revealed);
                    world
                        .put(entry)
                        .expect("parents and decisions are placed first");
                    placed.insert(e.id());
                    progress = true;
                }
            }
            if !progress {
                break;
            }
        }
        Conversion {
            world,
            logs: logs.iter().map(|l| (l.id, *l)).collect(),
        }
    }

    fn id_of(&self, s: u32) -> [u8; 32] {
        hex_decode(self.world.name(s)).try_into().unwrap_or([0; 32])
    }

    fn state(&self, log: &IdentityLog) -> IdentityState {
        let w = &self.world;
        let ident = w.get_sym(&hex_encode(&log.id)).expect("identity");
        let known = BTreeSet::new(); // no extensions are implemented yet
        let r = model::evaluate_identity(w, ident, &w.all(), Some(&known));
        let pair = |t: &[Val]| match t {
            [Val::Sym(a), Val::Sym(b)] => Some((self.id_of(*a), self.id_of(*b))),
            _ => None,
        };
        let valid: HashSet<EntryId> = r.unary("valid").iter().map(|s| self.id_of(*s)).collect();
        // what each key's adding op said
        let mut added: HashMap<KeyId, (u64, Option<HybridPublicKey>, Option<HybridPublicKey>)> =
            HashMap::new();
        for e in log.entries() {
            for op in e.ops() {
                if let OpBody::AddKey {
                    key,
                    power,
                    link_key,
                    recovery_key,
                    ..
                } = op.body()
                {
                    added
                        .entry(*key)
                        .or_insert((*power, link_key.clone(), recovery_key.clone()));
                }
                if let OpBody::Recover {
                    root, recovery_key, ..
                } = op.body()
                {
                    added
                        .entry(*root)
                        .or_insert((3, None, recovery_key.clone()));
                }
            }
        }
        let mut keys = BTreeMap::new();
        let effective: HashSet<KeyId> = r
            .unary("effective")
            .iter()
            .map(|s| self.id_of(*s))
            .collect();
        for t in r.rel("key_added") {
            let Some((k, e)) = pair(t) else { continue };
            if !effective.contains(&k) {
                continue;
            }
            let Some((p, link, _)) = added.get(&k) else {
                continue;
            };
            let Some(power) = Power::from_u64(*p) else {
                continue;
            };
            keys.entry(k).or_insert(KeyInfo {
                key: k,
                power,
                link_key: link.clone(),
                recovery_key: None,
                added_in: e,
            });
        }
        let mut roots = BTreeMap::new();
        for s in r.unary("root_eff") {
            let k = self.id_of(s);
            let rk = added.get(&k).and_then(|a| a.2.clone());
            let added_in = log
                .entries()
                .find(|e| {
                    e.ops().iter().any(|o| match o.body() {
                        OpBody::AddKey { key, .. } => *key == k,
                        OpBody::Recover { root, .. } => *root == k,
                        _ => false,
                    })
                })
                .map(|e| e.id())
                .unwrap_or(log.id);
            roots.insert(
                k,
                KeyInfo {
                    key: k,
                    power: Power::Root,
                    link_key: None,
                    recovery_key: rk,
                    added_in,
                },
            );
        }
        let encryption_key = r.unary("current_key").into_iter().next().and_then(|s| {
            let entry = self.id_of(s);
            log.get(&entry)?.ops().iter().find_map(|o| match o.body() {
                OpBody::SetEncryptionKey { public, .. } => Some(EncryptionKeyInfo {
                    entry,
                    public: public.clone(),
                }),
                _ => None,
            })
        });
        let _ = &self.logs;
        IdentityState {
            identity: log.id,
            frozen: r.frozen,
            contested: r.contested,
            valid,
            stalled: r.stalled.iter().map(|s| self.id_of(*s)).collect(),
            keys,
            roots,
            encryption_key,
            current_policies: r
                .unary("current_policy")
                .iter()
                .map(|s| self.id_of(*s))
                .collect(),
            effective_at: r.rel("effective_at").filter_map(pair).collect(),
            removed: r.unary("removed").iter().map(|s| self.id_of(*s)).collect(),
            removed_at: r.rel("removed_at").filter_map(pair).collect(),
        }
    }
}

fn convert(
    w: &mut World,
    log: &IdentityLog,
    e: &IdentityEntry,
    all: &HashMap<EntryId, (&IdentityLog, &IdentityEntry)>,
    revealed: &HashMap<EntryId, BTreeSet<EntryId>>,
) -> model::Entry {
    let mut sym = |b: &[u8; 32]| w.sym(&hex_encode(b));
    let id = e.id();
    let binding = if e.is_genesis() { log.root0 } else { log.id };
    let mut ops = Vec::new();
    for op in e.ops() {
        ops.push(match op.body() {
            OpBody::AddKey {
                key,
                power,
                link_key,
                proof,
                recovery_key,
            } => {
                let genesis_root = e.is_genesis() && *power == 3 && *key == e.signer();
                let shape = match power {
                    1 | 2 => link_key.is_some(),
                    3 => recovery_key.is_some(),
                    _ => false,
                };
                let proved = genesis_root
                    || proof.is_some_and(|p| {
                        check_add_key_proof(&binding, key, *power, link_key.as_ref(), &p)
                    });
                if shape && proved {
                    Op::Add {
                        key: sym(key),
                        power: *power as i64,
                    }
                } else {
                    Op::Invalid
                }
            }
            OpBody::RemoveKey { key } => Op::Rem { key: sym(key) },
            OpBody::SetEncryptionKey { .. } => Op::Sek,
            OpBody::Wrap { .. } => Op::Wrap,
            OpBody::SetRecovery {
                commitments,
                threshold,
                changes,
                controller,
                ..
            } => Op::Policy {
                changes: changes.as_ref().map(&mut sym),
                guardians: revealed
                    .get(&id)
                    .into_iter()
                    .flatten()
                    .map(&mut sym)
                    .collect(),
                slots: commitments.len(),
                threshold: (*threshold).min(i64::MAX as u64) as i64,
                controller: controller.as_ref().map(&mut sym),
            },
            OpBody::Recover {
                root, keep, policy, ..
            } => Op::Recover {
                root: sym(root),
                keeps: keep.iter().map(&mut sym).collect(),
                policy: sym(policy),
            },
            OpBody::Endorse { .. } => Op::Endorse,
            OpBody::Confirm { decision, .. } => {
                if all.contains_key(decision) {
                    Op::Confirm {
                        decision: sym(decision),
                    }
                } else {
                    Op::Endorse
                }
            }
            OpBody::Object { .. } => Op::Object,
            OpBody::SetProtocol { protocol } => Op::Protocol {
                declares: protocol.extensions.iter().map(&mut sym).collect(),
            },
            OpBody::Extension { name } => Op::Ext {
                name: sym(name),
                // whether an unknown extension is critical is said only
                // by its document; assume it is (DEVIATIONS.md)
                critical: true,
            },
            OpBody::Malformed => Op::Invalid,
        });
    }
    if let Some(p) = e.protocol() {
        // the genesis protocol record declares extensions like set_protocol
        ops.push(Op::Protocol {
            declares: p.extensions.iter().map(&mut sym).collect(),
        });
    }
    model::Entry {
        id: sym(&id),
        log: sym(&log.id),
        parents: e.parents().iter().map(&mut sym).collect(),
        signer: sym(&e.signer()),
        ops,
        author: None,
        head: None,
        membership: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn phrase(n: u8) -> RecoveryPhrase {
        RecoveryPhrase::from_entropy(&[n; 32])
    }

    #[test]
    fn create_add_remove_rotate() {
        let d1 = DeviceKeys::generate();
        let Created {
            mut log,
            phrase,
            encryption,
        } = IdentityLog::create_with(phrase(1), &d1, HybridKeyPair::generate()).unwrap();
        let st = log.state();
        assert!(!st.frozen && !st.contested);
        assert_eq!(st.valid.len(), 1);
        assert_eq!(st.power(&d1.key()), Some(Power::Admin));
        assert_eq!(st.roots.len(), 1);
        assert_eq!(
            st.encryption_key.as_ref().unwrap().public,
            *encryption.public_key()
        );
        assert_eq!(
            log.open_encryption_key(&d1).unwrap().public_key(),
            encryption.public_key()
        );
        assert_eq!(
            log.open_with_phrase(&phrase).unwrap().public_key(),
            encryption.public_key()
        );

        // add a device, wrapping the key for it
        let d2 = DeviceKeys::generate();
        let e = log
            .add_key(
                &d1.signing,
                &d2.request(&log.id(), Power::Device),
                Some(&encryption),
            )
            .unwrap();
        let st = log.state();
        assert!(st.is_valid(&e.id()));
        assert_eq!(st.power(&d2.key()), Some(Power::Device));
        assert!(st.is_effective_at(&d2.key(), &e.id()));
        assert!(!st.is_effective_at(&d2.key(), &log.id()));
        assert_eq!(
            log.open_encryption_key(&d2).unwrap().public_key(),
            encryption.public_key()
        );
        // a device cannot add or remove
        let d3 = DeviceKeys::generate();
        assert!(log
            .add_key(&d2.signing, &d3.request(&log.id(), Power::Device), None)
            .is_err());
        // a proof for another identity is refused
        assert!(log
            .add_key(&d1.signing, &d3.request(&[9; 32], Power::Device), None)
            .is_err());

        // remove it and rotate the encryption key
        let rm = log.remove_key(&d1.signing, &d2.key()).unwrap();
        let st = log.state();
        assert!(st.is_valid(&rm.id()));
        assert_eq!(st.power(&d2.key()), None);
        assert!(st.is_removed(&d2.key()));
        let new = HybridKeyPair::generate();
        log.set_encryption_key(&d1.signing, &new, Some(&encryption))
            .unwrap();
        let st = log.state();
        assert_eq!(
            st.encryption_key.as_ref().unwrap().public,
            *new.public_key()
        );
        assert!(log.open_encryption_key(&d2).is_err());
        let opened = log.open_encryption_key(&d1).unwrap();
        let chain = log.key_chain(opened);
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[1].public_key(), encryption.public_key());
        assert_eq!(
            log.open_with_phrase(&phrase).unwrap().public_key(),
            new.public_key()
        );

        // round trip through bytes into a fresh log
        let mut copy = IdentityLog::from_genesis(
            IdentityEntry::decode(&log.get(&log.id()).unwrap().encode()).unwrap(),
        )
        .unwrap();
        let mut entries: Vec<Vec<u8>> = log.entries().map(|e| e.encode()).collect();
        entries.reverse(); // out of order: held until parents arrive
        for b in &entries {
            copy.insert_bytes(b).unwrap();
        }
        assert_eq!(*copy.state(), *log.state());
    }

    #[test]
    fn bad_proof_makes_entry_invalid() {
        let d1 = DeviceKeys::generate();
        let Created { mut log, .. } =
            IdentityLog::create_with(phrase(2), &d1, HybridKeyPair::generate()).unwrap();
        let d2 = DeviceKeys::generate();
        let mut req = d2.request(&log.id(), Power::Admin);
        req.power = Power::Device; // consent was for another power
        let e = log
            .append(
                &d1.signing,
                vec![IdentityOp::add_key(
                    req.key,
                    req.power,
                    Some(&req.link_key),
                    Some(req.proof),
                    None,
                )],
            )
            .unwrap();
        let st = log.state();
        assert!(!st.is_valid(&e.id()));
        assert_eq!(st.power(&d2.key()), None);
    }

    #[test]
    fn root_replacement_and_contest_freeze() {
        let d1 = DeviceKeys::generate();
        let p = phrase(3);
        let root = p.root_signing_key();
        let Created { mut log, .. } =
            IdentityLog::create_with(p, &d1, HybridKeyPair::generate()).unwrap();
        let g = log.id();
        let rep = |n: u8| {
            let np = phrase(n);
            let nk = np.root_signing_key();
            let proof = add_key_proof(&nk, &g, Power::Root, None);
            EntryBuilder::new(g, &[g])
                .op(IdentityOp::add_key(
                    nk.public_key(),
                    Power::Root,
                    None,
                    Some(proof),
                    Some(np.recovery_key_pair().public_key()),
                ))
                .op(IdentityOp::remove_key(root.public_key()))
                .sign(&root)
                .unwrap()
        };
        let a = rep(4);
        log.insert(a.clone()).unwrap();
        let st = log.state();
        assert!(st.is_valid(&a.id()));
        assert_eq!(st.roots.len(), 1);
        assert!(st
            .roots
            .contains_key(&phrase(4).root_signing_key().public_key()));
        // a concurrent replacement of the same root: no guardians, frozen
        log.insert(rep(5)).unwrap();
        let st = log.state();
        assert!(st.contested && st.frozen);
    }
}
