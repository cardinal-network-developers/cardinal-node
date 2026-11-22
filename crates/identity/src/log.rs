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
use crate::model::{self, hex_decode, hex_encode, Op, World};
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
    /// Guardian decisions in effect: policies and recoveries. They are
    /// judged only as decisions, so they are not in `valid`.
    pub in_effect: HashSet<EntryId>,
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
    /// Other identities' logs held under this one's label: guardians'
    /// entries, up to their `endorse` and `confirm`, which guardian
    /// software delivers to the guarded identity
    /// (`identity.md#distribution`). Evaluating this log reads them.
    attached: BTreeMap<EntryId, IdentityLog>,
    /// Other identities' entries not (yet) part of a guardian's act on
    /// this log: held until an act makes them its past, at most
    /// [`MAX_PENDING`], the oldest dropped first. Never evaluated or
    /// served.
    unattached: std::collections::VecDeque<IdentityEntry>,
    unattached_ids: HashSet<EntryId>,
    /// Entries of other identities newly kept, until taken
    /// ([`take_attached`](IdentityLog::take_attached)).
    promoted: Vec<EntryId>,
}

/// The most entries of other identities held while nothing shows them to
/// be a guardian's act on a log.
pub const MAX_PENDING: usize = 512;

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
            attached: BTreeMap::new(),
            unattached: std::collections::VecDeque::new(),
            unattached_ids: HashSet::new(),
            promoted: Vec::new(),
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

    /// Whether entries are waiting for parents, here or in a log held
    /// under this one's label.
    pub fn is_waiting(&self) -> bool {
        // and an act on this log whose past is not all here
        self.dag.held().next().is_some()
            || self
                .unattached
                .iter()
                .any(|e| self.is_act_here(&e.identity(), e))
    }

    /// The heads of this log, then of each log held under its label: what
    /// a notice of the label names.
    pub fn all_heads(&self) -> Vec<EntryId> {
        let mut v = self.heads();
        for l in self.attached.values() {
            v.extend(l.heads());
        }
        v
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
            // a decision arriving after the acts on it
            if !self.unattached.is_empty() {
                let waiting: BTreeSet<EntryId> =
                    self.unattached.iter().map(|e| e.identity()).collect();
                for of in waiting {
                    self.promote(&of);
                }
            }
        }
        Ok(r)
    }

    /// The entries of other identities kept since this was last asked, in
    /// the order they were kept: what to store and serve under this log's
    /// label.
    pub fn take_attached(&mut self) -> Vec<IdentityEntry> {
        let ids = std::mem::take(&mut self.promoted);
        ids.iter()
            .filter_map(|id| self.attached.values().find_map(|l| l.get(id)).cloned())
            .collect()
    }

    /// Decodes and adds an entry.
    pub fn insert_bytes(&mut self, bytes: &[u8]) -> Result<Inserted, Error> {
        self.insert(IdentityEntry::decode(bytes)?)
    }

    /// Adds an entry of this log, or of another identity's log held under
    /// this one's label ([`attach`](Self::attach)).
    pub fn insert_any(&mut self, entry: IdentityEntry) -> Result<Inserted, Error> {
        if entry.identity() == self.id {
            self.insert(entry)
        } else {
            self.attach(entry)
        }
    }

    /// Adds an entry of another identity's log, held under this one's
    /// label: a guardian's, delivered with its `endorse` or `confirm`.
    ///
    /// Only the causal past of an act of a guardian on this log is kept: an
    /// `endorse` or `confirm` naming a decision here, whose position and
    /// salt open a commitment of that decision's policy for the identity
    /// that wrote it. Anything else waits, bounded, for such an act, and is
    /// not evaluated or served. `Added` lists every entry newly kept.
    pub fn attach(&mut self, entry: IdentityEntry) -> Result<Inserted, Error> {
        let of = entry.identity();
        if of == self.id {
            return Err(Error::WrongIdentity);
        }
        let id = entry.id();
        if self.unattached_ids.contains(&id)
            || self
                .attached
                .get(&of)
                .is_some_and(|l| l.dag.contains(&id) || l.dag.is_held(&id))
        {
            return Ok(Inserted::Duplicate);
        }
        self.unattached_ids.insert(id);
        self.unattached.push_back(entry);
        while self.unattached.len() > MAX_PENDING {
            if let Some(old) = self.unattached.pop_front() {
                self.unattached_ids.remove(&old.id());
            }
        }
        let added = self.promote(&of);
        if added.is_empty() {
            return Ok(Inserted::Held(vec![id]));
        }
        *self.state.get_mut().expect("lock") = None;
        Ok(Inserted::Added(added))
    }

    /// Whether `e`, of identity `of`, is a guardian's act on this log.
    fn is_act_here(&self, of: &EntryId, e: &IdentityEntry) -> bool {
        e.ops().iter().any(|op| {
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
                _ => return false,
            };
            let Some(de) = self.dag.get(d) else {
                return false;
            };
            let policy = de.ops().iter().find_map(|o| match o.body() {
                OpBody::Recover { policy, .. } => Some(*policy),
                OpBody::SetRecovery {
                    changes: Some(p), ..
                } => Some(*p),
                _ => None,
            });
            let Some(commitments) = policy.and_then(|p| self.dag.get(&p)).and_then(|pe| {
                pe.ops().iter().find_map(|o| match o.body() {
                    OpBody::SetRecovery { commitments, .. } => Some(commitments.clone()),
                    _ => None,
                })
            }) else {
                return false;
            };
            pos >= 1
                && (pos as usize) <= commitments.len()
                && commitments[pos as usize - 1] == guardian_commitment(salt, of)
        })
    }

    /// Moves `of`'s waiting entries that are the past of an act on this
    /// log into its attached log. Returns the ids moved.
    fn promote(&mut self, of: &EntryId) -> Vec<EntryId> {
        let mine: Vec<IdentityEntry> = self
            .unattached
            .iter()
            .filter(|e| e.identity() == *of)
            .cloned()
            .collect();
        let genesis = self
            .attached
            .get(of)
            .and_then(|l| l.get(&l.id).cloned())
            .or_else(|| mine.iter().find(|e| e.is_genesis()).cloned());
        let Some(genesis) = genesis else {
            return Vec::new();
        };
        let Ok(mut all) = IdentityLog::from_genesis(genesis) else {
            return Vec::new();
        };
        if let Some(l) = self.attached.get(of) {
            for e in l.entries() {
                let _ = all.insert(e.clone());
            }
        }
        for e in &mine {
            if !e.is_genesis() {
                let _ = all.insert(e.clone());
            }
        }
        let acts: Vec<EntryId> = all
            .entries()
            .filter(|e| self.is_act_here(of, e))
            .map(|e| e.id())
            .collect();
        let mut keep: HashSet<EntryId> = all.dag.ancestors_of(&acts);
        keep.extend(acts.iter().copied());
        let have = |id: &EntryId| self.attached.get(of).is_some_and(|l| l.dag.contains(id));
        let new: Vec<EntryId> = all
            .dag
            .log_order()
            .iter()
            .filter(|id| keep.contains(*id) && !have(id))
            .copied()
            .collect();
        if new.is_empty() {
            return Vec::new();
        }
        let target = match self.attached.remove(of) {
            Some(l) => l,
            None => {
                let g = all.get(&all.id).expect("genesis").clone();
                IdentityLog::from_genesis(g).expect("checked")
            }
        };
        let mut target = target;
        for id in &new {
            let e = all.get(id).expect("held").clone();
            let _ = target.insert(e);
        }
        self.attached.insert(*of, target);
        let moved: HashSet<EntryId> = new.iter().copied().collect();
        self.unattached.retain(|e| !moved.contains(&e.id()));
        for id in &new {
            self.unattached_ids.remove(id);
        }
        self.promoted.extend(new.iter().copied());
        *self.state.get_mut().expect("lock") = None;
        new
    }

    /// The other identities' logs held under this one's label.
    pub fn attached(&self) -> impl Iterator<Item = &IdentityLog> {
        self.attached.values()
    }

    /// One of them.
    pub fn attached_log(&self, identity: &EntryId) -> Option<&IdentityLog> {
        self.attached.get(identity)
    }

    /// Whether an attached entry is held.
    pub fn has_attached(&self, id: &EntryId) -> bool {
        self.attached.values().any(|l| l.dag.contains(id))
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
        let plan = gather(&logs);
        let owned = plan.owned();
        let refs = plan.refs(&owned);
        let conv = Conversion::new(&refs);
        conv.state(refs[0])
    }

    /// [`evaluate`](Self::evaluate) with no other log, as a verifier that
    /// knows the extensions `known` judges it.
    #[cfg(test)]
    fn evaluate_knowing(&self, known: &[[u8; 32]]) -> IdentityState {
        let logs: Vec<&IdentityLog> = vec![self];
        let plan = gather(&logs);
        let owned = plan.owned();
        let refs = plan.refs(&owned);
        let conv = Conversion::new(&refs);
        conv.state_knowing(refs[0], known)
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
        self.check_removal(author, key)?;
        self.append(author, vec![IdentityOp::remove_key(*key)])
    }

    /// Removes a key that was lost or stolen. What the key wrote that no
    /// other key built on is left out of the removal's parents, which
    /// discards it; [`remove_key`](Self::remove_key) keeps it. A person
    /// choosing to keep some of it would name those entries as parents too.
    pub fn remove_lost_key(
        &mut self,
        author: &SigningKey,
        key: &KeyId,
    ) -> Result<IdentityEntry, Error> {
        self.check_removal(author, key)?;
        let mut left_out: HashSet<EntryId> = HashSet::new();
        for id in self.dag.log_order().iter().rev() {
            let mine = self.dag.get(id).is_some_and(|e| e.signer() == *key);
            if mine && self.dag.children(id).iter().all(|c| left_out.contains(c)) {
                left_out.insert(*id);
            }
        }
        let parents: Vec<EntryId> = self
            .dag
            .log_order()
            .iter()
            .filter(|id| {
                !left_out.contains(*id)
                    && self.dag.children(id).iter().all(|c| left_out.contains(c))
            })
            .copied()
            .collect();
        let e = EntryBuilder::new(self.id, &parents)
            .op(IdentityOp::remove_key(*key))
            .sign(author)?;
        self.insert(e.clone())?;
        Ok(e)
    }

    fn check_removal(&self, author: &SigningKey, key: &KeyId) -> Result<(), Error> {
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
        Ok(())
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
        // and to the guardian key of the policy in effect
        for p in &st.current_policies {
            if let Some(gk) = self.policy(p).and_then(|p| p.guardian_key) {
                recovery_wraps.push(seal(
                    &gk,
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

/// Evaluates several identity logs together, each with the others at hand:
/// a guardian's confirmation is an entry in the guardian's own log, so what
/// a log means can depend on logs beside it. Returns one state for each
/// log, in the order given. A space judges its authors by these
/// (`spaces.md#authors`: "the whole log the verifier holds").
pub fn evaluate_together(logs: &[&IdentityLog]) -> Vec<IdentityState> {
    let plan = gather(logs);
    let owned = plan.owned();
    let refs = plan.refs(&owned);
    let conv = Conversion::new(&refs);
    refs[..plan.given].iter().map(|l| conv.state(l)).collect()
}

/// The model world of several identity logs, to which a space's entries can
/// be added for evaluation by the `space` program. Symbols are the lowercase
/// hex of ids and keys, so symbols compare as the bytes they stand for.
pub fn model_world(logs: &[&IdentityLog]) -> World {
    let plan = gather(logs);
    let owned = plan.owned();
    let refs = plan.refs(&owned);
    Conversion::new(&refs).world
}

/// Logs to evaluate together: those given, then the logs attached to them,
/// each identity once. Where one identity's entries come from more than
/// one place, they are merged into a log of their own.
struct Gathered<'a> {
    /// Each identity's sources, in order: the given logs first.
    sources: Vec<Vec<&'a IdentityLog>>,
    /// How many of them were given (deduplicated).
    given: usize,
}

fn gather<'a>(logs: &[&'a IdentityLog]) -> Gathered<'a> {
    let mut order: Vec<EntryId> = Vec::new();
    let mut sources: HashMap<EntryId, Vec<&'a IdentityLog>> = HashMap::new();
    let mut add = |l: &'a IdentityLog, order: &mut Vec<EntryId>| {
        let v = sources.entry(l.id).or_insert_with(|| {
            order.push(l.id);
            Vec::new()
        });
        v.push(l);
    };
    for l in logs {
        add(l, &mut order);
    }
    let given = order.len();
    for l in logs {
        for a in l.attached.values() {
            add(a, &mut order);
        }
    }
    Gathered {
        sources: order
            .iter()
            .map(|id| sources.remove(id).expect("added"))
            .collect(),
        given,
    }
}

impl<'a> Gathered<'a> {
    /// The merged logs, for identities with more than one source, in order.
    fn owned(&self) -> Vec<IdentityLog> {
        self.sources
            .iter()
            .filter(|s| s.len() > 1)
            .map(|s| {
                let first = s[0];
                let genesis = first.get(&first.id).expect("genesis").clone();
                let mut log = IdentityLog::from_genesis(genesis).expect("a checked genesis");
                for l in s {
                    for e in l.entries().chain(l.dag.held_values()) {
                        let _ = log.insert(e.clone());
                    }
                }
                log
            })
            .collect()
    }

    fn refs<'b>(&self, owned: &'b [IdentityLog]) -> Vec<&'b IdentityLog>
    where
        'a: 'b,
    {
        let mut next = 0;
        self.sources
            .iter()
            .map(|s| {
                if s.len() > 1 {
                    next += 1;
                    &owned[next - 1]
                } else {
                    s[0]
                }
            })
            .collect()
    }
}

/// Real entries of several logs, converted to the model's world.
struct Conversion<'a> {
    world: World,
    logs: HashMap<EntryId, &'a IdentityLog>,
}

impl<'a> Conversion<'a> {
    /// The logs converted, where the protocol records that count are
    /// those in valid entries signed by admin and root keys
    /// (`evolution.md#critical-and-ignorable`): whether an entry is valid
    /// turns on the records before it, so the logs are converted again with
    /// the records found to count until that holds of what is found. Most
    /// logs use no extension, and are converted once.
    fn new(logs: &[&'a IdentityLog]) -> Conversion<'a> {
        let uses = logs.iter().flat_map(|l| l.entries()).any(|e| {
            e.ops()
                .iter()
                .any(|o| matches!(o.body(), OpBody::Extension { .. }))
        });
        let mut conv = Conversion::with(logs, None);
        if !uses {
            return conv;
        }
        let records: Vec<(&IdentityLog, &IdentityEntry)> = logs
            .iter()
            .flat_map(|l| l.entries().map(move |e| (*l, e)))
            .filter(|(_, e)| {
                e.protocol().is_some()
                    || e.ops()
                        .iter()
                        .any(|o| matches!(o.body(), OpBody::SetProtocol { .. }))
            })
            .collect();
        let mut declarers: Option<HashSet<EntryId>> = None;
        // a handful of rounds settles any history a person makes
        for _ in 0..5 {
            let mut found = HashSet::new();
            let mut states: HashMap<EntryId, IdentityState> = HashMap::new();
            for (l, e) in &records {
                let st = states.entry(l.id).or_insert_with(|| conv.state(l));
                if st.valid.contains(&e.id()) && admin_or_root(l, &e.signer()) {
                    found.insert(e.id());
                }
            }
            let all = found.len() == records.len();
            if declarers.as_ref() == Some(&found) || (declarers.is_none() && all) {
                break;
            }
            conv = Conversion::with(logs, Some(&found));
            declarers = Some(found);
        }
        conv
    }

    fn with(logs: &[&'a IdentityLog], declarers: Option<&HashSet<EntryId>>) -> Conversion<'a> {
        let mut world = World::new();
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
        // A confirmation is a reference to another log's entry only where
        // it can count: it names a decision (a `recover`, or a
        // `set_recovery` after genesis) of another log, and its signer is a
        // key its own log names. Anything else reads as an endorsement, so
        // that no entry can make others wait on what it names.
        let decisions: HashSet<EntryId> = under.keys().copied().collect();
        let mut named: HashMap<EntryId, HashSet<KeyId>> = HashMap::new();
        for (l, e) in all.values() {
            for op in e.ops() {
                match op.body() {
                    OpBody::AddKey { key, .. } => {
                        named.entry(l.id).or_default().insert(*key);
                    }
                    OpBody::Recover { root, .. } => {
                        named.entry(l.id).or_default().insert(*root);
                    }
                    _ => {}
                }
            }
        }
        let refers = |l: &IdentityLog, e: &IdentityEntry, d: &EntryId| {
            decisions.contains(d)
                && all.get(d).is_some_and(|(dl, _)| dl.id != l.id)
                && named.get(&l.id).is_some_and(|k| k.contains(&e.signer()))
        };
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
                            refers(logs[li], e, decision) && !placed.contains(decision)
                        }
                        _ => false,
                    });
                    if waits {
                        break;
                    }
                    let e = q.pop().expect("entry");
                    let ok = |d: &EntryId| refers(logs[li], e, d);
                    let entry = convert(&mut world, logs[li], e, &ok, &revealed, declarers);
                    world
                        .put(entry)
                        .expect("parents and decisions are placed first");
                    placed.insert(e.id());
                    progress = true;
                }
            }
            if progress {
                continue;
            }
            // Confirmations waiting on each other in a cycle: the first one
            // blocked is placed with its confirmations read as endorsements,
            // rather than leaving it and everything after it out.
            let Some(li) = queues.iter().position(|q| !q.is_empty()) else {
                break;
            };
            let e = queues[li].pop().expect("entry");
            let entry = convert(&mut world, logs[li], e, &|_| false, &revealed, declarers);
            world.put(entry).expect("parents are placed first");
            placed.insert(e.id());
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
        // no extensions are implemented yet
        self.state_knowing(log, &[])
    }

    /// The state as a verifier that knows the extensions `known` judges it.
    fn state_knowing(&self, log: &IdentityLog, known: &[[u8; 32]]) -> IdentityState {
        let w = &self.world;
        let ident = w.get_sym(&hex_encode(&log.id)).expect("identity");
        let known: BTreeSet<_> = known
            .iter()
            .filter_map(|k| w.get_sym(&hex_encode(k)))
            .collect();
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
            in_effect: r
                .unary("in_effect")
                .iter()
                .map(|s| self.id_of(*s))
                .collect(),
            effective_at: r.rel("effective_at").filter_map(pair).collect(),
            removed: r.unary("removed").iter().map(|s| self.id_of(*s)).collect(),
            removed_at: r.rel("removed_at").filter_map(pair).collect(),
        }
    }
}

/// Whether `key` was added to `log` as an admin or root key.
fn admin_or_root(log: &IdentityLog, key: &KeyId) -> bool {
    log.entries().any(|e| {
        e.ops().iter().any(|o| match o.body() {
            OpBody::AddKey { key: k, power, .. } => k == key && *power >= 2,
            OpBody::Recover { root, .. } => root == key,
            _ => false,
        })
    })
}

/// The mark of extension `name` for entry `e` of `log`: whether a protocol
/// record in its causal past, or in it, marks it critical; `None` where no
/// record declares it. With `declarers`, only the records in those entries
/// of its past count, besides its own.
fn extension_mark(
    log: &IdentityLog,
    e: &IdentityEntry,
    name: &[u8; 32],
    declarers: Option<&HashSet<EntryId>>,
) -> Option<bool> {
    let dag = log.dag();
    let past = dag.ancestors_of(e.parents());
    let records = past
        .iter()
        .filter(|x| declarers.is_none_or(|d| d.contains(*x)))
        .filter_map(|x| dag.get(x))
        .chain(std::iter::once(e))
        .flat_map(|x| {
            let ops = x.ops().iter().filter_map(|o| match o.body() {
                OpBody::SetProtocol { protocol } => Some(protocol),
                _ => None,
            });
            ops.chain(x.protocol())
        });
    let mut mark = None;
    for p in records {
        for (n, critical) in &p.extensions {
            if n == name {
                mark = Some(mark.unwrap_or(false) || *critical);
            }
        }
    }
    mark
}

fn convert(
    w: &mut World,
    log: &IdentityLog,
    e: &IdentityEntry,
    refers: &dyn Fn(&EntryId) -> bool,
    revealed: &HashMap<EntryId, BTreeSet<EntryId>>,
    declarers: Option<&HashSet<EntryId>>,
) -> model::Entry {
    let mut sym = |b: &[u8; 32]| w.sym(&hex_encode(b));
    let id = e.id();
    let counts = declarers.is_none_or(|d| d.contains(&id));
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
                if refers(decision) {
                    Op::Confirm {
                        decision: sym(decision),
                    }
                } else {
                    Op::Endorse
                }
            }
            OpBody::Object { .. } => Op::Object,
            // what an entry that does not count declares, it declares to
            // nothing after it
            OpBody::SetProtocol { protocol } => Op::Protocol {
                declares: if counts {
                    protocol.extensions.iter().map(|(n, _)| sym(n)).collect()
                } else {
                    Vec::new()
                },
            },
            // The protocol records in its causal past, or in it, decide:
            // critical if any marks it so, ignorable if all say ignorable,
            // and an op nobody defined if none declares it
            // (`evolution.md#critical-and-ignorable`).
            OpBody::Extension { name } => match extension_mark(log, e, name, declarers) {
                Some(critical) => Op::Ext {
                    name: sym(name),
                    critical,
                },
                None => Op::Invalid,
            },
            OpBody::Malformed => Op::Invalid,
        });
    }
    if let Some(p) = e.protocol() {
        // the genesis protocol record declares extensions like set_protocol
        ops.push(Op::Protocol {
            declares: if counts {
                p.extensions.iter().map(|(n, _)| sym(n)).collect()
            } else {
                Vec::new()
            },
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn phrase(n: u8) -> RecoveryPhrase {
        RecoveryPhrase::from_entropy(&[n; 32])
    }

    /// An admin key that added a device, and the root that can remove it.
    fn a_key_with_a_last_entry() -> (IdentityLog, DeviceKeys, DeviceKeys, DeviceKeys, SigningKey) {
        let d1 = DeviceKeys::generate();
        let Created {
            mut log,
            phrase,
            encryption,
        } = IdentityLog::create_with(phrase(3), &d1, HybridKeyPair::generate()).unwrap();
        let root = phrase.root_signing_key();
        let (admin, added) = (DeviceKeys::generate(), DeviceKeys::generate());
        log.add_key(
            &d1.signing,
            &admin.request(&log.id(), Power::Admin),
            Some(&encryption),
        )
        .unwrap();
        log.add_key(
            &admin.signing,
            &added.request(&log.id(), Power::Device),
            Some(&encryption),
        )
        .unwrap();
        (log, d1, admin, added, root)
    }

    #[test]
    fn a_retired_key_keeps_what_it_did() {
        let (mut log, _, admin, added, root) = a_key_with_a_last_entry();
        log.remove_key(&root, &admin.key()).unwrap();
        let st = log.state();
        assert_eq!(st.power(&admin.key()), None);
        assert_eq!(st.power(&added.key()), Some(Power::Device));
    }

    #[test]
    fn a_lost_key_keeps_nothing_no_other_key_built_on() {
        let (mut log, d1, admin, added, root) = a_key_with_a_last_entry();
        log.remove_lost_key(&root, &admin.key()).unwrap();
        let st = log.state();
        assert_eq!(st.power(&admin.key()), None);
        assert_eq!(st.power(&added.key()), None, "not built on");
        assert_eq!(st.power(&d1.key()), Some(Power::Admin));

        // The next entry names what was left out as a parent, which brings
        // nothing back: only a removal's own past is kept.
        let other = DeviceKeys::generate();
        log.add_key(&d1.signing, &other.request(&log.id(), Power::Device), None)
            .unwrap();
        assert_eq!(log.state().power(&added.key()), None);
    }

    #[test]
    fn a_lost_key_keeps_what_another_key_built_on() {
        let (mut log, d1, admin, added, root) = a_key_with_a_last_entry();
        let other = DeviceKeys::generate();
        log.add_key(&d1.signing, &other.request(&log.id(), Power::Device), None)
            .unwrap();
        log.remove_lost_key(&root, &admin.key()).unwrap();
        let st = log.state();
        assert_eq!(st.power(&admin.key()), None);
        assert_eq!(st.power(&added.key()), Some(Power::Device));
        assert_eq!(st.power(&other.key()), Some(Power::Device));
    }

    /// Confirmations that name what is not a decision, from anyone, cannot
    /// make the person's own entries wait: an attacker who may send
    /// entries under the person's label attaches A1 = confirm(P_x) and A2,
    /// and pushes junk J beside P_x, sorting before it, holding
    /// confirm(A2). Before, J waited on A2, A2 on A1, A1 on P_x, and P_x and
    /// everything after it were never placed.
    #[test]
    fn confirmations_of_anything_cannot_stall_a_log() {
        let d1 = DeviceKeys::generate();
        let Created {
            mut log,
            encryption,
            ..
        } = IdentityLog::create_with(phrase(5), &d1, HybridKeyPair::generate()).unwrap();
        let admin = DeviceKeys::generate();
        let parents = log.heads();
        let px = log
            .add_key(
                &d1.signing,
                &admin.request(&log.id(), Power::Admin),
                Some(&encryption),
            )
            .unwrap();
        assert_eq!(log.state().power(&admin.key()), Some(Power::Admin));
        // the attacker's own identity
        let a = DeviceKeys::generate();
        let Created { log: mut alog, .. } =
            IdentityLog::create_with(phrase(6), &a, HybridKeyPair::generate()).unwrap();
        let a1 = alog
            .append(
                &a.signing,
                vec![IdentityOp::confirm(px.id(), 1, [0; 32], None)],
            )
            .unwrap();
        let a2 = alog
            .append(&a.signing, vec![IdentityOp::endorse(a1.id(), 1, [0; 32])])
            .unwrap();
        // junk beside P_x, ground to sort before it
        let j = loop {
            let k = SigningKey::generate();
            let j = EntryBuilder::new(log.id(), &parents)
                .op(IdentityOp::confirm(a2.id(), 1, [0; 32], None))
                .sign(&k)
                .unwrap();
            if j.id() < px.id() {
                break j;
            }
        };
        log.insert(j).unwrap();
        for e in alog.entries().cloned().collect::<Vec<_>>() {
            let _ = log.attach(e);
        }
        assert_eq!(log.state().power(&admin.key()), Some(Power::Admin));
        let together = evaluate_together(&[&log, &alog]);
        assert_eq!(together[0].power(&admin.key()), Some(Power::Admin));
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

    /// An ML-KEM public key that fails the FIPS 203 input check (a
    /// coefficient not below q) makes the op that carries it malformed, and
    /// its entry invalid, whatever else is right in it: in an `add_key`'s
    /// link key, whose proof is over exactly those bytes, and as the new key
    /// of a `set_encryption_key`. The entry stays in the graph.
    #[test]
    fn a_malformed_ml_kem_key_makes_its_entry_invalid() {
        use cardinal_encoding::Record;
        let d1 = DeviceKeys::generate();
        let Created { mut log, .. } =
            IdentityLog::create_with(phrase(6), &d1, HybridKeyPair::generate()).unwrap();
        let d2 = DeviceKeys::generate();
        let good = d2.request(&log.id(), Power::Device);
        let bad = |good: &HybridPublicKey| {
            Record::new()
                .with(1, *good.x25519())
                .with(2, vec![0xffu8; cardinal_crypto::kem::PUBLIC_KEY_LEN])
        };
        let link = bad(&good.link_key);
        assert!(HybridPublicKey::from_record(&link).is_err());
        let id = log.id();
        let add = |link: Record| {
            let mut m = crate::entry::add_key_proof_message(&id, &d2.key(), 1, None);
            m.extend(link.encode());
            let proof = d2.signing.sign(&m);
            IdentityOp::from_record(
                Record::new()
                    .with(0, 1u32)
                    .with(1, d2.key())
                    .with(2, 1u64)
                    .with(3, link)
                    .with(5, proof.to_vec()),
            )
        };
        let op = add(link);
        assert_eq!(op.body(), &OpBody::Malformed);
        let e = log.append(&d1.signing, vec![op]).unwrap();
        let st = log.state();
        assert!(!st.is_valid(&e.id()));
        assert_eq!(st.power(&d2.key()), None);
        assert!(log.entries().any(|x| x.id() == e.id()), "kept in the graph");
        // the same op with the key as it should be is valid
        let op = add(good.link_key.to_record());
        assert!(matches!(op.body(), OpBody::AddKey { .. }));
        let e = log.append(&d1.signing, vec![op]).unwrap();
        assert!(log.state().is_valid(&e.id()));
        assert_eq!(log.state().power(&d2.key()), Some(Power::Device));
        // a new encryption key that fails the check
        let fresh = HybridKeyPair::generate();
        let sek =
            IdentityOp::from_record(Record::new().with(0, 3u32).with(1, bad(fresh.public_key())));
        assert_eq!(sek.body(), &OpBody::Malformed);
        let e = log.append(&d1.signing, vec![sek]).unwrap();
        assert!(!log.state().is_valid(&e.id()));
    }

    /// `evolution.md#critical-and-ignorable` (designer, 2026-11-22): the
    /// protocol record marks each extension, and the mark decides on every
    /// device. Ignorable, its ops change no validity, for a verifier that
    /// knows the extension as for one that does not, and any key may use
    /// it. Critical, a device key may not use it, and a verifier that lacks
    /// it stops at an admin's entry that does, while one that knows it
    /// judges on; once marked critical it stays so. An extension no record
    /// declares is an op nobody defined, and a record that names one
    /// extension twice is malformed.
    #[test]
    fn the_protocol_record_marks_each_extension_and_the_mark_decides() {
        use cardinal_encoding::Record;
        let d1 = DeviceKeys::generate();
        let Created { mut log, .. } =
            IdentityLog::create_with(phrase(8), &d1, HybridKeyPair::generate()).unwrap();
        let device = DeviceKeys::generate();
        log.add_key(&d1.signing, &device.request(&log.id(), Power::Device), None)
            .unwrap();
        let (quiet, loud) = ([0x11u8; 32], [0x22u8; 32]);
        let ext =
            |name: [u8; 32]| IdentityOp::from_record(Record::new().with(0, name).with(1, 7u64));
        let protocol = |exts: &[([u8; 32], bool)]| Protocol {
            base: [0; 32],
            extensions: exts.to_vec(),
        };
        // undeclared: an op nobody defined, whatever its document says
        let e = log.append(&d1.signing, vec![ext(quiet)]).unwrap();
        assert!(!log.state().is_valid(&e.id()));
        let p = protocol(&[(quiet, false), (loud, true)]);
        // the record reads back as written
        assert_eq!(Protocol::from_record(&p.to_record()).unwrap(), p);
        let declared = log
            .append(&d1.signing, vec![IdentityOp::set_protocol(&p)])
            .unwrap();
        assert!(log.state().is_valid(&declared.id()));
        // ignorable: a device key may use it, and nobody stops at it
        let q = log.append(&device.signing, vec![ext(quiet)]).unwrap();
        for known in [&[][..], &[quiet][..]] {
            let st = log.evaluate_knowing(known);
            assert!(st.is_valid(&q.id()) && st.stalled.is_empty(), "{known:?}");
        }
        // critical: not a device key's to use
        let bad = log.append(&device.signing, vec![ext(loud)]).unwrap();
        assert!(!log.state().is_valid(&bad.id()));
        // an admin's entry with it is where a verifier without it stops
        let l = log.append(&d1.signing, vec![ext(loud)]).unwrap();
        let after = DeviceKeys::generate();
        let added = log
            .add_key(&d1.signing, &after.request(&log.id(), Power::Device), None)
            .unwrap();
        let without = log.evaluate_knowing(&[]);
        assert_eq!(without.stalled, [l.id()]);
        assert!(!without.is_valid(&added.id()), "what follows waits");
        let with = log.evaluate_knowing(&[loud]);
        assert!(with.stalled.is_empty() && with.is_valid(&added.id()));
        // marked ignorable later, it stays critical
        log.append(
            &d1.signing,
            vec![IdentityOp::set_protocol(&protocol(&[(loud, false)]))],
        )
        .unwrap();
        let again = log.append(&device.signing, vec![ext(loud)]).unwrap();
        assert!(!log.evaluate_knowing(&[loud]).is_valid(&again.id()));
        // a record naming one extension twice
        let twice = Record::new().with(1, [0u8; 32]).with(
            2,
            cardinal_encoding::Value::list([
                Record::new().with(1, quiet),
                Record::new().with(1, quiet).with(2, true),
            ]),
        );
        assert!(Protocol::from_record(&twice).is_err());
        let op = IdentityOp::from_record(Record::new().with(0, 10u32).with(1, twice));
        assert_eq!(op.body(), &OpBody::Malformed);
    }

    /// The review of 2026-11-22: only records in valid entries by admin
    /// and root keys declare. A device key's `set_protocol`, and one an
    /// admin key writes after its removal, declare nothing to what follows.
    #[test]
    fn only_valid_entries_by_admin_keys_declare() {
        use cardinal_encoding::Record;
        let d1 = DeviceKeys::generate();
        let Created { mut log, .. } =
            IdentityLog::create_with(phrase(9), &d1, HybridKeyPair::generate()).unwrap();
        let device = DeviceKeys::generate();
        log.add_key(&d1.signing, &device.request(&log.id(), Power::Device), None)
            .unwrap();
        let (a, b, c) = ([0x31u8; 32], [0x32u8; 32], [0x33u8; 32]);
        let ext =
            |name: [u8; 32]| IdentityOp::from_record(Record::new().with(0, name).with(1, 7u64));
        let protocol = |name: [u8; 32]| Protocol {
            base: [0; 32],
            extensions: vec![(name, false)],
        };
        // a device key's record
        let theirs = log
            .append(
                &device.signing,
                vec![IdentityOp::set_protocol(&protocol(a))],
            )
            .unwrap();
        let used = log.append(&device.signing, vec![ext(a)]).unwrap();
        let st = log.state();
        assert!(!st.is_valid(&theirs.id()) && !st.is_valid(&used.id()));
        // an admin's, once removed
        let admin = DeviceKeys::generate();
        log.add_key(&d1.signing, &admin.request(&log.id(), Power::Admin), None)
            .unwrap();
        let root = phrase(9).root_signing_key();
        log.append(
            &root,
            vec![IdentityOp::remove_key(admin.signing.public_key())],
        )
        .unwrap();
        assert!(log.state().power(&admin.signing.public_key()).is_none());
        let late = log
            .append(&admin.signing, vec![IdentityOp::set_protocol(&protocol(b))])
            .unwrap();
        let used = log.append(&device.signing, vec![ext(b)]).unwrap();
        let st = log.state();
        assert!(!st.is_valid(&late.id()) && !st.is_valid(&used.id()));
        // an admin's in effect declares
        log.append(&d1.signing, vec![IdentityOp::set_protocol(&protocol(c))])
            .unwrap();
        let used = log.append(&device.signing, vec![ext(c)]).unwrap();
        assert!(log.state().is_valid(&used.id()));
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
