//! A space as one device holds it: sealed and opened entries, epoch keys,
//! validity, and state, kept up to date as entries arrive.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use cardinal_crypto::{HybridKeyPair, HybridPublicKey, SigningKey};
use cardinal_identity::dag::{Dag, Inserted};
use cardinal_identity::{EntryId, IdentityLog, IdentityState, KeyId};

use crate::entry::{
    IdentityId, Policy, Profile, SealedEntry, SpaceEntry, SpaceEntryBuilder, SpaceId, SpaceOp,
    SpaceOpBody, OWNER,
};
use crate::epoch::{EpochId, EpochKey, Keyring};
use crate::state::State;
use crate::validity::{Judge, Member, Validity};
use crate::Error;

/// Counters of how the state was kept up to date.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UpdateStats {
    /// Entries applied incrementally.
    pub appended: u64,
    /// Full recomputations of the state.
    pub recomputed: u64,
}

/// A space held by a device of a member.
pub struct Space {
    id: SpaceId,
    profile: Profile,
    policy: Policy,
    creator: IdentityId,
    dag: Dag<SpaceEntry>,
    sealed: HashMap<EntryId, SealedEntry>,
    /// Other sealed forms of entries held. Only an entry's author can sign
    /// it again, and each signing gives the one entry another sealed form.
    /// Each is kept, as a host that cannot open them keeps them, so that
    /// sets reconcile; the entry is judged and applied once.
    resigned: Vec<(EntryId, SealedEntry)>,
    keyring: Keyring,
    judge: Judge,
    state: State,
    /// Each valid entry that no other valid entry descends from: the
    /// parents of the next entry written here.
    valid_heads: BTreeSet<EntryId>,
    current_epoch: Option<(EntryId, EpochId)>,
    stats: UpdateStats,
}

/// The cited head for a new entry by `device`: the last entry in log order
/// at which the key is in effect.
pub fn author_head(log: &IdentityLog, device: &cardinal_identity::KeyId) -> EntryId {
    let st = log.state();
    log.dag()
        .log_order()
        .iter()
        .rev()
        .find(|h| st.is_effective_at(device, h))
        .copied()
        .unwrap_or_else(|| log.id())
}

impl Space {
    /// Creates a space its author owns alone: a genesis entry that names
    /// the author as owner and starts epoch 0, wrapped to each identity
    /// encryption key in `recipients` (for a personal space, the author's
    /// own). Returns the space and the sealed genesis.
    pub fn create(
        profile: Profile,
        policy: Policy,
        author: &IdentityLog,
        device: &SigningKey,
        recipients: &[&HybridPublicKey],
        time: Option<u64>,
    ) -> Result<(Space, SealedEntry), Error> {
        let ops = vec![SpaceOp::add_member(author.id(), OWNER)];
        Space::create_with(profile, policy, author, device, recipients, ops, time)
    }

    /// Creates a space whose genesis entry holds `start` and then `ops`:
    /// the `add_member` ops that name its first members, its author among
    /// them (`spaces.md#members-and-roles`), and what it starts out with.
    /// A genesis that does not name its own author starts nothing.
    pub fn create_with(
        profile: Profile,
        policy: Policy,
        author: &IdentityLog,
        device: &SigningKey,
        recipients: &[&HybridPublicKey],
        ops: Vec<SpaceOp>,
        time: Option<u64>,
    ) -> Result<(Space, SealedEntry), Error> {
        let epoch = EpochKey::generate();
        let wraps: Vec<_> = recipients.iter().map(|r| epoch.wrap(r)).collect();
        let mut b = SpaceEntryBuilder::genesis(
            author.id(),
            author_head(author, &device.public_key()),
            epoch.id(),
        )
        .op(SpaceOp::start(profile, &policy))
        .ops(ops)
        .wraps(&wraps);
        if let Some(t) = time {
            b = b.time(t);
        }
        let g = b.sign(device)?;
        let sealed = SealedEntry::seal(&g, &epoch, Some(wraps), policy.public)?;
        let mut keyring = Keyring::new();
        keyring.add(epoch);
        let mut space = Space::from_genesis(g, keyring, Some(author.state()))?;
        space.sealed.insert(space.id, sealed.clone());
        Ok((space, sealed))
    }

    fn from_genesis(
        g: SpaceEntry,
        keyring: Keyring,
        author: Option<Arc<IdentityState>>,
    ) -> Result<Space, Error> {
        if !g.is_genesis() {
            return Err(Error::Malformed("not a genesis entry"));
        }
        let (profile, policy) = g
            .ops()
            .iter()
            .find_map(|o| match o.body() {
                SpaceOpBody::Start {
                    profile, policy, ..
                } => Some((*profile, policy.clone())),
                _ => None,
            })
            .ok_or(Error::Malformed("genesis without start"))?;
        let mut space = Space {
            id: g.id(),
            profile,
            policy,
            creator: g.author(),
            dag: Dag::new(),
            sealed: HashMap::new(),
            resigned: Vec::new(),
            keyring,
            judge: Judge::new(),
            state: State::new(profile),
            valid_heads: BTreeSet::new(),
            current_epoch: None,
            stats: UpdateStats::default(),
        };
        if let Some(a) = author {
            space.judge.set_state(&space.dag, a);
        }
        space.insert_entry(g);
        Ok(space)
    }

    /// Opens a space from its sealed genesis entry, with this identity's
    /// encryption keys (to open the epoch wrap) and, if it is held, the
    /// evaluated identity log of whoever wrote the genesis. Other authors'
    /// logs are given with [`set_identity`](Self::set_identity).
    pub fn open_genesis(
        sealed: &SealedEntry,
        identity_keys: &[&HybridKeyPair],
        author: Option<Arc<IdentityState>>,
    ) -> Result<Space, Error> {
        let (g, key) = sealed.open(&Keyring::new(), identity_keys)?;
        let mut keyring = Keyring::new();
        keyring.add(key);
        let mut space = Space::from_genesis(g, keyring, author)?;
        space.open_key_belongs(sealed)?;
        space.sealed.insert(space.id, sealed.clone());
        Ok(space)
    }

    /// Opens a space from its sealed genesis entry with keys learned
    /// elsewhere: a member added after it was made gets the current key in
    /// the entry that added them, and the earlier ones from rotations.
    pub fn open_genesis_with(
        sealed: &SealedEntry,
        keyring: Keyring,
        author: Option<Arc<IdentityState>>,
    ) -> Result<Space, Error> {
        let key = keyring
            .get(&sealed.epoch())
            .cloned()
            .ok_or(Error::NoEpochKey)?;
        let g = sealed.open_with(&key)?;
        let mut space = Space::from_genesis(g, keyring, author)?;
        space.open_key_belongs(sealed)?;
        space.sealed.insert(space.id, sealed.clone());
        Ok(space)
    }

    /// The epoch keys sealed entries give these identity keys: the wraps
    /// for them, and the keys rotations carry, as far back as they go.
    pub fn keys_in(sealed: &[SealedEntry], identity_keys: &[&HybridKeyPair]) -> Keyring {
        let mut ring = Keyring::new();
        for s in sealed {
            let found = s
                .wraps()
                .and_then(|w| EpochKey::open_wraps(w, &s.epoch(), identity_keys));
            if let Some(k) = found {
                ring.add(k);
            }
        }
        loop {
            let before = ring.len();
            for s in sealed {
                let Some(k) = ring.get(&s.epoch()).cloned() else {
                    continue;
                };
                let Ok(e) = s.open_with(&k) else {
                    continue;
                };
                for op in e.ops() {
                    if let SpaceOpBody::Rotate { previous } = op.body() {
                        for (id, b) in previous {
                            let key = EpochKey::from_bytes(*b);
                            if &key.id() == id {
                                ring.add(key);
                            }
                        }
                    }
                }
            }
            if ring.len() == before {
                break;
            }
        }
        ring
    }

    /// The space id.
    pub fn id(&self) -> SpaceId {
        self.id
    }

    /// The profile.
    pub fn profile(&self) -> Profile {
        self.profile
    }

    /// The policy from genesis.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// The identity that wrote the genesis. It owns the space only if the
    /// genesis says so ([`owner`](Self::owner)).
    pub fn creator(&self) -> IdentityId {
        self.creator
    }

    /// The space's one owner: the author of its genesis, if the genesis
    /// names it as owner. A space with no owner, such as a relationship,
    /// has the members its genesis names for good, and they decide together
    /// what an owner would decide alone.
    pub fn owner(&self) -> Option<IdentityId> {
        self.judge.owner()
    }

    /// The opened entries.
    pub fn dag(&self) -> &Dag<SpaceEntry> {
        &self.dag
    }

    /// An opened entry.
    pub fn entry(&self, id: &EntryId) -> Option<&SpaceEntry> {
        self.dag.get(id)
    }

    /// The sealed form of an entry.
    pub fn sealed(&self, id: &EntryId) -> Option<&SealedEntry> {
        self.sealed.get(id)
    }

    /// Every sealed entry held. An entry its author signed again is here
    /// once for each signature.
    pub fn sealed_entries(&self) -> impl Iterator<Item = (&EntryId, &SealedEntry)> {
        let resigned = self.resigned.iter().map(|(id, s)| (id, s));
        self.sealed.iter().chain(resigned)
    }

    /// The heads of what is held to be valid: each valid entry that no
    /// other valid entry descends from, sorted. These are the parents of a
    /// new entry; an entry held to be invalid is never one
    /// (`spaces.md#entries-and-sealed-entries`). The heads of everything
    /// held, valid or not, are [`dag`](Self::dag)`().heads()`.
    pub fn heads(&self) -> Vec<EntryId> {
        self.valid_heads.iter().copied().collect()
    }

    /// The epoch keys held.
    pub fn keyring(&self) -> &Keyring {
        &self.keyring
    }

    /// The current epoch: started by the valid epoch-starting entry last in
    /// log order among those with no epoch-starting descendants.
    pub fn current_epoch(&self) -> Option<EpochId> {
        self.current_epoch.map(|(_, e)| e)
    }

    /// Validity of the entries, and the members.
    pub fn validity(&self) -> &Validity {
        self.judge.validity()
    }

    /// The members: each identity with each role a valid entry gave it.
    pub fn members(&self) -> &[Member] {
        &self.judge.validity().members
    }

    /// The highest role `who` holds, if they are a member.
    pub fn role_of(&self, who: &IdentityId) -> Option<u64> {
        self.judge.validity().role_of(who)
    }

    /// Whether `who` has left: they wrote a valid `leave` that no valid
    /// `add_member` of them descends from. Leaving changes nothing about
    /// what is valid; the others stop sending to someone who left, and
    /// leave them out when the space's keys next change.
    pub fn has_left(&self, who: &IdentityId) -> bool {
        self.judge.has_left(&self.dag, who)
    }

    /// The members who have not left, each once, sorted: whom this space is
    /// still shared with.
    pub fn present(&self) -> Vec<IdentityId> {
        let gone: Vec<IdentityId> = self.left().into_iter().map(|(who, _)| who).collect();
        let mut all = self.validity().identities();
        all.retain(|who| !gone.contains(who));
        all
    }

    /// Who has left, and the `leave` of theirs that stands.
    pub fn left(&self) -> Vec<(IdentityId, EntryId)> {
        self.judge.standing_leaves(&self.dag)
    }

    /// Whether `who` has accepted the space and not left it since: they
    /// wrote something valid in it, its genesis or anything after, that no
    /// `leave` of theirs descends from (`spaces.md#holding-a-space`).
    pub fn accepted_by(&self, who: &IdentityId) -> bool {
        !self.has_left(who) && self.judge.wrote_since_leaving(&self.dag, who)
    }

    /// Whether a member has left since the current epoch began, or began it
    /// and then left: whoever writes next starts a new one, wrapped for
    /// those who stay (`spaces.md#when-to-rotate`).
    pub fn left_since_epoch(&self) -> bool {
        let Some((start, _)) = self.current_epoch else {
            return false;
        };
        let left = self.left();
        left.iter()
            .any(|(_, leave)| !self.dag.is_ancestor(leave, &start))
    }

    /// The successor that stands, if the space has been succeeded
    /// (`spaces.md#ending-a-space`).
    pub fn successor(&self) -> Option<SpaceId> {
        self.judge.successor(&self.dag)
    }

    /// Whether the space has ended as far as this device has seen: an entry
    /// written now, on everything valid, would descend from the end.
    pub fn ended(&self) -> bool {
        self.judge.closes(&self.dag, &self.heads())
    }

    /// The judge, for what it found beyond [`validity`](Self::validity).
    pub fn judge(&self) -> &Judge {
        &self.judge
    }

    /// The state.
    pub fn state(&self) -> &State {
        &self.state
    }

    /// How updates were made.
    pub fn stats(&self) -> UpdateStats {
        self.stats
    }

    /// Takes the evaluated identity log of an author, as this device holds
    /// it now. The signatures of that author's entries are judged again,
    /// and with them whatever rested on them.
    pub fn set_identity(&mut self, state: Arc<IdentityState>) {
        let changed = self.judge.set_state(&self.dag, state);
        self.took(None, changed);
    }

    /// [`set_identity`](Self::set_identity) for several authors at once,
    /// bringing the state up to date once at the end.
    pub fn set_identities(&mut self, states: impl IntoIterator<Item = Arc<IdentityState>>) {
        let mut changed = false;
        for state in states {
            changed |= !self.judge.set_state(&self.dag, state).is_empty();
        }
        if changed {
            self.start_over();
        }
    }

    /// Opens and adds a sealed entry. Returns what the graph did with it.
    pub fn receive(
        &mut self,
        sealed: SealedEntry,
        identity_keys: &[&HybridKeyPair],
    ) -> Result<Inserted, Error> {
        let (e, key) = sealed.open(&self.keyring, identity_keys)?;
        if e.space() != self.id {
            return Err(Error::WrongSpace);
        }
        self.open_key_belongs(&sealed)?;
        self.keyring.add(key);
        self.learn_keys(&e);
        let id = e.id();
        if let Some(held) = self.sealed.get(&id) {
            // The entry is here already, under the same key: its id says
            // who signed it. This is its author's signature made again,
            // which means the same. The sealed form is kept, and nothing
            // is judged again.
            let sid = sealed.sealed_id();
            let new =
                held.sealed_id() != sid && !self.resigned.iter().any(|(_, s)| s.sealed_id() == sid);
            if new {
                self.resigned.push((id, sealed));
            }
            return Ok(Inserted::Duplicate);
        }
        self.sealed.insert(id, sealed);
        Ok(self.insert_entry(e))
    }

    /// A member rejects a sealed entry that carries the epoch key in the
    /// clear where the space is not public, or does not where it is
    /// (`spaces.md#entries-and-sealed-entries`). The policy is the one the
    /// genesis gave: `set_policy` is not applied yet (DEVIATIONS.md).
    fn open_key_belongs(&self, sealed: &SealedEntry) -> Result<(), Error> {
        if sealed.open_key().is_some() == self.policy.public {
            Ok(())
        } else {
            Err(Error::Mismatch("open key"))
        }
    }

    fn learn_keys(&mut self, e: &SpaceEntry) {
        for op in e.ops() {
            if let SpaceOpBody::Rotate { previous } = op.body() {
                for (id, k) in previous {
                    let key = EpochKey::from_bytes(*k);
                    if &key.id() == id {
                        self.keyring.add(key);
                    }
                }
            }
        }
    }

    /// Adds an opened entry (already checked against its sealed form). It is
    /// judged once it and its ancestors are all here.
    pub fn insert_entry(&mut self, e: SpaceEntry) -> Inserted {
        let id = e.id();
        let r = self.dag.insert(id, e.parents().to_vec(), e);
        if let Inserted::Added(added) = &r {
            for x in added {
                let changed = self.judge.arrive(&self.dag, x);
                self.took(Some(x), changed);
            }
        }
        r
    }

    /// Brings the state up to date after validity changed for `changed`,
    /// on the arrival of `new` or, without one, a change of signatures.
    fn took(&mut self, new: Option<&EntryId>, changed: Vec<EntryId>) {
        match (new, changed.as_slice()) {
            // Nothing valid changed: an entry that does not count, or an
            // identity log that grew without changing which keys do.
            (_, []) => {}
            // The new entry is valid and nothing else moved.
            (Some(id), [only]) if only == id => {
                let e = self.dag.get(id).expect("entry");
                let behind = |h: &EntryId| e.parents().contains(h) || self.dag.is_ancestor(h, id);
                let after_all = self.valid_heads.iter().all(behind);
                let left: BTreeSet<EntryId> = self
                    .valid_heads
                    .iter()
                    .filter(|h| !behind(h))
                    .copied()
                    .collect();
                self.valid_heads = left;
                self.valid_heads.insert(*id);
                if after_all {
                    // It descends from everything applied, so it comes last
                    // in log order among what is valid.
                    self.state.append(&self.dag, e);
                    if e.starts_epoch() {
                        self.current_epoch = Some((*id, e.epoch()));
                    }
                    self.stats.appended += 1;
                } else {
                    self.recompute_state();
                }
            }
            // Entries that were here started or stopped being valid.
            _ => self.start_over(),
        }
    }

    fn start_over(&mut self) {
        self.valid_heads = self.compute_valid_heads();
        self.recompute_state();
    }

    fn recompute_state(&mut self) {
        self.stats.recomputed += 1;
        self.state = State::compute(self.profile, &self.dag, &self.validity().valid);
        self.current_epoch = self.compute_epoch();
    }

    /// Each valid entry that no other valid entry descends from.
    fn compute_valid_heads(&self) -> BTreeSet<EntryId> {
        let valid = &self.validity().valid;
        let mut heads = BTreeSet::new();
        // entries that a valid entry descends from
        let mut behind: HashSet<EntryId> = HashSet::new();
        for x in self.dag.log_order().iter().rev() {
            let is_valid = valid.contains(x);
            let covered = behind.contains(x);
            if is_valid && !covered {
                heads.insert(*x);
            }
            if is_valid || covered {
                behind.extend(self.dag.parents(x).iter().copied());
            }
        }
        heads
    }

    fn compute_epoch(&self) -> Option<(EntryId, EpochId)> {
        let starters: Vec<EntryId> = self
            .dag
            .log_order()
            .iter()
            .filter(|x| {
                self.validity().is_valid(x) && self.dag.get(x).is_some_and(|e| e.starts_epoch())
            })
            .copied()
            .collect();
        starters
            .iter()
            .rfind(|s| !starters.iter().any(|t| self.dag.is_ancestor(s, t)))
            .map(|s| (*s, self.dag.get(s).expect("entry").epoch()))
    }

    /// Whether the current epoch was wrapped for the identity encryption
    /// key `key`. If it was not, the epoch began before the identity moved
    /// to `key`, so a device removed since can still read it, and the next
    /// write must start a new one (`spaces.md#when-to-rotate`).
    pub fn epoch_wrapped_for(&self, key: &HybridKeyPair) -> bool {
        let Some((entry, epoch)) = self.current_epoch else {
            return true;
        };
        match self.sealed.get(&entry).and_then(SealedEntry::wraps) {
            Some(wraps) => EpochKey::open_wraps(wraps, &epoch, &[key]).is_some(),
            None => true,
        }
    }

    /// The entry that started the current epoch, and who wrote it.
    pub fn epoch_started_by(&self) -> Option<(EntryId, IdentityId)> {
        let (entry, _) = self.current_epoch?;
        Some((entry, self.dag.get(&entry)?.author()))
    }

    /// Whether `key` wrote something that no other key of its identity
    /// built on. Once the key is removed such an entry counts only if
    /// witnessed (`spaces.md#authors`), and a write by another of the
    /// identity's keys on the valid heads does that. Other members building
    /// on an entry does not save it.
    pub fn has_unwitnessed(&self, key: &KeyId) -> bool {
        self.judge.unwitnessed_work(&self.dag, key)
    }

    /// How many entries by the removed `key` do not count, for want of a
    /// witness.
    pub fn unwitnessed_by(&self, key: &KeyId) -> usize {
        let by_key = |x: &&EntryId| self.dag.get(x).is_some_and(|e| e.signer() == *key);
        self.validity().unwitnessed.iter().filter(by_key).count()
    }

    /// Writes an entry with `ops` under the current epoch, with the valid
    /// heads as parents. Returns the sealed entry to store and sync.
    pub fn write(
        &mut self,
        author: &IdentityLog,
        device: &SigningKey,
        ops: Vec<SpaceOp>,
        time: Option<u64>,
    ) -> Result<SealedEntry, Error> {
        Ok(self.write_entry(author, device, ops, time)?.1)
    }

    /// [`write`](Self::write), returning the new entry's id as well.
    pub fn write_entry(
        &mut self,
        author: &IdentityLog,
        device: &SigningKey,
        ops: Vec<SpaceOp>,
        time: Option<u64>,
    ) -> Result<(EntryId, SealedEntry), Error> {
        let heads = self.heads();
        self.write_on(author, device, &heads, ops, time)
    }

    /// Writes an entry with `ops` that does not descend from any of
    /// `exclude`: its parents are the latest valid entries that are not
    /// descendants of them (or them). The entry is concurrent with each
    /// of `exclude`, so its `set`s do not supersede theirs and its deletes
    /// yield to them: for a change made without having seen theirs.
    ///
    /// Refused (`NotAllowed`) when no such parents exist, or when the
    /// current epoch started in an entry the new one would not descend
    /// from (it must be encrypted under the epoch current in its past).
    pub fn write_concurrent(
        &mut self,
        author: &IdentityLog,
        device: &SigningKey,
        exclude: &[EntryId],
        ops: Vec<SpaceOp>,
        time: Option<u64>,
    ) -> Result<(EntryId, SealedEntry), Error> {
        let parents = self.latest_excluding(exclude);
        if parents.is_empty() {
            return Err(Error::NotAllowed("no parents outside the excluded entries"));
        }
        let (starter, _) = self.current_epoch.ok_or(Error::NoEpochKey)?;
        if !parents
            .iter()
            .any(|p| self.dag.is_ancestor_or_self(&starter, p))
        {
            return Err(Error::NotAllowed(
                "the current epoch starts after the excluded entries",
            ));
        }
        self.write_on(author, device, &parents, ops, time)
    }

    /// The latest valid entries that are neither one of `exclude` nor
    /// descend from one: the valid heads of the graph with `exclude` and
    /// everything after them removed.
    pub fn latest_excluding(&self, exclude: &[EntryId]) -> Vec<EntryId> {
        let mut gone: HashSet<EntryId> = HashSet::new();
        for x in exclude.iter().filter(|x| self.dag.contains(x)) {
            gone.insert(*x);
            gone.extend(self.dag.descendants(x));
        }
        // Step back from the valid heads, past what is excluded and what is
        // not valid, to the first valid entries behind them.
        let valid = &self.validity().valid;
        let mut kept: Vec<EntryId> = Vec::new();
        let mut seen: HashSet<EntryId> = HashSet::new();
        let mut todo: Vec<EntryId> = self.heads();
        while let Some(x) = todo.pop() {
            if !seen.insert(x) {
                continue;
            }
            if gone.contains(&x) || !valid.contains(&x) {
                todo.extend_from_slice(self.dag.parents(&x));
            } else {
                kept.push(x);
            }
        }
        let mut out: Vec<EntryId> = kept
            .iter()
            .filter(|c| !kept.iter().any(|k| self.dag.is_ancestor(c, k)))
            .copied()
            .collect();
        out.sort();
        out
    }

    /// Whether a new entry on `parents` may be written: there is something
    /// valid to build on, and the space has not ended there. Only an entry
    /// of `keep` ops is written into a space that has ended: it counts by
    /// its signature alone
    /// (`spaces.md#a-succession-by-a-device-that-is-later-removed`).
    fn may_write(&self, parents: &[EntryId], only_keeps: bool) -> Result<(), Error> {
        if parents.is_empty() {
            return Err(Error::NotAllowed("nothing valid here to build on"));
        }
        if !only_keeps && self.judge.closes(&self.dag, parents) {
            return Err(Error::NotAllowed("the space has ended"));
        }
        Ok(())
    }

    fn write_on(
        &mut self,
        author: &IdentityLog,
        device: &SigningKey,
        parents: &[EntryId],
        ops: Vec<SpaceOp>,
        time: Option<u64>,
    ) -> Result<(EntryId, SealedEntry), Error> {
        let keeps = |o: &SpaceOp| matches!(o.body(), SpaceOpBody::Keep { .. });
        self.may_write(parents, !ops.is_empty() && ops.iter().all(keeps))?;
        let epoch = self.current_epoch().ok_or(Error::NoEpochKey)?;
        let key = self.keyring.get(&epoch).cloned().ok_or(Error::NoEpochKey)?;
        let mut b = SpaceEntryBuilder::new(
            self.id,
            parents,
            author.id(),
            author_head(author, &device.public_key()),
            epoch,
        )
        .ops(ops);
        if let Some(t) = time {
            b = b.time(t);
        }
        let e = b.sign(device)?;
        let id = e.id();
        let sealed = SealedEntry::seal(&e, &key, None, self.policy.public)?;
        self.sealed.insert(id, sealed.clone());
        self.insert_entry(e);
        Ok((id, sealed))
    }

    /// Adds members in one entry, with the current epoch key wrapped for each
    /// one added (`spaces.md#distribution`), together with `ops`. A space
    /// that does not share history with new members rotates instead, for
    /// `everyone` already in it and those added.
    pub fn add_members(
        &mut self,
        author: &IdentityLog,
        device: &SigningKey,
        added: &[(IdentityId, u64, &HybridPublicKey)],
        everyone: &[&HybridPublicKey],
        ops: Vec<SpaceOp>,
        time: Option<u64>,
    ) -> Result<SealedEntry, Error> {
        let mut all: Vec<SpaceOp> = added
            .iter()
            .map(|(id, role, _)| SpaceOp::add_member(*id, *role))
            .collect();
        all.extend(ops);
        if !self.policy.history_shared {
            let mut recipients: Vec<&HybridPublicKey> = everyone.to_vec();
            recipients.extend(added.iter().map(|(_, _, k)| *k));
            return Ok(self.rotate(author, device, &recipients, all, time)?.0);
        }
        let heads = self.heads();
        self.may_write(&heads, false)?;
        let epoch = self.current_epoch().ok_or(Error::NoEpochKey)?;
        let key = self.keyring.get(&epoch).cloned().ok_or(Error::NoEpochKey)?;
        let wraps: Vec<_> = added.iter().map(|(_, _, k)| key.wrap(k)).collect();
        let mut b = SpaceEntryBuilder::new(
            self.id,
            &heads,
            author.id(),
            author_head(author, &device.public_key()),
            epoch,
        )
        .ops(all)
        .wraps(&wraps);
        if let Some(t) = time {
            b = b.time(t);
        }
        let e = b.sign(device)?;
        let sealed = SealedEntry::seal(&e, &key, Some(wraps), self.policy.public)?;
        self.sealed.insert(e.id(), sealed.clone());
        self.insert_entry(e);
        Ok(sealed)
    }

    /// Starts a new epoch wrapped to each member identity's encryption key
    /// in `recipients`, carrying the keys of the epochs it supersedes when
    /// history is shared, together with `ops`.
    pub fn rotate(
        &mut self,
        author: &IdentityLog,
        device: &SigningKey,
        recipients: &[&HybridPublicKey],
        ops: Vec<SpaceOp>,
        time: Option<u64>,
    ) -> Result<(SealedEntry, EpochKey), Error> {
        let (_, sealed, key) = self.rotate_entry(author, device, recipients, ops, time)?;
        Ok((sealed, key))
    }

    /// [`rotate`](Self::rotate), returning the new entry's id as well.
    pub fn rotate_entry(
        &mut self,
        author: &IdentityLog,
        device: &SigningKey,
        recipients: &[&HybridPublicKey],
        ops: Vec<SpaceOp>,
        time: Option<u64>,
    ) -> Result<(EntryId, SealedEntry, EpochKey), Error> {
        let new = EpochKey::generate();
        let heads = self.heads();
        self.may_write(&heads, false)?;
        // epochs current in the causal past: starters with no starter
        // descendant among the new entry's ancestors
        let past: HashSet<EntryId> = self.dag.ancestors_of(&heads);
        let starters: Vec<EntryId> = past
            .iter()
            .filter(|x| {
                self.validity().is_valid(x) && self.dag.get(x).is_some_and(|e| e.starts_epoch())
            })
            .copied()
            .collect();
        let mut previous = Vec::new();
        if self.policy.history_shared {
            for s in &starters {
                if starters.iter().any(|t| self.dag.is_ancestor(s, t)) {
                    continue;
                }
                let ep = self.dag.get(s).expect("entry").epoch();
                if let Some(k) = self.keyring.get(&ep) {
                    previous.push(k.clone());
                }
            }
        }
        let refs: Vec<&EpochKey> = previous.iter().collect();
        let wraps: Vec<_> = recipients.iter().map(|r| new.wrap(r)).collect();
        let mut b = SpaceEntryBuilder::new(
            self.id,
            &heads,
            author.id(),
            author_head(author, &device.public_key()),
            new.id(),
        )
        .op(SpaceOp::rotate(&refs))
        .ops(ops)
        .wraps(&wraps);
        if let Some(t) = time {
            b = b.time(t);
        }
        let e = b.sign(device)?;
        let id = e.id();
        let sealed = SealedEntry::seal(&e, &new, Some(wraps), self.policy.public)?;
        self.keyring.add(new.clone());
        self.sealed.insert(id, sealed.clone());
        self.insert_entry(e);
        Ok((id, sealed, new))
    }
}
