//! A space as one device holds it: sealed and opened entries, epoch keys,
//! validity, and state, kept up to date as entries arrive.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use cardinal_crypto::{HybridKeyPair, HybridPublicKey, SigningKey};
use cardinal_identity::dag::{Dag, Inserted};
use cardinal_identity::{EntryId, IdentityLog, IdentityState, KeyId};

use crate::entry::{
    IdentityId, MembershipId, Policy, Profile, SealedEntry, SpaceEntry, SpaceEntryBuilder, SpaceId,
    SpaceOp, SpaceOpBody,
};
use crate::epoch::{EpochId, EpochKey, Keyring};
use crate::membership::{evaluate_full, evaluate_single, membership_of, Validity};
use crate::state::State;
use crate::Error;

/// Counters of how the state was kept up to date.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UpdateStats {
    /// Entries applied incrementally.
    pub appended: u64,
    /// Full recomputations.
    pub recomputed: u64,
}

/// A space held by a device of a member.
pub struct Space {
    id: SpaceId,
    profile: Profile,
    policy: Policy,
    owner: IdentityId,
    dag: Dag<SpaceEntry>,
    sealed: HashMap<EntryId, SealedEntry>,
    keyring: Keyring,
    author: Option<Arc<IdentityState>>,
    validity: Validity,
    unsupported: Option<&'static str>,
    state: State,
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
    /// Creates a space: a genesis entry starting epoch 0, wrapped to each
    /// member identity's encryption key in `recipients` (for a personal
    /// space, the author's own). Returns the space and the sealed genesis.
    pub fn create(
        profile: Profile,
        policy: Policy,
        author: &IdentityLog,
        device: &SigningKey,
        recipients: &[&HybridPublicKey],
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
            owner: g.author(),
            dag: Dag::new(),
            sealed: HashMap::new(),
            keyring,
            author,
            validity: Validity::default(),
            unsupported: None,
            state: State::new(profile),
            current_epoch: None,
            stats: UpdateStats::default(),
        };
        space.insert_entry(g);
        Ok(space)
    }

    /// Opens a space from its sealed genesis entry, with this identity's
    /// encryption keys (to open the epoch wrap) and the creator's
    /// evaluated identity log.
    pub fn open_genesis(
        sealed: &SealedEntry,
        identity_keys: &[&HybridKeyPair],
        author: Option<Arc<IdentityState>>,
    ) -> Result<Space, Error> {
        let (g, key) = sealed.open(&Keyring::new(), identity_keys)?;
        let mut keyring = Keyring::new();
        keyring.add(key);
        let mut space = Space::from_genesis(g, keyring, author)?;
        space.sealed.insert(space.id, sealed.clone());
        Ok(space)
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

    /// The identity that created the space.
    pub fn owner(&self) -> IdentityId {
        self.owner
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

    /// Every sealed entry held.
    pub fn sealed_entries(&self) -> impl Iterator<Item = (&EntryId, &SealedEntry)> {
        self.sealed.iter()
    }

    /// The current heads.
    pub fn heads(&self) -> Vec<EntryId> {
        self.dag.heads()
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

    /// Validity of the entries.
    pub fn validity(&self) -> &Validity {
        &self.validity
    }

    /// Whether native evaluation refused this space, and why.
    pub fn unsupported(&self) -> Option<&'static str> {
        self.unsupported
    }

    /// The state.
    pub fn state(&self) -> &State {
        &self.state
    }

    /// How updates were made.
    pub fn stats(&self) -> UpdateStats {
        self.stats
    }

    /// The membership this space's creator writes under.
    pub fn owner_membership(&self) -> Option<MembershipId> {
        self.dag.get(&self.id).and_then(|g| g.genesis_membership())
    }

    /// Replaces the creator's evaluated identity log, re-evaluating if it
    /// changed.
    pub fn set_author(&mut self, author: Arc<IdentityState>) {
        if self.author.as_deref() != Some(&*author) {
            self.author = Some(author);
            self.recompute();
        }
    }

    /// Re-evaluates with the normative `space` program, given the authors'
    /// identity logs. This handles spaces with several members, at a cost
    /// quadratic in the number of entries.
    pub fn evaluate_full(&mut self, logs: &[&IdentityLog]) -> Result<(), Error> {
        self.validity = evaluate_full(&self.dag, logs)?;
        self.unsupported = None;
        self.state = State::compute(self.profile, &self.dag, &self.validity.valid);
        self.current_epoch = self.compute_epoch();
        self.stats.recomputed += 1;
        Ok(())
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
        self.keyring.add(key);
        self.learn_keys(&e);
        let id = e.id();
        self.sealed.entry(id).or_insert(sealed);
        Ok(self.insert_entry(e))
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

    fn can_append(&self, e: &SpaceEntry) -> bool {
        self.author.is_some()
            && self.unsupported.is_none()
            && self.validity.unwitnessed.is_empty()
            && !self.validity.members.is_empty()
            && self.dag.descends_from_all_heads(e.parents())
            && e.parents().iter().all(|p| self.dag.contains(p))
            && e.author() == self.owner
            && e.ops().iter().all(|o| match o.body() {
                SpaceOpBody::Rotate { .. } => true,
                b => !b.is_control(),
            })
    }

    /// Adds an opened entry (already checked against its sealed form).
    pub fn insert_entry(&mut self, e: SpaceEntry) -> Inserted {
        let fast = !self.dag.is_empty() && self.can_append(&e);
        let id = e.id();
        let r = self.dag.insert(id, e.parents().to_vec(), e);
        match &r {
            Inserted::Added(v) if fast && v.len() == 1 => self.append_one(&id),
            Inserted::Added(_) => self.recompute(),
            _ => {}
        }
        r
    }

    fn append_one(&mut self, id: &EntryId) {
        let e = self.dag.get(id).expect("entry");
        let author = self.author.as_ref().expect("author");
        let i0 = self.owner_membership();
        let valid = !author.frozen
            && membership_of(e) == i0
            && author.is_effective_at(&e.signer(), &e.author_head())
            && !author.is_removed(&e.signer());
        if author.is_effective_at(&e.signer(), &e.author_head()) {
            self.validity.author_ok.insert(*id);
        }
        if valid {
            self.validity.valid.insert(*id);
            self.state.append(&self.dag, e);
            if e.starts_epoch() {
                self.current_epoch = Some((*id, e.epoch()));
            }
        } else if author.is_effective_at(&e.signer(), &e.author_head()) && !author.frozen {
            // a removed key: it may be witnessed later
            self.validity.unwitnessed.insert(*id);
        }
        self.stats.appended += 1;
    }

    fn recompute(&mut self) {
        self.stats.recomputed += 1;
        let Some(author) = self.author.clone() else {
            self.validity = Validity::default();
            self.state = State::new(self.profile);
            self.current_epoch = None;
            return;
        };
        match evaluate_single(&self.dag, &author) {
            Ok(v) => {
                self.validity = v;
                self.unsupported = None;
            }
            Err(Error::Unsupported(why)) => {
                self.validity = Validity::default();
                self.unsupported = Some(why);
            }
            Err(_) => self.validity = Validity::default(),
        }
        self.state = State::compute(self.profile, &self.dag, &self.validity.valid);
        self.current_epoch = self.compute_epoch();
    }

    fn compute_epoch(&self) -> Option<(EntryId, EpochId)> {
        let starters: Vec<EntryId> = self
            .dag
            .log_order()
            .iter()
            .filter(|x| {
                self.validity.is_valid(x) && self.dag.get(x).is_some_and(|e| e.starts_epoch())
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

    /// Whether `key` wrote something that no other key built on. Once the
    /// key is removed such an entry counts only if witnessed
    /// (`spaces.md#authors`), and any other key's write on the heads does
    /// that.
    pub fn has_unwitnessed(&self, key: &KeyId) -> bool {
        self.dag
            .heads()
            .iter()
            .any(|h| self.dag.get(h).is_some_and(|e| e.signer() == *key))
    }

    /// How many entries by the removed `key` do not count, for want of a
    /// witness.
    pub fn unwitnessed_by(&self, key: &KeyId) -> usize {
        self.validity
            .unwitnessed
            .iter()
            .filter(|x| self.dag.get(x).is_some_and(|e| e.signer() == *key))
            .count()
    }

    /// Writes an entry with `ops` under the current epoch, with the current
    /// heads as parents. Returns the sealed entry to store and sync.
    pub fn write(
        &mut self,
        author: &IdentityLog,
        device: &SigningKey,
        ops: Vec<SpaceOp>,
        time: Option<u64>,
    ) -> Result<SealedEntry, Error> {
        let heads = self.heads();
        Ok(self.write_on(author, device, &heads, ops, time)?.1)
    }

    /// Writes an entry with `ops` that does not descend from any of
    /// `exclude`: its parents are the latest entries that are not
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

    /// The maximal entries that are neither one of `exclude` nor descend
    /// from one: the heads of the graph with `exclude` and everything
    /// after them removed.
    pub fn latest_excluding(&self, exclude: &[EntryId]) -> Vec<EntryId> {
        let mut gone: HashSet<EntryId> = HashSet::new();
        for x in exclude.iter().filter(|x| self.dag.contains(x)) {
            gone.insert(*x);
            gone.extend(self.dag.descendants(x));
        }
        let mut candidates: HashSet<EntryId> = self.dag.heads().into_iter().collect();
        for g in &gone {
            candidates.extend(self.dag.parents(g).iter().copied());
        }
        let mut out: Vec<EntryId> = candidates
            .into_iter()
            .filter(|c| !gone.contains(c) && self.dag.children(c).iter().all(|k| gone.contains(k)))
            .collect();
        out.sort();
        out
    }

    fn write_on(
        &mut self,
        author: &IdentityLog,
        device: &SigningKey,
        parents: &[EntryId],
        ops: Vec<SpaceOp>,
        time: Option<u64>,
    ) -> Result<(EntryId, SealedEntry), Error> {
        let epoch = self.current_epoch().ok_or(Error::NoEpochKey)?;
        let key = self.keyring.get(&epoch).cloned().ok_or(Error::NoEpochKey)?;
        let mut b = SpaceEntryBuilder::new(
            self.id,
            parents,
            author.id(),
            author_head(author, &device.public_key()),
            epoch,
            self.owner_membership_for(author.id()),
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

    fn owner_membership_for(&self, identity: IdentityId) -> Option<MembershipId> {
        if identity == self.owner {
            return self.owner_membership();
        }
        self.validity
            .members
            .iter()
            .filter(|m| m.identity == identity)
            .max_by_key(|m| m.role)
            .map(|m| m.id)
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
        let new = EpochKey::generate();
        let heads = self.heads();
        // epochs current in the causal past: starters with no starter
        // descendant among the new entry's ancestors
        let past: HashSet<EntryId> = self.dag.ancestors_of(&heads);
        let starters: Vec<EntryId> = past
            .iter()
            .filter(|x| {
                self.validity.is_valid(x) && self.dag.get(x).is_some_and(|e| e.starts_epoch())
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
            self.owner_membership_for(author.id()),
        )
        .op(SpaceOp::rotate(&refs))
        .ops(ops)
        .wraps(&wraps);
        if let Some(t) = time {
            b = b.time(t);
        }
        let e = b.sign(device)?;
        let sealed = SealedEntry::seal(&e, &new, Some(wraps), self.policy.public)?;
        self.keyring.add(new.clone());
        self.sealed.insert(e.id(), sealed.clone());
        self.insert_entry(e);
        Ok((sealed, new))
    }
}
