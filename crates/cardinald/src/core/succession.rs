//! Succession on this device (`spaces.md#succession`): the owner writing
//! one, a member's device following one, and what it posts again.
//!
//! - **Writing.** The owner succeeds a space with a genesis that names who
//!   stays and with what role ([`Core::succeed`]). The cut is the heads of
//!   everything valid held here; the identity logs it is judged with are
//!   pinned as this device holds them; the state at the cut goes in a blob
//!   encrypted under the successor's first epoch, whose reference is the
//!   initial state. The `succeed` goes in the old space with the
//!   successor's sealed genesis beside it, in the old space's set, which
//!   is the trail every member walks.
//! - **Following.** A member's device that learns of a successor that
//!   stands checks it as `spaces.md#following` says and, where it holds,
//!   holds the successor from then on, with a space node for it in the
//!   account whose field 4 names the old space ([`Core::follow`]). Its own
//!   check of the initial state is the blob it makes of the state at the
//!   cut as it works it out: the same reference, or not what it says.
//! - **Posting again.** The device posts again, into the space that
//!   stands, what it wrote that the successor does not carry, and what it
//!   wrote in a successor that no longer stands; never into a space with
//!   someone the work was written without, unless its person says so.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use cardinal_blob::{ConvergenceSecret, ObjectStore};
use cardinal_space::entry::{Succession, OWNER};
use cardinal_space::relationship::{self, Reach};
use cardinal_space::succession::{self as plan, Plan, Verdict};
use cardinal_space::{EpochKey, SpaceOpBody, State};

use super::*;

/// What a device noted of succession in one space.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Notes {
    /// Entries here that post work again, in hex, each with the entry it
    /// stands for in the space that work was first written in.
    #[serde(default)]
    pub posted: BTreeMap<String, String>,
    /// Work of this device's from another space, in hex, with that space:
    /// held back from being posted here until its person says, since
    /// someone is here it was written without.
    #[serde(default)]
    pub held_back: BTreeMap<String, String>,
    /// Work looked at and found to hold nothing to post again here.
    #[serde(default)]
    pub nothing: BTreeSet<String>,
    /// What this device made of the successor that stands, where it does
    /// not follow it: shown to the person.
    #[serde(default)]
    pub verdict: Option<String>,
    /// Successors this person's devices made of this space that did not
    /// stand, in hex: shown to them, who do again what each was for.
    #[serde(default)]
    pub did_not_stand: BTreeSet<String>,
    /// Work being posted again here, by the entry it stands for (hex),
    /// with the hash of the ops written for it: noted before the entry is
    /// written, so that one written just before a crash is found and not
    /// posted twice.
    #[serde(default)]
    pub pending: BTreeMap<String, String>,
    /// Work of this device's not posted here because its person's role
    /// here no longer allows it: shown to them.
    #[serde(default)]
    pub not_posted: usize,
    /// A successor opened on an initial state fetched from someone, which
    /// this device had nothing to check against: checked as soon as the
    /// space it succeeds is held here.
    #[serde(default)]
    pub unchecked: bool,
    /// Entries here that are nobody's work to post again: the owner's
    /// first entry in a successor, which sets again what the old space
    /// resolved, and concerned the succession alone.
    #[serde(default)]
    pub not_work: BTreeSet<String>,
    /// The person was shown how the group moved to this successor, and
    /// cleared the note.
    #[serde(default)]
    pub moved_seen: bool,
    /// When this device first held this successor, by its own clock: what
    /// the note of how the group moved is aged from.
    #[serde(default)]
    pub first_seen_ms: Option<u64>,
    /// Pairs of other members this device passed a group's messages
    /// between, as "<identity> <identity>" in hex, the smaller first, with
    /// when it last did, by its own clock (D89). Kept here alone, for
    /// [`super::RELAYED_FOR_MS`], and never sent anywhere.
    #[serde(default)]
    pub relayed: BTreeMap<String, u64>,
    /// The last call in this group that ended on this device, as `call`
    /// gives `ended`, with when (D92): kept here alone, across restarts,
    /// and never sent anywhere. Nothing in a space records a call.
    #[serde(default)]
    pub last_call: Option<LastCall>,
}

/// A call that ended on this device, for a group's `last_call`.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LastCall {
    pub id: String,
    pub who: String,
    pub name: String,
    pub how: String,
    /// When it ended here, in milliseconds since 1970, by this device's
    /// clock.
    pub at: u64,
}

/// What [`Core::succeed`] wrote, to send.
#[derive(Debug)]
pub struct Succeeded {
    /// The successor.
    pub new: SpaceId,
    /// The `succeed` and the successor's genesis, for the old space's set.
    pub old_entries: Vec<Vec<u8>>,
    /// The successor's genesis.
    pub new_entries: Vec<Vec<u8>>,
    /// What was written in the account, and its id.
    pub account: Option<(SpaceId, Vec<Vec<u8>>)>,
    /// The members the successor does not name.
    pub left_out: Vec<[u8; 32]>,
}

/// Entries written in one space, to send.
type Written = (SpaceId, Vec<Vec<u8>>);

/// What identifies the ops of a posting again: the hash of their records.
pub(crate) fn ops_hash(ops: &[SpaceOp]) -> String {
    let mut h = blake3::Hasher::new();
    for op in ops {
        h.update(&op.record().encode());
    }
    hex::encode(h.finalize().as_bytes())
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    hex::decode(s).ok()?.try_into().ok()
}

/// The reference of a blob of `state`'s canonical form, encrypted under
/// `epoch`: what a successor's genesis names as its initial state. Its
/// chunks are kept in `store`.
fn initial_ref<S: ObjectStore>(
    store: &S,
    epoch: &EpochKey,
    state: &State,
) -> anyhow::Result<(Record, Vec<u8>)> {
    let bytes = state.canonical().encode();
    let secret = ConvergenceSecret::from_epoch_key(epoch.bytes());
    let blob = cardinal_blob::encode_bytes(&bytes, &secret, store)?;
    Ok((blob.to_record(), bytes))
}

/// [`initial_ref`], for tests that write a successor of their own.
#[cfg(test)]
pub(crate) fn initial_ref_for_test<S: ObjectStore>(
    store: &S,
    epoch: &EpochKey,
    state: &State,
) -> (Record, Vec<u8>) {
    initial_ref(store, epoch, state).expect("encoded")
}

impl Holder {
    /// Writes one entry with `ops` and no new epoch: for the `succeed`,
    /// which ends the space. Returns the entry and its sealed bytes.
    fn write_plain(
        &mut self,
        identity: &Identity,
        keys: &Keys,
        ops: Vec<SpaceOp>,
    ) -> anyhow::Result<(EntryId, Vec<u8>)> {
        if identity.state().power(&keys.key()).is_none() {
            anyhow::bail!("this device was removed");
        }
        let space = self
            .space
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("space not open yet"))?;
        let (id, sealed) =
            space.write_entry(&identity.log, &keys.device.signing, ops, Some(now_ms()))?;
        let bytes = sealed.encode();
        self.persist(&[(sealed.sealed_id(), bytes.clone())])?;
        self.version += 1;
        Ok((id, bytes))
    }

    /// Keeps a successor's sealed genesis in this space's set, as the
    /// trail does.
    fn keep_in_trail(&mut self, sealed: &SealedEntry) -> anyhow::Result<()> {
        let bytes = sealed.encode();
        let sid = sealed.sealed_id();
        if !self.set.contains_id(&sid) {
            self.persist(&[(sid, bytes)])?;
        }
        self.keep_foreign(sealed.clone());
        Ok(())
    }
}

impl Core {
    /// The identity log of `who` held here: this person's own, or another's.
    fn log_of(&self, who: &[u8; 32]) -> Option<&IdentityLog> {
        let own = self.identity.as_ref().filter(|i| i.id() == *who);
        own.map(|i| &i.log)
            .or_else(|| self.others.get(who).map(|o| &o.log))
    }

    /// The space that stands in the place of `space` here: itself, or the
    /// successor this device followed from it, and so on; and for a
    /// successor that no longer stands, the one that does, or the old
    /// space it came from if none does.
    pub fn current(&self, space: &SpaceId) -> SpaceId {
        let mut id = *space;
        for _ in 0..64 {
            let Some(sp) = self.spaces.get(&id).and_then(|h| h.space.as_ref()) else {
                break;
            };
            // a successor this device followed that no longer stands
            if let Some(o) = sp.succeeds() {
                let old = self.spaces.get(&o).and_then(|h| h.space.as_ref());
                if old.is_some_and(|old| old.successor() != Some(id)) {
                    id = o;
                    continue;
                }
            }
            match sp.successor() {
                Some(s) if self.spaces.get(&s).is_some_and(|h| h.space.is_some()) => id = s,
                _ => break,
            }
        }
        id
    }

    /// `space`, then the space it succeeds, and so on, the nearest first:
    /// by what each says it succeeds, where it is open here, and else by
    /// field 4 of the account's node for it.
    pub fn chain(&self, space: &SpaceId) -> Vec<SpaceId> {
        let acc = self.account().and_then(|a| a.space.as_ref());
        let recorded = acc.map(|a| account::spaces(a.state())).unwrap_or_default();
        let mut out = vec![*space];
        while out.len() < 64 {
            let at = *out.last().expect("one");
            let held = self.spaces.get(&at).and_then(|h| h.space.as_ref());
            let next = held.and_then(|s| s.succeeds()).or_else(|| {
                recorded
                    .iter()
                    .filter(|r| r.space == at)
                    .find_map(|r| r.succeeded)
            });
            match next {
                Some(n) if !out.contains(&n) => out.push(n),
                _ => break,
            }
        }
        out
    }

    /// Whether another space stands in the place of `space` here: it was
    /// succeeded and this device followed, or it is a successor that no
    /// longer stands.
    pub fn is_superseded(&self, space: &SpaceId) -> bool {
        self.current(space) != *space
    }

    /// What the person is to be told of how `space` ended, where nothing
    /// here stands in its place: left out of what did, or what was put in
    /// its place and not followed, and why. Also each succession of theirs
    /// that did not stand.
    pub fn succession_news(&self, space: &SpaceId) -> (Option<String>, Vec<SpaceId>) {
        let Some(h) = self.spaces.get(space) else {
            return (None, Vec::new());
        };
        let lost = h.notes.did_not_stand.iter().filter_map(|s| hex32(s));
        let lost: Vec<SpaceId> = lost.collect();
        let ended = h.space.as_ref().is_some_and(|s| s.ended()) && !self.is_superseded(space);
        let verdict = h.notes.verdict.clone().filter(|_| ended);
        let verdict = verdict.or_else(|| {
            ended.then(|| "it has ended; what is in its place has not come here yet".to_owned())
        });
        (verdict, lost)
    }

    /// The spaces whose successor stands and whose genesis this device has
    /// not got: a notice brings the `succeed` and not the genesis, which is
    /// too long for one, and the trail gives it with the old space's set.
    pub fn trail_wanted(&self) -> Vec<SpaceId> {
        let mut out = Vec::new();
        for (id, h) in &self.spaces {
            let Some(s) = h.space.as_ref().and_then(|sp| sp.successor()) else {
                continue;
            };
            let followed = self.spaces.get(&s).is_some_and(|x| x.space.is_some());
            // a verdict is what this device made of a genesis it has, or
            // one it could not open
            if !followed && h.notes.verdict.is_none() {
                out.push(*id);
            }
        }
        out
    }

    /// The successors held here that wait for their initial state, with
    /// its blob reference, where the space each succeeds is not held: a
    /// member added to a successor, or a device of theirs, starts from
    /// what its creator put there (`spaces.md#what-comes-across`).
    pub fn initial_wanted(&self) -> Vec<(SpaceId, Record)> {
        let mut out = Vec::new();
        for (id, h) in &self.spaces {
            let Some((_, old, r)) = h.wants_initial.as_ref().filter(|_| h.space.is_none()) else {
                continue;
            };
            let held = old
                .and_then(|o| self.spaces.get(&o))
                .is_some_and(|o| o.space.is_some());
            if !held {
                out.push((*id, r.clone()));
            }
        }
        out
    }

    /// Takes the initial state of a successor held here, fetched as the
    /// blob its genesis names: it must read as a canonical state, and the
    /// successor opens on it.
    pub fn take_initial(&mut self, space: &SpaceId, canonical: &[u8]) -> anyhow::Result<()> {
        let logs = self.logs.clone();
        let ident = self
            .identity
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no identity"))?;
        let keys = ident.key_refs();
        let h = self
            .spaces
            .get(space)
            .ok_or_else(|| anyhow::anyhow!("not held"))?;
        let r = Record::decode(canonical)?;
        let Some((profile, old, _)) = h.wants_initial.clone() else {
            anyhow::bail!("it waits for no initial state");
        };
        // The space it succeeds came here meanwhile: it is checked against
        // that, by following, and not taken on anyone's word.
        let old_held = old
            .and_then(|o| self.spaces.get(&o))
            .is_some_and(|o| o.space.is_some());
        anyhow::ensure!(!old_held, "the space it succeeds is held here now");
        let h = self.spaces.get_mut(space).expect("held");
        State::from_canonical(profile, &r)?;
        std::fs::create_dir_all(Holder::dir(&self.paths, space))?;
        crate::paths::write_private(&h.initial_at, canonical, 0o600)?;
        h.notes.unchecked = true;
        h.save_notes();
        h.rebuild(Vec::new(), &keys, &logs);
        self.settle(space);
        Ok(())
    }

    /// The successors that stand here and have not been reconciled with a
    /// peer since this device started, or followed them: nothing is posted
    /// again into them until they are.
    pub fn unsynced_successors(&self) -> Vec<SpaceId> {
        let mut out = Vec::new();
        for (id, h) in &self.spaces {
            let Some(sp) = h.space.as_ref() else { continue };
            if sp.succeeds().is_some() && !self.synced.contains(id) && !self.is_superseded(id) {
                out.push(*id);
            }
        }
        out
    }

    /// `space` was reconciled with a peer that holds it.
    pub fn mark_synced(&mut self, space: &SpaceId) {
        self.synced.insert(*space);
    }

    /// What the successor `new` changed of who is in the space it
    /// succeeds, where that space is held here.
    pub fn changes_of(&self, new: &SpaceId) -> Option<plan::Changes> {
        let sp = self.spaces.get(new)?.space.as_ref()?;
        let old = self.spaces.get(&sp.succeeds()?)?.space.as_ref()?;
        Some(plan::changes(old, sp))
    }

    /// This device passed news of a group from `a`'s devices to `b`'s,
    /// both members of it and neither this person (D89). Noted at most once
    /// an hour for a pair, so that a busy group does not write the notes
    /// with every message; what is older than [`RELAYED_FOR_MS`] goes.
    pub fn note_relayed(&mut self, space: &SpaceId, a: &[u8; 32], b: &[u8; 32]) {
        let me = self.me();
        let Some(h) = self.spaces.get_mut(space) else {
            return;
        };
        let Some(sp) = h.space.as_ref() else {
            return;
        };
        let member = |w: &[u8; 32]| sp.role_of(w).is_some() && !sp.has_left(w);
        let group = sp.profile() == cardinal_space::group::GROUP;
        if !group || a == b || me == Some(*a) || me == Some(*b) || !member(a) || !member(b) {
            return;
        }
        let (x, y) = if a < b { (a, b) } else { (b, a) };
        let key = format!("{} {}", hex::encode(x), hex::encode(y));
        let now = now_ms();
        if h.notes
            .relayed
            .get(&key)
            .is_some_and(|t| now.saturating_sub(*t) < RELAY_NOTED_EVERY_MS)
        {
            return;
        }
        h.notes.relayed.insert(key, now);
        h.notes
            .relayed
            .retain(|_, t| now.saturating_sub(*t) < RELAYED_FOR_MS);
        h.save_notes();
    }

    /// The pairs of members this device passed a group's messages between
    /// within [`RELAYED_FOR_MS`] (D89).
    pub fn relayed_for(&self, space: &SpaceId) -> Vec<([u8; 32], [u8; 32])> {
        let Some(h) = self.spaces.get(space) else {
            return Vec::new();
        };
        let now = now_ms();
        let id = |s: &str| -> Option<[u8; 32]> { hex::decode(s).ok()?.try_into().ok() };
        h.notes
            .relayed
            .iter()
            .filter(|(_, t)| now.saturating_sub(**t) < RELAYED_FOR_MS)
            .filter_map(|(k, _)| {
                let (a, b) = k.split_once(' ')?;
                Some((id(a)?, id(b)?))
            })
            .collect()
    }

    /// Notes the last call in group `space` that ended on this device, for
    /// the group that stands in its place here where it was succeeded
    /// meanwhile (D92): the note follows the group. What is noted is
    /// given back to be written, which the caller does outside the lock.
    #[must_use]
    pub fn note_last_call(&mut self, space: &SpaceId, call: LastCall) -> Option<super::NotesSave> {
        let now = self.current(space);
        let h = self.spaces.get_mut(&now)?;
        h.notes.last_call = Some(call);
        Some(h.notes_to_save())
    }

    /// The last call in group `space` that ended on this device, as `call`
    /// gives `ended`, with `at`: the newest noted for it or for any group
    /// it succeeds, since the note follows a group to its successor. Its
    /// `group` is `space`, whichever it was noted for.
    #[cfg(any(test, debug_assertions, feature = "by-name"))]
    pub fn last_call(&self, space: &SpaceId) -> Option<serde_json::Value> {
        let noted = self.chain(space).into_iter();
        let noted = noted.filter_map(|s| self.spaces.get(&s)?.notes.last_call.as_ref());
        let c = noted.max_by_key(|c| c.at)?;
        Some(serde_json::json!({
            "id": c.id,
            "who": c.who,
            "name": c.name,
            "group": hex::encode(space),
            "how": c.how,
            "at": c.at,
        }))
    }

    /// [`Core::last_call`], typed. Its ids were written here in hex, from
    /// bytes; one that is not is left out, and logged.
    pub fn last_call_typed(&self, space: &SpaceId) -> Option<crate::api::CallEnded> {
        let noted = self.chain(space).into_iter();
        let noted = noted.filter_map(|s| self.spaces.get(&s)?.notes.last_call.as_ref());
        let c = noted.max_by_key(|c| c.at)?;
        let id = hex::decode(&c.id).ok().and_then(|b| b.try_into().ok());
        let who = hex::decode(&c.who).ok().and_then(|b| b.try_into().ok());
        let (Some(id), Some(who)) = (id, who) else {
            tracing::error!(
                "the last call noted for {} has an id not in hex",
                hex::encode(space)
            );
            return None;
        };
        Some(crate::api::CallEnded {
            group: Some(*space),
            how: c.how.clone().into(),
            id,
            name: c.name.clone(),
            who,
            at: Some(c.at),
        })
    }

    /// The person cleared the note of how the group moved to `space`.
    pub fn moved_seen(&mut self, space: &SpaceId) {
        if let Some(h) = self.spaces.get_mut(space) {
            if !h.notes.moved_seen {
                h.notes.moved_seen = true;
                h.save_notes();
            }
        }
    }

    /// How much work of this device's is held back from `space`, until its
    /// person says to post it there.
    pub fn held_back(&self, space: &SpaceId) -> usize {
        self.spaces
            .get(space)
            .map_or(0, |h| h.notes.held_back.len())
    }

    /// The owner succeeds `space` with a successor naming `named`, each
    /// with a role, this person as owner among them
    /// (`spaces.md#succession`). The cut is the valid heads held here. The
    /// chunks of the initial state go in `store`. Refused where the space
    /// has ended, where this person is not its owner, and where an
    /// identity log the cut needs, or a member's encryption key, is not
    /// here.
    pub fn succeed<S: ObjectStore>(
        &mut self,
        store: &S,
        space: &SpaceId,
        named: &[([u8; 32], u64)],
    ) -> anyhow::Result<Succeeded> {
        let ident = self
            .identity
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("this device has no identity yet"))?;
        let me = ident.id();
        let sp = self.spaces.get(space).and_then(|h| h.space.as_ref());
        let sp = sp.ok_or_else(|| anyhow::anyhow!("that space is not open here"))?;
        anyhow::ensure!(sp.owner() == Some(me), "only its owner can do that");
        anyhow::ensure!(!sp.ended(), "it has ended already");
        let mut named: Vec<([u8; 32], u64)> =
            named.iter().filter(|(w, _)| *w != me).copied().collect();
        named.insert(0, (me, OWNER));
        let ids: Vec<[u8; 32]> = named.iter().map(|(w, _)| *w).collect();
        let cut = sp.heads();
        anyhow::ensure!(!cut.is_empty(), "nothing valid here to succeed");
        // Every author's log, or the state at the cut would leave out what
        // they wrote.
        let missing = plan::authors_at(sp, &cut)
            .into_iter()
            .find(|w| self.log_of(w).is_none());
        anyhow::ensure!(
            missing.is_none(),
            "the identity log of someone who wrote in it is not here"
        );
        let judged = plan::judged_with(sp, &cut, |w| self.log_of(w));
        let states = plan::pinned_states(&judged, |w| self.log_of(w))
            .ok_or_else(|| anyhow::anyhow!("an identity log it needs is not here"))?;
        let at_cut = sp.state_at(&cut, states, &ids)?;
        let epoch = EpochKey::generate();
        let (initial, canonical) = initial_ref(store, &epoch, &at_cut)?;
        let mut old_keys = Vec::new();
        if sp.policy().history_shared {
            if let Some(e) = sp.current_epoch() {
                if let Some(k) = sp.keyring().get(&e) {
                    old_keys.push((e, *k.bytes()));
                }
            }
        }
        let from = Succession {
            succeeds: Some(*space),
            initial_state: Some(initial),
            cut,
            old_keys,
            judged_with: judged,
            fresh_start: false,
        };
        let mut keys: Vec<HybridPublicKey> = Vec::new();
        for who in &ids {
            if *who == me {
                let mine = ident.enc.first();
                let mine = mine.ok_or_else(|| anyhow::anyhow!("no encryption key"))?;
                keys.push(mine.public_key().clone());
            } else {
                keys.push(self.encryption_key_of(who)?);
            }
        }
        let refs: Vec<&HybridPublicKey> = keys.iter().collect();
        let mut ops: Vec<SpaceOp> = named
            .iter()
            .map(|(w, r)| SpaceOp::add_member(*w, *r))
            .collect();
        let profile = sp.profile();
        let initial = State::from_canonical(profile, &Record::decode(&canonical)?)?;
        // What only an admin's say sets counts for nothing as carried: the
        // owner sets it again in the genesis itself, so there is no gap
        // (`profiles.md#group`, "These values do not carry").
        if profile == cardinal_space::group::GROUP {
            ops.extend(cardinal_space::group::reassert_ops(sp, &initial));
        }
        let (new, genesis) = Space::create_successor(
            profile,
            sp.policy().clone(),
            &from,
            epoch,
            initial,
            &ident.log,
            &self.keys.device.signing,
            &refs,
            ops,
            Some(now_ms()),
        )?;
        let new_id = new.id();
        let left_out: Vec<[u8; 32]> = sp
            .validity()
            .identities()
            .into_iter()
            .filter(|w| !ids.contains(w))
            .collect();
        let local_name = cardinal_space::group::name(sp);
        // The successor first, so that nothing names what is not here.
        let dir = Holder::dir(&self.paths, &new_id);
        std::fs::create_dir_all(&dir)?;
        crate::paths::write_private(&dir.join("initial-state.bin"), &canonical, 0o600)?;
        let genesis_bytes = genesis.encode();
        self.ingest_space(new_id, std::slice::from_ref(&genesis_bytes))?;
        let new_entries = vec![genesis_bytes.clone()];
        let ident = self.identity.as_ref().expect("checked above");
        let h = self.spaces.get_mut(space).expect("held");
        let succeed = SpaceOp::succeed_with(new_id, &left_out, None);
        let (_, written) = h.write_plain(ident, &self.keys, vec![succeed])?;
        h.keep_in_trail(&genesis)?;
        self.settle(space);
        let account = self.follow_in_account(space, &new_id, &local_name)?;
        Ok(Succeeded {
            new: new_id,
            old_entries: vec![written, genesis_bytes],
            new_entries,
            account,
            left_out,
        })
    }

    /// The space node for a successor this person holds now, in the
    /// account, where they had joined the space it succeeds: nothing is
    /// joined by following that was not joined before.
    fn follow_in_account(
        &mut self,
        old: &SpaceId,
        new: &SpaceId,
        local_name: &str,
    ) -> anyhow::Result<Option<(SpaceId, Vec<Vec<u8>>)>> {
        let Some(acc) = self.account_id() else {
            return Ok(None);
        };
        if acc == *old || !self.is_joined(old) {
            return Ok(None);
        }
        let ops = {
            let st = self.account().and_then(|a| a.space.as_ref());
            let st = st.ok_or_else(|| anyhow::anyhow!("the account space is not open"))?;
            account::successor_ops(st.state(), old, new, local_name)
        };
        if ops.is_empty() {
            return Ok(None);
        }
        let written = self.write(&acc, ops)?;
        Ok(Some((acc, written.into_iter().map(|(_, b)| b).collect())))
    }

    /// Follows every successor that stands, as far as this device can
    /// check each, and posts again what is to be posted again. Returns
    /// what was written, by space, to send.
    pub fn follow<S: ObjectStore>(&mut self, store: &S) -> Vec<(SpaceId, Vec<Vec<u8>>)> {
        let mut out = Vec::new();
        if self.identity.is_none() {
            return out;
        }
        for _ in 0..16 {
            let mut moved = false;
            let held: Vec<SpaceId> = self.spaces.keys().copied().collect();
            for o in held {
                match self.try_follow(store, &o) {
                    Ok(Some(written)) => {
                        moved = true;
                        out.extend(written);
                    }
                    Ok(None) => {}
                    Err(e) => tracing::debug!("space {}: following: {e:#}", short(&o)),
                }
            }
            if !moved {
                break;
            }
        }
        self.check_unchecked(store);
        self.note_first_seen();
        out.extend(self.account_for_followed());
        out.extend(self.say_no_again());
        self.note_did_not_stand();
        out.extend(self.post_again_all(false));
        out
    }

    /// The space node of every successor that stands here in place of a
    /// space this person had joined, written again where it is missing:
    /// a device that stopped between following and writing it would
    /// otherwise not show the group.
    fn account_for_followed(&mut self) -> Vec<Written> {
        let mut pairs: Vec<(SpaceId, SpaceId, String)> = Vec::new();
        for (id, h) in &self.spaces {
            let Some(sp) = h.space.as_ref() else { continue };
            let Some(o) = sp.succeeds() else { continue };
            if self.current(&o) != *id || self.is_joined(id) {
                continue;
            }
            let old = self.spaces.get(&o).and_then(|h| h.space.as_ref());
            if let Some(old) = old {
                pairs.push((o, *id, cardinal_space::group::name(old)));
            }
        }
        let mut out = Vec::new();
        for (o, s, name) in pairs {
            match self.follow_in_account(&o, &s, &name) {
                Ok(Some(w)) => out.push(w),
                Ok(None) => {}
                Err(e) => tracing::debug!("space {}: the account: {e:#}", short(&s)),
            }
        }
        out
    }

    /// The person's no to naming their hosts, said in a space after its
    /// cut, said again in the successor that stands in its place: a `set`
    /// of a reach node is not posted again
    /// (`spaces.md#what-the-successor-does-not-carry`), so a device that
    /// said no where it had not yet followed would leave the successor
    /// naming what the person took out (D75). Where this person's list in
    /// the old space was set after the cut, and the account still records
    /// the no, for the successor or a space it succeeds: an emptied list,
    /// with "no hosts here", empties the successor's; a host taken out,
    /// with "not this host here", is taken out of it. Nothing is written
    /// where the successor's list says so already, and a yes clears the
    /// record, so nothing is said again over it.
    fn say_no_again(&mut self) -> Vec<Written> {
        let Some(me) = self.me() else {
            return Vec::new();
        };
        let mut pairs: Vec<(SpaceId, SpaceId)> = Vec::new();
        for (id, h) in &self.spaces {
            let Some(sp) = h.space.as_ref() else { continue };
            let Some(o) = sp.succeeds() else { continue };
            let old = self.spaces.get(&o).and_then(|h| h.space.as_ref());
            if old.is_some() && self.current(&o) == *id && self.is_joined(id) {
                pairs.push((o, *id));
            }
        }
        let mut out = Vec::new();
        for (o, s) in pairs {
            let Some(carried) = self.carried_into(&s) else {
                continue;
            };
            let old = self.spaces[&o].space.as_ref().expect("open");
            let after = |key: u64| {
                let values = old.state().reach_values(&me, key).iter();
                values
                    .filter(|v| !carried.contains(&v.entry))
                    .collect::<Vec<_>>()
            };
            if after(1).is_empty() {
                continue;
            }
            let was = relationship::reach_of(old, &me);
            // under the name this implementation wrote before, or the
            // spec's, which is written now and so comes last
            let rests: Option<EntryId> = after(relationship::old_no_record_key())
                .into_iter()
                .chain(after(relationship::no_record_key()))
                .filter_map(|v| {
                    v.value
                        .as_ref()?
                        .as_record()?
                        .get(1)?
                        .as_bytes()?
                        .try_into()
                        .ok()
                })
                .next_back();
            let no = self.hosts_no(&s);
            let now = self.reach_of(&s, &me);
            let kept: Vec<Reach> = match no.no_hosts && was.is_empty() {
                true => Vec::new(),
                false => {
                    let out =
                        |r: &&Reach| no.not_this(&r.host) && !was.iter().any(|w| w.host == r.host);
                    now.iter().filter(|r| !out(r)).cloned().collect()
                }
            };
            if kept.len() == now.len() {
                continue;
            }
            let mut ops = vec![relationship::set_reach(&me, &kept)];
            ops.extend(rests.map(|e| relationship::set_rests_on(&me, &e)));
            match self.write(&s, ops) {
                Ok(w) => out.push((s, w.into_iter().map(|(_, b)| b).collect())),
                Err(e) => tracing::debug!("space {}: the no again: {e:#}", short(&s)),
            }
        }
        out
    }

    /// Checks each successor opened unchecked, on an initial state fetched
    /// from someone, once the space it succeeds is held here: one that
    /// fails is left, and the person told, as for one that fails when it
    /// is followed.
    fn check_unchecked<S: ObjectStore>(&mut self, store: &S) {
        let todo: Vec<(SpaceId, SpaceId)> = self
            .spaces
            .iter()
            .filter(|(_, h)| h.notes.unchecked)
            .filter_map(|(id, h)| Some((*id, h.space.as_ref()?.succeeds()?)))
            .filter(|(_, o)| self.spaces.get(o).is_some_and(|h| h.space.is_some()))
            .collect();
        for (s, o) in todo {
            let me = self.me().expect("an identity");
            let old = self.spaces[&o].space.as_ref().expect("open");
            let new = self.spaces[&s].space.as_ref().expect("open");
            let ok = match plan::verdict(old, new, &me, false) {
                // one this member is not named in is not theirs to check
                Verdict::Follow | Verdict::LeftOut => self.check_cut(store, old, new),
                _ => Err("it does not succeed the space it names".to_owned()),
            };
            match ok {
                Ok(_) => {
                    let h = self.spaces.get_mut(&s).expect("held");
                    h.notes.unchecked = false;
                    h.save_notes();
                }
                Err(why) => {
                    tracing::warn!("space {}: left: {why}", short(&s));
                    let h = self.spaces.get_mut(&s).expect("held");
                    let _ = std::fs::remove_file(&h.initial_at);
                    h.space = None;
                    h.notes.unchecked = false;
                    h.save_notes();
                    let v = format!(
                        "it has ended, and what was put in its place does not match it: {why}"
                    );
                    self.note_verdict(&o, Some(v));
                }
            }
        }
    }

    /// The third condition of following (`spaces.md#following`): the
    /// initial state of `new` is the state of `old` at its cut, as this
    /// device works it out with the logs it pins. Gives the canonical state
    /// and the entries it carried, or why not.
    fn check_cut<S: ObjectStore>(
        &self,
        store: &S,
        old: &Space,
        new: &Space,
    ) -> Result<(Vec<u8>, HashSet<EntryId>), String> {
        let from = new.succession().ok_or("it succeeds nothing")?;
        let states = plan::pinned_states(&from.judged_with, |w| self.log_of(w))
            .ok_or("it cannot be checked yet: an identity log it was judged with is not here")?;
        let named: Vec<[u8; 32]> = plan::genesis_members(new)
            .into_iter()
            .map(|(w, _)| w)
            .collect();
        let at_cut = old
            .state_at(&from.cut, states, &named)
            .map_err(|_| "it cannot be checked yet: the entries it was cut at are not all here")?;
        let carried: HashSet<EntryId> = at_cut.accepted().copied().collect();
        let Some(claimed) = from.initial_state.as_ref() else {
            // no initial state is an empty one
            let empty = at_cut.is_empty() && at_cut.reach_nodes().next().is_none();
            return match empty {
                true => Ok((at_cut.canonical().encode(), carried)),
                false => Err("its initial state is not the state at its cut".to_owned()),
            };
        };
        // the genesis's epoch: the current one, or, where the genesis is set
        // aside until a keep of it comes (after a recovery), its own
        let first = new
            .current_epoch()
            .or_else(|| new.dag().get(&new.id()).map(|g| g.epoch()));
        let epoch = first
            .and_then(|e| new.keyring().get(&e).cloned())
            .ok_or("no key for its first epoch")?;
        let (reference, canonical) =
            initial_ref(store, &epoch, &at_cut).map_err(|e| format!("{e:#}"))?;
        if claimed.encode() != reference.encode() {
            return Err("its initial state is not the state at its cut".to_owned());
        }
        Ok((canonical, carried))
    }

    /// Notes when this device first held each successor it holds.
    fn note_first_seen(&mut self) {
        let now = now_ms();
        for h in self.spaces.values_mut() {
            let succ = h.space.as_ref().is_some_and(|s| s.succeeds().is_some());
            if succ && h.notes.first_seen_ms.is_none() {
                h.notes.first_seen_ms = Some(now);
                h.save_notes();
            }
        }
    }

    /// Notes, in the old space, each succession this person made of it
    /// that does not stand.
    fn note_did_not_stand(&mut self) {
        let Some(me) = self.me() else { return };
        let mut lost: Vec<(SpaceId, SpaceId)> = Vec::new();
        for (id, h) in &self.spaces {
            let Some(sp) = h.space.as_ref() else { continue };
            let Some(o) = sp.succeeds() else { continue };
            let old = self.spaces.get(&o).and_then(|h| h.space.as_ref());
            if sp.creator() == me && old.is_some_and(|old| old.successor() != Some(*id)) {
                lost.push((o, *id));
            }
        }
        for (o, s) in lost {
            let h = self.spaces.get_mut(&o).expect("held");
            if h.notes.did_not_stand.insert(hex::encode(s)) {
                h.save_notes();
            }
        }
    }

    fn note_verdict(&mut self, space: &SpaceId, verdict: Option<String>) {
        let Some(h) = self.spaces.get_mut(space) else {
            return;
        };
        if h.notes.verdict != verdict {
            h.notes.verdict = verdict;
            h.save_notes();
        }
    }

    /// Follows the successor that stands of `old`, if this device does not
    /// hold it yet and it can be checked. Returns what was written.
    fn try_follow<S: ObjectStore>(
        &mut self,
        store: &S,
        old: &SpaceId,
    ) -> anyhow::Result<Option<Vec<Written>>> {
        let ident = self.identity.as_ref().expect("an identity");
        let me = ident.id();
        let keys = ident.key_refs();
        let Some(h) = self.spaces.get(old) else {
            return Ok(None);
        };
        let Some(sp) = h.space.as_ref() else {
            return Ok(None);
        };
        let Some(s) = sp.successor() else {
            return Ok(None);
        };
        // The person's own account and files are not followed: nothing
        // here succeeds them, and a device keeps which space is its
        // account (D67), and the copies it holds for others beside it.
        if Some(*old) == self.account_id() || Some(*old) == self.files_id() {
            return Ok(None);
        }
        // Nor is an offer the person said no to: following it would offer
        // it again.
        if self.is_declined(old) {
            return Ok(None);
        }
        if self.spaces.get(&s).is_some_and(|x| x.space.is_some()) {
            return Ok(None);
        }
        // Judged already, on just what is here now: the verdict noted
        // stands.
        let key = self.follow_key(old, &s);
        if h.follow_checked == Some(key) {
            return Ok(None);
        }
        // Its genesis: in the trail, or held for itself already. Each is
        // opened once, and only the successor that stands is looked for.
        let held = self.spaces.get(&s).map(|x| x.pending()).unwrap_or(&[]);
        let mut opened: Vec<([u8; 32], Option<SpaceId>)> = Vec::new();
        let mut found = None;
        for f in h.foreign.iter().chain(held) {
            let sid = f.sealed_id();
            let id = match h.foreign_opened.get(&sid) {
                Some(id) => *id,
                None => {
                    let id = Space::open_genesis(f, &keys, None).ok().map(|o| o.id());
                    opened.push((sid, id));
                    id
                }
            };
            if id == Some(s) {
                found = Space::open_genesis(f, &keys, None)
                    .ok()
                    .map(|o| (f.clone(), o));
                break;
            }
        }
        let h = self.spaces.get_mut(old).expect("held");
        h.foreign_opened.extend(opened);
        let h = self.spaces.get(old).expect("held");
        let sp = h.space.as_ref().expect("open");
        let Some((sealed, mut new)) = found else {
            // A member who can open no wrap of it has been left out,
            // whatever the `succeed` says; one it names as left out is.
            let naming = sp.succeeds_naming(&s);
            let named_out = naming.iter().any(|e| {
                sp.entry(e).is_some_and(|e| {
                    e.ops().iter().any(|o| {
                        matches!(o.body(), SpaceOpBody::Succeed { left_out, .. } if left_out.contains(&me))
                    })
                })
            });
            let v = named_out.then(|| "you were left out of what took its place".to_owned());
            self.note_verdict(old, v);
            self.spaces.get_mut(old).expect("held").follow_checked = Some(key);
            return Ok(None);
        };
        new.set_identities(self.logs.iter().cloned());
        let owner = sp.owner();
        let frozen =
            owner.is_some_and(|o| self.logs.iter().any(|st| st.identity == o && st.frozen));
        let why = match plan::verdict(sp, &new, &me, frozen) {
            Verdict::Follow => None,
            Verdict::LeftOut => Some("you were left out of what took its place".to_owned()),
            Verdict::HandedOn => Some("its owner handed it on to someone else".to_owned()),
            Verdict::FrozenOwner => Some(
                "it was moved by an owner whose identity is frozen, and is not followed".to_owned(),
            ),
            Verdict::MadePublic => Some("its owner made it public".to_owned()),
            Verdict::NotWhatItSays(w) => Some(format!(
                "it has ended, and what was put in its place does not match it: {w}"
            )),
            Verdict::NoOwner => Some("its members proposed to start it afresh".to_owned()),
        };
        if why.is_some() {
            self.note_verdict(old, why);
            self.spaces.get_mut(old).expect("held").follow_checked = Some(key);
            return Ok(None);
        }
        // The third condition: its initial state is the state at the cut,
        // as this device works it out.
        let (canonical, carried) = match self.check_cut(store, sp, &new) {
            Ok(done) => done,
            Err(why) => {
                let v = match why.starts_with("it cannot be checked yet") {
                    true => why,
                    false => format!(
                        "it has ended, and what was put in its place does not match it: {why}"
                    ),
                };
                self.note_verdict(old, Some(v));
                self.spaces.get_mut(old).expect("held").follow_checked = Some(key);
                return Ok(None);
            }
        };
        let local_name = cardinal_space::group::name(sp);
        self.note_verdict(old, None);
        // Hold it, from its initial state.
        let dir = Holder::dir(&self.paths, &s);
        std::fs::create_dir_all(&dir)?;
        if new.succession().is_some_and(|f| f.initial_state.is_some()) {
            crate::paths::write_private(&dir.join("initial-state.bin"), &canonical, 0o600)?;
        }
        let bytes = sealed.encode();
        let had = self.spaces.contains_key(&s);
        self.open_space(s)?;
        let logs = self.logs.clone();
        let ident = self.identity.as_ref().expect("an identity");
        let keys = ident.key_refs();
        let h = self.spaces.get_mut(&s).expect("opened");
        if had && h.set.contains_id(&sealed.sealed_id()) {
            h.rebuild(Vec::new(), &keys, &logs);
        } else {
            h.ingest(std::slice::from_ref(&bytes), &keys, &logs)?;
        }
        h.carried = Some(carried);
        self.settle(&s);
        tracing::info!("space {}: followed its successor {}", short(old), short(&s));
        let mut out = Vec::new();
        if let Some(written) = self.follow_in_account(old, &s, &local_name)? {
            out.push(written);
        }
        Ok(Some(out))
    }

    /// What a verdict on following `s` from `old` rests on: what `old`
    /// holds, the geneses here, and every identity log held.
    fn follow_key(&self, old: &SpaceId, s: &SpaceId) -> [u8; 32] {
        let mut k = blake3::Hasher::new();
        k.update(s);
        if let Some(h) = self.spaces.get(old) {
            k.update(&(h.set_len() as u64).to_le_bytes());
        }
        if let Some(h) = self.spaces.get(s) {
            k.update(&(h.set_len() as u64).to_le_bytes());
        }
        if let Some(i) = self.identity.as_ref() {
            k.update(&(i.log.len() as u64).to_le_bytes());
        }
        for (who, o) in &self.others {
            k.update(who);
            k.update(&(o.log.len() as u64).to_le_bytes());
            k.update(&(o.log.all_heads().len() as u64).to_le_bytes());
        }
        *k.finalize().as_bytes()
    }

    /// The entries of `old` that the initial state of `new` carried.
    fn carried_into(&mut self, new: &SpaceId) -> Option<HashSet<EntryId>> {
        let h = self.spaces.get(new)?;
        if let Some(c) = &h.carried {
            return Some(c.clone());
        }
        let sp = h.space.as_ref()?;
        let from = sp.succession()?.clone();
        let old = self.spaces.get(&from.succeeds?)?.space.as_ref()?;
        let states = plan::pinned_states(&from.judged_with, |w| self.log_of(w))?;
        let named: Vec<[u8; 32]> = plan::genesis_members(sp)
            .into_iter()
            .map(|(w, _)| w)
            .collect();
        let at_cut = old.state_at(&from.cut, states, &named).ok()?;
        let carried: HashSet<EntryId> = at_cut.accepted().copied().collect();
        self.spaces.get_mut(new)?.carried = Some(carried.clone());
        Some(carried)
    }

    /// Posts again, into every space that stands here, what this device
    /// wrote that is to be posted again there
    /// (`spaces.md#what-the-successor-does-not-carry`). With `asked`, the
    /// work held back from a space with someone it was written without is
    /// posted too: its person said so.
    pub fn post_again_all(&mut self, asked: bool) -> Vec<(SpaceId, Vec<Vec<u8>>)> {
        let mut out = Vec::new();
        let held: Vec<SpaceId> = self.spaces.keys().copied().collect();
        for into in held {
            // nothing is written where another stands, or nothing does
            let ended = self.spaces[&into].space.as_ref().is_none_or(|s| s.ended());
            if ended || self.is_superseded(&into) {
                continue;
            }
            match self.post_again_into(&into, asked) {
                Ok(written) if !written.is_empty() => out.push((into, written)),
                Ok(_) => {}
                Err(e) => tracing::debug!("space {}: posting again: {e:#}", short(&into)),
            }
        }
        out
    }

    /// The spaces whose work posts again into `into`: the space it
    /// succeeds, unless it is a fresh start, and every successor of that
    /// space, or of `into` itself, that no longer stands.
    fn sources_of(&self, into: &SpaceId) -> Vec<SpaceId> {
        let Some(sp) = self.spaces.get(into).and_then(|h| h.space.as_ref()) else {
            return Vec::new();
        };
        let fresh = sp.succession().is_some_and(|s| s.fresh_start);
        let old = sp.succeeds();
        let mut out = Vec::new();
        if let Some(o) = old.filter(|_| !fresh) {
            if self.spaces.get(&o).is_some_and(|h| h.space.is_some()) {
                out.push(o);
            }
        }
        for (id, h) in &self.spaces {
            let Some(x) = h.space.as_ref() else { continue };
            let sibling = old.is_some() && x.succeeds() == old;
            let returned = x.succeeds() == Some(*into);
            if *id != *into && (sibling || returned) && self.current(id) == *into {
                out.push(*id);
            }
        }
        out
    }

    fn post_again_into(&mut self, into: &SpaceId, asked: bool) -> anyhow::Result<Vec<Vec<u8>>> {
        let mut written = Vec::new();
        let sources = self.sources_of(into);
        if sources.is_empty() {
            return Ok(written);
        }
        // What `into` carried, by the entry it was first written as: never
        // posted again, from wherever it comes. A successor whose cut
        // cannot be worked out here posts nothing: what it carried would
        // be posted twice.
        let is_successor = self.spaces[into]
            .space
            .as_ref()
            .is_some_and(|s| s.succeeds().is_some());
        let carried = match self.carried_into(into) {
            Some(c) => c,
            None if is_successor => return Ok(written),
            None => HashSet::new(),
        };
        for from in sources {
            written.extend(self.post_again_from(&from, into, &carried, asked)?);
        }
        Ok(written)
    }

    /// How `from` and `into` stand for posting again: when this is what
    /// it was the last time nothing was left to do, nothing is.
    fn post_mark(&self, from: &SpaceId, into: &SpaceId) -> [u64; 4] {
        let f = &self.spaces[from];
        let i = &self.spaces[into];
        let n = &i.notes;
        let notes = (n.posted.len() + n.held_back.len() + n.nothing.len()) as u64;
        [
            f.set_len() as u64,
            i.set_len() as u64,
            notes,
            f.notes.posted.len() as u64,
        ]
    }

    /// Posts again into `into` what this device wrote in `from` and `into`
    /// neither holds nor carried: in log order, each entry whole; one that
    /// has to wait waits, and the rest go on.
    fn post_again_from(
        &mut self,
        from: &SpaceId,
        into: &SpaceId,
        carried: &HashSet<EntryId>,
        asked: bool,
    ) -> anyhow::Result<Vec<Vec<u8>>> {
        let me = self.me().ok_or_else(|| anyhow::anyhow!("no identity"))?;
        let here = self.keys.key();
        let mut out = Vec::new();
        let mark = self.post_mark(from, into);
        if !asked && self.spaces[into].post_marks.get(from) == Some(&mark) {
            return Ok(out);
        }
        // Who is there is known only once the space was reconciled with
        // someone who holds it, since this device followed: an addition
        // after its genesis may not have come yet, and work would go
        // where someone is that it was written without.
        if !asked && !self.synced.contains(into) {
            return Ok(out);
        }
        let (Some(fh), Some(ih)) = (self.spaces.get(from), self.spaces.get(into)) else {
            return Ok(out);
        };
        let (Some(fs), Some(is)) = (fh.space.as_ref(), ih.space.as_ref()) else {
            return Ok(out);
        };
        // Who is in `into` that the work was written without.
        let was_in: HashSet<[u8; 32]> = fs.validity().identities().into_iter().collect();
        let strangers = is
            .validity()
            .identities()
            .iter()
            .any(|w| !was_in.contains(w));
        let origin_in = |n: &Notes, x: &EntryId| -> EntryId {
            n.posted
                .get(&hex::encode(x))
                .and_then(|o| hex32(o))
                .unwrap_or(*x)
        };
        let done: HashSet<String> = ih.notes.posted.values().cloned().collect();
        let valid = &fs.validity().valid;
        let candidates: Vec<EntryId> = fs
            .dag()
            .log_order()
            .iter()
            .filter(|x| **x != fs.id() && valid.contains(*x))
            .filter(|x| {
                fs.entry(x)
                    .is_some_and(|e| e.author() == me && e.signer() == here && !e.is_genesis())
            })
            .filter(|x| fs.state().is_accepted(x) && !fh.notes.not_work.contains(&hex::encode(x)))
            // control ops alone, a `succeed` among them, are nobody's work
            .filter(|x| fs.entry(x).is_some_and(plan::has_work))
            // what `into` holds itself, as when everyone returns to the old
            // space, or carried, or had posted again already
            .filter(|x| {
                let o = origin_in(&fh.notes, x);
                !is.dag().contains(&o) && !carried.contains(&o) && !done.contains(&hex::encode(o))
            })
            .filter(|x| {
                let o = hex::encode(origin_in(&fh.notes, x));
                !ih.notes.nothing.contains(&o)
            })
            .copied()
            .collect();
        if candidates.is_empty() {
            self.spaces
                .get_mut(into)
                .expect("held")
                .post_marks
                .insert(*from, mark);
            return Ok(out);
        }
        if !plan::may_post(is, &me) {
            // the person is told: their role there no longer allows it
            let h = self.spaces.get_mut(into).expect("held");
            if h.notes.not_posted != candidates.len() {
                h.notes.not_posted = candidates.len();
                h.save_notes();
            }
            return Ok(out);
        }
        let mut waiting = false;
        for x in candidates {
            let (fh, ih) = (&self.spaces[from], &self.spaces[into]);
            let (fs, is) = (fh.space.as_ref().unwrap(), ih.space.as_ref().unwrap());
            let origin = origin_in(&fh.notes, &x);
            let origin_hex = hex::encode(origin);
            if strangers && !asked {
                let h = self.spaces.get_mut(into).expect("held");
                if h.notes
                    .held_back
                    .insert(hex::encode(x), hex::encode(from))
                    .is_none()
                {
                    h.save_notes();
                }
                continue;
            }
            // One written just before this device stopped, and not noted.
            if let Some(hash) = ih.notes.pending.get(&origin_hex) {
                let mine = is.dag().iter().find(|(_, e)| {
                    let ops = e.ops();
                    e.author() == me
                        && e.signer() == here
                        && (0..=ops.len()).any(|n| ops_hash(&ops[..n]) == *hash)
                });
                if let Some((id, _)) = mine {
                    let id = *id;
                    let h = self.spaces.get_mut(into).expect("held");
                    h.notes.posted.insert(hex::encode(id), origin_hex.clone());
                    h.notes.pending.remove(&origin_hex);
                    h.notes.held_back.remove(&hex::encode(x));
                    h.save_notes();
                    continue;
                }
            }
            let notes = &ih.notes;
            let origin_of = |e: &EntryId| notes.posted.get(&hex::encode(e)).and_then(|o| hex32(o));
            match plan::plan_repost(fs, &x, is, &origin_of) {
                Plan::Wait => waiting = true,
                Plan::Nothing => {
                    let h = self.spaces.get_mut(into).expect("held");
                    h.notes.nothing.insert(origin_hex);
                    h.save_notes();
                }
                Plan::Post(r) => {
                    let ident = self.identity.as_ref().expect("an identity");
                    let h = self.spaces.get_mut(into).expect("held");
                    h.notes.pending.insert(origin_hex.clone(), ops_hash(&r.ops));
                    h.save_notes();
                    let (id, bytes) = h.write_one(ident, &self.keys, r.ops)?;
                    h.notes.posted.insert(hex::encode(id), origin_hex.clone());
                    h.notes.pending.remove(&origin_hex);
                    h.notes.held_back.remove(&hex::encode(x));
                    h.save_notes();
                    self.settle(into);
                    out.push(bytes);
                }
            }
        }
        if !waiting && out.is_empty() {
            let mark = self.post_mark(from, into);
            self.spaces
                .get_mut(into)
                .expect("held")
                .post_marks
                .insert(*from, mark);
        }
        Ok(out)
    }
}

/// What undoing a group change kept after a recovery puts right (D84):
/// whoever it left out, each with the role they had before it, and each
/// role it changed, as `(who, before, after)`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Undo {
    /// Whoever the change left out, with the role they had.
    pub out: Vec<([u8; 32], u64)>,
    /// Each role it changed: who, the role before, the role after.
    pub roles: Vec<([u8; 32], u64, u64)>,
}

/// The members a successor of `sp`, the group as it stands now, names to
/// undo `undo`: everyone in it who has not left, with their role, and
/// back whoever the change left out who is not in it again, with the role
/// they had, and back the role before for whoever still has the one the
/// change gave. Refused where nothing is left to undo.
pub fn undo_named(sp: &Space, undo: &Undo) -> anyhow::Result<Vec<([u8; 32], u64)>> {
    let mut named: Vec<([u8; 32], u64)> = cardinal_space::group::members(sp)
        .into_iter()
        .filter(|m| !m.left)
        .map(|m| (m.identity, m.role))
        .collect();
    let mut changed = false;
    for (who, role) in &undo.out {
        if !named.iter().any(|(w, _)| w == who) {
            named.push((*who, *role));
            changed = true;
        }
    }
    for (who, before, after) in &undo.roles {
        if let Some(m) = named.iter_mut().find(|(w, r)| w == who && r == after) {
            m.1 = *before;
            changed = true;
        }
    }
    anyhow::ensure!(
        changed,
        "nothing of that change is left to undo: it is as it was"
    );
    Ok(named)
}

impl Core {
    /// The group changes another of this person's devices made, signed by
    /// one of `keys` (the keys a recovery by guardians removed), that
    /// stand because this device wrote again a `keep` of them from before
    /// the loss (D84, [`Core::keep_earlier_keeps`]): each as `(old, new)`,
    /// the group it left and the one it moved to, in the order of the old
    /// groups' ids. A thief holding two of the devices could have made one
    /// and confirmed it on the other, so the person is shown each, to undo.
    pub fn kept_after_recovery(&self, keys: &[KeyId]) -> Vec<(SpaceId, SpaceId)> {
        let Some(me) = self.me() else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for (id, h) in &self.spaces {
            let Some(sp) = h
                .space
                .as_ref()
                .filter(|s| s.profile() == cardinal_space::group::GROUP)
            else {
                continue;
            };
            let dag = sp.dag();
            for x in dag.log_order() {
                let Some(e) = dag.get(x) else { continue };
                if e.author() != me || !keys.contains(&e.signer()) {
                    continue;
                }
                for o in e.ops() {
                    let SpaceOpBody::Succeed { successor, .. } = o.body() else {
                        continue;
                    };
                    if self.kept_by_me_now(id, &e.signer(), x) && !out.contains(&(*id, *successor))
                    {
                        out.push((*id, *successor));
                    }
                }
            }
        }
        out
    }

    /// What undoing the change that moved a group to `new` puts right
    /// ([`Undo`]). Refused where it is not held here, or where it handed
    /// the group on: the new owner holds it, and only they can hand it
    /// back.
    pub fn undo_of(&self, new: &SpaceId) -> anyhow::Result<Undo> {
        let me = self
            .me()
            .ok_or_else(|| anyhow::anyhow!("this device has no identity yet"))?;
        let sp = self.spaces.get(new).and_then(|h| h.space.as_ref());
        let sp = sp.ok_or_else(|| anyhow::anyhow!("that group is not held here"))?;
        let old = sp
            .succeeds()
            .and_then(|o| self.spaces.get(&o)?.space.as_ref());
        let old = old.ok_or_else(|| anyhow::anyhow!("the group it moved from is not held here"))?;
        anyhow::ensure!(
            sp.owner() == Some(me),
            "that group was handed on: its new owner holds it now, and only they can hand it \
             back. Undo cannot take it back"
        );
        let (left_out, roles) = plan::changes(old, sp);
        let out = left_out
            .into_iter()
            .map(|w| (w, old.role_of(&w).unwrap_or(cardinal_space::group::WRITER)))
            .collect();
        Ok(Undo { out, roles })
    }
}
