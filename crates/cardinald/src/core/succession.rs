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
            .get_mut(space)
            .ok_or_else(|| anyhow::anyhow!("not held"))?;
        let r = Record::decode(canonical)?;
        let Some((profile, _, _)) = h.wants_initial.as_ref() else {
            anyhow::bail!("it waits for no initial state");
        };
        State::from_canonical(*profile, &r)?;
        std::fs::create_dir_all(Holder::dir(&self.paths, space))?;
        crate::paths::write_private(&h.initial_at, canonical, 0o600)?;
        h.rebuild(Vec::new(), &keys, &logs);
        self.settle(space);
        Ok(())
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
        let ops = named
            .iter()
            .map(|(w, r)| SpaceOp::add_member(*w, *r))
            .collect();
        let profile = sp.profile();
        let initial = State::from_canonical(profile, &Record::decode(&canonical)?)?;
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
        let ident = self.identity.as_ref().expect("checked above");
        let h = self.spaces.get_mut(space).expect("held");
        let succeed = SpaceOp::succeed_with(new_id, &left_out, None);
        let (_, written) = h.write_plain(ident, &self.keys, vec![succeed])?;
        h.keep_in_trail(&genesis)?;
        self.settle(space);
        let account = self.follow_in_account(space, &new_id, &local_name)?;
        Ok(Succeeded {
            new: new_id,
            old_entries: vec![written, genesis_bytes.clone()],
            new_entries: vec![genesis_bytes],
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
        self.note_did_not_stand();
        out.extend(self.post_again_all(false));
        out
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
        if self.spaces.get(&s).is_some_and(|x| x.space.is_some()) {
            return Ok(None);
        }
        // Its genesis: in the trail, or held for itself already.
        let held = self.spaces.get(&s).map(|x| x.pending()).unwrap_or(&[]);
        let found = h.foreign.iter().chain(held).find_map(|f| {
            let open = Space::open_genesis(f, &keys, None).ok()?;
            (open.id() == s).then(|| (f.clone(), open))
        });
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
            return Ok(None);
        }
        // The third condition: its initial state is the state at the cut,
        // as this device works it out.
        let from = new.succession().cloned().expect("it succeeds");
        let Some(states) = plan::pinned_states(&from.judged_with, |w| self.log_of(w)) else {
            let v = "it cannot be checked yet: an identity log it was judged with is not here";
            self.note_verdict(old, Some(v.to_owned()));
            return Ok(None);
        };
        let named: Vec<[u8; 32]> = plan::genesis_members(&new)
            .into_iter()
            .map(|(w, _)| w)
            .collect();
        let at_cut = match sp.state_at(&from.cut, states, &named) {
            Ok(st) => st,
            Err(_) => {
                let v = "it cannot be checked yet: the entries it was cut at are not all here";
                self.note_verdict(old, Some(v.to_owned()));
                return Ok(None);
            }
        };
        let epoch = new
            .current_epoch()
            .and_then(|e| new.keyring().get(&e).cloned());
        let epoch = epoch.ok_or_else(|| anyhow::anyhow!("no key for its first epoch"))?;
        let (reference, canonical) = initial_ref(store, &epoch, &at_cut)?;
        let claimed = from.initial_state.as_ref().map(|r| r.encode());
        if claimed != Some(reference.encode()) {
            let v = "it has ended, and what was put in its place does not match it: its \
                     initial state is not the state at its cut";
            self.note_verdict(old, Some(v.to_owned()));
            return Ok(None);
        }
        let carried: HashSet<EntryId> = at_cut.accepted().copied().collect();
        let local_name = cardinal_space::group::name(sp);
        self.note_verdict(old, None);
        // Hold it, from its initial state.
        let dir = Holder::dir(&self.paths, &s);
        std::fs::create_dir_all(&dir)?;
        crate::paths::write_private(&dir.join("initial-state.bin"), &canonical, 0o600)?;
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

    /// The spaces whose work posts again into `into`, each with what of it
    /// `into` carried: the space it succeeds, unless it is a fresh start,
    /// and every successor of that space, or of `into` itself, that no
    /// longer stands.
    fn sources_of(&mut self, into: &SpaceId) -> Vec<(SpaceId, HashSet<EntryId>)> {
        let Some(sp) = self.spaces.get(into).and_then(|h| h.space.as_ref()) else {
            return Vec::new();
        };
        let fresh = sp.succession().is_some_and(|s| s.fresh_start);
        let old = sp.succeeds();
        let mut out = Vec::new();
        if let Some(o) = old.filter(|_| !fresh) {
            if self.spaces.get(&o).is_some_and(|h| h.space.is_some()) {
                let carried = self.carried_into(into).unwrap_or_default();
                out.push((o, carried));
            }
        }
        for (id, h) in &self.spaces {
            let Some(x) = h.space.as_ref() else { continue };
            let sibling = old.is_some() && x.succeeds() == old;
            let returned = x.succeeds() == Some(*into);
            if *id != *into && (sibling || returned) && self.current(id) == *into {
                out.push((*id, HashSet::new()));
            }
        }
        out
    }

    fn post_again_into(&mut self, into: &SpaceId, asked: bool) -> anyhow::Result<Vec<Vec<u8>>> {
        let mut written = Vec::new();
        let sources = self.sources_of(into);
        for (from, carried) in sources {
            written.extend(self.post_again_from(&from, into, &carried, asked)?);
        }
        Ok(written)
    }

    /// Posts again into `into` what this device wrote in `from` and `into`
    /// does not hold: in log order, each entry whole, up to the first that
    /// has to wait.
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
            .filter(|x| **x != fs.id() && valid.contains(*x) && !carried.contains(*x))
            .filter(|x| {
                fs.entry(x)
                    .is_some_and(|e| e.author() == me && e.signer() == here && !e.is_genesis())
            })
            .filter(|x| fs.state().is_accepted(x))
            // a posting again whose origin `into` holds itself, as when
            // everyone returns to the old space
            .filter(|x| {
                let o = origin_in(&fh.notes, x);
                !is.dag().contains(&o) && !done.contains(&hex::encode(o))
            })
            .filter(|x| {
                let o = hex::encode(origin_in(&fh.notes, x));
                !ih.notes.nothing.contains(&o)
            })
            .copied()
            .collect();
        if candidates.is_empty() {
            return Ok(out);
        }
        if !plan::may_post(is, &me) {
            return Ok(out);
        }
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
            let notes = &ih.notes;
            let origin_of = |e: &EntryId| notes.posted.get(&hex::encode(e)).and_then(|o| hex32(o));
            match plan::plan_repost(fs, &x, is, &origin_of) {
                Plan::Wait => break,
                Plan::Nothing => {
                    let h = self.spaces.get_mut(into).expect("held");
                    h.notes.nothing.insert(origin_hex);
                    h.save_notes();
                }
                Plan::Post(r) => {
                    let ident = self.identity.as_ref().expect("an identity");
                    let h = self.spaces.get_mut(into).expect("held");
                    let (id, bytes) = h.write_one(ident, &self.keys, r.ops)?;
                    h.notes.posted.insert(hex::encode(id), origin_hex);
                    h.notes.held_back.remove(&hex::encode(x));
                    h.save_notes();
                    self.settle(into);
                    out.push(bytes);
                }
            }
        }
        Ok(out)
    }
}
