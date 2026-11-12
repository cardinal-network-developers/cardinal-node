//! What the daemon holds: the identity log and the spaces, persisted as
//! append-only logs of the objects that make them up, and kept evaluated
//! in memory.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use cardinal_crypto::{HybridKeyPair, HybridPublicKey};
use cardinal_encoding::Record;
use cardinal_identity::{EntryId, IdentityEntry, IdentityLog, IdentityState, Inserted, KeyId};
use cardinal_space::account;
use cardinal_space::entry::NodeKind;
use cardinal_space::{Profile, SealedEntry, Space, SpaceId, SpaceOp, ROOT};
use cardinal_sync::{identity_log_label, MemSet, SetStore};

use crate::applog::{AppendLog, Loc};
use crate::keys::Keys;
use crate::paths::Paths;

/// The account-space secret holding the discovery secret.
pub const DISCOVERY_PURPOSE: &str = "discovery";

/// Largest total op size put in one entry; sealed entries may not exceed
/// 256 KiB.
pub const MAX_ENTRY_OPS_BYTES: usize = 96 * 1024;

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Short hex for logs.
pub fn short(id: &[u8]) -> String {
    hex::encode(&id[..id.len().min(4)])
}

/// The identity log this device belongs to.
pub struct Identity {
    /// The log.
    pub log: IdentityLog,
    /// The identity encryption keys this device can open, newest first.
    pub enc: Vec<HybridKeyPair>,
    file: AppendLog,
    locs: HashMap<EntryId, Loc>,
    /// Entry ids held (the sync set).
    pub set: MemSet,
}

impl Identity {
    /// The identity id.
    pub fn id(&self) -> EntryId {
        self.log.id()
    }

    /// The sync label of the log.
    pub fn label(&self) -> [u8; 32] {
        identity_log_label(&self.log.id())
    }

    /// The evaluated state.
    pub fn state(&self) -> Arc<IdentityState> {
        self.log.state()
    }

    fn refresh_keys(&mut self, keys: &Keys) {
        match self.log.open_encryption_key(&keys.device) {
            Ok(k) => self.enc = self.log.key_chain(k),
            Err(e) => {
                tracing::warn!("cannot open the identity encryption key yet: {e}");
            }
        }
    }

    fn key_refs(&self) -> Vec<&HybridKeyPair> {
        self.enc.iter().collect()
    }

    /// The bytes of an entry.
    pub fn get(&self, id: &EntryId) -> Option<Vec<u8>> {
        self.locs.get(id).and_then(|l| self.file.read(*l).ok())
    }

    /// Every entry's bytes, in log order.
    pub fn all_entries(&self) -> Vec<Vec<u8>> {
        self.log.entries().map(|e| e.encode()).collect()
    }

    /// Adds entries received from one of this person's devices. Returns
    /// whether the log changed.
    fn ingest(&mut self, objects: &[Vec<u8>]) -> anyhow::Result<bool> {
        let mut changed = false;
        let mut to_store: Vec<Vec<u8>> = Vec::new();
        for bytes in objects {
            let e = match IdentityEntry::decode(bytes) {
                Ok(e) => e,
                Err(err) => {
                    tracing::warn!("ignoring a malformed identity entry: {err}");
                    continue;
                }
            };
            if self.set.contains_id(&e.id()) || e.identity() != self.log.id() {
                continue;
            }
            let id = e.id();
            match self.log.insert(e) {
                Ok(Inserted::Duplicate) => continue,
                Ok(Inserted::Added(_)) => changed = true,
                Ok(Inserted::Held(_)) => {}
                Err(err) => {
                    tracing::warn!("rejected identity entry {}: {err}", short(&id));
                    continue;
                }
            }
            self.set.insert(id);
            to_store.push(bytes.clone());
        }
        self.store(&to_store)?;
        Ok(changed)
    }

    fn store(&mut self, entries: &[Vec<u8>]) -> anyhow::Result<()> {
        let refs: Vec<&[u8]> = entries.iter().map(|b| b.as_slice()).collect();
        let locs = self.file.append_many(&refs)?;
        for (b, l) in entries.iter().zip(locs) {
            let e = IdentityEntry::decode(b)?;
            self.locs.insert(e.id(), l);
        }
        Ok(())
    }

    /// Appends an entry written by this device.
    pub fn record_own(&mut self, e: &IdentityEntry) -> anyhow::Result<()> {
        self.set.insert(e.id());
        self.store(&[e.encode()])
    }
}

/// Another person's identity log (`identity.md#distribution`), kept to tell
/// which of their writes count and how to reach their devices.
pub struct OtherLog {
    /// The log.
    pub log: IdentityLog,
    file: AppendLog,
    locs: HashMap<EntryId, Loc>,
    /// Entry ids held (the sync set).
    pub set: MemSet,
}

impl OtherLog {
    /// Adds entries. Returns whether the log changed.
    fn ingest(&mut self, objects: &[Vec<u8>]) -> anyhow::Result<bool> {
        let mut changed = false;
        for bytes in objects {
            let Ok(e) = IdentityEntry::decode(bytes) else {
                continue;
            };
            if self.set.contains_id(&e.id()) || e.identity() != self.log.id() {
                continue;
            }
            let id = e.id();
            match self.log.insert(e) {
                Ok(Inserted::Added(_)) => changed = true,
                Ok(Inserted::Held(_)) => {}
                Ok(Inserted::Duplicate) | Err(_) => continue,
            }
            self.keep(id, bytes)?;
        }
        Ok(changed)
    }

    fn keep(&mut self, id: EntryId, bytes: &[u8]) -> anyhow::Result<()> {
        self.set.insert(id);
        for loc in self.file.append_many(&[bytes])? {
            self.locs.insert(id, loc);
        }
        Ok(())
    }

    /// The bytes of an entry.
    fn get(&self, id: &EntryId) -> Option<Vec<u8>> {
        self.locs.get(id).and_then(|l| self.file.read(*l).ok())
    }
}

/// Helpers on [`MemSet`].
pub trait SetExt {
    /// Whether the set holds `id`.
    fn contains_id(&self, id: &[u8; 32]) -> bool;
}

impl SetExt for MemSet {
    fn contains_id(&self, id: &[u8; 32]) -> bool {
        cardinal_sync::SetStore::contains(self, id)
    }
}

/// What this device held when an epoch reached it: each member's
/// encryption key, who had left, and whom it knew to be frozen
/// (`spaces.md#when-to-rotate`). Nothing in a space says whom an epoch was
/// wrapped for, or with which of a member's keys, so a device keeps its own
/// account with each epoch, as it keeps the space, and compares.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Reached {
    /// The fingerprint of each member's encryption key, by identity.
    keys: BTreeMap<String, String>,
    /// Who had left.
    left: BTreeSet<String>,
    /// Whom this device knew to be frozen.
    frozen: BTreeSet<String>,
}

impl Reached {
    /// What this device holds of a space's members now.
    fn now(space: &Space, logs: &[Arc<IdentityState>]) -> Reached {
        let mut now = Reached::default();
        for who in space.validity().identities() {
            let Some(st) = logs.iter().find(|st| st.identity == who) else {
                continue;
            };
            if let Some(k) = &st.encryption_key {
                let key = hex::encode(k.public.fingerprint());
                now.keys.insert(hex::encode(who), key);
            }
            if st.frozen {
                now.frozen.insert(hex::encode(who));
            }
        }
        now.left = space.left().iter().map(|(w, _)| hex::encode(w)).collect();
        now
    }

    /// Whether a new epoch is due for what changed since: the encryption
    /// key of a member who would be given the next one, a member who left,
    /// or one this device has learned is frozen.
    fn calls_for_a_new_epoch(&self, now: &Reached) -> bool {
        let out = |who: &String| now.left.contains(who) || now.frozen.contains(who);
        let key = |(who, key): (&String, &String)| {
            !out(who) && self.keys.get(who).is_some_and(|was| was != key)
        };
        now.keys.iter().any(key)
            || now.left.iter().any(|who| !self.left.contains(who))
            || now.frozen.iter().any(|who| !self.frozen.contains(who))
    }
}

/// One space as this device holds it.
pub struct Holder {
    /// The space id (also its sync label).
    pub id: SpaceId,
    /// The opened space, once its genesis entry has been opened.
    pub space: Option<Space>,
    /// Sealed ids held (the sync set).
    pub set: MemSet,
    locs: HashMap<[u8; 32], Loc>,
    /// Sealed entries that could not be opened yet (no epoch key).
    pending: Vec<SealedEntry>,
    file: AppendLog,
    /// Bumped whenever the state may have changed.
    pub version: u64,
    /// The encryption keys of the other members, for a new epoch.
    member_keys: Vec<HybridPublicKey>,
    /// The next write must start a new epoch because of who is in the
    /// space (`spaces.md#when-to-rotate`): by this device's record of the
    /// current epoch, or by the entries, or because the epoch was begun by
    /// a member this device would leave out.
    leave_out: bool,
    /// By epoch id: what this device held when the epoch reached it.
    reached: BTreeMap<String, Reached>,
    reached_at: PathBuf,
}

/// What ingesting objects did.
#[derive(Debug, Default)]
pub struct Ingested {
    /// Objects new to this device.
    pub new: usize,
    /// Some entries wait for parents this device lacks.
    pub missing_parents: bool,
    /// How many objects, new or waiting until now, have all they need
    /// here: what this device can announce.
    pub complete: usize,
    /// Those of them it can pass on as they are. Fewer than `complete` when
    /// there were many, or some had been waiting: a notice then names the
    /// heads.
    pub objects: Vec<Vec<u8>>,
}

impl Holder {
    fn dir(paths: &Paths, id: &SpaceId) -> PathBuf {
        paths.spaces().join(hex::encode(id))
    }

    /// Opens (or creates) the holder's storage and judges what it holds,
    /// with the identity logs this device has.
    fn open(
        paths: &Paths,
        id: SpaceId,
        keys: &[&HybridKeyPair],
        logs: &[Arc<IdentityState>],
    ) -> anyhow::Result<Holder> {
        let (file, records) = AppendLog::open(&Self::dir(paths, &id).join("entries.log"))?;
        let mut h = Holder {
            id,
            space: None,
            set: MemSet::new(),
            locs: HashMap::new(),
            pending: Vec::new(),
            file,
            version: 0,
            member_keys: Vec::new(),
            leave_out: false,
            reached: BTreeMap::new(),
            reached_at: Self::dir(paths, &id).join("epochs.json"),
        };
        // No record, or one that cannot be read, is an epoch that reaches
        // this device now.
        if let Ok(bytes) = std::fs::read(&h.reached_at) {
            h.reached = serde_json::from_slice(&bytes).unwrap_or_default();
        }
        let mut sealed = Vec::new();
        for (loc, bytes) in records {
            let sid = *blake3::hash(&bytes).as_bytes();
            h.locs.insert(sid, loc);
            h.set.insert(sid);
            match SealedEntry::decode(&bytes) {
                Ok(s) => sealed.push(s),
                Err(e) => tracing::warn!("space {}: bad stored entry: {e}", short(&id)),
            }
        }
        h.rebuild(sealed, keys, logs);
        Ok(h)
    }

    /// Starts again from nothing with `extra` added: opens the genesis, adds
    /// everything with no identity log at hand, so that nothing counts yet
    /// and no state is built, then judges it all once with the logs.
    fn rebuild(
        &mut self,
        extra: Vec<SealedEntry>,
        keys: &[&HybridKeyPair],
        logs: &[Arc<IdentityState>],
    ) {
        let mut all: Vec<SealedEntry> = std::mem::take(&mut self.pending);
        if let Some(sp) = self.space.take() {
            all.extend(sp.sealed_entries().map(|(_, s)| s.clone()));
        }
        all.extend(extra);
        let mut space = None;
        for s in all.iter().filter(|s| s.wraps().is_some()) {
            if let Ok(sp) = Space::open_genesis(s, keys, None) {
                if sp.id() == self.id {
                    space = Some(sp);
                    break;
                }
            }
        }
        if space.is_none() {
            space = Self::open_added(self.id, &all, keys);
        }
        let Some(mut space) = space else {
            self.pending = all;
            return;
        };
        let mut rest = all;
        loop {
            let mut progress = false;
            let mut still = Vec::new();
            for s in rest {
                match space.receive(s.clone(), keys) {
                    Ok(_) => progress = true,
                    Err(cardinal_space::Error::NoEpochKey) => still.push(s),
                    Err(e) => tracing::debug!("space {}: entry not opened: {e}", short(&self.id)),
                }
            }
            rest = still;
            if !progress || rest.is_empty() {
                break;
            }
        }
        self.pending = rest;
        space.set_identities(logs.iter().cloned());
        self.space = Some(space);
        self.version += 1;
    }

    /// A space this identity was added to after it began: the key comes in
    /// the entry that added them, and the earlier ones in rotations.
    fn open_added(id: SpaceId, all: &[SealedEntry], keys: &[&HybridKeyPair]) -> Option<Space> {
        let ring = Space::keys_in(all, keys);
        if ring.is_empty() {
            return None;
        }
        all.iter().find_map(|s| {
            let key = ring.get(&s.epoch())?;
            let e = s.open_with(key).ok()?;
            if !e.is_genesis() || e.id() != id {
                return None;
            }
            Space::open_genesis_with(s, ring.clone(), None).ok()
        })
    }

    /// How many objects the set holds.
    pub fn set_len(&self) -> usize {
        cardinal_sync::SetStore::len(&self.set)
    }

    /// The profile, once open.
    pub fn profile(&self) -> Option<Profile> {
        self.space.as_ref().map(|s| s.profile())
    }

    /// The bytes of a sealed entry.
    pub fn get(&self, sid: &[u8; 32]) -> Option<Vec<u8>> {
        self.locs.get(sid).and_then(|l| self.file.read(*l).ok())
    }

    /// Sealed ids of the heads of everything held, valid here or not: what
    /// a `heads` notice names, for a peer to fetch what it lacks.
    pub fn head_ids(&self) -> Vec<[u8; 32]> {
        let Some(sp) = &self.space else {
            return Vec::new();
        };
        sp.dag()
            .heads()
            .iter()
            .filter_map(|h| sp.sealed(h).map(|s| s.sealed_id()))
            .collect()
    }

    fn persist(&mut self, items: &[([u8; 32], Vec<u8>)]) -> anyhow::Result<()> {
        let refs: Vec<&[u8]> = items.iter().map(|(_, b)| b.as_slice()).collect();
        let locs = self.file.append_many(&refs)?;
        for ((sid, _), l) in items.iter().zip(locs) {
            self.locs.insert(*sid, l);
            self.set.insert(*sid);
        }
        Ok(())
    }

    /// Adds sealed entries received from another device.
    fn ingest(
        &mut self,
        objects: &[Vec<u8>],
        keys: &[&HybridKeyPair],
        logs: &[Arc<IdentityState>],
    ) -> anyhow::Result<Ingested> {
        let mut fresh = Vec::new();
        let mut items = Vec::new();
        for bytes in objects {
            let sid = *blake3::hash(bytes).as_bytes();
            if self.set.contains_id(&sid) || items.iter().any(|(s, _)| *s == sid) {
                continue;
            }
            match SealedEntry::decode(bytes) {
                Ok(s) => {
                    fresh.push(s);
                    items.push((sid, bytes.clone()));
                }
                Err(e) => tracing::warn!("space {}: ignoring a bad object: {e}", short(&self.id)),
            }
        }
        let mut out = Ingested {
            new: fresh.len(),
            ..Ingested::default()
        };
        if fresh.is_empty() {
            out.missing_parents = self.is_waiting();
            return Ok(out);
        }
        self.persist(&items)?;
        if self.space.is_none() || fresh.len() > 16 {
            out.complete = fresh.len();
            self.rebuild(fresh, keys, logs);
        } else if let Some(space) = self.space.as_mut() {
            for (s, (_, bytes)) in fresh.into_iter().zip(items) {
                match space.receive(s.clone(), keys) {
                    Ok(Inserted::Added(released)) => {
                        out.complete += released.len();
                        out.objects.push(bytes);
                    }
                    Ok(_) => {}
                    Err(cardinal_space::Error::NoEpochKey) => self.pending.push(s),
                    Err(e) => tracing::warn!("space {}: entry rejected: {e}", short(&self.id)),
                }
            }
            out.complete += self.open_pending(keys);
            self.version += 1;
        }
        out.missing_parents = self.is_waiting();
        Ok(out)
    }

    /// Tries again the entries no key could open yet. Returns how many
    /// entries that completed.
    fn open_pending(&mut self, keys: &[&HybridKeyPair]) -> usize {
        let Some(space) = self.space.as_mut() else {
            return 0;
        };
        let mut complete = 0;
        for s in std::mem::take(&mut self.pending) {
            match space.receive(s.clone(), keys) {
                Ok(Inserted::Added(released)) => complete += released.len(),
                Ok(_) => {}
                Err(cardinal_space::Error::NoEpochKey) => self.pending.push(s),
                Err(_) => {}
            }
        }
        complete
    }

    /// Whether entries wait for parents this device lacks. A genesis is too
    /// long to push, so what follows it can be the first to arrive.
    fn is_waiting(&self) -> bool {
        match &self.space {
            Some(sp) => sp.dag().held().next().is_some(),
            None => self.set.len() > 0,
        }
    }

    /// Whether the next write must start a new epoch
    /// (`spaces.md#when-to-rotate`): since the current one reached this
    /// device a member's encryption key changed, a member left, or the
    /// device learned that one is frozen ([`Reached`]); or the entries say
    /// so, on every device alike; or the epoch was begun by a member this
    /// device would leave out; or it is not wrapped for this identity's own
    /// key, which a removal always changes. A device that cannot open the
    /// current key yet cannot tell, and waits. Only a writer starts an
    /// epoch.
    fn rotation_due(&self, identity: &Identity) -> bool {
        let Some(space) = &self.space else {
            return false;
        };
        let writer = cardinal_space::entry::WRITER;
        let me = identity.id();
        if space.role_of(&me).is_none_or(|r| r < writer) || space.has_left(&me) {
            return false;
        }
        // Nothing is written in a space that has ended but what witnesses
        // or keeps, and that starts no epoch.
        if space.ended() {
            return false;
        }
        if self.leave_out {
            return true;
        }
        let st = identity.log.state();
        match (identity.enc.first(), &st.encryption_key) {
            (Some(k), Some(current)) if *k.public_key() == current.public => {
                !space.epoch_wrapped_for(k)
            }
            _ => false,
        }
    }

    /// Writes on every head if `key` wrote something nothing else builds
    /// on, so that it stays when the key is removed. Returns the sealed
    /// bytes to send to the person's other devices.
    pub fn witness(
        &mut self,
        identity: &Identity,
        keys: &Keys,
        key: &KeyId,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        if !self.space.as_ref().is_some_and(|s| s.has_unwitnessed(key)) {
            return Ok(None);
        }
        Ok(Some(self.write_one(identity, keys, Vec::new())?.1))
    }

    /// Starts a new epoch if one is due, in an entry of its own. Returns
    /// the sealed bytes to send to the person's other devices.
    pub fn rotate_if_due(
        &mut self,
        identity: &Identity,
        keys: &Keys,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        if !self.rotation_due(identity) {
            return Ok(None);
        }
        Ok(Some(self.write_one(identity, keys, Vec::new())?.1))
    }

    /// Writes one entry with `ops`. Returns the entry id and the sealed
    /// bytes to send to the person's other devices.
    pub fn write_one(
        &mut self,
        identity: &Identity,
        keys: &Keys,
        ops: Vec<SpaceOp>,
    ) -> anyhow::Result<(EntryId, Vec<u8>)> {
        if identity.state().power(&keys.key()).is_none() {
            anyhow::bail!("this device was removed");
        }
        let rotate = self.rotation_due(identity);
        let space = self
            .space
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("space not open yet"))?;
        let sealed = if rotate {
            let pk = identity
                .enc
                .first()
                .ok_or_else(|| anyhow::anyhow!("no encryption key"))?
                .public_key()
                .clone();
            let mut recipients = vec![&pk];
            recipients.extend(self.member_keys.iter());
            let (id, s, _) = space.rotate_entry(
                &identity.log,
                &keys.device.signing,
                &recipients,
                ops,
                Some(now_ms()),
            )?;
            (id, s)
        } else {
            space.write_entry(&identity.log, &keys.device.signing, ops, Some(now_ms()))?
        };
        let (id, sealed) = sealed;
        if !space.validity().is_valid(&id) {
            tracing::warn!(
                "space {}: own entry {} is not valid",
                short(&self.id),
                short(&id)
            );
        }
        let bytes = sealed.encode();
        let sid = sealed.sealed_id();
        self.persist(&[(sid, bytes.clone())])?;
        self.version += 1;
        Ok((id, bytes))
    }

    /// Adds members to a group in one entry, with the current key wrapped
    /// for them (`profiles.md#group`). Returns the sealed bytes.
    pub fn add_members(
        &mut self,
        identity: &Identity,
        keys: &Keys,
        added: &[([u8; 32], HybridPublicKey)],
        ops: Vec<SpaceOp>,
    ) -> anyhow::Result<Vec<u8>> {
        let mine = identity
            .enc
            .first()
            .ok_or_else(|| anyhow::anyhow!("no encryption key"))?
            .public_key()
            .clone();
        // A new epoch that is due starts in this entry, wrapped for those
        // added too (`spaces.md#when-to-rotate`).
        let due = self.rotation_due(identity);
        let space = self
            .space
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("space not open yet"))?;
        let role = cardinal_space::group::WRITER;
        let adding: Vec<_> = added.iter().map(|(w, k)| (*w, role, k)).collect();
        let mut everyone = vec![&mine];
        everyone.extend(self.member_keys.iter());
        let sealed = if due {
            let mut all: Vec<SpaceOp> = added
                .iter()
                .map(|(who, _)| SpaceOp::add_member(*who, role))
                .collect();
            all.extend(ops);
            everyone.extend(added.iter().map(|(_, k)| k));
            let signing = &keys.device.signing;
            let time = Some(now_ms());
            space
                .rotate_entry(&identity.log, signing, &everyone, all, time)?
                .1
        } else {
            space.add_members(
                &identity.log,
                &keys.device.signing,
                &adding,
                &everyone,
                ops,
                Some(now_ms()),
            )?
        };
        let bytes = sealed.encode();
        self.persist(&[(sealed.sealed_id(), bytes.clone())])?;
        self.version += 1;
        Ok(bytes)
    }

    /// Writes one entry with `ops` that does not descend from any of
    /// `exclude` ([`Space::write_concurrent`]): for local changes made
    /// without having seen those entries. Refused while an epoch rotation
    /// is due, or when the current epoch began after `exclude`.
    pub fn write_concurrent(
        &mut self,
        identity: &Identity,
        keys: &Keys,
        exclude: &[EntryId],
        ops: Vec<SpaceOp>,
    ) -> anyhow::Result<(EntryId, Vec<u8>)> {
        if identity.state().power(&keys.key()).is_none() {
            anyhow::bail!("this device was removed");
        }
        if self.rotation_due(identity) {
            anyhow::bail!("an epoch rotation is due");
        }
        let space = self
            .space
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("space not open yet"))?;
        let (id, sealed) = space.write_concurrent(
            &identity.log,
            &keys.device.signing,
            exclude,
            ops,
            Some(now_ms()),
        )?;
        let bytes = sealed.encode();
        let sid = sealed.sealed_id();
        self.persist(&[(sid, bytes.clone())])?;
        self.version += 1;
        Ok((id, bytes))
    }

    /// Writes `ops`, split over as many entries as their size needs.
    pub fn write(
        &mut self,
        identity: &Identity,
        keys: &Keys,
        ops: Vec<SpaceOp>,
    ) -> anyhow::Result<Vec<(EntryId, Vec<u8>)>> {
        let mut out = Vec::new();
        for batch in split_ops(ops) {
            out.push(self.write_one(identity, keys, batch)?);
        }
        Ok(out)
    }
}

/// Splits ops into batches small enough for one entry each.
pub fn split_ops(ops: Vec<SpaceOp>) -> Vec<Vec<SpaceOp>> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    let mut size = 0;
    for op in ops {
        let n = op.record().encode().len() + 8;
        if !cur.is_empty() && size + n > MAX_ENTRY_OPS_BYTES {
            out.push(std::mem::take(&mut cur));
            size = 0;
        }
        size += n;
        cur.push(op);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Everything the daemon holds.
pub struct Core {
    paths: Paths,
    /// This device's keys.
    pub keys: Arc<Keys>,
    /// The identity, once this device has one.
    pub identity: Option<Identity>,
    /// Spaces held.
    pub spaces: BTreeMap<SpaceId, Holder>,
    /// Identity entries received before this device joined the identity.
    joining: Vec<Vec<u8>>,
    /// Other people's identity logs.
    pub others: BTreeMap<[u8; 32], OtherLog>,
    /// Entries of a log whose genesis has not arrived yet.
    arriving: HashMap<[u8; 32], Vec<Vec<u8>>>,
    /// What every identity log held means, each evaluated with the others
    /// at hand: what the spaces judge their authors by. Worked out again
    /// when a log changes, and not otherwise.
    logs: Vec<Arc<IdentityState>>,
}

/// What a change to the identity log means for the rest of the daemon.
#[derive(Debug, Default)]
pub struct IdentityChange {
    /// The log changed.
    pub changed: bool,
    /// This device just joined the identity.
    pub joined: bool,
}

impl Core {
    /// Loads everything from disk.
    pub fn load(paths: &Paths, keys: Arc<Keys>) -> anyhow::Result<Core> {
        // Never opened as far as it goes: a store of another format is
        // refused whole (`format.rs`).
        crate::format::check(paths)?;
        let mut core = Core {
            paths: paths.clone(),
            keys,
            identity: None,
            spaces: BTreeMap::new(),
            joining: Vec::new(),
            others: BTreeMap::new(),
            arriving: HashMap::new(),
            logs: Vec::new(),
        };
        if paths.identity_log().exists() {
            let (file, records) = AppendLog::open(&paths.identity_log())?;
            core.identity = Some(Self::build_identity(file, records, &core.keys)?);
        }
        if core.identity.is_some() {
            core.load_others()?;
            core.read_logs();
            if let Ok(rd) = std::fs::read_dir(paths.spaces()) {
                for d in rd.flatten() {
                    let name = d.file_name().to_string_lossy().into_owned();
                    let Ok(b) = hex::decode(&name) else { continue };
                    let Ok(id) = <[u8; 32]>::try_from(&b[..]) else {
                        continue;
                    };
                    core.open_space(id)?;
                }
            }
            core.settle_all();
        }
        Ok(core)
    }

    fn load_others(&mut self) -> anyhow::Result<()> {
        let Ok(rd) = std::fs::read_dir(self.paths.others()) else {
            return Ok(());
        };
        for d in rd.flatten() {
            let (file, records) = AppendLog::open(&d.path())?;
            let mut entries = Vec::new();
            let mut locs = HashMap::new();
            let mut set = MemSet::new();
            for (loc, b) in records {
                let e = IdentityEntry::decode(&b)?;
                locs.insert(e.id(), loc);
                set.insert(e.id());
                entries.push(e);
            }
            let Some(at) = entries.iter().position(|e| e.is_genesis()) else {
                continue;
            };
            let mut log = IdentityLog::from_genesis(entries.remove(at))?;
            for e in entries {
                let _ = log.insert(e);
            }
            let other = OtherLog {
                log,
                file,
                locs,
                set,
            };
            self.others.insert(other.log.id(), other);
        }
        Ok(())
    }

    /// Adds entries of another person's identity log, the first of which
    /// may come in any order. Returns whether the log changed.
    pub fn ingest_other(
        &mut self,
        identity: [u8; 32],
        objects: &[Vec<u8>],
    ) -> anyhow::Result<bool> {
        if !self.others.contains_key(&identity) {
            let arriving = self.arriving.entry(identity).or_default();
            arriving.extend(objects.iter().cloned());
            let genesis = arriving
                .iter()
                .filter_map(|b| IdentityEntry::decode(b).ok())
                .find(|e| e.is_genesis() && e.identity() == identity);
            let Some(genesis) = genesis else {
                return Ok(false);
            };
            let (genesis_id, bytes) = (genesis.id(), genesis.encode());
            std::fs::create_dir_all(self.paths.others())?;
            let path = self.paths.others().join(hex::encode(identity));
            let (file, _) = AppendLog::open(&path)?;
            let mut other = OtherLog {
                log: IdentityLog::from_genesis(genesis)?,
                file,
                locs: HashMap::new(),
                set: MemSet::new(),
            };
            other.keep(genesis_id, &bytes)?;
            self.others.insert(identity, other);
            let held = self.arriving.remove(&identity).unwrap_or_default();
            let other = self.others.get_mut(&identity).expect("inserted");
            other.ingest(&held)?;
            self.settle_all();
            return Ok(true);
        }
        let other = self.others.get_mut(&identity).expect("checked");
        let changed = other.ingest(objects)?;
        if changed {
            self.settle_all();
        }
        Ok(changed)
    }

    /// The identity whose log has `label`, of those this device keeps.
    pub fn other_of_label(&self, label: &[u8; 32]) -> Option<[u8; 32]> {
        // This person is a member of their own spaces, and their log is
        // nobody else's.
        let me = self.identity.as_ref().map(|i| i.id());
        let members = self
            .spaces
            .values()
            .filter_map(|h| h.space.as_ref())
            .flat_map(|s| s.validity().members.iter().map(|m| m.identity));
        self.contacts()
            .into_iter()
            .map(|c| c.identity)
            .chain(self.others.keys().copied())
            .chain(members)
            .filter(|id| Some(*id) != me)
            .find(|id| identity_log_label(id) == *label)
    }

    /// This person's contacts, from the account space.
    pub fn contacts(&self) -> Vec<cardinal_space::account::ContactRecord> {
        self.account()
            .and_then(|a| a.space.as_ref())
            .map(|s| cardinal_space::account::contacts(s.state()))
            .unwrap_or_default()
    }

    /// The spaces shared with anyone, with the other members who have not
    /// left and whom this person has not refused.
    pub fn shared_spaces(&self) -> Vec<(SpaceId, Vec<[u8; 32]>)> {
        let me = self.identity.as_ref().map(|i| i.id());
        let contacts = self.contacts();
        let refused = |who: &[u8; 32]| contacts.iter().any(|c| c.identity == *who && c.refused);
        let mut out = Vec::new();
        for (id, h) in &self.spaces {
            let Some(space) = h.space.as_ref() else {
                continue;
            };
            let members = space.present().into_iter();
            let others: Vec<[u8; 32]> = members.filter(|m| Some(*m) != me && !refused(m)).collect();
            if !others.is_empty() {
                out.push((*id, others));
            }
        }
        out
    }

    /// This person's hosts with a mailbox: each grant and the device serving
    /// it.
    pub fn mailboxes(&self) -> Vec<(cardinal_space::grant::Grant, KeyId)> {
        let Some(space) = self.account().and_then(|a| a.space.as_ref()) else {
            return Vec::new();
        };
        let devices = cardinal_space::account::devices(space.state());
        let hosting = |key: &KeyId| devices.iter().any(|d| d.key == *key && d.is_host);
        cardinal_space::account::hosts(space.state())
            .iter()
            .filter_map(|h| cardinal_space::grant::Grant::open(&h.grant))
            .filter(|(g, signer)| {
                g.services.contains(&cardinal_space::grant::MAILBOX) && hosting(signer)
            })
            .collect()
    }

    /// Every host and token `who` gives in a space, in their reach node
    /// (`profiles.md#reach`). Empty if they gave none, or said nowhere.
    pub fn reach_of(
        &self,
        space: &SpaceId,
        who: &[u8; 32],
    ) -> Vec<cardinal_space::relationship::Reach> {
        let Some(h) = self.spaces.get(space).and_then(|h| h.space.as_ref()) else {
            return Vec::new();
        };
        cardinal_space::relationship::reach_of(h.state(), who)
    }

    /// Whether `who` has set their reach node in a space, if only to say
    /// nowhere.
    pub fn reach_is_set(&self, space: &SpaceId, who: &[u8; 32]) -> bool {
        let h = self.spaces.get(space).and_then(|h| h.space.as_ref());
        h.is_some_and(|h| cardinal_space::relationship::reach_is_set(h.state(), who))
    }

    /// Every blob reference in anything this device holds of any space:
    /// in any op of any entry it could open, valid or not, waiting for its
    /// parents or not, whatever the profile and wherever in the op it is.
    /// Current values, values in conflict and old versions are all among
    /// them. With that go the reasons it may not be all: a space that is
    /// held and not open here, and entries that no key here opens.
    pub fn named_blobs(&self) -> (Vec<cardinal_blob::BlobRef>, Vec<String>) {
        use cardinal_encoding::Value;
        fn refs_in(v: &Value, out: &mut std::collections::HashSet<cardinal_blob::BlobRef>) {
            if let Some(r) = v.as_record() {
                if let Ok(b) = cardinal_blob::BlobRef::from_record(r) {
                    out.insert(b);
                }
                r.iter().for_each(|(_, x)| refs_in(x, out));
            } else if let Some(list) = v.as_list() {
                list.iter().for_each(|x| refs_in(x, out));
            }
        }
        let mut refs = std::collections::HashSet::new();
        let mut unsure = Vec::new();
        for (id, h) in &self.spaces {
            let Some(sp) = h.space.as_ref() else {
                if h.set.len() > 0 {
                    unsure.push(format!(
                        "the space {} is held and cannot be opened here, so nothing says \
                         what it names",
                        short(id)
                    ));
                }
                continue;
            };
            if !h.pending.is_empty() {
                unsure.push(format!(
                    "{} entries of the space {} cannot be opened here yet, so nothing says \
                     what they name",
                    h.pending.len(),
                    short(id)
                ));
            }
            let here = sp.dag().iter().map(|(_, e)| e);
            for e in here.chain(sp.dag().held_values()) {
                for op in e.ops() {
                    op.record().iter().for_each(|(_, x)| refs_in(x, &mut refs));
                }
            }
        }
        (refs.into_iter().collect(), unsure)
    }

    /// The members of a space, this person aside, who are not their
    /// contacts and have not left: whoever a reach node set there would
    /// tell where this person's hosts are, and who has no host of theirs
    /// already (`hosts.md#telling-others-where-to-reach-you`). Someone
    /// refused is not a contact for this.
    pub fn not_contacts_in(&self, space: &SpaceId) -> Vec<[u8; 32]> {
        let me = self.identity.as_ref().map(|i| i.id());
        let Some(sp) = self.spaces.get(space).and_then(|h| h.space.as_ref()) else {
            return Vec::new();
        };
        let contacts = self.contacts();
        let known = |who: &[u8; 32]| contacts.iter().any(|c| c.identity == *who && !c.refused);
        let others = sp.present().into_iter();
        others.filter(|m| Some(*m) != me && !known(m)).collect()
    }

    /// The space this person gave out a token in.
    pub fn space_of_token(&self, token: &[u8; 16]) -> Option<SpaceId> {
        let me = self.identity.as_ref()?.id();
        self.spaces.keys().copied().find(|id| {
            let reach = self.reach_of(id, &me);
            reach.iter().any(|r| r.token == *token)
        })
    }

    /// The current epoch of a space, and its envelope key.
    pub fn envelope_key(
        &self,
        space: &SpaceId,
    ) -> Option<(
        cardinal_space::EpochId,
        cardinal_crypto::Zeroizing<[u8; 32]>,
    )> {
        let h = self.spaces.get(space)?.space.as_ref()?;
        let epoch = h.current_epoch()?;
        Some((epoch, h.keyring().get(&epoch)?.mailbox_key()))
    }

    /// An epoch's envelope key.
    pub fn envelope_key_of(
        &self,
        space: &SpaceId,
        epoch: &cardinal_space::EpochId,
    ) -> Option<cardinal_crypto::Zeroizing<[u8; 32]>> {
        let h = self.spaces.get(space)?.space.as_ref()?;
        Some(h.keyring().get(epoch)?.mailbox_key())
    }

    /// Whether a sealed entry of a space is held, and counts. One that does
    /// not may be waiting for its author's log.
    pub fn entry_counts(&self, space: &SpaceId, sealed: &[u8]) -> bool {
        let Some(h) = self.spaces.get(space).and_then(|h| h.space.as_ref()) else {
            return false;
        };
        let id = *blake3::hash(sealed).as_bytes();
        h.sealed_entries()
            .any(|(entry, s)| s.sealed_id() == id && h.validity().valid.contains(entry))
    }

    /// The entries of a space that `device` signed, sealed.
    pub fn entries_by(&self, space: &SpaceId, device: &KeyId) -> Vec<(EntryId, Vec<u8>)> {
        let Some(h) = self.spaces.get(space).and_then(|h| h.space.as_ref()) else {
            return Vec::new();
        };
        h.sealed_entries()
            .filter(|(id, _)| h.entry(id).is_some_and(|e| e.signer() == *device))
            .map(|(id, sealed)| (*id, sealed.encode()))
            .collect()
    }

    /// The labels of contacts' logs this device does not have yet.
    pub fn missing_logs(&self) -> Vec<[u8; 32]> {
        let me = self.identity.as_ref().map(|i| i.id());
        let contacts = self.contacts().into_iter().map(|c| c.identity);
        // And the members of the spaces here, whose writes their logs judge.
        let members = self
            .spaces
            .values()
            .filter_map(|h| h.space.as_ref())
            .flat_map(|s| s.validity().members.iter().map(|m| m.identity));
        let mut out: Vec<[u8; 32]> = Vec::new();
        for who in contacts.chain(members) {
            if Some(who) == me || self.others.contains_key(&who) {
                continue;
            }
            let label = identity_log_label(&who);
            if !out.contains(&label) {
                out.push(label);
            }
        }
        out
    }

    /// Whether `identity` is a member of the space `label` who has not left
    /// it, or `label` is this person's log, which every contact is entitled
    /// to. Nothing more of a space is sent to someone who left it
    /// (`spaces.md#members-and-roles`).
    pub fn shares(&self, identity: &[u8; 32], label: &[u8; 32]) -> bool {
        if Some(*label) == self.identity_label() {
            return self.others.contains_key(identity);
        }
        let open = self.spaces.get(label).and_then(|h| h.space.as_ref());
        open.is_some_and(|s| s.role_of(identity).is_some() && !s.has_left(identity))
    }

    /// Whether `label` is a space `identity` offered this person that is not
    /// open here yet: what they send of it is taken, so it can be opened, and
    /// nothing of it goes back, since an offer can name any space at all.
    pub fn offered_here(&self, identity: &[u8; 32], label: &[u8; 32]) -> bool {
        let open = self.spaces.get(label).is_some_and(|h| h.space.is_some());
        !open && self.offers_from(identity).iter().any(|o| o.space == *label)
    }

    /// Whether `identity`'s log, as held here, has this device in it.
    pub fn has_device(&self, identity: &[u8; 32], key: &[u8; 32], link: &[u8; 32]) -> bool {
        let Some(other) = self.others.get(identity) else {
            return false;
        };
        let state = other.log.state();
        let mut keys = state.keys.values();
        !state.frozen
            && keys
                .any(|k| k.key == *key && k.link_key.as_ref().is_some_and(|l| l.x25519() == link))
    }

    /// What a session with a contact may reconcile: this person's log and
    /// theirs, then the spaces they share (`spaces.md#holding-a-space`).
    pub fn labels_with(&self, identity: &[u8; 32]) -> Vec<[u8; 32]> {
        let mut v: Vec<[u8; 32]> = self.identity_label().into_iter().collect();
        v.push(identity_log_label(identity));
        v.extend(self.spaces.keys().filter(|l| self.shares(identity, l)));
        // An offered space not open here yet, to fetch from them.
        for o in self.offers_from(identity) {
            if !v.contains(&o.space) && self.offered_here(identity, &o.space) {
                v.push(o.space);
            }
        }
        // The other members' logs, for what they write to be judged.
        v.extend(
            self.members_shared_with(identity)
                .iter()
                .map(identity_log_label),
        );
        v
    }

    /// The logs of those whose devices may reach this one. The others are
    /// kept too, to judge what they write, but this device does not answer
    /// them (`contact.md#who-a-person-knows`).
    pub fn connectable_states(&self) -> Vec<Arc<cardinal_identity::IdentityState>> {
        self.contacts()
            .iter()
            .filter(|c| c.connects())
            .filter_map(|c| self.others.get(&c.identity))
            .map(|o| o.log.state())
            .collect()
    }

    /// Evaluates every identity log held, each with the others at hand.
    fn read_logs(&mut self) {
        let Some(ident) = self.identity.as_ref() else {
            self.logs.clear();
            return;
        };
        let mut logs = vec![&ident.log];
        logs.extend(self.others.values().map(|o| &o.log));
        let states = cardinal_identity::log::evaluate_together(&logs);
        self.logs = states.into_iter().map(Arc::new).collect();
    }

    /// After something was written or arrived in a space, or an identity
    /// log changed: the keys of the members a new epoch would be wrapped
    /// for, and whether one is due because of them. It is wrapped for every
    /// member but this one who has not left, and whom this device does not
    /// know to be frozen (`spaces.md#distribution`).
    fn settle(&mut self, space: &SpaceId) {
        let Some(ident) = self.identity.as_ref() else {
            return;
        };
        let Some(h) = self.spaces.get_mut(space) else {
            return;
        };
        let Some(sp) = h.space.as_ref() else {
            return;
        };
        let state = |who: &[u8; 32]| self.logs.iter().find(|st| st.identity == *who);
        h.member_keys = sp
            .validity()
            .identities()
            .iter()
            .filter(|who| **who != ident.id() && !sp.has_left(who))
            .filter_map(state)
            .filter(|st| !st.frozen)
            .filter_map(|st| Some(st.encryption_key.as_ref()?.public.clone()))
            .collect();
        // Since the epoch reached this device: a member's key changed, a
        // member left, or it learned that one is frozen.
        let now = Reached::now(sp, &self.logs);
        let mut changed = false;
        for key in sp.keyring().iter() {
            // An epoch with no record reaches this device now.
            let id = hex::encode(key.id());
            if let std::collections::btree_map::Entry::Vacant(e) = h.reached.entry(id) {
                e.insert(now.clone());
                changed = true;
            }
        }
        let current = sp.current_epoch().map(hex::encode);
        let by_record = match current.and_then(|id| h.reached.get_mut(&id)) {
            Some(record) => {
                // Someone added since, or whose log came since, has the key
                // they had when this device first saw them with one.
                for (who, key) in &now.keys {
                    if !record.keys.contains_key(who) {
                        record.keys.insert(who.clone(), key.clone());
                        changed = true;
                    }
                }
                record.calls_for_a_new_epoch(&now)
            }
            None => false,
        };
        if changed {
            let saved = serde_json::to_vec(&h.reached)
                .map_err(std::io::Error::other)
                .and_then(|bytes| crate::paths::write_private(&h.reached_at, &bytes, 0o600));
            if let Err(e) = saved {
                tracing::warn!("space {}: keeping its epochs: {e}", short(space));
            }
        }
        // "A writer does not encrypt under an epoch started by a member it
        // would leave out."
        let out = |who: &[u8; 32]| sp.has_left(who) || state(who).is_some_and(|st| st.frozen);
        let theirs = |(_, who): (EntryId, [u8; 32])| who != ident.id() && out(&who);
        // Two reasons need no record, and are the same on every device
        // that holds the same entries.
        let by_entries = sp.left_since_epoch() || sp.added_beside_epoch();
        h.leave_out = by_record || by_entries || sp.epoch_started_by().is_some_and(theirs);
    }

    /// After an identity log changed: every space judges again the entries
    /// of the authors whose keys count differently now, and what rests on
    /// them. Nothing else in a space is looked at.
    fn settle_all(&mut self) {
        self.read_logs();
        self.judge_all();
    }

    /// Gives every space the identity logs as they are read now.
    fn judge_all(&mut self) {
        let spaces: Vec<SpaceId> = self.spaces.keys().copied().collect();
        for space in &spaces {
            if let Some(h) = self.spaces.get_mut(space) {
                if let Some(sp) = h.space.as_mut() {
                    sp.set_identities(self.logs.iter().cloned());
                    h.version += 1;
                }
            }
            self.settle(space);
        }
    }

    /// Creates a relationship space with `other`, whose log this device must
    /// hold: a genesis wrapped for both (`contact.md#accepting`). Returns its
    /// id and the sealed genesis.
    pub fn create_relationship(&mut self, other: &[u8; 32]) -> anyhow::Result<(SpaceId, Vec<u8>)> {
        let ident = self
            .identity
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("this device has no identity yet"))?;
        let theirs = self
            .others
            .get(other)
            .and_then(|o| o.log.state().encryption_key.clone())
            .ok_or_else(|| anyhow::anyhow!("their identity log has no encryption key"))?;
        let mine = ident
            .enc
            .first()
            .ok_or_else(|| anyhow::anyhow!("no encryption key"))?
            .public_key()
            .clone();
        let (space, sealed) = Space::create_with(
            cardinal_space::Profile::RELATIONSHIP,
            cardinal_space::Policy::default(),
            &ident.log,
            &self.keys.device.signing,
            &[&mine, &theirs.public],
            cardinal_space::relationship::genesis_ops(ident.id(), *other),
            Some(now_ms()),
        )?;
        let id = space.id();
        let bytes = sealed.encode();
        self.ingest_space(id, std::slice::from_ref(&bytes))?;
        Ok((id, bytes))
    }

    /// The current encryption key of an identity whose log this device holds.
    pub fn encryption_key_of(&self, who: &[u8; 32]) -> anyhow::Result<HybridPublicKey> {
        let other = self.others.get(who);
        let key = other.and_then(|o| o.log.state().encryption_key.clone());
        Ok(key
            .ok_or_else(|| anyhow::anyhow!("their identity log has no encryption key"))?
            .public)
    }

    /// Makes a group of this person, as its owner, and `members`, each with
    /// the name the others see (`profiles.md#group`). Returns its id.
    pub fn create_group(
        &mut self,
        name: &str,
        me_as: &str,
        members: &[([u8; 32], String)],
    ) -> anyhow::Result<SpaceId> {
        use cardinal_space::group;
        let ident = self
            .identity
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("this device has no identity yet"))?;
        let mine = ident
            .enc
            .first()
            .ok_or_else(|| anyhow::anyhow!("no encryption key"))?
            .public_key()
            .clone();
        let mut keys = vec![mine];
        let mut ops = group::genesis_ops(ident.id(), name);
        for (who, _) in members {
            keys.push(self.encryption_key_of(who)?);
            ops.push(SpaceOp::add_member(*who, group::WRITER));
        }
        ops.push(group::create_member(&ident.id(), me_as, true));
        for (who, shown) in members {
            ops.push(group::create_member(who, shown, true));
        }
        let refs: Vec<&HybridPublicKey> = keys.iter().collect();
        let (space, sealed) = Space::create_with(
            group::GROUP,
            cardinal_space::Policy::default(),
            &ident.log,
            &self.keys.device.signing,
            &refs,
            ops,
            Some(now_ms()),
        )?;
        let id = space.id();
        self.ingest_space(id, &[sealed.encode()])?;
        Ok(id)
    }

    /// Adds `members` to a group, each with the name the others see.
    /// Returns the sealed bytes.
    pub fn add_to_group(
        &mut self,
        space: &SpaceId,
        members: &[([u8; 32], String)],
    ) -> anyhow::Result<Vec<u8>> {
        let mut added = Vec::new();
        for (who, _) in members {
            added.push((*who, self.encryption_key_of(who)?));
        }
        let ops = members
            .iter()
            .map(|(who, shown)| cardinal_space::group::create_member(who, shown, true))
            .collect();
        let ident = self
            .identity
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("this device has no identity yet"))?;
        let h = self
            .spaces
            .get_mut(space)
            .ok_or_else(|| anyhow::anyhow!("space not held"))?;
        let bytes = h.add_members(ident, &self.keys, &added, ops)?;
        self.settle(space);
        Ok(bytes)
    }

    /// The spaces offered to this person by `identity`, in the relationship
    /// space with them, that they have not declined (`spaces.md#holding-a-space`).
    pub fn offers_from(&self, identity: &[u8; 32]) -> Vec<cardinal_space::group::Offer> {
        let contacts = self.contacts();
        let Some(c) = contacts.iter().find(|c| c.identity == *identity) else {
            return Vec::new();
        };
        let Some(open) = self.spaces.get(&c.space).and_then(|h| h.space.as_ref()) else {
            return Vec::new();
        };
        let declined = self.declined();
        cardinal_space::group::offers(open.state())
            .into_iter()
            .filter(|o| o.from == *identity && !declined.contains(&o.space))
            .collect()
    }

    /// The spaces this person said no to.
    pub fn declined(&self) -> Vec<SpaceId> {
        let Some(acc) = self.account().and_then(|a| a.space.as_ref()) else {
            return Vec::new();
        };
        account::spaces(acc.state())
            .into_iter()
            .filter(|s| s.declined)
            .map(|s| s.space)
            .collect()
    }

    /// The members of the spaces this device holds that are shared with
    /// `identity`, other than the two of them: whose logs a member device
    /// reconciles with whoever it is connected to (`spaces.md#holding-a-space`).
    pub fn members_shared_with(&self, identity: &[u8; 32]) -> Vec<[u8; 32]> {
        let me = self.identity.as_ref().map(|i| i.id());
        let mut out: Vec<[u8; 32]> = Vec::new();
        for h in self.spaces.values() {
            let Some(sp) = h.space.as_ref() else {
                continue;
            };
            if sp.role_of(identity).is_none() || sp.has_left(identity) {
                continue;
            }
            for m in sp.validity().identities() {
                if m != *identity && Some(m) != me && !out.contains(&m) {
                    out.push(m);
                }
            }
        }
        out
    }

    /// Takes a relationship space with `inviter` from its sealed genesis.
    /// Returns its id. Anyone can seal a genesis to a public key, so what
    /// it is has to be read off it first: taken unread, it could stand in for
    /// the account space, or open a space this person already has.
    pub fn accept_relationship(
        &mut self,
        genesis: &[u8],
        inviter: &[u8; 32],
    ) -> anyhow::Result<SpaceId> {
        let ident = self
            .identity
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("this device has no identity yet"))?;
        let their_log = &self
            .others
            .get(inviter)
            .ok_or_else(|| anyhow::anyhow!("their identity log is not here"))?
            .log;
        let sealed = SealedEntry::decode(genesis)?;
        let mut space = Space::open_genesis(&sealed, &ident.key_refs(), None)?;
        let id = space.id();
        space.set_identities([ident.log.state(), their_log.state()]);
        // What the invitee must check before keeping it
        // (`contact.md#accepting`): a genesis that is valid by the
        // inviter's log, with the relationship profile and exactly two
        // `add_member` ops, one naming each of these two identities as a
        // writer; and a space it does not already hold.
        use cardinal_space::entry::WRITER;
        use cardinal_space::SpaceOpBody;
        let genesis_entry = space.entry(&id);
        let ops = genesis_entry.map_or(&[][..], |e| e.ops());
        let mut adds: Vec<([u8; 32], u64)> = ops
            .iter()
            .filter_map(|op| match op.body() {
                SpaceOpBody::AddMember { identity, role, .. } => Some((*identity, *role)),
                _ => None,
            })
            .collect();
        adds.sort();
        let mut the_two = [(ident.id(), WRITER), (*inviter, WRITER)];
        the_two.sort();
        anyhow::ensure!(
            space.validity().is_valid(&id)
                && space.creator() == *inviter
                && space.profile() == cardinal_space::Profile::RELATIONSHIP
                && adds == the_two
                && !self.spaces.contains_key(&id),
            "that is not a space between the two of you"
        );
        self.ingest_space(id, &[genesis.to_vec()])?;
        Ok(id)
    }

    fn build_identity(
        file: AppendLog,
        records: Vec<(Loc, Vec<u8>)>,
        keys: &Keys,
    ) -> anyhow::Result<Identity> {
        let mut entries = Vec::new();
        let mut locs = HashMap::new();
        for (loc, b) in records {
            let e = IdentityEntry::decode(&b)?;
            locs.insert(e.id(), loc);
            entries.push(e);
        }
        let gi = entries
            .iter()
            .position(|e| e.is_genesis())
            .ok_or_else(|| anyhow::anyhow!("the identity log has no genesis entry"))?;
        let g = entries.remove(gi);
        let mut log = IdentityLog::from_genesis(g)?;
        for e in entries {
            let _ = log.insert(e);
        }
        let mut set = MemSet::new();
        for id in locs.keys() {
            set.insert(*id);
        }
        let mut id = Identity {
            log,
            enc: Vec::new(),
            file,
            locs,
            set,
        };
        id.refresh_keys(keys);
        Ok(id)
    }

    /// Paths.
    pub fn paths(&self) -> &Paths {
        &self.paths
    }

    /// Opens or creates the holder of a space.
    pub fn open_space(&mut self, id: SpaceId) -> anyhow::Result<&mut Holder> {
        if !self.spaces.contains_key(&id) {
            let ident = self
                .identity
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("no identity"))?;
            let h = Holder::open(&self.paths, id, &ident.key_refs(), &self.logs)?;
            self.spaces.insert(id, h);
        }
        Ok(self.spaces.get_mut(&id).expect("inserted"))
    }

    /// After the identity log changed (received or written here): reopen
    /// the encryption keys, and have every space judge again what this
    /// identity signed.
    pub fn identity_updated(&mut self) {
        let Some(ident) = self.identity.as_mut() else {
            return;
        };
        ident.refresh_keys(&self.keys);
        let keys: Vec<HybridKeyPair> = ident
            .enc
            .iter()
            .map(|k| HybridKeyPair::from_secret_bytes(&k.secret_bytes()))
            .collect();
        let refs: Vec<&HybridKeyPair> = keys.iter().collect();
        self.read_logs();
        for h in self.spaces.values_mut() {
            if h.space.is_some() {
                // A rotation can arrive before the key it is wrapped for.
                h.open_pending(&refs);
                h.version += 1;
            } else {
                h.rebuild(Vec::new(), &refs, &self.logs);
            }
        }
        self.judge_all();
    }

    /// Installs an identity on a device that has none: one freshly created
    /// (`cardinal init`), or one this device was paired into or restored.
    /// This is where a store is made, so the format marker is written here,
    /// before anything else (`format.rs`).
    pub fn install_identity(&mut self, log_entries: &[Vec<u8>]) -> anyhow::Result<()> {
        crate::format::check(&self.paths)?;
        crate::format::write(&self.paths)?;
        {
            let (mut file, existing) = AppendLog::open(&self.paths.identity_log())?;
            if !existing.is_empty() {
                anyhow::bail!("this device already has an identity");
            }
            let refs: Vec<&[u8]> = log_entries.iter().map(|b| b.as_slice()).collect();
            file.append_many(&refs)?;
        }
        let (file, records) = AppendLog::open(&self.paths.identity_log())?;
        self.identity = Some(Self::build_identity(file, records, &self.keys)?);
        self.read_logs();
        Ok(())
    }

    /// The identity's sync label, if any.
    pub fn identity_label(&self) -> Option<[u8; 32]> {
        self.identity.as_ref().map(|i| i.label())
    }

    /// Whether `peer_x25519` is the link key of one of this person's
    /// devices in effect (not this one).
    pub fn is_own_device(&self, peer_x25519: &[u8; 32]) -> Option<KeyId> {
        let st = self.identity.as_ref()?.state();
        st.keys
            .values()
            .find(|k| k.link_key.as_ref().map(|l| l.x25519()) == Some(peer_x25519))
            .map(|k| k.key)
            .filter(|k| *k != self.keys.key())
    }

    /// The labels this device reconciles with its own devices: the
    /// identity log first, then every space.
    pub fn labels(&self) -> Vec<[u8; 32]> {
        let mut v = Vec::new();
        if let Some(l) = self.identity_label() {
            v.push(l);
            v.extend(
                self.contacts()
                    .iter()
                    .map(|c| identity_log_label(&c.identity)),
            );
            let me = self.identity.as_ref().map(|i| i.id());
            let members = self
                .spaces
                .values()
                .filter_map(|h| h.space.as_ref())
                .flat_map(|s| s.validity().members.iter().map(|m| m.identity));
            for m in members.filter(|m| Some(*m) != me) {
                let l = identity_log_label(&m);
                if !v.contains(&l) {
                    v.push(l);
                }
            }
            v.extend(self.spaces.keys().copied());
        }
        v
    }

    fn other(&self, label: &[u8; 32]) -> Option<&OtherLog> {
        self.others
            .values()
            .find(|o| identity_log_label(&o.log.id()) == *label)
    }

    /// The set behind a label, cloned (empty if not held).
    pub fn set(&self, label: &[u8; 32]) -> MemSet {
        if Some(*label) == self.identity_label() {
            return self.identity.as_ref().expect("identity").set.clone();
        }
        if let Some(o) = self.other(label) {
            return o.set.clone();
        }
        self.spaces
            .get(label)
            .map(|h| h.set.clone())
            .unwrap_or_default()
    }

    /// One object of a set.
    pub fn get(&self, label: &[u8; 32], id: &[u8; 32]) -> Option<Vec<u8>> {
        if Some(*label) == self.identity_label() {
            return self.identity.as_ref()?.get(id);
        }
        if let Some(o) = self.other(label) {
            return o.get(id);
        }
        self.spaces.get(label)?.get(id)
    }

    /// Whether a set holds an id.
    pub fn has(&self, label: &[u8; 32], id: &[u8; 32]) -> bool {
        if Some(*label) == self.identity_label() {
            return self
                .identity
                .as_ref()
                .is_some_and(|i| i.set.contains_id(id));
        }
        if let Some(o) = self.other(label) {
            return o.set.contains_id(id);
        }
        self.spaces
            .get(label)
            .is_some_and(|h| h.set.contains_id(id))
    }

    /// Whether objects of a set wait for parents this device lacks.
    pub fn is_waiting(&self, label: &[u8; 32]) -> bool {
        if Some(*label) == self.identity_label() {
            return self.identity.as_ref().is_some_and(|i| i.log.is_waiting());
        }
        if let Some(o) = self.other(label) {
            return o.log.is_waiting();
        }
        self.spaces.get(label).is_some_and(|h| h.is_waiting())
    }

    /// The latest objects of a set, as a `heads` notice names them.
    pub fn heads(&self, label: &[u8; 32]) -> Vec<[u8; 32]> {
        if Some(*label) == self.identity_label() {
            return self
                .identity
                .as_ref()
                .map(|i| i.log.heads())
                .unwrap_or_default();
        }
        if let Some(o) = self.other(label) {
            return o.log.heads();
        }
        self.spaces
            .get(label)
            .map(|h| h.head_ids())
            .unwrap_or_default()
    }

    /// Adds identity entries. Before this device belongs to an identity,
    /// entries of `expected` (the identity of the device it paired with)
    /// are collected until they include an `add_key` of this device.
    pub fn ingest_identity(
        &mut self,
        objects: &[Vec<u8>],
        expected: Option<[u8; 32]>,
    ) -> anyhow::Result<IdentityChange> {
        if let Some(ident) = self.identity.as_mut() {
            let changed = ident.ingest(objects)?;
            if changed {
                self.identity_updated();
            }
            return Ok(IdentityChange {
                changed,
                joined: false,
            });
        }
        let Some(expected) = expected else {
            return Ok(IdentityChange::default());
        };
        self.joining.extend(objects.iter().cloned());
        let entries: Vec<IdentityEntry> = self
            .joining
            .iter()
            .filter_map(|b| IdentityEntry::decode(b).ok())
            .filter(|e| e.identity() == expected)
            .collect();
        let Some(g) = entries.iter().find(|e| e.is_genesis()) else {
            return Ok(IdentityChange::default());
        };
        let mut log = IdentityLog::from_genesis(g.clone())?;
        for e in &entries {
            if !e.is_genesis() {
                let _ = log.insert(e.clone());
            }
        }
        if !log.state().keys.contains_key(&self.keys.key()) {
            return Ok(IdentityChange::default());
        }
        let bytes: Vec<Vec<u8>> = log.entries().map(|e| e.encode()).collect();
        self.install_identity(&bytes)?;
        self.joining.clear();
        tracing::info!(
            "joined identity {} as a device",
            short(&self.identity.as_ref().expect("installed").id())
        );
        Ok(IdentityChange {
            changed: true,
            joined: true,
        })
    }

    /// Restoring (`hosts.md#restore`): the entry that adds this device, as
    /// an admin device, to the log of `identity` collected from a host,
    /// signed by the root key from the words. Returns it and its id.
    pub fn add_restoring_device(
        &self,
        identity: &[u8; 32],
        phrase: &cardinal_crypto::RecoveryPhrase,
    ) -> anyhow::Result<(Vec<u8>, [u8; 32])> {
        let entries: Vec<IdentityEntry> = self
            .joining
            .iter()
            .filter_map(|b| IdentityEntry::decode(b).ok())
            .filter(|e| e.identity() == *identity)
            .collect();
        let g = entries
            .iter()
            .find(|e| e.is_genesis())
            .ok_or_else(|| anyhow::anyhow!("that device did not send the identity log"))?;
        let mut log = IdentityLog::from_genesis(g.clone())?;
        for e in entries.iter().filter(|e| !e.is_genesis()) {
            let _ = log.insert(e.clone());
        }
        let root = phrase.root_signing_key();
        if log.state().power(&root.public_key()) != Some(cardinal_identity::Power::Root) {
            anyhow::bail!("these recovery words are not in that device's identity log");
        }
        let enc = log.open_with_phrase(phrase)?;
        let request = self
            .keys
            .device
            .request(identity, cardinal_identity::Power::Admin);
        let entry = log.add_key(&root, &request, Some(&enc))?;
        Ok((entry.encode(), entry.id()))
    }

    /// Adds sealed entries of a space, creating the holder if needed.
    pub fn ingest_space(
        &mut self,
        space: SpaceId,
        objects: &[Vec<u8>],
    ) -> anyhow::Result<Ingested> {
        let ident = self
            .identity
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no identity"))?;
        let keys: Vec<HybridKeyPair> = ident
            .enc
            .iter()
            .map(|k| HybridKeyPair::from_secret_bytes(&k.secret_bytes()))
            .collect();
        let refs: Vec<&HybridKeyPair> = keys.iter().collect();
        self.open_space(space)?;
        let h = self.spaces.get_mut(&space).expect("open");
        let out = h.ingest(objects, &refs, &self.logs);
        self.settle(&space);
        out
    }

    /// Writes ops to a space. Returns the entries written.
    pub fn write(
        &mut self,
        space: &SpaceId,
        ops: Vec<SpaceOp>,
    ) -> anyhow::Result<Vec<(EntryId, Vec<u8>)>> {
        let ident = self
            .identity
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("this device has no identity yet"))?;
        let h = self
            .spaces
            .get_mut(space)
            .ok_or_else(|| anyhow::anyhow!("space not held"))?;
        let written = h.write(ident, &self.keys, ops);
        self.settle(space);
        written
    }

    /// Writes exactly one entry with `ops`.
    pub fn write_entry(
        &mut self,
        space: &SpaceId,
        ops: Vec<SpaceOp>,
    ) -> anyhow::Result<(EntryId, Vec<u8>)> {
        let ident = self
            .identity
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("this device has no identity yet"))?;
        let h = self
            .spaces
            .get_mut(space)
            .ok_or_else(|| anyhow::anyhow!("space not held"))?;
        let written = h.write_one(ident, &self.keys, ops);
        self.settle(space);
        written
    }

    /// The addresses a host's grant gives for a device, leaving out names.
    pub fn host_addresses(&self, device: &KeyId) -> Vec<std::net::SocketAddr> {
        let Some(space) = self.account().and_then(|a| a.space.as_ref()) else {
            return Vec::new();
        };
        cardinal_space::account::hosts(space.state())
            .iter()
            .filter_map(|h| cardinal_space::grant::Grant::open(&h.grant))
            .filter(|(_, signer)| signer == device)
            .flat_map(|(g, _)| g.endpoints)
            .filter_map(|e| e.socket_addr())
            .collect()
    }

    /// Where a contact's device that is one of their hosts listens, from the
    /// reach nodes they wrote: what a person with no host of their own stays
    /// in touch with (`hosts.md#staying-reachable`).
    pub fn contact_host_addresses(&self, device: &KeyId) -> Vec<std::net::SocketAddr> {
        for c in self.contacts() {
            let Some(o) = self.others.get(&c.identity) else {
                continue;
            };
            let st = o.log.state();
            let Some(link) = st.keys.get(device).and_then(|k| k.link_key.clone()) else {
                continue;
            };
            let reach = self.reach_of(&c.space, &c.identity);
            return reach
                .iter()
                .filter(|r| r.host == *link.x25519())
                .flat_map(|r| r.endpoints.iter().filter_map(|e| e.socket_addr()))
                .collect();
        }
        Vec::new()
    }

    /// Whether this device has heard that it was removed.
    pub fn removed(&self) -> bool {
        self.identity
            .as_ref()
            .is_some_and(|i| i.state().power(&self.keys.key()).is_none())
    }

    /// How many entries by the removed `key`, in all spaces, do not count.
    pub fn unwitnessed_by(&self, key: &KeyId) -> usize {
        self.spaces
            .values()
            .filter_map(|h| h.space.as_ref())
            .map(|s| s.unwitnessed_by(key))
            .sum()
    }

    /// Keeps what `key` wrote in a space ([`Holder::witness`]).
    pub fn witness(&mut self, space: &SpaceId, key: &KeyId) -> anyhow::Result<Option<Vec<u8>>> {
        let ident = self
            .identity
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("this device has no identity yet"))?;
        let h = self
            .spaces
            .get_mut(space)
            .ok_or_else(|| anyhow::anyhow!("space not held"))?;
        let written = h.witness(ident, &self.keys, key);
        self.settle(space);
        written
    }

    /// Starts a new epoch in a space if one is due
    /// ([`Holder::rotate_if_due`]).
    pub fn rotate_if_due(&mut self, space: &SpaceId) -> anyhow::Result<Option<Vec<u8>>> {
        let ident = self
            .identity
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("this device has no identity yet"))?;
        let h = self
            .spaces
            .get_mut(space)
            .ok_or_else(|| anyhow::anyhow!("space not held"))?;
        let written = h.rotate_if_due(ident, &self.keys);
        self.settle(space);
        written
    }

    /// Writes one entry with `ops` concurrent with `exclude`
    /// ([`Holder::write_concurrent`]).
    pub fn write_entry_concurrent(
        &mut self,
        space: &SpaceId,
        exclude: &[EntryId],
        ops: Vec<SpaceOp>,
    ) -> anyhow::Result<(EntryId, Vec<u8>)> {
        let ident = self
            .identity
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("this device has no identity yet"))?;
        let h = self
            .spaces
            .get_mut(space)
            .ok_or_else(|| anyhow::anyhow!("space not held"))?;
        let written = h.write_concurrent(ident, &self.keys, exclude, ops);
        self.settle(space);
        written
    }

    /// The account space, once held and open.
    pub fn account(&self) -> Option<&Holder> {
        self.spaces
            .values()
            .find(|h| h.profile() == Some(Profile::ACCOUNT))
    }

    /// The account space id.
    pub fn account_id(&self) -> Option<SpaceId> {
        self.account().map(|h| h.id)
    }

    /// The files space: the one the account space lists first, else any
    /// files space held.
    pub fn files_id(&self) -> Option<SpaceId> {
        if let Some(acc) = self.account().and_then(|h| h.space.as_ref()) {
            for rec in account::spaces(acc.state()) {
                if self
                    .spaces
                    .get(&rec.space)
                    .and_then(|h| h.profile())
                    .is_some_and(|p| p == Profile::FILES)
                {
                    return Some(rec.space);
                }
            }
        }
        self.spaces
            .values()
            .find(|h| h.profile() == Some(Profile::FILES))
            .map(|h| h.id)
    }

    /// Device names from the account space.
    pub fn device_names(&self) -> HashMap<KeyId, String> {
        let mut m = HashMap::new();
        if let Some(acc) = self.account().and_then(|h| h.space.as_ref()) {
            for d in account::devices(acc.state()) {
                m.insert(d.key, d.name);
            }
        }
        m
    }

    /// The discovery secret from the account space.
    pub fn discovery_secret(&self) -> Option<[u8; 32]> {
        let acc = self.account()?.space.as_ref()?;
        acc.state()
            .children(&ROOT)
            .into_iter()
            .filter(|n| n.kind == NodeKind::Uint(account::SECRET) && !n.deleted)
            .find(|n| n.field(1).and_then(|v| v.as_text()) == Some(DISCOVERY_PURPOSE))
            .and_then(|n| n.field(2)?.as_bytes()?.try_into().ok())
    }
}

/// `create` of a secret node in the account space.
pub fn create_secret(purpose: &str, value: &[u8]) -> SpaceOp {
    SpaceOp::create(
        NodeKind::Uint(account::SECRET),
        ROOT,
        purpose,
        Record::new().with(1, purpose).with(2, value.to_vec()),
    )
}

/// Whether a path holds an identity already.
pub fn has_identity(paths: &Paths) -> bool {
    paths.identity_log().exists()
        && std::fs::metadata(paths.identity_log()).is_ok_and(|m| m.len() > 0)
}

/// Removes a directory's contents if it exists.
pub fn clear_dir(p: &Path) -> std::io::Result<()> {
    if p.exists() {
        std::fs::remove_dir_all(p)?;
    }
    std::fs::create_dir_all(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::setup;
    use cardinal_space::entry::{ADMIN, OWNER, READER, WRITER};
    use cardinal_space::{group, relationship, Member, Policy};

    /// A person with one device, as `cardinal init` leaves it.
    struct Person {
        _dir: tempfile::TempDir,
        core: Core,
        /// The key of their recovery words, which nobody's device holds.
        root: cardinal_crypto::SigningKey,
    }

    impl Person {
        fn new() -> Person {
            let dir = tempfile::tempdir().unwrap();
            let paths = Paths::at(dir.path());
            let p = setup::prepare(&paths).unwrap();
            let root = p.phrase().root_signing_key();
            setup::install(&paths, p, &Config::default()).unwrap();
            let keys = Arc::new(Keys::load_or_create(&paths.device_key()).unwrap());
            let core = Core::load(&paths, keys).unwrap();
            Person {
                _dir: dir,
                core,
                root,
            }
        }

        fn id(&self) -> [u8; 32] {
            self.core.identity.as_ref().unwrap().id()
        }

        fn log(&self) -> Vec<Vec<u8>> {
            self.core.identity.as_ref().unwrap().all_entries()
        }

        fn enc(&self) -> HybridPublicKey {
            let ident = self.core.identity.as_ref().unwrap();
            ident.enc.first().unwrap().public_key().clone()
        }

        /// Takes another person's identity log, as an invitation does.
        fn meets(&mut self, other: &Person) {
            self.core.ingest_other(other.id(), &other.log()).unwrap();
        }

        /// A genesis this person writes, of `profile`, naming `members`.
        fn genesis(&self, profile: Profile, members: &[([u8; 32], u64)], to: &Person) -> Vec<u8> {
            let ident = self.core.identity.as_ref().unwrap();
            let mut ops: Vec<SpaceOp> = members
                .iter()
                .map(|(who, role)| SpaceOp::add_member(*who, *role))
                .collect();
            ops.extend(relationship::genesis_ops(self.id(), to.id()).split_off(2));
            let (_, sealed) = Space::create_with(
                profile,
                Policy::default(),
                &ident.log,
                &self.core.keys.device.signing,
                &[&self.enc(), &to.enc()],
                ops,
                Some(now_ms()),
            )
            .unwrap();
            sealed.encode()
        }

        fn space(&self, id: &SpaceId) -> &Space {
            self.core.spaces[id].space.as_ref().unwrap()
        }

        fn says(&mut self, space: &SpaceId, text: &str) -> Vec<u8> {
            let c = relationship::conversation(self.space(space)).unwrap();
            let op = relationship::create_message(c, text);
            self.core.write_entry(space, vec![op]).unwrap().1
        }

        fn said(&self, space: &SpaceId) -> Vec<String> {
            let all = relationship::messages(self.space(space));
            all.into_iter().map(|m| m.text).collect()
        }
    }

    #[test]
    fn a_relationship_names_both_as_writers_and_no_owner() {
        let (mut ana, mut bo) = (Person::new(), Person::new());
        ana.meets(&bo);
        bo.meets(&ana);
        let (id, genesis) = ana.core.create_relationship(&bo.id()).unwrap();
        assert_eq!(
            bo.core.accept_relationship(&genesis, &ana.id()).unwrap(),
            id
        );
        let mut the_two = [ana.id(), bo.id()].map(|identity| Member {
            identity,
            role: WRITER,
        });
        the_two.sort();
        for p in [&ana, &bo] {
            let sp = p.space(&id);
            assert_eq!(sp.profile(), Profile::RELATIONSHIP);
            assert_eq!(sp.owner(), None);
            assert_eq!(sp.members(), the_two);
        }
        // What each writes counts for the other, judged as it arrives.
        let hello = ana.says(&id, "hello");
        bo.core.ingest_space(id, &[hello]).unwrap();
        let back = bo.says(&id, "hello yourself");
        ana.core.ingest_space(id, &[back]).unwrap();
        assert_eq!(ana.said(&id), ["hello", "hello yourself"]);
        assert_eq!(bo.said(&id), ana.said(&id));
        // Neither can add anyone: there is no admin, and nobody to make one.
        let stranger = SpaceOp::add_member([7; 32], READER);
        let (added, sealed) = ana.core.write_entry(&id, vec![stranger]).unwrap();
        bo.core.ingest_space(id, &[sealed]).unwrap();
        for p in [&ana, &bo] {
            assert!(!p.space(&id).validity().is_valid(&added));
            assert_eq!(p.space(&id).members(), the_two);
        }
        // And what was written beside that still reaches both.
        let more = bo.says(&id, "still here");
        ana.core.ingest_space(id, &[more]).unwrap();
        assert_eq!(ana.said(&id).len(), 3);
        // What a restart loads is what was held.
        let paths = ana.core.paths().clone();
        let again = Core::load(&paths, ana.core.keys.clone()).unwrap();
        let sp = again.spaces[&id].space.as_ref().unwrap();
        assert_eq!(sp.validity().valid, ana.space(&id).validity().valid);
        assert_eq!(sp.members(), the_two);
    }

    #[test]
    fn the_invitee_keeps_only_a_space_between_the_two_of_them() {
        let (mut ana, mut bo, mut cy) = (Person::new(), Person::new(), Person::new());
        ana.meets(&bo);
        bo.meets(&ana);
        bo.meets(&cy);
        cy.meets(&bo);
        let (a, b, c) = (ana.id(), bo.id(), cy.id());
        let rel = Profile::RELATIONSHIP;
        // Anyone can seal a genesis to a public key. Each of these is a
        // space Ana could make, and none is a relationship with Bo.
        let not_theirs: [(&str, Vec<u8>); 10] = [
            (
                "an owner",
                ana.genesis(rel, &[(a, OWNER), (b, WRITER)], &bo),
            ),
            (
                "someone else in it",
                ana.genesis(rel, &[(a, WRITER), (b, WRITER), (c, READER)], &bo),
            ),
            (
                "the invitee only reads",
                ana.genesis(rel, &[(a, WRITER), (b, READER)], &bo),
            ),
            (
                "the inviter only reads",
                ana.genesis(rel, &[(a, READER), (b, WRITER)], &bo),
            ),
            (
                "a second role for one of them",
                ana.genesis(rel, &[(a, WRITER), (b, WRITER), (b, READER)], &bo),
            ),
            (
                "one of them named twice, which is three additions",
                ana.genesis(rel, &[(a, WRITER), (b, WRITER), (b, WRITER)], &bo),
            ),
            (
                "an admin and no owner, which starts nothing",
                ana.genesis(rel, &[(a, ADMIN), (b, WRITER)], &bo),
            ),
            (
                "the invitee is not in it",
                ana.genesis(rel, &[(a, WRITER), (c, WRITER)], &bo),
            ),
            (
                "another profile",
                ana.genesis(group::GROUP, &[(a, WRITER), (b, WRITER)], &bo),
            ),
            (
                "someone else wrote it",
                cy.genesis(rel, &[(a, WRITER), (b, WRITER)], &bo),
            ),
        ];
        let before = bo.core.spaces.len();
        for (what, genesis) in &not_theirs {
            let got = bo.core.accept_relationship(genesis, &a);
            assert!(got.is_err(), "kept a genesis with {what}");
            assert_eq!(bo.core.spaces.len(), before, "{what}");
        }
        // The one that is, is kept; and once only.
        let good = ana.genesis(rel, &[(a, WRITER), (b, WRITER)], &bo);
        let id = bo.core.accept_relationship(&good, &a).unwrap();
        assert!(bo.core.spaces.contains_key(&id));
        assert!(bo.core.accept_relationship(&good, &a).is_err());
        // Cy's own relationship with Bo is not Ana's to offer.
        let theirs = cy.genesis(rel, &[(c, WRITER), (b, WRITER)], &bo);
        assert!(bo.core.accept_relationship(&theirs, &a).is_err());
        assert!(bo.core.accept_relationship(&theirs, &c).is_ok());
    }

    impl Person {
        /// Everything this person holds of a space, as a device fetching it
        /// from theirs would get it.
        fn all_of(&self, space: &SpaceId) -> Vec<Vec<u8>> {
            let all = self.space(space).sealed_entries();
            all.map(|(_, s)| s.encode()).collect()
        }

        fn takes(&mut self, space: &SpaceId, entries: &[Vec<u8>]) {
            self.core.ingest_space(*space, entries).unwrap();
        }

        fn role(&self, space: &SpaceId, who: &Person) -> Option<u64> {
            self.space(space).role_of(&who.id())
        }
    }

    #[test]
    fn a_group_has_one_owner_and_its_admins_add() {
        let mut p = [Person::new(), Person::new(), Person::new()];
        for i in 0..3 {
            for j in 0..3 {
                if i != j {
                    let (log, id) = (p[j].log(), p[j].id());
                    p[i].core.ingest_other(id, &log).unwrap();
                }
            }
        }
        let [mut ana, mut bo, mut cy] = p;
        let bo_shown = [(bo.id(), "Bo".to_owned())];
        let g = ana
            .core
            .create_group("Garden club", "Ana", &bo_shown)
            .unwrap();
        bo.takes(&g, &ana.all_of(&g));
        for who in [&ana, &bo] {
            let sp = who.space(&g);
            // whoever made it owns it, and nobody else ever will
            assert_eq!(sp.owner(), Some(ana.id()));
            assert_eq!(who.role(&g, &ana), Some(OWNER));
            assert_eq!(who.role(&g, &bo), Some(WRITER));
        }
        // A writer adds nobody.
        let cy_shown = [(cy.id(), "Cy".to_owned())];
        let tried = bo.core.add_to_group(&g, &cy_shown).unwrap();
        ana.takes(&g, &[tried]);
        assert_eq!(ana.role(&g, &cy), None);
        assert_eq!(bo.role(&g, &cy), None);
        // The owner makes Bo an admin, and then Bo does.
        let admin = SpaceOp::add_member(bo.id(), ADMIN);
        let (_, made) = ana.core.write_entry(&g, vec![admin]).unwrap();
        bo.takes(&g, &[made]);
        let added = bo.core.add_to_group(&g, &cy_shown).unwrap();
        ana.takes(&g, &[added]);
        cy.takes(&g, &bo.all_of(&g));
        for who in [&ana, &bo, &cy] {
            assert_eq!(who.role(&g, &cy), Some(WRITER));
            assert_eq!(who.role(&g, &bo), Some(ADMIN));
        }
        // Nobody makes an owner, the owner included.
        let owner = ana.id();
        for (who, of) in [(&mut bo, cy.id()), (&mut ana, cy.id())] {
            let crown = SpaceOp::add_member(of, OWNER);
            let (id, _) = who.core.write_entry(&g, vec![crown]).unwrap();
            assert!(!who.space(&g).validity().is_valid(&id));
            assert_eq!(who.space(&g).owner(), Some(owner));
        }
        assert_eq!(ana.role(&g, &cy), Some(WRITER));
    }

    #[test]
    fn whoever_leaves_a_group_is_left_out_of_its_next_key() {
        let mut p = [Person::new(), Person::new(), Person::new()];
        for i in 0..3 {
            for j in 0..3 {
                if i != j {
                    let (log, id) = (p[j].log(), p[j].id());
                    p[i].core.ingest_other(id, &log).unwrap();
                }
            }
        }
        let [mut ana, mut bo, mut cy] = p;
        let both = [(bo.id(), "Bo".to_owned()), (cy.id(), "Cy".to_owned())];
        let g = ana.core.create_group("Garden club", "Ana", &both).unwrap();
        bo.takes(&g, &ana.all_of(&g));
        cy.takes(&g, &ana.all_of(&g));
        // Being added is an offer: Cy is in it once they write in it.
        assert!(!group::joined(cy.space(&g), &cy.id()));
        let hello = cy.says(&g, "hello");
        ana.takes(&g, std::slice::from_ref(&hello));
        bo.takes(&g, &[hello]);
        assert!(group::joined(cy.space(&g), &cy.id()));
        assert!(ana.core.shares(&cy.id(), &g));

        // Cy leaves. That is a statement: nothing stops being valid, and
        // Cy is still among those the group's entries name.
        let valid_before = ana.space(&g).validity().valid.len();
        let (leave, gone) = cy.core.write_entry(&g, vec![SpaceOp::leave()]).unwrap();
        ana.takes(&g, std::slice::from_ref(&gone));
        bo.takes(&g, &[gone]);
        for who in [&ana, &bo, &cy] {
            let sp = who.space(&g);
            assert!(sp.validity().is_valid(&leave));
            assert!(sp.has_left(&cy.id()) && !sp.has_left(&bo.id()));
            assert_eq!(who.role(&g, &cy), Some(WRITER));
            assert_eq!(sp.present().len(), 2);
            assert!(!group::joined(sp, &cy.id()));
        }
        assert_eq!(ana.space(&g).validity().valid.len(), valid_before + 1);
        // The others send Cy nothing more of it.
        assert!(!ana.core.shares(&cy.id(), &g) && !bo.core.shares(&cy.id(), &g));
        assert!(ana.core.shares(&bo.id(), &g));

        // Whoever writes next starts a new key, in that entry, and it is
        // not wrapped for Cy.
        let before = bo.space(&g).current_epoch();
        let after_cy = bo.says(&g, "after cy");
        let entry = *bo.space(&g).heads().first().unwrap();
        assert!(bo.space(&g).entry(&entry).unwrap().starts_epoch());
        assert_ne!(bo.space(&g).current_epoch(), before);
        ana.takes(&g, std::slice::from_ref(&after_cy));
        assert_eq!(ana.said(&g), ["hello", "after cy"]);
        cy.takes(&g, &[after_cy]);
        assert!(!cy.space(&g).dag().contains(&entry), "Cy opened it");
        assert_eq!(cy.said(&g), ["hello"]);
        // One new key is enough: the next entry is written under it.
        let more = ana.says(&g, "just us");
        let entry = *ana.space(&g).heads().first().unwrap();
        assert!(!ana.space(&g).entry(&entry).unwrap().starts_epoch());
        bo.takes(&g, std::slice::from_ref(&more));
        cy.takes(&g, &[more]);
        assert_eq!(bo.said(&g).len(), 3);
        assert_eq!(cy.said(&g), ["hello"]);

        // Added again, Cy is back: offered it again, with the key that is
        // current now, and in it once they write in it again.
        let again = [(cy.id(), "Cy".to_owned())];
        let added = ana.core.add_to_group(&g, &again).unwrap();
        bo.takes(&g, std::slice::from_ref(&added));
        cy.takes(&g, &[added]);
        for who in [&ana, &bo, &cy] {
            assert!(!who.space(&g).has_left(&cy.id()));
            assert!(!group::joined(who.space(&g), &cy.id()));
        }
        assert!(ana.core.shares(&cy.id(), &g));
        // history is shared, so Cy now reads what was written meanwhile
        assert_eq!(cy.said(&g), ["hello", "after cy", "just us"]);
        let back = cy.says(&g, "back");
        ana.takes(&g, &[back]);
        assert!(group::joined(ana.space(&g), &cy.id()));
        assert!(group::joined(cy.space(&g), &cy.id()));
    }

    /// Whom a reach node set in a space would tell where this person's
    /// hosts are, who has no host of theirs already: every other member
    /// still in it who is not a contact, or is one this person refused
    /// (`hosts.md#telling-others-where-to-reach-you`).
    #[test]
    fn whom_a_reach_node_would_tell() {
        use cardinal_space::account::{self, Regard};
        let mut p = [Person::new(), Person::new(), Person::new()];
        for i in 0..3 {
            for j in 0..3 {
                if i != j {
                    let (log, id) = (p[j].log(), p[j].id());
                    p[i].core.ingest_other(id, &log).unwrap();
                }
            }
        }
        let [mut ana, mut bo, mut cy] = p;
        let both = [(bo.id(), "Bo".to_owned()), (cy.id(), "Cy".to_owned())];
        let g = ana.core.create_group("Garden club", "Ana", &both).unwrap();
        bo.takes(&g, &ana.all_of(&g));
        cy.takes(&g, &ana.all_of(&g));
        // Bo knows nobody yet: both of the others would learn.
        let mut both = vec![ana.id(), cy.id()];
        both.sort();
        assert_eq!(bo.core.not_contacts_in(&g), both);
        // Ana becomes his contact. Being offered the group, and not yet
        // in it, Cy reads it all the same.
        let account = bo.core.account_id().unwrap();
        let contact = account::create_contact(&ana.id(), "Ana", &[7; 32], Regard::default());
        bo.core.write_entry(&account, vec![contact]).unwrap();
        assert_eq!(bo.core.not_contacts_in(&g), [cy.id()]);
        // Someone he refused is no contact for this, whatever else they are.
        let node = bo.core.contacts()[0].node;
        let refuse = account::set_field(node, account::REFUSED, true);
        bo.core.write_entry(&account, vec![refuse]).unwrap();
        assert_eq!(bo.core.not_contacts_in(&g), both);
        let unrefuse = account::set_field(node, account::REFUSED, false);
        bo.core.write_entry(&account, vec![unrefuse]).unwrap();
        // Whoever left is told nothing more.
        let (_, gone) = cy.core.write_entry(&g, vec![SpaceOp::leave()]).unwrap();
        bo.takes(&g, &[gone]);
        assert!(bo.core.not_contacts_in(&g).is_empty());
        // A space that is not here tells nobody anything.
        assert!(bo.core.not_contacts_in(&[9; 32]).is_empty());
    }

    impl Person {
        /// This person's recovery words are used twice, each time without
        /// knowing of the other: nobody can say whose hands their keys are
        /// in, and whoever holds both entries knows them to be frozen.
        fn recovers_twice(&self) -> Vec<Vec<u8>> {
            use cardinal_identity::entry::add_key_proof;
            use cardinal_identity::{EntryBuilder, IdentityOp, Power};
            let id = self.id();
            (0..2)
                .map(|_| {
                    let next = cardinal_crypto::RecoveryPhrase::generate();
                    let key = next.root_signing_key();
                    let proof = add_key_proof(&key, &id, Power::Root, None);
                    let recovery = next.recovery_key_pair();
                    EntryBuilder::new(id, &[id])
                        .op(IdentityOp::add_key(
                            key.public_key(),
                            Power::Root,
                            None,
                            Some(proof),
                            Some(recovery.public_key()),
                        ))
                        .op(IdentityOp::remove_key(self.root.public_key()))
                        .sign(&self.root)
                        .unwrap()
                        .encode()
                })
                .collect()
        }

        /// Starts a new epoch wrapped for `everyone`, whatever is due.
        fn begins_an_epoch(&mut self, space: &SpaceId, everyone: &[HybridPublicKey]) -> Vec<u8> {
            let ident = self.core.identity.as_ref().unwrap();
            let h = self.core.spaces.get_mut(space).unwrap();
            let to: Vec<&HybridPublicKey> = everyone.iter().collect();
            let space = h.space.as_mut().unwrap();
            let signing = &self.core.keys.device.signing;
            let (sealed, _) = space
                .rotate(&ident.log, signing, &to, vec![], Some(now_ms()))
                .unwrap();
            sealed.encode()
        }
    }

    #[test]
    fn someone_frozen_is_left_out_of_the_next_key() {
        let mut p = [Person::new(), Person::new(), Person::new()];
        for i in 0..3 {
            for j in 0..3 {
                if i != j {
                    let (log, id) = (p[j].log(), p[j].id());
                    p[i].core.ingest_other(id, &log).unwrap();
                }
            }
        }
        let [mut ana, mut bo, mut cy] = p;
        let both = [(bo.id(), "Bo".to_owned()), (cy.id(), "Cy".to_owned())];
        let g = ana.core.create_group("Garden club", "Ana", &both).unwrap();
        bo.takes(&g, &ana.all_of(&g));
        cy.takes(&g, &ana.all_of(&g));
        let hello = cy.says(&g, "hello");
        ana.takes(&g, std::slice::from_ref(&hello));
        bo.takes(&g, std::slice::from_ref(&hello));

        let id = cy.id();
        let twice = cy.recovers_twice();
        for who in [&mut ana, &mut bo] {
            assert!(who.core.ingest_other(id, &twice).unwrap());
            assert!(who.core.others[&id].log.state().frozen);
        }
        // Nothing Cy wrote is undone, and what Cy's keys write is judged
        // like anyone's.
        assert_eq!(ana.said(&g), ["hello"]);
        let again = cy.says(&g, "still me");
        ana.takes(&g, std::slice::from_ref(&again));
        bo.takes(&g, std::slice::from_ref(&again));
        assert_eq!(ana.said(&g), ["hello", "still me"]);

        // Cy's device starts a new epoch, wrapped for everyone. The others
        // knew of the freeze before it reached them, so nothing has
        // changed since by their account. Even so nobody writes under an
        // epoch that someone frozen began: whoever writes next starts
        // another, and Cy is left out of it.
        let everyone = [cy.enc(), ana.enc(), bo.enc()];
        let begun = cy.begins_an_epoch(&g, &everyone);
        ana.takes(&g, std::slice::from_ref(&begun));
        bo.takes(&g, std::slice::from_ref(&begun));
        let theirs = ana.space(&g).current_epoch();
        assert_eq!(theirs, cy.space(&g).current_epoch());
        let after = ana.says(&g, "without cy");
        let entry = *ana.space(&g).heads().first().unwrap();
        assert!(ana.space(&g).entry(&entry).unwrap().starts_epoch());
        assert_ne!(ana.space(&g).current_epoch(), theirs);
        bo.takes(&g, std::slice::from_ref(&after));
        assert_eq!(bo.said(&g), ["hello", "still me", "without cy"]);
        cy.takes(&g, std::slice::from_ref(&after));
        assert!(!cy.space(&g).dag().contains(&entry), "Cy opened it");
        // and one new epoch is enough
        let more = bo.says(&g, "just us");
        let entry = *bo.space(&g).heads().first().unwrap();
        assert!(!bo.space(&g).entry(&entry).unwrap().starts_epoch());
        ana.takes(&g, std::slice::from_ref(&more));
        assert_eq!(ana.said(&g).len(), 4);
    }

    /// `spaces.md#when-to-rotate`: a writer starts a new epoch when it has
    /// learned that a member is frozen since the current one reached it.
    #[test]
    fn learning_that_someone_is_frozen_calls_for_a_new_epoch() {
        let mut p = [Person::new(), Person::new(), Person::new()];
        for i in 0..3 {
            for j in 0..3 {
                if i != j {
                    let (log, id) = (p[j].log(), p[j].id());
                    p[i].core.ingest_other(id, &log).unwrap();
                }
            }
        }
        let [mut ana, mut bo, mut cy] = p;
        let both = [(bo.id(), "Bo".to_owned()), (cy.id(), "Cy".to_owned())];
        let g = ana.core.create_group("Garden club", "Ana", &both).unwrap();
        bo.takes(&g, &ana.all_of(&g));
        cy.takes(&g, &ana.all_of(&g));
        let hello = cy.says(&g, "hello");
        ana.takes(&g, std::slice::from_ref(&hello));
        bo.takes(&g, std::slice::from_ref(&hello));

        // Ana learns that Cy is frozen, and Bo does not yet. Her next
        // entry starts an epoch that Cy is left out of.
        let twice = cy.recovers_twice();
        assert!(ana.core.ingest_other(cy.id(), &twice).unwrap());
        let known = ana.says(&g, "we know");
        assert!(ana.began_an_epoch(&g));
        let entry = *ana.space(&g).heads().first().unwrap();
        cy.takes(&g, std::slice::from_ref(&known));
        assert!(!cy.space(&g).dag().contains(&entry), "Cy opened it");
        ana.says(&g, "one is enough");
        assert!(!ana.began_an_epoch(&g));

        // It reaches Bo, who has heard nothing, and starts none. Then he
        // hears: by his device's account that is since the epoch reached
        // it, and nothing in the epoch says whom it was wrapped for, so
        // he starts another.
        bo.takes(&g, &ana.all_of(&g));
        bo.says(&g, "what of it");
        assert!(!bo.began_an_epoch(&g));
        assert!(bo.core.ingest_other(cy.id(), &twice).unwrap());
        let also = bo.says(&g, "so we do");
        assert!(bo.began_an_epoch(&g));
        let entry = *bo.space(&g).heads().first().unwrap();
        cy.takes(&g, std::slice::from_ref(&also));
        assert!(!cy.space(&g).dag().contains(&entry), "Cy opened it");
        // His reaches Ana with nothing new to her, and it ends there.
        ana.takes(&g, &bo.all_of(&g));
        ana.says(&g, "settled");
        assert!(!ana.began_an_epoch(&g));
    }

    impl Person {
        /// The device starts again, with what it kept on disk.
        fn restarts(&mut self) {
            let paths = Paths::at(self._dir.path());
            let keys = Arc::new(Keys::load_or_create(&paths.device_key()).unwrap());
            self.core = Core::load(&paths, keys).unwrap();
        }

        /// Whether the last thing this person wrote in a space began a new
        /// epoch.
        fn began_an_epoch(&self, space: &SpaceId) -> bool {
            let sp = self.space(space);
            let mine = sp.dag().log_order().iter().rev();
            let mut mine = mine.filter_map(|x| sp.entry(x));
            let last = mine.find(|e| e.author() == self.id()).unwrap();
            last.starts_epoch()
        }

        /// This person's identity moves to a new encryption key, as it
        /// does when one of their devices is removed. Returns the entry
        /// for the others' copies of their log.
        fn changes_key(&mut self) -> Vec<u8> {
            let ident = self.core.identity.as_ref().unwrap();
            let all = self.log();
            let genesis = IdentityEntry::decode(&all[0]).unwrap();
            let mut log = IdentityLog::from_genesis(genesis).unwrap();
            for e in &all[1..] {
                log.insert_bytes(e).unwrap();
            }
            let new = HybridKeyPair::generate();
            let signing = &self.core.keys.device.signing;
            let entry = log
                .set_encryption_key(signing, &new, ident.enc.first())
                .unwrap();
            entry.encode()
        }
    }

    /// `spaces.md#when-to-rotate`: since the epoch reached this device, by
    /// its own account, which it keeps as it keeps the space.
    #[test]
    fn a_new_epoch_is_due_when_a_members_key_has_changed_since_this_one_came() {
        let mut p = [Person::new(), Person::new(), Person::new()];
        for i in 0..3 {
            for j in 0..3 {
                if i != j {
                    let (log, id) = (p[j].log(), p[j].id());
                    p[i].core.ingest_other(id, &log).unwrap();
                }
            }
        }
        let [mut ana, mut bo, mut cy] = p;
        let both = [(bo.id(), "Bo".to_owned()), (cy.id(), "Cy".to_owned())];
        let g = ana.core.create_group("Garden club", "Ana", &both).unwrap();
        bo.takes(&g, &ana.all_of(&g));
        cy.takes(&g, &ana.all_of(&g));
        let hello = cy.says(&g, "hello");
        ana.takes(&g, std::slice::from_ref(&hello));
        bo.takes(&g, std::slice::from_ref(&hello));
        assert!(!cy.began_an_epoch(&g));

        // Bo's identity moves to a new key. Ana hears of it, and Cy does
        // not yet.
        let moved = bo.changes_key();
        assert!(ana
            .core
            .ingest_other(bo.id(), std::slice::from_ref(&moved))
            .unwrap());
        let first = ana.says(&g, "new keys");
        assert!(ana.began_an_epoch(&g));
        // one is enough
        let second = ana.says(&g, "same keys");
        assert!(!ana.began_an_epoch(&g));

        // Ana's epoch reaches Cy, whose device notes what it holds then:
        // Bo's old key. Nothing says with which of Bo's keys Ana wrapped
        // it. Cy's device starts again, and then hears of Bo's new key:
        // by its own account that is since the epoch reached it, so it
        // starts another. Two devices rotated for one change, which costs
        // wraps and nothing else.
        cy.takes(&g, &[first, second]);
        let quiet = cy.says(&g, "nothing new");
        assert!(!cy.began_an_epoch(&g));
        ana.takes(&g, std::slice::from_ref(&quiet));
        cy.restarts();
        assert!(cy
            .core
            .ingest_other(bo.id(), std::slice::from_ref(&moved))
            .unwrap());
        cy.restarts();
        let third = cy.says(&g, "new keys again");
        assert!(cy.began_an_epoch(&g));
        let fourth = cy.says(&g, "and no more");
        assert!(!cy.began_an_epoch(&g));

        // Cy's epoch reaches Ana with nothing changed since, so she starts
        // none: it ends there.
        ana.takes(&g, &[third, fourth]);
        ana.says(&g, "settled");
        assert!(!ana.began_an_epoch(&g));
        assert_eq!(ana.said(&g).len(), 7);
    }

    /// Someone added after an epoch reached this device is held to the key
    /// they had when the device first saw them in the space, and a new
    /// epoch that is due starts in the entry that adds someone.
    #[test]
    fn a_new_epoch_starts_with_an_addition_and_counts_who_came_since() {
        let mut p = [Person::new(), Person::new(), Person::new(), Person::new()];
        for i in 0..4 {
            for j in 0..4 {
                if i != j {
                    let (log, id) = (p[j].log(), p[j].id());
                    p[i].core.ingest_other(id, &log).unwrap();
                }
            }
        }
        let [mut ana, mut bo, mut cy, mut dee] = p;
        let bo_shown = [(bo.id(), "Bo".to_owned())];
        let g = ana
            .core
            .create_group("Garden club", "Ana", &bo_shown)
            .unwrap();
        let first = ana.space(&g).current_epoch();
        // Bo's key changes, and Ana adds Cy: the entry that adds Cy starts
        // the new epoch, wrapped for Cy as for the others.
        let moved = bo.changes_key();
        assert!(ana.core.ingest_other(bo.id(), &[moved]).unwrap());
        let cy_shown = [(cy.id(), "Cy".to_owned())];
        ana.core.add_to_group(&g, &cy_shown).unwrap();
        assert!(ana.began_an_epoch(&g));
        let second = ana.space(&g).current_epoch();
        assert_ne!(second, first);
        assert!(!ana.space(&g).added_beside_epoch());
        cy.takes(&g, &ana.all_of(&g));
        assert_eq!(cy.role(&g, &cy), Some(WRITER));
        let hello = cy.says(&g, "hello");
        ana.takes(&g, &[hello]);
        assert_eq!(ana.said(&g), ["hello"]);

        // With nothing due, an addition is written under the epoch there
        // is, with its key wrapped for whoever is added.
        let dee_shown = [(dee.id(), "Dee".to_owned())];
        ana.core.add_to_group(&g, &dee_shown).unwrap();
        assert!(!ana.began_an_epoch(&g));
        assert_eq!(ana.space(&g).current_epoch(), second);
        dee.takes(&g, &ana.all_of(&g));
        assert_eq!(dee.said(&g), ["hello"]);
        // Dee was added under this epoch and has its key: nothing is due.
        assert!(!ana.space(&g).added_beside_epoch());
        ana.says(&g, "welcome");
        assert!(!ana.began_an_epoch(&g));

        // Dee came after the epoch reached Ana's device, which has held
        // Dee to the key Dee had then. It changes, and that counts as any
        // member's does.
        let moved = dee.changes_key();
        assert!(ana.core.ingest_other(dee.id(), &[moved]).unwrap());
        ana.says(&g, "new keys");
        assert!(ana.began_an_epoch(&g));
        ana.says(&g, "and no more");
        assert!(!ana.began_an_epoch(&g));
    }

    /// A store is made with its marker, and one with another, or with
    /// none, is never opened as far as it goes (`format.rs`).
    #[test]
    fn a_store_of_another_format_is_not_opened() {
        use crate::format::{self, Store};
        let ana = Person::new();
        let paths = Paths::at(ana._dir.path());
        assert_eq!(format::of(&paths), Store::Current);
        let keys = ana.core.keys.clone();
        assert!(Core::load(&paths, keys.clone()).is_ok());
        // what 0.1.13 left, and what a later version would
        for marker in [None, Some("1\n"), Some("3\n")] {
            match marker {
                None => std::fs::remove_file(format::marker(&paths)).unwrap(),
                Some(text) => std::fs::write(format::marker(&paths), text).unwrap(),
            }
            let refused = Core::load(&paths, keys.clone()).err().expect("opened");
            assert!(refused.to_string().contains("this version cannot read it"));
            let refused = setup::prepare(&paths).err().expect("set up over it");
            assert!(refused.to_string().contains("Nothing was changed"));
        }
        // An identity that arrives on a device with none, by pairing or by
        // restoring, makes a store as `init` does.
        let dir = tempfile::tempdir().unwrap();
        let fresh = Paths::at(dir.path());
        let keys = Arc::new(Keys::load_or_create(&fresh.device_key()).unwrap());
        let mut core = Core::load(&fresh, keys).unwrap();
        assert_eq!(format::of(&fresh), Store::Empty);
        core.install_identity(&ana.log()).unwrap();
        assert_eq!(format::of(&fresh), Store::Current);
    }

    /// What `cardinal free-space --unnamed` marks from: every blob
    /// reference in any entry this device holds of any space, wherever in
    /// an op it is, with the reasons that may not be all of them.
    #[test]
    fn every_blob_reference_in_what_is_held_is_named() {
        use cardinal_blob::BlobRef;
        use cardinal_encoding::Value;
        use cardinal_space::files::{self, Content};
        let (mut ana, mut bo) = (Person::new(), Person::new());
        ana.meets(&bo);
        bo.meets(&ana);
        let blob = |n: u8| BlobRef {
            id: [n; 32],
            key: [n + 100; 32],
            size: 5000,
            levels: 1,
        };
        let content = |n: u8| {
            let b = blob(n);
            Content::Blob(files::BlobRef {
                id: b.id,
                key: b.key,
                size: b.size,
                levels: b.levels,
            })
        };
        let named = |p: &Person| -> Vec<u8> {
            let (refs, unsure) = p.core.named_blobs();
            assert!(unsure.is_empty(), "{unsure:?}");
            let mut ids: Vec<u8> = refs.iter().map(|b| b.id[0]).collect();
            ids.sort();
            ids
        };
        assert!(named(&ana).is_empty());

        // A file, replaced: the old version is named as the current one is.
        let filespace = ana.core.files_id().unwrap();
        let made = files::create_file(ROOT, "a.bin", &content(1), 0o644, None);
        let (entry, _) = ana.core.write_entry(&filespace, vec![made]).unwrap();
        let node = files::created_node(&entry, 0);
        let replaced = files::set_content(node, &content(2));
        ana.core.write_entry(&filespace, vec![replaced]).unwrap();
        assert_eq!(named(&ana), [1, 2]);

        // An attachment in a conversation, deep in a list in a field, and
        // a reference somewhere no profile puts one.
        let (rel, genesis) = ana.core.create_relationship(&bo.id()).unwrap();
        bo.core.accept_relationship(&genesis, &ana.id()).unwrap();
        let c = relationship::conversation(ana.space(&rel)).unwrap();
        let attached = Value::list([Record::new()
            .with(1, "photo.jpg")
            .with(2, blob(3).to_record())
            .with(3, "image/jpeg")]);
        let fields = Record::new().with(1, "look").with(2, attached);
        let said = SpaceOp::create(NodeKind::Uint(2), c, "m", fields);
        let odd = SpaceOp::set(c, 99, Some(Value::list([blob(4).to_record()])));
        let (_, sent) = ana.core.write_entry(&rel, vec![said, odd]).unwrap();
        assert_eq!(named(&ana), [1, 2, 3, 4]);
        // Bo holds the conversation, and names what is in it.
        bo.takes(&rel, std::slice::from_ref(&sent));
        assert_eq!(named(&bo), [3, 4]);

        // An entry held for want of its parent is read all the same.
        let before = ana.says(&rel, "one");
        let more = SpaceOp::set(c, 98, Some(Value::Record(blob(5).to_record())));
        let (_, after) = ana.core.write_entry(&rel, vec![more]).unwrap();
        bo.takes(&rel, std::slice::from_ref(&after));
        assert!(bo.space(&rel).dag().held().next().is_some());
        assert_eq!(named(&bo), [3, 4, 5]);
        bo.takes(&rel, &[before]);
        assert_eq!(named(&bo), [3, 4, 5]);

        // An entry no key here opens says nothing of what it names, and
        // that is a reason to doubt: Ana starts an epoch that is not
        // wrapped for Bo.
        let alone = [ana.enc()];
        let begun = ana.begins_an_epoch(&rel, &alone);
        bo.takes(&rel, &[begun]);
        let (refs, unsure) = bo.core.named_blobs();
        assert_eq!(refs.len(), 3);
        assert_eq!(unsure.len(), 1, "{unsure:?}");
        assert!(unsure[0].contains("1 entries") && unsure[0].contains("cannot be opened"));
    }

    /// In a space that has ended a device writes only what witnesses or
    /// keeps its own person's work (`spaces.md#ending-a-space`), and that
    /// starts no epoch, whatever is due.
    #[test]
    fn nothing_but_a_witness_is_written_in_a_space_that_has_ended() {
        let (mut ana, mut bo) = (Person::new(), Person::new());
        ana.meets(&bo);
        bo.meets(&ana);
        let bo_shown = [(bo.id(), "Bo".to_owned())];
        let g = ana
            .core
            .create_group("Garden club", "Ana", &bo_shown)
            .unwrap();
        ana.says(&g, "hello");
        let end = vec![SpaceOp::succeed([7; 32])];
        ana.core.write_entry(&g, end).unwrap();
        assert!(ana.space(&g).ended());
        // Bo's key changes, which would call for a new epoch.
        let moved = bo.changes_key();
        assert!(ana.core.ingest_other(bo.id(), &[moved]).unwrap());
        let epoch = ana.space(&g).current_epoch();
        let heads = ana.space(&g).heads();
        let (id, _) = ana.core.write_entry(&g, Vec::new()).unwrap();
        let sp = ana.space(&g);
        assert!(!sp.entry(&id).unwrap().starts_epoch());
        assert_eq!(sp.current_epoch(), epoch);
        // it counts without being valid there, and nothing builds on it
        assert!(sp.validity().author_ok.contains(&id) && !sp.validity().is_valid(&id));
        assert_eq!(sp.heads(), heads);
        let c = relationship::conversation(sp).unwrap();
        let more = relationship::create_message(c, "anyone there?");
        assert!(ana.core.write_entry(&g, vec![more]).is_err());
    }

    /// `spaces.md#when-to-rotate`: someone added at the same time as a
    /// rotation was never given the key. Every device reads that from the
    /// entries, and whoever writes next starts a new epoch.
    #[test]
    fn someone_added_beside_a_rotation_is_given_the_next_key() {
        let mut p = [Person::new(), Person::new(), Person::new()];
        for i in 0..3 {
            for j in 0..3 {
                if i != j {
                    let (log, id) = (p[j].log(), p[j].id());
                    p[i].core.ingest_other(id, &log).unwrap();
                }
            }
        }
        let [mut ana, mut bo, mut cy] = p;
        let bo_shown = [(bo.id(), "Bo".to_owned())];
        let g = ana
            .core
            .create_group("Garden club", "Ana", &bo_shown)
            .unwrap();
        bo.takes(&g, &ana.all_of(&g));
        let hello = bo.says(&g, "hello");
        ana.takes(&g, std::slice::from_ref(&hello));

        // Ana adds Cy, under the first epoch, while Bo, who has not heard,
        // starts a second and writes under it.
        let cy_shown = [(cy.id(), "Cy".to_owned())];
        let added = ana.core.add_to_group(&g, &cy_shown).unwrap();
        let everyone = [bo.enc(), ana.enc()];
        let begun = bo.begins_an_epoch(&g, &everyone);
        assert!(!bo.space(&g).added_beside_epoch());
        let secret = bo.says(&g, "under the second");
        assert!(!bo.began_an_epoch(&g));
        ana.takes(&g, &[begun.clone(), secret.clone()]);
        bo.takes(&g, std::slice::from_ref(&added));
        cy.takes(&g, &ana.all_of(&g));
        // Cy is a member, with a key that opens nothing written now.
        for who in [&ana, &bo] {
            assert_eq!(who.role(&g, &cy), Some(WRITER));
            assert!(who.space(&g).added_beside_epoch());
        }
        assert_eq!(cy.said(&g), ["hello"]);

        // Whoever writes next starts a third, wrapped for Cy too, and it
        // carries the keys it supersedes: Cy reads what was written under
        // the second.
        let third = bo.says(&g, "welcome");
        assert!(bo.began_an_epoch(&g));
        assert!(!bo.space(&g).added_beside_epoch());
        ana.takes(&g, std::slice::from_ref(&third));
        cy.takes(&g, &[third]);
        assert_eq!(cy.said(&g), ["hello", "under the second", "welcome"]);
        // one is enough, for Ana as for Bo
        ana.says(&g, "hello Cy");
        assert!(!ana.began_an_epoch(&g));
        assert!(!ana.space(&g).added_beside_epoch());
    }
}
