//! What the daemon holds: the identity log and the spaces, persisted as
//! append-only logs of the objects that make them up, and kept evaluated
//! in memory.

use std::collections::{BTreeMap, HashMap};
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
    /// space: a member left since this one began, or it was begun by one
    /// this device would leave out (`spaces.md#when-to-rotate`).
    leave_out: bool,
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
        };
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

    /// Whether the next write must start a new epoch: the current one
    /// began before the identity's encryption key changed, which a removal
    /// always does, or before a member left, or was begun by a member this
    /// device would leave out (`spaces.md#when-to-rotate`). All but the
    /// last follow from the entries, so they hold on every device and
    /// across restarts. A device that cannot open the current key yet
    /// cannot tell, and waits. Only a writer starts an epoch.
    fn rotation_due(&self, identity: &Identity) -> bool {
        let Some(space) = &self.space else {
            return false;
        };
        let writer = cardinal_space::entry::WRITER;
        let me = identity.id();
        if space.role_of(&me).is_none_or(|r| r < writer) || space.has_left(&me) {
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
        let space = self
            .space
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("space not open yet"))?;
        let role = cardinal_space::group::WRITER;
        let adding: Vec<_> = added.iter().map(|(w, k)| (*w, role, k)).collect();
        let mut everyone = vec![&mine];
        everyone.extend(self.member_keys.iter());
        let sealed = space.add_members(
            &identity.log,
            &keys.device.signing,
            &adding,
            &everyone,
            ops,
            Some(now_ms()),
        )?;
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

    /// The reach node `who` wrote in a space.
    pub fn reach_of(
        &self,
        space: &SpaceId,
        who: &[u8; 32],
    ) -> Option<(
        cardinal_space::NodeId,
        Vec<cardinal_space::relationship::Reach>,
    )> {
        let h = self.spaces.get(space)?.space.as_ref()?;
        cardinal_space::relationship::reach_of(h.state(), who)
    }

    /// The space this person gave out a token in.
    pub fn space_of_token(&self, token: &[u8; 16]) -> Option<SpaceId> {
        let me = self.identity.as_ref()?.id();
        self.spaces.keys().copied().find(|id| {
            let reach = self.all_reach_of(id, &me);
            reach.iter().any(|r| r.token == *token)
        })
    }

    /// Each reach node `who` wrote in a space, with what it says.
    pub fn reach_nodes_of(
        &self,
        space: &SpaceId,
        who: &[u8; 32],
    ) -> Vec<(
        cardinal_space::NodeId,
        Vec<cardinal_space::relationship::Reach>,
    )> {
        let Some(h) = self.spaces.get(space).and_then(|h| h.space.as_ref()) else {
            return Vec::new();
        };
        cardinal_space::relationship::reach_nodes(h.state(), who)
    }

    /// Every host and token `who` gave in a space, from all their reach nodes.
    pub fn all_reach_of(
        &self,
        space: &SpaceId,
        who: &[u8; 32],
    ) -> Vec<cardinal_space::relationship::Reach> {
        let Some(h) = self.spaces.get(space).and_then(|h| h.space.as_ref()) else {
            return Vec::new();
        };
        cardinal_space::relationship::all_reach_of(h.state(), who)
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

    /// After something was written or arrived in a space: the keys of the
    /// members a new epoch would be wrapped for, and whether one is due
    /// because of them. It is wrapped for every member but this one who has
    /// not left, and whom this device does not know to be frozen
    /// (`spaces.md#distribution`).
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
        // "A writer does not encrypt under an epoch started by a member it
        // would leave out."
        let out = |who: &[u8; 32]| sp.has_left(who) || state(who).is_some_and(|st| st.frozen);
        let theirs = |(_, who): (EntryId, [u8; 32])| who != ident.id() && out(&who);
        h.leave_out = sp.left_since_epoch() || sp.epoch_started_by().is_some_and(theirs);
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
        // (`contact.md#accepting`): the relationship profile, no owner,
        // exactly these two identities as writers, and a space it does not
        // already hold. The members are read off a genesis that is valid,
        // so it is the inviter's and well formed; one that is not names
        // nobody.
        use cardinal_space::entry::WRITER;
        let mut the_two = [ident.id(), *inviter].map(|identity| cardinal_space::Member {
            identity,
            role: WRITER,
        });
        the_two.sort();
        anyhow::ensure!(
            space.profile() == cardinal_space::Profile::RELATIONSHIP
                && space.owner().is_none()
                && space.creator() == *inviter
                && space.members() == the_two
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

    /// Installs a freshly created identity (`cardinal init`).
    pub fn install_identity(&mut self, log_entries: &[Vec<u8>]) -> anyhow::Result<()> {
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
            let reach = self.all_reach_of(&c.space, &c.identity);
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
    }

    impl Person {
        fn new() -> Person {
            let dir = tempfile::tempdir().unwrap();
            let paths = Paths::at(dir.path());
            let p = setup::prepare(&paths).unwrap();
            setup::install(&paths, p, &Config::default()).unwrap();
            let keys = Arc::new(Keys::load_or_create(&paths.device_key()).unwrap());
            let core = Core::load(&paths, keys).unwrap();
            Person { _dir: dir, core }
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
        let not_theirs: [(&str, Vec<u8>); 9] = [
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
}
