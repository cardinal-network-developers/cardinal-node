//! What the daemon holds: the identity log and the spaces, persisted as
//! append-only logs of the objects that make them up, and kept evaluated
//! in memory.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use cardinal_crypto::HybridKeyPair;
use cardinal_encoding::Record;
use cardinal_identity::{EntryId, IdentityEntry, IdentityLog, IdentityState, Inserted, KeyId};
use cardinal_space::account;
use cardinal_space::entry::NodeKind;
use cardinal_space::{Profile, SealedEntry, Space, SpaceId, SpaceOp, ROOT};
use cardinal_sync::{identity_log_label, MemSet};

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
    /// The next write must start a new epoch (a device was removed).
    pub needs_rotate: bool,
}

/// What ingesting objects did.
#[derive(Debug, Default)]
pub struct Ingested {
    /// Objects new to this device.
    pub new: usize,
    /// Some entries wait for parents this device lacks.
    pub missing_parents: bool,
}

impl Holder {
    fn dir(paths: &Paths, id: &SpaceId) -> PathBuf {
        paths.spaces().join(hex::encode(id))
    }

    /// Opens (or creates) the holder's storage and evaluates what it holds.
    fn open(
        paths: &Paths,
        id: SpaceId,
        keys: &[&HybridKeyPair],
        author: Option<Arc<IdentityState>>,
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
            needs_rotate: false,
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
        h.rebuild(sealed, keys, author);
        Ok(h)
    }

    /// Re-evaluates from scratch with `extra` added: opens the genesis,
    /// adds everything without an author (cheap), then evaluates once.
    fn rebuild(
        &mut self,
        extra: Vec<SealedEntry>,
        keys: &[&HybridKeyPair],
        author: Option<Arc<IdentityState>>,
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
        if let Some(a) = author {
            space.set_author(a);
        }
        self.space = Some(space);
        self.version += 1;
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

    /// Sealed ids of the current heads.
    pub fn head_ids(&self) -> Vec<[u8; 32]> {
        let Some(sp) = &self.space else {
            return Vec::new();
        };
        sp.heads()
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

    /// Adds sealed entries received from one of this person's devices.
    fn ingest(
        &mut self,
        objects: &[Vec<u8>],
        keys: &[&HybridKeyPair],
        author: Option<Arc<IdentityState>>,
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
            missing_parents: false,
        };
        if fresh.is_empty() {
            return Ok(out);
        }
        self.persist(&items)?;
        if self.space.is_none() || fresh.len() > 16 {
            self.rebuild(fresh, keys, author);
        } else {
            let space = self.space.as_mut().expect("open");
            for s in fresh {
                match space.receive(s.clone(), keys) {
                    Ok(Inserted::Held(_)) => out.missing_parents = true,
                    Ok(_) => {}
                    Err(cardinal_space::Error::NoEpochKey) => self.pending.push(s),
                    Err(e) => tracing::warn!("space {}: entry rejected: {e}", short(&self.id)),
                }
            }
            if !self.pending.is_empty() {
                let pend = std::mem::take(&mut self.pending);
                for s in pend {
                    match space.receive(s.clone(), keys) {
                        Ok(_) => {}
                        Err(cardinal_space::Error::NoEpochKey) => self.pending.push(s),
                        Err(_) => {}
                    }
                }
            }
            self.version += 1;
        }
        if let Some(sp) = &self.space {
            if sp.dag().held().next().is_some() {
                out.missing_parents = true;
            }
        }
        Ok(out)
    }

    /// Writes one entry with `ops`. Returns the entry id and the sealed
    /// bytes to send to the person's other devices.
    pub fn write_one(
        &mut self,
        identity: &Identity,
        keys: &Keys,
        ops: Vec<SpaceOp>,
    ) -> anyhow::Result<(EntryId, Vec<u8>)> {
        let space = self
            .space
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("space not open yet"))?;
        let sealed = if self.needs_rotate {
            let pk = identity
                .enc
                .first()
                .ok_or_else(|| anyhow::anyhow!("no encryption key"))?
                .public_key()
                .clone();
            let (s, _) = space.rotate(
                &identity.log,
                &keys.device.signing,
                &[&pk],
                ops,
                Some(now_ms()),
            )?;
            self.needs_rotate = false;
            s
        } else {
            space.write(&identity.log, &keys.device.signing, ops, Some(now_ms()))?
        };
        let heads = space.heads();
        let id = if heads.len() == 1 {
            heads[0]
        } else {
            // the new entry descends from every head, so it is the only one
            anyhow::bail!("unexpected heads after a write")
        };
        if !space.validity().is_valid(&id) {
            tracing::warn!("space {}: own entry {} is not valid", short(&self.id), short(&id));
        }
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
        };
        if paths.identity_log().exists() {
            let (file, records) = AppendLog::open(&paths.identity_log())?;
            core.identity = Some(Self::build_identity(file, records, &core.keys)?);
        }
        if core.identity.is_some() {
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
        }
        Ok(core)
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
            let h = Holder::open(&self.paths, id, &ident.key_refs(), Some(ident.state()))?;
            self.spaces.insert(id, h);
        }
        Ok(self.spaces.get_mut(&id).expect("inserted"))
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
            v.extend(self.spaces.keys().copied());
        }
        v
    }

    /// The set behind a label, cloned (empty if not held).
    pub fn set(&self, label: &[u8; 32]) -> MemSet {
        if Some(*label) == self.identity_label() {
            return self.identity.as_ref().expect("identity").set.clone();
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
        self.spaces
            .get(label)
            .is_some_and(|h| h.set.contains_id(id))
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
                ident.refresh_keys(&self.keys);
                let st = ident.state();
                let keys: Vec<HybridKeyPair> = ident
                    .enc
                    .iter()
                    .map(|k| HybridKeyPair::from_secret_bytes(&k.secret_bytes()))
                    .collect();
                let refs: Vec<&HybridKeyPair> = keys.iter().collect();
                for h in self.spaces.values_mut() {
                    if let Some(sp) = h.space.as_mut() {
                        sp.set_author(st.clone());
                        h.version += 1;
                    } else {
                        h.rebuild(Vec::new(), &refs, Some(st.clone()));
                    }
                }
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
        let st = ident.state();
        self.open_space(space)?;
        let h = self.spaces.get_mut(&space).expect("open");
        h.ingest(objects, &refs, Some(st))
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
        h.write(ident, &self.keys, ops)
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
        h.write_one(ident, &self.keys, ops)
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
