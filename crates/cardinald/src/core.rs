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
use cardinal_space::relationship;
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
            if self.set.contains_id(&e.id()) {
                continue;
            }
            let id = e.id();
            let own = e.identity() == self.log.id();
            // Another identity's entries, held under this one's label: a
            // guardian's, up to what it did (`identity.md#distribution`).
            // They are kept only once an act shows them to be that.
            match self.log.insert_any(e) {
                Ok(Inserted::Duplicate) => continue,
                Ok(Inserted::Added(_)) => changed = true,
                Ok(Inserted::Held(_)) => {}
                Err(err) => {
                    tracing::warn!("rejected identity entry {}: {err}", short(&id));
                    continue;
                }
            }
            if own {
                self.set.insert(id);
                to_store.push(bytes.clone());
            }
            for a in self.log.take_attached() {
                changed = true;
                self.set.insert(a.id());
                to_store.push(a.encode());
            }
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
            if self.set.contains_id(&e.id()) {
                continue;
            }
            let id = e.id();
            let own = e.identity() == self.log.id();
            match self.log.insert_any(e) {
                Ok(Inserted::Added(_)) => changed = true,
                Ok(Inserted::Held(_)) => {}
                Ok(Inserted::Duplicate) | Err(_) => continue,
            }
            if own {
                self.keep(id, bytes)?;
            }
            for a in self.log.take_attached() {
                changed = true;
                self.keep(a.id(), &a.encode())?;
            }
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

/// Restoring through guardians (`hosts.md#restore`): with `root`, the
/// new root a recovery in effect named, the entries that add this
/// device as an admin device to the log collected from a host, and then
/// set a fresh encryption key whose chain carries the earlier ones
/// (`identity.md#what-a-recovery-does`). The current key comes from the
/// guardian key, rebuilt from the shares in the guardians'
/// confirmations, sealed to this device's link key.
///
/// `log` is [`Core::joining_log`]; this takes no lock, since rebuilding
/// the key may take a while.
pub fn recovered_entries(
    mut log: IdentityLog,
    keys: &Keys,
    root: &cardinal_crypto::SigningKey,
) -> anyhow::Result<Vec<(Vec<u8>, [u8; 32])>> {
    let identity = log.id();
    let identity = &identity;
    let st = log.state();
    if st.power(&root.public_key()) != Some(cardinal_identity::Power::Root) {
        anyhow::bail!(
            "the recovery is not in effect on that device yet: your guardians have not all \
             confirmed it, or their confirmations have not reached it"
        );
    }
    let recovery = log
        .recoveries()
        .into_iter()
        .find(|r| r.root == root.public_key() && st.in_effect.contains(&r.entry))
        .ok_or_else(|| anyhow::anyhow!("no recovery in that log names this device's root"))?;
    let guardian_key = log
        .rebuild_guardian_key(&recovery, &keys.device.link)
        .map_err(|e| anyhow::anyhow!("cannot rebuild the guardian key from the shares: {e}"))?;
    let enc = log.open_with_guardian_key(&guardian_key, &recovery.policy)?;
    let current = log
        .key_chain(enc)
        .into_iter()
        .next()
        .expect("the key itself");
    let request = keys
        .device
        .request(identity, cardinal_identity::Power::Admin);
    let added = log.add_key(root, &request, Some(&current))?;
    let fresh = HybridKeyPair::generate();
    let rotated = log.set_encryption_key(root, &fresh, Some(&current))?;
    Ok(vec![
        (added.encode(), added.id()),
        (rotated.encode(), rotated.id()),
    ])
}

/// Sealed entries written, by space.
pub type Written = Vec<(SpaceId, Vec<u8>)>;

/// Every entry of a log, its own first in log order, then those of the
/// logs held under its label: what an identity log file holds.
pub fn log_bytes(log: &IdentityLog) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = log.entries().map(|e| e.encode()).collect();
    for a in log.attached() {
        out.extend(a.entries().map(|e| e.encode()));
    }
    out
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

/// What this device held when an epoch reached it, which is when it first
/// held the epoch's key: each member's encryption key, and whom it knew to
/// be frozen (`spaces.md#when-to-rotate`). Nothing in a space says whom an
/// epoch was wrapped for, or with which of a member's keys, so a device
/// keeps its own account with each epoch, as it keeps the space, and
/// compares. Who had left is not in it: the rule read from the entries
/// covers every `leave` the epoch was started without, whenever it arrives.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Reached {
    /// The fingerprint of each member's encryption key, by identity.
    keys: BTreeMap<String, String>,
    /// Whom this device knew to be frozen.
    frozen: BTreeSet<String>,
}

impl Reached {
    /// What this device holds now of the members of a space who have not
    /// left: the others are given no epoch, whatever becomes of their keys.
    fn now(space: &Space, logs: &[Arc<IdentityState>]) -> Reached {
        let mut now = Reached::default();
        for who in space.present() {
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
        now
    }

    /// Whether a new epoch is due for what changed since: the encryption
    /// key of a member who would be given the next one, or a member this
    /// device has learned is frozen.
    fn calls_for_a_new_epoch(&self, now: &Reached) -> bool {
        let key = |(who, key): (&String, &String)| {
            !now.frozen.contains(who) && self.keys.get(who).is_some_and(|was| was != key)
        };
        now.keys.iter().any(key) || now.frozen.iter().any(|who| !self.frozen.contains(who))
    }
}

/// Whom this device has told its person of, among those added to a space
/// (`hosts.md#telling-others-where-to-reach-you`, "A yes is to the
/// space"). It is this device's own note, kept beside the space and not in
/// it, and no other device sees it. Each addition is noted once: as one
/// there is nothing to say of, or as one the person is still to be told
/// of. It is not worked out from when the list was last set: the list is
/// set again whenever an address or a token changes.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Arrivals {
    /// The additions the person has been told of, or need not be: the
    /// `add_member` entries, in hex.
    told: BTreeSet<String>,
    /// The additions they are still to be told of, and whom each added.
    due: BTreeMap<String, String>,
}

/// A yes this device keeps to itself (`hosts.md`, "An act that cannot be
/// finished is finished later, by the same device"): its person joined
/// among contacts, or said their hosts may be named, while no host could
/// be reached to register a token. It is kept beside the space, not in it
/// or in the account, and no other device sees it. It holds the entries
/// that had set the list when it was kept: once the list is set by
/// anything else, on any device, to anything, that is later than the yes,
/// and the yes is given up.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct KeptYes {
    /// The entries whose lists the reach node held, in hex, sorted.
    list_set_by: Vec<String>,
    /// The additions that counted when it was kept, in hex: who the yes
    /// was said among. Whoever is added before it is finished came after
    /// it, though the entry that names the hosts will have their addition
    /// in its past (R6). `None` in a note an earlier version kept, which
    /// is finished as that version would have.
    #[serde(default)]
    present: Option<BTreeSet<String>>,
}

/// What this person's reach node in a space tells, and whom
/// (`hosts.md#telling-others-where-to-reach-you`). A reach node says where
/// a person's hosts are to every member, and for a host at home that is a
/// home address. Their contacts have a host of theirs already; anyone else
/// in the space learns it there.
///
/// The list is the person's answer, and nothing else records one: an empty
/// list is their no, or their having no host, and no device can tell which.
/// So what software may do to the list is two things kept apart. On its
/// own a device changes only the entry that names itself (D70): a host
/// keeps its own endpoints and token current and takes itself out when it
/// stops serving, and no device judges, changes or removes another's, or
/// writes only to make two lists one. It names a host where none is named
/// only when its person says so on this device, or joins among contacts,
/// or in a relationship, where a device that becomes a host adds itself.
/// Everything here is read off what
/// the list holds now, whether there is a host, whether the space is
/// joined and is a relationship, and who is not a contact. Who was added
/// while the hosts were named, and is still to be told of, changes none of
/// it: a yes is to the space as it grows, and nothing waits for the
/// person.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Telling {
    /// Whether their reach node there names a host now. Where two of their
    /// devices set it at the same moment and either set it empty, it names
    /// none.
    pub shared: bool,
    /// Whether it has ever been set, if only to an empty list.
    pub set: bool,
    /// Whether it holds two lists or more, set by their devices at the
    /// same moment. Both count, and nobody writes only to make them one:
    /// they become one when a device next writes its own entry, or the
    /// person says yes or no.
    pub two: bool,
    /// Whether this device keeps a yes of theirs that it could not finish:
    /// it names their hosts once one can be reached, unless the list is
    /// set meanwhile.
    pub waiting: bool,
    /// Whether they have a host to name.
    pub hosted: bool,
    /// How many of their hosts the list does not name.
    pub unnamed: usize,
    /// Whether this device is one of them: a host of theirs, by its own
    /// account, that the list does not name.
    pub own_unnamed: bool,
    /// Whether this device is a host of theirs because it named itself,
    /// having an address outside (D72), and not by the person's act.
    pub own_self_named: bool,
    /// Whether every other member is a trusted contact, none refused, and
    /// the space is not public: where a device that named itself names
    /// itself unasked (D72).
    pub trusted_only: bool,
    /// Whether the person's account records "no hosts here" for the space
    /// (D75): no host names itself there.
    pub said_no: bool,
    /// Whether it records "not this host here" for this device (D75).
    pub own_not_here: bool,
    /// The hosts it records "not this host here" for, by static key.
    pub not_here: Vec<[u8; 32]>,
    /// Whether they are in the space by their own doing.
    pub joined: bool,
    /// Whether they have left it.
    pub left: bool,
    /// Whether the space is public: then whoever is in it now, anyone at
    /// all reads it, and nothing is ever set there unasked.
    pub public: bool,
    /// Whether the space is the relationship with a contact, whose devices
    /// have a host of the person's from it already: there the list is kept
    /// at the person's hosts, a new one included.
    pub relationship: bool,
    /// The members who are not their contacts and have not left: who
    /// learns what the reach node says and had no host of theirs already.
    pub who: Vec<[u8; 32]>,
    /// Those of them who were added while the list named the person's
    /// hosts, and of whom this device has not yet told its person.
    pub late: Vec<[u8; 32]>,
    /// The addresses of their hosts: what is learned.
    pub what: Vec<String>,
}

impl Telling {
    /// Whether everyone else there has a host of the person's already:
    /// they are all contacts, and nobody else reads the space.
    fn among_contacts(&self) -> bool {
        self.who.is_empty() && !self.public
    }

    /// Whether the person must be asked before software names their hosts
    /// there: they have a host, someone there is not their contact, and
    /// they have given no answer, which is a list they set. An offer always
    /// asks: whoever left emptied the list in leaving. Once they are in
    /// the space with a list set, empty or not, that is their answer, and
    /// only they change it.
    pub fn ask(&self) -> bool {
        // in a public space that is anyone at all, whoever is in it now
        let learns = self.public || !self.who.is_empty();
        self.hosted && learns && (!self.joined || !self.set)
    }

    /// Whether joining names the person's hosts: as they say now, or,
    /// where they say nothing, only among contacts.
    pub fn joins_sharing(&self, reach: Option<bool>) -> bool {
        reach.unwrap_or(self.among_contacts())
    }

    /// Those who are not the person's contacts and were added to a space
    /// where their reach node already named their hosts, of whom this
    /// device has yet to tell them: it SHOULD, and offer to empty the
    /// list. Nothing waits for that.
    pub fn added(&self) -> &[[u8; 32]] {
        match self.shared && self.joined {
            true => &self.late,
            false => &[],
        }
    }

    /// Whether software sets the list now without asking, to more than it
    /// names (D75, `hosts.md#telling-others-where-to-reach-you`). Only
    /// among contacts, and never where the person's account says "no
    /// hosts here". Where the list was never set, the person is in the
    /// space, as whoever made it is, and this is their joining: every host
    /// of theirs that may be named unasked is. Where it is set, empty or
    /// not, a host names itself, and no device adds another: this device,
    /// where the list does not name it and the account does not say "not
    /// this host here" for it. A list emptied by mistake fills itself
    /// again that way.
    ///
    /// A device that named itself (D72) names itself unasked only where
    /// every other member is a trusted contact.
    pub fn sets_unasked(&self) -> bool {
        if !self.joined || !self.among_contacts() || self.said_no {
            return false;
        }
        if !self.set {
            return true;
        }
        if !self.own_unnamed || self.own_not_here {
            return false;
        }
        !self.own_self_named || self.trusted_only
    }

    /// Whether what software would set unasked is worth an entry, given
    /// how many hosts it could add: one or more. A device writes the list
    /// when it has something to say (D75): with none to add it leaves the
    /// list as it is, unset too, and a device that cannot reach its
    /// person's host now waits for the host.
    pub fn worth_saying(&self, hosts: usize) -> bool {
        hosts > 0
    }

    /// Whether software empties the reach node now: the person has left
    /// and it names a host all the same. Emptying it again is the one
    /// thing a member who has left still writes
    /// (`spaces.md#members-and-roles`). Setting an empty list tells nobody
    /// anything, and needs no asking.
    pub fn empties_unasked(&self) -> bool {
        self.shared && self.left
    }

    /// Whether a host keeps its own entry in the list current: a token
    /// that has gone, an address that changed, and taking itself out when
    /// it stops serving. That needs no asking: the person agreed to the
    /// space naming their hosts, whoever is added to it.
    pub fn keeps_current(&self) -> bool {
        self.shared && self.joined
    }
}

/// [`Core::is_joined`], from the account and the space.
pub fn joined_in(account: Option<&Space>, sp: &Space, space: &SpaceId, me: &[u8; 32]) -> bool {
    if sp.accepted_by(me) {
        return true;
    }
    if sp.has_left(me) || sp.role_of(me).is_none() {
        return false;
    }
    account.is_some_and(|a| {
        account::spaces(a.state())
            .iter()
            .any(|r| r.space == *space && !r.declined)
    })
}

/// The entries whose lists a person's reach node holds, in hex, sorted:
/// what a [`KeptYes`] is kept against.
fn list_set_by(space: &Space, who: &[u8; 32]) -> Vec<String> {
    let values = space.state().reach_values(who, 1).iter();
    let mut by: Vec<String> = values.map(|v| hex::encode(v.entry)).collect();
    by.sort();
    by.dedup();
    by
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
    /// Something was taken into the space in memory and could not be
    /// saved: what is in memory is no longer what the device holds, and
    /// is read again from what it does ([`Core::settle`]).
    unsaved: bool,
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
    /// Whom this device has told its person of, among those added.
    arrivals: Arrivals,
    arrivals_at: PathBuf,
    /// A yes of the person's that this device has yet to finish.
    kept_yes: Option<KeptYes>,
    kept_yes_at: PathBuf,
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
            unsaved: false,
            version: 0,
            member_keys: Vec::new(),
            leave_out: false,
            reached: BTreeMap::new(),
            reached_at: Self::dir(paths, &id).join("epochs.json"),
            arrivals: Arrivals::default(),
            arrivals_at: Self::dir(paths, &id).join("arrivals.json"),
            kept_yes: None,
            kept_yes_at: Self::dir(paths, &id).join("kept-yes.json"),
        };
        h.kept_yes = std::fs::read(&h.kept_yes_at)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok());
        // No note, or one that cannot be read, is nobody told of yet.
        if let Ok(bytes) = std::fs::read(&h.arrivals_at) {
            h.arrivals = serde_json::from_slice(&bytes).unwrap_or_default();
        }
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

    /// Sealed entries held that could not be opened yet, for want of an
    /// epoch key.
    pub fn pending(&self) -> &[SealedEntry] {
        &self.pending
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
        let locs = match self.file.append_many(&refs) {
            Ok(locs) => locs,
            Err(e) => {
                // Whatever of this is in the space in memory already must
                // not stay: later entries would name it as a parent.
                self.unsaved = true;
                return Err(e.into());
            }
        };
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
        // Whatever is due, nothing is written in a space this person has
        // not accepted, or has declined: an entry there would be their
        // acceptance (`spaces.md#holding-a-space`). The epoch is started
        // by the entry that accepts, if they ever do.
        let me = identity.id();
        if !self.space.as_ref().is_some_and(|s| s.accepted_by(&me)) {
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
            // It has been started: what the same write holds besides goes
            // under it. Whether another is due is worked out again when
            // the write is done ([`Core::settle`]).
            self.leave_out = false;
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

    /// Writes `keep` ops on every head, set aside or not
    /// ([`Space::write_keeps`]). Returns the sealed bytes.
    pub fn write_keeps(
        &mut self,
        identity: &Identity,
        keys: &Keys,
        ops: Vec<SpaceOp>,
    ) -> anyhow::Result<Vec<u8>> {
        if identity.state().power(&keys.key()).is_none() {
            anyhow::bail!("this device was removed");
        }
        let space = self
            .space
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("space not open yet"))?;
        let (_, sealed) = space.write_keeps(&identity.log, &keys.device.signing, ops)?;
        let bytes = sealed.encode();
        self.persist(&[(sealed.sealed_id(), bytes.clone())])?;
        self.version += 1;
        Ok(bytes)
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
    /// This is a recovery helper's: it holds what guardians' personas give
    /// it for the recovery (D80).
    pub takes_recovery_copies: bool,
}

/// The most a copy held for someone takes on this device: past it, nothing
/// more of it is taken (D80: about the size of their account).
pub const HELD_CAP: u64 = 64 << 20;

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
            takes_recovery_copies: false,
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
            let named = d.file_name().to_string_lossy().into_owned();
            let at = entries
                .iter()
                .position(|e| e.is_genesis() && hex::encode(e.id()) == named)
                .or_else(|| entries.iter().position(|e| e.is_genesis()));
            let Some(at) = at else {
                continue;
            };
            let mut log = IdentityLog::from_genesis(entries.remove(at))?;
            for e in entries {
                let _ = log.insert_any(e);
            }
            // already stored
            let _ = log.take_attached();
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
        cardinal_space::relationship::reach_of(h, who)
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
        use crate::cleanup::refs_in;
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

    /// Whether every other member of a space who has not left is a
    /// trusted contact of this person's, refused by none, and the space is
    /// not public: where a device that named itself as a host names itself
    /// unasked (D72). The other members' trust is not asked: only the
    /// person's.
    pub fn among_trusted(&self, space: &SpaceId) -> bool {
        let me = self.identity.as_ref().map(|i| i.id());
        let Some(sp) = self.spaces.get(space).and_then(|h| h.space.as_ref()) else {
            return false;
        };
        if sp.is_public() {
            return false;
        }
        let contacts = self.contacts();
        let trusted = |who: &[u8; 32]| contacts.iter().any(|c| c.identity == *who && c.connects());
        let mut others = sp.present().into_iter().filter(|m| Some(*m) != me);
        others.all(|m| trusted(&m))
    }

    /// What this person's reach node in a space tells, and whom.
    pub fn telling(&self, space: &SpaceId) -> Telling {
        let Some(me) = self.identity.as_ref().map(|i| i.id()) else {
            return Telling::default();
        };
        let Some(sp) = self.spaces.get(space).and_then(|h| h.space.as_ref()) else {
            return Telling::default();
        };
        let who = self.not_contacts_in(space);
        let values = sp.state().reach_values(&me, 1);
        let since: Vec<EntryId> = values.iter().map(|v| v.entry).collect();
        let due = self.spaces.get(space).map(|h| &h.arrivals.due);
        let due = |m: &&[u8; 32]| due.is_some_and(|d| d.values().any(|w| *w == hex::encode(m)));
        let hosts = self.mailboxes();
        let endpoints = hosts.iter().flat_map(|(g, _)| g.endpoints.iter());
        let named = self.reach_of(space, &me);
        let kept = self.spaces.get(space).and_then(|h| h.kept_yes.as_ref());
        let stands = kept.is_some_and(|k| k.list_set_by == list_set_by(sp, &me));
        let is_named = |key: &[u8; 32]| named.iter().any(|r| r.host == *key);
        let unnamed = hosts.iter().filter(|(g, _)| !is_named(g.link_key.x25519()));
        let here = self.keys.key();
        let own_unnamed = unnamed.clone().any(|(_, device)| *device == here);
        let own_self_named = hosts
            .iter()
            .any(|(g, device)| *device == here && crate::outside::is_self_named(g));
        let no = self.hosts_no(space);
        let joined = self.is_joined(space);
        let own_not_here = hosts
            .iter()
            .any(|(g, device)| *device == here && no.not_this(g.link_key.x25519()));
        Telling {
            said_no: no.no_hosts,
            own_not_here,
            not_here: no.not_these.iter().map(|(_, h)| *h).collect(),
            shared: !named.is_empty(),
            set: !since.is_empty(),
            two: since.len() > 1,
            waiting: stands && named.is_empty() && joined,
            hosted: !hosts.is_empty(),
            unnamed: unnamed.count(),
            own_unnamed,
            own_self_named,
            trusted_only: self.among_trusted(space),
            joined,
            left: sp.has_left(&me),
            public: sp.is_public(),
            relationship: sp.profile() == Profile::RELATIONSHIP,
            late: who.iter().filter(due).copied().collect(),
            who,
            what: endpoints.map(|e| e.to_string()).collect(),
        }
    }

    /// Which of `messages` in a space this person has read, as their own
    /// devices know it: those their read marker comes after, and those the
    /// read position the account keeps while read markers are off comes
    /// after (`profiles.md#relationship`).
    pub fn read_here(&self, space: &SpaceId, messages: &[relationship::Message]) -> Vec<bool> {
        let (Some(me), Some(sp)) = (
            self.me(),
            self.spaces.get(space).and_then(|h| h.space.as_ref()),
        ) else {
            return vec![false; messages.len()];
        };
        let mut read = relationship::read_by(sp, &me, messages);
        let acc = self.account().and_then(|a| a.space.as_ref());
        let at = acc
            .map(|a| account::read_up_to(a.state(), space))
            .unwrap_or_default();
        let dag = sp.dag();
        for pos in at {
            let Some(upto) = messages.iter().find(|m| m.id == pos) else {
                continue;
            };
            for (m, r) in messages.iter().zip(read.iter_mut()) {
                *r |= dag.is_ancestor_or_self(&m.entry, &upto.entry);
            }
        }
        read
    }

    /// A number that changes whenever any space held may have: for what
    /// is worked out from them and kept, as the keys of contacts' tags.
    pub fn state_version(&self) -> u64 {
        let all = self.spaces.values().map(|h| h.version);
        all.fold(self.spaces.len() as u64, |a, v| {
            a.wrapping_mul(31).wrapping_add(v)
        })
    }

    /// Whether this person is in a space: they accepted it by an entry of
    /// theirs there, or, having joined with nothing to say there, their
    /// account has a node for it that is not a decline (D75: a device
    /// writes when it has something to say), and they have not left it.
    /// Leaving deletes that node, so an offer made again asks afresh.
    pub fn is_joined(&self, space: &SpaceId) -> bool {
        let Some(me) = self.me() else { return false };
        let Some(sp) = self.spaces.get(space).and_then(|h| h.space.as_ref()) else {
            return false;
        };
        joined_in(
            self.account().and_then(|a| a.space.as_ref()),
            sp,
            space,
            &me,
        )
    }

    /// What this person's account records of a no to naming their hosts
    /// in a space (D75).
    pub fn hosts_no(&self, space: &SpaceId) -> account::HostsNo {
        match self.account().and_then(|h| h.space.as_ref()) {
            Some(acc) => account::hosts_no(acc.state(), space),
            None => account::HostsNo::default(),
        }
    }

    /// The entries whose lists this person's reach node in a space holds,
    /// in hex, sorted: with [`telling`](Self::telling), what a write of
    /// the list is decided on, and looked at again before it is made.
    pub fn list_set_by(&self, space: &SpaceId) -> Vec<String> {
        let me = self.identity.as_ref().map(|i| i.id());
        let sp = self.spaces.get(space).and_then(|h| h.space.as_ref());
        match (me, sp) {
            (Some(me), Some(sp)) => list_set_by(sp, &me),
            _ => Vec::new(),
        }
    }

    /// Keeps the person's yes on this device, to finish when a host can
    /// be reached: against the list as it is set now, so call it after
    /// whatever this device wrote for the act itself.
    pub fn keep_yes(&mut self, space: &SpaceId) {
        let Some(me) = self.identity.as_ref().map(|i| i.id()) else {
            return;
        };
        let Some(sp) = self.spaces.get(space).and_then(|h| h.space.as_ref()) else {
            return;
        };
        let list_set_by = list_set_by(sp, &me);
        let adds = sp.judge().valid_adds().into_iter();
        let present = Some(adds.map(|(_, add)| hex::encode(add)).collect());
        let kept = KeptYes {
            list_set_by,
            present,
        };
        self.set_kept_yes(space, Some(kept));
    }

    /// Gives up a yes this device kept, if it kept one.
    pub fn drop_yes(&mut self, space: &SpaceId) {
        self.set_kept_yes(space, None);
    }

    fn set_kept_yes(&mut self, space: &SpaceId, kept: Option<KeptYes>) {
        let Some(h) = self.spaces.get_mut(space).filter(|h| h.kept_yes != kept) else {
            return;
        };
        h.kept_yes = kept;
        h.version += 1;
        let saved = match &h.kept_yes {
            Some(k) => serde_json::to_vec(k)
                .map_err(std::io::Error::other)
                .and_then(|bytes| crate::paths::write_private(&h.kept_yes_at, &bytes, 0o600)),
            None => match std::fs::remove_file(&h.kept_yes_at) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
                _ => Ok(()),
            },
        };
        if let Err(e) = saved {
            tracing::warn!("space {}: keeping a yes for later: {e}", short(space));
        }
    }

    /// Gives up a kept yes that the list has been set since, by any
    /// device, or whose person has left the space.
    fn judge_kept_yes(&mut self, space: &SpaceId) {
        let Some(me) = self.identity.as_ref().map(|i| i.id()) else {
            return;
        };
        let Some(h) = self.spaces.get(space) else {
            return;
        };
        let (Some(kept), Some(sp)) = (h.kept_yes.as_ref(), h.space.as_ref()) else {
            return;
        };
        if kept.list_set_by != list_set_by(sp, &me) || sp.has_left(&me) {
            self.drop_yes(space);
        }
    }

    /// What this device sets its person's reach node in a space to now
    /// for the sake of its own entry there, on its own (D70,
    /// `hosts.md#telling-others-where-to-reach-you`): the list as it
    /// reads, each host once, with only the entry that names this device
    /// changed. `None` if nothing is due, as wherever the list does not
    /// name this device.
    ///
    /// - A device that serves no longer takes itself out: `host` (its own
    ///   setting) says it is no host, and its account names it as none.
    /// - A host gives its entry a `fresh` token where the one there is not
    ///   `active` here, and the `endpoints` its grant gives now.
    ///
    /// Whether another device still serves is that device's to know, and
    /// nothing here asks: an entry whose device is off or gone stays until
    /// that device, or the person, takes it out.
    pub fn own_entry_due(
        &self,
        space: &SpaceId,
        host: bool,
        endpoints: Option<&[cardinal_space::grant::Endpoint]>,
        active: impl Fn(&[u8; 16]) -> bool,
        fresh: impl FnMut() -> [u8; 16],
    ) -> Option<Vec<cardinal_space::relationship::Reach>> {
        let me = self.identity.as_ref()?.id();
        if !self.telling(space).keeps_current() {
            return None;
        }
        let here = *self.keys.link.public_key().x25519();
        let mut reach = self.reach_of(space, &me);
        if !reach.iter().any(|r| r.host == here) {
            return None;
        }
        if host {
            let mut kept = reach.clone();
            let changed = crate::mailbox::kept_current(&mut kept, &here, endpoints, active, fresh);
            if !changed {
                return None;
            }
            // A device that named itself (D72) gives a new address or
            // token only where every other member is still a trusted
            // contact; anywhere else it takes itself out instead.
            let self_named = self
                .mailboxes()
                .iter()
                .any(|(g, device)| *device == self.keys.key() && crate::outside::is_self_named(g));
            if self_named && !self.among_trusted(space) {
                reach.retain(|r| r.host != here);
                return Some(reach);
            }
            return Some(kept);
        }
        if self.hosts_here() {
            // between the two: turning hosting on or off writes the
            // account first, and this waits for the setting
            return None;
        }
        reach.retain(|r| r.host != here);
        Some(reach)
    }

    /// Whether this device is a host of its person's with a mailbox, by
    /// its own account.
    pub fn hosts_here(&self) -> bool {
        let here = self.keys.key();
        self.mailboxes().iter().any(|(_, device)| *device == here)
    }

    /// The spaces whose list of this person's hosts names this device.
    pub fn spaces_naming_here(&self) -> Vec<SpaceId> {
        let Some(me) = self.identity.as_ref().map(|i| i.id()) else {
            return Vec::new();
        };
        let here = *self.keys.link.public_key().x25519();
        let named = |id: &&SpaceId| self.reach_of(id, &me).iter().any(|r| r.host == here);
        self.spaces.keys().filter(named).copied().collect()
    }

    /// Every token this person ever gave out for `host` in a space,
    /// whatever their list there says now (`profiles.md#reach`: each
    /// serves until it is revoked, named now or not).
    pub fn tokens_given(&self, space: &SpaceId, host: &[u8; 32]) -> Vec<[u8; 16]> {
        let me = self.identity.as_ref().map(|i| i.id());
        let sp = self.spaces.get(space).and_then(|h| h.space.as_ref());
        let (Some(me), Some(sp)) = (me, sp) else {
            return Vec::new();
        };
        let ever = cardinal_space::relationship::reach_ever(sp, &me).into_iter();
        ever.filter(|r| r.host == *host).map(|r| r.token).collect()
    }

    /// Notes the additions to a space this device has not looked at yet
    /// ([`Arrivals`]). While the person's list there names no host there
    /// is nobody to tell of, and nothing is noted: whoever is there when
    /// they next share is whom they share with, unless the sharing is a
    /// yes this device kept from before they came ([`KeptYes`]). While it names one, each
    /// new addition is noted once. The person is to be told of someone who
    /// is not their contact and came while the hosts were named: no entry
    /// that began the naming has their addition in its past, so someone
    /// who left and was added again counts. Anyone else needs no telling,
    /// someone who is a contact now included: refusing them later does
    /// not bring them back.
    fn note_arrivals(&mut self, space: &SpaceId) {
        let Some(me) = self.identity.as_ref().map(|i| i.id()) else {
            return;
        };
        let Some(sp) = self.spaces.get(space).and_then(|h| h.space.as_ref()) else {
            return;
        };
        let was = &self.spaces[space].arrivals;
        let mut now = was.clone();
        if cardinal_space::relationship::reach_of(sp, &me).is_empty() {
            now.due.clear();
        } else {
            let adds = sp.judge().valid_adds().into_iter();
            let noted = |add: &EntryId| {
                let add = hex::encode(add);
                was.told.contains(&add) || was.due.contains_key(&add)
            };
            let fresh: Vec<([u8; 32], EntryId)> = adds.filter(|(_, add)| !noted(add)).collect();
            if fresh.is_empty() {
                return;
            }
            let began = cardinal_space::relationship::naming_began(sp, &me);
            let came = sp.added_after(&began);
            let strangers = self.not_contacts_in(space);
            // A yes this device kept, finished by it just now: whoever
            // was added since it was kept came after the yes, and was not
            // there when it was given.
            let here = self.keys.key();
            let by_this_device = |e: &EntryId| sp.entry(e).is_some_and(|e| e.signer() == here);
            let kept = self.spaces[space].kept_yes.as_ref();
            let kept = kept.filter(|_| began.iter().all(by_this_device));
            let present = kept.and_then(|k| k.present.as_ref());
            let after_yes = |add: &EntryId| present.is_some_and(|p| !p.contains(&hex::encode(add)));
            for (who, add) in fresh {
                let late = came.contains(&who) || after_yes(&add);
                if late && strangers.contains(&who) {
                    now.due.insert(hex::encode(add), hex::encode(who));
                } else {
                    now.told.insert(hex::encode(add));
                }
            }
        }
        if now != *was {
            self.keep_arrivals(space, now);
        }
    }

    fn keep_arrivals(&mut self, space: &SpaceId, now: Arrivals) {
        let Some(h) = self.spaces.get_mut(space) else {
            return;
        };
        h.arrivals = now;
        h.version += 1;
        let saved = serde_json::to_vec(&h.arrivals)
            .map_err(std::io::Error::other)
            .and_then(|bytes| crate::paths::write_private(&h.arrivals_at, &bytes, 0o600));
        if let Err(e) = saved {
            tracing::warn!("space {}: keeping who was told of: {e}", short(space));
        }
    }

    /// The person has been told, on this device, of everyone added to a
    /// space so far (`group-reach`): nobody there is left to tell of here.
    /// Another of their devices tells them in its own time.
    pub fn told_of_all(&mut self, space: &SpaceId) {
        let Some(sp) = self.spaces.get(space).and_then(|h| h.space.as_ref()) else {
            return;
        };
        let mut now = self.spaces[space].arrivals.clone();
        now.due.clear();
        let adds = sp.judge().valid_adds().into_iter();
        now.told.extend(adds.map(|(_, add)| hex::encode(add)));
        if now != self.spaces[space].arrivals {
            self.keep_arrivals(space, now);
        }
    }

    /// The groups this person is in where their reach node names their
    /// hosts and `who` is a member who has not left: where someone they
    /// refuse still reads the address. Software asks about these as part
    /// of refusing, on the device refused on
    /// (`hosts.md#telling-others-where-to-reach-you`); the relationship
    /// with that person is not among them.
    pub fn groups_naming_hosts_to(&self, who: &[u8; 32]) -> Vec<SpaceId> {
        let mut out = Vec::new();
        for (id, h) in &self.spaces {
            let Some(sp) = h.space.as_ref() else { continue };
            if sp.profile() != cardinal_space::group::GROUP || !sp.present().contains(who) {
                continue;
            }
            let t = self.telling(id);
            if t.shared && t.joined {
                out.push(*id);
            }
        }
        out
    }

    /// The space this person gave out a token in: in the list as it
    /// stands, or in any list they ever set there. A token serves until
    /// it is revoked, and what was left under one the list names no
    /// longer is opened like any other (`profiles.md#reach`).
    pub fn space_of_token(&self, token: &[u8; 16]) -> Option<SpaceId> {
        let me = self.identity.as_ref()?.id();
        let named = self.spaces.keys().copied().find(|id| {
            let reach = self.reach_of(id, &me);
            reach.iter().any(|r| r.token == *token)
        });
        named.or_else(|| {
            let open = self.spaces.iter();
            let mut open = open.filter_map(|(id, h)| Some((id, h.space.as_ref()?)));
            let given = |sp: &Space| {
                let ever = cardinal_space::relationship::reach_ever(sp, &me);
                ever.iter().any(|r| r.token == *token)
            };
            open.find(|(_, sp)| given(sp)).map(|(id, _)| *id)
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

    /// The held copy nodes this person and `who` wrote in their relationship
    /// (`relationship::held`): (this person's, theirs).
    fn held_nodes(&self, who: &[u8; 32]) -> (Vec<[u8; 32]>, Vec<[u8; 32]>) {
        let me = self.me();
        let Some(c) = self.contacts().into_iter().find(|c| c.identity == *who) else {
            return (Vec::new(), Vec::new());
        };
        let Some(sp) = self.spaces.get(&c.space).and_then(|h| h.space.as_ref()) else {
            return (Vec::new(), Vec::new());
        };
        let all = cardinal_space::relationship::held(sp);
        let mine = all
            .iter()
            .filter(|(a, _)| Some(*a) == me)
            .map(|(_, l)| *l)
            .collect();
        let theirs = all
            .iter()
            .filter(|(a, _)| a == who)
            .map(|(_, l)| *l)
            .collect();
        (mine, theirs)
    }

    /// The sets this person gives `who` to hold for them, sealed (D80): its
    /// account, to a guardian; what a guardian holds, from their persona to
    /// a recovery helper. `who` may fetch them.
    pub fn held_given(&self, who: &[u8; 32]) -> Vec<[u8; 32]> {
        // to a guardian only while they are one, as the account marks them;
        // to a recovery helper, from a persona
        let contact = self.contacts().into_iter().find(|c| c.identity == *who);
        if !contact.is_some_and(|c| c.guardian || c.recovery_of.is_some()) {
            return Vec::new();
        }
        let (mine, _) = self.held_nodes(who);
        mine.into_iter()
            .filter(|l| self.spaces.contains_key(l))
            .collect()
    }

    /// Takes a copy held for someone off this device.
    pub fn drop_held(&mut self, label: &[u8; 32]) {
        if self.spaces.remove(label).is_some() {
            let dir = Holder::dir(&self.paths, label);
            if let Err(e) = std::fs::remove_dir_all(&dir) {
                tracing::warn!("cannot remove {}: {e}", dir.display());
            }
        }
    }

    /// Whether a copy held for someone grew past [`HELD_CAP`].
    pub fn held_full(&self, label: &[u8; 32]) -> bool {
        let file = Holder::dir(&self.paths, label).join("entries.log");
        std::fs::metadata(file).is_ok_and(|m| m.len() > HELD_CAP)
    }

    /// The sets `who` gives this person to hold, which it takes: a person's
    /// account, where this person guards them through a persona; what a
    /// guardian's persona gives, on a recovery helper.
    /// The sets `who` names for this person to hold, past the cap or not.
    pub fn held_named_by(&self, who: &[u8; 32]) -> Vec<[u8; 32]> {
        self.held_nodes(who).1
    }

    pub fn held_taken(&self, who: &[u8; 32]) -> Vec<[u8; 32]> {
        let contact = self.contacts().into_iter().find(|c| c.identity == *who);
        let takes = contact.is_some_and(|c| {
            (self.takes_recovery_copies && c.recovery_of.is_some())
                || (c.recovery_of.is_none() && self.guards_through_persona(who))
        });
        if !takes {
            return Vec::new();
        }
        // A guardian holds one set for a person, the first they named: the
        // account. A helper holds at most two from each persona: the
        // account and that guardian's relationship with the person. No
        // more, whoever names more (a thief with a stolen device among
        // them).
        let most = if self.takes_recovery_copies { 2 } else { 1 };
        let mut out: Vec<[u8; 32]> = Vec::new();
        for l in self.held_nodes(who).1 {
            if !out.contains(&l) && out.len() < most {
                out.push(l);
            }
        }
        // and none past the cap, whatever is sent
        out.retain(|l| !self.held_full(l));
        out
    }

    /// Whether this person holds a guardian persona for `who`, not burned.
    pub fn guards_through_persona(&self, who: &[u8; 32]) -> bool {
        let Some(acc) = self.account().and_then(|a| a.space.as_ref()) else {
            return false;
        };
        cardinal_space::account::personas(acc.state())
            .iter()
            .any(|p| {
                p.purpose == cardinal_space::account::GUARDIAN_PURPOSE
                    && p.for_identity == Some(*who)
                    && !p.burned
            })
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
        // copies held for one or the other (D80)
        for l in self
            .held_given(identity)
            .into_iter()
            .chain(self.held_taken(identity))
        {
            if !v.contains(&l) {
                v.push(l);
            }
        }
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
        self.reload_unsaved(space);
        self.note_arrivals(space);
        self.judge_kept_yes(space);
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
                // Someone added since the epoch started has the key they
                // had when this device first saw them with one: their
                // `add_member` gave them the epoch's. Anyone else the
                // record has no key for was a member when it started, and
                // may not have been wrapped for: this device did not hold
                // their identity log yet, or a `leave` of theirs has since
                // stopped counting. The first key held for them is a
                // change.
                let since: Vec<String> = sp.added_since_epoch().iter().map(hex::encode).collect();
                let mut unkeyed = false;
                for (who, key) in &now.keys {
                    if record.keys.contains_key(who) {
                        continue;
                    }
                    if since.contains(who) {
                        record.keys.insert(who.clone(), key.clone());
                        changed = true;
                    } else {
                        unkeyed = true;
                    }
                }
                unkeyed || record.calls_for_a_new_epoch(&now)
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

    /// A space that took something in memory and could not save it is read
    /// again from what the device holds, so that nothing written next
    /// builds on an entry that is nowhere. If it cannot be read either it
    /// stays as it is, and this is tried again.
    fn reload_unsaved(&mut self, space: &SpaceId) {
        let Some(was) = self.spaces.get(space).filter(|h| h.unsaved) else {
            return;
        };
        let Some(ident) = self.identity.as_ref() else {
            return;
        };
        let version = was.version + 1;
        match Holder::open(&self.paths, *space, &ident.key_refs(), &self.logs) {
            Ok(mut held) => {
                held.version = version;
                self.spaces.insert(*space, held);
            }
            Err(e) => tracing::error!(
                "space {}: an entry could not be saved, and the space could not be read \
                 again: {e:#}",
                short(space)
            ),
        }
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

    /// The groups whose content a contact may fetch from here: those the
    /// two are both in. This person is in a group once they have accepted
    /// it; one they were only offered serves nothing, since whoever made
    /// it chose what it names.
    pub fn groups_shared_with(&self, who: &[u8; 32]) -> Vec<SpaceId> {
        let me = self.me();
        let theirs = |s: &Space| {
            s.profile() == cardinal_space::group::GROUP
                && s.role_of(who).is_some()
                && !s.has_left(who)
        };
        let held = self.spaces.iter();
        let groups = held.filter(|(id, h)| {
            h.space.as_ref().is_some_and(theirs) && me.is_some() && self.is_joined(id)
        });
        groups.map(|(id, _)| *id).collect()
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
        // inviter's log, with the relationship profile, a policy that is
        // not public, and exactly two `add_member` ops, one naming each of
        // these two identities as a writer; and a space it does not
        // already hold. A public one would carry the key of everything
        // the two say in the clear.
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
                && !space.is_public()
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
        // The first genesis is this identity's: guardians' logs held under
        // its label come after it.
        let gi = entries
            .iter()
            .position(|e| e.is_genesis())
            .ok_or_else(|| anyhow::anyhow!("the identity log has no genesis entry"))?;
        let g = entries.remove(gi);
        let mut log = IdentityLog::from_genesis(g)?;
        for e in entries {
            let _ = log.insert_any(e);
        }
        // already stored
        let _ = log.take_attached();
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
                .map(|i| i.log.all_heads())
                .unwrap_or_default();
        }
        if let Some(o) = self.other(label) {
            return o.log.all_heads();
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
        let Some(log) = self.joining_log(&expected) else {
            return Ok(IdentityChange::default());
        };
        if !log.state().keys.contains_key(&self.keys.key()) {
            return Ok(IdentityChange::default());
        }
        let bytes = log_bytes(&log);
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

    /// The log of `identity` collected while joining it, with the
    /// guardians' logs that came under its label.
    pub fn joining_log(&self, identity: &[u8; 32]) -> Option<IdentityLog> {
        let entries: Vec<IdentityEntry> = self
            .joining
            .iter()
            .filter_map(|b| IdentityEntry::decode(b).ok())
            .collect();
        let g = entries
            .iter()
            .find(|e| e.is_genesis() && e.id() == *identity)?;
        let mut log = IdentityLog::from_genesis(g.clone()).ok()?;
        for e in &entries {
            if e.id() != *identity {
                let _ = log.insert_any(e.clone());
            }
        }
        Some(log)
    }

    /// Restoring (`hosts.md#restore`): the entry that adds this device, as
    /// an admin device, to the log of `identity` collected from a host,
    /// signed by the root key from the words. Returns it and its id.
    pub fn add_restoring_device(
        &self,
        identity: &[u8; 32],
        phrase: &cardinal_crypto::RecoveryPhrase,
    ) -> anyhow::Result<(Vec<u8>, [u8; 32])> {
        let mut log = self
            .joining_log(identity)
            .ok_or_else(|| anyhow::anyhow!("that device did not send the identity log"))?;
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

    /// The work of `key`, a device or admin key this person's log once
    /// named and has since removed, that nothing witnessed: in each space
    /// held, its own entries set aside, with the time each says it was
    /// written (`spaces.md#authors`). Other members' keys are not this
    /// person's to keep.
    pub fn unwitnessed_work(
        &self,
        key: &KeyId,
    ) -> anyhow::Result<Vec<(SpaceId, EntryId, Option<u64>)>> {
        let ident = self
            .identity
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("this device has no identity yet"))?;
        let me = ident.id();
        let named = ident.log.entries().any(|e| {
            e.ops().iter().any(|o| {
                matches!(o.body(), cardinal_identity::OpBody::AddKey { key: k, power, .. }
                    if k == key && *power < 3)
            })
        });
        anyhow::ensure!(named, "that is not one of your devices");
        anyhow::ensure!(
            ident.state().power(key).is_none(),
            "that device is still one of yours: its work counts as it is"
        );
        let mut out = Vec::new();
        for (id, h) in &self.spaces {
            let Some(space) = h.space.as_ref() else {
                continue;
            };
            for x in &space.validity().unwitnessed {
                let Some(e) = space.dag().get(x) else {
                    continue;
                };
                if e.signer() == *key && e.author() == me {
                    out.push((*id, *x, e.time()));
                }
            }
        }
        out.sort_by_key(|(s, x, t)| (*t, *s, *x));
        Ok(out)
    }

    /// Keeps the work of `key` that nothing witnessed, written up to
    /// `up_to` (milliseconds since the epoch, by the device's own clock;
    /// everything if `None`), in every space held: a `keep` op listing
    /// the latest of those entries, which covers the ones before them.
    /// What the person does not recognize, after the point they choose,
    /// stays set aside (`spaces.md#authors`). Returns what was written, by
    /// space, and how many entries are kept.
    pub fn keep_work(
        &mut self,
        key: &KeyId,
        up_to: Option<u64>,
    ) -> anyhow::Result<(Written, usize)> {
        let work = self.unwitnessed_work(key)?;
        let mut by_space: BTreeMap<SpaceId, Vec<EntryId>> = BTreeMap::new();
        for (space, x, t) in work {
            let wanted = match (up_to, t) {
                (None, _) => true,
                (Some(u), Some(t)) => t <= u,
                (Some(_), None) => false,
            };
            if wanted {
                by_space.entry(space).or_default().push(x);
            }
        }
        let ident = self.identity.as_ref().expect("checked");
        let mut written = Vec::new();
        let mut kept = 0;
        for (id, xs) in by_space {
            let h = self.spaces.get_mut(&id).expect("held");
            let dag = h.space.as_ref().expect("open").dag();
            // An entry kept keeps its ancestors, so a later one past the
            // point must not be listed: only the latest within it are.
            let mut latest: Vec<EntryId> = xs
                .iter()
                .filter(|x| !xs.iter().any(|y| y != *x && dag.is_ancestor(x, y)))
                .copied()
                .collect();
            latest.sort();
            kept += xs.len();
            let bytes = h.write_keeps(ident, &self.keys, vec![SpaceOp::keep(*key, &latest)])?;
            written.push((id, bytes));
        }
        let ids: Vec<SpaceId> = written.iter().map(|(id, _)| *id).collect();
        for id in ids {
            self.settle(&id);
        }
        Ok((written, kept))
    }

    /// Keeps, in each of `spaces`, everything this person's removed devices
    /// wrote that nothing witnessed: the account and relationships the
    /// guardians gave back after a recovery that kept no old key (D80),
    /// whose every entry is such work. Returns the entries written.
    pub fn keep_given_back(&mut self, spaces: &[SpaceId]) -> anyhow::Result<Written> {
        let ident = self
            .identity
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("this device has no identity yet"))?;
        let me = ident.id();
        let st = ident.state();
        let mut written = Vec::new();
        for id in spaces {
            let Some(h) = self.spaces.get_mut(id) else {
                continue;
            };
            let Some(space) = h.space.as_ref() else {
                continue;
            };
            let dag = space.dag();
            let mut by_key: BTreeMap<KeyId, Vec<EntryId>> = BTreeMap::new();
            for x in &space.validity().unwitnessed {
                let Some(e) = dag.get(x) else { continue };
                if e.author() == me && st.power(&e.signer()).is_none() {
                    by_key.entry(e.signer()).or_default().push(*x);
                }
            }
            for (key, xs) in by_key {
                let dag = h.space.as_ref().expect("open").dag();
                let mut latest: Vec<EntryId> = xs
                    .iter()
                    .filter(|x| !xs.iter().any(|y| y != *x && dag.is_ancestor(x, y)))
                    .copied()
                    .collect();
                latest.sort();
                let bytes = h.write_keeps(ident, &self.keys, vec![SpaceOp::keep(key, &latest)])?;
                written.push((*id, bytes));
            }
        }
        for id in spaces {
            if self.spaces.contains_key(id) {
                self.settle(id);
            }
        }
        Ok(written)
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

    /// The account space, once held and open: the one with the account
    /// profile that is this person's own (`profiles.md#account`, "Which
    /// space it is"). A device holds other people's spaces too, and one of
    /// those is never the account, whatever profile its genesis claims.
    pub fn account(&self) -> Option<&Holder> {
        let own = |h: &&Holder| h.profile() == Some(Profile::ACCOUNT) && self.own_alone(h);
        self.spaces.values().find(own)
    }

    /// Whether a space is this person's own and nobody else's: its genesis
    /// was written by their identity, counts, and names that identity as
    /// owner and nobody else. Nobody else can make such a space, since it
    /// takes a signature by a key of the identity; so it is one this
    /// person's devices made, however it reached this one.
    fn own_alone(&self, h: &Holder) -> bool {
        let me = self.identity.as_ref().map(|i| i.id());
        let (Some(me), Some(sp)) = (me, h.space.as_ref()) else {
            return false;
        };
        let Some(genesis) = sp.entry(&sp.id()) else {
            return false;
        };
        let named = genesis.ops().iter().filter_map(|op| match op.body() {
            cardinal_space::SpaceOpBody::AddMember { identity, role, .. } => {
                Some((*identity, *role))
            }
            _ => None,
        });
        let named: Vec<([u8; 32], u64)> = named.collect();
        let owner = cardinal_space::entry::OWNER;
        sp.creator() == me && sp.validity().is_valid(&sp.id()) && named == [(me, owner)]
    }

    /// Makes a space's log refuse what is appended from now on.
    #[cfg(test)]
    pub fn break_log_for_test(&mut self, space: &SpaceId) {
        self.spaces
            .get_mut(space)
            .expect("held")
            .file
            .break_for_test();
    }

    /// This person's identity, once the device has one.
    pub fn me(&self) -> Option<[u8; 32]> {
        self.identity.as_ref().map(|i| i.id())
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
        // one of this person's own, never a files space someone shared
        let own = |h: &&Holder| h.profile() == Some(Profile::FILES) && self.own_alone(h);
        self.spaces.values().find(own).map(|h| h.id)
    }

    /// The name the person suggests for themselves, from the account's
    /// self node, if it has one with a name in it.
    pub fn self_name(&self) -> Option<String> {
        let acc = self.account()?.space.as_ref()?;
        let (_, name) = account::self_node(acc.state())?;
        (!name.is_empty()).then_some(name)
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
            setup::install(&paths, p, &Config::default(), "Me").unwrap();
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
            self.genesis_with(profile, Policy::default(), members, to)
        }

        /// [`genesis`](Self::genesis), with a policy.
        fn genesis_with(
            &self,
            profile: Profile,
            policy: Policy,
            members: &[([u8; 32], u64)],
            to: &Person,
        ) -> Vec<u8> {
            let ident = self.core.identity.as_ref().unwrap();
            let mut ops: Vec<SpaceOp> = members
                .iter()
                .map(|(who, role)| SpaceOp::add_member(*who, *role))
                .collect();
            ops.extend(relationship::genesis_ops(self.id(), to.id()).split_off(2));
            let (_, sealed) = Space::create_with(
                profile,
                policy,
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

    /// P1 (`profiles.md#account`, "Which space it is"). A device's account
    /// is the space its own identity wrote, with the account profile, that
    /// names that identity as owner and nobody else. A space that a
    /// contact made is never it, whatever profile its genesis claims and
    /// whatever its id: here one that sorts before the real one, as a
    /// contact can make by trying a few.
    #[test]
    fn a_space_a_contact_made_is_never_the_account() {
        use cardinal_space::account::{self, Regard};
        let (mut ana, mut bo) = (Person::new(), Person::new());
        ana.meets(&bo);
        bo.meets(&ana);
        bo.knows(&ana, "Ana");
        let real = bo.core.account_id().unwrap();
        let files = bo.core.files_id().unwrap();
        let his = bo.enc();
        let made = |profile: Profile, roles: &[([u8; 32], u64)], below: &SpaceId| {
            let ident = ana.core.identity.as_ref().unwrap();
            let ops: Vec<SpaceOp> = roles
                .iter()
                .map(|(who, role)| SpaceOp::add_member(*who, *role))
                .collect();
            (0..400).find_map(|n| {
                let (space, sealed) = Space::create_with(
                    profile,
                    Policy::default(),
                    &ident.log,
                    &ana.core.keys.device.signing,
                    &[&ana.enc(), &his],
                    ops.clone(),
                    Some(now_ms() + n),
                )
                .unwrap();
                (space.id() < *below).then(|| (space.id(), sealed.encode()))
            })
        };
        let (a, b) = (ana.id(), bo.id());
        // The contact owns it, and the device's person is a writer in it.
        let (fake, genesis) = made(Profile::ACCOUNT, &[(a, OWNER), (b, WRITER)], &real).unwrap();
        // In it, a contact record of the contact's choosing.
        bo.core.ingest_space(fake, &[genesis]).unwrap();
        assert!(
            bo.core.spaces[&fake].space.is_some(),
            "the offered space is held"
        );
        assert_eq!(bo.core.account_id(), Some(real));
        let known: Vec<String> = bo.core.contacts().into_iter().map(|c| c.petname).collect();
        assert_eq!(known, ["Ana"]);
        // What this device writes to its account goes to its own.
        let account = bo.core.account_id().unwrap();
        let contact = account::create_contact(&[9; 32], "Cy", &[7; 32], Regard::default());
        bo.core.write_entry(&account, vec![contact]).unwrap();
        assert_eq!(bo.space(&fake).dag().len(), 1);
        // Nor one that names the person as owner, written by the contact;
        // nor one of their own with someone else in it.
        let (fake, genesis) = made(Profile::ACCOUNT, &[(a, WRITER), (b, OWNER)], &real).unwrap();
        bo.core.ingest_space(fake, &[genesis]).unwrap();
        assert_eq!(bo.core.account_id(), Some(real));
        // And a files space a contact made is not this person's files.
        let (fake, genesis) = made(Profile::FILES, &[(a, OWNER), (b, WRITER)], &files).unwrap();
        bo.core.ingest_space(fake, &[genesis]).unwrap();
        assert_eq!(bo.core.files_id(), Some(files));
        // An offer is never of an account or of a relationship: none of
        // these is shown as one, and a relationship a contact sent this
        // way is nobody's.
        let top = [255; 32];
        let (fake, genesis) =
            made(Profile::RELATIONSHIP, &[(a, WRITER), (b, WRITER)], &top).unwrap();
        bo.core.ingest_space(fake, &[genesis]).unwrap();
        let listed = crate::groups::list_of(&bo.core);
        assert_eq!(listed["offers"], serde_json::json!([]), "{listed}");
        assert_eq!(listed["groups"], serde_json::json!([]), "{listed}");
        assert_eq!(bo.core.contacts().len(), 2);
        // A restart finds the same.
        bo.restarts();
        assert_eq!(bo.core.account_id(), Some(real));
        assert_eq!(bo.core.files_id(), Some(files));
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
        let public = Policy {
            public: true,
            ..Policy::default()
        };
        let not_theirs: [(&str, Vec<u8>); 11] = [
            (
                "a policy that makes it public",
                ana.genesis_with(rel, public, &[(a, WRITER), (b, WRITER)], &bo),
            ),
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
        /// Makes this person's one device a host of theirs, at `address`.
        fn hosts_at(&mut self, address: &str) {
            use cardinal_space::grant::{Endpoint, Grant, MAILBOX, STORAGE};
            let account = self.core.account_id().unwrap();
            let me = self.core.keys.key();
            let grant = Grant {
                host: self.id(),
                served: self.id(),
                // as `cardinal host` makes one: storage too, so it is no
                // device that named itself (D72)
                services: vec![MAILBOX, STORAGE],
                storage_bytes: 0,
                retention_days: 0,
                endpoints: vec![Endpoint::parse(address).unwrap()],
                link_key: self.core.keys.link.public_key().clone(),
            }
            .sign(&self.core.keys.device.signing);
            let devices = account::devices(self.space(&account).state());
            let node = devices.iter().find(|d| d.key == me).unwrap().node;
            let ops = vec![
                account::set_field(node, 4, true),
                account::create_host(&grant),
            ];
            self.core.write_entry(&account, ops).unwrap();
            assert_eq!(self.core.mailboxes().len(), 1);
        }

        /// Records `other` as a contact, as accepting an invitation does.
        fn knows(&mut self, other: &Person, name: &str) {
            use cardinal_space::account::Regard;
            let account = self.core.account_id().unwrap();
            let contact = account::create_contact(&other.id(), name, &[7; 32], Regard::default());
            self.core.write_entry(&account, vec![contact]).unwrap();
        }

        /// The id of the space a sealed genesis starts.
        fn space_of(&self, genesis: &[u8]) -> SpaceId {
            let sealed = cardinal_space::SealedEntry::decode(genesis).unwrap();
            let ident = self.core.identity.as_ref().unwrap();
            let opened = Space::open_genesis(&sealed, &ident.key_refs(), None).unwrap();
            opened.id()
        }

        /// Sets this person's reach node in a space, to one host or none:
        /// the host they have, if they have one.
        fn says_reach(&mut self, space: &SpaceId, host: bool) -> Vec<u8> {
            let hosts = self.core.mailboxes();
            let key = hosts.first().map(|(g, _)| *g.link_key.x25519());
            let reach = relationship::Reach {
                endpoints: Vec::new(),
                host: key.unwrap_or([9; 32]),
                token: cardinal_crypto::random_bytes(),
                extra: Default::default(),
            };
            let list = if host { vec![reach] } else { Vec::new() };
            // the person's answer, recorded in the account first (D75)
            let account = self.core.account_id().unwrap();
            let st = self.space(&account).state();
            let record = match host {
                true => account::yes_ops(st, space, &key.into_iter().collect::<Vec<_>>()),
                false => account::say_no_ops(st, space, "a space"),
            };
            if !record.is_empty() {
                self.core.write_entry(&account, record).unwrap();
            }
            let op = relationship::set_reach(&self.id(), &list);
            self.core.write_entry(space, vec![op]).unwrap().1
        }

        /// Stops this person's device being a host, as `host --off` does.
        fn hosts_no_longer(&mut self) {
            let account = self.core.account_id().unwrap();
            let me = self.core.keys.key();
            let state = self.space(&account).state();
            let device = account::devices(state).into_iter().find(|d| d.key == me);
            let mut ops = vec![account::set_field(device.unwrap().node, 4, false)];
            let hosts = account::hosts(state).into_iter();
            ops.extend(hosts.map(|h| SpaceOp::delete(h.node)));
            self.core.write_entry(&account, ops).unwrap();
            assert!(self.core.mailboxes().is_empty());
        }
    }

    fn four() -> [Person; 4] {
        let mut p = [Person::new(), Person::new(), Person::new(), Person::new()];
        for i in 0..4 {
            for j in 0..4 {
                if i != j {
                    let (log, id) = (p[j].log(), p[j].id());
                    p[i].core.ingest_other(id, &log).unwrap();
                }
            }
        }
        p
    }

    /// `hosts.md#telling-others-where-to-reach-you`: software names a
    /// person's hosts unasked only when they join where everyone else is
    /// their contact. Anywhere else it asks first. The answer is the
    /// person's, the list is where it is kept, and no device goes against
    /// it: an empty list stays empty until they say otherwise.
    #[test]
    fn the_list_of_hosts_is_the_persons_answer() {
        let [mut ana, mut bo, cy, _] = four();
        bo.knows(&ana, "Ana");
        let both = [(bo.id(), "Bo".to_owned()), (cy.id(), "Cy".to_owned())];
        let g = ana.core.create_group("Garden club", "Ana", &both).unwrap();
        bo.takes(&g, &ana.all_of(&g));

        // Offered a group with Cy in it, who is not his contact. With no
        // host there is nothing anyone would learn, and nothing to ask.
        let t = bo.core.telling(&g);
        assert_eq!(
            (t.who.as_slice(), t.hosted, t.joined),
            (&[cy.id()][..], false, false)
        );
        assert!(!t.ask() && !t.sets_unasked());
        // With a host he is asked, and told who would learn what.
        bo.hosts_at("203.0.113.5:7171");
        let t = bo.core.telling(&g);
        assert!(t.ask() && !t.sets_unasked());
        assert_eq!(t.what, ["203.0.113.5:7171"]);
        // Joining shares as he says. With nothing said it shares only
        // among contacts, which these are not.
        assert!(t.joins_sharing(Some(true)) && !t.joins_sharing(Some(false)));
        assert!(!t.joins_sharing(None));

        // He joins and says no: the empty list, and nothing else. Nothing
        // fills it in, here or on another of his devices.
        bo.says_reach(&g, false);
        let t = bo.core.telling(&g);
        assert!(t.joined && t.set && !t.shared);
        assert!(!t.ask() && !t.sets_unasked() && !t.keeps_current());
        // not even once everyone there is his contact
        bo.knows(&cy, "Cy");
        let t = bo.core.telling(&g);
        assert!(t.who.is_empty() && !t.sets_unasked() && !t.empties_unasked());
        // and it survives a restart: it is in the space
        bo.restarts();
        let t = bo.core.telling(&g);
        assert!(t.set && !t.shared && !t.sets_unasked() && !t.ask());

        // He says yes, on this device: named, and kept current from then
        // on. Nothing empties it.
        bo.says_reach(&g, true);
        let t = bo.core.telling(&g);
        assert!(t.shared && !t.sets_unasked() && t.keeps_current());
        assert!(!t.empties_unasked() && t.unnamed == 0);
        // And no again: as it was.
        bo.says_reach(&g, false);
        let t = bo.core.telling(&g);
        assert!(!t.shared && !t.sets_unasked() && !t.ask());

        // Ana made the group and knows them both: she is in it, and her
        // list was never set. That is her joining, among contacts: it is
        // set unasked, to her hosts, or to nothing as here, and then left
        // alone.
        ana.knows(&bo, "Bo");
        ana.knows(&cy, "Cy");
        let t = ana.core.telling(&g);
        assert!(t.joined && !t.set && t.sets_unasked() && !t.ask());
        assert!(t.joins_sharing(None));
        ana.says_reach(&g, false);
        assert!(!ana.core.telling(&g).sets_unasked());
        // A host she takes up later is named in no group until she says
        // where: nobody can tell her empty list from a no.
        ana.hosts_at("203.0.113.6:7171");
        let t = ana.core.telling(&g);
        assert!(t.hosted && t.unnamed == 1);
        assert!(!t.sets_unasked() && !t.ask());
    }

    /// P10, D68, D75 (`hosts.md#telling-others-where-to-reach-you`). One
    /// of a person's devices says no: the record in the account, and the
    /// empty list. Another of their devices has both, a host to name, and
    /// nobody there but contacts. It must not name the hosts again, nor a
    /// host taken up later: only a yes takes the no out.
    #[test]
    fn a_device_does_not_fill_in_a_list_another_emptied() {
        let [mut ana, mut bo, cy, _] = four();
        bo.knows(&ana, "Ana");
        bo.hosts_at("203.0.113.5:7171");
        let both = [(bo.id(), "Bo".to_owned()), (cy.id(), "Cy".to_owned())];
        let club = ana.core.create_group("Garden club", "Ana", &both).unwrap();
        let bo_shown = [(bo.id(), "Bo".to_owned())];
        let choir = ana.core.create_group("Choir", "Ana", &bo_shown).unwrap();
        for g in [&club, &choir] {
            bo.takes(g, &ana.all_of(g));
        }
        for g in [&club, &choir] {
            // He shared his host there, and then, on another device,
            // stopped. This device has that entry of the space.
            bo.says_reach(g, true);
            assert!(bo.core.telling(g).shared);
            bo.says_reach(g, false);
            let t = bo.core.telling(g);
            assert!(t.joined && t.set && !t.shared && t.hosted);
            assert!(!t.sets_unasked(), "it names the hosts again");
            assert!(!t.keeps_current() && !t.ask());
            // and so it stays, through a restart
            bo.restarts();
            assert!(!bo.core.telling(g).sets_unasked());
        }
        // The same for a host he takes up later: among contacts too, it is
        // named in no group until he says so.
        ana.knows(&bo, "Bo");
        ana.says_reach(&choir, false);
        ana.hosts_at("203.0.113.6:7171");
        let t = ana.core.telling(&choir);
        assert!(t.who.is_empty() && t.hosted && !t.shared);
        assert!(!t.sets_unasked(), "a new host is named unasked");
    }

    /// D68, D70 (`profiles.md#reach`). Two of a person's devices set the
    /// list at the same moment, one to their host and one to nothing. The
    /// empty one wins wherever a host is looked up. Two lists that both
    /// name hosts both count, and a host named in both is one host.
    /// Nobody writes only to make the two one: nothing is due on any
    /// device until one writes its own entry or the person says yes or
    /// no.
    #[test]
    fn of_two_lists_an_empty_one_wins_and_nobody_writes_to_make_them_one() {
        let [mut ana, mut bo, mut cy, _] = four();
        bo.knows(&ana, "Ana");
        bo.hosts_at("203.0.113.5:7171");
        let own = *bo.core.keys.link.public_key().x25519();
        let bo_shown = [(bo.id(), "Bo".to_owned())];
        let g = ana.core.create_group("Choir", "Ana", &bo_shown).unwrap();
        bo.takes(&g, &ana.all_of(&g));
        bo.says_reach(&g, true);
        let me = bo.id();
        let one = |host: [u8; 32], n: u8| relationship::Reach {
            endpoints: Vec::new(),
            host,
            token: [n; 16],
            extra: Default::default(),
        };
        // A yes on one device, and a no on another at the same moment,
        // with the no in the account too (D75).
        let yes = relationship::set_reach(&me, &[one(own, 1)]);
        let (yes, _) = bo.core.write_entry(&g, vec![yes]).unwrap();
        let account = bo.core.account_id().unwrap();
        let record = account::say_no_ops(bo.space(&account).state(), &g, "Choir");
        bo.core.write_entry(&account, record).unwrap();
        let no = relationship::set_reach(&me, &[]);
        bo.core
            .write_entry_concurrent(&g, &[yes], vec![no])
            .unwrap();
        let t = bo.core.telling(&g);
        assert!(t.two && t.set && !t.shared);
        assert!(bo.core.reach_of(&g, &me).is_empty());
        assert!(!t.sets_unasked() && !t.keeps_current() && !t.empties_unasked());
        assert!(bo.nothing_due(&g, true) && bo.nothing_due(&g, false));
        // The token it had is still found, for what was left under it,
        // and is among those a no ends.
        assert_eq!(bo.core.space_of_token(&[1; 16]), Some(g));
        assert!(bo.core.tokens_given(&g, &own).contains(&[1; 16]));
        // The person says no: then there is one list.
        bo.says_reach(&g, false);
        let t = bo.core.telling(&g);
        assert!(!t.two && !t.shared && !t.sets_unasked());

        // Two lists that both name hosts: both count, the later first. His
        // host is in both, with two tokens, and is one host.
        let first = relationship::set_reach(&me, &[one(own, 1), one([7; 32], 2)]);
        let (first, _) = bo.core.write_entry(&g, vec![first]).unwrap();
        let second = relationship::set_reach(&me, &[one([8; 32], 3), one(own, 4)]);
        let (second, _) = bo
            .core
            .write_entry_concurrent(&g, &[first], vec![second])
            .unwrap();
        let dag = bo.space(&g).dag();
        let read = match dag.position(&first) > dag.position(&second) {
            true => vec![one(own, 1), one([7; 32], 2), one([8; 32], 3)],
            false => vec![one([8; 32], 3), one(own, 4), one([7; 32], 2)],
        };
        assert_eq!(bo.core.reach_of(&g, &me), read);
        assert_eq!(bo.space(&g).state().reach_values(&me, 1).len(), 2);
        let t = bo.core.telling(&g);
        assert!(t.two && t.shared && t.keeps_current() && t.unnamed == 0);
        // Both tokens serve, named in what is read or not.
        for token in [[1; 16], [4; 16]] {
            assert_eq!(bo.core.space_of_token(&token), Some(g));
            assert!(bo.core.tokens_given(&g, &own).contains(&token));
        }
        // Nothing is due for that, on his host or on any other device.
        assert!(bo.nothing_due(&g, true) && !t.sets_unasked());
        // Cy, whom he does not know, is added: he is to be told, and
        // nothing waits for that.
        let cy_shown = [(cy.id(), "Cy".to_owned())];
        let added = ana.core.add_to_group(&g, &cy_shown).unwrap();
        bo.takes(&g, &[added]);
        cy.takes(&g, &ana.all_of(&g));
        let t = bo.core.telling(&g);
        assert_eq!(t.added(), [cy.id()]);
        assert!(t.two && t.keeps_current());
        assert!(bo.nothing_due(&g, true));
    }

    /// `hosts.md`, "An act that cannot be finished is finished later, by
    /// the same device". A yes given while the host cannot be reached is
    /// kept by the device it was given on, beside the space, through a
    /// restart. Once the list is set by anything else, an empty list on
    /// another device included, that is later than the yes: the device
    /// gives it up, and does not name the host.
    #[test]
    fn a_kept_yes_gives_way_to_a_list_set_after_it() {
        let [mut ana, mut bo, _, _] = four();
        bo.knows(&ana, "Ana");
        bo.hosts_at("203.0.113.5:7171");
        let bo_shown = [(bo.id(), "Bo".to_owned())];
        let g = ana.core.create_group("Choir", "Ana", &bo_shown).unwrap();
        let other = ana.core.create_group("Band", "Ana", &bo_shown).unwrap();
        for id in [&g, &other] {
            bo.takes(id, &ana.all_of(id));
        }
        let kept_at = |p: &Person, id: &SpaceId| p.core.spaces[id].kept_yes_at.exists();
        for id in [&g, &other] {
            // He joins among contacts with the host out of reach: an
            // empty list, and the yes kept here.
            assert!(!bo.core.telling(id).waiting);
            bo.says_reach(id, false);
            bo.core.keep_yes(id);
            let t = bo.core.telling(id);
            assert!(t.waiting && !t.shared && t.joined && kept_at(&bo, id));
            // nothing software does on its own is due meanwhile
            assert!(bo.nothing_due(id, true) && !t.sets_unasked());
        }
        // T2. A no set on another device at the same moment as the list
        // the yes was kept against, and not after it: the node holds two
        // lists, which is not what the yes was kept against, and one of
        // them is empty. The yes gives way, and the host is not named.
        let band = ana.core.create_group("Trio", "Ana", &bo_shown).unwrap();
        bo.takes(&band, &ana.all_of(&band));
        bo.says_reach(&band, false);
        bo.core.keep_yes(&band);
        assert!(bo.core.telling(&band).waiting);
        let against = bo.space(&band).heads();
        let no = relationship::set_reach(&bo.id(), &[]);
        bo.core
            .write_entry_concurrent(&band, &against, vec![no])
            .unwrap();
        let t = bo.core.telling(&band);
        assert!(t.two && !t.waiting && !t.shared && !t.sets_unasked());
        assert!(!kept_at(&bo, &band), "the note is still there");
        // It is on the device, not in the space or the account: a restart
        // keeps it, and nobody else has it.
        bo.restarts();
        assert!(bo.core.telling(&g).waiting && bo.core.telling(&other).waiting);
        ana.takes(&g, &bo.all_of(&g));
        assert!(!ana.core.telling(&g).waiting);

        // Another of his devices says no meanwhile: an empty list, set
        // after the yes was kept. The yes is given up, and stays so.
        bo.says_reach(&g, false);
        let t = bo.core.telling(&g);
        assert!(!t.waiting && !t.shared && !t.sets_unasked());
        assert!(!kept_at(&bo, &g), "the note is still there");
        bo.restarts();
        assert!(!bo.core.telling(&g).waiting);
        // In the other group the host comes back and is named: setting
        // the list ends the wait.
        assert!(bo.core.telling(&other).waiting);
        bo.says_reach(&other, true);
        let t = bo.core.telling(&other);
        assert!(t.shared && !t.waiting && !kept_at(&bo, &other));
        // A yes kept and then given up by the person: no more waiting.
        bo.says_reach(&g, false);
        bo.core.keep_yes(&g);
        assert!(bo.core.telling(&g).waiting);
        bo.core.drop_yes(&g);
        assert!(!bo.core.telling(&g).waiting && !kept_at(&bo, &g));
        // And leaving gives it up.
        bo.says_reach(&g, false);
        bo.core.keep_yes(&g);
        let ops = relationship::leave_ops(&bo.id());
        bo.core.write_entry(&g, ops).unwrap();
        assert!(!bo.core.telling(&g).waiting && !kept_at(&bo, &g));
    }

    /// D70 (`hosts.md`, "On its own, a device changes only its own
    /// entry"; `Core::own_entry_due`). A host keeps the entry that names
    /// it: a new token where the one there has gone, the address it has
    /// now, and taking itself out when it stops serving. It writes the
    /// others as it read them, each host once, in their places, one it
    /// has never heard of included, and never with a new token.
    #[test]
    fn a_device_writing_its_own_entry_writes_the_others_as_it_read_them() {
        use cardinal_space::grant::Endpoint;
        let [mut ana, mut bo, _, _] = four();
        bo.knows(&ana, "Ana");
        bo.hosts_at("203.0.113.5:7171");
        let own = *bo.core.keys.link.public_key().x25519();
        let bo_shown = [(bo.id(), "Bo".to_owned())];
        let g = ana.core.create_group("Choir", "Ana", &bo_shown).unwrap();
        bo.takes(&g, &ana.all_of(&g));
        let me = bo.id();
        let one = |host: [u8; 32], n: u8| relationship::Reach {
            endpoints: Vec::new(),
            host,
            token: [n; 16],
            extra: Default::default(),
        };
        let tokens =
            |list: &[relationship::Reach]| -> Vec<u8> { list.iter().map(|r| r.token[0]).collect() };
        // Two lists, set at the same moment by two devices, that each
        // gave his host a token: T1.
        let first = relationship::set_reach(&me, &[one([7; 32], 1), one(own, 2)]);
        let (a, _) = bo.core.write_entry(&g, vec![first]).unwrap();
        let second = relationship::set_reach(&me, &[one([8; 32], 3), one(own, 9)]);
        let (b, _) = bo
            .core
            .write_entry_concurrent(&g, &[a], vec![second])
            .unwrap();
        let dag = bo.space(&g).dag();
        let a_first = dag.position(&a) > dag.position(&b);
        let (read, named) = match a_first {
            true => (vec![1, 2, 3], 2),
            false => (vec![3, 9, 1], 9),
        };
        assert_eq!(tokens(&bo.core.reach_of(&g, &me)), read);
        // While the token it reads for itself is active nothing is due,
        // whether the other is or not.
        let all = |_: &[u8; 16]| true;
        let none: fn() -> [u8; 16] = || panic!("a token is active");
        assert!(bo.core.own_entry_due(&g, true, None, all, none).is_none());
        // That token has gone: its entry gets another, in its place, and
        // the others are as they were read.
        let gone = |t: &[u8; 16]| t[0] != named;
        let due = bo.core.own_entry_due(&g, true, None, gone, || [5; 16]);
        let renewed: Vec<u8> = read
            .iter()
            .map(|n| if *n == named { 5 } else { *n })
            .collect();
        assert_eq!(tokens(&due.expect("its token has gone")), renewed);
        // Its address changed: its entry alone says so.
        let at = [Endpoint::parse("198.51.100.7:7171").unwrap()];
        let due = bo.core.own_entry_due(&g, true, Some(&at), all, none);
        let due = due.expect("its address changed");
        assert_eq!(tokens(&due), read);
        for r in &due {
            assert_eq!(r.endpoints.is_empty(), r.host != own);
        }
        // Written, it is one list; and then nothing is due.
        let set = relationship::set_reach(&me, &due);
        bo.core.write_entry(&g, vec![set]).unwrap();
        assert_eq!(bo.space(&g).state().reach_values(&me, 1).len(), 1);
        assert!(bo
            .core
            .own_entry_due(&g, true, Some(&at), all, none)
            .is_none());
        // A device that is no host and is not named has nothing to do
        // there, whatever it thinks of the hosts that are.
        assert!(ana.core.own_entry_due(&g, false, None, all, none).is_none());

        // It stops serving. While only its account says so, or only its
        // setting, it waits; once both do it takes itself out, and the
        // two it has never heard of stay where they were.
        assert!(bo.core.own_entry_due(&g, false, None, all, none).is_none());
        bo.hosts_no_longer();
        let due = bo.core.own_entry_due(&g, false, None, all, none);
        let kept: Vec<u8> = read.iter().copied().filter(|n| *n != named).collect();
        let due = due.expect("it is left in");
        assert_eq!(tokens(&due), kept);
        let set = relationship::set_reach(&me, &due);
        bo.core.write_entry(&g, vec![set]).unwrap();
        assert!(bo.nothing_due(&g, false) && bo.nothing_due(&g, true));
        // The tokens it gave there are still known for what they are.
        assert_eq!(bo.core.space_of_token(&[named; 16]), Some(g));
        // Where the list names nobody, nothing is kept current.
        let no = relationship::set_reach(&me, &[]);
        bo.core.write_entry(&g, vec![no]).unwrap();
        bo.hosts_at("203.0.113.5:7171");
        assert!(bo.nothing_due(&g, true));
    }

    /// D68, D75 (`hosts.md#telling-others-where-to-reach-you`). Among
    /// contacts a host names itself wherever the person has not said no:
    /// in a relationship, to a list never set, or emptied with no no
    /// recorded, as by mistake; and in a group of contacts alike. A no in
    /// the account stops it. Not while the contact is refused.
    #[test]
    fn a_relationship_names_a_host_taken_up_later() {
        let (mut ana, mut bo) = (Person::new(), Person::new());
        ana.meets(&bo);
        bo.meets(&ana);
        let (rel, genesis) = ana.core.create_relationship(&bo.id()).unwrap();
        bo.core.accept_relationship(&genesis, &ana.id()).unwrap();
        bo.says(&rel, "hello");
        // Until the contact is on record there is nobody known to be one.
        assert!(!bo.core.telling(&rel).sets_unasked());
        use cardinal_space::account::Regard;
        let account = bo.core.account_id().unwrap();
        let contact = account::create_contact(&ana.id(), "Ana", &rel, Regard::default());
        bo.core.write_entry(&account, vec![contact]).unwrap();
        // With no host there is nothing to say, and nothing is written.
        let t = bo.core.telling(&rel);
        assert!(t.relationship && t.joined && !t.set && t.who.is_empty());
        assert!(t.sets_unasked() && !t.worth_saying(0) && !t.ask());
        // He takes up a host: it is named there, unasked. P2: a device
        // that cannot reach the host has nothing to add, and waits.
        bo.hosts_at("203.0.113.5:7171");
        let t = bo.core.telling(&rel);
        assert!(t.unnamed == 1 && t.sets_unasked() && !t.ask());
        assert!(!t.worth_saying(0) && t.worth_saying(1));
        bo.says_reach(&rel, true);
        let t = bo.core.telling(&rel);
        assert!(t.shared && t.unnamed == 0 && !t.sets_unasked() && t.keeps_current());
        // A list emptied with no no recorded fills itself again.
        let empty = relationship::set_reach(&bo.id(), &[]);
        bo.core.write_entry(&rel, vec![empty]).unwrap();
        assert!(bo.core.telling(&rel).sets_unasked());
        // A no recorded stops it.
        bo.says_reach(&rel, false);
        let t = bo.core.telling(&rel);
        assert!(t.said_no && !t.sets_unasked());
        // In a group of contacts alike, with the same no.
        let bo_shown = [(bo.id(), "Bo".to_owned())];
        let g = ana.core.create_group("Choir", "Ana", &bo_shown).unwrap();
        bo.takes(&g, &ana.all_of(&g));
        let empty = relationship::set_reach(&bo.id(), &[]);
        bo.core.write_entry(&g, vec![empty]).unwrap();
        let t = bo.core.telling(&g);
        assert!(!t.relationship && t.who.is_empty() && t.unnamed == 1);
        assert!(t.sets_unasked());
        bo.says_reach(&g, false);
        assert!(!bo.core.telling(&g).sets_unasked());
        // Refused, Ana is no contact: nothing is set for her.
        bo.says_reach(&rel, true);
        let empty = relationship::set_reach(&bo.id(), &[]);
        bo.core.write_entry(&rel, vec![empty]).unwrap();
        assert!(bo.core.telling(&rel).sets_unasked());
        let node = bo.core.contacts()[0].node;
        let refuse = account::set_field(node, account::REFUSED, true);
        bo.core.write_entry(&account, vec![refuse]).unwrap();
        assert!(!bo.core.telling(&rel).sets_unasked());
    }

    impl Person {
        /// Another device of this person's, added to their identity with
        /// the key of their recovery words, with their account as it is
        /// now. It is a device and no host.
        fn second_device(&mut self) -> Person {
            let dir = tempfile::tempdir().unwrap();
            let paths = Paths::at(dir.path());
            let keys = Arc::new(Keys::load_or_create(&paths.device_key()).unwrap());
            let mut core = Core::load(&paths, keys).unwrap();
            let ident = self.core.identity.as_ref().unwrap();
            let all = self.log();
            let genesis = IdentityEntry::decode(&all[0]).unwrap();
            let mut log = IdentityLog::from_genesis(genesis).unwrap();
            for e in &all[1..] {
                log.insert_bytes(e).unwrap();
            }
            let request = core
                .keys
                .device
                .request(&self.id(), cardinal_identity::Power::Admin);
            let added = log
                .add_key(&self.root, &request, ident.enc.first())
                .unwrap();
            let added = added.encode();
            self.core.ingest_identity(&[added], None).unwrap();
            let joined = core.ingest_identity(&self.log(), Some(self.id())).unwrap();
            assert!(joined.joined);
            let account = self.core.account_id().unwrap();
            core.ingest_space(account, &self.all_of(&account)).unwrap();
            assert_eq!(core.account_id(), Some(account));
            let root = cardinal_crypto::SigningKey::from_seed(&self.root.seed());
            let mut second = Person {
                _dir: dir,
                core,
                root,
            };
            for (id, log) in self.others() {
                second.core.ingest_other(id, &log).unwrap();
            }
            second
        }

        /// The logs of the other people this device holds.
        fn others(&self) -> Vec<([u8; 32], Vec<Vec<u8>>)> {
            let others = self.core.others.iter();
            others
                .map(|(id, o)| (*id, o.log.entries().map(|e| e.encode()).collect()))
                .collect()
        }

        /// Whether nothing is due for this device's own entry in a space
        /// (`Core::own_entry_due`), with every token it gave still active.
        fn nothing_due(&self, space: &SpaceId, host: bool) -> bool {
            let fresh: fn() -> [u8; 16] = || panic!("a token is active");
            let due = self.core.own_entry_due(space, host, None, |_| true, fresh);
            due.is_none()
        }

        /// What a device does to its person's list in a space on its own,
        /// with every host of theirs in reach and every token given still
        /// active (`mailbox::write_reach`, `mailbox::keep_own_entry`).
        /// Says whether it wrote.
        fn looks(&mut self, space: &SpaceId, host: bool) -> bool {
            let me = self.id();
            let fresh = cardinal_crypto::random_bytes::<16>;
            let due = self.core.own_entry_due(space, host, None, |_| true, fresh);
            if let Some(list) = due {
                let set = relationship::set_reach(&me, &list);
                self.core.write_entry(space, vec![set]).unwrap();
                return true;
            }
            let t = self.core.telling(space);
            if t.sets_unasked() && t.own_unnamed {
                let mut list = self.core.reach_of(space, &me);
                let (grant, _) = self.core.mailboxes().remove(0);
                list.push(relationship::Reach {
                    endpoints: grant.endpoints,
                    host: *grant.link_key.x25519(),
                    token: cardinal_crypto::random_bytes(),
                    extra: Default::default(),
                });
                let set = relationship::set_reach(&me, &list);
                self.core.write_entry(space, vec![set]).unwrap();
                return true;
            }
            false
        }
    }

    /// R2, D70 (`hosts.md`, "On its own, a device changes only its own
    /// entry"). A host stops serving and starts again. Another device of
    /// its person's has heard of the stop and not of the start, and holds
    /// the relationship in full. It judged the host by its own account,
    /// took it out, the host put itself back with a new token, and so on
    /// for as long as the account was behind. Nothing a device does on its
    /// own touches another's entry: the two come to rest with the host
    /// listed.
    #[test]
    fn a_device_that_heard_only_of_a_hosts_stop_leaves_it_listed() {
        let (mut ana, mut bo) = (Person::new(), Person::new());
        ana.meets(&bo);
        bo.meets(&ana);
        let (rel, genesis) = ana.core.create_relationship(&bo.id()).unwrap();
        bo.core.accept_relationship(&genesis, &ana.id()).unwrap();
        use cardinal_space::account::Regard;
        let account = ana.core.account_id().unwrap();
        let contact = account::create_contact(&bo.id(), "Bo", &rel, Regard::default());
        ana.core.write_entry(&account, vec![contact]).unwrap();
        let mut phone = ana.second_device();
        let me = ana.id();
        let own = *ana.core.keys.link.public_key().x25519();
        // Her desktop is a host, and the relationship names it.
        ana.hosts_at("203.0.113.5:7171");
        assert!(ana.looks(&rel, true));
        assert_eq!(ana.core.reach_of(&rel, &me).len(), 1);
        // It stops, and takes itself out. The phone hears of that.
        ana.hosts_no_longer();
        assert!(ana.looks(&rel, false));
        assert!(ana.core.reach_of(&rel, &me).is_empty());
        phone.takes(&account, &ana.all_of(&account));
        assert!(phone.core.mailboxes().is_empty());
        // It starts again, and puts itself back. Of that the phone has
        // the relationship, and not the account.
        ana.hosts_at("203.0.113.5:7171");
        assert!(ana.looks(&rel, true));
        phone.takes(&rel, &ana.all_of(&rel));
        assert_eq!(phone.core.reach_of(&rel, &me).len(), 1);
        // Each looks in turn, and has what the other wrote.
        let mut wrote = 0;
        for round in 0..6 {
            let p = phone.looks(&rel, false);
            ana.takes(&rel, &phone.all_of(&rel));
            let a = ana.looks(&rel, true);
            phone.takes(&rel, &ana.all_of(&rel));
            if !p && !a {
                break;
            }
            wrote = round + 1;
        }
        assert_eq!(wrote, 0, "they wrote for {wrote} rounds");
        // The phone has a host it does not think is one: that is not its
        // to judge, and not its to add either.
        let t = phone.core.telling(&rel);
        assert!(t.shared && !t.hosted && !t.sets_unasked());
        for p in [&ana, &phone] {
            let named: Vec<[u8; 32]> = p.core.reach_of(&rel, &me).iter().map(|r| r.host).collect();
            assert_eq!(named, [own]);
        }
    }

    /// R6 (`hosts.md`, "An act that cannot be finished is finished later";
    /// D69). A yes is kept while the host is out of reach: here the yes
    /// nobody was asked for, of whoever made a group among contacts.
    /// Someone who is not a contact is added before it is finished. The
    /// entry that names the hosts has their addition in its past, and
    /// they were taken for present at the yes: nobody asked the person,
    /// and nobody told them. Whoever came since the yes was kept and is
    /// no contact is told of.
    #[test]
    fn whoever_came_while_a_yes_was_kept_is_told_of() {
        let [mut ana, bo, cy, dee] = four();
        ana.knows(&bo, "Bo");
        ana.knows(&dee, "Dee");
        ana.hosts_at("203.0.113.5:7171");
        let bo_shown = [(bo.id(), "Bo".to_owned())];
        let g = ana.core.create_group("Choir", "Ana", &bo_shown).unwrap();
        // Her joining, among contacts, with the host out of reach.
        ana.says_reach(&g, false);
        ana.core.keep_yes(&g);
        assert!(ana.core.telling(&g).waiting);
        // Cy, a stranger, and Dee, a contact, are added meanwhile.
        let more = [(cy.id(), "Cy".to_owned()), (dee.id(), "Dee".to_owned())];
        ana.core.add_to_group(&g, &more).unwrap();
        let t = ana.core.telling(&g);
        assert!(t.waiting && t.added().is_empty());
        // The host is back, and the yes is finished.
        ana.says_reach(&g, true);
        let t = ana.core.telling(&g);
        assert!(t.shared && !t.waiting);
        assert_eq!(t.added(), [cy.id()], "a stranger is not told of");
        // It is this device's note, and a restart keeps it.
        ana.restarts();
        assert_eq!(ana.core.telling(&g).added(), [cy.id()]);
        // Told, she is told no more.
        ana.core.told_of_all(&g);
        assert!(ana.core.telling(&g).added().is_empty());

        // A yes the person gave at once, with the same people there, has
        // nobody to tell of: whoever was there is whom they said it to.
        let [mut ana, bo, cy, _] = four();
        ana.knows(&bo, "Bo");
        ana.hosts_at("203.0.113.5:7171");
        let both = [(bo.id(), "Bo".to_owned()), (cy.id(), "Cy".to_owned())];
        let g = ana.core.create_group("Choir", "Ana", &both).unwrap();
        ana.says_reach(&g, false);
        ana.core.keep_yes(&g);
        ana.says_reach(&g, true);
        assert!(ana.core.telling(&g).added().is_empty());
    }

    /// D69 (`hosts.md`, "A yes is to the space, and to whoever it comes to
    /// hold"). When someone who is not the person's contact is added to a
    /// space where their reach node names their hosts, they are told, and
    /// offered to stop. Nothing waits for them: the list is kept current
    /// as before. Whom they have been told of is this device's own note,
    /// and setting the list again, as for an address that changed, does
    /// not stand for it.
    #[test]
    fn whoever_is_added_where_hosts_are_named_is_told_of() {
        let [mut ana, mut bo, mut cy, mut dee] = four();
        bo.knows(&ana, "Ana");
        bo.hosts_at("203.0.113.5:7171");
        let bo_shown = [(bo.id(), "Bo".to_owned())];
        let g = ana
            .core
            .create_group("Garden club", "Ana", &bo_shown)
            .unwrap();
        bo.takes(&g, &ana.all_of(&g));
        // Among contacts there is nothing to ask: joining names his host.
        assert!(!bo.core.telling(&g).ask());
        let said = bo.says_reach(&g, true);
        ana.takes(&g, &[said]);
        let t = bo.core.telling(&g);
        assert!(t.shared && t.added().is_empty() && t.keeps_current());

        // Ana adds Cy, whom Bo does not know. Cy reads what is there.
        let cy_shown = [(cy.id(), "Cy".to_owned())];
        let added = ana.core.add_to_group(&g, &cy_shown).unwrap();
        bo.takes(&g, std::slice::from_ref(&added));
        cy.takes(&g, &ana.all_of(&g));
        assert_eq!(relationship::reach_of(cy.space(&g), &bo.id()).len(), 1);
        let t = bo.core.telling(&g);
        assert_eq!(t.added(), [cy.id()]);
        // Nothing waits for him: what the list names is kept current,
        // and nothing asks him as if it were not yet shared.
        assert!(t.keeps_current() && !t.ask() && !t.sets_unasked());
        let listed = crate::groups::list_of(&bo.core);
        let reach = &listed["groups"][0]["reach"];
        assert_eq!(reach["added"], serde_json::json!(["Cy"]), "{listed}");
        assert_eq!(reach["shared"], true);

        // The list is set again, as his host does for a new token. He
        // has still not been told of Cy, here or after a restart.
        let again = bo.says_reach(&g, true);
        ana.takes(&g, &[again]);
        assert_eq!(bo.core.telling(&g).added(), [cy.id()]);
        bo.restarts();
        assert_eq!(bo.core.telling(&g).added(), [cy.id()]);
        // He is told, on this device, which notes it: beside the space,
        // not in it.
        let entries = bo.space(&g).dag().len();
        bo.core.told_of_all(&g);
        let t = bo.core.telling(&g);
        assert!(t.added().is_empty() && t.keeps_current() && t.shared);
        assert_eq!(t.who, [cy.id()]);
        assert_eq!(bo.space(&g).dag().len(), entries);
        bo.restarts();
        assert!(bo.core.telling(&g).added().is_empty());

        // Dee is added, and this time he empties it: nobody is left to
        // tell of, and Dee's being there is no news.
        let dee_shown = [(dee.id(), "Dee".to_owned())];
        let added = ana.core.add_to_group(&g, &dee_shown).unwrap();
        bo.takes(&g, &[added]);
        assert_eq!(bo.core.telling(&g).added(), [dee.id()]);
        bo.says_reach(&g, false);
        let t = bo.core.telling(&g);
        assert!(t.added().is_empty() && !t.shared && !t.ask());
        dee.takes(&g, &ana.all_of(&g));
        dee.takes(&g, &bo.all_of(&g));
        assert!(relationship::reach_of(dee.space(&g), &bo.id()).is_empty());
        // He shares again, with Cy and Dee there: they did not come while
        // it was named, on this device or any other of his.
        bo.says_reach(&g, true);
        let t = bo.core.telling(&g);
        assert!(t.shared && t.added().is_empty());

        // A contact who is added is nobody to tell of.
        let [mut eve, mut fay, mut gus, _] = four();
        fay.knows(&eve, "Eve");
        fay.knows(&gus, "Gus");
        fay.hosts_at("203.0.113.7:7171");
        let fay_shown = [(fay.id(), "Fay".to_owned())];
        let h = eve.core.create_group("Choir", "Eve", &fay_shown).unwrap();
        fay.takes(&h, &eve.all_of(&h));
        fay.says_reach(&h, true);
        let gus_shown = [(gus.id(), "Gus".to_owned())];
        let added = eve.core.add_to_group(&h, &gus_shown).unwrap();
        fay.takes(&h, &[added]);
        gus.takes(&h, &eve.all_of(&h));
        let t = fay.core.telling(&h);
        assert!(t.added().is_empty() && t.keeps_current());
    }

    /// D68 (`hosts.md`, "When the person refuses someone who is already a
    /// member of such a space"). Software asks as part of refusing, on the
    /// device they refuse on, and nothing tracks it afterwards: whoever is
    /// refused is not listed as someone added, and what the list names is
    /// still kept current. The relationship with them is not asked about.
    #[test]
    fn refusing_someone_who_is_there_is_asked_about_then_and_not_tracked() {
        use cardinal_space::account;
        let [mut ana, mut bo, cy, dee] = four();
        bo.knows(&ana, "Ana");
        bo.knows(&cy, "Cy");
        bo.hosts_at("203.0.113.5:7171");
        let both = [(bo.id(), "Bo".to_owned()), (cy.id(), "Cy".to_owned())];
        let g = ana.core.create_group("Garden club", "Ana", &both).unwrap();
        let bo_shown = [(bo.id(), "Bo".to_owned())];
        let quiet = ana.core.create_group("Choir", "Ana", &bo_shown).unwrap();
        let kept = ana.core.create_group("Band", "Ana", &both).unwrap();
        for id in [&g, &quiet, &kept] {
            bo.takes(id, &ana.all_of(id));
        }
        // Among contacts nothing is asked. He shares in two of the three.
        assert!(!bo.core.telling(&g).ask());
        bo.says_reach(&g, true);
        bo.says_reach(&quiet, true);
        bo.says_reach(&kept, false);
        let t = bo.core.telling(&g);
        assert!(t.shared && t.added().is_empty() && t.keeps_current());
        // What refusing Cy asks about: the group Cy is in where the host
        // is named. Not the one Cy is not in, nor the one that names none.
        assert_eq!(bo.core.groups_naming_hosts_to(&cy.id()), [g]);
        assert!(bo.core.groups_naming_hosts_to(&dee.id()).is_empty());

        // He refuses Cy, who is there and reads it.
        let account = bo.core.account_id().unwrap();
        let node = |p: &Person, who: [u8; 32]| {
            let all = p.core.contacts().into_iter();
            all.filter(|c| c.identity == who)
                .map(|c| c.node)
                .next()
                .unwrap()
        };
        let refuse = account::set_field(node(&bo, cy.id()), account::REFUSED, true);
        bo.core.write_entry(&account, vec![refuse]).unwrap();
        // Cy is no contact now, and learns what the list says. Nobody
        // came, so nobody is listed as added, and nothing waits.
        let t = bo.core.telling(&g);
        assert_eq!(t.who, [cy.id()]);
        assert!(t.added().is_empty() && t.late.is_empty());
        assert!(t.keeps_current() && !t.ask() && !t.sets_unasked() && !t.empties_unasked());
        let listed = crate::groups::list_of(&bo.core);
        let of = |name: &str| {
            let all = listed["groups"].as_array().unwrap().iter();
            let mut found = all
                .filter(|x| x["name"] == name)
                .map(|x| x["reach"].clone());
            found.next().unwrap()
        };
        assert_eq!(
            of("Garden club")["added"],
            serde_json::json!([]),
            "{listed}"
        );
        assert_eq!(of("Garden club")["shared"], true);
        assert_eq!(bo.core.groups_naming_hosts_to(&cy.id()), [g]);
        // His answer, as for anyone: the list, as it was or empty.
        bo.says_reach(&g, false);
        assert!(bo.core.groups_naming_hosts_to(&cy.id()).is_empty());
        assert!(!bo.core.telling(&g).shared);
    }

    /// P4 (`spaces.md#holding-a-space`). Being added is an offer. Whatever
    /// becomes due, a device writes nothing in a space its person has not
    /// accepted, or has declined: an entry there would be their
    /// acceptance. Here a new epoch is due everywhere, as it is when one
    /// of the person's devices is removed.
    #[test]
    fn nothing_is_written_in_a_space_that_was_only_offered() {
        let [mut ana, mut bo, _, _] = four();
        bo.knows(&ana, "Ana");
        let bo_shown = [(bo.id(), "Bo".to_owned())];
        let offered = ana.core.create_group("Choir", "Ana", &bo_shown).unwrap();
        let declined = ana.core.create_group("Club", "Ana", &bo_shown).unwrap();
        let joined = ana.core.create_group("Band", "Ana", &bo_shown).unwrap();
        for g in [&offered, &declined, &joined] {
            bo.takes(g, &ana.all_of(g));
        }
        let account = bo.core.account_id().unwrap();
        let no = cardinal_space::account::create_declined(&declined, "Club");
        bo.core.write_entry(&account, vec![no]).unwrap();
        bo.says_reach(&joined, false);
        let me = bo.id();
        let entries = |p: &Person, g: &SpaceId| p.space(g).dag().len();
        let before = [&offered, &declined, &joined].map(|g| entries(&bo, g));

        let moved = bo.changes_key();
        let took = bo.core.ingest_identity(std::slice::from_ref(&moved), None);
        assert!(took.unwrap().changed);
        let spaces: Vec<SpaceId> = bo.core.spaces.keys().copied().collect();
        for space in &spaces {
            bo.core.rotate_if_due(space).unwrap();
        }
        let after = [&offered, &declined, &joined].map(|g| entries(&bo, g));
        // A new epoch where he is, and nothing where he was only asked.
        assert_eq!(after, [before[0], before[1], before[2] + 1]);
        assert!(bo.began_an_epoch(&joined));
        assert!(!bo.space(&offered).accepted_by(&me));
        assert!(!bo.space(&declined).accepted_by(&me));
        let listed = crate::groups::list_of(&bo.core);
        let names = |k: &str| -> Vec<String> {
            let all = listed[k].as_array().cloned().unwrap_or_default();
            all.iter()
                .map(|g| g["name"].as_str().unwrap().to_owned())
                .collect()
        };
        assert_eq!(names("groups"), ["Band"], "{listed}");
        assert_eq!(names("offers"), ["Choir"], "{listed}");
        // His own spaces moved on with the rest.
        assert!(bo.began_an_epoch(&account));
    }

    /// P3 (`spaces.md#members-and-roles`), D68 (`profiles.md#reach`).
    /// Leaving empties the reach node in the entry that leaves. If another
    /// of the person's devices set it at the same moment, the node holds
    /// both lists, and the empty one wins: nobody reads a host from it,
    /// with nothing more written.
    #[test]
    fn a_reach_node_set_beside_leaving_names_no_host() {
        let [mut ana, mut bo, _, _] = four();
        bo.knows(&ana, "Ana");
        bo.hosts_at("203.0.113.5:7171");
        let bo_shown = [(bo.id(), "Bo".to_owned())];
        let g = ana.core.create_group("Choir", "Ana", &bo_shown).unwrap();
        bo.takes(&g, &ana.all_of(&g));
        bo.says_reach(&g, true);
        let me = bo.id();
        // He leaves on one device, and another, which has not heard,
        // sets the reach node.
        let (left, _) = bo
            .core
            .write_entry(&g, relationship::leave_ops(&me))
            .unwrap();
        let reach = relationship::Reach {
            endpoints: Vec::new(),
            host: [9; 32],
            token: cardinal_crypto::random_bytes(),
            extra: Default::default(),
        };
        let set = relationship::set_reach(&me, &[reach]);
        bo.core
            .write_entry_concurrent(&g, &[left], vec![set])
            .unwrap();
        ana.takes(&g, &bo.all_of(&g));
        assert!(ana.space(&g).has_left(&me));
        assert_eq!(ana.space(&g).state().reach_values(&me, 1).len(), 2);
        assert!(relationship::reach_of(ana.space(&g), &me).is_empty());
        let t = bo.core.telling(&g);
        assert!(!t.shared && !t.joined);
        assert!(!t.sets_unasked() && !t.keeps_current());
    }

    /// P5 (`hosts.md`, "Whoever is added later"). Someone who had left and
    /// is added again has been added: they read where the person's hosts
    /// are from then on, and the person is told of them, though an earlier
    /// addition of theirs came before the reach node was set.
    #[test]
    fn someone_who_left_and_is_added_again_is_told_of() {
        let [mut ana, mut bo, mut cy, _] = four();
        bo.knows(&ana, "Ana");
        bo.hosts_at("203.0.113.5:7171");
        // Cy, whom Bo does not know, is in the group, and leaves it.
        let cy_shown = [(cy.id(), "Cy".to_owned())];
        let g = ana.core.create_group("Choir", "Ana", &cy_shown).unwrap();
        cy.takes(&g, &ana.all_of(&g));
        let joined = cy.says_reach(&g, false);
        ana.takes(&g, &[joined]);
        let (_, gone) = cy
            .core
            .write_entry(&g, relationship::leave_ops(&cy.id()))
            .unwrap();
        ana.takes(&g, &[gone]);
        // Bo is added. Everyone there is his contact, and his host is
        // named without asking.
        let bo_shown = [(bo.id(), "Bo".to_owned())];
        ana.core.add_to_group(&g, &bo_shown).unwrap();
        bo.takes(&g, &ana.all_of(&g));
        let t = bo.core.telling(&g);
        assert!(t.who.is_empty() && !t.ask());
        let said = bo.says_reach(&g, true);
        ana.takes(&g, &[said]);
        assert!(bo.core.telling(&g).added().is_empty());
        // Cy is added again, and reads it.
        let again = ana.core.add_to_group(&g, &cy_shown).unwrap();
        bo.takes(&g, &[again]);
        let t = bo.core.telling(&g);
        assert_eq!(t.who, [cy.id()]);
        assert_eq!(t.added(), [cy.id()], "he is not told that Cy is back");
        assert!(t.keeps_current());
        let listed = crate::groups::list_of(&bo.core);
        assert_eq!(
            listed["groups"][0]["reach"]["added"],
            serde_json::json!(["Cy"])
        );
        // Told of Cy, he is told again if Cy leaves and comes back.
        bo.core.told_of_all(&g);
        assert!(bo.core.telling(&g).added().is_empty());
        cy.takes(&g, &ana.all_of(&g));
        cy.says_reach(&g, false);
        let (_, gone) = cy
            .core
            .write_entry(&g, relationship::leave_ops(&cy.id()))
            .unwrap();
        ana.takes(&g, &cy.all_of(&g));
        bo.takes(&g, &[gone]);
        assert!(bo.core.telling(&g).added().is_empty());
        let again = ana.core.add_to_group(&g, &cy_shown).unwrap();
        bo.takes(&g, &ana.all_of(&g));
        let _ = again;
        assert_eq!(bo.core.telling(&g).added(), [cy.id()]);
    }

    /// P11 (`hosts.md#telling-others-where-to-reach-you`). A public space
    /// is read by anyone at all, so software never sets a reach node there
    /// unasked, whoever its members are: it asks first.
    #[test]
    fn nothing_is_set_unasked_in_a_public_space() {
        let (mut ana, mut bo) = (Person::new(), Person::new());
        ana.meets(&bo);
        bo.meets(&ana);
        bo.knows(&ana, "Ana");
        bo.hosts_at("203.0.113.5:7171");
        let roles = [(ana.id(), OWNER), (bo.id(), WRITER)];
        let made = [false, true].map(|public| {
            let policy = Policy {
                public,
                ..Policy::default()
            };
            ana.genesis_with(cardinal_space::group::GROUP, policy, &roles, &bo)
        });
        let mut tellings = Vec::new();
        for (public, genesis) in [false, true].into_iter().zip(made) {
            let id = bo.space_of(&genesis);
            bo.core.ingest_space(id, &[genesis]).unwrap();
            assert_eq!(bo.space(&id).is_public(), public);
            // Everyone there is his contact, and he has a host.
            let offered = bo.core.telling(&id);
            assert!(offered.who.is_empty() && offered.hosted);
            bo.says_reach(&id, false);
            tellings.push((offered, bo.core.telling(&id)));
        }
        let (offered, joined) = &tellings[0];
        assert!(!offered.ask() && offered.joins_sharing(None));
        assert!(!joined.sets_unasked() && !joined.ask());
        let (offered, joined) = &tellings[1];
        assert!(offered.ask(), "joining a public group does not ask");
        assert!(!offered.joins_sharing(None));
        assert!(
            !joined.sets_unasked(),
            "his host is named to anyone at all, unasked"
        );
        // He joined with an empty list: that is his answer, and only he
        // changes it.
        assert!(!joined.ask());
    }

    /// P13 (`spaces.md#holding-a-space`). An offer is shown as coming from
    /// whoever added the person, not from whoever made the space: "Bo
    /// added you", under the name this person has for Bo.
    #[test]
    fn an_offer_comes_from_whoever_added_the_person() {
        let [ana, mut bo, mut cy, _] = four();
        cy.knows(&bo, "Bo");
        let roles = [(ana.id(), OWNER), (bo.id(), cardinal_space::entry::ADMIN)];
        let genesis = ana.genesis(cardinal_space::group::GROUP, &roles, &bo);
        let g = bo.space_of(&genesis);
        bo.core.ingest_space(g, &[genesis]).unwrap();
        bo.says_reach(&g, false);
        let cy_shown = [(cy.id(), "Cy".to_owned())];
        bo.core.add_to_group(&g, &cy_shown).unwrap();
        cy.takes(&g, &bo.all_of(&g));
        assert_eq!(cy.space(&g).creator(), ana.id());
        let listed = crate::groups::list_of(&cy.core);
        assert_eq!(listed["offers"][0]["from"], "Bo", "{listed}");
        // Whom the genesis names, its author added.
        let listed = crate::groups::list_of(&bo.core);
        assert_eq!(
            listed["groups"].as_array().map(Vec::len),
            Some(1),
            "{listed}"
        );
        assert_eq!(bo.space(&g).added_by(&bo.id()), Some(ana.id()));
        assert_eq!(cy.space(&g).added_by(&cy.id()), Some(bo.id()));
        assert_eq!(cy.space(&g).added_by(&[9; 32]), None);
    }

    /// P14. A write too large for one entry is cut into several. Where a
    /// new epoch is due, the first of them starts it, and the rest are
    /// written under it: it used to be due again for each.
    #[test]
    fn a_write_cut_into_entries_starts_one_epoch() {
        let [mut ana, mut bo, _, _] = four();
        let bo_shown = [(bo.id(), "Bo".to_owned())];
        let g = ana.core.create_group("Choir", "Ana", &bo_shown).unwrap();
        bo.takes(&g, &ana.all_of(&g));
        let joined = bo.says_reach(&g, false);
        ana.takes(&g, &[joined]);
        let (_, gone) = bo
            .core
            .write_entry(&g, relationship::leave_ops(&bo.id()))
            .unwrap();
        ana.takes(&g, &[gone]);
        assert!(ana.space(&g).left_since_epoch());
        let name = "n".repeat(1000);
        let much = 3 * MAX_ENTRY_OPS_BYTES / 1000;
        let ops: Vec<SpaceOp> = (0..much)
            .map(|k| {
                SpaceOp::create(
                    NodeKind::Uint(77),
                    ROOT,
                    &format!("{k}{name}"),
                    Record::new(),
                )
            })
            .collect();
        let written = ana.core.write(&g, ops).unwrap();
        assert!(written.len() >= 3);
        let sp = ana.space(&g);
        let began = |id: &EntryId| sp.entry(id).is_some_and(|e| e.starts_epoch());
        let epochs = written.iter().filter(|(id, _)| began(id)).count();
        assert!(began(&written[0].0));
        assert_eq!(epochs, 1, "an epoch for each of {} entries", written.len());
        assert!(written.iter().all(|(id, _)| sp.state().is_accepted(id)));
    }

    /// P14. What a contact may fetch from here takes in the groups the two
    /// are in. A group this person was only offered is not one: nothing in
    /// it is theirs to serve, and whoever made it chose what it names.
    #[test]
    fn a_group_that_was_only_offered_serves_nothing() {
        let [mut ana, mut bo, _, _] = four();
        bo.knows(&ana, "Ana");
        let bo_shown = [(bo.id(), "Bo".to_owned())];
        let offered = ana.core.create_group("Choir", "Ana", &bo_shown).unwrap();
        let joined = ana.core.create_group("Band", "Ana", &bo_shown).unwrap();
        for g in [&offered, &joined] {
            bo.takes(g, &ana.all_of(g));
        }
        bo.says_reach(&joined, false);
        assert_eq!(bo.core.groups_shared_with(&ana.id()), [joined]);
        // nor one he has left
        bo.core
            .write_entry(&joined, relationship::leave_ops(&bo.id()))
            .unwrap();
        assert!(bo.core.groups_shared_with(&ana.id()).is_empty());
    }

    /// D68 (`apps.md`, `group-reach`). A yes given while there was no host
    /// to name is not kept: nothing records it. Once there is a host it is
    /// named nowhere until the person says where, and nothing asks as if
    /// they had not answered: their list is set, and empty.
    #[test]
    fn a_yes_with_no_host_is_not_kept() {
        let [mut ana, mut bo, mut cy, _] = four();
        bo.knows(&ana, "Ana");
        let bo_shown = [(bo.id(), "Bo".to_owned())];
        let g = ana
            .core
            .create_group("Garden club", "Ana", &bo_shown)
            .unwrap();
        bo.takes(&g, &ana.all_of(&g));
        // He joins among contacts with no host: an empty list.
        assert!(bo.core.telling(&g).joins_sharing(None));
        bo.says_reach(&g, false);
        let cy_shown = [(cy.id(), "Cy".to_owned())];
        let added = ana.core.add_to_group(&g, &cy_shown).unwrap();
        bo.takes(&g, &[added]);
        cy.takes(&g, &ana.all_of(&g));
        bo.hosts_at("203.0.113.5:7171");
        let t = bo.core.telling(&g);
        // Cy came while the list named no host: there is nobody to tell
        // of.
        assert!(t.added().is_empty() && t.late.is_empty());
        assert!(!t.ask() && !t.sets_unasked() && !t.keeps_current());
        // He says so, with Cy there: it is named, and Cy did not come
        // while it was.
        bo.says_reach(&g, true);
        let t = bo.core.telling(&g);
        assert!(t.shared && !t.ask() && t.added().is_empty() && t.late.is_empty());
    }

    /// `spaces.md#members-and-roles`: the entry that carries `leave` also
    /// sets its author's reach node to an empty list, so that the space
    /// stops naming their hosts to whoever is in it or comes to it later.
    #[test]
    fn leaving_empties_the_reach_node() {
        let [mut ana, mut bo, mut cy, _] = four();
        let bo_shown = [(bo.id(), "Bo".to_owned())];
        let g = ana
            .core
            .create_group("Garden club", "Ana", &bo_shown)
            .unwrap();
        bo.takes(&g, &ana.all_of(&g));
        let said = bo.says_reach(&g, true);
        ana.takes(&g, &[said]);
        assert_eq!(relationship::reach_of(ana.space(&g), &bo.id()).len(), 1);
        let ops = relationship::leave_ops(&bo.id());
        let (leave, gone) = bo.core.write_entry(&g, ops).unwrap();
        ana.takes(&g, &[gone]);
        for who in [&ana, &bo] {
            let sp = who.space(&g);
            assert!(sp.validity().is_valid(&leave) && sp.state().is_accepted(&leave));
            assert!(sp.has_left(&bo.id()));
            assert!(relationship::reach_of(sp, &bo.id()).is_empty());
            // it is set, to nothing: not as if it had never been
            assert!(relationship::reach_is_set(sp.state(), &bo.id()));
        }
        // Someone who comes later reads no host of his in what stands.
        let cy_shown = [(cy.id(), "Cy".to_owned())];
        ana.core.add_to_group(&g, &cy_shown).unwrap();
        cy.takes(&g, &ana.all_of(&g));
        assert!(relationship::reach_of(cy.space(&g), &bo.id()).is_empty());
    }

    /// An offer of a group says so if the group is public
    /// (`profiles.md#group`).
    #[test]
    fn an_offer_says_if_the_group_is_public() {
        let (ana, mut bo) = (Person::new(), Person::new());
        let mut ana = ana;
        ana.meets(&bo);
        bo.meets(&ana);
        let offered = |bo: &Person| crate::groups::list_of(&bo.core)["offers"].clone();
        for public in [false, true] {
            let policy = Policy {
                public,
                ..Policy::default()
            };
            let ident = ana.core.identity.as_ref().unwrap();
            let mut ops = group::genesis_ops(ana.id(), "Notices");
            ops.push(SpaceOp::add_member(bo.id(), WRITER));
            ops.push(group::create_member(&ana.id(), "Ana", true));
            ops.push(group::create_member(&bo.id(), "Bo", true));
            let (space, sealed) = Space::create_with(
                group::GROUP,
                policy,
                &ident.log,
                &ana.core.keys.device.signing,
                &[&ana.enc(), &bo.enc()],
                ops,
                Some(now_ms()),
            )
            .unwrap();
            bo.takes(&space.id(), &[sealed.encode()]);
            let all = offered(&bo);
            let id = hex::encode(space.id());
            let offer = all.as_array().unwrap().iter().find(|o| o["group"] == id);
            let offer = offer.unwrap_or_else(|| panic!("no offer in {all}"));
            assert_eq!(offer["public"], public, "{offer}");
            assert_eq!(offer["name"], "Notices");
        }
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

    /// The order things reach the devices of a group in, after one member's
    /// encryption key has changed.
    #[derive(Clone, Copy, Debug)]
    enum Order {
        /// Every device hears of the new key, then the member whose key it
        /// is writes, and that reaches everyone before anyone else writes.
        HeardFirst,
        /// The member whose key it is writes, and that reaches everyone
        /// before they hear of the new key. Then one device after another
        /// hears and writes, and what it writes reaches everyone before
        /// the next one hears.
        EpochFirst,
        /// Hearing, writing and delivering in an order drawn from a seed.
        Random(u64),
    }

    /// Ten members with one device each. One member's encryption key
    /// changes; every device hears of it and writes once after it has.
    /// Returns how many epochs were started after the change, and how many
    /// wraps they carried.
    fn epochs_after_a_key_change(order: Order) -> (usize, usize) {
        const N: usize = 10;
        let mut p: Vec<Person> = (0..N).map(|_| Person::new()).collect();
        for i in 0..N {
            for j in 0..N {
                if i != j {
                    let (log, id) = (p[j].log(), p[j].id());
                    p[i].core.ingest_other(id, &log).unwrap();
                }
            }
        }
        let others: Vec<([u8; 32], String)> =
            (1..N).map(|i| (p[i].id(), format!("member {i}"))).collect();
        let g = p[0].core.create_group("Ten", "member 0", &others).unwrap();
        let genesis = p[0].all_of(&g);
        for person in p.iter_mut().skip(1) {
            person.takes(&g, &genesis);
        }
        // The last member's key changes: their own device has it at once.
        let x = N - 1;
        let x_id = p[x].id();
        let moved = p[x].changes_key();
        assert!(
            p[x].core
                .ingest_identity(std::slice::from_ref(&moved), None)
                .unwrap()
                .changed
        );
        let mut heard = vec![false; N];
        heard[x] = true;
        let mut wrote = vec![false; N];
        let mut inbox: Vec<std::collections::VecDeque<Vec<u8>>> = vec![Default::default(); N];

        fn hear(p: &mut [Person], heard: &mut [bool], i: usize, x_id: [u8; 32], moved: &[u8]) {
            p[i].core.ingest_other(x_id, &[moved.to_vec()]).unwrap();
            heard[i] = true;
        }
        let write = |p: &mut Vec<Person>,
                     wrote: &mut Vec<bool>,
                     inbox: &mut Vec<std::collections::VecDeque<Vec<u8>>>,
                     i: usize| {
            let bytes = p[i].says(&g, "once");
            wrote[i] = true;
            for (j, to) in inbox.iter_mut().enumerate() {
                if j != i {
                    to.push_back(bytes.clone());
                }
            }
        };
        let deliver = |p: &mut Vec<Person>,
                       inbox: &mut Vec<std::collections::VecDeque<Vec<u8>>>,
                       j: usize| {
            if let Some(bytes) = inbox[j].pop_front() {
                p[j].takes(&g, &[bytes]);
            }
        };
        let deliver_all =
            |p: &mut Vec<Person>, inbox: &mut Vec<std::collections::VecDeque<Vec<u8>>>| {
                for j in 0..N {
                    while !inbox[j].is_empty() {
                        deliver(p, inbox, j);
                    }
                }
            };
        match order {
            Order::HeardFirst => {
                for i in 0..x {
                    hear(&mut p, &mut heard, i, x_id, &moved);
                }
                write(&mut p, &mut wrote, &mut inbox, x);
                deliver_all(&mut p, &mut inbox);
                for i in 0..x {
                    write(&mut p, &mut wrote, &mut inbox, i);
                    deliver_all(&mut p, &mut inbox);
                }
            }
            Order::EpochFirst => {
                write(&mut p, &mut wrote, &mut inbox, x);
                deliver_all(&mut p, &mut inbox);
                for i in 0..x {
                    hear(&mut p, &mut heard, i, x_id, &moved);
                    write(&mut p, &mut wrote, &mut inbox, i);
                    deliver_all(&mut p, &mut inbox);
                }
            }
            Order::Random(seed) => {
                let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
                let mut below = |n: usize| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    (state % n as u64) as usize
                };
                loop {
                    // what can happen next: someone hears, someone who has
                    // heard writes, or something written reaches someone
                    let mut can: Vec<(u8, usize)> = Vec::new();
                    for i in 0..N {
                        if !heard[i] {
                            can.push((0, i));
                        } else if !wrote[i] {
                            can.push((1, i));
                        }
                        if !inbox[i].is_empty() {
                            can.push((2, i));
                        }
                    }
                    if can.is_empty() {
                        break;
                    }
                    match can[below(can.len())] {
                        (0, i) => hear(&mut p, &mut heard, i, x_id, &moved),
                        (1, i) => write(&mut p, &mut wrote, &mut inbox, i),
                        (_, j) => deliver(&mut p, &mut inbox, j),
                    }
                }
            }
        }
        deliver_all(&mut p, &mut inbox);
        assert!(heard.iter().all(|h| *h) && wrote.iter().all(|w| *w));
        // Everyone holds the same entries. Count what started an epoch
        // after the genesis, and the wraps those entries carry.
        let count = |person: &Person| -> (usize, usize) {
            let sp = person.space(&g);
            let starts = sp
                .dag()
                .iter()
                .filter(|(id, e)| **id != g && e.starts_epoch());
            let (mut epochs, mut wraps) = (0, 0);
            for (id, _) in starts {
                epochs += 1;
                wraps += sp.sealed(id).and_then(|s| s.wraps()).map_or(0, |w| w.len());
            }
            (epochs, wraps)
        };
        let counted = count(&p[0]);
        for person in &p {
            assert_eq!(person.space(&g).dag().len(), p[0].space(&g).dag().len());
            assert_eq!(count(person), counted);
            assert_eq!(person.said(&g).len(), N);
        }
        counted
    }

    /// What one changed key costs (`spaces.md#when-to-rotate`): each device
    /// goes by its own account of what it held when the current epoch
    /// reached it, so more than one device can start an epoch for the one
    /// change. A measurement, run with
    /// `cargo test -p cardinald --lib what_one_changed_key -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn what_one_changed_key_costs_in_epochs() {
        let (epochs, wraps) = epochs_after_a_key_change(Order::HeardFirst);
        eprintln!("MEASURE heard first: {epochs} epochs, {wraps} wraps");
        assert_eq!(epochs, 1);
        let (epochs, wraps) = epochs_after_a_key_change(Order::EpochFirst);
        eprintln!("MEASURE epoch first: {epochs} epochs, {wraps} wraps");
        assert_eq!(epochs, 10);
        let mut all = Vec::new();
        for seed in 1..=12 {
            let (epochs, wraps) = epochs_after_a_key_change(Order::Random(seed));
            eprintln!("MEASURE random order {seed}: {epochs} epochs, {wraps} wraps");
            assert!((1..=10).contains(&epochs));
            all.push(epochs);
        }
        all.sort();
        eprintln!(
            "MEASURE random orders: least {}, median {}, most {}",
            all[0],
            all[all.len() / 2],
            all[all.len() - 1]
        );
    }

    /// The two orders that bound it, as a test: one epoch where every
    /// device hears before the new epoch reaches it, and one from every
    /// device where each hears only after.
    #[test]
    fn one_changed_key_costs_between_one_epoch_and_one_from_every_device() {
        assert_eq!(epochs_after_a_key_change(Order::HeardFirst).0, 1);
        assert_eq!(epochs_after_a_key_change(Order::EpochFirst).0, 10);
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

    /// P8 (`spaces.md#when-to-rotate`). A device starts an epoch wrapped
    /// for the members whose keys it holds. One whose identity log it did
    /// not hold yet was a member and was not wrapped for: the first key
    /// the device holds for them is a change, and its next write starts an
    /// epoch they can open. It used to take that first key for the key
    /// they had been given, and they were left out for good.
    #[test]
    fn a_member_whose_log_came_late_is_given_the_next_epoch() {
        let (mut ana, mut bo, mut cy) = (Person::new(), Person::new(), Person::new());
        for (a, b) in [(0, 1), (0, 2)] {
            let p = [&mut ana, &mut bo, &mut cy];
            let (log, id) = (p[b].log(), p[b].id());
            p[a].core.ingest_other(id, &log).unwrap();
            let (log, id) = (p[a].log(), p[a].id());
            p[b].core.ingest_other(id, &log).unwrap();
        }
        // Cy holds Bo's log, and Bo does not hold Cy's.
        cy.meets(&bo);
        let both = [(bo.id(), "Bo".to_owned()), (cy.id(), "Cy".to_owned())];
        let g = ana.core.create_group("Choir", "Ana", &both).unwrap();
        bo.takes(&g, &ana.all_of(&g));
        cy.takes(&g, &ana.all_of(&g));
        let joined = bo.says_reach(&g, false);
        cy.takes(&g, &[joined]);
        let first = bo.space(&g).current_epoch();
        assert_eq!(cy.space(&g).current_epoch(), first);
        // An epoch comes due on Bo's device, and it starts one: for Ana,
        // whose key it holds, and not for Cy.
        let moved = bo.changes_key();
        assert!(
            bo.core
                .ingest_identity(std::slice::from_ref(&moved), None)
                .unwrap()
                .changed
        );
        cy.core.ingest_other(bo.id(), &[moved]).unwrap();
        let second = bo.says_reach(&g, false);
        assert!(bo.began_an_epoch(&g));
        cy.takes(&g, &[second]);
        assert_eq!(cy.space(&g).current_epoch(), first, "Cy was wrapped for");
        // Cy's log reaches Bo's device. Nothing was written in the space
        // since, and no key of Cy's has changed.
        bo.meets(&cy);
        let third = bo.says_reach(&g, false);
        assert!(bo.began_an_epoch(&g), "Cy is left out for good");
        cy.takes(&g, &[third]);
        assert_eq!(cy.space(&g).current_epoch(), bo.space(&g).current_epoch());
        // Once is enough.
        bo.says_reach(&g, false);
        assert!(!bo.began_an_epoch(&g));
    }

    /// P9 (`spaces.md#when-to-rotate`). A member whose `leave` stops
    /// counting is a member the current epoch was started without: here a
    /// stolen device wrote the `leave`, an epoch was started without its
    /// person, and they then removed the device as lost. The first key a
    /// device holds for them, now that they are in the space again, is a
    /// change.
    #[test]
    fn a_member_whose_leave_stopped_counting_is_given_the_next_epoch() {
        use cardinal_identity::{EntryBuilder, IdentityOp};
        let [mut ana, mut bo, mut dee, _] = four();
        let both = [(bo.id(), "Bo".to_owned()), (dee.id(), "Dee".to_owned())];
        let g = ana.core.create_group("Choir", "Ana", &both).unwrap();
        bo.takes(&g, &ana.all_of(&g));
        dee.takes(&g, &ana.all_of(&g));
        let joined = dee.says_reach(&g, false);
        ana.takes(&g, &[joined]);
        // Dee's device, in someone else's hands, leaves the group.
        let (_, gone) = dee
            .core
            .write_entry(&g, relationship::leave_ops(&dee.id()))
            .unwrap();
        ana.takes(&g, &[gone]);
        assert!(ana.space(&g).has_left(&dee.id()));
        // Whoever writes next starts an epoch without Dee.
        ana.says(&g, "without Dee");
        assert!(ana.began_an_epoch(&g));
        ana.says(&g, "and once is enough");
        assert!(!ana.began_an_epoch(&g));
        // Dee removes the device as lost, with their recovery words: what
        // it wrote that nobody of theirs built on counts no longer.
        let head = {
            let ident = dee.core.identity.as_ref().unwrap();
            *ident.log.dag().log_order().last().unwrap()
        };
        let lost = dee.core.keys.device.signing.public_key();
        let removal = EntryBuilder::new(dee.id(), &[head])
            .op(IdentityOp::remove_key(lost))
            .sign(&dee.root)
            .unwrap()
            .encode();
        assert!(ana.core.ingest_other(dee.id(), &[removal]).unwrap());
        assert!(!ana.space(&g).has_left(&dee.id()), "the leave still counts");
        // Dee is in the space, and the epoch there is was not started for
        // them: the next write starts one that is.
        ana.says(&g, "with Dee again");
        assert!(ana.began_an_epoch(&g), "Dee is never given the key again");
        ana.says(&g, "and once is enough");
        assert!(!ana.began_an_epoch(&g));
    }

    /// D2. An entry is taken into the space in memory and then saved. If it
    /// cannot be saved it must not stay in memory: every later entry would
    /// name it as a parent, and after a restart they would wait for ever
    /// for an entry that is nowhere.
    #[test]
    fn an_entry_that_could_not_be_saved_is_not_kept_in_memory() {
        use cardinal_space::files;
        let mut ana = Person::new();
        let space = ana.core.files_id().unwrap();
        let a = files::create_folder(ROOT, "a");
        ana.core.write_entry(&space, vec![a]).unwrap();
        let held = |p: &Person| (p.space(&space).dag().len(), p.space(&space).heads());
        let before = held(&ana);
        ana.core
            .spaces
            .get_mut(&space)
            .unwrap()
            .file
            .break_for_test();
        let b = files::create_folder(ROOT, "b");
        assert!(ana.core.write_entry(&space, vec![b]).is_err());
        assert_eq!(held(&ana), before, "an entry that was not saved is held");
        // What is written next is whole, here and after a restart.
        let c = files::create_folder(ROOT, "c");
        let (c, _) = ana.core.write_entry(&space, vec![c]).unwrap();
        let after = held(&ana);
        assert_eq!(after.0, before.0 + 1);
        ana.restarts();
        assert_eq!(held(&ana), after);
        let sp = ana.space(&space);
        assert!(sp.validity().is_valid(&c) && sp.state().is_accepted(&c));
    }

    /// A file that someone moved into a place where a file means nothing is
    /// not shown, and is current state all the same: its content is never
    /// freed as an old version, so that moved back it is whole
    /// (`state.md#operations`, `cleanup.rs`).
    #[test]
    fn the_content_of_what_is_not_shown_is_still_current() {
        use cardinal_blob::BlobRef;
        use cardinal_encoding::Value;
        use cardinal_space::files::{self, Content};
        let mut ana = Person::new();
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
        let space = ana.core.files_id().unwrap();
        let ops = vec![
            files::create_file(ROOT, "a.bin", &content(1), 0o644, None),
            files::create_file(ROOT, "b.bin", &content(2), 0o644, None),
        ];
        let (entry, _) = ana.core.write_entry(&space, ops).unwrap();
        let (a, b) = (
            files::created_node(&entry, 0),
            files::created_node(&entry, 1),
        );
        let shown = |p: &Person| -> Vec<u8> {
            let all = crate::fetch::current_blobs(p.space(&space));
            let mut ids: Vec<u8> = all.iter().map(|(_, b)| b.id[0]).collect();
            ids.sort();
            ids
        };
        // what is current, shown or not, less what is shown
        let unshown = |p: &Person| -> Vec<u8> {
            let listed = shown(p);
            let all = crate::fetch::current_refs(p.space(&space));
            let mut ids: Vec<u8> = all.iter().map(|b| b.id[0]).collect();
            assert!(listed.iter().all(|id| ids.contains(id)));
            ids.retain(|id| !listed.contains(id));
            ids.sort();
            ids
        };
        assert_eq!((shown(&ana), unshown(&ana)), (vec![1, 2], vec![]));
        // Moved into a file, and beside it a node of a kind nobody here
        // knows that names content of its own.
        let field = Record::new().with(9, Value::list([blob(3).to_record()]));
        let ops = vec![
            SpaceOp::mv(a, b, "a.bin"),
            SpaceOp::create(NodeKind::Uint(77), ROOT, "new", field),
        ];
        let (entry, _) = ana.core.write_entry(&space, ops).unwrap();
        assert!(ana.space(&space).state().is_accepted(&entry));
        assert_eq!((shown(&ana), unshown(&ana)), (vec![2], vec![1, 3]));
        // The cleaner knows every version there has been, and what is
        // current among them is what the folder shows and what it does not.
        let known = crate::cleanup::known_blobs(ana.space(&space));
        assert!(known.contains_key(&[1; 32]) && known.contains_key(&[2; 32]));
        // Moved back, it is shown again; deleted, the other is current no
        // longer.
        let odd = files::created_node(&entry, 1);
        let ops = vec![SpaceOp::mv(a, ROOT, "a.bin"), SpaceOp::delete(odd)];
        ana.core.write_entry(&space, ops).unwrap();
        assert_eq!((shown(&ana), unshown(&ana)), (vec![1, 2], vec![]));
    }

    /// `blobs.md#retention`: current state references every blob reference
    /// that a field of one of its nodes holds, whatever the node's kind,
    /// and a device that keeps a space in full fetches all of it, the
    /// content of a kind it does not know as much as a file's. One that
    /// keeps on demand fetches what is pinned; what nothing shows is never
    /// opened there.
    #[test]
    fn a_full_holder_fetches_the_content_of_kinds_it_does_not_know() {
        use cardinal_blob::BlobRef;
        use cardinal_encoding::Value;
        use cardinal_space::files::{self, Content};
        let [mut ana, mut bo, cy, _] = four();
        let blob = |n: u8| BlobRef {
            id: [n; 32],
            key: [n + 100; 32],
            size: 5000,
            levels: 1,
        };
        let held = |n: u8| Value::from(blob(n).to_record());
        let file = |n: u8| {
            let b = blob(n);
            Content::Blob(files::BlobRef {
                id: b.id,
                key: b.key,
                size: b.size,
                levels: b.levels,
            })
        };
        let odd = |name: &str, parent, value: Value| {
            let fields = Record::new().with(9, value);
            SpaceOp::create(NodeKind::Uint(77), parent, name, fields)
        };
        let space = ana.core.files_id().unwrap();
        // A file, and nodes of a kind nobody here knows: one holds a
        // reference in a list, one a record deep, one plainly, one the
        // file's own, and one is put in a folder made beside it.
        let deep = Record::new()
            .with(1, "caption")
            .with(2, Value::list([held(4)]));
        let beneath = Record::new().with(9, held(7));
        let ops = vec![
            files::create_file(ROOT, "a.bin", &file(1), 0o644, None),
            files::create_folder(ROOT, "gone"),
            odd("list", ROOT, Value::list([held(3)])),
            odd("deep", ROOT, deep.into()),
            odd("plain", ROOT, held(5)),
            odd("deleted", ROOT, held(6)),
            odd("same", ROOT, held(1)),
            SpaceOp::create_under(NodeKind::Uint(77), 1, "beneath", beneath),
        ];
        let (entry, _) = ana.core.write_entry(&space, ops).unwrap();
        assert!(ana.space(&space).state().is_accepted(&entry));
        let made = |k| files::created_node(&entry, k);
        let ids = |v: Vec<(String, BlobRef)>| {
            let mut ids: Vec<u8> = v.iter().map(|(_, b)| b.id[0]).collect();
            ids.sort();
            ids
        };
        let wanted = |p: &Person, on_demand, keep: &dyn Fn(&str, &BlobRef) -> bool| {
            let sp = p.space(&space);
            let shown = crate::fetch::current_blobs(sp);
            crate::fetch::wanted(sp, shown, on_demand, keep)
        };
        let nothing = |_: &str, _: &BlobRef| false;
        // In full: the file, and all that the other nodes hold, each once.
        let all = wanted(&ana, false, &nothing);
        let names: std::collections::HashSet<&str> = all.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(names.len(), 6);
        assert_eq!(ids(all), [1, 3, 4, 5, 6, 7]);
        // What a field held before is not current, nor what a deleted
        // node holds, nor what is beneath one.
        let ops = vec![
            SpaceOp::set(made(4), 9, Some(held(8))),
            SpaceOp::delete(made(5)),
            SpaceOp::delete(made(1)),
        ];
        ana.core.write_entry(&space, ops).unwrap();
        assert_eq!(ids(wanted(&ana, false, &nothing)), [1, 3, 4, 8]);
        // On demand: what is pinned, and nothing that is not shown.
        assert_eq!(ids(wanted(&ana, true, &nothing)), [] as [u8; 0]);
        assert_eq!(ids(wanted(&ana, true, &|p, _| p == "a.bin")), [1]);

        // A group: what a kind nobody knows holds comes through a member
        // this person knows, who keeps it, and from their own devices if
        // they know nobody there.
        bo.knows(&ana, "Ana");
        let both = [(bo.id(), "Bo".to_owned()), (cy.id(), "Cy".to_owned())];
        let g = ana.core.create_group("Garden club", "Ana", &both).unwrap();
        let op = odd("plan", ROOT, held(9));
        let (entry, _) = ana.core.write_entry(&g, vec![op]).unwrap();
        bo.takes(&g, &ana.all_of(&g));
        assert!(bo.space(&g).state().is_accepted(&entry));
        let (a, me) = (ana.id(), Some(bo.id()));
        let of = |known: &dyn Fn(&[u8; 32]) -> bool, on_demand| {
            let sp = bo.space(&g);
            let all = crate::fetch::wanted_of_group(sp, me, known, on_demand, &|_| false);
            let from = all.into_iter().map(|(from, (_, b))| (from, b.id[0]));
            from.collect::<Vec<_>>()
        };
        assert_eq!(of(&|w| *w == a, false), [(Some(a), 9)]);
        assert_eq!(of(&|_| false, false), [(None, 9)]);
        assert_eq!(of(&|w| *w == a, true), []);

        // What one fetches another serves. Between two people each gives
        // what they wrote there themselves, since a reference the other
        // wrote could name anything; in a group, a member gets whatever
        // its state holds.
        ana.meets(&bo);
        bo.meets(&ana);
        let (rel, genesis) = ana.core.create_relationship(&bo.id()).unwrap();
        bo.core.accept_relationship(&genesis, &ana.id()).unwrap();
        let hers = odd("hers", ROOT, held(11));
        let (_, hers) = ana.core.write_entry(&rel, vec![hers]).unwrap();
        bo.core.ingest_space(rel, &[hers]).unwrap();
        let his = odd("his", ROOT, held(12));
        let (_, his) = bo.core.write_entry(&rel, vec![his]).unwrap();
        ana.core.ingest_space(rel, &[his]).unwrap();
        let serves = |p: &Person, groups: &[SpaceId]| {
            let all = crate::contacts::shared_refs(&p.core, &rel, groups);
            let mut ids: Vec<u8> = all.iter().map(|b| b.id[0]).collect();
            ids.sort();
            ids.dedup();
            ids
        };
        assert_eq!(serves(&ana, &[]), [11]);
        assert_eq!(serves(&bo, &[]), [12]);
        assert_eq!(serves(&ana, &[g]), [9, 11]);
        assert_eq!(serves(&bo, &[g]), [9, 12]);
        // And each fetches all of it, in full.
        let sp = bo.space(&rel);
        let all = crate::fetch::wanted(sp, Vec::new(), false, &nothing);
        assert_eq!(ids(all), [11, 12]);
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
