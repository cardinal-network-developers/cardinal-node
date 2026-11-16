//! Freeing the space of deleted files and old versions
//! (`blobs.md#retention`: which chunks to keep is each device's choice).
//!
//! - A device keeps every blob of current state (every version of a file
//!   in conflict too).
//! - A blob that stops being current, because its file was replaced or
//!   deleted, is kept for a while so it can be restored: `keep_old` in
//!   `config.toml`, 30 days by default, or `forever`. The time counts from
//!   when this device first saw the blob was no longer current (kept in
//!   `old-versions.json`), not from any device's clock.
//! - Then its chunks and indexes are deleted, in a pass about every hour.
//!   `cardinal free-space` deletes them all now.
//! - Under on-demand retention, objects of current files that are not
//!   pinned also go beyond the budget, least recently used first.
//!
//! Objects stored or read in the last hour are never deleted: a commit
//! writes its chunks before the entry that names them, and a reader may be
//! using them.
//!
//! That pass deletes only what it knows to be old, so that a mistake in
//! finding what is current deletes nothing. It therefore never frees an
//! object that nothing names at all: what a space this device no longer
//! holds left behind, or a commit that never finished. A second pass, run
//! on purpose (`cardinal free-space --unnamed`), finds those: it marks
//! every object reachable from a blob reference in any entry of any space
//! held, and counts the rest. It deletes them only on the person's word,
//! and only when it is sure: if a space cannot be read, or an index it has
//! to follow is not here, what that names cannot be told from what nothing
//! names, and nothing is deleted.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

use cardinal_blob::{decrypt, BlobRef, Id, Index, ObjectStore};
use cardinal_space::files::{Content, FILE_CONTENT};
use cardinal_space::{Space, SpaceOpBody};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::core::now_ms;
use crate::daemon::Daemon;
use crate::fetch::{blob_ref, current_blobs};
use crate::paths::write_private;

const DAY_MS: u64 = 86_400_000;

/// How long old versions are kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Keep {
    /// This many days after they stop being current.
    Days(u64),
    /// Never deleted.
    Forever,
}

impl Keep {
    /// Parses `30`, `30d`, `30 days`, or `forever`.
    pub fn parse(s: &str) -> anyhow::Result<Keep> {
        let s = s.trim().to_ascii_lowercase();
        if s == "forever" {
            return Ok(Keep::Forever);
        }
        let n = s
            .trim_end_matches("days")
            .trim_end_matches("day")
            .trim_end_matches('d')
            .trim();
        n.parse::<u64>()
            .map(Keep::Days)
            .map_err(|_| anyhow::anyhow!("{s:?} is not a number of days (like 30) or `forever`"))
    }

    fn ms(&self) -> Option<u64> {
        match self {
            Keep::Days(n) => Some(n.saturating_mul(DAY_MS)),
            Keep::Forever => None,
        }
    }
}

impl std::fmt::Display for Keep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Keep::Days(1) => f.write_str("1 day"),
            Keep::Days(n) => write!(f, "{n} days"),
            Keep::Forever => f.write_str("forever"),
        }
    }
}

/// When this device first saw each blob that is no longer current stop
/// being current, by its top id.
#[derive(Default)]
pub struct Ledger {
    since: HashMap<Id, u64>,
    /// The old blobs this device has freed: what they named is gone on
    /// purpose, and is not missing.
    freed: HashSet<Id>,
}

#[derive(Default, Serialize, Deserialize)]
struct Saved {
    since: BTreeMap<String, u64>,
    #[serde(default)]
    freed: BTreeSet<String>,
}

impl Ledger {
    /// Notes which of the `known` blobs (every blob the history names) are
    /// `live` (current). Returns whether anything changed.
    pub fn update(&mut self, live: &HashSet<Id>, known: &HashSet<Id>, now: u64) -> bool {
        let before = self.since.len();
        self.since
            .retain(|id, _| known.contains(id) && !live.contains(id));
        // a version that is current again was fetched again
        let freed = self.freed.len();
        self.freed
            .retain(|id| known.contains(id) && !live.contains(id));
        let mut changed = self.since.len() != before || self.freed.len() != freed;
        for id in known.difference(live) {
            if !self.since.contains_key(id) {
                self.since.insert(*id, now);
                changed = true;
            }
        }
        changed
    }

    /// Notes old blobs as freed, and says whether that is news.
    fn note_freed(&mut self, ids: impl Iterator<Item = Id>) -> bool {
        let before = self.freed.len();
        self.freed.extend(ids);
        self.freed.len() != before
    }

    /// The references among `roots` that are not to a blob this device
    /// freed: for telling what is named, where a freed blob's index is not
    /// one that is missing. A blob that is `live` (current content), or
    /// whose top object is `here` again, was stored or fetched again since
    /// it was freed, and names what it names: only `update`, on the hourly
    /// pass, takes it off the list, and that may be long after.
    pub fn not_freed(
        &self,
        roots: Vec<BlobRef>,
        live: &HashSet<Id>,
        here: impl Fn(&Id) -> bool,
    ) -> Vec<BlobRef> {
        let kept = roots
            .into_iter()
            .filter(|b| !self.freed.contains(&b.id) || live.contains(&b.id) || here(&b.id));
        kept.collect()
    }

    /// Whether an old blob is still kept.
    pub fn kept(&self, id: &Id, now: u64, keep: Keep) -> bool {
        match (keep.ms(), self.since.get(id)) {
            (None, _) => true,
            (Some(ms), Some(t)) => now.saturating_sub(*t) < ms,
            (Some(_), None) => true,
        }
    }

    fn load(path: &Path) -> Ledger {
        let saved: Saved = std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let id = |k: &String| -> Option<Id> { hex::decode(k).ok()?.try_into().ok() };
        Ledger {
            freed: saved.freed.iter().filter_map(id).collect(),
            since: saved
                .since
                .into_iter()
                .filter_map(|(k, t)| Some((id(&k)?, t)))
                .collect(),
        }
    }

    fn save(&self, path: &Path) {
        let saved = Saved {
            since: self
                .since
                .iter()
                .map(|(k, t)| (hex::encode(k), *t))
                .collect(),
            freed: self.freed.iter().map(hex::encode).collect(),
        };
        let bytes = serde_json::to_vec(&saved).unwrap_or_default();
        if let Err(e) = write_private(path, &bytes, 0o600) {
            tracing::warn!("cannot save {}: {e}", path.display());
        }
    }
}

/// The objects of `b` this device holds: its top object, and below every
/// index it holds, what that index names. Indexes it lacks are skipped,
/// with what is beneath them (on demand, a file is fetched as it is read).
pub fn held_objects(store: &dyn ObjectStore, b: &BlobRef, out: &mut HashSet<Id>) -> io::Result<()> {
    let mut stack = vec![(b.id, b.key, b.levels > 0)];
    while let Some((id, key, index)) = stack.pop() {
        if out.contains(&id) || !store.has(&id)? {
            continue;
        }
        out.insert(id);
        if !index {
            continue;
        }
        let Some(ct) = store.get(&id)? else { continue };
        let Ok(ix) = decrypt(&key, &ct).and_then(|p| Index::decode(&p)) else {
            continue;
        };
        for e in ix.entries {
            stack.push((e.id, e.key, ix.level > 0));
        }
    }
    Ok(())
}

/// What blob references name, as far as this device can follow them.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Named {
    /// Every object they name, here or not: each top object, and below
    /// every index held, what that index names.
    pub objects: HashSet<Id>,
    /// Indexes they name that are not in the store.
    pub missing: u64,
    /// Indexes they name that are in the store and cannot be read.
    pub unreadable: u64,
}

/// Marks every object reachable from `roots`, through indexes at every
/// level. An index that is missing or unreadable is counted: the objects
/// it names cannot be told from objects nothing names.
pub fn named_objects(store: &dyn ObjectStore, roots: &[BlobRef]) -> io::Result<Named> {
    let mut out = Named::default();
    let mut stack: Vec<(Id, [u8; 32], bool)> =
        roots.iter().map(|b| (b.id, b.key, b.levels > 0)).collect();
    // an index is followed once for each key it is named with: a key that
    // does not open it is no reason not to try another that might
    let mut followed: HashSet<(Id, [u8; 32])> = HashSet::new();
    while let Some((id, key, index)) = stack.pop() {
        out.objects.insert(id);
        if !index || !followed.insert((id, key)) {
            continue;
        }
        let Some(ct) = store.get(&id)? else {
            out.missing += 1;
            continue;
        };
        match decrypt(&key, &ct).and_then(|p| Index::decode(&p)) {
            Ok(ix) => stack.extend(ix.entries.iter().map(|e| (e.id, e.key, ix.level > 0))),
            Err(_) => out.unreadable += 1,
        }
    }
    Ok(out)
}

/// The objects in the store that are not among `named`, with their sizes.
/// Objects stored or read less than `min_age` before `now` are left out:
/// a commit writes its chunks before the entry that names them.
pub fn unnamed_objects(
    store: &dyn ObjectStore,
    named: &HashSet<Id>,
    now: SystemTime,
    min_age: Duration,
) -> io::Result<Vec<(Id, u64)>> {
    let young = |used: SystemTime| now.duration_since(used).unwrap_or_default() < min_age;
    let all = store.list()?.into_iter();
    let unnamed = all.filter(|o| !named.contains(&o.id) && !young(o.used));
    Ok(unnamed.map(|o| (o.id, o.size)).collect())
}

/// What a pass for objects that nothing names found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Unnamed {
    /// How many objects nothing names, or how many were deleted.
    pub objects: u64,
    /// Their bytes.
    pub bytes: u64,
    /// Whether they were deleted.
    pub deleted: bool,
    /// Why the count may be too high. Nothing is deleted while there is
    /// any reason.
    pub unsure: Vec<String>,
}

fn unnamed_reasons(named: &Named, unsure: &mut Vec<String>) {
    if named.missing > 0 {
        unsure.push(format!(
            "{} indexes that entries name are not on this device, so what they name cannot \
             be told from what nothing names",
            named.missing
        ));
    }
    if named.unreadable > 0 {
        unsure.push(format!(
            "{} indexes that entries name cannot be read here, so what they name cannot be \
             told from what nothing names",
            named.unreadable
        ));
    }
}

/// Counts the objects in the store that nothing this device holds names,
/// and with `delete` removes them (blocking). It never deletes an object a
/// held space might name: with any reason to doubt the count it reports
/// the reason and deletes nothing.
pub fn unnamed(d: &Daemon, delete: bool) -> anyhow::Result<Unnamed> {
    let c = &d.cleanup;
    let _one_at_a_time = lock(&c.running);
    // From finding what is named to deleting, no commit runs.
    crate::fs::commit::without_commits(|| {
        let store: &dyn ObjectStore = &*d.store;
        // A read that fails is "here": nothing is left out as freed on a
        // guess.
        let here = |id: &Id| store.has(id).unwrap_or(true);
        let named_now = || {
            let core = d.core();
            let (roots, unsure) = core.named_blobs();
            let files = core.files_id().and_then(|f| core.spaces.get(&f));
            let live: HashSet<Id> = files
                .and_then(|h| h.space.as_ref())
                .map(|sp| crate::fetch::current_refs(sp).iter().map(|b| b.id).collect())
                .unwrap_or_default();
            (roots, unsure, live)
        };
        let (roots, mut unsure, live) = named_now();
        // less the old versions this device freed: their indexes are gone
        // on purpose
        let roots = lock(&c.ledger).not_freed(roots, &live, here);
        let mut named = named_objects(store, &roots)?;
        let mut found = unnamed_objects(store, &named.objects, SystemTime::now(), c.min_age)?;
        if delete && !found.is_empty() {
            // What arrived meanwhile may name something that was here.
            let (again, also, live) = named_now();
            let again = lock(&c.ledger).not_freed(again, &live, here);
            let known: HashSet<&BlobRef> = roots.iter().collect();
            let new: Vec<BlobRef> = again.into_iter().filter(|b| !known.contains(b)).collect();
            let more = named_objects(store, &new)?;
            found.retain(|(id, _)| !more.objects.contains(id));
            named.missing += more.missing;
            named.unreadable += more.unreadable;
            unsure = also;
        }
        unnamed_reasons(&named, &mut unsure);
        let mut out = Unnamed {
            objects: found.len() as u64,
            bytes: found.iter().map(|(_, size)| size).sum(),
            deleted: false,
            unsure,
        };
        if delete && out.unsure.is_empty() {
            (out.objects, out.bytes) = (0, 0);
            for (id, size) in &found {
                if store.delete(id)? {
                    out.objects += 1;
                    out.bytes += size;
                }
            }
            out.deleted = true;
            if out.objects > 0 {
                tracing::info!(
                    "deleted {} objects ({} bytes) that nothing named",
                    out.objects,
                    out.bytes
                );
            }
        }
        Ok(out)
    })
}

/// What a pass found, and what it deletes.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Plan {
    /// Objects to delete, with their sizes.
    pub delete: Vec<(Id, u64)>,
    /// Bytes held only for deleted files and old versions, before
    /// deleting.
    pub old_bytes: u64,
    /// Of those, the bytes the plan deletes.
    pub old_deleted: u64,
    /// Under on-demand retention, the objects of current files that may be
    /// dropped, least recently used first, and how many bytes over the
    /// budget there are: each is dropped only once a device that keeps
    /// everything produces it (`blobs.md#dropping-a-chunk`).
    pub evict: Vec<(Id, u64)>,
    /// Bytes to drop to get within the budget.
    pub excess: u64,
}

/// What to keep and what may go, for [`plan`].
pub struct Wanted<'a> {
    /// Blobs of current files.
    pub live: &'a [BlobRef],
    /// Old blobs still within the keep period.
    pub old: &'a [BlobRef],
    /// Old blobs past it.
    pub expired: &'a [BlobRef],
    /// Under on-demand retention: the blobs of pinned files, and the most
    /// bytes to keep of other current files.
    pub on_demand: Option<(&'a [BlobRef], u64)>,
}

/// Decides what to delete: the objects of expired blobs that no current
/// or kept blob also names (chunks are shared between files with the same
/// content); and, to evict, under on-demand retention the least recently
/// used objects of current files that are not pinned, beyond the budget. An
/// object no blob names is left alone: deleting only what is known to be
/// old keeps a mistake in finding what is current from deleting it.
/// Objects stored or read less than `min_age` before `now` stay.
pub fn plan(
    store: &dyn ObjectStore,
    wanted: &Wanted<'_>,
    now: SystemTime,
    min_age: Duration,
) -> io::Result<Plan> {
    let mut live = HashSet::new();
    for b in wanted.live {
        held_objects(store, b, &mut live)?;
    }
    let mut kept = live.clone();
    for b in wanted.old {
        held_objects(store, b, &mut kept)?;
    }
    let mut expired = HashSet::new();
    for b in wanted.expired {
        held_objects(store, b, &mut expired)?;
    }
    let young = |used: SystemTime| now.duration_since(used).unwrap_or_default() < min_age;
    let mut out = Plan::default();
    let mut unpinned = Vec::new();
    for o in store.list()? {
        let old = !live.contains(&o.id) && (kept.contains(&o.id) || expired.contains(&o.id));
        if old {
            out.old_bytes += o.size;
        }
        if young(o.used) {
            continue;
        }
        if old && !kept.contains(&o.id) {
            out.delete.push((o.id, o.size));
            out.old_deleted += o.size;
        } else if wanted.on_demand.is_some() && live.contains(&o.id) {
            unpinned.push(o);
        }
    }
    if let Some((pins, budget)) = wanted.on_demand {
        let mut pinned = HashSet::new();
        for b in pins {
            held_objects(store, b, &mut pinned)?;
        }
        unpinned.retain(|o| !pinned.contains(&o.id));
        let total: u64 = unpinned.iter().map(|o| o.size).sum();
        if total > budget {
            unpinned.sort_by_key(|o| o.used);
            out.excess = total - budget;
            out.evict = unpinned.into_iter().map(|o| (o.id, o.size)).collect();
        }
    }
    Ok(out)
}

/// Every blob reference in a value, at any depth: a record shaped like one
/// (`blobs.md#references`), wherever it is. That needs no knowledge of
/// what a profile keeps where, and errs toward finding too many.
pub fn refs_in(v: &cardinal_encoding::Value, out: &mut HashSet<BlobRef>) {
    if let Some(r) = v.as_record() {
        if let Ok(b) = BlobRef::from_record(r) {
            out.insert(b);
        }
        r.iter().for_each(|(_, x)| refs_in(x, out));
    } else if let Some(list) = v.as_list() {
        list.iter().for_each(|x| refs_in(x, out));
    }
}

/// Every blob a files space's history names, by top id: the content of
/// every `create` and `set` of a file, current or not.
pub fn known_blobs(sp: &Space) -> HashMap<Id, BlobRef> {
    let mut out = HashMap::new();
    let st = sp.state();
    for id in st.applied() {
        let Some(e) = sp.entry(id) else { continue };
        for op in e.ops() {
            let value = match op.body() {
                SpaceOpBody::Create { fields, .. } => fields.get(FILE_CONTENT),
                SpaceOpBody::Set { key, value, .. } if *key == FILE_CONTENT => value.as_ref(),
                _ => None,
            };
            if let Some(Content::Blob(b)) = value.and_then(Content::from_value) {
                out.insert(b.id, blob_ref(&b));
            }
        }
    }
    out
}

/// What the last pass saw, for `cardinal status`.
#[derive(Clone, Copy, Debug, Default)]
pub struct Seen {
    /// Bytes held for deleted files and old versions.
    pub old_bytes: u64,
    /// When (ms since the epoch).
    pub at: u64,
    /// Under on-demand retention: files and bytes over the budget that could
    /// not be dropped, because no device that keeps everything produced them.
    pub only_here: (u64, u64),
    /// Over the budget, and no device that keeps everything could be asked.
    pub unasked: bool,
}

/// The cleaner of a daemon.
pub struct Cleaner {
    path: PathBuf,
    ledger: Mutex<Ledger>,
    seen: Mutex<Option<Seen>>,
    /// Held during a pass, so passes never overlap.
    running: Mutex<()>,
    min_age: Duration,
}

/// What a pass did.
#[derive(Clone, Copy, Debug, Default)]
pub struct Freed {
    /// Objects deleted (or that would be, in a dry run).
    pub objects: u64,
    /// Their bytes.
    pub bytes: u64,
    /// Bytes of deleted files and old versions left after it (stored or
    /// read in the last hour, or within the keep period).
    pub left: u64,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Cleaner {
    /// Loads the ledger from `path`. `CARDINAL_TEST_FREE_MIN_AGE_MS`
    /// shortens the hour that new objects are safe (tests).
    pub fn load(path: PathBuf) -> Cleaner {
        let min_age = std::env::var("CARDINAL_TEST_FREE_MIN_AGE_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .map(Duration::from_millis)
            .unwrap_or(Duration::from_secs(3600));
        Cleaner {
            ledger: Mutex::new(Ledger::load(&path)),
            path,
            seen: Mutex::new(None),
            running: Mutex::new(()),
            min_age,
        }
    }

    /// What the last pass saw.
    pub fn seen(&self) -> Option<Seen> {
        *lock(&self.seen)
    }
}

/// One pass (blocking): deletes what is past the keep period, or with
/// `now_all` every old version, and with `dry_run` only says what it
/// would delete.
pub fn pass(d: &Daemon, now_all: bool, dry_run: bool) -> anyhow::Result<Freed> {
    let c = &d.cleanup;
    let _one_at_a_time = lock(&c.running);
    // From finding what is current to deleting, no commit runs.
    let (mut freed, evict, excess, live) =
        crate::fs::commit::without_commits(|| pass_now(d, now_all, dry_run))?;
    let (mut files, mut kept_bytes, mut unasked) = (0u64, 0u64, false);
    if !evict.is_empty() {
        let (objects, bytes, kept) = evict_checked(d, &evict, excess, dry_run);
        freed.objects += objects;
        freed.bytes += bytes;
        unasked = kept.unasked;
        if !kept.absent.is_empty() {
            let store: &dyn ObjectStore = &*d.store;
            for b in &live {
                let mut o = HashSet::new();
                if held_objects(store, b, &mut o).is_ok() && !o.is_disjoint(&kept.absent) {
                    files += 1;
                }
            }
            kept_bytes = evict
                .iter()
                .filter(|(id, _)| kept.absent.contains(id))
                .map(|(_, s)| s)
                .sum();
            tracing::warn!(
                "over its budget: {files} files ({kept_bytes} bytes) are not on a device \
                 that keeps everything yet, so they stay"
            );
        } else if unasked {
            tracing::info!("over its budget, and no device that keeps everything is reachable");
        }
    }
    let mut g = lock(&c.seen);
    let s = g.get_or_insert_with(Seen::default);
    s.only_here = (files, kept_bytes);
    s.unasked = unasked;
    Ok(freed)
}

/// What dropping found it could not drop.
struct Kept {
    /// Objects no device that keeps everything produced.
    absent: HashSet<Id>,
    /// Whether no such device could be asked.
    unasked: bool,
}

/// Lock, Check, Delete (`blobs.md#dropping-a-chunk`), down the list until
/// `excess` bytes are dropped: stops answering for a batch of objects, asks
/// devices that keep everything for them, and deletes those one of them
/// produced; what none produced is kept, and the next are tried. Returns the
/// objects and bytes dropped (or that would be, in a dry run) and what was
/// kept.
fn evict_checked(d: &Daemon, evict: &[(Id, u64)], excess: u64, dry_run: bool) -> (u64, u64, Kept) {
    const BATCH: usize = 16;
    let holders = crate::copies::full_holder_sessions(d);
    let (mut objects, mut bytes) = (0u64, 0u64);
    let mut kept = Kept {
        absent: HashSet::new(),
        unasked: holders.is_empty(),
    };
    if holders.is_empty() {
        return (0, 0, kept);
    }
    for batch in evict.chunks(BATCH) {
        if bytes >= excess {
            break;
        }
        let ids: Vec<Id> = batch.iter().map(|(id, _)| *id).collect();
        if !dry_run {
            lock(&d.leaving).extend(ids.iter().copied());
        }
        let mut produced: HashSet<Id> = HashSet::new();
        for s in &holders {
            let want: Vec<Id> = ids
                .iter()
                .filter(|i| !produced.contains(*i))
                .copied()
                .collect();
            if want.is_empty() {
                break;
            }
            let reply = d.rt.block_on(crate::net::blob_request(
                s,
                want,
                cardinal_link::Priority::Background,
            ));
            // a holder that does not answer in time is not asked again for this
            // batch; the next holder, or the next batch, is
            let Ok(reply) = reply else { continue };
            for item in reply.items {
                if let cardinal_sync::BlobItem::Held { id, ciphertext } = item {
                    if cardinal_blob::object_id(&ciphertext) == id {
                        produced.insert(id);
                    }
                }
            }
        }
        for (id, size) in batch {
            if !produced.contains(id) {
                kept.absent.insert(*id);
            } else if dry_run || d.store.delete(id).unwrap_or(false) {
                objects += 1;
                bytes += size;
            }
        }
        if !dry_run {
            let mut l = lock(&d.leaving);
            for id in &ids {
                l.remove(id);
            }
        }
    }
    if bytes >= excess {
        kept.absent.clear(); // within the budget: what stays is not a problem
    }
    (objects, bytes, kept)
}

type Passed = (Freed, Vec<(Id, u64)>, u64, Vec<BlobRef>);

fn pass_now(d: &Daemon, now_all: bool, dry_run: bool) -> anyhow::Result<Passed> {
    let c = &d.cleanup;
    let (keep, on_demand, pins, budget) = {
        let cfg = d.config();
        (
            Keep::parse(&cfg.keep_old).unwrap_or(Keep::Days(30)),
            cfg.on_demand(),
            cfg.pins.clone(),
            cfg.on_demand_budget,
        )
    };
    let (live, known, pinned) = {
        let core = d.core();
        let Some(sp) = core
            .files_id()
            .and_then(|f| core.spaces.get(&f))
            .and_then(|h| h.space.as_ref())
        else {
            return Ok((Freed::default(), Vec::new(), 0, Vec::new()));
        };
        let current = current_blobs(sp);
        let pinned: Vec<BlobRef> = current
            .iter()
            .filter(|(p, _)| {
                pins.iter()
                    .any(|pin| p == pin || p.starts_with(&format!("{pin}/")))
            })
            .map(|(_, b)| *b)
            .collect();
        // What the folder does not show is current state all the same: a
        // file of a kind this build does not know, or one that was moved
        // into a file. Its content is never freed as an old version.
        let live = crate::fetch::current_refs(sp);
        (live, known_blobs(sp), pinned)
    };
    let now = now_ms();
    let live_ids: HashSet<Id> = live.iter().map(|b| b.id).collect();
    let (old, expired): (Vec<BlobRef>, Vec<BlobRef>) = {
        let mut l = lock(&c.ledger);
        if l.update(&live_ids, &known.keys().copied().collect(), now) {
            l.save(&c.path);
        }
        known
            .values()
            .filter(|b| !live_ids.contains(&b.id))
            .partition(|b| !now_all && l.kept(&b.id, now, keep))
    };
    let wanted = Wanted {
        live: &live,
        old: &old,
        expired: &expired,
        on_demand: on_demand.then_some((&pinned[..], budget)),
    };
    let store: &dyn ObjectStore = &*d.store;
    let p = plan(store, &wanted, SystemTime::now(), c.min_age)?;
    let mut freed = Freed::default();
    for (id, size) in &p.delete {
        if dry_run || store.delete(id)? {
            freed.objects += 1;
            freed.bytes += size;
        }
    }
    // An expired version whose top object is gone was freed, now or
    // before: the entry that wrote it is held for good, and what it names
    // must not count as missing (`unnamed`).
    if !dry_run {
        let mut gone = Vec::new();
        for b in &expired {
            if !store.has(&b.id)? {
                gone.push(b.id);
            }
        }
        let mut l = lock(&c.ledger);
        if l.note_freed(gone.into_iter()) {
            l.save(&c.path);
        }
    }
    // An object already gone counts as freed: it is not left either.
    freed.left = p.old_bytes.saturating_sub(p.old_deleted);
    let old_bytes = freed.left;
    if !dry_run {
        if freed.objects > 0 {
            tracing::info!(
                "freed {} objects ({} bytes) of deleted files and old versions",
                freed.objects,
                freed.bytes
            );
        }
        let (only_here, unasked) = lock(&c.seen)
            .as_ref()
            .map(|s| (s.only_here, s.unasked))
            .unwrap_or_default();
        *lock(&c.seen) = Some(Seen {
            old_bytes,
            at: now,
            only_here,
            unasked,
        });
    }
    Ok((freed, p.evict, p.excess, live))
}

/// Starts the hourly pass (`CARDINAL_TEST_FREE_INTERVAL_MS` for tests),
/// the first a minute after start.
pub fn start(d: std::sync::Arc<Daemon>) {
    let interval = std::env::var("CARDINAL_TEST_FREE_INTERVAL_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .map(Duration::from_millis)
        .unwrap_or(Duration::from_secs(3600));
    let first = interval.min(Duration::from_secs(60));
    tokio::spawn(async move {
        let mut wait = first;
        let mut stop = d.stopping.subscribe();
        loop {
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = stop.changed() => {}
            }
            if *d.stopping.borrow() {
                break;
            }
            let d2 = d.clone();
            match tokio::task::spawn_blocking(move || pass(&d2, false, false)).await {
                Ok(Err(e)) => tracing::warn!("freeing old versions: {e:#}"),
                Err(e) => tracing::warn!("freeing old versions: {e}"),
                Ok(Ok(_)) => {}
            }
            wait = interval;
        }
    });
}

/// The `old` object of `cardinal status`: bytes held for deleted files and
/// old versions, as of the last pass, and how long they are kept.
pub fn status(d: &Daemon) -> Value {
    let keep = Keep::parse(&d.config().keep_old).unwrap_or(Keep::Days(30));
    match d.cleanup.seen() {
        Some(s) => json!({
            "bytes": s.old_bytes,
            "at": s.at,
            "keep": keep.to_string(),
            // over the budget, and on no device that keeps everything yet
            "only_here": {"files": s.only_here.0, "bytes": s.only_here.1},
            // over the budget, and no device that keeps everything reachable
            "unchecked": s.unasked,
        }),
        None => json!({"bytes": null, "keep": keep.to_string()}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cardinal_blob::{encode_bytes, ConvergenceSecret, MemStore};

    fn data(len: usize, seed: u64) -> Vec<u8> {
        let mut x = 0x9e37_79b9_7f4a_7c15 ^ seed;
        let mut v = Vec::with_capacity(len + 8);
        while v.len() < len {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            v.extend_from_slice(&x.to_le_bytes());
        }
        v.truncate(len);
        v
    }

    #[test]
    fn keep_parses() {
        assert_eq!(Keep::parse("30").unwrap(), Keep::Days(30));
        assert_eq!(Keep::parse("7d").unwrap(), Keep::Days(7));
        assert_eq!(Keep::parse(" 90 days").unwrap(), Keep::Days(90));
        assert_eq!(Keep::parse("1 day").unwrap(), Keep::Days(1));
        assert_eq!(Keep::parse("Forever").unwrap(), Keep::Forever);
        assert!(Keep::parse("soon").is_err());
        assert_eq!(Keep::Days(30).to_string(), "30 days");
    }

    #[test]
    fn the_ledger_counts_from_when_a_blob_stopped_being_current() {
        let (a, b, c) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let mut l = Ledger::default();
        let known: HashSet<Id> = [a, b, c].into();
        // a and b current, c replaced: c's clock starts now
        assert!(l.update(&[a, b].into(), &known, 1000));
        assert!(!l.update(&[a, b].into(), &known, 2000), "nothing new");
        let keep = Keep::Days(30);
        assert!(l.kept(&c, 1000 + 30 * DAY_MS - 1, keep));
        assert!(!l.kept(&c, 1000 + 30 * DAY_MS, keep));
        assert!(l.kept(&c, u64::MAX, Keep::Forever));
        // b replaced later: its own clock
        l.update(&[a].into(), &known, 5 * DAY_MS);
        assert!(l.kept(&b, 34 * DAY_MS, keep));
        // c restored (current again), then replaced again: a new clock
        l.update(&[a, c].into(), &known, 40 * DAY_MS);
        l.update(&[a].into(), &known, 41 * DAY_MS);
        assert!(l.kept(&c, 70 * DAY_MS, keep));
    }

    /// The second pass: everything reachable from a blob reference is
    /// named, through indexes at every level, and the rest is counted. An
    /// index that is missing or cannot be read is said, since what it
    /// names cannot be told from what nothing names.
    #[test]
    fn what_nothing_names_is_what_no_reference_reaches() {
        let store = MemStore::new();
        let secret = ConvergenceSecret::from_epoch_key(&[7u8; 32]);
        let big = encode_bytes(&data(3 << 20, 1), &secret, &store).unwrap();
        let small = encode_bytes(&data(2000, 2), &secret, &store).unwrap();
        assert!(big.levels > 0 && small.levels == 0);
        let stray = b"left over from a space this device no longer holds".to_vec();
        let stray_id = *blake3::hash(&stray).as_bytes();
        store.put(&stray_id, &stray).unwrap();
        let all = store.list().unwrap().len();
        let later = SystemTime::now() + Duration::from_secs(7200);
        let hour = Duration::from_secs(3600);

        // Both named: only the stray is not.
        let named = named_objects(&store, &[big, small]).unwrap();
        assert_eq!((named.missing, named.unreadable), (0, 0));
        assert_eq!(named.objects.len(), all - 1);
        let found = unnamed_objects(&store, &named.objects, later, hour).unwrap();
        assert_eq!(found, [(stray_id, stray.len() as u64)]);
        // What was stored within the hour is neither counted nor deleted:
        // a commit writes its chunks before the entry that names them.
        let now = SystemTime::now();
        assert!(unnamed_objects(&store, &named.objects, now, hour)
            .unwrap()
            .is_empty());

        // Naming is not holding: a blob that is not here names its top
        // object, and that is all that can be said of it. If the top is an
        // index, that is an index this device lacks.
        let elsewhere = MemStore::new();
        let away = encode_bytes(&data(3 << 20, 3), &secret, &elsewhere).unwrap();
        let lone = encode_bytes(&data(2000, 4), &secret, &elsewhere).unwrap();
        let named = named_objects(&store, &[big, small, lone]).unwrap();
        assert_eq!((named.missing, named.unreadable), (0, 0));
        let named = named_objects(&store, &[big, small, away, lone]).unwrap();
        assert_eq!((named.missing, named.unreadable), (1, 0));

        // With only the small file named, the big one's objects look
        // unnamed: this is what the pass deletes when it is sure.
        let named = named_objects(&store, &[small]).unwrap();
        let found = unnamed_objects(&store, &named.objects, later, hour).unwrap();
        assert_eq!(found.len(), all - 1);

        // The big file's index is gone. Its chunks are still here, and
        // nothing can say they are its: one index is missing, and the
        // count is too high by every one of them.
        assert!(store.delete(&big.id).unwrap());
        let named = named_objects(&store, &[big, small]).unwrap();
        assert_eq!((named.missing, named.unreadable), (1, 0));
        assert!(named.objects.contains(&big.id));
        let found = unnamed_objects(&store, &named.objects, later, hour).unwrap();
        assert_eq!(found.len(), all - 2, "the stray, and every chunk of it");

        // An index named with a key that does not open it cannot be read.
        let other = MemStore::new();
        let again = encode_bytes(&data(3 << 20, 1), &secret, &other).unwrap();
        let wrong = BlobRef {
            key: [9; 32],
            ..again
        };
        let named = named_objects(&other, &[wrong]).unwrap();
        assert_eq!((named.missing, named.unreadable), (0, 1));
        assert_eq!(named.objects.len(), 1);
        // The same index named again with the key that opens it is read.
        let named = named_objects(&other, &[wrong, again]).unwrap();
        assert_eq!((named.missing, named.unreadable), (0, 1));
        assert_eq!(named.objects.len(), other.list().unwrap().len());
        let mut why = Vec::new();
        unnamed_reasons(&named, &mut why);
        assert_eq!(why.len(), 1);
        assert!(why[0].contains("cannot be read here"), "{why:?}");
    }

    #[test]
    fn plans_keep_current_and_recent_and_delete_the_rest() {
        let store = MemStore::new();
        let secret = ConvergenceSecret::from_epoch_key(&[7u8; 32]);
        let cur = encode_bytes(&data(3 << 20, 1), &secret, &store).unwrap();
        let recent = encode_bytes(&data(1 << 20, 2), &secret, &store).unwrap();
        let expired = encode_bytes(&data(1 << 20, 3), &secret, &store).unwrap();
        // shares chunks with the current file: those stay
        let mut shared = data(3 << 20, 1);
        shared.extend_from_slice(&data(512 << 10, 4));
        let shared = encode_bytes(&shared, &secret, &store).unwrap();
        assert!(cur.levels > 0);
        let later = SystemTime::now() + Duration::from_secs(7200);
        // something no blob names: left alone
        let stray = b"left over from an interrupted commit".to_vec();
        let stray_id = *blake3::hash(&stray).as_bytes();
        store.put(&stray_id, &stray).unwrap();
        let wanted = Wanted {
            live: &[cur],
            old: &[recent],
            expired: &[expired, shared],
            on_demand: None,
        };
        let p = plan(&store, &wanted, later, Duration::from_secs(3600)).unwrap();
        let held = |b: &BlobRef| {
            let mut s = HashSet::new();
            held_objects(&store, b, &mut s).unwrap();
            s
        };
        let (cur_o, recent_o, expired_o, shared_o) =
            (held(&cur), held(&recent), held(&expired), held(&shared));
        let deleted: HashSet<Id> = p.delete.iter().map(|(id, _)| *id).collect();
        assert!(deleted.is_disjoint(&cur_o));
        assert!(deleted.is_disjoint(&recent_o));
        assert!(expired_o.is_subset(&deleted));
        let only_shared: HashSet<Id> = shared_o.difference(&cur_o).copied().collect();
        assert!(!only_shared.is_empty() && only_shared.is_subset(&deleted));
        assert!(shared_o.intersection(&cur_o).count() > 10, "deduplicated");
        assert!(!deleted.contains(&stray_id));
        // nothing is deleted while it is new
        let p = plan(
            &store,
            &wanted,
            SystemTime::now(),
            Duration::from_secs(3600),
        )
        .unwrap();
        assert!(p.delete.is_empty());
        assert!(p.old_bytes > 0);
    }

    #[test]
    fn missing_indexes_are_skipped_not_fatal() {
        let store = MemStore::new();
        let secret = ConvergenceSecret::from_epoch_key(&[7u8; 32]);
        // indexes of 4 entries: a top index over level-0 indexes
        let mut w = cardinal_blob::BlobWriter::new(&secret, &store).with_index_fanout(4);
        std::io::Write::write_all(&mut w, &data(1 << 20, 9)).unwrap();
        let (b, _) = w.finish().unwrap();
        assert!(b.levels >= 2, "{}", b.levels);
        let mut all = HashSet::new();
        held_objects(&store, &b, &mut all).unwrap();
        // drop the first level-0 index: its chunks are no longer reachable,
        // the other's still are
        let top =
            Index::decode(&decrypt(&b.key, &store.get(&b.id).unwrap().unwrap()).unwrap()).unwrap();
        let gone = top.entries[0].id;
        store.delete(&gone).unwrap();
        let mut some = HashSet::new();
        held_objects(&store, &b, &mut some).unwrap();
        assert!(some.contains(&b.id) && !some.contains(&gone));
        assert!(some.contains(&top.entries[1].id));
        assert!(some.len() < all.len() && some.len() > 1);
    }

    #[test]
    fn on_demand_keeps_pins_and_the_most_recent_within_the_budget() {
        let store = MemStore::new();
        let secret = ConvergenceSecret::from_epoch_key(&[7u8; 32]);
        let pinned = encode_bytes(&data(1 << 20, 5), &secret, &store).unwrap();
        let other = encode_bytes(&data(2 << 20, 6), &secret, &store).unwrap();
        let later = SystemTime::now() + Duration::from_secs(7200);
        let wanted = Wanted {
            live: &[pinned, other],
            old: &[],
            expired: &[],
            on_demand: Some((&[pinned], 512 << 10)),
        };
        let p = plan(&store, &wanted, later, Duration::from_secs(3600)).unwrap();
        let mut pin_o = HashSet::new();
        held_objects(&store, &pinned, &mut pin_o).unwrap();
        // dropped in this order, until the excess is gone
        let mut deleted: HashSet<Id> = HashSet::new();
        let mut dropped = 0;
        for (id, size) in &p.evict {
            if dropped >= p.excess {
                break;
            }
            deleted.insert(*id);
            dropped += size;
        }
        assert!(p.delete.is_empty(), "nothing old to delete");
        assert!(deleted.is_disjoint(&pin_o));
        let mut other_o = HashSet::new();
        held_objects(&store, &other, &mut other_o).unwrap();
        let kept: u64 = store
            .list()
            .unwrap()
            .iter()
            .filter(|o| other_o.contains(&o.id) && !deleted.contains(&o.id))
            .map(|o| o.size)
            .sum();
        assert!(kept <= 512 << 10 && kept > 0, "{kept}");
    }
}
