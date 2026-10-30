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

use std::collections::{BTreeMap, HashMap, HashSet};
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
}

#[derive(Default, Serialize, Deserialize)]
struct Saved {
    since: BTreeMap<String, u64>,
}

impl Ledger {
    /// Notes which of the `known` blobs (every blob the history names) are
    /// `live` (current). Returns whether anything changed.
    pub fn update(&mut self, live: &HashSet<Id>, known: &HashSet<Id>, now: u64) -> bool {
        let before = self.since.len();
        self.since
            .retain(|id, _| known.contains(id) && !live.contains(id));
        let mut changed = self.since.len() != before;
        for id in known.difference(live) {
            if !self.since.contains_key(id) {
                self.since.insert(*id, now);
                changed = true;
            }
        }
        changed
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
        Ledger {
            since: saved
                .since
                .into_iter()
                .filter_map(|(k, t)| Some((hex::decode(k).ok()?.try_into().ok()?, t)))
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

/// What a pass found, and what it deletes.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Plan {
    /// Objects to delete, with their sizes.
    pub delete: Vec<(Id, u64)>,
    /// Bytes held only for deleted files and old versions, before
    /// deleting.
    pub old_bytes: u64,
    /// Of those, the bytes the plan deletes (the rest of `delete` are
    /// on-demand evictions of current files).
    pub old_deleted: u64,
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
/// content), and under on-demand retention the least recently used
/// objects of current files that are not pinned, beyond the budget. An
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
        let mut total: u64 = unpinned.iter().map(|o| o.size).sum();
        unpinned.sort_by_key(|o| o.used);
        for o in unpinned {
            if total <= budget {
                break;
            }
            total -= o.size;
            out.delete.push((o.id, o.size));
        }
    }
    Ok(out)
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
            return Ok(Freed::default());
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
        let live: Vec<BlobRef> = current.into_iter().map(|(_, b)| b).collect();
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
        *lock(&c.seen) = Some(Seen { old_bytes, at: now });
    }
    Ok(freed)
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
        Some(s) => json!({"bytes": s.old_bytes, "at": s.at, "keep": keep.to_string()}),
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
        let deleted: HashSet<Id> = p.delete.iter().map(|(id, _)| *id).collect();
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
