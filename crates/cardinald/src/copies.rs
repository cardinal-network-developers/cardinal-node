//! Counting copies of the files space by what was seen
//! (`blobs.md#counting-copies`, decision D45).
//!
//! The account space says which devices are meant to keep everything:
//! placements of the files space with full retention. That is intent.
//! What this module counts is evidence:
//!
//! - **Checks.** About every 10 minutes, each online device meant to keep
//!   everything is asked for a few objects (chunks or indexes) chosen at
//!   random among content this device first saw more than an hour ago,
//!   through the ordinary `blob` service, the same request a fetch sends.
//!   The answers are verified by hash and dropped. Content younger than
//!   that is left out, so a device still copying new files is not counted
//!   as failing: the count is of copies of everything older than an hour.
//! - **Fetching resets the count.** This device notes which of those
//!   devices fetch such content from it. One that does stops counting
//!   until it passes a check started longer than one check interval after
//!   its last fetch (a rebuild after a lost disk is ordinary sync).
//!   Requests of a few objects per interval are what another device's
//!   checks of this one look like, and are not taken as fetching (see
//!   DEVIATIONS.md); a device that answers a check with objects it
//!   fetches from this device during that check fails it.
//! - **Repeated fetches.** A device that fetches the same objects from
//!   this one again and again is not keeping them: it stops counting, and
//!   status says so.
//!
//! This device counts itself when it keeps everything, unless its own
//! check (a sample drawn the same way, read from its store) found pieces
//! missing.
//!
//! The rules are pure functions of time ([`Holder`]); [`start`] runs the
//! checks. Results are kept in `copies.json`, so a restart does not forget
//! a device that passed checks and is offline now.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use cardinal_blob::{decrypt, BlobRef, FsStore, Index, ObjectStore};
use cardinal_identity::KeyId;
use cardinal_link::Priority;
use cardinal_space::account::{self, Retention};
use cardinal_space::SpaceId;
use cardinal_sync::{BlobItem, BlobReply};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::core::{now_ms, short};
use crate::daemon::Daemon;
use crate::paths::write_private;

/// How checks run and what they count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rules {
    /// Between two checks of one device: 10 minutes.
    pub interval_ms: u64,
    /// Content this device first saw less than this long ago is neither
    /// checked nor counted: an hour.
    pub min_age_ms: u64,
    /// Objects asked for per check.
    pub sample: usize,
    /// How long a passed check keeps an unchecked (offline) device
    /// counted: 7 days.
    pub horizon_ms: u64,
}

impl Default for Rules {
    fn default() -> Rules {
        Rules {
            interval_ms: 10 * 60_000,
            min_age_ms: 3_600_000,
            sample: 4,
            horizon_ms: 7 * 86_400_000,
        }
    }
}

impl Rules {
    /// The defaults, with `CARDINAL_TEST_CHECK_INTERVAL_MS` and
    /// `CARDINAL_TEST_CHECK_MIN_AGE_MS` for tests.
    pub fn from_env() -> Rules {
        let ms = |v: &str| {
            std::env::var(v)
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .filter(|n| *n > 0)
        };
        let mut r = Rules::default();
        if let Some(n) = ms("CARDINAL_TEST_CHECK_INTERVAL_MS") {
            r.interval_ms = n;
        }
        if let Some(n) = ms("CARDINAL_TEST_CHECK_MIN_AGE_MS") {
            r.min_age_ms = n;
        }
        r
    }

    /// A device that fetched counts again only by passing a check that
    /// started this long after its last fetch: longer than the interval
    /// between checks.
    pub fn wait_ms(&self) -> u64 {
        self.interval_ms + self.interval_ms / 2
    }

    /// Objects of counted content a device may fetch from this one within
    /// one interval and still be taken for checking it (two checks' worth,
    /// and one). More is fetching.
    pub fn allowance(&self) -> usize {
        2 * self.sample + 1
    }

    /// Fetches of one object closer together than this are one fetch
    /// (retries, hedged requests).
    pub fn repeat_gap_ms(&self) -> u64 {
        2 * self.interval_ms
    }

    /// A device seen fetching the same objects again and again counts
    /// again only after passing a check this long after the last such
    /// fetch: a day at the default interval.
    pub fn repeat_hold_ms(&self) -> u64 {
        144 * self.interval_ms
    }
}

/// Separate fetches of one object that show a device is not keeping it.
pub const REPEATS: u8 = 3;
/// Fetched objects remembered per device, at most.
const FETCHED_MAX: usize = 200_000;
/// Average chunk size, to weigh blobs by their number of chunks.
const AVG_CHUNK: u64 = 64 * 1024;

/// How a check ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Every object came back and hashed to its id.
    Passed,
    /// Something was missing or wrong, in plain words.
    Failed(String),
}

/// What this device has seen of one device meant to keep everything.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Holder {
    /// When the last check started (ms since the epoch).
    pub last_check: Option<u64>,
    /// When the last passing check started.
    pub last_pass: Option<u64>,
    /// When the last failing check started.
    pub last_fail: Option<u64>,
    /// Why it failed.
    pub fail_reason: Option<String>,
    /// When it last fetched counted content from this device.
    pub fetched_at: Option<u64>,
    /// When it last fetched objects it had fetched before.
    pub repeated_at: Option<u64>,
    /// Counted objects sent to it recently: (time, count) per request.
    #[serde(skip)]
    recent: VecDeque<(u64, usize)>,
    /// Objects it fetched (first 8 bytes of the id): last time, times.
    #[serde(skip)]
    fetched: HashMap<u64, (u64, u8)>,
}

/// Whether a device counts as a copy now, and if not, why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Counted: it passed the check that started at `checked`.
    Counted {
        /// When.
        checked: u64,
    },
    /// It fetched counted content from this device (last at `last`) and
    /// has not passed a check long enough after.
    Fetching {
        /// When it last fetched.
        last: u64,
    },
    /// It fetched the same objects again and again.
    Repeated {
        /// When it last did.
        at: u64,
    },
    /// Its last check failed.
    Failed {
        /// When the check started.
        at: u64,
        /// Why.
        reason: String,
    },
    /// Its last pass is older than the horizon.
    Stale {
        /// When.
        checked: u64,
    },
    /// Never checked.
    Unchecked,
}

impl Verdict {
    /// Whether it counts as a copy.
    pub fn counted(&self) -> bool {
        matches!(self, Verdict::Counted { .. })
    }

    /// A name for JSON.
    pub fn state(&self) -> &'static str {
        match self {
            Verdict::Counted { .. } => "passed",
            Verdict::Fetching { .. } => "fetching",
            Verdict::Repeated { .. } => "repeated",
            Verdict::Failed { .. } => "failed",
            Verdict::Stale { .. } => "stale",
            Verdict::Unchecked => "unchecked",
        }
    }
}

fn prefix(id: &[u8; 32]) -> u64 {
    u64::from_le_bytes(id[..8].try_into().expect("8 bytes"))
}

impl Holder {
    /// Records a check that started at `started`.
    pub fn checked(&mut self, started: u64, outcome: Outcome) {
        self.last_check = Some(self.last_check.map_or(started, |t| t.max(started)));
        match outcome {
            Outcome::Passed => self.last_pass = Some(started),
            Outcome::Failed(why) => {
                self.last_fail = Some(started);
                self.fail_reason = Some(why);
            }
        }
    }

    /// This device just sent it `old` objects of counted content (first
    /// seen here more than the minimum age ago). Returns whether that was
    /// fetching (more than checks ask for).
    pub fn served(&mut self, r: &Rules, now: u64, old: &[[u8; 32]]) -> bool {
        if old.is_empty() {
            return false;
        }
        while self
            .recent
            .front()
            .is_some_and(|(t, _)| now.saturating_sub(*t) >= r.interval_ms)
        {
            self.recent.pop_front();
        }
        self.recent.push_back((now, old.len()));
        let total: usize = self.recent.iter().map(|(_, n)| n).sum();
        if total <= r.allowance() {
            return false;
        }
        self.fetched_at = Some(now);
        let mut repeated = false;
        for id in old {
            match self.fetched.get_mut(&prefix(id)) {
                None => {
                    self.fetched.insert(prefix(id), (now, 1));
                }
                Some((last, times)) => {
                    if now.saturating_sub(*last) >= r.repeat_gap_ms() {
                        *last = now;
                        *times = times.saturating_add(1);
                        repeated |= *times >= REPEATS;
                    }
                }
            }
        }
        if repeated {
            self.repeated_at = Some(now);
        }
        if self.fetched.len() > FETCHED_MAX {
            // Forget the half fetched longest ago.
            let mut times: Vec<u64> = self.fetched.values().map(|(t, _)| *t).collect();
            let mid = times.len() / 2;
            let (_, cut, _) = times.select_nth_unstable(mid);
            let cut = *cut;
            self.fetched.retain(|_, (t, _)| *t > cut);
        }
        true
    }

    /// Whether it counts now.
    pub fn verdict(&self, r: &Rules, now: u64) -> Verdict {
        let passed_since = |t: u64| self.last_pass.is_some_and(|p| p >= t);
        if let Some(t) = self.repeated_at {
            if !passed_since(t.saturating_add(r.repeat_hold_ms())) {
                return Verdict::Repeated { at: t };
            }
        }
        // The last check failed (and nothing passed since).
        let failed = self
            .last_fail
            .filter(|f| self.last_pass.is_none_or(|p| p <= *f));
        let failure = |at: u64| Verdict::Failed {
            at,
            reason: self
                .fail_reason
                .clone()
                .unwrap_or_else(|| "failed a check".into()),
        };
        if let Some(t) = self.fetched_at {
            let after = t.saturating_add(r.wait_ms());
            if !passed_since(after) {
                // A check after the wait says more than "fetching".
                return match failed {
                    Some(f) if f >= after => failure(f),
                    _ => Verdict::Fetching { last: t },
                };
            }
        }
        if let Some(f) = failed {
            return failure(f);
        }
        match self.last_pass {
            Some(p) if now.saturating_sub(p) <= r.horizon_ms => Verdict::Counted { checked: p },
            Some(p) => Verdict::Stale { checked: p },
            None => Verdict::Unchecked,
        }
    }

    /// This device's own standing: it keeps everything, so it counts
    /// unless its latest own check found something missing.
    pub fn own_verdict(&self) -> Verdict {
        match (self.last_fail, self.last_pass) {
            (Some(f), p) if p.is_none_or(|p| p < f) => Verdict::Failed {
                at: f,
                reason: self
                    .fail_reason
                    .clone()
                    .unwrap_or_else(|| "failed a check".into()),
            },
            (_, p) => Verdict::Counted {
                checked: p.unwrap_or(0),
            },
        }
    }

    /// When it should be checked next. `jitter` (about 0.8 to 1.2)
    /// spreads checks out. A device that fetched is checked once the wait
    /// is over, not before (such a check could not count it).
    pub fn next_check(&self, r: &Rules, jitter: f64) -> u64 {
        let mut due = self
            .last_check
            .map_or(0, |t| t + (r.interval_ms as f64 * jitter) as u64);
        if let Some(t) = self.fetched_at {
            let after = t.saturating_add(r.wait_ms());
            if self.last_pass.is_none_or(|p| p < after) {
                due = due.max(after + 1);
            }
        }
        due
    }
}

/// Judges a reply to a check of `ids`. `local` words it for this
/// device's own store.
pub fn judge(ids: &[[u8; 32]], reply: &BlobReply, local: bool) -> Outcome {
    let (mut missing, mut damaged) = (0, 0);
    for id in ids {
        let item = reply.items.iter().find(|i| match i {
            BlobItem::Held { id: x, .. } | BlobItem::NotHeld(x) => x == id,
        });
        match item {
            Some(BlobItem::Held { ciphertext, .. })
                if blake3::hash(ciphertext).as_bytes() == id => {}
            Some(BlobItem::Held { .. }) => damaged += 1,
            _ => missing += 1,
        }
    }
    if missing == 0 && damaged == 0 {
        return Outcome::Passed;
    }
    let n = ids.len();
    let mut parts = Vec::new();
    if missing > 0 {
        parts.push(if local {
            format!("missing {missing} of the {n} pieces of your files checked")
        } else {
            format!("did not have {missing} of the {n} pieces of your files asked for")
        });
    }
    if damaged > 0 {
        parts.push(if local {
            format!("{damaged} of the {n} pieces checked are damaged")
        } else {
            format!("sent {damaged} of the {n} pieces damaged")
        });
    }
    Outcome::Failed(parts.join(", and "))
}

/// A small random number generator for sampling (splitmix64).
pub struct Rng(u64);

impl Rng {
    /// Seeded from the system.
    pub fn new() -> Rng {
        Rng(u64::from_le_bytes(cardinal_crypto::random_bytes()))
    }

    /// Seeded (tests).
    pub fn seeded(s: u64) -> Rng {
        Rng(s)
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A number below `n` (0 if `n` is 0).
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next() % n
        }
    }

    /// A number in [0, 1).
    pub fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
}

impl Default for Rng {
    fn default() -> Rng {
        Rng::new()
    }
}

/// When an object was stored on this device (ms since the epoch): its
/// file's birth time, or its modification time where the file system
/// has no birth time (reads touch that, so it errs late).
pub fn born(store: &FsStore, id: &[u8; 32]) -> Option<u64> {
    let m = std::fs::symlink_metadata(store.path_of(id)).ok()?;
    let t = m.created().or_else(|_| m.modified()).ok()?;
    Some(t.duration_since(std::time::UNIX_EPOCH).ok()?.as_millis() as u64)
}

/// What can be checked: blobs of the current files state that this
/// device first saw long enough ago.
#[derive(Default)]
pub struct Pool {
    version: Option<(SpaceId, u64)>,
    refs: Vec<BlobRef>,
    /// Top id -> when first seen here: the top object's birth here, or
    /// when this run first saw the reference.
    first_seen: HashMap<[u8; 32], u64>,
    /// Cumulative weight (about the chunk count), index into `refs`.
    eligible: Vec<(u64, usize)>,
}

impl Pool {
    /// Takes the blobs of the current state, noting when each was first
    /// seen. `born` gives an object's birth on this device, if held.
    pub fn set_refs(
        &mut self,
        refs: Vec<BlobRef>,
        now: u64,
        born: impl Fn(&[u8; 32]) -> Option<u64>,
    ) {
        let mut seen = HashSet::new();
        self.refs = refs.into_iter().filter(|r| seen.insert(r.id)).collect();
        let mut first = HashMap::with_capacity(self.refs.len());
        for r in &self.refs {
            let t = match self.first_seen.get(&r.id) {
                Some(t) => *t,
                None => born(&r.id).unwrap_or(now).min(now),
            };
            first.insert(r.id, t);
        }
        self.first_seen = first;
    }

    /// Recomputes which blobs are old enough to check.
    pub fn select(&mut self, now: u64, min_age: u64) {
        self.eligible.clear();
        let mut total = 0u64;
        for (i, r) in self.refs.iter().enumerate() {
            if self
                .first_seen
                .get(&r.id)
                .is_some_and(|t| now.saturating_sub(*t) >= min_age)
            {
                total += 1 + r.size / AVG_CHUNK;
                self.eligible.push((total, i));
            }
        }
    }

    /// Blobs in the current state.
    pub fn blobs(&self) -> usize {
        self.refs.len()
    }

    /// Blobs old enough to check.
    pub fn eligible(&self) -> usize {
        self.eligible.len()
    }

    /// Up to `n` distinct objects at random, about uniformly over the
    /// chunks of eligible blobs. Indexes this device holds are descended
    /// through `get`; where it holds none, the blob's top id is asked.
    pub fn sample(
        &self,
        n: usize,
        rng: &mut Rng,
        get: impl Fn(&[u8; 32]) -> Option<Vec<u8>>,
    ) -> Vec<[u8; 32]> {
        let Some(&(total, _)) = self.eligible.last() else {
            return Vec::new();
        };
        let mut out: Vec<[u8; 32]> = Vec::new();
        for _ in 0..n * 4 {
            if out.len() >= n {
                break;
            }
            let x = rng.below(total);
            let pos = self.eligible.partition_point(|(c, _)| *c <= x);
            let r = &self.refs[self.eligible[pos.min(self.eligible.len() - 1)].1];
            let id = pick(r, rng, &get);
            if !out.contains(&id) {
                out.push(id);
            }
        }
        out
    }
}

/// One object of a blob at random: descends through the indexes held,
/// choosing children in proportion to the bytes beneath them, and stops
/// at an index now and then so indexes are checked too.
fn pick(r: &BlobRef, rng: &mut Rng, get: &impl Fn(&[u8; 32]) -> Option<Vec<u8>>) -> [u8; 32] {
    let (mut id, mut key, mut levels) = (r.id, r.key, r.levels);
    while levels > 0 {
        let Some(ct) = get(&id) else { break };
        let Ok(ix) = decrypt(&key, &ct).and_then(|p| Index::decode(&p)) else {
            break;
        };
        let n = ix.entries.len() as u64;
        if n == 0 || rng.below(n + 1) == 0 {
            break;
        }
        let total: u64 = ix.entries.iter().map(|e| e.len.max(1)).sum();
        let mut x = rng.below(total);
        let Some(e) = ix.entries.iter().find(|e| {
            let w = e.len.max(1);
            if x < w {
                true
            } else {
                x -= w;
                false
            }
        }) else {
            break;
        };
        id = e.id;
        key = e.key;
        levels -= 1;
    }
    id
}

/// Which devices are meant to keep everything, as this device last saw.
#[derive(Clone, Debug)]
struct View {
    me: KeyId,
    names: HashMap<KeyId, String>,
    self_full: bool,
    /// Other devices meant to keep everything, with their link keys.
    remote: Vec<(KeyId, [u8; 32])>,
    eligible: usize,
    blobs: usize,
}

#[derive(Default)]
struct Inner {
    holders: BTreeMap<KeyId, Holder>,
    /// Link key -> device, for the other devices meant to keep everything.
    by_link: HashMap<[u8; 32], KeyId>,
    /// Checks under way: the objects asked for, and whether the device
    /// fetched one of them from this device meanwhile.
    in_flight: HashMap<KeyId, (Vec<[u8; 32]>, bool)>,
    /// Devices that may have answered a check with what they fetched from
    /// this device during it: checked again at the time given, and failed
    /// if it happens again.
    recheck: HashMap<KeyId, u64>,
    view: Option<View>,
    dirty: bool,
}

#[derive(Default, Serialize, Deserialize)]
struct Saved {
    holders: BTreeMap<String, Holder>,
}

/// The copy counter of a daemon.
pub struct Tracker {
    /// The rules.
    pub rules: Rules,
    path: PathBuf,
    inner: Mutex<Inner>,
}

impl Tracker {
    /// Loads earlier results from `path`, if any.
    pub fn load(path: PathBuf, rules: Rules) -> Tracker {
        let saved: Saved = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let holders = saved
            .holders
            .into_iter()
            .filter_map(|(k, h)| {
                let b = hex::decode(k).ok()?;
                Some((<[u8; 32]>::try_from(&b[..]).ok()?, h))
            })
            .collect();
        Tracker {
            rules,
            path,
            inner: Mutex::new(Inner {
                holders,
                ..Inner::default()
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Saves the results if they changed.
    pub fn save(&self) {
        let bytes = {
            let mut inner = self.lock();
            if !inner.dirty {
                return;
            }
            inner.dirty = false;
            let saved: BTreeMap<String, &Holder> = inner
                .holders
                .iter()
                .map(|(k, h)| (hex::encode(k), h))
                .collect();
            serde_json::to_vec_pretty(&json!({ "holders": saved })).unwrap_or_default()
        };
        if let Err(e) = write_private(&self.path, &bytes, 0o600) {
            tracing::warn!("cannot save {}: {e}", self.path.display());
        }
    }

    /// When a device should be checked next ([`Holder::next_check`]).
    fn next_check(&self, key: &KeyId, jitter: f64) -> u64 {
        let inner = self.lock();
        if let Some(t) = inner.recheck.get(key) {
            return *t;
        }
        inner
            .holders
            .get(key)
            .map_or(0, |h| h.next_check(&self.rules, jitter))
    }

    fn name(&self, key: &KeyId) -> String {
        self.lock()
            .view
            .as_ref()
            .and_then(|v| v.names.get(key).cloned())
            .unwrap_or_else(|| short(key))
    }

    fn set_view(&self, v: View) {
        let mut inner = self.lock();
        inner.by_link = v.remote.iter().map(|(k, x)| (*x, *k)).collect();
        inner.view = Some(v);
    }

    /// After this device served a blob request: notes which objects of
    /// counted content a device meant to keep everything fetched.
    pub fn observe_serve(&self, peer: &[u8; 32], reply: &BlobReply, store: &FsStore) {
        let Some(key) = self.lock().by_link.get(peer).copied() else {
            return;
        };
        let held: Vec<[u8; 32]> = reply
            .items
            .iter()
            .filter_map(|i| match i {
                BlobItem::Held { id, .. } => Some(*id),
                BlobItem::NotHeld(_) => None,
            })
            .collect();
        if held.is_empty() {
            return;
        }
        let now = now_ms();
        let old: Vec<[u8; 32]> = held
            .iter()
            .copied()
            .filter(|id| {
                born(store, id).is_some_and(|t| now.saturating_sub(t) >= self.rules.min_age_ms)
            })
            .collect();
        let name = self.name(&key);
        let mut inner = self.lock();
        if let Some((asked, relayed)) = inner.in_flight.get_mut(&key) {
            if held.iter().any(|id| asked.contains(id)) {
                *relayed = true;
            }
        }
        let rules = self.rules;
        let h = inner.holders.entry(key).or_default();
        let before = h.verdict(&rules, now).state();
        if h.served(&rules, now, &old) {
            let after = h.verdict(&rules, now).state();
            if after != before {
                match after {
                    "repeated" => tracing::warn!(
                        "{name} fetches the same pieces of your files again and again; not \
                         counting it as a copy"
                    ),
                    _ => tracing::info!(
                        "{name} is fetching files from this device; it counts as a copy again \
                         once it passes a check"
                    ),
                }
            }
            inner.dirty = true;
        }
    }

    fn begin(&self, key: KeyId, ids: Vec<[u8; 32]>) {
        self.lock().in_flight.insert(key, (ids, false));
    }

    /// Records a finished check (`None`: inconclusive, the session
    /// closed). A device that fetched some of the asked objects from this
    /// one while the check ran may have relayed them, or may have been
    /// checking this device with the same objects at that moment: it is
    /// checked again half an interval later, and fails if it happens
    /// again.
    fn finish(&self, key: KeyId, started: u64, outcome: Option<Outcome>) {
        let mut inner = self.lock();
        let relayed = inner.in_flight.remove(&key).is_some_and(|(_, r)| r);
        let Some(mut outcome) = outcome else { return };
        let suspected = inner.recheck.remove(&key).is_some();
        if relayed && outcome == Outcome::Passed {
            if !suspected {
                let at = now_ms() + self.rules.interval_ms / 2;
                inner.recheck.insert(key, at);
                return;
            }
            outcome = Outcome::Failed(
                "answered checks with pieces it fetched from this device meanwhile".into(),
            );
        }
        inner
            .holders
            .entry(key)
            .or_default()
            .checked(started, outcome);
        inner.dirty = true;
    }
}

/// Which devices are meant to keep everything (placements of the files
/// space with full retention, of devices in effect), and this device's
/// own retention.
struct Plan {
    files: SpaceId,
    version: u64,
    view: View,
}

fn plan(d: &Daemon) -> Option<Plan> {
    let self_full = !d.config().on_demand();
    let me = d.keys.key();
    let core = d.core();
    let files = core.files_id()?;
    let version = core.spaces.get(&files)?.version;
    let st = core.identity.as_ref()?.state();
    let names = core.device_names();
    let acc = core.account()?.space.as_ref()?;
    let mut remote: Vec<(KeyId, [u8; 32])> = Vec::new();
    for rec in account::spaces(acc.state())
        .into_iter()
        .filter(|r| r.space == files)
    {
        for p in rec.placements {
            if p.device == me || !matches!(p.retention, Retention::Full | Retention::History) {
                continue;
            }
            let Some(x) = st
                .keys
                .get(&p.device)
                .and_then(|k| k.link_key.as_ref())
                .map(|l| *l.x25519())
            else {
                continue;
            };
            if !remote.iter().any(|(k, _)| *k == p.device) {
                remote.push((p.device, x));
            }
        }
    }
    Some(Plan {
        files,
        version,
        view: View {
            me,
            names,
            self_full,
            remote,
            eligible: 0,
            blobs: 0,
        },
    })
}

/// What one round of the check loop decided, from the blocking part.
struct Round {
    pool: Pool,
    rng: Rng,
    samples: Vec<(KeyId, Vec<[u8; 32]>)>,
    own: Option<Outcome>,
}

/// Starts checking copies.
pub fn start(d: Arc<Daemon>) {
    tokio::spawn(async move {
        let rules = d.copies.rules;
        let tick = Duration::from_millis((rules.interval_ms / 4).clamp(200, 15_000));
        let mut pool = Some(Pool::default());
        let mut rng = Some(Rng::new());
        let mut jitter: HashMap<KeyId, f64> = HashMap::new();
        let mut checks: tokio::task::JoinSet<(KeyId, u64, Option<Outcome>)> =
            tokio::task::JoinSet::new();
        let mut running: HashSet<KeyId> = HashSet::new();
        let mut own_due = 0u64;
        let mut stop = d.stopping.subscribe();
        let mut timer = tokio::time::interval(tick);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = timer.tick() => {}
                r = checks.join_next(), if !checks.is_empty() => {
                    if let Some(Ok((key, started, outcome))) = r {
                        running.remove(&key);
                        if let Some(r) = rng.as_mut() {
                            jitter.insert(key, 0.8 + 0.4 * r.unit());
                        }
                        if let Some(o) = &outcome {
                            tracing::debug!("copy check of {}: {o:?}", short(&key));
                        }
                        d.copies.finish(key, started, outcome);
                        d.copies.save();
                    }
                    continue;
                }
                _ = stop.changed() => {}
            }
            if *d.stopping.borrow() {
                break;
            }
            let Some(p) = plan(&d) else { continue };
            let now = now_ms();
            // Who is due.
            let sessions: HashMap<[u8; 32], cardinal_link::Session> = d
                .own_sessions()
                .into_iter()
                .map(|s| (s.peer_static(), s))
                .collect();
            let due: Vec<(KeyId, cardinal_link::Session)> = p
                .view
                .remote
                .iter()
                .filter(|(k, _)| !running.contains(k))
                .filter_map(|(k, x)| Some((*k, sessions.get(x)?.clone())))
                .filter(|(k, _)| {
                    let j = jitter.get(k).copied().unwrap_or(1.0);
                    now >= d.copies.next_check(k, j)
                })
                .collect();
            let own = p.view.self_full && now >= own_due;
            // The blocking part: the pool, samples, this device's check.
            let (Some(pl), Some(rg)) = (pool.take(), rng.take()) else {
                break;
            };
            let d2 = d.clone();
            let keys: Vec<KeyId> = due.iter().map(|(k, _)| *k).collect();
            let (files, version) = (p.files, p.version);
            let round = tokio::task::spawn_blocking(move || {
                let (mut pool, mut rng) = (pl, rg);
                if pool.version != Some((files, version)) {
                    let refs: Option<Vec<BlobRef>> = {
                        let core = d2.core();
                        core.spaces
                            .get(&files)
                            .and_then(|h| h.space.as_ref())
                            .map(|sp| {
                                crate::fetch::current_blobs(sp)
                                    .into_iter()
                                    .map(|(_, b)| b)
                                    .collect()
                            })
                    };
                    if let Some(refs) = refs {
                        pool.set_refs(refs, now, |id| born(&d2.store, id));
                        pool.version = Some((files, version));
                    }
                }
                pool.select(now, rules.min_age_ms);
                let get = |id: &[u8; 32]| d2.store.get(id).ok().flatten();
                let samples: Vec<(KeyId, Vec<[u8; 32]>)> = keys
                    .into_iter()
                    .map(|k| (k, pool.sample(rules.sample, &mut rng, get)))
                    .filter(|(_, s)| !s.is_empty())
                    .collect();
                let own = if own {
                    let ids = pool.sample(rules.sample, &mut rng, get);
                    if ids.is_empty() {
                        None
                    } else {
                        let reply = cardinal_sync::BlobRequest { ids: ids.clone() }.serve(get);
                        Some(judge(&ids, &reply, true))
                    }
                } else {
                    None
                };
                Round {
                    pool,
                    rng,
                    samples,
                    own,
                }
            })
            .await;
            let Ok(round) = round else {
                tracing::warn!("copy check round failed; starting over");
                pool = Some(Pool::default());
                rng = Some(Rng::new());
                continue;
            };
            let mut view = p.view;
            view.eligible = round.pool.eligible();
            view.blobs = round.pool.blobs();
            let me = view.me;
            d.copies.set_view(view);
            pool = Some(round.pool);
            rng = Some(round.rng);
            if let Some(o) = round.own {
                if let Outcome::Failed(why) = &o {
                    tracing::debug!("own copy check: {why}");
                }
                d.copies.finish(me, now, Some(o));
                own_due = now + rules.interval_ms;
            }
            // Ask the others, through the ordinary blob service.
            for (key, ids) in round.samples {
                let Some((_, s)) = due.iter().find(|(k, _)| *k == key) else {
                    continue;
                };
                let s = s.clone();
                running.insert(key);
                d.copies.begin(key, ids.clone());
                checks.spawn(async move {
                    let started = now_ms();
                    let outcome =
                        match crate::net::blob_request(&s, ids.clone(), Priority::Background).await
                        {
                            Ok(reply) => Some(judge(&ids, &reply, false)),
                            Err(_) if s.is_closed() => None,
                            Err(e) => {
                                Some(Outcome::Failed(format!("did not answer a check: {e:#}")))
                            }
                        };
                    (key, started, outcome)
                });
            }
            d.copies.save();
        }
        d.copies.save();
    });
}

/// The copy count for `cardinal status`: per device meant to keep
/// everything, whether it counts and why. `null` before the files space
/// is known.
pub fn status(d: &Daemon) -> Value {
    let names = d.core().device_names();
    let t = &d.copies;
    let rules = t.rules;
    let now = now_ms();
    let Some(view) = t.lock().view.clone() else {
        return Value::Null;
    };
    let online: Vec<bool> = view.remote.iter().map(|(_, x)| d.is_online(x)).collect();
    let name = |k: &KeyId| {
        names
            .get(k)
            .cloned()
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| account::short_key(k))
    };
    let inner = t.lock();
    let empty = Holder::default();
    let entry = |k: &KeyId, this: bool, online: bool| {
        let h = inner.holders.get(k).unwrap_or(&empty);
        let verdict = if this {
            h.own_verdict()
        } else {
            h.verdict(&rules, now)
        };
        let reason = match &verdict {
            Verdict::Counted { .. } => None,
            Verdict::Fetching { .. } => Some("fetching files from this device".to_owned()),
            Verdict::Repeated { .. } => Some(
                "fetched the same pieces of your files from this device again and again, so it \
                 is not keeping them"
                    .to_owned(),
            ),
            Verdict::Failed { reason, .. } => Some(reason.clone()),
            Verdict::Stale { .. } => Some("not checked recently".to_owned()),
            Verdict::Unchecked => Some("not checked yet".to_owned()),
        };
        json!({
            "name": name(k),
            "key": hex::encode(&k[..8]),
            "this": this,
            "online": online,
            "counted": verdict.counted(),
            "state": verdict.state(),
            "reason": reason,
            "checking": inner.in_flight.contains_key(k),
            "last_check": h.last_check,
            "last_pass": h.last_pass,
            "last_fail": h.last_fail,
            "fetched_at": h.fetched_at,
            "repeated_at": h.repeated_at,
        })
    };
    let mut list = Vec::new();
    if view.self_full {
        list.push(entry(&view.me, true, true));
    }
    for ((k, _), on) in view.remote.iter().zip(online) {
        list.push(entry(k, false, on));
    }
    drop(inner);
    let count = list.iter().filter(|e| e["counted"] == true).count();
    json!({
        "now": now,
        "count": count,
        "older_than_ms": rules.min_age_ms,
        "interval_ms": rules.interval_ms,
        "blobs": view.blobs,
        "eligible": view.eligible,
        "holders": list,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: u64 = 60_000;

    fn rules() -> Rules {
        Rules::default()
    }

    fn ids(range: std::ops::Range<u8>) -> Vec<[u8; 32]> {
        range.map(|i| [i; 32]).collect()
    }

    #[test]
    fn unchecked_then_passed_then_failed() {
        let r = rules();
        let mut h = Holder::default();
        assert_eq!(h.verdict(&r, 0), Verdict::Unchecked);
        h.checked(1000, Outcome::Passed);
        assert_eq!(h.verdict(&r, 2000), Verdict::Counted { checked: 1000 });
        h.checked(1000 + 10 * MIN, Outcome::Failed("did not answer".into()));
        assert!(matches!(
            h.verdict(&r, 1000 + 11 * MIN),
            Verdict::Failed { .. }
        ));
        // passing again counts again
        h.checked(1000 + 20 * MIN, Outcome::Passed);
        assert!(h.verdict(&r, 1000 + 21 * MIN).counted());
    }

    #[test]
    fn a_pass_counts_until_the_horizon() {
        let r = rules();
        let mut h = Holder::default();
        h.checked(0, Outcome::Passed);
        assert!(h.verdict(&r, r.horizon_ms).counted());
        assert_eq!(
            h.verdict(&r, r.horizon_ms + 1),
            Verdict::Stale { checked: 0 }
        );
    }

    #[test]
    fn checks_are_not_fetching() {
        // Another device checking this one asks for a few objects per
        // interval: that does not reset it.
        let r = rules();
        let mut h = Holder::default();
        h.checked(0, Outcome::Passed);
        let mut t = MIN;
        for _ in 0..20 {
            assert!(!h.served(&r, t, &ids(0..r.sample as u8)));
            t += r.interval_ms / 2; // two checks per interval, at worst
        }
        assert!(h.verdict(&r, t).counted());
        assert_eq!(h.fetched_at, None);
    }

    #[test]
    fn fetching_resets_until_a_check_after_the_wait() {
        let r = rules();
        let mut h = Holder::default();
        h.checked(0, Outcome::Passed);
        let t = 5 * MIN;
        assert!(h.served(&r, t, &ids(0..16)));
        assert_eq!(h.verdict(&r, t), Verdict::Fetching { last: t });
        // a check before the wait is over does not count it again
        h.checked(t + r.interval_ms, Outcome::Passed);
        assert_eq!(
            h.verdict(&r, t + r.interval_ms + 1),
            Verdict::Fetching { last: t }
        );
        // the next check is due only after the wait
        assert!(h.next_check(&r, 1.0) > t + r.wait_ms());
        // one after the wait does
        h.checked(t + r.wait_ms(), Outcome::Passed);
        assert!(h.verdict(&r, t + r.wait_ms() + 1).counted());
        // but a failed check after the wait does not
        let mut g = Holder::default();
        g.served(&r, t, &ids(0..16));
        g.checked(
            t + r.wait_ms(),
            Outcome::Failed("did not have 4 of 4".into()),
        );
        assert!(matches!(
            g.verdict(&r, t + r.wait_ms() + 1),
            Verdict::Failed { .. }
        ));
    }

    #[test]
    fn small_fetches_add_up() {
        let r = rules();
        let mut h = Holder::default();
        // a check's worth, then a few more objects within the interval
        assert!(!h.served(&r, 0, &ids(0..4)));
        assert!(!h.served(&r, 1000, &ids(4..8)));
        assert!(h.served(&r, 2000, &ids(8..12)));
        assert_eq!(h.fetched_at, Some(2000));
        // what was sent an interval ago no longer adds up
        let mut g = Holder::default();
        assert!(!g.served(&r, 0, &ids(0..8)));
        assert!(!g.served(&r, r.interval_ms, &ids(8..16)));
    }

    #[test]
    fn repeated_fetches_stop_counting() {
        let r = rules();
        let mut h = Holder::default();
        let batch = ids(0..16);
        // a rebuild fetches each object once; retries soon after are the
        // same fetch
        h.served(&r, 0, &batch);
        h.served(&r, 20_000, &batch);
        let t1 = 20_000 + r.wait_ms();
        h.checked(t1, Outcome::Passed);
        assert!(h.verdict(&r, t1 + 1).counted());
        assert_eq!(h.repeated_at, None);
        // fetched again later: a second fetch, still not "again and again"
        let t2 = t1 + r.repeat_gap_ms();
        h.served(&r, t2, &batch);
        assert_eq!(h.repeated_at, None);
        // and a third time: it is not keeping them
        let t3 = t2 + r.repeat_gap_ms();
        h.served(&r, t3, &batch);
        assert_eq!(h.repeated_at, Some(t3));
        assert_eq!(h.verdict(&r, t3), Verdict::Repeated { at: t3 });
        // passing checks soon after does not count it again
        h.checked(t3 + r.wait_ms(), Outcome::Passed);
        assert_eq!(
            h.verdict(&r, t3 + r.wait_ms() + 1),
            Verdict::Repeated { at: t3 }
        );
        // after the hold, a passing check does
        let t4 = t3 + r.repeat_hold_ms();
        h.checked(t4, Outcome::Passed);
        assert!(h.verdict(&r, t4 + 1).counted());
    }

    #[test]
    fn serving_resets_and_relays_are_caught() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsStore::open(dir.path().join("blobs"), cardinal_blob::Fsync::Never).unwrap();
        let r = Rules {
            min_age_ms: 0,
            ..Rules::default()
        };
        let t = Tracker::load(dir.path().join("copies.json"), r);
        let (k, link) = ([1u8; 32], [2u8; 32]);
        t.set_view(View {
            me: [9; 32],
            names: HashMap::new(),
            self_full: true,
            remote: vec![(k, link)],
            eligible: 0,
            blobs: 0,
        });
        let objects: Vec<Vec<u8>> = (0..20u8).map(|i| vec![i; 100]).collect();
        let ids: Vec<[u8; 32]> = objects
            .iter()
            .map(|o| {
                let id = *blake3::hash(o).as_bytes();
                store.put(&id, o).unwrap();
                id
            })
            .collect();
        let reply = |n: std::ops::Range<usize>| BlobReply {
            items: n
                .map(|i| BlobItem::Held {
                    id: ids[i],
                    ciphertext: objects[i].clone(),
                })
                .collect(),
        };
        // A device that is not meant to keep everything is not tracked.
        t.observe_serve(&[7; 32], &reply(0..20), &store);
        assert!(t.lock().holders.is_empty());
        // During a check of k, k fetches one of the objects asked for: the
        // check is not taken, k is asked again later...
        t.begin(k, vec![ids[0], ids[1]]);
        t.observe_serve(&link, &reply(0..1), &store);
        t.finish(k, 100, Some(Outcome::Passed));
        assert_eq!(t.lock().holders[&k].last_check, None);
        assert!(t.next_check(&k, 1.0) > 0);
        // ...and when it happens again, it fails.
        t.begin(k, vec![ids[2], ids[3]]);
        t.observe_serve(&link, &reply(2..3), &store);
        t.finish(k, 200, Some(Outcome::Passed));
        assert!(matches!(
            t.lock().holders[&k].verdict(&r, 300),
            Verdict::Failed { .. }
        ));
        // Fetching many objects resets it; the results survive a restart.
        t.observe_serve(&link, &reply(0..20), &store);
        assert!(t.lock().holders[&k].fetched_at.is_some());
        t.save();
        let again = Tracker::load(dir.path().join("copies.json"), r);
        assert!(again.lock().holders[&k].fetched_at.is_some());
        assert_eq!(again.lock().holders[&k].last_fail, Some(200));
    }

    #[test]
    fn own_verdict() {
        let mut h = Holder::default();
        assert!(h.own_verdict().counted());
        h.checked(10, Outcome::Failed("missing 1 of the 4 pieces".into()));
        assert!(!h.own_verdict().counted());
        h.checked(20, Outcome::Passed);
        assert!(h.own_verdict().counted());
    }

    #[test]
    fn persisted_results_round_trip() {
        let mut h = Holder::default();
        h.checked(5, Outcome::Passed);
        h.served(&rules(), 7, &ids(0..20));
        let s = serde_json::to_string(&h).unwrap();
        let back: Holder = serde_json::from_str(&s).unwrap();
        assert_eq!(back.last_pass, Some(5));
        assert_eq!(back.fetched_at, Some(7));
        assert_eq!(
            back.verdict(&rules(), 8),
            h.verdict(&rules(), 8),
            "the verdict survives a restart"
        );
    }

    fn blob(i: u8, size: u64) -> BlobRef {
        BlobRef {
            id: [i; 32],
            key: [0; 32],
            size,
            levels: 0,
        }
    }

    #[test]
    fn sampling_window() {
        let mut p = Pool::default();
        let now = 10 * 3_600_000;
        // blob 1 was stored here two hours ago, blob 2 ten minutes ago,
        // blob 3 is not held (first seen now)
        let born = |id: &[u8; 32]| match id[0] {
            1 => Some(now - 2 * 3_600_000),
            2 => Some(now - 10 * MIN),
            _ => None,
        };
        p.set_refs(vec![blob(1, 5000), blob(2, 5000), blob(3, 5000)], now, born);
        p.select(now, 3_600_000);
        assert_eq!((p.blobs(), p.eligible()), (3, 1));
        let mut rng = Rng::seeded(1);
        let s = p.sample(4, &mut rng, |_| None);
        assert_eq!(s, vec![[1; 32]], "only content older than an hour");
        // an hour later the others are old enough too; blob 3 counts from
        // when this run first saw it, even once fetched since
        let later = now + 3_600_000;
        p.set_refs(
            vec![blob(1, 5000), blob(2, 5000), blob(3, 5000)],
            later,
            |_| Some(later),
        );
        p.select(later, 3_600_000);
        assert_eq!(p.eligible(), 3);
        let mut s = p.sample(3, &mut rng, |_| None);
        s.sort();
        assert_eq!(s, vec![[1; 32], [2; 32], [3; 32]]);
    }

    #[test]
    fn sampling_descends_into_indexes() {
        use cardinal_blob::{encode_bytes, ConvergenceSecret, MemStore};
        let store = MemStore::new();
        let secret = ConvergenceSecret::from_epoch_key(&[7u8; 32]);
        let mut data = Vec::new();
        let mut x: u64 = 1;
        while data.len() < 3 << 20 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            data.extend_from_slice(&x.to_le_bytes());
        }
        let r = encode_bytes(&data, &secret, &store).unwrap();
        assert!(r.levels > 0);
        let mut p = Pool::default();
        p.set_refs(vec![r], 0, |_| Some(0));
        p.select(3_600_000, 3_600_000);
        let mut rng = Rng::seeded(7);
        let get = |id: &[u8; 32]| store.get(id).ok().flatten();
        let s = p.sample(4, &mut rng, get);
        assert_eq!(s.len(), 4);
        assert!(s.iter().all(|id| store.has(id).unwrap()));
        assert!(s.iter().any(|id| *id != r.id), "chunks, not only the top");
        // without the indexes, only the top can be asked
        let s = p.sample(4, &mut rng, |_| None);
        assert_eq!(s, vec![r.id]);
    }

    #[test]
    fn judging_replies() {
        let good = b"chunk".to_vec();
        let id = *blake3::hash(&good).as_bytes();
        let other = [9u8; 32];
        let reply = BlobReply {
            items: vec![
                BlobItem::Held {
                    id,
                    ciphertext: good.clone(),
                },
                BlobItem::NotHeld(other),
            ],
        };
        assert_eq!(judge(&[id], &reply, false), Outcome::Passed);
        assert_eq!(
            judge(&[id, other], &reply, false),
            Outcome::Failed("did not have 1 of the 2 pieces of your files asked for".into())
        );
        let bad = BlobReply {
            items: vec![BlobItem::Held {
                id,
                ciphertext: b"other".to_vec(),
            }],
        };
        assert_eq!(
            judge(&[id], &bad, false),
            Outcome::Failed("sent 1 of the 1 pieces damaged".into())
        );
    }
}
