//! Counting copies of the files space by what was seen
//! (`blobs.md#counting-copies`, decisions D45 and D46).
//!
//! The account space says which devices are meant to keep everything:
//! placements of the files space with full retention. That is intent.
//! What this module counts is evidence, from spot checks that trust what
//! comes back:
//!
//! - **Checks.** About every 10 minutes, each online device meant to keep
//!   everything is asked for a few objects (chunks or indexes) chosen at
//!   random among all current content, through the ordinary `blob`
//!   service, the same request a fetch sends. The answers are verified by
//!   hash and dropped.
//! - **A piece produced counts for its holder at once, whatever its age.**
//!   A piece "not held" counts against it only where this device has had
//!   the content for an hour: a device still copying new files is not
//!   failing. So the count is of copies of everything older than an hour.
//! - **Only a missing or damaged piece fails.** A device that answers
//!   "not held" for such a piece, or sends one that does not hash to its
//!   id, stops counting until it passes a check. Silence or slowness is
//!   never a failure (`blobs.md#counting-copies`): one that does not
//!   answer within what it is expected to take
//!   ([`crate::sched::PeerStats::expect`], learned from its replies, and
//!   patient with one not measured) has not confirmed anything since, and
//!   is asked again at its next check. A pass within the horizon (7 days)
//!   keeps it counted meanwhile, as it keeps a device offline counted;
//!   past that, or with no pass, it is unconfirmed rather than failed or
//!   missing pieces. The count is for the person: dropping a chunk asks a
//!   holder afresh (`cleanup.rs`, lock, check, delete). What devices fetch is not
//!   watched: one rebuilding after a lost disk fails checks while pieces
//!   are missing and passes once it has them again.
//! - **Still copying, or missing pieces.** A device that has never passed
//!   a check is still copying, and is said to be; one that passed and now
//!   does not is missing pieces.
//!
//! This device counts itself when it keeps everything, unless its own
//! check (a sample drawn the same way, read from its store) found pieces
//! missing.
//!
//! The rules are pure functions of time ([`Holder`]); [`start`] runs the
//! checks. Results are kept in `copies.json`, so a restart does not forget
//! a device that passed checks and is offline now.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use cardinal_blob::{decrypt, BlobRef, FsStore, Index, ObjectStore};
use cardinal_identity::KeyId;
use cardinal_link::Priority;
use cardinal_space::account;
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
    /// Content this device first saw less than this long ago is asked
    /// for like any other, and a holder that does not have it yet is not
    /// failing: an hour.
    pub min_age_ms: u64,
    /// Objects asked for per check.
    pub sample: usize,
    /// How long a passed check keeps a device counted that has not been
    /// checked since, or has left checks unanswered since, as one offline
    /// does: 7 days. For what the person is shown only.
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
}

/// Average chunk size, to weigh blobs by their number of chunks.
const AVG_CHUNK: u64 = 64 * 1024;

/// How a check ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Every object came back and hashed to its id.
    Passed,
    /// Something was missing or wrong, in plain words.
    Failed(String),
    /// Nothing was wrong, and it does not have yet what this device has
    /// had for less than the minimum age: it is still copying. Neither a
    /// pass nor a failure.
    Copying(String),
    /// No answer in the time its device is expected to take, or the
    /// service failed, in plain words: nothing confirmed, nothing failed.
    Unanswered(String),
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
    /// Checks it left unanswered since it last answered one.
    pub missed: u8,
    /// Why the last one went unanswered.
    pub silent: Option<String>,
    /// When the last check it answered started, pass or not.
    pub last_answer: Option<u64>,
    /// Whether the last failure was for not answering, as an earlier build
    /// counted silence: such a failure is not one now.
    pub unanswered: bool,
}

/// Whether a device counts as a copy now, and if not, why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Counted: it passed the check that started at `checked`.
    Counted {
        /// When.
        checked: u64,
    },
    /// It did not answer its last check: it has not confirmed anything,
    /// so it does not count, but it has not failed either.
    Unconfirmed {
        /// Why, in plain words.
        reason: String,
    },
    /// It passed a check once, and its last one found pieces missing or
    /// damaged.
    Missing {
        /// When the check started.
        at: u64,
        /// Why.
        reason: String,
    },
    /// It has answered and never yet passed: it is still copying.
    Copying {
        /// What the last check found.
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
            Verdict::Unconfirmed { .. } => "unconfirmed",
            Verdict::Missing { .. } => "missing",
            Verdict::Copying { .. } => "copying",
            Verdict::Stale { .. } => "stale",
            Verdict::Unchecked => "unchecked",
        }
    }
}

impl Holder {
    /// Records a check that started at `started`. An unanswered check
    /// confirms nothing and fails nothing.
    pub fn checked(&mut self, started: u64, outcome: Outcome) {
        self.last_check = Some(self.last_check.map_or(started, |t| t.max(started)));
        if !matches!(outcome, Outcome::Unanswered(_)) {
            self.last_answer = Some(started);
            self.missed = 0;
            self.silent = None;
        }
        match outcome {
            Outcome::Passed => self.last_pass = Some(started),
            Outcome::Failed(why) => self.fail(started, why, false),
            // It stands as it stood: a pass still counts, and a failure
            // is not mended by what it does not have yet.
            Outcome::Copying(_) => {}
            Outcome::Unanswered(why) => {
                self.missed = self.missed.saturating_add(1);
                self.silent = Some(why);
            }
        }
    }

    fn fail(&mut self, started: u64, why: String, unanswered: bool) {
        self.last_fail = Some(started);
        self.fail_reason = Some(why);
        self.unanswered = unanswered;
    }

    /// Its last failure, if it stands: not one for silence an earlier
    /// build recorded.
    fn failed_at(&self) -> Option<u64> {
        self.last_fail.filter(|_| !self.unanswered)
    }

    /// What a check that did not pass makes of a device: one that has
    /// passed before is missing pieces; one that never has is still
    /// copying (`blobs.md#counting-copies`).
    fn failing(&self, at: u64) -> Verdict {
        let reason = self.fail_reason.clone();
        let reason = reason.unwrap_or_else(|| "failed a check".into());
        match self.last_pass {
            Some(_) => Verdict::Missing { at, reason },
            None => Verdict::Copying { reason },
        }
    }

    /// Whether it counts now, for what the person is shown: a pass
    /// within the horizon counts though a check since went unanswered, as
    /// one does when its device goes offline. Dropping a chunk never goes
    /// by this: it asks a holder afresh (`blobs.md#dropping-a-chunk`).
    pub fn verdict(&self, r: &Rules, now: u64) -> Verdict {
        let standing_fail = self
            .failed_at()
            .filter(|f| self.last_pass.is_none_or(|p| p <= *f));
        // Silent at its last check: nothing confirmed since, but a pass
        // within the horizon, with no failure after it, still counts.
        if self.missed > 0 {
            if let Some(p) = self
                .last_pass
                .filter(|p| standing_fail.is_none() && now.saturating_sub(*p) <= r.horizon_ms)
            {
                return Verdict::Counted { checked: p };
            }
            let why = self.silent.as_deref().unwrap_or("no answer");
            let reason = match self.missed {
                1 => format!("did not answer its last check ({why})"),
                n => format!("did not answer its last {n} checks ({why})"),
            };
            return Verdict::Unconfirmed { reason };
        }
        // The last check failed (and nothing passed since).
        if let Some(f) = standing_fail {
            return self.failing(f);
        }
        match self.last_pass {
            Some(p) if now.saturating_sub(p) <= r.horizon_ms => Verdict::Counted { checked: p },
            Some(p) => Verdict::Stale { checked: p },
            // answered, with nothing wrong and nothing to count yet
            None if self.last_answer.is_some() => Verdict::Copying {
                reason: "does not have the newest of your files yet".into(),
            },
            None => Verdict::Unchecked,
        }
    }

    /// This device's own standing: it keeps everything, so it counts
    /// unless its latest own check found something missing.
    pub fn own_verdict(&self) -> Verdict {
        match (self.failed_at(), self.last_pass) {
            (Some(f), p) if p.is_none_or(|p| p < f) => self.failing(f),
            (_, p) => Verdict::Counted {
                checked: p.unwrap_or(0),
            },
        }
    }

    /// When it should be checked next. `jitter` (about 0.8 to 1.2)
    /// spreads checks out.
    pub fn next_check(&self, r: &Rules, jitter: f64) -> u64 {
        self.last_check
            .map_or(0, |t| t + (r.interval_ms as f64 * jitter) as u64)
    }
}

/// An object a check asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Asked {
    /// Its id.
    pub id: [u8; 32],
    /// Whether this device has had its content for the minimum age: only
    /// then does a holder that lacks it fail.
    pub old: bool,
}

/// Judges a reply to a check of `asked`. `local` words it for this
/// device's own store.
///
/// A piece produced counts for the holder whatever its age. One "not
/// held" counts against it only if it is old; a damaged one always does.
/// With nothing against it, it passes if every old piece asked for came,
/// or, where none was old, every piece did. Otherwise it is still
/// copying: it has produced nothing wrong and lacks only what is new.
pub fn judge(asked: &[Asked], reply: &BlobReply, local: bool) -> Outcome {
    let (mut missing, mut damaged, mut not_yet, mut produced) = (0, 0, 0, 0);
    for a in asked {
        let item = reply.items.iter().find(|i| match i {
            BlobItem::Held { id: x, .. } | BlobItem::NotHeld(x) => *x == a.id,
        });
        match item {
            Some(BlobItem::Held { ciphertext, .. })
                if *blake3::hash(ciphertext).as_bytes() == a.id =>
            {
                produced += 1
            }
            Some(BlobItem::Held { .. }) => damaged += 1,
            _ if a.old => missing += 1,
            _ => not_yet += 1,
        }
    }
    let n = asked.len();
    if missing == 0 && damaged == 0 {
        let old = asked.iter().filter(|a| a.old).count();
        return match not_yet == 0 || (old > 0 && produced > 0) {
            true => Outcome::Passed,
            false => Outcome::Copying(if local {
                format!("{not_yet} of the {n} pieces checked are of new files not here yet")
            } else {
                format!("does not have {not_yet} of the {n} pieces asked for yet, of new files")
            }),
        };
    }
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

/// What can be checked: every blob of the current files state, each
/// with whether this device first saw it long enough ago for a holder
/// that lacks it to fail.
#[derive(Default)]
pub struct Pool {
    version: Option<(SpaceId, u64)>,
    refs: Vec<BlobRef>,
    /// Top id -> when first seen here: the top object's birth here, or
    /// when this run first saw the reference.
    first_seen: HashMap<[u8; 32], u64>,
    /// Cumulative weight (about the chunk count), index into `refs`, and
    /// whether the blob is old enough.
    weighed: Vec<(u64, usize, bool)>,
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

    /// Weighs every blob for sampling, and notes which are old enough
    /// that a holder without them fails.
    pub fn select(&mut self, now: u64, min_age: u64) {
        self.weighed.clear();
        let mut total = 0u64;
        for (i, r) in self.refs.iter().enumerate() {
            let first = self.first_seen.get(&r.id);
            let old = first.is_some_and(|t| now.saturating_sub(*t) >= min_age);
            total += 1 + r.size / AVG_CHUNK;
            self.weighed.push((total, i, old));
        }
    }

    /// Blobs in the current state.
    pub fn blobs(&self) -> usize {
        self.refs.len()
    }

    /// Blobs old enough that a holder without them fails.
    pub fn eligible(&self) -> usize {
        self.weighed.iter().filter(|(_, _, old)| *old).count()
    }

    /// Up to `n` distinct objects at random, about uniformly over the
    /// chunks of all current blobs, each with whether its blob is old
    /// enough. Indexes this device holds are descended through `get`;
    /// where it holds none, the blob's top id is asked.
    pub fn sample(
        &self,
        n: usize,
        rng: &mut Rng,
        get: impl Fn(&[u8; 32]) -> Option<Vec<u8>>,
    ) -> Vec<Asked> {
        let Some(&(total, ..)) = self.weighed.last() else {
            return Vec::new();
        };
        let mut out: Vec<Asked> = Vec::new();
        for _ in 0..n * 4 {
            if out.len() >= n {
                break;
            }
            let x = rng.below(total);
            let pos = self.weighed.partition_point(|(c, ..)| *c <= x);
            let (_, at, old) = self.weighed[pos.min(self.weighed.len() - 1)];
            let id = pick(&self.refs[at], rng, &get);
            match out.iter_mut().find(|a| a.id == id) {
                // the same content in an old file and a new one is old
                Some(a) => a.old |= old,
                None => out.push(Asked { id, old }),
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
    /// Devices with a check under way.
    checking: HashSet<KeyId>,
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
        self.lock()
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
        self.lock().view = Some(v);
    }

    fn begin(&self, key: KeyId) {
        self.lock().checking.insert(key);
    }

    /// Records a finished check (`None`: inconclusive, the session
    /// closed). Logs when a device stops or starts counting.
    fn finish(&self, key: KeyId, started: u64, outcome: Option<Outcome>) {
        let name = self.name(&key);
        let (rules, now) = (self.rules, now_ms());
        let mut inner = self.lock();
        inner.checking.remove(&key);
        let Some(outcome) = outcome else { return };
        let me = inner.view.as_ref().is_some_and(|v| v.me == key);
        let h = inner.holders.entry(key).or_default();
        let verdict = |h: &Holder| {
            if me {
                h.own_verdict()
            } else {
                h.verdict(&rules, now)
            }
        };
        let before = verdict(h).counted();
        h.checked(started, outcome);
        match (before, verdict(h)) {
            (true, Verdict::Unconfirmed { reason } | Verdict::Missing { reason, .. }) => {
                tracing::warn!("not counting {name} as a copy of your files: {reason}")
            }
            (false, v) if v.counted() => tracing::info!("{name} counts as a copy of your files"),
            _ => {}
        }
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
            if p.device == me || !p.retention.keeps_all_current() {
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

/// Sessions open now with this person's devices that the account space says
/// keep the files space in full.
pub(crate) fn full_holder_sessions(d: &Daemon) -> Vec<cardinal_link::Session> {
    let Some(p) = plan(d) else {
        return Vec::new();
    };
    let sessions: HashMap<[u8; 32], cardinal_link::Session> = d
        .own_sessions()
        .into_iter()
        .map(|s| (s.peer_static(), s))
        .collect();
    p.view
        .remote
        .iter()
        .filter_map(|(_, x)| sessions.get(x).cloned())
        .collect()
}

/// What one round of the check loop decided, from the blocking part.
struct Round {
    pool: Pool,
    rng: Rng,
    samples: Vec<(KeyId, Vec<Asked>)>,
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
                            // what the folder shows, and whatever else
                            // current state references
                            .map(crate::fetch::current_refs)
                    };
                    if let Some(refs) = refs {
                        pool.set_refs(refs, now, |id| born(&d2.store, id));
                        pool.version = Some((files, version));
                    }
                }
                pool.select(now, rules.min_age_ms);
                let get = |id: &[u8; 32]| d2.store.get(id).ok().flatten();
                let samples: Vec<(KeyId, Vec<Asked>)> = keys
                    .into_iter()
                    .map(|k| (k, pool.sample(rules.sample, &mut rng, get)))
                    .filter(|(_, s)| !s.is_empty())
                    .collect();
                let own = if own {
                    let asked = pool.sample(rules.sample, &mut rng, get);
                    if asked.is_empty() {
                        None
                    } else {
                        let ids = asked.iter().map(|a| a.id).collect();
                        let reply = cardinal_sync::BlobRequest { ids }.serve(get);
                        Some(judge(&asked, &reply, true))
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
            for (key, asked) in round.samples {
                let Some((_, s)) = due.iter().find(|(k, _)| *k == key) else {
                    continue;
                };
                let s = s.clone();
                running.insert(key);
                d.copies.begin(key);
                // As long as this device is expected to take, from what it
                // has shown, patient where nothing was measured.
                let within = d
                    .blob_stats
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .get(&s.peer_static())
                    .copied()
                    .unwrap_or_default()
                    .expect(asked.len());
                checks.spawn(async move {
                    let started = now_ms();
                    let ids: Vec<[u8; 32]> = asked.iter().map(|a| a.id).collect();
                    let asking = crate::net::blob_request(&s, ids, Priority::Background);
                    let outcome = match tokio::time::timeout(within, asking).await {
                        Ok(Ok(reply)) => Some(judge(&asked, &reply, false)),
                        Ok(Err(_)) | Err(_) if s.is_closed() => None,
                        Ok(Err(e)) => Some(Outcome::Unanswered(format!("{e:#}"))),
                        Err(_) => Some(Outcome::Unanswered(format!(
                            "not within {:.0} s, what it is expected to take",
                            within.as_secs_f64()
                        ))),
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
            Verdict::Unconfirmed { reason }
            | Verdict::Missing { reason, .. }
            | Verdict::Copying { reason } => Some(reason.clone()),
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
            "checking": inner.checking.contains(k),
            "last_check": h.last_check,
            "last_pass": h.last_pass,
            "last_fail": h.last_fail,
            "missed": h.missed,
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

    #[test]
    fn unchecked_then_passed_then_missing() {
        let r = rules();
        let mut h = Holder::default();
        assert_eq!(h.verdict(&r, 0), Verdict::Unchecked);
        h.checked(1000, Outcome::Passed);
        assert_eq!(h.verdict(&r, 2000), Verdict::Counted { checked: 1000 });
        h.checked(1000 + 10 * MIN, Outcome::Failed("did not answer".into()));
        assert!(matches!(
            h.verdict(&r, 1000 + 11 * MIN),
            Verdict::Missing { .. }
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
    fn silence_confirms_nothing_and_fails_nothing() {
        let r = rules();
        let mut h = Holder::default();
        h.checked(0, Outcome::Passed);
        let silent = || Outcome::Unanswered("not within 4 s".into());
        // Silent: neither failed nor missing pieces, and asked again an
        // interval later. Its pass, within the horizon, still counts, as
        // it does for a device gone offline.
        h.checked(10 * MIN, silent());
        let v = h.verdict(&r, 10 * MIN + 1);
        assert_eq!(v, Verdict::Counted { checked: 0 });
        assert_eq!(h.next_check(&r, 1.0), 10 * MIN + r.interval_ms);
        for i in 2..30 {
            h.checked(i * 10 * MIN, silent());
            assert!(h.verdict(&r, i * 10 * MIN + 1).counted());
        }
        // Past the horizon it is unconfirmed, however long it stays silent.
        let late = r.horizon_ms + 1;
        h.checked(late, silent());
        let v = h.verdict(&r, late + 1);
        assert!(!v.counted());
        assert_eq!(v.state(), "unconfirmed");
        assert!(matches!(
            v,
            Verdict::Unconfirmed { reason } if reason.starts_with("did not answer its last 30 checks")
        ));
        // With no pass, silence confirms nothing.
        let mut never = Holder::default();
        never.checked(0, silent());
        assert_eq!(
            never.verdict(&r, 1),
            Verdict::Unconfirmed {
                reason: "did not answer its last check (not within 4 s)".into()
            }
        );
        assert!(h.last_fail.is_none());
        // An answer stands as it says.
        let t = late + 400 * MIN;
        h.checked(t, Outcome::Passed);
        assert!(h.verdict(&r, t + 1).counted());
        assert_eq!(h.missed, 0);
        // Only "not held" counts against it, and silence after it does
        // not bring back the count.
        h.checked(t + 10 * MIN, silent());
        h.checked(
            t + 20 * MIN,
            Outcome::Failed("did not have 1 of the 4 pieces".into()),
        );
        assert_eq!(h.verdict(&r, t + 20 * MIN + 1).state(), "missing");
        h.checked(t + 30 * MIN, silent());
        assert!(!h.verdict(&r, t + 30 * MIN + 1).counted());
        // What an earlier build saved of failing for silence is no failure.
        let saved = r#"{"last_check": 9, "last_pass": 5, "last_fail": 9,
            "fail_reason": "did not answer 2 checks in a row", "missed": 0,
            "unanswered": true}"#;
        let old: Holder = serde_json::from_str(saved).unwrap();
        assert!(old.verdict(&r, 10).counted());
    }

    #[test]
    fn a_rebuild_fails_while_pieces_are_missing() {
        // A device that lost its disk fetches everything again; nothing
        // is declared and fetching is not held against it.
        let r = rules();
        let mut h = Holder::default();
        h.checked(0, Outcome::Passed);
        let missing =
            Outcome::Failed("did not have 3 of the 4 pieces of your files asked for".into());
        h.checked(10 * MIN, missing);
        assert!(!h.verdict(&r, 10 * MIN + 1).counted());
        h.checked(20 * MIN, Outcome::Passed);
        assert_eq!(
            h.verdict(&r, 20 * MIN + 1),
            Verdict::Counted { checked: 20 * MIN }
        );
    }

    #[test]
    fn results_survive_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("copies.json");
        let r = rules();
        let t = Tracker::load(path.clone(), r);
        let k = [1u8; 32];
        t.begin(k);
        assert!(t.lock().checking.contains(&k));
        t.finish(k, 100, Some(Outcome::Passed));
        t.finish(k, 200, Some(Outcome::Unanswered("timed out".into())));
        // a closed session is not a check
        t.finish(k, 300, None);
        assert!(t.lock().checking.is_empty());
        t.save();
        let again = Tracker::load(path.clone(), r);
        let h = again.lock().holders[&k].clone();
        assert_eq!(
            (h.last_check, h.last_pass, h.missed),
            (Some(200), Some(100), 1)
        );
        again.finish(k, 400, Some(Outcome::Unanswered("timed out".into())));
        // its pass is within the horizon: it counts for the person still
        assert!(again.lock().holders[&k].verdict(&r, 500).counted());
        assert_eq!(again.lock().holders[&k].missed, 2);
        let past = r.horizon_ms + 101;
        assert!(!again.lock().holders[&k].verdict(&r, past).counted());
        // a file written by an earlier build, with fields no longer used
        std::fs::write(
            &path,
            format!(
                r#"{{"holders": {{"{}": {{"last_check": 5, "last_pass": 5,
                    "fetched_at": 7, "repeated_at": 9}}}}}}"#,
                hex::encode(k)
            ),
        )
        .unwrap();
        let old = Tracker::load(path, r);
        assert_eq!(
            old.lock().holders[&k].verdict(&r, 10),
            Verdict::Counted { checked: 5 }
        );
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

    fn blob(i: u8, size: u64) -> BlobRef {
        BlobRef {
            id: [i; 32],
            key: [0; 32],
            size,
            levels: 0,
        }
    }

    /// `blobs.md#counting-copies`: the sample is drawn from all current
    /// content, whatever its age, and says of each piece whether this
    /// device has had it for the minimum age.
    #[test]
    fn everything_current_is_sampled_and_its_age_noted() {
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
        let mut s = p.sample(3, &mut rng, |_| None);
        s.sort_by_key(|a| a.id);
        let asked = |n: u8, old: bool| Asked { id: [n; 32], old };
        assert_eq!(
            s,
            [asked(1, true), asked(2, false), asked(3, false)],
            "new content is left out, or taken for old"
        );
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
        s.sort_by_key(|a| a.id);
        assert_eq!(s, [asked(1, true), asked(2, true), asked(3, true)]);
    }

    /// A piece produced counts for its holder at once, whatever its age;
    /// "not held" counts against it only for what this device has had
    /// for the minimum age; a damaged piece always does.
    #[test]
    fn a_piece_not_held_fails_only_if_it_is_old() {
        let piece = |n: u8| {
            let bytes = vec![n; 9];
            (*blake3::hash(&bytes).as_bytes(), bytes)
        };
        let ((a, a_bytes), (b, b_bytes), (c, _)) = (piece(1), piece(2), piece(3));
        let held = |id, ciphertext: &Vec<u8>| BlobItem::Held {
            id,
            ciphertext: ciphertext.clone(),
        };
        let asked = |id, old| Asked { id, old };
        let reply = |items| BlobReply { items };
        // New content it has already: a pass, at once.
        let both = reply(vec![held(a, &a_bytes), held(b, &b_bytes)]);
        let new = [asked(a, false), asked(b, false)];
        assert_eq!(judge(&new, &both, false), Outcome::Passed);
        // New content it does not have yet: no pass, and no failure.
        let none = reply(vec![BlobItem::NotHeld(a), BlobItem::NotHeld(b)]);
        let copying = judge(&new, &none, false);
        assert!(matches!(copying, Outcome::Copying(_)), "{copying:?}");
        let some = reply(vec![held(a, &a_bytes), BlobItem::NotHeld(b)]);
        let copying = judge(&new, &some, false);
        assert!(matches!(copying, Outcome::Copying(_)), "{copying:?}");
        // The old piece it has and a new one it has not: everything
        // older than the minimum age is there, which is what is counted.
        let mixed = [asked(a, true), asked(b, false)];
        assert_eq!(judge(&mixed, &some, false), Outcome::Passed);
        // An old piece it does not have fails, whatever else it has.
        let old = [asked(a, false), asked(b, true)];
        assert_eq!(
            judge(&old, &some, false),
            Outcome::Failed("did not have 1 of the 2 pieces of your files asked for".into())
        );
        // No word of a piece is "not held".
        let silent = [asked(a, false), asked(c, true)];
        assert!(matches!(judge(&silent, &some, false), Outcome::Failed(_)));
        // A damaged piece fails at any age.
        let bad = reply(vec![held(a, &b_bytes)]);
        assert_eq!(
            judge(&[asked(a, false)], &bad, false),
            Outcome::Failed("sent 1 of the 1 pieces damaged".into())
        );
    }

    /// A holder that has never passed is still copying; one that passed
    /// and now misses pieces is missing them; one that does not answer is
    /// unconfirmed. None of them counts.
    #[test]
    fn still_copying_is_told_from_missing_pieces() {
        let r = rules();
        let missing = || Outcome::Failed("did not have 2 of the 4 pieces".into());
        let not_yet = || Outcome::Copying("does not have 4 of the 4 pieces yet".into());
        let state = |h: &Holder, now| h.verdict(&r, now).state();
        // Never passed.
        let mut h = Holder::default();
        assert_eq!(state(&h, 0), "unchecked");
        h.checked(MIN, not_yet());
        assert_eq!(state(&h, 2 * MIN), "copying");
        h.checked(10 * MIN, missing());
        assert_eq!(state(&h, 11 * MIN), "copying");
        assert!(!h.verdict(&r, 11 * MIN).counted());
        // new content it lacks does not mend that, and a pass does
        h.checked(20 * MIN, not_yet());
        assert_eq!(state(&h, 21 * MIN), "copying");
        h.checked(30 * MIN, Outcome::Passed);
        assert_eq!(state(&h, 31 * MIN), "passed");
        // Passed, and new content it does not have yet: it still counts.
        h.checked(40 * MIN, not_yet());
        assert!(h.verdict(&r, 41 * MIN).counted());
        // Passed, and now pieces are missing.
        h.checked(50 * MIN, missing());
        assert_eq!(state(&h, 51 * MIN), "missing");
        assert!(!h.verdict(&r, 51 * MIN).counted());
        h.checked(60 * MIN, Outcome::Passed);
        assert_eq!(state(&h, 61 * MIN), "passed");
        // Not answering is neither.
        let timed_out = || Outcome::Unanswered("timed out".into());
        h.checked(70 * MIN, timed_out());
        h.checked(80 * MIN, timed_out());
        // its pass, within the horizon, still counts
        assert_eq!(state(&h, 81 * MIN), "passed");
        assert_eq!(state(&h, 60 * MIN + r.horizon_ms + 1), "unconfirmed");
        let mut never = Holder::default();
        never.checked(MIN, timed_out());
        assert_eq!(state(&never, 2 * MIN), "unconfirmed");
        never.checked(2 * MIN, timed_out());
        assert_eq!(state(&never, 3 * MIN), "unconfirmed");
        // This device, for itself.
        let mut own = Holder::default();
        assert_eq!(own.own_verdict().state(), "passed");
        own.checked(MIN, missing());
        assert_eq!(own.own_verdict().state(), "copying");
        own.checked(2 * MIN, Outcome::Passed);
        own.checked(3 * MIN, missing());
        assert_eq!(own.own_verdict().state(), "missing");
        // What 0.1.13 saved of a failure has neither new field: read as a
        // piece missing, until the next check says.
        let saved = r#"{"last_check": 9, "last_pass": 5, "last_fail": 9,
            "fail_reason": "did not have 1 of the 4 pieces", "missed": 0}"#;
        let old: Holder = serde_json::from_str(saved).unwrap();
        assert_eq!(old.verdict(&r, 10).state(), "missing");
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
        assert!(s.iter().all(|a| a.old && store.has(&a.id).unwrap()));
        assert!(s.iter().any(|a| a.id != r.id), "chunks, not only the top");
        // without the indexes, only the top can be asked
        let s = p.sample(4, &mut rng, |_| None);
        assert_eq!(
            s,
            vec![Asked {
                id: r.id,
                old: true
            }]
        );
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
        let old = |id| Asked { id, old: true };
        let (id, other) = (old(id), old(other));
        assert_eq!(judge(&[id], &reply, false), Outcome::Passed);
        assert_eq!(
            judge(&[id, other], &reply, false),
            Outcome::Failed("did not have 1 of the 2 pieces of your files asked for".into())
        );
        let bad = BlobReply {
            items: vec![BlobItem::Held {
                id: id.id,
                ciphertext: b"other".to_vec(),
            }],
        };
        assert_eq!(
            judge(&[id], &bad, false),
            Outcome::Failed("sent 1 of the 1 pieces damaged".into())
        );
    }
}
