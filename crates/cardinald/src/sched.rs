//! Which device to ask for which blob object: a local, adaptive policy
//! (no protocol involved; objects verify by hash whoever sends them).
//!
//! - Per device, a decaying estimate of throughput (bytes per second
//!   while it has requests outstanding) and of request latency (typical
//!   and best).
//! - Requests go to the device expected to finish them first, given what
//!   it already has outstanding, so work spreads in proportion to
//!   throughput. Each device's window (requests outstanding) is sized to
//!   keep its link busy: about throughput × best latency, doubled.
//! - A device new to the scheduler gets a small probe window until it
//!   has answered.
//! - Objects a device turned out not to have are remembered for a while
//!   (devices keep fetching) and asked of the others at once. An object
//!   every live device lacks is reported unavailable.
//! - A request outstanding much longer than its device's typical latency
//!   is hedged: its ids are asked of another device too, and whichever
//!   copy arrives first is kept.
//!
//! The scheduler does no I/O and takes the time as an argument, so it is
//! tested on its own; `net.rs` drives it.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

/// An object id.
pub type Id = [u8; 32];
/// A device (its link static key).
pub type Peer = [u8; 32];

/// Ids per request: 16 chunks of at most 256 KiB.
pub const BATCH: usize = 16;
/// Requests outstanding over all devices (bounds memory: replies are at
/// most 4 MiB, about 1 MiB typically).
pub const MAX_TOTAL: usize = 24;
/// Most requests outstanding on one device.
pub const MAX_WINDOW: usize = 12;
/// Requests a device that has not answered yet may have outstanding.
pub const PROBE_WINDOW: usize = 1;
/// How long a device's "does not have it" is believed.
pub const LACK_MEMORY: Duration = Duration::from_secs(30);
/// A request is hedged after this many times its device's typical
/// latency...
pub const HEDGE_FACTOR: u32 = 4;
/// ... but never sooner than this.
pub const HEDGE_MIN: Duration = Duration::from_millis(750);
/// Consecutive failures before a device is left out (until it
/// reconnects).
pub const MAX_FAILURES: u32 = 3;
/// Throughput samples cover at least this much busy time (or one typical
/// latency): replies come in bursts.
const RATE_SPAN: Duration = Duration::from_millis(250);
/// Weight of a new sample in the decaying estimates.
const ALPHA: f64 = 0.25;
/// Throughput assumed for a device not measured yet (bytes/s).
const PRIOR_RATE: f64 = 1e6;
/// Bytes assumed for a request whose size is unknown.
const PRIOR_REQUEST: f64 = 1024.0 * 1024.0;

/// What is known of one device's performance; kept across fetches.
#[derive(Clone, Copy, Debug, Default)]
pub struct PeerStats {
    /// Bytes per second while busy (decaying average); 0 if unmeasured.
    pub rate: f64,
    /// Typical request latency, seconds (decaying average).
    pub latency: f64,
    /// Best recent request latency, seconds (creeps up over time so it
    /// follows a link that got slower).
    pub min_latency: f64,
    /// Bytes per reply (decaying average).
    pub reply_bytes: f64,
    /// Replies measured.
    pub samples: u64,
    /// Bytes received from this device since the daemon started,
    /// including late duplicates of hedged requests.
    pub bytes_total: u64,
}

impl PeerStats {
    fn rate_or_prior(&self) -> f64 {
        if self.samples == 0 || self.rate <= 0.0 {
            PRIOR_RATE
        } else {
            self.rate
        }
    }

    /// Requests to keep outstanding so the link stays busy.
    pub fn window(&self) -> usize {
        if self.samples == 0 {
            return PROBE_WINDOW;
        }
        let per = self.reply_bytes.max(64.0 * 1024.0);
        let bdp = self.rate * self.min_latency.max(0.001);
        let w = (2.0 * bdp / per).ceil() as usize + 1;
        w.clamp(2, MAX_WINDOW)
    }

    /// When an outstanding request should be hedged.
    pub fn hedge_after(&self) -> Duration {
        if self.samples == 0 {
            return HEDGE_MIN * 4;
        }
        Duration::from_secs_f64(self.latency * HEDGE_FACTOR as f64).max(HEDGE_MIN)
    }

    /// One reply: its size and latency. The first reply also gives a
    /// first throughput (one request alone).
    fn sample_reply(&mut self, bytes: u64, latency: Duration) {
        let lat = latency.as_secs_f64();
        if self.samples == 0 {
            self.rate = bytes as f64 / lat.max(1e-4);
            self.latency = lat;
            self.min_latency = lat;
            self.reply_bytes = bytes as f64;
        } else {
            self.latency += ALPHA * (lat - self.latency);
            self.reply_bytes += ALPHA * (bytes as f64 - self.reply_bytes);
            // the best latency drifts up 2% a sample so it can recover
            self.min_latency = (self.min_latency * 1.02).min(lat);
        }
        self.samples += 1;
        self.bytes_total += bytes;
    }

    /// Throughput over a stretch of time with requests outstanding.
    fn sample_rate(&mut self, rate: f64) {
        self.rate += ALPHA * (rate - self.rate);
    }

    /// A failed or very slow request: the device looks slower.
    fn penalize(&mut self, waited: Duration) {
        if self.samples == 0 {
            return;
        }
        self.rate *= 0.5;
        let lat = waited.as_secs_f64();
        if lat > self.latency {
            self.latency += ALPHA * (lat - self.latency);
        }
    }
}

struct PeerState {
    stats: PeerStats,
    outstanding: usize,
    /// Bytes expected from the outstanding requests.
    expected: f64,
    failures: u32,
    live: bool,
    /// Throughput is measured over time with requests outstanding: the
    /// last time that was accounted, and the busy time and bytes since
    /// the last rate sample.
    busy_mark: Option<Instant>,
    busy: f64,
    busy_bytes: u64,
    lacks: HashMap<Id, Instant>,
}

impl PeerState {
    fn new(stats: PeerStats) -> PeerState {
        PeerState {
            stats,
            outstanding: 0,
            expected: 0.0,
            failures: 0,
            live: true,
            busy_mark: None,
            busy: 0.0,
            busy_bytes: 0,
            lacks: HashMap::new(),
        }
    }

    fn lacks(&self, id: &Id, now: Instant) -> bool {
        self.lacks
            .get(id)
            .is_some_and(|t| now.saturating_duration_since(*t) < LACK_MEMORY)
    }

    /// Accounts busy time up to `now`; call before `outstanding` changes.
    fn tick(&mut self, now: Instant) {
        if self.outstanding > 0 {
            if let Some(m) = self.busy_mark {
                self.busy += now.saturating_duration_since(m).as_secs_f64();
            }
        }
        self.busy_mark = Some(now);
    }

    /// Bytes received; a throughput sample once enough busy time passed.
    fn received(&mut self, bytes: u64) {
        self.busy_bytes += bytes;
        let span = RATE_SPAN.as_secs_f64().max(self.stats.latency);
        if self.stats.samples > 1 && self.busy >= span {
            self.stats.sample_rate(self.busy_bytes as f64 / self.busy);
            self.busy = 0.0;
            self.busy_bytes = 0;
        }
    }

    fn has_room(&self) -> bool {
        self.live && self.outstanding < self.stats.window()
    }

    /// When a request of `bytes` given to it now would be done.
    fn finish_estimate(&self, bytes: f64) -> f64 {
        (self.expected + bytes) / self.stats.rate_or_prior()
    }
}

/// A request to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// Pass back to [`Scheduler::reply`] or [`Scheduler::failed`].
    pub id: u64,
    /// The device to ask.
    pub peer: Peer,
    /// The objects to ask for.
    pub ids: Vec<Id>,
    /// Whether this duplicates a slow request.
    pub hedge: bool,
}

struct Outstanding {
    peer: Peer,
    ids: Vec<Id>,
    sent: Instant,
    expected: f64,
    hedged: bool,
}

/// What a reply means.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReplyOutcome {
    /// Ids received for the first time: keep these objects (the others
    /// are duplicates of a hedged request).
    pub accepted: Vec<Id>,
}

/// Assigns object requests to devices. See the module documentation.
#[derive(Default)]
pub struct Scheduler {
    peers: HashMap<Peer, PeerState>,
    order: Vec<Peer>,
    fresh: VecDeque<Id>,
    /// Ids to ask again (a device lacked them, or a request failed).
    retry: VecDeque<Id>,
    /// Ids pushed and not yet delivered or given up, with how many
    /// outstanding requests name them.
    wanted: HashMap<Id, u32>,
    requests: HashMap<u64, Outstanding>,
    next_request: u64,
    unavailable: Vec<Id>,
}

impl Scheduler {
    /// An empty scheduler.
    pub fn new() -> Scheduler {
        Scheduler::default()
    }

    /// Sets the devices that are online now, with what is known of each.
    /// Devices not named are left out until named again.
    pub fn set_peers(&mut self, peers: &[(Peer, PeerStats)]) {
        let now: HashSet<Peer> = peers.iter().map(|(p, _)| *p).collect();
        for (k, p) in self.peers.iter_mut() {
            if !now.contains(k) {
                p.live = false;
            }
        }
        for (k, stats) in peers {
            match self.peers.get_mut(k) {
                Some(p) if !p.live => {
                    // reconnected: start over, keeping what it lacked
                    let lacks = std::mem::take(&mut p.lacks);
                    let (outstanding, expected) = (p.outstanding, p.expected);
                    *p = PeerState::new(*stats);
                    p.lacks = lacks;
                    p.outstanding = outstanding;
                    p.expected = expected;
                }
                Some(_) => {}
                None => {
                    self.peers.insert(*k, PeerState::new(*stats));
                    self.order.push(*k);
                }
            }
        }
    }

    /// What is known of a device now.
    pub fn stats(&self, peer: &Peer) -> Option<PeerStats> {
        self.peers.get(peer).map(|p| p.stats)
    }

    /// Adds an object to fetch (ignored if already wanted).
    pub fn push(&mut self, id: Id) {
        if let std::collections::hash_map::Entry::Vacant(e) = self.wanted.entry(id) {
            e.insert(0);
            self.fresh.push_back(id);
        }
    }

    /// Objects wanted and not yet delivered.
    pub fn wanted(&self) -> usize {
        self.wanted.len()
    }

    /// Requests outstanding.
    pub fn outstanding(&self) -> usize {
        self.requests.len()
    }

    /// Whether nothing is wanted or outstanding.
    pub fn is_idle(&self) -> bool {
        self.wanted.is_empty() && self.requests.is_empty()
    }

    /// Ids found unavailable since the last call: every live device
    /// lacks them (or there is none).
    pub fn take_unavailable(&mut self) -> Vec<Id> {
        std::mem::take(&mut self.unavailable)
    }

    fn give_up(&mut self, id: Id) {
        if self.wanted.remove(&id).is_some() {
            self.unavailable.push(id);
        }
    }

    /// The device to give a request of `bytes` with `id` in it: live,
    /// with room, not known to lack it, expected to finish first.
    fn best_peer(&self, id: &Id, bytes: f64, now: Instant, exclude: Option<&Peer>) -> Option<Peer> {
        self.order
            .iter()
            .filter(|k| Some(*k) != exclude)
            .filter_map(|k| self.peers.get(k).map(|p| (k, p)))
            .filter(|(_, p)| p.has_room() && !p.lacks(id, now))
            .min_by(|a, b| {
                a.1.finish_estimate(bytes)
                    .total_cmp(&b.1.finish_estimate(bytes))
            })
            .map(|(k, _)| *k)
    }

    fn any_live_without_lack(&self, id: &Id, now: Instant) -> bool {
        self.peers.values().any(|p| p.live && !p.lacks(id, now))
    }

    fn issue(&mut self, peer: Peer, ids: Vec<Id>, now: Instant, hedge: bool) -> Request {
        let p = self.peers.get_mut(&peer).expect("peer");
        let expected = if p.stats.samples > 0 {
            p.stats.reply_bytes
        } else {
            PRIOR_REQUEST
        } * ids.len() as f64
            / BATCH as f64;
        p.tick(now);
        p.outstanding += 1;
        p.expected += expected;
        for id in &ids {
            if let Some(n) = self.wanted.get_mut(id) {
                *n += 1;
            }
        }
        let id = self.next_request;
        self.next_request += 1;
        self.requests.insert(
            id,
            Outstanding {
                peer,
                ids: ids.clone(),
                sent: now,
                expected,
                // a hedge is not hedged again
                hedged: hedge,
            },
        );
        Request {
            id,
            peer,
            ids,
            hedge,
        }
    }

    /// Requests to send now: hedges of slow requests first, then new
    /// work while devices have room.
    pub fn poll(&mut self, now: Instant) -> Vec<Request> {
        let mut out = Vec::new();
        // Hedges.
        let slow: Vec<u64> = self
            .requests
            .iter()
            .filter(|(_, r)| {
                !r.hedged
                    && self.peers.get(&r.peer).is_some_and(|p| {
                        now.saturating_duration_since(r.sent) > p.stats.hedge_after()
                    })
            })
            .map(|(k, _)| *k)
            .collect();
        for rid in slow {
            if self.requests.len() >= MAX_TOTAL + MAX_TOTAL / 2 {
                break;
            }
            let (peer, ids) = {
                let r = &self.requests[&rid];
                let ids: Vec<Id> = r
                    .ids
                    .iter()
                    .filter(|i| self.wanted.contains_key(*i))
                    .copied()
                    .collect();
                (r.peer, ids)
            };
            if ids.is_empty() {
                continue;
            }
            let bytes = ids.len() as f64 * PRIOR_REQUEST / BATCH as f64;
            let Some(other) = self.best_peer(&ids[0], bytes, now, Some(&peer)) else {
                continue;
            };
            self.requests.get_mut(&rid).expect("request").hedged = true;
            if let Some(p) = self.peers.get_mut(&peer) {
                p.stats
                    .penalize(now.saturating_duration_since(self.requests[&rid].sent));
            }
            let ids: Vec<Id> = ids
                .into_iter()
                .filter(|i| !self.peers[&other].lacks(i, now))
                .collect();
            out.push(self.issue(other, ids, now, true));
        }
        self.drop_unreachable(now);
        // New work, retries first, to the devices expected to finish
        // first. A device busy or lacking the ids at the head of the
        // queue does not hold up the others.
        while self.requests.len() < MAX_TOTAL && self.queued() > 0 {
            let mut candidates: Vec<Peer> = self
                .order
                .iter()
                .filter(|k| self.peers.get(*k).is_some_and(|p| p.has_room()))
                .copied()
                .collect();
            candidates.sort_by(|a, b| {
                self.peers[a]
                    .finish_estimate(PRIOR_REQUEST)
                    .total_cmp(&self.peers[b].finish_estimate(PRIOR_REQUEST))
            });
            let mut issued = false;
            for peer in candidates {
                let ids = self.take_batch(&peer, now);
                if !ids.is_empty() {
                    out.push(self.issue(peer, ids, now, false));
                    issued = true;
                    break;
                }
            }
            if !issued {
                break;
            }
        }
        // Ids every live device is known to lack (fresh ones found so
        // while making batches), or no device at all.
        self.drop_unreachable(now);
        if !self.peers.values().any(|p| p.live) {
            while let Some(id) = self.fresh.pop_front() {
                self.give_up(id);
            }
            while let Some(id) = self.retry.pop_front() {
                if self.wanted.get(&id) == Some(&0) {
                    self.give_up(id);
                }
            }
        }
        out
    }

    /// Ids to ask again that no live device may have: gives up on them
    /// (or, if a request for one is still out, waits for its answer).
    fn drop_unreachable(&mut self, now: Instant) {
        let mut keep = VecDeque::with_capacity(self.retry.len());
        while let Some(id) = self.retry.pop_front() {
            match self.wanted.get(&id) {
                None => {} // delivered meanwhile
                Some(_) if self.any_live_without_lack(&id, now) => keep.push_back(id),
                Some(0) => self.give_up(id),
                Some(_) => {} // outstanding elsewhere; requeued if that fails
            }
        }
        self.retry = keep;
    }

    fn queued(&self) -> usize {
        self.fresh.len() + self.retry.len()
    }

    /// Up to [`BATCH`] ids for `peer`: ids to ask again that it may have,
    /// then fresh ones.
    fn take_batch(&mut self, peer: &Peer, now: Instant) -> Vec<Id> {
        let p = &self.peers[peer];
        let mut ids = Vec::with_capacity(BATCH);
        if !self.retry.is_empty() {
            let mut keep = VecDeque::with_capacity(self.retry.len());
            while let Some(id) = self.retry.pop_front() {
                if ids.len() < BATCH && self.wanted.contains_key(&id) && !p.lacks(&id, now) {
                    ids.push(id);
                } else if self.wanted.contains_key(&id) {
                    keep.push_back(id);
                }
            }
            self.retry = keep;
        }
        while ids.len() < BATCH {
            let Some(id) = self.fresh.pop_front() else {
                break;
            };
            if !self.wanted.contains_key(&id) {
                continue;
            }
            if p.lacks(&id, now) {
                self.retry.push_back(id);
                continue;
            }
            ids.push(id);
        }
        ids
    }

    /// The next time [`poll`](Self::poll) may hedge a request.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.requests
            .values()
            .filter(|r| !r.hedged)
            .filter_map(|r| {
                self.peers
                    .get(&r.peer)
                    .map(|p| r.sent + p.stats.hedge_after())
            })
            .min()
    }

    fn finish(&mut self, rid: u64, now: Instant) -> Option<Outstanding> {
        let r = self.requests.remove(&rid)?;
        if let Some(p) = self.peers.get_mut(&r.peer) {
            p.tick(now);
            p.outstanding = p.outstanding.saturating_sub(1);
            p.expected = (p.expected - r.expected).max(0.0);
        }
        for id in &r.ids {
            if let Some(n) = self.wanted.get_mut(id) {
                *n = n.saturating_sub(1);
            }
        }
        Some(r)
    }

    /// A reply arrived: `got` are the ids whose objects came (verified),
    /// `bytes` their total size. The other ids asked are ones the device
    /// does not have.
    pub fn reply(&mut self, rid: u64, got: &[Id], bytes: u64, now: Instant) -> ReplyOutcome {
        let Some(r) = self.finish(rid, now) else {
            return ReplyOutcome::default();
        };
        let got: HashSet<Id> = got.iter().copied().collect();
        if let Some(p) = self.peers.get_mut(&r.peer) {
            p.failures = 0;
            p.stats
                .sample_reply(bytes, now.saturating_duration_since(r.sent));
            p.received(bytes);
            for id in &r.ids {
                if !got.contains(id) {
                    p.lacks.insert(*id, now);
                }
            }
            if p.lacks.len() > 100_000 {
                p.lacks
                    .retain(|_, t| now.saturating_duration_since(*t) < LACK_MEMORY);
            }
        }
        let mut accepted = Vec::new();
        for id in &r.ids {
            if got.contains(id) {
                if self.wanted.remove(id).is_some() {
                    accepted.push(*id);
                }
            } else if self.wanted.get(id) == Some(&0) {
                // nothing else outstanding for it: ask another device now
                self.retry.push_front(*id);
            }
        }
        ReplyOutcome { accepted }
    }

    /// A request failed (timed out, the session closed, a bad reply).
    pub fn failed(&mut self, rid: u64, now: Instant) {
        let Some(r) = self.finish(rid, now) else {
            return;
        };
        if let Some(p) = self.peers.get_mut(&r.peer) {
            p.failures += 1;
            p.stats.penalize(now.saturating_duration_since(r.sent));
            if p.failures >= MAX_FAILURES {
                p.live = false;
            }
        }
        for id in r.ids.iter().rev() {
            if self.wanted.get(id) == Some(&0) {
                self.retry.push_front(*id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u32) -> Id {
        let mut i = [0u8; 32];
        i[..4].copy_from_slice(&n.to_le_bytes());
        i
    }

    const A: Peer = [1; 32];
    const B: Peer = [2; 32];
    const C: Peer = [3; 32];

    fn measured(rate: f64, latency: f64) -> PeerStats {
        PeerStats {
            rate,
            latency,
            min_latency: latency,
            reply_bytes: 1024.0 * 1024.0,
            samples: 10,
            bytes_total: 0,
        }
    }

    /// Runs a simulation: each device serves its requests one after
    /// another at its own rate (1 MiB per request); returns the objects
    /// each device delivered.
    fn simulate(s: &mut Scheduler, rates: &[(Peer, f64)], n: u32) -> HashMap<Peer, usize> {
        let t0 = Instant::now();
        for i in 0..n {
            s.push(id(i));
        }
        let mut now = t0;
        // per device: queue of (finish time, request)
        let mut busy: HashMap<Peer, Instant> = HashMap::new();
        let mut pending: Vec<(Instant, Request)> = Vec::new();
        let mut delivered: HashMap<Peer, usize> = HashMap::new();
        let mut steps = 0;
        while !s.is_idle() {
            steps += 1;
            assert!(steps < 100_000, "no progress");
            for r in s.poll(now) {
                let rate = rates.iter().find(|(p, _)| *p == r.peer).unwrap().1;
                let per_id = 1024.0 * 1024.0 / BATCH as f64;
                let secs = r.ids.len() as f64 * per_id / rate;
                let start = busy.get(&r.peer).copied().unwrap_or(now).max(now);
                let done = start + Duration::from_secs_f64(secs) + Duration::from_millis(2);
                busy.insert(r.peer, done);
                pending.push((done, r));
            }
            pending.sort_by_key(|(t, _)| *t);
            let (t, r) = pending.remove(0);
            now = t;
            let bytes = (r.ids.len() * 1024 * 1024 / BATCH) as u64;
            let out = s.reply(r.id, &r.ids, bytes, now);
            *delivered.entry(r.peer).or_default() += out.accepted.len();
        }
        delivered
    }

    #[test]
    fn work_follows_throughput() {
        let mut s = Scheduler::new();
        s.set_peers(&[(A, PeerStats::default()), (B, PeerStats::default())]);
        // A is 8 times faster than B.
        let got = simulate(&mut s, &[(A, 80e6), (B, 10e6)], 16 * 400);
        let (a, b) = (got[&A] as f64, got[&B] as f64);
        assert!(a / (a + b) > 0.75, "A {a} B {b}");
        assert!(b > 0.0, "B gets some work: {a} {b}");
        let sa = s.stats(&A).unwrap();
        let sb = s.stats(&B).unwrap();
        assert!(sa.rate > 4.0 * sb.rate, "{sa:?} {sb:?}");
    }

    #[test]
    fn estimates_keep_adapting() {
        let mut s = Scheduler::new();
        s.set_peers(&[(A, PeerStats::default()), (B, PeerStats::default())]);
        simulate(&mut s, &[(A, 80e6), (B, 10e6)], 16 * 200);
        // Now B improves and A degrades.
        let got = simulate(&mut s, &[(A, 5e6), (B, 80e6)], 16 * 400);
        let (a, b) = (got[&A] as f64, got[&B] as f64);
        assert!(b / (a + b) > 0.7, "A {a} B {b}");
    }

    #[test]
    fn new_device_gets_a_probe_share() {
        let mut s = Scheduler::new();
        s.set_peers(&[(A, measured(50e6, 0.02)), (B, PeerStats::default())]);
        for i in 0..16 * 100 {
            s.push(id(i));
        }
        let reqs = s.poll(Instant::now());
        let to_b = reqs.iter().filter(|r| r.peer == B).count();
        let to_a = reqs.iter().filter(|r| r.peer == A).count();
        assert_eq!(to_b, PROBE_WINDOW);
        assert!(to_a >= 2, "{to_a}");
    }

    #[test]
    fn lacking_objects_go_elsewhere_at_once() {
        let now = Instant::now();
        let mut s = Scheduler::new();
        s.set_peers(&[(A, measured(50e6, 0.02)), (B, measured(10e6, 0.02))]);
        s.push(id(1));
        s.push(id(2));
        let r = s.poll(now);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].peer, A);
        // A has only id 1.
        let out = s.reply(r[0].id, &[id(1)], 1000, now);
        assert_eq!(out.accepted, vec![id(1)]);
        let r = s.poll(now);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].peer, B);
        assert_eq!(r[0].ids, vec![id(2)]);
        // B lacks it too: unavailable (no other device).
        s.reply(r[0].id, &[], 0, now);
        assert!(s.poll(now).is_empty());
        assert_eq!(s.take_unavailable(), vec![id(2)]);
        assert!(s.is_idle());
        // Asked again soon: not asked of devices known to lack it.
        s.push(id(2));
        assert!(s.poll(now).is_empty());
        assert_eq!(s.take_unavailable(), vec![id(2)]);
        // A third device comes online: asked of it.
        s.set_peers(&[
            (A, measured(50e6, 0.02)),
            (B, measured(10e6, 0.02)),
            (C, PeerStats::default()),
        ]);
        s.push(id(2));
        let r = s.poll(now);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].peer, C);
        // Later, the memory expires and A is asked again.
        s.failed(r[0].id, now);
        s.set_peers(&[(A, measured(50e6, 0.02))]);
        let later = now + LACK_MEMORY + Duration::from_secs(1);
        let r = s.poll(later);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].peer, A);
    }

    #[test]
    fn a_busy_device_does_not_hold_up_the_others() {
        let now = Instant::now();
        let mut s = Scheduler::new();
        s.set_peers(&[(A, measured(1e6, 0.3)), (B, measured(50e6, 0.02))]);
        // B lacks ids 0..64; they wait for A, whose window is full.
        for i in 0..64 {
            s.push(id(i));
        }
        let first = s.poll(now);
        for r in first.iter().filter(|r| r.peer == B) {
            s.reply(r.id, &[], 0, now);
        }
        // Fresh ids arrive: B takes them although A is busy and the
        // ids at the head of the queue are A's only.
        for i in 64..128 {
            s.push(id(i));
        }
        let r = s.poll(now);
        assert!(
            r.iter()
                .any(|r| r.peer == B && r.ids.iter().all(|i| i[0] >= 64)),
            "{r:?}"
        );
    }

    #[test]
    fn slow_requests_are_hedged() {
        let now = Instant::now();
        let mut s = Scheduler::new();
        s.set_peers(&[(A, measured(50e6, 0.05)), (B, measured(40e6, 0.05))]);
        for i in 0..4 {
            s.push(id(i));
        }
        let r = s.poll(now);
        assert_eq!(r.len(), 1);
        let first = r[0].clone();
        assert!(s.poll(now + Duration::from_millis(100)).is_empty());
        let deadline = s.next_deadline().unwrap();
        assert_eq!(deadline, now + HEDGE_MIN);
        // Past the deadline: the same ids are asked of the other device.
        let h = s.poll(deadline + Duration::from_millis(1));
        assert_eq!(h.len(), 1);
        assert!(h[0].hedge);
        assert_ne!(h[0].peer, first.peer);
        assert_eq!(h[0].ids, first.ids);
        // Hedged once only.
        assert!(s.poll(deadline + Duration::from_secs(5)).is_empty());
        // The hedge answers first; the late original is a duplicate.
        let t = deadline + Duration::from_millis(50);
        let out = s.reply(h[0].id, &h[0].ids, 4000, t);
        assert_eq!(out.accepted.len(), 4);
        let out = s.reply(first.id, &first.ids, 4000, t + Duration::from_secs(1));
        assert!(out.accepted.is_empty());
        assert!(s.is_idle());
        // The slow device's estimate dropped.
        let slow = s.stats(&first.peer).unwrap();
        assert!(slow.rate < 40e6, "{slow:?}");
    }

    #[test]
    fn hedge_lacking_does_not_lose_the_original() {
        let now = Instant::now();
        let mut s = Scheduler::new();
        s.set_peers(&[(A, measured(50e6, 0.05)), (B, measured(40e6, 0.05))]);
        s.push(id(7));
        let first = s.poll(now).remove(0);
        let later = now + Duration::from_secs(2);
        let h = s.poll(later).remove(0);
        // The other device lacks it; the original is still outstanding.
        s.reply(h.id, &[], 0, later);
        assert!(s.poll(later).is_empty());
        assert!(s.take_unavailable().is_empty());
        let out = s.reply(first.id, &[id(7)], 100, later);
        assert_eq!(out.accepted, vec![id(7)]);
        assert!(s.is_idle());
    }

    #[test]
    fn failures_retry_then_drop_the_device() {
        let now = Instant::now();
        let mut s = Scheduler::new();
        s.set_peers(&[(A, measured(50e6, 0.05))]);
        s.push(id(1));
        for _ in 0..MAX_FAILURES {
            let r = s.poll(now);
            assert_eq!(r.len(), 1);
            s.failed(r[0].id, now);
        }
        assert!(s.poll(now).is_empty());
        assert_eq!(s.take_unavailable(), vec![id(1)]);
    }

    #[test]
    fn window_follows_bandwidth_delay() {
        let slow = measured(1e6, 0.05);
        let fast = measured(100e6, 0.03);
        assert_eq!(slow.window(), 2);
        assert!(fast.window() > 4, "{}", fast.window());
        assert!(fast.window() <= MAX_WINDOW);
        assert_eq!(PeerStats::default().window(), PROBE_WINDOW);
    }
}
