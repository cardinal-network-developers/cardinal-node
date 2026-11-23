//! Known paths to trusted contacts' devices (D86, `hosts.md#known-paths`).
//!
//! Keeping a way to each trusted contact's devices is every device's part,
//! in proportion to what it can afford. For each of their devices this one
//! keeps the last address a direct session worked at, and when that was
//! confirmed. While there is no session it confirms it about every 30
//! minutes, and at once on waking or a network change, with a 28-byte probe
//! (`hosts.md#probe`) that only a device of a person who trusts this one
//! answers. A probe with no answer doubles the wait, up to four hours;
//! anything that shows the device puts it back.
//!
//! On waking, and when its network changes, a device that cannot receive
//! connections dials up to eight of those devices at their known paths.
//! A device that helps others (an anchor) keeps those sessions alive, up to
//! 64 of them; one that does not sends no keepalive on a contact's session
//! it is not using, and leaves it to the other side: only where none of
//! the sessions it has is kept alive by an anchor does it ping its
//! neighbours, about every two minutes (`sync.md#neighbours`).
//!
//! When its person turns to a contact and nothing else found them, a
//! device probes its own subnet (`hosts.md#looking-for-someone`), at most
//! once in five minutes: multicast does not carry on many Wi-Fi networks
//! and phones, and a unicast probe does.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use cardinal_contact::discovery as disc;
use cardinal_crypto::{random_bytes, HybridPublicKey};
use cardinal_identity::KeyId;
use cardinal_link::{LinkError, Target};
use serde_json::{json, Value as Json};
use zeroize::Zeroizing;

use crate::core::short;
use crate::daemon::Daemon;

/// How often a known path is confirmed while there is no session.
const CHECK_EVERY: Duration = Duration::from_secs(30 * 60);
/// The longest wait between checks of a device that does not answer.
const MAX_WAIT: Duration = Duration::from_secs(4 * 3600);
/// How long an answer to a probe may take.
const ANSWER_WITHIN: Duration = Duration::from_secs(5);
/// How long a look tries a known path.
const PATH_WITHIN: Duration = Duration::from_secs(3);
/// How long a dial on waking may take before it counts as a miss.
const DIAL_WITHIN: Duration = Duration::from_secs(60);
/// How long the nonces of probes answered are kept. A probe carries no
/// time, so this is all that stops one being answered twice here; one
/// replayed later, or elsewhere, tells whoever replays it that a device
/// there recognizes its tag, as a replayed advertisement does.
const NONCES_FOR: Duration = Duration::from_secs(600);
/// The most nonces kept; older ones go first.
const NONCES_KEPT: usize = 4096;
/// The most probes answered for one address in a minute.
const ANSWERS_PER_SOURCE: u32 = 10;
/// The most contacts' devices dialled on waking.
pub const REACH_OUT: usize = 8;
/// The most contacts' sessions an anchor keeps alive.
pub const ANCHOR_KEEPS: usize = 64;
/// How seldom the local network is swept.
const SWEEP_EVERY: Duration = Duration::from_secs(300);
/// The most ports a sweep probes.
const SWEEP_PORTS: usize = 4;
/// The most probes one sweep sends.
const SWEEP_MAX: usize = 2048;
/// Probes sent at once in a sweep, and the pause between those batches.
const SWEEP_BATCH: usize = 64;
const SWEEP_PAUSE: Duration = Duration::from_millis(20);
/// How long after a network change keepalives are left as they are, so
/// that every session is asked for an answer.
const CHECKING_FOR: Duration = Duration::from_secs(15);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn unix_ms() -> u64 {
    let since = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
    since.map_or(0, |t| t.as_millis() as u64)
}

/// The usual wait between checks, which tests shorten.
fn check_every() -> Duration {
    std::env::var("CARDINAL_TEST_PATH_CHECK_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .map_or(CHECK_EVERY, Duration::from_secs)
}

/// The known path to one device of a trusted contact.
#[derive(Clone, Debug)]
pub struct Path {
    /// Whose device it is.
    pub who: [u8; 32],
    /// The last address a direct session with it worked at.
    pub addr: SocketAddr,
    /// When that was last confirmed, in milliseconds since 1970.
    pub confirmed: Option<u64>,
    /// The wait before the next check.
    pub wait: Duration,
    /// When the next check is due.
    pub next: Instant,
    /// Checks in a row that had no answer.
    pub misses: u32,
    /// When the check under way began, if one is.
    pub checking: Option<Instant>,
    /// Whether that check is a dial, which takes longer than a probe.
    pub dialling: bool,
    /// Probes sent to it, all told.
    pub probes: u64,
}

impl Path {
    fn new(who: [u8; 32], addr: SocketAddr, now: Instant) -> Path {
        Path {
            who,
            addr,
            confirmed: None,
            wait: check_every(),
            next: now,
            misses: 0,
            checking: None,
            dialling: false,
            probes: 0,
        }
    }

    /// A session, or an answer, at `addr`: confirmed now.
    fn confirm(&mut self, addr: SocketAddr, now: Instant) {
        self.addr = addr;
        self.confirmed = Some(unix_ms());
        self.heard(now);
    }

    /// Something showed the device: the usual wait again.
    fn heard(&mut self, now: Instant) {
        self.wait = check_every();
        self.next = now + self.wait;
        self.misses = 0;
        self.checking = None;
        self.dialling = false;
    }

    /// A check had no answer: the wait doubles, up to [`MAX_WAIT`].
    fn missed(&mut self, now: Instant) {
        self.misses += 1;
        self.wait = (self.wait * 2).min(MAX_WAIT);
        self.next = now + self.wait;
        self.checking = None;
        self.dialling = false;
    }

    /// Whether the check under way has had its time and no answer.
    fn overdue(&self, now: Instant) -> bool {
        let limit = if self.dialling {
            DIAL_WITHIN
        } else {
            ANSWER_WITHIN
        };
        self.checking
            .is_some_and(|c| now.duration_since(c) >= limit)
    }
}

/// A probe sent, waiting for answers.
struct Sent {
    probe: disc::Probe,
    /// Where it went: an answer from anywhere else is none.
    to: HashSet<SocketAddr>,
    /// The device whose path it checks, or none for a sweep.
    device: Option<KeyId>,
    /// The person it looks for.
    who: [u8; 32],
    at: Instant,
}

/// The keys probes are checked with, for the state they were read from.
#[derive(Default)]
struct Keys {
    version: u64,
    own: Option<Zeroizing<[u8; 32]>>,
    mine: Option<Zeroizing<[u8; 32]>>,
    theirs: Vec<([u8; 32], Zeroizing<[u8; 32]>)>,
}

/// What this device keeps of the ways to its trusted contacts.
#[derive(Default)]
pub struct Known {
    paths: Mutex<HashMap<KeyId, Path>>,
    sent: Mutex<VecDeque<Sent>>,
    answered: Mutex<VecDeque<([u8; 8], Instant)>>,
    sources: Mutex<HashMap<IpAddr, (Instant, u32)>>,
    swept: Mutex<Option<Instant>>,
    /// Woken, or the network changed: dial the devices to reach out to.
    woke: AtomicBool,
    checking_until: Mutex<Option<Instant>>,
    keys: Mutex<Keys>,
    /// The contacts' devices seen keeping a session alive, by link key:
    /// anchors, whose silence means they went away.
    anchors: Mutex<HashSet<[u8; 32]>>,
}

impl Known {
    /// The device was seen in a session, or answered, at `addr`.
    pub fn confirm(&self, device: KeyId, who: [u8; 32], addr: SocketAddr) {
        let now = Instant::now();
        let mut paths = lock(&self.paths);
        paths
            .entry(device)
            .or_insert_with(|| Path::new(who, addr, now))
            .confirm(addr, now);
    }

    /// Another device said where this one is, or its tag was seen: the
    /// usual wait again, without a confirmation.
    pub fn heard(&self, device: &KeyId) {
        if let Some(p) = lock(&self.paths).get_mut(device) {
            p.heard(Instant::now());
        }
    }

    /// Woken, or the network changed: every path is checked at once, and
    /// the devices to reach out to are dialled.
    pub fn woke(&self) {
        let now = Instant::now();
        for p in lock(&self.paths).values_mut() {
            p.next = now;
            p.checking = None;
            p.dialling = false;
        }
        self.woke.store(true, Ordering::SeqCst);
        *lock(&self.checking_until) = Some(now + CHECKING_FOR);
    }

    /// The path to a device, if one is known.
    pub fn path(&self, device: &KeyId) -> Option<Path> {
        lock(&self.paths).get(device).cloned()
    }

    /// The known paths to a person's devices.
    pub fn of(&self, who: &[u8; 32]) -> Vec<(KeyId, Path)> {
        lock(&self.paths)
            .iter()
            .filter(|(_, p)| p.who == *who)
            .map(|(k, p)| (*k, p.clone()))
            .collect()
    }

    /// A device's path as `contact-status` shows it.
    pub fn json(&self, device: &KeyId) -> Json {
        let Some(p) = self.path(device) else {
            return Json::Null;
        };
        let now = Instant::now();
        json!({
            "addr": p.addr.to_string(),
            "confirmed_s_ago": p.confirmed.map(|t| unix_ms().saturating_sub(t) / 1000),
            "next_check_s": p.next.saturating_duration_since(now).as_secs(),
            "wait_s": p.wait.as_secs(),
            "misses": p.misses,
            "probes": p.probes,
            "checking": p.checking.is_some(),
        })
    }

    /// Notes a nonce answered, and says whether it was new.
    fn first_answer(&self, nonce: [u8; 8]) -> bool {
        let now = Instant::now();
        let mut seen = lock(&self.answered);
        while seen
            .front()
            .is_some_and(|(_, t)| now.duration_since(*t) >= NONCES_FOR)
        {
            seen.pop_front();
        }
        if seen.iter().any(|(n, _)| *n == nonce) {
            return false;
        }
        if seen.len() >= NONCES_KEPT {
            seen.pop_front();
        }
        seen.push_back((nonce, now));
        true
    }

    /// Whether another probe from `ip` may be answered this minute.
    fn may_answer(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut s = lock(&self.sources);
        s.retain(|_, (since, _)| now.duration_since(*since) < Duration::from_secs(60));
        let e = s.entry(ip).or_insert((now, 0));
        e.1 += 1;
        e.1 <= ANSWERS_PER_SOURCE
    }

    /// Whether this device sent a probe with this nonce lately.
    fn sent_here(&self, nonce: [u8; 8]) -> bool {
        lock(&self.sent)
            .iter()
            .any(|s| disc::probe_nonce(&s.probe) == nonce)
    }
}

/// A trusted contact's device, as the tick sees it.
struct Theirs {
    who: [u8; 32],
    device: KeyId,
    link: HybridPublicKey,
    /// Named as their host in a reach node.
    host: bool,
}

/// The devices of the trusted contacts this device may reach directly.
fn trusted_devices(d: &Daemon) -> Vec<Theirs> {
    let core = d.core();
    let mut out = Vec::new();
    for (who, (trusted, spaces)) in crate::presence::by_identity(&core) {
        if !trusted {
            continue;
        }
        let Some(o) = core.others.get(&who) else {
            continue;
        };
        let st = o.log.state();
        if st.frozen {
            continue;
        }
        let hosts: Vec<[u8; 32]> = spaces
            .iter()
            .flat_map(|s| core.reach_of(s, &who))
            .map(|r| r.host)
            .collect();
        for k in st.keys.values() {
            let Some(link) = k.link_key.clone() else {
                continue;
            };
            out.push(Theirs {
                who,
                device: k.key,
                host: hosts.contains(link.x25519()),
                link,
            });
        }
    }
    out
}

/// One candidate to reach out to on waking.
#[derive(Clone, Debug)]
pub struct Candidate {
    pub device: KeyId,
    /// When its person was last turned to here.
    pub used: Option<Instant>,
    /// Named as their host in a reach node.
    pub host: bool,
    /// When its path was last confirmed, in milliseconds since 1970.
    pub confirmed: Option<u64>,
}

/// The devices to dial on waking: at most [`REACH_OUT`], those of the
/// contacts last turned to first, a device named as their host before
/// others, then the paths confirmed last.
pub fn reach_out(mut c: Vec<Candidate>) -> Vec<KeyId> {
    c.sort_by(|a, b| {
        b.used
            .cmp(&a.used)
            .then(b.host.cmp(&a.host))
            .then(b.confirmed.cmp(&a.confirmed))
            .then(a.device.cmp(&b.device))
    });
    c.into_iter().take(REACH_OUT).map(|c| c.device).collect()
}

/// One contact's session, as an anchor weighs keeping it alive.
pub struct Kept {
    pub x: [u8; 32],
    /// A neighbour's (`sync.md#neighbours`).
    pub neighbour: bool,
    /// When its person was last turned to here.
    pub used: Option<Instant>,
    /// How long it has been open.
    pub open: Duration,
}

/// The contacts' sessions an anchor keeps alive, by static key: at most
/// [`ANCHOR_KEEPS`], its neighbours' first, then those of the contacts last
/// turned to, then the sessions open longest.
pub fn anchor_keeps(mut s: Vec<Kept>) -> HashSet<[u8; 32]> {
    s.sort_by(|a, b| {
        b.neighbour
            .cmp(&a.neighbour)
            .then(b.used.cmp(&a.used))
            .then(b.open.cmp(&a.open))
            .then(a.x.cmp(&b.x))
    });
    s.into_iter().take(ANCHOR_KEEPS).map(|k| k.x).collect()
}

/// Starts answering probes and keeping the paths.
pub fn start(d: Arc<Daemon>) {
    let mut rx = d.endpoint.probes();
    let d2 = d.clone();
    tokio::spawn(async move {
        while let Some((pkt, from)) = rx.recv().await {
            match pkt.first() {
                Some(&cardinal_link::packet::TYPE_PROBE) => on_probe(&d2, &pkt, from),
                Some(&cardinal_link::packet::TYPE_PROBE_ANSWER) => on_answer(&d2, &pkt, from),
                _ => {}
            }
        }
    });
    d.known.woke();
    tokio::spawn(async move {
        let mut stop = d.stopping.subscribe();
        let every = check_every().min(Duration::from_secs(5));
        loop {
            tick(&d).await;
            tokio::select! {
                _ = tokio::time::sleep(every) => {}
                _ = stop.changed() => break,
            }
        }
    });
}

/// The keys probes are made and checked with, read again when the state
/// changed.
fn keys(d: &Daemon) -> MutexGuard<'_, Keys> {
    let version = d.core().state_version();
    let mut k = lock(&d.known.keys);
    if k.version != version || k.own.is_none() {
        let core = d.core();
        k.version = version;
        k.own = core.discovery_secret().map(|s| disc::discovery_key(&s));
        k.mine = crate::presence::advertised(&core).map(|s| disc::presence_key(&s));
        k.theirs = crate::presence::of_contacts(&core)
            .iter()
            .map(|(who, s)| (*who, disc::presence_key(s)))
            .collect();
    }
    k
}

/// A probe came: answered once, to where it came from, if one of its tags
/// is one this device knows; otherwise nothing at all.
fn on_probe(d: &Arc<Daemon>, pkt: &[u8], from: SocketAddr) {
    let Some(p) = disc::read_probe(pkt) else {
        return;
    };
    let nonce = disc::probe_nonce(&p);
    if d.known.sent_here(nonce) {
        return;
    }
    let answer = {
        let k = keys(d);
        if k.own.as_ref().is_some_and(|o| disc::probe_from_own(&p, o)) {
            k.own.as_ref().map(|o| disc::probe_answer(o, &p))
        } else if k
            .theirs
            .iter()
            .any(|(_, t)| disc::probe_from_contact(&p, t))
        {
            k.mine.as_ref().map(|m| disc::probe_answer(m, &p))
        } else {
            None
        }
    };
    let Some(answer) = answer else {
        return;
    };
    if !d.known.may_answer(from.ip()) || !d.known.first_answer(nonce) {
        return;
    }
    tracing::debug!("answering a probe from {from}");
    d.endpoint.send_probe(&answer, from);
}

/// An answer came: to a check of a path, or to a sweep.
fn on_answer(d: &Arc<Daemon>, pkt: &[u8], from: SocketAddr) {
    let now = Instant::now();
    let matched: Vec<(Option<KeyId>, [u8; 32], bool)> = {
        let k = keys(d);
        let mut sent = lock(&d.known.sent);
        sent.retain(|s| now.duration_since(s.at) < ANSWER_WITHIN);
        let mut out = Vec::new();
        for s in sent.iter().filter(|s| s.to.contains(&from)) {
            let own = s.device.is_none()
                && k.own
                    .as_ref()
                    .is_some_and(|o| disc::answers(pkt, &s.probe, o));
            let theirs = k
                .theirs
                .iter()
                .filter(|(w, _)| *w == s.who)
                .any(|(_, t)| disc::answers(pkt, &s.probe, t));
            if own || theirs {
                out.push((s.device, s.who, own));
            }
        }
        out
    };
    for (device, who, own) in matched {
        match device {
            Some(device) => {
                tracing::debug!("{}'s device answered at {from}", short(&who));
                if let Some(p) = lock(&d.known.paths).get_mut(&device) {
                    p.confirm(from, now);
                }
            }
            None if own => {
                let d = d.clone();
                tokio::spawn(async move { d.discovered(from).await });
            }
            None => {
                tracing::info!("{} answered on this network at {from}", short(&who));
                d.rendezvous
                    .step(&who, Some(true), format!("found on this network at {from}"));
                let d = d.clone();
                tokio::spawn(async move {
                    let near = crate::rendezvous::Near::Lan(from);
                    crate::rendezvous::found_near(&d, who, near).await
                });
            }
        }
    }
}

/// A new probe, made now.
fn new_probe(d: &Daemon) -> Option<disc::Probe> {
    let k = keys(d);
    let own = k.own.as_ref()?;
    Some(disc::probe(own, k.mine.as_deref(), random_bytes()))
}

/// One pass: the paths follow the sessions open, those due are checked,
/// and keepalives follow what this device can afford.
async fn tick(d: &Arc<Daemon>) {
    let theirs = trusted_devices(d);
    let all: Vec<crate::neighbours::Theirs> = theirs
        .iter()
        .map(|t| crate::neighbours::Theirs {
            who: t.who,
            device: t.device,
            x: *t.link.x25519(),
            host: t.host,
        })
        .collect();
    crate::neighbours::tick(d, &all);
    let now = Instant::now();
    let woke = d.known.woke.swap(false, Ordering::SeqCst);
    let mut learnt = Vec::new();
    {
        let mut paths = lock(&d.known.paths);
        paths.retain(|k, _| theirs.iter().any(|t| t.device == *k));
        for t in &theirs {
            let x = t.link.x25519();
            if d.is_direct_ip(x) {
                if let Some(s) = d
                    .session(x)
                    .filter(|s| s.carrier() == Some(cardinal_link::CarrierKind::Udp))
                {
                    if let Some(addr) = s.remote_addr() {
                        let p = paths.entry(t.device).or_insert_with(|| {
                            let mut p = Path::new(t.who, addr, now);
                            p.confirmed = None;
                            p
                        });
                        let new = p.confirmed.is_none() || p.addr != addr;
                        if s.role() == cardinal_link::Role::Initiator && new {
                            learnt.push((t.device, addr));
                        }
                        p.confirm(addr, now);
                    }
                }
                continue;
            }
            if let std::collections::hash_map::Entry::Vacant(e) = paths.entry(t.device) {
                if let Some(addr) = d.known_addrs(&t.device).into_iter().next() {
                    e.insert(Path::new(t.who, addr, now));
                }
            }
        }
        for p in paths.values_mut() {
            if p.overdue(now) {
                p.missed(now);
            }
        }
    }
    // Where a session this device opened worked: kept across restarts.
    for (device, addr) in learnt {
        d.learn_addr(&device, addr);
    }
    let dial: HashSet<KeyId> = if woke && crate::host::own_grant(d).is_none() {
        let used = d.rendezvous.used_at();
        let paths = lock(&d.known.paths);
        let candidates = theirs
            .iter()
            .filter(|t| !d.is_direct_ip(t.link.x25519()))
            .filter_map(|t| {
                let p = paths.get(&t.device)?;
                Some(Candidate {
                    device: t.device,
                    used: used.get(&t.who).copied(),
                    host: t.host,
                    confirmed: p.confirmed,
                })
            })
            .collect();
        reach_out(candidates).into_iter().collect()
    } else {
        HashSet::new()
    };
    let mut probes = Vec::new();
    {
        let mut paths = lock(&d.known.paths);
        for t in &theirs {
            if d.is_direct_ip(t.link.x25519()) {
                continue;
            }
            let Some(p) = paths.get_mut(&t.device) else {
                continue;
            };
            if p.checking.is_some() || p.next > now {
                continue;
            }
            p.checking = Some(now);
            p.dialling = dial.contains(&t.device);
            if p.dialling {
                let (d, device, who, link, addr) =
                    (d.clone(), t.device, t.who, t.link.clone(), p.addr);
                tokio::spawn(async move { reach_device(&d, who, device, link, addr).await });
            } else {
                p.probes += 1;
                probes.push((t.device, t.who, p.addr));
            }
        }
    }
    lock(&d.known.sent).retain(|s| now.duration_since(s.at) < ANSWER_WITHIN);
    for (device, who, addr) in probes {
        let Some(probe) = new_probe(d) else {
            break;
        };
        lock(&d.known.sent).push_back(Sent {
            probe,
            to: HashSet::from([addr]),
            device: Some(device),
            who,
            at: Instant::now(),
        });
        d.endpoint.send_probe(&probe, addr);
    }
    keepalives(d);
}

/// Dials a contact's device at its known path, on waking.
async fn reach_device(
    d: &Arc<Daemon>,
    who: [u8; 32],
    device: KeyId,
    link: HybridPublicKey,
    addr: SocketAddr,
) {
    match d.dial(|c| Target::new(addr, c, &link)).await {
        Ok(s) => {
            tracing::info!("reached {}'s device at its known path {addr}", short(&who));
            d.on_session(s);
            d.known.confirm(device, who, addr);
        }
        Err(LinkError::Closed(cardinal_link::CloseReason::Replaced)) => {
            d.known.confirm(device, who, addr);
        }
        Err(e) => {
            tracing::debug!("{}'s device at {addr}: {e}", short(&who));
            if let Some(p) = lock(&d.known.paths).get_mut(&device) {
                p.missed(Instant::now());
            }
        }
    }
}

/// Keepalives follow what this device can afford: an anchor keeps up to
/// [`ANCHOR_KEEPS`] contacts' sessions alive, its neighbours' first;
/// another those of the contacts its person is turning to, and otherwise
/// sends none of its own, leaving them to its anchors: each ping wakes a
/// phone's radio. Only when no session it has is kept alive by an anchor
/// does it ping its neighbours, every [`crate::neighbours::SPARING_KEEPALIVE`].
fn keepalives(d: &Daemon) {
    let checking = lock(&d.known.checking_until).is_some_and(|t| Instant::now() < t);
    if checking {
        return;
    }
    let sessions = d.contacts_in_touch();
    let used = d.rendezvous.used_at();
    let neighbours = d.neighbours.statics();
    let helps = d.conditions.helps();
    let within = crate::neighbours::ANCHOR_PINGS_WITHIN;
    let mut sessions = sessions;
    {
        // A session only answered sees no ping of its own go unanswered:
        // an anchor that has gone quiet has gone, or stopped helping, and
        // its session is let go, so that it is dialled again or replaced.
        let mut anchors = lock(&d.known.anchors);
        anchors.retain(|x| sessions.iter().any(|(_, s)| s.peer_static() == *x));
        for (_, s) in &sessions {
            if s.pinged_twice_within(within) {
                anchors.insert(s.peer_static());
            }
        }
        sessions.retain(|(_, s)| {
            let quiet = anchors.contains(&s.peer_static())
                && s.keepalive().is_none()
                && s.last_heard().elapsed() > within;
            if quiet {
                tracing::info!("an anchor went quiet: letting its session go");
                anchors.remove(&s.peer_static());
                s.close("quiet");
            }
            !quiet
        });
    }
    let anchored = !helps && sessions.iter().any(|(_, s)| s.pinged_twice_within(within));
    let keep: HashSet<[u8; 32]> = if helps {
        // A contact's device present here as one this device hosts (D87)
        // is kept alive as a neighbour's is: its host is its anchor.
        let hosted = crate::hosting::present_here(d);
        let all = sessions
            .iter()
            .map(|(who, s)| Kept {
                x: s.peer_static(),
                neighbour: neighbours.contains(&s.peer_static())
                    || hosted.contains(&s.peer_static()),
                used: used.get(who).copied(),
                open: d
                    .session_since(&s.peer_static())
                    .map_or(Duration::ZERO, |(_, t)| t),
            })
            .collect();
        anchor_keeps(all)
    } else {
        HashSet::new()
    };
    for (who, s) in sessions {
        let want = if keep.contains(&s.peer_static()) || d.rendezvous.in_use(&who) {
            Some(crate::daemon::KEEPALIVE)
        } else if !anchored && neighbours.contains(&s.peer_static()) {
            Some(crate::neighbours::SPARING_KEEPALIVE)
        } else {
            None
        };
        s.set_keepalive(want);
    }
}

/// Tries a contact's devices at their known paths, as a step of a look.
pub async fn try_paths(d: &Arc<Daemon>, who: &[u8; 32]) {
    let theirs: Vec<Theirs> = trusted_devices(d)
        .into_iter()
        .filter(|t| t.who == *who && !d.is_direct_ip(t.link.x25519()))
        .collect();
    let mut tries = tokio::task::JoinSet::new();
    for t in theirs {
        // One that did not answer its last check is away: a look does not
        // wait on it.
        let Some(p) = d.known.path(&t.device).filter(|p| p.misses == 0) else {
            continue;
        };
        let d = d.clone();
        tries.spawn(async move {
            let target =
                Target::new(p.addr, cardinal_link::CarrierKind::Udp, &t.link).within(PATH_WITHIN);
            let r = d.endpoint.connect(target).await;
            (t, p.addr, r)
        });
    }
    while let Some(Ok((t, addr, r))) = tries.join_next().await {
        let label = hex::encode(&t.device[..8]);
        match r {
            Ok(s) => {
                d.on_session(s);
                d.known.confirm(t.device, t.who, addr);
                d.rendezvous.step(
                    who,
                    Some(true),
                    format!("their {label}: reached at its known path {addr}"),
                );
            }
            Err(e) => d.rendezvous.step(
                who,
                Some(false),
                format!("their {label}: not at its known path {addr}: {e}"),
            ),
        }
    }
}

/// This device's own IPv4 addresses, for a sweep.
fn own_v4(d: &Daemon) -> Vec<Ipv4Addr> {
    let Some(udp) = d.endpoint.udp_addr() else {
        return Vec::new();
    };
    match udp.ip() {
        IpAddr::V4(v4) if !v4.is_unspecified() => vec![v4],
        IpAddr::V4(_) => crate::daemon::local_ips()
            .into_iter()
            .filter_map(|ip| match ip {
                IpAddr::V4(v4) if v4.is_private() || v4.is_link_local() => Some(v4),
                _ => None,
            })
            .collect(),
        IpAddr::V6(_) => Vec::new(),
    }
}

/// Probes this device's own network for a contact's devices, as the last
/// step of a look (`hosts.md#looking-for-someone`): at most once in
/// [`SWEEP_EVERY`], whoever it is for. Says how many probes went.
pub async fn sweep(d: &Arc<Daemon>, who: [u8; 32]) -> usize {
    {
        let mut swept = lock(&d.known.swept);
        if swept.is_some_and(|t| t.elapsed() < SWEEP_EVERY) {
            return 0;
        }
        *swept = Some(Instant::now());
    }
    let Some(probe) = new_probe(d) else {
        return 0;
    };
    let mut ports: Vec<u16> = d
        .endpoint
        .udp_addr()
        .map(|a| a.port())
        .into_iter()
        .collect();
    for (_, p) in d.known.of(&who) {
        if ports.len() >= SWEEP_PORTS {
            break;
        }
        if !ports.contains(&p.addr.port()) {
            ports.push(p.addr.port());
        }
    }
    let nets = crate::networks::subnets().unwrap_or_default();
    let mut to: Vec<SocketAddr> = Vec::new();
    for own in own_v4(d) {
        for ip in crate::networks::sweep_range(own, &nets) {
            for port in &ports {
                if to.len() < SWEEP_MAX {
                    to.push(SocketAddr::new(IpAddr::V4(ip), *port));
                }
            }
        }
    }
    // A device behind the tests' simulated NAT has no network of its own:
    // everything it sends goes through the one gateway.
    if to.is_empty() || std::env::var_os("CARDINAL_TEST_UDP_GATEWAY").is_some() {
        return 0;
    }
    lock(&d.known.sent).push_back(Sent {
        probe,
        to: to.iter().copied().collect(),
        device: None,
        who,
        at: Instant::now(),
    });
    d.rendezvous.step(
        &who,
        None,
        format!(
            "probing this network: {} addresses, port{} {}",
            to.len() / ports.len().max(1),
            if ports.len() == 1 { "" } else { "s" },
            ports
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    );
    tracing::debug!(
        "probing {} addresses on this network for {}",
        to.len(),
        short(&who)
    );
    for batch in to.chunks(SWEEP_BATCH) {
        for a in batch {
            d.endpoint.send_probe(&probe, *a);
        }
        tokio::time::sleep(SWEEP_PAUSE).await;
    }
    // The answers have as long as the probes took, and more.
    if let Some(s) = lock(&d.known.sent).iter_mut().find(|s| s.probe == probe) {
        s.at = Instant::now();
    }
    to.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn a_device_that_does_not_answer_is_checked_ever_less_often() {
        let now = Instant::now();
        let mut p = Path::new([1; 32], addr("10.0.0.2:7171"), now);
        assert_eq!(p.wait, CHECK_EVERY);
        let mut waits = Vec::new();
        for _ in 0..12 {
            p.missed(now);
            waits.push(p.wait.as_secs() / 60);
        }
        assert_eq!(&waits[..4], &[60, 120, 240, 240]);
        assert!(waits.iter().all(|w| *w <= 240));
        assert_eq!(p.misses, 12);
        assert_eq!(p.next, now + MAX_WAIT);
        // Seen anywhere: the usual wait again, and the new address.
        p.confirm(addr("10.0.0.3:7171"), now);
        assert_eq!((p.wait, p.misses), (CHECK_EVERY, 0));
        assert_eq!(p.addr, addr("10.0.0.3:7171"));
        assert!(p.confirmed.is_some());
        p.missed(now);
        p.heard(now);
        assert_eq!((p.wait, p.misses), (CHECK_EVERY, 0));
    }

    #[test]
    fn at_most_eight_are_reached_out_to_those_in_use_first() {
        let now = Instant::now();
        let mut c: Vec<Candidate> = (0..20u8)
            .map(|i| Candidate {
                device: [i; 32],
                used: None,
                host: false,
                confirmed: Some(u64::from(i)),
            })
            .collect();
        c[3].used = Some(now);
        c[5].host = true;
        let out = reach_out(c);
        assert_eq!(out.len(), REACH_OUT);
        assert_eq!(out[0], [3; 32], "the one in use first");
        assert_eq!(out[1], [5; 32], "then one named as their host");
        assert_eq!(out[2], [19; 32], "then the latest confirmed");
    }

    #[test]
    fn an_anchor_keeps_at_most_64() {
        let now = Instant::now();
        let s: Vec<_> = (0..100u8)
            .map(|i| Kept {
                x: [i; 32],
                neighbour: i == 1,
                used: (i == 99).then_some(now),
                open: Duration::from_secs(u64::from(i)),
            })
            .collect();
        let keep = anchor_keeps(s);
        assert_eq!(keep.len(), ANCHOR_KEEPS);
        assert!(keep.contains(&[1; 32]), "a neighbour first");
        assert!(keep.contains(&[99; 32]));
        assert!(keep.contains(&[98; 32]), "then the longest open");
        assert!(!keep.contains(&[0; 32]));
    }

    #[test]
    fn a_nonce_is_answered_once() {
        let k = Known::default();
        assert!(k.first_answer([1; 8]));
        assert!(!k.first_answer([1; 8]));
        assert!(k.first_answer([2; 8]));
    }

    #[test]
    fn answers_to_one_address_are_limited() {
        let k = Known::default();
        let ip: IpAddr = "10.0.0.9".parse().unwrap();
        let n = (0..30).filter(|_| k.may_answer(ip)).count();
        assert_eq!(n, ANSWERS_PER_SOURCE as usize);
        assert!(k.may_answer("10.0.0.8".parse().unwrap()));
    }
}
