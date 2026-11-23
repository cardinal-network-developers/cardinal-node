//! Hosting a trusted contact (D87, `hosts.md#hosting-a-contact`).
//!
//! A person offers, in the relationship they share, to host a trusted
//! contact on some of their devices: those that can be reached from
//! outside their network. The offer holds one grant for each serving
//! device. The contact says yes there, and from then on their devices name
//! each serving device in their reach nodes as one of their hosts, register
//! tokens with it, present themselves to it and collect their mailbox from
//! it. Either can end it there, at any time; nothing undoes an end.
//!
//! Step 1 is reach only: mailbox, rendezvous and relay. A serving device
//! learns who leaves envelopes for the contact (by token), when, and how
//! big, and whom it relays them with; when their devices are online, and
//! the addresses they come from and present; never what anything says.
//!
//! A hosted device spends no radio wakeups on upkeep: the serving device
//! keeps its session alive, as its anchor, and says when an envelope
//! waits. The device presents itself on a new session or a new network,
//! and collects when told, on a new session and on a new network.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cardinal_crypto::random_bytes;
use cardinal_encoding::{Record, Value};
use cardinal_identity::KeyId;
use cardinal_link::{Service, Session, Target};
use cardinal_space::grant::{Grant, QuotaClass, MAILBOX, RELAY, RENDEZVOUS};
use cardinal_space::relationship::{self, Hosting, Reach};
use cardinal_space::{NodeId, SpaceId, SpaceOp};
use serde_json::{json, Value as Json};

use crate::core::short;
use crate::daemon::{Daemon, PeerKind};
use crate::mailbox::{self, Refused, Store, Token};
use crate::rendezvous::call;

/// Envelopes waiting, and deposits a day, for one person hosted, all their
/// tokens together, unless the host says otherwise.
pub const ENVELOPES: u64 = 256;
/// Relay bytes a day for one person hosted, unless the host says otherwise.
pub const RELAY_BYTES: u64 = 50_000_000;
/// How long what waits for a contact stays after the hosting ends.
const KEEP_AFTER_END: u64 = 7 * DAY;
const DAY: u64 = 24 * 60 * 60;
/// How often to look at what hosting asks of this device. A look sends
/// nothing unless something is due.
const LOOK_EVERY: Duration = Duration::from_secs(10);
/// How long a hosted device waits before it tries again a host it could
/// not reach, present itself at or collect from: at first and at most.
/// Each failure doubles it.
const RETRY: (Duration, Duration) = (Duration::from_secs(30), Duration::from_secs(30 * 60));

const OP_PRESENT: u64 = 1;
const OP_CONNECT: u64 = 2;
const OP_ANSWER: u64 = 5;
const OP_RELAY: u64 = 1;
const BUSY: u64 = 5;

/// What the person offered is told the host's devices see.
pub const SEES: &str = "The host's devices see who leaves you envelopes, when, and how big, \
     and whom you reach through them; when your devices are online, the public addresses \
     they come from, and the local addresses they give; never what anything says.";

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn now() -> u64 {
    let since = SystemTime::now().duration_since(UNIX_EPOCH);
    since.map_or(0, |t| t.as_secs())
}

/// The default quota class of a grant to a contact (D87).
pub fn default_class() -> QuotaClass {
    QuotaClass {
        number: 0,
        outstanding: Some(ENVELOPES),
        per_day: Some(ENVELOPES),
        relay_bytes: Some(RELAY_BYTES),
    }
}

/// Relay bytes left.
type Budget = Arc<AtomicU64>;

/// A contact's device present at this one: whose, its session, and the
/// local addresses it gave.
type Present = ([u8; 32], Session, Vec<SocketAddr>);

/// A device of this person's hosting someone, and a device of someone's
/// hosting this person, keep this.
pub struct Hosted {
    dir: PathBuf,
    /// As a host: the mailbox of each contact served, by identity.
    stores: Mutex<HashMap<[u8; 32], Store>>,
    /// As a host: the tokens let in, by contact.
    admitted: Mutex<HashMap<[u8; 32], HashSet<Token>>>,
    /// As a host: contacts' devices present, by static key: whose, the
    /// session, and the local addresses they gave.
    present: Mutex<HashMap<[u8; 32], Present>>,
    /// As a host: relay bytes left today, by contact and day.
    relay: Mutex<HashMap<([u8; 32], u64), Budget>>,
    /// As one hosted, by host: the session and network this device last
    /// presented itself on, and collected on.
    presented: Mutex<HashMap<[u8; 32], Done>>,
    collected: Mutex<HashMap<[u8; 32], Done>>,
    /// As one hosted: the hosts that said an envelope waits.
    waiting: Mutex<HashSet<[u8; 32]>>,
    /// As one hosted: the hosts that could not be reached, and when to
    /// try again.
    dialed: Mutex<HashMap<[u8; 32], Again>>,
    /// As one hosted: the tokens registered nowhere yet for a host that
    /// refused, and when to try again.
    naming: Mutex<HashMap<[u8; 32], Again>>,
    /// Counts the times this device woke or its network changed.
    moved: AtomicU64,
    /// Wakes the look at once.
    poke: tokio::sync::Notify,
}

/// When to try something again that failed, and how long the wait was.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Again {
    at: Instant,
    wait: Duration,
    /// The network it failed on: a new one tries again at once.
    moved: u64,
}

impl Again {
    /// After a failure: twice the wait before, if there was one.
    fn after(before: Option<&Again>, moved: u64, now: Instant) -> Again {
        let wait = before
            .filter(|b| b.moved == moved)
            .map_or(RETRY.0, |b| (b.wait * 2).min(RETRY.1));
        Again {
            at: now + wait,
            wait,
            moved,
        }
    }

    fn due(&self, moved: u64, now: Instant) -> bool {
        self.moved != moved || now >= self.at
    }
}

/// Something done on a session with a host: on which session, on which
/// network, and when to try again if it failed.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Done {
    session: [u8; 32],
    moved: u64,
    again: Option<Again>,
}

/// Whether to do something again on `session`: never yet on it, or the
/// network changed since, or it failed and its wait is over. Nothing else
/// makes it due: no timer.
fn due(done: Option<&Done>, session: [u8; 32], moved: u64, now: Instant) -> bool {
    done.is_none_or(|d| {
        d.session != session || d.moved != moved || d.again.is_some_and(|a| a.due(moved, now))
    })
}

/// What was done, after doing it: `ok`, or to be tried again.
fn done(before: Option<&Done>, session: [u8; 32], moved: u64, ok: bool, now: Instant) -> Done {
    let again = (!ok).then(|| {
        let before = before
            .filter(|b| b.session == session)
            .and_then(|b| b.again);
        Again::after(before.as_ref(), moved, now)
    });
    Done {
        session,
        moved,
        again,
    }
}

impl Hosted {
    /// Opens what is kept in `dir`: a mailbox for each contact served.
    pub fn load(dir: PathBuf) -> Hosted {
        let mut stores = HashMap::new();
        for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let id = e.file_name().to_str().and_then(|n| hex::decode(n).ok());
            if let Some(id) = id.and_then(|b| <[u8; 32]>::try_from(b).ok()) {
                stores.insert(id, Store::load(e.path()).until_collected());
            }
        }
        Hosted {
            dir,
            stores: Mutex::new(stores),
            admitted: Mutex::default(),
            present: Mutex::default(),
            relay: Mutex::default(),
            presented: Mutex::default(),
            collected: Mutex::default(),
            waiting: Mutex::default(),
            dialed: Mutex::default(),
            naming: Mutex::default(),
            moved: AtomicU64::new(0),
            poke: tokio::sync::Notify::new(),
        }
    }

    fn store_dir(&self, who: &[u8; 32]) -> PathBuf {
        self.dir.join(hex::encode(who))
    }
}

// ---- What the relationships say ----

/// A hosting of a contact by this device: whom, whether it serves them now,
/// with what quota, and its serving node and grant.
#[derive(Clone)]
pub(crate) struct Serving {
    pub who: [u8; 32],
    pub space: SpaceId,
    pub active: bool,
    pub class: QuotaClass,
    pub node: NodeId,
    pub grant: Grant,
}

/// A device of a contact's that hosts this person now.
#[derive(Clone)]
pub(crate) struct MyHost {
    pub who: [u8; 32],
    pub grant: Grant,
}

impl MyHost {
    fn key(&self) -> [u8; 32] {
        *self.grant.link_key.x25519()
    }
}

/// Every hosting in every relationship with a contact: the contact, the
/// relationship, whether this person trusts them, and the hosting.
fn all(d: &Daemon) -> Vec<([u8; 32], SpaceId, bool, Hosting)> {
    let core = d.core();
    let contacts = core.contacts();
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for c in &contacts {
        if c.recovery_of.is_some() || !seen.insert(c.space) {
            continue;
        }
        let Some(sp) = core.spaces.get(&c.space).and_then(|h| h.space.as_ref()) else {
            continue;
        };
        let trusted = cardinal_space::account::connects(&contacts, &c.identity);
        for h in relationship::hostings(sp) {
            out.push((c.identity, c.space, trusted, h));
        }
    }
    out
}

/// The grants of a hosting that hold: signed by a device of the host, for
/// that host and the other member.
fn grants(d: &Daemon, host: &[u8; 32], served: &[u8; 32], h: &Hosting) -> Vec<(NodeId, Grant)> {
    let core = d.core();
    let me = core.me();
    let st = if me == Some(*host) {
        core.identity.as_ref().map(|i| i.state())
    } else {
        core.others.get(host).map(|o| o.log.state())
    };
    let Some(st) = st.filter(|st| !st.frozen) else {
        return Vec::new();
    };
    h.serving
        .iter()
        .filter_map(|(node, bytes)| {
            let (g, signer) = Grant::open(bytes)?;
            let by_host = st.keys.values().any(|k| k.key == signer);
            (by_host && g.host == *host && g.served == *served).then_some((*node, g))
        })
        .collect()
}

/// The contacts this device serves, or did and keeps envelopes for.
pub(crate) fn serving(d: &Daemon) -> Vec<Serving> {
    let Some(me) = d.core().me() else {
        return Vec::new();
    };
    let here = *d.keys.link.public_key().x25519();
    let mut out: Vec<Serving> = Vec::new();
    for (who, space, trusted, h) in all(d) {
        if h.host != me || !h.accepted {
            continue;
        }
        for (node, grant) in grants(d, &me, &who, &h) {
            if *grant.link_key.x25519() != here {
                continue;
            }
            let s = Serving {
                who,
                space,
                active: trusted && !h.ended,
                class: grant.classes.first().cloned().unwrap_or_default(),
                node,
                grant,
            };
            // one that serves now before one that ended
            match out.iter_mut().find(|o| o.who == who) {
                Some(o) if !o.active => *o = s,
                Some(_) => {}
                None => out.push(s),
            }
        }
    }
    out
}

/// The contacts' devices that host this person now.
pub(crate) fn my_hosts(d: &Daemon) -> Vec<MyHost> {
    let Some(me) = d.core().me() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (who, _, trusted, h) in all(d) {
        if h.host != who || !h.accepted || h.ended || !trusted {
            continue;
        }
        for (_, grant) in grants(d, &who, &me, &h) {
            out.push(MyHost { who, grant });
        }
    }
    out
}

/// The static keys of every device a contact offered to host this person
/// on, whether it does now or not.
fn ever_offered(d: &Daemon) -> HashSet<[u8; 32]> {
    let Some(me) = d.core().me() else {
        return HashSet::new();
    };
    let mut out = HashSet::new();
    for (who, _, _, h) in all(d) {
        if h.host == who {
            out.extend(
                grants(d, &who, &me, &h)
                    .iter()
                    .map(|(_, g)| *g.link_key.x25519()),
            );
        }
    }
    out
}

/// Whether `who` hosts this person now.
pub(crate) fn hosts_me(d: &Daemon, who: &[u8; 32]) -> bool {
    my_hosts(d).iter().any(|h| h.who == *who)
}

/// Whether a token is one a contact this device hosts registered, and not
/// one of this device's own person's.
pub(crate) fn is_hosted_token(d: &Daemon, token: &Token) -> bool {
    !d.mailbox.is_active(token)
        && lock(&d.mailbox.hosted.stores)
            .values()
            .any(|s| s.is_active(token))
}

// ---- As a host ----

/// Whose a token is, among the contacts served now, and their quota. A
/// token of this device's own person's is never a contact's, and one
/// active for two contacts, which no register lets happen, is nobody's.
fn token_owner(d: &Daemon, token: &Token) -> Option<Serving> {
    if d.mailbox.is_active(token) {
        return None;
    }
    let who = {
        let stores = lock(&d.mailbox.hosted.stores);
        let mut whose = stores.iter().filter(|(_, s)| s.is_active(token));
        let (who, _) = whose.next()?;
        if whose.next().is_some() {
            return None;
        }
        *who
    };
    serving(d).into_iter().find(|s| s.who == who && s.active)
}

/// Whether a token is active anywhere on this device but in `who`'s
/// mailbox here: this device's person's own, or another contact's.
fn active_elsewhere(d: &Daemon, who: &[u8; 32], token: &Token) -> bool {
    d.mailbox.is_active(token)
        || lock(&d.mailbox.hosted.stores)
            .iter()
            .any(|(w, s)| w != who && s.is_active(token))
}

/// Leaves an envelope for a contact this device hosts.
pub(crate) fn deposit(
    d: &Daemon,
    token: &Token,
    envelope: &[u8],
    now: u64,
) -> Result<u64, Refused> {
    let Some(s) = token_owner(d, token) else {
        return Err(Refused::NotPermitted);
    };
    let mut stores = lock(&d.mailbox.hosted.stores);
    let Some(store) = stores.get_mut(&s.who) else {
        return Err(Refused::NotPermitted);
    };
    let left = store.deposit_within(token, envelope, now, (s.class.outstanding, s.class.per_day));
    drop(stores);
    match left {
        Err(Refused::Full) => tracing::info!("{}'s mailbox here is full", short(&s.who)),
        // Their devices present here are told, so that none need ask.
        Ok(_) => {
            for (_, session, _) in present_of(d, &s.who) {
                let waiting = Record::new().with(0, mailbox::OP_WAITING);
                crate::rendezvous::tell_device(session, Service::MAILBOX, waiting);
            }
        }
        Err(_) => {}
    }
    left
}

/// What a device of a contact this device hosts asks of their own
/// mailbox here: what an owner device may, while the hosting lasts, and
/// fetching what is left for a week after. `None` if they are not hosted
/// here.
pub(crate) fn answer_owner(
    d: &Daemon,
    who: &[u8; 32],
    device: &KeyId,
    r: &Record,
) -> Option<Record> {
    let s = serving(d).into_iter().find(|s| s.who == *who)?;
    let op = r.get(0).and_then(Value::as_uint);
    if !s.active && !matches!(op, Some(mailbox::OP_FETCH | mailbox::OP_ACK)) {
        return Some(mailbox::error(mailbox::NOT_PERMITTED));
    }
    if s.active {
        open_store(d, who);
    }
    let mut stores = lock(&d.mailbox.hosted.stores);
    let store = stores.get_mut(who)?;
    let reply = match op {
        Some(mailbox::OP_FETCH) => {
            let after = r.get(1).and_then(Value::as_uint).unwrap_or(0);
            let (page, more) = store.fetch(device, after, now());
            let list = page.iter().map(|h| {
                let held = Record::new().with(1, h.sequence).with(2, h.token);
                Value::Record(held.with(3, h.envelope.clone()))
            });
            Record::new()
                .with(0, mailbox::OP_FETCH)
                .with(1, Value::list(list))
                .with(2, more)
        }
        Some(mailbox::OP_ACK) => match r.get(1).and_then(Value::as_uint) {
            Some(sequence) => {
                store.ack(device, sequence, now());
                Record::new().with(0, mailbox::OP_ACK)
            }
            None => mailbox::error(mailbox::MALFORMED),
        },
        Some(mailbox::OP_REGISTER) => {
            let Ok(list) = r.record_list(1) else {
                return Some(mailbox::error(mailbox::MALFORMED));
            };
            let tokens: Vec<Token> = list
                .iter()
                .filter_map(|t| t.get(1)?.as_bytes()?.try_into().ok())
                .collect();
            drop(stores);
            // A token active anywhere else here is refused: it is someone
            // else's, and would let them be taken over.
            let mut active = Vec::new();
            for t in &tokens {
                if active_elsewhere(d, who, t) {
                    tracing::info!("{} registered a token in use here: refused", short(who));
                    continue;
                }
                let mut stores = lock(&d.mailbox.hosted.stores);
                if let Some(store) = stores.get_mut(who) {
                    store.register(t);
                    if store.is_active(t) {
                        active.push(*t);
                    }
                }
            }
            for t in &active {
                admit(d, who, t);
            }
            Record::new().with(0, mailbox::OP_REGISTER)
        }
        Some(mailbox::OP_REVOKE) => {
            let Ok(list) = r.list(1) else {
                return Some(mailbox::error(mailbox::MALFORMED));
            };
            let tokens: Vec<Token> = list
                .iter()
                .filter_map(|t| t.as_bytes()?.try_into().ok())
                .collect();
            for t in &tokens {
                store.revoke(t);
            }
            drop(stores);
            // Only their own tokens stop being let in.
            for t in &tokens {
                let theirs = lock(&d.mailbox.hosted.admitted)
                    .get_mut(who)
                    .is_some_and(|a| a.remove(t));
                if theirs {
                    mailbox::dismiss(d, t);
                }
            }
            Record::new().with(0, mailbox::OP_REVOKE)
        }
        Some(mailbox::OP_USAGE) => {
            let list = store.usage().into_iter().map(|(token, held, today)| {
                let line = Record::new().with(1, token).with(2, held as u64);
                Value::Record(line.with(3, u64::from(today)))
            });
            Record::new()
                .with(0, mailbox::OP_USAGE)
                .with(1, Value::list(list))
        }
        _ => mailbox::error(mailbox::UNKNOWN),
    };
    Some(reply)
}

fn open_store(d: &Daemon, who: &[u8; 32]) {
    let mut stores = lock(&d.mailbox.hosted.stores);
    if !stores.contains_key(who) {
        let dir = d.mailbox.hosted.store_dir(who);
        stores.insert(*who, Store::load(dir).until_collected());
    }
}

fn admit(d: &Daemon, who: &[u8; 32], token: &Token) {
    let new = lock(&d.mailbox.hosted.admitted)
        .entry(*who)
        .or_default()
        .insert(*token);
    if new {
        mailbox::admit(d, token);
    }
}

/// What rendezvous and relay ask of this device as a contact's host. `None`
/// if it is nothing of that; otherwise the reply, if one is due.
pub(crate) async fn serve_rendezvous(
    d: &Arc<Daemon>,
    s: &Session,
    kind: &PeerKind,
    service: Service,
    r: &Record,
) -> Option<Option<Record>> {
    let op = r.get(0).and_then(Value::as_uint);
    let rendezvous = service == Service::RENDEZVOUS;
    if let PeerKind::Contact(who, _) = kind {
        if rendezvous && matches!(op, Some(OP_PRESENT | OP_ANSWER)) {
            if !serving(d).iter().any(|x| x.who == *who && x.active) {
                return None;
            }
            if op == Some(OP_ANSWER) {
                crate::rendezvous::answered(d, s, r);
                return Some(None);
            }
            let local = crate::rendezvous::read_addresses(r.get(1));
            lock(&d.mailbox.hosted.present).insert(s.peer_static(), (*who, s.clone(), local));
            return Some(Some(Record::new().with(0, OP_PRESENT)));
        }
    }
    let token: Token = r.get(1)?.as_bytes()?.try_into().ok()?;
    let allowed = match kind {
        PeerKind::Token(t) => *t == token,
        PeerKind::Contact(..) => true,
        _ => false,
    };
    if !allowed {
        return None;
    }
    let owner = token_owner(d, &token)?;
    let present = present_of(d, &owner.who);
    match op {
        Some(OP_CONNECT) if rendezvous => Some(Some(
            crate::rendezvous::connect_holder_among(d, s, token, present).await,
        )),
        Some(OP_RELAY) if !rendezvous => {
            if !d.conditions.helps() {
                return Some(Some(mailbox::error(BUSY)));
            }
            let device = r.get(2).and_then(Value::as_bytes)?;
            let other = present.into_iter().map(|(_, s, _)| s).find(|o| {
                o.peer_identity()
                    .is_some_and(|p| p.signing_key.as_slice() == device)
            });
            let budget = relay_budget(d, &owner.who, &owner.class);
            Some(Some(crate::rendezvous::relay_holder_to(
                d, s, other, budget,
            )))
        }
        _ => Some(Some(mailbox::error(mailbox::UNKNOWN))),
    }
}

/// The static keys of the contacts' devices present here, as one this
/// device hosts.
pub(crate) fn present_here(d: &Daemon) -> HashSet<[u8; 32]> {
    let mut present = lock(&d.mailbox.hosted.present);
    present.retain(|_, (_, s, _)| !s.is_closed());
    present.keys().copied().collect()
}

/// The devices of a contact present here.
fn present_of(d: &Daemon, who: &[u8; 32]) -> Vec<([u8; 32], Session, Vec<SocketAddr>)> {
    let mut present = lock(&d.mailbox.hosted.present);
    present.retain(|_, (_, s, _)| !s.is_closed());
    present
        .iter()
        .filter(|(_, (w, _, _))| w == who)
        .map(|(k, (_, s, l))| (*k, s.clone(), l.clone()))
        .collect()
}

/// What is left of a contact's relay bytes today, all their tokens
/// together.
fn relay_budget(d: &Daemon, who: &[u8; 32], class: &QuotaClass) -> Option<Arc<AtomicU64>> {
    let limit = class.relay_bytes?;
    let day = now() / DAY;
    let mut all = lock(&d.mailbox.hosted.relay);
    all.retain(|(_, at), _| *at == day);
    Some(
        all.entry((*who, day))
            .or_insert_with(|| Arc::new(AtomicU64::new(limit)))
            .clone(),
    )
}

/// Keeps this device's part as a host: lets in the tokens of whom it
/// serves, stops letting in those of whom it no longer does, lets go of
/// their mailbox a week after, and keeps its grants' addresses current, or
/// takes itself out where it can no longer be reached.
fn keep_as_host(d: &Arc<Daemon>) {
    let serving = serving(d);
    for s in serving.iter().filter(|s| s.active) {
        open_store(d, &s.who);
    }
    let known: Vec<[u8; 32]> = lock(&d.mailbox.hosted.stores).keys().copied().collect();
    for who in known {
        let s = serving.iter().find(|s| s.who == who);
        let marker = d.mailbox.hosted.store_dir(&who).join("ended");
        if s.is_some_and(|s| s.active) {
            // A device taken out of their log holds nothing up.
            let devices: HashSet<KeyId> = {
                let core = d.core();
                let st = core.others.get(&who).map(|o| o.log.state());
                st.map(|st| st.keys.keys().copied().collect())
                    .unwrap_or_default()
            };
            let tokens = {
                let mut stores = lock(&d.mailbox.hosted.stores);
                let store = stores.get_mut(&who);
                store.map_or_else(Vec::new, |s| {
                    if !devices.is_empty() {
                        s.keep_fetchers(&devices, now());
                    }
                    s.active()
                })
            };
            for t in &tokens {
                if !active_elsewhere(d, &who, t) {
                    admit(d, &who, t);
                }
            }
            let _ = std::fs::remove_file(&marker);
            continue;
        }
        // It ended: nobody leaves anything more, and what is there waits
        // a week for them.
        let let_in = lock(&d.mailbox.hosted.admitted).remove(&who);
        for t in let_in.into_iter().flatten() {
            mailbox::dismiss(d, &t);
        }
        lock(&d.mailbox.hosted.present).retain(|_, (w, _, _)| *w != who);
        let ended = std::fs::read_to_string(&marker)
            .ok()
            .and_then(|t| t.trim().parse::<u64>().ok());
        match ended {
            None => {
                let _ = std::fs::create_dir_all(d.mailbox.hosted.store_dir(&who));
                let _ = std::fs::write(&marker, now().to_string());
            }
            Some(at) if now().saturating_sub(at) >= KEEP_AFTER_END => {
                lock(&d.mailbox.hosted.stores).remove(&who);
                let _ = std::fs::remove_dir_all(d.mailbox.hosted.store_dir(&who));
            }
            Some(_) => {}
        }
    }
    // This device's own grants, where it serves.
    let own = crate::host::own_grant(d);
    for s in serving.iter().filter(|s| s.active) {
        let op = match &own {
            None => SpaceOp::delete(s.node),
            Some(g) if g.endpoints != s.grant.endpoints => {
                let grant = Grant {
                    endpoints: g.endpoints.clone(),
                    ..s.grant.clone()
                };
                relationship::set_host_serving(s.node, &grant.sign(&d.keys.signing))
            }
            Some(_) => continue,
        };
        if let Err(e) = d.write_and_push(&s.space, vec![op]) {
            tracing::debug!("keeping a grant to {} current: {e:#}", short(&s.who));
        }
    }
}

// ---- As one hosted ----

/// Keeps this device's part as one hosted: in touch with each host,
/// present there, its mailbox collected, each host named where this
/// person's hosts are, a host that no longer serves taken out, and a
/// hosting by someone no longer trusted ended. Nothing here is sent on a
/// timer: a host says when an envelope waits, and keeps the session alive.
async fn keep_as_hosted(d: &Arc<Daemon>) {
    end_untrusted(d);
    let hosts = my_hosts(d);
    let moved = d.mailbox.hosted.moved.load(Ordering::Relaxed);
    for h in &hosts {
        let key = h.key();
        let s = match d.session(&key) {
            Some(s) => s,
            None => {
                reach_host(d, h, moved).await;
                continue;
            }
        };
        if s.is_relayed() {
            continue;
        }
        let session = s.handshake_hash();
        let present_now = {
            let m = lock(&d.mailbox.hosted.presented);
            due(m.get(&key), session, moved, Instant::now())
        };
        if present_now {
            let ask = Record::new().with(0, OP_PRESENT).with(
                1,
                crate::rendezvous::address_list(&crate::rendezvous::local_addresses(d)),
            );
            tracing::debug!("presenting to {}'s device", short(&h.who));
            let ok = match call(&s, Service::RENDEZVOUS, ask).await {
                Ok(r) => r.get(0).and_then(Value::as_uint) == Some(OP_PRESENT),
                Err(e) => {
                    tracing::debug!("presenting to {}'s device: {e:#}", short(&h.who));
                    false
                }
            };
            let mut m = lock(&d.mailbox.hosted.presented);
            let was = m.get(&key).copied();
            m.insert(key, done(was.as_ref(), session, moved, ok, Instant::now()));
        }
        let told = lock(&d.mailbox.hosted.waiting).remove(&key);
        let collect_now = told || {
            let m = lock(&d.mailbox.hosted.collected);
            due(m.get(&key), session, moved, Instant::now())
        };
        if collect_now {
            tracing::debug!("collecting at {}'s device", short(&h.who));
            let ok = match mailbox::collect_at(d, &s).await {
                Ok((n, held_back)) => {
                    if n > 0 {
                        tracing::info!("took in {n} envelopes left with {}", short(&h.who));
                    }
                    !held_back
                }
                Err(e) => {
                    tracing::debug!("collecting at {}'s device: {e:#}", short(&h.who));
                    false
                }
            };
            let mut m = lock(&d.mailbox.hosted.collected);
            let was = m.get(&key).copied();
            m.insert(key, done(was.as_ref(), session, moved, ok, Instant::now()));
        }
        let naming_due = lock(&d.mailbox.hosted.naming)
            .get(&key)
            .is_none_or(|a| a.due(moved, Instant::now()));
        if naming_due {
            let ok = name(d, h, &s).await;
            let mut m = lock(&d.mailbox.hosted.naming);
            if ok {
                m.remove(&key);
            } else {
                let was = m.get(&key).copied();
                m.insert(key, Again::after(was.as_ref(), moved, Instant::now()));
            }
        }
    }
    take_out(d, &hosts).await;
}

/// Ends every hosting of this person by a contact they no longer trust,
/// and every offer from one: the host stops keeping anything for them.
fn end_untrusted(d: &Arc<Daemon>) {
    let mut ends: HashMap<SpaceId, Vec<SpaceOp>> = HashMap::new();
    for (who, space, trusted, h) in all(d) {
        if h.host == who && !trusted && !h.ended {
            ends.entry(space)
                .or_default()
                .push(relationship::create_host_end(h.offer));
        }
    }
    for (space, ops) in ends {
        match d.write_and_push(&space, ops) {
            Ok(_) => tracing::info!(
                "{} ends a hosting by someone no longer trusted",
                short(&space)
            ),
            Err(e) => tracing::debug!("ending a hosting: {e:#}"),
        }
    }
}

/// Opens a session with a host, at the addresses its grant gives: at once
/// on waking or a new network, and otherwise only once the wait after the
/// last failure is over, which doubles each time.
async fn reach_host(d: &Arc<Daemon>, h: &MyHost, moved: u64) {
    let key = h.key();
    let now = Instant::now();
    if lock(&d.mailbox.hosted.dialed)
        .get(&key)
        .is_some_and(|a| !a.due(moved, now))
    {
        return;
    }
    for addr in h.grant.endpoints.iter().filter_map(|e| e.socket_addr()) {
        let link = h.grant.link_key.clone();
        if let Ok(s) = d.dial(|c| Target::new(addr, c, &link)).await {
            d.on_session(s);
            lock(&d.mailbox.hosted.dialed).remove(&key);
            return;
        }
    }
    let mut m = lock(&d.mailbox.hosted.dialed);
    let was = m.get(&key).copied();
    m.insert(key, Again::after(was.as_ref(), moved, Instant::now()));
}

/// This device woke, or its network changed: each host is reached,
/// presented to and collected from again.
pub(crate) fn network_changed(d: &Daemon) {
    d.mailbox.hosted.moved.fetch_add(1, Ordering::Relaxed);
    d.mailbox.hosted.poke.notify_one();
}

/// A contact's device says an envelope waits there for this person: it is
/// collected at once, if that device hosts them.
pub(crate) fn told_waiting(d: &Daemon, who: &[u8; 32], from: &[u8; 32]) {
    if my_hosts(d)
        .iter()
        .any(|h| h.who == *who && h.key() == *from)
    {
        tracing::debug!("{}'s device says an envelope waits", short(who));
        lock(&d.mailbox.hosted.waiting).insert(*from);
        d.mailbox.hosted.poke.notify_one();
    }
}

/// Names a host wherever this person's hosts are named unasked and it is
/// not named yet: only where every other member is a trusted contact (it
/// is someone's home address), never where the person said no, and only
/// once the account holds whatever no the list rests on (D75). A token is
/// registered with the host first, over the session `s`. Gives whether
/// the host took every token asked of it.
async fn name(d: &Arc<Daemon>, h: &MyHost, s: &Session) -> bool {
    let host = h.key();
    let _one = d.mailbox.reaching.lock().await;
    let Some(me) = d.core().me() else {
        return true;
    };
    let spaces = d.core().shared_spaces();
    for (space, _) in spaces {
        let (named, decided) = {
            let core = d.core();
            let t = core.telling(&space);
            let named = core.reach_of(&space, &me);
            let skip = !t.joined
                || t.left
                || t.public
                || !t.who.is_empty()
                || !t.trusted_only
                || t.said_no
                || t.not_here.contains(&host)
                || named.iter().any(|r| r.host == host)
                || (t.set && !mailbox::record_here(&core, &space));
            if skip {
                continue;
            }
            (named, mailbox::Decided::now(&core, &space))
        };
        if mailbox::is_put_off(d, &space) {
            continue;
        }
        let token: Token = random_bytes();
        let one = Value::Record(Record::new().with(1, token).with(2, 0u64));
        let ask = Record::new()
            .with(0, mailbox::OP_REGISTER)
            .with(1, Value::list([one]));
        match call(s, Service::MAILBOX, ask).await {
            Ok(r) if r.get(0).and_then(Value::as_uint) == Some(mailbox::OP_REGISTER) => {}
            other => {
                tracing::debug!("registering a token with {}: {other:?}", short(&h.who));
                return false;
            }
        }
        let mut reach = named;
        reach.push(Reach {
            endpoints: h.grant.endpoints.clone(),
            host,
            token,
            extra: Default::default(),
        });
        let set = relationship::set_reach(&me, &reach);
        let written = d.write_and_push_if(&space, vec![set], |core| decided.still(core, &space));
        match written {
            Ok(Some(_)) => tracing::info!(
                "{} names {}'s device as a host of this person's",
                short(&space),
                short(&h.who)
            ),
            other => {
                if other.is_err() {
                    mailbox::put_off(d, &space);
                }
                let back = Record::new()
                    .with(0, mailbox::OP_REVOKE)
                    .with(1, Value::list([Value::from(token)]));
                let _ = call(s, Service::MAILBOX, back).await;
            }
        }
    }
    true
}

/// Takes out of this person's reach nodes every contact's device that
/// hosted them and does not now: the hosting ended, or that device was
/// taken out of it. A host of their own is never taken out here.
async fn take_out(d: &Arc<Daemon>, hosts: &[MyHost]) {
    let now: HashSet<[u8; 32]> = hosts.iter().map(MyHost::key).collect();
    let own: HashSet<[u8; 32]> = d
        .core()
        .mailboxes()
        .iter()
        .map(|(g, _)| *g.link_key.x25519())
        .collect();
    let gone: HashSet<[u8; 32]> = ever_offered(d)
        .into_iter()
        .filter(|k| !now.contains(k) && !own.contains(k))
        .collect();
    if gone.is_empty() {
        return;
    }
    let _one = d.mailbox.reaching.lock().await;
    let Some(me) = d.core().me() else { return };
    let spaces = d.core().shared_spaces();
    for (space, _) in spaces {
        let (reach, decided) = {
            let core = d.core();
            let named = core.reach_of(&space, &me);
            if !named.iter().any(|r| gone.contains(&r.host)) {
                continue;
            }
            let kept: Vec<Reach> = named
                .into_iter()
                .filter(|r| !gone.contains(&r.host))
                .collect();
            (kept, mailbox::Decided::now(&core, &space))
        };
        let set = relationship::set_reach(&me, &reach);
        match d.write_and_push_if(&space, vec![set], |core| decided.still(core, &space)) {
            Ok(Some(_)) => tracing::info!("{} no longer names a contact's host", short(&space)),
            Ok(None) => {}
            Err(e) => tracing::debug!("taking a contact's host out: {e:#}"),
        }
    }
}

/// Keeps hosting going, both ways, whenever something may have changed.
pub fn start(d: Arc<Daemon>) {
    tokio::spawn(async move {
        let mut changed = d.changed.subscribe();
        let mut every = tokio::time::interval(LOOK_EVERY);
        loop {
            tokio::select! {
                _ = every.tick() => {}
                _ = changed.changed() => {}
                _ = d.mailbox.hosted.poke.notified() => {}
            }
            if d.core().identity.is_none() {
                continue;
            }
            keep_as_host(&d);
            keep_as_hosted(&d).await;
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    });
}

// ---- What the person asks ----

/// This person's devices that can host someone now: those that can be
/// reached from outside their network, each with its grant to itself.
fn can_host(d: &Daemon) -> Vec<(KeyId, Grant)> {
    d.core()
        .mailboxes()
        .into_iter()
        .filter(|(g, _)| g.endpoints.iter().any(|e| e.socket_addr().is_some()))
        .map(|(g, k)| (k, g))
        .collect()
}

/// Why none of this person's devices can host anyone now.
pub const WHY_NOT: &str = "None of your devices can be reached from outside its network now. \
     At home, say this is your network, so that your router can open a port, or set up a host.";

fn device_name(d: &Daemon, key: &KeyId) -> String {
    let names = d.core().device_names();
    names
        .get(key)
        .cloned()
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| cardinal_space::account::short_key(key))
}

/// The hosting of `who` this person offered that has not ended, if any.
fn offered_to(d: &Daemon, who: &[u8; 32]) -> Option<(SpaceId, Hosting)> {
    let me = d.core().me()?;
    all(d)
        .into_iter()
        .filter(|(w, _, _, h)| w == who && h.host == me && !h.ended)
        .map(|(_, sp, _, h)| (sp, h))
        .next_back()
}

/// Offers to host a trusted contact on this person's devices that can
/// (`devices`, by name; all of them if none is named), with a quota; or,
/// where an offer stands, adds the devices named and sets the quota.
pub fn offer(
    d: &Arc<Daemon>,
    who: &str,
    devices: &[String],
    envelopes: Option<u64>,
    relay_mb: Option<u64>,
) -> anyhow::Result<Json> {
    let contact = crate::contacts::find(d, who)?;
    anyhow::ensure!(
        contact.connects(),
        "only a trusted contact can be hosted: trust {who} first"
    );
    let me = d
        .core()
        .me()
        .ok_or_else(|| anyhow::anyhow!("this device does not belong to anyone"))?;
    let able = can_host(d);
    anyhow::ensure!(!able.is_empty(), "{WHY_NOT}");
    let chosen: Vec<(KeyId, Grant)> = if devices.is_empty() {
        able.clone()
    } else {
        let mut out = Vec::new();
        for name in devices {
            let found = able
                .iter()
                .find(|(k, _)| device_name(d, k).eq_ignore_ascii_case(name));
            match found {
                Some(x) => out.push(x.clone()),
                None => anyhow::bail!(
                    "{name} cannot host anyone now: it cannot be reached from outside its network"
                ),
            }
        }
        out
    };
    let standing = offered_to(d, &contact.identity);
    let was = standing
        .as_ref()
        .and_then(|(_, h)| grants(d, &me, &contact.identity, h).into_iter().next())
        .and_then(|(_, g)| g.classes.first().cloned());
    let mut class = was.unwrap_or_else(default_class);
    if let Some(n) = envelopes {
        class.outstanding = Some(n);
        class.per_day = Some(n);
    }
    if let Some(mb) = relay_mb {
        class.relay_bytes = Some(mb * 1_000_000);
    }
    let grant_for = |g: &Grant| {
        Grant {
            host: me,
            served: contact.identity,
            services: vec![MAILBOX, RENDEZVOUS, RELAY],
            classes: vec![class.clone()],
            storage_bytes: Some(0),
            retention_days: None,
            endpoints: g.endpoints.clone(),
            link_key: g.link_key.clone(),
        }
        .sign(&d.keys.signing)
    };
    let ops = match &standing {
        None => {
            let grants: Vec<Vec<u8>> = chosen.iter().map(|(_, g)| grant_for(g)).collect();
            relationship::create_host_offer(&grants)
        }
        Some((_, h)) => {
            let have = grants(d, &me, &contact.identity, h);
            let mut ops = Vec::new();
            // the quota, on every device already serving
            for (node, g) in &have {
                if g.classes.first() != Some(&class) {
                    ops.push(relationship::set_host_serving(*node, &grant_for(g)));
                }
            }
            for (_, g) in &chosen {
                if !have.iter().any(|(_, o)| o.link_key == g.link_key) {
                    ops.push(relationship::create_host_serving(h.offer, &grant_for(g)));
                }
            }
            ops
        }
    };
    if !ops.is_empty() {
        d.write_and_push(&contact.space, ops)?;
    }
    let names: Vec<String> = chosen.iter().map(|(k, _)| device_name(d, k)).collect();
    Ok(json!({"devices": names, "sees": SEES}))
}

/// The person says yes to a contact's offer to host them.
pub fn accept(d: &Arc<Daemon>, who: &str) -> anyhow::Result<Json> {
    let contact = crate::contacts::find(d, who)?;
    anyhow::ensure!(contact.connects(), "you do not trust {who}");
    let offer = all(d)
        .into_iter()
        .filter(|(w, _, _, h)| *w == contact.identity && h.host == contact.identity && !h.ended)
        .map(|(_, _, _, h)| h)
        .next_back()
        .ok_or_else(|| anyhow::anyhow!("{who} has not offered to host you"))?;
    if !offer.accepted {
        let op = relationship::create_host_accept(offer.offer);
        d.write_and_push(&contact.space, vec![op])?;
    }
    Ok(json!({"sees": SEES}))
}

/// Either side ends a hosting, or an offer not yet answered.
pub fn end(d: &Arc<Daemon>, who: &str) -> anyhow::Result<Json> {
    let contact = crate::contacts::find(d, who)?;
    let me = d
        .core()
        .me()
        .ok_or_else(|| anyhow::anyhow!("this device does not belong to anyone"))?;
    let open: Vec<NodeId> = all(d)
        .into_iter()
        .filter(|(w, _, _, h)| *w == contact.identity && !h.ended)
        .filter(|(_, _, _, h)| h.host == me || h.host == contact.identity)
        .map(|(_, _, _, h)| h.offer)
        .collect();
    if !open.is_empty() {
        let ops = open
            .into_iter()
            .map(relationship::create_host_end)
            .collect();
        d.write_and_push(&contact.space, ops)?;
    }
    Ok(json!({"ended": true}))
}

/// Whom this person hosts, who hosts them, and the offers between, with
/// the devices that can host someone now, or why none can.
pub fn list(d: &Daemon) -> Json {
    let me = d.core().me();
    let contacts = d.core().contacts();
    let here = *d.keys.link.public_key().x25519();
    let name_of = |who: &[u8; 32]| {
        contacts
            .iter()
            .find(|c| c.identity == *who)
            .map_or_else(|| short(who), |c| c.petname.clone())
    };
    let mine: HashMap<[u8; 32], KeyId> = d
        .core()
        .mailboxes()
        .into_iter()
        .map(|(g, k)| (*g.link_key.x25519(), k))
        .collect();
    let mut out = Vec::new();
    for (who, _, _, h) in all(d) {
        if h.ended {
            continue;
        }
        let by_me = Some(h.host) == me;
        let (host, served) = if by_me {
            (me.unwrap_or_default(), who)
        } else {
            (who, me.unwrap_or_default())
        };
        let gs = grants(d, &host, &served, &h);
        let class = gs
            .first()
            .and_then(|(_, g)| g.classes.first().cloned())
            .unwrap_or_default();
        let devices: Vec<String> = match by_me {
            true => gs
                .iter()
                .map(|(_, g)| match mine.get(g.link_key.x25519()) {
                    Some(k) => device_name(d, k),
                    None => hex::encode(&g.link_key.x25519()[..4]),
                })
                .collect(),
            false => Vec::new(),
        };
        let serves_here = by_me && gs.iter().any(|(_, g)| *g.link_key.x25519() == here);
        let waiting = serves_here.then(|| {
            lock(&d.mailbox.hosted.stores)
                .get(&who)
                .map_or(0, Store::waiting)
        });
        out.push(json!({
            "accepted": h.accepted,
            "devices": devices,
            "ended": false,
            "envelopes": class.outstanding,
            "mine": by_me,
            "name": name_of(&who),
            "relay_bytes": class.relay_bytes,
            "sees": SEES,
            "waiting": waiting,
            "who": hex::encode(who),
        }));
    }
    let can: Vec<String> = can_host(d).iter().map(|(k, _)| device_name(d, k)).collect();
    let why_not = can.is_empty().then_some(WHY_NOT);
    json!({"can": can, "hosting": out, "why_not": why_not})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::Access;
    use cardinal_space::grant::Endpoint;

    /// A service in this process, with nothing running in it but what a
    /// test calls: one device of a person who has one trusted contact, Bo,
    /// whose device is a core of its own here.
    struct Two {
        d: Arc<Daemon>,
        rel: SpaceId,
        bo_id: [u8; 32],
        bo: crate::core::Core,
        bo_keys: Arc<crate::keys::Keys>,
        _dirs: [tempfile::TempDir; 2],
    }

    impl Two {
        async fn new() -> Two {
            use cardinal_space::account::{self, Regard};
            let dirs = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
            let (paths, config) = crate::testing::set_up(dirs[0].path());
            let d = Daemon::start(paths, config).await.unwrap();
            let (paths, _) = crate::testing::set_up(dirs[1].path());
            let keys = crate::keys::Keys::load_or_create(&paths.device_key()).unwrap();
            let bo_keys = Arc::new(keys);
            let mut bo = crate::core::Core::load(&paths, bo_keys.clone()).unwrap();
            let me = d.core().me().unwrap();
            let them = bo.me().unwrap();
            let log = |c: &crate::core::Core| c.identity.as_ref().unwrap().all_entries();
            let (mine, theirs) = (log(&d.core()), log(&bo));
            d.core().ingest_other(them, &theirs).unwrap();
            bo.ingest_other(me, &mine).unwrap();
            let (rel, genesis) = d.core().create_relationship(&them).unwrap();
            bo.accept_relationship(&genesis, &me).unwrap();
            let account = d.core().account_id().unwrap();
            let contact = account::create_contact(&them, "Bo", &rel, Regard::default());
            d.write_and_push(&account, vec![contact]).unwrap();
            Two {
                d,
                rel,
                bo_id: them,
                bo,
                bo_keys,
                _dirs: dirs,
            }
        }

        /// What this device wrote in the relationship reaches Bo.
        fn bo_hears(&mut self) {
            let mine = self.d.core().entries_by(&self.rel, &self.d.keys.key());
            let mine: Vec<Vec<u8>> = mine.into_iter().map(|(_, e)| e).collect();
            self.bo.ingest_space(self.rel, &mine).unwrap();
        }

        fn bo_writes(&mut self, ops: Vec<SpaceOp>) {
            let (_, entry) = self.bo.write_entry(&self.rel, ops).unwrap();
            self.d.ingest(self.rel, vec![entry], Access::Full).unwrap();
        }

        fn hostings(&self) -> Vec<Hosting> {
            let core = self.d.core();
            relationship::hostings(core.spaces[&self.rel].space.as_ref().unwrap())
        }

        /// This device can be reached, offers to host Bo, and he says yes.
        fn hosts_bo(&mut self, envelopes: Option<u64>) {
            crate::host::enable(&self.d, &["203.0.113.5:7171".to_owned()]).unwrap();
            offer(&self.d, "Bo", &[], envelopes, None).unwrap();
            self.bo_hears();
            let offer = self.hostings().last().unwrap().offer;
            self.bo_writes(vec![relationship::create_host_accept(offer)]);
            let s = serving(&self.d);
            assert!(s.iter().any(|s| s.who == self.bo_id && s.active));
        }

        /// What Bo's device asks of his mailbox here.
        fn bo_asks(&self, r: Record) -> Record {
            let device = self.bo_keys.key();
            answer_owner(&self.d, &self.bo_id, &device, &r).unwrap()
        }

        fn bo_registers(&self, t: &Token) {
            let one = Value::Record(Record::new().with(1, *t).with(2, 0u64));
            let r = Record::new()
                .with(0, mailbox::OP_REGISTER)
                .with(1, Value::list([one]));
            assert_eq!(self.bo_asks(r).get(0).and_then(Value::as_uint), Some(4));
        }

        fn bo_revokes(&self, t: &Token) {
            let r = Record::new()
                .with(0, mailbox::OP_REVOKE)
                .with(1, Value::list([Value::from(*t)]));
            self.bo_asks(r);
        }

        fn bos_store_has(&self, t: &Token) -> bool {
            let stores = lock(&self.d.mailbox.hosted.stores);
            stores.get(&self.bo_id).is_some_and(|s| s.is_active(t))
        }

        /// Another contact this device hosts, Cy, with a token active.
        fn cy_has(&self, t: &Token) -> [u8; 32] {
            let cy = [7; 32];
            let dir = self.d.mailbox.hosted.store_dir(&cy);
            let mut store = Store::load(dir).until_collected();
            store.register(t);
            lock(&self.d.mailbox.hosted.stores).insert(cy, store);
            admit(&self.d, &cy, t);
            cy
        }

        fn trusts_bo(&self, trusted: bool) {
            use cardinal_space::account;
            let account = self.d.core().account_id().unwrap();
            let node = self.d.core().contacts()[0].node;
            let set = account::set_field(node, account::TRUSTED, trusted);
            self.d.write_and_push(&account, vec![set]).unwrap();
        }
    }

    /// Review H1. A contact this device hosts cannot register a token
    /// active here for anyone else: this device's own person's, which they
    /// may know as a contact of theirs, or another contact's. Neither is
    /// then theirs to deposit, connect or relay under.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_hosted_contact_cannot_take_over_a_token_in_use_here() {
        let mut h = Two::new().await;
        h.hosts_bo(None);
        let own: Token = random_bytes();
        mailbox::register(&h.d, &own);
        h.bo_registers(&own);
        assert!(!h.bos_store_has(&own), "the host's own token was taken");
        assert!(token_owner(&h.d, &own).is_none());
        assert!(!is_hosted_token(&h.d, &own));
        assert!(deposit(&h.d, &own, b"x", now()).is_err());

        let cys: Token = random_bytes();
        h.cy_has(&cys);
        h.bo_registers(&cys);
        assert!(!h.bos_store_has(&cys), "another contact's token was taken");
        assert!(deposit(&h.d, &cys, b"x", now()).is_err());

        let his: Token = random_bytes();
        h.bo_registers(&his);
        assert!(h.bos_store_has(&his));
        assert_eq!(token_owner(&h.d, &his).map(|s| s.who), Some(h.bo_id));
        assert!(h.d.mailbox.admits(&his));
        assert!(deposit(&h.d, &his, b"x", now()).is_ok());
    }

    /// Review H1. A revoke from a contact this device hosts ends only their
    /// own tokens: neither the host's own nor another contact's stops
    /// being let in.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_hosted_contact_can_end_only_its_own_tokens() {
        let mut h = Two::new().await;
        h.hosts_bo(None);
        let own: Token = random_bytes();
        mailbox::register(&h.d, &own);
        let cys: Token = random_bytes();
        h.cy_has(&cys);
        let his: Token = random_bytes();
        h.bo_registers(&his);
        for t in [&own, &cys, &his] {
            assert!(h.d.mailbox.admits(t));
        }
        h.bo_revokes(&own);
        h.bo_revokes(&cys);
        assert!(h.d.mailbox.admits(&own), "the host's own token was ended");
        assert!(
            h.d.mailbox.admits(&cys),
            "another contact's token was ended"
        );
        assert!(h.d.mailbox.is_active(&own));
        h.bo_revokes(&his);
        assert!(!h.d.mailbox.admits(&his));
        assert!(!h.bos_store_has(&his));
    }

    /// Review H1. A token of the host's own person's is theirs even where a
    /// contact's mailbox holds it too, as one registered before refusing
    /// was: rendezvous and relay never take it for the contact's.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_hosts_own_tokens_are_never_shadowed() {
        let mut h = Two::new().await;
        h.hosts_bo(None);
        let own: Token = random_bytes();
        mailbox::register(&h.d, &own);
        open_store(&h.d, &h.bo_id);
        lock(&h.d.mailbox.hosted.stores)
            .get_mut(&h.bo_id)
            .unwrap()
            .register(&own);
        assert!(token_owner(&h.d, &own).is_none());
        assert!(!is_hosted_token(&h.d, &own));
        // and one active for two contacts is nobody's
        let both: Token = random_bytes();
        h.cy_has(&both);
        lock(&h.d.mailbox.hosted.stores)
            .get_mut(&h.bo_id)
            .unwrap()
            .register(&both);
        assert!(token_owner(&h.d, &both).is_none());
    }

    /// Review M6. The quota is for the person hosted, all their tokens
    /// together: registering more tokens gives no more room, and relay
    /// bytes are counted for them, not for each token.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_quota_is_for_the_person_hosted() {
        let mut h = Two::new().await;
        h.hosts_bo(Some(2));
        let tokens: Vec<Token> = (0..4).map(|_| random_bytes()).collect();
        for t in &tokens {
            h.bo_registers(t);
        }
        assert!(deposit(&h.d, &tokens[0], b"x", now()).is_ok());
        assert!(deposit(&h.d, &tokens[1], b"x", now()).is_ok());
        for t in &tokens {
            assert_eq!(deposit(&h.d, t, b"x", now()), Err(Refused::Full));
        }
        let class = serving(&h.d)[0].class.clone();
        let a = relay_budget(&h.d, &h.bo_id, &class).unwrap();
        let b = relay_budget(&h.d, &h.bo_id, &class).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(a.load(Ordering::Relaxed), RELAY_BYTES);
    }

    /// Review H2. A device that fetched here and was taken out of the
    /// person's log, or never was in it, holds nothing up: once those in
    /// it have collected, the envelope goes.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_device_out_of_their_log_holds_nothing_up() {
        let mut h = Two::new().await;
        h.hosts_bo(None);
        let his: Token = random_bytes();
        h.bo_registers(&his);
        let fetch = Record::new().with(0, mailbox::OP_FETCH).with(1, 0u64);
        h.bo_asks(fetch.clone());
        answer_owner(&h.d, &h.bo_id, &[9; 32], &fetch).unwrap();
        let sequence = deposit(&h.d, &his, b"x", now()).unwrap();
        h.bo_asks(Record::new().with(0, mailbox::OP_ACK).with(1, sequence));
        let waiting = || lock(&h.d.mailbox.hosted.stores)[&h.bo_id].waiting();
        assert_eq!(waiting(), 1, "the other device has not collected it");
        keep_as_host(&h.d);
        assert_eq!(waiting(), 0);
    }

    /// Review H2. Someone hosted who stops trusting their host ends the
    /// hosting, so that the host keeps nothing more for them.
    #[tokio::test(flavor = "multi_thread")]
    async fn one_who_no_longer_trusts_their_host_ends_it() {
        let mut h = Two::new().await;
        let me = h.d.core().me().unwrap();
        let grant = Grant {
            host: h.bo_id,
            served: me,
            services: vec![MAILBOX, RENDEZVOUS, RELAY],
            classes: vec![default_class()],
            storage_bytes: Some(0),
            retention_days: None,
            endpoints: vec![Endpoint::parse("192.0.2.1:7171").unwrap()],
            link_key: h.bo_keys.link.public_key().clone(),
        }
        .sign(&h.bo_keys.signing);
        h.bo_writes(relationship::create_host_offer(&[grant]));
        accept(&h.d, "Bo").unwrap();
        assert_eq!(my_hosts(&h.d).len(), 1);
        end_untrusted(&h.d);
        assert!(!h.hostings()[0].ended, "ended while trusted");
        h.trusts_bo(false);
        end_untrusted(&h.d);
        assert!(h.hostings()[0].ended);
        assert!(my_hosts(&h.d).is_empty());
    }

    /// Review M3. A hosted device presents itself and collects only on a
    /// new session or a new network, however long it waits: nothing on a
    /// timer. What failed is tried again after 30 seconds, then twice as
    /// long each time, up to 30 minutes, and at once on a new network.
    #[test]
    fn a_hosted_device_does_nothing_on_a_timer() {
        let now = Instant::now();
        let (one, two) = ([1; 32], [2; 32]);
        assert!(due(None, one, 0, now));
        let d = done(None, one, 0, true, now);
        let much_later = now + Duration::from_secs(30 * 24 * 60 * 60);
        assert!(!due(Some(&d), one, 0, much_later));
        assert!(due(Some(&d), two, 0, now), "a new session");
        assert!(due(Some(&d), one, 1, now), "a new network");
        // failures back off
        let mut last = done(None, one, 0, false, now);
        let mut waits = Vec::new();
        for _ in 0..10 {
            let a = last.again.unwrap();
            waits.push(a.wait);
            assert!(!due(Some(&last), one, 0, a.at - Duration::from_secs(1)));
            assert!(due(Some(&last), one, 0, a.at));
            assert!(due(Some(&last), one, 1, now), "a new network");
            last = done(Some(&last), one, 0, false, a.at);
        }
        assert_eq!(waits[0], RETRY.0);
        assert_eq!(waits[1], 2 * RETRY.0);
        assert_eq!(*waits.last().unwrap(), RETRY.1);
        // and a success ends the backing off
        let ok = done(Some(&last), one, 0, true, now);
        assert!(ok.again.is_none());
        assert!(!due(Some(&ok), one, 0, much_later));
    }

    /// Review M4. A device that does not help others dials no neighbours
    /// in the reconnect loop's passes; when it wakes, it does.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_device_that_does_not_help_dials_no_neighbours_on_a_timer() {
        let h = Two::new().await;
        // with a host of its own, it stays in touch with nobody for that
        crate::host::enable(&h.d, &["203.0.113.5:7171".to_owned()]).unwrap();
        let bo = h.bo_keys.key();
        let x = *h.bo_keys.link.public_key().x25519();
        h.d.neighbours.choose_now(bo, x, Instant::now());
        let has = |list: Vec<(KeyId, _)>| list.iter().any(|(k, _)| *k == bo);
        assert!(has(h.d.to_dial(true)), "on waking");
        // and its person is not turning to Bo, a contact new no longer
        lock(&h.d.rendezvous.in_use).clear();
        assert!(has(h.d.to_dial(true)), "on waking");
        assert!(!has(h.d.to_dial(false)), "on a timer");
    }
}
