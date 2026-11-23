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
//! big, and whom it relays them with; never what anything says.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
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

/// Envelopes waiting, and deposits a day, under one token, unless the host
/// says otherwise.
pub const ENVELOPES: u64 = 256;
/// Relay bytes a day under one token, unless the host says otherwise.
pub const RELAY_BYTES: u64 = 50_000_000;
/// How long what waits for a contact stays after the hosting ends.
const KEEP_AFTER_END: u64 = 7 * DAY;
const DAY: u64 = 24 * 60 * 60;
/// How often to look at what hosting asks of this device.
const LOOK_EVERY: Duration = Duration::from_secs(10);
/// How often a hosted device tells its host where it is again.
const PRESENT_EVERY: Duration = Duration::from_secs(120);
/// How often a hosted device collects its mailbox when nothing says so.
const COLLECT_EVERY: Duration = Duration::from_secs(30);
/// How often a hosted device tries to reach a host it has no session with.
const DIAL_EVERY: Duration = Duration::from_secs(30);

const OP_PRESENT: u64 = 1;
const OP_CONNECT: u64 = 2;
const OP_ANSWER: u64 = 5;
const OP_RELAY: u64 = 1;
const BUSY: u64 = 5;

/// What the person offered is told the host's devices see.
pub const SEES: &str = "The host's devices see who leaves you envelopes, when, and how big, \
     and whom you reach through them; never what anything says.";

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
    /// As a host: relay bytes left today, by token and day.
    relay: Mutex<HashMap<(Token, u64), Arc<AtomicU64>>>,
    /// As one hosted: when, and on which session, this device last
    /// presented itself to each host: a new session, which replaces one
    /// that closed, is presented on at once. And when it last
    /// collected from it, and tried to reach it.
    presented: Mutex<HashMap<[u8; 32], (Instant, Session)>>,
    collected: Mutex<HashMap<[u8; 32], Instant>>,
    dialed: Mutex<HashMap<[u8; 32], Instant>>,
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
            dialed: Mutex::default(),
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

/// Whether a token is one a contact this device hosts registered.
pub(crate) fn is_hosted_token(d: &Daemon, token: &Token) -> bool {
    lock(&d.mailbox.hosted.stores)
        .values()
        .any(|s| s.is_active(token))
}

// ---- As a host ----

/// Whose a token is, among the contacts served now, and their quota.
fn token_owner(d: &Daemon, token: &Token) -> Option<Serving> {
    let who = {
        let stores = lock(&d.mailbox.hosted.stores);
        stores
            .iter()
            .find(|(_, s)| s.is_active(token))
            .map(|(w, _)| *w)
    }?;
    serving(d).into_iter().find(|s| s.who == who && s.active)
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
    if left == Err(Refused::Full) {
        tracing::info!("{}'s mailbox here is full under one token", short(&s.who));
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
            for t in &tokens {
                store.register(t);
            }
            drop(stores);
            for t in &tokens {
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
            for t in &tokens {
                mailbox::dismiss(d, t);
                if let Some(a) = lock(&d.mailbox.hosted.admitted).get_mut(who) {
                    a.remove(t);
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
            let budget = relay_budget(d, &token, &owner.class);
            Some(Some(crate::rendezvous::relay_holder_to(
                d, s, other, budget,
            )))
        }
        _ => Some(Some(mailbox::error(mailbox::UNKNOWN))),
    }
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

/// What is left of a token's relay bytes today.
fn relay_budget(d: &Daemon, token: &Token, class: &QuotaClass) -> Option<Arc<AtomicU64>> {
    let limit = class.relay_bytes?;
    let day = now() / DAY;
    let mut all = lock(&d.mailbox.hosted.relay);
    all.retain(|(_, at), _| *at == day);
    Some(
        all.entry((*token, day))
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
            let tokens = lock(&d.mailbox.hosted.stores)
                .get(&who)
                .map(Store::active)
                .unwrap_or_default();
            for t in &tokens {
                admit(d, &who, t);
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
/// person's hosts are, and a host that no longer serves taken out.
async fn keep_as_hosted(d: &Arc<Daemon>) {
    let hosts = my_hosts(d);
    for h in &hosts {
        let key = h.key();
        let s = match d.session(&key) {
            Some(s) => s,
            None => {
                reach_host(d, h).await;
                continue;
            }
        };
        if s.is_relayed() {
            continue;
        }
        let due = |m: &Mutex<HashMap<[u8; 32], Instant>>, every: Duration| {
            let mut m = lock(m);
            let due = m.get(&key).is_none_or(|t| t.elapsed() >= every);
            if due {
                m.insert(key, Instant::now());
            }
            due
        };
        let present_now = {
            let mut m = lock(&d.mailbox.hosted.presented);
            let due = m
                .get(&key)
                .is_none_or(|(t, on)| t.elapsed() >= PRESENT_EVERY || on.is_closed());
            if due {
                m.insert(key, (Instant::now(), s.clone()));
            }
            due
        };
        if present_now {
            let ask = Record::new().with(0, OP_PRESENT).with(
                1,
                crate::rendezvous::address_list(&crate::rendezvous::local_addresses(d)),
            );
            if let Err(e) = call(&s, Service::RENDEZVOUS, ask).await {
                tracing::debug!("presenting to {}'s device: {e:#}", short(&h.who));
                lock(&d.mailbox.hosted.presented).remove(&key);
            }
        }
        if due(&d.mailbox.hosted.collected, COLLECT_EVERY) {
            match mailbox::collect_at(d, &s).await {
                Ok(0) => {}
                Ok(n) => tracing::info!("took in {n} envelopes left with {}", short(&h.who)),
                Err(e) => tracing::debug!("collecting at {}'s device: {e:#}", short(&h.who)),
            }
        }
        name(d, h, &s).await;
    }
    take_out(d, &hosts).await;
}

/// Opens a session with a host, at the addresses its grant gives.
async fn reach_host(d: &Arc<Daemon>, h: &MyHost) {
    let key = h.key();
    {
        let mut dialed = lock(&d.mailbox.hosted.dialed);
        if dialed.get(&key).is_some_and(|t| t.elapsed() < DIAL_EVERY) {
            return;
        }
        dialed.insert(key, Instant::now());
    }
    for addr in h.grant.endpoints.iter().filter_map(|e| e.socket_addr()) {
        let link = h.grant.link_key.clone();
        if let Ok(s) = d.dial(|c| Target::new(addr, c, &link)).await {
            d.on_session(s);
            lock(&d.mailbox.hosted.presented).remove(&key);
            return;
        }
    }
}

/// Names a host wherever this person's hosts are named unasked and it is
/// not named yet: only where every other member is a trusted contact (it
/// is someone's home address), never where the person said no, and only
/// once the account holds whatever no the list rests on (D75). A token is
/// registered with the host first, over the session `s`.
async fn name(d: &Arc<Daemon>, h: &MyHost, s: &Session) {
    let host = h.key();
    let _one = d.mailbox.reaching.lock().await;
    let Some(me) = d.core().me() else { return };
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
                return;
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
