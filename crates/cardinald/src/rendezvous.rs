//! Reaching a device of this person's that cannot be reached directly
//! (`hosts.md#rendezvous`, `hosts.md#relay`,
//! `hosts.md#help-from-a-persons-own-devices`).
//!
//! Devices are known by their keys, and any of them may move or sit behind a
//! NAT. Each one presents itself to the others it has a session with. A
//! device looking for another asks them, and whichever has a session with
//! both tells each where it sees the other. They send to each other at the
//! same moment, which opens a way through most NATs. If nothing comes of that
//! in three seconds, one of them asks a device to relay. The session is end to
//! end either way, and a direct one takes over as soon as there is one.
//!
//! None of this needs a host, only a device with a session to both. A host is
//! what is there when nothing else is, for a device with no session at all, and
//! a device reaches one only at an address it has seen: names stay on the
//! recovery sheet.
//!
//! A trusted contact's device does the same through the hosts that contact's
//! reach node names, with the token it gives. The host asks the person's
//! devices first, and names only those that agree, so a token says nothing of
//! who is online to anyone they would not talk to.
//!
//! Contacts are looked for only while in use (`sync.md#neighbours`): when
//! this person turns to them, or has news for them, and a while after. A
//! person's own devices help with them too, the ones they are in touch with,
//! so someone with no host of their own stays in touch with a few contacts'
//! always-on devices and is found through those.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use cardinal_crypto::{derive, random_bytes, HybridPublicKey, Purpose};
use cardinal_encoding::{Record, Value};
use cardinal_identity::KeyId;
use cardinal_link::{CarrierKind, LinkError, Priority, Service, Session, Stream, Target};
use cardinal_space::relationship::Reach;
use cardinal_space::SpaceId;
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;

use crate::core::short;
use crate::daemon::{Daemon, PeerKind};
use crate::mailbox::Token;

/// How long two devices get to reach each other before they relay.
const PUNCH_WITHIN: Duration = Duration::from_secs(3);
/// How long a host gets to answer.
const CALL_WITHIN: Duration = Duration::from_secs(5);
/// How often a device tells a host its addresses again: they can change.
const PRESENT_EVERY: Duration = Duration::from_secs(120);
/// How often a device asks its hosts about devices it cannot reach.
const ASK_EVERY: Duration = Duration::from_secs(10);
/// How often it looks for a direct way to one it reaches through a host.
const ASK_RELAYED_EVERY: Duration = Duration::from_secs(60);
/// The longest message here: a device's addresses, for each device present.
const MAX_MESSAGE: usize = 64 * 1024;
/// The most local addresses a device can report.
const MAX_LOCAL: usize = 8;
/// The most devices a device can tell of in one message.
const MAX_DEVICES: usize = 64;
/// How long a host waits for a person's devices to agree to a token holder:
/// anything but a yes in that time is a no.
const ANSWER_WITHIN: Duration = Duration::from_secs(1);
/// How long a device's agreement lets a token holder ask for a relay to it.
const AGREED_FOR: Duration = Duration::from_secs(60);
/// The least time between asks with one token: each one wakes the person's
/// devices.
const TOKEN_ASK_GAP: Duration = Duration::from_secs(1);
/// How often to look for a trusted contact this device cannot reach.
const REACH_EVERY: Duration = Duration::from_secs(30);
/// How long a contact stays in use after this person last turned to them,
/// or they rang: while they are, their devices are looked for.
const IN_USE_FOR: Duration = Duration::from_secs(600);
/// How many contacts' always-on devices a person with no host of their own
/// stays in touch with (`hosts.md#staying-reachable`).
const STANDING: usize = 3;
/// The most devices a contact's host may name: a log can name any number,
/// and each one named is sent to.
const MAX_FOUND: usize = 8;
/// The least time between looks for one contact, when a call wants them now.
const REACH_GAP: Duration = Duration::from_secs(5);
/// How long a call waits for a contact to be found.
const REACH_WITHIN: Duration = Duration::from_secs(12);
/// How far apart a contact's devices can have this one send to an address
/// they name: each time is a few handshake packets to wherever they say.
const PUNCH_FOR_CONTACT_EVERY: Duration = Duration::from_secs(5);
/// How lately a session must have been heard from to count as alive when
/// someone says the device at its other end is looking for this one.
const HEARD_LATELY: Duration = Duration::from_secs(5);
/// How often a contact is tried at one address their tag was seen at.
const NEARBY_EVERY: Duration = Duration::from_secs(10);
/// How many tries nearby one contact gets in a minute, at any addresses.
const NEARBY_PER_MINUTE: usize = 3;
/// The most nearby tries kept for each contact's trail.
const NEARBY_KEPT: usize = 20;
/// How long a look waits for a host in use for something else.
const HOST_IN_USE_FOR: Duration = Duration::from_secs(5);

const OP_ERROR: u64 = 0;
const OP_PRESENT: u64 = 1;
const OP_CONNECT: u64 = 2;
const OP_INCOMING: u64 = 3;
const OP_ADDRESSES: u64 = 4;
const OP_ANSWER: u64 = 5;
const OP_RELAY: u64 = 1;
const OP_RELAYED: u64 = 2;
const NOT_PERMITTED: u64 = 1;
const UNKNOWN: u64 = 3;
const NOT_PRESENT: u64 = 4;
const BUSY: u64 = 5;

/// An endpoint's carrier: `hosts.md#grants`.
const UDP: u64 = 1;
const TCP: u64 = 2;
/// The field of a device's local addresses, in what is said of it.
const LOCAL: u64 = 4;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// A static key: who a session is with.
type Static = [u8; 32];

/// What a device answered a token holder: itself, and yes or no.
type Answer = (Static, bool);

/// The asks waiting for answers, each with its number.
type Waiting = Vec<(u64, mpsc::UnboundedSender<Answer>)>;

/// What this device keeps about rendezvous, as a device and as a host.
#[derive(Default)]
pub struct Rendezvous {
    /// As a host: the devices present, by static key.
    present: Mutex<HashMap<[u8; 32], Presence>>,
    /// As a host: the channels it forwards, and the two devices of each.
    /// One for each pair, so at most as many as a person has pairs.
    channels: Mutex<HashMap<u32, [[u8; 32]; 2]>>,
    /// When this device last presented itself to each of its devices.
    presented: Mutex<HashMap<[u8; 32], Instant>>,
    /// The devices being reached right now, and at what addresses. A device
    /// that moved meanwhile has others, and those must not wait.
    meeting: Mutex<HashSet<(KeyId, Vec<SocketAddr>)>>,
    /// When this device last asked its hosts.
    asked: Mutex<Option<Instant>>,
    /// As a host: the token holders waiting for a person's devices to agree,
    /// by the holder's static key, and where the answers go.
    answers: Mutex<HashMap<Static, Waiting>>,
    /// As a host: a number for each ask, so two from one holder keep apart.
    asks: std::sync::atomic::AtomicU64,
    /// As a host: which device agreed to which token holder, and when.
    agreed: Mutex<HashMap<(Static, Static), Instant>>,
    /// As a host: when each holder last asked with each token. Per holder, so
    /// someone else with the same token cannot keep the holder waiting; a
    /// token holds only so many sessions at once.
    token_asked: Mutex<HashMap<(Token, Static), Instant>>,
    /// Sessions with contacts' hosts that relays to them run through, by
    /// host, and whose host each is.
    paths: Mutex<HashMap<Static, (Static, Session)>>,
    /// When each contact was last looked for.
    looked: Mutex<HashMap<[u8; 32], Instant>>,
    /// The contacts being looked for right now.
    looking: Mutex<HashSet<[u8; 32]>>,
    /// When this person last turned to each contact, and when that was last
    /// saved, as seconds since 1970.
    in_use: Mutex<HashMap<[u8; 32], (Instant, u64)>>,
    /// Where that is kept, so a device restarted mid-conversation still
    /// looks for whom it was talking to.
    in_use_path: Option<PathBuf>,
    /// The contacts this device has known of: one it learns of, made on
    /// another of the person's devices or before this one joined, is in use
    /// for a while, as one met here is.
    known: Mutex<HashSet<[u8; 32]>>,
    /// Contacts' devices whose session did not answer when asked, by static
    /// key: looked for as if there were none, until a new one opens.
    suspect: Mutex<HashSet<[u8; 32]>>,
    /// When a contact's device last had this one send to an address it named.
    punched_for: Mutex<HashMap<[u8; 32], Instant>>,
    /// How each contact was last looked for, and their sessions coming and
    /// going: what `contact-status` shows.
    trails: Mutex<HashMap<[u8; 32], Trail>>,
    /// When each contact was last tried at an address whose advertisement
    /// carried their tag (D74): at most once in [`NEARBY_EVERY`].
    nearby: Mutex<HashMap<([u8; 32], String), Instant>>,
    /// When each contact was tried nearby in the last minute, whatever the
    /// address, by carrier: at most [`NEARBY_PER_MINUTE`] on each. A tag can
    /// be replayed anywhere, and that is to cost a try and no more, and a
    /// tag replayed over Bluetooth does not use up the tries on the LAN.
    nearby_tries: Mutex<HashMap<([u8; 32], Carrier), Tries>>,
    /// The contacts being tried nearby right now, by carrier: apart from the
    /// looks through hosts, which a replayed tag must not keep from running.
    nearby_going: Mutex<HashSet<([u8; 32], Carrier)>>,
    /// Places where a contact's tag led to a session: tried again there
    /// whatever the minute's tries, at most [`NEARBY_REACHED`] kept.
    nearby_reached: Mutex<std::collections::VecDeque<([u8; 32], String)>>,
}

/// When something was tried in the last minute.
type Tries = std::collections::VecDeque<Instant>;

/// Which way a contact's tag was seen: each has its own tries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Carrier {
    /// The local network.
    Lan,
    /// Bluetooth.
    Ble,
}

/// The most places kept where a tag led to a session.
const NEARBY_REACHED: usize = 64;

/// The most sessions opening and closing kept for each contact.
const EVENTS: usize = 20;
/// The most steps kept of one look.
const STEPS: usize = 40;

/// One thing that happened in reaching a contact.
#[derive(Clone, Debug)]
pub struct Step {
    /// When, in milliseconds since 1970.
    pub at: u64,
    /// Whether it worked, where that means anything.
    pub ok: Option<bool>,
    /// What happened, in words.
    pub text: String,
}

/// What is kept of reaching one contact.
#[derive(Clone, Debug, Default)]
pub struct Trail {
    /// The steps of the latest look, in order.
    pub look: Vec<Step>,
    /// How many looks since a session with them last opened.
    pub looks: u64,
    /// When the first of those was, in milliseconds since 1970.
    pub looking_since: Option<u64>,
    /// Their sessions opening and closing, the newest last.
    pub events: std::collections::VecDeque<Step>,
    /// Tries at an address where their tag was seen on the local network
    /// (D74), the newest last: apart from the looks, which a tag seen does
    /// not overwrite.
    pub nearby: std::collections::VecDeque<Step>,
}

fn unix_ms() -> u64 {
    let since = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
    since.map_or(0, |t| t.as_millis() as u64)
}

fn in_use_for() -> Duration {
    std::env::var("CARDINAL_TEST_IN_USE_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .map_or(IN_USE_FOR, Duration::from_secs)
}

/// What is kept of the contacts in use, and of those this device knows.
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct InUseFile {
    #[serde(default)]
    in_use: HashMap<String, u64>,
    #[serde(default)]
    known: Vec<String>,
}

fn unix_now() -> u64 {
    let since = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
    since.map_or(0, |t| t.as_secs())
}

/// How often one contact's use is saved: only roughly, for after a restart.
const SAVE_USE_EVERY: u64 = 60;

impl Rendezvous {
    /// Whether a contact may be tried where their tag was seen, noting the
    /// try: once in [`NEARBY_EVERY`] at one place, and, at places not
    /// `known` (where no session was reached before), [`NEARBY_PER_MINUTE`]
    /// times a minute on each carrier.
    fn may_try_nearby(&self, who: [u8; 32], carrier: Carrier, place: &str, known: bool) -> bool {
        let mut tried = lock(&self.nearby);
        let recent = tried
            .get(&(who, place.to_owned()))
            .is_some_and(|t| t.elapsed() < NEARBY_EVERY);
        if recent {
            return false;
        }
        if !known {
            let mut tries = lock(&self.nearby_tries);
            tries.retain(|_, q| {
                q.back()
                    .is_some_and(|t| t.elapsed() < Duration::from_secs(60))
            });
            let mine = tries.entry((who, carrier)).or_default();
            while mine
                .front()
                .is_some_and(|t| t.elapsed() >= Duration::from_secs(60))
            {
                mine.pop_front();
            }
            if mine.len() >= NEARBY_PER_MINUTE {
                return false;
            }
            mine.push_back(Instant::now());
        }
        tried.retain(|_, t| t.elapsed() < NEARBY_EVERY);
        tried.insert((who, place.to_owned()), Instant::now());
        true
    }

    /// With what was saved at `path` of the contacts in use.
    pub fn load(path: PathBuf) -> Rendezvous {
        let file: InUseFile = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let known = file
            .known
            .iter()
            .filter_map(|w| hex::decode(w).ok()?.try_into().ok())
            .collect();
        let saved = file.in_use;
        let (now, at) = (Instant::now(), unix_now());
        let in_use = saved
            .into_iter()
            .filter_map(|(who, when)| {
                let who: [u8; 32] = hex::decode(who).ok()?.try_into().ok()?;
                let ago = Duration::from_secs(at.checked_sub(when)?);
                let since = now.checked_sub(ago)?;
                (ago < in_use_for()).then_some((who, (since, when)))
            })
            .collect();
        Rendezvous {
            in_use: Mutex::new(in_use),
            in_use_path: Some(path),
            known: Mutex::new(known),
            ..Default::default()
        }
    }

    /// Notes the contacts this device knows of now, and uses each it did
    /// not know before.
    pub fn knows(&self, contacts: impl IntoIterator<Item = [u8; 32]>) {
        let new: Vec<[u8; 32]> = {
            let mut known = lock(&self.known);
            contacts.into_iter().filter(|c| known.insert(*c)).collect()
        };
        if new.is_empty() {
            return;
        }
        let at = unix_now();
        {
            let mut used = lock(&self.in_use);
            for who in new {
                used.insert(who, (Instant::now(), at));
            }
        }
        self.save();
    }

    /// Saves the contacts in use and those this device knows of.
    fn save(&self) {
        let Some(path) = &self.in_use_path else {
            return;
        };
        let in_use = lock(&self.in_use)
            .iter()
            .filter(|(_, (t, _))| t.elapsed() < in_use_for())
            .map(|(w, (_, s))| (hex::encode(w), *s))
            .collect();
        let known = lock(&self.known).iter().map(hex::encode).collect();
        let b = serde_json::to_vec(&InUseFile { in_use, known }).unwrap_or_default();
        if let Err(e) = crate::paths::write_private(path, &b, 0o600) {
            tracing::debug!("saving the contacts in use: {e}");
        }
    }

    /// This person turned to a contact: opened their conversation, wrote to
    /// them, called, or was rung by them.
    pub fn use_contact(&self, who: &[u8; 32]) {
        let at = unix_now();
        let save = {
            let mut used = lock(&self.in_use);
            let saved = used.get(who).map_or(0, |(_, s)| *s);
            let save = at.saturating_sub(saved) >= SAVE_USE_EVERY;
            used.insert(*who, (Instant::now(), if save { at } else { saved }));
            save
        };
        if save {
            self.save();
        }
    }

    /// A contact's device whose session did not answer: it may be one left
    /// on a network that device has since left.
    pub fn suspect(&self, device: &[u8; 32]) {
        lock(&self.suspect).insert(*device);
    }

    /// A session opened with a device, which answers for it now.
    pub fn opened(&self, device: &[u8; 32]) {
        lock(&self.suspect).remove(device);
    }

    /// Starts a new look for a contact, forgetting the steps of the last.
    fn look_begins(&self, who: &[u8; 32], text: String) {
        let mut trails = lock(&self.trails);
        let t = trails.entry(*who).or_default();
        let at = unix_ms();
        t.look = vec![Step { at, ok: None, text }];
        t.looks += 1;
        t.looking_since.get_or_insert(at);
    }

    /// A step of the look for a contact under way.
    fn step(&self, who: &[u8; 32], ok: Option<bool>, text: String) {
        let mut trails = lock(&self.trails);
        let t = trails.entry(*who).or_default();
        if t.look.len() < STEPS {
            t.look.push(Step {
                at: unix_ms(),
                ok,
                text,
            });
        }
    }

    /// A session with one of a contact's devices opened or closed.
    pub fn event(&self, who: &[u8; 32], opened: bool, text: String) {
        let mut trails = lock(&self.trails);
        let t = trails.entry(*who).or_default();
        if opened {
            t.looks = 0;
            t.looking_since = None;
        }
        t.events.push_back(Step {
            at: unix_ms(),
            ok: Some(opened),
            text,
        });
        while t.events.len() > EVENTS {
            t.events.pop_front();
        }
    }

    /// A try at an address where a contact's tag was seen.
    fn nearby_step(&self, who: &[u8; 32], ok: Option<bool>, text: String) {
        let mut trails = lock(&self.trails);
        let t = trails.entry(*who).or_default();
        t.nearby.push_back(Step {
            at: unix_ms(),
            ok,
            text,
        });
        while t.nearby.len() > NEARBY_KEPT {
            t.nearby.pop_front();
        }
    }

    /// What is kept of reaching a contact.
    pub fn trail(&self, who: &[u8; 32]) -> Trail {
        lock(&self.trails).get(who).cloned().unwrap_or_default()
    }

    /// How long ago a contact was last looked for, and whether a look is
    /// under way.
    pub fn looked(&self, who: &[u8; 32]) -> (Option<Duration>, bool) {
        let ago = lock(&self.looked).get(who).map(Instant::elapsed);
        (ago, lock(&self.looking).contains(who))
    }

    /// How much longer a contact stays in use, if they are.
    pub fn in_use_left(&self, who: &[u8; 32]) -> Option<Duration> {
        let used = lock(&self.in_use);
        let (t, _) = used.get(who)?;
        in_use_for().checked_sub(t.elapsed())
    }

    /// How often a contact in use is looked for, while no session with each
    /// of their devices is open.
    pub fn look_every() -> Duration {
        REACH_EVERY
    }

    /// Whether a contact is in use, and so to be looked for.
    pub fn in_use(&self, who: &[u8; 32]) -> bool {
        let used = lock(&self.in_use);
        used.get(who)
            .is_some_and(|(t, _)| t.elapsed() < in_use_for())
    }

    /// Whether a relay to a contact runs through a session with this host,
    /// which a second session would end.
    pub fn holds(&self, host: &[u8; 32]) -> bool {
        lock(&self.paths)
            .get(host)
            .is_some_and(|(_, s)| !s.is_closed())
    }
}

struct Presence {
    session: Session,
    local: Vec<SocketAddr>,
}

/// Where another device can be tried.
struct Found {
    device: [u8; 32],
    observed: Option<SocketAddr>,
    local: Vec<SocketAddr>,
}

impl Found {
    /// Local addresses first: they work if the two share a network.
    fn addresses(&self) -> Vec<SocketAddr> {
        let mut v = self.local.clone();
        v.extend(self.observed.filter(|o| !self.local.contains(o)));
        v
    }
}

fn address_record(a: &SocketAddr) -> Record {
    let ip = match a.ip() {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    };
    Record::new()
        .with(1, UDP)
        .with(2, ip)
        .with(3, a.port() as u64)
}

fn read_address(v: &Value) -> Option<SocketAddr> {
    let r = v.as_record()?;
    // A carrier this version does not know says itself what its other
    // fields hold: such an address is skipped (`hosts.md#grants`).
    if !matches!(r.get(1)?.as_uint()?, UDP | TCP) {
        return None;
    }
    let ip: IpAddr = match r.get(2)?.as_bytes()?.len() {
        4 => <[u8; 4]>::try_from(r.get(2)?.as_bytes()?).ok()?.into(),
        16 => <[u8; 16]>::try_from(r.get(2)?.as_bytes()?).ok()?.into(),
        _ => return None,
    };
    let port = u16::try_from(r.get(3)?.as_uint()?).ok()?;
    Some(SocketAddr::new(ip, port))
}

fn address_list(addresses: &[SocketAddr]) -> Value {
    Value::list(addresses.iter().map(|a| Value::Record(address_record(a))))
}

fn read_addresses(v: Option<&Value>) -> Vec<SocketAddr> {
    v.and_then(Value::as_list)
        .unwrap_or_default()
        .iter()
        .take(MAX_LOCAL)
        .filter_map(read_address)
        .collect()
}

fn found_record(f: &Found) -> Record {
    Record::new()
        .with(1, f.device)
        .with_opt(
            2,
            f.observed
                .as_ref()
                .map(|a| Value::Record(address_record(a))),
        )
        .with(LOCAL, address_list(&f.local))
}

fn read_found(r: &Record) -> Option<Found> {
    Some(Found {
        device: r.get(1)?.as_bytes()?.try_into().ok()?,
        observed: r.get(2).and_then(read_address),
        local: read_addresses(r.get(LOCAL)),
    })
}

/// Where a host sees a device, if a packet can be sent back there: over TCP
/// the port says nothing about the device's UDP socket.
fn observed(s: &Session) -> Option<SocketAddr> {
    let udp = s.carrier() == Some(CarrierKind::Udp) && !s.is_relayed();
    s.remote_addr().filter(|_| udp)
}

/// The addresses this device has on its own networks, and the one its
/// router gave it outside, if it gave one.
fn local_addresses(d: &Daemon) -> Vec<SocketAddr> {
    let Some(udp) = d.endpoint.udp_addr() else {
        return Vec::new();
    };
    let mut all: Vec<SocketAddr> = if udp.ip().is_unspecified() {
        let ips = crate::daemon::local_ips();
        ips.into_iter()
            .map(|ip| SocketAddr::new(ip, udp.port()))
            .collect()
    } else {
        vec![udp]
    };
    all.extend(crate::portmap::external(d).filter(|e| !all.contains(e)));
    all
}

/// The sessions with this person's devices that can help: one hop, so not
/// one that itself goes through a device.
fn helpers(d: &Daemon) -> Vec<Session> {
    let sessions = d.own_sessions().into_iter();
    sessions.filter(|s| !s.is_relayed()).collect()
}

/// The devices of this person's with no direct session, by static key.
fn wanted(d: &Daemon) -> HashMap<[u8; 32], (KeyId, HybridPublicKey)> {
    let devices: Vec<(KeyId, HybridPublicKey)> = {
        let core = d.core();
        let Some(ident) = core.identity.as_ref() else {
            return HashMap::new();
        };
        ident
            .state()
            .keys
            .values()
            .filter(|k| k.key != d.keys.key())
            .filter_map(|k| Some((k.key, k.link_key.clone()?)))
            .collect()
    };
    devices
        .into_iter()
        .filter(|(_, link)| !d.is_direct_ip(link.x25519()))
        .map(|(key, link)| (*link.x25519(), (key, link)))
        .collect()
}

/// A session with one of this person's devices opened: this device presents
/// itself, and asks after the ones it cannot reach.
pub async fn session_opened(d: Arc<Daemon>, s: Session) {
    if !s.is_relayed() {
        present(&d, &s).await;
        ask(&d, &s).await;
    }
}

/// Tells one of this person's devices that this one is here, at what
/// addresses, and where the others have been reached.
async fn present(d: &Daemon, s: &Session) {
    let ask = Record::new()
        .with(0, OP_PRESENT)
        .with(1, address_list(&local_addresses(d)));
    // Whatever the answer: a device on an older version knows nothing of
    // this, and would be asked on every pass of the reconnect loop.
    lock(&d.rendezvous.presented).insert(s.peer_static(), Instant::now());
    match call(s, Service::RENDEZVOUS, ask).await {
        Ok(r) if r.get(0).and_then(Value::as_uint) == Some(OP_PRESENT) => {}
        Ok(_) => tracing::debug!("{} refused", short(&s.peer_static())),
        Err(e) => tracing::debug!("presenting to {}: {e:#}", short(&s.peer_static())),
    }
    let known: Vec<Value> = d
        .addresses_to_share()
        .iter()
        .take(MAX_DEVICES)
        .map(|(device, addresses)| {
            let r = Record::new().with(1, *device);
            Value::Record(r.with(2, address_list(addresses)))
        })
        .collect();
    let tell = Record::new()
        .with(0, OP_ADDRESSES)
        .with(1, Value::list(known));
    tell_device(s.clone(), Service::RENDEZVOUS, tell);
}

/// Sends a message that has no reply.
fn tell_device(s: Session, service: Service, message: Record) {
    tokio::spawn(async move {
        if let Ok(mut st) = s.open_stream(service, Priority::Interactive) {
            let _ = st.send_message(&Value::Record(message)).await;
            let _ = st.shutdown().await;
        }
    });
}

/// Presents this device where it has not lately: addresses change.
async fn stay_present(d: &Daemon) {
    for s in helpers(d) {
        let due = lock(&d.rendezvous.presented)
            .get(&s.peer_static())
            .is_none_or(|t| t.elapsed() >= PRESENT_EVERY);
        if due {
            present(d, &s).await;
        }
    }
}

/// Asks a device something and waits a while for its answer.
pub(crate) async fn call(s: &Session, service: Service, ask: Record) -> anyhow::Result<Record> {
    let exchange = async {
        let mut st = s.open_stream(service, Priority::Interactive)?;
        st.send_message(&Value::Record(ask)).await?;
        st.shutdown().await?;
        let v = st
            .recv_message_max(MAX_MESSAGE)
            .await?
            .ok_or_else(|| anyhow::anyhow!("no reply"))?;
        v.as_record()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("not a record"))
    };
    tokio::time::timeout(CALL_WITHIN, exchange)
        .await
        .map_err(|_| anyhow::anyhow!("no answer in time"))?
}

/// Asks this person's devices after those it cannot reach directly. It costs
/// a message each, so not on every pass of the reconnect loop.
pub async fn ask_helpers(d: Arc<Daemon>) {
    stay_present(&d).await;
    let every = {
        let wanted = wanted(&d);
        if wanted.is_empty() {
            return;
        }
        if wanted.keys().any(|x| !d.is_online(x)) {
            ASK_EVERY
        } else {
            ASK_RELAYED_EVERY
        }
    };
    {
        let mut asked = lock(&d.rendezvous.asked);
        if asked.is_some_and(|t| t.elapsed() < every) {
            return;
        }
        *asked = Some(Instant::now());
    }
    for s in helpers(&d) {
        ask(&d, &s).await;
    }
}

async fn ask(d: &Arc<Daemon>, s: &Session) {
    let wanted = wanted(d);
    if wanted.is_empty() {
        return;
    }
    let ask = Record::new().with(0, OP_CONNECT).with(2, d.keys.key());
    let reply = match call(s, Service::RENDEZVOUS, ask).await {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!("asking {}: {e:#}", short(&s.peer_static()));
            return;
        }
    };
    for r in reply.record_list(1).unwrap_or_default() {
        let Some(found) = read_found(r) else {
            continue;
        };
        if let Some((device, link)) = wanted.get(&found.device) {
            let addresses = found.addresses();
            let (d, device, link) = (d.clone(), *device, link.clone());
            tokio::spawn(async move { meet(d, device, link, addresses).await });
        }
    }
}

/// Reaches a device from what another said of it: directly if that can be
/// done, and through one of them if not.
async fn meet(d: Arc<Daemon>, device: KeyId, link: HybridPublicKey, addresses: Vec<SocketAddr>) {
    let meeting = (device, addresses.clone());
    if !lock(&d.rendezvous.meeting).insert(meeting.clone()) {
        return;
    }
    punch(&d, &link, addresses).await;
    // One of the two asks, and either can tell which.
    let mine = *d.keys.link.public_key().x25519();
    if mine < *link.x25519() {
        for helper in helpers(&d) {
            if d.is_online(link.x25519()) {
                break;
            }
            if helper.peer_static() == *link.x25519() {
                continue;
            }
            let ask = Record::new().with(0, OP_RELAY).with(2, device);
            match relay(&d, &helper, ask, &device, &link).await {
                Ok(()) => break,
                Err(e) => tracing::debug!("relaying to {}: {e:#}", short(&device)),
            }
        }
    }
    lock(&d.rendezvous.meeting).remove(&meeting);
}

/// Sends to every address at once. The other device is doing the same, so
/// that each one's packets open its own NAT to the other's.
async fn punch(d: &Arc<Daemon>, link: &HybridPublicKey, addresses: Vec<SocketAddr>) {
    let (done, give_up) = watch::channel(false);
    let mut tries = JoinSet::new();
    for addr in addresses {
        let target = Target::new(addr, CarrierKind::Udp, link)
            .within(PUNCH_WITHIN)
            .unless(give_up.clone());
        let d = d.clone();
        tries.spawn(async move { d.endpoint.connect(target).await });
    }
    while let Some(tried) = tries.join_next().await {
        match tried {
            // The first to complete wins; a later one would replace it.
            Ok(Ok(s)) => {
                let _ = done.send(true);
                tracing::info!("reached {} at {:?}", short(link.x25519()), s.remote_addr());
                d.on_session(s);
            }
            Ok(Err(LinkError::Closed(_))) | Err(_) => {}
            Ok(Err(e)) => tracing::debug!("punching to {}: {e}", short(link.x25519())),
        }
    }
}

async fn relay(
    d: &Arc<Daemon>,
    helper: &Session,
    ask: Record,
    device: &KeyId,
    link: &HybridPublicKey,
) -> anyhow::Result<()> {
    let reply = call(helper, Service::RELAY, ask).await?;
    anyhow::ensure!(
        reply.get(0).and_then(Value::as_uint) == Some(OP_RELAY),
        "refused"
    );
    let channel = reply
        .get(1)
        .and_then(Value::as_uint)
        .and_then(|c| u32::try_from(c).ok())
        .ok_or_else(|| anyhow::anyhow!("no channel"))?;
    if reached(d, link.x25519()) {
        return Ok(());
    }
    let at = helper
        .remote_addr()
        .ok_or_else(|| anyhow::anyhow!("no address"))?;
    let target = Target::new(at, CarrierKind::Udp, link)
        .through(helper, channel)
        .within(PUNCH_WITHIN);
    match d.endpoint.connect(target).await {
        Ok(s) => {
            tracing::info!("reached {} through a relay", short(device));
            d.on_session(s);
            Ok(())
        }
        // One the other device opened at the same moment won.
        Err(LinkError::Closed(cardinal_link::CloseReason::Replaced))
            if reached(d, link.x25519()) =>
        {
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

/// Serves the rendezvous and relay services on a stream from one of this
/// person's devices, or from someone with a token this device serves.
pub async fn serve(d: &Arc<Daemon>, s: &Session, mut st: Stream) -> anyhow::Result<()> {
    let Some(v) = st.recv_message_max(MAX_MESSAGE).await? else {
        return Ok(());
    };
    let Some(r) = v.as_record() else {
        return Ok(());
    };
    let op = r.get(0).and_then(Value::as_uint);
    let kind = d.classify(s);
    if let PeerKind::Contact(who, _) = kind {
        // One of their devices helps another of theirs to this one.
        let rendezvous = st.service() == Service::RENDEZVOUS;
        if rendezvous && op == Some(OP_INCOMING) && r.get(3).is_none() {
            contact_incoming(d, &who, r);
            return Ok(());
        }
        if !rendezvous && op == Some(OP_RELAYED) {
            return Ok(());
        }
    }
    let reply = if !matches!(kind, PeerKind::Own(_)) {
        let rendezvous = st.service() == Service::RENDEZVOUS;
        match holder_token(d, &kind, r) {
            None => Some(error(NOT_PERMITTED)),
            Some(token) if rendezvous && op == Some(OP_CONNECT) => {
                Some(connect_holder(d, s, token).await)
            }
            Some(_) if !rendezvous && op == Some(OP_RELAY) => {
                // Only a device that helps others now: plugged in, and not
                // on a metered network (`hosts.md#relay`).
                if !d.conditions.helps() {
                    Some(error(BUSY))
                } else {
                    Some(relay_holder(d, s, r))
                }
            }
            Some(_) => Some(error(UNKNOWN)),
        }
    } else if st.service() == Service::RENDEZVOUS {
        match op {
            Some(OP_INCOMING) => {
                incoming(d, s, r);
                None
            }
            Some(OP_ANSWER) => {
                answered(d, s, r);
                None
            }
            Some(OP_ADDRESSES) => {
                heard_addresses(d, r);
                None
            }
            Some(OP_PRESENT) => {
                let local = read_addresses(r.get(1));
                if let PeerKind::Own(device) = &kind {
                    d.keep_outside(device, &local);
                }
                let session = s.clone();
                let presence = Presence { session, local };
                lock(&d.rendezvous.present).insert(s.peer_static(), presence);
                Some(Record::new().with(0, OP_PRESENT))
            }
            Some(OP_CONNECT) => Some(match identity_field(r.get(3)) {
                Some(who) => connect_contact(s, d, &who),
                None => connect(s, d),
            }),
            _ => Some(error(UNKNOWN)),
        }
    } else {
        match op {
            Some(OP_RELAYED) => None,
            Some(OP_RELAY) if !d.conditions.helps() => Some(error(BUSY)),
            Some(OP_RELAY) => Some(open_relay(d, s, r)),
            _ => Some(error(UNKNOWN)),
        }
    };
    if let Some(reply) = reply {
        st.send_message(&Value::Record(reply)).await?;
        st.shutdown().await?;
    }
    Ok(())
}

fn error(code: u64) -> Record {
    Record::new().with(0, OP_ERROR).with(1, code)
}

/// Tells every device present of `s`, and `s` of them.
fn connect(s: &Session, d: &Daemon) -> Record {
    let me = s.peer_static();
    let mut present = lock(&d.rendezvous.present);
    present.retain(|_, p| !p.session.is_closed());
    let asker = Found {
        device: me,
        observed: observed(s),
        local: present
            .get(&me)
            .map(|p| p.local.clone())
            .unwrap_or_default(),
    };
    let tell = found_record(&asker).with(0, OP_INCOMING);
    let mut found = Vec::new();
    for (device, p) in present.iter().filter(|(k, _)| **k != me) {
        found.push(Value::Record(found_record(&Found {
            device: *device,
            observed: observed(&p.session),
            local: p.local.clone(),
        })));
        tell_device(p.session.clone(), Service::RENDEZVOUS, tell.clone());
    }
    Record::new()
        .with(0, OP_CONNECT)
        .with(1, Value::list(found))
}

/// Another of this person's devices says one is looking for this one: one
/// of the person's own, or someone with a token.
fn incoming(d: &Arc<Daemon>, s: &Session, r: &Record) {
    let token = r.get(3).and_then(Value::as_bytes);
    if let Some(token) = token.and_then(|t| Token::try_from(t).ok()) {
        return holder_incoming(d, s, r, &token);
    }
    let Some(found) = read_found(r) else {
        return;
    };
    if let Some((device, link)) = wanted(d).remove(&found.device) {
        tokio::spawn(meet(d.clone(), device, link, found.addresses()));
    }
}

/// Another of this person's devices says where it has reached the others.
fn heard_addresses(d: &Daemon, r: &Record) {
    for r in r
        .record_list(1)
        .unwrap_or_default()
        .iter()
        .take(MAX_DEVICES)
    {
        let device: Option<KeyId> = r
            .get(1)
            .and_then(Value::as_bytes)
            .and_then(|b| b.try_into().ok());
        if let Some(device) = device {
            d.hear_addresses(&device, &read_addresses(r.get(2)));
        }
    }
}

/// Opens a channel between `s` and the device it names. Neither may itself
/// go through a device: help goes one hop.
fn open_relay(d: &Daemon, s: &Session, r: &Record) -> Record {
    let Some(device) = r.get(2).and_then(Value::as_bytes) else {
        return error(UNKNOWN);
    };
    match present_device(d, device).or_else(|| contact_session(d, device)) {
        Some(other) => open_channel(d, s, &other),
        None => error(NOT_PRESENT),
    }
}

fn identity_field(v: Option<&Value>) -> Option<[u8; 32]> {
    v?.as_bytes()?.try_into().ok()
}

/// Whether a contact's device has a session that answers for it: one that
/// may be left behind is no session when looking for them.
///
/// A session over Bluetooth alone is not: it holds while the two are in
/// range, and the looks go on for a way that does not end there; one found
/// replaces it (`Endpoint` prefers a direct session over IP).
fn reached(d: &Daemon, device: &[u8; 32]) -> bool {
    d.is_online(device)
        && !d.is_bluetooth_only(device)
        && !lock(&d.rendezvous.suspect).contains(device)
}

/// A direct session with a trusted contact's device, by its signing key, for
/// one of this person's own devices to be helped to.
fn contact_session(d: &Daemon, device: &[u8]) -> Option<Session> {
    let theirs = d.contacts_in_touch().into_iter();
    theirs.map(|(_, s)| s).find(|o| {
        !o.is_relayed()
            && o.peer_identity()
                .is_some_and(|p| p.signing_key.as_slice() == device)
    })
}

/// One of this person's devices looks for a contact's: each of theirs in
/// touch here is told where that one is, and that one where they are. Only
/// devices with a direct session here: help goes one hop.
fn connect_contact(s: &Session, d: &Daemon, who: &[u8; 32]) -> Record {
    let asker = observed(s);
    let mut found = Vec::new();
    let theirs = d.contacts_in_touch().into_iter();
    for (_, o) in theirs.filter(|(i, o)| i == who && !o.is_relayed()) {
        found.push(Value::Record(found_record(&Found {
            device: o.peer_static(),
            observed: observed(&o),
            local: Vec::new(),
        })));
        let mut tell = Record::new().with(0, OP_INCOMING).with(1, s.peer_static());
        if let Some(at) = asker {
            tell = tell.with(2, Value::Record(address_record(&at)));
        }
        tell_device(o, Service::RENDEZVOUS, tell);
    }
    tracing::debug!("helping to {} of {}'s devices", found.len(), short(who));
    Record::new()
        .with(0, OP_CONNECT)
        .with(1, Value::list(found))
}

/// A trusted contact's device says another of that person's devices is
/// looking for this one, and where it is. Only a device of the same person:
/// nobody can aim this one at a third party.
fn contact_incoming(d: &Arc<Daemon>, who: &[u8; 32], r: &Record) {
    let Some(x) = identity_field(r.get(1)) else {
        return;
    };
    let Some(at) = r.get(2).and_then(read_address) else {
        return;
    };
    let Some((_, link)) = contact_device(d, who, &x) else {
        return;
    };
    let trusted = d
        .core()
        .contacts()
        .iter()
        .any(|c| c.identity == *who && c.connects());
    if !trusted {
        return;
    }
    // A session that was heard from a moment ago is alive, whatever they
    // think: a second would only end it, and a call on it. One that has gone
    // quiet may be left on a network theirs has left.
    if let Some(s) = d.session(link.x25519()) {
        if s.last_heard().elapsed() < HEARD_LATELY {
            return;
        }
        d.rendezvous.suspect(link.x25519());
    }
    // Packets to an address only they vouch for: not as often as they like.
    {
        let mut punched = lock(&d.rendezvous.punched_for);
        punched.retain(|_, t| t.elapsed() < PUNCH_FOR_CONTACT_EVERY);
        if punched.contains_key(who) {
            return;
        }
        punched.insert(*who, Instant::now());
    }
    // They turned to this person: look for them again if this goes.
    d.rendezvous.use_contact(who);
    tracing::debug!("{} is looking for this device", short(&x));
    let d = d.clone();
    tokio::spawn(async move { punch(&d, &link, vec![at]).await });
}

/// The session of a device present here, by its signing key.
fn present_device(d: &Daemon, device: &[u8]) -> Option<Session> {
    let present = lock(&d.rendezvous.present);
    present.values().map(|p| p.session.clone()).find(|o| {
        !o.is_closed()
            && o.peer_identity()
                .is_some_and(|p| p.signing_key.as_slice() == device)
    })
}

/// Opens a channel between `s` and `other`, or finds the one they have.
fn open_channel(d: &Daemon, s: &Session, other: &Session) -> Record {
    if s.is_closed() || s.is_relayed() || other.is_relayed() {
        return error(NOT_PRESENT);
    }
    let (mine, theirs) = (s.peer_static(), other.peer_static());
    let channel = {
        let mut channels = lock(&d.rendezvous.channels);
        let known = channels
            .iter()
            .find(|(_, v)| v.contains(&mine) && v.contains(&theirs))
            .map(|(c, _)| *c);
        let channel = known.unwrap_or_else(|| loop {
            let c = u32::from_le_bytes(random_bytes::<4>());
            if !channels.contains_key(&c) {
                break c;
            }
        });
        channels.insert(channel, [mine, theirs]);
        channel
    };
    d.endpoint.relay_open(channel, s, other);
    let tell = Record::new()
        .with(0, OP_RELAYED)
        .with(1, channel as u64)
        .with(2, s.peer_static());
    tell_device(other.clone(), Service::RELAY, tell);
    Record::new().with(0, OP_RELAY).with(1, channel as u64)
}

/// The token a request names, if whoever asks may use it here: on a session
/// opened with that token, or a trusted contact's, and only while it is active.
fn holder_token(d: &Daemon, kind: &PeerKind, r: &Record) -> Option<Token> {
    let token = Token::try_from(r.get(1)?.as_bytes()?).ok()?;
    let allowed = match kind {
        PeerKind::Token(t) => *t == token,
        PeerKind::Contact(..) => true,
        _ => false,
    };
    (allowed && d.mailbox.is_active(&token)).then_some(token)
}

/// Someone with a token looks for the devices of the person this host is
/// theirs. Each device present is asked, and only those that agree in time
/// are named, so nothing tells the holder whether the others are online. The
/// ones named are then told where the holder is, and each side tries the other.
async fn connect_holder(d: &Arc<Daemon>, s: &Session, token: Token) -> Record {
    let holder = s.peer_static();
    {
        let mut asked = lock(&d.rendezvous.token_asked);
        let when = asked.get(&(token, holder));
        if when.is_some_and(|t| t.elapsed() < TOKEN_ASK_GAP) {
            return error(BUSY);
        }
        asked.retain(|_, t| t.elapsed() < TOKEN_ASK_GAP);
        asked.insert((token, holder), Instant::now());
    }
    let present: Vec<([u8; 32], Session, Vec<SocketAddr>)> = {
        let mut present = lock(&d.rendezvous.present);
        present.retain(|_, p| !p.session.is_closed());
        present
            .iter()
            .filter(|(k, _)| **k != holder)
            .map(|(k, p)| (*k, p.session.clone(), p.local.clone()))
            .collect()
    };
    tracing::debug!("a token holder looks for {} devices here", present.len());
    let (tx, mut rx) = mpsc::unbounded_channel();
    let ask_id = d
        .rendezvous
        .asks
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    lock(&d.rendezvous.answers)
        .entry(holder)
        .or_default()
        .push((ask_id, tx));
    let ask = Record::new()
        .with(0, OP_INCOMING)
        .with(1, holder)
        .with(3, token);
    for (_, session, _) in &present {
        tell_device(session.clone(), Service::RENDEZVOUS, ask.clone());
    }
    let (mut heard, mut agreed) = (HashSet::new(), HashSet::new());
    let deadline = tokio::time::sleep(ANSWER_WITHIN);
    tokio::pin!(deadline);
    while heard.len() < present.len() {
        tokio::select! {
            got = rx.recv() => match got {
                Some((device, yes)) => {
                    heard.insert(device);
                    if yes {
                        agreed.insert(device);
                    }
                }
                None => break,
            },
            _ = &mut deadline => break,
        }
    }
    {
        let mut answers = lock(&d.rendezvous.answers);
        if let Some(mine) = answers.get_mut(&holder) {
            mine.retain(|(id, _)| *id != ask_id);
            if mine.is_empty() {
                answers.remove(&holder);
            }
        }
    }
    // Nobody agreed: the reply comes when it would with no device here, so
    // how long it took says nothing of who is.
    if agreed.is_empty() {
        deadline.await;
    }

    let theirs = observed(s);
    let mut found = Vec::new();
    for (device, session, local) in present.iter().filter(|(k, ..)| agreed.contains(k)) {
        {
            let mut agreed = lock(&d.rendezvous.agreed);
            agreed.retain(|_, t| t.elapsed() < AGREED_FOR);
            agreed.insert((holder, *device), Instant::now());
        }
        let seen = observed(session);
        // Behind the same router, they share a network already.
        let together = theirs.zip(seen).is_some_and(|(a, b)| a.ip() == b.ip());
        found.push(Value::Record(found_record(&Found {
            device: *device,
            observed: seen,
            local: if together { local.clone() } else { Vec::new() },
        })));
        if let Some(at) = theirs {
            let go = Record::new()
                .with(0, OP_INCOMING)
                .with(1, holder)
                .with(2, Value::Record(address_record(&at)))
                .with(3, token);
            tell_device(session.clone(), Service::RENDEZVOUS, go);
        }
    }
    Record::new()
        .with(0, OP_CONNECT)
        .with(1, Value::list(found))
}

/// One of this person's devices says whether a token holder may reach it.
fn answered(d: &Daemon, s: &Session, r: &Record) {
    let who = r.get(1).and_then(Value::as_bytes);
    let Some(who) = who.and_then(|b| <[u8; 32]>::try_from(b).ok()) else {
        return;
    };
    let yes = r.get(2).and_then(Value::as_bool) == Some(true);
    if let Some(waiting) = lock(&d.rendezvous.answers).get(&who) {
        for (_, tx) in waiting {
            let _ = tx.send((s.peer_static(), yes));
        }
    }
}

/// Opens a channel between a token holder and a device of this person's that
/// agreed to them lately. To the holder, any other is simply not present.
fn relay_holder(d: &Daemon, s: &Session, r: &Record) -> Record {
    let Some(device) = r.get(2).and_then(Value::as_bytes) else {
        return error(UNKNOWN);
    };
    let other = present_device(d, device).filter(|o| {
        let agreed = lock(&d.rendezvous.agreed);
        let when = agreed.get(&(s.peer_static(), o.peer_static()));
        when.is_some_and(|t| t.elapsed() < AGREED_FOR)
    });
    match other {
        Some(other) => open_channel(d, s, &other),
        None => error(NOT_PRESENT),
    }
}

/// A host of this person's says a token holder is looking for this device:
/// first to ask whether they may, and then, once this device agreed, where
/// they are.
fn holder_incoming(d: &Arc<Daemon>, s: &Session, r: &Record, token: &Token) {
    let who = r.get(1).and_then(Value::as_bytes);
    let Some(who) = who.and_then(|b| <[u8; 32]>::try_from(b).ok()) else {
        return;
    };
    let theirs = trusted_holder(d, token, &s.peer_static(), &who);
    match r.get(2).and_then(read_address) {
        None => {
            let answer = Record::new()
                .with(0, OP_ANSWER)
                .with(1, who)
                .with(2, theirs.is_some());
            tell_device(s.clone(), Service::RENDEZVOUS, answer);
        }
        Some(at) => {
            if let Some(link) = theirs.filter(|l| !d.is_direct_ip(l.x25519())) {
                let d = d.clone();
                tokio::spawn(async move { punch(&d, &link, vec![at]).await });
            }
        }
    }
}

/// The link key of a trusted contact's device with static key `who`, if this
/// person gave that contact `token` for the host `host`.
fn trusted_holder(
    d: &Daemon,
    token: &Token,
    host: &[u8; 32],
    who: &[u8; 32],
) -> Option<HybridPublicKey> {
    let core = d.core();
    let me = core.identity.as_ref()?.id();
    for c in core.contacts().iter().filter(|c| c.connects()) {
        let reach = core.reach_of(&c.space, &me);
        let gave = reach.iter().any(|r| r.token == *token && r.host == *host);
        if !gave {
            continue;
        }
        let Some(o) = core.others.get(&c.identity) else {
            continue;
        };
        let st = o.log.state();
        // A frozen identity's keys open nothing (`identity.md`).
        if st.frozen {
            continue;
        }
        let links = st.keys.values().filter_map(|k| k.link_key.clone());
        if let Some(link) = links.into_iter().find(|l| l.x25519() == who) {
            return Some(link);
        }
    }
    None
}

/// A contact's device, by the X25519 half of its link key.
fn contact_device(d: &Daemon, who: &[u8; 32], x: &[u8; 32]) -> Option<(KeyId, HybridPublicKey)> {
    let core = d.core();
    let st = core.others.get(who)?.log.state();
    if st.frozen {
        return None;
    }
    let found = st.keys.values().find_map(|k| {
        let link = k.link_key.clone()?;
        (link.x25519() == x).then_some((k.key, link))
    });
    found
}

/// Looks, through the hosts their reach nodes name, for the trusted contacts
/// in use with a device this one has no session with. A session with one
/// device is not enough: it may be their host, and a call rings the devices a
/// person uses. Each is looked for now and then, and a call looks at once.
pub async fn reach_contacts(d: Arc<Daemon>) {
    let wanted: Vec<([u8; 32], SpaceId)> = {
        let core = d.core();
        let contacts = core.contacts();
        let missing = |who: &[u8; 32]| {
            let Some(o) = core.others.get(who) else {
                return false;
            };
            let st = o.log.state();
            // one that could not be read waits its turn (`unreadable.rs`)
            let links = st
                .keys
                .values()
                .filter_map(|k| Some((k.key, k.link_key.as_ref()?)));
            links
                .into_iter()
                .any(|(k, l)| !d.is_online(l.x25519()) && d.unreadable.due(&k, l.x25519()))
        };
        let ones = contacts.iter().filter(|c| c.connects());
        let ones = ones.filter(|c| d.rendezvous.in_use(&c.identity));
        ones.filter(|c| missing(&c.identity))
            .map(|c| (c.identity, c.space))
            .collect()
    };
    let unused: Vec<Session> = {
        let mut paths = lock(&d.rendezvous.paths);
        let mut unused = Vec::new();
        paths.retain(|_, (who, host)| {
            let relayed = d.sessions_of(who).iter().any(Session::is_relayed);
            if !relayed && !host.is_closed() {
                unused.push(host.clone());
            }
            relayed && !host.is_closed()
        });
        unused
    };
    for host in unused {
        host.close("no longer relaying");
    }
    for (who, space) in wanted {
        let due = lock(&d.rendezvous.looked)
            .get(&who)
            .is_none_or(|t| t.elapsed() >= REACH_EVERY);
        if due {
            let d = d.clone();
            tokio::spawn(async move { reach(&d, who, space).await });
        }
    }
}

/// Looks for a contact now, unless that was done a moment ago, and says
/// whether there is a session with them after.
pub async fn reach_now(d: &Arc<Daemon>, who: [u8; 32], space: SpaceId) -> bool {
    let recent = lock(&d.rendezvous.looked)
        .get(&who)
        .is_some_and(|t| t.elapsed() < REACH_GAP);
    if !recent {
        // Waited for, not cut short: a look stopped halfway would leave a
        // session with the host open.
        let looking = tokio::spawn({
            let d = d.clone();
            async move { reach(&d, who, space).await }
        });
        let _ = tokio::time::timeout(REACH_WITHIN, looking).await;
    }
    !d.sessions_of(&who).is_empty()
}

/// A contact being looked for, until this goes.
struct Looking<'a> {
    d: &'a Daemon,
    who: [u8; 32],
}

impl Drop for Looking<'_> {
    fn drop(&mut self) {
        lock(&self.d.rendezvous.looking).remove(&self.who);
    }
}

async fn reach(d: &Arc<Daemon>, who: [u8; 32], space: SpaceId) {
    if !lock(&d.rendezvous.looking).insert(who) {
        return;
    }
    let _looking = Looking { d, who };
    lock(&d.rendezvous.looked).insert(who, Instant::now());
    let reach = d.core().reach_of(&space, &who);
    let usable = crate::mailbox::addresses(&reach);
    d.rendezvous.look_begins(
        &who,
        format!(
            "looking for them: {} named in your space, {} address{} to try",
            plural(reach.len(), "host"),
            usable.len(),
            if usable.len() == 1 { "" } else { "es" }
        ),
    );
    through_helpers(d, &who).await;
    tracing::debug!("looking for {} at {} hosts", short(&who), reach.len());
    for (r, addr) in usable {
        if all_reached(d, &who) {
            break;
        }
        // A host that is a device of theirs, as one that named itself
        // (D72), is theirs to reach directly, as a trusted contact's.
        if let Some((_, link)) = contact_device(d, &who, &r.host) {
            if !reached(d, link.x25519()) {
                match d.dial(|c| Target::new(addr, c, &link)).await {
                    Ok(s) => {
                        d.on_session(s);
                        d.rendezvous.step(
                            &who,
                            Some(true),
                            format!("their device at {addr}, named as their host: reached"),
                        );
                    }
                    Err(e) => d.rendezvous.step(
                        &who,
                        Some(false),
                        format!("their device at {addr}, named as their host: {e}"),
                    ),
                }
            }
        }
        if let Err(e) = through_host(d, &who, r, addr).await {
            d.rendezvous
                .step(&who, Some(false), format!("their host at {addr}: {e:#}"));
            tracing::debug!("looking for {} at {addr}: {e:#}", short(&who));
        }
    }
}

fn plural(n: usize, what: &str) -> String {
    format!("{n} {what}{}", if n == 1 { "" } else { "s" })
}

/// Whether every device of a contact's has a session here.
fn all_reached(d: &Daemon, who: &[u8; 32]) -> bool {
    let core = d.core();
    let Some(o) = core.others.get(who) else {
        return false;
    };
    let st = o.log.state();
    let links: Vec<[u8; 32]> = st
        .keys
        .values()
        .filter_map(|k| Some(*k.link_key.as_ref()?.x25519()))
        .collect();
    drop(core);
    links.iter().all(|x| reached(d, x))
}

/// A contact's device as `contact-status` names it: the start of its key.
fn device_label(device: &KeyId) -> String {
    hex::encode(&device[..8])
}

/// One of this person's devices, by its session, as a person names it.
fn own_label(d: &Daemon, s: &Session) -> String {
    let own = d.core().is_own_device(&s.peer_static());
    own.map_or_else(|| short(&s.peer_static()), |k| d.device_name(&k))
}

fn addr_list(a: &[SocketAddr]) -> String {
    if a.is_empty() {
        return "no address".into();
    }
    a.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Asks this person's own devices for a contact's devices they are in touch
/// with, tries each directly, and relays through the helper to any that cannot
/// be reached that way. Without a host, this is how such a contact is found.
async fn through_helpers(d: &Arc<Daemon>, who: &[u8; 32]) {
    // Every device of theirs reached already: nothing to ask, and asking
    // would have theirs try this one again.
    let missing = {
        let core = d.core();
        let theirs = core.others.get(who).map(|o| o.log.state());
        let links: Vec<[u8; 32]> = theirs
            .iter()
            .flat_map(|st| {
                st.keys
                    .values()
                    .filter_map(|k| Some(*k.link_key.as_ref()?.x25519()))
            })
            .collect();
        links
    };
    if missing.iter().all(|x| reached(d, x)) {
        d.rendezvous.step(
            who,
            Some(true),
            "every device of theirs reached already".into(),
        );
        return;
    }
    let helpers = helpers(d);
    if helpers.is_empty() {
        d.rendezvous.step(
            who,
            None,
            "no other device of yours to ask: none has a direct session here".into(),
        );
    }
    for helper in helpers {
        let name = own_label(d, &helper);
        let ask = Record::new()
            .with(0, OP_CONNECT)
            .with(2, d.keys.key())
            .with(3, *who);
        let found: Vec<Found> = match call(&helper, Service::RENDEZVOUS, ask).await {
            Ok(r) if r.get(0).and_then(Value::as_uint) == Some(OP_CONNECT) => {
                let list = r.record_list(1).unwrap_or_default();
                list.into_iter()
                    .take(MAX_FOUND)
                    .filter_map(read_found)
                    .collect()
            }
            Ok(_) => {
                d.rendezvous
                    .step(who, Some(false), format!("asked your {name}: it refused"));
                continue;
            }
            Err(e) => {
                d.rendezvous
                    .step(who, Some(false), format!("asked your {name}: {e:#}"));
                tracing::debug!(
                    "asking {} for {}: {e:#}",
                    short(&helper.peer_static()),
                    short(who)
                );
                continue;
            }
        };
        d.rendezvous.step(
            who,
            Some(!found.is_empty()),
            format!(
                "asked your {name}: in touch with {} of their devices",
                found.len()
            ),
        );
        for f in found {
            let Some((device, link)) = contact_device(d, who, &f.device) else {
                continue;
            };
            if reached(d, link.x25519()) {
                continue;
            }
            try_found(d, who, &device, &link, &f, &helper, &name, None).await;
        }
    }
}

/// The always-on devices of trusted contacts this device stays in touch with
/// when its person has no host of their own, with where each listens: the
/// hosts their reach nodes name that are their own devices. Those of the
/// contacts last in use come first, and only a few (`hosts.md#staying-reachable`).
pub fn standing(d: &Daemon) -> Vec<(KeyId, HybridPublicKey)> {
    let core = d.core();
    if core.identity.is_none() || !core.mailboxes().is_empty() {
        return Vec::new();
    }
    let used: HashMap<[u8; 32], Instant> = lock(&d.rendezvous.in_use)
        .iter()
        .map(|(w, (t, _))| (*w, *t))
        .collect();
    let mut contacts: Vec<_> = core
        .contacts()
        .into_iter()
        .filter(|c| c.connects())
        .collect();
    contacts.sort_by_key(|c| std::cmp::Reverse(used.get(&c.identity).copied()));
    let mut out = Vec::new();
    let mut kept = 0;
    for c in contacts {
        if kept >= STANDING {
            break;
        }
        let Some(o) = core.others.get(&c.identity) else {
            continue;
        };
        let st = o.log.state();
        if st.frozen {
            continue;
        }
        let hosts: Vec<[u8; 32]> = core
            .reach_of(&c.space, &c.identity)
            .iter()
            .map(|r| r.host)
            .collect();
        let theirs: Vec<_> = st
            .keys
            .values()
            .filter_map(|k| Some((k.key, k.link_key.clone()?)))
            .filter(|(_, l)| hosts.contains(l.x25519()))
            .collect();
        if !theirs.is_empty() {
            kept += 1;
            out.extend(theirs);
        }
    }
    out
}

/// Tries each of a trusted contact's devices at an address the person
/// gives, as a step of a look: the way out when neither side names anything
/// the other can use.
pub async fn try_at(d: &Arc<Daemon>, who: [u8; 32], addr: SocketAddr) {
    let theirs: Vec<(KeyId, HybridPublicKey)> = {
        let core = d.core();
        let Some(o) = core.others.get(&who) else {
            return;
        };
        let st = o.log.state();
        st.keys
            .values()
            .filter_map(|k| Some((k.key, k.link_key.clone()?)))
            .collect()
    };
    // One look at a time, as for any other.
    if !lock(&d.rendezvous.looking).insert(who) {
        return;
    }
    let _looking = Looking { d, who };
    d.rendezvous.look_begins(
        &who,
        format!("trying their devices at {addr}, as you asked"),
    );
    for (device, link) in theirs {
        if reached(d, link.x25519()) {
            continue;
        }
        punch(d, &link, vec![addr]).await;
        if reached(d, link.x25519()) {
            d.rendezvous.step(
                &who,
                Some(true),
                format!("their {}: reached at {addr}", device_label(&device)),
            );
            return;
        }
    }
    d.rendezvous.step(
        &who,
        Some(false),
        format!("none of their devices answered at {addr}"),
    );
}

/// Where a trusted contact's tag was seen (D74).
#[derive(Clone)]
pub enum Near {
    /// On the local network, in an advertisement for this address.
    Lan(SocketAddr),
    /// Over Bluetooth (`carriers/ble.md`), from this device.
    Ble(crate::bluetooth::Seen),
}

impl Near {
    fn carrier(&self) -> Carrier {
        match self {
            Near::Lan(_) => Carrier::Lan,
            Near::Ble(_) => Carrier::Ble,
        }
    }

    fn key(&self) -> String {
        match self {
            Near::Lan(a) => a.to_string(),
            Near::Ble(s) => format!("bluetooth {}", s.addr),
        }
    }

    fn said(&self) -> String {
        match self {
            Near::Lan(a) => format!("on the local network at {a}"),
            Near::Ble(s) => format!("over Bluetooth, at {}", s.addr),
        }
    }
}

/// An advertisement on the local network carried a trusted contact's tag
/// (D74, `hosts.md#local-discovery`): each of their devices without a
/// session is tried at its address, as at one their host named. A tag is a
/// hint to try and nothing more: only a session says they are near, and
/// the trail says which. Each address is tried at most once in
/// [`NEARBY_EVERY`].
pub async fn found_nearby(d: &Arc<Daemon>, who: [u8; 32], addr: SocketAddr) {
    found_near(d, who, Near::Lan(addr)).await
}

/// A trusted contact's tag was seen, on the local network or over
/// Bluetooth: [`found_nearby`], wherever it was.
pub async fn found_near(d: &Arc<Daemon>, who: [u8; 32], near: Near) {
    let trusted = crate::presence::by_identity(&d.core())
        .get(&who)
        .is_some_and(|(t, _)| *t);
    if !trusted {
        return;
    }
    let theirs: Vec<(KeyId, HybridPublicKey)> = {
        let core = d.core();
        let Some(o) = core.others.get(&who) else {
            return;
        };
        let st = o.log.state();
        if st.frozen {
            return;
        }
        st.keys
            .values()
            .filter_map(|k| Some((k.key, k.link_key.clone()?)))
            .collect()
    };
    // Over Bluetooth a device with any session is left alone; on the LAN
    // one reached only over Bluetooth is tried, for something better.
    let carrier = near.carrier();
    let have = |l: &HybridPublicKey| match carrier {
        Carrier::Lan => reached(d, l.x25519()),
        Carrier::Ble => d.is_online(l.x25519()),
    };
    if theirs.iter().all(|(_, l)| have(l)) {
        return;
    }
    let place = near.key();
    // Where a session was reached before, or an address the book has for
    // one of their devices, the minute's tries are not spent.
    let known_place = lock(&d.rendezvous.nearby_reached).contains(&(who, place.clone()))
        || match &near {
            Near::Lan(addr) => {
                let book = lock(&d.book);
                let there = book.at(addr);
                theirs
                    .iter()
                    .any(|(k, _)| there.iter().any(|x| **x == hex::encode(k)))
            }
            Near::Ble(_) => false,
        };
    if !d
        .rendezvous
        .may_try_nearby(who, carrier, &place, known_place)
    {
        return;
    }
    // One try at a time for a contact on each carrier, apart from the
    // looks through hosts.
    if !lock(&d.rendezvous.nearby_going).insert((who, carrier)) {
        return;
    }
    struct Going<'a>(&'a Daemon, ([u8; 32], Carrier));
    impl Drop for Going<'_> {
        fn drop(&mut self) {
            lock(&self.0.rendezvous.nearby_going).remove(&self.1);
        }
    }
    let _going = Going(d, (who, carrier));
    let remember = || {
        let mut held = lock(&d.rendezvous.nearby_reached);
        if !held.contains(&(who, place.clone())) {
            if held.len() >= NEARBY_REACHED {
                held.pop_front();
            }
            held.push_back((who, place.clone()));
        }
    };
    let at = near.said();
    let found = |device: &KeyId| {
        d.rendezvous.nearby_step(
            &who,
            Some(true),
            format!("their {}: found {at}", device_label(device)),
        );
        tracing::info!("found {} {at}", short(&who));
    };
    let theirs: Vec<(KeyId, HybridPublicKey)> =
        theirs.into_iter().filter(|(_, l)| !have(l)).collect();
    match &near {
        Near::Lan(addr) => {
            for (device, link) in theirs {
                if have(&link) {
                    continue;
                }
                match d.dial(|c| Target::new(*addr, c, &link)).await {
                    Ok(s) => {
                        d.on_session(s);
                        remember();
                        found(&device);
                        // the first that answers: the tag was one device's
                        return;
                    }
                    Err(e) => tracing::debug!("{} at {addr}: {e}", short(&device)),
                }
            }
        }
        // One channel, and every device of theirs tried on it at once:
        // only the one at the other end answers.
        Near::Ble(seen) => {
            let links: Vec<HybridPublicKey> = theirs.iter().map(|(_, l)| l.clone()).collect();
            match crate::bluetooth::dial(d, seen, &links).await {
                Ok(s) => {
                    let ps = s.peer_static();
                    d.on_session(s);
                    remember();
                    if let Some((device, _)) = theirs.iter().find(|(_, l)| *l.x25519() == ps) {
                        found(device);
                    }
                    return;
                }
                Err(e) => tracing::debug!("{} {at}: {e:#}", short(&who)),
            }
        }
    }
    d.rendezvous.nearby_step(
        &who,
        Some(false),
        format!("their tag seen {at}: none of their devices answered"),
    );
}

/// Tries a contact's device where a helper says it is, and else relays
/// through the helper, noting each step.
#[allow(clippy::too_many_arguments)]
async fn try_found(
    d: &Arc<Daemon>,
    who: &[u8; 32],
    device: &KeyId,
    link: &HybridPublicKey,
    f: &Found,
    helper: &Session,
    helper_name: &str,
    token: Option<[u8; 16]>,
) {
    let addresses = f.addresses();
    let label = device_label(device);
    punch(d, link, addresses.clone()).await;
    if reached(d, link.x25519()) {
        d.rendezvous.step(
            who,
            Some(true),
            format!(
                "their {label}: reached directly, tried {}",
                addr_list(&addresses)
            ),
        );
        return;
    }
    d.rendezvous.step(
        who,
        Some(false),
        format!(
            "their {label}: no answer directly at {}",
            addr_list(&addresses)
        ),
    );
    let mut ask = Record::new().with(0, OP_RELAY);
    if let Some(t) = token {
        ask = ask.with(1, t);
    }
    let ask = ask.with(2, *device);
    match relay(d, helper, ask, device, link).await {
        Ok(()) => d.rendezvous.step(
            who,
            Some(true),
            format!("their {label}: relayed through {helper_name}"),
        ),
        Err(e) => {
            d.rendezvous.step(
                who,
                Some(false),
                format!("their {label}: relay through {helper_name}: {e:#}"),
            );
            tracing::debug!("relaying to {}: {e:#}", short(device));
        }
    }
}

/// Asks a contact's host for their devices, tries each directly, and relays
/// to any that cannot be reached that way. The session with the host stays
/// open while a relay runs through it.
async fn through_host(
    d: &Arc<Daemon>,
    who: &[u8; 32],
    r: &Reach,
    addr: SocketAddr,
) -> anyhow::Result<()> {
    let (mut host, mut opened) = host_session(d, r, addr, false).await?;
    let ask = Record::new().with(0, OP_CONNECT).with(1, r.token);
    let mut reply = call(&host, Service::RENDEZVOUS, ask.clone()).await;
    if reply.is_err() && !opened {
        // The session it found may have been one the host was ending, as
        // a direct one from someone it does not take for a trusted
        // contact ("prove first"), and another such may be open by now:
        // once more, on a session of its own with the token.
        (host, opened) = host_session(d, r, addr, true).await?;
        reply = call(&host, Service::RENDEZVOUS, ask).await;
    }
    let found = match reply {
        Ok(reply) if reply.get(0).and_then(Value::as_uint) == Some(OP_CONNECT) => {
            let list = reply.record_list(1).unwrap_or_default();
            list.into_iter()
                .take(MAX_FOUND)
                .filter_map(read_found)
                .collect()
        }
        Ok(_) => Vec::new(),
        Err(e) => {
            if opened {
                host.close("no answer");
            }
            return Err(e);
        }
    };
    tracing::debug!(
        "{}'s host named {} of their devices",
        short(who),
        found.len()
    );
    d.rendezvous.step(
        who,
        Some(!found.is_empty()),
        format!(
            "their host at {addr}: {} of their devices there, and agreeing",
            found.len()
        ),
    );
    for f in found {
        let Some((device, link)) = contact_device(d, who, &f.device) else {
            continue;
        };
        if reached(d, link.x25519()) {
            continue;
        }
        let name = format!("their host at {addr}");
        try_found(d, who, &device, &link, &f, &host, &name, Some(r.token)).await;
    }
    let relayed = d.sessions_of(who).iter().any(Session::is_relayed);
    if opened {
        if relayed {
            lock(&d.rendezvous.paths).insert(r.host, (*who, host));
        } else {
            host.close("done");
        }
    }
    Ok(())
}

/// A session with a contact's host: one already open, or a new one opened
/// with the token, which says nothing of who is asking. Says whether it is
/// new. With `fresh`, always a new one.
async fn host_session(
    d: &Arc<Daemon>,
    r: &Reach,
    addr: SocketAddr,
    fresh: bool,
) -> anyhow::Result<(Session, bool)> {
    anyhow::ensure!(
        r.host != *d.keys.link.public_key().x25519(),
        "that host is this device"
    );
    // Another errand there, a mailbox's say, is quick: this waits for it
    // rather than give up on a call.
    let asked = Instant::now();
    loop {
        if let Some(s) = d.session(&r.host).filter(|_| !fresh) {
            return Ok((s, false));
        }
        let held = lock(&d.rendezvous.paths).get(&r.host).cloned();
        if let Some((_, s)) = held.filter(|(_, s)| !s.is_closed() && !fresh) {
            return Ok((s, false));
        }
        if let Some(_going) = crate::mailbox::going_to(d, r.host) {
            let secret = derive(Purpose::Token, &r.token);
            let target = |c| Target::invitation(addr, c, r.host, &secret[..]).anonymous();
            return Ok((d.dial(target).await?, true));
        }
        anyhow::ensure!(asked.elapsed() < HOST_IN_USE_FOR, "that host is in use");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// A session with this device ended: what went through it is over.
pub fn session_closed(d: &Daemon, peer_static: &[u8; 32]) {
    lock(&d.rendezvous.present).remove(peer_static);
    lock(&d.rendezvous.presented).remove(peer_static);
    lock(&d.rendezvous.channels).retain(|channel, devices| {
        let keep = !devices.contains(peer_static);
        if !keep {
            d.endpoint.relay_close(*channel);
        }
        keep
    });
}

#[cfg(test)]
mod nearby_tests {
    use super::*;

    #[test]
    fn tags_replayed_over_bluetooth_leave_the_lan_its_tries() {
        let r = Rendezvous::default();
        let who = [7u8; 32];
        // Played again from address after address over Bluetooth.
        let ble: Vec<bool> = (0..6)
            .map(|i| r.may_try_nearby(who, Carrier::Ble, &format!("bluetooth {i}"), false))
            .collect();
        assert_eq!(ble.iter().filter(|x| **x).count(), NEARBY_PER_MINUTE);
        // The local network has its own.
        assert!(r.may_try_nearby(who, Carrier::Lan, "192.168.1.9:7171", false));
        // A place a session was reached is tried whatever the minute's
        // tries, but not twice in ten seconds.
        assert!(r.may_try_nearby(who, Carrier::Ble, "bluetooth known", true));
        assert!(!r.may_try_nearby(who, Carrier::Ble, "bluetooth known", true));
        // Someone else's tries are theirs.
        assert!(r.may_try_nearby([8; 32], Carrier::Ble, "bluetooth 0", false));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_reads_back() {
        for a in ["172.20.1.20:7171", "[2001:db8::1]:9"] {
            let a: SocketAddr = a.parse().unwrap();
            assert_eq!(read_address(&Value::Record(address_record(&a))), Some(a));
        }
        let wrong = Record::new().with(2, vec![1u8; 5]).with(3, 1u64);
        assert_eq!(read_address(&Value::Record(wrong)), None);
    }

    #[test]
    fn what_a_host_says_of_a_device_reads_back() {
        let f = Found {
            device: [7; 32],
            observed: Some("203.0.113.9:40000".parse().unwrap()),
            local: vec!["192.168.1.5:7171".parse().unwrap()],
        };
        let back = read_found(&found_record(&f)).unwrap();
        assert_eq!(back.device, f.device);
        assert_eq!(back.observed, f.observed);
        assert_eq!(back.local, f.local);
        assert_eq!(back.addresses()[0], f.local[0], "local first");
        assert_eq!(back.addresses()[1], f.observed.unwrap());

        // One seen over TCP has no address to punch to.
        let f = Found {
            device: [7; 32],
            observed: None,
            local: Vec::new(),
        };
        assert!(read_found(&found_record(&f))
            .unwrap()
            .addresses()
            .is_empty());
    }

    #[test]
    fn a_device_cannot_report_any_number_of_addresses() {
        let many: Vec<SocketAddr> = (0..100)
            .map(|n| SocketAddr::from(([10, 0, 0, n], 7171)))
            .collect();
        let v = address_list(&many);
        assert_eq!(read_addresses(Some(&v)).len(), MAX_LOCAL);
    }
}
