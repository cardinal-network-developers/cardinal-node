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

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
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
/// The least time between looks for one contact, when a call wants them now.
const REACH_GAP: Duration = Duration::from_secs(5);
/// How long a call waits for a contact to be found.
const REACH_WITHIN: Duration = Duration::from_secs(12);

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
/// The field of a device's local addresses, in what is said of it.
const LOCAL: u64 = 4;
/// Where this kind of system lists what powers it.
const POWER_SUPPLIES: &str = "/sys/class/power_supply";

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// A static key: who a session is with.
type Static = [u8; 32];

/// What a device answered a token holder: itself, and yes or no.
type Answer = (Static, bool);

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
    answers: Mutex<HashMap<Static, mpsc::UnboundedSender<Answer>>>,
    /// As a host: which device agreed to which token holder, and when.
    agreed: Mutex<HashMap<(Static, Static), Instant>>,
    /// As a host: when each token was last used to ask.
    token_asked: Mutex<HashMap<Token, Instant>>,
    /// Sessions with contacts' hosts that relays to them run through, by
    /// host, and whose host each is.
    paths: Mutex<HashMap<Static, (Static, Session)>>,
    /// When each contact was last looked for.
    looked: Mutex<HashMap<[u8; 32], Instant>>,
    /// The contacts being looked for right now.
    looking: Mutex<HashSet<[u8; 32]>>,
}

impl Rendezvous {
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

/// The addresses this device has on its own networks.
fn local_addresses(d: &Daemon) -> Vec<SocketAddr> {
    let Some(udp) = d.endpoint.udp_addr() else {
        return Vec::new();
    };
    if udp.ip().is_unspecified() {
        let ips = crate::daemon::local_ips();
        ips.into_iter()
            .map(|ip| SocketAddr::new(ip, udp.port()))
            .collect()
    } else {
        vec![udp]
    }
}

/// The sessions with this person's devices that can help: one hop, so not
/// one that itself goes through a device.
fn helpers(d: &Daemon) -> Vec<Session> {
    let sessions = d.own_sessions().into_iter();
    sessions.filter(|s| !s.is_relayed()).collect()
}

/// Where this machine lists its power supplies. A test on a laptop must not
/// depend on whether it is plugged in.
fn power_supplies() -> PathBuf {
    std::env::var_os("CARDINAL_TEST_POWER_SUPPLIES")
        .map_or_else(|| PathBuf::from(POWER_SUPPLIES), PathBuf::from)
}

/// Whether this machine runs on its battery, which relaying would run down.
fn on_battery(power_supplies: &Path) -> bool {
    let read = |p: PathBuf, f: &str| std::fs::read_to_string(p.join(f)).unwrap_or_default();
    let mut battery = false;
    for d in std::fs::read_dir(power_supplies)
        .into_iter()
        .flatten()
        .flatten()
    {
        match read(d.path(), "type").trim() {
            "Battery" => battery = true,
            _ if read(d.path(), "online").trim() == "1" => return false,
            _ => {}
        }
    }
    battery
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
        .filter(|(_, link)| !d.is_direct(link.x25519()))
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
    if d.is_online(link.x25519()) {
        return Ok(());
    }
    let at = helper
        .remote_addr()
        .ok_or_else(|| anyhow::anyhow!("no address"))?;
    let target = Target::new(at, CarrierKind::Udp, link)
        .through(helper, channel)
        .within(PUNCH_WITHIN);
    let s = d.endpoint.connect(target).await?;
    tracing::info!("reached {} through a relay", short(device));
    d.on_session(s);
    Ok(())
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
    let reply = if !matches!(kind, PeerKind::Own(_)) {
        let rendezvous = st.service() == Service::RENDEZVOUS;
        match holder_token(d, &kind, r) {
            None => Some(error(NOT_PERMITTED)),
            Some(token) if rendezvous && op == Some(OP_CONNECT) => {
                Some(connect_holder(d, s, token).await)
            }
            Some(_) if !rendezvous && op == Some(OP_RELAY) => {
                if on_battery(&power_supplies()) {
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
                let session = s.clone();
                let presence = Presence { session, local };
                lock(&d.rendezvous.present).insert(s.peer_static(), presence);
                Some(Record::new().with(0, OP_PRESENT))
            }
            Some(OP_CONNECT) => Some(connect(s, d)),
            _ => Some(error(UNKNOWN)),
        }
    } else {
        match op {
            Some(OP_RELAYED) => None,
            Some(OP_RELAY) if on_battery(&power_supplies()) => Some(error(BUSY)),
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
    match present_device(d, device) {
        Some(other) => open_channel(d, s, &other),
        None => error(NOT_PRESENT),
    }
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
    {
        let mut asked = lock(&d.rendezvous.token_asked);
        if asked
            .get(&token)
            .is_some_and(|t| t.elapsed() < TOKEN_ASK_GAP)
        {
            return error(BUSY);
        }
        asked.retain(|_, t| t.elapsed() < TOKEN_ASK_GAP);
        asked.insert(token, Instant::now());
    }
    let holder = s.peer_static();
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
    lock(&d.rendezvous.answers).insert(holder, tx);
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
    lock(&d.rendezvous.answers).remove(&holder);

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
    if let Some(tx) = lock(&d.rendezvous.answers).get(&who) {
        let _ = tx.send((s.peer_static(), yes));
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
            if let Some(link) = theirs.filter(|l| !d.is_direct(l.x25519())) {
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
        let reach = core.all_reach_of(&c.space, &me);
        let gave = reach.iter().any(|r| r.token == *token && r.host == *host);
        if !gave {
            continue;
        }
        let Some(o) = core.others.get(&c.identity) else {
            continue;
        };
        let st = o.log.state();
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
    let found = st.keys.values().find_map(|k| {
        let link = k.link_key.clone()?;
        (link.x25519() == x).then_some((k.key, link))
    });
    found
}

/// Looks, through the hosts their reach nodes name, for the trusted contacts
/// with a device this one has no session with. A session with one device is
/// not enough: it may be their host, and a call rings the devices a person
/// uses. Each is looked for now and then, and a call looks at once.
pub async fn reach_contacts(d: Arc<Daemon>) {
    let wanted: Vec<([u8; 32], SpaceId)> = {
        let core = d.core();
        let contacts = core.contacts();
        let missing = |who: &[u8; 32]| {
            let Some(o) = core.others.get(who) else {
                return false;
            };
            let st = o.log.state();
            let links = st.keys.values().filter_map(|k| k.link_key.as_ref());
            links.into_iter().any(|l| !d.is_online(l.x25519()))
        };
        let ones = contacts.iter().filter(|c| c.connects());
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
    let reach = d.core().reach_of(&space, &who).map(|(_, r)| r);
    let reach = reach.unwrap_or_default();
    tracing::debug!("looking for {} at {} hosts", short(&who), reach.len());
    for (r, addr) in crate::mailbox::addresses(&reach) {
        if let Err(e) = through_host(d, &who, r, addr).await {
            tracing::debug!("looking for {} at {addr}: {e:#}", short(&who));
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
    let (host, opened) = host_session(d, r, addr).await?;
    let ask = Record::new().with(0, OP_CONNECT).with(1, r.token);
    let reply = call(&host, Service::RENDEZVOUS, ask).await;
    let found = match reply {
        Ok(reply) if reply.get(0).and_then(Value::as_uint) == Some(OP_CONNECT) => {
            let list = reply.record_list(1).unwrap_or_default();
            list.into_iter()
                .take(MAX_DEVICES)
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
    for f in found {
        let Some((device, link)) = contact_device(d, who, &f.device) else {
            continue;
        };
        if d.is_online(link.x25519()) {
            continue;
        }
        punch(d, &link, f.addresses()).await;
        if !d.is_online(link.x25519()) {
            let ask = Record::new()
                .with(0, OP_RELAY)
                .with(1, r.token)
                .with(2, device);
            if let Err(e) = relay(d, &host, ask, &device, &link).await {
                tracing::debug!("relaying to {}: {e:#}", short(&device));
            }
        }
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
/// with the token, which says nothing of who is asking. Says whether it is new.
async fn host_session(
    d: &Arc<Daemon>,
    r: &Reach,
    addr: SocketAddr,
) -> anyhow::Result<(Session, bool)> {
    if let Some(s) = d.session(&r.host) {
        return Ok((s, false));
    }
    let held = lock(&d.rendezvous.paths).get(&r.host).cloned();
    if let Some((_, s)) = held.filter(|(_, s)| !s.is_closed()) {
        return Ok((s, false));
    }
    anyhow::ensure!(
        r.host != *d.keys.link.public_key().x25519(),
        "that host is this device"
    );
    let _going = crate::mailbox::going_to(d, r.host)
        .ok_or_else(|| anyhow::anyhow!("that host is in use"))?;
    let secret = derive(Purpose::Token, &r.token);
    let target = |c| Target::invitation(addr, c, r.host, &secret[..]).anonymous();
    Ok((d.dial(target).await?, true))
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

    fn power(dir: &Path, name: &str, kind: &str, online: Option<&str>) {
        let d = dir.join(name);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("type"), kind).unwrap();
        if let Some(o) = online {
            std::fs::write(d.join("online"), o).unwrap();
        }
    }

    #[test]
    fn a_device_on_battery_is_told_apart() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!on_battery(dir.path()), "a desktop has no battery");
        assert!(!on_battery(Path::new("/nothing/here")));
        power(dir.path(), "BAT0", "Battery\n", None);
        power(dir.path(), "AC", "Mains\n", Some("0\n"));
        power(dir.path(), "usb-c", "USB\n", Some("0\n"));
        assert!(on_battery(dir.path()), "nothing plugged in");
        power(dir.path(), "usb-c", "USB\n", Some("1\n"));
        assert!(!on_battery(dir.path()), "charging over USB");
        power(dir.path(), "usb-c", "USB\n", Some("0\n"));
        power(dir.path(), "AC", "Mains\n", Some("1\n"));
        assert!(!on_battery(dir.path()), "plugged in");
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
