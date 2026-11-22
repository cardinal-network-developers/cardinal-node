//! Bluetooth Low Energy (`carriers/ble.md`, D74): people with their phones
//! and nothing else find each other, sync and write.
//!
//! Optional, and the person's: two switches and three states, a setting of
//! this device ([`Mode`]): off, the default; on while Cardinal is open, that
//! is while a window watches the service (`{"cmd": "watch", "window":
//! true}`); and on while it is closed too.
//!
//! While on, the device listens for L2CAP channels, advertises its tags
//! under the service UUID, and scans:
//!
//! - type 1, its own devices' tag, from the discovery secret: a device that
//!   recognizes it tries each of the person's devices it has no session with;
//! - type 2, its trusted contacts' tag, from the presence secret it gives
//!   them: one of theirs tries each of this person's devices, as on a local
//!   network ([`crate::rendezvous::found_near`]);
//! - type 3, a one-time tag for each outstanding invitation this device
//!   answers for: whoever holds the code finds it, since the code carries the
//!   secret ([`find_invitation`]).
//!
//! A tag is a hint to try. The channel goes to the link as another carrier
//! ([`cardinal_link::Endpoint::attach`]), and only the session that follows
//! says whose device it reached. Every device a tag could stand for is tried
//! at once on one channel, since only the one at the other end can answer.
//!
//! The radio is behind [`cardinal_contact::ble::Radio`]: BlueZ on Linux
//! ([`crate::bluez`]), and, for tests, radios meeting in the directory
//! `CARDINAL_TEST_BLE_ETHER` names.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cardinal_contact::ble::{self, Advert, BleAddr, Keys, NotAvailable, Radio, Sighting, TagType};
use cardinal_contact::discovery::{discovery_key, presence_key};
use cardinal_contact::Invitation;
use cardinal_crypto::HybridPublicKey;
use cardinal_identity::KeyId;
use cardinal_link::{Attached, CarrierKind, Session, Target};
use serde_json::{json, Value};
use tokio::sync::{mpsc, watch, Notify};
use zeroize::Zeroizing;

use crate::daemon::{lock, Daemon};

/// The person's choice for this device.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    /// Off, the default.
    #[default]
    Off,
    /// On while Cardinal is open: while a window watches the service.
    Open,
    /// On while it is closed too.
    Always,
}

impl Mode {
    /// Reads `off`, `open` or `always`.
    pub fn parse(s: &str) -> Option<Mode> {
        match s.trim() {
            "off" => Some(Mode::Off),
            "open" => Some(Mode::Open),
            "always" => Some(Mode::Always),
            _ => None,
        }
    }

    /// As written in the settings.
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Off => "off",
            Mode::Open => "open",
            Mode::Always => "always",
        }
    }
}

/// How often the advertisement is made again, with fresh nonces.
const ADVERTISE_EVERY: Duration = Duration::from_secs(30);
/// How often what is advertised is checked for a change.
const LOOK_EVERY: Duration = Duration::from_secs(2);
/// The same advertisement from the same device is looked at again only
/// after this long: a radio reports one many times a second.
const SEEN_AGAIN: Duration = Duration::from_secs(2);
/// How often an own device's tag at one address is tried.
const OWN_EVERY: Duration = Duration::from_secs(10);
/// How often an own device's tag is tried in a minute, at any addresses: a
/// tag recorded and played again from address after address costs this.
const OWN_PER_MINUTE: usize = 3;
/// The most advertisements looked at in a second, whoever sends them: each
/// costs a keyed hash per key.
const SIGHTINGS_PER_SECOND: u32 = 50;
/// The most devices whose last advertisement is kept.
const LAST_MAX: usize = 512;
/// How long a channel someone opened may go with no session over it.
const UNPROVEN_WITHIN: Duration = Duration::from_secs(10);
/// The most channels one address may have open to this device.
const MAX_PER_ADDR: usize = 2;
/// How long opening a channel may take.
const CHANNEL_WITHIN: Duration = Duration::from_secs(10);
/// How long a handshake over a channel may take.
const HANDSHAKE_WITHIN: Duration = Duration::from_secs(8);
/// How long someone accepting an invitation looks for its tag: where the
/// other device has more one-time tags than places, its own is in a random
/// few of its advertisements, made every [`ADVERTISE_FAST`].
const INVITATION_WITHIN: Duration = Duration::from_secs(60);
/// How often the advertisement is made again while it has a one-time tag,
/// so that more of them than there are places take turns soon.
const ADVERTISE_FAST: Duration = Duration::from_secs(10);
/// How long to wait before trying the radio again when it failed: the
/// app that drives it on Android connects a moment after the service starts.
const RETRY_EVERY: Duration = Duration::from_secs(5);
/// The most channels others may have open to this device at once.
const MAX_INCOMING: usize = 16;

/// Where a target over a channel says it is: nowhere, since the channel is
/// what it goes over.
const NOWHERE: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);

/// A device seen over Bluetooth, and the radio that saw it.
#[derive(Clone)]
pub struct Seen {
    /// Its address now.
    pub addr: BleAddr,
    /// The PSM it listens on.
    pub psm: u16,
    radio: Arc<dyn Radio>,
}

/// An invitation being accepted here: its one-time key, and where to say
/// a device advertising it was seen.
type Wanted = (Zeroizing<[u8; 32]>, mpsc::Sender<Seen>);

/// What the person sees of Bluetooth on this device: what [`status`]
/// says, but for the counts. It changes only through [`show`], which tells
/// whoever watches the service.
#[derive(Clone, Default, PartialEq)]
struct Shown {
    /// The radio, in words, once one was made.
    radio: Option<String>,
    /// Whether it could be used, the last time it was asked.
    available: Option<Result<(), NotAvailable>>,
    /// Advertising, scanning and listening now.
    on: bool,
    /// The PSM listened on.
    psm: Option<u16>,
    /// What went wrong last.
    error: Option<String>,
}

/// Bluetooth on this device.
#[derive(Default)]
pub struct Bluetooth {
    /// Windows watching the service now.
    windows: AtomicUsize,
    /// Wakes the controller: the setting or the windows changed.
    poke: Notify,
    started: AtomicBool,
    shown: Mutex<Shown>,
    /// The radio, made once.
    radio: Mutex<Option<Arc<dyn Radio>>>,
    /// The radio while on: what invitations are looked for with.
    running: Mutex<Option<Arc<dyn Radio>>>,
    /// Invitations being accepted here, by their one-time key.
    wanted: Mutex<Vec<Wanted>>,
    /// When an own device's tag at each address was last tried.
    tried: Mutex<HashMap<BleAddr, Instant>>,
    /// When an own device's tag was tried in the last minute, anywhere.
    own_tries: Mutex<VecDeque<Instant>>,
    /// Own devices being tried over Bluetooth now: apart from the tries
    /// over IP, which a tag seen here must never hold up.
    dialling: Mutex<HashSet<KeyId>>,
    /// Advertisements under the service UUID seen since start.
    seen: AtomicU64,
    /// Of those, the ones with a tag this device recognized.
    recognized: AtomicU64,
    /// Channels others have open to this device.
    incoming: Mutex<Vec<Incoming>>,
    /// A pairing code this device shows: its channel, advertised by the tag
    /// made from it, and where a channel whose first message is pairing's
    /// goes.
    pairing: Mutex<Option<Pairing>>,
}

/// A pairing shown over Bluetooth.
type Pairing = (u16, mpsc::Sender<(ble::BoxChannel, Vec<u8>)>);

/// How long a channel opened while a pairing code shows may take to say
/// whether it carries pairing or a link session.
const FIRST_WITHIN: Duration = Duration::from_secs(10);
/// How long the typer of a pairing code looks for its tag.
const PAIRING_WITHIN: Duration = Duration::from_secs(20);

/// A channel someone opened to this device.
struct Incoming {
    from: BleAddr,
    at: Instant,
    on: Attached,
}

/// Changes what the person sees of Bluetooth, and, where that changed
/// anything, tells whoever watches the service: the radio coming on, going
/// off or failing is news as much as the setting is.
fn show<T>(d: &Daemon, f: impl FnOnce(&mut Shown) -> T) -> T {
    let (t, changed) = {
        let mut shown = lock(&d.bluetooth.shown);
        let before = shown.clone();
        let t = f(&mut shown);
        (t, *shown != before)
    };
    if changed {
        d.bump();
    }
    t
}

/// A window, while it watches the service.
pub struct Window(Arc<Daemon>);

impl Drop for Window {
    fn drop(&mut self) {
        self.0.bluetooth.windows.fetch_sub(1, Ordering::SeqCst);
        self.0.bluetooth.poke.notify_one();
    }
}

impl Bluetooth {
    /// Uses `radio` instead of the system's, as tests do.
    pub fn use_radio(&self, radio: Arc<dyn Radio>) {
        *lock(&self.radio) = Some(radio);
    }

    /// Whether the radio is on now.
    pub fn is_on(&self) -> bool {
        lock(&self.shown).on
    }
}

/// A window began to watch: while one does, "on while open" is on.
pub fn window(d: &Arc<Daemon>) -> Window {
    d.bluetooth.windows.fetch_add(1, Ordering::SeqCst);
    d.bluetooth.poke.notify_one();
    Window(d.clone())
}

/// The setting of this device.
pub fn mode(d: &Daemon) -> Mode {
    Mode::parse(&d.config().bluetooth).unwrap_or_default()
}

/// Whether the radio should be on now.
fn wanted(d: &Daemon) -> bool {
    match mode(d) {
        Mode::Off => false,
        Mode::Open => d.bluetooth.windows.load(Ordering::SeqCst) > 0,
        Mode::Always => true,
    }
}

/// Sets this device's choice, and acts on it.
pub fn set(d: &Arc<Daemon>, m: Mode) -> anyhow::Result<Value> {
    d.config().bluetooth = m.as_str().to_owned();
    d.save_config()?;
    start(d);
    d.bluetooth.poke.notify_one();
    d.bump();
    Ok(status(d))
}

/// The radio this device uses, made the first time.
fn radio(d: &Daemon) -> Result<Arc<dyn Radio>, String> {
    let mut held = lock(&d.bluetooth.radio);
    if let Some(r) = held.as_ref() {
        return Ok(r.clone());
    }
    let r = system_radio(d)?;
    show(d, |s| s.radio = Some(r.describe()));
    *held = Some(r.clone());
    Ok(r)
}

/// Where the app that drives the radio connects, where one does: on
/// Android, or wherever `CARDINAL_BLE_BRIDGE` names a socket.
fn bridge_path(d: &Daemon) -> Option<std::path::PathBuf> {
    if let Some(p) = std::env::var_os("CARDINAL_BLE_BRIDGE") {
        return Some(p.into());
    }
    cfg!(target_os = "android").then(|| d.paths.home.join("bluetooth.sock"))
}

fn system_radio(d: &Daemon) -> Result<Arc<dyn Radio>, String> {
    #[cfg(unix)]
    if let Some(dir) = std::env::var_os("CARDINAL_TEST_BLE_ETHER") {
        let ether = ble::DirEther::new(dir).map_err(|e| e.to_string())?;
        // A radio of an older phone, for tests.
        if std::env::var_os("CARDINAL_TEST_BLE_TOO_OLD").is_some() {
            return Ok(Arc::new(ether.old_radio()));
        }
        return Ok(Arc::new(ether.radio()));
    }
    #[cfg(unix)]
    if let Some(path) = bridge_path(d) {
        let r = ble::BridgeRadio::bind(&path)
            .map_err(|e| format!("cannot listen for the app at {}: {e}", path.display()))?;
        return Ok(Arc::new(r));
    }
    let _ = d;
    #[cfg(target_os = "linux")]
    {
        Ok(Arc::new(crate::bluez::BlueZ::new()))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err("Bluetooth is not built for this system yet".into())
    }
}

/// Starts the controller once: it turns the radio on and off as the
/// setting and the windows say.
pub fn start(d: &Arc<Daemon>) {
    // A persona's devices advertise nothing for it (`identity.md#personas`),
    // and the radio is its device's service's.
    if d.config().this_run.inside() {
        return;
    }
    if d.bluetooth.started.swap(true, Ordering::SeqCst) {
        return;
    }
    // The app that drives the radio may connect before it is turned on.
    if bridge_path(d).is_some() {
        if let Err(e) = radio(d) {
            tracing::warn!("Bluetooth: {e}");
        }
    }
    let d = d.clone();
    tokio::spawn(async move {
        let mut stop = d.stopping.subscribe();
        let mut running: Option<tokio::task::JoinHandle<()>> = None;
        loop {
            let want = wanted(&d);
            let alive = running.as_ref().is_some_and(|h| !h.is_finished());
            if want && !alive {
                running = Some(tokio::spawn(on(d.clone())));
            } else if !want && alive {
                if let Some(h) = running.take() {
                    h.abort();
                }
                off(&d);
                tracing::info!("Bluetooth off");
            }
            tokio::select! {
                _ = d.bluetooth.poke.notified() => {}
                _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                _ = stop.changed() => break,
            }
        }
        if let Some(h) = running.take() {
            h.abort();
        }
        off(&d);
    });
}

fn off(d: &Daemon) {
    *lock(&d.bluetooth.running) = None;
    show(d, |s| {
        s.on = false;
        s.psm = None;
    });
}

/// What this device advertises now: its own devices' tag, its trusted
/// contacts' tag where it gives the secret to anyone, and a one-time tag for
/// each outstanding invitation it answers for.
///
/// The one-time tags come first: someone holding an invitation is looking
/// for this device now, and is to find it soonest.
fn keys(d: &Daemon) -> Keys {
    let mut keys = Vec::new();
    // Someone typing the code is looking now.
    if let Some((channel, tx)) = lock(&d.bluetooth.pairing).as_ref() {
        if !tx.is_closed() {
            keys.push((TagType::OneTime, ble::pairing_key(*channel)));
        }
    }
    for secret in crate::contacts::answered_here(d) {
        keys.push((TagType::OneTime, ble::one_time_key(&secret)));
    }
    let (own, presence) = {
        let core = d.core();
        (core.discovery_secret(), crate::presence::advertised(&core))
    };
    if let Some(s) = own {
        keys.push((TagType::Own, discovery_key(&s)));
    }
    if let Some(s) = presence {
        keys.push((TagType::Contacts, presence_key(&s)));
    }
    Keys { keys }
}

/// The keys tags seen are checked against, derived once for the state they
/// come from.
#[derive(Default)]
struct Known {
    version: Option<u64>,
    own: Option<Zeroizing<[u8; 32]>>,
    contacts: Vec<([u8; 32], Zeroizing<[u8; 32]>)>,
}

impl Known {
    fn fresh(&mut self, d: &Daemon) -> &Known {
        let core = d.core();
        let version = core.state_version();
        if self.version != Some(version) {
            self.own = core.discovery_secret().map(|s| discovery_key(&s));
            self.contacts = crate::presence::of_contacts(&core)
                .iter()
                .map(|(who, s)| (*who, presence_key(s)))
                .collect();
            self.version = Some(version);
        }
        self
    }
}

/// So many in a second at most.
struct Budget {
    since: Instant,
    used: u32,
    per_second: u32,
}

impl Budget {
    fn new(per_second: u32) -> Budget {
        Budget {
            since: Instant::now(),
            used: 0,
            per_second,
        }
    }

    fn take(&mut self) -> bool {
        if self.since.elapsed() >= Duration::from_secs(1) {
            self.since = Instant::now();
            self.used = 0;
        }
        self.used += 1;
        self.used <= self.per_second
    }
}

/// What was last seen of each device, at most [`LAST_MAX`] of them: a
/// sighting is looked at again only when it changed, or after
/// [`SEEN_AGAIN`].
#[derive(Default)]
struct Last(HashMap<BleAddr, (Vec<u8>, Instant)>);

impl Last {
    /// Whether `s` is to be looked at, noting it if so.
    fn fresh(&mut self, s: &Sighting) -> bool {
        let fresh = self
            .0
            .get(&s.addr)
            .is_none_or(|(data, at)| *data != s.data || at.elapsed() >= SEEN_AGAIN);
        if fresh {
            if self.0.len() >= LAST_MAX && !self.0.contains_key(&s.addr) {
                let oldest = self
                    .0
                    .iter()
                    .min_by_key(|(_, (_, at))| *at)
                    .map(|(a, _)| *a);
                if let Some(a) = oldest {
                    self.0.remove(&a);
                }
            }
            self.0.insert(s.addr, (s.data.clone(), Instant::now()));
        }
        fresh
    }

    fn prune(&mut self) {
        self.0
            .retain(|_, (_, at)| at.elapsed() < Duration::from_secs(60));
    }
}

fn same(a: &Keys, b: &Keys) -> bool {
    a.keys.len() == b.keys.len()
        && a.keys
            .iter()
            .zip(&b.keys)
            .all(|((ta, ka), (tb, kb))| ta == tb && ka[..] == kb[..])
}

/// Advertises, scans and listens until aborted, or until the radio fails.
async fn on(d: Arc<Daemon>) {
    if let Err(e) = run(&d).await {
        // Said once, not at every try.
        let again = lock(&d.bluetooth.shown).error.as_ref() == Some(&e);
        if again {
            tracing::debug!("Bluetooth: {e}");
        } else {
            tracing::warn!("Bluetooth: {e}");
        }
        show(&d, |s| s.error = Some(e.clone()));
        off(&d);
        // The controller tries again after this.
        tokio::time::sleep(RETRY_EVERY).await;
    }
}

async fn run(d: &Arc<Daemon>) -> Result<(), String> {
    let radio = radio(d)?;
    let available = radio.available().await.map_err(|e| e.to_string())?;
    show(d, |s| s.available = Some(available.clone()));
    // A radio too old for extended advertisements stays off: nobody would
    // find this device, and there is no short form.
    available.map_err(|e| e.to_string())?;
    let mut listening = radio
        .listen()
        .await
        .map_err(|e| format!("cannot listen: {e}"))?;
    let psm = listening.psm;
    let mut seen = radio
        .scan()
        .await
        .map_err(|e| format!("cannot scan: {e}"))?;
    let mut advertised = keys(d);
    let mut _ad = if advertised.is_empty() {
        None
    } else {
        Some(
            radio
                .advertise(&advertised, psm)
                .await
                .map_err(|e| format!("cannot advertise: {e}"))?,
        )
    };
    show(d, |s| {
        s.on = true;
        s.psm = Some(psm);
        s.error = None;
    });
    *lock(&d.bluetooth.running) = Some(radio.clone());
    tracing::info!("Bluetooth on: {}, PSM {psm}", radio.describe());
    let mut look = tokio::time::interval(LOOK_EVERY);
    let mut made = Instant::now();
    let mut last = Last::default();
    let mut known = Known::default();
    let mut budget = Budget::new(SIGHTINGS_PER_SECOND);
    loop {
        tokio::select! {
            ch = listening.incoming.recv() => {
                let Some((from, ch)) = ch else {
                    return Err("the radio stopped listening".into());
                };
                take_channel(d, from, ch);
            }
            s = seen.recv() => {
                let Some(s) = s else {
                    return Err(match radio.failure() {
                        Some(why) => format!("the radio stopped scanning: {why}"),
                        None => "the radio stopped scanning".into(),
                    });
                };
                if last.fresh(&s) && budget.take() {
                    sighted(d, &radio, s, known.fresh(d));
                }
            }
            _ = look.tick() => {
                last.prune();
                let now = keys(d);
                let every = if now.keys.iter().any(|(t, _)| *t == TagType::OneTime) {
                    ADVERTISE_FAST
                } else {
                    ADVERTISE_EVERY
                };
                if !same(&now, &advertised) || made.elapsed() >= every {
                    // The old one goes first: an adapter holds few.
                    _ad = None;
                    if !now.is_empty() {
                        match radio.advertise(&now, psm).await {
                            Ok(a) => _ad = Some(a),
                            Err(e) => tracing::warn!("Bluetooth: cannot advertise: {e}"),
                        }
                    }
                    advertised = now;
                    made = Instant::now();
                }
            }
        }
    }
}

/// A channel someone opened to this device: carried for the link, which
/// answers only a handshake it can check. At most [`MAX_INCOMING`] at once
/// and [`MAX_PER_ADDR`] from one address; when all are taken, the oldest
/// with no session over it gives way.
fn take_channel(d: &Arc<Daemon>, from: BleAddr, ch: ble::BoxChannel) {
    // While a pairing code shows, the first message says which a channel
    // carries: pairing's is a record, a link packet starts with its type
    // (`carriers/ble.md`).
    let pairing = lock(&d.bluetooth.pairing)
        .as_ref()
        .map(|(_, tx)| tx.clone())
        .filter(|tx| !tx.is_closed());
    if let Some(tx) = pairing {
        let d = d.clone();
        tokio::spawn(async move {
            let mut ch = ch;
            let first = tokio::time::timeout(
                FIRST_WITHIN,
                cardinal_contact::pairing::read_message(&mut ch),
            );
            let Ok(Ok(first)) = first.await else {
                return;
            };
            if cardinal_contact::pairing::is_pairing_message(&first) {
                let _ = tx.try_send((ch, first));
                return;
            }
            let mut head = (first.len() as u16).to_le_bytes().to_vec();
            head.extend_from_slice(&first);
            let ch: ble::BoxChannel = Box::new(ble::Prefixed::new(head, ch));
            link_channel(&d, from, ch);
        });
        return;
    }
    link_channel(d, from, ch);
}

/// A channel someone opened to this device, for the link.
fn link_channel(d: &Arc<Daemon>, from: BleAddr, ch: ble::BoxChannel) {
    {
        let mut held = lock(&d.bluetooth.incoming);
        held.retain(|c| !c.on.is_closed());
        if held.iter().filter(|c| c.from == from).count() >= MAX_PER_ADDR {
            tracing::debug!("Bluetooth: {from} has channels open already; one more is refused");
            return;
        }
        if held.len() >= MAX_INCOMING {
            let oldest = held
                .iter()
                .enumerate()
                .filter(|(_, c)| !d.carried_on(&c.on))
                .min_by_key(|(_, c)| c.at)
                .map(|(i, _)| i);
            match oldest {
                Some(i) => {
                    let c = held.remove(i);
                    tracing::debug!("Bluetooth: a channel from {} gives way", c.from);
                    c.on.close();
                }
                None => {
                    tracing::debug!(
                        "Bluetooth: too many channels open; one from {from} is refused"
                    );
                    return;
                }
            }
        }
        let on = d
            .endpoint
            .attach(ch, CarrierKind::Ble, format!("bluetooth {from}"));
        held.push(Incoming {
            from,
            at: Instant::now(),
            on: on.clone(),
        });
        tokio::spawn(keep_while_used(d.clone(), on));
    }
}

/// Closes a channel once no session has run over it for
/// [`UNPROVEN_WITHIN`]: from the start, for one nobody proved anything on,
/// and after its session ended or moved to a better path.
async fn keep_while_used(d: Arc<Daemon>, on: Attached) {
    let mut used = Instant::now();
    while !on.is_closed() {
        tokio::time::sleep(Duration::from_secs(1)).await;
        if d.carried_on(&on) {
            used = Instant::now();
        } else if used.elapsed() >= UNPROVEN_WITHIN {
            on.close();
        }
    }
}

/// An advertisement under the service UUID: what its tags say to try.
fn sighted(d: &Arc<Daemon>, radio: &Arc<dyn Radio>, s: Sighting, known: &Known) {
    if radio.own_addr() == Some(s.addr) {
        return;
    }
    let Some(ad) = Advert::decode(&s.data) else {
        return;
    };
    d.bluetooth.seen.fetch_add(1, Ordering::Relaxed);
    let seen = Seen {
        addr: s.addr,
        psm: ad.psm,
        radio: radio.clone(),
    };
    let mut recognized = false;
    // Someone here holds an invitation this one answers for.
    {
        let mut wanted = lock(&d.bluetooth.wanted);
        wanted.retain(|(_, tx)| !tx.is_closed());
        for (k, tx) in wanted.iter() {
            if ad.has(k) {
                recognized = true;
                let _ = tx.try_send(seen.clone());
            }
        }
    }
    if known.own.as_ref().is_some_and(|k| ad.has(k)) {
        recognized = true;
        let d = d.clone();
        let seen = seen.clone();
        tokio::spawn(async move { found_own(&d, seen).await });
    }
    // One keyed hash per trusted contact per advertisement.
    let mut found: Vec<[u8; 32]> = Vec::new();
    for (who, k) in &known.contacts {
        if !found.contains(who) && ad.has(k) {
            found.push(*who);
        }
    }
    for who in found {
        recognized = true;
        let d = d.clone();
        let near = crate::rendezvous::Near::Ble(seen.clone());
        tokio::spawn(async move { crate::rendezvous::found_near(&d, who, near).await });
    }
    if recognized {
        d.bluetooth.recognized.fetch_add(1, Ordering::Relaxed);
    }
}

/// One of the person's own devices advertises: each of theirs this device
/// has no session with is tried, at once, on one channel.
async fn found_own(d: &Arc<Daemon>, seen: Seen) {
    if !own_try(&d.bluetooth, seen.addr) {
        return;
    }
    let devices: Vec<(KeyId, HybridPublicKey)> = {
        let core = d.core();
        let Some(ident) = core.identity.as_ref() else {
            return;
        };
        ident
            .state()
            .keys
            .values()
            .filter(|k| k.key != d.keys.key())
            .filter_map(|k| Some((k.key, k.link_key.clone()?)))
            .filter(|(_, l)| !d.is_direct(l.x25519()))
            .collect()
    };
    // Not those a Bluetooth try is on now. The tries over IP keep their own
    // count (`Daemon::connecting`), and this one never holds them up.
    let devices: Vec<_> = {
        let mut dialling = lock(&d.bluetooth.dialling);
        devices
            .into_iter()
            .filter(|(k, _)| dialling.insert(*k))
            .collect()
    };
    if devices.is_empty() {
        return;
    }
    let links: Vec<HybridPublicKey> = devices.iter().map(|(_, l)| l.clone()).collect();
    let r = dial(d, &seen, &links).await;
    {
        let mut dialling = lock(&d.bluetooth.dialling);
        for (k, _) in &devices {
            dialling.remove(k);
        }
    }
    match r {
        Ok(s) => {
            let ps = s.peer_static();
            if let Some((k, _)) = devices.iter().find(|(_, l)| *l.x25519() == ps) {
                tracing::info!(
                    "found {} over Bluetooth, at {}",
                    d.device_name(k),
                    seen.addr
                );
            }
            d.on_session(s);
        }
        Err(e) => tracing::debug!("Bluetooth: own device at {}: {e:#}", seen.addr),
    }
}

/// Whether an own device's tag seen at `addr` may be tried now: once in
/// [`OWN_EVERY`] at one address, and [`OWN_PER_MINUTE`] times a minute at
/// all of them, so that a tag played again from new addresses costs no
/// more.
fn own_try(b: &Bluetooth, addr: BleAddr) -> bool {
    let mut tried = lock(&b.tried);
    if tried.get(&addr).is_some_and(|t| t.elapsed() < OWN_EVERY) {
        return false;
    }
    let mut minute = lock(&b.own_tries);
    while minute
        .front()
        .is_some_and(|t| t.elapsed() >= Duration::from_secs(60))
    {
        minute.pop_front();
    }
    if minute.len() >= OWN_PER_MINUTE {
        return false;
    }
    minute.push_back(Instant::now());
    tried.retain(|_, t| t.elapsed() < OWN_EVERY);
    tried.insert(addr, Instant::now());
    true
}

/// Opens a channel to a device seen, and a session over it with whichever
/// of `links` is at the other end.
pub async fn dial(
    d: &Arc<Daemon>,
    seen: &Seen,
    links: &[HybridPublicKey],
) -> anyhow::Result<Session> {
    let targets = links
        .iter()
        .map(|l| Target::new(NOWHERE, CarrierKind::Ble, l))
        .collect();
    dial_targets(d, seen, targets).await
}

/// Opens a channel to a device seen, and tries every target on it at once.
async fn dial_targets(
    d: &Arc<Daemon>,
    seen: &Seen,
    targets: Vec<Target>,
) -> anyhow::Result<Session> {
    anyhow::ensure!(!targets.is_empty(), "nobody to try");
    let ch = tokio::time::timeout(CHANNEL_WITHIN, seen.radio.connect(seen.addr, seen.psm))
        .await
        .map_err(|_| anyhow::anyhow!("no channel to {} in time", seen.addr))?
        .map_err(|e| anyhow::anyhow!("no channel to {}: {e}", seen.addr))?;
    let on = d
        .endpoint
        .attach(ch, CarrierKind::Ble, format!("bluetooth {}", seen.addr));
    let watched = on.clone();
    let (done, give_up) = watch::channel(false);
    let mut tries = tokio::task::JoinSet::new();
    for t in targets {
        let (ep, on) = (d.endpoint.clone(), on.clone());
        let t = t.within(HANDSHAKE_WITHIN).unless(give_up.clone());
        tries.spawn(async move { ep.connect_on(&on, t).await });
    }
    let mut last = None;
    while let Some(r) = tries.join_next().await {
        match r {
            Ok(Ok(s)) => {
                // The others stop, and clean up after themselves.
                let _ = done.send(true);
                tries.detach_all();
                tokio::spawn(keep_while_used(d.clone(), watched));
                return Ok(s);
            }
            Ok(Err(e)) => last = Some(e.to_string()),
            Err(e) => last = Some(e.to_string()),
        }
    }
    on.close();
    anyhow::bail!(
        "nobody answered on the channel to {} ({})",
        seen.addr,
        last.unwrap_or_default()
    )
}

/// Whether the radio is on now, for what may be found over it.
pub fn is_running(d: &Daemon) -> bool {
    lock(&d.bluetooth.running).is_some()
}

/// Shows a pairing code over Bluetooth too, while `tx` is open: the tag
/// made from its channel is advertised, and channels whose first message
/// is pairing's go to `tx`.
pub fn show_pairing(d: &Daemon, channel: u16, tx: mpsc::Sender<(ble::BoxChannel, Vec<u8>)>) {
    *lock(&d.bluetooth.pairing) = Some((channel, tx));
    d.bluetooth.poke.notify_one();
}

/// The pairing code is no longer shown.
pub fn stop_pairing(d: &Daemon) {
    *lock(&d.bluetooth.pairing) = None;
}

/// Looks nearby for a device showing a pairing code on `channel`, by the
/// tag made from the channel alone. `None` where Bluetooth is off, or
/// nobody was found in time.
pub async fn find_pairing(d: &Arc<Daemon>, channel: u16) -> Option<Seen> {
    lock(&d.bluetooth.running).as_ref()?;
    let (tx, mut rx) = mpsc::channel(4);
    lock(&d.bluetooth.wanted).push((ble::pairing_key(channel), tx));
    tracing::info!("looking for the device showing the pairing code over Bluetooth");
    tokio::time::timeout(PAIRING_WITHIN, rx.recv())
        .await
        .ok()
        .flatten()
}

/// Opens a channel to a device seen.
pub async fn open_channel(seen: &Seen) -> anyhow::Result<ble::BoxChannel> {
    tokio::time::timeout(CHANNEL_WITHIN, seen.radio.connect(seen.addr, seen.psm))
        .await
        .map_err(|_| anyhow::anyhow!("no channel to {} in time", seen.addr))?
        .map_err(|e| anyhow::anyhow!("no channel to {}: {e}", seen.addr))
}

/// Gives a channel a pairing ran over to the link, for the session that
/// follows on it, closed once no session runs over it.
pub fn carry(d: &Arc<Daemon>, ch: ble::BoxChannel, label: String) -> Attached {
    let on = d.endpoint.attach(ch, CarrierKind::Ble, label);
    tokio::spawn(keep_while_used(d.clone(), on.clone()));
    on
}

/// Looks for the device that made `invitation` nearby, by the one-time tag
/// its secret makes, and opens the invitation's session with it. `None`
/// where Bluetooth is off, or nobody advertising it was found in time.
pub async fn find_invitation(
    d: &Arc<Daemon>,
    invitation: &Invitation,
) -> Option<anyhow::Result<Session>> {
    lock(&d.bluetooth.running).as_ref()?;
    let (tx, mut rx) = mpsc::channel(4);
    lock(&d.bluetooth.wanted).push((ble::one_time_key(&invitation.secret), tx));
    tracing::info!("looking for whoever made the invitation over Bluetooth");
    let deadline = tokio::time::Instant::now() + INVITATION_WITHIN;
    let mut last = None;
    while let Ok(Some(seen)) = tokio::time::timeout_at(deadline, rx.recv()).await {
        let target = Target::invitation(
            NOWHERE,
            CarrierKind::Ble,
            invitation.responder_static,
            &invitation.secret,
        );
        match dial_targets(d, &seen, vec![target]).await {
            Ok(s) => return Some(Ok(s)),
            Err(e) => last = Some(e),
        }
    }
    last.map(Err)
}

/// Where Bluetooth stands on this device.
pub fn status(d: &Daemon) -> Value {
    let b = &d.bluetooth;
    let shown = lock(&b.shown);
    let (available, why_not) = match &shown.available {
        None => (Value::Null, Value::Null),
        Some(Ok(())) => (json!(true), Value::Null),
        Some(Err(e)) => (json!(false), json!(e.to_string())),
    };
    let too_old = shown.available == Some(Err(NotAvailable::TooOld));
    json!({
        "mode": mode(d).as_str(),
        "on": shown.on,
        "windows": b.windows.load(Ordering::SeqCst),
        "radio": shown.radio,
        "available": available,
        "why_not": why_not,
        "error": shown.error,
        "psm": shown.psm,
        "seen": b.seen.load(Ordering::Relaxed),
        "recognized": b.recognized.load(Ordering::Relaxed),
        "channels_in": lock(&b.incoming).iter().filter(|c| !c.on.is_closed()).count(),
        // This device's Bluetooth cannot send extended advertisements:
        // Bluetooth stays off, whatever the setting.
        "too_old": too_old,
    })
}

/// Asks the radio whether it can be used, without turning it on, and
/// says where Bluetooth stands.
pub async fn check(d: &Daemon) -> Value {
    if !lock(&d.bluetooth.shown).on {
        let r = match radio(d) {
            Ok(r) => match tokio::time::timeout(Duration::from_secs(3), r.available()).await {
                Ok(Ok(a)) => a,
                Ok(Err(e)) => Err(e.to_string().into()),
                Err(_) => Err("the radio did not answer".to_owned().into()),
            },
            Err(e) => Err(e.into()),
        };
        show(d, |s| s.available = Some(r));
    }
    status(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_own_tag_played_again_from_new_addresses_costs_three_tries_a_minute() {
        let b = Bluetooth::default();
        let at = |i: u8| BleAddr::parse(&format!("C0:00:00:00:00:{i:02X}"), true).unwrap();
        let tried: Vec<bool> = (0..10).map(|i| own_try(&b, at(i))).collect();
        assert_eq!(tried.iter().filter(|x| **x).count(), OWN_PER_MINUTE);
        assert!(tried[..OWN_PER_MINUTE].iter().all(|x| *x));
        // Bluetooth's tries are its own: the set the tries over IP use is
        // not touched (review H1).
        assert!(lock(&b.dialling).is_empty());
    }

    #[test]
    fn what_was_seen_is_kept_bounded_and_looked_at_again_only_when_changed() {
        let mut last = Last::default();
        let at = |i: u16| BleAddr {
            bytes: [0xc0, 0, 0, 0, (i >> 8) as u8, i as u8],
            random: true,
        };
        let s = |i: u16, d: u8| Sighting {
            addr: at(i),
            data: vec![d],
        };
        assert!(last.fresh(&s(1, 1)));
        assert!(!last.fresh(&s(1, 1)), "the same, again at once");
        assert!(last.fresh(&s(1, 2)), "changed");
        for i in 2..(LAST_MAX as u16 + 100) {
            last.fresh(&s(i, 0));
        }
        assert_eq!(last.0.len(), LAST_MAX);
        let mut budget = Budget::new(SIGHTINGS_PER_SECOND);
        let taken = (0..200).filter(|_| budget.take()).count();
        assert_eq!(taken, SIGHTINGS_PER_SECOND as usize);
    }

    #[test]
    fn modes_read_and_write() {
        for m in [Mode::Off, Mode::Open, Mode::Always] {
            assert_eq!(Mode::parse(m.as_str()), Some(m));
        }
        assert_eq!(Mode::parse("on"), None);
        assert_eq!(Mode::default(), Mode::Off);
    }
}
