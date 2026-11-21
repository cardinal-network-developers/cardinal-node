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

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cardinal_contact::ble::{self, Advert, BleAddr, Keys, Radio, Sighting, TagType};
use cardinal_contact::discovery::{discovery_key, presence_key};
use cardinal_contact::Invitation;
use cardinal_crypto::HybridPublicKey;
use cardinal_link::{CarrierKind, Session, Target};
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
/// How long opening a channel may take.
const CHANNEL_WITHIN: Duration = Duration::from_secs(10);
/// How long a handshake over a channel may take.
const HANDSHAKE_WITHIN: Duration = Duration::from_secs(8);
/// How long someone accepting an invitation looks for its tag.
const INVITATION_WITHIN: Duration = Duration::from_secs(30);
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

/// What the person sees of Bluetooth on this device.
#[derive(Default)]
struct Shown {
    /// The radio, in words, once one was made.
    radio: Option<String>,
    /// Whether it could be used, the last time it was asked.
    available: Option<Result<(), String>>,
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
    /// Advertisements under the service UUID seen since start.
    seen: AtomicU64,
    /// Of those, the ones with a tag this device recognized.
    recognized: AtomicU64,
    /// Channels others have open to this device.
    incoming: Arc<AtomicUsize>,
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
    lock(&d.bluetooth.shown).radio = Some(r.describe());
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
    let mut shown = lock(&d.bluetooth.shown);
    shown.on = false;
    shown.psm = None;
}

/// What this device advertises now: its own devices' tag, its trusted
/// contacts' tag where it gives the secret to anyone, and a one-time tag for
/// each outstanding invitation it answers for.
fn keys(d: &Daemon) -> Keys {
    let mut keys = Vec::new();
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
    for secret in crate::contacts::answered_here(d) {
        keys.push((TagType::OneTime, ble::one_time_key(&secret)));
    }
    Keys { keys }
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
        lock(&d.bluetooth.shown).error = Some(e.clone());
        off(&d);
        // The controller tries again after this.
        tokio::time::sleep(RETRY_EVERY).await;
    }
}

async fn run(d: &Arc<Daemon>) -> Result<(), String> {
    let radio = radio(d)?;
    let available = radio.available().await.map_err(|e| e.to_string())?;
    lock(&d.bluetooth.shown).available = Some(available.clone());
    available?;
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
    {
        let mut shown = lock(&d.bluetooth.shown);
        shown.on = true;
        shown.psm = Some(psm);
        shown.error = None;
    }
    *lock(&d.bluetooth.running) = Some(radio.clone());
    tracing::info!("Bluetooth on: {}, PSM {psm}", radio.describe());
    let mut look = tokio::time::interval(LOOK_EVERY);
    let mut made = Instant::now();
    let mut last: HashMap<BleAddr, (Vec<u8>, Instant)> = HashMap::new();
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
                    return Err("the radio stopped scanning".into());
                };
                let fresh = last.get(&s.addr).is_none_or(|(data, at)| {
                    *data != s.data || at.elapsed() >= SEEN_AGAIN
                });
                if fresh {
                    last.retain(|_, (_, at)| at.elapsed() < Duration::from_secs(60));
                    last.insert(s.addr, (s.data.clone(), Instant::now()));
                    sighted(d, &radio, s);
                }
            }
            _ = look.tick() => {
                let now = keys(d);
                if !same(&now, &advertised) || made.elapsed() >= ADVERTISE_EVERY {
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
/// answers only a handshake it can check.
fn take_channel(d: &Arc<Daemon>, from: BleAddr, ch: ble::BoxChannel) {
    let incoming = d.bluetooth.incoming.clone();
    if incoming.load(Ordering::SeqCst) >= MAX_INCOMING {
        tracing::debug!("Bluetooth: too many channels open; one from {from} is refused");
        return;
    }
    incoming.fetch_add(1, Ordering::SeqCst);
    let on = d
        .endpoint
        .attach(ch, CarrierKind::Ble, format!("bluetooth {from}"));
    tokio::spawn(async move {
        while !on.is_closed() {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        incoming.fetch_sub(1, Ordering::SeqCst);
    });
}

/// An advertisement under the service UUID: what its tags say to try.
fn sighted(d: &Arc<Daemon>, radio: &Arc<dyn Radio>, s: Sighting) {
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
            if ad.has(TagType::OneTime, k) {
                recognized = true;
                let _ = tx.try_send(seen.clone());
            }
        }
    }
    let own = d.core().discovery_secret().map(|s| discovery_key(&s));
    if own.is_some_and(|k| ad.has(TagType::Own, &k)) {
        recognized = true;
        let d = d.clone();
        let seen = seen.clone();
        tokio::spawn(async move { found_own(&d, seen).await });
    }
    // One keyed hash per trusted contact per advertisement.
    let theirs = crate::presence::of_contacts(&d.core());
    let mut found: Vec<[u8; 32]> = Vec::new();
    for (who, secret) in &theirs {
        if !found.contains(who) && ad.has(TagType::Contacts, &presence_key(secret)) {
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
    {
        let mut tried = lock(&d.bluetooth.tried);
        if tried
            .get(&seen.addr)
            .is_some_and(|t| t.elapsed() < OWN_EVERY)
        {
            return;
        }
        tried.retain(|_, t| t.elapsed() < OWN_EVERY);
        tried.insert(seen.addr, Instant::now());
    }
    let devices: Vec<(cardinal_identity::KeyId, HybridPublicKey)> = {
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
    // Not those another way is trying now.
    let devices: Vec<_> = {
        let mut connecting = lock(&d.connecting);
        devices
            .into_iter()
            .filter(|(k, _)| connecting.insert(*k))
            .collect()
    };
    if devices.is_empty() {
        return;
    }
    let links: Vec<HybridPublicKey> = devices.iter().map(|(_, l)| l.clone()).collect();
    let r = dial(d, &seen, &links).await;
    {
        let mut connecting = lock(&d.connecting);
        for (k, _) in &devices {
            connecting.remove(k);
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

/// Opens a channel to a device seen, and a session over it with whichever
/// of `links` is at the other end.
pub async fn dial(d: &Daemon, seen: &Seen, links: &[HybridPublicKey]) -> anyhow::Result<Session> {
    let targets = links
        .iter()
        .map(|l| Target::new(NOWHERE, CarrierKind::Ble, l))
        .collect();
    dial_targets(d, seen, targets).await
}

/// Opens a channel to a device seen, and tries every target on it at once.
async fn dial_targets(d: &Daemon, seen: &Seen, targets: Vec<Target>) -> anyhow::Result<Session> {
    anyhow::ensure!(!targets.is_empty(), "nobody to try");
    let ch = tokio::time::timeout(CHANNEL_WITHIN, seen.radio.connect(seen.addr, seen.psm))
        .await
        .map_err(|_| anyhow::anyhow!("no channel to {} in time", seen.addr))?
        .map_err(|e| anyhow::anyhow!("no channel to {}: {e}", seen.addr))?;
    let on = d
        .endpoint
        .attach(ch, CarrierKind::Ble, format!("bluetooth {}", seen.addr));
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

/// Looks for the device that made `invitation` nearby, by the one-time tag
/// its secret makes, and opens the invitation's session with it. `None`
/// where Bluetooth is off, or nobody advertising it was found in time.
pub async fn find_invitation(
    d: &Daemon,
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
        Some(Err(e)) => (json!(false), json!(e)),
    };
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
        "channels_in": b.incoming.load(Ordering::SeqCst),
    })
}

/// Asks the radio whether it can be used, without turning it on, and
/// says where Bluetooth stands.
pub async fn check(d: &Daemon) -> Value {
    if !lock(&d.bluetooth.shown).on {
        let r = match radio(d) {
            Ok(r) => match tokio::time::timeout(Duration::from_secs(3), r.available()).await {
                Ok(Ok(a)) => a,
                Ok(Err(e)) => Err(e.to_string()),
                Err(_) => Err("the radio did not answer".into()),
            },
            Err(e) => Err(e),
        };
        lock(&d.bluetooth.shown).available = Some(r);
    }
    status(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_read_and_write() {
        for m in [Mode::Off, Mode::Open, Mode::Always] {
            assert_eq!(Mode::parse(m.as_str()), Some(m));
        }
        assert_eq!(Mode::parse("on"), None);
        assert_eq!(Mode::default(), Mode::Off);
    }
}
