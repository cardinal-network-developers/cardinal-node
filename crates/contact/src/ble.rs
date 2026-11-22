//! Bluetooth Low Energy (`carriers/ble.md`, D74): finding devices by the
//! tags of local discovery in an advertisement, and the [`Radio`] that
//! advertises, scans and opens L2CAP channels.
//!
//! A device advertises the service UUID [`SERVICE_UUID`] with service data
//! under it: the PSM it listens on (2 bytes, little-endian), then always
//! [`TAGS`] tags of 16 bytes, each `nonce (8) || first8(BLAKE3.keyed_hash(k,
//! nonce))` as on a local network, with no type, in a random order, and
//! random bytes in the places this device has no tag for (D81). The keys:
//!
//! - its own devices', `k = derive("discovery", discovery secret)`;
//! - its trusted contacts', `k = derive("presence", presence secret)`;
//! - `k = derive("one-time", secret)`, while an invitation that carries the
//!   secret is outstanding.
//!
//! Whoever sees one checks every tag against every key they hold.
//!
//! A legacy advertisement cannot hold that much: it has the PSM and one tag,
//! a different one at each refresh, cut to `nonce (4) || first6(...)`
//! ([`Advert::encode_legacy`]). [`Advert::decode`] reads both.
//!
//! Link packets go over an L2CAP connection-oriented channel to that PSM,
//! each prefixed by its length as over TCP; the link crate carries them
//! ([`cardinal_link::Endpoint::attach`]). A tag is a hint to try and nothing
//! more: the session proves whose device it reached.
//!
//! [`Radio`] keeps the radio behind a trait. [`MemoryEther`] is radios in
//! one process; [`DirEther`] is radios in several processes on one machine,
//! meeting in a directory, for tests that run the real service. Neither
//! touches a real radio.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cardinal_crypto::{ct_eq, derive, hash, keyed_hash, random_bytes, Purpose};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

#[cfg(unix)]
mod bridge;
#[cfg(unix)]
pub use bridge::BridgeRadio;

/// The service UUID, random and not one from the Bluetooth SIG.
pub const SERVICE_UUID: &str = "9aff7475-3349-47e9-9d08-96d65641b52f";

/// [`SERVICE_UUID`] as bytes, most significant first.
pub const SERVICE_UUID_BYTES: [u8; 16] = [
    0x9a, 0xff, 0x74, 0x75, 0x33, 0x49, 0x47, 0xe9, 0x9d, 0x08, 0x96, 0xd6, 0x56, 0x41, 0xb5, 0x2f,
];

/// The carrier's name in an endpoint until it is published: the first 8
/// bytes of `BLAKE3("cardinal draft carrier: ble 1")` (`evolution.md`,
/// "Carriers are named by hash").
pub fn carrier_name() -> [u8; 8] {
    let h = hash(b"cardinal draft carrier: ble 1");
    let mut n = [0u8; 8];
    n.copy_from_slice(&h[..8]);
    n
}

/// The bytes of one full tag: a nonce and the first 8 bytes of the keyed
/// hash, as on a local network, with no type.
pub const TAG_LEN: usize = 16;
/// The bytes of a legacy advertisement's service data: the PSM, a 4-byte
/// nonce and the first 6 bytes of the keyed hash.
pub const LEGACY_LEN: usize = 2 + 4 + 6;
/// How many tags an extended advertisement carries, always: places this
/// device has no tag for are random bytes, which look like tags, so that
/// an advertisement says nothing of how many it has, or of what kinds.
pub const TAGS: usize = 4;

/// What a tag is for, on this device only, to choose which to send. A tag
/// carries no type on the air: whoever sees it checks it against every key
/// they hold, and the keys, derived for different purposes, never match
/// each other's tags.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TagType {
    /// The person's own devices (`t=`).
    Own,
    /// Their trusted contacts (`c=`).
    Contacts,
    /// A one-time secret, while an invitation that carries it is
    /// outstanding.
    OneTime,
}

/// `k = derive("one-time", secret)`: the key of a one-time tag.
pub fn one_time_key(secret: &[u8]) -> Zeroizing<[u8; 32]> {
    derive(Purpose::OneTime, secret)
}

/// One tag as it came: full, or cut to fit a legacy advertisement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tag {
    /// `nonce (8) || first8(...)`, or as many random bytes.
    Full([u8; TAG_LEN]),
    /// `nonce (4) || first6(...)`.
    Short([u8; 10]),
}

impl Tag {
    /// A full tag made with `k`.
    pub fn make(k: &[u8; 32], nonce: [u8; 8]) -> Tag {
        let h = keyed_hash(k, &nonce);
        let mut body = [0u8; TAG_LEN];
        body[..8].copy_from_slice(&nonce);
        body[8..].copy_from_slice(&h[..8]);
        Tag::Full(body)
    }

    /// Random bytes in a tag's place, which no key matches.
    pub fn filler() -> Tag {
        Tag::Full(random_bytes())
    }

    /// Whether this is a tag made with `k`.
    pub fn matches(&self, k: &[u8; 32]) -> bool {
        match self {
            Tag::Full(body) => ct_eq(&keyed_hash(k, &body[..8])[..8], &body[8..]),
            Tag::Short(body) => ct_eq(&keyed_hash(k, &body[..4])[..6], &body[4..]),
        }
    }

    /// The same tag cut for a legacy advertisement: the first 4 bytes of
    /// its nonce, and the first 6 of the hash of those 4.
    pub fn shorten(k: &[u8; 32], nonce: [u8; 4]) -> Tag {
        let h = keyed_hash(k, &nonce);
        let mut body = [0u8; 10];
        body[..4].copy_from_slice(&nonce);
        body[4..].copy_from_slice(&h[..6]);
        Tag::Short(body)
    }
}

/// The service data of an advertisement: the PSM, and the tags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Advert {
    /// The L2CAP PSM the device listens on.
    pub psm: u16,
    /// Its tags.
    pub tags: Vec<Tag>,
}

/// The keys a device advertises with, by what each is for: what an
/// [`Advert`] is made from at each refresh, with fresh nonces.
#[derive(Clone, Default)]
pub struct Keys {
    /// Tags to make: own devices, contacts, and each one-time secret.
    pub keys: Vec<(TagType, Zeroizing<[u8; 32]>)>,
}

impl Keys {
    /// Whether there is nothing to advertise.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// [`TAGS`] full tags with fresh nonces, in a random order: the own
    /// devices' and the contacts' tags, one-time tags in the places left
    /// (a random choice of them, if there are more), and random bytes in
    /// any place still empty.
    pub fn advert(&self, psm: u16) -> Advert {
        let (mut once, rest): (Vec<_>, Vec<_>) =
            self.keys.iter().partition(|(t, _)| *t == TagType::OneTime);
        shuffle(&mut once);
        let mut tags: Vec<Tag> = rest
            .into_iter()
            .chain(once)
            .take(TAGS)
            .map(|(_, k)| Tag::make(k, random_bytes()))
            .collect();
        while tags.len() < TAGS {
            tags.push(Tag::filler());
        }
        shuffle(&mut tags);
        Advert { psm, tags }
    }

    /// The one short tag a legacy advertisement holds at refresh `n`: the
    /// keys take turns, and while there are one-time keys, one of them has
    /// every other turn, since someone holding an invitation is looking for
    /// it now.
    pub fn legacy(&self, psm: u16, n: usize) -> Option<Advert> {
        let (once, rest): (Vec<_>, Vec<_>) =
            self.keys.iter().partition(|(t, _)| *t == TagType::OneTime);
        fn pick<'a>(
            of: &[&'a (TagType, Zeroizing<[u8; 32]>)],
            i: usize,
        ) -> Option<&'a (TagType, Zeroizing<[u8; 32]>)> {
            of.get(i % of.len().max(1)).copied()
        }
        let chosen = match (once.is_empty(), rest.is_empty()) {
            (true, _) => pick(&rest, n),
            (false, true) => pick(&once, n),
            (false, false) if n % 2 == 0 => pick(&once, n / 2),
            (false, false) => pick(&rest, n / 2),
        };
        let (_, k) = chosen?;
        Some(Advert {
            psm,
            tags: vec![Tag::shorten(k, random_bytes())],
        })
    }
}

/// Shuffles `v` in place (Fisher–Yates), from fresh randomness.
fn shuffle<T>(v: &mut [T]) {
    for i in (1..v.len()).rev() {
        let r = u64::from_le_bytes(random_bytes());
        v.swap(i, (r % (i as u64 + 1)) as usize);
    }
}

impl Advert {
    /// The service data of an extended advertisement.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.tags.len() * TAG_LEN);
        out.extend_from_slice(&self.psm.to_le_bytes());
        for t in &self.tags {
            match t {
                Tag::Full(body) => out.extend_from_slice(body),
                // A short tag goes only alone, in a legacy advertisement.
                Tag::Short(_) => {}
            }
        }
        out
    }

    /// The service data of a legacy advertisement: the PSM and its first
    /// tag, which must be short.
    pub fn encode_legacy(&self) -> Option<Vec<u8>> {
        let Some(Tag::Short(body)) = self.tags.first() else {
            return None;
        };
        let mut out = Vec::with_capacity(LEGACY_LEN);
        out.extend_from_slice(&self.psm.to_le_bytes());
        out.extend_from_slice(body);
        Some(out)
    }

    /// Reads service data of either kind: the PSM and one short tag, or
    /// the PSM and any number of full ones.
    pub fn decode(data: &[u8]) -> Option<Advert> {
        if data.len() < 2 + TAG_LEN.min(LEGACY_LEN - 2) {
            return None;
        }
        let psm = u16::from_le_bytes([data[0], data[1]]);
        let rest = &data[2..];
        let tags = if data.len() == LEGACY_LEN {
            let mut body = [0u8; 10];
            body.copy_from_slice(rest);
            vec![Tag::Short(body)]
        } else if rest.len() % TAG_LEN == 0 {
            rest.chunks(TAG_LEN)
                .map(|c| {
                    let mut body = [0u8; TAG_LEN];
                    body.copy_from_slice(c);
                    Tag::Full(body)
                })
                .collect()
        } else {
            return None;
        };
        Some(Advert { psm, tags })
    }

    /// Whether any tag is made with `k`.
    pub fn has(&self, k: &[u8; 32]) -> bool {
        self.tags.iter().any(|t| t.matches(k))
    }
}

/// A Bluetooth device address. Addresses rotate, so one is of use only
/// while the device is in range.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BleAddr {
    /// The six bytes, most significant first, as written.
    pub bytes: [u8; 6],
    /// A random address, as a phone's is, and not a public one.
    pub random: bool,
}

impl BleAddr {
    /// A random static address, for a simulated radio.
    pub fn random() -> BleAddr {
        let mut bytes: [u8; 6] = random_bytes();
        bytes[0] |= 0xc0;
        BleAddr {
            bytes,
            random: true,
        }
    }

    /// Reads `AA:BB:CC:DD:EE:FF`.
    pub fn parse(s: &str, random: bool) -> Option<BleAddr> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 6 {
            return None;
        }
        let mut bytes = [0u8; 6];
        for (b, p) in bytes.iter_mut().zip(parts) {
            *b = u8::from_str_radix(p, 16).ok()?;
        }
        Some(BleAddr { bytes, random })
    }

    fn hex(&self) -> String {
        let mut s: String = self.bytes.iter().map(|b| format!("{b:02x}")).collect();
        if self.random {
            s.push('r');
        }
        s
    }

    fn from_hex(s: &str) -> Option<BleAddr> {
        let s = s.trim();
        let (h, random) = match s.strip_suffix('r') {
            Some(h) => (h, true),
            None => (s, false),
        };
        if h.len() != 12 {
            return None;
        }
        let mut bytes = [0u8; 6];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).ok()?;
        }
        Some(BleAddr { bytes, random })
    }
}

impl std::fmt::Display for BleAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let b = &self.bytes;
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        )
    }
}

impl std::fmt::Debug for BleAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

/// An advertisement seen while scanning.
#[derive(Clone, Debug)]
pub struct Sighting {
    /// Who sent it.
    pub addr: BleAddr,
    /// The service data under [`SERVICE_UUID`].
    pub data: Vec<u8>,
}

/// An L2CAP channel, or what stands in for one.
pub trait Channel: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> Channel for T {}

/// A channel, boxed.
pub type BoxChannel = Box<dyn Channel>;

/// A future a [`Radio`] returns.
pub type RadioFuture<'a, T> = Pin<Box<dyn Future<Output = io::Result<T>> + Send + 'a>>;

/// Channels others opened to this device's PSM, each with who opened it.
pub struct Listening {
    /// The PSM.
    pub psm: u16,
    /// The channels as they come. Dropping it stops listening.
    pub incoming: mpsc::Receiver<(BleAddr, BoxChannel)>,
    /// Kept while listening: dropping it stops.
    pub guard: Box<dyn Send>,
}

/// The radio. Each method opens something the caller drops to stop it, so
/// a device stops advertising, scanning and listening by dropping what it
/// holds.
pub trait Radio: Send + Sync + 'static {
    /// What the radio is, for the person: "BlueZ, adapter hci0", say.
    fn describe(&self) -> String;

    /// Whether there is a radio to use, and if not, why not.
    fn available(&self) -> RadioFuture<'_, Result<(), String>>;

    /// Listens for L2CAP channels on a PSM of the system's choosing.
    fn listen(&self) -> RadioFuture<'_, Listening>;

    /// Advertises `ad` until the returned value is dropped; a later call
    /// replaces it.
    fn advertise(&self, keys: &Keys, psm: u16) -> RadioFuture<'_, Box<dyn Send>>;

    /// Scans for advertisements under [`SERVICE_UUID`] until the receiver
    /// is dropped. The same advertisement may be reported many times.
    fn scan(&self) -> RadioFuture<'_, mpsc::Receiver<Sighting>>;

    /// Opens an L2CAP channel to `to` on `psm`.
    fn connect(&self, to: BleAddr, psm: u16) -> RadioFuture<'_, BoxChannel>;

    /// What the radio last said went wrong, where it says: why a scan
    /// stopped, say.
    fn failure(&self) -> Option<String> {
        None
    }

    /// This radio's own address, where it knows it: what it skips when it
    /// sees its own advertisement.
    fn own_addr(&self) -> Option<BleAddr> {
        None
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// How often a simulated radio reports what it sees.
const SIM_SCAN_EVERY: Duration = Duration::from_millis(200);

/// Dropping it runs `f`.
struct OnDrop<F: FnMut() + Send>(F);

impl<F: FnMut() + Send> Drop for OnDrop<F> {
    fn drop(&mut self) {
        (self.0)();
    }
}

// ---------------------------------------------------------------------
// Radios in one process.

#[derive(Default)]
struct Air {
    ads: HashMap<BleAddr, Vec<u8>>,
    listening: HashMap<(BleAddr, u16), mpsc::Sender<(BleAddr, BoxChannel)>>,
    next_psm: u16,
    /// Pairs of radios out of range of each other.
    apart: Vec<(BleAddr, BleAddr)>,
}

/// Radios in one process that hear each other: for tests.
#[derive(Clone, Default)]
pub struct MemoryEther {
    air: Arc<Mutex<Air>>,
}

impl MemoryEther {
    /// An ether with nobody in it.
    pub fn new() -> MemoryEther {
        MemoryEther::default()
    }

    /// A radio in it, at a random address.
    pub fn radio(&self) -> MemoryRadio {
        MemoryRadio {
            air: self.air.clone(),
            addr: BleAddr::random(),
        }
    }

    /// Puts two radios out of range of each other, or back in range.
    pub fn set_apart(&self, a: BleAddr, b: BleAddr, apart: bool) {
        let mut air = lock(&self.air);
        air.apart.retain(|p| *p != (a, b) && *p != (b, a));
        if apart {
            air.apart.push((a, b));
        }
    }
}

impl Air {
    fn in_range(&self, a: BleAddr, b: BleAddr) -> bool {
        !self.apart.iter().any(|p| *p == (a, b) || *p == (b, a))
    }
}

/// A radio in a [`MemoryEther`].
#[derive(Clone)]
pub struct MemoryRadio {
    air: Arc<Mutex<Air>>,
    addr: BleAddr,
}

impl MemoryRadio {
    /// Its address.
    pub fn addr(&self) -> BleAddr {
        self.addr
    }

    /// Advertises service data as it is, until the returned value is
    /// dropped: for a test that stands in for another program's radio.
    pub fn advertise_data(&self, data: Vec<u8>) -> Box<dyn Send> {
        lock(&self.air).ads.insert(self.addr, data);
        let (air, addr) = (self.air.clone(), self.addr);
        Box::new(OnDrop(move || {
            lock(&air).ads.remove(&addr);
        }))
    }
}

impl Radio for MemoryRadio {
    fn describe(&self) -> String {
        format!("a radio in memory at {}", self.addr)
    }

    fn available(&self) -> RadioFuture<'_, Result<(), String>> {
        Box::pin(async { Ok(Ok(())) })
    }

    fn listen(&self) -> RadioFuture<'_, Listening> {
        Box::pin(async move {
            let (tx, rx) = mpsc::channel(16);
            let psm = {
                let mut air = lock(&self.air);
                air.next_psm = air.next_psm.max(0x80) + 1;
                let psm = air.next_psm;
                air.listening.insert((self.addr, psm), tx);
                psm
            };
            let (air, addr) = (self.air.clone(), self.addr);
            let guard = OnDrop(move || {
                lock(&air).listening.remove(&(addr, psm));
            });
            Ok(Listening {
                psm,
                incoming: rx,
                guard: Box::new(guard),
            })
        })
    }

    fn advertise(&self, keys: &Keys, psm: u16) -> RadioFuture<'_, Box<dyn Send>> {
        let data = keys.advert(psm).encode();
        Box::pin(async move {
            lock(&self.air).ads.insert(self.addr, data);
            let (air, addr) = (self.air.clone(), self.addr);
            let guard = OnDrop(move || {
                lock(&air).ads.remove(&addr);
            });
            Ok(Box::new(guard) as Box<dyn Send>)
        })
    }

    fn scan(&self) -> RadioFuture<'_, mpsc::Receiver<Sighting>> {
        Box::pin(async move {
            let (tx, rx) = mpsc::channel(64);
            let (air, me) = (self.air.clone(), self.addr);
            tokio::spawn(async move {
                loop {
                    let seen: Vec<Sighting> = {
                        let air = lock(&air);
                        air.ads
                            .iter()
                            .filter(|(a, _)| **a != me && air.in_range(me, **a))
                            .map(|(a, d)| Sighting {
                                addr: *a,
                                data: d.clone(),
                            })
                            .collect()
                    };
                    for s in seen {
                        if tx.send(s).await.is_err() {
                            return;
                        }
                    }
                    tokio::time::sleep(SIM_SCAN_EVERY).await;
                    if tx.is_closed() {
                        return;
                    }
                }
            });
            Ok(rx)
        })
    }

    fn connect(&self, to: BleAddr, psm: u16) -> RadioFuture<'_, BoxChannel> {
        Box::pin(async move {
            let tx = {
                let air = lock(&self.air);
                if !air.in_range(self.addr, to) {
                    None
                } else {
                    air.listening.get(&(to, psm)).cloned()
                }
            };
            let tx = tx.ok_or_else(|| io::Error::from(io::ErrorKind::ConnectionRefused))?;
            let (near, far) = tokio::io::duplex(64 * 1024);
            tx.send((self.addr, Box::new(far)))
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::ConnectionRefused))?;
            Ok(Box::new(near) as BoxChannel)
        })
    }

    fn own_addr(&self) -> Option<BleAddr> {
        Some(self.addr)
    }
}

// ---------------------------------------------------------------------
// Radios in several processes, meeting in a directory.

/// Radios in several processes on one machine that hear each other through
/// a directory: each advertisement is a file named by the radio's address,
/// and each listening PSM a Unix socket. For tests that run the real
/// service; set `CARDINAL_TEST_BLE_ETHER` to the directory.
#[cfg(unix)]
#[derive(Clone, Debug)]
pub struct DirEther {
    dir: std::path::PathBuf,
}

#[cfg(unix)]
impl DirEther {
    /// The ether in `dir`, made if need be.
    pub fn new(dir: impl Into<std::path::PathBuf>) -> io::Result<DirEther> {
        let dir = dir.into();
        std::fs::create_dir_all(dir.join("ads"))?;
        std::fs::create_dir_all(dir.join("l2cap"))?;
        Ok(DirEther { dir })
    }

    /// A radio in it, at a random address.
    pub fn radio(&self) -> DirRadio {
        DirRadio {
            dir: self.dir.clone(),
            addr: BleAddr::random(),
            next_psm: Arc::new(Mutex::new(0x80)),
        }
    }
}

/// A radio in a [`DirEther`].
#[cfg(unix)]
pub struct DirRadio {
    dir: std::path::PathBuf,
    addr: BleAddr,
    next_psm: Arc<Mutex<u16>>,
}

#[cfg(unix)]
impl DirRadio {
    fn socket(&self, addr: BleAddr, psm: u16) -> std::path::PathBuf {
        self.dir.join("l2cap").join(format!("{}-{psm}", addr.hex()))
    }
}

#[cfg(unix)]
impl Radio for DirRadio {
    fn describe(&self) -> String {
        format!(
            "a simulated radio at {} in {}",
            self.addr,
            self.dir.display()
        )
    }

    fn available(&self) -> RadioFuture<'_, Result<(), String>> {
        Box::pin(async move {
            Ok(match self.dir.join("ads").is_dir() {
                true => Ok(()),
                false => Err(format!("{} is gone", self.dir.display())),
            })
        })
    }

    fn listen(&self) -> RadioFuture<'_, Listening> {
        Box::pin(async move {
            use tokio::io::AsyncReadExt;
            let psm = {
                let mut n = lock(&self.next_psm);
                *n += 1;
                *n
            };
            let path = self.socket(self.addr, psm);
            let _ = std::fs::remove_file(&path);
            let listener = tokio::net::UnixListener::bind(&path)?;
            let (tx, rx) = mpsc::channel::<(BleAddr, BoxChannel)>(16);
            let task = tokio::spawn(async move {
                while let Ok((mut s, _)) = listener.accept().await {
                    // Who opened it, as a radio would say.
                    let mut who = [0u8; 13];
                    let read = tokio::time::timeout(Duration::from_secs(2), s.read_exact(&mut who));
                    let Ok(Ok(_)) = read.await else { continue };
                    let Some(from) = std::str::from_utf8(&who).ok().and_then(BleAddr::from_hex)
                    else {
                        continue;
                    };
                    if tx.send((from, Box::new(s) as BoxChannel)).await.is_err() {
                        break;
                    }
                }
            });
            let guard = OnDrop(move || {
                task.abort();
                let _ = std::fs::remove_file(&path);
            });
            Ok(Listening {
                psm,
                incoming: rx,
                guard: Box::new(guard),
            })
        })
    }

    fn advertise(&self, keys: &Keys, psm: u16) -> RadioFuture<'_, Box<dyn Send>> {
        let data = keys.advert(psm).encode();
        Box::pin(async move {
            let ads = self.dir.join("ads");
            let path = ads.join(self.addr.hex());
            let tmp = ads.join(format!(".{}.tmp", self.addr.hex()));
            std::fs::write(&tmp, &data)?;
            std::fs::rename(&tmp, &path)?;
            let guard = OnDrop(move || {
                let _ = std::fs::remove_file(&path);
            });
            Ok(Box::new(guard) as Box<dyn Send>)
        })
    }

    fn scan(&self) -> RadioFuture<'_, mpsc::Receiver<Sighting>> {
        Box::pin(async move {
            let (tx, rx) = mpsc::channel(64);
            let (ads, me) = (self.dir.join("ads"), self.addr);
            tokio::spawn(async move {
                loop {
                    let mut seen = Vec::new();
                    if let Ok(dir) = std::fs::read_dir(&ads) {
                        for e in dir.flatten() {
                            let name = e.file_name();
                            let Some(addr) = name.to_str().and_then(BleAddr::from_hex) else {
                                continue;
                            };
                            if addr == me {
                                continue;
                            }
                            if let Ok(data) = std::fs::read(e.path()) {
                                seen.push(Sighting { addr, data });
                            }
                        }
                    }
                    for s in seen {
                        if tx.send(s).await.is_err() {
                            return;
                        }
                    }
                    tokio::time::sleep(SIM_SCAN_EVERY).await;
                    if tx.is_closed() {
                        return;
                    }
                }
            });
            Ok(rx)
        })
    }

    fn connect(&self, to: BleAddr, psm: u16) -> RadioFuture<'_, BoxChannel> {
        Box::pin(async move {
            use tokio::io::AsyncWriteExt;
            let mut s = tokio::net::UnixStream::connect(self.socket(to, psm)).await?;
            let mut who = self.addr.hex();
            if !self.addr.random {
                who.push(' ');
            }
            s.write_all(who.as_bytes()).await?;
            Ok(Box::new(s) as BoxChannel)
        })
    }

    fn own_addr(&self) -> Option<BleAddr> {
        Some(self.addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn the_uuid_is_the_one_written() {
        let hex: String = SERVICE_UUID.chars().filter(|c| *c != '-').collect();
        let bytes: Vec<u8> = (0..16)
            .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
            .collect();
        assert_eq!(bytes, SERVICE_UUID_BYTES);
        let name = carrier_name();
        assert_eq!(name[..], hash(b"cardinal draft carrier: ble 1")[..8]);
    }

    #[test]
    fn tags_are_recognized_by_their_key_alone() {
        let own = cardinal_crypto::derive(Purpose::Discovery, &[1; 32]);
        let theirs = cardinal_crypto::derive(Purpose::Presence, &[2; 32]);
        let once = one_time_key(&[3; 16]);
        let keys = Keys {
            keys: vec![
                (TagType::Own, own.clone()),
                (TagType::Contacts, theirs.clone()),
                (TagType::OneTime, once.clone()),
            ],
        };
        let ad = keys.advert(0x81);
        let data = ad.encode();
        // Always four tags of sixteen bytes, whatever there is to say.
        assert_eq!(data.len(), 2 + TAGS * TAG_LEN);
        assert_eq!(&data[..2], &[0x81, 0]);
        let back = Advert::decode(&data).unwrap();
        assert_eq!(back, ad);
        assert!(back.has(&own));
        assert!(back.has(&theirs));
        assert!(back.has(&once));
        // Each tag matches its own key and no other: the keys are derived
        // for different purposes, so a tag needs no type.
        for t in &back.tags {
            let n = [&own, &theirs, &once]
                .iter()
                .filter(|k| t.matches(k))
                .count();
            assert!(n <= 1, "{t:?}");
        }
        assert_eq!(
            back.tags
                .iter()
                .filter(|t| [&own, &theirs, &once].iter().any(|k| t.matches(k)))
                .count(),
            3
        );
        let stranger = cardinal_crypto::derive(Purpose::Presence, &[9; 32]);
        assert!(!back.has(&stranger));
        // Fresh nonces at each refresh: nothing links two advertisements.
        let again = keys.advert(0x81);
        assert_ne!(again.encode(), data);
        assert!(again.has(&theirs));
        // A tampered tag matches nothing.
        let at = back.tags.iter().position(|t| t.matches(&theirs)).unwrap();
        let mut bad = data.clone();
        bad[2 + at * TAG_LEN + 15] ^= 1;
        assert!(!Advert::decode(&bad).unwrap().has(&theirs));
        // Lengths that are neither form are not an advertisement.
        assert!(Advert::decode(&data[..5]).is_none());
        assert!(Advert::decode(&data[..data.len() - 1]).is_none());
        assert!(Advert::decode(&[1]).is_none());
    }

    #[test]
    fn an_advertisement_says_nothing_of_how_many_tags_it_has() {
        let own = cardinal_crypto::derive(Purpose::Discovery, &[1; 32]);
        let one = Keys {
            keys: vec![(TagType::Own, own.clone())],
        };
        let ad = one.advert(0x81);
        // one tag and three places of random bytes, as long as four tags
        assert_eq!(ad.tags.len(), TAGS);
        assert_eq!(ad.encode().len(), 2 + TAGS * TAG_LEN);
        assert_eq!(ad.tags.iter().filter(|t| t.matches(&own)).count(), 1);
        // and where it stands changes
        let places: std::collections::HashSet<usize> = (0..64)
            .map(|_| {
                one.advert(0x81)
                    .tags
                    .iter()
                    .position(|t| t.matches(&own))
                    .unwrap()
            })
            .collect();
        assert!(places.len() > 1, "{places:?}");
        // The filler is not the same twice.
        let filler: Vec<Tag> = ad
            .tags
            .iter()
            .filter(|t| !t.matches(&own))
            .copied()
            .collect();
        assert_eq!(filler.len(), TAGS - 1);
        assert!(filler.windows(2).all(|w| w[0] != w[1]));
        // More than four: the own devices' and the contacts' are always
        // there, and one-time ones fill the rest, a different few each time.
        let theirs = cardinal_crypto::derive(Purpose::Presence, &[2; 32]);
        let onces: Vec<Zeroizing<[u8; 32]>> = (0..5u8).map(|i| one_time_key(&[i; 16])).collect();
        let mut keys = vec![
            (TagType::Own, own.clone()),
            (TagType::Contacts, theirs.clone()),
        ];
        keys.extend(onces.iter().map(|k| (TagType::OneTime, k.clone())));
        let many = Keys { keys };
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let ad = many.advert(1);
            assert_eq!(ad.tags.len(), TAGS);
            assert!(ad.has(&own) && ad.has(&theirs));
            for (i, k) in onces.iter().enumerate() {
                if ad.has(k) {
                    seen.insert(i);
                }
            }
        }
        assert_eq!(seen.len(), onces.len());
        // Nothing to say, and still four places.
        assert_eq!(Keys::default().advert(1).tags.len(), TAGS);
    }

    #[test]
    fn a_legacy_advertisement_carries_one_short_tag_in_turn() {
        let own = cardinal_crypto::derive(Purpose::Discovery, &[1; 32]);
        let theirs = cardinal_crypto::derive(Purpose::Presence, &[2; 32]);
        let keys = Keys {
            keys: vec![
                (TagType::Own, own.clone()),
                (TagType::Contacts, theirs.clone()),
            ],
        };
        let first = keys.legacy(0x99, 0).unwrap();
        let data = first.encode_legacy().unwrap();
        assert_eq!(data.len(), LEGACY_LEN);
        // 31 bytes at most: the service data element (length, type, UUID)
        // and this.
        assert!(2 + 16 + data.len() <= 31);
        let back = Advert::decode(&data).unwrap();
        assert_eq!(back.psm, 0x99);
        assert!(back.has(&own));
        assert!(!back.has(&theirs));
        let second = keys.legacy(0x99, 1).unwrap();
        let back = Advert::decode(&second.encode_legacy().unwrap()).unwrap();
        assert!(back.has(&theirs));
        assert!(Keys::default().legacy(1, 0).is_none());
        // With an invitation outstanding, its tag is in every other one.
        let once = cardinal_crypto::derive(Purpose::OneTime, &[3; 16]);
        let with = Keys {
            keys: vec![
                (TagType::Own, own.clone()),
                (TagType::Contacts, theirs.clone()),
                (TagType::OneTime, once.clone()),
            ],
        };
        let carried: Vec<[bool; 3]> = (0..6)
            .map(|n| {
                let ad =
                    Advert::decode(&with.legacy(1, n).unwrap().encode_legacy().unwrap()).unwrap();
                [ad.has(&own), ad.has(&theirs), ad.has(&once)]
            })
            .collect();
        for (n, c) in carried.iter().enumerate() {
            assert_eq!(c[2], n % 2 == 0, "turn {n}: {c:?}");
        }
        assert!(carried.iter().any(|c| c[0]) && carried.iter().any(|c| c[1]));
        // A full advertisement has no legacy form.
        assert!(keys.advert(1).encode_legacy().is_none());
    }

    #[test]
    fn addresses_read_and_write() {
        let a = BleAddr::parse("C0:11:22:33:44:5F", true).unwrap();
        assert_eq!(a.to_string(), "C0:11:22:33:44:5F");
        assert_eq!(BleAddr::from_hex(&a.hex()), Some(a));
        let p = BleAddr::parse("00:11:22:33:44:55", false).unwrap();
        assert_eq!(BleAddr::from_hex(&p.hex()), Some(p));
        assert!(BleAddr::parse("00:11", false).is_none());
    }

    async fn radios_meet(a: &dyn Radio, b: &dyn Radio, b_addr: BleAddr) {
        let theirs = cardinal_crypto::derive(Purpose::Presence, &[2; 32]);
        let mut listening = b.listen().await.unwrap();
        let keys = Keys {
            keys: vec![(TagType::Contacts, theirs.clone())],
        };
        let ad = b.advertise(&keys, listening.psm).await.unwrap();
        let mut seen = a.scan().await.unwrap();
        let s = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let s = seen.recv().await.unwrap();
                if s.addr == b_addr {
                    return s;
                }
            }
        })
        .await
        .unwrap();
        let advert = Advert::decode(&s.data).unwrap();
        assert!(advert.has(&theirs));
        let mut ch = a.connect(s.addr, advert.psm).await.unwrap();
        let (from, mut far) = listening.incoming.recv().await.unwrap();
        assert_eq!(Some(from), a.own_addr());
        ch.write_all(b"hello").await.unwrap();
        let mut got = [0u8; 5];
        far.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello");
        // Stopping: nobody sees it, nobody can connect.
        drop(ad);
        drop(listening);
        assert!(a.connect(s.addr, advert.psm).await.is_err());
    }

    #[tokio::test]
    async fn memory_radios_find_and_connect() {
        let ether = MemoryEther::new();
        let (a, b) = (ether.radio(), ether.radio());
        radios_meet(&a, &b, b.addr()).await;
        // Out of range, nothing is seen.
        let mut l = b.listen().await.unwrap();
        let _ad = b.advertise(&Keys::default(), l.psm).await.unwrap();
        ether.set_apart(a.addr(), b.addr(), true);
        let mut seen = a.scan().await.unwrap();
        let none = tokio::time::timeout(Duration::from_millis(600), seen.recv()).await;
        assert!(none.is_err(), "a radio out of range is not heard");
        assert!(a.connect(b.addr(), l.psm).await.is_err());
        assert!(l.incoming.try_recv().is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn directory_radios_find_and_connect() {
        let dir = std::env::temp_dir().join(format!(
            "cardinal-ether-{}",
            random_bytes::<6>()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        let ether = DirEther::new(&dir).unwrap();
        let (a, b) = (ether.radio(), ether.radio());
        let b_addr = b.own_addr().unwrap();
        radios_meet(&a, &b, b_addr).await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
