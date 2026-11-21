//! The Bluetooth radio on Linux: BlueZ over D-Bus for advertising and
//! scanning, and the kernel's L2CAP sockets for channels
//! (`carriers/ble.md`). Pure Rust: zbus speaks D-Bus, and the sockets are
//! opened with libc, so neither libdbus nor libbluetooth is linked.
//!
//! - **Advertising**: an `org.bluez.LEAdvertisement1` object this process
//!   serves, registered with the adapter's `LEAdvertisingManager1`, of type
//!   `peripheral` (connectable), with the service UUID in the advertisement
//!   and the service data under it. Where the adapter says an advertisement
//!   cannot hold it all (`SupportedCapabilities`' `MaxAdvLen`), or refuses
//!   it, the advertisement has the UUID and the scan response one short tag
//!   (`ScanResponseServiceData`, which BlueZ has only when run with
//!   `--experimental`). Where the adapter takes a second advertisement, the
//!   legacy one goes beside the full one, for scanners that see only
//!   legacy advertisements.
//! - **Scanning**: `SetDiscoveryFilter` (LE, the service UUID, duplicates
//!   reported) and `StartDiscovery`; each `org.bluez.Device1` whose
//!   `ServiceData` has the UUID is a sighting, again at each change of its
//!   properties, its signal strength included. BlueZ stops the discovery
//!   when this process leaves the bus.
//! - **Privacy**: only with the controller's privacy on (BlueZ's
//!   `Privacy = device`), read from the kernel's management interface or,
//!   where that cannot be read, from `/etc/bluetooth/main.conf`. Without it
//!   the adapter advertises and connects from its fixed public address, by
//!   which anyone could follow the computer, and the radio is not used.
//! - **Channels**: `AF_BLUETOOTH`, `SOCK_STREAM`, `BTPROTO_L2CAP` sockets
//!   bound to an LE address type, so the kernel makes LE credit-based
//!   channels, at security level low: no Bluetooth pairing, since the link
//!   session is what proves and encrypts. The PSM is the kernel's choice
//!   from the LE dynamic range. Writes are cut to the channel's send MTU.

use std::collections::HashMap;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use cardinal_contact::ble::{
    BleAddr, BoxChannel, Keys, Listening, Radio, RadioFuture, Sighting, SERVICE_UUID,
};
use futures_util::StreamExt;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Mutex};
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zbus::{Connection, Proxy};

const BLUEZ: &str = "org.bluez";
const ADAPTER: &str = "org.bluez.Adapter1";
const DEVICE: &str = "org.bluez.Device1";
const ADVERTISING: &str = "org.bluez.LEAdvertisingManager1";

/// BlueZ, on the system bus.
pub struct BlueZ {
    /// The bus, once reached: one connection for this process.
    bus: Mutex<Option<Connection>>,
    /// Another bus than the system's, for tests.
    address: Option<String>,
    /// Advertisements registered, for their object paths.
    made: AtomicU64,
    /// Refreshes of the advertisement: whose turn a legacy one is.
    turn: AtomicU64,
}

impl Default for BlueZ {
    fn default() -> Self {
        BlueZ::new()
    }
}

/// D-Bus errors in words.
fn dbus(e: zbus::Error) -> io::Error {
    io::Error::other(e.to_string())
}

impl BlueZ {
    /// BlueZ on the system bus. Nothing is asked of it until it is used.
    pub fn new() -> BlueZ {
        BlueZ {
            bus: Mutex::new(None),
            address: std::env::var("CARDINAL_TEST_BLUEZ_BUS").ok(),
            made: AtomicU64::new(0),
            turn: AtomicU64::new(0),
        }
    }

    async fn bus(&self) -> io::Result<Connection> {
        let mut held = self.bus.lock().await;
        if let Some(c) = held.as_ref() {
            return Ok(c.clone());
        }
        let c = match &self.address {
            Some(a) => zbus::connection::Builder::address(a.as_str())
                .map_err(dbus)?
                .build()
                .await
                .map_err(dbus)?,
            None => Connection::system().await.map_err(dbus)?,
        };
        *held = Some(c.clone());
        Ok(c)
    }

    /// The first adapter BlueZ has, and its properties.
    async fn adapter(&self) -> io::Result<(OwnedObjectPath, Objects)> {
        let bus = self.bus().await?;
        let all = managed_objects(&bus).await?;
        let mut adapters: Vec<&OwnedObjectPath> = all
            .iter()
            .filter(|(_, ifaces)| ifaces.contains_key(ADAPTER))
            .map(|(p, _)| p)
            .collect();
        adapters.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        let path = adapters
            .first()
            .map(|p| (*p).clone())
            .ok_or_else(|| io::Error::other("BlueZ has no Bluetooth adapter"))?;
        Ok((path, all))
    }
}

type Props = HashMap<String, OwnedValue>;
type Objects = HashMap<OwnedObjectPath, HashMap<String, Props>>;

async fn managed_objects(bus: &Connection) -> io::Result<Objects> {
    let om = Proxy::new(bus, BLUEZ, "/", "org.freedesktop.DBus.ObjectManager")
        .await
        .map_err(dbus)?;
    om.call("GetManagedObjects", &()).await.map_err(dbus)
}

async fn proxy<'a>(
    bus: &Connection,
    path: &'a OwnedObjectPath,
    iface: &'a str,
) -> io::Result<Proxy<'a>> {
    Proxy::new(bus, BLUEZ, path.as_str(), iface)
        .await
        .map_err(dbus)
}

fn get<T: TryFrom<OwnedValue>>(props: &Props, name: &str) -> Option<T> {
    T::try_from(props.get(name)?.try_clone().ok()?).ok()
}

/// The service data under our UUID in a device's properties.
fn service_data(props: &Props) -> Option<Vec<u8>> {
    let all: HashMap<String, OwnedValue> = get(props, "ServiceData")?;
    let (_, v) = all
        .into_iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(SERVICE_UUID))?;
    Vec::<u8>::try_from(v).ok()
}

fn device_addr(props: &Props) -> Option<BleAddr> {
    let addr: String = get(props, "Address")?;
    let kind: String = get(props, "AddressType").unwrap_or_default();
    BleAddr::parse(&addr, kind == "random")
}

/// What a device's properties say, kept by object path: a change of signal
/// strength alone does not carry the service data again.
#[derive(Clone)]
struct Known {
    addr: Option<BleAddr>,
    data: Option<Vec<u8>>,
}

impl Known {
    fn update(&mut self, props: &Props) {
        if let Some(a) = device_addr(props) {
            self.addr = Some(a);
        }
        if let Some(d) = service_data(props) {
            self.data = Some(d);
        }
    }

    fn sighting(&self) -> Option<Sighting> {
        Some(Sighting {
            addr: self.addr?,
            data: self.data.clone()?,
        })
    }
}

/// The most devices whose properties are kept.
const DEVICES_MAX: usize = 300;

/// What is known of devices, by object path, at most [`DEVICES_MAX`]: the
/// one heard from longest ago goes first.
#[derive(Default)]
struct Devices {
    by_path: HashMap<OwnedObjectPath, (Known, u64)>,
    next: u64,
}

impl Devices {
    fn update(&mut self, path: OwnedObjectPath, props: &Props) -> &Known {
        if !self.by_path.contains_key(&path) && self.by_path.len() >= DEVICES_MAX {
            let oldest = self
                .by_path
                .iter()
                .min_by_key(|(_, (_, n))| *n)
                .map(|(p, _)| p.clone());
            if let Some(p) = oldest {
                self.by_path.remove(&p);
            }
        }
        self.next += 1;
        let n = self.next;
        let (k, at) = self.by_path.entry(path).or_insert((
            Known {
                addr: None,
                data: None,
            },
            n,
        ));
        *at = n;
        k.update(props);
        k
    }

    fn remove(&mut self, path: &OwnedObjectPath) {
        self.by_path.remove(path);
    }

    fn all(&self) -> impl Iterator<Item = &Known> {
        self.by_path.values().map(|(k, _)| k)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.by_path.len()
    }
}

// ---------------------------------------------------------------------
// The advertisement this process serves.

/// The advertisement, as BlueZ reads it.
struct Advertisement {
    /// Service data under the UUID, in the advertisement itself.
    data: Option<Vec<u8>>,
    /// Service data in the scan response, for a legacy advertisement.
    scan_response: Option<Vec<u8>>,
}

fn data_map(data: &Option<Vec<u8>>) -> HashMap<String, OwnedValue> {
    let mut m = HashMap::new();
    if let Some(d) = data {
        if let Ok(v) = OwnedValue::try_from(Value::from(d.clone())) {
            m.insert(SERVICE_UUID.to_owned(), v);
        }
    }
    m
}

#[zbus::interface(name = "org.bluez.LEAdvertisement1")]
impl Advertisement {
    /// BlueZ no longer advertises it.
    fn release(&self) {}

    /// Connectable, so a channel can be opened to it.
    #[zbus(property, name = "Type")]
    fn kind(&self) -> String {
        "peripheral".into()
    }

    #[zbus(property, name = "ServiceUUIDs")]
    fn service_uuids(&self) -> Vec<String> {
        vec![SERVICE_UUID.into()]
    }

    #[zbus(property, name = "ServiceData")]
    fn service_data(&self) -> HashMap<String, OwnedValue> {
        data_map(&self.data)
    }

    #[zbus(property, name = "ScanResponseServiceData")]
    fn scan_response_service_data(&self) -> HashMap<String, OwnedValue> {
        data_map(&self.scan_response)
    }
}

/// Unregisters the advertisement when dropped.
struct Advertising {
    bus: Connection,
    adapter: OwnedObjectPath,
    path: OwnedObjectPath,
}

impl Drop for Advertising {
    fn drop(&mut self) {
        let (bus, adapter, path) = (self.bus.clone(), self.adapter.clone(), self.path.clone());
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                if let Ok(m) = proxy(&bus, &adapter, ADVERTISING).await {
                    let _: Result<(), _> = m.call("UnregisterAdvertisement", &(&path,)).await;
                }
                let _ = bus
                    .object_server()
                    .remove::<Advertisement, _>(path.as_str())
                    .await;
            });
        }
    }
}

/// The longest advertisement the adapter says it sends, if it says.
async fn max_adv_len(bus: &Connection, adapter: &OwnedObjectPath) -> Option<usize> {
    let m = proxy(bus, adapter, ADVERTISING).await.ok()?;
    let caps: HashMap<String, OwnedValue> = m.get_property("SupportedCapabilities").await.ok()?;
    let v = caps.get("MaxAdvLen")?.try_clone().ok()?;
    u8::try_from(v).ok().map(usize::from)
}

/// The bytes an advertisement with the service data in it takes: flags,
/// the 128-bit UUID list, and the service data element.
fn full_len(data: &[u8]) -> usize {
    3 + (2 + 16) + (2 + 16 + data.len())
}

impl BlueZ {
    async fn register(
        &self,
        bus: &Connection,
        adapter: &OwnedObjectPath,
        ad: Advertisement,
    ) -> io::Result<Advertising> {
        let n = self.made.fetch_add(1, Ordering::Relaxed);
        let path = format!("/network/cardinal/advertisement{}/{n}", std::process::id());
        let path = OwnedObjectPath::try_from(path).map_err(|e| io::Error::other(e.to_string()))?;
        bus.object_server()
            .at(path.as_str(), ad)
            .await
            .map_err(dbus)?;
        let held = Advertising {
            bus: bus.clone(),
            adapter: adapter.clone(),
            path: path.clone(),
        };
        let m = proxy(bus, adapter, ADVERTISING).await?;
        let options: HashMap<String, OwnedValue> = HashMap::new();
        let r: Result<(), zbus::Error> = m.call("RegisterAdvertisement", &(&path, options)).await;
        r.map_err(dbus)?;
        Ok(held)
    }
}

// ---------------------------------------------------------------------
// Privacy.

/// Why a radio without privacy is not used, and what to do.
pub const NO_PRIVACY: &str = "this computer's Bluetooth would send its fixed address, by which \
     anyone could follow it: set `Privacy = device` under [General] in /etc/bluetooth/main.conf \
     and restart Bluetooth (`systemctl restart bluetooth`)";

/// The adapter's index, from its object path (`/org/bluez/hci0`).
fn adapter_index(path: &str) -> Option<u16> {
    path.rsplit('/').next()?.strip_prefix("hci")?.parse().ok()
}

/// Whether BlueZ's settings turn privacy on: `Privacy` under `[General]`,
/// anything but `off` (the default).
fn privacy_in_conf(conf: &str) -> bool {
    let mut general = false;
    for line in conf.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            general = line.eq_ignore_ascii_case("[general]");
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            if general && k.trim() == "Privacy" {
                return !v.trim().eq_ignore_ascii_case("off");
            }
        }
    }
    false
}

/// The kernel's management interface, for what BlueZ's D-Bus does not
/// say: whether the controller uses resolvable private addresses.
pub mod mgmt {
    use super::*;

    const AF_BLUETOOTH: libc::c_int = 31;
    const BTPROTO_HCI: libc::c_int = 1;
    const HCI_CHANNEL_CONTROL: u16 = 3;
    const HCI_DEV_NONE: u16 = 0xffff;
    /// Read Controller Information.
    const READ_INFO: u16 = 0x0004;
    /// Command Complete.
    const COMPLETE: u16 = 0x0001;
    /// The Privacy bit of the current settings.
    const PRIVACY: u32 = 1 << 13;

    #[repr(C)]
    struct SockaddrHci {
        family: libc::sa_family_t,
        dev: u16,
        channel: u16,
    }

    /// Whether controller `index` has privacy on, if the kernel says.
    /// Reading controller information needs no privilege.
    pub fn privacy(index: u16) -> Option<bool> {
        // SAFETY: plain socket calls on a descriptor this function owns.
        let fd = unsafe {
            libc::socket(
                AF_BLUETOOTH,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                BTPROTO_HCI,
            )
        };
        if fd < 0 {
            return None;
        }
        // SAFETY: `fd` is a new descriptor, owned from here.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let addr = SockaddrHci {
            family: AF_BLUETOOTH as libc::sa_family_t,
            dev: HCI_DEV_NONE,
            channel: HCI_CHANNEL_CONTROL,
        };
        // SAFETY: `addr` is a valid `sockaddr_hci` of the length given.
        let r = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &addr as *const SockaddrHci as *const libc::sockaddr,
                std::mem::size_of::<SockaddrHci>() as libc::socklen_t,
            )
        };
        if r < 0 {
            return None;
        }
        let mut cmd = Vec::with_capacity(6);
        cmd.extend_from_slice(&READ_INFO.to_le_bytes());
        cmd.extend_from_slice(&index.to_le_bytes());
        cmd.extend_from_slice(&0u16.to_le_bytes());
        // SAFETY: writes `cmd.len()` bytes from `cmd`.
        let n = unsafe { libc::write(fd.as_raw_fd(), cmd.as_ptr().cast(), cmd.len()) };
        if n != cmd.len() as isize {
            return None;
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        let mut buf = vec![0u8; 1024];
        while let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) {
            let mut p = libc::pollfd {
                fd: fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one valid `pollfd`.
            let r = unsafe { libc::poll(&mut p, 1, left.as_millis().max(1) as libc::c_int) };
            if r <= 0 {
                return None;
            }
            // SAFETY: reads at most `buf.len()` bytes into `buf`.
            let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                return None;
            }
            if let Some(p) = privacy_in_reply(&buf[..n as usize], index) {
                return p;
            }
        }
        None
    }

    /// What an event on the control channel says of privacy:
    /// `Some(Some(on))` for the answer to Read Controller Information for
    /// `index`, `Some(None)` where that failed, `None` for another event.
    pub fn privacy_in_reply(ev: &[u8], index: u16) -> Option<Option<bool>> {
        let u16_at = |i: usize| Some(u16::from_le_bytes(ev.get(i..i + 2)?.try_into().ok()?));
        if u16_at(0)? != COMPLETE || u16_at(2)? != index || u16_at(6)? != READ_INFO {
            return None;
        }
        if *ev.get(8)? != 0 {
            return Some(None);
        }
        // Address (6), version (1), manufacturer (2), supported (4), then
        // the current settings.
        let at = 9 + 6 + 1 + 2 + 4;
        let current = u32::from_le_bytes(ev.get(at..at + 4)?.try_into().ok()?);
        Some(Some(current & PRIVACY != 0))
    }
}

// ---------------------------------------------------------------------
// The radio.

impl Radio for BlueZ {
    fn describe(&self) -> String {
        "BlueZ".into()
    }

    fn available(&self) -> RadioFuture<'_, Result<(), String>> {
        Box::pin(async move {
            let (path, all) = match self.adapter().await {
                Ok(x) => x,
                Err(e) => return Ok(Err(format!("no Bluetooth here: {e}"))),
            };
            let ifaces = &all[&path];
            if !ifaces.contains_key(ADVERTISING) {
                return Ok(Err(format!(
                    "{} cannot advertise over Bluetooth Low Energy",
                    path.as_str()
                )));
            }
            let powered: bool = get(&ifaces[ADAPTER], "Powered").unwrap_or(false);
            if !powered {
                return Ok(Err(format!(
                    "Bluetooth is off on this computer ({})",
                    path.as_str()
                )));
            }
            // Without privacy, the adapter advertises and connects from its
            // fixed address, and anyone could follow this computer by it.
            let index = adapter_index(path.as_str());
            let private = match index {
                Some(i) => tokio::task::spawn_blocking(move || mgmt::privacy(i))
                    .await
                    .ok()
                    .flatten(),
                None => None,
            };
            let private = private.or_else(|| {
                let conf = std::fs::read_to_string("/etc/bluetooth/main.conf").ok()?;
                Some(privacy_in_conf(&conf))
            });
            if private != Some(true) {
                return Ok(Err(NO_PRIVACY.into()));
            }
            Ok(Ok(()))
        })
    }

    fn listen(&self) -> RadioFuture<'_, Listening> {
        Box::pin(async move {
            let listener = l2cap::Listener::bind()?;
            let psm = listener.psm()?;
            let (tx, rx) = mpsc::channel::<(BleAddr, BoxChannel)>(16);
            let task = tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((s, from)) => {
                            if tx.send((from, Box::new(s) as BoxChannel)).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            tracing::debug!("Bluetooth: accepting a channel: {e}");
                            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                        }
                    }
                }
            });
            Ok(Listening {
                psm,
                incoming: rx,
                guard: Box::new(AbortOnDrop(task)),
            })
        })
    }

    fn advertise(&self, keys: &Keys, psm: u16) -> RadioFuture<'_, Box<dyn Send>> {
        let full = keys.advert(psm).encode();
        let n = self.turn.fetch_add(1, Ordering::Relaxed) as usize;
        let legacy = keys.legacy(psm, n).and_then(|a| a.encode_legacy());
        Box::pin(async move {
            let bus = self.bus().await?;
            let (adapter, _) = self.adapter().await?;
            let fits = max_adv_len(&bus, &adapter)
                .await
                .is_none_or(|max| full_len(&full) <= max);
            let legacy_ad = || Advertisement {
                data: None,
                scan_response: legacy.clone(),
            };
            if fits {
                let ad = Advertisement {
                    data: Some(full),
                    scan_response: None,
                };
                match self.register(&bus, &adapter, ad).await {
                    Ok(a) => {
                        // A legacy one beside it, where the adapter has room,
                        // for scanners that see no extended advertisement.
                        let beside = match self.register(&bus, &adapter, legacy_ad()).await {
                            Ok(b) => Some(b),
                            Err(e) => {
                                tracing::debug!("Bluetooth: no legacy advertisement beside: {e}");
                                None
                            }
                        };
                        return Ok(Box::new((a, beside)) as Box<dyn Send>);
                    }
                    Err(e) => tracing::debug!("Bluetooth: a full advertisement: {e}"),
                }
            }
            let a = self.register(&bus, &adapter, legacy_ad()).await?;
            Ok(Box::new(a) as Box<dyn Send>)
        })
    }

    fn scan(&self) -> RadioFuture<'_, mpsc::Receiver<Sighting>> {
        Box::pin(async move {
            let bus = self.bus().await?;
            let (adapter, all) = self.adapter().await?;
            let a = proxy(&bus, &adapter, ADAPTER).await?;
            let mut filter: HashMap<&str, Value> = HashMap::new();
            filter.insert("Transport", Value::from("le"));
            filter.insert("UUIDs", Value::from(vec![SERVICE_UUID]));
            filter.insert("DuplicateData", Value::from(true));
            let r: Result<(), zbus::Error> = a.call("SetDiscoveryFilter", &(filter,)).await;
            r.map_err(dbus)?;
            // Only what is said of devices: their properties changing, and
            // their coming and going.
            let changes = zbus::MatchRule::builder()
                .msg_type(zbus::message::Type::Signal)
                .sender(BLUEZ)
                .map_err(dbus)?
                .interface("org.freedesktop.DBus.Properties")
                .map_err(dbus)?
                .member("PropertiesChanged")
                .map_err(dbus)?
                .arg(0, DEVICE)
                .map_err(dbus)?
                .build();
            let comings = zbus::MatchRule::builder()
                .msg_type(zbus::message::Type::Signal)
                .sender(BLUEZ)
                .map_err(dbus)?
                .interface("org.freedesktop.DBus.ObjectManager")
                .map_err(dbus)?
                .build();
            let changes = zbus::MessageStream::for_match_rule(changes, &bus, Some(256))
                .await
                .map_err(dbus)?;
            let comings = zbus::MessageStream::for_match_rule(comings, &bus, Some(64))
                .await
                .map_err(dbus)?;
            let mut signals = futures_util::stream::select(changes, comings);
            let r: Result<(), zbus::Error> = a.call("StartDiscovery", &()).await;
            r.map_err(dbus)?;
            let (tx, rx) = mpsc::channel(64);
            let mut known = Devices::default();
            for (path, ifaces) in all {
                if let Some(props) = ifaces.get(DEVICE) {
                    known.update(path, props);
                }
            }
            drop(a);
            tokio::spawn(async move {
                for k in known.all() {
                    if let Some(s) = k.sighting() {
                        let _ = tx.try_send(s);
                    }
                }
                loop {
                    let msg = tokio::select! {
                        m = signals.next() => m,
                        _ = tx.closed() => None,
                    };
                    let Some(Ok(msg)) = msg else { break };
                    let header = msg.header();
                    let member = header.member().map(|m| m.as_str().to_owned());
                    let changed: Option<(OwnedObjectPath, Props)> = match member.as_deref() {
                        Some("InterfacesRemoved") => {
                            let gone = msg
                                .body()
                                .deserialize::<(OwnedObjectPath, Vec<String>)>()
                                .ok();
                            if let Some((p, ifaces)) = gone {
                                if ifaces.iter().any(|i| i == DEVICE) {
                                    known.remove(&p);
                                }
                            }
                            None
                        }
                        Some("InterfacesAdded") => msg
                            .body()
                            .deserialize::<(OwnedObjectPath, HashMap<String, Props>)>()
                            .ok()
                            .and_then(|(p, mut i)| Some((p, i.remove(DEVICE)?))),
                        Some("PropertiesChanged") => {
                            let path = header.path().map(|p| OwnedObjectPath::from(p.to_owned()));
                            let body = msg.body();
                            let b = body.deserialize::<(String, Props, Vec<String>)>().ok();
                            match (path, b) {
                                (Some(p), Some((iface, props, _))) if iface == DEVICE => {
                                    Some((p, props))
                                }
                                _ => None,
                            }
                        }
                        _ => None,
                    };
                    let Some((path, props)) = changed else {
                        continue;
                    };
                    let k = known.update(path, &props);
                    if let Some(s) = k.sighting() {
                        if tx.send(s).await.is_err() {
                            break;
                        }
                    }
                }
                if let Ok(a) = proxy(&bus, &adapter, ADAPTER).await {
                    let _: Result<(), _> = a.call("StopDiscovery", &()).await;
                }
            });
            Ok(rx)
        })
    }

    fn connect(&self, to: BleAddr, psm: u16) -> RadioFuture<'_, BoxChannel> {
        Box::pin(async move {
            let s = l2cap::Stream::connect(to, psm).await?;
            Ok(Box::new(s) as BoxChannel)
        })
    }
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

// ---------------------------------------------------------------------
// L2CAP sockets.

/// L2CAP LE credit-based channels through the kernel's sockets.
pub mod l2cap {
    use super::*;

    const AF_BLUETOOTH: libc::c_int = 31;
    const BTPROTO_L2CAP: libc::c_int = 0;
    const SOL_BLUETOOTH: libc::c_int = 274;
    const BT_SECURITY: libc::c_int = 4;
    const BT_SECURITY_LOW: u8 = 1;
    const BT_SNDMTU: libc::c_int = 12;
    const BDADDR_LE_PUBLIC: u8 = 1;
    const BDADDR_LE_RANDOM: u8 = 2;

    /// `struct sockaddr_l2`.
    #[repr(C)]
    #[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
    pub struct SockaddrL2 {
        pub l2_family: libc::sa_family_t,
        pub l2_psm: u16,
        pub l2_bdaddr: [u8; 6],
        pub l2_cid: u16,
        pub l2_bdaddr_type: u8,
    }

    /// `struct bt_security`.
    #[repr(C)]
    struct BtSecurity {
        level: u8,
        key_size: u8,
    }

    impl SockaddrL2 {
        /// For `to` on `psm`. The kernel keeps an address least
        /// significant byte first.
        pub fn of(to: Option<BleAddr>, psm: u16) -> SockaddrL2 {
            let mut bdaddr = to.map(|a| a.bytes).unwrap_or_default();
            bdaddr.reverse();
            SockaddrL2 {
                l2_family: AF_BLUETOOTH as libc::sa_family_t,
                l2_psm: psm.to_le(),
                l2_bdaddr: bdaddr,
                l2_cid: 0,
                l2_bdaddr_type: match to {
                    Some(a) if a.random => BDADDR_LE_RANDOM,
                    _ => BDADDR_LE_PUBLIC,
                },
            }
        }

        /// The address in it.
        pub fn addr(&self) -> BleAddr {
            let mut bytes = self.l2_bdaddr;
            bytes.reverse();
            BleAddr {
                bytes,
                random: self.l2_bdaddr_type == BDADDR_LE_RANDOM,
            }
        }

        /// The PSM in it.
        pub fn psm(&self) -> u16 {
            u16::from_le(self.l2_psm)
        }
    }

    fn register(fd: OwnedFd) -> io::Result<AsyncFd<OwnedFd>> {
        // SAFETY: the descriptor is owned, and is neither replaced nor
        // closed while the `AsyncFd` holds it.
        Ok(unsafe { AsyncFd::register(fd)? })
    }

    fn check(r: libc::c_int) -> io::Result<libc::c_int> {
        if r < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(r)
        }
    }

    fn socket() -> io::Result<OwnedFd> {
        // SAFETY: plain system calls on a new descriptor this owns.
        unsafe {
            let fd = check(libc::socket(
                AF_BLUETOOTH,
                libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                BTPROTO_L2CAP,
            ))?;
            let fd = OwnedFd::from_raw_fd(fd);
            let sec = BtSecurity {
                level: BT_SECURITY_LOW,
                key_size: 0,
            };
            check(libc::setsockopt(
                fd.as_raw_fd(),
                SOL_BLUETOOTH,
                BT_SECURITY,
                &sec as *const BtSecurity as *const libc::c_void,
                std::mem::size_of::<BtSecurity>() as libc::socklen_t,
            ))?;
            Ok(fd)
        }
    }

    fn bind(fd: &OwnedFd, at: &SockaddrL2) -> io::Result<()> {
        // SAFETY: `at` is a valid sockaddr_l2 for its size.
        unsafe {
            check(libc::bind(
                fd.as_raw_fd(),
                at as *const SockaddrL2 as *const libc::sockaddr,
                std::mem::size_of::<SockaddrL2>() as libc::socklen_t,
            ))?;
        }
        Ok(())
    }

    fn local(fd: &OwnedFd) -> io::Result<SockaddrL2> {
        let mut a = SockaddrL2::default();
        let mut len = std::mem::size_of::<SockaddrL2>() as libc::socklen_t;
        // SAFETY: `a` has room for `len` bytes.
        unsafe {
            check(libc::getsockname(
                fd.as_raw_fd(),
                &mut a as *mut SockaddrL2 as *mut libc::sockaddr,
                &mut len,
            ))?;
        }
        Ok(a)
    }

    fn send_mtu(fd: &OwnedFd) -> usize {
        let mut mtu: u16 = 0;
        let mut len = std::mem::size_of::<u16>() as libc::socklen_t;
        // SAFETY: `mtu` has room for `len` bytes.
        let r = unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                SOL_BLUETOOTH,
                BT_SNDMTU,
                &mut mtu as *mut u16 as *mut libc::c_void,
                &mut len,
            )
        };
        if r < 0 || mtu == 0 {
            // The smallest an LE channel may have.
            23
        } else {
            usize::from(mtu)
        }
    }

    /// A socket listening for channels.
    pub struct Listener {
        fd: AsyncFd<OwnedFd>,
    }

    impl Listener {
        /// Listens on a PSM of the kernel's choosing.
        pub fn bind() -> io::Result<Listener> {
            let fd = socket()?;
            bind(&fd, &SockaddrL2::of(None, 0))?;
            // SAFETY: a bound socket this owns.
            unsafe {
                check(libc::listen(fd.as_raw_fd(), 8))?;
            }
            Ok(Listener { fd: register(fd)? })
        }

        /// The PSM listened on.
        pub fn psm(&self) -> io::Result<u16> {
            Ok(local(self.fd.get_ref())?.psm())
        }

        /// The next channel, and who opened it.
        pub async fn accept(&self) -> io::Result<(Stream, BleAddr)> {
            loop {
                let mut guard = self.fd.readable().await?;
                let mut peer = SockaddrL2::default();
                let mut len = std::mem::size_of::<SockaddrL2>() as libc::socklen_t;
                // SAFETY: `peer` has room for `len` bytes.
                let r = unsafe {
                    libc::accept4(
                        self.fd.get_ref().as_raw_fd(),
                        &mut peer as *mut SockaddrL2 as *mut libc::sockaddr,
                        &mut len,
                        libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                    )
                };
                if r < 0 {
                    let e = io::Error::last_os_error();
                    if e.kind() == io::ErrorKind::WouldBlock {
                        guard.clear_ready();
                        continue;
                    }
                    return Err(e);
                }
                // SAFETY: a new descriptor the kernel gave this process.
                let fd = unsafe { OwnedFd::from_raw_fd(r) };
                return Ok((Stream::new(fd)?, peer.addr()));
            }
        }
    }

    /// An open channel.
    pub struct Stream {
        fd: AsyncFd<OwnedFd>,
        mtu: usize,
    }

    impl Stream {
        fn new(fd: OwnedFd) -> io::Result<Stream> {
            let mtu = send_mtu(&fd);
            Ok(Stream {
                fd: register(fd)?,
                mtu,
            })
        }

        /// Opens a channel to `to` on `psm`.
        pub async fn connect(to: BleAddr, psm: u16) -> io::Result<Stream> {
            let fd = socket()?;
            bind(&fd, &SockaddrL2::of(None, 0))?;
            let at = SockaddrL2::of(Some(to), psm);
            // SAFETY: `at` is a valid sockaddr_l2 for its size.
            let r = unsafe {
                libc::connect(
                    fd.as_raw_fd(),
                    &at as *const SockaddrL2 as *const libc::sockaddr,
                    std::mem::size_of::<SockaddrL2>() as libc::socklen_t,
                )
            };
            if r < 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() != Some(libc::EINPROGRESS) {
                    return Err(e);
                }
            }
            let fd = register(fd)?;
            let _ = fd.writable().await?;
            let mut err: libc::c_int = 0;
            let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            // SAFETY: `err` has room for `len` bytes.
            unsafe {
                check(libc::getsockopt(
                    fd.get_ref().as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    &mut err as *mut libc::c_int as *mut libc::c_void,
                    &mut len,
                ))?;
            }
            if err != 0 {
                return Err(io::Error::from_raw_os_error(err));
            }
            let mtu = send_mtu(fd.get_ref());
            Ok(Stream { fd, mtu })
        }
    }

    impl AsyncRead for Stream {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            loop {
                let mut guard = ready!(self.fd.poll_read_ready(cx))?;
                let space = buf.initialize_unfilled();
                // SAFETY: `space` is writable for its length.
                let r = unsafe {
                    libc::read(
                        self.fd.get_ref().as_raw_fd(),
                        space.as_mut_ptr() as *mut libc::c_void,
                        space.len(),
                    )
                };
                if r < 0 {
                    let e = io::Error::last_os_error();
                    if e.kind() == io::ErrorKind::WouldBlock {
                        guard.clear_ready();
                        continue;
                    }
                    return Poll::Ready(Err(e));
                }
                buf.advance(r as usize);
                return Poll::Ready(Ok(()));
            }
        }
    }

    impl AsyncWrite for Stream {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            let n = data.len().min(self.mtu);
            loop {
                let mut guard = ready!(self.fd.poll_write_ready(cx))?;
                // SAFETY: `data` is readable for `n` bytes.
                let r = unsafe {
                    libc::write(
                        self.fd.get_ref().as_raw_fd(),
                        data.as_ptr() as *const libc::c_void,
                        n,
                    )
                };
                if r < 0 {
                    let e = io::Error::last_os_error();
                    if e.kind() == io::ErrorKind::WouldBlock {
                        guard.clear_ready();
                        continue;
                    }
                    return Poll::Ready(Err(e));
                }
                return Poll::Ready(Ok(r as usize));
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            // SAFETY: a socket this owns.
            unsafe {
                libc::shutdown(self.fd.get_ref().as_raw_fd(), libc::SHUT_WR);
            }
            Poll::Ready(Ok(()))
        }
    }
}

#[allow(dead_code)]
fn _assert_send(b: BlueZ) -> Arc<dyn Radio> {
    Arc::new(b)
}

#[cfg(test)]
mod tests {
    use super::l2cap::SockaddrL2;
    use super::*;

    #[test]
    fn a_socket_address_is_kept_least_significant_byte_first() {
        assert_eq!(std::mem::size_of::<SockaddrL2>(), 14);
        let a = BleAddr::parse("C0:11:22:33:44:55", true).unwrap();
        let s = SockaddrL2::of(Some(a), 0x0081);
        assert_eq!(s.l2_bdaddr, [0x55, 0x44, 0x33, 0x22, 0x11, 0xc0]);
        assert_eq!(s.l2_bdaddr_type, 2);
        assert_eq!(s.psm(), 0x81);
        assert_eq!(s.addr(), a);
        let p = BleAddr::parse("00:11:22:33:44:55", false).unwrap();
        assert_eq!(SockaddrL2::of(Some(p), 1).l2_bdaddr_type, 1);
        // Listening: any address, an LE type, the PSM the kernel picks.
        let any = SockaddrL2::of(None, 0);
        assert_eq!(
            (any.l2_bdaddr, any.l2_bdaddr_type, any.psm()),
            ([0; 6], 1, 0)
        );
    }

    #[test]
    fn a_full_advertisement_fits_an_extended_one() {
        use cardinal_contact::ble::{Advert, Tag, TagType};
        let k = [7u8; 32];
        let tags = (0..cardinal_contact::ble::MAX_TAGS)
            .map(|_| Tag::make(TagType::Contacts, &k, [1; 8]))
            .collect();
        let data = Advert { psm: 0x81, tags }.encode();
        // An extended advertisement holds up to 251 bytes in one packet.
        assert!(full_len(&data) <= 251);
        // Three tags are already more than a legacy one holds.
        let three = Advert {
            psm: 0x81,
            tags: vec![Tag::make(TagType::Own, &k, [1; 8]); 3],
        };
        assert!(full_len(&three.encode()) > 31);
    }

    #[test]
    fn privacy_is_read_from_the_kernel_or_the_settings() {
        // Command Complete for Read Controller Information on hci0.
        let mut ev = vec![];
        ev.extend_from_slice(&1u16.to_le_bytes());
        ev.extend_from_slice(&0u16.to_le_bytes());
        ev.extend_from_slice(&0u16.to_le_bytes()); // length, unread
        ev.extend_from_slice(&4u16.to_le_bytes());
        ev.push(0); // status
        ev.extend_from_slice(&[0; 6 + 1 + 2 + 4]);
        let mut on = ev.clone();
        on.extend_from_slice(&(1u32 << 13 | 1).to_le_bytes());
        let mut off = ev.clone();
        off.extend_from_slice(&1u32.to_le_bytes());
        assert_eq!(mgmt::privacy_in_reply(&on, 0), Some(Some(true)));
        assert_eq!(mgmt::privacy_in_reply(&off, 0), Some(Some(false)));
        assert_eq!(mgmt::privacy_in_reply(&on, 1), None, "another adapter's");
        let mut failed = ev[..8].to_vec();
        failed.push(0x0d);
        assert_eq!(mgmt::privacy_in_reply(&failed, 0), Some(None));
        assert_eq!(mgmt::privacy_in_reply(&[6, 0, 0, 0], 0), None);

        assert!(!privacy_in_conf(""));
        assert!(!privacy_in_conf("[General]\n#Privacy = device\n"));
        assert!(privacy_in_conf("[General]\nName = x\nPrivacy = device\n"));
        assert!(!privacy_in_conf("[General]\nPrivacy=off\n"));
        assert!(!privacy_in_conf("[Policy]\nPrivacy = device\n"));
        assert_eq!(adapter_index("/org/bluez/hci1"), Some(1));
        assert_eq!(adapter_index("/org/bluez"), None);
    }

    #[test]
    fn a_bounded_number_of_devices_is_kept() {
        let mut devices = Devices::default();
        let props: Props = HashMap::new();
        for i in 0..DEVICES_MAX + 50 {
            let p = OwnedObjectPath::try_from(format!("/org/bluez/hci0/dev_{i}")).unwrap();
            devices.update(p, &props);
        }
        assert_eq!(devices.len(), DEVICES_MAX);
        let first = OwnedObjectPath::try_from("/org/bluez/hci0/dev_0").unwrap();
        assert!(!devices.by_path.contains_key(&first), "the oldest went");
        let last =
            OwnedObjectPath::try_from(format!("/org/bluez/hci0/dev_{}", DEVICES_MAX + 49)).unwrap();
        devices.remove(&last);
        assert_eq!(devices.len(), DEVICES_MAX - 1);
    }

    #[test]
    fn a_device_says_its_service_data() {
        let mut props: Props = HashMap::new();
        props.insert(
            "Address".into(),
            OwnedValue::try_from(Value::from("C0:11:22:33:44:55")).unwrap(),
        );
        props.insert(
            "AddressType".into(),
            OwnedValue::try_from(Value::from("random")).unwrap(),
        );
        let mut sd: HashMap<String, OwnedValue> = HashMap::new();
        sd.insert(
            SERVICE_UUID.to_uppercase(),
            OwnedValue::try_from(Value::from(vec![1u8, 2, 3])).unwrap(),
        );
        props.insert(
            "ServiceData".into(),
            OwnedValue::try_from(Value::from(sd)).unwrap(),
        );
        let mut k = Known {
            addr: None,
            data: None,
        };
        k.update(&props);
        let s = k.sighting().unwrap();
        assert_eq!(s.data, vec![1, 2, 3]);
        assert_eq!(s.addr, BleAddr::parse("C0:11:22:33:44:55", true).unwrap());
        // A change of signal strength alone keeps what was known.
        let mut rssi: Props = HashMap::new();
        rssi.insert("RSSI".into(), OwnedValue::from(-60i16));
        k.update(&rssi);
        assert_eq!(k.sighting().unwrap().data, vec![1, 2, 3]);
    }
}
