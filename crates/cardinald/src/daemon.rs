//! The daemon: holds everything, keeps sessions with this person's other
//! devices, syncs, serves the mount and the control socket.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use cardinal_blob::{FsStore, Fsync};
use cardinal_identity::KeyId;
use cardinal_link::{
    Bind, CarrierKind, Endpoint, EndpointConfig, EndpointEvent, LocalIdentity, Session,
    SessionConfig, Target,
};
use cardinal_space::account;
use cardinal_space::files::created_node;
use cardinal_space::SpaceId;
use cardinal_sync::Label;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use crate::config::Config;
use crate::core::{short, Core, Ingested};
use crate::directory::Directory;
use crate::keys::Keys;
use crate::net::{self, Access};
use crate::paths::{write_private, Paths};

/// Who a session's peer is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerKind {
    /// One of this person's devices (its signing key).
    Own(KeyId),
    /// The admin device this device is pairing with, before it belongs to
    /// the identity (the identity id).
    PairingAdmin([u8; 32]),
    /// A device this one does not know, in a restore session, before it
    /// proved it holds the root key (`host.rs`).
    Restoring,
    /// The same device after it did.
    Proven,
    /// A device of someone this person has a relationship with (their
    /// identity, and the device's signing key).
    Contact([u8; 32], KeyId),
    /// A session opened with an invitation, before they have a relationship:
    /// the identity that used it or gave it, which is only a claim until
    /// that person's log says otherwise, and the space made for it, once
    /// there is one.
    Inviting([u8; 32], Option<SpaceId>),
    /// A session opened with a delivery token, by someone this device need
    /// not know (`hosts.md#delivery-tokens`).
    Token(crate::mailbox::Token),
    /// Anyone else.
    Stranger,
}

/// A session with one of this person's devices.
#[derive(Clone)]
pub struct Conn {
    /// The session.
    pub session: Session,
    /// Who the peer is.
    pub kind: PeerKind,
    /// Registration number.
    pub gen: u64,
    /// Since when.
    pub since: Instant,
}

/// How long a device gets to answer over UDP before TCP is tried. Most of a
/// failed attempt is an older device that does not listen there.
const UDP_WITHIN: Duration = Duration::from_secs(2);
/// How long it then gets over TCP. A device that does not answer is usually
/// the wrong one, so what an address costs should stay small.
const TCP_WITHIN: Duration = Duration::from_secs(3);

/// The most addresses kept for a device.
const BOOK_LEN: usize = 6;
/// A trusted contact, and the key their `c=` tags are made with.
type TagKey = ([u8; 32], zeroize::Zeroizing<[u8; 32]>);
/// The window for [`NEARBY_PER_SOURCE`].
const NEARBY_WINDOW: Duration = Duration::from_secs(10);
/// How many `c=` tags from one address are checked in a window: a device
/// refreshes every 30 s, and a flood is not worth a keyed hash each.
const NEARBY_PER_SOURCE: u32 = 8;
/// How often the LAN advertisement is made again, with fresh nonces.
const ADVERTISE_EVERY: Duration = Duration::from_secs(30);

/// Addresses of this person's devices, learned from pairing, discovery,
/// successful connections, and each other.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PeerBook {
    /// Device signing key (hex) -> addresses.
    pub addrs: HashMap<String, Vec<String>>,
    /// Manual peer (`host:port`) -> the device found there (hex key).
    pub manual: HashMap<String, String>,
}

impl PeerBook {
    fn add(&mut self, device: &KeyId, addr: SocketAddr) -> bool {
        let v = self.addrs.entry(hex::encode(device)).or_default();
        let a = addr.to_string();
        if let Some(i) = v.iter().position(|x| *x == a) {
            if i == 0 {
                return false;
            }
            v.remove(i);
        }
        v.insert(0, a);
        v.truncate(BOOK_LEN);
        true
    }

    /// Keeps what another device said of `device`, after what this one
    /// found out for itself. Returns whether that added anything.
    fn hear(&mut self, device: &KeyId, addrs: &[SocketAddr]) -> bool {
        let v = self.addrs.entry(hex::encode(device)).or_default();
        let before = v.len();
        for a in addrs {
            let a = a.to_string();
            if v.len() < BOOK_LEN && !v.contains(&a) {
                v.push(a);
            }
        }
        v.len() > before
    }

    /// Keeps the outside address a device says its router gave it, after
    /// the one this device last reached it at: a device that leaves home
    /// takes it along, to reach the other from elsewhere. Returns whether
    /// that changed anything.
    fn keep_outside(&mut self, device: &KeyId, addr: SocketAddr) -> bool {
        let v = self.addrs.entry(hex::encode(device)).or_default();
        let a = addr.to_string();
        let at = v.len().min(1);
        if v.iter().position(|x| *x == a).is_some_and(|i| i <= at) {
            return false;
        }
        v.retain(|x| *x != a);
        v.insert(at.min(v.len()), a);
        v.truncate(BOOK_LEN);
        true
    }

    /// A device connected from `ip`, so that is where it is now. It came
    /// from a port of the moment, so this keeps the port it was last
    /// reached at. A device never reached has none to keep.
    fn moved(&mut self, device: &KeyId, ip: IpAddr) -> bool {
        let port = self
            .addrs
            .get(&hex::encode(device))
            .and_then(|v| v.first())
            .and_then(|a| a.parse::<SocketAddr>().ok())
            .map(|a| a.port());
        match port {
            Some(port) => self.add(device, SocketAddr::new(ip, port)),
            None => false,
        }
    }

    /// The devices known at `addr`, by key (hex).
    pub(crate) fn at(&self, addr: &SocketAddr) -> Vec<&String> {
        let a = addr.to_string();
        self.addrs
            .iter()
            .filter(|(_, v)| v.contains(&a))
            .map(|(k, _)| k)
            .collect()
    }
}

/// Where pairing stands on this device.
#[derive(Clone, Debug, Default)]
pub enum PairState {
    /// Not pairing.
    #[default]
    Idle,
    /// Showing a code, waiting for an admin device to type it.
    Showing {
        /// The code.
        code: String,
    },
    /// Paired with an admin device; waiting for its identity log.
    Joining {
        /// The identity this device is joining.
        identity: [u8; 32],
        /// The admin device's link static key.
        admin_static: [u8; 32],
        /// Its name.
        admin_name: String,
        /// Its signing key.
        admin_key: [u8; 32],
        /// Its link endpoint, as it told us (the IP may be unspecified).
        admin_addr: Option<SocketAddr>,
        /// The power this device joins at, as the admin device named it
        /// and this one signed: what its person is shown.
        power: Option<cardinal_identity::Power>,
    },
    /// Joined.
    Joined {
        /// The admin device's name.
        admin_name: String,
        /// The power it joined at.
        power: Option<cardinal_identity::Power>,
    },
    /// Failed.
    Failed(String),
}

/// Whether a FUSE mount can work here: `/dev/fuse` and `fusermount3`
/// present, and `/dev/fuse` openable (containers often lack it, or deny
/// it, and `fusermount3` then fails obscurely).
pub fn fuse_usable() -> Result<(), String> {
    crate::fs::available()?;
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/fuse")
        .map(|_| ())
        .map_err(|e| format!("cannot open /dev/fuse: {e}"))
}

/// Background fetching progress.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Progress {
    /// Files whose content is not all on this device yet.
    pub files_pending: u64,
    /// Bytes of content this device keeps (its retention's share of the
    /// current files).
    pub bytes_wanted: u64,
    /// Bytes of that content still missing (files not examined yet count
    /// in full; partly fetched ones only for what they lack).
    pub bytes_pending: u64,
    /// Bytes fetched since the daemon started.
    pub bytes_fetched: u64,
    /// Bytes per second fetched, over the last few seconds.
    pub rate: u64,
    /// The last fetch error.
    pub last_error: Option<String>,
}

/// The daemon.
pub struct Daemon {
    /// Paths.
    pub paths: Paths,
    /// Settings.
    pub config: Mutex<Config>,
    /// Keys.
    pub keys: Arc<Keys>,
    core: Mutex<Core>,
    /// Chunks and indexes.
    pub store: Arc<FsStore>,
    /// The link endpoint.
    pub endpoint: Endpoint,
    /// The link's view of the identity log.
    pub directory: Arc<Directory>,
    /// The tokio runtime.
    pub rt: tokio::runtime::Handle,
    sessions: Mutex<HashMap<[u8; 32], Conn>>,
    /// Addresses of devices.
    pub book: Mutex<PeerBook>,
    backoff: Mutex<HashMap<KeyId, (Instant, Duration)>>,
    /// Devices whose sessions closed on something one side could not read
    /// (`unreadable.rs`).
    pub unreadable: crate::unreadable::Unreadables,
    pub(crate) connecting: Mutex<HashSet<KeyId>>,
    /// Bumped on every change to the identity or a space.
    pub changed: watch::Sender<u64>,
    /// News waiting to be passed on.
    pub news: Mutex<crate::news::Waiting>,
    /// Static keys of restore sessions that proved the root key.
    proven: Mutex<HashSet<[u8; 32]>>,
    /// The recovery helper of a recovery through guardians under way on
    /// this new device (`helper.rs`).
    pub helper: Mutex<Option<Arc<crate::helper::Helper>>>,
    /// The services of this person's personas this device acts as
    /// (`helper.rs`), by persona id.
    pub personas: Mutex<HashMap<[u8; 32], Arc<crate::helper::Helper>>>,
    saving_book: Mutex<()>,
    /// Rendezvous and relay, as a device and as a host.
    pub rendezvous: crate::rendezvous::Rendezvous,
    /// What this device, as a host, holds for its owner.
    pub mailbox: crate::mailbox::Mailbox,
    /// Pairing.
    pub pairing: Mutex<PairState>,
    /// The call under way.
    pub call: Mutex<Option<crate::calls::Call>>,
    /// How the last call here ended, for whoever looks after it has gone.
    pub call_ended: Mutex<Option<serde_json::Value>>,
    /// The last thing copied on any of this person's devices (`clipboard.rs`).
    pub clip: Mutex<Option<crate::clipboard::Clip>>,
    /// The port the router gave, if it gave one (`portmap.rs`).
    pub portmap: Mutex<crate::portmap::State>,
    /// The outside addresses this device names itself at (`outside.rs`).
    pub outside: Mutex<crate::outside::Outside>,
    /// The group calls this device is on or carries, by call.
    pub group_calls: Mutex<HashMap<[u8; 16], crate::calls::Group>>,
    /// The group calls this device rang for lately, or its person made.
    pub rung_calls: Mutex<std::collections::VecDeque<[u8; 16]>>,
    /// The group calls whose ring this device passed on lately.
    pub passed_rings: Mutex<std::collections::VecDeque<[u8; 16]>>,
    /// Whether this device can help others now (`conditions.rs`).
    pub conditions: crate::conditions::Conditions,
    /// When each contact rang lately, so they can ring only so often.
    pub rang: Mutex<HashMap<[u8; 32], std::collections::VecDeque<Instant>>>,
    /// What this device lacks of each set, which peers hold it and which
    /// is being asked, so `want`s spread across peers (`sync.md#fetching-objects`).
    pub spread: Mutex<cardinal_sync::Spread<[u8; 32]>>,
    /// The person's grant to inspect what this device holds, if any
    /// (`inspect.rs`): in memory only, so a restart ends it.
    pub inspection: crate::inspect::Inspection,
    /// The data directory, held for as long as the service runs.
    _lock: crate::lock::Lock,
    /// Audio heard on calls, for a client, by call.
    /// A call's audio as it comes in: the call, whose voice it is in a group
    /// call, and the frame.
    pub call_audio: tokio::sync::broadcast::Sender<([u8; 16], Option<[u8; 8]>, bytes::Bytes)>,
    /// Frames of a call's other formats, such as video, for clients.
    pub call_video: tokio::sync::broadcast::Sender<([u8; 16], crate::calls::Format, bytes::Bytes)>,
    /// An identity made for a client, until its person has written the words
    /// down.
    pub setting_up: Mutex<Option<(crate::setup::Prepared, [usize; 2])>>,
    /// The mount, if mounted.
    pub mount: Mutex<Option<crate::fs::Mounted>>,
    /// Why mounting is impossible here (no FUSE), if it is.
    pub mount_unavailable: Mutex<Option<String>>,
    /// Held while mounting or unmounting, so concurrent housekeeping
    /// mounts once and a stop never races a mount.
    mount_lock: Mutex<()>,
    /// Background fetching.
    pub progress: Mutex<Progress>,
    /// How fast each device has been sending blob objects
    /// (`sched.rs`), kept across fetches.
    pub blob_stats: Mutex<HashMap<[u8; 32], crate::sched::PeerStats>>,
    /// Copies of the files space seen on the person's devices
    /// (`copies.rs`).
    pub copies: crate::copies::Tracker,
    /// Freeing deleted files and old versions (`cleanup.rs`).
    pub cleanup: crate::cleanup::Cleaner,
    /// Objects being dropped: answered as not held until they are gone or
    /// kept (`blobs.md#dropping-a-chunk`).
    pub leaving: Arc<Mutex<HashSet<[u8; 32]>>>,
    /// Speed tests this device serves (`speedtest.rs`).
    pub speedtest: crate::speedtest::Limiter,
    /// Bluetooth Low Energy (`bluetooth.rs`).
    pub bluetooth: crate::bluetooth::Bluetooth,
    /// How the person will regard whoever uses each outstanding invitation,
    /// by its secret's id.
    invitations: Mutex<HashMap<u64, account::Regard>>,
    /// The account's outstanding invitations this device lets in.
    admitted: Mutex<HashMap<[u8; 16], u64>>,
    /// Exchanges under way on each invitation's secret.
    using: Mutex<HashMap<u64, u32>>,
    /// The space made for each invitation's session, by the peer's static
    /// key.
    invited: Mutex<HashMap<[u8; 32], SpaceId>>,
    /// The peers, by static key, of invitation sessions that have begun
    /// their one exchange.
    exchanging: Mutex<HashSet<[u8; 32]>>,
    /// Held while this device's own account nodes are checked and
    /// written, so concurrent housekeeping writes them once.
    placement_lock: Mutex<()>,
    /// Set when the daemon should stop.
    pub stopping: watch::Sender<bool>,
    next_gen: AtomicU64,
    started: Instant,
    discovery_started: AtomicBool,
}

/// Saved link counters (`link.md#handshake`).
#[derive(Default, Serialize, Deserialize)]
struct LinkState {
    last_counter: u64,
    confirmed: HashMap<String, u64>,
}

pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Waits for the system to ask this process to end.
#[cfg(unix)]
async fn asked_to_end() -> anyhow::Result<()> {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    term.recv().await;
    Ok(())
}

/// Windows ends a service by other means, so this never happens.
#[cfg(not(unix))]
async fn asked_to_end() -> anyhow::Result<()> {
    std::future::pending().await
}

#[cfg(not(unix))]
fn raise_fd_limit() {}

/// Raises the open-file limit to the hard limit. The soft default (often
/// 1024) is too low for a file server with many peers and open files.
#[cfg(unix)]
fn raise_fd_limit() {
    let mut l = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit and setrlimit only read and write `l`.
    unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut l) == 0 && l.rlim_cur < l.rlim_max {
            l.rlim_cur = l.rlim_max;
            if libc::setrlimit(libc::RLIMIT_NOFILE, &l) != 0 {
                tracing::warn!("cannot raise the open-file limit");
            }
        }
    }
}

/// Why the daemon cannot listen, and how to choose another port. The
/// service reads its port from the settings, so the hint is the setting,
/// not a flag only a daemon started by hand would see.
fn cannot_listen(paths: &Paths, listen: SocketAddr, e: &std::io::Error) -> anyhow::Error {
    if e.kind() == std::io::ErrorKind::AddrInUse {
        anyhow::anyhow!(
            "cannot listen on {listen}: another program uses port {port}, perhaps another \
             person's Cardinal on this machine. Choose another port: set `listen = \
             \"0.0.0.0:PORT\"` under [daemon] in {config} and start again (or, by hand, \
             `cardinal daemon --listen 0.0.0.0:PORT`).",
            port = listen.port(),
            config = paths.config().display()
        )
    } else {
        anyhow::anyhow!("cannot listen on {listen}: {e}")
    }
}

impl Daemon {
    /// Loads everything and binds the link endpoint.
    pub async fn start(paths: Paths, config: Config) -> anyhow::Result<Arc<Daemon>> {
        let lock = Self::take(&paths)?;
        Self::start_holding(paths, config, lock).await
    }

    /// Takes the data directory for a service. It is this process's from
    /// here on, before anything in it is read or written, its settings
    /// too: a second service would empty what the first is still writing
    /// and save its own settings over the first's, and a store must not
    /// be cleared under one.
    pub fn take(paths: &Paths) -> anyhow::Result<crate::lock::Lock> {
        let taken = crate::lock::take(paths);
        let taken = taken.map_err(|e| anyhow::anyhow!("{}", crate::lock::cannot(paths, &e)))?;
        taken.ok_or_else(|| {
            anyhow::anyhow!(
                "Cardinal is already running on {}. Nothing was changed.",
                paths.home.display()
            )
        })
    }

    /// [`start`](Self::start), on a directory already taken.
    pub async fn start_holding(
        paths: Paths,
        mut config: Config,
        lock: crate::lock::Lock,
    ) -> anyhow::Result<Arc<Daemon>> {
        raise_fd_limit();
        crate::format::check(&paths)?;
        let keys = Arc::new(Keys::load_or_create(&paths.device_key())?);
        let mut core = Core::load(&paths, keys.clone())?;
        core.takes_recovery_copies = config.this_run.helper;
        let store = Arc::new(FsStore::open(paths.blobs(), Fsync::Deferred)?);
        std::fs::create_dir_all(paths.staging())?;
        let directory = Arc::new(Directory::default());
        directory.update(
            core.identity.as_ref().map(|i| i.state()).as_deref(),
            &core.connectable_states(),
        );
        let mut ec = EndpointConfig::new(keys.link.clone(), directory.clone());
        ec.udp_gateway = std::env::var("CARDINAL_TEST_UDP_GATEWAY")
            .ok()
            .and_then(|a| a.parse().ok());
        ec.identity = core.identity.as_ref().map(|i| LocalIdentity {
            identity: i.id(),
            signing_key: keys.signing.clone(),
        });
        ec.connect_timeout = Duration::from_secs(5);
        ec.allow_public = config.host;
        ec.session = SessionConfig {
            keepalive: Some(Duration::from_secs(20)),
            software: Some(format!("cardinal {}", cardinal_update::VERSION)),
            ..SessionConfig::default()
        };
        let listen: SocketAddr = config.listen.parse().map_err(|_| {
            anyhow::anyhow!(
                "the listen address {:?} is not ip:port (fix it in {})",
                config.listen,
                paths.config().display()
            )
        })?;
        // Nothing gets to a device behind a NAT, in the tests.
        let gateway_free = ec.udp_gateway.is_none();
        let bind = |at: SocketAddr| Bind {
            udp: config.uses_udp().then_some(at),
            tcp: gateway_free.then_some(at),
        };
        let endpoint = match Endpoint::bind(ec.clone(), bind(listen)).await {
            Ok(e) => e,
            // The port is taken, by another person's Cardinal on this
            // machine or any other program: the device moves to the next
            // free one and keeps it, and tells its devices and contacts as
            // it reaches them (a host also rewrites its grant). Only a port
            // asked for on the command line is held to.
            Err(e)
                if e.kind() == std::io::ErrorKind::AddrInUse && !config.this_run.listen_given =>
            {
                let mut found = None;
                for port in listen.port().saturating_add(1)..listen.port().saturating_add(100) {
                    let at = SocketAddr::new(listen.ip(), port);
                    if let Ok(e) = Endpoint::bind(ec.clone(), bind(at)).await {
                        found = Some((e, at));
                        break;
                    }
                }
                let (endpoint, at) = found.ok_or_else(|| cannot_listen(&paths, listen, &e))?;
                tracing::warn!(
                    "port {} is in use; listening on {at} instead",
                    listen.port()
                );
                config.listen = at.to_string();
                config.save(&paths.config())?;
                config.this_run.moved_from = Some(listen.port());
                endpoint
            }
            Err(e) => return Err(cannot_listen(&paths, listen, &e)),
        };
        let book: PeerBook = std::fs::read(paths.peers())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let copies_path = paths.copies();
        let old_versions = paths.old_versions();
        let mailbox = crate::mailbox::Mailbox::load(paths.mailbox());
        let rendezvous = crate::rendezvous::Rendezvous::load(paths.in_use());
        let d = Arc::new(Daemon {
            paths,
            config: Mutex::new(config),
            keys,
            core: Mutex::new(core),
            store,
            endpoint,
            directory,
            rt: tokio::runtime::Handle::current(),
            sessions: Mutex::new(HashMap::new()),
            book: Mutex::new(book),
            backoff: Mutex::new(HashMap::new()),
            unreadable: Default::default(),
            connecting: Mutex::new(HashSet::new()),
            changed: watch::channel(0).0,
            pairing: Mutex::new(PairState::Idle),
            call: Mutex::new(None),
            call_ended: Mutex::new(None),
            clip: Mutex::new(None),
            portmap: Mutex::new(crate::portmap::State::default()),
            outside: Mutex::new(crate::outside::Outside::default()),
            group_calls: Mutex::new(HashMap::new()),
            rung_calls: Mutex::new(std::collections::VecDeque::new()),
            passed_rings: Mutex::new(std::collections::VecDeque::new()),
            conditions: crate::conditions::Conditions::default(),
            rang: Mutex::new(HashMap::new()),
            spread: Mutex::new(cardinal_sync::Spread::new()),
            inspection: Default::default(),
            _lock: lock,
            call_audio: tokio::sync::broadcast::channel(64).0,
            call_video: tokio::sync::broadcast::channel(512).0,
            setting_up: Mutex::new(None),
            mount: Mutex::new(None),
            mount_unavailable: Mutex::new(None),
            mount_lock: Mutex::new(()),
            progress: Mutex::new(Progress::default()),
            blob_stats: Mutex::new(HashMap::new()),
            news: Mutex::new(HashMap::new()),
            proven: Mutex::new(HashSet::new()),
            helper: Mutex::new(None),
            personas: Mutex::new(HashMap::new()),
            saving_book: Mutex::new(()),
            rendezvous,
            mailbox,
            copies: crate::copies::Tracker::load(copies_path, crate::copies::Rules::from_env()),
            cleanup: crate::cleanup::Cleaner::load(old_versions),
            leaving: Arc::default(),
            speedtest: crate::speedtest::Limiter::default(),
            bluetooth: crate::bluetooth::Bluetooth::default(),
            invitations: Mutex::new(HashMap::new()),
            admitted: Mutex::new(HashMap::new()),
            using: Mutex::new(HashMap::new()),
            invited: Mutex::new(HashMap::new()),
            exchanging: Mutex::new(HashSet::new()),
            placement_lock: Mutex::new(()),
            stopping: watch::channel(false).0,
            next_gen: AtomicU64::new(1),
            started: Instant::now(),
            discovery_started: AtomicBool::new(false),
        });
        d.restore_counters();
        crate::outside::load(&d);
        if crate::outside::serving(&d) {
            crate::mailbox::open(&d);
        }
        Ok(d)
    }

    /// The core, locked.
    pub fn core(&self) -> MutexGuard<'_, Core> {
        lock(&self.core)
    }

    /// The settings, locked.
    pub fn config(&self) -> MutexGuard<'_, Config> {
        lock(&self.config)
    }

    /// Saves the settings.
    pub fn save_config(&self) -> anyhow::Result<()> {
        self.config().save(&self.paths.config())
    }

    /// How long the daemon has been running.
    pub fn uptime(&self) -> Duration {
        self.started.elapsed()
    }

    /// Signals that the identity or a space changed.
    pub fn bump(&self) {
        self.changed.send_modify(|v| *v += 1);
    }

    /// Who a session's peer is.
    pub fn classify(&self, s: &Session) -> PeerKind {
        let ps = s.peer_static();
        if s.role() == cardinal_link::Role::Responder
            && s.admission() == cardinal_link::Admission::Public
        {
            return if self.is_proven(&ps) {
                PeerKind::Proven
            } else {
                PeerKind::Restoring
            };
        }
        // Before anything else: a session opened with a token is for that,
        // whoever opened it.
        if let Some(token) = self.mailbox.token_of(s) {
            return PeerKind::Token(token);
        }
        let known = self.core().is_own_device(&ps);
        if let Some(k) = known {
            return PeerKind::Own(k);
        }
        // By who proved themselves in this session. A log can name any key,
        // so finding this one in a log says nothing. Two nodes for one
        // contact, made at once on two devices, are one contact: trusted
        // only where every one says so and none refuses them (`presence.rs`).
        let contact = s.peer_identity().and_then(|p| {
            let core = self.core();
            let contacts = core.contacts();
            let connects = account::connects(&contacts, &p.identity);
            (connects && core.has_device(&p.identity, &p.signing_key, &ps))
                .then_some((p.identity, p.signing_key))
        });
        if let Some((identity, key)) = contact {
            return PeerKind::Contact(identity, key);
        }
        if let PairState::Joining {
            identity,
            admin_static,
            ..
        } = &*lock(&self.pairing)
        {
            if *admin_static == ps {
                return PeerKind::PairingAdmin(*identity);
            }
        }
        if self.is_invitation(s) {
            if let Some(p) = s.peer_identity() {
                let shut_out = {
                    let core = self.core();
                    let contacts = core.contacts();
                    core.identity.as_ref().map(|i| i.id()) == Some(p.identity)
                        || account::refused(&contacts, &p.identity)
                };
                if !shut_out {
                    let space = lock(&self.invited).get(&ps).copied();
                    return PeerKind::Inviting(p.identity, space);
                }
            }
        }
        PeerKind::Stranger
    }

    /// Whether a restore session with this static key proved the root key.
    pub fn is_proven(&self, peer_static: &[u8; 32]) -> bool {
        lock(&self.proven).contains(peer_static)
    }

    /// Records that a restore session proved the root key.
    pub fn set_proven(&self, peer_static: [u8; 32]) {
        lock(&self.proven).insert(peer_static);
    }

    /// Sessions with this person's devices.
    /// The device's network changed, as a phone moving off Wi-Fi does: every
    /// session is asked for an answer, those over the old network end within
    /// seconds, and then this device looks again for its own devices and its
    /// contacts', through hosts where it must. Said by whatever sees the
    /// change, since a phone asleep keeps no timers of its own running.
    pub fn network_changed(self: &Arc<Self>, why: &str) -> serde_json::Value {
        let sessions = self.endpoint.sessions();
        tracing::info!(
            "{why}: checking {} sessions, then looking again",
            sessions.len()
        );
        for s in &sessions {
            s.check();
        }
        self.unreadable.network_changed();
        // and the services of the personas this device acts as, which
        // listen on the same network
        let inside: Vec<Arc<crate::helper::Helper>> = lock(&self.helper)
            .iter()
            .cloned()
            .chain(lock(&self.personas).values().cloned())
            .collect();
        for h in inside {
            let (hd, why) = (h.d.clone(), why.to_owned());
            h.d.rt.spawn(async move {
                hd.network_changed(&why);
            });
        }
        let d = self.clone();
        tokio::spawn(async move {
            // Long enough for an answer to be missed (`answer_timeout`).
            tokio::time::sleep(Duration::from_secs(11)).await;
            d.connect_all().await;
            crate::rendezvous::reach_contacts(d.clone()).await;
        });
        serde_json::json!({"checking": sessions.len()})
    }

    pub fn own_sessions(&self) -> Vec<Session> {
        // Never locks the core: callers may hold the mount's tree.
        let mut v: Vec<Conn> = lock(&self.sessions)
            .values()
            .filter(|c| !c.session.is_closed() && matches!(c.kind, PeerKind::Own(_)))
            .cloned()
            .collect();
        v.sort_by_key(|c| c.since);
        v.into_iter().map(|c| c.session).collect()
    }

    /// The sessions with contacts entitled to `label`. A contact's session
    /// hears of nothing else (`spaces.md#holding-a-space`).
    pub fn contact_sessions(&self, label: &[u8; 32]) -> Vec<Session> {
        let open: Vec<([u8; 32], Session)> = lock(&self.sessions)
            .values()
            .filter(|c| !c.session.is_closed())
            .filter_map(|c| match c.kind {
                PeerKind::Contact(identity, _) => Some((identity, c.session.clone())),
                _ => None,
            })
            .collect();
        let core = self.core();
        open.into_iter()
            // and a copy given them to hold (D80)
            .filter(|(identity, _)| {
                core.shares(identity, label) || core.held_given(identity).contains(label)
            })
            .map(|(_, s)| s)
            .collect()
    }

    /// The open session with a device, by its static key.
    pub fn session(&self, peer_static: &[u8; 32]) -> Option<Session> {
        lock(&self.sessions)
            .get(peer_static)
            .map(|c| c.session.clone())
            .filter(|s| !s.is_closed())
    }

    /// Who a session's peer was last found to be. Takes no lock on the core,
    /// so it is fit for a path as busy as serving blobs.
    pub fn session_kind(&self, peer_static: &[u8; 32]) -> Option<PeerKind> {
        lock(&self.sessions).get(peer_static).map(|c| c.kind)
    }

    /// The open sessions with `person`'s devices that are contacts' sessions,
    /// and those still an invitation's, which reach nothing but the log and
    /// the relationship (`contact.md#accepting`).
    pub fn contact_and_inviting(&self, person: &[u8; 32]) -> (Vec<Session>, Vec<Session>) {
        let (mut contact, mut inviting) = (Vec::new(), Vec::new());
        for c in lock(&self.sessions)
            .values()
            .filter(|c| !c.session.is_closed())
        {
            match c.kind {
                PeerKind::Contact(identity, _) if identity == *person => {
                    contact.push(c.session.clone())
                }
                PeerKind::Inviting(identity, _) if identity == *person => {
                    inviting.push(c.session.clone())
                }
                _ => {}
            }
        }
        (contact, inviting)
    }

    /// The open sessions with a contact's devices. The session an invitation
    /// opened counts, since it carries what the two share until it ends.
    pub fn sessions_of(&self, person: &[u8; 32]) -> Vec<Session> {
        let theirs = |kind: &PeerKind| match kind {
            PeerKind::Contact(identity, _) | PeerKind::Inviting(identity, Some(_)) => {
                identity == person
            }
            _ => false,
        };
        lock(&self.sessions)
            .values()
            .filter(|c| !c.session.is_closed() && theirs(&c.kind))
            .map(|c| c.session.clone())
            .collect()
    }

    /// The open sessions with contacts' devices, with whose each is.
    pub fn contacts_in_touch(&self) -> Vec<([u8; 32], Session)> {
        lock(&self.sessions)
            .values()
            .filter(|c| !c.session.is_closed())
            .filter_map(|c| match c.kind {
                PeerKind::Contact(identity, _) => Some((identity, c.session.clone())),
                _ => None,
            })
            .collect()
    }

    /// The people reached only through a relay.
    pub fn relayed_people(&self) -> HashSet<[u8; 32]> {
        let sessions = lock(&self.sessions);
        let open = sessions.values().filter(|c| !c.session.is_closed());
        let mut relayed = HashSet::new();
        let mut direct = HashSet::new();
        for c in open {
            if let PeerKind::Contact(identity, _) = c.kind {
                if c.session.is_relayed() {
                    relayed.insert(identity);
                } else {
                    direct.insert(identity);
                }
            }
        }
        relayed.retain(|i| !direct.contains(i));
        relayed
    }

    /// The people with a session open to one of their devices.
    pub fn connected_people(&self) -> HashSet<[u8; 32]> {
        lock(&self.sessions)
            .values()
            .filter(|c| !c.session.is_closed())
            .filter_map(|c| match c.kind {
                PeerKind::Contact(identity, _) => Some(identity),
                _ => None,
            })
            .collect()
    }

    /// The people with any session here, an invitation's included. The link
    /// keeps one session between two devices, so nothing else may be opened
    /// to them meanwhile, or it would end that one.
    pub fn people_in_touch(&self) -> HashSet<[u8; 32]> {
        lock(&self.sessions)
            .values()
            .filter(|c| !c.session.is_closed())
            .filter_map(|c| match c.kind {
                // An invitation only once proven: until then it is a claim,
                // and a claim must not hold up delivery to the real person.
                PeerKind::Contact(identity, _) | PeerKind::Inviting(identity, Some(_)) => {
                    Some(identity)
                }
                _ => None,
            })
            .collect()
    }

    /// Notes how to regard whoever uses an invitation.
    pub fn invitation_made(&self, secret: u64, regard: account::Regard) {
        lock(&self.invitations).insert(secret, regard);
    }

    /// An invitation that is no longer outstanding.
    pub fn invitation_done(&self, secret: u64) {
        lock(&self.invitations).remove(&secret);
    }

    /// How many exchanges are under way on each invitation's secret.
    pub fn invitations_using(&self) -> MutexGuard<'_, HashMap<u64, u32>> {
        lock(&self.using)
    }

    /// The invitations this device lets in, by their secret, with the id of
    /// that secret at the endpoint.
    pub fn admitted_invitations(&self) -> MutexGuard<'_, HashMap<[u8; 16], u64>> {
        lock(&self.admitted)
    }

    /// How to regard whoever opened `s` with an outstanding invitation.
    pub fn invitation_of(&self, s: &Session) -> Option<account::Regard> {
        match s.admission() {
            cardinal_link::Admission::Secret { id, .. } => {
                lock(&self.invitations).get(&id).copied()
            }
            _ => None,
        }
    }

    /// Whether `s` may begin an exchange. One invitation is one contact,
    /// however many streams ask.
    pub fn exchange_begins(&self, s: &Session) -> bool {
        lock(&self.exchanging).insert(s.peer_static())
    }

    /// `space` is what `s`'s invitation was for: all of a session it opens.
    pub fn invited_to(&self, s: &Session, space: SpaceId) {
        lock(&self.invited).insert(s.peer_static(), space);
    }

    /// `s` has done what its invitation was for.
    pub fn invitation_finished(&self, s: &Session) {
        if let cardinal_link::Admission::Secret { id, .. } = s.admission() {
            lock(&self.invitations).remove(&id);
        }
    }

    /// Whether `s` is an invitation's: this device used one, or one it made
    /// is outstanding. Any other secret is no invitation, or a token that
    /// was revoked would pass for one.
    fn is_invitation(&self, s: &Session) -> bool {
        match s.role() {
            cardinal_link::Role::Initiator => {
                matches!(s.admission(), cardinal_link::Admission::Secret { .. })
            }
            cardinal_link::Role::Responder => self.invitation_of(s).is_some(),
        }
    }

    /// Ends the sessions opened with a token, without a word.
    pub fn end_token_sessions(&self, token: &crate::mailbox::Token) {
        let sessions: Vec<Session> = lock(&self.sessions)
            .values()
            .filter(|c| c.kind == PeerKind::Token(*token))
            .map(|c| c.session.clone())
            .collect();
        for s in sessions {
            s.abandon();
        }
    }

    /// Whether a device has an open session.
    pub fn is_online(&self, link_x25519: &[u8; 32]) -> bool {
        lock(&self.sessions)
            .get(link_x25519)
            .is_some_and(|c| !c.session.is_closed())
    }

    /// A device's open session, and how long it has been open.
    pub fn session_since(&self, link_x25519: &[u8; 32]) -> Option<(Session, Duration)> {
        let sessions = lock(&self.sessions);
        let c = sessions
            .get(link_x25519)
            .filter(|c| !c.session.is_closed())?;
        Some((c.session.clone(), c.since.elapsed()))
    }

    /// What a device's session runs over.
    pub fn session_carrier(&self, link_x25519: &[u8; 32]) -> Option<&'static str> {
        let sessions = lock(&self.sessions);
        let s = &sessions.get(link_x25519)?.session;
        if s.is_relayed() {
            return Some("relay");
        }
        Some(match s.carrier()? {
            CarrierKind::Udp => "UDP",
            CarrierKind::Tcp => "TCP",
            CarrierKind::Ble => "Bluetooth",
        })
    }

    /// Whether a device has an open session that does not go through a host.
    pub fn is_direct(&self, link_x25519: &[u8; 32]) -> bool {
        lock(&self.sessions)
            .get(link_x25519)
            .is_some_and(|c| !c.session.is_closed() && !c.session.is_relayed())
    }

    /// Whether a device has an open session over IP that does not go
    /// through a host: what is tried for while it has none, even with a
    /// session over Bluetooth, which holds only while the two are in range.
    pub fn is_direct_ip(&self, link_x25519: &[u8; 32]) -> bool {
        lock(&self.sessions).get(link_x25519).is_some_and(|c| {
            !c.session.is_closed()
                && !c.session.is_relayed()
                && c.session.carrier() != Some(CarrierKind::Ble)
        })
    }

    /// Whether an open session runs over `on`.
    pub fn carried_on(&self, on: &cardinal_link::Attached) -> bool {
        lock(&self.sessions)
            .values()
            .any(|c| !c.session.is_closed() && on.carries(&c.session))
    }

    /// Whether a device's only session is over Bluetooth.
    pub fn is_bluetooth_only(&self, link_x25519: &[u8; 32]) -> bool {
        lock(&self.sessions).get(link_x25519).is_some_and(|c| {
            !c.session.is_closed() && c.session.carrier() == Some(CarrierKind::Ble)
        })
    }

    /// The device a relayed session runs through, by link key.
    pub fn relayed_through(&self, link_x25519: &[u8; 32]) -> Option<[u8; 32]> {
        let sessions = lock(&self.sessions);
        let s = &sessions.get(link_x25519)?.session;
        if !s.is_relayed() {
            return None;
        }
        // A path with no address, as over Bluetooth, is nobody's relay.
        let at = s.remote_addr()?;
        relay_of(
            sessions
                .iter()
                .filter(|(_, c)| !c.session.is_relayed())
                .map(|(x, c)| (*x, c.session.remote_addr())),
            at,
        )
    }

    /// The remote address of a device's session.
    pub fn session_addr(&self, link_x25519: &[u8; 32]) -> Option<SocketAddr> {
        lock(&self.sessions)
            .get(link_x25519)
            .and_then(|c| c.session.remote_addr())
    }

    /// Takes on a new session: serves it and syncs everything.
    pub fn on_session(self: &Arc<Self>, s: Session) {
        self.rendezvous.opened(&s.peer_static());
        let kind = self.classify(&s);
        if kind == PeerKind::Stranger {
            // Someone refused may hold an invitation still. They hear what
            // anyone hears from a device that is off.
            if self.is_invitation(&s) {
                s.abandon();
                return;
            }
            tracing::info!("closing a session with an unknown device");
            s.close("unknown device");
            return;
        }
        if let PeerKind::Token(token) = kind {
            let open = lock(&self.sessions)
                .values()
                .filter(|c| c.kind == PeerKind::Token(token) && !c.session.is_closed())
                .count();
            if open >= crate::mailbox::TOKEN_SESSIONS {
                s.abandon();
                return;
            }
        }
        let gen = self.next_gen.fetch_add(1, Ordering::Relaxed);
        let ps = s.peer_static();
        {
            let mut m = lock(&self.sessions);
            // Replaced already by a simultaneous session with the same
            // device: that one is (or will be) here instead. Checked under
            // the lock, since the replacement arrives only after it closed
            // this one.
            if s.is_closed() {
                tracing::debug!("session with {} replaced before use", short(&ps));
                return;
            }
            m.insert(
                ps,
                Conn {
                    session: s.clone(),
                    kind,
                    gen,
                    since: Instant::now(),
                },
            );
        }
        let name = match kind {
            PeerKind::Own(k) => self.device_name(&k),
            PeerKind::Restoring | PeerKind::Proven => "a device restoring".into(),
            PeerKind::Contact(_, _) => "a contact's device".into(),
            PeerKind::Inviting(..) => "someone with an invitation".into(),
            PeerKind::Token(_) => "someone with a token".into(),
            _ => "the device being paired".into(),
        };
        tracing::info!(
            "connected to {name} ({:?}, {})",
            s.remote_addr(),
            if s.role() == cardinal_link::Role::Initiator {
                "outgoing"
            } else {
                "incoming"
            }
        );
        self.bump();
        if let PeerKind::Contact(who, k) = kind {
            self.rendezvous.event(
                &who,
                true,
                format!("{} opened: {}", hex::encode(&k[..8]), route(&s)),
            );
        }
        if let PeerKind::Own(k) | PeerKind::Contact(_, k) = kind {
            lock(&self.backoff).remove(&k);
            if s.role() == cardinal_link::Role::Responder && !s.is_relayed() {
                if let Some(a) = s.remote_addr() {
                    if lock(&self.book).moved(&k, a.ip()) {
                        self.save_book();
                    }
                }
            }
        }
        self.save_counters();
        let d = self.clone();
        let s2 = s.clone();
        tokio::spawn(net::serve(d, s2, gen));
        if matches!(kind, PeerKind::Own(_)) {
            tokio::spawn(crate::rendezvous::session_opened(self.clone(), s.clone()));
        }
        let d = self.clone();
        if kind == PeerKind::Restoring {
            tokio::spawn(async move {
                tokio::time::sleep(crate::host::PROVE_WITHIN).await;
                if crate::host::is_unproven(&d, &s) {
                    s.close("did not prove anything");
                }
            });
            return;
        }
        if matches!(kind, PeerKind::Inviting(..) | PeerKind::Token(_)) {
            return;
        }
        tokio::spawn(async move { net::sync_all(&d, &s).await });
    }

    /// Forgets a closed session.
    pub fn session_closed(&self, peer_static: &[u8; 32], gen: u64) {
        let mut m = lock(&self.sessions);
        if m.get(peer_static).is_some_and(|c| c.gen == gen) {
            let mut refused = None;
            let mut unread = None;
            if let Some(c) = m.remove(peer_static) {
                if let PeerKind::Own(k) | PeerKind::Contact(_, k) = c.kind {
                    if is_prove_first(c.session.close_reason().as_ref()) {
                        refused = Some(k);
                    }
                    if let Some(r) = c.session.close_reason() {
                        unread = self
                            .unreadable
                            .closed(k, *peer_static, &r)
                            .map(|_| (c.kind, k));
                    }
                }
                if let PeerKind::Contact(who, k) = c.kind {
                    let why = c
                        .session
                        .close_reason()
                        .map_or_else(|| "closed".to_owned(), |r| closed_why(&r));
                    let lasted = crate::contacts::span(c.since.elapsed());
                    self.rendezvous.event(
                        &who,
                        false,
                        format!("{} closed after {lasted}: {why}", hex::encode(&k[..8])),
                    );
                }
            }
            drop(m);
            // A host of theirs that does not take this device for anyone
            // it serves answers every session so, at once: dialling again
            // each round would only be told the same (connecting cleared
            // the backoff).
            if let Some(k) = refused {
                let next = Instant::now() + PROVE_FIRST_BACKOFF;
                lock(&self.backoff).insert(k, (next, PROVE_FIRST_BACKOFF));
            }
            // Said once, not at each session that closes the same way.
            if let Some((kind, k)) = unread {
                let name = self.unreadable_name(&kind);
                if let Some(v) = self.unreadable.json(&k, &name) {
                    tracing::warn!(
                        "{} ({}; they do not sync until then, and this device dials \
                         them less often)",
                        v["says"].as_str().unwrap_or(""),
                        v["reason"].as_str().unwrap_or("")
                    );
                }
            }
            lock(&self.proven).remove(peer_static);
            lock(&self.invited).remove(peer_static);
            lock(&self.exchanging).remove(peer_static);
            tracing::info!("disconnected from {}", short(peer_static));
            crate::rendezvous::session_closed(self, peer_static);
            // A device has one session with another, so a fetch may have
            // been waiting for this one to end.
            self.bump();
        }
    }

    /// Who a device that could not be read is to the person: their own
    /// device's name, or a contact's device.
    pub fn unreadable_name(&self, kind: &PeerKind) -> String {
        match kind {
            PeerKind::Own(k) => self.device_name(k),
            PeerKind::Contact(who, _) => {
                let name = self
                    .core()
                    .contacts()
                    .into_iter()
                    .find(|c| c.identity == *who)
                    .map(|c| c.petname);
                match name {
                    Some(n) => format!("One of {n}'s devices"),
                    None => "A contact's device".into(),
                }
            }
            _ => "A device".into(),
        }
    }

    /// A device's name from the account space.
    pub fn device_name(&self, key: &KeyId) -> String {
        self.core()
            .device_names()
            .get(key)
            .cloned()
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| account::short_key(key))
    }

    /// Ingests objects of a set (blocking: evaluation can take a while).
    pub fn ingest(
        self: &Arc<Self>,
        label: Label,
        objects: Vec<Vec<u8>>,
        access: Access,
    ) -> anyhow::Result<Ingested> {
        let mut core = self.core();
        let other = match access {
            Access::Other(identity) => Some(identity),
            _ => core.other_of_label(&label),
        };
        if let Some(identity) = other {
            let changed = core.ingest_other(identity, &objects)?;
            // Entries whose parents are not here yet, as a notice that named
            // only the heads brings: the rest is asked for.
            let missing_parents = core.is_waiting(&label);
            let states = core.connectable_states();
            let own = core.identity.as_ref().map(|i| i.state());
            drop(core);
            if !changed {
                return Ok(Ingested {
                    missing_parents,
                    ..Ingested::default()
                });
            }
            // a recovery of someone this person guards may be pending now
            crate::guardians::observe(self);
            // and when their policy was first seen here, for the date shown
            crate::contacts::note_policies(self, &identity);
            // and a succession judged with this log may be checked now
            crate::following::follow(self);
            self.directory.update(own.as_deref(), &states);
            self.endpoint.recheck_peers();
            return Ok(Ingested {
                new: objects.len(),
                complete: objects.len(),
                objects,
                missing_parents,
            });
        }
        if Some(label) == core.identity_label() {
            let ch = core.ingest_identity(&objects, None)?;
            let missing_parents = core.is_waiting(&label);
            drop(core);
            if !ch.changed {
                return Ok(Ingested {
                    missing_parents,
                    ..Ingested::default()
                });
            }
            self.identity_changed();
            return Ok(Ingested {
                new: objects.len(),
                missing_parents,
                complete: objects.len(),
                objects,
            });
        }
        if let Access::Join(identity) = access {
            let ch = core.ingest_identity(&objects, Some(identity))?;
            drop(core);
            if ch.joined {
                self.joined();
            }
            return Ok(Ingested::default());
        }
        if core.identity.is_none() {
            return Ok(Ingested::default());
        }
        let account = core.account_id() == Some(label);
        let out = core.ingest_space(label, &objects)?;
        drop(core);
        if out.new > 0 {
            tracing::debug!("space {}: {} new entries", short(&label), out.new);
            if account {
                self.peers_changed();
            }
            // this person may have left it, on another of their devices
            crate::mailbox::revoke_left(self, &label);
            // a copy given this person to hold may be named in it (D80)
            crate::guardians::held_named(self, &label);
            // it may have ended, or brought what stands in its place
            crate::following::follow(self);
            // after a recovery, what the removed devices wrote in it: kept
            // up to the time lost, but for their successions, which fall
            crate::recovering::tend_recovered(self);
            self.bump();
            self.housekeeping();
        }
        Ok(out)
    }

    /// After the identity log changed.
    pub fn identity_changed(&self) {
        self.core().identity_updated();
        self.peers_changed();
    }

    /// After who may reach this device changed: its person's devices, or how
    /// they regard someone.
    pub fn peers_changed(&self) {
        let (st, others) = {
            let core = self.core();
            (
                core.identity.as_ref().map(|i| i.state()),
                core.connectable_states(),
            )
        };
        self.directory.update(st.as_deref(), &others);
        crate::mailbox::revoke_refused(self);
        let conns: Vec<Conn> = lock(&self.sessions).values().cloned().collect();
        for c in conns {
            let kind = self.classify(&c.session);
            // Without a word: a contact no longer trusted must not be able
            // to tell this from a device being off.
            if matches!(c.kind, PeerKind::Contact(..)) && !matches!(kind, PeerKind::Contact(..)) {
                c.session.abandon();
            }
            // Refused while still using an invitation.
            if matches!(c.kind, PeerKind::Inviting(..))
                && kind == PeerKind::Stranger
                && self.is_invitation(&c.session)
            {
                c.session.abandon();
            }
            if let (PeerKind::Contact(who, k), false) =
                (kind, matches!(c.kind, PeerKind::Contact(..)))
            {
                if !c.session.is_closed() {
                    let how = route(&c.session);
                    let text = format!("{} opened: {how}", hex::encode(&k[..8]));
                    self.rendezvous.event(&who, true, text);
                }
            }
            if let Some(x) = lock(&self.sessions).get_mut(&c.session.peer_static()) {
                x.kind = kind;
            }
        }
        self.endpoint.recheck_peers();
        self.bump();
    }

    /// After this device joined an identity by pairing.
    fn joined(self: &Arc<Self>) {
        let (id, st) = {
            let core = self.core();
            let i = core.identity.as_ref().expect("joined");
            (i.id(), i.state())
        };
        self.endpoint.set_identity(Some(LocalIdentity {
            identity: id,
            signing_key: self.keys.signing.clone(),
        }));
        self.directory.update(Some(&st), &[]);
        let prev = std::mem::take(&mut *lock(&self.pairing));
        let (admin_name, power) = match &prev {
            PairState::Joining {
                admin_name, power, ..
            } => (admin_name.clone(), *power),
            _ => (String::new(), None),
        };
        *lock(&self.pairing) = PairState::Joined { admin_name, power };
        // Reconnect as a member: the pairing session carried no proof of
        // this device, so the admin will treat a new session normally.
        if let PairState::Joining {
            admin_static,
            admin_key,
            admin_addr,
            ..
        } = prev
        {
            let old = lock(&self.sessions).remove(&admin_static);
            if let Some(mut a) = admin_addr {
                if a.ip().is_unspecified() {
                    if let Some(r) = old.as_ref().and_then(|c| c.session.remote_addr()) {
                        a.set_ip(r.ip());
                    }
                }
                if !a.ip().is_unspecified() {
                    self.learn_addr(&admin_key, a);
                }
            }
            if let Some(c) = old {
                c.session.close("joined; reconnecting");
            }
        }
        self.bump();
        let d = self.clone();
        tokio::spawn(async move { d.connect_all().await });
    }

    /// Writes ops to a space and sends the new entries to online devices.
    pub fn write_and_push(
        self: &Arc<Self>,
        space: &SpaceId,
        ops: Vec<cardinal_space::SpaceOp>,
    ) -> anyhow::Result<Vec<cardinal_identity::EntryId>> {
        let written = self.core().write(space, ops)?;
        let ids: Vec<_> = written.iter().map(|(i, _)| *i).collect();
        self.push(space, written.into_iter().map(|(_, b)| b).collect());
        self.bump();
        Ok(ids)
    }

    /// [`write_and_push`](Self::write_and_push), if `still` holds of the
    /// core at the moment of writing: for what was decided before waiting
    /// on something else, as on a host for a token, while entries kept
    /// arriving. `None` if it holds no longer, and nothing is written.
    pub fn write_and_push_if(
        self: &Arc<Self>,
        space: &SpaceId,
        ops: Vec<cardinal_space::SpaceOp>,
        still: impl FnOnce(&Core) -> bool,
    ) -> anyhow::Result<Option<Vec<cardinal_identity::EntryId>>> {
        let written = {
            let mut core = self.core();
            if !still(&core) {
                return Ok(None);
            }
            core.write(space, ops)?
        };
        let ids: Vec<_> = written.iter().map(|(i, _)| *i).collect();
        self.push(space, written.into_iter().map(|(_, b)| b).collect());
        self.bump();
        Ok(Some(ids))
    }

    /// Tells peers of new entries of a space.
    pub fn push(self: &Arc<Self>, space: &SpaceId, entries: Vec<Vec<u8>>) {
        if !entries.is_empty() {
            self.notify(*space, entries, &HashSet::new());
        }
    }

    /// Tells peers of new identity entries.
    pub fn push_identity(self: &Arc<Self>, entries: Vec<Vec<u8>>) {
        let label = self.core().identity_label();
        if let Some(label) = label {
            self.notify(label, entries, &HashSet::new());
        }
    }

    /// Keeps the account space describing this device, and the mount up.
    pub fn housekeeping(self: &Arc<Self>) {
        let d = self.clone();
        self.rt.spawn(async move {
            if let Err(e) = d.ensure_placement() {
                tracing::debug!("housekeeping: {e:#}");
            }
            if let Err(e) = crate::host::refresh(&d) {
                tracing::debug!("housekeeping: {e:#}");
            }
            if let Err(e) = crate::host::follow_port(&d) {
                tracing::warn!("cannot give the new port in the grant: {e:#}");
            }
            // A month without any address it names, or port mapping
            // turned off while it was not running, is acted on.
            crate::outside::tick(&d);
            crate::contacts::admit_invitations(&d);
            // Mounting blocks, and may wait for another mount or unmount.
            let d2 = d.clone();
            let _ = tokio::task::spawn_blocking(move || d2.ensure_mounted()).await;
            d.start_discovery();
            crate::bluetooth::start(&d);
        });
    }

    /// Keeps this device's device node and its placement of the files
    /// space in the account space, with its current retention, so the
    /// person's other devices know what it means to keep
    /// (`blobs.md#counting-copies`).
    fn ensure_placement(self: &Arc<Self>) -> anyhow::Result<()> {
        let _one = lock(&self.placement_lock);
        let (acc, files, has_device, space_node, mine, others, named) = {
            let core = self.core();
            let (Some(acc), Some(files)) = (core.account_id(), core.files_id()) else {
                return Ok(());
            };
            let st = core.spaces[&acc].space.as_ref().expect("open").state();
            let me = self.keys.key();
            let has_device = account::devices(st).iter().any(|d| d.key == me);
            // What the person's devices call this one, renamed from any of them.
            let named = account::devices(st)
                .into_iter()
                .find(|d| d.key == me)
                .map(|d| d.name);
            let others: Vec<String> = account::devices(st)
                .into_iter()
                .filter(|d| d.key != me)
                .map(|d| d.name)
                .collect();
            let rec = account::spaces(st).into_iter().find(|r| r.space == files);
            let space_node = rec.as_ref().map(|r| r.node);
            let mine: Vec<account::PlacementRecord> = rec
                .map(|r| {
                    r.placements
                        .into_iter()
                        .filter(|p| p.device == me)
                        .collect()
                })
                .unwrap_or_default();
            (acc, files, has_device, space_node, mine, others, named)
        };
        if let Some(named) = named.filter(|n| !n.is_empty() && *n != self.config().name) {
            tracing::info!("this device is called {named:?} now");
            let mut saved = crate::config::Config::load(&self.paths.config())?;
            saved.name = named.clone();
            saved.save(&self.paths.config())?;
            self.config().name = named;
        }
        let me = self.keys.key();
        let cfg = self.config().clone();
        let mut ops = Vec::new();
        if !has_device {
            // A device is also found by its name, so no two of a person's
            // share one: a second "carbonite" becomes "carbonite 2".
            let name = unique_name(&cfg.name, &others);
            if name != cfg.name {
                tracing::info!(
                    "another of your devices is called {:?}: this one is {name:?}",
                    cfg.name
                );
                let mut saved = crate::config::Config::load(&self.paths.config())?;
                saved.name = name.clone();
                saved.save(&self.paths.config())?;
                self.config().name = name.clone();
            }
            ops.push(account::create_device(&me, &name, false, false));
        }
        match space_node {
            Some(node) if mine.is_empty() => {
                ops.push(crate::setup::placement_op(node, &me, &cfg));
            }
            None => {
                let ids =
                    self.write_and_push(&acc, vec![account::create_space(&files, "Cardinal")])?;
                let node = created_node(&ids[0], 0);
                ops.push(crate::setup::placement_op(node, &me, &cfg));
            }
            Some(_) => {
                let want = crate::setup::retention(&cfg);
                let days = crate::setup::history_days(&cfg);
                for p in mine
                    .iter()
                    .filter(|p| p.retention != want || p.days != days)
                {
                    tracing::info!(
                        "recording this device's retention ({}, old versions kept {}) in the \
                         account space",
                        cfg.retention,
                        cfg.keep_old
                    );
                    // the days first: a placement saying history for a
                    // number of days without one is malformed
                    if let Some(n) = days.filter(|n| p.days != Some(*n)) {
                        ops.push(account::set_field(p.node, account::PLACEMENT_DAYS, n));
                    }
                    if p.retention != want {
                        ops.push(account::set_field(p.node, 2, want as u32));
                    }
                }
            }
        }
        if !ops.is_empty() {
            self.write_and_push(&acc, ops)?;
        }
        Ok(())
    }

    /// Mounts the files space if it is held, a mount point is configured,
    /// it is not mounted yet, and the daemon is not stopping.
    pub fn ensure_mounted(self: &Arc<Self>) {
        let _one_at_a_time = lock(&self.mount_lock);
        if lock(&self.mount).is_some() || *self.stopping.borrow() {
            return;
        }
        let Some(path) = self.config().mount_here().cloned() else {
            return;
        };
        let Some(files) = self.core().files_id() else {
            return;
        };
        if let Err(why) = fuse_usable() {
            let mut prev = lock(&self.mount_unavailable);
            if prev.as_deref() != Some(why.as_str()) {
                tracing::warn!(
                    "FUSE is not available here ({why}); syncing without a mount. \
                     `cardinal unmount` stops trying for good."
                );
                *prev = Some(why);
            }
            return;
        }
        *lock(&self.mount_unavailable) = None;
        match crate::fs::mount(self.clone(), files, &path) {
            Ok(m) => {
                tracing::info!("mounted your files at {}", path.display());
                *lock(&self.mount) = Some(m);
            }
            Err(e) => tracing::error!("cannot mount at {}: {e:#}", path.display()),
        }
    }

    /// Unmounts, committing pending changes first.
    pub fn unmount(&self) {
        let _one_at_a_time = lock(&self.mount_lock);
        let m = lock(&self.mount).take();
        if let Some(m) = m {
            m.unmount();
        }
    }

    // ---- connections ----

    /// Tries to connect to every own device that is not online, and to the
    /// devices of the contacts in use (`sync.md#neighbours`), and of those
    /// this device stays in touch with because its person has no host.
    pub async fn connect_all(self: &Arc<Self>) {
        let standing = crate::rendezvous::standing(self);
        let devices: Vec<(KeyId, cardinal_crypto::HybridPublicKey)> = {
            let core = self.core();
            let Some(ident) = core.identity.as_ref() else {
                return;
            };
            let st = ident.state();
            let own = st.keys.values().filter(|k| k.key != self.keys.key());
            let mut devices: Vec<_> = own
                .filter_map(|k| Some((k.key, k.link_key.clone()?)))
                .collect();
            let contacts = core.contacts();
            self.rendezvous.knows(contacts.iter().map(|c| c.identity));
            let wanted = contacts.iter().filter(|c| c.connects());
            for c in wanted.filter(|c| self.rendezvous.in_use(&c.identity)) {
                let Some(o) = core.others.get(&c.identity) else {
                    continue;
                };
                let st = o.log.state();
                devices.extend(
                    st.keys
                        .values()
                        .filter_map(|k| Some((k.key, k.link_key.clone()?))),
                );
            }
            for (key, link) in standing {
                if !devices.iter().any(|(k, _)| *k == key) {
                    devices.push((key, link));
                }
            }
            devices
        };
        for (key, link) in devices {
            if self.is_direct_ip(link.x25519()) {
                continue;
            }
            {
                let b = lock(&self.backoff);
                if let Some((next, _)) = b.get(&key) {
                    if Instant::now() < *next {
                        continue;
                    }
                }
            }
            if !self.unreadable.due(&key, link.x25519()) {
                continue;
            }
            if !lock(&self.connecting).insert(key) {
                continue;
            }
            let d = self.clone();
            tokio::spawn(async move {
                let ok = d.try_device(key, link).await;
                lock(&d.connecting).remove(&key);
                if !ok {
                    let mut b = lock(&d.backoff);
                    let delay = b
                        .get(&key)
                        .map(|(_, d)| (*d * 2).min(Duration::from_secs(60)))
                        .unwrap_or(Duration::from_secs(1));
                    b.insert(key, (Instant::now() + delay, delay));
                }
            });
        }
        tokio::spawn(crate::rendezvous::ask_helpers(self.clone()));
        tokio::spawn(crate::rendezvous::reach_contacts(self.clone()));
    }

    /// Opens a session at an address, over UDP if something answers there,
    /// and over TCP if not: an older device, or a network that blocks UDP.
    pub async fn dial(
        &self,
        target: impl Fn(CarrierKind) -> Target,
    ) -> Result<Session, cardinal_link::LinkError> {
        if self.endpoint.udp_addr().is_some() {
            let udp = target(CarrierKind::Udp).within(UDP_WITHIN);
            match self.endpoint.connect(udp).await {
                Err(e @ cardinal_link::LinkError::Closed(_)) => return Err(e),
                Err(e) => tracing::debug!("over UDP: {e}"),
                ok => return ok,
            }
        }
        let tcp = target(CarrierKind::Tcp).within(TCP_WITHIN);
        self.endpoint.connect(tcp).await
    }

    async fn candidate_addrs(&self, key: &KeyId) -> Vec<(SocketAddr, Option<String>)> {
        let (known, manual): (Vec<String>, Vec<(String, Option<String>)>) = {
            let book = lock(&self.book);
            let known = book
                .addrs
                .get(&hex::encode(key))
                .cloned()
                .unwrap_or_default();
            // Manual peers are this person's own: no use for a contact.
            let own = self
                .core()
                .identity
                .as_ref()
                .is_some_and(|i| i.state().keys.contains_key(key));
            let peers = if own {
                self.config().peers.clone()
            } else {
                Vec::new()
            };
            let manual = peers
                .into_iter()
                .filter_map(|p| match book.manual.get(&p) {
                    Some(k) if *k != hex::encode(key) => None,
                    Some(_) => Some((p, None)),
                    None => Some((p.clone(), Some(p))),
                })
                .collect();
            (known, manual)
        };
        let mut out: Vec<(SocketAddr, Option<String>)> = Vec::new();
        for a in known {
            if let Ok(sa) = a.parse() {
                out.push((sa, None));
            }
        }
        // What a host's grant gives, unless that is a name: names are for
        // the recovery sheet, and nothing here should depend on a registrar.
        let hosting = {
            let core = self.core();
            let mut v = core.host_addresses(key);
            v.extend(core.contact_host_addresses(key));
            v
        };
        for sa in hosting {
            if !out.iter().any(|(x, _)| *x == sa) {
                out.push((sa, None));
            }
        }
        for (p, tag) in manual {
            let lookup = tokio::net::lookup_host(p.clone()).await;
            if let Ok(it) = lookup {
                for sa in it {
                    if !out.iter().any(|(x, _)| *x == sa) {
                        out.push((sa, tag.clone().or(Some(p.clone()))));
                    }
                }
            }
        }
        out
    }

    /// Tries every known address at once: most of them are old, and each
    /// one tried in turn would keep a returning device waiting.
    async fn try_device(
        self: &Arc<Self>,
        key: KeyId,
        link: cardinal_crypto::HybridPublicKey,
    ) -> bool {
        let (done, give_up) = tokio::sync::watch::channel(false);
        let mut tries = tokio::task::JoinSet::new();
        for (addr, manual) in self.candidate_addrs(&key).await {
            let (d, link, give_up) = (self.clone(), link.clone(), give_up.clone());
            tries.spawn(async move {
                let target = |c| Target::new(addr, c, &link).unless(give_up.clone());
                (addr, manual, d.dial(target).await)
            });
        }
        let mut reached = false;
        while let Some(tried) = tries.join_next().await {
            let Ok((addr, manual, result)) = tried else {
                continue;
            };
            match result {
                Ok(s) => {
                    let _ = done.send(true);
                    {
                        let mut book = lock(&self.book);
                        book.add(&key, addr);
                        if let Some(m) = manual {
                            book.manual.insert(m, hex::encode(key));
                        }
                    }
                    self.save_book();
                    self.on_session(s);
                    reached = true;
                }
                // The device's own simultaneous session won: connected.
                Err(cardinal_link::LinkError::Closed(cardinal_link::CloseReason::Replaced)) => {
                    let _ = done.send(true);
                    reached = true;
                }
                Err(e) => {
                    tracing::debug!("connect to {} at {addr}: {e}", short(&key));
                }
            }
        }
        reached || self.is_direct_ip(link.x25519())
    }

    /// Where this device has reached its own devices, for the others.
    pub fn addresses_to_share(&self) -> Vec<(KeyId, Vec<SocketAddr>)> {
        let own: Vec<KeyId> = {
            let core = self.core();
            let Some(ident) = core.identity.as_ref() else {
                return Vec::new();
            };
            ident.state().keys.keys().copied().collect()
        };
        let book = lock(&self.book);
        own.into_iter()
            .filter_map(|key| {
                let known = book.addrs.get(&hex::encode(key))?;
                let addrs = known.iter().filter_map(|a| a.parse().ok()).collect();
                Some((key, addrs))
            })
            .collect()
    }

    /// Another of this person's devices says where it reached `device`.
    pub fn hear_addresses(&self, device: &KeyId, addrs: &[SocketAddr]) {
        let own = {
            let core = self.core();
            core.identity
                .as_ref()
                .is_some_and(|i| i.state().keys.contains_key(device))
        };
        if own && *device != self.keys.key() && lock(&self.book).hear(device, addrs) {
            self.save_book();
        }
    }

    /// Where this device knows another of its person's to be reached.
    pub fn known_addrs(&self, device: &KeyId) -> Vec<SocketAddr> {
        let book = lock(&self.book);
        let known = book.addrs.get(&hex::encode(device));
        known
            .into_iter()
            .flatten()
            .filter_map(|a| a.parse().ok())
            .collect()
    }

    /// One of this person's devices presented an outside address, one its
    /// router gave it: it is kept with what this device saves of it
    /// (`later.md`: a device leaving home took nothing of what was only
    /// presented).
    pub fn keep_outside(&self, device: &KeyId, addrs: &[SocketAddr]) {
        if *device == self.keys.key() {
            return;
        }
        let mut changed = false;
        {
            let mut book = lock(&self.book);
            for a in addrs.iter().filter(|a| crate::outside::is_outside(a.ip())) {
                changed |= book.keep_outside(device, *a);
            }
        }
        if changed {
            self.save_book();
        }
    }

    /// Records where a device was seen.
    pub fn learn_addr(&self, key: &KeyId, addr: SocketAddr) {
        if lock(&self.book).add(key, addr) {
            self.save_book();
        }
    }

    fn save_book(&self) {
        // Several addresses can answer at once, and a save goes by way of
        // one temporary file.
        let _one = lock(&self.saving_book);
        let b = serde_json::to_vec_pretty(&*lock(&self.book)).unwrap_or_default();
        if let Err(e) = write_private(&self.paths.peers(), &b, 0o600) {
            tracing::warn!("cannot save peers: {e}");
        }
    }

    /// Starts LAN discovery once the discovery secret is known: `t=` for
    /// this person's own devices, and `c=` for their trusted contacts
    /// (D74, `hosts.md#local-discovery`).
    pub fn start_discovery(self: &Arc<Self>) {
        if !self.config().discovers() {
            return;
        }
        let Some(secret) = self.core().discovery_secret() else {
            return;
        };
        if self.discovery_started.swap(true, Ordering::SeqCst) {
            return;
        }
        let Some(port) = self.endpoint.tcp_addr().map(|a| a.port()) else {
            return;
        };
        let cfg = self.mdns_config();
        let d = self.clone();
        tokio::spawn(async move {
            use cardinal_contact::discovery::{self as disc, check_tag_txt, CONTACTS};
            let mut secret = secret;
            let mut own = disc::discovery_key(&secret);
            // The advertisement is made again when the presence secret
            // given changes, so `c=` follows it within a few seconds; and
            // when the discovery secret does (renewed after a recovery).
            let advertise = |secret: &[u8; 32], presence: Option<[u8; 32]>| {
                // The advertised port is the TCP link port (see README).
                match disc::advertise_tags(cfg, secret, presence.as_ref(), port, ADVERTISE_EVERY) {
                    Ok(a) => Some(a),
                    Err(e) => {
                        tracing::warn!("LAN discovery: cannot advertise: {e}");
                        None
                    }
                }
            };
            let mut presence = crate::presence::advertised(&d.core());
            let mut _ad = advertise(&secret, presence);
            let mut browser = match disc::browse_devices(cfg, Duration::from_secs(15)) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!("LAN discovery: cannot browse: {e}");
                    return;
                }
            };
            let mut stop = d.stopping.subscribe();
            let mut look = tokio::time::interval(Duration::from_secs(2));
            // The keys of the contacts' tags, derived once for the state
            // they were read from (review M3).
            let mut keys: (u64, Vec<TagKey>) = (u64::MAX, Vec::new());
            // c= work per source, at most so much in a window (M3).
            let mut by_source: HashMap<std::net::IpAddr, (Instant, u32)> = HashMap::new();
            loop {
                tokio::select! {
                    f = browser.next() => {
                        let Some(f) = f else { break };
                        // Only from the local link, and only its source is
                        // dialled, whatever its records say (L1).
                        if !crate::networks::on_local_link(f.from) {
                            continue;
                        }
                        let at = SocketAddr::new(f.from, f.addr.port());
                        if Some(at.port()) == d.endpoint.tcp_addr().map(|a| a.port())
                            && is_local_ip(&at.ip()) {
                            continue;
                        }
                        // Own devices first: one hash, never held up by
                        // the work for contacts.
                        if f.txt.iter().any(|t| disc::check_device_txt(&own, t)) {
                            d.discovered(at).await;
                            continue;
                        }
                        // Only the first c= is looked at.
                        let Some(tag) = f.txt.iter().find(|t| t.starts_with(CONTACTS)) else {
                            continue;
                        };
                        let now = Instant::now();
                        by_source.retain(|_, (since, _)| now.duration_since(*since) < NEARBY_WINDOW);
                        let seen = by_source.entry(f.from).or_insert((now, 0));
                        seen.1 += 1;
                        if seen.1 > NEARBY_PER_SOURCE {
                            continue;
                        }
                        let version = d.core().state_version();
                        if keys.0 != version {
                            let theirs = crate::presence::of_contacts(&d.core());
                            let derived = theirs.iter().map(|(who, s)| (*who, disc::presence_key(s)));
                            keys = (version, derived.collect());
                        }
                        let found = keys.1.iter().find(|(_, k)| check_tag_txt(CONTACTS, k, tag));
                        if let Some((who, _)) = found {
                            let (d, who) = (d.clone(), *who);
                            tokio::spawn(async move {
                                crate::rendezvous::found_nearby(&d, who, at).await
                            });
                        }
                    }
                    _ = look.tick() => {
                        let now = crate::presence::advertised(&d.core());
                        let mine = d.core().discovery_secret();
                        let renewed = mine.is_some_and(|m| m != secret);
                        if now != presence || renewed {
                            if let Some(m) = mine.filter(|_| renewed) {
                                secret = m;
                                own = disc::discovery_key(&secret);
                            }
                            presence = now;
                            _ad = None;
                            _ad = advertise(&secret, presence);
                        }
                    }
                    _ = stop.changed() => break,
                }
            }
        });
    }

    /// The multicast DNS configuration.
    /// `CARDINAL_TEST_MDNS_INTERFACE` names the interface address to use,
    /// as tests on loopback do.
    pub fn mdns_config(&self) -> cardinal_contact::mdns::MdnsConfig {
        let mut cfg = cardinal_contact::mdns::MdnsConfig {
            port: self.config().mdns(),
            ..Default::default()
        };
        let named = std::env::var("CARDINAL_TEST_MDNS_INTERFACE").ok();
        if let Some(ip) = named.and_then(|i| i.parse().ok()) {
            cfg.interface = ip;
        }
        cfg
    }

    async fn discovered(self: &Arc<Self>, addr: SocketAddr) {
        let devices: Vec<(KeyId, cardinal_crypto::HybridPublicKey)> = {
            let core = self.core();
            let Some(ident) = core.identity.as_ref() else {
                return;
            };
            ident
                .state()
                .keys
                .values()
                .filter(|k| k.key != self.keys.key())
                .filter_map(|k| Some((k.key, k.link_key.clone()?)))
                .collect()
        };
        // A sighting does not say which device it is, so an offline one
        // could be there, unless a device already online is.
        let known: Vec<String> = lock(&self.book).at(&addr).into_iter().cloned().collect();
        let taken = devices
            .iter()
            .any(|(k, l)| known.contains(&hex::encode(k)) && self.is_direct_ip(l.x25519()));
        if taken {
            return;
        }
        for (key, link) in devices {
            if self.is_direct_ip(link.x25519()) {
                continue;
            }
            if !lock(&self.connecting).insert(key) {
                continue;
            }
            let r = self.dial(|c| Target::new(addr, c, &link)).await;
            lock(&self.connecting).remove(&key);
            if let Ok(s) = r {
                tracing::info!(
                    "found {} on the local network at {addr}",
                    self.device_name(&key)
                );
                self.learn_addr(&key, addr);
                self.on_session(s);
                return;
            }
        }
    }

    // ---- link counters ----

    fn restore_counters(&self) {
        let Ok(b) = std::fs::read(self.paths.link_state()) else {
            return;
        };
        let Ok(ls) = serde_json::from_slice::<LinkState>(&b) else {
            return;
        };
        // A margin covers initiations made after the last save.
        self.endpoint.set_last_counter(ls.last_counter + 1024);
        for (k, c) in ls.confirmed {
            if let Ok(v) = hex::decode(&k) {
                if let Ok(a) = <[u8; 32]>::try_from(&v[..]) {
                    self.endpoint.set_confirmed_counter(a, c);
                }
            }
        }
    }

    /// Saves the link counters.
    pub fn save_counters(&self) {
        let mut ls = LinkState {
            last_counter: self.endpoint.last_counter(),
            confirmed: HashMap::new(),
        };
        let statics: Vec<[u8; 32]> = {
            let core = self.core();
            core.identity
                .as_ref()
                .map(|i| {
                    i.state()
                        .keys
                        .values()
                        .filter_map(|k| k.link_key.as_ref().map(|l| *l.x25519()))
                        .collect()
                })
                .unwrap_or_default()
        };
        for s in statics {
            if let Some(c) = self.endpoint.confirmed_counter(&s) {
                ls.confirmed.insert(hex::encode(s), c);
            }
        }
        if let Ok(b) = serde_json::to_vec(&ls) {
            let _ = write_private(&self.paths.link_state(), &b, 0o600);
        }
    }

    // ---- running ----

    /// Runs until stopped.
    pub async fn run(self: Arc<Self>) -> anyhow::Result<()> {
        // A recovery helper is driven by the service it runs in.
        let helper = self.config().this_run.inside();
        let control = match helper {
            true => None,
            false => Some(crate::control::serve(self.clone())?),
        };
        tracing::info!(
            "cardinal {} daemon started: data in {}, listening on {}, control socket {}",
            cardinal_update::VERSION,
            self.paths.home.display(),
            self.endpoint
                .tcp_addr()
                .map(|a| a.to_string())
                .unwrap_or_default(),
            self.paths.socket.display()
        );
        if self.core().identity.is_none() && !helper {
            tracing::info!(
                "this device does not belong to anyone yet: run `cardinal init` (first device) \
                 or `cardinal pair` (to add it to your other devices)"
            );
        }
        // what stopped half way: a successor not followed yet, work not
        // posted again yet
        crate::following::follow(&self);
        // accept sessions
        let d = self.clone();
        tokio::spawn(async move {
            while let Some(s) = d.endpoint.accept().await {
                d.on_session(s);
            }
        });
        // endpoint events
        let d = self.clone();
        let mut ev = self.endpoint.events();
        tokio::spawn(async move {
            loop {
                match ev.recv().await {
                    Ok(EndpointEvent::Closed {
                        peer_static,
                        reason,
                    }) => {
                        tracing::debug!("session with {} closed: {reason}", short(&peer_static));
                        let gen = lock(&d.sessions).get(&peer_static).map(|c| c.gen);
                        if let Some(g) = gen {
                            let closed = lock(&d.sessions)
                                .get(&peer_static)
                                .is_some_and(|c| c.session.is_closed());
                            if closed {
                                d.session_closed(&peer_static, g);
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(_) => break,
                }
            }
        });
        // reconnect loop
        let d = self.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(Duration::from_secs(2));
            loop {
                t.tick().await;
                d.connect_all().await;
            }
        });
        // counters
        let d = self.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(Duration::from_secs(30));
            loop {
                t.tick().await;
                d.save_counters();
            }
        });
        crate::fetch::start(self.clone());
        crate::copies::start(self.clone());
        crate::cleanup::start(self.clone());
        // Objects put without a sync (chunks read on demand) are flushed
        // within a second, so a killed process does not leave them in tmp.
        {
            let d = self.clone();
            tokio::spawn(async move {
                let mut stop = d.stopping.subscribe();
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
                        _ = stop.changed() => {}
                    }
                    if *d.stopping.borrow() {
                        break;
                    }
                    if d.store.has_pending() {
                        let s = d.store.clone();
                        let _ = tokio::task::spawn_blocking(move || {
                            use cardinal_blob::ObjectStore;
                            if let Err(e) = s.sync() {
                                tracing::warn!("cannot flush stored objects: {e}");
                            }
                        })
                        .await;
                    }
                }
            });
        }
        crate::mailbox::start(self.clone());
        crate::groups::start(self.clone());
        crate::introductions::start(self.clone());
        crate::names::start(self.clone());
        // Report (never install) new releases, if the person allows it.
        let cfg_path = self.paths.config();
        let looks = !helper;
        tokio::spawn(async move {
            if !looks {
                return;
            }
            loop {
                let p = cfg_path.clone();
                let r = tokio::task::spawn_blocking(move || -> anyhow::Result<Option<String>> {
                    let c = cardinal_update::config::UpdateConfig::load(&p)?;
                    if !c.auto_check {
                        return Ok(None);
                    }
                    cardinal_update::check_for_update()
                })
                .await;
                match r {
                    Ok(Ok(Some(v))) => tracing::info!(
                        "cardinal {v} is available (this is {}); run `cardinal update`",
                        cardinal_update::VERSION
                    ),
                    Ok(Err(e)) => tracing::debug!("update check: {e:#}"),
                    _ => {}
                }
                tokio::time::sleep(Duration::from_secs(24 * 3600)).await;
            }
        });
        self.housekeeping();
        if !helper {
            // Always, but for a helper: switched off now, on another
            // device it may be turned on.
            tokio::spawn(crate::portmap::keep(self.clone()));
            // a recovery through guardians under way goes on
            crate::recovering::resume(&self);
            // and this person's guardian personas act
            crate::guardians::start_personas(&self);
        }

        let mut stop = self.stopping.subscribe();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => tracing::info!("interrupted"),
            _ = asked_to_end() => tracing::info!("terminated"),
            _ = stop.wait_for(|v| *v) => tracing::info!("stop requested"),
        }
        let _ = self.stopping.send(true);
        let d = self.clone();
        tokio::task::spawn_blocking(move || d.unmount()).await?;
        self.save_counters();
        // Tell the other devices, so they drop the session now rather
        // than keep a dead one that a restart's new session must beat.
        self.endpoint
            .close_gracefully(Duration::from_millis(500))
            .await;
        if control.is_some() {
            drop(control);
            let _ = std::fs::remove_file(&self.paths.socket);
        }
        if !helper {
            crate::helper::stop_all(&self).await;
        }
        tracing::info!("stopped");
        Ok(())
    }
}

/// Whether an address is one of this machine's.
pub fn is_local_ip(ip: &std::net::IpAddr) -> bool {
    if ip.is_loopback() {
        return true;
    }
    local_ips().contains(ip)
}

/// This machine's addresses, best effort: the address used to reach the
/// internet, and loopback.
pub fn local_ips() -> Vec<std::net::IpAddr> {
    let mut v = Vec::new();
    if let Ok(s) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if s.connect("192.0.2.1:9").is_ok() {
            if let Ok(a) = s.local_addr() {
                v.push(a.ip());
            }
        }
    }
    v
}

#[cfg(test)]
mod book_tests {
    use super::*;

    const D: KeyId = [1; 32];

    fn book(addrs: &[&str]) -> PeerBook {
        let mut b = PeerBook::default();
        b.addrs.insert(
            hex::encode(D),
            addrs.iter().map(|a| (*a).to_owned()).collect(),
        );
        b
    }

    #[test]
    fn a_device_that_moved_keeps_its_port_at_the_new_address() {
        let mut b = book(&["172.20.0.240:7171", "10.0.0.1:9000"]);
        assert!(b.moved(&D, "172.20.1.20".parse().unwrap()));
        assert_eq!(
            b.addrs[&hex::encode(D)],
            ["172.20.1.20:7171", "172.20.0.240:7171", "10.0.0.1:9000"]
        );
        assert!(!b.moved(&D, "172.20.1.20".parse().unwrap()), "no news");
    }

    #[test]
    fn what_a_device_is_told_comes_after_what_it_found_out() {
        let told: Vec<SocketAddr> = vec![
            "10.0.0.1:1".parse().unwrap(),
            "172.20.0.240:7171".parse().unwrap(),
        ];
        let mut b = book(&["172.20.0.240:7171"]);
        assert!(b.hear(&D, &told));
        assert_eq!(
            b.addrs[&hex::encode(D)],
            ["172.20.0.240:7171", "10.0.0.1:1"]
        );
        assert!(!b.hear(&D, &told), "no news");

        // It never pushes out what is already there.
        let many: Vec<SocketAddr> = (0..20)
            .map(|n| SocketAddr::from(([10, 0, 1, n], 7171)))
            .collect();
        b.hear(&D, &many);
        assert_eq!(b.addrs[&hex::encode(D)].len(), BOOK_LEN);
        assert_eq!(b.addrs[&hex::encode(D)][0], "172.20.0.240:7171");
    }

    #[test]
    fn a_device_never_reached_has_no_port_to_keep() {
        let mut b = PeerBook::default();
        assert!(!b.moved(&D, "172.20.1.20".parse().unwrap()));
        assert!(b.addrs.is_empty());
    }

    #[test]
    fn an_address_names_the_devices_known_there() {
        let b = book(&["172.20.0.251:7171"]);
        assert_eq!(b.at(&"172.20.0.251:7171".parse().unwrap()).len(), 1);
        assert!(b.at(&"172.20.0.251:7172".parse().unwrap()).is_empty());
    }
}

/// `name`, or the first of "name 2", "name 3", ... that none of `others`
/// is called, ignoring case.
pub fn unique_name(name: &str, others: &[String]) -> String {
    let taken = |n: &str| others.iter().any(|o| o.to_lowercase() == n.to_lowercase());
    if !taken(name) {
        return name.to_owned();
    }
    (2..)
        .map(|i| format!("{name} {i}"))
        .find(|n| !taken(n))
        .expect("some number is free")
}

#[cfg(test)]
mod unique_name_tests {
    #[test]
    fn a_path_with_no_address_is_nobodys_relay() {
        let host: std::net::SocketAddr = "192.0.2.1:7171".parse().unwrap();
        let direct = vec![([1u8; 32], None), ([2u8; 32], Some(host))];
        assert_eq!(
            super::relay_of(direct.clone().into_iter(), host),
            Some([2; 32])
        );
        let only_radio = vec![([1u8; 32], None)];
        assert_eq!(super::relay_of(only_radio.into_iter(), host), None);
    }

    #[test]
    fn a_name_another_device_has_gets_the_next_number() {
        let others = vec!["Carbonite".to_owned(), "carbonite 2".to_owned()];
        assert_eq!(super::unique_name("desk", &others), "desk");
        assert_eq!(super::unique_name("carbonite", &others), "carbonite 3");
        assert_eq!(super::unique_name("CARBONITE", &[]), "CARBONITE");
    }
}

/// Of direct sessions, by link key and remote address, the one at `at`.
fn relay_of(
    direct: impl Iterator<Item = ([u8; 32], Option<SocketAddr>)>,
    at: SocketAddr,
) -> Option<[u8; 32]> {
    direct
        .filter(|(_, a)| *a == Some(at))
        .map(|(x, _)| x)
        .next()
}

/// How a session runs, and who opened it, in words.
fn route(s: &Session) -> String {
    let by = if s.role() == cardinal_link::Role::Initiator {
        "you reached them"
    } else {
        "they reached you"
    };
    match (s.is_relayed(), s.remote_addr(), s.carrier()) {
        (true, _, _) => format!("relayed, {by}"),
        (false, Some(a), Some(CarrierKind::Tcp)) => format!("direct at {a} over TCP, {by}"),
        (false, None, Some(CarrierKind::Ble)) => format!("direct over Bluetooth, {by}"),
        (false, Some(a), _) => format!("direct at {a}, {by}"),
        (false, None, _) => by.to_owned(),
    }
}

/// Why a session closed, in words.
/// How long a device that closed a session with "prove first" is left
/// before it is dialled again.
const PROVE_FIRST_BACKOFF: Duration = Duration::from_secs(60);

/// Whether a session was closed by the other end because this device is
/// not one it serves (`host.rs`).
fn is_prove_first(r: Option<&cardinal_link::CloseReason>) -> bool {
    matches!(r, Some(cardinal_link::CloseReason::Remote(w)) if w == crate::host::PROVE_FIRST)
}

pub(crate) fn closed_why(r: &cardinal_link::CloseReason) -> String {
    use cardinal_link::CloseReason as R;
    match r {
        R::Local(w) => format!("closed here ({w})"),
        R::Remote(w) => format!("closed by them ({w})"),
        R::Idle => "nothing heard from them for too long".into(),
        R::Timeout => "not set up in time".into(),
        R::Protocol(w) => format!("broke the protocol ({w})"),
        R::Carrier => "the network failed".into(),
        R::Identity => "their device's proof no longer counts".into(),
        R::Replaced => "replaced by a newer session".into(),
        R::EndpointClosed => "this service stopped".into(),
        #[allow(unreachable_patterns)]
        _ => format!("{r:?}"),
    }
}
