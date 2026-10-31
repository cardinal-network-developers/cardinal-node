//! The daemon: holds everything, keeps sessions with this person's other
//! devices, syncs, serves the mount and the control socket.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
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

/// Addresses of this person's devices, learned from pairing, discovery,
/// and successful connections.
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
        v.truncate(6);
        true
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
    },
    /// Joined.
    Joined {
        /// The admin device's name.
        admin_name: String,
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
    connecting: Mutex<HashSet<KeyId>>,
    /// Bumped on every change to the identity or a space.
    pub changed: watch::Sender<u64>,
    /// News waiting to be passed on.
    pub news: Mutex<crate::news::Waiting>,
    /// Static keys of restore sessions that proved the root key.
    proven: Mutex<HashSet<[u8; 32]>>,
    /// Pairing.
    pub pairing: Mutex<PairState>,
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
    /// Speed tests this device serves (`speedtest.rs`).
    pub speedtest: crate::speedtest::Limiter,
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

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Raises the open-file limit to the hard limit. The soft default (often
/// 1024) is too low for a file server with many peers and open files.
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

impl Daemon {
    /// Loads everything and binds the link endpoint.
    pub async fn start(paths: Paths, config: Config) -> anyhow::Result<Arc<Daemon>> {
        raise_fd_limit();
        std::fs::create_dir_all(&paths.home)?;
        let keys = Arc::new(Keys::load_or_create(&paths.device_key())?);
        let core = Core::load(&paths, keys.clone())?;
        let store = Arc::new(FsStore::open(paths.blobs(), Fsync::Deferred)?);
        std::fs::create_dir_all(paths.staging())?;
        let directory = Arc::new(Directory::default());
        directory.update(core.identity.as_ref().map(|i| i.state()).as_deref());
        let mut ec = EndpointConfig::new(keys.link.clone(), directory.clone());
        ec.identity = core.identity.as_ref().map(|i| LocalIdentity {
            identity: i.id(),
            signing_key: keys.signing.clone(),
        });
        ec.connect_timeout = Duration::from_secs(5);
        ec.allow_public = config.host;
        ec.session = SessionConfig {
            keepalive: Some(Duration::from_secs(20)),
            ..SessionConfig::default()
        };
        let listen: SocketAddr = config.listen.parse().map_err(|_| {
            anyhow::anyhow!(
                "the listen address {:?} is not ip:port (fix it in {})",
                config.listen,
                paths.config().display()
            )
        })?;
        let endpoint = Endpoint::bind(
            ec,
            Bind {
                udp: if config.udp { Some(listen) } else { None },
                tcp: Some(listen),
            },
        )
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "cannot listen on {listen}: {e}. Is another cardinal daemon running? \
                 Set another port with `cardinal daemon --listen 0.0.0.0:PORT`."
            )
        })?;
        let book: PeerBook = std::fs::read(paths.peers())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let copies_path = paths.copies();
        let old_versions = paths.old_versions();
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
            connecting: Mutex::new(HashSet::new()),
            changed: watch::channel(0).0,
            pairing: Mutex::new(PairState::Idle),
            mount: Mutex::new(None),
            mount_unavailable: Mutex::new(None),
            mount_lock: Mutex::new(()),
            progress: Mutex::new(Progress::default()),
            blob_stats: Mutex::new(HashMap::new()),
            news: Mutex::new(HashMap::new()),
            proven: Mutex::new(HashSet::new()),
            copies: crate::copies::Tracker::load(copies_path, crate::copies::Rules::from_env()),
            cleanup: crate::cleanup::Cleaner::load(old_versions),
            speedtest: crate::speedtest::Limiter::default(),
            placement_lock: Mutex::new(()),
            stopping: watch::channel(false).0,
            next_gen: AtomicU64::new(1),
            started: Instant::now(),
            discovery_started: AtomicBool::new(false),
        });
        d.restore_counters();
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
        if let Some(k) = self.core().is_own_device(&ps) {
            return PeerKind::Own(k);
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

    /// Whether a device has an open session.
    pub fn is_online(&self, link_x25519: &[u8; 32]) -> bool {
        lock(&self.sessions)
            .get(link_x25519)
            .is_some_and(|c| !c.session.is_closed())
    }

    /// The remote address of a device's session.
    pub fn session_addr(&self, link_x25519: &[u8; 32]) -> Option<SocketAddr> {
        lock(&self.sessions)
            .get(link_x25519)
            .and_then(|c| c.session.remote_addr())
    }

    /// Takes on a new session: serves it and syncs everything.
    pub fn on_session(self: &Arc<Self>, s: Session) {
        let kind = self.classify(&s);
        if kind == PeerKind::Stranger {
            tracing::info!("closing a session with an unknown device");
            s.close("unknown device");
            return;
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
        if let PeerKind::Own(k) = kind {
            lock(&self.backoff).remove(&k);
        }
        self.save_counters();
        let d = self.clone();
        let s2 = s.clone();
        tokio::spawn(net::serve(d, s2, gen));
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
        tokio::spawn(async move { net::sync_all(&d, &s).await });
    }

    /// Forgets a closed session.
    pub fn session_closed(&self, peer_static: &[u8; 32], gen: u64) {
        let mut m = lock(&self.sessions);
        if m.get(peer_static).is_some_and(|c| c.gen == gen) {
            m.remove(peer_static);
            lock(&self.proven).remove(peer_static);
            tracing::info!("disconnected from {}", short(peer_static));
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
        let out = core.ingest_space(label, &objects)?;
        drop(core);
        if out.new > 0 {
            tracing::debug!("space {}: {} new entries", short(&label), out.new);
            self.bump();
            self.housekeeping();
        }
        Ok(out)
    }

    /// After the identity log changed.
    pub fn identity_changed(&self) {
        let st = {
            let mut core = self.core();
            core.identity_updated();
            core.identity.as_ref().map(|i| i.state())
        };
        self.directory.update(st.as_deref());
        self.endpoint.recheck_peers();
        let conns: Vec<Conn> = lock(&self.sessions).values().cloned().collect();
        for c in conns {
            let kind = self.classify(&c.session);
            if let Some(x) = lock(&self.sessions).get_mut(&c.session.peer_static()) {
                x.kind = kind;
            }
        }
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
        self.directory.update(Some(&st));
        let prev = std::mem::take(&mut *lock(&self.pairing));
        let admin_name = match &prev {
            PairState::Joining { admin_name, .. } => admin_name.clone(),
            _ => String::new(),
        };
        *lock(&self.pairing) = PairState::Joined { admin_name };
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
            // Mounting blocks, and may wait for another mount or unmount.
            let d2 = d.clone();
            let _ = tokio::task::spawn_blocking(move || d2.ensure_mounted()).await;
            d.start_discovery();
        });
    }

    /// Keeps this device's device node and its placement of the files
    /// space in the account space, with its current retention, so the
    /// person's other devices know what it means to keep
    /// (`blobs.md#counting-copies`).
    fn ensure_placement(self: &Arc<Self>) -> anyhow::Result<()> {
        let _one = lock(&self.placement_lock);
        let (acc, files, has_device, space_node, mine) = {
            let core = self.core();
            let (Some(acc), Some(files)) = (core.account_id(), core.files_id()) else {
                return Ok(());
            };
            let st = core.spaces[&acc].space.as_ref().expect("open").state();
            let me = self.keys.key();
            let has_device = account::devices(st).iter().any(|d| d.key == me);
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
            (acc, files, has_device, space_node, mine)
        };
        let me = self.keys.key();
        let cfg = self.config().clone();
        let mut ops = Vec::new();
        if !has_device {
            ops.push(account::create_device(&me, &cfg.name, false, false));
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
                for p in mine.iter().filter(|p| p.retention != want) {
                    tracing::info!(
                        "recording this device's retention ({}) in the account space",
                        cfg.retention
                    );
                    ops.push(account::set_field(p.node, 2, want as u32));
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

    /// Tries to connect to every own device that is not online.
    pub async fn connect_all(self: &Arc<Self>) {
        let devices: Vec<(KeyId, cardinal_crypto::HybridPublicKey)> = {
            let core = self.core();
            let Some(ident) = core.identity.as_ref() else {
                return;
            };
            let st = ident.state();
            st.keys
                .values()
                .filter(|k| k.key != self.keys.key())
                .filter_map(|k| Some((k.key, k.link_key.clone()?)))
                .collect()
        };
        for (key, link) in devices {
            if self.is_online(link.x25519()) {
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
    }

    async fn candidate_addrs(&self, key: &KeyId) -> Vec<(SocketAddr, Option<String>)> {
        let (known, manual): (Vec<String>, Vec<(String, Option<String>)>) = {
            let book = lock(&self.book);
            let known = book
                .addrs
                .get(&hex::encode(key))
                .cloned()
                .unwrap_or_default();
            let peers = self.config().peers.clone();
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
        for (p, tag) in manual {
            let lookup = tokio::net::lookup_host(p.clone()).await;
            if let Ok(mut it) = lookup {
                if let Some(sa) = it.next() {
                    if !out.iter().any(|(x, _)| *x == sa) {
                        out.push((sa, tag.or(Some(p))));
                    }
                }
            }
        }
        out
    }

    async fn try_device(
        self: &Arc<Self>,
        key: KeyId,
        link: cardinal_crypto::HybridPublicKey,
    ) -> bool {
        for (addr, manual) in self.candidate_addrs(&key).await {
            if self.is_online(link.x25519()) {
                return true;
            }
            let t = Target::new(addr, CarrierKind::Tcp, &link);
            match self.endpoint.connect(t).await {
                Ok(s) => {
                    {
                        let mut book = lock(&self.book);
                        book.add(&key, addr);
                        if let Some(m) = manual {
                            book.manual.insert(m, hex::encode(key));
                        }
                    }
                    self.save_book();
                    self.on_session(s);
                    return true;
                }
                // The device's own simultaneous session won: connected.
                Err(cardinal_link::LinkError::Closed(cardinal_link::CloseReason::Replaced)) => {
                    return true;
                }
                Err(e) => {
                    tracing::debug!("connect to {} at {addr}: {e}", short(&key));
                }
            }
        }
        false
    }

    /// Records where a device was seen.
    pub fn learn_addr(&self, key: &KeyId, addr: SocketAddr) {
        if lock(&self.book).add(key, addr) {
            self.save_book();
        }
    }

    fn save_book(&self) {
        let b = serde_json::to_vec_pretty(&*lock(&self.book)).unwrap_or_default();
        if let Err(e) = write_private(&self.paths.peers(), &b, 0o600) {
            tracing::warn!("cannot save peers: {e}");
        }
    }

    /// Starts LAN discovery once the discovery secret is known.
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
            // The advertised port is the TCP link port (see README).
            let _ad = match cardinal_contact::discovery::advertise_device(
                cfg,
                &secret,
                port,
                Duration::from_secs(30),
            ) {
                Ok(a) => Some(a),
                Err(e) => {
                    tracing::warn!("LAN discovery: cannot advertise: {e}");
                    None
                }
            };
            let mut browser = match cardinal_contact::discovery::DeviceBrowser::start(
                cfg,
                &[secret],
                Duration::from_secs(15),
            ) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!("LAN discovery: cannot browse: {e}");
                    return;
                }
            };
            let mut stop = d.stopping.subscribe();
            loop {
                tokio::select! {
                    f = browser.next() => {
                        let Some(f) = f else { break };
                        if Some(f.addr.port()) == d.endpoint.tcp_addr().map(|a| a.port())
                            && is_local_ip(&f.addr.ip()) {
                            continue;
                        }
                        d.discovered(f.addr).await;
                    }
                    _ = stop.changed() => break,
                }
            }
        });
    }

    /// The multicast DNS configuration.
    pub fn mdns_config(&self) -> cardinal_contact::mdns::MdnsConfig {
        cardinal_contact::mdns::MdnsConfig {
            port: self.config().mdns(),
            ..Default::default()
        }
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
        for (key, link) in devices {
            if self.is_online(link.x25519()) {
                continue;
            }
            if !lock(&self.connecting).insert(key) {
                continue;
            }
            let t = Target::new(addr, CarrierKind::Tcp, &link);
            let r = self.endpoint.connect(t).await;
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
        let control = crate::control::serve(self.clone())?;
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
        if self.core().identity.is_none() {
            tracing::info!(
                "this device does not belong to anyone yet: run `cardinal init` (first device) \
                 or `cardinal pair` (to add it to your other devices)"
            );
        }
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
        // Report (never install) new releases, if the person allows it.
        let cfg_path = self.paths.config();
        tokio::spawn(async move {
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

        let mut stop = self.stopping.subscribe();
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => tracing::info!("interrupted"),
            _ = term.recv() => tracing::info!("terminated"),
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
        drop(control);
        let _ = std::fs::remove_file(&self.paths.socket);
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
