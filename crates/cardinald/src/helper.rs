//! The recovery helper (`identity.md#how-guardians-act`, D77): an identity
//! of its own that a new device makes only to talk to guardians, with no
//! words of its own and nothing it would ever need to merge. It meets each
//! guardian through an ordinary invitation, so it has everything a person
//! has for that (relationships, mailboxes, the sessions contacts open) and
//! the guardians nothing they would not have with anyone they meet.
//!
//! It runs as a second service inside the new device's, with a data
//! directory of its own (`recovery-helper` in the new device's) and keys of
//! its own, on a runtime of its own, so that stopping it ends all it does.
//! It has no control socket, no mount, no discovery and no port mapping;
//! the new device's service drives it (`recovering.rs`). Once the recovery
//! is in effect, or given up, it is stopped and its directory removed.

use std::sync::Arc;
use std::time::Duration;

use crate::config::Config;
use crate::daemon::Daemon;
use crate::paths::Paths;

/// The name a helper suggests for itself, which guardians' devices do not
/// show: they show the relationship as "recovery for" the person.
pub const NAME: &str = "Recovery helper";

/// A recovery helper's service, running.
pub struct Helper {
    /// Its service.
    pub d: Arc<Daemon>,
    thread: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
    /// The identity entries carried into each relationship by this run, so
    /// that each is looked at once (`recovering.rs`).
    pub carried: std::sync::Mutex<
        std::collections::HashMap<cardinal_space::SpaceId, std::collections::HashSet<[u8; 32]>>,
    >,
    /// The helper's change count when the new device last carried.
    pub seen: std::sync::atomic::AtomicU64,
}

impl Helper {
    /// Runs `f` on the helper's runtime, where whatever it spawns belongs
    /// to the helper and ends with it.
    pub async fn on<T, F, Fut>(&self, f: F) -> anyhow::Result<T>
    where
        F: FnOnce(Arc<Daemon>) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = anyhow::Result<T>> + Send + 'static,
        T: Send + 'static,
    {
        let d = self.d.clone();
        self.d
            .rt
            .spawn(async move { f(d).await })
            .await
            .map_err(|e| anyhow::anyhow!("the recovery helper stopped: {e}"))?
    }

    /// The helper's identity.
    pub fn identity(&self) -> Option<[u8; 32]> {
        self.d.core().me()
    }
}

/// The paths of the helper of the device whose paths are `main`.
pub fn paths(main: &Paths) -> Paths {
    let home = main.recovery_helper();
    Paths {
        socket: home.join("control.sock"),
        config_dir: home.clone(),
        home,
    }
}

/// Where the helper listens: on the address the new device listens on,
/// at a port of its own.
fn listen(main: &Daemon) -> String {
    let ip = main
        .endpoint
        .udp_addr()
        .or(main.endpoint.tcp_addr())
        .map(|a| a.ip())
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    std::net::SocketAddr::new(ip, 0).to_string()
}

/// The settings of a persona's service, inside `main`'s.
fn service_config(main: &Daemon, name: &str) -> Config {
    Config {
        name: name.to_owned(),
        listen: listen(main),
        mount: None,
        discovery: false,
        port_mapping: false,
        tcp_only: main.config().tcp_only,
        ..Config::default()
    }
}

/// Starts the helper of `main`, making its identity first if it has none.
pub async fn start(main: &Arc<Daemon>) -> anyhow::Result<Arc<Helper>> {
    if let Some(h) = main
        .helper
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
    {
        return Ok(h);
    }
    let paths = paths(&main.paths);
    let mut config = service_config(main, NAME);
    if !crate::core::has_identity(&paths) {
        // No words: nobody ever needs them, and losing the helper costs
        // only starting the recovery over.
        let prepared = crate::setup::prepare(&paths)?;
        config.save(&paths.config())?;
        crate::setup::install(&paths, prepared, &config, NAME)?;
    }
    config.this_run.helper = true;
    let h = run_service(paths, config, "recovery-helper").await?;
    *main.helper.lock().unwrap_or_else(|e| e.into_inner()) = Some(h.clone());
    tracing::info!(
        "recovery helper {} started",
        h.identity()
            .map(|i| crate::core::short(&i))
            .unwrap_or_default()
    );
    Ok(h)
}

/// The name a guardian's persona suggests for itself, which a helper's
/// device does not show: its person knows whom they asked.
pub const GUARDIAN_NAME: &str = "Guardian";

/// The paths of the service of `main`'s persona `id`.
pub fn persona_paths(main: &Paths, id: &[u8; 32]) -> Paths {
    let home = main.home.join("personas").join(hex::encode(id));
    Paths {
        socket: home.join("control.sock"),
        config_dir: home.clone(),
        home,
    }
}

/// A persona just made: its entropy, its id, and its log.
pub type MadePersona = ([u8; 32], [u8; 32], Vec<Vec<u8>>);

/// Makes a guardian persona on this device (`identity.md#personas`): its
/// root from 32 fresh bytes, a device key of this device's service for it,
/// and a log, in a directory of its own. Returns the entropy, the id and
/// the log.
pub fn make_persona(main: &Daemon) -> anyhow::Result<MadePersona> {
    let entropy: [u8; 32] = cardinal_crypto::random_bytes();
    let phrase = cardinal_crypto::RecoveryPhrase::from_entropy(&entropy);
    let making = main.paths.home.join("personas").join(format!(
        "making-{}",
        hex::encode(cardinal_crypto::random_bytes::<8>())
    ));
    let tmp = Paths {
        socket: making.join("control.sock"),
        config_dir: making.clone(),
        home: making.clone(),
    };
    std::fs::create_dir_all(&tmp.home)?;
    let keys = crate::keys::Keys::load_or_create(&tmp.device_key())?;
    let created = cardinal_identity::IdentityLog::create_with(
        phrase,
        &keys.device,
        cardinal_crypto::HybridKeyPair::generate(),
    )?;
    let id = created.log.id();
    let entries: Vec<Vec<u8>> = created.log.entries().map(|e| e.encode()).collect();
    let config = service_config(main, GUARDIAN_NAME);
    config.save(&tmp.config())?;
    crate::setup::install_entries(&tmp, &entries, &config, GUARDIAN_NAME)?;
    let paths = persona_paths(&main.paths, &id);
    std::fs::rename(&making, &paths.home)?;
    Ok((entropy, id, entries))
}

/// Starts the service of `main`'s persona `id`, if this device has one.
pub async fn start_persona(main: &Arc<Daemon>, id: &[u8; 32]) -> anyhow::Result<Arc<Helper>> {
    // one start at a time, so that two never take the same directory
    static STARTING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let _one = STARTING.lock().await;
    if let Some(h) = lock(&main.personas).get(id).cloned() {
        return Ok(h);
    }
    let paths = persona_paths(&main.paths, id);
    anyhow::ensure!(
        crate::core::has_identity(&paths),
        "this device does not act as that persona"
    );
    let mut config = service_config(main, GUARDIAN_NAME);
    config.this_run.guardian_persona = true;
    let h = run_service(paths, config, "persona").await?;
    lock(&main.personas).insert(*id, h.clone());
    tracing::info!("persona {} started", crate::core::short(id));
    Ok(h)
}

/// Stops the service of `main`'s persona `id`, and with `drop` removes it.
pub async fn stop_persona(main: &Arc<Daemon>, id: &[u8; 32], drop: bool) {
    let h = lock(&main.personas).remove(id);
    if let Some(h) = h {
        halt(h).await;
    }
    if drop {
        let home = persona_paths(&main.paths, id).home;
        if let Err(e) = std::fs::remove_dir_all(&home) {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!("cannot remove {}: {e}", home.display());
            }
        }
    }
}

fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Runs a persona's service on a thread and runtime of its own.
async fn run_service(
    paths: Paths,
    mut config: Config,
    thread: &str,
) -> anyhow::Result<Arc<Helper>> {
    config.this_run.no_mount = true;
    config.this_run.no_discovery = true;
    // a port of its own each time
    config.this_run.listen_given = true;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let name = thread.to_owned();
    let thread = std::thread::Builder::new()
        .name(name.clone())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_name(name)
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = tx.send(Err(anyhow::anyhow!("{e}")));
                    return;
                }
            };
            rt.block_on(async move {
                let started = async {
                    let lock = Daemon::take(&paths)?;
                    Daemon::start_holding(paths, config, lock).await
                };
                match started.await {
                    Ok(d) => {
                        let _ = tx.send(Ok(d.clone()));
                        if let Err(e) = d.run().await {
                            tracing::warn!("a persona's service stopped: {e:#}");
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(e));
                    }
                }
            });
            rt.shutdown_timeout(Duration::from_secs(2));
        })?;
    let d = rx
        .await
        .map_err(|_| anyhow::anyhow!("a persona's service did not start"))??;
    Ok(Arc::new(Helper {
        d,
        thread: std::sync::Mutex::new(Some(thread)),
        carried: Default::default(),
        seen: std::sync::atomic::AtomicU64::new(u64::MAX),
    }))
}

/// Stops a service and waits for its thread.
async fn halt(h: Arc<Helper>) {
    let _ = h.d.stopping.send(true);
    let thread = h.thread.lock().unwrap_or_else(|e| e.into_inner()).take();
    drop(h);
    if let Some(t) = thread {
        let _ = tokio::task::spawn_blocking(move || {
            let _ = t.join();
        })
        .await;
    }
}

/// Stops the helper of `main`. [`remove_left`] then drops it: its
/// directory goes, and with it its identity and every relationship it had.
pub async fn stop(main: &Arc<Daemon>) -> anyhow::Result<()> {
    let h = main.helper.lock().unwrap_or_else(|e| e.into_inner()).take();
    if let Some(h) = h {
        halt(h).await;
    }
    Ok(())
}

/// Stops every persona's service of `main`.
pub async fn stop_all(main: &Arc<Daemon>) {
    let _ = stop(main).await;
    let all: Vec<Arc<Helper>> = lock(&main.personas).drain().map(|(_, h)| h).collect();
    for h in all {
        halt(h).await;
    }
}

/// Removes a helper's directory, if there is one and no recovery is under
/// way. What cannot be removed now (a file still open, on Windows) is
/// removed when the service starts next.
pub fn remove_left(main: &Daemon) {
    let home = main.paths.recovery_helper();
    if main.paths.recovering().exists() || !home.exists() {
        return;
    }
    if let Err(e) = std::fs::remove_dir_all(&home) {
        tracing::warn!(
            "cannot remove the recovery helper's {} yet: {e}",
            home.display()
        );
    }
}
