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
    let mut config = Config {
        name: NAME.to_owned(),
        listen: listen(main),
        mount: None,
        discovery: false,
        port_mapping: false,
        tcp_only: main.config().tcp_only,
        ..Config::default()
    };
    if !crate::core::has_identity(&paths) {
        // No words: nobody ever needs them, and losing the helper costs
        // only starting the recovery over.
        let prepared = crate::setup::prepare(&paths)?;
        config.save(&paths.config())?;
        crate::setup::install(&paths, prepared, &config, NAME)?;
    }
    config.this_run.helper = true;
    config.this_run.no_mount = true;
    config.this_run.no_discovery = true;
    // a port of its own each time
    config.this_run.listen_given = true;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let thread = std::thread::Builder::new()
        .name("recovery-helper".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_name("recovery-helper")
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
                            tracing::warn!("the recovery helper stopped: {e:#}");
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
        .map_err(|_| anyhow::anyhow!("the recovery helper did not start"))??;
    let h = Arc::new(Helper {
        d,
        thread: std::sync::Mutex::new(Some(thread)),
        carried: Default::default(),
        seen: std::sync::atomic::AtomicU64::new(u64::MAX),
    });
    *main.helper.lock().unwrap_or_else(|e| e.into_inner()) = Some(h.clone());
    tracing::info!(
        "recovery helper {} started",
        h.identity()
            .map(|i| crate::core::short(&i))
            .unwrap_or_default()
    );
    Ok(h)
}

/// Stops the helper of `main`. [`remove_left`] then drops it: its
/// directory goes, and with it its identity and every relationship it had.
pub async fn stop(main: &Arc<Daemon>) -> anyhow::Result<()> {
    let h = main.helper.lock().unwrap_or_else(|e| e.into_inner()).take();
    if let Some(h) = h {
        let _ = h.d.stopping.send(true);
        let thread = h.thread.lock().unwrap_or_else(|e| e.into_inner()).take();
        drop(h);
        if let Some(t) = thread {
            tokio::task::spawn_blocking(move || {
                let _ = t.join();
            })
            .await?;
        }
    }
    Ok(())
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
