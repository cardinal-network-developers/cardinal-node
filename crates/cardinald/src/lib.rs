//! The Cardinal daemon (`cardinal daemon`): it holds this device's keys,
//! identity log, spaces, and content store; keeps link sessions with the
//! person's other devices and syncs with them; mounts the files space as
//! a folder; and answers the `cardinal` command on a local socket.
//!
//! See `README.md` in this crate for the design.

pub mod applog;
pub mod config;
pub mod control;
pub mod copies;
pub mod core;
pub mod daemon;
pub mod directory;
pub mod fetch;
pub mod fs;
pub mod keys;
pub mod net;
pub mod pair;
pub mod paths;
pub mod sched;
pub mod setup;
pub mod speedtest;

pub use config::Config;
pub use daemon::Daemon;
pub use paths::Paths;

/// Logs to stderr, which journald collects when run as a systemd service.
/// `RUST_LOG` (or `CARDINAL_LOG`) sets the filter; the default is `info`.
pub fn init_logging() {
    use tracing_subscriber::EnvFilter;
    let filter = std::env::var("CARDINAL_LOG")
        .ok()
        .or_else(|| std::env::var("RUST_LOG").ok())
        .unwrap_or_else(|| "info".into());
    // Under journald, timestamps are added by the journal.
    let journal = std::env::var_os("JOURNAL_STREAM").is_some();
    let b = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(filter))
        .with_writer(std::io::stderr)
        .with_target(false);
    if journal {
        let _ = b.without_time().with_ansi(false).try_init();
    } else {
        let _ = b.try_init();
    }
}

/// Settings given on the command line, overriding the saved ones.
#[derive(Clone, Debug, Default)]
pub struct Overrides {
    /// `--listen`.
    pub listen: Option<String>,
    /// `--mount`.
    pub mount: Option<std::path::PathBuf>,
    /// `--no-mount`.
    pub no_mount: bool,
    /// `--no-discovery`.
    pub no_discovery: bool,
    /// `--mdns-port`.
    pub mdns_port: Option<u16>,
    /// `--name`.
    pub name: Option<String>,
}

/// Runs the daemon until it is stopped.
pub async fn run(paths: Paths, o: Overrides) -> anyhow::Result<()> {
    std::fs::create_dir_all(&paths.home)?;
    let mut config = Config::load(&paths.config())?;
    let mut changed = Config::load(&paths.config()).is_ok()
        && !std::fs::read_to_string(paths.config()).is_ok_and(|t| t.contains("[daemon]"));
    if let Some(l) = o.listen {
        changed |= config.listen != l;
        config.listen = l;
    }
    if let Some(m) = o.mount {
        changed |= config.mount.as_ref() != Some(&m);
        config.mount = Some(m);
    }
    if let Some(n) = o.name {
        changed |= config.name != n;
        config.name = n;
    }
    if let Some(p) = o.mdns_port {
        config.mdns_port = p;
    }
    if o.no_discovery {
        config.discovery = false;
    }
    if changed {
        config.save(&paths.config())?;
    }
    if o.no_mount {
        config.mount = None;
    }
    let d = Daemon::start(paths, config).await?;
    d.run().await
}
