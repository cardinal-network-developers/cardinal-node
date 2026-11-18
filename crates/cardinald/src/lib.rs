//! The Cardinal daemon (`cardinal daemon`): it holds this device's keys,
//! identity log, spaces, and content store; keeps link sessions with the
//! person's other devices and syncs with them; mounts the files space as
//! a folder; and answers the `cardinal` command on a local socket.
//!
//! See `README.md` in this crate for the design.

pub mod applog;
pub mod calls;
pub mod cleanup;
pub mod clear;
pub mod conditions;
pub mod config;
pub mod contacts;
pub mod control;
pub mod copies;
pub mod core;
pub mod daemon;
pub mod directory;
pub mod fetch;
pub mod format;
pub mod fs;
pub mod fsat;
pub mod groups;
pub mod host;
pub mod introductions;
pub mod keys;
pub mod lock;
pub mod mailbox;
pub mod mesh;
pub mod names;
pub mod net;
pub mod news;
pub mod onefolder;
pub mod pair;
pub mod paths;
pub mod recovery;
pub mod rendezvous;
pub mod sched;
pub mod setup;
pub mod speedtest;
pub mod transport;

/// What tests in several modules set up alike.
#[cfg(test)]
pub(crate) mod testing {
    use crate::config::Config;
    use crate::paths::Paths;

    /// A device set up in `dir` as `cardinal init` leaves it, and the
    /// settings for a service on it that listens on a port of its own
    /// and does nothing else by itself: start it with `Daemon::start`.
    pub fn set_up(dir: &std::path::Path) -> (Paths, Config) {
        let paths = Paths::at(dir);
        let mut config = Config {
            listen: "127.0.0.1:0".into(),
            ..Default::default()
        };
        config.this_run.no_mount = true;
        config.this_run.no_discovery = true;
        config.this_run.no_udp = true;
        let p = crate::setup::prepare(&paths).unwrap();
        crate::setup::install(&paths, p, &config, "Me").unwrap();
        (paths, config)
    }
}

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
    /// `--no-udp`.
    pub no_udp: bool,
    /// `--mdns-port`.
    pub mdns_port: Option<u16>,
    /// `--name`.
    pub name: Option<String>,
}

/// Runs the daemon until it is stopped.
pub async fn run(paths: Paths, o: Overrides) -> anyhow::Result<()> {
    // Tests: let a debugger attach to a daemon that hangs (Yama allows only
    // ancestors otherwise).
    #[cfg(target_os = "linux")]
    if std::env::var_os("CARDINAL_TEST_PTRACE").is_some() {
        // SAFETY: prctl with these arguments only changes who may trace us.
        unsafe { libc::prctl(libc::PR_SET_PTRACER, libc::PR_SET_PTRACER_ANY, 0, 0, 0) };
    }
    // The directory is taken before anything in it is read or written:
    // a service that is refused because one runs there already must not
    // have saved its settings over that one's (S9).
    let lock = Daemon::take(&paths)?;
    // A store written under other rules is refused before anything in it
    // is read or written.
    format::check(&paths)?;
    let mut config = Config::load(&paths.config())?;
    let mut changed = Config::load(&paths.config()).is_ok()
        && !std::fs::read_to_string(paths.config()).is_ok_and(|t| t.contains("[daemon]"));
    if let Some(l) = o.listen {
        changed |= config.listen != l;
        config.listen = l;
        config.this_run.listen_given = true;
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
        config.this_run.mdns_port = Some(p);
    }
    if o.no_udp {
        config.this_run.no_udp = true;
    }
    if o.no_discovery {
        config.this_run.no_discovery = true;
    }
    if changed {
        config.save(&paths.config())?;
    }
    if o.no_mount {
        config.this_run.no_mount = true;
    }
    let d = Daemon::start_holding(paths, config, lock).await?;
    d.run().await
}
