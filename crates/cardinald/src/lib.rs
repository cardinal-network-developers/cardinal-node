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
pub mod clipboard;
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
pub mod outside;
pub mod pair;
pub mod paths;
pub mod portmap;
pub mod recovery;
pub mod rendezvous;
pub mod sched;
pub mod setup;
pub mod speedtest;
pub mod transport;
pub mod upnp;

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
/// `CARDINAL_LOG_FILE` names a file to append to instead, for a service a
/// window starts where nothing collects what it says (Windows): the one
/// before is kept beside it, `.old`, once it passes a mebibyte.
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
    if let Some(file) = std::env::var_os("CARDINAL_LOG_FILE").and_then(|p| log_file(p.as_ref())) {
        let _ = b
            .with_ansi(false)
            .with_writer(std::sync::Mutex::new(file))
            .try_init();
    } else if journal {
        let _ = b.without_time().with_ansi(false).try_init();
    } else {
        let _ = b.try_init();
    }
}

/// The log file at `path`, appended to; moved aside to `.old` whenever it
/// passes a mebibyte, at start or while running.
fn log_file(path: &std::path::Path) -> Option<LogFile> {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let mut log = LogFile {
        path: path.to_owned(),
        file: None,
        written: 0,
        look_at: 0,
    };
    log.open();
    log.file.is_some().then_some(log)
}

/// A log file that keeps itself to about a mebibyte, with one before it.
struct LogFile {
    path: std::path::PathBuf,
    file: Option<std::fs::File>,
    /// What is in it, or was offered to it while it could not be opened.
    written: u64,
    /// When it is looked at again.
    look_at: u64,
}

impl LogFile {
    const KEEP: u64 = 1 << 20;
    const AGAIN: u64 = 64 << 10;

    fn open(&mut self) {
        let size = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        if size > Self::KEEP {
            self.file = None;
            let mut old = self.path.as_os_str().to_owned();
            old.push(".old");
            let _ = std::fs::rename(&self.path, old);
        }
        self.file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .ok();
        self.written = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        // Past a mebibyte it is moved aside. A file that could not be
        // opened, or moved aside (on Windows another program may hold it),
        // is tried again after a little more, not on every line.
        self.look_at = if self.file.is_none() || self.written > Self::KEEP {
            self.written + Self::AGAIN
        } else {
            Self::KEEP + 1
        };
    }
}

impl std::io::Write for LogFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.written >= self.look_at {
            self.open();
        }
        let Some(f) = self.file.as_mut() else {
            self.written += buf.len() as u64;
            return Ok(buf.len());
        };
        let n = f.write(buf)?;
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.as_mut().map_or(Ok(()), |f| f.flush())
    }
}

#[cfg(test)]
mod log_tests {
    use std::io::Write;

    #[test]
    fn a_log_that_could_not_be_opened_is_tried_again() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("logs").join("service.log");
        let mut log = super::LogFile {
            path: path.clone(),
            file: None,
            written: 0,
            look_at: 0,
        };
        // The folder is not there yet: nothing can be opened.
        log.write_all(b"lost\n").unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        for _ in 0..100 {
            log.write_all(&[b'y'; 1000]).unwrap();
        }
        assert!(
            std::fs::metadata(&path).is_ok_and(|m| m.len() > 0),
            "opened once it could be"
        );
    }

    #[test]
    fn a_long_running_log_is_moved_aside_and_begun_again() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("service.log");
        let mut log = super::log_file(&path).unwrap();
        let line = [b'x'; 1000];
        for _ in 0..2200 {
            log.write_all(&line).unwrap();
        }
        let now = std::fs::metadata(&path).unwrap().len();
        let old = std::fs::metadata(dir.path().join("service.log.old"))
            .unwrap()
            .len();
        assert!(now <= (1 << 20) + 1000, "{now}");
        assert!(old > 1 << 20, "{old}");
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
