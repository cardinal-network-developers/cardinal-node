//! Where things live on disk.
//!
//! - Data: `$CARDINAL_HOME`, else `$XDG_DATA_HOME/cardinal`, else
//!   `~/.local/share/cardinal`.
//! - Control socket: `$CARDINAL_SOCKET`, else
//!   `$XDG_RUNTIME_DIR/cardinal.sock` for the default data directory and
//!   `$XDG_RUNTIME_DIR/cardinal-<name>.sock` when `CARDINAL_HOME` is set
//!   (so two devices can run on one machine), else `<data>/control.sock`.

use std::path::{Path, PathBuf};

/// The paths of one device's data.
#[derive(Clone, Debug)]
pub struct Paths {
    /// The data directory.
    pub home: PathBuf,
    /// The control socket.
    pub socket: PathBuf,
}

fn user_home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

impl Paths {
    /// Paths from the environment.
    pub fn from_env() -> Paths {
        let custom = std::env::var_os("CARDINAL_HOME").map(PathBuf::from);
        let home = custom.clone().unwrap_or_else(|| {
            std::env::var_os("XDG_DATA_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| user_home().join(".local/share"))
                .join("cardinal")
        });
        let home = absolute(&home);
        let socket = if let Some(s) = std::env::var_os("CARDINAL_SOCKET") {
            PathBuf::from(s)
        } else if let Some(run) = std::env::var_os("XDG_RUNTIME_DIR") {
            let run = PathBuf::from(run);
            match &custom {
                None => run.join("cardinal.sock"),
                Some(_) => run.join(format!("cardinal-{}.sock", socket_name(&home))),
            }
        } else {
            home.join("control.sock")
        };
        Paths { home, socket }
    }

    /// Paths for a data directory, with the socket inside it (tests).
    pub fn at(home: &Path) -> Paths {
        let home = absolute(home);
        Paths {
            socket: home.join("control.sock"),
            home,
        }
    }

    /// The device's private keys.
    pub fn device_key(&self) -> PathBuf {
        self.home.join("device.key")
    }
    /// Settings.
    pub fn config(&self) -> PathBuf {
        self.home.join("config.json")
    }
    /// The identity log.
    pub fn identity_log(&self) -> PathBuf {
        self.home.join("identity.log")
    }
    /// One directory per space.
    pub fn spaces(&self) -> PathBuf {
        self.home.join("spaces")
    }
    /// The chunk and index store.
    pub fn blobs(&self) -> PathBuf {
        self.home.join("blobs")
    }
    /// Files being written, before they become blobs.
    pub fn staging(&self) -> PathBuf {
        self.home.join("staging")
    }
    /// Link counters.
    pub fn link_state(&self) -> PathBuf {
        self.home.join("link.json")
    }
    /// Known addresses of this person's devices.
    pub fn peers(&self) -> PathBuf {
        self.home.join("peers.json")
    }
}

fn absolute(p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|d| d.join(p))
            .unwrap_or_else(|_| p.to_path_buf())
    }
}

/// `<last path component>-<4 hex digits of a hash of the path>`.
fn socket_name(home: &Path) -> String {
    let base: String = home
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(24)
        .collect();
    let h = blake3::hash(home.as_os_str().as_encoded_bytes());
    format!("{}-{}", base, hex::encode(&h.as_bytes()[..2]))
}

/// The user's home directory.
pub fn home_dir() -> PathBuf {
    user_home()
}

/// Writes `bytes` to `path` atomically, with permissions `mode`.
pub fn write_private(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}
