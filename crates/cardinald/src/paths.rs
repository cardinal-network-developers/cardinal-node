//! Where things live on disk.
//!
//! - Data: `$CARDINAL_HOME`, else `$CARDINAL_DATA_DIR` (set by the
//!   systemd unit), else `$XDG_DATA_HOME/cardinal`, else
//!   `~/.local/share/cardinal`.
//! - Settings: `config.toml` (table `[daemon]`; `[update]` belongs to
//!   `cardinal-update`) in `$CARDINAL_HOME`, else `$CARDINAL_CONFIG_DIR`,
//!   else `$XDG_CONFIG_HOME/cardinal`, else `~/.config/cardinal`.
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
    /// The configuration directory (holds `config.toml`).
    pub config_dir: PathBuf,
    /// The control socket.
    pub socket: PathBuf,
}

fn user_home() -> PathBuf {
    let home = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(home)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

/// Where a person's programs keep their data.
fn user_data() -> PathBuf {
    match std::env::var_os("LOCALAPPDATA") {
        Some(d) if cfg!(windows) => PathBuf::from(d),
        _ => user_home().join(".local/share"),
    }
}

impl Paths {
    /// Paths from the environment.
    pub fn from_env() -> Paths {
        let custom = std::env::var_os("CARDINAL_HOME")
            .filter(|h| !h.is_empty())
            .map(PathBuf::from);
        let deploy = cardinal_update::Paths::from_env().ok();
        let env_dir = |v: &str| {
            std::env::var_os(v)
                .filter(|h| !h.is_empty())
                .map(PathBuf::from)
        };
        let home = custom
            .clone()
            .or_else(|| env_dir("CARDINAL_DATA_DIR"))
            .unwrap_or_else(|| {
                deploy
                    .as_ref()
                    .map(|p| p.data_dir.clone())
                    .unwrap_or_else(|| user_data().join("cardinal"))
            });
        // The directory by its one true name, so that whatever is derived
        // from it, the socket's name above all, is the same however the
        // directory was named this time: with a trailing slash, from
        // another place, or through a link.
        let home = canonical(&absolute(&home));
        let config_dir = match &custom {
            Some(_) => home.clone(),
            None => env_dir("CARDINAL_CONFIG_DIR").unwrap_or_else(|| {
                deploy
                    .as_ref()
                    .map(|p| p.config_dir.clone())
                    .unwrap_or_else(|| user_home().join(".config/cardinal"))
            }),
        };
        let config_dir = absolute(&config_dir);
        let socket = if let Some(s) = std::env::var_os("CARDINAL_SOCKET") {
            PathBuf::from(s)
        } else if cfg!(windows) {
            PathBuf::from(format!(r"\\.\pipe\cardinal-{}", socket_name(&home)))
        } else if let Some(run) = std::env::var_os("XDG_RUNTIME_DIR") {
            let run = PathBuf::from(run);
            match &custom {
                None => run.join("cardinal.sock"),
                Some(_) => run.join(format!("cardinal-{}.sock", socket_name(&home))),
            }
        } else {
            home.join("control.sock")
        };
        Paths {
            home,
            config_dir,
            socket,
        }
    }

    /// Paths for a data directory, with the socket inside it (tests).
    pub fn at(home: &Path) -> Paths {
        let home = absolute(home);
        Paths {
            socket: home.join("control.sock"),
            config_dir: home.clone(),
            home,
        }
    }

    /// The device's private keys.
    pub fn device_key(&self) -> PathBuf {
        self.home.join("device.key")
    }
    /// Settings, shared with `cardinal-update`.
    pub fn config(&self) -> PathBuf {
        self.config_dir.join("config.toml")
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
    /// What `.cardinalignore` keeps on this device only (`fs/local.rs`).
    pub fn local(&self) -> PathBuf {
        self.home.join("local")
    }
    /// Link counters.
    pub fn link_state(&self) -> PathBuf {
        self.home.join("link.json")
    }
    /// Other people's identity logs.
    pub fn others(&self) -> PathBuf {
        self.home.join("others")
    }
    /// What this device, as a host, holds for its owner.
    pub fn mailbox(&self) -> PathBuf {
        self.home.join("mailbox")
    }
    /// Known addresses of this person's devices.
    /// When this person last turned to each contact (`sync.md#neighbours`).
    pub fn in_use(&self) -> PathBuf {
        self.home.join("in-use.json")
    }

    pub fn peers(&self) -> PathBuf {
        self.home.join("peers.json")
    }
    /// What copy checks saw of this person's devices.
    pub fn copies(&self) -> PathBuf {
        self.home.join("copies.json")
    }
    /// When old versions stopped being current (`cleanup.rs`).
    pub fn old_versions(&self) -> PathBuf {
        self.home.join("old-versions.json")
    }
    /// Contacts' pictures, as files windows can open (`names.rs`).
    pub fn pictures(&self) -> PathBuf {
        self.home.join("pictures")
    }
}

/// A path with links resolved and nothing redundant in it, as far as it
/// exists: what does not exist yet is kept as named, under the true name
/// of what does.
fn canonical(p: &Path) -> PathBuf {
    if let Ok(c) = std::fs::canonicalize(p) {
        return plain(c);
    }
    match (p.parent(), p.file_name()) {
        (Some(up), Some(name)) => canonical(up).join(name),
        // ends in `..` or is a root: nothing better to say
        _ => p.to_path_buf(),
    }
}

/// The name other programs understand. On Windows `canonicalize` gives the
/// extended form, `\\?\C:\...`, which many cannot use (a .NET `Uri` among
/// them), and every path the service hands a window starts from this one.
/// Rust adds the extended form itself where a path is too long without it.
fn plain(c: PathBuf) -> PathBuf {
    #[cfg(windows)]
    {
        use std::path::{Component, Prefix};
        if let Some(Component::Prefix(p)) = c.components().next() {
            let s = c.to_string_lossy();
            match p.kind() {
                Prefix::VerbatimDisk(_) => return PathBuf::from(&s[4..]),
                Prefix::VerbatimUNC(..) => return PathBuf::from(format!(r"\\{}", &s[8..])),
                _ => {}
            }
        }
    }
    c
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
    let tmp = path.with_extension("tmp");
    {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, mode);
        #[cfg(not(unix))]
        let _ = mode;
        let mut f = options.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// D4. What is derived from the data directory's path, the socket's
    /// name above all, is the same however the directory is named.
    #[test]
    fn a_directory_has_one_name_however_it_is_given() {
        let dir = tempfile::tempdir().unwrap();
        let real = std::fs::canonicalize(dir.path()).unwrap().join("dev1");
        std::fs::create_dir_all(&real).unwrap();
        let slash = PathBuf::from(format!("{}/", real.display()));
        let dotted = real.parent().unwrap().join("./dev1/.");
        let around = real.join("../dev1");
        for named in [&slash, &dotted, &around] {
            assert_ne!(named.as_os_str(), real.as_os_str());
            assert_eq!(canonical(named), real, "{named:?}");
            assert_eq!(socket_name(&canonical(named)), socket_name(&real));
        }
        #[cfg(unix)]
        {
            let link = real.parent().unwrap().join("link");
            std::os::unix::fs::symlink(&real, &link).unwrap();
            assert_eq!(canonical(&link), real);
        }
        // What is not there yet keeps its name, under the true name of
        // what is: a service names its socket before it makes the
        // directory, and a command after.
        let new = PathBuf::from(format!("{}/new/", slash.display()));
        assert_eq!(canonical(&new), real.join("new"));
        std::fs::create_dir_all(real.join("new")).unwrap();
        assert_eq!(canonical(&new), real.join("new"));
    }
}
