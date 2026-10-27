//! Where an installation lives, following the XDG base directory
//! specification.

use std::env;
use std::path::{Path, PathBuf};

/// The service unit's name.
pub const UNIT_NAME: &str = "cardinal.service";

/// Every location the installer reads or writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    /// Directory holding the binary (`~/.local/bin`, or `$XDG_BIN_HOME`).
    pub bin_dir: PathBuf,
    /// Local data: stores, keys (`$XDG_DATA_HOME/cardinal`).
    pub data_dir: PathBuf,
    /// Configuration (`$XDG_CONFIG_HOME/cardinal`).
    pub config_dir: PathBuf,
    /// systemd user units (`$XDG_CONFIG_HOME/systemd/user`).
    pub unit_dir: PathBuf,
    /// Default source for development builds
    /// (`$XDG_DATA_HOME/cardinal-dev-releases`).
    pub dev_releases: PathBuf,
}

impl Paths {
    /// Locations for the current user, from `HOME` and the `XDG_*`
    /// variables. Relative XDG values are ignored, as the specification
    /// requires.
    pub fn from_env() -> anyhow::Result<Paths> {
        let home = env::var_os("HOME")
            .filter(|h| !h.is_empty())
            .map(PathBuf::from)
            .ok_or_else(|| anyhow::anyhow!("HOME is not set"))?;
        let xdg = |var: &str, default: &str| {
            env::var_os(var)
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .unwrap_or_else(|| home.join(default))
        };
        let data = xdg("XDG_DATA_HOME", ".local/share");
        let config = xdg("XDG_CONFIG_HOME", ".config");
        Ok(Paths::new(
            xdg("XDG_BIN_HOME", ".local/bin"),
            &data,
            &config,
        ))
    }

    /// Locations from explicit base directories (for tests).
    pub fn new(bin_dir: impl Into<PathBuf>, data_home: &Path, config_home: &Path) -> Paths {
        Paths {
            bin_dir: bin_dir.into(),
            data_dir: data_home.join("cardinal"),
            config_dir: config_home.join("cardinal"),
            unit_dir: config_home.join("systemd/user"),
            dev_releases: data_home.join("cardinal-dev-releases"),
        }
    }

    /// The installed binary.
    pub fn bin(&self) -> PathBuf {
        self.bin_dir.join("cardinal")
    }

    /// The binary kept from before the last update, for rollback.
    pub fn previous_bin(&self) -> PathBuf {
        self.bin_dir.join("cardinal.previous")
    }

    /// The configuration file.
    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("config.toml")
    }

    /// The systemd user unit.
    pub fn unit_file(&self) -> PathBuf {
        self.unit_dir.join(UNIT_NAME)
    }
}
