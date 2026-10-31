//! Local settings: the `[daemon]` table of `config.toml`, which is shared
//! with `cardinal-update` (it owns `[update]`; other tables are kept as
//! they are when saving). Everything a person's other devices need to know
//! lives in the account space instead; this holds only what is about this
//! one device.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::paths::write_private;

/// Default TCP port of the link endpoint.
pub const DEFAULT_PORT: u16 = 7171;

/// Default budget for on-demand retention: 2 GiB.
pub const DEFAULT_ON_DEMAND_BUDGET: u64 = 2 << 30;

/// Settings from the command line for this run only. They are never saved,
/// and last when the file is read again.
#[derive(Clone, Debug, Default)]
pub struct ThisRun {
    /// `--no-mount`.
    pub no_mount: bool,
    /// `--no-discovery`.
    pub no_discovery: bool,
    /// `--mdns-port`.
    pub mdns_port: Option<u16>,
}

/// Device settings.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// What this run was told on the command line.
    #[serde(skip)]
    pub this_run: ThisRun,
    /// This device's name, shown on the person's other devices.
    pub name: String,
    /// Where the link endpoint listens (TCP).
    pub listen: String,
    /// Also listen on UDP (experimental: no congestion control yet).
    pub udp: bool,
    /// Where the files space is mounted; `None` (written as `""`) to not
    /// mount.
    #[serde(with = "opt_path")]
    pub mount: Option<PathBuf>,
    /// `full` or `on-demand`.
    pub retention: String,
    /// The most bytes on-demand retention keeps of files not pinned.
    pub on_demand_budget: u64,
    /// How long deleted files and old versions are kept after they stop
    /// being current: a number of days, or `forever` (`cleanup.rs`).
    pub keep_old: String,
    /// Addresses (`host:port`) of devices reached over the internet.
    pub peers: Vec<String>,
    /// Paths (inside the mount) kept local under on-demand retention.
    pub pins: Vec<String>,
    /// LAN discovery by multicast DNS.
    pub discovery: bool,
    /// The multicast DNS port (5353; tests use another).
    pub mdns_port: u16,
    /// This device is a host for its own identity (`host.rs`).
    pub host: bool,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            name: default_name(),
            listen: format!("0.0.0.0:{DEFAULT_PORT}"),
            udp: false,
            this_run: ThisRun::default(),
            mount: Some(crate::paths::home_dir().join("Cardinal")),
            retention: "full".into(),
            on_demand_budget: DEFAULT_ON_DEMAND_BUDGET,
            keep_old: "30 days".into(),
            peers: Vec::new(),
            pins: Vec::new(),
            discovery: true,
            mdns_port: 5353,
            host: false,
        }
    }
}

/// The machine's host name, as a default device name.
pub fn default_name() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "this device".into())
}

mod opt_path {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::path::PathBuf;

    pub fn serialize<S: Serializer>(p: &Option<PathBuf>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(
            &p.as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
        )
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<PathBuf>, D::Error> {
        let s = String::deserialize(d)?;
        Ok(if s.is_empty() {
            None
        } else {
            Some(PathBuf::from(s))
        })
    }
}

fn read_table(path: &Path) -> anyhow::Result<toml::Table> {
    match std::fs::read_to_string(path) {
        Ok(t) => t
            .parse::<toml::Table>()
            .map_err(|e| anyhow::anyhow!("{} is not valid TOML: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(toml::Table::new()),
        Err(e) => Err(e.into()),
    }
}

impl Config {
    /// Loads the settings, or the defaults if there are none.
    pub fn load(path: &Path) -> anyhow::Result<Config> {
        let t = read_table(path)?;
        match t.get("daemon") {
            Some(v) => v
                .clone()
                .try_into()
                .map_err(|e| anyhow::anyhow!("[daemon] in {} is not valid: {e}", path.display())),
            None => Ok(Config::default()),
        }
    }

    /// Saves the settings into `[daemon]`, keeping the other tables and
    /// their comments.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(e.into()),
        };
        let mut doc: toml_edit::DocumentMut = text
            .parse()
            .map_err(|e| anyhow::anyhow!("{} is not valid TOML: {e}", path.display()))?;
        let mine: toml_edit::DocumentMut = toml::to_string(self)?.parse()?;
        let mut table = mine.as_table().clone();
        table.set_implicit(false);
        doc["daemon"] = toml_edit::Item::Table(table);
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d)?;
        }
        write_private(path, doc.to_string().as_bytes(), 0o600)?;
        Ok(())
    }

    /// Where to mount on this run, if at all.
    pub fn mount_here(&self) -> Option<&PathBuf> {
        self.mount.as_ref().filter(|_| !self.this_run.no_mount)
    }

    /// Whether to look for devices on the local network on this run.
    pub fn discovers(&self) -> bool {
        self.discovery && !self.this_run.no_discovery
    }

    /// The multicast DNS port on this run.
    pub fn mdns(&self) -> u16 {
        self.this_run.mdns_port.unwrap_or(self.mdns_port)
    }

    /// Whether retention is on demand.
    pub fn on_demand(&self) -> bool {
        self.retention == "on-demand"
    }
}
