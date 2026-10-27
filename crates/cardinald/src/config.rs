//! Local settings (`config.json` in the data directory). Everything a
//! person's other devices need to know lives in the account space instead;
//! this file holds only what is about this one device.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::paths::write_private;

/// Default TCP port of the link endpoint.
pub const DEFAULT_PORT: u16 = 7171;

/// Default budget for on-demand retention: 2 GiB.
pub const DEFAULT_ON_DEMAND_BUDGET: u64 = 2 << 30;

/// Device settings.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// This device's name, shown on the person's other devices.
    pub name: String,
    /// Where the link endpoint listens (TCP).
    pub listen: String,
    /// Also listen on UDP (experimental: no congestion control yet).
    pub udp: bool,
    /// Where the files space is mounted; `None` to not mount.
    pub mount: Option<PathBuf>,
    /// `full` or `on-demand`.
    pub retention: String,
    /// The most bytes on-demand retention keeps of files not pinned.
    pub on_demand_budget: u64,
    /// Addresses (`host:port`) of devices reached over the internet.
    pub peers: Vec<String>,
    /// Paths (inside the mount) kept local under on-demand retention.
    pub pins: Vec<String>,
    /// LAN discovery by multicast DNS.
    pub discovery: bool,
    /// The multicast DNS port (5353; tests use another).
    pub mdns_port: u16,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            name: default_name(),
            listen: format!("0.0.0.0:{DEFAULT_PORT}"),
            udp: false,
            mount: Some(crate::paths::home_dir().join("Cardinal")),
            retention: "full".into(),
            on_demand_budget: DEFAULT_ON_DEMAND_BUDGET,
            peers: Vec::new(),
            pins: Vec::new(),
            discovery: true,
            mdns_port: 5353,
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

impl Config {
    /// Loads the settings, or the defaults if there are none.
    pub fn load(path: &Path) -> anyhow::Result<Config> {
        match std::fs::read(path) {
            Ok(b) => Ok(serde_json::from_slice(&b)
                .map_err(|e| anyhow::anyhow!("{} is not valid: {e}", path.display()))?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Saves the settings.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let b = serde_json::to_vec_pretty(self)?;
        write_private(path, &b, 0o600)?;
        Ok(())
    }

    /// Whether retention is on demand.
    pub fn on_demand(&self) -> bool {
        self.retention == "on-demand"
    }
}
