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
    /// `--no-udp`.
    pub no_udp: bool,
    /// `--listen`: this run must have that port, or not run.
    pub listen_given: bool,
    /// The port this device had, when it was taken at start and the device
    /// moved to another.
    pub moved_from: Option<u16>,
    /// Addresses given for this device that still name the port it left,
    /// and cannot be made to follow it: a router's forward.
    pub left_behind: Vec<String>,
    /// This is a recovery helper's service, run inside a new device's for
    /// as long as a recovery through guardians is under way
    /// (`helper.rs`): no control socket, no mount, no discovery, no port
    /// mapping, no looking for releases.
    pub helper: bool,
    /// This is the service of a guardian's persona, run inside the
    /// guardian's device's for as long as the persona is not burned
    /// (`helper.rs`), with the same things left out.
    pub guardian_persona: bool,
}

impl ThisRun {
    /// Whether this is a persona's service run inside another's.
    pub fn inside(&self) -> bool {
        self.helper || self.guardian_persona
    }
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
    /// Do not listen on UDP. This replaced a `udp` setting that was false
    /// by default and written out by every save, so that setting is ignored.
    pub tcp_only: bool,
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
    /// Ask the router for a port, by PCP or NAT-PMP (`portmap.rs`).
    pub port_mapping: bool,
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
            tcp_only: false,
            this_run: ThisRun::default(),
            mount: Some(crate::paths::home_dir().join("Cardinal")),
            retention: "full".into(),
            on_demand_budget: DEFAULT_ON_DEMAND_BUDGET,
            keep_old: "30 days".into(),
            peers: Vec::new(),
            pins: Vec::new(),
            discovery: true,
            port_mapping: true,
            mdns_port: 5353,
            host: false,
        }
    }
}

/// The machine's name, as a default device name: Linux keeps it in
/// /etc/hostname, Windows in COMPUTERNAME. The person can rename the device.
pub fn default_name() -> String {
    pick_name(
        std::fs::read_to_string("/etc/hostname").ok(),
        std::env::var("COMPUTERNAME").ok(),
    )
}

fn pick_name(hostname: Option<String>, computer_name: Option<String>) -> String {
    [hostname, computer_name]
        .into_iter()
        .flatten()
        .map(|s| s.trim().to_owned())
        .find(|s| !s.is_empty())
        .unwrap_or_else(|| "this device".into())
}

/// A name for the person, where they were not asked for one: the full name
/// their login has on this machine, or else the login itself, or else the
/// machine's name. Only a default: the person changes it with `me`.
pub fn default_person() -> String {
    let login = ["USER", "USERNAME", "LOGNAME"]
        .iter()
        .filter_map(|v| std::env::var(v).ok())
        .map(|s| s.trim().to_owned())
        .find(|s| !s.is_empty());
    let passwd = std::fs::read_to_string("/etc/passwd").ok();
    pick_person(login, passwd.as_deref()).unwrap_or_else(default_name)
}

fn pick_person(login: Option<String>, passwd: Option<&str>) -> Option<String> {
    let login = login?;
    // name:x:uid:gid:Full Name,room,phone:home:shell
    let full = passwd.and_then(|p| {
        p.lines()
            .map(|l| l.split(':').collect::<Vec<_>>())
            .find(|f| f.len() > 4 && f[0] == login)
            .map(|f| f[4].split(',').next().unwrap_or("").trim().to_owned())
    });
    Some(full.filter(|f| !f.is_empty()).unwrap_or(login))
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

    /// Whether to listen on UDP on this run.
    pub fn uses_udp(&self) -> bool {
        !self.tcp_only && !self.this_run.no_udp
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Linux names the machine in /etc/hostname, Windows in COMPUTERNAME;
    /// "this device" is the last resort, since it means nothing on the
    /// person's other devices.
    #[test]
    fn a_device_is_named_after_its_machine() {
        let s = |t: &str| Some(t.to_owned());
        assert_eq!(pick_name(s("laptop\n"), s("DESK")), "laptop");
        assert_eq!(pick_name(None, s("DESK")), "DESK");
        assert_eq!(pick_name(s(" \n"), s(" DESK ")), "DESK");
        assert_eq!(pick_name(None, s("")), "this device");
        assert_eq!(pick_name(None, None), "this device");
    }

    /// A person not asked for their name is given their login's full
    /// name, or the login, never the machine's name while there is one.
    #[test]
    fn a_person_is_named_after_their_login() {
        let passwd = "root:x:0:0:root:/root:/bin/sh\nana:x:1000:1000:Ana Lima,,,:/home/ana:/bin/sh\nbo:x:1001:1001::/home/bo:/bin/sh\n";
        let s = |t: &str| Some(t.to_owned());
        assert_eq!(pick_person(s("ana"), Some(passwd)), s("Ana Lima"));
        assert_eq!(pick_person(s("bo"), Some(passwd)), s("bo"));
        assert_eq!(pick_person(s("cy"), None), s("cy"));
        assert_eq!(pick_person(None, Some(passwd)), None);
    }

    /// Every install before UDP worked has this line, from a save.
    #[test]
    fn an_old_config_does_not_turn_udp_off() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[daemon]\nname = \"old\"\nudp = false\n").unwrap();
        let c = Config::load(&path).unwrap();
        assert_eq!(c.name, "old");
        assert!(c.uses_udp());
        c.save(&path).unwrap();
        let saved = std::fs::read_to_string(&path).unwrap();
        assert!(!saved.contains("udp = false"), "{saved}");
        assert!(Config::load(&path).unwrap().uses_udp());
    }
}
