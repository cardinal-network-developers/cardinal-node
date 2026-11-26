//! Whether this device can help others now (`profiles.md#calls`): it helps
//! when it is plugged in and its network is not metered. Nothing else about
//! a device decides it: not what kind it is, nor whether it is always on.
//!
//! A client that knows better says so (`conditions` on the local
//! interface). Otherwise Linux reads its power supplies, and takes no
//! network to be metered. Android says nothing until its app does, since a
//! phone is usually on battery. Elsewhere a device helps until told not to.

use std::sync::Mutex;

/// What a client said.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Told {
    pub plugged_in: bool,
    pub metered: bool,
}

#[derive(Default)]
pub struct Conditions {
    told: Mutex<Option<Told>>,
    /// What the system said lately, and when: reading a battery can take a
    /// while, and the answer is asked for often.
    read: Mutex<Option<(std::time::Instant, Option<bool>)>>,
}

/// How long what the system said is good for.
const READ_FOR: std::time::Duration = std::time::Duration::from_secs(10);

impl Conditions {
    pub fn tell(&self, t: Told) {
        *self.told.lock().unwrap_or_else(|e| e.into_inner()) = Some(t);
    }

    /// Whether it is plugged in, if known, and whether metered.
    pub fn now(&self) -> (Option<bool>, bool) {
        let told = *self.told.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(t) = told {
            return (Some(t.plugged_in), t.metered);
        }
        let mut read = self.read.lock().unwrap_or_else(|e| e.into_inner());
        match *read {
            Some((at, plugged_in)) if at.elapsed() < READ_FOR => (plugged_in, false),
            _ => {
                let plugged_in = plugged_in_here();
                *read = Some((std::time::Instant::now(), plugged_in));
                (plugged_in, false)
            }
        }
    }

    /// Whether this device helps others: carries their calls.
    pub fn helps(&self) -> bool {
        let (plugged_in, metered) = self.now();
        plugged_in == Some(true) && !metered
    }

    /// What `conditions` answers.
    pub fn reply(&self) -> crate::api::ConditionsReply {
        let (plugged_in, metered) = self.now();
        crate::api::ConditionsReply {
            plugged_in,
            metered,
            helps: self.helps(),
        }
    }

    pub fn json(&self) -> serde_json::Value {
        let (plugged_in, metered) = self.now();
        serde_json::json!({
            "plugged_in": plugged_in,
            "metered": metered,
            "helps": self.helps(),
        })
    }
}

/// Where Linux lists what powers it. A test on a laptop must not depend on
/// whether it is plugged in, and says somewhere else.
#[cfg(target_os = "linux")]
fn plugged_in_here() -> Option<bool> {
    let dir = std::env::var_os("CARDINAL_TEST_POWER_SUPPLIES").map_or_else(
        || "/sys/class/power_supply".into(),
        std::path::PathBuf::from,
    );
    plugged_in_from(&dir)
}

#[cfg(target_os = "android")]
fn plugged_in_here() -> Option<bool> {
    None
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn plugged_in_here() -> Option<bool> {
    Some(true)
}

/// From the kernel's power supplies: plugged in when any supply that is not
/// a battery is online, or a battery says it is charging or full. A machine
/// with no battery at all runs on mains.
#[cfg(any(target_os = "linux", test))]
fn plugged_in_from(dir: &std::path::Path) -> Option<bool> {
    let read = |p: std::path::PathBuf| {
        std::fs::read_to_string(p)
            .map(|s| s.trim().to_owned())
            .unwrap_or_default()
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Some(true);
    };
    let mut battery = false;
    for e in entries.flatten() {
        let p = e.path();
        match read(p.join("type")).as_str() {
            "Battery" => {
                battery = true;
                if matches!(
                    read(p.join("status")).as_str(),
                    "Charging" | "Full" | "Not charging"
                ) {
                    return Some(true);
                }
            }
            _ => {
                if read(p.join("online")) == "1" {
                    return Some(true);
                }
            }
        }
    }
    Some(!battery)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn supply(dir: &std::path::Path, name: &str, files: &[(&str, &str)]) {
        let d = dir.join(name);
        std::fs::create_dir_all(&d).unwrap();
        for (f, v) in files {
            std::fs::write(d.join(f), format!("{v}\n")).unwrap();
        }
    }

    #[test]
    fn power_supplies_say_whether_plugged_in() {
        let none = tempfile::tempdir().unwrap();
        assert_eq!(plugged_in_from(none.path()), Some(true), "no battery");
        let nowhere = std::path::Path::new("/nothing/here");
        assert_eq!(plugged_in_from(nowhere), Some(true));
        let laptop = tempfile::tempdir().unwrap();
        supply(laptop.path(), "AC", &[("type", "Mains"), ("online", "0")]);
        supply(
            laptop.path(),
            "BAT0",
            &[("type", "Battery"), ("status", "Discharging")],
        );
        assert_eq!(plugged_in_from(laptop.path()), Some(false));
        supply(laptop.path(), "AC", &[("type", "Mains"), ("online", "1")]);
        assert_eq!(plugged_in_from(laptop.path()), Some(true));
        supply(laptop.path(), "AC", &[("type", "Mains"), ("online", "0")]);
        supply(laptop.path(), "usb-c", &[("type", "USB"), ("online", "1")]);
        assert_eq!(
            plugged_in_from(laptop.path()),
            Some(true),
            "charging over USB"
        );
        supply(laptop.path(), "usb-c", &[("type", "USB"), ("online", "0")]);
        supply(
            laptop.path(),
            "BAT0",
            &[("type", "Battery"), ("status", "Full")],
        );
        assert_eq!(plugged_in_from(laptop.path()), Some(true));
    }

    #[test]
    fn a_client_saying_so_decides() {
        let c = Conditions::default();
        c.tell(Told {
            plugged_in: true,
            metered: true,
        });
        assert!(!c.helps(), "metered");
        c.tell(Told {
            plugged_in: true,
            metered: false,
        });
        assert!(c.helps());
    }
}
