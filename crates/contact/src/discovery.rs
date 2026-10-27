//! Local discovery (`hosts.md#local-discovery`) and the pairing
//! advertisement (`contact.md#pairing`).
//!
//! A device advertises `_cardinal._udp` with TXT `t=` followed by hex of
//! `nonce (8) || first8(BLAKE3.keyed_hash(d, nonce))`, where
//! `d = derive("discovery", discovery secret)`. The nonce, and the instance
//! and host names, change on every refresh, so successive advertisements
//! cannot be linked and name nothing; only holders of the secret recognize
//! the tag.

use std::net::SocketAddr;
use std::time::Duration;

use cardinal_crypto::{ct_eq, derive, keyed_hash, random_bytes, Purpose};
use zeroize::Zeroizing;

use crate::mdns::{self, Advertiser, Browser, MdnsConfig, ServiceInfo};
use crate::ContactError;

/// The device discovery service type.
pub const DEVICE_SERVICE: &str = "_cardinal._udp";
/// The pairing service type.
pub const PAIR_SERVICE: &str = "_cardinal-pair._udp";

/// `d = derive("discovery", secret)`.
pub fn discovery_key(secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    derive(Purpose::Discovery, secret)
}

/// `t=` and hex of `nonce || first8(keyed_hash(d, nonce))`.
pub fn device_txt(d: &[u8; 32], nonce: [u8; 8]) -> String {
    let tag = keyed_hash(d, &nonce);
    let mut s = String::from("t=");
    for b in nonce.iter().chain(&tag[..8]) {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Whether a TXT string carries a tag made with `d`.
pub fn check_device_txt(d: &[u8; 32], txt: &str) -> bool {
    let Some(hex) = txt.strip_prefix("t=") else {
        return false;
    };
    if hex.len() != 32 {
        return false;
    }
    let mut bytes = [0u8; 16];
    for (i, b) in bytes.iter_mut().enumerate() {
        match u8::from_str_radix(&hex[2 * i..2 * i + 2], 16) {
            Ok(v) => *b = v,
            Err(_) => return false,
        }
    }
    let tag = keyed_hash(d, &bytes[..8]);
    ct_eq(&tag[..8], &bytes[8..])
}

fn random_label() -> String {
    random_bytes::<8>()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Advertises this device's link endpoint (UDP `port`) to holders of the
/// discovery secret, refreshing (and re-randomizing) every `refresh`.
pub fn advertise_device(
    cfg: MdnsConfig,
    secret: &[u8; 32],
    port: u16,
    refresh: Duration,
) -> std::io::Result<Advertiser> {
    let d = discovery_key(secret);
    mdns::advertise(cfg, refresh, move || ServiceInfo {
        service: DEVICE_SERVICE.into(),
        instance: random_label(),
        port,
        txt: vec![device_txt(&d, random_bytes())],
        host: random_label(),
        addrs: Vec::new(),
    })
}

/// A device found by discovery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredDevice {
    /// Its link endpoint (UDP).
    pub addr: SocketAddr,
    /// Which of the browsed secrets matched.
    pub secret_index: usize,
}

/// Browses for devices whose tags match one of `secrets`.
pub struct DeviceBrowser {
    inner: Browser,
    keys: Vec<Zeroizing<[u8; 32]>>,
}

impl DeviceBrowser {
    /// Starts browsing.
    pub fn start(
        cfg: MdnsConfig,
        secrets: &[[u8; 32]],
        requery: Duration,
    ) -> std::io::Result<DeviceBrowser> {
        Ok(DeviceBrowser {
            inner: mdns::browse(cfg, DEVICE_SERVICE, requery)?,
            keys: secrets.iter().map(discovery_key).collect(),
        })
    }

    /// The next recognized device. Advertisements whose tag matches no
    /// secret are skipped: to everyone else they are noise.
    pub async fn next(&mut self) -> Option<DiscoveredDevice> {
        loop {
            let f = self.inner.next().await?;
            for txt in &f.txt {
                if let Some(i) = self.keys.iter().position(|d| check_device_txt(d, txt)) {
                    return Some(DiscoveredDevice {
                        addr: f.addr,
                        secret_index: i,
                    });
                }
            }
        }
    }
}

/// Advertises a pairing socket: `_cardinal-pair._udp` with TXT
/// `c=<channel>`.
pub fn advertise_pairing(
    cfg: MdnsConfig,
    channel: u16,
    port: u16,
    refresh: Duration,
) -> std::io::Result<Advertiser> {
    let instance = random_label();
    let host = random_label();
    mdns::advertise(cfg, refresh, move || ServiceInfo {
        service: PAIR_SERVICE.into(),
        instance: instance.clone(),
        port,
        txt: vec![format!("c={channel}")],
        host: host.clone(),
        addrs: Vec::new(),
    })
}

/// Finds the pairing socket advertising `channel`.
pub async fn find_pairing(
    cfg: MdnsConfig,
    channel: u16,
    timeout: Duration,
) -> Result<SocketAddr, ContactError> {
    let mut b = mdns::browse(cfg, PAIR_SERVICE, Duration::from_millis(500))?;
    let want = format!("c={channel}");
    tokio::time::timeout(timeout, async {
        while let Some(f) = b.next().await {
            if f.txt.contains(&want) {
                return Ok(f.addr);
            }
        }
        Err(ContactError::Timeout)
    })
    .await
    .map_err(|_| ContactError::Timeout)?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags() {
        let d = discovery_key(&[7; 32]);
        let t1 = device_txt(&d, [1; 8]);
        let t2 = device_txt(&d, [2; 8]);
        assert_ne!(t1, t2, "a fresh nonce unlinks advertisements");
        assert!(check_device_txt(&d, &t1));
        assert!(check_device_txt(&d, &t2));
        let other = discovery_key(&[8; 32]);
        assert!(!check_device_txt(&other, &t1));
        let mut bad = t1.clone();
        bad.replace_range(30..32, "00");
        assert!(!check_device_txt(&d, &bad) || bad == t1);
        assert!(!check_device_txt(&d, "t=zz"));
        assert!(!check_device_txt(&d, "c=4"));
        assert_eq!(t1.len(), 2 + 32);
    }
}
