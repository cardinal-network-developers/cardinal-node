//! Local discovery (`hosts.md#local-discovery`) and the pairing
//! advertisement (`contact.md#pairing`).
//!
//! A device advertises `_cardinal._udp` with TXT `t=` followed by hex of
//! `nonce (8) || first8(BLAKE3.keyed_hash(d, nonce))`, where
//! `d = derive("discovery", discovery secret)`, for its person's own
//! devices; and beside it `c=`, a tag made the same way with
//! `derive("presence", presence secret)`, for their trusted contacts (D74),
//! where the person has given that secret to anyone. Each tag has a nonce
//! of its own. The nonces, and the instance and host names, change on
//! every refresh, so successive advertisements cannot be linked and name
//! nothing; only holders of a secret recognize its tag. A tag is a hint to
//! try, and nothing more: the session that follows proves whose device it
//! is.

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

/// `k = derive("presence", secret)`: the key of a `c=` tag.
pub fn presence_key(secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    derive(Purpose::Presence, secret)
}

/// The letter of the tag for a person's own devices.
pub const OWN: &str = "t=";
/// The letter of the tag for their trusted contacts.
pub const CONTACTS: &str = "c=";

/// `letter` (`t=` or `c=`) and hex of `nonce || first8(keyed_hash(k, nonce))`.
pub fn tag_txt(letter: &str, k: &[u8; 32], nonce: [u8; 8]) -> String {
    let tag = keyed_hash(k, &nonce);
    let mut s = String::from(letter);
    for b in nonce.iter().chain(&tag[..8]) {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// `t=` and hex of `nonce || first8(keyed_hash(d, nonce))`.
pub fn device_txt(d: &[u8; 32], nonce: [u8; 8]) -> String {
    tag_txt(OWN, d, nonce)
}

/// Whether a TXT string carries a `t=` tag made with `d`.
pub fn check_device_txt(d: &[u8; 32], txt: &str) -> bool {
    check_tag_txt(OWN, d, txt)
}

/// Whether a TXT string carries a tag under `letter` made with `k`.
pub fn check_tag_txt(letter: &str, k: &[u8; 32], txt: &str) -> bool {
    let Some(hex) = txt.strip_prefix(letter) else {
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
    let tag = keyed_hash(k, &bytes[..8]);
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
    advertise_tags(cfg, secret, None, port, refresh)
}

/// Advertises this device's link endpoint with `t=`, from the discovery
/// secret, and `c=`, from the presence secret where there is one to give
/// (D74), each with a nonce of its own, refreshing every `refresh`.
pub fn advertise_tags(
    cfg: MdnsConfig,
    secret: &[u8; 32],
    presence: Option<&[u8; 32]>,
    port: u16,
    refresh: Duration,
) -> std::io::Result<Advertiser> {
    let d = discovery_key(secret);
    let c = presence.map(presence_key);
    mdns::advertise(cfg, refresh, move || {
        let mut txt = vec![device_txt(&d, random_bytes())];
        if let Some(c) = &c {
            txt.push(tag_txt(CONTACTS, c, random_bytes()));
        }
        ServiceInfo {
            service: DEVICE_SERVICE.into(),
            instance: random_label(),
            port,
            txt,
            host: random_label(),
            addrs: Vec::new(),
        }
    })
}

/// Browses for every device advertisement, recognized or not: for a
/// caller whose secrets change while it browses, which matches each with
/// [`check_tag_txt`].
pub fn browse_devices(cfg: MdnsConfig, requery: Duration) -> std::io::Result<mdns::Browser> {
    mdns::browse(cfg, DEVICE_SERVICE, requery)
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

// ---- probes (`hosts.md#probe`) ----

use cardinal_link::packet::{PROBE_ANSWER_LEN, PROBE_LEN, TYPE_PROBE, TYPE_PROBE_ANSWER};

/// The bytes a probe's tags are made over: its first 16.
const PROBE_SIGNED: usize = 16;

fn tag8(k: &[u8; 32], over: &[u8]) -> [u8; 8] {
    let h = keyed_hash(k, over);
    let mut t = [0u8; 8];
    t.copy_from_slice(&h[..8]);
    t
}

/// A probe: `6, 0, 0, 0`, `time` (u32, seconds since 1970), `nonce`, the
/// own tag made with `own` (a discovery key), and the contact tag made with
/// `contacts` (a presence key), or 8 zero bytes for none.
pub fn probe(own: &[u8; 32], contacts: Option<&[u8; 32]>, time: u32, nonce: [u8; 8]) -> [u8; 32] {
    let mut p = [0u8; PROBE_LEN];
    p[0] = TYPE_PROBE;
    p[4..8].copy_from_slice(&time.to_le_bytes());
    p[8..16].copy_from_slice(&nonce);
    let own_tag = tag8(own, &p[..PROBE_SIGNED]);
    p[16..24].copy_from_slice(&own_tag);
    if let Some(k) = contacts {
        let theirs = tag8(k, &p[..PROBE_SIGNED]);
        p[24..32].copy_from_slice(&theirs);
    }
    p
}

/// A probe as it came, if it is one: exactly 32 bytes, type 6, then three
/// zero bytes. Anything else is no probe.
pub fn read_probe(b: &[u8]) -> Option<[u8; 32]> {
    if b.len() != PROBE_LEN || b[0] != TYPE_PROBE || b[1..4] != [0, 0, 0] {
        return None;
    }
    b.try_into().ok()
}

/// A probe's time, in seconds since 1970.
pub fn probe_time(p: &[u8; 32]) -> u32 {
    u32::from_le_bytes([p[4], p[5], p[6], p[7]])
}

/// A probe's nonce.
pub fn probe_nonce(p: &[u8; 32]) -> [u8; 8] {
    let mut n = [0u8; 8];
    n.copy_from_slice(&p[8..16]);
    n
}

/// Whether a probe's own tag was made with `own`: one of this person's
/// devices sent it.
pub fn probe_from_own(p: &[u8; 32], own: &[u8; 32]) -> bool {
    ct_eq(&tag8(own, &p[..PROBE_SIGNED]), &p[16..24])
}

/// Whether a probe's contact tag was made with `k`, a trusted contact's
/// presence key. A probe with no contact tag matches none.
pub fn probe_from_contact(p: &[u8; 32], k: &[u8; 32]) -> bool {
    p[24..32] != [0u8; 8] && ct_eq(&tag8(k, &p[..PROBE_SIGNED]), &p[24..32])
}

/// The answer to a probe, made with `k`: the discovery key if the probe
/// came from one of this person's devices, else this person's presence key.
pub fn probe_answer(k: &[u8; 32], p: &[u8; 32]) -> [u8; 12] {
    let mut a = [0u8; PROBE_ANSWER_LEN];
    a[0] = TYPE_PROBE_ANSWER;
    a[4..].copy_from_slice(&tag8(k, p));
    a
}

/// Whether `a` answers probe `p` and was made with `k`. Only exactly 12
/// bytes of type 7 with its three zero bytes can.
pub fn answers(a: &[u8], p: &[u8; 32], k: &[u8; 32]) -> bool {
    a.len() == PROBE_ANSWER_LEN
        && a[0] == TYPE_PROBE_ANSWER
        && a[1..4] == [0, 0, 0]
        && ct_eq(&tag8(k, p), &a[4..])
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
        // A tag for contacts is told from one for own devices by its
        // letter, and is made with a key of its own.
        let c = presence_key(&[7; 32]);
        assert_ne!(*c, *d);
        let t = tag_txt(CONTACTS, &c, [1; 8]);
        assert!(t.starts_with("c="));
        assert!(check_tag_txt(CONTACTS, &c, &t));
        assert!(!check_tag_txt(OWN, &c, &t));
        assert!(!check_device_txt(&d, &t));
        assert!(!check_tag_txt(CONTACTS, &d, &t));
    }
    #[test]
    fn a_probe_is_answered_only_with_the_right_secret() {
        let own = [1u8; 32];
        let theirs = [2u8; 32];
        let p = probe(&own, Some(&theirs), 1_800_000_000, [9; 8]);
        assert_eq!(read_probe(&p), Some(p));
        assert_eq!(probe_time(&p), 1_800_000_000);
        assert_eq!(probe_nonce(&p), [9; 8]);
        assert!(probe_from_own(&p, &own));
        assert!(!probe_from_own(&p, &theirs));
        assert!(probe_from_contact(&p, &theirs));
        assert!(!probe_from_contact(&p, &own));
        let a = probe_answer(&theirs, &p);
        assert!(answers(&a, &p, &theirs));
        assert!(!answers(&a, &p, &own));
        // To another probe, it is no answer.
        let q = probe(&own, Some(&theirs), 1_800_000_000, [8; 8]);
        assert!(!answers(&a, &q, &theirs));
    }

    #[test]
    fn a_malformed_probe_or_answer_is_none() {
        let p = probe(&[1; 32], None, 5, [3; 8]);
        assert!(
            !probe_from_contact(&p, &[0; 32]),
            "no contact tag, no match"
        );
        let mut longer = p.to_vec();
        longer.push(0);
        assert_eq!(read_probe(&longer), None);
        assert_eq!(read_probe(&p[..31]), None);
        let mut padded = p;
        padded[2] = 1;
        assert_eq!(read_probe(&padded), None);
        let mut typed = p;
        typed[0] = 7;
        assert_eq!(read_probe(&typed), None);
        let a = probe_answer(&[1; 32], &p);
        assert!(answers(&a, &p, &[1; 32]));
        let mut off = a;
        off[3] = 1;
        assert!(!answers(&off, &p, &[1; 32]));
        assert!(!answers(&a[..11], &p, &[1; 32]));
        assert!(!answers(&[&a[..], &[0]].concat(), &p, &[1; 32]));
    }
}
