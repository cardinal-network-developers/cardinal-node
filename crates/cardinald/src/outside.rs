//! A device that can be reached names itself as a host (D72,
//! `hosts.md#a-device-that-can-be-reached-names-itself`).
//!
//! Where the router gives this device a port outside (`portmap.rs`), the
//! device grants itself to its own identity, with rendezvous, relay and a
//! mailbox, and no storage: it is no restore point, and is not on the
//! recovery sheet. The grant's endpoints are its outside addresses, up to
//! [`KEEP`], the newest first, and never an address on its own network.
//! The rest is what any host of the person's does: it is named in their
//! reach nodes as the rules in `mailbox.rs` and `core.rs` say (unasked,
//! only where every other member is a trusted contact, D72), and keeps its
//! own entry there current.
//!
//! What it names, and when each address was last its own, is kept in
//! `outside.json`, so that a month without any of them can be told.
//!
//! It writes only for an address it does not name already: a renewal, or an
//! address that comes back, writes nothing, and nothing is written only to
//! reorder. It takes itself out when the person turns port mapping off
//! (`cardinal router off`), or when none of the addresses it names has been
//! its own for a month. An explicit host (`cardinal host`) keeps the
//! endpoints its person gave, and none of this applies to it.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use cardinal_encoding::{Record, Value};
use cardinal_space::account;
use cardinal_space::grant::{Endpoint, Grant, MAILBOX, RELAY, RENDEZVOUS, STORAGE};
use cardinal_space::SpaceOp;
use serde::{Deserialize, Serialize};

use crate::daemon::Daemon;

/// How many outside addresses a device names at most.
pub const KEEP: usize = 3;
/// How long an address it names may go without being its own.
pub const MONTH: u64 = 30 * 24 * 60 * 60;

/// An address this device names, and when it last held it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Named {
    pub addr: SocketAddr,
    /// Seconds since the epoch.
    pub own_at: u64,
}

/// Whether an address can be reached from outside the network it is on:
/// not a private, shared (carrier-grade NAT), link-local or loopback one.
/// Only such an address is ever named.
pub fn is_outside(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            let shared = o[0] == 100 && (o[1] & 0xc0) == 64;
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || shared
                || o[0] == 0)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_outside(IpAddr::V4(v4));
            }
            let s = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s & 0xfe00) == 0xfc00
                || (s & 0xffc0) == 0xfe80)
        }
    }
}

/// What this device names next, from what it names, whether naming is on,
/// the outside address it holds now (if any), and the time. Says whether
/// the grant is to be written: only for an address not named already, or
/// to take itself out.
pub fn next(named: &[Named], on: bool, have: Option<SocketAddr>, now: u64) -> (Vec<Named>, bool) {
    if !on {
        return (Vec::new(), !named.is_empty());
    }
    let mut list = named.to_vec();
    let mut write = false;
    if let Some(addr) = have.filter(|a| is_outside(a.ip())) {
        match list.iter_mut().find(|n| n.addr == addr) {
            // renewed, or back: nothing to write, and the order stays
            Some(n) => n.own_at = now,
            None => {
                list.insert(0, Named { addr, own_at: now });
                list.truncate(KEEP);
                write = true;
            }
        }
    }
    let stale = |n: &Named| now.saturating_sub(n.own_at) >= MONTH;
    if !list.is_empty() && list.iter().all(stale) {
        return (Vec::new(), true);
    }
    (list, write)
}

/// The endpoints a grant gives for `named`: UDP, which is what a router
/// maps.
pub fn endpoints(named: &[Named]) -> Vec<Endpoint> {
    named
        .iter()
        .map(|n| {
            let address = match n.addr.ip() {
                IpAddr::V4(a) => a.octets().to_vec(),
                IpAddr::V6(a) => a.octets().to_vec(),
            };
            Endpoint::from_record(
                &Record::new()
                    .with(1, 1u64)
                    .with(2, Value::from(address))
                    .with(3, n.addr.port() as u64),
            )
        })
        .collect()
}

/// Whether a grant is one a device made by naming itself: it offers no
/// storage, as an explicit host's always does.
pub fn is_self_named(g: &Grant) -> bool {
    !g.services.contains(&STORAGE)
}

/// Whether this device serves its person as a host now: an explicit host,
/// or one that names itself.
pub fn serving(d: &Daemon) -> bool {
    d.config().host || !named(d).is_empty()
}

/// What this device names now.
pub fn named(d: &Daemon) -> Vec<Named> {
    d.outside.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |t| t.as_secs())
}

/// Reads what was named before; called once, at start.
pub fn load(d: &Daemon) {
    let saved: Vec<Named> = std::fs::read(d.paths.outside())
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    *d.outside.lock().unwrap_or_else(|e| e.into_inner()) = saved;
}

fn save(d: &Daemon, list: &[Named]) {
    let bytes = serde_json::to_vec_pretty(list).unwrap_or_default();
    if let Err(e) = crate::paths::write_private(&d.paths.outside(), &bytes, 0o600) {
        tracing::warn!("cannot save the outside addresses this device names: {e}");
    }
}

/// Forgets what this device names, as when it stops being an explicit
/// host: it names itself again from the next address the router gives.
pub fn forget(d: &Daemon) {
    d.outside.lock().unwrap_or_else(|e| e.into_inner()).clear();
    save(d, &[]);
}

/// This device's own grant as one that names itself, if it has one.
fn own_self_grant(d: &Daemon) -> Option<Grant> {
    crate::host::own_grant(d).filter(is_self_named)
}

/// Brings what this device names up to date with the address the router
/// gives it now, and the grant with it. Call it whenever the router gives
/// an address, renewals included, and now and then besides.
pub fn tick(d: &Arc<Daemon>) {
    if d.config().host {
        // An explicit host's endpoints are its person's.
        return;
    }
    if d.core().account().and_then(|a| a.space.as_ref()).is_none() {
        return;
    }
    let on = d.config().port_mapping;
    let have = crate::portmap::external(d);
    let was = named(d);
    let (list, _) = next(&was, on, have, now());
    // What the grant gives is what decides: a crash between the two
    // writes, or a grant another version wrote, is put right here.
    let given = own_self_grant(d).map(|g| g.endpoints).unwrap_or_default();
    if endpoints(&list) != given {
        if let Err(e) = write_grant(d, &list) {
            tracing::warn!("cannot name this device as a host: {e:#}");
            return;
        }
        match list.first() {
            Some(n) => tracing::info!("this device names itself as a host at {}", n.addr),
            None => tracing::info!("this device no longer names itself as a host"),
        }
    }
    // Times change on every renewal; they are kept, an hour apart at most.
    let moved = was.len() != list.len()
        || was
            .iter()
            .zip(&list)
            .any(|(a, b)| a.addr != b.addr || b.own_at.saturating_sub(a.own_at) >= 3600);
    if moved {
        save(d, &list);
    }
    *d.outside.lock().unwrap_or_else(|e| e.into_inner()) = list;
}

/// Writes this device's grant for `named` in the account space, or takes
/// it away where `named` is empty, and says in its device node whether it
/// is a host.
fn write_grant(d: &Arc<Daemon>, named: &[Named]) -> anyhow::Result<()> {
    let (space, mut ops) = {
        let core = d.core();
        let acc = core
            .account()
            .ok_or_else(|| anyhow::anyhow!("the account space is not here yet"))?;
        let st = acc
            .space
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("the account space is not open yet"))?
            .state();
        let me = d.keys.key();
        let mut ops = Vec::new();
        for h in account::hosts(st) {
            if Grant::open(&h.grant).is_some_and(|(_, signer)| signer == me) {
                ops.push(SpaceOp::delete(h.node));
            }
        }
        if let Some(n) = account::devices(st).into_iter().find(|n| n.key == me) {
            if n.is_host == named.is_empty() {
                ops.push(account::set_field(n.node, 4, !named.is_empty()));
            }
        }
        (acc.id, ops)
    };
    if !named.is_empty() {
        let identity = d
            .core()
            .identity
            .as_ref()
            .map(|i| i.id())
            .ok_or_else(|| anyhow::anyhow!("this device does not belong to anyone"))?;
        let grant = Grant {
            host: identity,
            served: identity,
            services: vec![MAILBOX, RENDEZVOUS, RELAY],
            storage_bytes: 0,
            retention_days: 0,
            endpoints: endpoints(named),
            link_key: d.keys.link.public_key().clone(),
        }
        .sign(&d.keys.signing);
        ops.push(account::create_host(&grant));
    }
    d.write_and_push(&space, ops)?;
    // The list is in place before the entries that name it are kept.
    *d.outside.lock().unwrap_or_else(|e| e.into_inner()) = named.to_vec();
    if named.is_empty() {
        crate::mailbox::close(d);
    } else {
        crate::mailbox::open(d);
    }
    // Its endpoints changed, or it serves no longer: wherever it is named,
    // its entry follows.
    crate::mailbox::keep_own_entry(d);
    Ok(())
}

/// For `status`: what this device names itself at.
pub fn status(d: &Daemon) -> serde_json::Value {
    let list = named(d);
    serde_json::json!(list.iter().map(|n| n.addr.to_string()).collect::<Vec<_>>())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn addrs(l: &[Named]) -> Vec<String> {
        l.iter().map(|n| n.addr.to_string()).collect()
    }

    #[test]
    fn a_lan_address_is_never_outside() {
        for s in [
            "192.168.1.5",
            "10.0.0.1",
            "172.20.1.20",
            "100.64.1.10",
            "127.0.0.1",
            "169.254.3.4",
            "fd00::1",
            "fe80::1",
            "::1",
            "::ffff:192.168.1.5",
        ] {
            assert!(!is_outside(s.parse().unwrap()), "{s}");
        }
        for s in ["203.0.113.5", "198.51.100.10", "8.8.8.8", "2001:db8::1"] {
            assert!(is_outside(s.parse().unwrap()), "{s}");
        }
        let (l, write) = next(&[], true, Some(a("192.168.1.5:7171")), 100);
        assert!(l.is_empty() && !write, "a LAN address was named");
    }

    #[test]
    fn up_to_three_addresses_newest_first() {
        let mut l = Vec::new();
        for (i, s) in [
            "203.0.113.1:1",
            "203.0.113.2:2",
            "203.0.113.3:3",
            "203.0.113.4:4",
        ]
        .iter()
        .enumerate()
        {
            let (n, write) = next(&l, true, Some(a(s)), 100 + i as u64);
            assert!(write, "a new address is written");
            l = n;
        }
        assert_eq!(
            addrs(&l),
            ["203.0.113.4:4", "203.0.113.3:3", "203.0.113.2:2"],
            "the oldest is left out"
        );
    }

    #[test]
    fn a_renewal_or_an_address_that_comes_back_writes_nothing() {
        let (l, _) = next(&[], true, Some(a("203.0.113.1:1")), 100);
        let (l, _) = next(&l, true, Some(a("203.0.113.2:2")), 200);
        let (l2, write) = next(&l, true, Some(a("203.0.113.2:2")), 300);
        assert!(!write, "a renewal was written");
        assert_eq!(l2[0].own_at, 300, "but it is noted");
        // the first comes back: not moved to the front
        let (l3, write) = next(&l2, true, Some(a("203.0.113.1:1")), 400);
        assert!(!write, "written only to reorder");
        assert_eq!(addrs(&l3), ["203.0.113.2:2", "203.0.113.1:1"]);
        // away, with no address: nothing changes
        let (l4, write) = next(&l3, true, None, 500);
        assert!(!write);
        assert_eq!(l4, l3);
    }

    #[test]
    fn it_takes_itself_out_when_turned_off_or_after_a_month_without_any() {
        let (l, _) = next(&[], true, Some(a("203.0.113.1:1")), 100);
        assert_eq!(next(&l, false, None, 200), (Vec::new(), true));
        assert_eq!(next(&[], false, None, 200), (Vec::new(), false));
        let (l, _) = next(&l, true, Some(a("203.0.113.2:2")), 100 + MONTH - 10);
        // one of them was its own within the month
        let (kept, write) = next(&l, true, None, 100 + MONTH + 5);
        assert!(!write && kept.len() == 2);
        assert_eq!(next(&l, true, None, 100 + 2 * MONTH), (Vec::new(), true));
    }

    #[test]
    fn its_endpoints_are_udp_at_its_addresses() {
        let (l, _) = next(&[], true, Some(a("203.0.113.1:60001")), 100);
        let e = endpoints(&l);
        assert_eq!(e[0].socket_addr(), Some(a("203.0.113.1:60001")));
        assert_eq!(e[0].to_record().get(1).and_then(Value::as_uint), Some(1));
    }
}
