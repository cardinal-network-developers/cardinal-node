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
/// How long the router must have given an address before it is named: a
/// device on the network that answers as a router, or a router that
/// gives a new address at each renewal, makes no write.
pub const HOLD: u64 = 10 * 60;
/// After the first, at most one new address is named in this time.
pub const DAY: u64 = 24 * 60 * 60;

/// [`HOLD`], or `CARDINAL_TEST_HOLD_SECS` in tests.
pub fn hold() -> u64 {
    std::env::var("CARDINAL_TEST_HOLD_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(HOLD)
}

/// What this device names itself at, and what that rests on.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outside {
    /// The addresses it names, newest first.
    pub named: Vec<Named>,
    /// When it last named a new one (seconds since the epoch).
    #[serde(default)]
    pub last_new: u64,
    /// The address the router gives now, and since when, while it is not
    /// named yet. Not saved: after a restart it is held again first.
    #[serde(skip)]
    pub seen: Option<(SocketAddr, u64)>,
}

/// An address this device names, and when it last held it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Named {
    pub addr: SocketAddr,
    /// Seconds since the epoch.
    pub own_at: u64,
}

/// Whether an address can be reached from outside the network it is on:
/// not a private, shared (carrier-grade NAT), link-local, loopback,
/// benchmarking, protocol-assignment or reserved one, and not one of the
/// IPv6 ranges that carry an IPv4 address (NAT64) or are for
/// documentation. Only such an address is ever named. The IPv4
/// documentation ranges are left in: the tests here stand for the
/// internet with them, as RFC 5737 means them to.
pub fn is_outside(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            let shared = o[0] == 100 && (o[1] & 0xc0) == 64;
            let benchmarking = o[0] == 198 && (o[1] & 0xfe) == 18;
            let protocol = o[0] == 192 && o[1] == 0 && o[2] == 0;
            let reserved = o[0] >= 240;
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || shared
                || benchmarking
                || protocol
                || reserved
                || o[0] == 0)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_outside(IpAddr::V4(v4));
            }
            let g = v6.segments();
            let nat64 = g[0] == 0x64 && g[1] == 0xff9b;
            let documentation = g[0] == 0x2001 && g[1] == 0x0db8;
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (g[0] & 0xfe00) == 0xfc00
                || (g[0] & 0xffc0) == 0xfe80
                || nat64
                || documentation)
        }
    }
}

/// What this device names next, from what it names, whether naming is on,
/// the outside address the router gives now (if any), the time, and how
/// long an address must be held first. Says whether the grant is to be
/// written: only for an address not named already, which the router has
/// given for `hold` seconds, and no sooner than a [`DAY`] after the last
/// new one unless none is named; or to take itself out.
pub fn next(
    was: &Outside,
    on: bool,
    have: Option<SocketAddr>,
    now: u64,
    hold: u64,
) -> (Outside, bool) {
    if !on {
        let out = Outside {
            last_new: was.last_new,
            ..Outside::default()
        };
        return (out, !was.named.is_empty());
    }
    let mut out = was.clone();
    let mut write = false;
    let have = have.filter(|a| is_outside(a.ip()));
    match have {
        Some(addr) => match out.named.iter_mut().find(|n| n.addr == addr) {
            // renewed, or back: nothing to write, and the order stays
            Some(n) => {
                n.own_at = now;
                out.seen = None;
            }
            None => {
                let since = match out.seen {
                    Some((a, t)) if a == addr => t,
                    _ => now,
                };
                out.seen = Some((addr, since));
                let held = now.saturating_sub(since) >= hold;
                let due = out.named.is_empty() || now.saturating_sub(out.last_new) >= DAY;
                if held && due {
                    out.named.insert(0, Named { addr, own_at: now });
                    out.named.truncate(KEEP);
                    out.last_new = now;
                    out.seen = None;
                    write = true;
                }
            }
        },
        None => out.seen = None,
    }
    let stale = |n: &Named| now.saturating_sub(n.own_at) >= MONTH;
    if !out.named.is_empty() && out.named.iter().all(stale) {
        out.named.clear();
        return (out, true);
    }
    (out, write)
}

/// Whether the address the router gives is due to be named now: the
/// port mapping loop looks often, and [`tick`] is called only then.
pub fn due(d: &Daemon) -> bool {
    let o = d.outside.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let have = crate::portmap::external(d);
    let on = crate::networks::routers_on(d);
    let (_, write) = next(&o, on, have, now(), hold());
    write
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
    d.outside
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .named
        .clone()
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |t| t.as_secs())
}

/// Reads what was named before; called once, at start.
pub fn load(d: &Daemon) {
    let saved: Outside = std::fs::read(d.paths.outside())
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    *d.outside.lock().unwrap_or_else(|e| e.into_inner()) = saved;
}

fn save(d: &Daemon, o: &Outside) {
    let bytes = serde_json::to_vec_pretty(o).unwrap_or_default();
    if let Err(e) = crate::paths::write_private(&d.paths.outside(), &bytes, 0o600) {
        tracing::warn!("cannot save the outside addresses this device names: {e}");
    }
}

/// Forgets what this device names, as when it stops being an explicit
/// host: it names itself again from the next address the router gives.
pub fn forget(d: &Daemon) {
    let o = {
        let mut o = d.outside.lock().unwrap_or_else(|e| e.into_inner());
        o.named.clear();
        o.clone()
    };
    save(d, &o);
}

/// This device's own grant as one that names itself, if it has one.
fn own_self_grant(d: &Daemon) -> Option<Grant> {
    crate::host::own_grant(d).filter(is_self_named)
}

/// Brings what this device names up to date with the address the router
/// gives it now, and the grant with it. Call it whenever the router gives
/// an address, renewals included, and now and then besides.
pub fn tick(d: &Arc<Daemon>) {
    // A persona's service never names itself: it shares no hosts or reach
    // nodes with anyone (`identity.md#personas`).
    if d.config().this_run.inside() {
        return;
    }
    if d.config().host {
        // An explicit host's endpoints are its person's.
        return;
    }
    if d.core().account().and_then(|a| a.space.as_ref()).is_none() {
        return;
    }
    let on = crate::networks::routers_on(d);
    let have = crate::portmap::external(d);
    let all = d.outside.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let was = all.named.clone();
    let (out, _) = next(&all, on, have, now(), hold());
    let list = out.named.clone();
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
    if moved || out.last_new != all.last_new {
        save(d, &out);
    }
    *d.outside.lock().unwrap_or_else(|e| e.into_inner()) = out;
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
            storage_bytes: None,
            retention_days: None,
            endpoints: endpoints(named),
            link_key: d.keys.link.public_key().clone(),
        }
        .sign(&d.keys.signing);
        ops.push(account::create_host(&grant));
    }
    d.write_and_push(&space, ops)?;
    // The list is in place before the entries that name it are kept.
    d.outside.lock().unwrap_or_else(|e| e.into_inner()).named = named.to_vec();
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

    fn addrs(o: &Outside) -> Vec<String> {
        o.named.iter().map(|n| n.addr.to_string()).collect()
    }

    /// The router gives `at` at `now`, held long enough, and a day after
    /// the last new one: as if nothing held it back.
    fn given(o: &Outside, at: &str, now: u64) -> (Outside, bool) {
        let mut o = o.clone();
        o.last_new = o.last_new.min(now.saturating_sub(DAY));
        o.seen = Some((a(at), 0));
        next(&o, true, Some(a(at)), now, HOLD)
    }

    #[test]
    fn only_an_address_outside_is_named() {
        for s in [
            "192.168.1.5",
            "10.0.0.1",
            "172.20.1.20",
            "100.64.1.10",
            "127.0.0.1",
            "169.254.3.4",
            "198.18.0.1",
            "198.19.255.1",
            "192.0.0.8",
            "240.0.0.1",
            "255.255.255.255",
            "0.1.2.3",
            "fd00::1",
            "fe80::1",
            "::1",
            "::ffff:192.168.1.5",
            "64:ff9b::c0a8:105",
            "2001:db8::1",
        ] {
            assert!(!is_outside(s.parse().unwrap()), "{s}");
        }
        for s in [
            "203.0.113.5",
            "198.51.100.10",
            "8.8.8.8",
            "198.20.0.1",
            "2a00:1450::1",
        ] {
            assert!(is_outside(s.parse().unwrap()), "{s}");
        }
        let (o, write) = given(&Outside::default(), "192.168.1.5:7171", 10 * DAY);
        assert!(o.named.is_empty() && !write, "a LAN address was named");
    }

    #[test]
    fn an_address_is_named_only_once_it_has_held() {
        let t = 10 * DAY;
        let o = Outside::default();
        let (o, write) = next(&o, true, Some(a("203.0.113.1:1")), t, HOLD);
        assert!(!write && o.named.is_empty(), "named at once");
        // another address meanwhile starts the wait again
        let (o, write) = next(&o, true, Some(a("203.0.113.2:2")), t + HOLD, HOLD);
        assert!(!write && o.named.is_empty());
        let (o, write) = next(&o, true, Some(a("203.0.113.2:2")), t + 2 * HOLD - 1, HOLD);
        assert!(!write && o.named.is_empty());
        let (o, write) = next(&o, true, Some(a("203.0.113.2:2")), t + 2 * HOLD, HOLD);
        assert!(write && addrs(&o) == ["203.0.113.2:2"]);
        // none at all, and the wait is forgotten
        let (o, _) = next(&o, true, Some(a("203.0.113.3:3")), t + 3 * HOLD, HOLD);
        let (o, _) = next(&o, true, None, t + 4 * HOLD, HOLD);
        assert_eq!(o.seen, None);
    }

    #[test]
    fn after_the_first_at_most_one_new_address_a_day() {
        let t = 10 * DAY;
        let (o, write) = given(&Outside::default(), "203.0.113.1:1", t);
        assert!(write);
        // held, but within the day: waits
        let mut held = o.clone();
        held.seen = Some((a("203.0.113.2:2"), 0));
        let (o2, write) = next(&held, true, Some(a("203.0.113.2:2")), t + HOLD, HOLD);
        assert!(
            !write && addrs(&o2) == ["203.0.113.1:1"],
            "a second the same day"
        );
        let (o3, write) = next(&o2, true, Some(a("203.0.113.2:2")), t + DAY, HOLD);
        assert!(write && addrs(&o3) == ["203.0.113.2:2", "203.0.113.1:1"]);
        // turned off and on: the first is named at once again
        let (off, _) = next(&o3, false, None, t + DAY + 1, HOLD);
        let mut on = off.clone();
        on.seen = Some((a("203.0.113.9:9"), 0));
        let (on, write) = next(&on, true, Some(a("203.0.113.9:9")), t + DAY + 2, HOLD);
        assert!(write && addrs(&on) == ["203.0.113.9:9"]);
    }

    #[test]
    fn up_to_three_addresses_newest_first() {
        let mut o = Outside::default();
        for (i, s) in [
            "203.0.113.1:1",
            "203.0.113.2:2",
            "203.0.113.3:3",
            "203.0.113.4:4",
        ]
        .iter()
        .enumerate()
        {
            let (n, write) = given(&o, s, (10 + i as u64) * DAY);
            assert!(write, "a new address is written");
            o = n;
        }
        assert_eq!(
            addrs(&o),
            ["203.0.113.4:4", "203.0.113.3:3", "203.0.113.2:2"],
            "the oldest is left out"
        );
    }

    #[test]
    fn a_renewal_or_an_address_that_comes_back_writes_nothing() {
        let t = 10 * DAY;
        let (o, _) = given(&Outside::default(), "203.0.113.1:1", t);
        let (o, _) = given(&o, "203.0.113.2:2", t + DAY);
        let (o2, write) = next(&o, true, Some(a("203.0.113.2:2")), t + DAY + 300, HOLD);
        assert!(!write, "a renewal was written");
        assert_eq!(o2.named[0].own_at, t + DAY + 300, "but it is noted");
        // the first comes back: not moved to the front
        let (o3, write) = next(&o2, true, Some(a("203.0.113.1:1")), t + DAY + 400, HOLD);
        assert!(!write, "written only to reorder");
        assert_eq!(addrs(&o3), ["203.0.113.2:2", "203.0.113.1:1"]);
        // away, with no address: nothing changes
        let (o4, write) = next(&o3, true, None, t + DAY + 500, HOLD);
        assert!(!write);
        assert_eq!(o4.named, o3.named);
    }

    #[test]
    fn it_takes_itself_out_when_turned_off_or_after_a_month_without_any() {
        let t = 10 * DAY;
        let (o, _) = given(&Outside::default(), "203.0.113.1:1", t);
        let (off, write) = next(&o, false, None, t + 1, HOLD);
        assert!(write && off.named.is_empty());
        assert!(!next(&Outside::default(), false, None, t, HOLD).1);
        let (o, _) = given(&o, "203.0.113.2:2", t + MONTH - 10);
        // one of them was its own within the month
        let (kept, write) = next(&o, true, None, t + MONTH + 5, HOLD);
        assert!(!write && kept.named.len() == 2);
        let (gone, write) = next(&o, true, None, t + 2 * MONTH, HOLD);
        assert!(write && gone.named.is_empty());
    }

    #[test]
    fn its_endpoints_are_udp_at_its_addresses() {
        let (o, _) = given(&Outside::default(), "203.0.113.1:60001", 10 * DAY);
        let e = endpoints(&o.named);
        assert_eq!(e[0].socket_addr(), Some(a("203.0.113.1:60001")));
        assert_eq!(e[0].to_record().get(1).and_then(Value::as_uint), Some(1));
    }
}
