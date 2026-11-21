//! Which network this device is on, and whether its person said it is
//! theirs (D76, `hosts.md#a-device-that-can-be-reached-names-itself`).
//!
//! A network is known by its router's hardware address: on Linux, the
//! default route's gateway (`/proc/net/route`) looked up in the neighbour
//! table (`/proc/net/arp`). The person's answer to "Is this your network?"
//! is kept in their account as a network node (kind 15), so a yes on one
//! device holds on all of them. No is the default, and a question not
//! answered is a no: only on a network marked as theirs does a device ask
//! the router for a port and name itself at the address it gives (D72).
//! Elsewhere it behaves as before D72.
//!
//! Two switches: each device's own (`port_mapping` in its settings,
//! `cardinal router on|off --this-device`), and one in the account that
//! turns off asking any router on every device of the person's
//! (`cardinal router on|off`; a setting node named [`ROUTERS`]).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use cardinal_encoding::{Record, Value};
use cardinal_space::account;
use cardinal_space::entry::{NodeKind, SpaceOp};
use cardinal_space::ROOT;
use serde_json::{json, Value as Json};

use crate::daemon::Daemon;

/// The account setting that turns off asking any router, on every device.
pub const ROUTERS: &str = "ask routers";

/// A router's hardware address.
pub type Router = [u8; 6];

/// `aa:bb:cc:dd:ee:ff`.
pub fn router_text(r: &Router) -> String {
    let parts: Vec<String> = r.iter().map(|b| format!("{b:02x}")).collect();
    parts.join(":")
}

/// Reads `aa:bb:cc:dd:ee:ff` (or with `-`), as `/proc/net/arp` and people
/// write it.
pub fn parse_router(s: &str) -> Option<Router> {
    let parts: Vec<&str> = s.trim().split([':', '-']).collect();
    if parts.len() != 6 {
        return None;
    }
    let mut out = [0u8; 6];
    for (o, p) in out.iter_mut().zip(parts) {
        *o = u8::from_str_radix(p, 16).ok()?;
    }
    Some(out)
}

/// The hardware address `/proc/net/arp` gives for `ip`, if the entry is
/// complete.
pub fn arp_lookup(table: &str, ip: Ipv4Addr) -> Option<Router> {
    table.lines().skip(1).find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() < 4 || f[0].parse::<Ipv4Addr>().ok()? != ip {
            return None;
        }
        let flags = u32::from_str_radix(f[2].trim_start_matches("0x"), 16).ok()?;
        // ATF_COM: the entry is complete
        if flags & 0x2 == 0 {
            return None;
        }
        parse_router(f[3]).filter(|r| *r != [0; 6])
    })
}

/// What a test says the router is: `CARDINAL_TEST_ROUTER_MAC`, a hardware
/// address, or `none`. `None` where it says nothing.
fn test_router() -> Option<Option<Router>> {
    let named = std::env::var("CARDINAL_TEST_ROUTER_MAC").ok()?;
    Some(parse_router(&named))
}

/// The gateway's IPv4 address, from the default route.
fn gateway_ip() -> Option<Ipv4Addr> {
    let routes = std::fs::read_to_string("/proc/net/route").ok()?;
    crate::portmap::default_gateway(&routes)
}

/// The router of the network this device is on now, as far as can be
/// told without sending anything.
pub fn router_now() -> Option<Router> {
    if let Some(r) = test_router() {
        return r;
    }
    let ip = gateway_ip()?;
    let table = std::fs::read_to_string("/proc/net/arp").ok()?;
    arp_lookup(&table, ip)
}

/// [`router_now`], and where the neighbour table has no complete entry
/// for the gateway, an empty datagram to its discard port (9): sending it
/// makes the system ask for the gateway's hardware address, which the
/// table then holds. It is looked at again after a wait, and the datagram
/// sent again, up to three times, waiting longer each time. Nothing is
/// asked of the router.
pub async fn find_router() -> Option<Router> {
    if let Some(r) = router_now() {
        return Some(r);
    }
    if test_router().is_some() {
        return None;
    }
    let ip = gateway_ip()?;
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let mut wait = Duration::from_millis(200);
    for _ in 0..3 {
        let _ = sock.send_to(&[], SocketAddr::from((ip, 9))).await;
        tokio::time::sleep(wait).await;
        if let Some(r) = router_now() {
            return Some(r);
        }
        wait *= 2;
    }
    None
}

/// The subnets this device is on directly, from `/proc/net/route`: each
/// route with no gateway other than the default, as (network, mask).
pub fn on_link_subnets(routes: &str) -> Vec<(Ipv4Addr, Ipv4Addr)> {
    let le = |h: &str| {
        u32::from_str_radix(h, 16)
            .ok()
            .map(|v| Ipv4Addr::from(v.to_le_bytes()))
    };
    routes
        .lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 8 || f[2] != "00000000" || f[1] == "00000000" {
                return None;
            }
            Some((le(f[1])?, le(f[7])?))
        })
        .collect()
}

/// Whether an address is on the local link: link-local, or in a subnet
/// this device is on directly. Where the routes cannot be read, a private
/// address counts. Loopback counts only where a test runs discovery on it
/// (`CARDINAL_TEST_MDNS_INTERFACE` names a loopback address).
pub fn on_local_link(ip: std::net::IpAddr) -> bool {
    let std::net::IpAddr::V4(v4) = ip else {
        return false;
    };
    if v4.is_loopback() {
        let test = std::env::var("CARDINAL_TEST_MDNS_INTERFACE").ok();
        return test
            .and_then(|t| t.parse::<Ipv4Addr>().ok())
            .is_some_and(|t| t.is_loopback());
    }
    if v4.is_link_local() {
        return true;
    }
    match std::fs::read_to_string("/proc/net/route") {
        Ok(routes) => on_link_subnets(&routes)
            .iter()
            .any(|(net, mask)| u32::from(v4) & u32::from(*mask) == u32::from(*net)),
        Err(_) => v4.is_private(),
    }
}

/// What the account says of one network.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Marked {
    /// Whether the person answered for it, on any device.
    pub answered: bool,
    /// Whether they said it is theirs. Where two devices answered at
    /// once, one yes and one no, it is a no: no is the default.
    pub mine: bool,
    /// What a device called it when the person answered.
    pub name: Option<String>,
}

/// What the account says of the network whose router is `r`.
pub fn marked(state: &cardinal_space::State, r: &Router) -> Marked {
    let nodes = state.children(&ROOT).into_iter().filter(|n| {
        n.kind == NodeKind::Uint(account::NETWORK)
            && !n.deleted
            && n.values(1)
                .iter()
                .any(|v| v.value.as_ref().and_then(Value::as_bytes) == Some(&r[..]))
    });
    let mut out = Marked::default();
    let mut all_yes = true;
    for n in nodes {
        out.answered = true;
        let said = n
            .values(2)
            .iter()
            .map(|v| v.value.as_ref().and_then(Value::as_bool));
        for s in said {
            all_yes &= s == Some(true);
        }
        let name = n
            .values(3)
            .iter()
            .rev()
            .find_map(|v| v.value.as_ref()?.as_text());
        out.name = out.name.or(name.map(str::to_owned));
    }
    out.mine = out.answered && all_yes;
    out
}

/// What records the person's answer for the network whose router is `r`:
/// a `set` on each node the account has for it, or a new one.
pub fn mark_ops(
    state: &cardinal_space::State,
    r: &Router,
    mine: bool,
    name: Option<&str>,
) -> Vec<SpaceOp> {
    let nodes: Vec<_> = state
        .children(&ROOT)
        .into_iter()
        .filter(|n| n.kind == NodeKind::Uint(account::NETWORK) && !n.deleted)
        .filter(|n| {
            n.values(1)
                .iter()
                .any(|v| v.value.as_ref().and_then(Value::as_bytes) == Some(&r[..]))
        })
        .map(|n| n.id)
        .collect();
    if nodes.is_empty() {
        let fields = Record::new().with(1, *r).with(2, mine).with_opt(3, name);
        return vec![SpaceOp::create(
            NodeKind::Uint(account::NETWORK),
            ROOT,
            &router_text(r),
            fields,
        )];
    }
    let mut ops = Vec::new();
    for n in nodes {
        ops.push(account::set_field(n, 2, mine));
        if let Some(name) = name {
            ops.push(account::set_field(n, 3, name));
        }
    }
    ops
}

/// Whether the account's switch lets this person's devices ask routers:
/// on unless a setting node named [`ROUTERS`] says false, in any value.
pub fn account_allows(state: &cardinal_space::State) -> bool {
    crate::settings::on(state, ROUTERS)
}

/// What sets the account's switch.
fn switch_ops(state: &cardinal_space::State, on: bool) -> Vec<SpaceOp> {
    crate::settings::set_ops(state, ROUTERS, on)
}

/// Whether this device may ask routers at all: its own switch and the
/// account's both on. Off, a device that named itself takes itself out.
pub fn routers_on(d: &Daemon) -> bool {
    if !d.config().port_mapping {
        return false;
    }
    let core = d.core();
    match core.account().and_then(|a| a.space.as_ref()) {
        Some(acc) => account_allows(acc.state()),
        None => true,
    }
}

/// What the account says of the network this device is on now.
pub fn current(d: &Daemon) -> Option<(Router, Marked)> {
    let r = router_now()?;
    let core = d.core();
    let acc = core.account().and_then(|a| a.space.as_ref())?;
    Some((r, marked(acc.state(), &r)))
}

/// Whether this device is on a network its person said is theirs.
pub fn on_mine(d: &Daemon) -> bool {
    current(d).is_some_and(|(_, m)| m.mine)
}

/// What `status` and `network` say: the network this device is on, by
/// its router, whether the person said it is theirs, and whether to ask
/// them ("Is this your network?"): a network known, not answered for, on
/// a device that would ask its router.
pub fn status(d: &Daemon) -> Json {
    let on = routers_on(d);
    let Some(r) = router_now() else {
        return json!({"known": false, "mine": false, "ask": false, "routers": on});
    };
    let m = {
        let core = d.core();
        let acc = core.account().and_then(|a| a.space.as_ref());
        acc.map(|a| marked(a.state(), &r)).unwrap_or_default()
    };
    json!({
        "known": true,
        "router": router_text(&r),
        "name": m.name,
        "answered": m.answered,
        "mine": m.mine,
        "ask": on && !m.answered,
        "routers": on,
    })
}

/// The person answers "Is this your network?" for the one this device is
/// on now, with what to call it.
pub fn mark(d: &Arc<Daemon>, mine: bool, name: Option<&str>) -> anyhow::Result<Json> {
    let r = router_now().ok_or_else(|| {
        anyhow::anyhow!("this device cannot tell which network it is on: it sees no router")
    })?;
    let name = name.map(str::trim).filter(|n| !n.is_empty());
    let (account, ops) = {
        let core = d.core();
        let acc = core
            .account()
            .ok_or_else(|| anyhow::anyhow!("the account space is not here yet"))?;
        let st = acc
            .space
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("the account space is not open yet"))?
            .state();
        (acc.id, mark_ops(st, &r, mine, name))
    };
    d.write_and_push(&account, ops)?;
    changed(d);
    Ok(status(d))
}

/// Turns asking routers on or off: on this device alone, or with the
/// account's switch on every device of the person's.
pub fn set_routers(d: &Arc<Daemon>, on: bool, this_device: bool) -> anyhow::Result<()> {
    if this_device {
        d.config().port_mapping = on;
        d.save_config()?;
    } else {
        let (account, ops) = {
            let core = d.core();
            let acc = core
                .account()
                .ok_or_else(|| anyhow::anyhow!("the account space is not here yet"))?;
            let st = acc
                .space
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("the account space is not open yet"))?
                .state();
            (acc.id, switch_ops(st, on))
        };
        d.write_and_push(&account, ops)?;
        if on && !d.config().port_mapping {
            // Turned on for every device, this one included.
            d.config().port_mapping = true;
            d.save_config()?;
        }
    }
    changed(d);
    Ok(())
}

/// Something the port mapping loop goes by changed: it looks again now.
fn changed(d: &Arc<Daemon>) {
    if routers_on(d) {
        tokio::spawn(crate::portmap::keep(d.clone()));
    } else if !d.portmap.lock().unwrap_or_else(|e| e.into_inner()).running {
        crate::outside::tick(d);
    }
    d.bump();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_subnets_on_the_link_are_read_from_the_routes() {
        let routes =
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                      wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
                      wlan0\t0001A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0\n";
        let nets = on_link_subnets(routes);
        assert_eq!(
            nets,
            [(
                "192.168.1.0".parse().unwrap(),
                "255.255.255.0".parse().unwrap()
            )]
        );
        assert!(!on_local_link("8.8.8.8".parse().unwrap()));
        assert!(on_local_link("169.254.7.7".parse().unwrap()));
    }

    #[test]
    fn a_router_is_read_from_the_neighbour_table_only_when_complete() {
        let table = "IP address       HW type     Flags       HW address            Mask     Device\n\
                     192.168.1.1      0x1         0x2         d6:a5:7f:9d:79:29     *        wlan0\n\
                     192.168.1.7      0x1         0x0         00:00:00:00:00:00     *        wlan0\n";
        let gw: Ipv4Addr = "192.168.1.1".parse().unwrap();
        assert_eq!(
            arp_lookup(table, gw),
            Some([0xd6, 0xa5, 0x7f, 0x9d, 0x79, 0x29])
        );
        assert_eq!(arp_lookup(table, "192.168.1.7".parse().unwrap()), None);
        assert_eq!(arp_lookup(table, "10.0.0.1".parse().unwrap()), None);
        let r = parse_router("D6-A5-7F-9D-79-29").unwrap();
        assert_eq!(router_text(&r), "d6:a5:7f:9d:79:29");
        assert!(parse_router("d6:a5:7f").is_none());
    }
}
