//! Asks the router for a port (`later.md`, self-healing): PCP (RFC 6887),
//! or NAT-PMP (RFC 6886) where the router knows only that, for the UDP port
//! this device listens on. A router that grants one makes an ordinary device
//! reachable from outside with nobody setting up a forward, and the mapping
//! follows the device if its port moves. The external address joins the
//! addresses the device gives when it says where it is.
//!
//! A router that does neither is asked again now and then, not often: many
//! do neither, and say nothing.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value as Json};
use tokio::net::UdpSocket;

use crate::daemon::Daemon;

/// Where routers listen for both.
const PORT: u16 = 5351;
/// What is asked for; the router may give less, and it is renewed at half.
const LIFETIME: u32 = 7200;
/// How long a router has to answer, each try, doubling (RFC 6886 3.1).
const FIRST_WAIT: Duration = Duration::from_millis(250);
const TRIES: u32 = 4;
/// How long before asking a router that gave nothing again.
const AGAIN: Duration = Duration::from_secs(30 * 60);

const PCP_VERSION: u8 = 2;
const PCP_MAP: u8 = 1;
const PCP_UNSUPP_VERSION: u8 = 1;
const UDP: u8 = 17;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Pcp,
    NatPmp,
    Upnp,
}

impl Protocol {
    fn name(self) -> &'static str {
        match self {
            Protocol::Pcp => "PCP",
            Protocol::NatPmp => "NAT-PMP",
            Protocol::Upnp => "UPnP",
        }
    }
}

/// A port the router gave.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub protocol: Protocol,
    /// Where others reach this device from outside.
    pub external: SocketAddr,
    pub internal_port: u16,
    pub lifetime: u32,
}

/// What came of asking, for `status`.
#[derive(Clone, Debug, Default)]
pub struct State {
    pub mapping: Option<(Mapping, Instant)>,
    /// Why there is none, in words.
    pub why_not: Option<String>,
    /// Whether [`keep`] is running.
    pub running: bool,
}

impl State {
    pub fn status(&self) -> Json {
        match (&self.mapping, &self.why_not) {
            (Some((m, at)), _) => json!({
                "protocol": m.protocol.name(),
                "external": m.external.to_string(),
                "seconds_left": u64::from(m.lifetime).saturating_sub(at.elapsed().as_secs()),
            }),
            (None, Some(why)) => json!({"error": why}),
            (None, None) => Json::Null,
        }
    }
}

/// The address a PCP message carries for an IPv4 one: IPv4-mapped IPv6.
fn mapped(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

fn unmapped(b: &[u8]) -> IpAddr {
    let v6 = Ipv6Addr::from(<[u8; 16]>::try_from(b).expect("16 bytes"));
    match v6.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(v6),
    }
}

/// A PCP MAP request for UDP `port` from `client` (RFC 6887 7.1, 11.1),
/// suggesting `outside` as the port outside.
pub fn pcp_request(
    client: IpAddr,
    port: u16,
    outside: u16,
    lifetime: u32,
    nonce: [u8; 12],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(60);
    m.extend([PCP_VERSION, PCP_MAP, 0, 0]);
    m.extend(lifetime.to_be_bytes());
    m.extend(mapped(client));
    m.extend(nonce);
    m.extend([UDP, 0, 0, 0]);
    m.extend(port.to_be_bytes());
    // the port outside it would like, if it is free
    m.extend(outside.to_be_bytes());
    m.extend(mapped(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
    m
}

#[derive(Debug, PartialEq, Eq)]
pub enum Answer {
    Mapped(Mapping),
    /// The router speaks only NAT-PMP, or an older PCP.
    TryNatPmp,
    /// It said no, with its result code.
    Refused(u8),
}

/// A router's answer to [`pcp_request`]; nothing if it is not one.
pub fn pcp_answer(b: &[u8], port: u16, nonce: [u8; 12]) -> Option<Answer> {
    // A NAT-PMP router answers a version it does not know with its own.
    if b.len() >= 4 && b[0] == 0 {
        return Some(Answer::TryNatPmp);
    }
    if b.len() < 24 || b[1] != 0x80 | PCP_MAP {
        return None;
    }
    let result = b[3];
    if result == PCP_UNSUPP_VERSION {
        return Some(Answer::TryNatPmp);
    }
    if result != 0 {
        return Some(Answer::Refused(result));
    }
    if b.len() < 60 || b[24..36] != nonce || b[36] != UDP {
        return None;
    }
    let internal = u16::from_be_bytes([b[40], b[41]]);
    if internal != port {
        return None;
    }
    let external = u16::from_be_bytes([b[42], b[43]]);
    let lifetime = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
    Some(Answer::Mapped(Mapping {
        protocol: Protocol::Pcp,
        external: SocketAddr::new(unmapped(&b[44..60]), external),
        internal_port: port,
        lifetime,
    }))
}

/// NAT-PMP's two requests: the external address, and a UDP mapping.
pub fn natpmp_address_request() -> Vec<u8> {
    vec![0, 0]
}

pub fn natpmp_map_request(port: u16, outside: u16, lifetime: u32) -> Vec<u8> {
    let mut m = vec![0, 1, 0, 0];
    m.extend(port.to_be_bytes());
    m.extend(outside.to_be_bytes());
    m.extend(lifetime.to_be_bytes());
    m
}

/// The external address in an answer to [`natpmp_address_request`].
pub fn natpmp_address(b: &[u8]) -> Option<Result<Ipv4Addr, u16>> {
    if b.len() < 8 || b[0] != 0 || b[1] != 128 {
        return None;
    }
    let result = u16::from_be_bytes([b[2], b[3]]);
    if result != 0 {
        return Some(Err(result));
    }
    (b.len() >= 12).then(|| Ok(Ipv4Addr::new(b[8], b[9], b[10], b[11])))
}

/// The port and lifetime in an answer to [`natpmp_map_request`].
pub fn natpmp_mapped(b: &[u8], port: u16) -> Option<Result<(u16, u32), u16>> {
    if b.len() < 8 || b[0] != 0 || b[1] != 129 {
        return None;
    }
    let result = u16::from_be_bytes([b[2], b[3]]);
    if result != 0 {
        return Some(Err(result));
    }
    if b.len() < 16 || u16::from_be_bytes([b[8], b[9]]) != port {
        return None;
    }
    let external = u16::from_be_bytes([b[10], b[11]]);
    let lifetime = u32::from_be_bytes([b[12], b[13], b[14], b[15]]);
    Some(Ok((external, lifetime)))
}

/// The default gateway: `CARDINAL_TEST_GATEWAY` (an address and port, or
/// `none`, for tests), or on Linux the default route's.
pub fn gateway() -> Option<SocketAddr> {
    match std::env::var("CARDINAL_TEST_GATEWAY").ok().as_deref() {
        // as on a system that does not say which is the gateway
        Some("none") => return None,
        Some(at) => return at.parse().ok(),
        None => {}
    }
    system_gateway()
}

/// Whether a test named a gateway it did not mean: then no router is asked,
/// rather than the real one by way of UPnP.
fn test_gateway_mistyped() -> bool {
    std::env::var("CARDINAL_TEST_GATEWAY")
        .is_ok_and(|g| g != "none" && g.parse::<SocketAddr>().is_err())
}

/// The default route's gateway, on Linux.
fn system_gateway() -> Option<SocketAddr> {
    let routes = std::fs::read_to_string("/proc/net/route").ok()?;
    default_gateway(&routes).map(|ip| SocketAddr::new(IpAddr::V4(ip), PORT))
}

/// The gateway of the default route in `/proc/net/route`.
pub fn default_gateway(routes: &str) -> Option<Ipv4Addr> {
    routes.lines().skip(1).find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() < 3 || f[1] != "00000000" {
            return None;
        }
        let g = u32::from_str_radix(f[2], 16).ok()?;
        // written in the machine's order, which is little-endian here
        let ip = Ipv4Addr::from(g.to_le_bytes());
        (!ip.is_unspecified()).then_some(ip)
    })
}

/// Sends `request` on a socket connected to the router until an answer
/// `read` takes comes, doubling the wait.
async fn ask<T>(sock: &UdpSocket, request: &[u8], read: impl Fn(&[u8]) -> Option<T>) -> Option<T> {
    let mut wait = FIRST_WAIT;
    let mut buf = [0u8; 1100];
    for _ in 0..TRIES {
        // A port nobody listens on comes back as an error: no answer.
        let _ = sock.send(request).await;
        let until = Instant::now() + wait;
        while let Some(left) = until.checked_duration_since(Instant::now()) {
            match tokio::time::timeout(left, sock.recv(&mut buf)).await {
                Ok(Ok(n)) => {
                    if let Some(t) = read(&buf[..n]) {
                        return Some(t);
                    }
                }
                Ok(Err(_)) => tokio::time::sleep(left.min(Duration::from_millis(50))).await,
                Err(_) => break,
            }
        }
        wait *= 2;
    }
    None
}

/// Asks the router at `gateway` for UDP `port`: PCP, then NAT-PMP.
/// The nonce of this device's PCP mapping of `port`: the same each time,
/// renewals and restarts included, as RFC 6887 (11.2) asks of a renewal.
pub fn nonce_for(secret: &[u8; 32], port: u16) -> [u8; 12] {
    let h =
        cardinal_crypto::keyed_hash_parts(secret, &[b"cardinal pcp nonce", &port.to_be_bytes()]);
    h[..12].try_into().expect("12 bytes")
}

/// `outside` is the port outside asked for, which the router may not give.
pub async fn map(
    gateway: SocketAddr,
    port: u16,
    outside: u16,
    lifetime: u32,
    nonce: [u8; 12],
    held: Option<u16>,
) -> Result<Mapping, String> {
    let bind: SocketAddr = match gateway {
        SocketAddr::V4(_) => "0.0.0.0:0".parse().expect("address"),
        SocketAddr::V6(_) => "[::]:0".parse().expect("address"),
    };
    let sock = UdpSocket::bind(bind).await.map_err(|e| e.to_string())?;
    sock.connect(gateway).await.map_err(|e| e.to_string())?;
    let client = sock.local_addr().map_err(|e| e.to_string())?.ip();
    let request = pcp_request(client, port, outside, lifetime, nonce);
    match ask(&sock, &request, |b| pcp_answer(b, port, nonce)).await {
        Some(Answer::Mapped(m)) => return Ok(m),
        Some(Answer::Refused(code)) => {
            return Err(format!("the router said no (PCP result {code})"))
        }
        Some(Answer::TryNatPmp) | None => {}
    }
    let Some(address) = ask(&sock, &natpmp_address_request(), natpmp_address).await else {
        return upnp(gateway, client, port, outside, lifetime, held).await;
    };
    let address = address.map_err(|c| format!("the router said no (NAT-PMP result {c})"))?;
    let request = natpmp_map_request(port, outside, lifetime);
    let mapped = ask(&sock, &request, |b| natpmp_mapped(b, port)).await;
    let (external, lifetime) = mapped
        .ok_or("the router gave its address but no port")?
        .map_err(|c| format!("the router said no (NAT-PMP result {c})"))?;
    Ok(Mapping {
        protocol: Protocol::NatPmp,
        external: SocketAddr::new(IpAddr::V4(address), external),
        internal_port: port,
        lifetime,
    })
}

/// UPnP, last: finding the router by SSDP goes to the whole network, so
/// it is tried only for a real gateway, or one a test names.
async fn upnp(
    gateway: SocketAddr,
    client: IpAddr,
    port: u16,
    outside: u16,
    lifetime: u32,
    held: Option<u16>,
) -> Result<Mapping, String> {
    const NONE: &str = "the router does not give ports (no answer to PCP, NAT-PMP or UPnP)";
    let described = std::env::var("CARDINAL_TEST_UPNP").ok();
    if gateway.ip().is_loopback() && described.is_none() {
        return Err(NONE.into());
    }
    let g = crate::upnp::find(Some(gateway.ip()), described)
        .await
        .map_err(|e| {
            if e.starts_with("no UPnP router") {
                NONE.to_owned()
            } else {
                e
            }
        })?;
    let (ip, external, lifetime) =
        crate::upnp::map(&g, client, port, outside, lifetime, held).await?;
    Ok(Mapping {
        protocol: Protocol::Upnp,
        external: SocketAddr::new(ip, external),
        internal_port: port,
        lifetime,
    })
}

/// UPnP alone, from the address this device faces its network with.
async fn upnp_only(
    port: u16,
    outside: u16,
    lifetime: u32,
    held: Option<u16>,
) -> Result<Mapping, String> {
    let probe = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| e.to_string())?;
    // A connected socket says which address it would send from; nothing is sent.
    probe
        .connect("239.255.255.250:1900")
        .await
        .map_err(|e| e.to_string())?;
    let client = probe.local_addr().map_err(|e| e.to_string())?.ip();
    let g = crate::upnp::find(None, std::env::var("CARDINAL_TEST_UPNP").ok())
        .await
        .map_err(|e| {
            if e.starts_with("no UPnP router") {
                "the router does not give ports by UPnP, and this system does not say which is the gateway"
                    .to_owned()
            } else {
                e
            }
        })?;
    let (ip, external, lifetime) =
        crate::upnp::map(&g, client, port, outside, lifetime, held).await?;
    Ok(Mapping {
        protocol: Protocol::Upnp,
        external: SocketAddr::new(ip, external),
        internal_port: port,
        lifetime,
    })
}

/// The external address the router gave this device, while it holds.
pub fn external(d: &Daemon) -> Option<SocketAddr> {
    let st = d.portmap.lock().unwrap_or_else(|e| e.into_inner());
    st.mapping
        .as_ref()
        .filter(|(m, at)| at.elapsed() < Duration::from_secs(m.lifetime.into()))
        .map(|(m, _)| m.external)
}

/// Everything `status` says of the router: whether this device asks it
/// (`cardinal router on|off`), what it gave or why it gave nothing, and the
/// outside addresses this device names itself at (D72).
///
/// `on` is whether this device asks routers at all: its own switch
/// (`this_device`) and the account's, for every device (`everywhere`),
/// both on. It asks only on a network its person said is theirs (D76):
/// `network` says which this is.
pub fn status(d: &Daemon) -> Json {
    let on = crate::networks::routers_on(d);
    let mut v = d.portmap.lock().unwrap_or_else(|e| e.into_inner()).status();
    if !v.is_object() {
        v = json!({});
    }
    v["on"] = json!(on);
    v["this_device"] = json!(d.config().port_mapping);
    let everywhere = {
        let core = d.core();
        let acc = core.account().and_then(|a| a.space.as_ref());
        acc.is_none_or(|a| crate::networks::account_allows(a.state()))
    };
    v["everywhere"] = json!(everywhere);
    v["named"] = crate::outside::status(d);
    v["network"] = crate::networks::status(d);
    v
}

/// Turns port mapping, and with it naming this device as a host at the
/// address the router gives (D72), on or off, for good: on this device
/// alone, or on every device of the person's. Off, the port is given back
/// and the device takes itself out of the lists that name it.
pub fn set_on(d: &Arc<Daemon>, on: bool, this_device: bool) -> anyhow::Result<()> {
    crate::networks::set_routers(d, on, this_device)
}

/// Another of this person's devices that is reached at `at`: a host whose
/// grant gives it, or one whose address this device knows. A mapping there
/// would lead to that device, not this one, as a router's forward set up
/// by hand wins over it.
fn reached_there(d: &Daemon, at: SocketAddr) -> Option<String> {
    let me = d.keys.key();
    let others: Vec<[u8; 32]> = {
        let core = d.core();
        let ident = core.identity.as_ref()?;
        ident
            .state()
            .keys
            .keys()
            .copied()
            .filter(|k| *k != me)
            .collect()
    };
    let found = others.into_iter().find(|k| {
        let granted = d.core().host_addresses(k).contains(&at);
        granted || d.known_addrs(k).contains(&at)
    })?;
    Some(d.device_name(&found))
}

/// Where to ask for a port outside other than the one the router gave:
/// the same each time for a device and port, so a renewal asks for it.
fn another_port(nonce: [u8; 12]) -> u16 {
    1024 + u16::from_be_bytes([nonce[0], nonce[1]]) % (65535 - 1024)
}

/// Asks whichever router there is for UDP `port`, with `outside` the port
/// outside asked for. `None` where nobody is to be asked.
async fn ask_router(
    port: u16,
    outside: u16,
    nonce: [u8; 12],
    held: Option<u16>,
) -> Option<Result<Mapping, String>> {
    match gateway() {
        _ if test_gateway_mistyped() => None,
        Some(gw) => Some(map(gw, port, outside, LIFETIME, nonce, held).await),
        // Where the gateway cannot be read (Windows, Android), UPnP
        // finds the router itself.
        None => Some(upnp_only(port, outside, LIFETIME, held).await),
    }
}

/// Gives a mapping back: asks for it again with no lifetime.
async fn release(m: &Mapping, nonce: [u8; 12]) {
    let gw = gateway();
    match (m.protocol, gw) {
        (Protocol::Pcp | Protocol::NatPmp, Some(gw)) => {
            let bind = if gw.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
            let Ok(sock) = UdpSocket::bind(bind).await else {
                return;
            };
            if sock.connect(gw).await.is_err() {
                return;
            }
            let Ok(client) = sock.local_addr().map(|a| a.ip()) else {
                return;
            };
            let port = m.internal_port;
            if m.protocol == Protocol::Pcp {
                let request = pcp_request(client, port, m.external.port(), 0, nonce);
                let _ = ask(&sock, &request, |b| pcp_answer(b, port, nonce)).await;
            } else {
                let request = natpmp_map_request(port, 0, 0);
                let _ = ask(&sock, &request, |b| natpmp_mapped(b, port)).await;
            }
        }
        (Protocol::Upnp, gw) => {
            let described = std::env::var("CARDINAL_TEST_UPNP").ok();
            if let Ok(g) = crate::upnp::find(gw.map(|g| g.ip()), described).await {
                crate::upnp::unmap(&g, m.external.port()).await;
            }
        }
        _ => {}
    }
}

/// Asks for a port, and gives back one whose outside address is where
/// another of this person's devices is reached, asking once for another
/// port outside (`later.md`, found on the home pfSense: a forward set up
/// by hand to the host won over the mapping of the same port).
async fn ask_mine(
    d: &Daemon,
    port: u16,
    nonce: [u8; 12],
    held: Option<u16>,
    outside: u16,
) -> Option<Result<Mapping, String>> {
    let first = ask_router(port, outside, nonce, held).await?;
    let Ok(m) = first else {
        return Some(first);
    };
    let Some(who) = reached_there(d, m.external) else {
        return Some(Ok(m));
    };
    tracing::info!(
        "the router gives {}, where your {who} is reached: giving it back",
        m.external
    );
    release(&m, nonce).await;
    let other = another_port(nonce);
    let second = ask_router(port, other, nonce, None).await?;
    let Ok(m) = second else {
        return Some(second);
    };
    match reached_there(d, m.external) {
        None => Some(Ok(m)),
        Some(who) => {
            release(&m, nonce).await;
            Some(Err(format!(
                "the router gives {}, where your {who} is reached, and no other port",
                m.external
            )))
        }
    }
}

/// Keeps a port from the router for as long as the service runs and
/// port mapping is on: asked at start, renewed at half its lifetime, asked
/// again for a new port if the device's moved, and asked now and then of a
/// router that gave nothing. Turned off, it gives the port back and ends.
pub async fn keep(d: Arc<Daemon>) {
    {
        let mut st = d.portmap.lock().unwrap_or_else(|e| e.into_inner());
        if st.running {
            return;
        }
        st.running = true;
    }
    // Keyed by a secret of the device's, so nobody who has seen its
    // public keys can compute it (RFC 6887 11.1).
    let device = d.keys.signing.seed();
    loop {
        // Listening on loopback alone, as tests do, nothing outside can
        // reach it: no router is asked.
        let udp = d.endpoint.udp_addr().filter(|a| !a.ip().is_loopback());
        let port = udp.map(|a| a.port());
        let held_now = {
            let st = d.portmap.lock().unwrap_or_else(|e| e.into_inner());
            st.mapping
                .as_ref()
                .filter(|(m, _)| Some(m.internal_port) == port)
                .map(|(m, _)| (m.protocol, m.external.port()))
        };
        if !crate::networks::routers_on(&d) {
            let held = d
                .portmap
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .mapping
                .take();
            if let Some((m, _)) = held {
                release(&m, nonce_for(&device, m.internal_port)).await;
                d.bump();
            }
            {
                let mut st = d.portmap.lock().unwrap_or_else(|e| e.into_inner());
                st.why_not = None;
                st.running = false;
            }
            crate::outside::tick(&d);
            return;
        }
        // Only on a network the person said is theirs (D76). Anywhere
        // else nothing is asked of the router, and nothing sent to it: a
        // mapping held on another network is let go without a word to
        // this one's router, and lapses there.
        let router = crate::networks::find_router().await;
        if !router.is_some_and(|_| crate::networks::on_mine(&d)) {
            let dropped = {
                let mut st = d.portmap.lock().unwrap_or_else(|e| e.into_inner());
                st.why_not = Some(match router {
                    Some(_) => "not asked: this is not a network you said is yours".to_owned(),
                    None => "not asked: this device cannot tell which network it is on".to_owned(),
                });
                st.mapping.take().is_some()
            };
            if dropped {
                d.bump();
            }
            crate::outside::tick(&d);
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let moved = crate::networks::router_now() != router;
                if moved || !crate::networks::routers_on(&d) || crate::networks::on_mine(&d) {
                    break;
                }
            }
            continue;
        }
        // The port outside a UPnP router gave this one, to renew; and the
        // one to ask any router for, which it gives again on a renewal.
        let held = held_now
            .filter(|(p, _)| *p == Protocol::Upnp)
            .map(|(_, e)| e);
        let asked = match port {
            Some(port) => {
                let nonce = nonce_for(&device, port);
                let outside = held_now.map_or(port, |(_, e)| e);
                ask_mine(&d, port, nonce, held, outside).await
            }
            None => None,
        };
        let wait = match asked {
            Some(asked) => match asked {
                Ok(m) => {
                    let half = Duration::from_secs(u64::from(m.lifetime.max(120)) / 2);
                    let fresh = external(&d) != Some(m.external);
                    tracing::info!("the router gives {} ({})", m.external, m.protocol.name());
                    {
                        let mut st = d.portmap.lock().unwrap_or_else(|e| e.into_inner());
                        st.mapping = Some((m, Instant::now()));
                        st.why_not = None;
                    }
                    if fresh {
                        // Where this device is to be found has changed.
                        d.bump();
                    }
                    half
                }
                Err(why) => {
                    tracing::debug!("port from the router: {why}");
                    let mut st = d.portmap.lock().unwrap_or_else(|e| e.into_inner());
                    st.mapping = None;
                    st.why_not = Some(why);
                    AGAIN
                }
            },
            _ => AGAIN,
        };
        crate::outside::tick(&d);
        // A port that moved is asked for again at once, and port mapping
        // turned off is acted on.
        let until = Instant::now() + wait;
        while Instant::now() < until {
            tokio::time::sleep(Duration::from_secs(1).min(wait)).await;
            let now = d
                .endpoint
                .udp_addr()
                .filter(|a| !a.ip().is_loopback())
                .map(|a| a.port());
            if now != port || !crate::networks::routers_on(&d) {
                break;
            }
            // Moved to another network, or this one is no longer marked.
            if crate::networks::router_now() != router || !crate::networks::on_mine(&d) {
                break;
            }
            // An address held long enough is named without waiting for
            // the next renewal.
            if crate::outside::due(&d) {
                crate::outside::tick(&d);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pcp_map_request_is_as_rfc_6887_lays_it_out() {
        let client: IpAddr = "192.168.1.20".parse().unwrap();
        let m = pcp_request(client, 47555, 47555, 7200, [7; 12]);
        assert_eq!(m.len(), 60);
        assert_eq!(&m[..4], &[2, 1, 0, 0]);
        assert_eq!(&m[4..8], &7200u32.to_be_bytes());
        assert_eq!(&m[8..24], &mapped(client));
        assert_eq!(&m[18..20], &[0xff, 0xff], "IPv4-mapped");
        assert_eq!(&m[24..36], &[7; 12]);
        assert_eq!(m[36], 17);
        assert_eq!(&m[40..44], &[0xb9, 0xc3, 0xb9, 0xc3]);
    }

    fn pcp_reply(nonce: [u8; 12], result: u8, port: u16, external: SocketAddr) -> Vec<u8> {
        let mut b = vec![2, 0x81, 0, result];
        b.extend(3600u32.to_be_bytes());
        b.extend([0; 16]);
        b.extend(nonce);
        b.extend([17, 0, 0, 0]);
        b.extend(port.to_be_bytes());
        b.extend(external.port().to_be_bytes());
        b.extend(mapped(external.ip()));
        b
    }

    #[test]
    fn a_pcp_answer_gives_the_port_outside_or_says_why_not() {
        let out: SocketAddr = "203.0.113.5:60001".parse().unwrap();
        let a = pcp_answer(&pcp_reply([7; 12], 0, 47555, out), 47555, [7; 12]);
        let Some(Answer::Mapped(m)) = a else {
            panic!("{a:?}")
        };
        assert_eq!(
            (m.external, m.lifetime, m.protocol),
            (out, 3600, Protocol::Pcp)
        );
        // another request's answer, or another port's, is not this one's
        assert_eq!(
            pcp_answer(&pcp_reply([8; 12], 0, 47555, out), 47555, [7; 12]),
            None
        );
        assert_eq!(
            pcp_answer(&pcp_reply([7; 12], 0, 1, out), 47555, [7; 12]),
            None
        );
        assert_eq!(
            pcp_answer(&pcp_reply([7; 12], 2, 47555, out), 47555, [7; 12]),
            Some(Answer::Refused(2))
        );
        // a NAT-PMP router answers a PCP request in its own version
        assert_eq!(
            pcp_answer(&[0, 0x81, 0, 1], 47555, [7; 12]),
            Some(Answer::TryNatPmp)
        );
        assert_eq!(
            pcp_answer(&pcp_reply([7; 12], 1, 47555, out), 47555, [7; 12]),
            Some(Answer::TryNatPmp)
        );
    }

    #[test]
    fn nat_pmp_is_as_rfc_6886_lays_it_out() {
        assert_eq!(natpmp_address_request(), [0, 0]);
        assert_eq!(
            natpmp_map_request(47555, 47555, 7200),
            [0, 1, 0, 0, 0xb9, 0xc3, 0xb9, 0xc3, 0, 0, 0x1c, 0x20]
        );
        let addr = [0, 128, 0, 0, 0, 0, 0, 5, 203, 0, 113, 5];
        assert_eq!(
            natpmp_address(&addr),
            Some(Ok(Ipv4Addr::new(203, 0, 113, 5)))
        );
        assert_eq!(natpmp_address(&[0, 128, 0, 3, 0, 0, 0, 5]), Some(Err(3)));
        let map = [
            0, 129, 0, 0, 0, 0, 0, 5, 0xb9, 0xc3, 0xea, 0x61, 0, 0, 0x0e, 0x10,
        ];
        assert_eq!(natpmp_mapped(&map, 47555), Some(Ok((60001, 3600))));
        assert_eq!(natpmp_mapped(&map, 1), None);
    }

    #[test]
    fn a_mapping_keeps_its_nonce_and_each_port_and_device_has_its_own() {
        assert_eq!(nonce_for(&[1; 32], 47555), nonce_for(&[1; 32], 47555));
        assert_ne!(nonce_for(&[1; 32], 47555), nonce_for(&[1; 32], 47556));
        assert_ne!(nonce_for(&[1; 32], 47555), nonce_for(&[2; 32], 47555));
    }

    #[test]
    fn the_default_gateway_is_read_from_the_routing_table() {
        let routes = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n\
                      wlp0s20f3\t00000000\t011414AC\t0003\t0\t0\t600\t00000000\n\
                      wlp0s20f3\t000014AC\t00000000\t0001\t0\t0\t600\t00FEFFFF\n";
        assert_eq!(default_gateway(routes), Some(Ipv4Addr::new(172, 20, 20, 1)));
        assert_eq!(default_gateway("Iface\tDestination\tGateway\n"), None);
    }

    /// A router in a test: answers PCP, or only NAT-PMP, as told.
    async fn router(pcp: bool) -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let at = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 1100];
            loop {
                let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                    return;
                };
                let b = &buf[..n];
                let reply = match (b[0], b[1]) {
                    (2, 1) if pcp => {
                        let nonce: [u8; 12] = b[24..36].try_into().unwrap();
                        let port = u16::from_be_bytes([b[40], b[41]]);
                        pcp_reply(nonce, 0, port, "203.0.113.5:60001".parse().unwrap())
                    }
                    (2, _) => vec![0, 0x81, 0, 1],
                    (0, 0) => vec![0, 128, 0, 0, 0, 0, 0, 5, 203, 0, 113, 6],
                    (0, 1) => {
                        let mut r = vec![0, 129, 0, 0, 0, 0, 0, 5];
                        r.extend(&b[4..6]);
                        r.extend(60002u16.to_be_bytes());
                        r.extend(1800u32.to_be_bytes());
                        r
                    }
                    _ => continue,
                };
                let _ = sock.send_to(&reply, from).await;
            }
        });
        at
    }

    #[tokio::test]
    async fn a_router_that_speaks_pcp_gives_a_port_and_one_that_speaks_nat_pmp_too() {
        let m = map(router(true).await, 47555, 47555, 7200, [7; 12], None)
            .await
            .unwrap();
        assert_eq!(
            (m.protocol, m.external),
            (Protocol::Pcp, "203.0.113.5:60001".parse().unwrap())
        );
        let m = map(router(false).await, 47555, 47555, 7200, [7; 12], None)
            .await
            .unwrap();
        assert_eq!(
            (m.protocol, m.external),
            (Protocol::NatPmp, "203.0.113.6:60002".parse().unwrap())
        );
        assert_eq!(m.lifetime, 1800);
    }

    #[tokio::test]
    async fn a_router_that_says_nothing_is_said_so() {
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let at = silent.local_addr().unwrap();
        let t = Instant::now();
        let e = map(at, 47555, 47555, 7200, [7; 12], None)
            .await
            .unwrap_err();
        assert!(e.contains("does not give ports"), "{e}");
        assert!(t.elapsed() < Duration::from_secs(10), "{:?}", t.elapsed());
        drop(silent);
    }
}
