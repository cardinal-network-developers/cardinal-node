//! A minimal DNS-SD over multicast DNS (RFC 6762, RFC 6763): enough to
//! advertise one service instance and to browse for a service type.
//!
//! Advertisements are unsolicited responses (PTR, SRV, TXT, and A records
//! when addresses are known), sent when started, on every refresh, and in
//! answer to queries for the service type. Browsing sends a PTR query and
//! collects responses. IPv4 only for now.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

const TYPE_A: u16 = 1;
const TYPE_PTR: u16 = 12;
const TYPE_TXT: u16 = 16;
const TYPE_SRV: u16 = 33;
const CLASS_IN: u16 = 1;
const CACHE_FLUSH: u16 = 0x8000;
const TTL: u32 = 120;

/// Where multicast DNS runs.
#[derive(Clone, Copy, Debug)]
pub struct MdnsConfig {
    /// The multicast group (224.0.0.251).
    pub group: Ipv4Addr,
    /// The port (5353).
    pub port: u16,
    /// The interface address to join and send on (unspecified: the
    /// system's default).
    pub interface: Ipv4Addr,
}

impl Default for MdnsConfig {
    fn default() -> MdnsConfig {
        MdnsConfig {
            group: Ipv4Addr::new(224, 0, 0, 251),
            port: 5353,
            interface: Ipv4Addr::UNSPECIFIED,
        }
    }
}

impl MdnsConfig {
    fn group_addr(&self) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(self.group, self.port))
    }
}

/// Opens a socket bound to the mDNS port (shared with other responders)
/// and joined to the group.
pub fn open_socket(cfg: &MdnsConfig) -> std::io::Result<UdpSocket> {
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_reuse_address(true)?;
    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
    s.set_reuse_port(true)?;
    s.bind(&SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, cfg.port)).into())?;
    s.join_multicast_v4(&cfg.group, &cfg.interface)?;
    s.set_multicast_loop_v4(true)?;
    s.set_multicast_ttl_v4(255)?;
    if !cfg.interface.is_unspecified() {
        s.set_multicast_if_v4(&cfg.interface)?;
    }
    s.set_nonblocking(true)?;
    UdpSocket::from_std(s.into())
}

/// One service instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceInfo {
    /// The service type without `.local`, e.g. `_cardinal._udp`.
    pub service: String,
    /// The instance label.
    pub instance: String,
    /// The port.
    pub port: u16,
    /// TXT strings (`key=value`).
    pub txt: Vec<String>,
    /// The host label (without `.local`).
    pub host: String,
    /// Addresses for A records; if empty, browsers use the packet's source.
    pub addrs: Vec<Ipv4Addr>,
}

/// An instance found by browsing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Found {
    /// Instance label.
    pub instance: String,
    /// Address and port.
    pub addr: SocketAddr,
    /// TXT strings.
    pub txt: Vec<String>,
}

fn write_name(out: &mut Vec<u8>, name: &str) {
    for label in name.split('.').filter(|l| !l.is_empty()) {
        let b = label.as_bytes();
        out.push(b.len().min(63) as u8);
        out.extend_from_slice(&b[..b.len().min(63)]);
    }
    out.push(0);
}

fn write_rr(out: &mut Vec<u8>, name: &str, ty: u16, class: u16, rdata: &[u8]) {
    write_name(out, name);
    out.extend_from_slice(&ty.to_be_bytes());
    out.extend_from_slice(&class.to_be_bytes());
    out.extend_from_slice(&TTL.to_be_bytes());
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(rdata);
}

/// A response announcing `info`.
pub fn build_announcement(info: &ServiceInfo) -> Vec<u8> {
    let service = format!("{}.local", info.service);
    let instance = format!("{}.{}", info.instance, service);
    let host = format!("{}.local", info.host);
    let mut out = Vec::with_capacity(512);
    let answers = 3 + info.addrs.len() as u16;
    out.extend_from_slice(&[0, 0, 0x84, 0x00, 0, 0]);
    out.extend_from_slice(&answers.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    let mut ptr = Vec::new();
    write_name(&mut ptr, &instance);
    write_rr(&mut out, &service, TYPE_PTR, CLASS_IN, &ptr);
    let mut srv = vec![0, 0, 0, 0];
    srv.extend_from_slice(&info.port.to_be_bytes());
    write_name(&mut srv, &host);
    write_rr(&mut out, &instance, TYPE_SRV, CLASS_IN | CACHE_FLUSH, &srv);
    let mut txt = Vec::new();
    for t in &info.txt {
        let b = t.as_bytes();
        txt.push(b.len().min(255) as u8);
        txt.extend_from_slice(&b[..b.len().min(255)]);
    }
    if txt.is_empty() {
        txt.push(0);
    }
    write_rr(&mut out, &instance, TYPE_TXT, CLASS_IN | CACHE_FLUSH, &txt);
    for a in &info.addrs {
        write_rr(&mut out, &host, TYPE_A, CLASS_IN | CACHE_FLUSH, &a.octets());
    }
    out
}

/// A query for instances of `service`.
pub fn build_query(service: &str) -> Vec<u8> {
    let mut out = vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    write_name(&mut out, &format!("{service}.local"));
    out.extend_from_slice(&TYPE_PTR.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out
}

/// Reads a possibly compressed name at `pos`; returns it and the position
/// after it.
fn read_name(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end = None;
    let mut jumps = 0;
    loop {
        let len = *msg.get(pos)? as usize;
        if len & 0xc0 == 0xc0 {
            let off = ((len & 0x3f) << 8) | *msg.get(pos + 1)? as usize;
            if end.is_none() {
                end = Some(pos + 2);
            }
            jumps += 1;
            if jumps > 16 {
                return None;
            }
            pos = off;
            continue;
        }
        if len == 0 {
            pos += 1;
            break;
        }
        let label = msg.get(pos + 1..pos + 1 + len)?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        pos += 1 + len;
    }
    Some((labels.join("."), end.unwrap_or(pos)))
}

struct Rr {
    name: String,
    ty: u16,
    rdata_at: usize,
    rdlen: usize,
}

fn parse_message(msg: &[u8]) -> Option<(bool, Vec<String>, Vec<Rr>)> {
    if msg.len() < 12 {
        return None;
    }
    let is_response = msg[2] & 0x80 != 0;
    let count = |i: usize| u16::from_be_bytes([msg[i], msg[i + 1]]) as usize;
    let (qd, an, ns, ar) = (count(4), count(6), count(8), count(10));
    let mut pos = 12;
    let mut questions = Vec::new();
    for _ in 0..qd {
        let (name, p) = read_name(msg, pos)?;
        questions.push(name);
        pos = p + 4;
    }
    let mut rrs = Vec::new();
    for _ in 0..an + ns + ar {
        let (name, p) = read_name(msg, pos)?;
        let h = msg.get(p..p + 10)?;
        let ty = u16::from_be_bytes([h[0], h[1]]);
        let rdlen = u16::from_be_bytes([h[8], h[9]]) as usize;
        let rdata_at = p + 10;
        msg.get(rdata_at..rdata_at + rdlen)?;
        rrs.push(Rr {
            name,
            ty,
            rdata_at,
            rdlen,
        });
        pos = rdata_at + rdlen;
    }
    Some((is_response, questions, rrs))
}

/// Whether `msg` is a query asking for `service`.
pub fn is_query_for(msg: &[u8], service: &str) -> bool {
    let want = format!("{service}.local").to_ascii_lowercase();
    matches!(parse_message(msg), Some((false, qs, _)) if qs.contains(&want))
}

/// Instances of `service` in a response. `source` is used when the
/// response carries no A record for the target host.
pub fn parse_response(msg: &[u8], source: IpAddr, service: &str) -> Vec<Found> {
    let Some((true, _, rrs)) = parse_message(msg) else {
        return Vec::new();
    };
    let service = format!("{service}.local").to_ascii_lowercase();
    let mut out = Vec::new();
    for ptr in rrs.iter().filter(|r| r.ty == TYPE_PTR && r.name == service) {
        let Some((instance_name, _)) = read_name(msg, ptr.rdata_at) else {
            continue;
        };
        let mut port = None;
        let mut host = None;
        let mut txt = Vec::new();
        for r in rrs.iter().filter(|r| r.name == instance_name) {
            let d = &msg[r.rdata_at..r.rdata_at + r.rdlen];
            match r.ty {
                TYPE_SRV if d.len() >= 7 => {
                    port = Some(u16::from_be_bytes([d[4], d[5]]));
                    host = read_name(msg, r.rdata_at + 6).map(|x| x.0);
                }
                TYPE_TXT => {
                    let mut i = 0;
                    while i < d.len() {
                        let l = d[i] as usize;
                        if let Some(s) = d.get(i + 1..i + 1 + l) {
                            if !s.is_empty() {
                                txt.push(String::from_utf8_lossy(s).into_owned());
                            }
                        }
                        i += 1 + l;
                    }
                }
                _ => {}
            }
        }
        let Some(port) = port else { continue };
        let ip = host
            .and_then(|h| {
                rrs.iter()
                    .find(|r| r.ty == TYPE_A && r.name == h && r.rdlen == 4)
                    .map(|r| {
                        let d = &msg[r.rdata_at..r.rdata_at + 4];
                        IpAddr::V4(Ipv4Addr::new(d[0], d[1], d[2], d[3]))
                    })
            })
            .unwrap_or(source);
        let instance = instance_name
            .strip_suffix(&format!(".{service}"))
            .unwrap_or(&instance_name)
            .to_string();
        out.push(Found {
            instance,
            addr: SocketAddr::new(ip, port),
            txt,
        });
    }
    out
}

/// A running advertisement. Stops when dropped.
pub struct Advertiser {
    task: JoinHandle<()>,
}

impl Drop for Advertiser {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Advertises the service `make()` returns, re-made on every refresh (so
/// rotating TXT values and instance names change each time).
pub fn advertise(
    cfg: MdnsConfig,
    refresh: Duration,
    make: impl Fn() -> ServiceInfo + Send + Sync + 'static,
) -> std::io::Result<Advertiser> {
    let socket = open_socket(&cfg)?;
    let task = tokio::spawn(async move {
        let mut buf = vec![0u8; 9000];
        loop {
            let info = make();
            let pkt = build_announcement(&info);
            let _ = socket.send_to(&pkt, cfg.group_addr()).await;
            let next = tokio::time::Instant::now() + refresh;
            while let Ok(r) = tokio::time::timeout_at(next, socket.recv_from(&mut buf)).await {
                let Ok((n, _)) = r else { break };
                if is_query_for(&buf[..n], &info.service) {
                    let _ = socket.send_to(&pkt, cfg.group_addr()).await;
                }
            }
        }
    });
    Ok(Advertiser { task })
}

/// A running browse. Stops when dropped.
pub struct Browser {
    task: JoinHandle<()>,
    rx: mpsc::Receiver<Found>,
}

impl Drop for Browser {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Browser {
    /// The next instance seen (instances repeat as they re-announce).
    pub async fn next(&mut self) -> Option<Found> {
        self.rx.recv().await
    }
}

/// Browses for `service`, querying every `requery`.
pub fn browse(cfg: MdnsConfig, service: &str, requery: Duration) -> std::io::Result<Browser> {
    let socket = Arc::new(open_socket(&cfg)?);
    let (tx, rx) = mpsc::channel(64);
    let service = service.to_string();
    let task = tokio::spawn(async move {
        let query = build_query(&service);
        let mut buf = vec![0u8; 9000];
        loop {
            let _ = socket.send_to(&query, cfg.group_addr()).await;
            let next = tokio::time::Instant::now() + requery;
            while let Ok(r) = tokio::time::timeout_at(next, socket.recv_from(&mut buf)).await {
                let Ok((n, from)) = r else { break };
                for f in parse_response(&buf[..n], from.ip(), &service) {
                    if tx.send(f).await.is_err() {
                        return;
                    }
                }
            }
        }
    });
    Ok(Browser { task, rx })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn announcement_round_trip() {
        let info = ServiceInfo {
            service: "_cardinal._udp".into(),
            instance: "a1b2c3".into(),
            port: 4242,
            txt: vec!["t=00ff".into()],
            host: "h1".into(),
            addrs: vec![Ipv4Addr::new(192, 0, 2, 5)],
        };
        let pkt = build_announcement(&info);
        let found = parse_response(&pkt, "10.0.0.1".parse().unwrap(), "_cardinal._udp");
        assert_eq!(
            found,
            vec![Found {
                instance: "a1b2c3".into(),
                addr: "192.0.2.5:4242".parse().unwrap(),
                txt: vec!["t=00ff".into()],
            }]
        );
        assert!(parse_response(&pkt, "10.0.0.1".parse().unwrap(), "_other._udp").is_empty());
        let mut no_a = info.clone();
        no_a.addrs.clear();
        let found = parse_response(
            &build_announcement(&no_a),
            "10.0.0.1".parse().unwrap(),
            "_cardinal._udp",
        );
        assert_eq!(found[0].addr, "10.0.0.1:4242".parse().unwrap());
        assert!(is_query_for(
            &build_query("_cardinal._udp"),
            "_cardinal._udp"
        ));
        assert!(!is_query_for(
            &build_query("_cardinal._udp"),
            "_cardinal-pair._udp"
        ));
    }

    #[test]
    fn compressed_names() {
        // A PTR whose target uses a compression pointer to the question.
        let mut m = vec![0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        let svc_at = m.len();
        write_name(&mut m, "_x._udp.local");
        m.extend_from_slice(&TYPE_PTR.to_be_bytes());
        m.extend_from_slice(&CLASS_IN.to_be_bytes());
        m.extend_from_slice(&TTL.to_be_bytes());
        let rd = [3, b'i', b'n', b's', 0xc0, svc_at as u8];
        m.extend_from_slice(&(rd.len() as u16).to_be_bytes());
        m.extend_from_slice(&rd);
        let (_, _, rrs) = parse_message(&m).unwrap();
        assert_eq!(
            read_name(&m, rrs[0].rdata_at).unwrap().0,
            "ins._x._udp.local"
        );
    }
}
