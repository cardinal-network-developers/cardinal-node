//! UPnP's way of asking the router for a port (the Internet Gateway Device
//! protocol), for the many home routers that speak it and neither PCP nor
//! NAT-PMP (`portmap.rs`): find the router by SSDP, read where its
//! WANIPConnection service is from its description, and ask that service
//! for its external address and a UDP mapping, by SOAP over HTTP.
//!
//! Only what this needs of HTTP and XML is here: the router is on the
//! local network, and answers small, plain messages.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

const SSDP: &str = "239.255.255.250:1900";
const SEARCH_FOR: &str = "urn:schemas-upnp-org:device:InternetGatewayDevice:1";
/// The services that map ports, newest first.
const SERVICES: [&str; 3] = [
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
];
/// How long routers have to answer a search, and each request.
const WAIT: Duration = Duration::from_secs(3);
/// The UPnP error for a router that keeps only mappings with no end.
const ONLY_PERMANENT: &str = "725";
/// The UPnP error for a port outside that another mapping has.
const CONFLICT: &str = "718";

/// The router's service that maps ports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gateway {
    /// Where to send its requests: host and port, and path.
    pub at: SocketAddr,
    pub path: String,
    pub service: String,
}

/// The description's address from an SSDP answer: its `LOCATION`.
pub fn location(answer: &str) -> Option<String> {
    answer.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim()
            .eq_ignore_ascii_case("location")
            .then(|| v.trim().to_owned())
    })
}

/// Whether a path can go into a request line as it is: a router's
/// description is anyone's on the network, and a space or a line break in
/// it would write the rest of the request.
fn safe_path(path: &str) -> bool {
    path.starts_with('/') && path.bytes().all(|b| b > 0x20 && b != 0x7f)
}

/// Whether an address can be a router on this device's own network: not
/// this device itself, nor anything beyond the network.
fn on_the_network(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
        }
    }
}

/// Whether an SSDP answer from `from` naming `url` can be taken: the
/// description is on the machine that answered, which is on this network.
pub fn trusted_location(url: &str, from: IpAddr) -> bool {
    split_url(url).is_some_and(|(at, _)| at.ip() == from && on_the_network(from))
}

/// An `http://host:port/path` address, as an address and a path.
pub fn split_url(url: &str) -> Option<(SocketAddr, String)> {
    let rest = url.strip_prefix("http://")?;
    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_owned()),
        None => (rest, "/".to_owned()),
    };
    let at = if host.contains(':') {
        host.parse().ok()?
    } else {
        SocketAddr::new(host.parse().ok()?, 80)
    };
    safe_path(&path).then_some((at, path))
}

/// What one tag holds, the first time it comes in `xml`.
fn tag<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&format!("</{name}>"))? + start;
    Some(xml[start..end].trim())
}

/// The service that maps ports in a device description, with its control
/// address made whole from where the description came from.
pub fn gateway_in(description: &str, from: &str) -> Option<Gateway> {
    let (from_at, _) = split_url(from)?;
    // Only the host the description came from: a description could name
    // any address, this device's own services or one beyond the network.
    let base = tag(description, "URLBase")
        .and_then(split_url)
        .map(|(at, _)| at)
        .filter(|at| at.ip() == from_at.ip());
    for wanted in SERVICES {
        let mut rest = description;
        while let Some(i) = rest.find("<service>") {
            let block = &rest[i..];
            let end = block
                .find("</service>")
                .map_or(block.len(), |e| e + "</service>".len());
            let service = &block[..end];
            rest = &block[end..];
            if tag(service, "serviceType") != Some(wanted) {
                continue;
            }
            let control = tag(service, "controlURL")?;
            let (at, path) = if control.starts_with("http://") {
                split_url(control).filter(|(at, _)| at.ip() == from_at.ip())?
            } else {
                let path = if control.starts_with('/') {
                    control.to_owned()
                } else {
                    format!("/{control}")
                };
                if !safe_path(&path) {
                    return None;
                }
                (base.unwrap_or(from_at), path)
            };
            return Some(Gateway {
                at,
                path,
                service: wanted.to_owned(),
            });
        }
    }
    None
}

/// A SOAP request for `action` with these arguments.
pub fn soap(g: &Gateway, action: &str, args: &[(&str, String)]) -> Vec<u8> {
    let mut body = format!(
        "<?xml version=\"1.0\"?>\r\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body>\
         <u:{action} xmlns:u=\"{}\">",
        g.service
    );
    for (k, v) in args {
        body.push_str(&format!("<{k}>{v}</{k}>"));
    }
    body.push_str(&format!("</u:{action}></s:Body></s:Envelope>"));
    let head = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: text/xml; charset=\"utf-8\"\r\n\
         SOAPAction: \"{}#{action}\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        g.path,
        g.at,
        g.service,
        body.len()
    );
    [head.into_bytes(), body.into_bytes()].concat()
}

/// Sends one HTTP request and reads the whole answer: its status and body.
async fn exchange(at: SocketAddr, request: &[u8]) -> Result<(u16, String), String> {
    let go = async {
        let mut s = TcpStream::connect(at).await.map_err(|e| e.to_string())?;
        s.write_all(request).await.map_err(|e| e.to_string())?;
        let mut answer = Vec::new();
        s.take(256 * 1024)
            .read_to_end(&mut answer)
            .await
            .map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&answer).into_owned();
        let status = text
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .ok_or("not an HTTP answer")?;
        let body = text
            .split_once("\r\n\r\n")
            .map_or("", |(_, b)| b)
            .to_owned();
        Ok((status, body))
    };
    tokio::time::timeout(WAIT, go)
        .await
        .map_err(|_| "the router did not answer".to_owned())?
}

/// Finds the router's description by SSDP, preferring the gateway's own.
async fn search(gateway_ip: Option<IpAddr>) -> Option<String> {
    let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let ask = format!(
        "M-SEARCH * HTTP/1.1\r\nHOST: {SSDP}\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {SEARCH_FOR}\r\n\r\n"
    );
    sock.send_to(ask.as_bytes(), SSDP).await.ok()?;
    let mut buf = [0u8; 2048];
    let mut found = None;
    let until = tokio::time::Instant::now() + WAIT;
    while let Ok(Ok((n, from))) = tokio::time::timeout_at(until, sock.recv_from(&mut buf)).await {
        let Some(url) = location(&String::from_utf8_lossy(&buf[..n])) else {
            continue;
        };
        if !trusted_location(&url, from.ip()) {
            continue;
        }
        if Some(from.ip()) == gateway_ip {
            return Some(url);
        }
        found.get_or_insert(url);
    }
    found
}

/// The router's port-mapping service: from the description at `described`
/// where that is given, or found by SSDP.
pub async fn find(
    gateway_ip: Option<IpAddr>,
    described: Option<String>,
) -> Result<Gateway, String> {
    let url = match described {
        Some(u) => u,
        None => search(gateway_ip).await.ok_or("no UPnP router answered")?,
    };
    let (at, path) =
        split_url(&url).ok_or("the router's description has an address this cannot use")?;
    let get = format!("GET {path} HTTP/1.1\r\nHost: {at}\r\nConnection: close\r\n\r\n");
    let (status, body) = exchange(at, get.as_bytes()).await?;
    if status != 200 {
        return Err(format!("the router's description: HTTP {status}"));
    }
    gateway_in(&body, &url).ok_or_else(|| "the UPnP router maps no ports".to_owned())
}

/// Asks the router's service for UDP `port`, `outside` outside (or the
/// next free one, or `held`, to renew it), for this device at `client`, and for the router's external address. A router
/// that keeps only mappings with no end is asked for one: renewing it
/// changes nothing.
pub async fn map(
    g: &Gateway,
    client: IpAddr,
    port: u16,
    outside: u16,
    lifetime: u32,
    held: Option<u16>,
) -> Result<(IpAddr, u16, u32), String> {
    let mut lease = lifetime;
    // Another device behind the same router may hold the port outside:
    // then the next few are asked for. What this device holds already is
    // asked for first, so a renewal renews it.
    let mut external = held.unwrap_or(outside);
    let mut taken = 0;
    loop {
        let add = soap(
            g,
            "AddPortMapping",
            &[
                ("NewRemoteHost", String::new()),
                ("NewExternalPort", external.to_string()),
                ("NewProtocol", "UDP".into()),
                ("NewInternalPort", port.to_string()),
                ("NewInternalClient", client.to_string()),
                ("NewEnabled", "1".into()),
                ("NewPortMappingDescription", "Cardinal".into()),
                ("NewLeaseDuration", lease.to_string()),
            ],
        );
        let (status, body) = exchange(g.at, &add).await?;
        if status == 200 {
            break;
        }
        let code = tag(&body, "errorCode").unwrap_or("");
        if code == ONLY_PERMANENT && lease != 0 {
            lease = 0;
            continue;
        }
        if code == CONFLICT && taken < 10 {
            taken += 1;
            external = external.checked_add(1).unwrap_or(1024);
            continue;
        }
        let what = tag(&body, "errorDescription").unwrap_or("");
        return Err(format!("the router said no (UPnP {code} {what})").replace("  ", " "));
    }
    // A mapping of another port outside, held before, would otherwise stay
    // on a router that keeps mappings with no end.
    if let Some(old) = held.filter(|h| *h != external) {
        let delete = soap(
            g,
            "DeletePortMapping",
            &[
                ("NewRemoteHost", String::new()),
                ("NewExternalPort", old.to_string()),
                ("NewProtocol", "UDP".into()),
            ],
        );
        let _ = exchange(g.at, &delete).await;
    }
    let (status, body) = exchange(g.at, &soap(g, "GetExternalIPAddress", &[])).await?;
    let ip = tag(&body, "NewExternalIPAddress")
        .and_then(|a| a.parse::<IpAddr>().ok())
        .filter(|_| status == 200)
        .ok_or("the router mapped the port but did not say its own address")?;
    // Behind another router, its address is a private one, of no use to
    // anyone outside.
    if !public(ip) {
        return Err(format!(
            "the router is behind another one (its address is {ip})"
        ));
    }
    // No end: asked again as often as one that has one, to stay mapped.
    Ok((ip, external, if lease == 0 { lifetime } else { lease }))
}

/// Whether others on the internet could reach `ip`.
fn public(ip: IpAddr) -> bool {
    crate::outside::is_outside(ip)
}

/// Gives back the mapping of UDP port `external` outside.
pub async fn unmap(g: &Gateway, external: u16) {
    let delete = soap(
        g,
        "DeletePortMapping",
        &[
            ("NewRemoteHost", String::new()),
            ("NewExternalPort", external.to_string()),
            ("NewProtocol", "UDP".into()),
        ],
    );
    let _ = exchange(g.at, &delete).await;
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A description as miniupnpd (pfSense, OpenWrt) writes one, cut down.
    pub const DESCRIPTION: &str = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0"><specVersion><major>1</major><minor>1</minor></specVersion>
<device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
<serviceList><service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>
<controlURL>/ctl/L3F</controlURL></service></serviceList>
<deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
<deviceList><device><deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
<serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
<serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
<controlURL>/ctl/IPConn</controlURL><eventSubURL>/evt/IPConn</eventSubURL>
<SCPDURL>/WANIPCn.xml</SCPDURL></service></serviceList></device></deviceList>
</device></deviceList></device></root>"#;

    #[test]
    fn an_ssdp_answer_says_where_the_description_is() {
        let answer = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\n\
                      ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
                      Location: http://172.20.0.1:2189/rootDesc.xml\r\nSERVER: OpenWRT UPnP/1.1\r\n\r\n";
        assert_eq!(
            location(answer).as_deref(),
            Some("http://172.20.0.1:2189/rootDesc.xml")
        );
        let (at, path) = split_url("http://172.20.0.1:2189/rootDesc.xml").unwrap();
        assert_eq!(
            (at.to_string().as_str(), path.as_str()),
            ("172.20.0.1:2189", "/rootDesc.xml")
        );
        assert_eq!(split_url("http://10.0.0.1").unwrap().0.port(), 80);
        assert_eq!(split_url("https://10.0.0.1/x"), None);
    }

    #[test]
    fn the_description_says_where_ports_are_mapped() {
        let g = gateway_in(DESCRIPTION, "http://172.20.0.1:2189/rootDesc.xml").unwrap();
        assert_eq!(g.at.to_string(), "172.20.0.1:2189");
        assert_eq!(g.path, "/ctl/IPConn");
        assert_eq!(g.service, "urn:schemas-upnp-org:service:WANIPConnection:1");
        assert_eq!(gateway_in("<root></root>", "http://172.20.0.1/x"), None);
    }

    #[test]
    fn what_the_network_says_cannot_steer_the_requests_elsewhere() {
        let from = "http://172.20.0.1:2189/rootDesc.xml";
        let with = |control: &str| {
            let tag = format!("<controlURL>{control}</controlURL>");
            DESCRIPTION.replace("<controlURL>/ctl/IPConn</controlURL>", &tag)
        };
        // a line break or a space would write the rest of the request
        let injected = "/x HTTP/1.1\r\nHost: evil\r\n\r\nDELETE /admin";
        assert_eq!(gateway_in(&with(injected), from), None);
        assert_eq!(gateway_in(&with("http://172.20.0.1:5000/x y"), from), None);
        // another host, this device's own services among them
        assert_eq!(gateway_in(&with("http://127.0.0.1:631/x"), from), None);
        assert_eq!(gateway_in(&with("http://203.0.113.9/ctl"), from), None);
        // the same host, another port, is a router's own
        let g = gateway_in(&with("http://172.20.0.1:5000/ctl"), from).unwrap();
        assert_eq!(g.at.to_string(), "172.20.0.1:5000");
        // an answer to the search is taken only from the machine it names, on this network
        let lan: IpAddr = "172.20.0.1".parse().unwrap();
        assert!(trusted_location(from, lan));
        assert!(!trusted_location(from, "172.20.0.9".parse().unwrap()));
        let local: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(!trusted_location("http://127.0.0.1:2189/d.xml", local));
        let far: IpAddr = "203.0.113.9".parse().unwrap();
        assert!(!trusted_location("http://203.0.113.9/d.xml", far));
    }

    #[test]
    fn a_soap_request_names_its_action_and_arguments() {
        let g = gateway_in(DESCRIPTION, "http://172.20.0.1:2189/rootDesc.xml").unwrap();
        let r = String::from_utf8(soap(
            &g,
            "AddPortMapping",
            &[("NewExternalPort", "47555".into())],
        ))
        .unwrap();
        assert!(r.starts_with("POST /ctl/IPConn HTTP/1.1\r\n"), "{r}");
        assert!(r.contains(
            "SOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\""
        ));
        assert!(r.contains("<NewExternalPort>47555</NewExternalPort>"));
        let body = r.split_once("\r\n\r\n").unwrap().1;
        assert!(r.contains(&format!("Content-Length: {}\r\n", body.len())));
    }

    /// A UPnP router on loopback: its description, and a service that keeps
    /// only mappings with no end, as some do. Says what it was asked.
    pub(crate) async fn router() -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = l.local_addr().unwrap();
        let asked = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = asked.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l.accept().await else {
                    return;
                };
                let seen = seen.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let mut got = Vec::new();
                    // the head, and as much body as it says
                    loop {
                        let n = s.read(&mut buf).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        got.extend_from_slice(&buf[..n]);
                        let text = String::from_utf8_lossy(&got).into_owned();
                        if let Some((head, body)) = text.split_once("\r\n\r\n") {
                            let len = head
                                .lines()
                                .find_map(|l| l.strip_prefix("Content-Length: "))
                                .and_then(|n| n.trim().parse::<usize>().ok())
                                .unwrap_or(0);
                            if body.len() >= len {
                                break;
                            }
                        }
                    }
                    let text = String::from_utf8_lossy(&got).into_owned();
                    seen.lock().unwrap().push(text.clone());
                    let (status, body) = if text.starts_with("GET ") {
                        ("200 OK", DESCRIPTION.to_owned())
                    } else if text.contains("#AddPortMapping")
                        && !text.contains("<NewLeaseDuration>0<")
                    {
                        let fault = "<s:Envelope><s:Body><s:Fault><detail><UPnPError><errorCode>725</errorCode>\
                                     <errorDescription>OnlyPermanentLeasesSupported</errorDescription>\
                                     </UPnPError></detail></s:Fault></s:Body></s:Envelope>";
                        ("500 Internal Server Error", fault.to_owned())
                    } else if text.contains("#AddPortMapping")
                        && text.contains("<NewExternalPort>47555<")
                    {
                        // another device has that port outside
                        let fault = "<s:Envelope><s:Body><s:Fault><detail><UPnPError>\
                                     <errorCode>718</errorCode></UPnPError></detail></s:Fault></s:Body></s:Envelope>";
                        ("500 Internal Server Error", fault.to_owned())
                    } else if text.contains("#AddPortMapping") {
                        (
                            "200 OK",
                            "<s:Envelope><s:Body></s:Body></s:Envelope>".to_owned(),
                        )
                    } else {
                        let ip = "<NewExternalIPAddress>198.51.100.7</NewExternalIPAddress>";
                        (
                            "200 OK",
                            format!("<s:Envelope><s:Body><u:x>{ip}</u:x></s:Body></s:Envelope>"),
                        )
                    };
                    let reply = format!(
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = s.write_all(reply.as_bytes()).await;
                });
            }
        });
        (format!("http://{at}/rootDesc.xml"), asked)
    }

    #[tokio::test]
    async fn a_upnp_router_gives_a_port_with_no_end_where_it_keeps_only_those() {
        let (url, asked) = router().await;
        let g = find(None, Some(url)).await.unwrap();
        let client: IpAddr = "192.168.1.20".parse().unwrap();
        let (ip, external, lifetime) = map(&g, client, 47555, 47555, 7200, None).await.unwrap();
        assert_eq!(ip.to_string(), "198.51.100.7");
        assert_eq!(
            external, 47556,
            "the port outside another device has is passed over"
        );
        assert_eq!(lifetime, 7200, "renewed as often as one with an end");
        let asked = asked.lock().unwrap();
        let adds: Vec<&String> = asked
            .iter()
            .filter(|r| r.contains("#AddPortMapping"))
            .collect();
        assert_eq!(
            adds.len(),
            3,
            "with an end, then with none, then the next port"
        );
        assert!(adds[2].contains("<NewInternalClient>192.168.1.20</NewInternalClient>"));
        assert!(adds[2].contains("<NewInternalPort>47555</NewInternalPort>"));
        assert!(adds[2].contains("<NewProtocol>UDP</NewProtocol>"));
    }

    /// Renewing asks for the port outside it holds, not the one it first
    /// wanted; one it no longer holds is taken away, not left for good.
    #[tokio::test]
    async fn a_renewal_keeps_the_port_it_holds_and_lets_go_of_one_it_does_not() {
        let (url, asked) = router().await;
        let g = find(None, Some(url)).await.unwrap();
        let client: IpAddr = "192.168.1.20".parse().unwrap();
        let (_, external, _) = map(&g, client, 47555, 47555, 7200, Some(47556))
            .await
            .unwrap();
        assert_eq!(external, 47556);
        {
            let asked = asked.lock().unwrap();
            let adds = asked
                .iter()
                .filter(|r| r.contains("#AddPortMapping"))
                .count();
            assert_eq!(adds, 2, "the held port, with an end and then without");
            assert!(!asked.iter().any(|r| r.contains("#DeletePortMapping")));
        }
        // Held 47555, which another device has now: moved, and let go of.
        let (_, external, _) = map(&g, client, 47555, 47555, 7200, Some(47555))
            .await
            .unwrap();
        assert_eq!(external, 47556);
        let asked = asked.lock().unwrap();
        let deleted: Vec<&String> = asked
            .iter()
            .filter(|r| r.contains("#DeletePortMapping"))
            .collect();
        assert_eq!(deleted.len(), 1);
        assert!(deleted[0].contains("<NewExternalPort>47555</NewExternalPort>"));
    }

    #[test]
    fn only_an_address_others_could_reach_is_the_routers_own() {
        for a in ["198.51.100.7", "8.8.8.8", "2001:db8::1"] {
            assert!(public(a.parse().unwrap()), "{a}");
        }
        for a in [
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "100.64.0.1",
            "169.254.1.1",
            "255.255.255.255",
            "0.0.0.0",
            "127.0.0.1",
            "fe80::1",
            "fd00::1",
        ] {
            assert!(!public(a.parse().unwrap()), "{a}");
        }
    }
}
