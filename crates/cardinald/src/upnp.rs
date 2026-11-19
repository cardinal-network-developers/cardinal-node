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
    Some((at, path))
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
    let base = tag(description, "URLBase")
        .and_then(split_url)
        .map(|(at, _)| at);
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
            let (at, path) = match split_url(control) {
                Some(whole) => whole,
                None => {
                    let path = if control.starts_with('/') {
                        control.to_owned()
                    } else {
                        format!("/{control}")
                    };
                    (base.unwrap_or(from_at), path)
                }
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

/// Asks the router's service for UDP `port`, the same outside, for this
/// device at `client`, and for the router's external address. A router
/// that keeps only mappings with no end is asked for one: renewing it
/// changes nothing.
pub async fn map(
    g: &Gateway,
    client: IpAddr,
    port: u16,
    lifetime: u32,
) -> Result<(IpAddr, u32), String> {
    let mut lease = lifetime;
    loop {
        let add = soap(
            g,
            "AddPortMapping",
            &[
                ("NewRemoteHost", String::new()),
                ("NewExternalPort", port.to_string()),
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
        let what = tag(&body, "errorDescription").unwrap_or("");
        return Err(format!("the router said no (UPnP {code} {what})").replace("  ", " "));
    }
    let (status, body) = exchange(g.at, &soap(g, "GetExternalIPAddress", &[])).await?;
    let ip = tag(&body, "NewExternalIPAddress")
        .and_then(|a| a.parse().ok())
        .filter(|_| status == 200)
        .ok_or("the router mapped the port but did not say its own address")?;
    // No end: asked again as often as one that has one, to stay mapped.
    Ok((ip, if lease == 0 { lifetime } else { lease }))
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
        let (ip, lifetime) = map(&g, client, 47555, 7200).await.unwrap();
        assert_eq!(ip.to_string(), "198.51.100.7");
        assert_eq!(lifetime, 7200, "renewed as often as one with an end");
        let asked = asked.lock().unwrap();
        let adds: Vec<&String> = asked
            .iter()
            .filter(|r| r.contains("#AddPortMapping"))
            .collect();
        assert_eq!(adds.len(), 2, "with an end, then with none");
        assert!(adds[1].contains("<NewInternalClient>192.168.1.20</NewInternalClient>"));
        assert!(adds[1].contains("<NewProtocol>UDP</NewProtocol>"));
    }
}
