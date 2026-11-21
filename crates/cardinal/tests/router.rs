//! A device asks its router for a port (PCP, RFC 6887), and says what it
//! got, on a network its person said is theirs (D76), and nowhere else.
//! The router here is a stand-in on loopback, named by
//! CARDINAL_TEST_GATEWAY with its hardware address in
//! CARDINAL_TEST_ROUTER_MAC, so no real router is asked.

mod common;

use common::*;
use serde_json::json;
use std::net::UdpSocket;
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const ROUTER_MAC: &str = "02:00:5e:10:00:01";

/// A router that gives every PCP MAP request 203.0.113.5:60001, counting them.
fn router() -> (u16, Arc<AtomicUsize>) {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = sock.local_addr().unwrap().port();
    let asked = Arc::new(AtomicUsize::new(0));
    let count = asked.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 1100];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            let b = &buf[..n];
            if n < 60 || b[0] != 2 || b[1] != 1 {
                continue;
            }
            count.fetch_add(1, Ordering::SeqCst);
            let mut r = vec![2, 0x81, 0, 0];
            r.extend(3600u32.to_be_bytes());
            r.extend([0; 16]);
            r.extend(&b[24..36]); // nonce
            r.extend([17, 0, 0, 0]);
            r.extend(&b[40..42]); // internal port
            r.extend(60001u16.to_be_bytes());
            let ip: std::net::Ipv4Addr = "203.0.113.5".parse().unwrap();
            r.extend(ip.to_ipv6_mapped().octets());
            let _ = sock.send_to(&r, from);
        }
    });
    (port, asked)
}

#[test]
fn a_device_asks_its_router_for_a_port_and_says_what_it_got() {
    let root = tempfile::tempdir().unwrap();
    let (at, asked) = router();
    let mut d = Dev::new(root.path(), "ana", free_port());
    d.env
        .push(("CARDINAL_TEST_GATEWAY".into(), format!("127.0.0.1:{at}")));
    d.env
        .push(("CARDINAL_TEST_ROUTER_MAC".into(), ROUTER_MAC.into()));
    let log = std::fs::File::create(d.home.join("daemon.log")).unwrap();
    // On every interface, as a device is: on loopback alone no router is asked.
    let mut child = d
        .cmd()
        .args(["daemon", "--no-discovery", "--no-mount", "--listen"])
        .arg(format!("0.0.0.0:{}", d.port))
        .stdout(Stdio::null())
        .stderr(log)
        .spawn()
        .unwrap();
    wait("the service up", 20, || {
        d.try_cli(&["status", "--json"]).status.success()
    });
    d.cli(&["init", "--yes", "--name", "Ana"]);
    d.cli(&["network", "mine"]);
    wait("a port from the router", 20, || {
        d.status()["router"]["external"] == "203.0.113.5:60001"
    });
    assert_eq!(d.status()["router"]["protocol"], "PCP");
    let said = d.cli(&["status"]);
    assert!(said.contains("203.0.113.5:60001"), "{said}");
    assert_eq!(
        asked.load(Ordering::SeqCst),
        1,
        "asked once, renewed only at half its life"
    );
    let _ = d.try_cli(&["stop"]);
    let _ = child.wait();
}

/// A UPnP router: its description, and a port for anyone who asks.
fn upnp_router() -> String {
    use std::io::{Read, Write};
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let at = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { return };
            let mut got = Vec::new();
            let mut buf = [0u8; 4096];
            s.set_read_timeout(Some(std::time::Duration::from_millis(300)))
                .unwrap();
            while let Ok(n) = s.read(&mut buf) {
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
                let t = String::from_utf8_lossy(&got);
                if t.starts_with("GET ") && t.contains("\r\n\r\n") || t.ends_with("</s:Envelope>") {
                    break;
                }
            }
            let t = String::from_utf8_lossy(&got);
            let body = if t.starts_with("GET ") {
                "<root><device><serviceList><service>\
                 <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>\
                 <controlURL>/ctl/IPConn</controlURL></service></serviceList></device></root>"
            } else if t.contains("#GetExternalIPAddress") {
                "<s:Envelope><s:Body><NewExternalIPAddress>198.51.100.7</NewExternalIPAddress></s:Body></s:Envelope>"
            } else {
                "<s:Envelope><s:Body></s:Body></s:Envelope>"
            };
            let _ = write!(
                s,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    format!("http://{at}/rootDesc.xml")
}

#[test]
fn a_router_that_speaks_only_upnp_gives_a_port_too() {
    let root = tempfile::tempdir().unwrap();
    // Says nothing to PCP or NAT-PMP, as most home routers.
    let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut d = Dev::new(root.path(), "ana", free_port());
    d.env.push((
        "CARDINAL_TEST_GATEWAY".into(),
        silent.local_addr().unwrap().to_string(),
    ));
    d.env
        .push(("CARDINAL_TEST_ROUTER_MAC".into(), ROUTER_MAC.into()));
    d.env.push(("CARDINAL_TEST_UPNP".into(), upnp_router()));
    let log = std::fs::File::create(d.home.join("daemon.log")).unwrap();
    let mut child = d
        .cmd()
        .args(["daemon", "--no-discovery", "--no-mount", "--listen"])
        .arg(format!("0.0.0.0:{}", d.port))
        .stdout(Stdio::null())
        .stderr(log)
        .spawn()
        .unwrap();
    wait("the service up", 20, || {
        d.try_cli(&["status", "--json"]).status.success()
    });
    d.cli(&["init", "--yes", "--name", "Ana"]);
    d.cli(&["network", "mine"]);
    let want = format!("198.51.100.7:{}", d.port);
    wait("a port by UPnP", 30, || {
        d.status()["router"]["external"] == want.as_str()
    });
    assert_eq!(d.status()["router"]["protocol"], "UPnP");
    let _ = d.try_cli(&["stop"]);
    let _ = child.wait();
    drop(silent);
}

/// Where the system does not say which is the gateway (Windows, Android),
/// UPnP finds the router itself.
#[test]
fn a_device_that_cannot_name_its_gateway_finds_a_upnp_router() {
    let root = tempfile::tempdir().unwrap();
    let mut d = Dev::new(root.path(), "ana", free_port());
    d.env.push(("CARDINAL_TEST_GATEWAY".into(), "none".into()));
    d.env
        .push(("CARDINAL_TEST_ROUTER_MAC".into(), ROUTER_MAC.into()));
    d.env.push(("CARDINAL_TEST_UPNP".into(), upnp_router()));
    let log = std::fs::File::create(d.home.join("daemon.log")).unwrap();
    let mut child = d
        .cmd()
        .args(["daemon", "--no-discovery", "--no-mount", "--listen"])
        .arg(format!("0.0.0.0:{}", d.port))
        .stdout(Stdio::null())
        .stderr(log)
        .spawn()
        .unwrap();
    wait("the service up", 20, || {
        d.try_cli(&["status", "--json"]).status.success()
    });
    d.cli(&["init", "--yes", "--name", "Ana"]);
    d.cli(&["network", "mine"]);
    let want = format!("198.51.100.7:{}", d.port);
    wait("a port by UPnP", 20, || {
        d.status()["router"]["external"] == want.as_str()
    });
    let _ = d.try_cli(&["stop"]);
    let _ = child.wait();
}

/// D76. On a network nobody said is theirs, the router is not asked, and
/// the device names nothing; status says to ask the person. Once they say
/// it is theirs, it is asked; said not to be, it is let go.
#[test]
fn a_router_on_a_network_not_marked_as_the_persons_is_not_asked() {
    let root = tempfile::tempdir().unwrap();
    let (at, asked) = router();
    let mut d = Dev::new(root.path(), "ana", free_port());
    d.env
        .push(("CARDINAL_TEST_GATEWAY".into(), format!("127.0.0.1:{at}")));
    d.env
        .push(("CARDINAL_TEST_ROUTER_MAC".into(), ROUTER_MAC.into()));
    d.env.push(("CARDINAL_TEST_HOLD_SECS".into(), "1".into()));
    let log = std::fs::File::create(d.home.join("daemon.log")).unwrap();
    let mut child = d
        .cmd()
        .args(["daemon", "--no-discovery", "--no-mount", "--listen"])
        .arg(format!("0.0.0.0:{}", d.port))
        .stdout(Stdio::null())
        .stderr(log)
        .spawn()
        .unwrap();
    wait("the service up", 20, || {
        d.try_cli(&["status", "--json"]).status.success()
    });
    d.cli(&["init", "--yes", "--name", "Ana"]);
    let network = &d.status()["network"];
    assert_eq!(network["router"], ROUTER_MAC, "{network}");
    assert_eq!(
        (&network["mine"], &network["answered"], &network["ask"]),
        (&json!(false), &json!(false), &json!(true)),
        "{network}"
    );
    std::thread::sleep(std::time::Duration::from_secs(4));
    assert_eq!(asked.load(Ordering::SeqCst), 0, "the router was asked");
    let r = &d.status()["router"];
    assert!(r["external"].is_null() && r["named"] == json!([]), "{r}");
    let said = d.cli(&["status"]);
    assert!(said.contains("is this your network?"), "{said}");
    let said = d.cli(&["network"]);
    assert!(said.contains("Is this your network?"), "{said}");
    // Said not to be: the same, and nothing more to ask.
    let said = d.cli(&["network", "not-mine"]);
    assert!(said.contains("is not yours"), "{said}");
    assert_eq!(d.status()["network"]["ask"], false);
    std::thread::sleep(std::time::Duration::from_secs(2));
    assert_eq!(asked.load(Ordering::SeqCst), 0, "the router was asked");
    // Said to be: asked, and named.
    d.cli(&["network", "mine", "--name", "Home"]);
    wait("a port from the router", 20, || {
        d.status()["router"]["external"] == "203.0.113.5:60001"
    });
    wait("it names itself", 20, || {
        d.status()["router"]["named"] == json!(["203.0.113.5:60001"])
    });
    assert_eq!(d.status()["network"]["name"], "Home");
    // This device's own switch: off here, and the person's left on.
    let said = d.cli(&["router", "off", "--this-device"]);
    assert!(said.contains("This device no longer"), "{said}");
    let r = &d.status()["router"];
    assert_eq!(
        (&r["on"], &r["this_device"], &r["everywhere"]),
        (&json!(false), &json!(false), &json!(true)),
        "{r}"
    );
    wait("the port is given back", 10, || {
        d.status()["router"]["external"].is_null()
    });
    let _ = d.try_cli(&["stop"]);
    let _ = child.wait();
}
