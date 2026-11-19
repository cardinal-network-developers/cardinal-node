//! A device asks its router for a port (PCP, RFC 6887), and says what it
//! got. The router here is a stand-in on loopback, named by
//! CARDINAL_TEST_GATEWAY, so no real router is asked.

mod common;

use common::*;
use std::net::UdpSocket;
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

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
