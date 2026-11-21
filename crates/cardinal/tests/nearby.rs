//! Trusted contacts find each other nearby (D74, `hosts.md#local-discovery`).
//!
//! 2026-11-19: Daniel's phone and Claude's device, on one LAN, could not
//! find each other once their invitation's session had ended. Neither had
//! a host, so neither reach node named anything the other could use. Here
//! two people meet, the session ends, and both start again with nothing
//! but local discovery: each recognizes the other's `c=` tag and connects.
//! Multicast runs on loopback, on a port of the test's own; where loopback
//! carries no multicast the test says so and passes.

mod common;

use common::*;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::os::unix::net::UnixStream;
use std::process::Stdio;

/// A port for multicast on loopback, if loopback carries it here.
fn loopback_mdns() -> Option<u16> {
    let port = free_port();
    let group = Ipv4Addr::new(224, 0, 0, 251);
    let open = || -> std::io::Result<UdpSocket> {
        let s = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        s.set_reuse_address(true)?;
        s.set_reuse_port(true)?;
        s.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)).into())?;
        s.join_multicast_v4(&group, &Ipv4Addr::LOCALHOST)?;
        s.set_multicast_if_v4(&Ipv4Addr::LOCALHOST)?;
        s.set_multicast_loop_v4(true)?;
        Ok(s.into())
    };
    let (a, b) = (open().ok()?, open().ok()?);
    b.set_read_timeout(Some(std::time::Duration::from_millis(500)))
        .ok()?;
    a.send_to(b"probe", (group, port)).ok()?;
    let mut buf = [0u8; 16];
    matches!(b.recv_from(&mut buf), Ok((5, _))).then_some(port)
}

/// Starts a device on loopback with no mount; with LAN discovery on
/// `mdns` if given, else none.
fn start(d: &mut Dev, mdns: Option<u16>) {
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(d.home.join("daemon.log"))
        .unwrap();
    let mut c = d.cmd();
    c.args(["daemon", "--no-mount", "--name", d.name])
        .arg("--listen")
        .arg(format!("127.0.0.1:{}", d.port));
    match mdns {
        Some(port) => {
            c.arg("--mdns-port").arg(port.to_string());
            c.env("CARDINAL_TEST_MDNS_INTERFACE", "127.0.0.1");
        }
        None => {
            c.arg("--no-discovery");
        }
    }
    let child = c.stdout(Stdio::null()).stderr(log).spawn().unwrap();
    d.child = Some(child);
    wait("the service up", 20, || {
        d.try_cli(&["status"]).status.success()
    });
}

fn stop(d: &mut Dev) {
    let _ = d.try_cli(&["stop"]);
    if let Some(mut c) = d.child.take() {
        let _ = c.wait();
    }
}

fn ask(d: &Dev, req: Value) -> Value {
    let mut s = UnixStream::connect(d.home.join("control.sock")).unwrap();
    writeln!(s, "{req}").unwrap();
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).unwrap();
    let reply: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(reply["ok"], true, "{req} got {reply}");
    reply
}

fn status_of(d: &Dev, who: &str) -> Value {
    ask(d, json!({"cmd": "contact-status", "who": who}))
}

fn online(d: &Dev, who: &str) -> bool {
    let v = status_of(d, who);
    let devices = v["devices"].as_array().cloned().unwrap_or_default();
    devices.iter().any(|x| x["online"] == true)
}

#[test]
fn trusted_contacts_with_no_host_find_each_other_on_the_local_network() {
    let Some(mdns) = loopback_mdns() else {
        eprintln!("skipping: multicast on loopback is unavailable");
        return;
    };
    let root = tempfile::tempdir().unwrap();
    let mut ana = Dev::new(root.path(), "ana", free_port());
    let mut bo = Dev::new(root.path(), "bo", free_port());
    start(&mut ana, None);
    start(&mut bo, None);
    ana.cli(&["init", "--yes", "--name", "Ana"]);
    bo.cli(&["init", "--yes", "--name", "Bo"]);
    let code = ana.cli(&[
        "invite",
        "--address",
        &format!("127.0.0.1:{}", ana.port),
        "--name",
        "Ana",
    ]);
    bo.cli(&["accept", code.trim(), "--name", "Ana"]);
    wait("Ana lists Bo", 30, || ana.cli(&["contacts"]).contains("Bo"));
    // Each gives the other its presence secret in the relationship, and
    // each device has what the other gave.
    wait("each has the other's presence secret", 60, || {
        let a = status_of(&ana, "Bo")["nearby"].clone();
        let b = status_of(&bo, "Ana")["nearby"].clone();
        a["they_give_secret"] == true
            && a["you_give_secret"] == true
            && b["they_give_secret"] == true
            && b["you_give_secret"] == true
    });
    // Neither names a host the other could use.
    assert!(status_of(&bo, "Ana")["their_reach"]
        .as_array()
        .is_none_or(|r| r.is_empty()));

    // The invitation's session ends, and each comes back at an address
    // the other has never seen, as a phone does on a network it joins
    // again. Without local discovery nothing brings them together: that
    // was 2026-11-19.
    stop(&mut ana);
    stop(&mut bo);
    ana.port = free_port();
    bo.port = free_port();
    start(&mut ana, None);
    start(&mut bo, None);
    bo.cli(&["say", "Ana", "anyone there?"]);
    std::thread::sleep(std::time::Duration::from_secs(8));
    assert!(
        !online(&ana, "Bo") && !online(&bo, "Ana"),
        "they met without discovery: the test shows nothing"
    );
    // Both come back with local discovery.
    stop(&mut ana);
    stop(&mut bo);
    start(&mut ana, Some(mdns));
    start(&mut bo, Some(mdns));
    wait("they find each other", 60, || {
        online(&ana, "Bo") && online(&bo, "Ana")
    });
    // Whoever dialled says so in the trail.
    let said = |d: &Dev, who: &str| {
        let v = status_of(d, who);
        v["last_look"]
            .to_string()
            .contains("found on the local network")
    };
    assert!(
        said(&ana, "Bo") || said(&bo, "Ana"),
        "{}\n{}",
        status_of(&ana, "Bo"),
        status_of(&bo, "Ana")
    );
    let shown = bo.cli(&["contacts", "Ana"]);
    let shown2 = ana.cli(&["contacts", "Bo"]);
    assert!(
        shown.contains("found on the local network")
            || shown2.contains("found on the local network"),
        "{shown}\n{shown2}"
    );
    // And they talk.
    bo.cli(&["say", "Ana", "found you"]);
    wait("Ana reads it", 30, || {
        ana.cli(&["messages", "Bo"]).contains("found you")
    });
    stop(&mut ana);
    stop(&mut bo);
}
