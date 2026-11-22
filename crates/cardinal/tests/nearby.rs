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
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
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
    let reply = common::reply(d, &req);
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
    let c = ask(&bo, json!({"cmd": "conversations"}))["conversations"][0].clone();
    assert_eq!(c["nearby"], false, "{c}");
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
        v["nearby_tries"]
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
    // Now, and only now, each is nearby to the other: a direct session on
    // the local network. Neither names a host.
    let near = |d: &Dev| {
        let c = ask(d, json!({"cmd": "conversations"}))["conversations"][0].clone();
        let l = ask(d, json!({"cmd": "contacts"}))["contacts"][0].clone();
        (c, l)
    };
    let (c, l) = near(&bo);
    assert_eq!(
        (&c["nearby"], &l["nearby"]),
        (&json!(true), &json!(true)),
        "{c}\n{l}"
    );
    assert_eq!(
        c["reach"],
        json!({"shared": false, "waiting": false, "said_no": false, "named": []}),
        "{c}"
    );
    // And they talk.
    bo.cli(&["say", "Ana", "found you"]);
    wait("Ana reads it", 30, || {
        ana.cli(&["messages", "Bo"]).contains("found you")
    });
    stop(&mut ana);
    stop(&mut bo);
}

/// Every `peers.json` under `dir`: the addresses a device learned.
fn forget_addresses(dir: &std::path::Path) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            forget_addresses(&p);
        } else if p.file_name().is_some_and(|n| n == "peers.json") {
            std::fs::remove_file(&p).unwrap();
        }
    }
}

/// 2026-11-22: after both updated to 0.1.19, the designer "lost a
/// connection with the kids' device", a trusted contact on the same LAN.
/// Two contacts on one LAN, neither with a host, on the release before;
/// one updates, and while the other is still old their sessions close for
/// what the new one cannot read, so it backs off dialling (`unreadable.rs`).
/// Then the other updates too, and comes back at an address the first has
/// never seen, its own addresses forgotten: nothing but `c=` brings them
/// together, and it does within a minute, the backoff notwithstanding.
/// Needs `CARDINAL_OLD_BIN`, the release before (0.1.18).
#[test]
fn contacts_updated_one_after_the_other_find_each_other_again_on_the_lan() {
    let Some(old) = std::env::var_os("CARDINAL_OLD_BIN") else {
        eprintln!("skipping: CARDINAL_OLD_BIN is not set");
        return;
    };
    let Some(mdns) = loopback_mdns() else {
        eprintln!("skipping: multicast on loopback is unavailable");
        return;
    };
    let root = tempfile::tempdir().unwrap();
    let mut ana = Dev::new(root.path(), "ana", free_port());
    let mut bo = Dev::new(root.path(), "bo", free_port());
    ana.bin = old.clone().into();
    bo.bin = old.into();
    start(&mut ana, Some(mdns));
    start(&mut bo, Some(mdns));
    ana.cli(&["init", "--yes", "--name", "Ana"]);
    bo.cli(&["init", "--yes", "--name", "Bo"]);
    let at = format!("127.0.0.1:{}", ana.port);
    let code = ana.cli(&["invite", "--address", &at, "--name", "Ana"]);
    bo.cli(&["accept", code.trim(), "--name", "Ana"]);
    wait("Ana lists Bo", 30, || ana.cli(&["contacts"]).contains("Bo"));
    // The old release's control socket speaks another protocol: what it
    // says of a contact is asked of its command line.
    let old_says = |d: &Dev, who: &str| -> Value {
        serde_json::from_str(&d.cli(&["contacts", who, "--json"])).unwrap_or_default()
    };
    let mut gives = (Value::Null, Value::Null);
    for _ in 0..60 {
        gives = (
            old_says(&ana, "Bo")["nearby"]["they_give_secret"].clone(),
            old_says(&bo, "Ana")["nearby"]["they_give_secret"].clone(),
        );
        if gives == (json!(true), json!(true)) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    eprintln!("on the old release, each has the other's secret: {gives:?}");

    // Bo updates; Ana, still old, keeps dialling, and their sessions close
    // unread.
    stop(&mut bo);
    bo.bin = BIN.into();
    start(&mut bo, Some(mdns));
    let mut unread = false;
    for _ in 0..90 {
        unread = status_of(&bo, "Ana")["devices"]
            .as_array()
            .is_some_and(|ds| ds.iter().any(|d| d["unreadable"].is_object()));
        if unread {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    if !unread {
        eprintln!("the old version is read: no mixed window to come back from");
    } else {
        let u = status_of(&bo, "Ana")["devices"].clone();
        eprintln!("mixed window: Bo cannot read Ana: {u}");
        // Long enough for the wait to double at least once.
        std::thread::sleep(std::time::Duration::from_secs(40));
    }

    // Ana updates, at a new address, having forgotten Bo's.
    stop(&mut ana);
    forget_addresses(&ana.home);
    ana.port = free_port();
    ana.bin = BIN.into();
    start(&mut ana, Some(mdns));
    wait("they find each other again on the LAN", 60, || {
        online(&ana, "Bo") && online(&bo, "Ana")
    });
    let found = |d: &Dev, who: &str| {
        status_of(d, who)["nearby_tries"]
            .to_string()
            .contains("found on the local network")
    };
    assert!(
        found(&ana, "Bo") || found(&bo, "Ana"),
        "{}\n{}",
        status_of(&ana, "Bo"),
        status_of(&bo, "Ana")
    );
    // and the record of what could not be read is gone once they sync
    bo.cli(&["say", "Ana", "both new"]);
    wait("Ana reads it", 30, || {
        ana.cli(&["messages", "Bo"]).contains("both new")
    });
    wait("Bo reads Ana again", 30, || {
        status_of(&bo, "Ana")["devices"]
            .as_array()
            .is_some_and(|ds| ds.iter().all(|d| d["unreadable"].is_null()))
    });
    stop(&mut ana);
    stop(&mut bo);
}
