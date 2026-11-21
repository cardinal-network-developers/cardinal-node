//! A device that can be reached names itself as a host (D72): the router
//! gives it a port outside, and its trusted contacts are told the address
//! in the reach node of the relationship. `cardinal router off` takes it
//! out again. A mapping that leads where another of the person's devices
//! is reached is given back, and another port asked for. The router here is
//! a stand-in on loopback, named by CARDINAL_TEST_GATEWAY, as in router.rs;
//! nothing reaches the address it gives, so these show what is written and
//! said, not a connection through it (scripts/lab.py `mapped` does that).

mod common;

use common::*;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::net::UdpSocket;
use std::os::unix::net::UnixStream;
use std::process::Stdio;
use std::sync::{Arc, Mutex};

/// What a stand-in router was asked: (port outside asked for, lifetime).
type Asked = Arc<Mutex<Vec<(u16, u32)>>>;

/// A PCP router that gives 203.0.113.5 with the port outside asked for,
/// and forgets a mapping given back (lifetime 0).
fn router() -> (u16, Asked) {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = sock.local_addr().unwrap().port();
    let asked: Asked = Default::default();
    let log = asked.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 1100];
        // internal port -> port outside, while mapped
        let mut held: std::collections::HashMap<[u8; 2], [u8; 2]> = Default::default();
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            let b = &buf[..n];
            if n < 60 || b[0] != 2 || b[1] != 1 {
                continue;
            }
            let lifetime = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
            let internal: [u8; 2] = [b[40], b[41]];
            let wanted: [u8; 2] = [b[42], b[43]];
            log.lock()
                .unwrap()
                .push((u16::from_be_bytes(wanted), lifetime));
            let outside = if lifetime == 0 {
                held.remove(&internal).unwrap_or(wanted)
            } else {
                *held.entry(internal).or_insert(wanted)
            };
            let mut r = vec![2, 0x81, 0, 0];
            r.extend(lifetime.min(3600).to_be_bytes());
            r.extend([0; 16]);
            r.extend(&b[24..36]); // nonce
            r.extend([17, 0, 0, 0]);
            r.extend(internal);
            r.extend(outside);
            let ip: std::net::Ipv4Addr = "203.0.113.5".parse().unwrap();
            r.extend(ip.to_ipv6_mapped().octets());
            let _ = sock.send_to(&r, from);
        }
    });
    (port, asked)
}

/// The stand-in router's hardware address.
const ROUTER_MAC: &str = "02:00:5e:10:00:01";

/// The person says this is their network: only there is the router asked
/// (D76).
fn mine(d: &Dev) {
    let said = d.cli(&["network", "mine", "--name", "Home"]);
    assert!(said.contains("is yours"), "{said}");
}

/// A device on every interface, as a device is (on loopback alone no
/// router is asked), with the stand-in router as its gateway.
fn start_behind(d: &mut Dev, router: u16) {
    d.env.push((
        "CARDINAL_TEST_GATEWAY".into(),
        format!("127.0.0.1:{router}"),
    ));
    // An address is named once the router has given it this long.
    d.env.push(("CARDINAL_TEST_HOLD_SECS".into(), "2".into()));
    // The router's hardware address, which knows the network (D76).
    d.env
        .push(("CARDINAL_TEST_ROUTER_MAC".into(), ROUTER_MAC.into()));
    let log = std::fs::File::create(d.home.join("daemon.log")).unwrap();
    let child = d
        .cmd()
        .args(["daemon", "--no-discovery", "--no-mount", "--name", d.name])
        .arg("--listen")
        .arg(format!("0.0.0.0:{}", d.port))
        .stdout(Stdio::null())
        .stderr(log)
        .spawn()
        .unwrap();
    d.child = Some(child);
    wait("the service up", 20, || {
        d.try_cli(&["status"]).status.success()
    });
}

fn start_here(d: &mut Dev) {
    let log = std::fs::File::create(d.home.join("daemon.log")).unwrap();
    let child = d
        .cmd()
        .args(["daemon", "--no-discovery", "--no-mount", "--name", d.name])
        .arg("--listen")
        .arg(format!("127.0.0.1:{}", d.port))
        .stdout(Stdio::null())
        .stderr(log)
        .spawn()
        .unwrap();
    d.child = Some(child);
    wait("the service up", 20, || {
        d.try_cli(&["status"]).status.success()
    });
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

/// The endpoints Bo's device reads in Ana's reach node.
fn their_reach(b: &Dev) -> Vec<String> {
    let v = ask(b, json!({"cmd": "contact-status", "who": "Ana"}));
    v["their_reach"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|r| r["endpoints"].as_array().cloned().unwrap_or_default())
        .filter_map(|e| e["endpoint"].as_str().map(str::to_owned))
        .collect()
}

#[test]
fn a_device_the_router_gives_a_port_names_itself_to_a_trusted_contact() {
    let root = tempfile::tempdir().unwrap();
    let (at, _) = router();
    let mut a = Dev::new(root.path(), "ana", free_port());
    start_behind(&mut a, at);
    a.cli(&["init", "--yes", "--name", "Ana"]);
    mine(&a);
    let want = format!("203.0.113.5:{}", a.port);
    wait("a port from the router", 20, || {
        a.status()["router"]["external"] == want.as_str()
    });
    wait("it names itself", 20, || {
        a.status()["router"]["named"] == json!([want])
    });
    let said = a.cli(&["status"]);
    assert!(
        said.contains(&format!("named as a host at {want}")),
        "{said}"
    );
    // No restore comes from it: it is not on the recovery sheet.
    assert_eq!(a.status()["hosts"], 0);

    let mut b = Dev::new(root.path(), "bo", free_port());
    start_here(&mut b);
    b.cli(&["init", "--yes", "--name", "Bo"]);
    let code = a.cli(&[
        "invite",
        "--address",
        &format!("127.0.0.1:{}", a.port),
        "--name",
        "Ana",
    ]);
    b.cli(&["accept", code.trim(), "--name", "Ana"]);
    wait("Bo reads the address in Ana's reach node", 60, || {
        their_reach(&b) == [want.clone()]
    });

    // Turned off, it takes itself out, and says so.
    let said = a.cli(&["router", "off"]);
    assert!(said.contains("not asked for a port"), "{said}");
    wait("it is no longer named", 60, || their_reach(&b).is_empty());
    let r = &a.status()["router"];
    assert_eq!(r["on"], false, "{r}");
    assert_eq!(r["named"], json!([]), "{r}");
    // The port is given back at the loop's next look, within a second.
    wait("the port is given back", 10, || {
        a.status()["router"]["external"].is_null()
    });
    let said = a.cli(&["router"]);
    assert!(said.contains("`cardinal router on`"), "{said}");
    let _ = a.try_cli(&["stop"]);
    let _ = b.try_cli(&["stop"]);
    if let Some(mut c) = a.child.take() {
        let _ = c.wait();
    }
    if let Some(mut c) = b.child.take() {
        let _ = c.wait();
    }
}

#[test]
fn a_contact_who_is_not_trusted_is_not_told() {
    let root = tempfile::tempdir().unwrap();
    let (at, _) = router();
    let mut a = Dev::new(root.path(), "ana", free_port());
    start_behind(&mut a, at);
    a.cli(&["init", "--yes", "--name", "Ana"]);
    mine(&a);
    let want = format!("203.0.113.5:{}", a.port);
    wait("it names itself", 20, || {
        a.status()["router"]["named"] == json!([want])
    });
    let mut b = Dev::new(root.path(), "bo", free_port());
    start_here(&mut b);
    b.cli(&["init", "--yes", "--name", "Bo"]);
    let code = a.cli(&[
        "invite",
        "--address",
        &format!("127.0.0.1:{}", a.port),
        "--name",
        "Ana",
        "--hosts-only",
    ]);
    b.cli(&["accept", code.trim(), "--name", "Ana"]);
    wait("Ana lists Bo", 30, || a.cli(&["contacts"]).contains("Bo"));
    // Long enough for several looks at the list.
    std::thread::sleep(std::time::Duration::from_secs(5));
    assert!(their_reach(&b).is_empty(), "{:?}", their_reach(&b));
    for d in [&mut a, &mut b] {
        let _ = d.try_cli(&["stop"]);
        if let Some(mut c) = d.child.take() {
            let _ = c.wait();
        }
    }
}

/// On the home pfSense a mapping of the port a host's forward had led to
/// the host: such a mapping is given back, and another port asked for.
#[test]
fn a_mapping_where_another_device_is_reached_is_given_back() {
    // Pairing mounts the files.
    if !fuse_available() {
        eprintln!("skipped: no FUSE");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (at, asked) = router();
    let mut host = Dev::new(root.path(), "host", free_port());
    host.start();
    host.cli(&["init", "--yes", "--name", "Ana"]);
    let mut laptop = Dev::new(root.path(), "laptop", free_port());
    // The router's forward of this port leads to the host.
    let forward = format!("203.0.113.5:{}", laptop.port);
    host.cli(&[
        "host",
        "--address",
        &format!("127.0.0.1:{}", host.port),
        "--address",
        &forward,
    ]);
    laptop.start();
    pair(&host, &laptop);
    wait("the laptop knows the host's grant", 30, || {
        laptop.cli(&["recovery", "sheet"]).contains(&forward)
    });
    laptop.stop();
    start_behind(&mut laptop, at);
    mine(&laptop);
    let mut external = String::new();
    wait("a port from the router", 30, || {
        external = laptop.status()["router"]["external"]
            .as_str()
            .unwrap_or("")
            .to_owned();
        !external.is_empty()
    });
    assert_ne!(external, forward, "the mapping leads to the host");
    assert!(external.starts_with("203.0.113.5:"), "{external}");
    let asked = asked.lock().unwrap().clone();
    assert!(
        asked.contains(&(laptop.port, 0)),
        "the mapping was not given back: {asked:?}"
    );
    for d in [&mut host, &mut laptop] {
        let _ = d.try_cli(&["stop"]);
        if let Some(mut c) = d.child.take() {
            let _ = c.wait();
        }
    }
}

#[test]
fn a_host_given_only_a_name_is_warned_that_contacts_cannot_use_it() {
    let root = tempfile::tempdir().unwrap();
    let mut a = Dev::new(root.path(), "ana", free_port());
    start_here(&mut a);
    a.cli(&["init", "--yes", "--name", "Ana"]);
    let named = format!("saint-joseph.home:{}", a.port);
    let said = a.cli(&["host", "--address", &named]);
    assert!(said.contains(&format!("{named} is a name")), "{said}");
    assert!(said.contains("Give the address"), "{said}");
    let _ = a.try_cli(&["stop"]);
    if let Some(mut c) = a.child.take() {
        let _ = c.wait();
    }
}

/// Review L2. `cardinal router off` on one device is the person's switch:
/// another device of theirs gives its port back, and asks again once it
/// is turned on, from any device.
#[test]
fn the_router_switch_set_on_one_device_holds_on_another() {
    if !fuse_available() {
        eprintln!("skipped: no FUSE");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (at, _) = router();
    let mut desk = Dev::new(root.path(), "desk", free_port());
    desk.start();
    desk.cli(&["init", "--yes", "--name", "Ana"]);
    let mut laptop = Dev::new(root.path(), "laptop", free_port());
    laptop.start();
    pair(&desk, &laptop);
    laptop.stop();
    start_behind(&mut laptop, at);
    mine(&laptop);
    let given = |d: &Dev| !d.status()["router"]["external"].is_null();
    wait("a port from the router", 30, || given(&laptop));
    desk.cli(&["router", "off"]);
    wait("the laptop gives its port back", 60, || !given(&laptop));
    assert_eq!(laptop.status()["router"]["on"], false);
    desk.cli(&["router", "on"]);
    wait("the laptop asks again", 60, || given(&laptop));
    for d in [&mut desk, &mut laptop] {
        let _ = d.try_cli(&["stop"]);
        if let Some(mut c) = d.child.take() {
            let _ = c.wait();
        }
    }
}
