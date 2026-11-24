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
use std::net::UdpSocket;
use std::process::Stdio;
use std::sync::{Arc, Mutex};

/// What a stand-in router was asked: (port outside asked for, lifetime).
type Asked = Arc<Mutex<Vec<(u16, u32)>>>;

/// A PCP router that gives 203.0.113.5 with the port outside asked for,
/// and forgets a mapping given back (lifetime 0).
fn router() -> (u16, Asked) {
    router_with(None, false)
}

/// A stand-in router as [`router`], that gives only the port outside
/// `fixed`, if named, as when a forward set up by hand holds every other,
/// or says no to everything with PCP result 2 (NOT_AUTHORIZED), as the
/// home pfSense did to the NUC whose port it forwards by hand.
fn router_with(fixed: Option<u16>, refuse: bool) -> (u16, Asked) {
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
            let wanted = fixed.map_or(wanted, u16::to_be_bytes);
            let outside = if lifetime == 0 {
                held.remove(&internal).unwrap_or(wanted)
            } else {
                *held.entry(internal).or_insert(wanted)
            };
            let mut r = vec![2, 0x81, 0, if refuse { 2 } else { 0 }];
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
    let reply = common::reply(d, &req);
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
    // It is the always-on device all the same, keeping mail, as `status`
    // and `hosting` both say.
    wait("status counts it", 20, || {
        a.status()["always_on"] == json!(["ana"])
    });
    let said = a.cli(&["status"]);
    assert!(
        said.contains("Always-on device: ana, reachable from outside"),
        "{said}"
    );
    assert!(!said.contains("none yet"), "{said}");
    let h = ask(&a, json!({"cmd": "hosting"}));
    let own = h["devices"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|d| d["name"] == "ana")
        .cloned();
    assert_eq!(
        own.as_ref().map(|d| d["outside"].clone()),
        Some(json!(true)),
        "{h}"
    );

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
    // Her conversation with Bo says which of her devices it names, by the
    // name `no-host` takes.
    let c = ask(&a, json!({"cmd": "conversations"}))["conversations"][0].clone();
    assert_eq!(
        c["reach"],
        json!({"shared": true, "waiting": false, "said_no": false, "named": ["ana"]}),
        "{c}"
    );

    // Turned off, it takes itself out, and says so.
    let said = a.cli(&["router", "off"]);
    assert!(said.contains("not asked for a port"), "{said}");
    wait("it is no longer named", 60, || their_reach(&b).is_empty());
    let r = &a.status()["router"];
    assert_eq!(r["on"], false, "{r}");
    assert_eq!(r["named"], json!([]), "{r}");
    // and drops back: no longer the always-on device, nor keeping mail
    assert_eq!(a.status()["always_on"], json!([]));
    assert!(a.cli(&["status"]).contains("Always-on device: none yet"));
    let h = ask(&a, json!({"cmd": "hosting"}));
    assert!(
        h["devices"]
            .as_array()
            .into_iter()
            .flatten()
            .all(|d| d["outside"] != true),
        "{h}"
    );
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

/// A router that lets no application open a port says so in plain words.
#[test]
fn a_router_that_lets_no_app_open_ports_is_said_so_plainly() {
    let root = tempfile::tempdir().unwrap();
    let (at, _) = router_with(None, true);
    let mut a = Dev::new(root.path(), "ana", free_port());
    start_behind(&mut a, at);
    a.cli(&["init", "--yes", "--name", "Ana"]);
    mine(&a);
    let plain = "your router doesn't let apps open ports: set up a forward by hand, \
                 or turn on PCP/UPnP in the router";
    wait("the router's no", 20, || {
        a.status()["router"]["error"] == plain
    });
    let said = a.cli(&["status"]);
    assert!(
        said.contains(&format!("Router: gives no port: {plain}.")),
        "{said}"
    );
    assert!(!said.contains("PCP result"), "{said}");
    assert_eq!(a.status()["router"]["named"], json!([]));
    let _ = a.try_cli(&["stop"]);
    if let Some(mut c) = a.child.take() {
        let _ = c.wait();
    }
}

/// A router whose only port is forwarded by hand to another of the
/// person's devices: this one gets none, and `status` says where it goes.
#[test]
fn a_port_forwarded_to_another_device_is_said_so_plainly() {
    if !fuse_available() {
        eprintln!("skipped: no FUSE");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut host = Dev::new(root.path(), "host", free_port());
    host.start();
    host.cli(&["init", "--yes", "--name", "Ana"]);
    let mut laptop = Dev::new(root.path(), "laptop", free_port());
    let forwarded = free_port();
    let (at, _) = router_with(Some(forwarded), false);
    let forward = format!("203.0.113.5:{forwarded}");
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
    let want = format!("port {forwarded} is forwarded to host; this device gets none");
    wait("the router's answer", 30, || {
        laptop.status()["router"]["error"] == want.as_str()
    });
    assert!(laptop.status()["router"]["external"].is_null());
    let said = laptop.cli(&["status"]);
    assert!(said.contains(&want), "{said}");
    for d in [&mut host, &mut laptop] {
        let _ = d.try_cli(&["stop"]);
        if let Some(mut c) = d.child.take() {
            let _ = c.wait();
        }
    }
}
