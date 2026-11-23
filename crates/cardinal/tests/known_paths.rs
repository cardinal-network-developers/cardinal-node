//! Known paths to trusted contacts' devices (D86, `hosts.md#known-paths`).
//!
//! 2026-11-23: a trusted contact's Android phone, with no host on either
//! side and on the same home Wi-Fi, could not be found until Bluetooth was
//! turned on: multicast does not carry reliably on Wi-Fi and phones. Here
//! multicast is off altogether (`--no-discovery`), and a device finds a
//! contact on its own network by a unicast probe of the subnet; and a
//! device that does not answer is checked ever less often.

mod common;

use common::*;
use serde_json::{json, Value};
use std::process::Stdio;
use std::time::Duration;

/// Starts a device at `ip` with no mount and no multicast.
fn start_at(d: &mut Dev, ip: &str) {
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(d.home.join("daemon.log"))
        .unwrap();
    let mut c = d.cmd();
    c.args(["daemon", "--no-mount", "--no-discovery", "--name", d.name])
        .arg("--listen")
        .arg(format!("{ip}:{}", d.port));
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

/// The known path to the one device a contact has.
fn path_of(d: &Dev, who: &str) -> Value {
    status_of(d, who)["devices"][0]["path"].clone()
}

/// How long a contact stays in use here, so that nobody looks for anyone
/// unasked.
const BRIEFLY: (&str, &str) = ("CARDINAL_TEST_IN_USE_SECS", "4");

/// Ana and Bo, each on loopback with no host, meet by an invitation and
/// have each other's presence secret.
fn two(root: &std::path::Path, env: &[(&str, &str)]) -> (Dev, Dev) {
    let mut ana = Dev::new(root, "ana", free_port());
    let mut bo = Dev::new(root, "bo", free_port());
    for d in [&mut ana, &mut bo] {
        d.env.push((BRIEFLY.0.into(), BRIEFLY.1.into()));
        d.env
            .extend(env.iter().map(|(k, v)| (k.to_string(), v.to_string())));
    }
    start_at(&mut ana, "127.0.0.1");
    start_at(&mut bo, "127.0.0.1");
    ana.cli(&["init", "--yes", "--name", "Ana"]);
    bo.cli(&["init", "--yes", "--name", "Bo"]);
    let at = format!("127.0.0.1:{}", ana.port);
    let code = ana.cli(&["invite", "--address", &at, "--name", "Ana"]);
    bo.cli(&["accept", code.trim(), "--name", "Ana"]);
    wait("Ana lists Bo", 30, || ana.cli(&["contacts"]).contains("Bo"));
    wait("each has the other's presence secret", 60, || {
        let a = status_of(&ana, "Bo")["nearby"].clone();
        let b = status_of(&bo, "Ana")["nearby"].clone();
        a["they_give_secret"] == true
            && a["you_give_secret"] == true
            && b["they_give_secret"] == true
            && b["you_give_secret"] == true
    });
    (ana, bo)
}

/// Every `peers.json` under `dir`: the addresses a device learned.
fn forget_addresses(dir: &std::path::Path) {
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = e.path();
        if p.is_dir() {
            forget_addresses(&p);
        } else if p.file_name().is_some_and(|n| n == "peers.json") {
            let _ = std::fs::remove_file(&p);
        }
    }
}

/// Bo's device comes back on the same network at another address, as a
/// phone given a new one by the router does, and knows nothing of Ana's.
/// Multicast carries nothing, neither names a host, and the address Ana
/// knew is dead: her last step, a probe of her own subnet, finds him.
#[test]
fn a_probe_of_the_subnet_finds_a_contact_where_multicast_does_not_carry() {
    let root = tempfile::tempdir().unwrap();
    let (mut ana, mut bo) = two(root.path(), &[]);
    wait("they are in touch", 30, || online(&ana, "Bo"));
    // Long enough that neither turns to the other any more.
    std::thread::sleep(Duration::from_secs(6));
    stop(&mut bo);
    forget_addresses(&bo.home);
    start_at(&mut bo, "127.0.0.9");
    std::thread::sleep(Duration::from_secs(3));
    assert!(
        !online(&ana, "Bo"),
        "they met some other way: the test shows nothing"
    );

    ana.cli(&["say", "Bo", "on this network?"]);
    wait("Bo reads it", 40, || {
        bo.cli(&["messages", "Ana"]).contains("on this network?")
    });
    let v = status_of(&ana, "Bo");
    let said = v.to_string();
    assert!(said.contains("probing this network"), "{v}");
    assert!(
        said.contains("found on the local network at 127.0.0.9"),
        "{v}"
    );
    // And the path follows the session to where he is now.
    wait("the path is where he is", 20, || {
        path_of(&ana, "Bo")["addr"] == format!("127.0.0.9:{}", bo.port)
    });
    stop(&mut ana);
    stop(&mut bo);
}

/// Bo's device goes away. Ana's keeps its last address and checks it with
/// a probe, waiting twice as long after each that has no answer; when Bo's
/// comes back, it reaches her at the path it knows, and her wait is the
/// usual one again.
#[test]
fn an_absent_device_is_checked_ever_less_often() {
    let root = tempfile::tempdir().unwrap();
    let (mut ana, mut bo) = two(root.path(), &[("CARDINAL_TEST_PATH_CHECK_SECS", "1")]);
    wait("they are in touch", 30, || online(&ana, "Bo"));
    wait("a confirmed path", 20, || {
        path_of(&ana, "Bo")["confirmed_s_ago"].is_u64()
    });
    std::thread::sleep(Duration::from_secs(6));
    stop(&mut bo);
    wait("three checks unanswered", 60, || {
        path_of(&ana, "Bo")["misses"].as_u64().unwrap_or(0) >= 3
    });
    let p = path_of(&ana, "Bo");
    let misses = p["misses"].as_u64().unwrap();
    assert_eq!(p["wait_s"].as_u64().unwrap(), 1 << misses, "{p}");
    assert_eq!(p["addr"], format!("127.0.0.1:{}", bo.port), "{p}");
    // A probe a check, not a flood.
    assert!(p["probes"].as_u64().unwrap() <= misses + 1, "{p}");
    let shown = ana.cli(&["contacts", "Bo"]);
    assert!(shown.contains("checks unanswered"), "{shown}");

    start_at(&mut bo, "127.0.0.1");
    wait("Bo's device reaches Ana's at the path it knows", 30, || {
        online(&ana, "Bo")
    });
    wait("the usual wait again", 10, || {
        let p = path_of(&ana, "Bo");
        p["misses"] == 0 && p["wait_s"] == 1
    });
    stop(&mut ana);
    stop(&mut bo);
}
