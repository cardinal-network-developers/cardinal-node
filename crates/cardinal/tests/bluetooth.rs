//! Bluetooth Low Energy (`carriers/ble.md`, D74): two people with their
//! phones and nothing else, on a mountaintop, find each other, sync and
//! write. No radio is opened: the services run as they would, with radios
//! that meet in a directory of the test's own (`CARDINAL_TEST_BLE_ETHER`),
//! and channels that are Unix sockets there. No multicast, no host, and no
//! address either knows of the other once they have met.

mod common;

use common::*;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Stdio;

/// A device whose radio is in `ether`.
fn dev(root: &Path, name: &'static str, ether: &Path) -> Dev {
    let mut d = Dev::new(root, name, free_port());
    d.env.push((
        "CARDINAL_TEST_BLE_ETHER".into(),
        ether.display().to_string(),
    ));
    d
}

/// Starts a device on loopback with no mount and no LAN discovery.
fn start(d: &mut Dev) {
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(d.home.join("daemon.log"))
        .unwrap();
    let mut c = d.cmd();
    c.args(["daemon", "--no-mount", "--no-discovery", "--name", d.name])
        .arg("--listen")
        .arg(format!("127.0.0.1:{}", d.port));
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

fn bluetooth(d: &Dev) -> Value {
    ask(d, json!({"cmd": "bluetooth"}))
}

fn status_of(d: &Dev, who: &str) -> Value {
    ask(d, json!({"cmd": "contact-status", "who": who}))
}

fn online(d: &Dev, who: &str) -> bool {
    let v = status_of(d, who);
    let devices = v["devices"].as_array().cloned().unwrap_or_default();
    devices.iter().any(|x| x["online"] == true)
}

/// Turns Bluetooth on, open or closed, and waits for the radio.
fn always(d: &Dev) {
    let said = d.cli(&["bluetooth", "always"]);
    assert!(said.contains("Bluetooth is on"), "{said}");
    wait("the radio on", 20, || bluetooth(d)["on"] == true);
}

/// Ana invites Bo, who reaches her only over Bluetooth: the invitation's
/// address leads nowhere.
fn meet(ana: &Dev, bo: &Dev) {
    let code = ana.cli(&["invite", "--address", "127.0.0.1:1", "--name", "Ana"]);
    let o = bo.try_cli(&["accept", code.trim(), "--name", "Ana"]);
    assert!(
        o.status.success(),
        "{}{}\n{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr),
        bo.log()
    );
    wait("Ana lists Bo", 30, || ana.cli(&["contacts"]).contains("Bo"));
    wait("each has the other's presence secret", 60, || {
        let a = status_of(ana, "Bo")["nearby"].clone();
        let b = status_of(bo, "Ana")["nearby"].clone();
        a["they_give_secret"] == true && b["they_give_secret"] == true
    });
}

#[test]
fn two_people_with_no_network_meet_sync_and_write_over_bluetooth() {
    let root = tempfile::tempdir().unwrap();
    let ether = root.path().join("ether");
    let mut ana = dev(root.path(), "ana", &ether);
    let mut bo = dev(root.path(), "bo", &ether);
    start(&mut ana);
    start(&mut bo);
    ana.cli(&["init", "--yes", "--name", "Ana"]);
    bo.cli(&["init", "--yes", "--name", "Bo"]);
    // Off by default, and nothing is advertised.
    let b = bluetooth(&ana);
    assert_eq!(
        (b["mode"].clone(), b["on"].clone()),
        (json!("off"), json!(false))
    );
    assert_eq!(
        std::fs::read_dir(ether.join("ads"))
            .map(|d| d.count())
            .unwrap_or(0),
        0
    );
    // With it off, the invitation cannot be taken up.
    let code = ana.cli(&["invite", "--address", "127.0.0.1:1", "--name", "Ana"]);
    assert!(!bo.try_cli(&["accept", code.trim()]).status.success());
    always(&ana);
    always(&bo);
    let b = bluetooth(&ana);
    assert_eq!(b["available"], true, "{b}");
    assert!(ana
        .cli(&["status"])
        .contains("Bluetooth: on, open or closed"));

    // An invitation over Bluetooth: Bo finds Ana by the tag its secret makes.
    meet(&ana, &bo);
    assert!(
        bo.log()
            .contains("looking for whoever made the invitation over Bluetooth"),
        "{}",
        bo.log()
    );

    // Both come back at addresses neither has seen. Over Bluetooth alone,
    // each recognizes the other's tag, and they reconnect.
    stop(&mut ana);
    stop(&mut bo);
    ana.port = free_port();
    bo.port = free_port();
    start(&mut ana);
    start(&mut bo);
    wait("they find each other over Bluetooth", 60, || {
        online(&ana, "Bo") && online(&bo, "Ana")
    });
    let said = |d: &Dev, who: &str| {
        status_of(d, who)["nearby_tries"]
            .to_string()
            .contains("found over Bluetooth")
    };
    assert!(
        said(&ana, "Bo") || said(&bo, "Ana"),
        "{}\n{}",
        status_of(&ana, "Bo"),
        status_of(&bo, "Ana")
    );
    let shown = format!(
        "{}{}",
        ana.cli(&["contacts", "Bo"]),
        bo.cli(&["contacts", "Ana"])
    );
    assert!(shown.contains("Bluetooth"), "{shown}");
    // They write, and what each wrote syncs.
    bo.cli(&["say", "Ana", "on the summit"]);
    wait("Ana reads it", 30, || {
        ana.cli(&["messages", "Bo"]).contains("on the summit")
    });
    ana.cli(&["say", "Bo", "the view!"]);
    wait("Bo reads it", 30, || {
        bo.cli(&["messages", "Ana"]).contains("the view!")
    });

    // Bluetooth off: the radio stops, and its advertisement goes.
    let said = bo.cli(&["bluetooth", "off"]);
    assert!(said.contains("off"), "{said}");
    wait("Bo's radio off", 20, || bluetooth(&bo)["on"] == false);
    stop(&mut ana);
    stop(&mut bo);
}

#[test]
fn a_strangers_advertisement_is_seen_and_ignored() {
    let root = tempfile::tempdir().unwrap();
    let ether = root.path().join("ether");
    let mut ana = dev(root.path(), "ana", &ether);
    let mut cy = dev(root.path(), "cy", &ether);
    start(&mut ana);
    start(&mut cy);
    ana.cli(&["init", "--yes", "--name", "Ana"]);
    cy.cli(&["init", "--yes", "--name", "Cy"]);
    always(&ana);
    always(&cy);
    // Each hears the other, and neither recognizes anything.
    wait("each sees the other", 30, || {
        bluetooth(&ana)["seen"].as_u64() > Some(2) && bluetooth(&cy)["seen"].as_u64() > Some(2)
    });
    std::thread::sleep(std::time::Duration::from_secs(3));
    for d in [&ana, &cy] {
        let b = bluetooth(d);
        assert_eq!(b["recognized"], 0, "{b}");
        assert_eq!(b["channels_in"], 0, "nobody opened a channel: {b}");
    }
    assert!(ana.cli(&["contacts"]).lines().all(|l| !l.contains("Cy")));
    stop(&mut ana);
    stop(&mut cy);
}

/// Pairs `b` to `a` over loopback, as `pair` does, with neither mounted.
fn pair_unmounted(a: &Dev, b: &Dev) {
    let mut shower = b
        .cmd()
        .arg("pair")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut out = BufReader::new(shower.stdout.take().unwrap());
    let (mut code, mut at) = (None, None);
    let mut line = String::new();
    while code.is_none() || at.is_none() {
        line.clear();
        assert!(out.read_line(&mut line).unwrap() > 0, "pair ended early");
        let l = line.trim();
        if let Some(c) = l.strip_prefix("cardinal pair ") {
            code = Some(c.to_owned());
        }
        if let Some(i) = l.find("--at ") {
            let rest = &l[i + 5..];
            let port = rest
                .trim_end_matches(|c: char| !c.is_ascii_digit())
                .rsplit(':')
                .next()
                .unwrap();
            at = Some(format!("127.0.0.1:{port}"));
        }
    }
    let typed = a.cli(&["pair", &code.unwrap(), "--at", &at.unwrap()]);
    assert!(typed.contains("Added"), "{typed}");
    let mut rest = String::new();
    std::io::Read::read_to_string(&mut out, &mut rest).unwrap();
    assert!(shower.wait().unwrap().success(), "{rest}");
}

#[test]
fn own_devices_find_each_other_over_bluetooth() {
    let root = tempfile::tempdir().unwrap();
    let ether = root.path().join("ether");
    let mut a = dev(root.path(), "laptop", &ether);
    let mut b = dev(root.path(), "phone", &ether);
    start(&mut a);
    start(&mut b);
    a.cli(&["init", "--yes", "--name", "Ana"]);
    pair_unmounted(&a, &b);
    always(&a);
    always(&b);
    stop(&mut a);
    stop(&mut b);
    a.port = free_port();
    b.port = free_port();
    start(&mut a);
    start(&mut b);
    wait("they find each other over Bluetooth", 60, || {
        a.log().contains("over Bluetooth, at") || b.log().contains("over Bluetooth, at")
    });
    let v = ask(&a, json!({"cmd": "devices"}));
    let shown = v.to_string();
    assert!(shown.contains("Bluetooth"), "{shown}");
    // Over Bluetooth is not as good as over IP: once the phone knows where
    // the laptop listens, it dials there, and that session (UDP or TCP)
    // replaces the one over Bluetooth (review M6).
    b.cli(&["peer", "add", &format!("127.0.0.1:{}", a.port)]);
    let moved = (0..60).any(|_| {
        if over_ip(&b, "laptop") {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
        false
    });
    assert!(
        moved,
        "the session moves to IP: {}\n{}",
        ask(&b, json!({"cmd": "devices"})),
        b.log()
    );
    stop(&mut a);
    stop(&mut b);
}

/// How a device's session with the device named `name` runs.
fn carrier_of(d: &Dev, name: &str) -> Option<String> {
    let v = ask(d, json!({"cmd": "devices"}));
    v["devices"]
        .as_array()?
        .iter()
        .find(|x| x["name"] == name)?["carrier"]
        .as_str()
        .map(str::to_owned)
}

/// Whether a device's session with `name` runs directly over IP.
fn over_ip(d: &Dev, name: &str) -> bool {
    matches!(carrier_of(d, name).as_deref(), Some("UDP" | "TCP"))
}

/// An address in the ether nobody else uses.
fn fake_addr(i: u32) -> String {
    format!("c0ffee{i:06x}r")
}

/// Advertises `data` from `addr`, with a listener on `psm` there that takes
/// channels and says nothing on them: someone who recorded another's
/// advertisement plays it again.
fn replay(ether: &Path, addr: &str, psm: u16, data: &[u8]) -> std::thread::JoinHandle<()> {
    let sock = ether.join("l2cap").join(format!("{addr}-{psm}"));
    let _ = std::fs::remove_file(&sock);
    let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    std::fs::write(ether.join("ads").join(addr), data).unwrap();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for s in listener.incoming().flatten() {
            held.push(s);
        }
    })
}

#[test]
fn a_replayed_tag_of_ones_own_devices_does_not_keep_them_apart() {
    let root = tempfile::tempdir().unwrap();
    let ether = root.path().join("ether");
    let mut a = dev(root.path(), "laptop", &ether);
    let mut b = dev(root.path(), "phone", &ether);
    start(&mut a);
    start(&mut b);
    a.cli(&["init", "--yes", "--name", "Ana"]);
    pair_unmounted(&a, &b);
    always(&a);
    // The laptop's advertisement, as someone in range recorded it.
    let mine = std::fs::read_dir(ether.join("ads"))
        .unwrap()
        .flatten()
        .find(|e| !e.file_name().to_string_lossy().starts_with('.'))
        .map(|e| std::fs::read(e.path()).unwrap())
        .expect("the laptop advertises");
    let psm = u16::from_le_bytes([mine[0], mine[1]]);
    a.cli(&["bluetooth", "off"]);
    always(&b);
    // Played again from a new address every second, each answering a
    // channel and nothing more, while the laptop starts again where the
    // phone knows to find it. The phone starts again where the laptop does
    // not know to find it: only the phone's dial brings them together.
    stop(&mut a);
    stop(&mut b);
    b.port = free_port();
    start(&mut b);
    let mut replays = Vec::new();
    for i in 0..4 {
        replays.push(replay(&ether, &fake_addr(i), psm, &mine));
    }
    wait("the phone takes the replays for the laptop", 30, || {
        bluetooth(&b)["recognized"].as_u64() > Some(0)
    });
    start(&mut a);
    let mut i = 4;
    let started = std::time::Instant::now();
    let mut back = false;
    while started.elapsed() < std::time::Duration::from_secs(40) {
        replays.push(replay(&ether, &fake_addr(i), psm, &mine));
        i += 1;
        if carrier_of(&b, "laptop").is_some() {
            back = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    let seen = bluetooth(&b);
    assert!(
        back,
        "the phone reaches the laptop over IP: {seen}\n{}",
        b.log()
    );
    assert!(
        over_ip(&b, "laptop"),
        "{}",
        ask(&b, json!({"cmd": "devices"}))
    );
    stop(&mut a);
    stop(&mut b);
}

#[test]
fn a_channel_nobody_proves_anything_on_is_closed() {
    let root = tempfile::tempdir().unwrap();
    let ether = root.path().join("ether");
    let mut a = dev(root.path(), "ana", &ether);
    start(&mut a);
    a.cli(&["init", "--yes", "--name", "Ana"]);
    always(&a);
    let psm = bluetooth(&a)["psm"].as_u64().unwrap();
    let sock = std::fs::read_dir(ether.join("l2cap"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.to_string_lossy().ends_with(&format!("-{psm}")))
        .unwrap();
    // Three channels from one address: two are taken, and the third is not.
    let mut held = Vec::new();
    for _ in 0..3 {
        let mut s = UnixStream::connect(&sock).unwrap();
        s.write_all(fake_addr(1).as_bytes()).unwrap();
        held.push(s);
    }
    wait("the channels taken", 10, || {
        bluetooth(&a)["channels_in"] == 2
    });
    std::thread::sleep(std::time::Duration::from_secs(1));
    assert_eq!(bluetooth(&a)["channels_in"], 2, "two from one address");
    // Nothing is said on them: they are closed.
    wait("the channels closed", 30, || {
        bluetooth(&a)["channels_in"] == 0
    });
    stop(&mut a);
}
