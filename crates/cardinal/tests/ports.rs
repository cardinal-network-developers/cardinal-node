//! The port: when the one a device listens on is taken (another person's
//! Cardinal on the same machine, or any other program), the device moves to
//! a free one and keeps it. A host's grant follows it where the address is
//! this device's own; an address that reaches it another way (a router's
//! forward) cannot follow and is shown. Its other devices find it again.
//! A port asked for on the command line is held to.

mod common;

use common::*;
use std::net::UdpSocket;
use std::process::Stdio;

/// Starts `d` on the port in its settings, as a service does.
fn start_as_service(d: &mut Dev) {
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(d.home.join("daemon.log"))
        .unwrap();
    let child = d
        .cmd()
        .args(["daemon", "--no-discovery", "--mount"])
        .arg(&d.mount)
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .unwrap();
    d.child = Some(child);
    wait(&format!("{} daemon up", d.name), 20, || {
        d.try_cli(&["status"]).status.success()
    });
}

fn port_of(addr: &str) -> u16 {
    addr.rsplit(':').next().unwrap().parse().unwrap()
}

#[test]
fn a_device_whose_port_is_taken_moves_and_is_found_again() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut alpha = Dev::new(root.path(), "alpha", free_port());
    let mut beta = Dev::new(root.path(), "beta", free_port());
    alpha.start();
    beta.start();
    alpha.cli(&["init", "--yes", "--name", "alpha"]);
    let old = alpha.port;
    alpha.cli(&[
        "host",
        "--address",
        &format!("127.0.0.1:{old}"),
        // as if a router forwarded this port here
        "--address",
        &format!("203.0.113.9:{old}"),
    ]);
    pair(&alpha, &beta);
    wait("beta knows the host", 30, || {
        beta.cli(&["recovery", "sheet"])
            .contains(&format!("127.0.0.1:{old}"))
    });

    alpha.stop();
    let _someone_else = UdpSocket::bind(("127.0.0.1", old)).unwrap();
    start_as_service(&mut alpha);

    let s = alpha.status();
    let now = port_of(s["listen"].as_str().unwrap());
    assert_ne!(now, old);
    assert_eq!(s["moved_from"].as_u64(), Some(old as u64), "{s}");
    let mine = format!("127.0.0.1:{now}");
    wait("the grant follows the port", 20, || {
        alpha.cli(&["recovery", "sheet"]).contains(&mine)
    });
    let sheet = alpha.cli(&["recovery", "sheet"]);
    assert!(sheet.contains(&format!("203.0.113.9:{old}")), "{sheet}");
    let shown = alpha.cli(&["status"]);
    assert!(shown.contains(&format!("listens on {now} now")), "{shown}");
    assert!(
        shown.contains(&format!("203.0.113.9:{old} still names port {old}")),
        "{shown}"
    );

    // Its other device, which knew only the old port, learns the new one.
    wait("beta learns the new address", 60, || {
        beta.cli(&["recovery", "sheet"]).contains(&mine)
    });

    // Moved once, it stays: free again, the old port is not taken back.
    drop(_someone_else);
    alpha.stop();
    start_as_service(&mut alpha);
    assert_eq!(port_of(alpha.status()["listen"].as_str().unwrap()), now);
    assert!(alpha.status()["moved_from"].is_null());
}

#[test]
fn a_port_asked_for_is_held_to() {
    let root = tempfile::tempdir().unwrap();
    let d = Dev::new(root.path(), "alpha", free_port());
    let _taken = UdpSocket::bind(("127.0.0.1", d.port)).unwrap();
    let o = d
        .cmd()
        .args(["daemon", "--no-discovery", "--no-mount", "--listen"])
        .arg(format!("127.0.0.1:{}", d.port))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(!o.status.success());
    assert!(
        err.contains(&format!("another program uses port {}", d.port)),
        "{err}"
    );
    assert!(err.contains("listen = "), "{err}");
}
