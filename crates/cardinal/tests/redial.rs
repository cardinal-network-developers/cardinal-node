//! How often a device dials its own devices when it cannot reach them
//! (`hosts.md#staying-reachable`, D86; `redial.rs`). Each dial wakes a
//! phone's radio.
//!
//! Alpha and beta are one person's; beta is switched off. Alpha, plugged
//! in, helps others: it keeps trying beta, but waits twice as long each
//! time. On battery it stops dialling on a timer: in touch with nobody, it
//! would try again in minutes, and a few times an hour at most. Told it
//! woke, it dials at once.
//!
//! Skipped (with a message) when `/dev/fuse` or `fusermount3` is missing.

mod common;

use common::*;
use serde_json::{json, Value};
use std::time::{Duration, Instant};

fn start(d: &mut Dev) {
    d.start();
}

/// Beta, as alpha sees it.
fn beta(a: &Dev) -> Value {
    let s = a.status();
    let all = s["devices"].as_array().cloned().unwrap_or_default();
    all.into_iter()
        .find(|x| x["name"] == "beta")
        .unwrap_or_else(|| panic!("no beta in {s}"))
}

fn dials(a: &Dev) -> u64 {
    beta(a)["dials"].as_u64().unwrap()
}

#[test]
fn a_phone_on_battery_spares_its_radio_and_dials_when_it_wakes() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut a = Dev::new(root.path(), "alpha", free_port());
    let mut b = Dev::new(root.path(), "beta", free_port());
    start(&mut a);
    let out = a.cli(&["init", "--yes", "--name", "alpha"]);
    assert!(out.contains("Set up"), "{out}");
    start(&mut b);
    pair(&a, &b);
    wait("alpha sees beta", 30, || beta(&a)["online"] == true);
    b.stop();
    wait("alpha sees beta go", 30, || beta(&a)["online"] == false);

    // Plugged in, alpha keeps trying, less and less often.
    let (n0, t0) = (dials(&a), Instant::now());
    wait("alpha waits longer for beta", 90, || {
        beta(&a)["redial_s"].as_u64().is_some_and(|w| w >= 16)
    });
    let tried = dials(&a) - n0;
    let secs = t0.elapsed().as_secs();
    // 1 + 2 + 4 + 8 + 16 s, and a pass's two seconds besides
    assert!(tried <= 8, "{tried} dials in {secs} s: {}", beta(&a));

    // On battery, it dials nothing on a timer for minutes.
    let on_battery = json!({"cmd": "conditions", "plugged_in": false, "metered": false});
    ask(&a, &on_battery);
    let redial = a.status()["redial"].clone();
    assert_eq!(redial["helps"], false, "{redial}");
    assert_eq!(redial["alone"], true, "{redial}");
    assert!(
        redial["sparing"]["next_s"].as_u64().unwrap() > 30,
        "{redial}"
    );
    // One may have been on its way when it was told.
    std::thread::sleep(Duration::from_secs(3));
    let n1 = dials(&a);
    std::thread::sleep(Duration::from_secs(40));
    let n2 = dials(&a);
    assert_eq!(n2, n1, "dialled on a timer on battery: {}", beta(&a));

    // It woke: it dials at once, and once more when the old sessions
    // have had time to answer, and then leaves it.
    ask(&a, &json!({"cmd": "wake"}));
    let took = wait("alpha dials beta on waking", 5, || dials(&a) > n2);
    assert!(took < Duration::from_secs(3), "{took:?}");
    std::thread::sleep(Duration::from_secs(25));
    let n3 = dials(&a);
    assert!(n3 - n2 <= 3, "{} dials after waking", n3 - n2);
    std::thread::sleep(Duration::from_secs(20));
    assert_eq!(dials(&a), n3, "dialled on a timer after waking");

    // Beta comes back and dials alpha itself: they are in touch.
    start(&mut b);
    wait("beta reaches alpha", 30, || beta(&a)["online"] == true);
    assert_eq!(a.status()["redial"]["alone"], false);
}
