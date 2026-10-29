//! Reconnecting after a restart. The device that stops tells the other,
//! which drops the session at once; otherwise the other keeps a dead
//! session, and a restart within 10 s of connecting looks "simultaneous"
//! to it (`link.md#identity-binding`): the dead session could win and the
//! new one be closed, again and again, until 10 s had passed. And when
//! both devices dial at once, each daemon must hold the session the link
//! kept, never the one it closed.
//!
//! Alpha and beta restart in turn, each right after the last reconnect,
//! so the session the other side holds was always opened seconds before
//! and was always dialed by that side. Each time, both must see each
//! other again within a few seconds and stay connected.
//!
//! Skipped (with a message) when `/dev/fuse` or `fusermount3` is missing.

mod common;

use common::*;
use std::time::{Duration, Instant};

fn online(d: &Dev, other: &str) -> bool {
    d.status()["devices"]
        .as_array()
        .is_some_and(|a| a.iter().any(|x| x["name"] == other && x["online"] == true))
}

/// Sessions the daemon has taken on so far (its log survives restarts).
fn connects(d: &Dev) -> usize {
    d.log().matches("connected to ").count()
}

#[derive(Debug)]
#[allow(dead_code)] // read through Debug
struct Round {
    restarted: &'static str,
    reconnect_ms: u128,
    offline_samples: usize,
    sessions: (usize, usize),
}

#[test]
fn restarts_reconnect_at_once() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut a = Dev::new(root.path(), "alpha", free_port());
    let mut b = Dev::new(root.path(), "beta", free_port());
    a.start();
    let out = a.cli(&["init", "--yes", "--name", "alpha"]);
    assert!(out.contains("Set up"), "{out}");
    b.start();
    pair(&a, &b);
    let both = |a: &Dev, b: &Dev| online(a, "beta") && online(b, "alpha");
    wait("alpha and beta online", 30, || both(&a, &b));

    let mut rounds = Vec::new();
    for i in 0..6 {
        let (s0, t0) = ((connects(&a), connects(&b)), Instant::now());
        let restarted = if i % 2 == 0 {
            a.stop();
            a.start();
            "alpha"
        } else {
            b.stop();
            b.start();
            "beta"
        };
        let up = Instant::now();
        wait("alpha and beta online after a restart", 30, || both(&a, &b));
        let reconnect_ms = up.elapsed().as_millis();
        let mut offline_samples = 0;
        let watch = Instant::now();
        while watch.elapsed() < Duration::from_secs(3) {
            if !both(&a, &b) {
                offline_samples += 1;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let r = Round {
            restarted,
            reconnect_ms,
            offline_samples,
            sessions: (connects(&a) - s0.0, connects(&b) - s0.1),
        };
        eprintln!("{r:?} ({} ms in all)", t0.elapsed().as_millis());
        rounds.push(r);
    }
    for r in &rounds {
        // Two sessions at most per side: a simultaneous pair can replace
        // one taken on a moment before.
        assert!(
            r.reconnect_ms < 5000
                && r.offline_samples == 0
                && r.sessions.0 <= 2
                && r.sessions.1 <= 2,
            "reconnect at once and stay connected: {rounds:#?}"
        );
    }
}
