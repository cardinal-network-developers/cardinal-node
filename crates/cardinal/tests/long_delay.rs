//! Two devices whose link counts as long (`sync.md#long-delays`): every
//! reconciliation opens with a summary, answered with what is absent and
//! then the exact drill-down. `CARDINAL_TEST_SUMMARY_RTT_MS=0` makes every
//! link long, standing in for a round trip of minutes.
//!
//! Skipped (with a message) when `/dev/fuse` or `fusermount3` is missing.

mod common;

use common::*;

#[test]
fn summaries_on_a_long_link() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut a = Dev::new(root.path(), "alpha", free_port());
    let mut b = Dev::new(root.path(), "beta", free_port());
    for d in [&mut a, &mut b] {
        d.env
            .push(("CARDINAL_TEST_SUMMARY_RTT_MS".into(), "0".into()));
    }
    a.start();
    b.start();
    let out = a.cli(&["init", "--yes", "--name", "alpha"]);
    assert!(out.contains("Set up"), "{out}");
    a.wait_mounted();
    for i in 0..40 {
        std::fs::write(a.p(&format!("a{i:02}.txt")), format!("alpha {i}\n")).unwrap();
    }
    a.cli(&["flush"]);

    // A device that holds nothing says so, and is sent everything.
    pair(&a, &b);
    b.wait_mounted();
    wait("beta has alpha's files", 30, || {
        (0..40).all(|i| {
            read(&b.p(&format!("a{i:02}.txt"))).as_deref() == Some(&format!("alpha {i}\n"))
        })
    });

    // Then each writes with the other away, and they meet again: each
    // summary brings what the other lacks.
    b.stop();
    for i in 0..20 {
        std::fs::write(a.p(&format!("later{i:02}.txt")), format!("later {i}\n")).unwrap();
    }
    a.cli(&["flush"]);
    b.start();
    b.wait_mounted();
    std::fs::write(b.p("from-beta.txt"), "beta\n").unwrap();
    wait("beta has what alpha wrote while it was away", 60, || {
        (0..20).all(|i| {
            read(&b.p(&format!("later{i:02}.txt"))).as_deref() == Some(&format!("later {i}\n"))
        })
    });
    wait("alpha has beta's file", 30, || {
        read(&a.p("from-beta.txt")).as_deref() == Some("beta\n")
    });

    for d in [&a, &b] {
        let log = d.log();
        assert!(
            log.contains(": a summary of"),
            "{} sent none: {log}",
            d.name
        );
        assert!(
            log.contains("answering a summary of"),
            "{} answered none",
            d.name
        );
        assert!(
            !log.contains("summary:"),
            "{} found one malformed: {log}",
            d.name
        );
    }
}

/// An answer to a summary that brings more objects unasked than one may
/// carry (here, for the test, three) is refused: the stream is reset, and
/// the set reconciled turn by turn, its objects asked for. Nothing is lost.
#[test]
fn an_answer_beyond_what_a_summary_may_carry_is_refused() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut a = Dev::new(root.path(), "alpha", free_port());
    let mut b = Dev::new(root.path(), "beta", free_port());
    for d in [&mut a, &mut b] {
        d.env
            .push(("CARDINAL_TEST_SUMMARY_RTT_MS".into(), "0".into()));
        d.env
            .push(("CARDINAL_TEST_SUMMARY_ANSWER_MAX".into(), "3".into()));
    }
    a.start();
    b.start();
    let out = a.cli(&["init", "--yes", "--name", "alpha"]);
    assert!(out.contains("Set up"), "{out}");
    a.wait_mounted();
    for i in 0..20 {
        std::fs::write(a.p(&format!("a{i:02}.txt")), format!("alpha {i}\n")).unwrap();
    }
    a.cli(&["flush"]);
    pair(&a, &b);
    b.wait_mounted();
    wait("beta has alpha's files", 60, || {
        (0..20).all(|i| {
            read(&b.p(&format!("a{i:02}.txt"))).as_deref() == Some(&format!("alpha {i}\n"))
        })
    });
    let log = b.log();
    assert!(
        log.contains("reconciling") && log.contains("turn by turn"),
        "{log}"
    );
}
