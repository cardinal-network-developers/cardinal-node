//! Two in-memory peers reconcile random overlapping sets.
//!
//! The large cases are ignored by default; run them in release:
//!
//! ```text
//! cargo test --release -p cardinal-sync --test converge -- --ignored --nocapture
//! ```

use std::time::Instant;

use cardinal_sync::{
    answer_want, want_messages, Id, MemSet, Message, Reconciler, SetStore, MAX_MESSAGE,
};
use proptest::prelude::*;

/// Deterministic ids: BLAKE3 of a seed and a counter.
fn id(seed: u64, n: u64) -> Id {
    let mut h = blake3::Hasher::new();
    h.update(&seed.to_le_bytes());
    h.update(&n.to_le_bytes());
    *h.finalize().as_bytes()
}

#[derive(Debug, Default)]
struct Outcome {
    messages: u64,
    round_trips: u64,
    bytes_a: u64,
    bytes_b: u64,
    truncated: u64,
}

fn reconcile(a: &MemSet, b: &MemSet, max: usize) -> (Vec<Id>, Vec<Id>, Outcome) {
    let label = [9u8; 32];
    let mut ra = Reconciler::new(label, a).with_max_message(max);
    let mut rb = Reconciler::new(label, b).with_max_message(max);
    let mut out = Outcome::default();
    let mut msg = Some(ra.initiate());
    let mut to_b = true;
    while let Some(m) = msg {
        let bytes = m.encode();
        assert!(bytes.len() <= max, "message of {} bytes", bytes.len());
        if to_b {
            out.bytes_a += bytes.len() as u64;
        } else {
            out.bytes_b += bytes.len() as u64;
        }
        out.messages += 1;
        let m = Message::decode(&bytes).unwrap();
        msg = if to_b {
            rb.handle(&m).unwrap()
        } else {
            ra.handle(&m).unwrap()
        };
        to_b = !to_b;
        assert!(out.messages < 100_000, "no convergence");
    }
    assert!(ra.is_done() && rb.is_done());
    out.round_trips = out.messages.div_ceil(2);
    out.truncated = ra.stats().truncated + rb.stats().truncated;
    (ra.take_wanted(), rb.take_wanted(), out)
}

/// Sets of about `n` ids each, sharing `n * (1 - diff)`, each holding
/// `n * diff` the other lacks.
fn overlapping(n: u64, diff: f64, seed: u64) -> (MemSet, MemSet, Vec<Id>, Vec<Id>) {
    let only = (n as f64 * diff) as u64;
    let common = n - only;
    let shared: Vec<Id> = (0..common).map(|i| id(seed, i)).collect();
    let only_a: Vec<Id> = (0..only).map(|i| id(seed + 1, i)).collect();
    let only_b: Vec<Id> = (0..only).map(|i| id(seed + 2, i)).collect();
    let a = MemSet::from_unsorted(shared.iter().chain(&only_a).copied().collect());
    let b = MemSet::from_unsorted(shared.into_iter().chain(only_b.iter().copied()).collect());
    let mut only_a = only_a;
    let mut only_b = only_b;
    only_a.sort();
    only_b.sort();
    (a, b, only_a, only_b)
}

fn case(n: u64, diff: f64) {
    let t = Instant::now();
    let (a, b, only_a, only_b) = overlapping(n, diff, n ^ diff.to_bits());
    let built = t.elapsed();
    let t = Instant::now();
    let (wa, wb, o) = reconcile(&a, &b, MAX_MESSAGE);
    let took = t.elapsed();
    assert_eq!(wa, only_b, "A must want exactly B's extra ids");
    assert_eq!(wb, only_a, "B must want exactly A's extra ids");
    println!(
        "n={n:>8} diff={:>6.2}% each-side-extra={:>6}  round trips={:>4}  bytes A->B={:>9} B->A={:>9}  truncated={:>3}  reconcile {:>7.1} ms (build {:.1} ms)",
        diff * 100.0,
        only_a.len(),
        o.round_trips,
        o.bytes_a,
        o.bytes_b,
        o.truncated,
        took.as_secs_f64() * 1e3,
        built.as_secs_f64() * 1e3,
    );
}

#[test]
fn moderate_sets() {
    for (n, diff) in [
        (10_000, 0.0),
        (10_000, 0.001),
        (10_000, 0.01),
        (10_000, 0.5),
        (50_000, 0.01),
        (100_000, 0.0005),
    ] {
        case(n, diff);
    }
}

#[test]
#[ignore]
fn large_sets() {
    for (n, diff) in [
        (1_000_000, 0.0),
        (1_000_000, 0.00001),
        (1_000_000, 0.0001),
        (1_000_000, 0.001),
        (1_000_000, 0.01),
        (1_000_000, 0.1),
    ] {
        case(n, diff);
    }
}

#[test]
fn disjoint_and_one_sided() {
    let a: MemSet = (0..5000).map(|i| id(1, i)).collect();
    let b: MemSet = (0..5000).map(|i| id(2, i)).collect();
    let empty = MemSet::new();
    let (wa, wb, _) = reconcile(&a, &b, MAX_MESSAGE);
    assert_eq!(wa.len(), 5000);
    assert_eq!(wb.len(), 5000);
    let (wa, wb, o) = reconcile(&empty, &a, MAX_MESSAGE);
    assert_eq!(wa.len(), 5000);
    assert!(wb.is_empty());
    // An empty initiator lists nothing; the peer answers "you lack" with
    // everything, in as many messages as the size limit requires.
    assert!(o.round_trips >= 3, "{o:?}");
}

#[test]
fn reconcile_then_fetch() {
    let (a, b, _, _) = overlapping(20_000, 0.02, 77);
    // Objects are the ids' preimages here: "object" = id bytes reversed.
    let object = |id: &Id| {
        let mut o = id.to_vec();
        o.reverse();
        o
    };
    let (wa, wb, _) = reconcile(&a, &b, MAX_MESSAGE);
    let mut a2 = a.clone();
    for want in want_messages([9; 32], &wa) {
        let Message::Want { ids, .. } = want else {
            unreachable!()
        };
        for reply in answer_want([9; 32], &ids, |id| b.contains(id).then(|| object(id))) {
            let Message::Objects { objects, .. } = Message::decode(&reply.encode()).unwrap() else {
                unreachable!()
            };
            for o in objects {
                let mut id = [0u8; 32];
                id.copy_from_slice(&o);
                id.reverse();
                a2.insert(id);
            }
        }
    }
    let mut b2 = b.clone();
    b2.extend_from(wb);
    assert_eq!(a2.len(), b2.len());
    assert!(a2.iter().eq(b2.iter()));
    // And now they agree in one round trip.
    let (wa, wb, o) = reconcile(&a2, &b2, MAX_MESSAGE);
    assert!(wa.is_empty() && wb.is_empty());
    assert_eq!(o.round_trips, 1);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// Arbitrary sets drawn from a small universe (so they overlap) and
    /// arbitrary message limits always converge to the exact differences.
    #[test]
    fn converges(
        xs in proptest::collection::vec(0u64..3000, 0..1500),
        ys in proptest::collection::vec(0u64..3000, 0..1500),
        max in 4096usize..70_000,
        a_starts in any::<bool>(),
    ) {
        let a: MemSet = xs.iter().map(|&i| id(5, i)).collect();
        let b: MemSet = ys.iter().map(|&i| id(5, i)).collect();
        let (first, second) = if a_starts { (&a, &b) } else { (&b, &a) };
        let (w1, w2, _) = reconcile(first, second, max);
        let expect1: Vec<Id> = second.iter().filter(|i| !first.contains(i)).copied().collect();
        let expect2: Vec<Id> = first.iter().filter(|i| !second.contains(i)).copied().collect();
        prop_assert_eq!(w1, expect1);
        prop_assert_eq!(w2, expect2);
    }

    /// Ids clustered at the extremes of the id space (long shared prefixes
    /// of 0x00, 0x7f and 0xff bytes, plus the all-zero and all-one ids)
    /// converge too. The tail of each id stays a hash: ids with only a few
    /// free bytes would make the additive fingerprints of the specification
    /// collide (two ranges whose ids differ only in their top byte can have
    /// equal sums), which real ids, being hashes, do not.
    #[test]
    fn clustered_ids(
        xs in proptest::collection::vec((0u8..3, 0usize..31, any::<u16>()), 0..200),
        ys in proptest::collection::vec((0u8..3, 0usize..31, any::<u16>()), 0..200),
        extremes in any::<(bool, bool)>(),
    ) {
        let mk = |(p, n, r): (u8, usize, u16)| {
            let fill = [0x00, 0x7f, 0xff];
            let mut id = id(99, r as u64);
            id[..n].fill(fill[p as usize]);
            id
        };
        let mut a: MemSet = xs.into_iter().map(mk).collect();
        let b: MemSet = ys.into_iter().map(mk).collect();
        if extremes.0 {
            a.insert([0u8; 32]);
        }
        if extremes.1 {
            a.insert([0xffu8; 32]);
        }
        let (wa, wb, _) = reconcile(&a, &b, 4096);
        let ea: Vec<Id> = b.iter().filter(|i| !a.contains(i)).copied().collect();
        let eb: Vec<Id> = a.iter().filter(|i| !b.contains(i)).copied().collect();
        prop_assert_eq!(wa, ea);
        prop_assert_eq!(wb, eb);
    }
}
