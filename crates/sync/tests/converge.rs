//! Two in-memory peers reconcile random overlapping sets.
//!
//! The large cases are ignored by default; run them in release:
//!
//! ```text
//! cargo test --release -p cardinal-sync --test converge -- --ignored --nocapture
//! ```

use std::time::Instant;

use cardinal_sync::{
    answer_want, short_id, summary_bits, summary_messages, want_messages, Id, MemSet, Message,
    Reconciler, SetStore, SummaryReader, MAX_MESSAGE, MAX_TURN,
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
    turns: u64,
    round_trips: u64,
    bytes_a: u64,
    bytes_b: u64,
    truncated: u64,
}

fn reconcile(a: &MemSet, b: &MemSet, max: usize) -> (Vec<Id>, Vec<Id>, Outcome) {
    reconcile_turns(a, b, max, MAX_TURN, MAX_TURN)
}

/// Runs a reconciliation, A initiating, each side with its own turn limit;
/// gathers what each learns after every message, as a fetcher would.
fn reconcile_turns(
    a: &MemSet,
    b: &MemSet,
    max: usize,
    turn_a: usize,
    turn_b: usize,
) -> (Vec<Id>, Vec<Id>, Outcome) {
    let label = [9u8; 32];
    let mut ra = Reconciler::new(label, a)
        .with_max_message(max)
        .with_max_turn(turn_a);
    let rb = Reconciler::new(label, b)
        .with_max_message(max)
        .with_max_turn(turn_b);
    let first = vec![ra.initiate()];
    let (wa, wb, out) = converse(ra, rb, first, max);
    (wa, wb, out)
}

/// Carries turns between two reconcilers until both are done, starting
/// with `turn` going to B.
fn converse<S: SetStore>(
    mut ra: Reconciler<S>,
    mut rb: Reconciler<S>,
    mut turn: Vec<Message>,
    max: usize,
) -> (Vec<Id>, Vec<Id>, Outcome) {
    let mut out = Outcome::default();
    let (mut wa, mut wb) = (Vec::new(), Vec::new());
    let mut to_b = true;
    while !turn.is_empty() {
        out.turns += 1;
        let mut next = Vec::new();
        for m in turn {
            let bytes = m.encode();
            assert!(bytes.len() <= max, "message of {} bytes", bytes.len());
            if to_b {
                out.bytes_a += bytes.len() as u64;
            } else {
                out.bytes_b += bytes.len() as u64;
            }
            out.messages += 1;
            let m = Message::decode(&bytes).unwrap();
            let (r, w) = if to_b {
                (&mut rb, &mut wb)
            } else {
                (&mut ra, &mut wa)
            };
            assert!(next.is_empty(), "a reply before the turn ended");
            next = r.handle(&m).unwrap();
            w.extend(r.take_wanted());
        }
        turn = next;
        to_b = !to_b;
        assert!(out.messages < 100_000, "no convergence");
    }
    assert!(ra.is_done() && rb.is_done());
    out.round_trips = out.turns.div_ceil(2);
    out.truncated = ra.stats().truncated + rb.stats().truncated;
    wa.sort();
    wa.dedup();
    wb.sort();
    wb.dedup();
    (wa, wb, out)
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
    // everything, in one turn of as many messages as the size limit
    // requires, and the initiator's skips end it.
    assert_eq!(o.turns, 3, "{o:?}");
    assert!(o.messages > o.turns, "{o:?}");
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
        turns in (0usize..3, 0usize..3),
    ) {
        let a: MemSet = xs.iter().map(|&i| id(5, i)).collect();
        let b: MemSet = ys.iter().map(|&i| id(5, i)).collect();
        let (first, second) = if a_starts { (&a, &b) } else { (&b, &a) };
        // One-message turns, a few messages, or the default.
        let limit = |k: usize| [max, 3 * max, MAX_TURN][k];
        let (w1, w2, _) = reconcile_turns(first, second, max, limit(turns.0), limit(turns.1));
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

/// A summary round on a long-delay link: A opens with a summary of `a`
/// (with `bits`, and `extra` short ids added as if A held more), B answers
/// with the objects it sends, A takes them in, and B opens the exact
/// drill-down as initiator. Returns what B sent, what A learned it still
/// lacks, what B learned it lacks, and the turns of the backstop.
fn summary_round(
    a: &MemSet,
    b: &MemSet,
    bits: u32,
    extra: &[[u8; 32]],
) -> (Vec<Id>, Vec<Id>, Vec<Id>, Outcome) {
    let label = [9u8; 32];
    let nonce = [3u8; 32];
    let mut msgs = summary_messages(label, a, nonce, bits, MAX_MESSAGE);
    if !extra.is_empty() {
        // A chance match: A names short ids it does not hold.
        let Message::Summary {
            count, short_ids, ..
        } = &mut msgs[0]
        else {
            unreachable!()
        };
        let w = (bits / 8) as usize;
        let mut all: Vec<Vec<u8>> = short_ids.chunks(w).map(<[u8]>::to_vec).collect();
        all.extend(extra.iter().map(|s| s[..w].to_vec()));
        all.sort();
        *short_ids = all.concat();
        *count += extra.len() as u64;
        assert_eq!(msgs.len(), 1, "a small set for this");
    }
    let mut reader = SummaryReader::new(label, 1 << 30);
    let mut summary = None;
    for m in &msgs {
        summary = reader.push(&Message::decode(&m.encode()).unwrap()).unwrap();
    }
    let summary = summary.expect("the whole summary");
    let sent = summary.to_send(b);
    let mut a2 = a.clone();
    a2.extend_from(sent.iter().copied());
    // The backstop: B initiates, A answers with what it holds now.
    let mut rb = Reconciler::new(label, b);
    let ra = Reconciler::new(label, &a2);
    let first = vec![rb.initiate()];
    // The first turn goes to `converse`'s second side, A here.
    let (wb, wa, o) = converse(rb, ra, first, MAX_MESSAGE);
    (sent, wa, wb, o)
}

fn three_ways(n: u64, common: u64, seed: u64) -> (MemSet, MemSet) {
    let a: MemSet = (0..n).map(|i| id(seed, i)).collect();
    let b: MemSet = (n - common..2 * n - common).map(|i| id(seed, i)).collect();
    (a, b)
}

#[test]
fn a_summary_sends_what_is_absent_and_the_backstop_agrees() {
    let (a, b) = three_ways(20_000, 15_000, 41);
    let (sent, wa, wb, o) = summary_round(&a, &b, summary_bits(a.len()), &[]);
    let expect: Vec<Id> = b.iter().filter(|i| !a.contains(i)).copied().collect();
    assert_eq!(sent, expect, "B sends exactly what A lacks");
    assert!(wa.is_empty(), "the backstop finds nothing more for A");
    let lacks: Vec<Id> = a.iter().filter(|i| !b.contains(i)).copied().collect();
    assert_eq!(wb, lacks, "and gives B what it lacks");
    println!("summary backstop: {o:?}");
}

#[test]
fn a_summary_of_nothing_brings_everything() {
    let empty = MemSet::new();
    let b: MemSet = (0..5000).map(|i| id(42, i)).collect();
    let (sent, wa, wb, o) = summary_round(&empty, &b, summary_bits(0), &[]);
    assert_eq!(sent.len(), 5000);
    assert!(wa.is_empty() && wb.is_empty());
    // B's fingerprint, A's equal one: one round trip.
    assert_eq!(o.turns, 2, "{o:?}");
}

#[test]
fn short_bits_send_the_whole_set() {
    let (a, b) = three_ways(3000, 2000, 43);
    // 24 bits for 3,000 a side: E = 9e6 / 2^24, far above 2^-20.
    let (sent, wa, _, _) = summary_round(&a, &b, 24, &[]);
    assert_eq!(sent.len(), b.len(), "everything B holds");
    assert!(wa.is_empty());
}

#[test]
fn the_backstop_finds_a_chance_match() {
    let a: MemSet = (0..20).map(|i| id(44, i)).collect();
    let b: MemSet = (10..40).map(|i| id(44, i)).collect();
    // One of B's ids that A lacks, its short id in A's summary as though
    // one of A's own had the same.
    let hidden = id(44, 30);
    let bits = summary_bits(a.len());
    let forged = short_id(&[3u8; 32], &hidden, (bits / 8) as usize);
    let (sent, wa, wb, _) = summary_round(&a, &b, bits, &[forged]);
    assert!(!sent.contains(&hidden), "held back by the chance match");
    assert_eq!(sent.len(), 19);
    assert_eq!(wa, vec![hidden], "the drill-down finds it");
    assert_eq!(wb.len(), 10);
}
