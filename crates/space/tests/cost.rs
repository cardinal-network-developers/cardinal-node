//! What an entry costs as a space grows (`spaces.md#cost`): judged once, an
//! entry costs the same at the twenty-thousandth as at the twentieth.
//!
//! The measurements are `#[ignore]`d: run them optimized, with
//! `cargo test -p cardinal-space --release --test cost -- --ignored --nocapture`.
//! The test that is not ignored checks the same thing by counting instead of
//! timing, so that it holds on any machine.

use std::time::{Duration, Instant};

use cardinal_crypto::{HybridKeyPair, RecoveryPhrase};
use cardinal_identity::{Created, DeviceKeys, IdentityLog};
use cardinal_space::validity::by_rules;
use cardinal_space::{relationship, NodeId, Policy, Profile, SealedEntry, Space, SpaceOp};

struct Person {
    log: IdentityLog,
    enc: HybridKeyPair,
    device: DeviceKeys,
}

fn person(n: u8) -> Person {
    let device = DeviceKeys::generate();
    let Created {
        log, encryption, ..
    } = IdentityLog::create_with(
        RecoveryPhrase::from_entropy(&[n; 32]),
        &device,
        HybridKeyPair::generate(),
    )
    .unwrap();
    Person {
        log,
        enc: encryption,
        device,
    }
}

/// Two people and the space between them, as each of their devices holds it.
struct Pair {
    ana: Person,
    bo: Person,
    a: Space,
    b: Space,
    c: NodeId,
}

fn pair() -> Pair {
    let (ana, bo) = (person(61), person(62));
    let (mut a, genesis) = Space::create_with(
        Profile::RELATIONSHIP,
        Policy::default(),
        &ana.log,
        &ana.device.signing,
        &[ana.enc.public_key(), bo.enc.public_key()],
        relationship::genesis_ops(ana.log.id(), bo.log.id()),
        None,
    )
    .unwrap();
    a.set_identity(bo.log.state());
    let c = relationship::conversation(&a).unwrap();
    let mut b = Space::open_genesis(&genesis, &[&bo.enc], Some(ana.log.state())).unwrap();
    b.set_identity(bo.log.state());
    Pair { ana, bo, a, b, c }
}

impl Pair {
    fn message(&self, n: usize) -> Vec<SpaceOp> {
        vec![relationship::create_message(
            self.c,
            &format!("message {n}"),
        )]
    }

    /// Ana writes and Bo's device takes it, or the other way about. Returns
    /// how long the receiving device took to open, judge and apply it.
    fn exchange(&mut self, n: usize) -> Duration {
        let ops = self.message(n);
        if n % 2 == 0 {
            let s = self
                .a
                .write(&self.ana.log, &self.ana.device.signing, ops, Some(n as u64))
                .unwrap();
            let start = Instant::now();
            self.b.receive(s, &[&self.bo.enc]).unwrap();
            start.elapsed()
        } else {
            let s = self
                .b
                .write(&self.bo.log, &self.bo.device.signing, ops, Some(n as u64))
                .unwrap();
            let start = Instant::now();
            self.a.receive(s, &[&self.ana.enc]).unwrap();
            start.elapsed()
        }
    }

    /// Both write at once, and each then takes the other's: an entry that
    /// does not descend from everything the receiver holds.
    fn at_once(&mut self, n: usize) -> Duration {
        let sa = self
            .a
            .write(
                &self.ana.log,
                &self.ana.device.signing,
                self.message(n),
                Some(n as u64),
            )
            .unwrap();
        let sb = self
            .b
            .write(
                &self.bo.log,
                &self.bo.device.signing,
                self.message(n + 1),
                Some(n as u64),
            )
            .unwrap();
        let start = Instant::now();
        self.b.receive(sa, &[&self.bo.enc]).unwrap();
        let took = start.elapsed();
        self.a.receive(sb, &[&self.ana.enc]).unwrap();
        took
    }
}

fn median(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v[v.len() / 2]
}

/// A stranger's entry: it opens, since whoever wrote it had the key, and
/// counts for nothing. Nobody builds on it, so it stays a head for good.
fn stranger_writes(p: &Pair) -> SealedEntry {
    let eve = person(63);
    let mut copy = Space::open_genesis(
        p.a.sealed(&p.a.id()).unwrap(),
        &[&p.ana.enc],
        Some(p.ana.log.state()),
    )
    .unwrap();
    copy.write(
        &eve.log,
        &eve.device.signing,
        vec![relationship::create_message(p.c, "let me in")],
        None,
    )
    .unwrap()
}

/// An entry is judged once, and applied without looking at the rest: by
/// count, whatever the machine.
#[test]
fn a_long_conversation_applies_each_entry_once() {
    let mut p = pair();
    // someone who is not in it writes into it, early on
    let junk = stranger_writes(&p);
    p.a.receive(junk.clone(), &[&p.ana.enc]).unwrap();
    p.b.receive(junk, &[&p.bo.enc]).unwrap();
    let n = 600;
    for i in 0..n {
        p.exchange(i);
    }
    for space in [&p.a, &p.b] {
        let stats = space.stats();
        // every entry was appended; nothing was worked out again, though a
        // head that is not valid has been there all along
        assert_eq!(stats.recomputed, 0, "{stats:?}");
        assert_eq!(stats.appended, n as u64 + 1, "{stats:?}");
        assert_eq!(space.heads().len(), 1);
        assert_eq!(space.dag().heads().len(), 2);
        assert_eq!(relationship::messages(space).len(), n);
    }
}

/// What is found one entry at a time is what the rules find in all of it,
/// with the stranger's entry there too.
#[test]
fn a_conversation_judged_as_it_goes_is_what_the_rules_find() {
    let mut p = pair();
    let junk = stranger_writes(&p);
    p.a.receive(junk, &[&p.ana.enc]).unwrap();
    for i in 0..40 {
        p.exchange(i);
    }
    let rules = by_rules(p.a.dag(), &[&p.ana.log, &p.bo.log]).unwrap();
    assert!(p.a.validity().valid == rules.valid && rules.valid.len() == 41);
    assert_eq!(p.a.dag().len(), 42);
}

/// What the 2,000th and the 20,000th entry cost in a two-person space, and
/// what running the whole program after each entry cost at sizes where
/// that can still be waited for.
#[test]
#[ignore]
fn cost_of_an_entry_in_a_long_conversation() {
    let mut p = pair();
    let mut window: Vec<Duration> = Vec::new();
    let marks = [200usize, 2_000, 20_000];
    let rules_at = [100usize, 200, 400, 800];
    let total = *marks.last().unwrap();
    for n in 1..=total {
        window.push(p.exchange(n));
        if window.len() > 200 {
            window.remove(0);
        }
        if marks.contains(&n) {
            let apply = median(window.clone());
            let together = median((0..21).map(|i| p.at_once(n * 10 + 2 * i)).collect());
            eprintln!(
                "MEASURE at entry {n}: {apply:?} to take one that builds on everything, \
                 {together:?} to take one written at the same time as another"
            );
        }
        if rules_at.contains(&n) {
            let start = Instant::now();
            let rules = by_rules(p.a.dag(), &[&p.ana.log, &p.bo.log]).unwrap();
            let took = start.elapsed();
            assert!(rules.valid == p.a.validity().valid);
            eprintln!("MEASURE at entry {n}: {took:?} for the whole program, once");
        }
    }
    let stats = p.b.stats();
    eprintln!("MEASURE {stats:?}");
}

/// The same, in a space that holds one entry that is not valid: nobody
/// builds on it, so it is a head for good, and no later entry descends from
/// every head.
#[test]
#[ignore]
fn cost_of_an_entry_beside_one_that_does_not_count() {
    let mut p = pair();
    let junk = stranger_writes(&p);
    p.a.receive(junk.clone(), &[&p.ana.enc]).unwrap();
    p.b.receive(junk, &[&p.bo.enc]).unwrap();
    let mut window: Vec<Duration> = Vec::new();
    for n in 1..=20_000usize {
        window.push(p.exchange(n));
        if window.len() > 200 {
            window.remove(0);
        }
        if [200, 2_000, 20_000].contains(&n) {
            let apply = median(window.clone());
            eprintln!("MEASURE at entry {n}, beside an invalid head: {apply:?} to take one");
        }
    }
    eprintln!("MEASURE {:?}", p.b.stats());
}
