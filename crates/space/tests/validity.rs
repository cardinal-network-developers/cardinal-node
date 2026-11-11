//! Property: the native evaluation of a space agrees with the normative
//! `space` program of `model/rules.md`, on random histories with several
//! people, an owner or none, admins who add, removed devices, stale heads,
//! witnesses, `keep` ops, successions, thieves who write with a device's key
//! after it is removed, strangers who were never added, and entries that
//! someone signed again with a key of their own.
//!
//! Three things are checked on each history:
//!
//! - entries arriving in log order with every identity log held;
//! - entries arriving in a random order, compared with the program on what
//!   has arrived at random points on the way;
//! - entries arriving in a random order while identity logs arrive late and
//!   change, so that signatures start and stop counting under entries that
//!   are already judged.
//!
//! A fourth test takes the same histories through [`Space`], sealed, and
//! checks the state, the valid heads and the current epoch it keeps as it
//! goes against ones worked out from nothing.

use std::collections::HashSet;
use std::sync::{Arc, OnceLock};

use cardinal_crypto::{HybridKeyPair, RecoveryPhrase, SigningKey};
use cardinal_encoding::{Record, Value};
use cardinal_identity::dag::{Dag, Inserted};
use cardinal_identity::{
    Created, DeviceKeys, EntryBuilder, EntryId, IdentityEntry, IdentityLog, IdentityOp,
    IdentityState, Power,
};
use cardinal_space::entry::{derived_id, NodeId, ADMIN, OWNER, READER, WRITER};
use cardinal_space::validity::{by_rules_as, Judge, Validity};
use cardinal_space::{
    group, EpochKey, NodeKind, Policy, Profile, SealedEntry, Space, SpaceEntry, SpaceEntryBuilder,
    SpaceOp, State, ROOT,
};
use proptest::prelude::*;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }

    fn pick<'a, T>(&mut self, of: &'a [T]) -> &'a T {
        &of[self.below(of.len())]
    }
}

const PEOPLE: usize = 5; // Ana, Ben, Cy, Dee, and Eve, whom nobody honest adds
const ANA: usize = 0;
const BEN: usize = 1;
const EVE: usize = 4;

/// The people as they start out, made once: an identity each, with an admin
/// key and two device keys. Each history starts from a copy.
struct Seeds {
    logs: Vec<Vec<Vec<u8>>>,
    keys: Vec<[[u8; 32]; 3]>,
}

fn seeds() -> &'static Seeds {
    static SEEDS: OnceLock<Seeds> = OnceLock::new();
    SEEDS.get_or_init(|| {
        let mut logs = Vec::new();
        let mut keys = Vec::new();
        for n in 0..PEOPLE {
            let d0 = DeviceKeys::generate();
            let Created { mut log, .. } = IdentityLog::create_with(
                RecoveryPhrase::from_entropy(&[n as u8 + 40; 32]),
                &d0,
                HybridKeyPair::generate(),
            )
            .unwrap();
            let mut mine = [*d0.signing.seed(), [0; 32], [0; 32]];
            for slot in mine.iter_mut().skip(1) {
                let d = DeviceKeys::generate();
                let request = d.request(&log.id(), Power::Device);
                log.add_key(&d0.signing, &request, None).unwrap();
                *slot = *d.signing.seed();
            }
            logs.push(log.entries().map(|e| e.encode()).collect());
            keys.push(mine);
        }
        Seeds { logs, keys }
    })
}

struct Person {
    log: IdentityLog,
    keys: Vec<SigningKey>,
    /// The log as it was evaluated each time it changed, oldest first.
    was: Vec<Arc<IdentityState>>,
}

fn people() -> Vec<Person> {
    let s = seeds();
    (0..PEOPLE)
        .map(|n| {
            let mut entries = s.logs[n].iter().map(|b| IdentityEntry::decode(b).unwrap());
            let mut log = IdentityLog::from_genesis(entries.next().unwrap()).unwrap();
            let mut was = vec![log.state()];
            for e in entries {
                log.insert(e).unwrap();
                was.push(log.state());
            }
            Person {
                log,
                keys: s.keys[n].iter().map(SigningKey::from_seed).collect(),
                was,
            }
        })
        .collect()
}

/// A history: the people, and the entries of one space in the order they
/// were written, the genesis first.
struct History {
    people: Vec<Person>,
    profile: Profile,
    entries: Vec<SpaceEntry>,
    epoch: EpochKey,
    enc: &'static HybridKeyPair,
    genesis: SealedEntry,
}

fn member_key() -> &'static HybridKeyPair {
    static KEY: OnceLock<HybridKeyPair> = OnceLock::new();
    KEY.get_or_init(HybridKeyPair::generate)
}

fn folder() -> SpaceOp {
    SpaceOp::create(NodeKind::Uint(5), ROOT, "x", Record::new())
}

fn reach() -> SpaceOp {
    SpaceOp::create(NodeKind::Uint(9), ROOT, "reach", Record::new())
}

fn history(seed: u64, steps: usize) -> History {
    let mut rng = Rng(seed | 1);
    let mut people = people();
    let id = |p: &Person| p.log.id();
    let (ana, ben, cy) = (id(&people[0]), id(&people[1]), id(&people[2]));
    let latest = |p: &Person| *p.log.dag().log_order().last().unwrap();

    // The genesis: Ana's alone, or shared with Ben and no owner, or one of
    // the shapes no space can start from.
    let shape = rng.below(100);
    let ownerless = (60..88).contains(&shape);
    let profile = if ownerless {
        Profile::RELATIONSHIP
    } else {
        group::GROUP
    };
    let start = SpaceOp::start(profile, &Policy::default());
    let add = SpaceOp::add_member;
    let mut ops = match shape {
        0..=44 => vec![start, add(ana, OWNER)],
        45..=54 => vec![start, add(ana, OWNER), add(ben, ADMIN), folder()],
        55..=59 => vec![start, add(ana, OWNER), add(ana, WRITER), add(cy, READER)],
        60..=79 => vec![start, add(ana, WRITER), add(ben, WRITER), folder()],
        80..=87 => vec![start, add(ana, WRITER), add(ben, READER), add(cy, READER)],
        88 => vec![start, add(ana, OWNER), add(ben, OWNER)],
        89 => vec![start, add(ana, WRITER), add(ben, OWNER)],
        90 => vec![start, add(ana, WRITER), add(ben, ADMIN)],
        91 => vec![start, add(ben, WRITER)],
        92 => vec![start, add(ana, OWNER), add(ana, OWNER)],
        93 => vec![start.clone(), start, add(ana, OWNER)],
        94 => vec![start, add(ana, OWNER), SpaceOp::succeed([7; 32])],
        95 => vec![start, add(ana, OWNER), add(ben, 7)],
        96 => vec![start, add(ana, READER), add(ben, READER), folder()],
        97 => vec![
            start,
            add(ana, WRITER),
            add(ben, WRITER),
            SpaceOp::set_policy(&Policy::default()),
        ],
        98 => vec![add(ana, OWNER)],
        _ => vec![
            start,
            add(ana, OWNER),
            SpaceOp::from_record(Record::new().with(0, 20u32)),
        ],
    };
    if rng.chance(8) {
        // a successor's genesis: kept, never witnessed
        let from = cardinal_space::entry::Succession {
            succeeds: Some([9; 32]),
            ..Default::default()
        };
        ops[0] = SpaceOp::start_with(profile, &Policy::default(), None, &from);
    }
    if rng.chance(15) {
        ops.push(reach());
    }
    let epoch = EpochKey::generate();
    let enc = member_key();
    let wraps = vec![epoch.wrap(enc.public_key())];
    // mostly by her admin key; sometimes by a device that may be removed
    let signer = if rng.chance(75) { 0 } else { 1 + rng.below(2) };
    let g = SpaceEntryBuilder::genesis(ana, latest(&people[ANA]), epoch.id())
        .ops(ops)
        .wraps(&wraps)
        .sign(&people[ANA].keys[signer])
        .unwrap();
    let genesis = SealedEntry::seal(&g, &epoch, Some(wraps), false).unwrap();
    let space = g.id();

    let mut dag: Dag<SpaceEntry> = Dag::new();
    dag.insert(space, vec![], g.clone());
    let mut entries = vec![g];
    let mut removed = [[false; 3]; PEOPLE];
    // reach nodes made so far: the node, and who made it
    let mut reach_nodes: Vec<(NodeId, usize)> = Vec::new();
    for step in 0..steps {
        if rng.chance(9) {
            // a device is removed, at the heads of its log or from an old
            // point in it
            let p = rng.below(PEOPLE);
            let k = 1 + rng.below(2);
            if !removed[p][k] {
                let person = &mut people[p];
                let key = person.keys[k].public_key();
                if rng.chance(70) {
                    person.log.remove_key(&person.keys[0], &key).unwrap();
                } else {
                    let order = person.log.dag().log_order();
                    let at = order[rng.below(order.len())];
                    let e = EntryBuilder::new(person.log.id(), &[at])
                        .op(IdentityOp::remove_key(key))
                        .sign(&person.keys[0])
                        .unwrap();
                    person.log.insert(e).unwrap();
                }
                person.was.push(person.log.state());
                removed[p][k] = true;
            }
            continue;
        }
        if entries.len() > 1 && rng.chance(4) {
            // Someone signs an entry again: the same body, and so the same
            // id, under another key. Its author's other device, or anyone.
            let e = &entries[1 + rng.below(entries.len() - 1)];
            let author = people.iter().position(|p| p.log.id() == e.author());
            let by = match author {
                Some(a) if rng.chance(50) => a,
                _ => rng.below(PEOPLE),
            };
            let again =
                SpaceEntryBuilder::new(space, e.parents(), e.author(), e.author_head(), e.epoch())
                    .ops(e.ops().to_vec())
                    .sign(&people[by].keys[rng.below(3)])
                    .unwrap();
            assert_eq!(again.id(), e.id());
            entries.push(again);
            continue;
        }
        // who writes, and with which key: its owner, a thief who holds it
        // after it was removed, or a stranger signing as someone else
        let who = match rng.below(100) {
            0..=34 => ANA,
            35..=54 => BEN,
            55..=69 => 2,
            70..=84 => 3,
            _ => EVE,
        };
        let key = if rng.chance(45) { 0 } else { rng.below(3) };
        let forged = rng.chance(4);
        let signer = if forged { EVE } else { who };
        let p = &people[who];
        let order = p.log.dag().log_order();
        let head = if rng.chance(22) {
            order[rng.below(order.len())]
        } else {
            *order.last().unwrap()
        };
        let all: Vec<EntryId> = entries.iter().map(|e| e.id()).collect();
        let parents = match rng.below(100) {
            0..=59 => dag.heads(),
            60..=84 => vec![*rng.pick(&all)],
            _ => vec![*rng.pick(&all), *rng.pick(&all)],
        };
        let someone = |rng: &mut Rng| people[rng.below(PEOPLE)].log.id();
        let mut ops = match rng.below(100) {
            0..=27 => vec![folder()],
            28..=37 => vec![reach()],
            38..=44 if !reach_nodes.is_empty() => {
                // mostly its own reach node, sometimes another's
                let mine: Vec<&(NodeId, usize)> =
                    reach_nodes.iter().filter(|(_, by)| *by == who).collect();
                let node = match mine.as_slice() {
                    [] => rng.pick(&reach_nodes).0,
                    some if rng.chance(80) => rng.pick(some).0,
                    _ => rng.pick(&reach_nodes).0,
                };
                vec![SpaceOp::set(node, 1, Some(Value::from("there")))]
            }
            38..=57 => {
                let role = match rng.below(20) {
                    0..=5 => READER,
                    6..=12 => WRITER,
                    13..=17 => ADMIN,
                    18 => OWNER,
                    _ => 7,
                };
                vec![SpaceOp::add_member(someone(&mut rng), role)]
            }
            58..=67 if step * 2 > steps || rng.chance(30) => {
                vec![SpaceOp::succeed([1 + rng.below(2) as u8; 32])]
            }
            58..=71 => vec![SpaceOp::leave()],
            72..=80 => {
                let by: Vec<EntryId> = entries
                    .iter()
                    .filter(|e| e.author() == p.log.id())
                    .map(|e| e.id())
                    .collect();
                let from = if rng.chance(85) && !by.is_empty() {
                    &by
                } else {
                    &all
                };
                let listed: Vec<EntryId> = (0..1 + rng.below(2)).map(|_| *rng.pick(from)).collect();
                vec![SpaceOp::keep(p.keys[rng.below(3)].public_key(), &listed)]
            }
            81..=83 => vec![SpaceOp::start(profile, &Policy::default())],
            84..=86 => vec![SpaceOp::set_policy(&Policy::default())],
            87..=88 => vec![SpaceOp::from_record(Record::new().with(0, 20u32))],
            89..=90 => vec![SpaceOp::from_record(Record::new().with(0, 40u32))],
            91..=92 => vec![SpaceOp::rotate(&[])],
            _ => vec![],
        };
        if rng.chance(20) {
            ops.push(if rng.chance(50) { folder() } else { reach() });
        }
        let e = SpaceEntryBuilder::new(space, &parents, p.log.id(), head, epoch.id())
            .ops(ops)
            .sign(&people[signer].keys[key])
            .unwrap();
        for (i, op) in e.ops().iter().enumerate() {
            if op.record() == reach().record() {
                reach_nodes.push((derived_id(&e.id(), i), who));
            }
        }
        let names = |e: &SpaceEntry| e.ops().iter().any(|o| o.record().uint(0) == Ok(8));
        if names(&e) && !forged && rng.chance(40) {
            // another of their devices names a successor too, before
            // hearing of the first
            let other = SpaceEntryBuilder::new(space, &parents, p.log.id(), head, epoch.id())
                .op(SpaceOp::succeed([1 + rng.below(2) as u8; 32]))
                .sign(&people[who].keys[rng.below(3)])
                .unwrap();
            if other.id() != e.id() {
                dag.insert(other.id(), other.parents().to_vec(), other.clone());
                entries.push(other);
            }
        }
        dag.insert(e.id(), e.parents().to_vec(), e.clone());
        entries.push(e);
    }
    History {
        people,
        profile,
        entries,
        epoch,
        enc,
        genesis,
    }
}

impl History {
    fn logs(&self) -> Vec<&IdentityLog> {
        self.people.iter().map(|p| &p.log).collect()
    }

    fn states(&self) -> Vec<Arc<IdentityState>> {
        self.people.iter().map(|p| p.log.state()).collect()
    }

    /// The entries in a random order; the graph holds back the ones whose
    /// parents have not come.
    fn shuffled(&self, rng: &mut Rng) -> Vec<&SpaceEntry> {
        let mut v: Vec<&SpaceEntry> = self.entries.iter().collect();
        for i in (1..v.len()).rev() {
            v.swap(i, rng.below(i + 1));
        }
        v
    }
}

/// Two sets of entries are the same, or the failure says, briefly, which
/// entries are in one only.
fn same(a: &HashSet<EntryId>, b: &HashSet<EntryId>, what: &str) {
    let short = |s: Vec<&EntryId>| -> Vec<String> {
        s.iter()
            .map(|x| format!("{:02x}{:02x}", x[0], x[1]))
            .collect()
    };
    assert!(
        a == b,
        "{what}: only in the first {:?}, only in the second {:?}",
        short(a.difference(b).collect()),
        short(b.difference(a).collect())
    );
}

fn same_validity(a: &Validity, b: &Validity, what: &str) {
    same(&a.author_ok, &b.author_ok, &format!("author_ok, {what}"));
    same(&a.valid, &b.valid, &format!("valid, {what}"));
    same(
        &a.unwitnessed,
        &b.unwitnessed,
        &format!("unwitnessed, {what}"),
    );
    assert!(a.members == b.members, "members, {what}");
}

/// Everything the native evaluation found against everything the program
/// finds, for what has arrived in `dag`.
fn compare(judge: &Judge, dag: &Dag<SpaceEntry>, logs: &[&IdentityLog], what: &str) {
    // an entry held under two signatures is read by the one the judge reads
    let signer = |x: &EntryId, _: &SpaceEntry| judge.key_of(dag, x).unwrap();
    let rules = by_rules_as(dag, logs, &signer).unwrap();
    let found = judge.validity();
    same(
        &found.author_ok,
        &rules.author_ok,
        &format!("author_ok, {what}"),
    );
    same(&found.valid, &rules.valid, &format!("valid, {what}"));
    assert!(found.members == rules.members, "members, {what}");
    let closed: HashSet<EntryId> = dag
        .log_order()
        .iter()
        .filter(|x| judge.is_closed(dag, x))
        .copied()
        .collect();
    same(&closed, &rules.closed, &format!("closed, {what}"));
    assert_eq!(
        judge.candidates(dag),
        rules.candidates,
        "candidates, {what}"
    );
    assert_eq!(judge.successor(dag), rules.successor, "successor, {what}");
    // what waits for a witness is what its key signed in good time and
    // does not count
    assert!(found.unwitnessed.is_disjoint(&found.author_ok), "{what}");
}

fn arrive(judge: &mut Judge, dag: &mut Dag<SpaceEntry>, e: &SpaceEntry) {
    match dag.insert(e.id(), e.parents().to_vec(), e.clone()) {
        Inserted::Added(added) => {
            for x in added {
                judge.arrive(dag, &x);
            }
        }
        // the same entry under another signature
        Inserted::Duplicate => {
            judge.also_signed(dag, &e.id(), e.signer());
        }
        Inserted::Held(_) => {}
    }
}

#[derive(Default)]
struct Tally {
    entries: usize,
    valid: usize,
    counted: usize,
    closed: usize,
    succeeded: usize,
    rivals: usize,
    started: usize,
    ownerless: usize,
    members: usize,
    waiting: usize,
}

fn run(seed: u64, steps: usize, tally: &mut Tally) {
    let h = history(seed, steps);
    let logs = h.logs();
    let mut rng = Rng(seed.rotate_left(17) | 1);

    // 1. In the order written, every identity log held from the start.
    let mut dag = Dag::new();
    let mut judge = Judge::new(h.profile);
    for st in h.states() {
        judge.set_state(&dag, st);
    }
    for e in &h.entries {
        arrive(&mut judge, &mut dag, e);
    }
    compare(&judge, &dag, &logs, &format!("in order (seed {seed})"));
    let found = judge.validity().clone();
    tally.entries += dag.len();
    tally.valid += found.valid.len();
    tally.counted += found.author_ok.len();
    tally.closed += dag.iter().filter(|(x, _)| judge.is_closed(&dag, x)).count();
    tally.succeeded += judge.successor(&dag).is_some() as usize;
    tally.rivals += (judge.candidates(&dag).len() > 1) as usize;
    tally.started += !found.valid.is_empty() as usize;
    tally.ownerless += (!found.valid.is_empty() && judge.owner().is_none()) as usize;
    tally.members += found.members.len();
    tally.waiting += found.unwitnessed.len();

    // 2. In a random order, compared on the way.
    let mut dag = Dag::new();
    let mut judge = Judge::new(h.profile);
    for st in h.states() {
        judge.set_state(&dag, st);
    }
    for e in h.shuffled(&mut rng) {
        arrive(&mut judge, &mut dag, e);
        if !dag.is_empty() && rng.chance(8) {
            compare(&judge, &dag, &logs, &format!("on the way (seed {seed})"));
        }
    }
    compare(&judge, &dag, &logs, &format!("shuffled (seed {seed})"));
    same_validity(judge.validity(), &found, &format!("shuffled (seed {seed})"));

    // 3. In a random order, while identity logs arrive late, and as they
    // were at some earlier time before they are as they are now.
    let mut dag = Dag::new();
    let mut judge = Judge::new(h.profile);
    for p in &h.people {
        if rng.chance(50) {
            judge.set_state(&dag, rng.pick(&p.was).clone());
        }
    }
    for e in h.shuffled(&mut rng) {
        arrive(&mut judge, &mut dag, e);
        if rng.chance(12) {
            let p = rng.pick(&h.people);
            judge.set_state(&dag, rng.pick(&p.was).clone());
        }
    }
    for st in h.states() {
        judge.set_state(&dag, st);
    }
    compare(&judge, &dag, &logs, &format!("late logs (seed {seed})"));
    same_validity(
        judge.validity(),
        &found,
        &format!("late logs (seed {seed})"),
    );
}

#[test]
fn native_matches_rules_fixed_seeds() {
    let mut t = Tally::default();
    for seed in 1..=120 {
        run(seed, 12 + (seed as usize * 7) % 30, &mut t);
    }
    eprintln!(
        "{} entries: {} valid, {} with a signature that counts, {} closed, {} waiting for a \
         witness; {} spaces started, {} with no owner, {} succeeded, {} with a rival; {} \
         members",
        t.entries,
        t.valid,
        t.counted,
        t.closed,
        t.waiting,
        t.started,
        t.ownerless,
        t.succeeded,
        t.rivals,
        t.members
    );
    // the histories reach what the rules are about
    assert!(t.valid * 6 > t.entries && t.valid < t.counted, "valid");
    assert!(t.counted < t.entries, "signatures that do not count");
    assert!(t.closed > 20 && t.succeeded > 10, "successions");
    assert!(t.rivals > 0, "two successors named, of which one stands");
    assert!(t.waiting > 10, "entries waiting for a witness");
    assert!(t.ownerless > 10 && t.started > 80, "kinds of space");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]
    #[test]
    fn native_matches_rules(seed in any::<u64>(), steps in 5usize..45) {
        run(seed, steps, &mut Tally::default());
    }
}

/// The valid heads, by their definition: each valid entry that no other
/// valid entry descends from.
fn valid_heads(space: &Space) -> Vec<EntryId> {
    let valid = &space.validity().valid;
    let mut heads: Vec<EntryId> = valid
        .iter()
        .filter(|x| space.dag().descendants(x).is_disjoint(valid))
        .copied()
        .collect();
    heads.sort();
    heads
}

/// The current epoch, by its definition.
fn current_epoch(space: &Space) -> Option<EntryId> {
    let dag = space.dag();
    let starts =
        |x: &&EntryId| space.validity().is_valid(x) && dag.get(x).is_some_and(|e| e.starts_epoch());
    let starters: Vec<&EntryId> = dag.log_order().iter().filter(starts).collect();
    let open = |s: &&&EntryId| !starters.iter().any(|t| dag.is_ancestor(s, t));
    starters.iter().rfind(open).map(|s| **s)
}

fn check_space(space: &Space, logs: &[&IdentityLog], what: &str) {
    compare(space.judge(), space.dag(), logs, what);
    let again = State::compute(space.profile(), space.dag(), &space.validity().valid);
    assert!(
        space.state().canonical() == again.canonical(),
        "state, {what}"
    );
    assert!(space.heads() == valid_heads(space), "valid heads, {what}");
    let started = space.epoch_started_by().map(|(entry, _)| entry);
    assert_eq!(started, current_epoch(space), "epoch, {what}");
}

fn run_space(seed: u64, steps: usize) -> (u64, u64) {
    let h = history(seed, steps);
    let logs = h.logs();
    let mut rng = Rng(seed.rotate_left(29) | 1);
    let sealed: Vec<SealedEntry> = h.entries[1..]
        .iter()
        .map(|e| SealedEntry::seal(e, &h.epoch, None, false).unwrap())
        .collect();
    // Identity logs come late and change, as they do on a device.
    let ana = rng.chance(60).then(|| h.people[ANA].log.state());
    let Ok(mut space) = Space::open_genesis(&h.genesis, &[h.enc], ana) else {
        // a genesis with no `start` op is not a space to open
        assert!(h.entries[0].profile().is_none());
        return (0, 0);
    };
    let mut order: Vec<&SealedEntry> = sealed.iter().collect();
    for i in (1..order.len()).rev() {
        order.swap(i, rng.below(i + 1));
    }
    for s in order {
        space.receive(s.clone(), &[h.enc]).unwrap();
        match rng.below(100) {
            0..=9 => {
                let p = rng.pick(&h.people);
                space.set_identity(rng.pick(&p.was).clone());
            }
            10..=14 => space.set_identities(h.states()),
            _ => {}
        }
        if rng.chance(6) {
            // whatever logs are held now, what is kept adds up
            let again = State::compute(space.profile(), space.dag(), &space.validity().valid);
            assert!(
                space.state().canonical() == again.canonical(),
                "seed {seed}"
            );
            assert!(
                space.heads() == valid_heads(&space),
                "on the way (seed {seed})"
            );
        }
    }
    space.set_identities(h.states());
    check_space(&space, &logs, &format!("space (seed {seed})"));

    // A device that writes here builds on what it holds valid, and what it
    // writes is judged like anything else.
    let heads = space.heads();
    let ben = &h.people[BEN];
    let wrote = space.write_entry(&ben.log, &ben.keys[0], vec![folder()], None);
    match wrote {
        Ok((id, _)) => {
            let e = space.entry(&id).unwrap();
            assert_eq!(e.parents(), heads.as_slice(), "parents (seed {seed})");
            assert!(!space.ended());
            check_space(&space, &logs, &format!("after a write (seed {seed})"));
        }
        // nothing valid to build on, or the space has ended
        Err(_) => assert!(heads.is_empty() || space.ended(), "seed {seed}"),
    }
    let stats = space.stats();
    (stats.appended, stats.recomputed)
}

#[test]
fn a_space_keeps_what_it_holds_up_to_date() {
    let (mut appended, mut recomputed) = (0, 0);
    for seed in 1..=60 {
        let (a, r) = run_space(seed, 10 + (seed as usize * 5) % 30);
        appended += a;
        recomputed += r;
    }
    eprintln!("{appended} entries appended, {recomputed} recomputations");
    assert!(appended > 0 && recomputed > 0);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]
    #[test]
    fn a_space_keeps_up(seed in any::<u64>(), steps in 5usize..40) {
        run_space(seed, steps);
    }
}

// ------------------------------------------------------------- scenarios
//
// The space scenarios of the specification's `model/scenarios.py`, with real
// entries and real identity logs: each says what the rules must give, and
// each is also compared with the program. Keys are named as there: `a` is a
// person's admin key and `p` their phone, a device key.

const A: usize = 0; // the admin key
const P: usize = 1; // the phone
const CY: usize = 2;

struct Scene {
    people: Vec<Person>,
    dag: Dag<SpaceEntry>,
    judge: Judge,
    named: std::collections::HashMap<&'static str, EntryId>,
    space: EntryId,
}

impl Scene {
    /// A space whose genesis `author` writes with `key`, naming `members`.
    fn new(
        author: usize,
        key: usize,
        members: &[(usize, u64)],
        succeeds: Option<[u8; 32]>,
    ) -> Scene {
        let people = people();
        let from = cardinal_space::entry::Succession {
            succeeds,
            ..Default::default()
        };
        let mut ops = vec![SpaceOp::start_with(
            group::GROUP,
            &Policy::default(),
            None,
            &from,
        )];
        ops.extend(
            members
                .iter()
                .map(|(m, r)| SpaceOp::add_member(people[*m].log.id(), *r)),
        );
        let head = *people[author].log.dag().log_order().last().unwrap();
        let g = SpaceEntryBuilder::genesis(people[author].log.id(), head, [1; 16])
            .ops(ops)
            .sign(&people[author].keys[key])
            .unwrap();
        let mut scene = Scene {
            people,
            dag: Dag::new(),
            judge: Judge::new(group::GROUP),
            named: Default::default(),
            space: g.id(),
        };
        for p in &scene.people {
            scene.judge.set_state(&scene.dag, p.log.state());
        }
        scene.named.insert("genesis", g.id());
        arrive(&mut scene.judge, &mut scene.dag, &g);
        scene
    }

    fn id(&self, who: usize) -> [u8; 32] {
        self.people[who].log.id()
    }

    /// Writes an entry: on the heads of everything, or on `parents`.
    fn write(
        &mut self,
        name: &'static str,
        who: usize,
        key: usize,
        ops: Vec<SpaceOp>,
        parents: Option<&[&str]>,
    ) {
        let parents: Vec<EntryId> = match parents {
            Some(names) => names.iter().map(|n| self.named[n]).collect(),
            None => self.dag.heads(),
        };
        let p = &self.people[who];
        let head = *p.log.dag().log_order().last().unwrap();
        // the time tells apart two entries that say the same thing in the
        // same place: without it they would be one entry, signed twice
        let e = SpaceEntryBuilder::new(self.space, &parents, p.log.id(), head, [1; 16])
            .ops(ops)
            .time(self.named.len() as u64)
            .sign(&p.keys[key])
            .unwrap();
        self.named.insert(name, e.id());
        arrive(&mut self.judge, &mut self.dag, &e);
    }

    /// Removes a person's phone from their identity.
    fn remove_phone(&mut self, who: usize) {
        let p = &mut self.people[who];
        let key = p.keys[P].public_key();
        p.log.remove_key(&p.keys[A], &key).unwrap();
        self.judge.set_state(&self.dag, p.log.state());
    }

    fn valid(&self, names: &[&str]) -> Vec<bool> {
        let logs: Vec<&IdentityLog> = self.people.iter().map(|p| &p.log).collect();
        compare(&self.judge, &self.dag, &logs, "scenario");
        let valid = &self.judge.validity().valid;
        names
            .iter()
            .map(|n| valid.contains(&self.named[n]))
            .collect()
    }

    fn all_valid(&self, names: &[&str]) -> bool {
        self.valid(names).iter().all(|v| *v)
    }

    fn none_valid(&self, names: &[&str]) -> bool {
        !self.valid(names).iter().any(|v| *v)
    }

    fn is_member(&self, who: usize, role: u64) -> bool {
        let m = cardinal_space::Member {
            identity: self.id(who),
            role,
        };
        self.judge.validity().members.contains(&m)
    }

    fn successor(&self) -> Option<[u8; 32]> {
        self.judge.successor(&self.dag)
    }
}

fn add(s: &Scene, who: usize, role: u64) -> Vec<SpaceOp> {
    vec![SpaceOp::add_member(s.id(who), role)]
}

fn app() -> Vec<SpaceOp> {
    vec![folder()]
}

fn succeed(n: u8) -> Vec<SpaceOp> {
    vec![SpaceOp::succeed([n; 32])]
}

fn keep(s: &Scene, who: usize, key: usize, listed: &[&str]) -> Vec<SpaceOp> {
    let listed: Vec<EntryId> = listed.iter().map(|n| s.named[n]).collect();
    vec![SpaceOp::keep(s.people[who].keys[key].public_key(), &listed)]
}

#[test]
fn witnessing_does_not_loop_through_members() {
    let mut s = Scene::new(ANA, A, &[(ANA, OWNER)], None);
    s.write("x", ANA, P, add(&s, BEN, WRITER), None);
    s.write("w", ANA, A, app(), None);
    s.write("ben", BEN, P, app(), None);
    // her phone is removed from an old point in her log, which the witness
    // does not cite
    let ana = &mut s.people[ANA];
    let (log, phone) = (ana.log.id(), ana.keys[P].public_key());
    let lost = EntryBuilder::new(log, &[log])
        .op(IdentityOp::remove_key(phone))
        .sign(&ana.keys[A])
        .unwrap();
    ana.log.insert(lost).unwrap();
    s.judge.set_state(&s.dag, s.people[ANA].log.state());
    assert!(s.all_valid(&["x", "w", "ben"]) && s.is_member(BEN, WRITER));
}

#[test]
fn roles_are_only_given() {
    // adding someone again takes nothing away: there is no lowering, and an
    // admin's additions stand whatever is written beside them or after
    let mut s = Scene::new(ANA, A, &[(ANA, OWNER)], None);
    s.write("e1", ANA, A, add(&s, BEN, ADMIN), None);
    s.write("again", ANA, A, add(&s, BEN, READER), None);
    s.write("add", BEN, P, add(&s, CY, WRITER), None);
    s.write("cy", CY, P, app(), None);
    s.write("old", BEN, P, add(&s, CY, ADMIN), Some(&["e1"]));
    assert!(s.all_valid(&["add", "cy", "old"]));
    assert!(s.is_member(BEN, ADMIN) && s.is_member(BEN, READER));
    assert!(s.is_member(CY, WRITER) && s.is_member(CY, ADMIN));
    assert_eq!(s.judge.validity().role_of(&s.id(BEN)), Some(ADMIN));
}

#[test]
fn a_role_counts_from_the_entry_that_gave_it() {
    let mut s = Scene::new(ANA, A, &[(ANA, OWNER)], None);
    s.write("e1", ANA, A, add(&s, BEN, READER), None);
    s.write("e2", ANA, A, add(&s, BEN, WRITER), None);
    s.write("early", BEN, P, app(), Some(&["e1"])); // still a reader there
    s.write("late", BEN, P, app(), Some(&["e2"]));
    assert_eq!(s.valid(&["early", "late"]), [false, true]);
}

#[test]
fn a_reader_writes_its_own_reach_node_and_nothing_else() {
    let mut s = Scene::new(ANA, A, &[(ANA, OWNER), (BEN, READER), (CY, READER)], None);
    s.write("reach", BEN, P, vec![reach()], None);
    s.write("message", BEN, P, app(), None);
    let node = derived_id(&s.named["reach"], 0);
    let there = || vec![SpaceOp::set(node, 1, Some(Value::from("there")))];
    s.write("moved", BEN, A, there(), None);
    // not someone else's, and not before it was made
    s.write("theirs", CY, P, there(), None);
    s.write("before", BEN, P, there(), Some(&["genesis"]));
    s.write("empty", CY, P, vec![], None);
    assert_eq!(
        s.valid(&["reach", "message", "moved", "theirs", "before", "empty"]),
        [true, false, true, false, false, true]
    );
}

#[test]
fn leaving_is_a_statement() {
    let mut s = Scene::new(ANA, A, &[(ANA, OWNER)], None);
    s.write("e1", ANA, A, add(&s, CY, WRITER), None);
    assert!(!s.judge.has_left(&s.dag, &s.id(CY)));
    s.write("bye", CY, P, vec![SpaceOp::leave()], None);
    s.write("back", CY, P, app(), None);
    s.write("old", CY, P, app(), Some(&["e1"]));
    // it changes nothing about what is valid
    assert!(s.all_valid(&["bye", "back", "old"]) && s.is_member(CY, WRITER));
    assert!(s.judge.has_left(&s.dag, &s.id(CY)));
    assert!(!s.judge.has_left(&s.dag, &s.id(ANA)));
    // one who is added again is back, if the addition had seen them leave
    s.write("beside", ANA, A, add(&s, CY, WRITER), Some(&["e1"]));
    assert!(s.judge.has_left(&s.dag, &s.id(CY)));
    s.write("again", ANA, A, add(&s, CY, READER), None);
    assert!(!s.judge.has_left(&s.dag, &s.id(CY)));
    // a stranger's leave is nobody's
    s.write("eve", EVE, A, vec![SpaceOp::leave()], None);
    assert!(s.none_valid(&["eve"]) && !s.judge.has_left(&s.dag, &s.id(EVE)));
}

#[test]
fn succession_closes_the_old_space() {
    let mut s = Scene::new(ANA, A, &[(ANA, OWNER)], None);
    s.write("e1", ANA, A, add(&s, BEN, ADMIN), None);
    s.write("inflight", BEN, P, app(), Some(&["e1"]));
    s.write("succ", ANA, A, succeed(7), Some(&["e1"]));
    s.write("after", BEN, P, app(), Some(&["succ", "inflight"]));
    s.write("addafter", BEN, P, add(&s, BEN, ADMIN), Some(&["succ"]));
    assert!(s.all_valid(&["succ", "inflight"]) && s.none_valid(&["after", "addafter"]));
    assert_eq!(s.successor(), Some([7; 32]));
    assert!(s.judge.closes(&s.dag, &[s.named["succ"]]));
    assert!(!s.judge.closes(&s.dag, &[s.named["inflight"]]));
}

#[test]
fn only_the_owner_ends_a_space() {
    let mut s = Scene::new(ANA, A, &[(ANA, OWNER)], None);
    s.write("e1", ANA, A, add(&s, BEN, ADMIN), None);
    s.write("coup", BEN, P, succeed(2), None);
    s.write("crown", BEN, P, add(&s, BEN, OWNER), Some(&["e1"]));
    s.write("eve", EVE, P, succeed(3), Some(&["genesis"]));
    s.write("work", ANA, A, app(), None);
    assert!(s.none_valid(&["coup", "crown", "eve"]) && s.all_valid(&["work"]));
    assert_eq!(s.successor(), None);
    assert_eq!(s.judge.owner(), Some(s.id(ANA)));
    assert!(!s.is_member(BEN, OWNER));
}

#[test]
fn of_two_successors_the_smallest_id_stands() {
    // two of the owner's devices each succeed before hearing of the other
    let mut s = Scene::new(ANA, A, &[(ANA, OWNER)], None);
    s.write("e1", ANA, A, add(&s, BEN, WRITER), None);
    s.write("s2", ANA, A, succeed(2), Some(&["e1"]));
    s.write("s1", ANA, P, succeed(1), Some(&["e1"]));
    s.write("x", BEN, P, app(), Some(&["s2"]));
    assert!(s.all_valid(&["s1", "s2"]) && s.none_valid(&["x"]));
    assert_eq!(s.successor(), Some([1; 32]));
    // a succeed that descends from one is invalid like any entry there, and
    // names nothing, however small the id it names
    s.write("s0", ANA, A, succeed(0), Some(&["s1"]));
    assert!(s.none_valid(&["s0"]));
    assert_eq!(s.successor(), Some([1; 32]));
}

#[test]
fn a_stolen_phone_s_succession_stands_or_falls_with_its_key() {
    let mut s = Scene::new(ANA, A, &[(ANA, OWNER)], None);
    s.write("e1", ANA, A, add(&s, BEN, WRITER), None);
    s.write("b1", BEN, P, app(), None);
    // a thief holding Ana's phone succeeds the space, from an old point
    s.write("t", ANA, P, succeed(7), Some(&["e1"]));
    s.write("b2", BEN, P, app(), Some(&["t", "b1"]));
    assert_eq!(s.valid(&["b1", "b2"]), [true, false]);
    assert_eq!(s.successor(), Some([7; 32]));
    // her laptop builds on it, as it would after following. That witnesses
    // nothing: what ends a space is kept on purpose, or not at all
    s.write("a3", ANA, A, vec![reach()], Some(&["t"]));
    // Ana removes the phone. The succeed is void, the space is open again,
    // and nothing honest was lost
    s.remove_phone(ANA);
    assert_eq!(s.valid(&["t", "e1", "b1", "b2"]), [false, true, true, true]);
    assert_eq!(s.successor(), None);
    // or she keeps it, and puts things right in the successor. A keep counts
    // by its signature alone, so it works in the space it closes
    s.write("k", ANA, A, keep(&s, ANA, P, &["t"]), Some(&["t"]));
    assert_eq!(s.valid(&["t", "b2", "k"]), [true, false, false]);
    assert_eq!(s.successor(), Some([7; 32]));
}

#[test]
fn a_successor_s_genesis_is_kept_never_witnessed() {
    // a plain genesis by the phone is witnessed by the laptop building on it
    let mut s = Scene::new(ANA, P, &[(ANA, OWNER)], None);
    s.write("w", ANA, A, add(&s, BEN, WRITER), None);
    s.remove_phone(ANA);
    assert!(s.all_valid(&["genesis", "w"]));
    // a successor's genesis by the phone is not, however much is built on it
    let mut t = Scene::new(ANA, P, &[(ANA, OWNER), (BEN, WRITER)], Some([9; 32]));
    t.write("tw", ANA, A, app(), None);
    t.write("tb", BEN, P, app(), None);
    t.remove_phone(ANA);
    assert!(t.none_valid(&["genesis", "tw", "tb"]));
    assert!(t.judge.validity().members.is_empty());
    // kept, it stands with everything written in it
    t.write("k", ANA, A, keep(&t, ANA, P, &["genesis"]), None);
    assert!(t.all_valid(&["genesis", "tw", "tb", "k"]));
}

#[test]
fn a_space_with_no_owner_ends_when_every_member_says_so() {
    let mut s = Scene::new(ANA, A, &[(ANA, WRITER), (BEN, WRITER)], None);
    assert_eq!(s.judge.owner(), None);
    assert_eq!(s.judge.deciders().len(), 2);
    s.write("m1", BEN, P, app(), None);
    s.write("add", ANA, A, add(&s, CY, READER), Some(&["m1"]));
    s.write("pa", ANA, A, succeed(7), Some(&["m1"]));
    s.write("m2", ANA, A, app(), Some(&["pa"]));
    // nobody may add to it, and one member's word ends nothing
    assert_eq!(
        s.valid(&["m1", "pa", "m2", "add"]),
        [true, true, true, false]
    );
    assert_eq!(s.successor(), None);
    s.write("pb", BEN, P, succeed(7), Some(&["m2"]));
    s.write("m3", BEN, P, app(), Some(&["pb"]));
    s.write("m4", ANA, A, app(), Some(&["m2"]));
    // closed is what descends from both namings; what had seen only one
    // stands
    assert_eq!(
        s.valid(&["m2", "pb", "m4", "m3"]),
        [true, true, true, false]
    );
    assert_eq!(s.successor(), Some([7; 32]));
    // two heads that have each seen one naming: what is written on both
    // would descend from the end
    let (pb, m4) = (s.named["pb"], s.named["m4"]);
    assert!(s.judge.closes(&s.dag, &[pb]) && !s.judge.closes(&s.dag, &[m4]));

    // naming different successors agrees on none
    let mut c = Scene::new(ANA, A, &[(ANA, WRITER), (BEN, WRITER)], None);
    c.write("pa", ANA, A, succeed(1), Some(&["genesis"]));
    c.write("pb", BEN, P, succeed(2), Some(&["genesis"]));
    c.write("m", BEN, P, app(), None);
    assert!(c.all_valid(&["m"]));
    assert_eq!(c.successor(), None);
}

#[test]
fn a_genesis_names_one_owner_its_author_or_none() {
    let shapes: [&[(usize, u64)]; 6] = [
        &[(ANA, OWNER), (BEN, OWNER)],  // two owners
        &[(ANA, WRITER), (BEN, OWNER)], // an owner who did not write it
        &[(ANA, WRITER), (BEN, ADMIN)], // no owner, yet an admin
        &[(BEN, WRITER)],               // its author is not in it
        &[(ANA, OWNER), (ANA, OWNER)],  // an owner named twice
        &[(ANA, WRITER), (BEN, 4)],     // a role there is not
    ];
    for members in shapes {
        let mut s = Scene::new(ANA, A, members, None);
        s.write("x", BEN, P, app(), None);
        assert!(s.none_valid(&["genesis", "x"]), "{members:?}");
        assert!(s.judge.validity().members.is_empty(), "{members:?}");
    }
    // what it holds besides its members is what its author's role allows
    for (role, ops, good) in [
        (WRITER, app(), true),
        (READER, app(), false),
        (READER, vec![reach()], true),
        (OWNER, vec![SpaceOp::set_policy(&Policy::default())], true),
        (WRITER, vec![SpaceOp::set_policy(&Policy::default())], false),
        (OWNER, succeed(7), false),
        (
            OWNER,
            vec![SpaceOp::start(group::GROUP, &Policy::default())],
            false,
        ),
    ] {
        let people = people();
        let ana = &people[ANA];
        let mut all = vec![
            SpaceOp::start(group::GROUP, &Policy::default()),
            SpaceOp::add_member(ana.log.id(), role),
        ];
        all.extend(ops);
        let head = *ana.log.dag().log_order().last().unwrap();
        let g = SpaceEntryBuilder::genesis(ana.log.id(), head, [1; 16])
            .ops(all)
            .sign(&ana.keys[A])
            .unwrap();
        let (mut dag, mut judge) = (Dag::new(), Judge::new(group::GROUP));
        judge.set_state(&dag, ana.log.state());
        arrive(&mut judge, &mut dag, &g);
        let logs: Vec<&IdentityLog> = people.iter().map(|p| &p.log).collect();
        compare(&judge, &dag, &logs, "a genesis");
        assert_eq!(
            judge.validity().is_valid(&g.id()),
            good,
            "{role} {:?}",
            g.ops()
        );
    }
}

#[test]
fn removed_device_entries_need_a_witness() {
    let mut s = Scene::new(ANA, A, &[(ANA, OWNER)], None);
    s.write("p1", ANA, P, app(), None); // seen by the laptop
    s.write("w", ANA, A, app(), None);
    s.write("p2", ANA, P, app(), Some(&["p1"])); // never seen
    s.remove_phone(ANA);
    assert_eq!(s.valid(&["p1", "p2"]), [true, false]);
    assert!(s.judge.validity().unwitnessed.contains(&s.named["p2"]));
    s.write("k", ANA, A, keep(&s, ANA, P, &["p2"]), None);
    assert!(s.all_valid(&["p2"]));
    assert!(s.judge.validity().unwitnessed.is_empty());
}

#[test]
fn a_removed_device_s_additions_fall_with_it() {
    // the one way an entry is voided from outside its own past: a signature
    // it rests on stops counting
    let mut s = Scene::new(ANA, A, &[(ANA, OWNER)], None);
    s.write("add", ANA, P, add(&s, BEN, WRITER), None);
    s.write("ben", BEN, P, app(), None);
    assert!(s.all_valid(&["add", "ben"]));
    s.remove_phone(ANA);
    assert!(s.none_valid(&["add", "ben"]) && !s.is_member(BEN, WRITER));
    s.write("k", ANA, A, keep(&s, ANA, P, &["add"]), None);
    assert!(s.all_valid(&["add", "ben"]) && s.is_member(BEN, WRITER));
}

#[test]
fn a_frozen_member_is_judged_like_anyone() {
    // freezing cuts an identity off by sessions and by keys, and the owner
    // succeeds the space without it. No rule voids what its keys wrote
    let mut s = Scene::new(ANA, A, &[(ANA, OWNER)], None);
    s.write("e1", ANA, A, add(&s, CY, WRITER), None);
    s.write("t1", CY, A, app(), None);
    // Cy's root replaces itself twice, each without knowing of the other
    let phrase = |n: u8| RecoveryPhrase::from_entropy(&[n; 32]);
    let root = phrase(CY as u8 + 40).root_signing_key();
    let cy = s.id(CY);
    for n in [90, 91] {
        let next = phrase(n);
        let key = next.root_signing_key();
        let proof = cardinal_identity::entry::add_key_proof(&key, &cy, Power::Root, None);
        let e = EntryBuilder::new(cy, &[cy])
            .op(IdentityOp::add_key(
                key.public_key(),
                Power::Root,
                None,
                Some(proof),
                Some(next.recovery_key_pair().public_key()),
            ))
            .op(IdentityOp::remove_key(root.public_key()))
            .sign(&root)
            .unwrap();
        s.people[CY].log.insert(e).unwrap();
    }
    let frozen = s.people[CY].log.state();
    assert!(frozen.frozen);
    s.judge.set_state(&s.dag, frozen);
    s.write("t2", CY, A, app(), None);
    assert!(s.all_valid(&["t1", "t2"]));
}

#[test]
fn an_entry_signed_twice_is_judged_by_one_key_whichever_came_first() {
    // The id of an entry does not cover its signature. Whoever holds a key
    // can sign someone's entry again; that must neither void it nor depend
    // on which signed object a device saw first.
    let people = people();
    let (ana, eve) = (&people[ANA], &people[EVE]);
    let head = *ana.log.dag().log_order().last().unwrap();
    let genesis = || {
        SpaceEntryBuilder::genesis(ana.log.id(), head, [1; 16])
            .op(SpaceOp::start(group::GROUP, &Policy::default()))
            .op(SpaceOp::add_member(ana.log.id(), OWNER))
    };
    let g = genesis().sign(&ana.keys[A]).unwrap();
    let entry = |key: &SigningKey| {
        SpaceEntryBuilder::new(g.id(), &[g.id()], ana.log.id(), head, [1; 16])
            .op(folder())
            .sign(key)
            .unwrap()
    };
    let (hers, forged, phone) = (
        entry(&ana.keys[A]),
        entry(&eve.keys[A]),
        entry(&ana.keys[P]),
    );
    assert!(hers.id() == forged.id() && hers.id() == phone.id());
    let mut logs = people.iter().map(|p| &p.log).collect::<Vec<_>>();
    // of her two keys, both in effect, the smaller: never the stranger's
    let (a, p) = (ana.keys[A].public_key(), ana.keys[P].public_key());
    let chosen = a.min(p);
    for order in [
        [&hers, &forged, &phone],
        [&forged, &phone, &hers],
        [&phone, &hers, &forged],
    ] {
        let (mut dag, mut judge) = (Dag::new(), Judge::new(group::GROUP));
        for p in &people {
            judge.set_state(&dag, p.log.state());
        }
        arrive(&mut judge, &mut dag, &g);
        for e in order {
            arrive(&mut judge, &mut dag, e);
        }
        compare(&judge, &dag, &logs, "signed twice");
        assert!(judge.validity().is_valid(&hers.id()));
        assert!(judge.key_of(&dag, &hers.id()) == Some(chosen));
    }
    // With only the phone's signature and a stranger's, the entry is the
    // phone's, and falls with it.
    let mut people = people;
    let (mut dag, mut judge) = (Dag::new(), Judge::new(group::GROUP));
    for p in &people {
        judge.set_state(&dag, p.log.state());
    }
    for e in [&g, &forged, &phone] {
        arrive(&mut judge, &mut dag, e);
    }
    assert!(judge.validity().is_valid(&hers.id()));
    let ana = &mut people[ANA];
    let key = ana.keys[P].public_key();
    ana.log.remove_key(&ana.keys[A], &key).unwrap();
    judge.set_state(&dag, ana.log.state());
    assert!(!judge.validity().is_valid(&hers.id()));
    logs = people.iter().map(|p| &p.log).collect();
    compare(&judge, &dag, &logs, "signed twice, and the key removed");
    // Her own signature, arriving last, is the one that counts.
    arrive(&mut judge, &mut dag, &hers);
    assert!(judge.validity().is_valid(&hers.id()));
    assert!(judge.key_of(&dag, &hers.id()) == Some(a));
    compare(&judge, &dag, &logs, "signed twice, and then by her");
}
