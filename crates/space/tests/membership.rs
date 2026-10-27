//! Property: for spaces whose only member is their creator, the native
//! membership evaluation agrees with the normative `space` program of
//! `model/rules.md`, on random histories with removed devices, stale
//! heads, witnesses, keep ops, leaving, and malformed ops.

use cardinal_crypto::{HybridKeyPair, RecoveryPhrase};
use cardinal_encoding::Record;
use cardinal_identity::dag::Dag;
use cardinal_identity::{Created, DeviceKeys, EntryId, IdentityLog, Power};
use cardinal_space::membership::{evaluate_full, evaluate_single};
use cardinal_space::{files, Policy, Profile, SpaceEntry, SpaceEntryBuilder, SpaceOp, ROOT};
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
}

fn run(seed: u64, steps: usize) -> (usize, usize) {
    let mut rng = Rng(seed | 1);
    let d0 = DeviceKeys::generate();
    let Created { mut log, .. } = IdentityLog::create_with(
        RecoveryPhrase::from_entropy(&[seed as u8; 32]),
        &d0,
        HybridKeyPair::generate(),
    )
    .unwrap();
    let mut devices = vec![d0];
    for _ in 0..2 {
        let d = DeviceKeys::generate();
        log.add_key(
            &devices[0].signing,
            &d.request(&log.id(), Power::Device),
            None,
        )
        .unwrap();
        devices.push(d);
    }
    let me = log.id();
    let epoch = [1u8; 16];
    let g = SpaceEntryBuilder::genesis(me, *log.dag().log_order().last().unwrap(), epoch)
        .op(SpaceOp::start(Profile::FILES, &Policy::default()))
        .sign(&devices[0].signing)
        .unwrap();
    let i0 = g.genesis_membership().unwrap();
    let space = g.id();
    let mut dag: Dag<SpaceEntry> = Dag::new();
    let mut ids: Vec<EntryId> = vec![space];
    dag.insert(space, vec![], g);
    let mut removed = [false; 3];
    for step in 0..steps {
        if rng.below(10) == 0 {
            let k = 1 + rng.below(2);
            if !removed[k] {
                log.remove_key(&devices[0].signing, &devices[k].key())
                    .unwrap();
                removed[k] = true;
            }
            continue;
        }
        let who = rng.below(3);
        let mut parents = vec![ids[rng.below(ids.len())]];
        if rng.below(2) == 0 {
            parents.push(ids[rng.below(ids.len())]);
        }
        if rng.below(2) == 0 {
            parents = dag.heads();
        }
        let order = log.dag().log_order();
        let head = if rng.below(3) == 0 {
            order[rng.below(order.len())]
        } else {
            *order.last().unwrap()
        };
        let membership = match rng.below(12) {
            0 => None,
            1 => Some([7u8; 16]),
            _ => Some(i0),
        };
        let op = match rng.below(14) {
            0 => SpaceOp::remove_member(i0),
            1 if step > steps / 2 => SpaceOp::succeed([3; 32]),
            2 => SpaceOp::remove_member([7; 16]),
            3 | 4 => {
                let k = 1 + rng.below(2);
                let theirs: Vec<EntryId> = ids
                    .iter()
                    .filter(|x| dag.get(x).unwrap().signer() == devices[k].key())
                    .copied()
                    .collect();
                let pick: Vec<EntryId> = theirs
                    .iter()
                    .filter(|_| rng.below(2) == 0)
                    .copied()
                    .collect();
                SpaceOp::keep(devices[k].key(), &pick)
            }
            5 => SpaceOp::from_record(Record::new().with(0, 20u32)),
            6 => SpaceOp::start(Profile::FILES, &Policy::default()),
            _ => files::create_folder(ROOT, "x"),
        };
        let mut b = SpaceEntryBuilder::new(space, &parents, me, head, epoch, membership).op(op);
        if rng.below(4) == 0 {
            b = b.op(files::create_folder(ROOT, "y"));
        }
        let e = b.sign(&devices[who].signing).unwrap();
        let id = e.id();
        dag.insert(id, e.parents().to_vec(), e);
        ids.push(id);
    }
    let state = log.state();
    let native = evaluate_single(&dag, &state).unwrap();
    let full = evaluate_full(&dag, &[&log]).unwrap();
    assert_eq!(native.valid, full.valid, "valid (seed {seed})");
    assert_eq!(native.author_ok, full.author_ok, "author_ok (seed {seed})");
    assert_eq!(native.members, full.members, "members (seed {seed})");
    (native.valid.len(), dag.len())
}

#[test]
fn native_matches_rules_fixed_seeds() {
    let (mut valid, mut total) = (0, 0);
    for seed in 1..30 {
        let (v, t) = run(seed, 30);
        valid += v;
        total += t;
    }
    eprintln!("{valid} of {total} entries valid");
    assert!(valid > total / 5 && valid < total, "{valid} of {total}");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]
    #[test]
    fn native_matches_rules(seed in any::<u64>(), steps in 5usize..40) {
        run(seed, steps);
    }
}
