//! Property: replicas that write concurrently and exchange entries in any
//! order converge to the same state, and incremental updates give the same
//! state as computing from scratch.

use cardinal_crypto::{HybridKeyPair, RecoveryPhrase};
use cardinal_identity::{Created, DeviceKeys, IdentityLog, Power};
use cardinal_space::files::{self, Content};
use cardinal_space::{NodeId, NodeKind, Policy, Profile, Space, SpaceOp, State, ROOT};
use proptest::prelude::*;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            let j = self.below(i + 1);
            v.swap(i, j);
        }
    }
}

const NAMES: [&str; 4] = ["a", "b", "a.txt", "c"];

fn random_ops(rng: &mut Rng, st: &State) -> Vec<SpaceOp> {
    let mut nodes: Vec<NodeId> = st.nodes().map(|n| n.id).collect();
    nodes.sort();
    let folders: Vec<NodeId> = std::iter::once(ROOT)
        .chain(
            nodes
                .iter()
                .copied()
                .filter(|n| st.node(n).unwrap().kind == NodeKind::Uint(files::FOLDER)),
        )
        .collect();
    let filez: Vec<NodeId> = nodes
        .iter()
        .copied()
        .filter(|n| st.node(n).unwrap().kind == NodeKind::Uint(files::FILE))
        .collect();
    let mut ops = Vec::new();
    for _ in 0..1 + rng.below(3) {
        let folder = folders[rng.below(folders.len())];
        let name = NAMES[rng.below(NAMES.len())];
        let content = Content::Inline(vec![rng.below(256) as u8]);
        let op = match rng.below(20) {
            0..=4 => files::create_folder(folder, name),
            5..=8 => files::create_file(folder, name, &content, 0o644, None),
            9..=12 if !filez.is_empty() => {
                files::set_content(filez[rng.below(filez.len())], &content)
            }
            13..=15 if !nodes.is_empty() => {
                SpaceOp::mv(nodes[rng.below(nodes.len())], folder, name)
            }
            16..=17 if !nodes.is_empty() => SpaceOp::delete(nodes[rng.below(nodes.len())]),
            18 if !nodes.is_empty() => SpaceOp::restore(nodes[rng.below(nodes.len())]),
            _ => files::create_folder(ROOT, name),
        };
        ops.push(op);
    }
    ops
}

fn deliver(rng: &mut Rng, from: &Space, to: &mut Space, keys: &HybridKeyPair) {
    let mut missing: Vec<_> = from
        .dag()
        .log_order()
        .iter()
        .filter(|id| !to.dag().contains(id))
        .copied()
        .collect();
    rng.shuffle(&mut missing);
    for id in missing {
        to.receive(from.sealed(&id).unwrap().clone(), &[keys])
            .unwrap();
    }
}

/// Returns (field conflicts, delete conflicts, deleted nodes, appended, recomputed).
fn run(seed: u64, replicas: usize, steps: usize) -> [u64; 5] {
    let mut rng = Rng(seed | 1);
    let d0 = DeviceKeys::generate();
    let Created {
        mut log,
        encryption,
        ..
    } = IdentityLog::create_with(
        RecoveryPhrase::from_entropy(&[seed as u8; 32]),
        &d0,
        HybridKeyPair::generate(),
    )
    .unwrap();
    let mut devices = vec![d0];
    for _ in 1..replicas {
        let d = DeviceKeys::generate();
        log.add_key(
            &devices[0].signing,
            &d.request(&log.id(), Power::Device),
            Some(&encryption),
        )
        .unwrap();
        devices.push(d);
    }
    let (first, genesis) = Space::create(
        Profile::FILES,
        Policy::default(),
        &log,
        &devices[0].signing,
        &[encryption.public_key()],
        None,
    )
    .unwrap();
    let mut spaces = vec![first];
    for _ in 1..replicas {
        spaces.push(Space::open_genesis(&genesis, &[&encryption], Some(log.state())).unwrap());
    }
    for _ in 0..steps {
        let r = rng.below(replicas);
        if rng.below(3) == 0 {
            let s = rng.below(replicas);
            if s != r {
                let (a, b) = if s < r {
                    let (x, y) = spaces.split_at_mut(r);
                    (&x[s], &mut y[0])
                } else {
                    let (x, y) = spaces.split_at_mut(s);
                    (&y[0], &mut x[r])
                };
                deliver(&mut rng, a, b, &encryption);
            }
        } else {
            let ops = random_ops(&mut rng, spaces[r].state());
            spaces[r]
                .write(&log, &devices[r].signing, ops, None)
                .unwrap();
        }
    }
    // everyone gets everything, in random orders
    for r in 0..replicas {
        for s in 0..replicas {
            if r != s {
                let from = std::mem::replace(
                    &mut spaces[s],
                    Space::open_genesis(&genesis, &[&encryption], Some(log.state())).unwrap(),
                );
                deliver(&mut rng, &from, &mut spaces[r], &encryption);
                spaces[s] = from;
            }
        }
    }
    // a fresh replica receiving everything at once, shuffled
    let mut fresh = Space::open_genesis(&genesis, &[&encryption], Some(log.state())).unwrap();
    deliver(&mut rng, &spaces[0], &mut fresh, &encryption);
    let want = spaces[0].state().canonical();
    for s in spaces.iter().chain(std::iter::once(&fresh)) {
        assert_eq!(s.dag().len(), spaces[0].dag().len());
        assert_eq!(
            s.state().canonical(),
            want,
            "replicas diverged (seed {seed})"
        );
        let full = State::compute(Profile::FILES, s.dag(), &s.validity().valid);
        assert_eq!(full.canonical(), want, "incremental differs (seed {seed})");
    }
    let st = spaces[0].state();
    let stats: Vec<_> = spaces.iter().map(|s| s.stats()).collect();
    [
        st.nodes()
            .filter(|n| n.fields.values().any(|v| v.len() > 1))
            .count() as u64,
        st.nodes().filter(|n| n.delete_conflict).count() as u64,
        st.nodes().filter(|n| n.deleted).count() as u64,
        stats.iter().map(|s| s.appended).sum(),
        stats.iter().map(|s| s.recomputed).sum(),
    ]
}

#[test]
fn converges_fixed_seeds() {
    // Keys are random, so how often each case comes up varies: content
    // conflicts are rare (2 to 7 in 8 seeds). Run 8 seeds, and more until
    // every case has come up.
    let mut total = [0u64; 5];
    for seed in 1..=64 {
        let r = run(seed, 3, 50);
        for i in 0..5 {
            total[i] += r[i];
        }
        if seed >= 8 && total.iter().all(|&t| t > 0) {
            break;
        }
    }
    eprintln!("conflicts, delete conflicts, deleted, appended, recomputed: {total:?}");
    // the histories exercise what they are meant to
    assert!(total.iter().all(|&t| t > 0), "{total:?}");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]
    #[test]
    fn converges(seed in any::<u64>(), replicas in 2usize..5, steps in 10usize..60) {
        run(seed, replicas, steps);
    }
}
