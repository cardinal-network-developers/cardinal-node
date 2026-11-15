//! What working the state out, and judging entries, cost in memory (review
//! findings V1 and V3).
//!
//! This file is a test binary of its own, and its tests run one at a time,
//! because it counts every allocation the process makes.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use cardinal_crypto::{HybridKeyPair, RecoveryPhrase};
use cardinal_encoding::Record;
use cardinal_identity::{Created, DeviceKeys, IdentityLog};
use cardinal_space::entry::derived_id;
use cardinal_space::files;
use cardinal_space::{NodeKind, Policy, Profile, Space, SpaceOp, State, ROOT};

struct Counting;

static NOW: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let now = NOW.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
        PEAK.fetch_max(now, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        NOW.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// One test at a time: each reads what the whole process has allocated.
static ONE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Two entries from one writer: a folder with a few thousand nodes in it,
/// and the same `delete` of that folder a few thousand times, with one
/// entry beside it so that the state is worked out from scratch. Each
/// delete takes everything beneath the folder. Holding what every one of
/// them takes at once is the number of deletes times the size of the
/// folder; a device must hold no more than one at a time.
#[test]
fn many_deletes_of_one_large_folder_are_not_all_held_at_once() {
    let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
    // `V1_CHILDREN` and `V1_DELETES` measure another size, and then
    // nothing is asserted of the peak.
    let size = |name: &str| {
        std::env::var(name)
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
    };
    let measuring = size("V1_CHILDREN").is_some() || size("V1_DELETES").is_some();
    let children = size("V1_CHILDREN").unwrap_or(500) as u32;
    let deletes = size("V1_DELETES").unwrap_or(2_000);
    let device = DeviceKeys::generate();
    let Created {
        log, encryption, ..
    } = IdentityLog::create_with(
        RecoveryPhrase::from_entropy(&[81; 32]),
        &device,
        HybridKeyPair::generate(),
    )
    .unwrap();
    let (mut space, _) = Space::create(
        Profile::FILES,
        Policy::default(),
        &log,
        &device.signing,
        &[encryption.public_key()],
        None,
    )
    .unwrap();
    let write = |space: &mut Space, ops: Vec<SpaceOp>| {
        let (id, _) = space.write_entry(&log, &device.signing, ops, None).unwrap();
        id
    };
    let mut ops = vec![files::create_folder(ROOT, "F")];
    let folder = NodeKind::Uint(files::FOLDER);
    ops.extend(
        (0..children).map(|k| SpaceOp::create_under(folder, 0, &k.to_string(), Record::new())),
    );
    let a = write(&mut space, ops);
    let f = derived_id(&a, 0);
    let b = write(&mut space, vec![SpaceOp::delete(f); deletes]);
    let beside = vec![files::create_folder(ROOT, "beside")];
    let (c, _) = space
        .write_concurrent(&log, &device.signing, &[b], beside, None)
        .unwrap();
    for id in [a, b, c] {
        assert!(space.state().is_accepted(&id));
    }

    let before = NOW.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let state = State::compute(Profile::FILES, space.dag(), &space.validity().valid);
    let peak = PEAK.load(Ordering::Relaxed) - before;
    eprintln!(
        "MEASURE working out the state took {} KiB at its peak",
        peak >> 10
    );
    assert!(state.node(&f).unwrap().deleted);
    assert_eq!(state.canonical(), space.state().canonical());
    // The state itself is a few hundred bytes a node. Every delete's
    // subtree held at once is 2,000 x 501 ids, 15 MiB; at 11,000 deletes of
    // 30,000 nodes, which half a megabyte of entries holds, 5 GiB.
    assert!(measuring || peak < 4 << 20, "{} KiB", peak >> 10);
}

/// V3. Every entry that holds an `add_member` or a `succeed` is given a
/// mark, whether it counts or not, and every entry keeps the set of marks
/// in its causal past. Kept as one flat bit set each, a chain of N such
/// entries holds N squared over sixteen bytes of them: 625 MiB at a hundred
/// thousand, from anyone who can get entries stored. Sets that differ in
/// their last few marks now share the rest, so twice the chain costs
/// little more an entry.
#[test]
fn the_marks_in_a_long_chain_s_past_are_shared() {
    use cardinal_crypto::SigningKey;
    use cardinal_identity::dag::Dag;
    use cardinal_space::entry::SpaceEntryBuilder;
    use cardinal_space::validity::Judge;
    let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
    let size = std::env::var("V3_ENTRIES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok());
    let entries = size.unwrap_or(8_000);
    let device = DeviceKeys::generate();
    let Created {
        log, encryption, ..
    } = IdentityLog::create_with(
        RecoveryPhrase::from_entropy(&[82; 32]),
        &device,
        HybridKeyPair::generate(),
    )
    .unwrap();
    let (space, _) = Space::create(
        Profile::FILES,
        Policy::default(),
        &log,
        &device.signing,
        &[encryption.public_key()],
        None,
    )
    .unwrap();
    // The chain is a stranger's: nobody the space names, and no log held
    // for them. None of it counts, and all of it is judged and kept.
    let stranger = SigningKey::from_seed(&[83; 32]);
    let genesis = space.entry(&space.id()).unwrap().clone();
    let mut dag = Dag::new();
    dag.insert(genesis.id(), Vec::new(), genesis.clone());
    let mut last = genesis.id();
    for k in 0..2 * entries {
        let e = SpaceEntryBuilder::new(space.id(), &[last], [9; 32], [9; 32], [1; 16])
            .ops([SpaceOp::add_member([7; 32], 0)])
            .time(k as u64)
            .sign(&stranger)
            .unwrap();
        last = e.id();
        dag.insert(e.id(), vec![e.parents()[0]], e);
    }
    let order = dag.log_order().to_vec();
    // What a judge holds for the first `n` of them, in bytes an entry.
    let held_for = |n: usize| {
        let before = NOW.load(Ordering::Relaxed);
        let mut judge = Judge::new();
        judge.set_state(&dag, log.state());
        for id in &order[..=n] {
            judge.arrive(&dag, id);
        }
        let held = NOW.load(Ordering::Relaxed) - before;
        assert_eq!(judge.validity().valid.len(), 1);
        eprintln!(
            "MEASURE a judge holds {} KiB for a chain of {n} entries that each add a member: {} bytes an entry",
            held >> 10,
            held / n
        );
        held / n
    };
    let (once, twice) = (held_for(entries), held_for(2 * entries));
    // As flat sets, twice the chain is entries / 16 bytes more an entry:
    // 500 at this size.
    assert!(
        size.is_some() || twice < once + 150,
        "{once} and {twice} bytes an entry"
    );
}
