//! What working the state out costs in memory (review finding V1).
//!
//! This file is a test binary of its own, with one test, because it counts
//! every allocation the process makes.

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

/// Two entries from one writer: a folder with a few thousand nodes in it,
/// and the same `delete` of that folder a few thousand times, with one
/// entry beside it so that the state is worked out from scratch. Each
/// delete takes everything beneath the folder. Holding what every one of
/// them takes at once is the number of deletes times the size of the
/// folder; a device must hold no more than one at a time.
#[test]
fn many_deletes_of_one_large_folder_are_not_all_held_at_once() {
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
