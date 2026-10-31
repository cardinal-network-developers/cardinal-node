//! End-to-end tests of a personal files space and account space across a
//! person's devices.

use cardinal_crypto::{HybridKeyPair, RecoveryPhrase};
use cardinal_identity::{Created, DeviceKeys, IdentityLog, Power};
use cardinal_space::account::{self, Retention};
use cardinal_space::files::{self, Content, FileKind, Files};
use cardinal_space::{Policy, Profile, SealedEntry, Space, SpaceOp, ROOT};

struct Person {
    log: IdentityLog,
    enc: HybridKeyPair,
    devices: Vec<DeviceKeys>,
}

fn person(n: u8, extra_devices: usize) -> Person {
    let d0 = DeviceKeys::generate();
    let Created {
        mut log,
        encryption,
        ..
    } = IdentityLog::create_with(
        RecoveryPhrase::from_entropy(&[n; 32]),
        &d0,
        HybridKeyPair::generate(),
    )
    .unwrap();
    let mut devices = vec![d0];
    for _ in 0..extra_devices {
        let d = DeviceKeys::generate();
        log.add_key(
            &devices[0].signing,
            &d.request(&log.id(), Power::Device),
            Some(&encryption),
        )
        .unwrap();
        devices.push(d);
    }
    Person {
        log,
        enc: encryption,
        devices,
    }
}

fn sync(from: &Space, to: &mut Space, keys: &HybridKeyPair) {
    let mut ids: Vec<_> = from.dag().log_order().to_vec();
    ids.reverse(); // worst order: children before parents
    for id in ids {
        if !to.dag().contains(&id) {
            to.receive(from.sealed(&id).unwrap().clone(), &[keys])
                .unwrap();
        }
    }
}

fn file(content: &[u8]) -> Content {
    Content::Inline(content.to_vec())
}

#[test]
fn files_space_across_two_devices() {
    let p = person(1, 1);
    let (d0, d1) = (&p.devices[0], &p.devices[1]);
    let (mut a, genesis) = Space::create(
        Profile::FILES,
        Policy::default(),
        &p.log,
        &d0.signing,
        &[p.enc.public_key()],
        Some(1),
    )
    .unwrap();
    // the second device opens the space from the sealed genesis
    let enc1 = p.log.open_encryption_key(d1).unwrap();
    let genesis = SealedEntry::decode(&genesis.encode()).unwrap();
    let mut b = Space::open_genesis(&genesis, &[&enc1], Some(p.log.state())).unwrap();
    assert_eq!(b.id(), a.id());

    // device 0 creates docs/notes.txt in one entry
    let s = a
        .write(
            &p.log,
            &d0.signing,
            vec![
                files::create_folder(ROOT, "docs"),
                SpaceOp::create(
                    cardinal_space::NodeKind::Uint(files::FILE),
                    [5; 16],
                    "never",
                    Default::default(),
                ),
            ],
            Some(2),
        )
        .unwrap();
    let _ = s;
    // that entry named a node that does not exist: valid, but not accepted
    let last = *a.dag().log_order().last().unwrap();
    assert!(a.validity().is_valid(&last));
    assert!(!a.state().is_accepted(&last));
    // now properly
    a.write(
        &p.log,
        &d0.signing,
        vec![files::create_folder(ROOT, "docs")],
        Some(3),
    )
    .unwrap();
    let docs_entry = *a.dag().log_order().last().unwrap();
    let docs = files::created_node(&docs_entry, 0);
    a.write(
        &p.log,
        &d0.signing,
        vec![files::create_file(
            docs,
            "notes.txt",
            &file(b"v1"),
            0o644,
            Some(10),
        )],
        Some(4),
    )
    .unwrap();
    let notes = files::created_node(a.dag().log_order().last().unwrap(), 0);
    assert_eq!(a.stats().recomputed, 1, "{:?}", a.stats());

    sync(&a, &mut b, &enc1);
    assert_eq!(b.state().canonical(), a.state().canonical());

    // concurrent edits: a conflict, shown as a conflict copy
    a.write(
        &p.log,
        &d0.signing,
        vec![files::set_content(notes, &file(b"from a"))],
        Some(5),
    )
    .unwrap();
    b.write(
        &p.log,
        &d1.signing,
        vec![files::set_content(notes, &file(b"from b"))],
        Some(6),
    )
    .unwrap();
    sync(&a, &mut b, &enc1);
    sync(&b, &mut a, &p.enc);
    assert_eq!(b.state().canonical(), a.state().canonical());
    let fa = Files::new(&a);
    let versions = fa.content(&notes);
    assert_eq!(versions.len(), 2);
    let listing = fa.list_path("/docs").unwrap();
    assert_eq!(listing.len(), 2, "{listing:?}");
    let copy = listing
        .iter()
        .find(|e| e.conflict_version.is_some())
        .unwrap();
    assert!(copy.name.starts_with("notes (conflict, "), "{}", copy.name);
    assert!(copy.name.ends_with(").txt"));
    let main = fa.resolve("docs/notes.txt").unwrap();
    assert_eq!(main.node, notes);
    let st = fa.stat(&notes).unwrap();
    assert_eq!(
        (st.kind, st.versions, st.mode),
        (FileKind::File, 2, Some(0o644))
    );
    // the main version is the one last in log order
    assert!(a.dag().before(&versions[0].entry, &versions[1].entry));
    assert_eq!(st.size, versions[1].content.as_ref().map(|c| c.size()));
    let devices: Vec<_> = versions.iter().map(|v| v.device).collect();
    assert!(devices.contains(&d0.key()) && devices.contains(&d1.key()));
    drop(fa);

    // editing the main file settles the conflict
    a.write(
        &p.log,
        &d0.signing,
        vec![files::set_content(notes, &file(b"merged"))],
        Some(7),
    )
    .unwrap();
    let fa = Files::new(&a);
    assert_eq!(fa.content(&notes).len(), 1);
    assert_eq!(fa.list_path("docs").unwrap().len(), 1);
    assert_eq!(fa.history(&notes).len(), 4);
    drop(fa);

    // a move that would make a cycle is skipped
    a.write(
        &p.log,
        &d0.signing,
        vec![
            files::create_folder(docs, "inner"),
            SpaceOp::mv(docs, files::created_node(&[0; 32], 0), "x"),
        ],
        None,
    )
    .unwrap();
    let e = *a.dag().log_order().last().unwrap();
    assert!(
        !a.state().is_accepted(&e),
        "names a node that does not exist"
    );
    a.write(
        &p.log,
        &d0.signing,
        vec![files::create_folder(docs, "inner")],
        None,
    )
    .unwrap();
    let inner = files::created_node(a.dag().log_order().last().unwrap(), 0);
    a.write(
        &p.log,
        &d0.signing,
        vec![SpaceOp::mv(docs, inner, "docs")],
        None,
    )
    .unwrap();
    assert_eq!(a.state().node(&docs).unwrap().parent, ROOT);

    // delete yields to concurrent work: b edits while a deletes the folder
    sync(&a, &mut b, &enc1);
    a.write(&p.log, &d0.signing, vec![SpaceOp::delete(docs)], None)
        .unwrap();
    b.write(
        &p.log,
        &d1.signing,
        vec![files::set_content(notes, &file(b"still editing"))],
        None,
    )
    .unwrap();
    sync(&a, &mut b, &enc1);
    sync(&b, &mut a, &p.enc);
    assert_eq!(b.state().canonical(), a.state().canonical());
    let st = a.state();
    assert!(!st.node(&docs).unwrap().deleted && st.node(&docs).unwrap().delete_conflict);
    assert!(!st.node(&notes).unwrap().deleted, "touched concurrently");
    assert!(st.node(&inner).unwrap().deleted, "not touched");
    assert_eq!(st.conflicts().len(), 1);

    // an uncontested delete, then restore
    a.write(&p.log, &d0.signing, vec![SpaceOp::delete(docs)], None)
        .unwrap();
    assert!(a.state().node(&notes).unwrap().deleted);
    assert!(Files::new(&a).list(&ROOT).is_empty());
    a.write(&p.log, &d0.signing, vec![SpaceOp::restore(docs)], None)
        .unwrap();
    assert!(!a.state().node(&notes).unwrap().deleted);
    assert_eq!(Files::new(&a).list(&ROOT).len(), 1);

    // a full recomputation gives the same state as incremental updates
    let full = cardinal_space::State::compute(Profile::FILES, a.dag(), &a.validity().valid);
    assert_eq!(full.canonical(), a.state().canonical());
    assert_eq!(full.root_hash(), a.state().root_hash());
}

#[test]
fn removed_device_and_rotation() {
    let mut p = person(2, 1);
    let d0 = DeviceKeys {
        signing: cardinal_crypto::SigningKey::from_seed(&p.devices[0].signing.seed()),
        link: HybridKeyPair::from_secret_bytes(&p.devices[0].link.secret_bytes()),
    };
    let d1 = DeviceKeys {
        signing: cardinal_crypto::SigningKey::from_seed(&p.devices[1].signing.seed()),
        link: HybridKeyPair::from_secret_bytes(&p.devices[1].link.secret_bytes()),
    };
    let (mut a, _) = Space::create(
        Profile::FILES,
        Policy::default(),
        &p.log,
        &d0.signing,
        &[p.enc.public_key()],
        None,
    )
    .unwrap();
    a.write(
        &p.log,
        &d1.signing,
        vec![files::create_folder(ROOT, "x")],
        None,
    )
    .unwrap();
    let by_d1 = *a.dag().log_order().last().unwrap();
    assert!(a.validity().is_valid(&by_d1));
    assert!(a.has_unwitnessed(&d1.key()));
    assert!(!a.has_unwitnessed(&d0.key()));
    let epoch0 = a.current_epoch().unwrap();

    // the device is removed and the identity key rotated
    p.log.remove_key(&d0.signing, &d1.key()).unwrap();
    let new_enc = HybridKeyPair::generate();
    p.log
        .set_encryption_key(&d0.signing, &new_enc, Some(&p.enc))
        .unwrap();
    p.enc = new_enc;
    a.set_author(p.log.state());
    // d1's entry was not witnessed by another device before the removal
    assert!(!a.validity().is_valid(&by_d1));
    assert!(a.validity().unwitnessed.contains(&by_d1));
    assert_eq!(a.unwitnessed_by(&d1.key()), 1);
    // a keep op by an honest device keeps it
    a.write(
        &p.log,
        &d0.signing,
        vec![SpaceOp::keep(d1.key(), &[by_d1])],
        None,
    )
    .unwrap();
    assert!(a.validity().is_valid(&by_d1));

    // the current epoch is not one the new identity key received
    assert!(!a.epoch_wrapped_for(&p.enc));

    // rotation wraps the new epoch to the new identity key only, and
    // carries the old epoch's key
    let (sealed, key) = a
        .rotate(&p.log, &d0.signing, &[p.enc.public_key()], vec![], None)
        .unwrap();
    assert_eq!(a.current_epoch(), Some(key.id()));
    assert_ne!(key.id(), epoch0);
    assert!(a.epoch_wrapped_for(&p.enc));
    let mut fresh = cardinal_space::Keyring::new();
    assert!(sealed.open(&fresh, &[&d1.link]).is_err());
    let (e, k) = sealed.open(&fresh, &[&p.enc]).unwrap();
    assert_eq!(k, key);
    fresh.add(k);
    assert!(e.starts_epoch());

    // after removal the device's new writes do not count
    let late = a
        .write(
            &p.log,
            &d1.signing,
            vec![files::create_folder(ROOT, "late")],
            None,
        )
        .unwrap();
    let _ = late;
    let last = *a.dag().log_order().last().unwrap();
    assert!(!a.validity().is_valid(&last));
}

#[test]
fn account_space_devices_and_placements() {
    let p = person(3, 1);
    let d0 = &p.devices[0];
    let (mut acct, _) = Space::create(
        Profile::ACCOUNT,
        Policy::default(),
        &p.log,
        &d0.signing,
        &[p.enc.public_key()],
        None,
    )
    .unwrap();
    let files_space = [9u8; 32];
    acct.write(
        &p.log,
        &d0.signing,
        vec![
            account::create_device(&d0.key(), "laptop", false, false),
            account::create_device(&p.devices[1].key(), "server", true, true),
            account::create_space(&files_space, "Documents"),
        ],
        None,
    )
    .unwrap();
    let e = *acct.dag().log_order().last().unwrap();
    let space_node = files::created_node(&e, 2);
    acct.write(
        &p.log,
        &d0.signing,
        vec![account::create_placement(
            space_node,
            &d0.key(),
            Retention::OnDemand,
            Some("~/Cardinal"),
            false,
        )],
        None,
    )
    .unwrap();
    let devs = account::devices(acct.state());
    assert_eq!(devs.len(), 2);
    assert_eq!(
        account::device_name(acct.state(), &p.devices[1].key()).as_deref(),
        Some("server")
    );
    let spaces = account::spaces(acct.state());
    assert_eq!(spaces.len(), 1);
    assert_eq!(spaces[0].space, files_space);
    assert_eq!(spaces[0].placements[0].retention, Retention::OnDemand);
    assert_eq!(spaces[0].placements[0].path.as_deref(), Some("~/Cardinal"));
    // a placement must be under a space node
    acct.write(
        &p.log,
        &d0.signing,
        vec![account::create_placement(
            ROOT,
            &d0.key(),
            Retention::Full,
            None,
            false,
        )],
        None,
    )
    .unwrap();
    assert!(!acct
        .state()
        .is_accepted(acct.dag().log_order().last().unwrap()));
}

#[test]
fn types_cross_threads() {
    fn send_sync<T: Send + Sync>() {}
    send_sync::<Space>();
    send_sync::<IdentityLog>();
    send_sync::<cardinal_identity::IdentityState>();
}

#[test]
fn display_names_are_unique() {
    // Two folders named `c` and one named `c (2)`: the second `c` cannot
    // show as `c (2)`, which is taken.
    let p = person(3, 0);
    let d0 = &p.devices[0];
    let (mut a, _) = Space::create(
        Profile::FILES,
        Policy::default(),
        &p.log,
        &d0.signing,
        &[p.enc.public_key()],
        Some(1),
    )
    .unwrap();
    for name in ["c", "c (2)", "c", "c.txt", "c.txt"] {
        a.write(
            &p.log,
            &d0.signing,
            vec![files::create_folder(ROOT, name)],
            Some(2),
        )
        .unwrap();
    }
    let names: Vec<String> = Files::new(&a)
        .list(&ROOT)
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(names, ["c", "c (2)", "c (2).txt", "c (3)", "c.txt"]);
}
