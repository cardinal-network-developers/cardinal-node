//! End-to-end tests of a personal files space and account space across a
//! person's devices.

use cardinal_crypto::{HybridKeyPair, RecoveryPhrase};
use cardinal_encoding::Record;
use cardinal_identity::{Created, DeviceKeys, IdentityLog, Power};
use cardinal_space::account::{self, Retention};
use cardinal_space::files::{self, Content, FileKind, Files};
use cardinal_space::relationship;
use cardinal_space::{NodeKind, Policy, Profile, SealedEntry, Space, SpaceOp, ROOT};

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
    // every entry so far was applied as it came, the genesis too
    assert_eq!(a.stats().recomputed, 0, "{:?}", a.stats());

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
    a.set_identity(p.log.state());
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

/// D68 (`profiles.md#account`, kind 2). A space record no longer holds an
/// answer about hosts: field 5, where an earlier version kept one, is not
/// a field of it. A record that has it reads as any other, and a refusal
/// written beside it changes nothing about the space.
#[test]
fn an_answer_an_earlier_version_kept_in_the_account_is_not_read() {
    use cardinal_space::account::{Regard, REFUSED};
    let p = person(5, 1);
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
    let (club, choir, cy) = ([1u8; 32], [2u8; 32], [3u8; 32]);
    let old = |space: [u8; 32], name: &str, yes: bool| {
        let record = Record::new().with(1, space).with(2, name).with(5, yes);
        SpaceOp::create(NodeKind::Uint(account::SPACE), ROOT, name, record)
    };
    let ops = vec![
        account::create_contact(&cy, "Cy", &[7; 32], Regard::default()),
        old(club, "Garden club", true),
        old(choir, "Choir", false),
        account::create_space(&[9; 32], "Band"),
    ];
    let (made, _) = acct.write_entry(&p.log, &d0.signing, ops, None).unwrap();
    let refuse = account::set_field(files::created_node(&made, 0), REFUSED, true);
    acct.write(&p.log, &d0.signing, vec![refuse], None).unwrap();
    let mut read: Vec<(String, bool)> = account::spaces(acct.state())
        .into_iter()
        .map(|s| (s.name, s.declined))
        .collect();
    read.sort();
    let names = ["Band", "Choir", "Garden club"];
    assert_eq!(read, names.map(|n| (n.to_owned(), false)));
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
    // A placement means something under a space node. One under the root
    // is in the state like any node, and is nobody's placement; so is a
    // device under a space node, a space under a device, and a node of a
    // kind the account has no table for (`state.md#operations`).
    let before = cardinal_encoding::Value::as_list(acct.state().canonical().get(1).unwrap())
        .unwrap()
        .len();
    let device_node = devs[0].node;
    let odd = vec![
        account::create_placement(ROOT, &d0.key(), Retention::Full, None, false),
        account::create_device(&[7; 32], "nowhere", false, false),
        account::create_space(&[8; 32], "under a device"),
        SpaceOp::create(
            NodeKind::Uint(77),
            ROOT,
            "new",
            cardinal_encoding::Record::new(),
        ),
    ];
    let odd: Vec<SpaceOp> = odd
        .into_iter()
        .zip([ROOT, space_node, device_node, ROOT])
        .map(|(op, parent)| match op.body() {
            cardinal_space::SpaceOpBody::Create {
                kind, name, fields, ..
            } => SpaceOp::create(*kind, parent, name, fields.clone()),
            _ => unreachable!(),
        })
        .collect();
    let (odd_entry, _) = acct.write_entry(&p.log, &d0.signing, odd, None).unwrap();
    assert!(acct.state().is_accepted(&odd_entry));
    let after = cardinal_encoding::Value::as_list(acct.state().canonical().get(1).unwrap())
        .unwrap()
        .len();
    assert_eq!(after, before + 4, "kept, and in the canonical state");
    // and none of it is shown
    assert_eq!(account::devices(acct.state()).len(), 2);
    let spaces = account::spaces(acct.state());
    assert_eq!(spaces.len(), 1);
    assert_eq!(spaces[0].placements.len(), 1);
    assert_eq!(spaces[0].placements[0].retention, Retention::OnDemand);
}

#[test]
fn a_node_of_any_kind_anywhere_is_kept_and_not_shown() {
    // `state.md#operations`: a `create` is accepted whatever its kind and
    // wherever it puts the node. A node of a kind a device does not know,
    // or in a place where its kind means nothing, is in the state and in
    // the canonical state, and software does not show it. Whatever maps a
    // space to a folder steps over it, at any depth.
    use cardinal_encoding::{Record, Value};
    let p = person(24, 0);
    let d0 = &p.devices[0];
    let (mut a, genesis) = Space::create(
        Profile::FILES,
        Policy::default(),
        &p.log,
        &d0.signing,
        &[p.enc.public_key()],
        None,
    )
    .unwrap();
    let write = |a: &mut Space, ops: Vec<SpaceOp>| {
        let (id, _) = a.write_entry(&p.log, &d0.signing, ops, None).unwrap();
        assert!(a.validity().is_valid(&id));
        assert!(a.state().is_accepted(&id), "not accepted for state");
        id
    };
    let made = files::created_node;
    let e = write(
        &mut a,
        vec![
            files::create_folder(ROOT, "docs"),
            files::create_file(ROOT, "notes.txt", &file(b"plain"), 0o644, None),
        ],
    );
    let (docs, notes) = (made(&e, 0), made(&e, 1));
    let inside = write(
        &mut a,
        vec![files::create_file(docs, "a.txt", &file(b"a"), 0o644, None)],
    );
    let a_txt = made(&inside, 0);
    // what this build has no meaning for
    let content = Record::new().with(files::FILE_CONTENT, file(b"new").to_value());
    let e = write(
        &mut a,
        vec![
            // a kind it does not know, at the top and in a folder
            SpaceOp::create(NodeKind::Uint(77), ROOT, "seventy-seven", content.clone()),
            SpaceOp::create(NodeKind::Uint(77), docs, "in docs", Record::new()),
            SpaceOp::create(NodeKind::Named([5; 32]), ROOT, "named", Record::new()),
            // kinds it knows, where they mean nothing: in a file
            files::create_file(notes, "file in a file", &file(b"x"), 0o644, None),
            files::create_folder(notes, "folder in a file"),
        ],
    );
    let (unknown, in_docs, in_file, folder_in_file) =
        (made(&e, 0), made(&e, 1), made(&e, 3), made(&e, 4));
    // and beneath those, to any depth
    let e = write(
        &mut a,
        vec![
            files::create_folder(unknown, "under the unknown"),
            files::create_file(folder_in_file, "deep.txt", &file(b"deep"), 0o644, None),
            files::create_folder(folder_in_file, "deeper"),
        ],
    );
    let (under_unknown, deep, deeper) = (made(&e, 0), made(&e, 1), made(&e, 2));
    let e = write(
        &mut a,
        vec![files::create_file(
            deeper,
            "deepest.txt",
            &file(b"d"),
            0o644,
            None,
        )],
    );
    let deepest = made(&e, 0);

    // All of it is in the state and the canonical state.
    let records = |s: &Space| {
        let c = s.state().canonical();
        Value::as_list(c.get(1).unwrap()).unwrap().len()
    };
    assert_eq!(records(&a), 12);
    for odd in [
        unknown,
        in_docs,
        in_file,
        folder_in_file,
        under_unknown,
        deep,
        deeper,
        deepest,
    ] {
        assert!(a.state().node(&odd).is_some());
    }
    // The folder shows what it showed before.
    let names = |s: &Space, path: &str| -> Option<Vec<String>> {
        let list = Files::new(s).list_path(path)?;
        Some(list.into_iter().map(|e| e.name).collect())
    };
    assert_eq!(names(&a, "").unwrap(), ["docs", "notes.txt"]);
    assert_eq!(names(&a, "docs").unwrap(), ["a.txt"]);
    let f = Files::new(&a);
    for shown in [docs, notes, a_txt] {
        assert!(f.shows(&shown) && f.belongs(&shown));
    }
    for odd in [
        unknown,
        in_docs,
        in_file,
        folder_in_file,
        under_unknown,
        deep,
        deeper,
        deepest,
    ] {
        assert!(!f.shows(&odd) && !f.belongs(&odd));
        assert!(f.list(&odd).is_empty(), "something is listed in it");
    }
    // nothing is reached through a file, by any path
    assert!(f.resolve("notes.txt/file in a file").is_none());
    assert!(f.resolve("notes.txt/folder in a file/deep.txt").is_none());
    assert!(f.resolve("seventy-seven").is_none());
    assert_eq!(f.list_path("notes.txt").unwrap(), []);
    drop(f);

    // A move is accepted wherever it puts a node, too. A folder moved into
    // a file is not shown, with everything in it; moved back, it is.
    write(&mut a, vec![SpaceOp::mv(docs, notes, "docs")]);
    assert_eq!(names(&a, "").unwrap(), ["notes.txt"]);
    let f = Files::new(&a);
    assert!(!f.shows(&docs) && !f.shows(&a_txt));
    assert!(f.resolve("notes.txt/docs/a.txt").is_none());
    drop(f);
    write(&mut a, vec![SpaceOp::mv(docs, ROOT, "docs")]);
    assert_eq!(names(&a, "docs").unwrap(), ["a.txt"]);
    // and something shown can be moved out of where it meant nothing
    write(&mut a, vec![SpaceOp::mv(deep, docs, "deep.txt")]);
    assert_eq!(names(&a, "docs").unwrap(), ["a.txt", "deep.txt"]);
    assert_eq!(records(&a), 12);

    // A device that takes it all at once computes the same state, and one
    // that works it out from scratch does too.
    let mut b = Space::open_genesis(&genesis, &[&p.enc], Some(p.log.state())).unwrap();
    sync(&a, &mut b, &p.enc);
    assert_eq!(b.state().canonical(), a.state().canonical());
    let full = cardinal_space::State::compute(Profile::FILES, a.dag(), &a.validity().valid);
    assert_eq!(full.canonical(), a.state().canonical());
    assert_eq!(names(&b, "docs").unwrap(), ["a.txt", "deep.txt"]);

    // An op the profile does not define is another matter: nobody can
    // apply an op they do not know, and the entry stays out of the state.
    let unknown_op = SpaceOp::from_record(Record::new().with(0, 40u32));
    let (id, _) = a
        .write_entry(&p.log, &d0.signing, vec![unknown_op], None)
        .unwrap();
    assert!(a.validity().is_valid(&id) && !a.state().is_accepted(&id));
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

#[test]
fn a_relationship_has_two_writers_no_owner_and_a_conversation() {
    let ana = person(11, 0);
    let bo = person(12, 0);
    let stranger = person(13, 0);
    let (mut a, genesis) = Space::create_with(
        Profile::RELATIONSHIP,
        Policy::default(),
        &ana.log,
        &ana.devices[0].signing,
        &[ana.enc.public_key(), bo.enc.public_key()],
        relationship::genesis_ops(ana.log.id(), bo.log.id()),
        None,
    )
    .unwrap();
    let c = relationship::conversation(&a).unwrap();
    // Both are writers, and nobody owns it: neither can add anyone, and
    // neither can end it alone.
    assert_eq!(a.owner(), None);
    assert_eq!(a.creator(), ana.log.id());
    for who in [&ana, &bo] {
        assert_eq!(
            a.role_of(&who.log.id()),
            Some(cardinal_space::entry::WRITER)
        );
    }
    assert_eq!(a.members().len(), 2);

    // Bo opens it with Bo's own key. A stranger's cannot.
    assert!(Space::open_genesis(&genesis, &[&stranger.enc], Some(ana.log.state())).is_err());
    let mut b = Space::open_genesis(&genesis, &[&bo.enc], Some(ana.log.state())).unwrap();
    assert_eq!(relationship::conversation(&b), Some(c));

    // Each writes, and each reads what the other wrote, in the same order.
    // What Bo writes counts once his identity log is held, and not before.
    let hi = relationship::create_message(c, "hello");
    let sealed = a
        .write(&ana.log, &ana.devices[0].signing, vec![hi], Some(1))
        .unwrap();
    b.receive(sealed, &[&bo.enc]).unwrap();
    let back = relationship::create_message(c, "hello yourself");
    let sealed = b
        .write(&bo.log, &bo.devices[0].signing, vec![back], Some(2))
        .unwrap();
    assert_eq!(relationship::messages(&b).len(), 1);
    b.set_identity(bo.log.state());
    assert_eq!(relationship::messages(&b).len(), 2);
    a.receive(sealed, &[&ana.enc]).unwrap();
    assert_eq!(relationship::messages(&a).len(), 1);
    a.set_identity(bo.log.state());
    let said: Vec<(_, String)> = relationship::messages(&a)
        .into_iter()
        .map(|m| (m.author, m.text))
        .collect();
    assert_eq!(
        said,
        [
            (ana.log.id(), "hello".to_owned()),
            (bo.log.id(), "hello yourself".to_owned())
        ]
    );
    assert_eq!(relationship::messages(&a), relationship::messages(&b));

    // An identity that is not a member writes nothing that counts, even with
    // the key.
    let mut c2 = Space::open_genesis(&genesis, &[&bo.enc], Some(ana.log.state())).unwrap();
    for (_, s) in a.sealed_entries() {
        let _ = c2.receive(s.clone(), &[&bo.enc]);
    }
    c2.set_identity(bo.log.state());
    let all = [&ana.log, &bo.log, &stranger.log];
    let forged = relationship::create_message(c, "from a stranger");
    let (id, s) = c2
        .write_entry(
            &stranger.log,
            &stranger.devices[0].signing,
            vec![forged],
            None,
        )
        .unwrap();
    a.receive(s, &[&ana.enc]).unwrap();
    a.set_identity(stranger.log.state());
    // the stranger's signature is the stranger's, and nobody added them
    assert!(a.validity().author_ok.contains(&id) && !a.validity().is_valid(&id));
    assert_eq!(relationship::messages(&a).len(), 2);
    // nobody builds on what they hold to be invalid
    assert!(!a.heads().contains(&id) && a.dag().heads().contains(&id));
    let rules = cardinal_space::validity::by_rules(a.dag(), &all).unwrap();
    assert!(a.validity().valid == rules.valid && a.validity().members == rules.members);

    // Neither can add anyone, and one alone ends nothing.
    let add = SpaceOp::add_member(stranger.log.id(), cardinal_space::entry::READER);
    let (added, _) = a
        .write_entry(&ana.log, &ana.devices[0].signing, vec![add], None)
        .unwrap();
    assert!(!a.validity().is_valid(&added));
    let (named, sealed) = a
        .write_entry(
            &ana.log,
            &ana.devices[0].signing,
            vec![SpaceOp::succeed([5; 32])],
            None,
        )
        .unwrap();
    assert!(a.validity().is_valid(&named) && a.successor().is_none() && !a.ended());
    // When the other names the same successor, it ends, and nothing more
    // is written in it.
    b.set_identity(bo.log.state());
    for (_, s) in a.sealed_entries() {
        let _ = b.receive(s.clone(), &[&bo.enc]);
    }
    let _ = sealed;
    let agreed = b
        .write(
            &bo.log,
            &bo.devices[0].signing,
            vec![SpaceOp::succeed([5; 32])],
            None,
        )
        .unwrap();
    a.receive(agreed, &[&ana.enc]).unwrap();
    assert_eq!(a.successor(), Some([5; 32]));
    assert!(a.ended() && b.ended());
    let more = relationship::create_message(c, "anyone there?");
    assert!(a
        .write(&ana.log, &ana.devices[0].signing, vec![more.clone()], None)
        .is_err());
    // What witnesses or keeps a person's own work is still written: an
    // empty entry, or a `keep`. Those count without being valid there, and
    // nothing builds on them.
    let heads = a.heads();
    let key = ana.devices[0].signing.public_key();
    let kept = SpaceOp::keep(key, &[named]);
    for ops in [vec![], vec![kept.clone()], vec![kept.clone(), kept.clone()]] {
        let (id, _) = a
            .write_entry(&ana.log, &ana.devices[0].signing, ops, None)
            .unwrap();
        assert!(a.validity().author_ok.contains(&id) && !a.validity().is_valid(&id));
        assert_eq!(a.heads(), heads);
    }
    // and nothing else, beside a `keep` or not
    assert!(a
        .write(&ana.log, &ana.devices[0].signing, vec![kept, more], None)
        .is_err());
}

#[test]
fn the_canonical_state_says_in_what_order_and_when_nodes_were_made() {
    // `state.md#canonical-state`: field 10 is a node's place in the order
    // the nodes were created in, counting from 0: log order, and within an
    // entry the order of its ops. Field 11 is the time of the entry that
    // created it.
    use cardinal_encoding::Value;
    let p = person(23, 0);
    let d0 = &p.devices[0];
    let (mut a, _) = Space::create(
        Profile::FILES,
        Policy::default(),
        &p.log,
        &d0.signing,
        &[p.enc.public_key()],
        None,
    )
    .unwrap();
    let folder = |name: &str| files::create_folder(ROOT, name);
    let (first, _) = a
        .write_entry(
            &p.log,
            &d0.signing,
            vec![folder("b"), folder("a")],
            Some(100),
        )
        .unwrap();
    let (second, _) = a
        .write_entry(&p.log, &d0.signing, vec![folder("c")], None)
        .unwrap();
    // deleted, a node keeps its place
    let made = |e, i| cardinal_space::entry::derived_id(&e, i);
    a.write(
        &p.log,
        &d0.signing,
        vec![SpaceOp::delete(made(first, 0))],
        Some(300),
    )
    .unwrap();
    let state = a.state().canonical();
    let records = state.get(1).and_then(Value::as_list).unwrap();
    let of = |id: [u8; 16]| {
        let all = records.iter().filter_map(Value::as_record);
        let mut found = all.filter(|r| r.get(1).and_then(Value::as_bytes) == Some(&id[..]));
        let r = found.next().unwrap();
        let rank = r.get(10).and_then(Value::as_uint);
        (rank, r.get(11).and_then(Value::as_uint))
    };
    assert_eq!(of(made(first, 0)), (Some(0), Some(100)));
    assert_eq!(of(made(first, 1)), (Some(1), Some(100)));
    // an entry that gives no time gives the node none
    assert_eq!(of(made(second, 0)), (Some(2), None));
    assert_eq!(records.len(), 3);
}

#[test]
fn written_beside_supersedes_and_deletes_nothing() {
    // `state.md`: a `set` written beside adds its value and supersedes none;
    // a `delete` written beside deletes nothing and flags a delete conflict.
    let p = person(21, 0);
    let d0 = &p.devices[0];
    let (mut a, _) = Space::create(
        Profile::FILES,
        Policy::default(),
        &p.log,
        &d0.signing,
        &[p.enc.public_key()],
        None,
    )
    .unwrap();
    let write = |a: &mut Space, op: SpaceOp| {
        a.write_entry(&p.log, &d0.signing, vec![op], None)
            .unwrap()
            .0
    };
    let made = write(
        &mut a,
        files::create_file(ROOT, "f", &file(b"v1"), 0o644, None),
    );
    let f = files::created_node(&made, 0);
    let content = |text: &[u8]| Some(file(text).to_value());
    write(&mut a, SpaceOp::set(f, files::FILE_CONTENT, content(b"v2")));
    assert_eq!(
        a.state()
            .node(&f)
            .unwrap()
            .values(files::FILE_CONTENT)
            .len(),
        1
    );
    // it descends from v2, and still does not replace it
    let beside = write(
        &mut a,
        SpaceOp::set_beside(f, files::FILE_CONTENT, content(b"v3")),
    );
    let values = a
        .state()
        .node(&f)
        .unwrap()
        .values(files::FILE_CONTENT)
        .to_vec();
    assert_eq!(values.len(), 2);
    assert!(values.iter().any(|v| v.entry == beside));
    assert!(a.state().node(&f).unwrap().in_conflict(files::FILE_CONTENT));
    // and is superseded like any other
    write(&mut a, SpaceOp::set(f, files::FILE_CONTENT, content(b"v4")));
    assert_eq!(
        a.state()
            .node(&f)
            .unwrap()
            .values(files::FILE_CONTENT)
            .len(),
        1
    );

    write(&mut a, SpaceOp::delete_beside(f));
    let n = a.state().node(&f).unwrap();
    assert!(!n.deleted && n.delete_conflict);
    assert_eq!(a.state().conflicts().len(), 1);
    // worked out from nothing, the same
    let full = cardinal_space::State::compute(Profile::FILES, a.dag(), &a.validity().valid);
    assert_eq!(full.canonical(), a.state().canonical());
    let plain =
        cardinal_space::State::compute_by_definition(Profile::FILES, a.dag(), &a.validity().valid);
    assert_eq!(plain.canonical(), a.state().canonical());
    // a plain delete still deletes
    write(&mut a, SpaceOp::delete(f));
    assert!(a.state().node(&f).unwrap().deleted);
}

#[test]
fn the_epoch_key_is_in_the_clear_in_a_public_space_and_in_no_other() {
    // `spaces.md#entries-and-sealed-entries`: a member rejects a sealed entry
    // that carries the epoch key where the space is not public, and one that
    // does not where it is.
    let p = person(22, 0);
    let d0 = &p.devices[0];
    for public in [false, true] {
        let policy = Policy {
            public,
            ..Policy::default()
        };
        let (mut a, genesis) = Space::create(
            Profile::FILES,
            policy,
            &p.log,
            &d0.signing,
            &[p.enc.public_key()],
            None,
        )
        .unwrap();
        assert_eq!(genesis.open_key().is_some(), public);
        let (id, sealed) = a
            .write_entry(
                &p.log,
                &d0.signing,
                vec![files::create_folder(ROOT, "x")],
                None,
            )
            .unwrap();
        assert_eq!(sealed.open_key().is_some(), public);
        let epoch = a.keyring().get(&sealed.epoch()).unwrap().clone();
        let entry = a.entry(&id).unwrap();
        let other = SealedEntry::seal(entry, &epoch, None, !public).unwrap();
        let other_genesis = {
            let g = a.entry(&a.id()).unwrap();
            let wraps = genesis.wraps().map(|w| w.to_vec());
            SealedEntry::seal(g, &epoch, wraps, !public).unwrap()
        };
        // the genesis says what the space is, and is held to it
        assert!(Space::open_genesis(&other_genesis, &[&p.enc], Some(p.log.state())).is_err());
        let mut b = Space::open_genesis(&genesis, &[&p.enc], Some(p.log.state())).unwrap();
        assert!(b.receive(other, &[&p.enc]).is_err());
        assert!(!b.dag().contains(&id));
        b.receive(sealed, &[&p.enc]).unwrap();
        assert!(b.validity().is_valid(&id));
        assert_eq!((a.is_public(), b.is_public()), (public, public));

        // Public is the genesis's to say, for good. The owner's
        // `set_policy` saying otherwise is valid, and changes nothing
        // about it: not what the space is, not what its entries carry,
        // and not what a member takes.
        let said = Policy {
            public: !public,
            ..Policy::default()
        };
        let (set, sealed_set) = a
            .write_entry(&p.log, &d0.signing, vec![SpaceOp::set_policy(&said)], None)
            .unwrap();
        assert!(a.validity().is_valid(&set));
        assert_eq!(sealed_set.open_key().is_some(), public);
        b.receive(sealed_set, &[&p.enc]).unwrap();
        assert!(b.validity().is_valid(&set));
        let (after, sealed_after) = a
            .write_entry(
                &p.log,
                &d0.signing,
                vec![files::create_folder(ROOT, "y")],
                None,
            )
            .unwrap();
        assert_eq!(sealed_after.open_key().is_some(), public);
        // one sealed as the `set_policy` would have it is refused
        let as_said = SealedEntry::seal(a.entry(&after).unwrap(), &epoch, None, !public).unwrap();
        assert!(b.receive(as_said, &[&p.enc]).is_err());
        assert!(!b.dag().contains(&after));
        b.receive(sealed_after, &[&p.enc]).unwrap();
        assert!(b.validity().is_valid(&after));
        assert_eq!((a.is_public(), b.is_public()), (public, public));
        // a device that opens the space afresh, with everything at once
        // and the `set_policy` among it, reads the same from the genesis
        let mut c = Space::open_genesis(&genesis, &[&p.enc], Some(p.log.state())).unwrap();
        let later: Vec<_> = a.dag().log_order().iter().rev().copied().collect();
        for x in later.iter().filter(|x| **x != a.id()) {
            c.receive(a.sealed(x).unwrap().clone(), &[&p.enc]).unwrap();
        }
        assert_eq!(c.is_public(), public);
        assert!(c.validity().is_valid(&after));

        // A `set_policy` in the genesis itself, beside the `start`, says
        // no more than one written after: field 2 is read from the `start`
        // and from nothing else.
        let policy = Policy {
            public,
            ..Policy::default()
        };
        let (mut g, sealed_genesis) = Space::create_with(
            Profile::FILES,
            policy,
            &p.log,
            &d0.signing,
            &[p.enc.public_key()],
            vec![
                SpaceOp::add_member(p.log.id(), cardinal_space::entry::OWNER),
                SpaceOp::set_policy(&said),
            ],
            None,
        )
        .unwrap();
        assert!(g.validity().is_valid(&g.id()));
        assert_eq!(g.entry(&g.id()).unwrap().ops().len(), 3);
        assert_eq!(g.is_public(), public);
        assert_eq!(sealed_genesis.open_key().is_some(), public);
        let opened = Space::open_genesis(&sealed_genesis, &[&p.enc], Some(p.log.state()));
        assert_eq!(opened.unwrap().is_public(), public);
        let folder = vec![files::create_folder(ROOT, "z")];
        let (_, next) = g.write_entry(&p.log, &d0.signing, folder, None).unwrap();
        assert_eq!(next.open_key().is_some(), public);
    }
}

/// D70 (`profiles.md#reach`). Two of a person's devices are both hosts,
/// and each sets the reach list again at the same moment, with a new token
/// for itself and the token it had read for the other. The node then
/// holds two lists that name each host, with two tokens each. Read, each
/// host is there once, where it first stands; every token either was
/// given is still known as given; and nothing in the reading depends on
/// which device is which host, so no device has a result to set that
/// another would set differently. It once grew without end: each device
/// took the other's stale token for its own to renew, and then each set
/// "the one result" by its own view of the account.
/// The tokens a person ever gave in a space are known from the entries
/// present, however they arrived: one held for its parent counts once the
/// parent comes, and not before. (They are kept as entries arrive, since a
/// host asks at every batch, and going through the history each time was
/// quadratic over a large first sync.)
#[test]
fn every_token_given_is_known_however_the_entries_arrive() {
    use cardinal_space::relationship::{reach_ever, Reach};
    let p = person(9, 0);
    let other = person(10, 0);
    let me = p.log.id();
    let (mut a, genesis) = Space::create_with(
        Profile::RELATIONSHIP,
        Policy::default(),
        &p.log,
        &p.devices[0].signing,
        &[p.enc.public_key(), other.enc.public_key()],
        relationship::genesis_ops(me, other.log.id()),
        None,
    )
    .unwrap();
    let one = |token: u8| Reach {
        endpoints: Vec::new(),
        host: [0xa0; 32],
        token: [token; 16],
        extra: Default::default(),
    };
    let first = a
        .write(
            &p.log,
            &p.devices[0].signing,
            vec![relationship::set_reach(&me, &[one(1)])],
            None,
        )
        .unwrap();
    let second = a
        .write(
            &p.log,
            &p.devices[0].signing,
            vec![relationship::set_reach(&me, &[one(2)])],
            None,
        )
        .unwrap();
    let tokens = |s: &Space| {
        let mut t: Vec<u8> = reach_ever(s, &me).iter().map(|r| r.token[0]).collect();
        t.sort();
        t
    };
    assert_eq!(tokens(&a), [1, 2]);

    let mut b = Space::open_genesis(&genesis, &[&p.enc], Some(p.log.state())).unwrap();
    b.receive(second, &[&p.enc]).unwrap();
    assert_eq!(
        tokens(&b),
        Vec::<u8>::new(),
        "held for its parent, it is not here yet"
    );
    b.receive(first.clone(), &[&p.enc]).unwrap();
    assert_eq!(tokens(&b), [1, 2]);
    // The same entry again changes nothing.
    b.receive(first, &[&p.enc]).unwrap();
    assert_eq!(tokens(&b), [1, 2]);
}

#[test]
fn two_hosts_setting_the_reach_list_at_once_are_each_one_host() {
    use cardinal_space::relationship::{reach_ever, reach_of, Reach};
    let p = person(7, 1);
    let (d0, d1) = (&p.devices[0], &p.devices[1]);
    let other = person(8, 0);
    let me = p.log.id();
    let (mut space, _) = Space::create_with(
        Profile::RELATIONSHIP,
        Policy::default(),
        &p.log,
        &d0.signing,
        &[p.enc.public_key(), other.enc.public_key()],
        relationship::genesis_ops(me, other.log.id()),
        None,
    )
    .unwrap();
    let (host0, host1) = ([0xa0u8; 32], [0xa1u8; 32]);
    let one = |host: [u8; 32], token: u8| Reach {
        endpoints: Vec::new(),
        host,
        token: [token; 16],
        extra: Default::default(),
    };
    // What both had read: each host with an old token.
    let old = relationship::set_reach(&me, &[one(host0, 1), one(host1, 2)]);
    space.write(&p.log, &d0.signing, vec![old], None).unwrap();
    // Each renews its own at the same moment.
    let by0 = relationship::set_reach(&me, &[one(host0, 11), one(host1, 2)]);
    let (first, _) = space
        .write_entry(&p.log, &d0.signing, vec![by0], None)
        .unwrap();
    let by1 = relationship::set_reach(&me, &[one(host0, 1), one(host1, 12)]);
    let (second, _) = space
        .write_concurrent(&p.log, &d1.signing, &[first], vec![by1], None)
        .unwrap();
    assert_eq!(space.state().reach_values(&me, 1).len(), 2);
    // Each host once, as the list later in log order has it.
    let dag = space.dag();
    let read = match dag.position(&first) > dag.position(&second) {
        true => [one(host0, 11), one(host1, 2)],
        false => [one(host0, 1), one(host1, 12)],
    };
    assert_eq!(reach_of(&space, &me), read);
    // Every token given is known, read now or not: each serves until it
    // is revoked.
    let ever: Vec<u8> = reach_ever(&space, &me).iter().map(|r| r.token[0]).collect();
    for token in [1, 2, 11, 12] {
        assert!(ever.contains(&token), "{token} is forgotten");
    }

    // A list that names a host twice, as an earlier version left them,
    // names it once, where it first stands.
    let twice = [one(host0, 11), one(host1, 12), one(host0, 3), one(host0, 4)];
    let set = relationship::set_reach(&me, &twice);
    space.write(&p.log, &d0.signing, vec![set], None).unwrap();
    assert_eq!(reach_of(&space, &me), [one(host0, 11), one(host1, 12)]);
    // An empty list beside one that names a host reads as empty.
    let no = relationship::set_reach(&me, &[]);
    let (no, _) = space
        .write_entry(&p.log, &d0.signing, vec![no], None)
        .unwrap();
    let yes = relationship::set_reach(&me, &[one(host1, 12)]);
    space
        .write_concurrent(&p.log, &d1.signing, &[no], vec![yes], None)
        .unwrap();
    assert!(reach_of(&space, &me).is_empty());
}

/// D71 (`profiles.md#account`, kind 13). Where two self nodes were made at
/// once, every device reads the one with the lowest node id, whichever
/// came first. A contact's petname absent or empty is none: the name they
/// suggest is shown, marked as theirs.
#[test]
fn the_lowest_self_node_counts_and_a_petname_may_be_none() {
    use cardinal_space::account::{Regard, PETNAME};
    let p = person(6, 1);
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
    assert_eq!(account::self_node(acct.state()), None);
    let (first, _) = acct
        .write_entry(&p.log, &d0.signing, vec![account::create_self("Ana")], None)
        .unwrap();
    let (second, _) = acct
        .write_entry(
            &p.log,
            &d0.signing,
            vec![account::create_self("Ana L")],
            None,
        )
        .unwrap();
    let (a, b) = (
        files::created_node(&first, 0),
        files::created_node(&second, 0),
    );
    let lowest = if a < b { (a, "Ana") } else { (b, "Ana L") };
    assert_eq!(
        account::self_node(acct.state()),
        Some((lowest.0, lowest.1.to_owned()))
    );

    let (cy, bo) = ([3u8; 32], [4u8; 32]);
    let ops = vec![
        account::create_contact_suggesting(
            &cy,
            "Cousin",
            Some("Cy"),
            &[7; 32],
            Regard::default(),
            None,
        ),
        // as a release before kept it: no suggested name
        account::create_contact(&bo, "Bo", &[8; 32], Regard::default()),
    ];
    let (made, _) = acct.write_entry(&p.log, &d0.signing, ops, None).unwrap();
    let shown = |st: &cardinal_space::State| {
        let mut v: Vec<(String, bool, Option<String>)> = account::contacts(st)
            .into_iter()
            .map(|c| (c.petname, c.own, c.suggested))
            .collect();
        v.sort();
        v
    };
    assert_eq!(
        shown(acct.state()),
        [
            ("Bo".to_owned(), true, None),
            ("Cousin".to_owned(), true, Some("Cy".to_owned()))
        ]
    );
    let clear = account::set_field(files::created_node(&made, 0), PETNAME, "");
    let absent = SpaceOp::set(files::created_node(&made, 1), PETNAME, None);
    acct.write(&p.log, &d0.signing, vec![clear, absent], None)
        .unwrap();
    // Bo suggested nothing that was kept: the start of their id.
    assert_eq!(
        shown(acct.state()),
        [
            ("04040404".to_owned(), false, None),
            ("Cy".to_owned(), false, Some("Cy".to_owned()))
        ]
    );
}
