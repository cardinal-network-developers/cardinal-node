//! Reach nodes (`state.md#nodes`, `profiles.md#reach`): every identity has
//! one in every space, from the start. It is never created, its id follows
//! from the identity's, and only that identity writes to it, and only with
//! `set`.

use cardinal_crypto::{HybridKeyPair, RecoveryPhrase};
use cardinal_encoding::{Record, Value};
use cardinal_identity::{Created, DeviceKeys, IdentityLog};
use cardinal_space::relationship::{self, Reach};
use cardinal_space::{reach_node_id, NodeKind, Policy, Profile, Space, SpaceOp, ROOT};

fn person(n: u8) -> (IdentityLog, HybridKeyPair, DeviceKeys) {
    let d = DeviceKeys::generate();
    let Created {
        log, encryption, ..
    } = IdentityLog::create_with(
        RecoveryPhrase::from_entropy(&[n; 32]),
        &d,
        HybridKeyPair::generate(),
    )
    .unwrap();
    (log, encryption, d)
}

fn reach(token: u8) -> Reach {
    Reach {
        endpoints: Vec::new(),
        host: [9; 32],
        token: [token; 16],
    }
}

struct Two {
    space: Space,
    ana: IdentityLog,
    ana_dev: DeviceKeys,
    bo: IdentityLog,
    bo_dev: DeviceKeys,
}

fn two() -> Two {
    let (ana, ana_enc, ana_dev) = person(31);
    let (bo, bo_enc, bo_dev) = person(32);
    let (mut space, _) = Space::create_with(
        Profile::RELATIONSHIP,
        Policy::default(),
        &ana,
        &ana_dev.signing,
        &[ana_enc.public_key(), bo_enc.public_key()],
        relationship::genesis_ops(ana.id(), bo.id()),
        None,
    )
    .unwrap();
    space.set_identity(bo.state());
    Two {
        space,
        ana,
        ana_dev,
        bo,
        bo_dev,
    }
}

/// The node records of the canonical state.
fn records(space: &Space) -> Vec<Record> {
    let state = space.state().canonical();
    let list = state.get(1).and_then(Value::as_list).unwrap();
    list.iter()
        .map(|v| v.as_record().unwrap().clone())
        .collect()
}

#[test]
fn its_id_follows_from_the_identitys() {
    let who = [0x61; 32];
    let derived = blake3::derive_key("cardinal 1 reach node", &who);
    assert_eq!(reach_node_id(&who), derived[..16]);
    assert_ne!(reach_node_id(&who), reach_node_id(&[0x62; 32]));
    assert_ne!(reach_node_id(&who), ROOT);
}

/// Two of Ana's devices set it at the same moment, and each registered a
/// token. It holds both lists, and both count: a host maps either token to
/// the space. The list set later in log order comes first, and within a
/// list the order is its person's. One that has seen both replaces both.
#[test]
fn two_lists_set_at_once_both_count() {
    let mut t = two();
    let (ana, bo) = (t.ana.id(), t.bo.id());
    assert!(!relationship::reach_is_set(t.space.state(), &ana));
    let op = relationship::set_reach(&ana, &[reach(1), reach(5)]);
    let (first, _) = t
        .space
        .write_entry(&t.ana, &t.ana_dev.signing, vec![op], Some(1))
        .unwrap();
    let op = relationship::set_reach(&ana, &[reach(7), reach(2), reach(5)]);
    let (second, _) = t
        .space
        .write_concurrent(&t.ana, &t.ana_dev.signing, &[first], vec![op], Some(2))
        .unwrap();

    let all = relationship::reach_of(&t.space, &ana);
    let tokens: Vec<u8> = all.iter().map(|r| r.token[0]).collect();
    let dag = t.space.dag();
    let later_first = match dag.position(&first) > dag.position(&second) {
        true => [1, 5, 7, 2],
        false => [7, 2, 5, 1],
    };
    assert_eq!(tokens, later_first);
    assert_eq!(t.space.state().reach_values(&ana, 1).len(), 2);
    assert!(relationship::reach_is_set(t.space.state(), &ana));
    assert!(relationship::reach_of(&t.space, &bo).is_empty());
    assert!(!relationship::reach_is_set(t.space.state(), &bo));

    let op = relationship::set_reach(&ana, &[reach(3)]);
    t.space
        .write(&t.ana, &t.ana_dev.signing, vec![op], Some(3))
        .unwrap();
    let all = relationship::reach_of(&t.space, &ana);
    assert_eq!(all, [reach(3)]);
}

/// D68 (`profiles.md#reach`). An empty list is how a person says no. Where
/// two of their devices set the list at the same moment and either set it
/// empty, it is empty for whoever looks a host up, whichever came first:
/// no host and no token is read from it.
#[test]
fn of_two_lists_set_at_once_an_empty_one_wins() {
    for emptied_first in [true, false] {
        let mut t = two();
        let ana = t.ana.id();
        let lists: [&[Reach]; 2] = match emptied_first {
            true => [&[], &[reach(1)]],
            false => [&[reach(1)], &[]],
        };
        let op = relationship::set_reach(&ana, lists[0]);
        let (first, _) = t
            .space
            .write_entry(&t.ana, &t.ana_dev.signing, vec![op], Some(1))
            .unwrap();
        let op = relationship::set_reach(&ana, lists[1]);
        t.space
            .write_concurrent(&t.ana, &t.ana_dev.signing, &[first], vec![op], Some(2))
            .unwrap();
        assert_eq!(t.space.state().reach_values(&ana, 1).len(), 2);
        assert!(
            relationship::reach_of(&t.space, &ana).is_empty(),
            "a host is read beside a no (emptied first: {emptied_first})"
        );
        assert!(relationship::reach_is_set(t.space.state(), &ana));
        // The one result, set by a device that has seen both, stands.
        let op = relationship::set_reach(&ana, &[]);
        t.space
            .write(&t.ana, &t.ana_dev.signing, vec![op], Some(3))
            .unwrap();
        assert_eq!(t.space.state().reach_values(&ana, 1).len(), 1);
        assert!(relationship::reach_of(&t.space, &ana).is_empty());
    }
}

/// Someone with no host sets an empty list (`contact.md#accepting`, step
/// 5): they have said, and there is nowhere.
#[test]
fn an_empty_list_is_an_answer() {
    let mut t = two();
    let bo = t.bo.id();
    let op = relationship::set_reach(&bo, &[]);
    let (id, _) = t
        .space
        .write_entry(&t.bo, &t.bo_dev.signing, vec![op], Some(1))
        .unwrap();
    assert!(t.space.validity().is_valid(&id));
    assert!(t.space.state().is_accepted(&id));
    assert!(relationship::reach_is_set(t.space.state(), &bo));
    assert!(relationship::reach_of(&t.space, &bo).is_empty());
    // it is their first entry here, which is how a space is accepted
    assert!(t.space.accepted_by(&bo));
}

/// Only its identity writes to it, and only with `set`. An entry that
/// names a reach node any other way is not accepted for state, as a whole.
#[test]
fn nothing_else_names_a_reach_node() {
    let mut t = two();
    let (ana, bo) = (t.ana.id(), t.bo.id());
    let mine = reach_node_id(&ana);
    let theirs = reach_node_id(&bo);
    let folder = |parent| SpaceOp::create(NodeKind::Uint(5), parent, "x", Record::new());
    let refused: Vec<(&str, Vec<SpaceOp>)> = vec![
        (
            "another's set",
            vec![SpaceOp::set(theirs, 1, Some(Value::list([] as [Value; 0])))],
        ),
        (
            "another's set, beside a create of one's own",
            vec![
                folder(ROOT),
                SpaceOp::set(theirs, 7, Some(Value::from("x"))),
            ],
        ),
        ("a delete of one's own", vec![SpaceOp::delete(mine)]),
        ("a restore of one's own", vec![SpaceOp::restore(mine)]),
        ("a move of one's own", vec![SpaceOp::mv(mine, ROOT, "x")]),
        ("a move under one's own", {
            let made = relationship::conversation(&t.space).unwrap();
            vec![SpaceOp::mv(made, mine, "x")]
        }),
        ("a create under one's own", vec![folder(mine)]),
        ("a create under another's", vec![folder(theirs)]),
    ];
    let before = t.space.state().root_hash();
    for (what, ops) in refused {
        let (id, _) = t
            .space
            .write_entry(&t.ana, &t.ana_dev.signing, ops, None)
            .unwrap();
        // a writer may write any op numbered 32 or above: what it does is
        // for state to say
        assert!(t.space.validity().is_valid(&id), "{what}");
        assert!(!t.space.state().is_accepted(&id), "{what}");
        assert_eq!(t.space.state().root_hash(), before, "{what}");
    }
    assert!(records(&t.space).iter().all(|r| r.get(2).is_some()));
    // its own `set` is accepted beside anything else that is
    let ops = vec![folder(ROOT), relationship::set_reach(&ana, &[reach(1)])];
    let (id, _) = t
        .space
        .write_entry(&t.ana, &t.ana_dev.signing, ops, None)
        .unwrap();
    assert!(t.space.state().is_accepted(&id));
    assert_eq!(relationship::reach_of(&t.space, &ana), [reach(1)]);
}

/// A reach node has a record in the canonical state only while it has a
/// field to record, and the record holds its id and its fields alone
/// (`state.md#canonical-state`). A cleared field is a value with no
/// field 2.
#[test]
fn in_the_canonical_state() {
    let mut t = two();
    let ana = t.ana.id();
    let node = reach_node_id(&ana);
    let of_reach = |space: &Space| -> Vec<Record> {
        let all = records(space).into_iter();
        all.filter(|r| r.get(1).and_then(Value::as_bytes) == Some(&node[..]))
            .collect()
    };
    assert!(of_reach(&t.space).is_empty());

    let op = relationship::set_reach(&ana, &[reach(1)]);
    let (set, _) = t
        .space
        .write_entry(&t.ana, &t.ana_dev.signing, vec![op.clone()], None)
        .unwrap();
    let found = of_reach(&t.space);
    assert_eq!(found.len(), 1);
    let value = match op.body() {
        cardinal_space::SpaceOpBody::Set { value, .. } => value.clone().unwrap(),
        _ => unreachable!(),
    };
    let one = Record::new().with(1, set).with(2, value);
    let field = Record::new().with(1, 1u64).with(2, Value::list([one]));
    let expected = Record::new().with(1, node).with(5, Value::list([field]));
    assert_eq!(found[0], expected);
    // sorted by node id, among the others
    let ids: Vec<Vec<u8>> = records(&t.space)
        .iter()
        .map(|r| r.get(1).and_then(Value::as_bytes).unwrap().to_vec())
        .collect();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(ids, sorted);
    assert!(ids.len() > 1);

    // cleared: the field still has a value to record, which says so
    let (cleared, _) = t
        .space
        .write_entry(
            &t.ana,
            &t.ana_dev.signing,
            vec![SpaceOp::set(node, 1, None)],
            None,
        )
        .unwrap();
    let one = Record::new().with(1, cleared);
    let field = Record::new().with(1, 1u64).with(2, Value::list([one]));
    let expected = Record::new().with(1, node).with(5, Value::list([field]));
    assert_eq!(of_reach(&t.space), [expected]);
    assert!(relationship::reach_of(&t.space, &ana).is_empty());
    assert!(relationship::reach_is_set(t.space.state(), &ana));
}

/// The state is the same whatever order the entries came in, reach nodes
/// and all.
#[test]
fn the_same_from_scratch() {
    let mut t = two();
    let (ana, bo) = (t.ana.id(), t.bo.id());
    let op = relationship::set_reach(&ana, &[reach(1)]);
    let (first, _) = t
        .space
        .write_entry(&t.ana, &t.ana_dev.signing, vec![op], Some(1))
        .unwrap();
    let op = relationship::set_reach(&bo, &[reach(2)]);
    t.space
        .write_concurrent(&t.bo, &t.bo_dev.signing, &[first], vec![op], Some(2))
        .unwrap();
    let op = SpaceOp::set(reach_node_id(&ana), 1, Some(Value::from("mine")));
    t.space
        .write_concurrent(&t.bo, &t.bo_dev.signing, &[first], vec![op], Some(3))
        .unwrap();
    let valid = t.space.validity().valid.clone();
    let again =
        cardinal_space::State::compute(Profile::RELATIONSHIP, t.space.dag(), &valid).root_hash();
    assert_eq!(t.space.state().root_hash(), again);
    assert_eq!(relationship::reach_of(&t.space, &ana), [reach(1)]);
    assert_eq!(relationship::reach_of(&t.space, &bo), [reach(2)]);
}

/// V8. A reach node is a list its member writes, a reader as well. Taking
/// each entry once by comparing it with every one taken so far is the
/// square of its length, each time anyone asks where the member is
/// reached: they are told apart by looking them up.
#[test]
fn a_long_reach_list_is_read_in_one_pass() {
    let asked = std::env::var("V8_REACH")
        .ok()
        .and_then(|v| v.parse::<usize>().ok());
    let many = asked.unwrap_or(1_600);
    let mut t = two();
    let who = t.ana.id();
    let list: Vec<Reach> = (0..many as u32)
        .map(|n| {
            let mut r = reach(1);
            r.token[..4].copy_from_slice(&n.to_le_bytes());
            r
        })
        .collect();
    // each of them twice, as two devices that set the same list
    let mut twice = list.clone();
    twice.extend(list.iter().cloned());
    let set = relationship::set_reach(&who, &twice);
    t.space
        .write(&t.ana, &t.ana_dev.signing, vec![set], None)
        .unwrap();
    let began = std::time::Instant::now();
    let read = relationship::reach_of(&t.space, &who);
    let took = began.elapsed();
    eprintln!(
        "MEASURE a reach node of {} entries was read in {took:?}",
        twice.len()
    );
    assert_eq!(read, list);
    // a debug build took 45 ms for this by comparing, and takes 2
    let bound = std::time::Duration::from_millis(30);
    assert!(asked.is_some() || took < bound, "{took:?}");
}

/// D68 (`hosts.md#grants`). A reach list may name an endpoint this version
/// cannot use: a carrier it does not know, or an address of a length it
/// does not know. The host beside it is read all the same, and the list
/// written again, as when another endpoint in it is brought up to date,
/// holds that endpoint as it came.
#[test]
fn an_endpoint_that_cannot_be_used_is_kept_as_it_came() {
    let mut t = two();
    let who = t.ana.id();
    let radio = Record::new()
        .with(1, [0x52u8; 8])
        .with(2, "anything its document says");
    let other_network = Record::new()
        .with(1, 1u64)
        .with(2, vec![7u8; 6])
        .with(3, 7171u64);
    let tcp = Record::new()
        .with(1, 2u64)
        .with(2, vec![192u8, 0, 2, 1])
        .with(3, 7171u64);
    let host = |endpoints: Vec<Record>, n: u8| {
        Value::Record(
            Record::new()
                .with(1, Value::list(endpoints))
                .with(2, [n; 32])
                .with(3, [n; 16]),
        )
    };
    let list = Value::list([
        host(vec![radio.clone(), tcp.clone()], 1),
        host(vec![other_network.clone()], 2),
    ]);
    let set = SpaceOp::set(reach_node_id(&who), 1, Some(list.clone()));
    t.space
        .write(&t.ana, &t.ana_dev.signing, vec![set], None)
        .unwrap();
    let read = relationship::reach_of(&t.space, &who);
    assert_eq!(read.len(), 2, "a host is dropped for an endpoint");
    let addresses: Vec<std::net::SocketAddr> = read
        .iter()
        .flat_map(|r| r.endpoints.iter().filter_map(|e| e.socket_addr()))
        .collect();
    assert_eq!(addresses, ["192.0.2.1:7171".parse().unwrap()]);
    // written again from what was read, it is the same value
    let again = relationship::set_reach(&who, &read);
    assert_eq!(again, SpaceOp::set(reach_node_id(&who), 1, Some(list)));
}
