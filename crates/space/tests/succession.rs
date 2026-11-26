//! Succession across two spaces (`spaces.md#succession`): the state at a
//! cut, a successor that starts from it, whether a member follows, and what
//! it posts again there.

use std::collections::HashMap;

use cardinal_crypto::{HybridKeyPair, RecoveryPhrase};
use cardinal_encoding::Record;
use cardinal_identity::{Created, DeviceKeys, EntryId, IdentityLog};
use cardinal_space::entry::Succession;
use cardinal_space::group::{self, ADMIN, OWNER, WRITER};
use cardinal_space::relationship;
use cardinal_space::succession::{self, Plan, Verdict};
use cardinal_space::{EpochKey, Policy, SealedEntry, Space, SpaceOp, State};

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

impl Person {
    fn id(&self) -> [u8; 32] {
        self.log.id()
    }

    fn says(&self, sp: &mut Space, text: &str) -> EntryId {
        let c = relationship::conversation(sp).unwrap();
        let op = relationship::create_message(c, text);
        let (id, _) = sp
            .write_entry(&self.log, &self.device.signing, vec![op], Some(1))
            .unwrap();
        id
    }
}

fn said(sp: &Space) -> Vec<String> {
    relationship::messages(sp)
        .into_iter()
        .map(|m| m.text)
        .collect()
}

/// Everything `from` holds that `to` does not, in an order that puts
/// children before parents.
fn sync(from: &Space, to: &mut Space, keys: &HybridKeyPair) {
    let mut ids: Vec<_> = from.dag().log_order().to_vec();
    ids.reverse();
    for id in ids {
        if !to.dag().contains(&id) {
            to.receive(from.sealed(&id).unwrap().clone(), &[keys])
                .unwrap();
        }
    }
}

struct Three {
    ana: Person,
    bo: Person,
    cy: Person,
    /// Each one's copy of the group.
    spaces: [Space; 3],
}

/// Ana's group of three, where each has said hello.
fn three() -> Three {
    three_for(false)
}

/// [`three`], and with `for_call` a group made for a call.
fn three_for(for_call: bool) -> Three {
    let (ana, bo, cy) = (person(1), person(2), person(3));
    let mut ops = group::genesis_ops_for(ana.id(), "Family", for_call);
    ops.push(SpaceOp::add_member(bo.id(), WRITER));
    ops.push(SpaceOp::add_member(cy.id(), WRITER));
    ops.push(group::create_member(&bo.id(), "Bo", true));
    ops.push(group::create_member(&cy.id(), "Cy", true));
    let (mut a, g) = Space::create_with(
        group::GROUP,
        Policy::default(),
        &ana.log,
        &ana.device.signing,
        &[
            ana.enc.public_key(),
            bo.enc.public_key(),
            cy.enc.public_key(),
        ],
        ops,
        Some(1),
    )
    .unwrap();
    let logs = [ana.log.state(), bo.log.state(), cy.log.state()];
    let open = |p: &Person| {
        let mut sp = Space::open_genesis(&g, &[&p.enc], None).unwrap();
        sp.set_identities(logs.iter().cloned());
        sp
    };
    let (mut b, mut c) = (open(&bo), open(&cy));
    a.set_identities(logs.iter().cloned());
    ana.says(&mut a, "hello from ana");
    sync(&a, &mut b, &bo.enc);
    bo.says(&mut b, "hello from bo");
    sync(&b, &mut c, &cy.enc);
    cy.says(&mut c, "hello from cy");
    sync(&c, &mut a, &ana.enc);
    sync(&c, &mut b, &bo.enc);
    Three {
        ana,
        bo,
        cy,
        spaces: [a, b, c],
    }
}

/// The logs a test knows, by identity.
fn logs<'a>(people: &[&'a Person]) -> HashMap<[u8; 32], &'a IdentityLog> {
    people.iter().map(|p| (p.id(), &p.log)).collect()
}

/// Ana succeeds her copy of the group with one naming `named`, from the
/// heads she holds. Returns the successor, its sealed genesis, and the
/// state at the cut.
fn succeed(
    t: &mut Three,
    named: &[([u8; 32], u64)],
    keys: &[&cardinal_crypto::HybridPublicKey],
) -> (Space, SealedEntry, State) {
    succeed_as(t, named, keys, true)
}

/// [`succeed`]; without `reassert`, as software from before that sets
/// nothing again in the genesis, or before field 3 was known.
fn succeed_as(
    t: &mut Three,
    named: &[([u8; 32], u64)],
    keys: &[&cardinal_crypto::HybridPublicKey],
    reassert: bool,
) -> (Space, SealedEntry, State) {
    let all = logs(&[&t.ana, &t.bo, &t.cy]);
    let a = &mut t.spaces[0];
    let cut = a.heads();
    let pinned = succession::judged_with(a, &cut, |w| all.get(w).copied());
    let states = succession::pinned_states(&pinned, |w| all.get(w).copied()).unwrap();
    let ids: Vec<[u8; 32]> = named.iter().map(|(w, _)| *w).collect();
    let at_cut = a.state_at(&cut, states, &ids).unwrap();
    let from = Succession {
        succeeds: Some(a.id()),
        // a blob reference in the node; here the canonical state stands in
        initial_state: Some(Record::new().with(1, at_cut.root_hash())),
        cut: cut.clone(),
        judged_with: pinned,
        ..Succession::default()
    };
    let mut ops: Vec<SpaceOp> = named
        .iter()
        .map(|(w, r)| SpaceOp::add_member(*w, *r))
        .collect();
    // The owner sets again, in the genesis, what only an admin's say counts
    // on: carried, it counts for nothing.
    if reassert {
        ops.extend(group::reassert_ops(a, &at_cut));
    }
    let (mut s, g) = Space::create_successor(
        group::GROUP,
        a.policy().clone(),
        &from,
        EpochKey::generate(),
        State::from_canonical(group::GROUP, &at_cut.canonical()).unwrap(),
        &t.ana.log,
        &t.ana.device.signing,
        keys,
        ops,
        Some(2),
    )
    .unwrap();
    let left: Vec<[u8; 32]> = a
        .validity()
        .identities()
        .into_iter()
        .filter(|w| !ids.contains(w))
        .collect();
    a.write(
        &t.ana.log,
        &t.ana.device.signing,
        vec![SpaceOp::succeed_with(s.id(), &left, None)],
        Some(3),
    )
    .unwrap();
    s.set_identities([t.ana.log.state(), t.bo.log.state(), t.cy.log.state()]);
    (s, g, at_cut)
}

#[test]
fn a_canonical_state_read_back_is_the_same_state() {
    let t = three();
    let a = &t.spaces[0];
    let canonical = a.state().canonical();
    let back = State::from_canonical(group::GROUP, &canonical).unwrap();
    assert_eq!(back.canonical(), canonical);
    assert_eq!(back.len(), a.state().len());
    assert!(a.state().nodes().all(|n| back.is_carried(&n.id)));
    assert!(State::from_canonical(group::GROUP, &Record::new().with(0, 12u32)).is_err());
}

#[test]
fn removing_someone_carries_the_group_and_leaves_them_out() {
    let mut t = three();
    let named = [(t.ana.id(), OWNER), (t.bo.id(), WRITER)];
    let keys = [
        t.ana.enc.public_key().clone(),
        t.bo.enc.public_key().clone(),
    ];
    let refs: Vec<_> = keys.iter().collect();
    let (s, g, at_cut) = succeed(&mut t, &named, &refs);
    let [a, b, c] = &mut t.spaces;
    assert!(a.ended());
    assert_eq!(a.successor(), Some(s.id()));
    // The successor starts where the group was: the conversation, the
    // names, every message, and in the order they were written.
    assert_eq!(group::name(&s), "Family");
    assert_eq!(
        said(&s),
        ["hello from ana", "hello from bo", "hello from cy"]
    );
    assert_eq!(s.initial_state().unwrap().canonical(), at_cut.canonical());
    assert_eq!(s.owner(), Some(t.ana.id()));
    assert_eq!(s.role_of(&t.cy.id()), None);
    // Cy's reach node is not carried: nobody there could empty it.
    assert!(s
        .state()
        .reach_nodes()
        .all(|(n, _)| *n != cardinal_space::reach_node_id(&t.cy.id())));

    // Bo learns of the end, and follows: his own state at the cut is the
    // successor's.
    sync(a, b, &t.bo.enc);
    assert!(b.ended());
    let mine = Space::open_genesis(&g, &[&t.bo.enc], None).unwrap();
    assert_eq!(
        succession::verdict(b, &mine, &t.bo.id(), false),
        Verdict::Follow
    );
    let all = logs(&[&t.ana, &t.bo, &t.cy]);
    let from = mine.succession().unwrap().clone();
    let states = succession::pinned_states(&from.judged_with, |w| all.get(w).copied()).unwrap();
    let ids: Vec<[u8; 32]> = named.iter().map(|(w, _)| *w).collect();
    let his = b.state_at(&from.cut, states, &ids).unwrap();
    assert_eq!(his.canonical(), at_cut.canonical());
    // Cy opens no wrap of it: left out.
    sync(a, c, &t.cy.enc);
    assert!(c.ended());
    assert!(Space::open_genesis(&g, &[&t.cy.enc], None).is_err());
    assert_eq!(
        succession::verdict(c, &mine, &t.cy.id(), false),
        Verdict::LeftOut
    );
    // nor does anything but a witness get written there any more
    let tried = c.write(&t.cy.log, &t.cy.device.signing, vec![], Some(9));
    assert!(tried.is_ok());
    let c_id = relationship::conversation(c).unwrap();
    let op = relationship::create_message(c_id, "still here?");
    assert!(c
        .write(&t.cy.log, &t.cy.device.signing, vec![op], Some(9))
        .is_err());
}

#[test]
fn a_successor_by_someone_else_or_naming_another_space_is_not_followed() {
    let mut t = three();
    let named = [(t.ana.id(), OWNER), (t.bo.id(), ADMIN)];
    let keys = [
        t.ana.enc.public_key().clone(),
        t.bo.enc.public_key().clone(),
    ];
    let refs: Vec<_> = keys.iter().collect();
    let (s, _, _) = succeed(&mut t, &named, &refs);
    let [a, b, _] = &mut t.spaces;
    sync(a, b, &t.bo.enc);
    // a frozen owner's is shown as one handed on
    assert_eq!(
        succession::verdict(b, &s, &t.bo.id(), true),
        Verdict::FrozenOwner
    );
    // the space it names is another
    let other = Space::create(
        group::GROUP,
        Policy::default(),
        &t.ana.log,
        &t.ana.device.signing,
        &[t.bo.enc.public_key()],
        None,
    )
    .unwrap()
    .0;
    assert!(matches!(
        succession::verdict(b, &other, &t.bo.id(), false),
        Verdict::NotWhatItSays(_)
    ));
}

#[test]
fn what_the_cut_left_behind_is_posted_again_beside_what_its_writer_had_not_seen() {
    let mut t = three();
    // Bo writes, and edits Ana's group name, before he hears of the end.
    let (bo_said, bo_named) = {
        let b = &mut t.spaces[1];
        let said = t.bo.says(b, "written before he heard");
        let c = relationship::conversation(b).unwrap();
        let (named, _) = b
            .write_entry(
                &t.bo.log,
                &t.bo.device.signing,
                vec![group::rename(c, "Family!")],
                Some(4),
            )
            .unwrap();
        (said, named)
    };
    // Ana renames the group too, and then succeeds it, without Bo's.
    {
        let a = &mut t.spaces[0];
        let c = relationship::conversation(a).unwrap();
        a.write(
            &t.ana.log,
            &t.ana.device.signing,
            vec![group::rename(c, "The family")],
            Some(4),
        )
        .unwrap();
    }
    let named = [
        (t.ana.id(), OWNER),
        (t.bo.id(), WRITER),
        (t.cy.id(), WRITER),
    ];
    let keys = [
        t.ana.enc.public_key().clone(),
        t.bo.enc.public_key().clone(),
        t.cy.enc.public_key().clone(),
    ];
    let refs: Vec<_> = keys.iter().collect();
    let (mut s, _, _) = succeed(&mut t, &named, &refs);
    let [a, b, _] = &mut t.spaces;
    sync(a, b, &t.bo.enc);
    assert!(said(&s).iter().all(|m| m != "written before he heard"));
    // Bo's device posts again what it wrote that the cut left behind.
    let none = |_: &EntryId| None;
    let plan = succession::plan_repost(b, &bo_said, &s, &none);
    let Plan::Post(r) = plan else {
        panic!("{plan:?}")
    };
    s.write(&t.bo.log, &t.bo.device.signing, r.ops, Some(5))
        .unwrap();
    assert!(said(&s).iter().any(|m| m == "written before he heard"));
    // His rename had not seen Ana's: it stands beside it, in conflict.
    let Plan::Post(r) = succession::plan_repost(b, &bo_named, &s, &none) else {
        panic!()
    };
    assert!(r.ops.iter().all(|op| op.record().get(4).is_some()));
    s.write(&t.bo.log, &t.bo.device.signing, r.ops, Some(6))
        .unwrap();
    let c = relationship::conversation(&s).unwrap();
    assert!(s.state().node(&c).unwrap().in_conflict(1));
    // A message's own `create` lists the id it had, and a reply to it
    // waits for nothing.
    let posted = relationship::messages(&s);
    let again = posted
        .iter()
        .find(|m| m.text == "written before he heard")
        .unwrap();
    let old = relationship::messages(b);
    let was = old
        .iter()
        .find(|m| m.text == "written before he heard")
        .unwrap();
    assert_eq!(s.state().now_called(&was.id), Some(again.id));
}

#[test]
fn a_delete_of_a_carried_node_yields_to_work_beside_it() {
    let mut t = three();
    let named = [(t.ana.id(), OWNER), (t.bo.id(), WRITER)];
    let keys = [
        t.ana.enc.public_key().clone(),
        t.bo.enc.public_key().clone(),
    ];
    let refs: Vec<_> = keys.iter().collect();
    let (mut s, g, at_cut) = succeed(&mut t, &named, &refs);
    let mut theirs = Space::open_genesis(&g, &[&t.bo.enc], None).unwrap();
    theirs.set_initial_state(State::from_canonical(group::GROUP, &at_cut.canonical()).unwrap());
    theirs.set_identities([t.ana.log.state(), t.bo.log.state(), t.cy.log.state()]);
    assert_eq!(said(&theirs), said(&s));
    // Ana deletes the conversation the successor carried, while Bo writes
    // in it, neither having seen the other.
    let c = relationship::conversation(&s).unwrap();
    s.write(
        &t.ana.log,
        &t.ana.device.signing,
        vec![SpaceOp::delete(c)],
        Some(5),
    )
    .unwrap();
    t.bo.says(&mut theirs, "still talking");
    sync(&s, &mut theirs, &t.bo.enc);
    sync(&theirs, &mut s, &t.ana.enc);
    for sp in [&s, &theirs] {
        let n = sp.state().node(&c).unwrap();
        assert!(!n.deleted && n.delete_conflict, "{n:?}");
        assert!(said(sp).contains(&"still talking".to_owned()));
        // and the old messages, untouched, went with the delete
        assert!(!said(sp).contains(&"hello from cy".to_owned()));
    }
    assert_eq!(s.state().canonical(), theirs.state().canonical());
}

#[test]
fn what_a_writer_set_where_only_an_admin_counts_does_not_count_after() {
    let mut t = three();
    // Bo, a writer, renames the group and himself; neither counts.
    {
        let b = &mut t.spaces[1];
        let c = relationship::conversation(b).unwrap();
        let me = group::members(b)
            .into_iter()
            .find(|m| m.identity == t.bo.id())
            .unwrap()
            .node
            .unwrap();
        b.write(
            &t.bo.log,
            &t.bo.device.signing,
            vec![
                group::rename(c, "Bo's club"),
                group::set_member_name(me, "Boss"),
            ],
            Some(4),
        )
        .unwrap();
    }
    {
        let [a, b, _] = &mut t.spaces;
        sync(b, a, &t.ana.enc);
    }
    let name_of = |sp: &Space, who: [u8; 32]| {
        group::members(sp)
            .into_iter()
            .find(|m| m.identity == who)
            .and_then(|m| m.name)
    };
    let was_name = group::name(&t.spaces[0]);
    let was_bo = name_of(&t.spaces[0], t.bo.id());
    assert_ne!(was_name, "Bo's club");
    assert_ne!(was_bo.as_deref(), Some("Boss"));
    let named = [(t.ana.id(), OWNER), (t.bo.id(), WRITER)];
    let keys = [
        t.ana.enc.public_key().clone(),
        t.bo.enc.public_key().clone(),
    ];
    let refs: Vec<_> = keys.iter().collect();
    let (s, g, at_cut) = succeed(&mut t, &named, &refs);
    // Carried, his values are there; what stands is what Ana's group said.
    assert_eq!(group::name(&s), was_name);
    assert_eq!(name_of(&s, t.bo.id()), was_bo);
    // and with the genesis alone, which sets them again, there is no gap:
    // the names Ana's group gave, never Bo's (`profiles.md#group`)
    assert_eq!(s.dag().len(), 1, "the genesis alone");
    let mut bare = Space::open_genesis(&g, &[&t.bo.enc], None).unwrap();
    bare.set_initial_state(State::from_canonical(group::GROUP, &at_cut.canonical()).unwrap());
    bare.set_identities([t.ana.log.state(), t.bo.log.state()]);
    assert_eq!(group::name(&bare), was_name);
    assert_eq!(name_of(&bare, t.bo.id()), was_bo);
}

#[test]
fn a_canonical_state_that_is_no_tree_is_refused() {
    let t = three();
    let canonical = t.spaces[0].state().canonical();
    // a node whose parent is nowhere in it
    let mut records: Vec<cardinal_encoding::Value> = canonical.list(1).unwrap().to_vec();
    let first = records
        .iter()
        .position(|r| r.as_record().unwrap().get(2).is_some())
        .unwrap();
    let r = records[first]
        .as_record()
        .unwrap()
        .clone()
        .with(3, [9u8; 16]);
    records[first] = r.into();
    let broken = canonical
        .clone()
        .with(1, cardinal_encoding::Value::list(records));
    assert!(State::from_canonical(group::GROUP, &broken).is_err());
}

#[test]
fn a_node_whose_maker_can_no_longer_write_is_not_waited_for() {
    let mut t = three();
    // Cy writes, Bo reacts to it, and neither reaches Ana before she
    // makes Cy a reader.
    let cy_said = t.cy.says(&mut t.spaces[2], "cy, unheard");
    let reaction = {
        let [_, b, c] = &mut t.spaces;
        sync(c, b, &t.bo.enc);
        let m = relationship::messages(b)
            .into_iter()
            .find(|m| m.text == "cy, unheard")
            .unwrap();
        let (id, _) = b
            .write_entry(
                &t.bo.log,
                &t.bo.device.signing,
                vec![relationship::create_reaction(m.id, "+1")],
                Some(5),
            )
            .unwrap();
        id
    };
    let _ = cy_said;
    let named = [
        (t.ana.id(), OWNER),
        (t.bo.id(), WRITER),
        (t.cy.id(), group::READER),
    ];
    let keys = [
        t.ana.enc.public_key().clone(),
        t.bo.enc.public_key().clone(),
        t.cy.enc.public_key().clone(),
    ];
    let refs: Vec<_> = keys.iter().collect();
    let (s, _, _) = succeed(&mut t, &named, &refs);
    // Cy cannot post his message again there: Bo's reaction goes ahead
    // without it, at the nearest node the successor has.
    let none = |_: &EntryId| None;
    let plan = succession::plan_repost(&t.spaces[1], &reaction, &s, &none);
    let Plan::Post(r) = plan else {
        panic!("{plan:?}")
    };
    let c = relationship::conversation(&s).unwrap();
    assert_eq!(
        r.ops[0].record().get(2).and_then(|v| v.as_bytes()),
        Some(&c[..])
    );
}

/// Writes `ops` as `who`, in their copy `i` of the group, and gives it to
/// the other two copies.
fn write_as(t: &mut Three, i: usize, ops: Vec<SpaceOp>) {
    let who = [&t.ana, &t.bo, &t.cy][i];
    t.spaces[i]
        .write(&who.log, &who.device.signing, ops, Some(5))
        .unwrap();
    let encs = [&t.ana.enc, &t.bo.enc, &t.cy.enc];
    for j in 0..3 {
        if j != i {
            let (from, to) = if i < j {
                let (l, r) = t.spaces.split_at_mut(j);
                (&l[i], &mut r[0])
            } else {
                let (l, r) = t.spaces.split_at_mut(i);
                (&r[0], &mut l[j])
            };
            sync(from, to, encs[j]);
        }
    }
}

/// D92, as the mark was settled: a group is made for a call while field 3
/// of its conversation node holds only what its genesis wrote, true. Any
/// later write there, by anyone, of any value, makes it an ordinary group,
/// and nothing in that space makes it one again.
#[test]
fn only_a_genesis_makes_a_group_one_made_for_a_call() {
    assert!(!group::for_call(&three().spaces[0]), "an ordinary group");
    let t = three_for(true);
    assert!(t.spaces.iter().all(group::for_call), "made for a call");
    let value = |v: Option<bool>| v.map(cardinal_encoding::Value::from);
    // (who writes, what): the owner keeping it, an admin's or a writer's
    // true, a clearing set, and something that is not a bool
    let writes: [(usize, Option<cardinal_encoding::Value>); 5] = [
        (0, value(Some(false))),
        (0, value(Some(true))),
        (1, value(Some(true))),
        (2, None),
        (0, Some(cardinal_encoding::Value::from(1u64))),
    ];
    for (who, v) in writes {
        let mut t = three_for(true);
        let c = relationship::conversation(&t.spaces[0]).unwrap();
        write_as(
            &mut t,
            who,
            vec![SpaceOp::set(c, group::FOR_CALL, v.clone())],
        );
        for sp in &t.spaces {
            assert!(!group::for_call(sp), "after {who} wrote {v:?}");
        }
        // and the owner's true after that does not make it one again
        write_as(
            &mut t,
            0,
            vec![SpaceOp::set(c, group::FOR_CALL, value(Some(true)))],
        );
        assert!(!group::for_call(&t.spaces[1]), "set again after {v:?}");
    }
    // Keep this group, as the node writes it
    let mut t = three_for(true);
    let c = relationship::conversation(&t.spaces[0]).unwrap();
    write_as(&mut t, 0, vec![group::keep_group(c)]);
    assert!(!group::for_call(&t.spaces[2]));
    // the other fields are untouched by it
    assert_eq!(group::name(&t.spaces[2]), "Family");
}

/// A successor is made for a call only where its own genesis sets field 3
/// true: the owner's software does so where the group it succeeds was one
/// at the cut, and not otherwise. What it carried counts for nothing.
#[test]
fn a_successor_is_made_for_a_call_only_by_its_own_genesis() {
    let named = |t: &Three| [(t.ana.id(), OWNER), (t.bo.id(), WRITER)];
    let keys = |t: &Three| {
        [
            t.ana.enc.public_key().clone(),
            t.bo.enc.public_key().clone(),
        ]
    };
    // a call group, succeeded by software that sets it again
    let mut t = three_for(true);
    let (n, k) = (named(&t), keys(&t));
    let refs: Vec<_> = k.iter().collect();
    let (s, g, at_cut) = succeed(&mut t, &n, &refs);
    assert!(group::for_call(&s), "set again by the genesis");
    let mut bare = Space::open_genesis(&g, &[&t.bo.enc], None).unwrap();
    bare.set_initial_state(State::from_canonical(group::GROUP, &at_cut.canonical()).unwrap());
    bare.set_identities([t.ana.log.state(), t.bo.log.state()]);
    assert!(group::for_call(&bare), "as Bo reads it from the genesis");
    // the same, by software that does not set it again: only carried
    let mut t = three_for(true);
    let (n, k) = (named(&t), keys(&t));
    let refs: Vec<_> = k.iter().collect();
    let (s, _, _) = succeed_as(&mut t, &n, &refs, false);
    assert!(!group::for_call(&s), "a carried mark counts for nothing");
    // a call group kept as an ordinary one stays ordinary when succeeded
    let mut t = three_for(true);
    let c = relationship::conversation(&t.spaces[0]).unwrap();
    write_as(&mut t, 0, vec![group::keep_group(c)]);
    let (n, k) = (named(&t), keys(&t));
    let refs: Vec<_> = k.iter().collect();
    let (s, _, _) = succeed(&mut t, &n, &refs);
    assert!(!group::for_call(&s), "kept, then succeeded");
    // and an ordinary one too
    let mut t = three();
    let (n, k) = (named(&t), keys(&t));
    let refs: Vec<_> = k.iter().collect();
    let (s, _, _) = succeed(&mut t, &n, &refs);
    assert!(!group::for_call(&s));
}

/// D92: a `set` of field 3 written beside what the genesis wrote stands
/// beside it, and the group is an ordinary one from then on; so are two
/// writes made apart, by two members who had not seen each other's.
#[test]
fn a_write_beside_or_two_apart_make_a_call_group_ordinary() {
    let value = |v: bool| Some(cardinal_encoding::Value::from(v));
    // beside: the genesis's true is still there, with another
    let mut t = three_for(true);
    let c = relationship::conversation(&t.spaces[0]).unwrap();
    write_as(
        &mut t,
        1,
        vec![SpaceOp::set_beside(c, group::FOR_CALL, value(true))],
    );
    for sp in &t.spaces {
        let n = sp.state().node(&c).unwrap();
        assert_eq!(n.values(group::FOR_CALL).len(), 2, "beside, not over");
        assert!(!group::for_call(sp), "a write beside the genesis's");
    }
    // apart: Bo and Cy each write, neither seeing the other's
    let mut t = three_for(true);
    let c = relationship::conversation(&t.spaces[0]).unwrap();
    for (i, v) in [(1, true), (2, false)] {
        let who = [&t.ana, &t.bo, &t.cy][i];
        t.spaces[i]
            .write(
                &who.log,
                &who.device.signing,
                vec![SpaceOp::set(c, group::FOR_CALL, value(v))],
                Some(5),
            )
            .unwrap();
    }
    let encs = [&t.ana.enc, &t.bo.enc, &t.cy.enc];
    for (from, to) in [(1, 0), (2, 0), (1, 2), (2, 1)] {
        let (f, tt) = if from < to {
            let (l, r) = t.spaces.split_at_mut(to);
            (&l[from], &mut r[0])
        } else {
            let (l, r) = t.spaces.split_at_mut(from);
            (&r[0], &mut l[to])
        };
        sync(f, tt, encs[to]);
    }
    for sp in &t.spaces {
        assert!(!group::for_call(sp), "two writes apart");
    }
}

/// "The genesis creates one conversation node" (`profiles.md#relationship`):
/// the group's name and its mark are read from that node and no other. A
/// second conversation node a member writes under the root, whatever its
/// name, displaces nothing, nor does deleting it, or writing the mark on
/// it; and messages are still written under the genesis's.
#[test]
fn a_second_conversation_node_displaces_nothing() {
    use cardinal_space::{NodeKind, ROOT};
    let mut t = three_for(true);
    let c = relationship::conversation(&t.spaces[0]).unwrap();
    // Bo, a writer, makes one whose name sorts before "conversation"
    let fields = Record::new().with(1, "Not Family");
    let op = SpaceOp::create(
        NodeKind::Uint(relationship::CONVERSATION),
        ROOT,
        "a",
        fields,
    );
    write_as(&mut t, 1, vec![op]);
    let other = {
        let st = t.spaces[0].state();
        let kids = st.children(&ROOT);
        let found = kids
            .into_iter()
            .find(|n| n.kind == NodeKind::Uint(relationship::CONVERSATION) && n.id != c);
        found.expect("the second one").id
    };
    for sp in &t.spaces {
        assert_eq!(relationship::conversation(sp), Some(c));
        assert_eq!(group::name(sp), "Family");
        assert!(group::for_call(sp), "still a call group");
    }
    // the mark written on the second one: nothing changes
    let keep = vec![group::keep_group(other)];
    write_as(&mut t, 2, keep);
    assert!(group::for_call(&t.spaces[0]), "kept on the wrong node");
    // a group kept on its own node stays kept, with the second deleted
    write_as(&mut t, 0, vec![group::keep_group(c)]);
    write_as(&mut t, 1, vec![SpaceOp::delete(other)]);
    for sp in &t.spaces {
        assert!(!group::for_call(sp), "made a call group again");
        assert_eq!(relationship::conversation(sp), Some(c));
    }
    t.cy.says(&mut t.spaces[2], "hello there");
    assert!(said(&t.spaces[2]).contains(&"hello there".to_owned()));
}

/// "Which node is the conversation" (`profiles.md#relationship`): the one
/// the genesis created, the lowest in rank of kind 1, wherever it has been
/// moved; a successor carries it with its rank, so it is the same node
/// there, deleted or not. A second one a writer made, whatever its name,
/// is not it, in the space or in a successor.
#[test]
fn a_successor_reads_the_conversation_its_first_genesis_made() {
    use cardinal_space::{NodeKind, ROOT};
    let mut t = three();
    let c = relationship::conversation(&t.spaces[0]).unwrap();
    // Bo makes another, named to come first among the root's children
    let fields = Record::new().with(1, "Not Family");
    let kind = NodeKind::Uint(relationship::CONVERSATION);
    write_as(&mut t, 1, vec![SpaceOp::create(kind, ROOT, "a", fields)]);
    // Ana moves the real one into a folder of its own
    write_as(
        &mut t,
        0,
        vec![SpaceOp::create(NodeKind::Uint(7), ROOT, "folder", Record::new())],
    );
    let folder = {
        let st = t.spaces[0].state();
        let kids = st.children(&ROOT);
        kids.into_iter().find(|n| n.name == "folder").unwrap().id
    };
    write_as(&mut t, 0, vec![SpaceOp::mv(c, folder, "conversation")]);
    for sp in &t.spaces {
        assert_eq!(relationship::conversation(sp), Some(c), "moved");
        assert_eq!(group::name(sp), "Family");
    }
    let named = [(t.ana.id(), OWNER), (t.bo.id(), WRITER)];
    let keys = [
        t.ana.enc.public_key().clone(),
        t.bo.enc.public_key().clone(),
    ];
    let refs: Vec<_> = keys.iter().collect();
    let (mut s, _, _) = succeed(&mut t, &named, &refs);
    assert_eq!(relationship::conversation(&s), Some(c), "in the successor");
    assert_eq!(group::name(&s), "Family");
    // deleted there, it is still the node the name is read from, and
    // nothing is written under it
    s.write(
        &t.ana.log,
        &t.ana.device.signing,
        vec![SpaceOp::delete(c)],
        Some(4),
    )
    .unwrap();
    assert_eq!(relationship::the_conversation(&s), Some(c));
    assert_eq!(relationship::conversation(&s), None);
    assert_eq!(group::name(&s), "Family");
}

/// Who may ring someone only offered a group (`profiles.md#calls-guidance`,
/// "Someone only offered the group"): a contact a valid entry of whose
/// added them, the genesis included, with no valid `leave` of theirs
/// descending from it. The genesis counts even where another addition of
/// them came since; and a leave taken back by a later addition still
/// stands between the person and the addition before it.
#[test]
fn whoever_added_someone_is_read_from_every_valid_addition_and_leave() {
    let mut t = three();
    let (ana, bo, cy) = (t.ana.id(), t.bo.id(), t.cy.id());
    write_as(&mut t, 0, vec![SpaceOp::add_member(bo, ADMIN)]);
    // Bo adds Cy, whom Ana's genesis named, again
    write_as(&mut t, 1, vec![SpaceOp::add_member(cy, WRITER)]);
    for sp in &t.spaces {
        assert!(sp.added_by_and_not_left(&cy, &ana), "by the genesis");
        assert!(sp.added_by_and_not_left(&cy, &bo), "by Bo's");
    }
    // Ana adds him once more; he leaves; Bo adds him back
    write_as(&mut t, 0, vec![SpaceOp::add_member(cy, WRITER)]);
    write_as(&mut t, 2, vec![SpaceOp::leave()]);
    write_as(&mut t, 1, vec![SpaceOp::add_member(cy, WRITER)]);
    for sp in &t.spaces {
        assert!(!sp.added_by_and_not_left(&cy, &ana), "he left after Ana's");
        assert!(sp.added_by_and_not_left(&cy, &bo), "Bo's came after");
    }
}
