//! What a conversation's messages can say beyond their text
//! (`profiles.md#relationship`): replies, edits, deletes and reactions, and
//! that each is only its author's to change.

use cardinal_crypto::{HybridKeyPair, RecoveryPhrase};
use cardinal_identity::{Created, DeviceKeys, IdentityLog, Power};
use cardinal_space::relationship;
use cardinal_space::{NodeId, Policy, Profile, SealedEntry, Space, SpaceOp};

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

struct Pair {
    ana: Person,
    bo: Person,
    a: Space,
    b: Space,
    c: NodeId,
}

fn relationship_of(ana: Person, bo: Person) -> Pair {
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
    // each holds the other's identity log, which judges what they write
    a.set_identity(bo.log.state());
    let c = relationship::conversation(&a).unwrap();
    let mut b = Space::open_genesis(&genesis, &[&bo.enc], Some(ana.log.state())).unwrap();
    b.set_identity(bo.log.state());
    Pair { ana, bo, a, b, c }
}

impl Pair {
    /// What each holds valid, judged as entries arrived, is what the rules
    /// find in all of it.
    fn eval(&mut self) {
        let logs = [&self.ana.log, &self.bo.log];
        for space in [&self.a, &self.b] {
            let rules = cardinal_space::validity::by_rules(space.dag(), &logs).unwrap();
            assert!(space.validity().valid == rules.valid);
        }
    }
    fn ana_writes(&mut self, ops: Vec<SpaceOp>) -> SealedEntry {
        let s = self
            .a
            .write(&self.ana.log, &self.ana.devices[0].signing, ops, Some(1))
            .unwrap();
        self.b.receive(s.clone(), &[&self.bo.enc]).unwrap();
        self.eval();
        s
    }
    fn bo_writes(&mut self, ops: Vec<SpaceOp>) -> SealedEntry {
        let s = self
            .b
            .write(&self.bo.log, &self.bo.devices[0].signing, ops, Some(1))
            .unwrap();
        self.a.receive(s.clone(), &[&self.ana.enc]).unwrap();
        self.eval();
        s
    }
}

fn said(space: &Space) -> Vec<relationship::Message> {
    relationship::messages(space)
}

/// `state.md#operations`: a node in a place where its kind means nothing
/// is in the state and is not shown. A message that is not in the
/// conversation is no message of it, nor is a reaction that is not under a
/// message a reaction, nor a second conversation inside the first one a
/// conversation.
#[test]
fn what_is_out_of_place_is_kept_and_not_shown() {
    use cardinal_space::{NodeKind, ROOT};
    let mut p = relationship_of(person(61, 0), person(62, 0));
    let c = p.c;
    p.ana_writes(vec![relationship::create_message(c, "in its place")]);
    let m = said(&p.b)[0].id;
    let record = cardinal_encoding::Record::new;
    let odd = vec![
        // a message at the top, and one under a message
        relationship::create_message(ROOT, "at the top"),
        relationship::create_message(m, "under a message"),
        // a reaction in the conversation, not under a message
        relationship::create_reaction(c, "!"),
        // a conversation inside the conversation, and a kind nobody knows
        SpaceOp::create(
            NodeKind::Uint(relationship::CONVERSATION),
            c,
            "inner",
            record(),
        ),
        SpaceOp::create(NodeKind::Uint(200), c, "new", record().with(1, "text")),
    ];
    let before = p.b.state().len();
    p.bo_writes(odd);
    for space in [&p.a, &p.b] {
        let last = *space.dag().log_order().last().unwrap();
        assert!(space.validity().is_valid(&last) && space.state().is_accepted(&last));
        assert_eq!(space.state().len(), before + 5, "kept");
        let all = said(space);
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].text, "in its place");
        assert!(all[0].reactions.is_empty());
        assert_eq!(relationship::conversation(space), Some(c));
    }
    assert_eq!(p.a.state().canonical(), p.b.state().canonical());
}

#[test]
fn a_reply_names_what_it_answers() {
    let mut p = relationship_of(person(41, 0), person(42, 0));
    let c = p.c;
    p.ana_writes(vec![relationship::create_message(c, "lunch?")]);
    let asked = said(&p.b)[0].id;
    p.bo_writes(vec![relationship::create_reply(c, "yes", Some(asked))]);
    let all = said(&p.a);
    assert_eq!(all[1].text, "yes");
    assert_eq!(all[1].reply_to, Some(asked));
    assert_eq!(all[0].reply_to, None);
}

#[test]
fn an_author_edits_and_deletes_their_own() {
    let mut p = relationship_of(person(43, 0), person(44, 0));
    let c = p.c;
    p.ana_writes(vec![relationship::create_message(c, "helo")]);
    let m = said(&p.b)[0].id;
    assert!(!said(&p.b)[0].edited);
    p.ana_writes(vec![relationship::edit_message(m, "hello")]);
    assert_eq!(said(&p.b)[0].text, "hello");
    assert!(said(&p.b)[0].edited);
    p.ana_writes(vec![SpaceOp::delete(m)]);
    assert!(said(&p.a).is_empty() && said(&p.b).is_empty());
}

#[test]
fn nobody_changes_what_someone_else_wrote() {
    let mut p = relationship_of(person(45, 0), person(46, 0));
    let c = p.c;
    p.ana_writes(vec![relationship::create_message(c, "mine")]);
    let m = said(&p.b)[0].id;
    p.bo_writes(vec![relationship::edit_message(m, "bo's now")]);
    p.bo_writes(vec![SpaceOp::delete(m)]);
    for space in [&p.a, &p.b] {
        let all = said(space);
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].text, "mine");
        assert!(!all[0].edited);
    }
}

#[test]
fn each_member_reacts_for_themselves() {
    let mut p = relationship_of(person(47, 0), person(48, 0));
    let c = p.c;
    p.ana_writes(vec![relationship::create_message(c, "news")]);
    let m = said(&p.b)[0].id;
    p.ana_writes(vec![relationship::create_reaction(m, "👍")]);
    p.bo_writes(vec![relationship::create_reaction(m, "🎉")]);
    let reactions = &said(&p.a)[0].reactions;
    assert_eq!(reactions.len(), 2);
    let ana_r = reactions
        .iter()
        .find(|r| r.author == p.ana.log.id())
        .unwrap();
    let bo_r = reactions
        .iter()
        .find(|r| r.author == p.bo.log.id())
        .unwrap()
        .id;
    assert_eq!(ana_r.text, "👍");

    // Ana changes hers; Bo cannot change or take away hers.
    let ana_r = ana_r.id;
    p.ana_writes(vec![relationship::set_reaction(ana_r, "❤")]);
    p.bo_writes(vec![relationship::set_reaction(ana_r, "👎")]);
    p.bo_writes(vec![SpaceOp::delete(ana_r)]);
    let reactions = &said(&p.b)[0].reactions;
    let ana_now = reactions
        .iter()
        .find(|r| r.author == p.ana.log.id())
        .unwrap();
    assert_eq!(ana_now.text, "❤");

    p.bo_writes(vec![SpaceOp::delete(bo_r)]);
    assert_eq!(said(&p.a)[0].reactions.len(), 1);
}

/// A read marker stands at a message, and one naming nothing known is not
/// taken either.
#[test]
fn a_marker_at_nothing_known_is_not_taken() {
    let mut p = relationship_of(person(51, 0), person(52, 0));
    let c = p.c;
    p.bo_writes(vec![relationship::create_message(c, "hi")]);
    let me = p.ana.log.id();
    p.ana_writes(vec![relationship::create_read_marker(c, [9; 16])]);
    assert!(relationship::read_marker(&p.b, &me).is_none());
    let m = said(&p.b)[0].id;
    p.ana_writes(vec![relationship::create_read_marker(c, m)]);
    assert!(relationship::read_marker(&p.b, &me).is_some());
}

/// A reply names the message it answers, and one naming nothing known is not
/// taken, as an op naming an unknown node is not (`state.md`).
#[test]
fn a_reply_to_nothing_known_is_not_taken() {
    let mut p = relationship_of(person(49, 0), person(50, 0));
    let c = p.c;
    p.ana_writes(vec![relationship::create_reply(
        c,
        "to nowhere",
        Some([9; 16]),
    )]);
    assert!(said(&p.a).is_empty());
    assert!(said(&p.b).is_empty());
    p.ana_writes(vec![relationship::create_message(c, "hi")]);
    let m = said(&p.b)[0].id;
    p.bo_writes(vec![relationship::create_reply(c, "back", Some(m))]);
    assert_eq!(said(&p.a)[1].reply_to, Some(m));
    // A reply holds the id of what it answers, and nothing else will do
    // (`state.md#a-node-made-in-the-same-entry`): not the index of a
    // message made earlier in the same entry, which a reply cannot answer,
    // nor text, nor bytes of another length. Such an entry is valid, and
    // none of it is taken.
    let reply_to = |to: cardinal_encoding::Value| {
        let fields = cardinal_encoding::Record::new()
            .with(1, "to what?")
            .with(3, to)
            .with(15, 1u32);
        SpaceOp::create(cardinal_space::NodeKind::Uint(2), c, "m", fields)
    };
    let before = said(&p.a).len();
    for not_an_id in [
        cardinal_encoding::Value::from(0u32),
        cardinal_encoding::Value::from("first"),
        cardinal_encoding::Value::from(m[..15].to_vec()),
        cardinal_encoding::Value::from([&m[..], &[0]].concat()),
    ] {
        p.ana_writes(vec![
            relationship::create_message(c, "first"),
            reply_to(not_an_id),
        ]);
        let last = *p.b.dag().log_order().last().unwrap();
        assert!(p.b.validity().is_valid(&last) && !p.b.state().is_accepted(&last));
        assert_eq!(said(&p.b).len(), before);
    }
    // The root is only ever a parent: a reply to it names it otherwise,
    // and is not taken (`state.md#nodes`). Nor is an edit that turns a
    // reply into one.
    p.ana_writes(vec![relationship::create_reply(
        c,
        "to the root",
        Some(cardinal_space::ROOT),
    )]);
    let last = *p.b.dag().log_order().last().unwrap();
    assert!(p.b.validity().is_valid(&last) && !p.b.state().is_accepted(&last));
    let back = said(&p.a)[1].id;
    let root = cardinal_encoding::Value::from(cardinal_space::ROOT);
    p.bo_writes(vec![SpaceOp::set(back, 3, Some(root))]);
    let last = *p.a.dag().log_order().last().unwrap();
    assert!(!p.a.state().is_accepted(&last));
    assert_eq!(said(&p.a).len(), 2);
    assert_eq!(said(&p.a)[1].reply_to, Some(m));
}

/// Carol introduces someone to Bo in their space. Bo may answer it, with an
/// invitation, or say no; who is introduced, and by whom, are Carol's alone.
/// Written over by Bo, it is no introduction of anyone's
/// (`contact.md#introductions`).
#[test]
fn an_introduction_says_only_what_its_maker_wrote_of_it() {
    use cardinal_encoding::{Record, Value};
    let mut p = relationship_of(person(51, 0), person(52, 0));
    let (ana, introduced, other) = (p.ana.log.id(), [7u8; 32], [8u8; 32]);
    let make = |name: &str| {
        relationship::create_introduction(&ana, &introduced, name, Some("hi"), None, None)
    };
    p.ana_writes(vec![make("Dee")]);
    let node = relationship::introductions(&p.b)[0].node;
    // Bo tries to make it another's introduction, by someone else.
    p.bo_writes(vec![
        SpaceOp::set(node, 2, Some(Value::from(other))),
        SpaceOp::set(node, 1, Some(Value::from([9u8; 32]))),
    ]);
    let left = relationship::introductions(&p.a);
    assert!(
        left.iter()
            .all(|i| i.introduced == introduced && i.introducer == ana),
        "{left:?}"
    );
    // His answer and his no are his to give.
    p.ana_writes(vec![make("Dee")]);
    let node = relationship::introductions(&p.b)[0].node;
    let invitation = Record::new().with(1, 5u64);
    p.bo_writes(relationship::answer_introduction(
        node,
        invitation.clone(),
        None,
    ));
    let i = &relationship::introductions(&p.a)[0];
    assert_eq!(
        (i.introduced, i.invitation.clone()),
        (introduced, Some(invitation))
    );
    p.bo_writes(vec![relationship::decline_introduction(node)]);
    assert!(relationship::introductions(&p.a)[0].declined);
    // And its maker cannot say no for him.
    let mut q = relationship_of(person(53, 0), person(54, 0));
    q.ana_writes(vec![relationship::create_introduction(
        &q.ana.log.id(),
        &introduced,
        "Dee",
        None,
        None,
        None,
    )]);
    let node = relationship::introductions(&q.a)[0].node;
    q.ana_writes(vec![relationship::decline_introduction(node)]);
    assert!(!relationship::introductions(&q.b)[0].declined);
}
