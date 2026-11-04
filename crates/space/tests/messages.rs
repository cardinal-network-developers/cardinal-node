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
        relationship::genesis_ops(bo.log.id()),
        None,
    )
    .unwrap();
    a.evaluate_full(&[&ana.log, &bo.log]).unwrap();
    let c = relationship::conversation(&a).unwrap();
    let mut b = Space::open_genesis(&genesis, &[&bo.enc], Some(ana.log.state())).unwrap();
    b.evaluate_full(&[&ana.log, &bo.log]).unwrap();
    Pair { ana, bo, a, b, c }
}

impl Pair {
    fn eval(&mut self) {
        let logs = [&self.ana.log, &self.bo.log];
        self.a.evaluate_full(&logs).unwrap();
        self.b.evaluate_full(&logs).unwrap();
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
}
