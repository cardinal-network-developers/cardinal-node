//! Review tests: what a read marker can be made to say.

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

fn read_count(space: &Space, who: &[u8; 32], said: &[relationship::Message]) -> usize {
    let read = relationship::read_by(space, who, said);
    read.into_iter().filter(|r| *r).count()
}

/// `contacts::conversations`, for one person.
fn unread(space: &Space, me: &[u8; 32]) -> usize {
    let said = relationship::messages(space);
    let read = relationship::read_by(space, me, &said);
    let both = said.iter().zip(read);
    both.filter(|(m, read)| m.author != *me && !read).count()
}

/// Negative control: the marker itself cannot be touched.
#[test]
fn a_contact_cannot_touch_someone_elses_marker() {
    let mut p = relationship_of(person(21, 0), person(22, 0));
    let c = p.c;
    p.bo_writes(vec![relationship::create_message(c, "one")]);
    p.bo_writes(vec![relationship::create_message(c, "two")]);
    let all = relationship::messages(&p.a);
    let last = all[1].id;
    let first = all[0].id;
    let me = p.ana.log.id();
    p.ana_writes(vec![relationship::create_read_marker(c, last)]);
    assert_eq!(read_count(&p.b, &me, &all), 2);
    let marker = relationship::read_marker(&p.b, &me).unwrap();

    // Bo moves Ana's marker back, then deletes it, then restores it.
    p.bo_writes(vec![relationship::set_read_marker(marker, first)]);
    p.bo_writes(vec![SpaceOp::delete(marker)]);
    assert_eq!(read_count(&p.a, &me, &all), 2);
    assert_eq!(read_count(&p.b, &me, &all), 2);

    // Bo's own marker does not count as Ana's.
    p.bo_writes(vec![relationship::create_read_marker(c, first)]);
    assert_eq!(read_count(&p.a, &me, &all), 2);
}

/// Deleting the message a marker stands on takes the whole marker away: the
/// person who read it sees everything unread again.
#[test]
fn deleting_a_message_leaves_the_other_persons_marker() {
    let mut p = relationship_of(person(23, 0), person(24, 0));
    let c = p.c;
    for t in ["one", "two", "three"] {
        p.bo_writes(vec![relationship::create_message(c, t)]);
    }
    let all = relationship::messages(&p.a);
    let last = all[2].id;
    let me = p.ana.log.id();
    p.ana_writes(vec![relationship::create_read_marker(c, last)]);
    assert_eq!(unread(&p.a, &me), 0);

    // Bo takes back the last thing Bo said.
    p.bo_writes(vec![SpaceOp::delete(last)]);
    let left = relationship::messages(&p.a);
    assert_eq!(left.len(), 2);
    eprintln!(
        "MEASURE after a delete: ana read_up_to {} of {}, unread {}",
        read_count(&p.a, &me, &left),
        left.len(),
        unread(&p.a, &me)
    );
    assert_eq!(
        unread(&p.a, &me),
        0,
        "ana read everything, and has done nothing since"
    );
}

/// Bo has two devices apart. What the second wrote may sort before the
/// message Ana's marker stands on, and then it is read without being seen.
#[test]
fn a_message_ana_has_not_seen_is_not_read_already() {
    let mut p = relationship_of(person(25, 1), person(26, 1));
    let c = p.c;
    p.bo_writes(vec![relationship::create_message(c, "from the laptop")]);
    let all = relationship::messages(&p.a);
    let written = all[0].entry;
    let at = all[0].id;
    let me = p.ana.log.id();
    p.ana_writes(vec![relationship::create_read_marker(c, at)]);
    assert_eq!(unread(&p.a, &me), 0);

    // The phone had not heard of the laptop's message. Half the time its
    // entry's id puts it first.
    let mut hidden = 0;
    let mut apart = vec![written];
    for n in 0..24 {
        let text = format!("from the phone {n}");
        let (id, s) =
            p.b.write_concurrent(
                &p.bo.log,
                &p.bo.devices[1].signing,
                &apart,
                vec![relationship::create_message(c, &text)],
                Some(2),
            )
            .unwrap();
        apart.push(id);
        let before = unread(&p.a, &me);
        p.a.receive(s, &[&p.ana.enc]).unwrap();
        p.eval();
        if unread(&p.a, &me) == before {
            hidden += 1;
        }
    }
    let said = relationship::messages(&p.a);
    assert_eq!(said.len(), 25);
    eprintln!(
        "MEASURE {hidden} of 24 new messages never counted as unread; ana's unread is {}",
        unread(&p.a, &me)
    );
    assert_eq!(hidden, 0, "a message arrived and was already read");
}

/// Ana's two devices each move her marker while apart, one further than the
/// other. Whichever `set` is last in log order wins, not the furthest.
#[test]
fn two_devices_cannot_move_a_marker_backwards() {
    let mut p = relationship_of(person(29, 1), person(30, 0));
    let c = p.c;
    for t in ["one", "two", "three", "four"] {
        p.bo_writes(vec![relationship::create_message(c, t)]);
    }
    let all = relationship::messages(&p.a);
    let me = p.ana.log.id();
    p.ana_writes(vec![relationship::create_read_marker(c, all[0].id)]);
    let marker = relationship::read_marker(&p.a, &me).unwrap();
    let mut backwards = 0;
    for round in 0..16 {
        // The laptop has read everything.
        let laptop =
            p.a.write(
                &p.ana.log,
                &p.ana.devices[0].signing,
                vec![relationship::set_read_marker(marker, all[3].id)],
                Some(10 + round),
            )
            .unwrap();
        let _ = laptop;
        let head = *p.a.dag().log_order().last().unwrap();
        // The phone, apart from it, has read only the second.
        let (_, _) =
            p.a.write_concurrent(
                &p.ana.log,
                &p.ana.devices[1].signing,
                &[head],
                vec![relationship::set_read_marker(marker, all[1].id)],
                Some(10 + round),
            )
            .unwrap();
        p.eval();
        let read = read_count(&p.a, &me, &all);
        if read < 4 {
            backwards += 1;
        }
        // Next round starts from everything read, by a later entry.
        p.a.write(
            &p.ana.log,
            &p.ana.devices[0].signing,
            vec![relationship::set_read_marker(marker, all[3].id)],
            Some(30 + round),
        )
        .unwrap();
        p.eval();
    }
    eprintln!("MEASURE the marker went back in {backwards} of 16 merges");
    assert_eq!(backwards, 0, "a device read everything, and it is unread");
}

/// What the read position costs when a contact writes many markers.
#[test]
#[ignore]
fn cost_of_many_markers() {
    let mut p = relationship_of(person(27, 0), person(28, 0));
    let c = p.c;
    let (n, k) = (20_000usize, 20_000usize);
    let mut bytes = 0;
    for chunk in (0..n).collect::<Vec<_>>().chunks(200) {
        let ops: Vec<SpaceOp> = chunk
            .iter()
            .map(|i| relationship::create_message(c, &format!("m{i}")))
            .collect();
        let s =
            p.b.write(&p.bo.log, &p.bo.devices[0].signing, ops, Some(1))
                .unwrap();
        bytes += s.encode().len();
        p.a.receive(s, &[&p.ana.enc]).unwrap();
    }
    let all = relationship::messages(&p.b);
    assert_eq!(all.len(), n);
    let last = all.last().unwrap().id;
    for chunk in (0..k).collect::<Vec<_>>().chunks(200) {
        let ops: Vec<SpaceOp> = chunk
            .iter()
            .map(|_| relationship::create_read_marker(c, last))
            .collect();
        let s =
            p.b.write(&p.bo.log, &p.bo.devices[0].signing, ops, Some(1))
                .unwrap();
        bytes += s.encode().len();
        p.a.receive(s, &[&p.ana.enc]).unwrap();
    }
    eprintln!("MEASURE {} bytes of entries", bytes);
    let them = p.bo.log.id();
    let start = std::time::Instant::now();
    let all = relationship::messages(&p.a);
    let messages_took = start.elapsed();
    let start = std::time::Instant::now();
    let read = read_count(&p.a, &them, &all);
    eprintln!(
        "MEASURE {n} messages, {k} markers: messages() {messages_took:?}, read_up_to() {:?} -> {read}",
        start.elapsed()
    );
}
