//! Hosting a contact (D87, `profiles.md#relationship`): an offer, the
//! devices that serve under it, a yes, and an end, each counting only from
//! whom it may.

use cardinal_crypto::{HybridKeyPair, RecoveryPhrase};
use cardinal_identity::{Created, DeviceKeys, IdentityLog, Power};
use cardinal_space::grant::{Grant, QuotaClass, MAILBOX};
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

#[allow(dead_code)]
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
    #[allow(dead_code)]
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

fn grant(p: &Pair, port: u16) -> Vec<u8> {
    Grant {
        host: p.ana.log.id(),
        served: p.bo.log.id(),
        services: vec![MAILBOX],
        classes: vec![QuotaClass {
            number: 0,
            outstanding: Some(256),
            per_day: Some(256),
            relay_bytes: Some(50_000_000),
        }],
        storage_bytes: Some(0),
        retention_days: None,
        endpoints: vec![
            cardinal_space::grant::Endpoint::parse(&format!("192.0.2.1:{port}")).unwrap(),
        ],
        link_key: HybridKeyPair::from_seed(&[port as u8; 32])
            .public_key()
            .clone(),
    }
    .sign(&p.ana.devices[0].signing)
}

#[test]
fn an_offer_counts_only_from_whom_it_may() {
    let mut p = relationship_of(person(71, 0), person(72, 0));
    let (g1, g2) = (grant(&p, 1), grant(&p, 2));
    p.ana_writes(relationship::create_host_offer(&[g1.clone()]));
    let h = relationship::hostings(&p.b);
    assert_eq!(h.len(), 1);
    assert_eq!(h[0].host, p.ana.log.id());
    assert!(!h[0].accepted && !h[0].ended);
    let offer = h[0].offer;

    // Ana's own yes is none; a device Bo puts under her offer serves nobody.
    p.ana_writes(vec![relationship::create_host_accept(offer)]);
    p.bo_writes(vec![relationship::create_host_serving(offer, &g2)]);
    let h = &relationship::hostings(&p.a)[0];
    assert!(!h.accepted);
    assert_eq!(h.serving.len(), 1);

    // Bo's yes counts; Ana adds a device, with no new yes.
    p.bo_writes(vec![relationship::create_host_accept(offer)]);
    p.ana_writes(vec![relationship::create_host_serving(offer, &g2)]);
    for space in [&p.a, &p.b] {
        let h = &relationship::hostings(space)[0];
        assert!(h.accepted && !h.ended);
        assert_eq!(h.serving.len(), 2);
        let opened = Grant::open(&h.serving[0].1).unwrap().0;
        assert_eq!(opened.classes[0].relay_bytes, Some(50_000_000));
    }

    // Either ends it, and nothing undoes that.
    p.bo_writes(vec![relationship::create_host_end(offer)]);
    assert!(relationship::hostings(&p.a)[0].ended);
}
