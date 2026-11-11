//! Where a member says they can be reached, when more than one record says so.

use cardinal_crypto::{HybridKeyPair, RecoveryPhrase};
use cardinal_identity::{Created, DeviceKeys, IdentityLog};
use cardinal_space::relationship::{self, Reach};
use cardinal_space::{Policy, Profile, Space};

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

/// Two of Ana's devices wrote at once, and each registered a token. Both
/// tokens stay good: a host maps either one to the space.
#[test]
fn every_reach_node_a_member_wrote_counts() {
    let (ana, ana_enc, ana_dev) = person(31);
    let (bo, bo_enc, _) = person(32);
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
    for token in [1, 2] {
        let op = relationship::create_reach(&ana.id(), &[reach(token)]);
        space
            .write(&ana, &ana_dev.signing, vec![op], Some(1))
            .unwrap();
    }

    let all = relationship::all_reach_of(space.state(), &ana.id());
    let mut tokens: Vec<u8> = all.iter().map(|r| r.token[0]).collect();
    tokens.sort();
    assert_eq!(tokens, [1, 2]);
    let (_, one) = relationship::reach_of(space.state(), &ana.id()).unwrap();
    assert_eq!(one.len(), 1, "one node, as before");
    assert!(relationship::all_reach_of(space.state(), &bo.id()).is_empty());
}
