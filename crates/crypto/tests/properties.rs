//! Property tests for the crypto suite's reversible operations.

use cardinal_crypto::aead::{
    chacha20poly1305_decrypt, chacha20poly1305_encrypt, xchacha20poly1305_decrypt,
    xchacha20poly1305_encrypt,
};
use cardinal_crypto::bip39::{entropy_to_words, words_to_entropy};
use cardinal_crypto::{derive, derive_parts, Purpose, RecoveryPhrase};
use proptest::prelude::*;

proptest! {
    #[test]
    fn bip39_round_trip(entropy in any::<[u8; 32]>()) {
        let words = entropy_to_words(&entropy).join(" ");
        prop_assert_eq!(*words_to_entropy(&words).unwrap(), entropy);
        prop_assert_eq!(&*RecoveryPhrase::from_entropy(&entropy).to_words(), &words);
    }

    #[test]
    fn aead_round_trip(key in any::<[u8; 32]>(), n12 in any::<[u8; 12]>(), n24 in any::<[u8; 24]>(),
                       aad in proptest::collection::vec(any::<u8>(), 0..64),
                       pt in proptest::collection::vec(any::<u8>(), 0..256),
                       flip in any::<prop::sample::Index>()) {
        let c = chacha20poly1305_encrypt(&key, &n12, &aad, &pt);
        prop_assert_eq!(chacha20poly1305_decrypt(&key, &n12, &aad, &c).unwrap(), pt.clone());
        let mut x = xchacha20poly1305_encrypt(&key, &n24, &aad, &pt);
        prop_assert_eq!(xchacha20poly1305_decrypt(&key, &n24, &aad, &x).unwrap(), pt);
        let i = flip.index(x.len());
        x[i] ^= 0x40;
        prop_assert!(xchacha20poly1305_decrypt(&key, &n24, &aad, &x).is_err());
    }

    #[test]
    fn derive_parts_is_concatenation(a in proptest::collection::vec(any::<u8>(), 0..80),
                                     b in proptest::collection::vec(any::<u8>(), 0..80)) {
        let joined = [a.clone(), b.clone()].concat();
        prop_assert_eq!(*derive_parts(Purpose::Pair, &[&a, &b]), *derive(Purpose::Pair, &joined));
    }
}

#[test]
fn seal_round_trip_many_sizes() {
    let kp = cardinal_crypto::HybridKeyPair::generate();
    for n in [0usize, 1, 15, 16, 17, 1000, 70_000] {
        let pt = vec![0xa5u8; n];
        let s = cardinal_crypto::seal(kp.public_key(), &pt, b"ctx");
        let decoded = cardinal_crypto::Sealed::decode(&s.encode()).unwrap();
        assert_eq!(
            &cardinal_crypto::open(&kp, &decoded, b"ctx").unwrap()[..],
            &pt[..]
        );
    }
}
