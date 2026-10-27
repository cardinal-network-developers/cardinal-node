//! X25519 (RFC 7748), via `x25519-dalek`.
//!
//! [`X25519Secret::diffie_hellman`] returns the raw shared secret and does
//! not reject low-order peer keys (which yield all zeros); every use in the
//! specification mixes the result into a hash together with other secrets,
//! and callers that need contributory behaviour can check
//! [`is_all_zero`].

use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::random::random_bytes;

/// An X25519 private key, zeroized on drop.
pub struct X25519Secret(StaticSecret);

impl X25519Secret {
    /// A new key from the operating system's random source.
    pub fn generate() -> X25519Secret {
        X25519Secret::from_bytes(&Zeroizing::new(random_bytes::<32>()))
    }

    /// The key with these private bytes (clamped when used, per RFC 7748).
    pub fn from_bytes(bytes: &[u8; 32]) -> X25519Secret {
        X25519Secret(StaticSecret::from(*bytes))
    }

    /// The private bytes, for storage.
    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    /// The public key.
    pub fn public_key(&self) -> [u8; 32] {
        PublicKey::from(&self.0).to_bytes()
    }

    /// `X25519(self, peer)`.
    pub fn diffie_hellman(&self, peer: &[u8; 32]) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.diffie_hellman(&PublicKey::from(*peer)).to_bytes())
    }
}

impl std::fmt::Debug for X25519Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("X25519Secret(..)")
    }
}

/// Whether a shared secret is all zeros (the peer key had low order).
pub fn is_all_zero(shared: &[u8; 32]) -> bool {
    crate::ct_eq(shared, &[0u8; 32])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    /// RFC 7748 section 6.1.
    #[test]
    fn rfc7748_vector() {
        let a = X25519Secret::from_bytes(&h(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        ));
        let b = X25519Secret::from_bytes(&h(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        ));
        assert_eq!(
            a.public_key(),
            h("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
        assert_eq!(
            b.public_key(),
            h("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        );
        let k = h("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(*a.diffie_hellman(&b.public_key()), k);
        assert_eq!(*b.diffie_hellman(&a.public_key()), k);
        assert!(!is_all_zero(&k));
        assert!(is_all_zero(&a.diffie_hellman(&[0; 32])));
    }
}
