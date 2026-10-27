//! Ed25519 signing (RFC 8032) and ZIP-215 verification
//! (`crypto.md#signature-verification`).
//!
//! Both use `ed25519-zebra` (Zcash Foundation), whose verification
//! implements exactly the ZIP-215 rules the specification requires: `S`
//! must be canonical (less than the group order), encodings of `A` and `R`
//! need not be canonical, and the cofactored equation
//! `[8][S]B = [8]R + [8][k]A` decides. Its signing is standard RFC 8032, so
//! signatures it produces are canonical and verify under any library.

use cardinal_encoding::{ObjectSignature, SignedObject};
use zeroize::{Zeroize, Zeroizing};

use crate::random::random_bytes;
use crate::Error;

/// Length of an Ed25519 public key.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Length of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// An Ed25519 signing key, zeroized on drop.
pub struct SigningKey(ed25519_zebra::SigningKey);

impl SigningKey {
    /// A new key from the operating system's random source.
    pub fn generate() -> SigningKey {
        let seed = Zeroizing::new(random_bytes::<32>());
        SigningKey::from_seed(&seed)
    }

    /// The key whose RFC 8032 secret (seed) is `seed`.
    pub fn from_seed(seed: &[u8; 32]) -> SigningKey {
        SigningKey(ed25519_zebra::SigningKey::from(*seed))
    }

    /// The RFC 8032 secret (seed), for storage.
    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.0.as_bytes())
    }

    /// The public key.
    pub fn public_key(&self) -> [u8; 32] {
        ed25519_zebra::VerificationKeyBytes::from(&self.0).into()
    }

    /// Signs `msg` (pure Ed25519).
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.0.sign(msg).into()
    }

    /// Adds this key's signature to a signed object
    /// (`encoding.md#signed-objects`), replacing any earlier signature by
    /// the same key.
    pub fn sign_object(&self, obj: &mut SignedObject) {
        let sig = self.sign(&obj.signing_message());
        obj.add_signature(ObjectSignature::new(self.public_key(), sig));
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey")
            .field("public", &hex_short(&self.public_key()))
            .finish()
    }
}

fn hex_short(b: &[u8]) -> String {
    b.iter()
        .take(8)
        .map(|x| format!("{x:02x}"))
        .collect::<String>()
        + ".."
}

/// Verifies an Ed25519 signature under ZIP-215 rules.
pub fn verify(public_key: &[u8; 32], msg: &[u8], signature: &[u8; 64]) -> Result<(), Error> {
    let vk =
        ed25519_zebra::VerificationKey::try_from(*public_key).map_err(|_| Error::BadSignature)?;
    vk.verify(&ed25519_zebra::Signature::from(*signature), msg)
        .map_err(|_| Error::BadSignature)
}

/// Verifies one signature of a signed object.
pub fn verify_object_signature(obj: &SignedObject, sig: &ObjectSignature) -> Result<(), Error> {
    verify(&sig.key, &obj.signing_message(), &sig.signature)
}

/// Verifies every signature of a signed object. An object with no
/// signatures passes; whether its signers suffice is for the caller.
pub fn verify_object(obj: &SignedObject) -> Result<(), Error> {
    let msg = obj.signing_message();
    for s in obj.signatures() {
        verify(&s.key, &msg, &s.signature)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cardinal_encoding::Record;

    fn h<const N: usize>(s: &str) -> [u8; N] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    /// RFC 8032 section 7.1, test 1 and test 3.
    #[test]
    fn rfc8032_vectors() {
        let sk = SigningKey::from_seed(&h(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        ));
        assert_eq!(
            sk.public_key(),
            h::<32>("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        );
        let sig = sk.sign(b"");
        assert_eq!(sig, h::<64>("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"));
        verify(&sk.public_key(), b"", &sig).unwrap();

        let sk = SigningKey::from_seed(&h(
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        ));
        assert_eq!(
            sk.public_key(),
            h::<32>("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025")
        );
        let sig = sk.sign(&[0xaf, 0x82]);
        assert_eq!(sig, h::<64>("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"));
    }

    #[test]
    fn rejects_wrong_message_and_key() {
        let sk = SigningKey::generate();
        let sig = sk.sign(b"m");
        assert!(verify(&sk.public_key(), b"m", &sig).is_ok());
        assert_eq!(
            verify(&sk.public_key(), b"n", &sig),
            Err(Error::BadSignature)
        );
        let other = SigningKey::generate();
        assert_eq!(
            verify(&other.public_key(), b"m", &sig),
            Err(Error::BadSignature)
        );
    }

    #[test]
    fn rejects_non_canonical_s() {
        // S + l is the same scalar mod l but MUST be rejected.
        let sk = SigningKey::from_seed(&[1; 32]);
        let mut sig = sk.sign(b"x");
        let l: [u8; 32] = h("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
        let mut carry = 0u16;
        for i in 0..32 {
            let v = u16::from(sig[32 + i]) + u16::from(l[i]) + carry;
            sig[32 + i] = v as u8;
            carry = v >> 8;
        }
        assert_eq!(carry, 0);
        assert_eq!(
            verify(&sk.public_key(), b"x", &sig),
            Err(Error::BadSignature)
        );
    }

    #[test]
    fn signed_objects() {
        let a = SigningKey::from_seed(&[1; 32]);
        let b = SigningKey::from_seed(&[2; 32]);
        let mut obj = SignedObject::new(Record::new().with(0, 2u32).with(1, "x"));
        b.sign_object(&mut obj);
        a.sign_object(&mut obj);
        assert_eq!(obj.signatures().len(), 2);
        verify_object(&obj).unwrap();
        let back = SignedObject::decode(&obj.encode()).unwrap();
        verify_object(&back).unwrap();

        let mut forged = obj.clone();
        let mut s = forged.signatures()[0].clone();
        s.signature[0] ^= 1;
        forged.add_signature(s);
        assert_eq!(verify_object(&forged), Err(Error::BadSignature));
    }
}
