//! Ed25519 signing (RFC 8032) and ZIP-215 verification
//! (`crypto.md#signature-verification`).
//!
//! Both use `ed25519-zebra` (Zcash Foundation), whose verification
//! implements exactly the ZIP-215 rules the specification requires: `S`
//! must be canonical (less than the group order), encodings of `A` and `R`
//! need not be canonical, and the cofactored equation
//! `[8][S]B = [8]R + [8][k]A` decides. Its signing is standard RFC 8032, so
//! signatures it produces are canonical and verify under any library.
//!
//! One departure from ZIP-215: a public key of small order signs nothing.
//! For such a key the equation holds whatever was signed, so anyone could
//! sign as it.

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

    /// Signs `msg` with a nonce drawn from `salt` instead of the one RFC
    /// 8032 derives: another valid signature by this key over the same
    /// message, with other bytes. A key's holder can always do this, and
    /// nobody else can. Tests use it to make an entry's second signed form.
    #[cfg(any(test, feature = "test-rng"))]
    pub fn sign_salted(&self, msg: &[u8], salt: &[u8; 32]) -> [u8; 64] {
        use curve25519_dalek::edwards::EdwardsPoint;
        use curve25519_dalek::scalar::Scalar;
        use sha2::{Digest, Sha512};
        let wide = |parts: &[&[u8]]| {
            let mut h = Sha512::new();
            for p in parts {
                h.update(p);
            }
            let mut out = [0u8; 64];
            out.copy_from_slice(&h.finalize());
            out
        };
        let expanded = wide(&[&self.seed()[..]]);
        let mut a = [0u8; 32];
        a.copy_from_slice(&expanded[..32]);
        a[0] &= 248;
        a[31] &= 127;
        a[31] |= 64;
        let a = Scalar::from_bytes_mod_order(a);
        let r = Scalar::from_bytes_mod_order_wide(&wide(&[salt, &expanded[32..], msg]));
        let big_r = EdwardsPoint::mul_base(&r).compress().to_bytes();
        let k = Scalar::from_bytes_mod_order_wide(&wide(&[&big_r, &self.public_key(), msg]));
        let s = r + k * a;
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&big_r);
        sig[32..].copy_from_slice(s.as_bytes());
        sig
    }

    /// Signs a signed object as its one signer
    /// (`encoding.md#signed-objects`), replacing whatever signatures it
    /// bore. The object's id covers the signing key, so the same body
    /// signed by another key is another object.
    pub fn sign_object(&self, obj: &mut SignedObject) {
        sign_object(obj, &[self]);
    }
}

/// Signs a signed object by every one of `keys`, replacing whatever
/// signatures it bore. Each signs the id that names them all, so a signer
/// cannot be added later without the others signing again.
pub fn sign_object(obj: &mut SignedObject, keys: &[&SigningKey]) {
    let public: Vec<[u8; 32]> = keys.iter().map(|k| k.public_key()).collect();
    obj.sign_with(&public, |key, message| {
        let signer = keys.iter().find(|k| k.public_key() == *key);
        signer.expect("one of the keys given").sign(message)
    });
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

/// Whether `public_key` decodes, as ZIP-215 decodes it, to a point of small
/// order: one of the eight that eight times over is nothing.
pub fn is_small_order(public_key: &[u8; 32]) -> bool {
    let point = curve25519_dalek::edwards::CompressedEdwardsY(*public_key).decompress();
    point.is_some_and(|p| p.is_small_order())
}

/// Verifies an Ed25519 signature under ZIP-215 rules, with the one
/// departure the specification makes: a public key of small order signs
/// nothing.
pub fn verify(public_key: &[u8; 32], msg: &[u8], signature: &[u8; 64]) -> Result<(), Error> {
    if is_small_order(public_key) {
        return Err(Error::BadSignature);
    }
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
        sign_object(&mut obj, &[&b, &a]);
        assert_eq!(obj.signatures().len(), 2);
        verify_object(&obj).unwrap();
        let back = SignedObject::decode(&obj.encode()).unwrap();
        verify_object(&back).unwrap();

        let mut forged = obj.clone();
        let mut s = forged.signatures()[0].clone();
        s.signature[0] ^= 1;
        forged.add_signature(s);
        assert_eq!(verify_object(&forged), Err(Error::BadSignature));

        // An id says who signed. The same body signed by one of them alone
        // is another object, and a signature made for it does not pass for
        // one over the object both signed.
        let mut alone = SignedObject::new(Record::new().with(0, 2u32).with(1, "x"));
        a.sign_object(&mut alone);
        verify_object(&alone).unwrap();
        assert_ne!(alone.id(), obj.id());
        let mut passed_off = obj.clone();
        passed_off.add_signature(alone.signatures()[0].clone());
        assert_eq!(verify_object(&passed_off), Err(Error::BadSignature));
        // Nobody adds their signature to someone's object: the id it would
        // have is one its author never signed.
        let mut joined = alone.clone();
        let theirs = b.sign(&joined.signing_message());
        joined.add_signature(ObjectSignature::new(b.public_key(), theirs));
        assert_ne!(joined.id(), alone.id());
        assert_eq!(verify_object(&joined), Err(Error::BadSignature));
        // Signed again by its one signer, it is the same object.
        let id = alone.id();
        a.sign_object(&mut alone);
        assert_eq!(alone.id(), id);
    }

    #[test]
    fn a_key_of_small_order_signs_nothing() {
        // For a key of small order the cofactored equation holds whatever
        // was signed: R the identity and S = 0 pass for any message under
        // ZIP-215 alone.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let mut sig = [0u8; 64];
        sig[0] = 1;
        assert!(is_small_order(&identity));
        let zip215 = ed25519_zebra::VerificationKey::try_from(identity).unwrap();
        for msg in [&b"anything"[..], b"anything else"] {
            zip215
                .verify(&ed25519_zebra::Signature::from(sig), msg)
                .unwrap();
            assert_eq!(verify(&identity, msg, &sig), Err(Error::BadSignature));
        }
        // an ordinary key is not of small order
        assert!(!is_small_order(
            &SigningKey::from_seed(&[1; 32]).public_key()
        ));
    }

    #[test]
    fn a_keys_holder_can_sign_one_message_twice() {
        let k = SigningKey::from_seed(&[5; 32]);
        let plain = k.sign(b"m");
        let again = k.sign_salted(b"m", &[1; 32]);
        let third = k.sign_salted(b"m", &[2; 32]);
        assert!(plain != again && again != third);
        for sig in [plain, again, third] {
            verify(&k.public_key(), b"m", &sig).unwrap();
        }
        assert!(verify(&k.public_key(), b"n", &again).is_err());
    }
}
