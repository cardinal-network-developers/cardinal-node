//! Hybrid public keys: X25519 plus ML-KEM-768
//! (`crypto.md#hybrid-public-keys`).

use cardinal_encoding::{Record, SchemaError};
use zeroize::Zeroizing;

use crate::derive::{derive_into, Purpose};
use crate::kem::{KemPublicKey, KemSecretKey, SEED_LEN as KEM_SEED_LEN};
use crate::random::random_bytes;
use crate::x25519::X25519Secret;
use crate::Error;

/// Length of a hybrid key pair's secret material: the X25519 private key
/// followed by the ML-KEM seed `d || z`.
pub const SECRET_LEN: usize = 32 + KEM_SEED_LEN;

/// A hybrid public key, the record `{1: x25519 public, 2: ML-KEM-768
/// encapsulation key}`. Unknown fields of a decoded key are preserved, so
/// its encoding and fingerprint are unchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridPublicKey {
    x25519: [u8; 32],
    kem: KemPublicKey,
    extra: Record,
}

impl HybridPublicKey {
    /// A key from its two parts.
    pub fn new(x25519: [u8; 32], kem: KemPublicKey) -> HybridPublicKey {
        HybridPublicKey {
            x25519,
            kem,
            extra: Record::new(),
        }
    }

    /// The X25519 public key.
    pub fn x25519(&self) -> &[u8; 32] {
        &self.x25519
    }

    /// The ML-KEM-768 encapsulation key.
    pub fn kem(&self) -> &KemPublicKey {
        &self.kem
    }

    /// The record form.
    pub fn to_record(&self) -> Record {
        self.extra
            .clone()
            .with(1, self.x25519)
            .with(2, self.kem.as_bytes().to_vec())
    }

    /// Reads the record form, validating both keys.
    pub fn from_record(r: &Record) -> Result<HybridPublicKey, Error> {
        let x25519 = r.bytes_n::<32>(1)?;
        let kem_bytes = r.bytes(2)?;
        if kem_bytes.len() != crate::kem::PUBLIC_KEY_LEN {
            return Err(SchemaError::WrongLength {
                key: 2,
                expected: crate::kem::PUBLIC_KEY_LEN,
                found: kem_bytes.len(),
            }
            .into());
        }
        let kem = KemPublicKey::from_bytes(kem_bytes)?;
        Ok(HybridPublicKey {
            x25519,
            kem,
            extra: r.without(&[1, 2]),
        })
    }

    /// The canonical encoding of the record.
    pub fn encode(&self) -> Vec<u8> {
        self.to_record().encode()
    }

    /// Decodes and validates a hybrid public key.
    pub fn decode(bytes: &[u8]) -> Result<HybridPublicKey, Error> {
        HybridPublicKey::from_record(&Record::decode(bytes)?)
    }

    /// The fingerprint: `BLAKE3` of the encoding.
    pub fn fingerprint(&self) -> [u8; 32] {
        crate::hash(&self.encode())
    }
}

/// A hybrid key pair. Private parts are zeroized on drop.
pub struct HybridKeyPair {
    x25519: X25519Secret,
    kem: KemSecretKey,
    public: HybridPublicKey,
}

impl HybridKeyPair {
    /// A key pair from fresh randomness.
    pub fn generate() -> HybridKeyPair {
        HybridKeyPair::from_secret_bytes(&Zeroizing::new(random_bytes::<SECRET_LEN>()))
    }

    /// The key pair generated from seed `s`: 96 bytes of
    /// `derive("hybrid key", s)`, the first 32 the X25519 private key and the
    /// next 64 the ML-KEM-768 seed `d || z`.
    pub fn from_seed(seed: &[u8]) -> HybridKeyPair {
        let mut material = Zeroizing::new([0u8; SECRET_LEN]);
        derive_into(Purpose::HybridKey, seed, &mut material[..]);
        HybridKeyPair::from_secret_bytes(&material)
    }

    /// Restores a key pair from [`secret_bytes`](HybridKeyPair::secret_bytes).
    pub fn from_secret_bytes(secret: &[u8; SECRET_LEN]) -> HybridKeyPair {
        let x: [u8; 32] = secret[..32].try_into().expect("32 bytes");
        let x25519 = X25519Secret::from_bytes(&Zeroizing::new(x));
        let kem_seed: Zeroizing<[u8; KEM_SEED_LEN]> =
            Zeroizing::new(secret[32..].try_into().expect("64 bytes"));
        let kem = KemSecretKey::from_seed(&kem_seed);
        let public = HybridPublicKey::new(x25519.public_key(), kem.public_key().clone());
        HybridKeyPair {
            x25519,
            kem,
            public,
        }
    }

    /// The private material, for storage: X25519 private key then ML-KEM
    /// seed.
    pub fn secret_bytes(&self) -> Zeroizing<[u8; SECRET_LEN]> {
        let mut out = Zeroizing::new([0u8; SECRET_LEN]);
        out[..32].copy_from_slice(&self.x25519.to_bytes()[..]);
        out[32..].copy_from_slice(self.kem.seed());
        out
    }

    /// The public key.
    pub fn public_key(&self) -> &HybridPublicKey {
        &self.public
    }

    /// The X25519 private key.
    pub fn x25519(&self) -> &X25519Secret {
        &self.x25519
    }

    /// The ML-KEM-768 decapsulation key.
    pub fn kem(&self) -> &KemSecretKey {
        &self.kem
    }
}

impl std::fmt::Debug for HybridKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridKeyPair")
            .field(
                "fingerprint",
                &crate::hash(&self.public.encode())[..8].to_vec(),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_round_trip() {
        let kp = HybridKeyPair::generate();
        let bytes = kp.public_key().encode();
        // Record header, then key + 2-byte bytes header + body for each field.
        assert_eq!(bytes.len(), 1 + (1 + 2 + 32) + (1 + 2 + 1184));
        let back = HybridPublicKey::decode(&bytes).unwrap();
        assert_eq!(&back, kp.public_key());
        assert_eq!(back.fingerprint(), kp.public_key().fingerprint());
    }

    #[test]
    fn seeded_and_restored() {
        let a = HybridKeyPair::from_seed(b"seed");
        let b = HybridKeyPair::from_seed(b"seed");
        assert_eq!(a.public_key(), b.public_key());
        assert_ne!(
            a.public_key(),
            HybridKeyPair::from_seed(b"other").public_key()
        );
        let c = HybridKeyPair::from_secret_bytes(&a.secret_bytes());
        assert_eq!(c.public_key(), a.public_key());
        let mut expect = [0u8; 96];
        derive_into(Purpose::HybridKey, b"seed", &mut expect);
        assert_eq!(a.secret_bytes()[..], expect[..]);
    }

    #[test]
    fn unknown_fields_kept() {
        let kp = HybridKeyPair::from_seed(b"x");
        let r = kp.public_key().to_record().with(9, "future");
        let k = HybridPublicKey::from_record(&r).unwrap();
        assert_eq!(k.to_record(), r);
        assert_ne!(k.fingerprint(), kp.public_key().fingerprint());
    }

    #[test]
    fn rejects_malformed() {
        let kp = HybridKeyPair::from_seed(b"x");
        let r = kp.public_key().to_record().with(1, [0u8; 31]);
        assert!(HybridPublicKey::from_record(&r).is_err());
        let r = kp.public_key().to_record().with(2, vec![0xffu8; 1184]);
        assert!(HybridPublicKey::from_record(&r).is_err());
        let r = kp.public_key().to_record().with(2, vec![0u8; 1183]);
        assert!(HybridPublicKey::from_record(&r).is_err());
    }
}
