//! ML-KEM-768 (FIPS 203), via RustCrypto `ml-kem`.
//!
//! Decapsulation keys are kept in their 64-byte seed form `d || z`.

use ml_kem::array::Array;
use ml_kem::{Decapsulate, KeyExport, MlKem768};
use zeroize::Zeroizing;

use crate::random::random_bytes;
use crate::Error;

/// Length of an ML-KEM-768 encapsulation key.
pub const PUBLIC_KEY_LEN: usize = 1184;
/// Length of an ML-KEM-768 ciphertext.
pub const CIPHERTEXT_LEN: usize = 1088;
/// Length of an ML-KEM key-generation seed `d || z`.
pub const SEED_LEN: usize = 64;

type Ek = ml_kem::EncapsulationKey<MlKem768>;
type Dk = ml_kem::DecapsulationKey<MlKem768>;

/// An ML-KEM-768 encapsulation (public) key.
#[derive(Clone, PartialEq, Eq)]
pub struct KemPublicKey {
    key: Ek,
    bytes: Box<[u8; PUBLIC_KEY_LEN]>,
}

impl KemPublicKey {
    /// Parses an encapsulation key, applying the FIPS 203 input check.
    pub fn from_bytes(bytes: &[u8]) -> Result<KemPublicKey, Error> {
        let arr: [u8; PUBLIC_KEY_LEN] = bytes
            .try_into()
            .map_err(|_| Error::InvalidKey("ML-KEM-768 encapsulation key length"))?;
        let key = Ek::new(&Array::from(arr))
            .map_err(|_| Error::InvalidKey("ML-KEM-768 encapsulation key"))?;
        Ok(KemPublicKey {
            key,
            bytes: Box::new(arr),
        })
    }

    fn from_key(key: Ek) -> KemPublicKey {
        let bytes: [u8; PUBLIC_KEY_LEN] = key.to_bytes().into();
        KemPublicKey {
            key,
            bytes: Box::new(bytes),
        }
    }

    /// The 1184-byte encoding.
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.bytes
    }

    /// Encapsulates a fresh shared secret: `(ciphertext, shared secret)`.
    pub fn encapsulate(&self) -> ([u8; CIPHERTEXT_LEN], Zeroizing<[u8; 32]>) {
        let m = Zeroizing::new(random_bytes::<32>());
        self.encapsulate_with_randomness(&m)
    }

    /// Encapsulation with caller-chosen randomness `m`
    /// (`ML-KEM.Encaps_internal`). For reproducible test vectors only.
    #[cfg(any(test, feature = "test-rng"))]
    pub fn encapsulate_deterministic(
        &self,
        m: &[u8; 32],
    ) -> ([u8; CIPHERTEXT_LEN], Zeroizing<[u8; 32]>) {
        self.encapsulate_with_randomness(m)
    }

    pub(crate) fn encapsulate_with_randomness(
        &self,
        m: &[u8; 32],
    ) -> ([u8; CIPHERTEXT_LEN], Zeroizing<[u8; 32]>) {
        let (ct, ss) = self.key.encapsulate_deterministic(&Array::from(*m));
        (ct.into(), Zeroizing::new(ss.into()))
    }
}

impl std::fmt::Debug for KemPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "KemPublicKey({:02x}{:02x}{:02x}{:02x}..)",
            self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3]
        )
    }
}

/// An ML-KEM-768 decapsulation key, zeroized on drop.
pub struct KemSecretKey {
    key: Dk,
    seed: Zeroizing<[u8; SEED_LEN]>,
    public: KemPublicKey,
}

impl KemSecretKey {
    /// A new key from the operating system's random source.
    pub fn generate() -> KemSecretKey {
        KemSecretKey::from_seed(&Zeroizing::new(random_bytes::<SEED_LEN>()))
    }

    /// The key generated from seed `d || z` (`ML-KEM.KeyGen_internal`).
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> KemSecretKey {
        let key = Dk::from_seed(Array::from(*seed));
        let public = KemPublicKey::from_key(key.encapsulation_key().clone());
        KemSecretKey {
            key,
            seed: Zeroizing::new(*seed),
            public,
        }
    }

    /// The seed `d || z`, for storage.
    pub fn seed(&self) -> &[u8; SEED_LEN] {
        &self.seed
    }

    /// The encapsulation key.
    pub fn public_key(&self) -> &KemPublicKey {
        &self.public
    }

    /// Decapsulates a ciphertext. An ML-KEM ciphertext of the right length
    /// always yields a secret (implicit rejection); a wrong one yields an
    /// unrelated secret, which the AEAD that follows then rejects.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Zeroizing<[u8; 32]>, Error> {
        let ct: [u8; CIPHERTEXT_LEN] = ciphertext
            .try_into()
            .map_err(|_| Error::InvalidKey("ML-KEM-768 ciphertext length"))?;
        let ss = self.key.decapsulate(&Array::from(ct));
        Ok(Zeroizing::new(ss.into()))
    }
}

impl std::fmt::Debug for KemSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KemSecretKey")
            .field("public", &self.public)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let sk = KemSecretKey::generate();
        let (ct, ss) = sk.public_key().encapsulate();
        assert_eq!(*sk.decapsulate(&ct).unwrap(), *ss);
        let mut bad = ct;
        bad[5] ^= 1;
        assert_ne!(*sk.decapsulate(&bad).unwrap(), *ss);
        assert!(sk.decapsulate(&ct[..100]).is_err());
    }

    #[test]
    fn seeded_is_deterministic() {
        let a = KemSecretKey::from_seed(&[3; 64]);
        let b = KemSecretKey::from_seed(&[3; 64]);
        assert_eq!(a.public_key(), b.public_key());
        let parsed = KemPublicKey::from_bytes(a.public_key().as_bytes()).unwrap();
        assert_eq!(&parsed, a.public_key());
        let (c1, s1) = a.public_key().encapsulate_deterministic(&[9; 32]);
        let (c2, s2) = b.public_key().encapsulate_deterministic(&[9; 32]);
        assert_eq!(c1, c2);
        assert_eq!(*s1, *s2);
    }

    #[test]
    fn rejects_bad_public_keys() {
        assert!(KemPublicKey::from_bytes(&[0; 100]).is_err());
        // Coefficients >= q fail the FIPS 203 modulus check.
        assert!(KemPublicKey::from_bytes(&[0xff; PUBLIC_KEY_LEN]).is_err());
    }

    /// Accumulated known-answer test for final FIPS 203, as in Go's
    /// `crypto/mlkem` `TestAccumulated`: a SHAKE-128 stream supplies each
    /// seed `d || z`, message `m`, and a random (invalid) ciphertext; `ek`,
    /// `ct`, `k`, and the implicit-rejection key are absorbed into a second
    /// SHAKE-128 whose first 32 bytes are compared.
    fn accumulated(n: usize) -> String {
        use shake::{ExtendableOutput, Shake128, Update, XofReader};

        let mut rng = Shake128::default().finalize_xof();
        let mut acc = Shake128::default();
        for _ in 0..n {
            let mut seed = [0u8; 64];
            rng.read(&mut seed);
            let sk = KemSecretKey::from_seed(&seed);
            acc.update(sk.public_key().as_bytes());
            let mut m = [0u8; 32];
            rng.read(&mut m);
            let (ct, k) = sk.public_key().encapsulate_deterministic(&m);
            acc.update(&ct);
            acc.update(&k[..]);
            assert_eq!(*sk.decapsulate(&ct).unwrap(), *k);
            let mut bad = [0u8; CIPHERTEXT_LEN];
            rng.read(&mut bad);
            acc.update(&sk.decapsulate(&bad).unwrap()[..]);
        }
        let mut out = [0u8; 32];
        acc.finalize_xof().read(&mut out);
        hex::encode(out)
    }

    #[test]
    fn accumulated_100() {
        assert_eq!(
            accumulated(100),
            "1114b1b6699ed191734fa339376afa7e285c9e6acf6ff0177d346696ce564415"
        );
    }

    #[test]
    #[ignore = "slow; run with --ignored"]
    fn accumulated_10000() {
        assert_eq!(
            accumulated(10_000),
            "8a518cc63da366322a8e7a818c7a0d63483cb3528d34a4cf42f35d5ad73f22fc"
        );
    }
}
