//! Sealing to a hybrid public key (`crypto.md#sealing`).

use cardinal_encoding::{Record, SchemaError};
use zeroize::Zeroizing;

use crate::aead::{chacha20poly1305_decrypt, chacha20poly1305_encrypt};
use crate::derive::{derive_parts, Purpose};
use crate::hybrid::{HybridKeyPair, HybridPublicKey};
use crate::kem::CIPHERTEXT_LEN;
use crate::random::random_bytes;
use crate::x25519::X25519Secret;
use crate::Error;

/// A sealed record `{1: E, 2: ML-KEM ciphertext, 3: AEAD ciphertext}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sealed {
    /// The ephemeral X25519 public key `E`.
    pub ephemeral: [u8; 32],
    /// The ML-KEM-768 ciphertext.
    pub kem_ciphertext: Box<[u8; CIPHERTEXT_LEN]>,
    /// The ChaCha20-Poly1305 ciphertext with its tag.
    pub ciphertext: Vec<u8>,
}

impl Sealed {
    /// The record form.
    pub fn to_record(&self) -> Record {
        Record::new()
            .with(1, self.ephemeral)
            .with(2, self.kem_ciphertext.to_vec())
            .with(3, self.ciphertext.clone())
    }

    /// Reads the record form.
    pub fn from_record(r: &Record) -> Result<Sealed, Error> {
        let ephemeral = r.bytes_n::<32>(1)?;
        let ct = r.bytes(2)?;
        let kem_ciphertext: [u8; CIPHERTEXT_LEN] =
            ct.try_into().map_err(|_| SchemaError::WrongLength {
                key: 2,
                expected: CIPHERTEXT_LEN,
                found: ct.len(),
            })?;
        let ciphertext = r.bytes(3)?.to_vec();
        Ok(Sealed {
            ephemeral,
            kem_ciphertext: Box::new(kem_ciphertext),
            ciphertext,
        })
    }

    /// The canonical encoding.
    pub fn encode(&self) -> Vec<u8> {
        self.to_record().encode()
    }

    /// Decodes a sealed record.
    pub fn decode(bytes: &[u8]) -> Result<Sealed, Error> {
        Sealed::from_record(&Record::decode(bytes)?)
    }
}

fn seal_key(
    ss_kem: &[u8; 32],
    ss_dh: &[u8; 32],
    ephemeral: &[u8; 32],
    kem_ct: &[u8; CIPHERTEXT_LEN],
    recipient: &HybridPublicKey,
    context: &[u8],
) -> Zeroizing<[u8; 32]> {
    let fingerprint = recipient.fingerprint();
    let context_hash = crate::hash(context);
    derive_parts(
        Purpose::Seal,
        &[
            ss_kem,
            ss_dh,
            ephemeral,
            kem_ct,
            &fingerprint,
            &context_hash,
        ],
    )
}

/// `seal(recipient, plaintext, context)`: encrypts `plaintext` so only the
/// holder of `recipient`'s private key can read it, bound to `context`.
pub fn seal(recipient: &HybridPublicKey, plaintext: &[u8], context: &[u8]) -> Sealed {
    let e = Zeroizing::new(random_bytes::<32>());
    let m = Zeroizing::new(random_bytes::<32>());
    seal_with(recipient, plaintext, context, &e, &m)
}

/// [`seal`] with caller-chosen randomness: the ephemeral X25519 private key
/// and the ML-KEM encapsulation randomness `m`. For reproducible test
/// vectors only.
#[cfg(any(test, feature = "test-rng"))]
pub fn seal_deterministic(
    recipient: &HybridPublicKey,
    plaintext: &[u8],
    context: &[u8],
    ephemeral_secret: &[u8; 32],
    kem_randomness: &[u8; 32],
) -> Sealed {
    seal_with(
        recipient,
        plaintext,
        context,
        ephemeral_secret,
        kem_randomness,
    )
}

fn seal_with(
    recipient: &HybridPublicKey,
    plaintext: &[u8],
    context: &[u8],
    ephemeral_secret: &[u8; 32],
    kem_randomness: &[u8; 32],
) -> Sealed {
    let e = X25519Secret::from_bytes(ephemeral_secret);
    let ephemeral = e.public_key();
    let (kem_ct, ss_kem) = recipient.kem().encapsulate_with_randomness(kem_randomness);
    let ss_dh = e.diffie_hellman(recipient.x25519());
    let k = seal_key(&ss_kem, &ss_dh, &ephemeral, &kem_ct, recipient, context);
    let ciphertext = chacha20poly1305_encrypt(&k, &[0u8; 12], context, plaintext);
    Sealed {
        ephemeral,
        kem_ciphertext: Box::new(kem_ct),
        ciphertext,
    }
}

/// Opens a sealed record. Fails with [`Error::Decrypt`] if it was sealed to
/// another key or another context, or was modified.
pub fn open(
    recipient: &HybridKeyPair,
    sealed: &Sealed,
    context: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let ss_kem = recipient.kem().decapsulate(&sealed.kem_ciphertext[..])?;
    let ss_dh = recipient.x25519().diffie_hellman(&sealed.ephemeral);
    let k = seal_key(
        &ss_kem,
        &ss_dh,
        &sealed.ephemeral,
        &sealed.kem_ciphertext,
        recipient.public_key(),
        context,
    );
    chacha20poly1305_decrypt(&k, &[0u8; 12], context, &sealed.ciphertext).map(Zeroizing::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let kp = HybridKeyPair::generate();
        let sealed = seal(kp.public_key(), b"secret", b"ctx");
        assert_eq!(sealed.ciphertext.len(), 6 + 16);
        let back = Sealed::decode(&sealed.encode()).unwrap();
        assert_eq!(&open(&kp, &back, b"ctx").unwrap()[..], b"secret");
        // Overhead as the specification states, plus headers.
        assert_eq!(
            sealed.encode().len(),
            1 + (1 + 2 + 32) + (1 + 2 + 1088) + (1 + 2 + 6 + 16)
        );
    }

    #[test]
    fn wrong_recipient_context_or_tamper() {
        let kp = HybridKeyPair::generate();
        let other = HybridKeyPair::generate();
        let sealed = seal(kp.public_key(), b"secret", b"ctx");
        assert_eq!(open(&other, &sealed, b"ctx"), Err(Error::Decrypt));
        assert_eq!(open(&kp, &sealed, b"other"), Err(Error::Decrypt));
        let mut t = sealed.clone();
        t.kem_ciphertext[0] ^= 1;
        assert_eq!(open(&kp, &t, b"ctx"), Err(Error::Decrypt));
        let mut t = sealed.clone();
        t.ephemeral[0] ^= 1;
        assert_eq!(open(&kp, &t, b"ctx"), Err(Error::Decrypt));
        let mut t = sealed;
        t.ciphertext[0] ^= 1;
        assert_eq!(open(&kp, &t, b"ctx"), Err(Error::Decrypt));
    }

    #[test]
    fn deterministic() {
        let kp = HybridKeyPair::from_seed(b"r");
        let a = seal_deterministic(kp.public_key(), b"p", b"c", &[1; 32], &[2; 32]);
        let b = seal_deterministic(kp.public_key(), b"p", b"c", &[1; 32], &[2; 32]);
        assert_eq!(a, b);
        assert_eq!(&open(&kp, &a, b"c").unwrap()[..], b"p");
    }
}
