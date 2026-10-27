//! Convergent encryption of chunks and indexes (`blobs.md#encryption`).
//!
//! ```text
//! k  = BLAKE3.keyed_hash(convergence secret, m)
//! c  = ChaCha20-Poly1305(k, nonce = 0, aad = "", m)
//! id = BLAKE3(c)
//! ```

use cardinal_crypto::aead::{chacha20poly1305_decrypt, chacha20poly1305_encrypt};
use cardinal_crypto::{derive, keyed_hash, Purpose};
use zeroize::Zeroizing;

use crate::{object_id, BlobError, Id, Key};

/// The per-epoch convergence secret, `derive("convergence", epoch key)`.
#[derive(Clone)]
pub struct ConvergenceSecret(Zeroizing<[u8; 32]>);

impl ConvergenceSecret {
    /// The convergence secret of an epoch.
    pub fn from_epoch_key(epoch_key: &[u8; 32]) -> ConvergenceSecret {
        ConvergenceSecret(derive(Purpose::Convergence, epoch_key))
    }

    /// The convergence secret of public spaces: 32 zero bytes.
    pub fn public() -> ConvergenceSecret {
        ConvergenceSecret(Zeroizing::new([0u8; 32]))
    }

    /// A secret given directly.
    pub fn from_bytes(bytes: [u8; 32]) -> ConvergenceSecret {
        ConvergenceSecret(Zeroizing::new(bytes))
    }

    /// The secret bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The key of a plaintext: `BLAKE3.keyed_hash(secret, m)`.
    pub fn key_of(&self, plaintext: &[u8]) -> Key {
        keyed_hash(&self.0, plaintext)
    }
}

impl std::fmt::Debug for ConvergenceSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConvergenceSecret(..)")
    }
}

/// An encrypted chunk or index: its id, its key, and its ciphertext.
#[derive(Clone, PartialEq, Eq)]
pub struct Encrypted {
    /// `BLAKE3(ciphertext)`.
    pub id: Id,
    /// The ChaCha20-Poly1305 key.
    pub key: Key,
    /// The ciphertext with its 16-byte tag.
    pub ciphertext: Vec<u8>,
}

impl std::fmt::Debug for Encrypted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Encrypted {{ id: {}, len: {} }}",
            crate::reference::hex(&self.id),
            self.ciphertext.len()
        )
    }
}

/// Encrypts a chunk or an encoded index.
pub fn encrypt(secret: &ConvergenceSecret, plaintext: &[u8]) -> Encrypted {
    let key = secret.key_of(plaintext);
    let ciphertext = chacha20poly1305_encrypt(&key, &[0u8; 12], b"", plaintext);
    Encrypted {
        id: object_id(&ciphertext),
        key,
        ciphertext,
    }
}

/// Decrypts a chunk or index ciphertext. The caller should already have
/// checked the ciphertext against its id.
pub fn decrypt(key: &Key, ciphertext: &[u8]) -> Result<Vec<u8>, BlobError> {
    chacha20poly1305_decrypt(key, &[0u8; 12], b"", ciphertext).map_err(|_| BlobError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convergent_and_round_trip() {
        let s = ConvergenceSecret::from_epoch_key(&[1u8; 32]);
        let a = encrypt(&s, b"hello");
        let b = encrypt(&s, b"hello");
        assert_eq!(a, b);
        assert_eq!(a.ciphertext.len(), 5 + 16);
        assert_eq!(decrypt(&a.key, &a.ciphertext).unwrap(), b"hello");
        let other = ConvergenceSecret::from_epoch_key(&[2u8; 32]);
        assert_ne!(encrypt(&other, b"hello").id, a.id);
        assert!(decrypt(&[0u8; 32], &a.ciphertext).is_err());
    }
}
