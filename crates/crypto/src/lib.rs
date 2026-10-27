//! Cryptographic suite 1 of the Cardinal protocol (`core/spec/crypto.md`).
//!
//! | Purpose | Primitive | Crate |
//! |---|---|---|
//! | Hash, KDF, MAC | BLAKE3 | `blake3` |
//! | Signature | Ed25519, verified by ZIP-215 rules | `ed25519-zebra` |
//! | Key agreement | X25519 | `x25519-dalek` |
//! | Post-quantum KEM | ML-KEM-768 | `ml-kem` |
//! | AEAD | XChaCha20-Poly1305, ChaCha20-Poly1305 | `chacha20poly1305` |
//! | PAKE | CPace over Ristretto255 with SHA-512 | `curve25519-dalek`, `sha2` |
//! | Mnemonic | BIP-39 English wordlist, 24 words | embedded list, `sha2` |
//!
//! No primitive is implemented here; this crate composes vetted ones as the
//! specification describes. Private keys are zeroized when dropped, and
//! functions returning secrets return [`Zeroizing`] buffers.
//!
//! The `test-rng` feature exposes variants of the randomized operations
//! that take their randomness as arguments, for reproducible test vectors.

pub mod aead;
pub mod bip39;
pub mod cpace;
mod derive;
mod error;
pub mod hybrid;
pub mod kem;
mod random;
pub mod seal;
pub mod sign;
pub mod x25519;

pub use bip39::RecoveryPhrase;
pub use cpace::{Cpace, Isk, Role as CpaceRole};
pub use derive::{
    ct_eq, derive, derive_into, derive_into_parts, derive_parts, hash, hash_parts, keyed_hash,
    keyed_hash_parts, Purpose,
};
pub use error::{Error, MnemonicError};
pub use hybrid::{HybridKeyPair, HybridPublicKey};
pub use kem::{KemPublicKey, KemSecretKey};
pub use random::{fill_random, random_bytes};
pub use seal::{open, seal, Sealed};
pub use sign::{verify, verify_object, verify_object_signature, SigningKey};
pub use x25519::X25519Secret;
pub use zeroize::{Zeroize, Zeroizing};

#[cfg(test)]
mod vectors;
