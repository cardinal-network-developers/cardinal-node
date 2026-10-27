//! ChaCha20-Poly1305 (RFC 8439) and XChaCha20-Poly1305
//! (draft-irtf-cfrg-xchacha), via RustCrypto `chacha20poly1305`.
//!
//! Ciphertexts are the encrypted bytes followed by the 16-byte tag.
//! Use XChaCha20-Poly1305 with random nonces, and ChaCha20-Poly1305 only
//! with counter nonces or single-use keys.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};

use crate::random::random_bytes;
use crate::Error;

/// Key length for both AEADs.
pub const KEY_LEN: usize = 32;
/// ChaCha20-Poly1305 nonce length.
pub const NONCE_LEN: usize = 12;
/// XChaCha20-Poly1305 nonce length.
pub const XNONCE_LEN: usize = 24;
/// Tag length for both AEADs.
pub const TAG_LEN: usize = 16;

/// ChaCha20-Poly1305 encryption.
pub fn chacha20poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    ChaCha20Poly1305::new(&(*key).into())
        .encrypt(
            &(*nonce).into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("ChaCha20-Poly1305 input within limits")
}

/// ChaCha20-Poly1305 decryption.
pub fn chacha20poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    ChaCha20Poly1305::new(&(*key).into())
        .decrypt(
            &(*nonce).into(),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Decrypt)
}

/// XChaCha20-Poly1305 encryption with the given nonce.
pub fn xchacha20poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    XChaCha20Poly1305::new(&(*key).into())
        .encrypt(
            &(*nonce).into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("XChaCha20-Poly1305 input within limits")
}

/// XChaCha20-Poly1305 encryption with a fresh random nonce, returned
/// alongside the ciphertext.
pub fn xchacha20poly1305_encrypt_random(
    key: &[u8; 32],
    aad: &[u8],
    plaintext: &[u8],
) -> ([u8; 24], Vec<u8>) {
    let nonce = random_bytes::<24>();
    (
        nonce,
        xchacha20poly1305_encrypt(key, &nonce, aad, plaintext),
    )
}

/// XChaCha20-Poly1305 decryption.
pub fn xchacha20poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    XChaCha20Poly1305::new(&(*key).into())
        .decrypt(
            &(*nonce).into(),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s.split_whitespace().collect::<String>()).unwrap()
    }

    /// RFC 8439 section 2.8.2.
    #[test]
    fn rfc8439_vector() {
        let key: [u8; 32] = h("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
            .try_into()
            .unwrap();
        let nonce: [u8; 12] = h("070000004041424344454647").try_into().unwrap();
        let aad = h("50515253c0c1c2c3c4c5c6c7");
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let ct = chacha20poly1305_encrypt(&key, &nonce, &aad, pt);
        let expected = h(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6
            3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36
            92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc
            3ff4def08e4b7a9de576d26586cec64b6116
            1ae10b594f09e26a7e902ecbd0600691",
        );
        assert_eq!(ct, expected);
        assert_eq!(
            chacha20poly1305_decrypt(&key, &nonce, &aad, &ct).unwrap(),
            pt
        );
    }

    /// draft-irtf-cfrg-xchacha-03 appendix A.3.1.
    #[test]
    fn xchacha_draft_vector() {
        let key: [u8; 32] = h("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
            .try_into()
            .unwrap();
        let nonce: [u8; 24] = h("404142434445464748494a4b4c4d4e4f5051525354555657")
            .try_into()
            .unwrap();
        let aad = h("50515253c0c1c2c3c4c5c6c7");
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let ct = xchacha20poly1305_encrypt(&key, &nonce, &aad, pt);
        let expected = h(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb
            731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452
            2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9
            21f9664c97637da9768812f615c68b13b52e
            c0875924c1c7987947deafd8780acf49",
        );
        assert_eq!(ct, expected);
        assert_eq!(
            xchacha20poly1305_decrypt(&key, &nonce, &aad, &ct).unwrap(),
            pt
        );
    }

    #[test]
    fn tamper_detected() {
        let key = [7u8; 32];
        let (nonce, mut ct) = xchacha20poly1305_encrypt_random(&key, b"ad", b"secret");
        assert_eq!(ct.len(), 6 + TAG_LEN);
        assert_eq!(
            xchacha20poly1305_decrypt(&key, &nonce, b"ad", &ct).unwrap(),
            b"secret"
        );
        assert_eq!(
            xchacha20poly1305_decrypt(&key, &nonce, b"AD", &ct),
            Err(Error::Decrypt)
        );
        ct[0] ^= 1;
        assert_eq!(
            xchacha20poly1305_decrypt(&key, &nonce, b"ad", &ct),
            Err(Error::Decrypt)
        );
        assert_eq!(
            chacha20poly1305_decrypt(&key, &[0; 12], b"", &[0; 15]),
            Err(Error::Decrypt)
        );
    }
}
