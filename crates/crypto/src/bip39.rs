//! The BIP-39 English wordlist and the recovery phrase
//! (`crypto.md`, `identity.md#recovery-phrase`).
//!
//! The phrase encodes 256 bits of entropy as 24 words with BIP-39's
//! checksum (the first 8 bits of SHA-256 of the entropy). BIP-39's PBKDF2
//! seed step is **not** used: the root key seed is
//! `derive("root key", entropy)` and the recovery seed is
//! `derive("recovery key", entropy)`.

use std::sync::OnceLock;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::derive::{derive, Purpose};
use crate::hybrid::HybridKeyPair;
use crate::random::random_bytes;
use crate::sign::SigningKey;
use crate::{Error, MnemonicError};

/// The BIP-39 English wordlist file, as published in the BIP repository
/// (SHA-256 `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`).
const ENGLISH: &str = include_str!("bip39/english.txt");

/// The number of words in a recovery phrase.
pub const PHRASE_WORDS: usize = 24;

/// The BIP-39 English wordlist, 2048 words in order.
pub fn wordlist() -> &'static [&'static str] {
    static LIST: OnceLock<Vec<&'static str>> = OnceLock::new();
    LIST.get_or_init(|| {
        let words: Vec<&str> = ENGLISH.lines().collect();
        assert_eq!(words.len(), 2048, "BIP-39 wordlist must have 2048 words");
        debug_assert!(words.windows(2).all(|w| w[0] < w[1]), "wordlist is sorted");
        words
    })
}

/// The word with index `i` (0 to 2047).
///
/// # Panics
///
/// Panics if `i >= 2048`.
pub fn word(i: u16) -> &'static str {
    wordlist()[usize::from(i)]
}

/// The index of `word` in the list, ignoring ASCII case.
pub fn word_index(word: &str) -> Option<u16> {
    let lower = word.to_ascii_lowercase();
    wordlist()
        .binary_search(&lower.as_str())
        .ok()
        .map(|i| i as u16)
}

/// The word `typed` stands for, ignoring ASCII case: itself, or the one
/// word that starts with it when it is at least four letters long. The
/// first four letters of every BIP-39 English word are unique, so they are
/// enough to type a phrase.
pub fn complete_word(typed: &str) -> Option<&'static str> {
    if let Some(i) = word_index(typed) {
        return Some(word(i));
    }
    let lower = typed.to_ascii_lowercase();
    if lower.len() < 4 {
        return None;
    }
    let mut found = wordlist().iter().filter(|w| w.starts_with(&lower));
    match (found.next(), found.next()) {
        (Some(w), None) => Some(w),
        _ => None,
    }
}

/// The 24 words for 256 bits of entropy, with BIP-39's checksum.
pub fn entropy_to_words(entropy: &[u8; 32]) -> [&'static str; PHRASE_WORDS] {
    let checksum = Sha256::digest(entropy)[0];
    let mut bits = Zeroizing::new([0u8; 33]);
    bits[..32].copy_from_slice(entropy);
    bits[32] = checksum;
    let mut words = [""; PHRASE_WORDS];
    for (i, w) in words.iter_mut().enumerate() {
        let mut idx = 0u16;
        for b in 0..11 {
            let pos = i * 11 + b;
            let bit = (bits[pos / 8] >> (7 - pos % 8)) & 1;
            idx = (idx << 1) | u16::from(bit);
        }
        *w = word(idx);
    }
    words
}

/// Parses 24 words (separated by any whitespace, ASCII case ignored) back
/// to entropy, checking the checksum.
pub fn words_to_entropy(phrase: &str) -> Result<Zeroizing<[u8; 32]>, Error> {
    let words: Vec<&str> = phrase.split_whitespace().collect();
    if words.len() != PHRASE_WORDS {
        return Err(MnemonicError::WordCount {
            expected: PHRASE_WORDS,
            found: words.len(),
        }
        .into());
    }
    let mut bits = Zeroizing::new([0u8; 33]);
    for (i, w) in words.iter().enumerate() {
        let idx = word_index(w).ok_or(MnemonicError::UnknownWord { position: i })?;
        for b in 0..11 {
            if (idx >> (10 - b)) & 1 == 1 {
                let pos = i * 11 + b;
                bits[pos / 8] |= 1 << (7 - pos % 8);
            }
        }
    }
    let mut entropy = Zeroizing::new([0u8; 32]);
    entropy.copy_from_slice(&bits[..32]);
    if Sha256::digest(&entropy[..])[0] != bits[32] {
        return Err(MnemonicError::Checksum.into());
    }
    Ok(entropy)
}

/// A recovery phrase: 256 bits of entropy, zeroized on drop.
pub struct RecoveryPhrase {
    entropy: Zeroizing<[u8; 32]>,
}

impl RecoveryPhrase {
    /// A new phrase from the operating system's random source.
    pub fn generate() -> RecoveryPhrase {
        RecoveryPhrase {
            entropy: Zeroizing::new(random_bytes::<32>()),
        }
    }

    /// The phrase for this entropy.
    pub fn from_entropy(entropy: &[u8; 32]) -> RecoveryPhrase {
        RecoveryPhrase {
            entropy: Zeroizing::new(*entropy),
        }
    }

    /// Parses a typed phrase.
    pub fn parse(phrase: &str) -> Result<RecoveryPhrase, Error> {
        Ok(RecoveryPhrase {
            entropy: words_to_entropy(phrase)?,
        })
    }

    /// The entropy.
    pub fn entropy(&self) -> &[u8; 32] {
        &self.entropy
    }

    /// The 24 words joined by single spaces.
    pub fn to_words(&self) -> Zeroizing<String> {
        Zeroizing::new(entropy_to_words(&self.entropy).join(" "))
    }

    /// The root key seed: `derive("root key", entropy)`.
    pub fn root_seed(&self) -> Zeroizing<[u8; 32]> {
        derive(Purpose::RootKey, &self.entropy[..])
    }

    /// The root Ed25519 key, whose RFC 8032 secret is the root key seed.
    pub fn root_signing_key(&self) -> SigningKey {
        SigningKey::from_seed(&self.root_seed())
    }

    /// The recovery seed: `derive("recovery key", entropy)`.
    pub fn recovery_seed(&self) -> Zeroizing<[u8; 32]> {
        derive(Purpose::RecoveryKey, &self.entropy[..])
    }

    /// The recovery key pair: the hybrid key pair generated from the
    /// recovery seed.
    pub fn recovery_key_pair(&self) -> HybridKeyPair {
        HybridKeyPair::from_seed(&self.recovery_seed()[..])
    }
}

impl std::fmt::Debug for RecoveryPhrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryPhrase(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_shape() {
        let l = wordlist();
        assert_eq!(l.len(), 2048);
        assert_eq!(l[0], "abandon");
        assert_eq!(l[2047], "zoo");
        assert!(l.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(word_index("Zoo"), Some(2047));
        assert_eq!(word_index("zzz"), None);
    }

    #[test]
    fn completing_words() {
        assert_eq!(complete_word("act"), Some("act"));
        assert_eq!(complete_word("Abse"), Some("absent"));
        assert_eq!(complete_word("absent"), Some("absent"));
        assert_eq!(complete_word("abs"), None, "three letters are not enough");
        assert_eq!(complete_word("absx"), None);
        // four letters always name exactly one word
        let mut prefixes: Vec<&str> = wordlist().iter().map(|w| &w[..w.len().min(4)]).collect();
        prefixes.dedup();
        assert_eq!(prefixes.len(), 2048);
        for w in wordlist() {
            assert_eq!(complete_word(&w[..w.len().min(4)]), Some(*w));
        }
    }

    /// Entropy-to-mnemonic vectors from the BIP-39 reference test set
    /// (trezor/python-mnemonic vectors.json, 256-bit entries).
    #[test]
    fn bip39_reference_vectors() {
        let cases = [
            ("0000000000000000000000000000000000000000000000000000000000000000",
             "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"),
            ("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
             "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"),
            ("8080808080808080808080808080808080808080808080808080808080808080",
             "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless"),
            ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
             "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"),
            ("68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
             "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length"),
        ];
        for (e, phrase) in cases {
            let entropy: [u8; 32] = hex::decode(e).unwrap().try_into().unwrap();
            assert_eq!(entropy_to_words(&entropy).join(" "), phrase);
            assert_eq!(*words_to_entropy(phrase).unwrap(), entropy);
        }
    }

    #[test]
    fn parse_errors() {
        let good = RecoveryPhrase::from_entropy(&[5; 32]).to_words();
        let mut words: Vec<&str> = good.split(' ').collect();
        assert!(words_to_entropy(&words[..23].join(" ")).is_err());
        let last = words[23];
        words[23] = if last == "zoo" { "abandon" } else { "zoo" };
        assert_eq!(
            words_to_entropy(&words.join(" ")).unwrap_err(),
            Error::Mnemonic(MnemonicError::Checksum)
        );
        words[3] = "notaword";
        assert_eq!(
            words_to_entropy(&words.join(" ")).unwrap_err(),
            Error::Mnemonic(MnemonicError::UnknownWord { position: 3 })
        );
        // Whitespace and case are forgiven.
        let messy = format!("  {}\n", good.to_uppercase().replace(' ', "\t "));
        assert_eq!(*words_to_entropy(&messy).unwrap(), [5; 32]);
    }

    #[test]
    fn keys_from_phrase() {
        let p = RecoveryPhrase::from_entropy(&[9; 32]);
        let q = RecoveryPhrase::parse(&p.to_words()).unwrap();
        assert_eq!(
            p.root_signing_key().public_key(),
            q.root_signing_key().public_key()
        );
        assert_eq!(
            p.recovery_key_pair().public_key(),
            q.recovery_key_pair().public_key()
        );
        assert_eq!(
            *p.root_seed(),
            blake3::derive_key("cardinal 1 root key", &[9; 32])
        );
        assert_eq!(
            *p.recovery_seed(),
            blake3::derive_key("cardinal 1 recovery key", &[9; 32])
        );
    }
}
