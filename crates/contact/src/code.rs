//! Pairing codes (`contact.md#pairing`): a channel number from 0 to 999
//! and three words from the BIP-39 English list, shown as
//! `4-anchor-harbor-quit`.

use cardinal_crypto::bip39::{word, word_index};
use cardinal_crypto::random_bytes;

use crate::ContactError;

/// A pairing code.
#[derive(Clone, PartialEq, Eq)]
pub struct PairingCode {
    /// The channel, 0 to 999: not secret; it lets the typer find the
    /// right advertisement.
    pub channel: u16,
    /// Three word indexes into the BIP-39 English list: 33 secret bits.
    pub words: [u16; 3],
}

impl std::fmt::Debug for PairingCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairingCode")
            .field("channel", &self.channel)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for PairingCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}-{}-{}-{}",
            self.channel,
            word(self.words[0]),
            word(self.words[1]),
            word(self.words[2])
        )
    }
}

impl PairingCode {
    /// A fresh random code.
    pub fn generate() -> PairingCode {
        let r = random_bytes::<8>();
        let x = u64::from_le_bytes(r);
        PairingCode {
            channel: (x % 1000) as u16,
            words: [
                ((x >> 10) & 0x7ff) as u16,
                ((x >> 21) & 0x7ff) as u16,
                ((x >> 32) & 0x7ff) as u16,
            ],
        }
    }

    /// Parses a typed code. Accepts any case, and spaces as well as
    /// hyphens between the parts.
    pub fn parse(s: &str) -> Result<PairingCode, ContactError> {
        let lower = s.trim().to_ascii_lowercase();
        let parts: Vec<&str> = lower
            .split(|c: char| c == '-' || c.is_whitespace())
            .filter(|p| !p.is_empty())
            .collect();
        if parts.len() != 4 {
            return Err(ContactError::BadCode);
        }
        let channel: u16 = parts[0].parse().map_err(|_| ContactError::BadCode)?;
        if channel > 999 {
            return Err(ContactError::BadCode);
        }
        let mut words = [0u16; 3];
        for (i, w) in parts[1..].iter().enumerate() {
            words[i] = word_index(w).ok_or(ContactError::BadCode)?;
        }
        Ok(PairingCode { channel, words })
    }

    /// The CPace password: the three words joined by single spaces.
    pub fn password(&self) -> Vec<u8> {
        format!(
            "{} {} {}",
            word(self.words[0]),
            word(self.words[1]),
            word(self.words[2])
        )
        .into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_and_parse() {
        let c = PairingCode::parse("4-anchor-harbor-quit").unwrap();
        assert_eq!(c.channel, 4);
        assert_eq!(c.to_string(), "4-anchor-harbor-quit");
        assert_eq!(c.password(), b"anchor harbor quit");
        assert_eq!(PairingCode::parse(" 4 Anchor HARBOR-quit ").unwrap(), c);
        assert!(PairingCode::parse("1000-anchor-harbor-quit").is_err());
        assert!(PairingCode::parse("4-anchor-harbor").is_err());
        assert!(PairingCode::parse("4-anchor-harbor-notaword").is_err());
        for _ in 0..100 {
            let g = PairingCode::generate();
            assert!(g.channel < 1000);
            assert_eq!(PairingCode::parse(&g.to_string()).unwrap(), g);
        }
    }
}
