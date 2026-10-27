//! BLAKE3 hashing, keyed hashing, and the derivation function
//! (`crypto.md#derivations`).

use zeroize::Zeroizing;

/// Every `purpose` string the specification uses with [`derive`](fn@crate::derive)(fn@derive).
///
/// The context string is `"cardinal 1 " || purpose`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Purpose {
    /// `seal`: hybrid sealing key (crypto.md).
    Seal,
    /// `root key`: identity root key seed from the recovery phrase (identity.md).
    RootKey,
    /// `recovery key`: recovery seed from the recovery phrase (identity.md).
    RecoveryKey,
    /// `entry key`: space entry encryption key, from an epoch key (spaces.md).
    EntryKey,
    /// `epoch id`: epoch identifier, from an epoch key (spaces.md).
    EpochId,
    /// `convergence`: per-epoch convergence secret for chunks (blobs.md).
    Convergence,
    /// `mailbox`: envelope key, from an epoch key (hosts.md).
    Mailbox,
    /// `discovery`: LAN discovery MAC key (hosts.md).
    Discovery,
    /// `invite`: invitation keys (contact.md).
    Invite,
    /// `token`: link secret from a delivery token (link.md).
    Token,
    /// `pair`: pairing channel key (contact.md).
    Pair,
    /// `handshake`: link handshake key schedule (link.md).
    Handshake,
    /// `rekey`: link post-quantum rekey (link.md).
    Rekey,
    /// `hybrid key`: hybrid key pair from a seed (crypto.md).
    HybridKey,
}

impl Purpose {
    /// All purposes, in the order of the specification's table.
    pub const ALL: [Purpose; 14] = [
        Purpose::Seal,
        Purpose::RootKey,
        Purpose::RecoveryKey,
        Purpose::EntryKey,
        Purpose::EpochId,
        Purpose::Convergence,
        Purpose::Mailbox,
        Purpose::Discovery,
        Purpose::Invite,
        Purpose::Token,
        Purpose::Pair,
        Purpose::Handshake,
        Purpose::Rekey,
        Purpose::HybridKey,
    ];

    /// The purpose string from the specification's table.
    pub const fn as_str(self) -> &'static str {
        match self {
            Purpose::Seal => "seal",
            Purpose::RootKey => "root key",
            Purpose::RecoveryKey => "recovery key",
            Purpose::EntryKey => "entry key",
            Purpose::EpochId => "epoch id",
            Purpose::Convergence => "convergence",
            Purpose::Mailbox => "mailbox",
            Purpose::Discovery => "discovery",
            Purpose::Invite => "invite",
            Purpose::Token => "token",
            Purpose::Pair => "pair",
            Purpose::Handshake => "handshake",
            Purpose::Rekey => "rekey",
            Purpose::HybridKey => "hybrid key",
        }
    }

    /// The BLAKE3 key-derivation context: `"cardinal 1 " || purpose`.
    pub const fn context(self) -> &'static str {
        match self {
            Purpose::Seal => "cardinal 1 seal",
            Purpose::RootKey => "cardinal 1 root key",
            Purpose::RecoveryKey => "cardinal 1 recovery key",
            Purpose::EntryKey => "cardinal 1 entry key",
            Purpose::EpochId => "cardinal 1 epoch id",
            Purpose::Convergence => "cardinal 1 convergence",
            Purpose::Mailbox => "cardinal 1 mailbox",
            Purpose::Discovery => "cardinal 1 discovery",
            Purpose::Invite => "cardinal 1 invite",
            Purpose::Token => "cardinal 1 token",
            Purpose::Pair => "cardinal 1 pair",
            Purpose::Handshake => "cardinal 1 handshake",
            Purpose::Rekey => "cardinal 1 rekey",
            Purpose::HybridKey => "cardinal 1 hybrid key",
        }
    }
}

/// `derive(purpose, material)`: 32 bytes of
/// `BLAKE3.derive_key("cardinal 1 " || purpose, material)`.
pub fn derive(purpose: Purpose, material: &[u8]) -> Zeroizing<[u8; 32]> {
    derive_parts(purpose, &[material])
}

/// [`derive`](fn@crate::derive)(fn@derive) over the concatenation of `parts`, without building it.
pub fn derive_parts(purpose: Purpose, parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    derive_into_parts(purpose, parts, &mut out[..]);
    out
}

/// Fills `out` with the extended output of `derive(purpose, material)`;
/// for derivations that need more than 32 bytes (the first 32 bytes equal
/// [`derive`](fn@crate::derive)(fn@derive)'s output).
pub fn derive_into(purpose: Purpose, material: &[u8], out: &mut [u8]) {
    derive_into_parts(purpose, &[material], out);
}

/// [`derive_into`] over the concatenation of `parts`.
pub fn derive_into_parts(purpose: Purpose, parts: &[&[u8]], out: &mut [u8]) {
    let mut h = blake3::Hasher::new_derive_key(purpose.context());
    for p in parts {
        h.update(p);
    }
    h.finalize_xof().fill(out);
}

/// `BLAKE3(data)`.
pub fn hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// `BLAKE3` of the concatenation of `parts`.
pub fn hash_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    for p in parts {
        h.update(p);
    }
    *h.finalize().as_bytes()
}

/// `BLAKE3.keyed_hash(key, data)`.
pub fn keyed_hash(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    keyed_hash_parts(key, &[data])
}

/// `BLAKE3.keyed_hash(key, ·)` of the concatenation of `parts`.
pub fn keyed_hash_parts(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_keyed(key);
    for p in parts {
        h.update(p);
    }
    *h.finalize().as_bytes()
}

/// Compares two byte strings in constant time (for equal lengths).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contexts_match_strings() {
        for p in Purpose::ALL {
            assert_eq!(p.context(), format!("cardinal 1 {}", p.as_str()));
        }
    }

    #[test]
    fn derive_matches_blake3() {
        let out = derive(Purpose::Seal, b"material");
        assert_eq!(*out, blake3::derive_key("cardinal 1 seal", b"material"));
        let mut long = [0u8; 96];
        derive_into(Purpose::Seal, b"material", &mut long);
        assert_eq!(long[..32], out[..]);
        assert_eq!(*derive_parts(Purpose::Seal, &[b"mate", b"rial"]), *out);
    }

    #[test]
    fn hashes() {
        assert_eq!(hash(b"ab"), hash_parts(&[b"a", b"b"]));
        assert_eq!(
            keyed_hash(&[1; 32], b"ab"),
            keyed_hash_parts(&[1; 32], &[b"a", b"b"])
        );
        assert_eq!(
            keyed_hash(&[1; 32], b"ab"),
            *blake3::keyed_hash(&[1; 32], b"ab").as_bytes()
        );
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }
}
