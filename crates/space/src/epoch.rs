//! Epoch keys (`spaces.md#epochs`): ids, entry keys, and wraps to member
//! identities' encryption keys.

use std::collections::HashMap;

use cardinal_crypto::{
    derive, open, random_bytes, seal, HybridKeyPair, HybridPublicKey, Purpose, Sealed,
};
use zeroize::Zeroizing;

/// An epoch id: the first 16 bytes of `derive("epoch id", epoch key)`.
pub type EpochId = [u8; 16];

/// Context prefix of an epoch key wrap.
pub const SPACE_KEY_CONTEXT: &[u8] = b"space key";

/// A random 32-byte epoch key, zeroized on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct EpochKey(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for EpochKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EpochKey({:02x?}..)", &self.id()[..4])
    }
}

impl EpochKey {
    /// A fresh key.
    pub fn generate() -> EpochKey {
        EpochKey(Zeroizing::new(random_bytes::<32>()))
    }

    /// A key from its bytes.
    pub fn from_bytes(b: [u8; 32]) -> EpochKey {
        EpochKey(Zeroizing::new(b))
    }

    /// The key bytes.
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The epoch id.
    pub fn id(&self) -> EpochId {
        derive(Purpose::EpochId, &self.0[..])[..16]
            .try_into()
            .expect("16 bytes")
    }

    /// The AEAD key of entries in this epoch: `derive("entry key", key)`.
    pub fn entry_key(&self) -> Zeroizing<[u8; 32]> {
        derive(Purpose::EntryKey, &self.0[..])
    }

    /// The wrap context: `"space key" || epoch id`.
    pub fn wrap_context(id: &EpochId) -> Vec<u8> {
        [SPACE_KEY_CONTEXT, &id[..]].concat()
    }

    /// Seals this key to a member identity's encryption key.
    pub fn wrap(&self, recipient: &HybridPublicKey) -> Sealed {
        seal(recipient, &self.0[..], &Self::wrap_context(&self.id()))
    }

    /// Tries to open a wrap of epoch `id` with any of `keys`.
    pub fn open_wraps(wraps: &[Sealed], id: &EpochId, keys: &[&HybridKeyPair]) -> Option<EpochKey> {
        let ctx = Self::wrap_context(id);
        for w in wraps {
            for k in keys {
                if let Ok(pt) = open(k, w, &ctx) {
                    if let Ok(b) = <[u8; 32]>::try_from(&pt[..]) {
                        let key = EpochKey::from_bytes(b);
                        if &key.id() == id {
                            return Some(key);
                        }
                    }
                }
            }
        }
        None
    }
}

/// The epoch keys a member holds.
#[derive(Clone, Debug, Default)]
pub struct Keyring {
    keys: HashMap<EpochId, EpochKey>,
}

impl Keyring {
    /// An empty keyring.
    pub fn new() -> Keyring {
        Keyring::default()
    }

    /// Adds a key.
    pub fn add(&mut self, key: EpochKey) {
        self.keys.insert(key.id(), key);
    }

    /// The key of an epoch.
    pub fn get(&self, id: &EpochId) -> Option<&EpochKey> {
        self.keys.get(id)
    }

    /// The number of keys held.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether no key is held.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Every key held.
    pub fn iter(&self) -> impl Iterator<Item = &EpochKey> {
        self.keys.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_round_trip() {
        let k = EpochKey::from_bytes([3; 32]);
        let member = HybridKeyPair::from_seed(b"m");
        let other = HybridKeyPair::from_seed(b"o");
        let w = k.wrap(member.public_key());
        assert_eq!(
            EpochKey::open_wraps(std::slice::from_ref(&w), &k.id(), &[&other, &member]),
            Some(k.clone())
        );
        assert_eq!(
            EpochKey::open_wraps(std::slice::from_ref(&w), &k.id(), &[&other]),
            None
        );
        assert_eq!(EpochKey::open_wraps(&[w], &[0; 16], &[&member]), None);
        assert_ne!(k.entry_key()[..], k.bytes()[..]);
    }
}
