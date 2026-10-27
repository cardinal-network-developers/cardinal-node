//! What the link needs from the identity layer, as traits, plus a small
//! in-memory implementation for tests and simple deployments.
//!
//! The daemon implements [`PeerDirectory`] over the identity logs and space
//! memberships it holds, so this crate does not depend on the identity
//! crate.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use cardinal_crypto::{HybridPublicKey, SigningKey};

/// The identity layer as the link sees it.
pub trait PeerDirectory: Send + Sync + 'static {
    /// The full link key of the device with this X25519 static key, if this
    /// device accepts sessions from it without a secret: its own devices,
    /// devices of identities it has a relationship or a space with, and its
    /// hosts (`link.md#keys`). `None` means "a stranger".
    fn link_key(&self, static_x25519: &[u8; 32]) -> Option<HybridPublicKey>;

    /// Whether `signing_key` is effective in the log of `identity`, and that
    /// log lists `static_x25519` as the key's link key
    /// (`link.md#identity-binding`). The signature of the proof has already
    /// been checked.
    fn verify_device(
        &self,
        identity: &[u8; 32],
        signing_key: &[u8; 32],
        static_x25519: &[u8; 32],
    ) -> bool;
}

/// This device's identity, for its `device proof` frames.
#[derive(Clone)]
pub struct LocalIdentity {
    /// Identity id.
    pub identity: [u8; 32],
    /// This device's signing key.
    pub signing_key: Arc<SigningKey>,
}

impl std::fmt::Debug for LocalIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalIdentity")
            .field("identity", &hex8(&self.identity))
            .finish_non_exhaustive()
    }
}

/// What a session knows about the peer's identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerIdentity {
    /// Identity id from the peer's device proof.
    pub identity: [u8; 32],
    /// The peer's device signing key.
    pub signing_key: [u8; 32],
    /// `true` if [`PeerDirectory::verify_device`] confirmed the proof
    /// against the identity log. `false` if it was accepted provisionally
    /// in a session opened with a secret, because it matched what the
    /// secret's issuer expected (an invitation or a pairing); the daemon
    /// must re-check once it has the log
    /// ([`Endpoint::recheck_peers`](crate::Endpoint::recheck_peers)).
    pub verified_by_log: bool,
}

/// Who may complete a session opened with a secret, for sessions whose
/// peer's identity log is not known yet.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExpectedPeer {
    /// If set, the peer's device proof must name this identity (an
    /// invitation's `for` field, or the inviter identity on the invitee's
    /// side).
    pub identity: Option<[u8; 32]>,
    /// If set, the peer's device proof must use this signing key (pairing).
    pub signing_key: Option<[u8; 32]>,
    /// If set, the peer must present no identity (an empty device proof).
    pub no_identity: bool,
}

/// A simple [`PeerDirectory`] held in memory.
#[derive(Default)]
pub struct MemoryDirectory {
    inner: RwLock<MemInner>,
}

#[derive(Default)]
struct MemInner {
    peers: HashMap<[u8; 32], HybridPublicKey>,
    devices: HashSet<([u8; 32], [u8; 32], [u8; 32])>,
}

impl MemoryDirectory {
    /// An empty directory.
    pub fn new() -> Arc<MemoryDirectory> {
        Arc::new(MemoryDirectory::default())
    }

    /// Accepts sessions from this link key.
    pub fn add_peer(&self, link_key: HybridPublicKey) {
        self.inner
            .write()
            .expect("lock")
            .peers
            .insert(*link_key.x25519(), link_key);
    }

    /// Records a device of an identity (and accepts its link key).
    pub fn add_device(&self, identity: [u8; 32], signing_key: [u8; 32], link_key: HybridPublicKey) {
        let mut g = self.inner.write().expect("lock");
        g.devices
            .insert((identity, signing_key, *link_key.x25519()));
        g.peers.insert(*link_key.x25519(), link_key);
    }

    /// Forgets a device (as if removed from its log).
    pub fn remove_device(
        &self,
        identity: &[u8; 32],
        signing_key: &[u8; 32],
        static_x25519: &[u8; 32],
    ) {
        let mut g = self.inner.write().expect("lock");
        g.devices.remove(&(*identity, *signing_key, *static_x25519));
        g.peers.remove(static_x25519);
    }
}

impl PeerDirectory for MemoryDirectory {
    fn link_key(&self, static_x25519: &[u8; 32]) -> Option<HybridPublicKey> {
        self.inner
            .read()
            .expect("lock")
            .peers
            .get(static_x25519)
            .cloned()
    }

    fn verify_device(
        &self,
        identity: &[u8; 32],
        signing_key: &[u8; 32],
        static_x25519: &[u8; 32],
    ) -> bool {
        self.inner.read().expect("lock").devices.contains(&(
            *identity,
            *signing_key,
            *static_x25519,
        ))
    }
}

pub(crate) fn hex8(b: &[u8]) -> String {
    b.iter().take(8).map(|x| format!("{x:02x}")).collect()
}
