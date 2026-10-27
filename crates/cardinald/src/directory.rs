//! The link's view of the identity layer: which static keys belong to this
//! person's devices. A snapshot, refreshed whenever the identity log
//! changes, so the link never waits on the daemon's locks.

use std::collections::HashMap;
use std::sync::RwLock;

use cardinal_crypto::HybridPublicKey;
use cardinal_identity::IdentityState;
use cardinal_link::PeerDirectory;

#[derive(Default)]
struct Snapshot {
    identity: Option<[u8; 32]>,
    /// x25519 static key -> (full link key, signing key)
    devices: HashMap<[u8; 32], (HybridPublicKey, [u8; 32])>,
}

/// A [`PeerDirectory`] over this person's identity log.
#[derive(Default)]
pub struct Directory {
    inner: RwLock<Snapshot>,
}

impl Directory {
    /// Replaces the snapshot with the devices in effect in `state`.
    pub fn update(&self, state: Option<&IdentityState>) {
        let mut s = Snapshot::default();
        if let Some(st) = state {
            s.identity = Some(st.identity);
            for k in st.keys.values() {
                if let Some(l) = &k.link_key {
                    s.devices.insert(*l.x25519(), (l.clone(), k.key));
                }
            }
        }
        *self.inner.write().expect("lock") = s;
    }
}

impl PeerDirectory for Directory {
    fn link_key(&self, static_x25519: &[u8; 32]) -> Option<HybridPublicKey> {
        self.inner
            .read()
            .expect("lock")
            .devices
            .get(static_x25519)
            .map(|(l, _)| l.clone())
    }

    fn verify_device(
        &self,
        identity: &[u8; 32],
        signing_key: &[u8; 32],
        static_x25519: &[u8; 32],
    ) -> bool {
        let s = self.inner.read().expect("lock");
        s.identity.as_ref() == Some(identity)
            && s.devices
                .get(static_x25519)
                .is_some_and(|(_, k)| k == signing_key)
    }
}
