//! The link's view of the identity layer: which static keys belong to this
//! person's devices. A snapshot, refreshed whenever the identity log
//! changes, so the link never waits on the daemon's locks.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use cardinal_crypto::HybridPublicKey;
use cardinal_identity::IdentityState;
use cardinal_link::PeerDirectory;

#[derive(Default)]
struct Snapshot {
    identity: Option<[u8; 32]>,
    /// x25519 static key -> (full link key, signing key)
    devices: HashMap<[u8; 32], (HybridPublicKey, [u8; 32])>,
    /// The same for contacts' devices, with their identities.
    others: HashMap<[u8; 32], (HybridPublicKey, [u8; 32], [u8; 32])>,
}

/// A [`PeerDirectory`] over this person's identity log.
#[derive(Default)]
pub struct Directory {
    inner: RwLock<Snapshot>,
}

impl Directory {
    /// Replaces the snapshot with the devices in effect in `state`, and
    /// those of the other logs this device keeps.
    pub fn update(&self, state: Option<&IdentityState>, others: &[Arc<IdentityState>]) {
        let mut s = Snapshot::default();
        for o in others {
            for k in o.keys.values() {
                if let Some(l) = &k.link_key {
                    s.others.insert(*l.x25519(), (l.clone(), k.key, o.identity));
                }
            }
        }
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
        let s = self.inner.read().expect("lock");
        s.devices
            .get(static_x25519)
            .map(|(l, _)| l.clone())
            .or_else(|| s.others.get(static_x25519).map(|(l, _, _)| l.clone()))
    }

    fn verify_device(
        &self,
        identity: &[u8; 32],
        signing_key: &[u8; 32],
        static_x25519: &[u8; 32],
    ) -> bool {
        let s = self.inner.read().expect("lock");
        let own = s.identity.as_ref() == Some(identity)
            && s.devices
                .get(static_x25519)
                .is_some_and(|(_, k)| k == signing_key);
        own || s
            .others
            .get(static_x25519)
            .is_some_and(|(_, k, i)| k == signing_key && i == identity)
    }
}
