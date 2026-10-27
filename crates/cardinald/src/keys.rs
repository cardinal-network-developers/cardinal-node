//! The device's private keys, in a file readable only by its owner.
//!
//! `device.key` holds the Ed25519 signing seed and the hybrid link key's
//! secret bytes as JSON hex, with permissions 0600. Keeping them in the
//! desktop keyring (Secret Service) or a TPM is future work.

use std::path::Path;
use std::sync::Arc;

use cardinal_crypto::{HybridKeyPair, SigningKey};
use cardinal_identity::DeviceKeys;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::paths::write_private;

#[derive(Serialize, Deserialize)]
struct KeyFile {
    signing: String,
    link: String,
}

/// This device's keys, shareable.
pub struct Keys {
    /// The device keys as the identity layer uses them.
    pub device: DeviceKeys,
    /// The same signing key, shared.
    pub signing: Arc<SigningKey>,
    /// The same link key pair, shared.
    pub link: Arc<HybridKeyPair>,
}

impl Keys {
    fn from_parts(seed: &[u8; 32], link: &[u8; 96]) -> Keys {
        Keys {
            device: DeviceKeys {
                signing: SigningKey::from_seed(seed),
                link: HybridKeyPair::from_secret_bytes(link),
            },
            signing: Arc::new(SigningKey::from_seed(seed)),
            link: Arc::new(HybridKeyPair::from_secret_bytes(link)),
        }
    }

    /// The signing public key.
    pub fn key(&self) -> [u8; 32] {
        self.device.key()
    }

    /// Loads the keys, creating them on first use.
    pub fn load_or_create(path: &Path) -> anyhow::Result<Keys> {
        match std::fs::read(path) {
            Ok(b) => {
                let kf: KeyFile = serde_json::from_slice(&b)
                    .map_err(|e| anyhow::anyhow!("{} is damaged: {e}", path.display()))?;
                let seed = Zeroizing::new(hex::decode(&kf.signing)?);
                let link = Zeroizing::new(hex::decode(&kf.link)?);
                let seed: &[u8; 32] = seed[..]
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("{}: bad signing key", path.display()))?;
                let link: &[u8; 96] = link[..]
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("{}: bad link key", path.display()))?;
                Ok(Keys::from_parts(seed, link))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let d = DeviceKeys::generate();
                let seed = d.signing.seed();
                let link = d.link.secret_bytes();
                let kf = KeyFile {
                    signing: hex::encode(&seed[..]),
                    link: hex::encode(&link[..]),
                };
                let json = Zeroizing::new(serde_json::to_vec(&kf)?);
                if let Some(dir) = path.parent() {
                    std::fs::create_dir_all(dir)?;
                }
                write_private(path, &json, 0o600)?;
                Ok(Keys::from_parts(&seed, &link))
            }
            Err(e) => Err(e.into()),
        }
    }
}
