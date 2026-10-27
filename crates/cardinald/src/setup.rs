//! Creating a new identity on the first device (`cardinal init`).
//!
//! The identity is created in memory first, so the person can write the
//! recovery phrase down before anything is saved; [`install`] then writes
//! the identity log, the account space (this device, the discovery secret,
//! the files space and where this device shows it) and the files space.

use std::sync::Arc;

use cardinal_crypto::RecoveryPhrase;
use cardinal_identity::{Created, IdentityLog};
use cardinal_space::account::{self, Retention};
use cardinal_space::files::created_node;
use cardinal_space::{Policy, Profile, Space};

use crate::config::Config;
use crate::core::{create_secret, has_identity, now_ms, Core, DISCOVERY_PURPOSE};
use crate::keys::Keys;
use crate::paths::Paths;

/// A new identity not yet saved.
pub struct Prepared {
    created: Created,
}

impl Prepared {
    /// The recovery phrase, to show once.
    pub fn phrase(&self) -> &RecoveryPhrase {
        &self.created.phrase
    }
}

/// Creates an identity in memory with this device as its first admin.
pub fn prepare(paths: &Paths) -> anyhow::Result<Prepared> {
    if has_identity(paths) {
        anyhow::bail!(
            "this device already belongs to someone ({}). Nothing was changed.",
            paths.home.display()
        );
    }
    std::fs::create_dir_all(&paths.home)?;
    let keys = Keys::load_or_create(&paths.device_key())?;
    Ok(Prepared {
        created: IdentityLog::create(&keys.device)?,
    })
}

/// Saves a prepared identity and creates the account and files spaces.
pub fn install(paths: &Paths, prepared: Prepared, config: &Config) -> anyhow::Result<()> {
    let keys = Arc::new(Keys::load_or_create(&paths.device_key())?);
    let mut core = Core::load(paths, keys.clone())?;
    let created = prepared.created;
    let entries: Vec<Vec<u8>> = created.log.entries().map(|e| e.encode()).collect();
    core.install_identity(&entries)?;
    let ident = core.identity.as_ref().expect("installed");
    if ident.enc.is_empty() {
        anyhow::bail!("could not open the new identity's encryption key");
    }
    let pk = created.encryption.public_key().clone();

    let (account, acc_genesis) = Space::create(
        Profile::ACCOUNT,
        Policy::default(),
        &ident.log,
        &keys.device.signing,
        &[&pk],
        Some(now_ms()),
    )?;
    let (files, files_genesis) = Space::create(
        Profile::FILES,
        Policy::default(),
        &ident.log,
        &keys.device.signing,
        &[&pk],
        Some(now_ms()),
    )?;
    let (acc_id, files_id) = (account.id(), files.id());
    core.ingest_space(acc_id, &[acc_genesis.encode()])?;
    core.ingest_space(files_id, &[files_genesis.encode()])?;

    let secret: [u8; 32] = cardinal_crypto::random_bytes();
    let written = core.write(
        &acc_id,
        vec![
            account::create_device(&keys.key(), &config.name, false, false),
            create_secret(DISCOVERY_PURPOSE, &secret),
            account::create_space(&files_id, "Cardinal"),
        ],
    )?;
    let space_node = created_node(&written[0].0, 2);
    core.write(&acc_id, vec![placement_op(space_node, &keys.key(), config)])?;
    Ok(())
}

/// The placement of the files space on this device.
pub fn placement_op(
    space_node: cardinal_space::NodeId,
    device: &[u8; 32],
    config: &Config,
) -> cardinal_space::SpaceOp {
    let retention = if config.on_demand() {
        Retention::OnDemand
    } else {
        Retention::Full
    };
    let path = config.mount.as_ref().map(|p| p.display().to_string());
    account::create_placement(space_node, device, retention, path.as_deref(), false)
}
