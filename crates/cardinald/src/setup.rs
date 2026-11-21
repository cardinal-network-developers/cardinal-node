//! Creating a new identity on the first device (`cardinal init`).
//!
//! The identity is created in memory first, so the person can write the
//! recovery phrase down before anything is saved; [`install`] then writes
//! the identity log, the account space (this device, the discovery secret,
//! the files space and where this device shows it, and the name the person
//! suggests for themselves) and the files space.

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
    crate::format::check(paths)?;
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
/// `person` is the name the person suggests for themselves, kept in the
/// account's self node; the device is named `config.name`.
pub fn install(
    paths: &Paths,
    prepared: Prepared,
    config: &Config,
    person: &str,
) -> anyhow::Result<()> {
    let created = prepared.created;
    let entries: Vec<Vec<u8>> = created.log.entries().map(|e| e.encode()).collect();
    install_entries(paths, &entries, config, person)
}

/// Saves an identity log, `entries` (its own first, then any held under
/// its label), and creates new account and files spaces for it: for a
/// new identity, or one taken up again through guardians with nothing
/// left of its spaces (`hosts.md#restore`). This device must be one of
/// its devices, and the log must open its encryption key.
pub fn install_entries(
    paths: &Paths,
    entries: &[Vec<u8>],
    config: &Config,
    person: &str,
) -> anyhow::Result<()> {
    crate::format::check(paths)?;
    let keys = Arc::new(Keys::load_or_create(&paths.device_key())?);
    let mut core = Core::load(paths, keys.clone())?;
    core.install_identity(entries)?;
    create_spaces(&mut core, &keys, config, person)
}

/// Saves an identity log taken up again through guardians, with the sets
/// they gave back (D80): the sealed account and the relationship spaces,
/// by label. With no account among them, new account and files spaces are
/// made. Returns whether the account came back.
pub fn install_recovered(
    paths: &Paths,
    entries: &[Vec<u8>],
    copies: &[([u8; 32], Vec<Vec<u8>>)],
    config: &Config,
    person: &str,
) -> anyhow::Result<bool> {
    crate::format::check(paths)?;
    let keys = Arc::new(Keys::load_or_create(&paths.device_key())?);
    let mut core = Core::load(paths, keys.clone())?;
    core.install_identity(entries)?;
    core.identity_updated();
    for (label, sealed) in copies {
        if let Err(e) = core.ingest_space(*label, sealed) {
            tracing::warn!("a set a guardian gave back: {e:#}");
        }
    }
    // Every entry of them is the removed devices' work, set aside until
    // kept: the person's account and relationships, kept whole.
    let labels: Vec<[u8; 32]> = copies.iter().map(|(l, _)| *l).collect();
    if let Err(e) = core.keep_given_back(&labels) {
        tracing::warn!("keeping what the guardians gave back: {e:#}");
    }
    if core.account_id().is_some() {
        return Ok(true);
    }
    create_spaces(&mut core, &keys, config, person)?;
    Ok(false)
}

/// Creates the account and files spaces of an identity just installed.
pub(crate) fn create_spaces(
    core: &mut Core,
    keys: &Arc<Keys>,
    config: &Config,
    person: &str,
) -> anyhow::Result<()> {
    let ident = core.identity.as_ref().expect("installed");
    let Some(enc) = ident.enc.first() else {
        anyhow::bail!("could not open the identity's encryption key");
    };
    let pk = enc.public_key().clone();

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
            account::create_self(person),
        ],
    )?;
    let space_node = created_node(&written[0].0, 2);
    core.write(&acc_id, vec![placement_op(space_node, &keys.key(), config)])?;
    Ok(())
}

/// The retention policy a configuration asks for: full with old
/// versions kept forever is history (`blobs.md#retention`).
pub fn retention(config: &Config) -> Retention {
    if config.on_demand() {
        Retention::OnDemand
    } else if matches!(
        crate::cleanup::Keep::parse(&config.keep_old),
        Ok(crate::cleanup::Keep::Forever)
    ) {
        Retention::History
    } else {
        Retention::Full
    }
}

/// The placement of the files space on this device.
pub fn placement_op(
    space_node: cardinal_space::NodeId,
    device: &[u8; 32],
    config: &Config,
) -> cardinal_space::SpaceOp {
    let retention = retention(config);
    let path = config.mount.as_ref().map(|p| p.display().to_string());
    account::create_placement(space_node, device, retention, path.as_deref(), false)
}
