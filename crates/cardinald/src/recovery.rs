//! The recovery words in place of an admin device
//! (`identity.md#recovery-phrase`). Entered on any of the person's
//! devices, they recreate the root key, which may add and remove devices
//! and admin devices. It signs the entries asked for and is dropped; it is
//! never stored.

use cardinal_crypto::{Error, MnemonicError, RecoveryPhrase, SigningKey};
use cardinal_identity::Power;

use crate::daemon::Daemon;

/// An action this device lacks the power for, which the recovery words
/// can approve instead. The control socket replies `needs_words: true`,
/// and the command line asks for them and tries again.
#[derive(Debug)]
pub struct NeedsWords(pub String);

impl std::fmt::Display for NeedsWords {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for NeedsWords {}

/// The root key from typed recovery words, checked against this identity.
pub fn root_from_words(d: &Daemon, words: &str) -> anyhow::Result<SigningKey> {
    let phrase = RecoveryPhrase::parse(words).map_err(|e| anyhow::anyhow!(plain(&e)))?;
    let root = phrase.root_signing_key();
    let core = d.core();
    let ident = core
        .identity
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("this device does not belong to anyone"))?;
    if ident.state().power(&root.public_key()) != Some(Power::Root) {
        anyhow::bail!(
            "these are not your recovery words: they are real recovery words, but not the ones \
             for your identity"
        );
    }
    Ok(root)
}

/// What is wrong with typed words, in plain words.
fn plain(e: &Error) -> String {
    match e {
        Error::Mnemonic(MnemonicError::WordCount { expected, found }) => {
            format!("that is {found} words; there are {expected}")
        }
        Error::Mnemonic(MnemonicError::UnknownWord { position }) => format!(
            "word {} is not a recovery word; check its spelling",
            position + 1
        ),
        Error::Mnemonic(MnemonicError::Checksum) => {
            "the words do not fit together: one is wrong or out of place".to_owned()
        }
        e => e.to_string(),
    }
}

/// The key to sign an action with: none (this device's own) when its
/// power is `enough`; else the root key from `words`; else [`NeedsWords`]
/// with `why`.
pub fn signer(
    d: &Daemon,
    words: Option<&str>,
    enough: impl FnOnce(Option<Power>) -> bool,
    why: impl FnOnce() -> String,
) -> anyhow::Result<Option<SigningKey>> {
    let mine = d
        .core()
        .identity
        .as_ref()
        .and_then(|i| i.state().power(&d.keys.key()));
    if enough(mine) {
        return Ok(None);
    }
    match words {
        Some(w) => root_from_words(d, w).map(Some),
        None => Err(NeedsWords(why()).into()),
    }
}
