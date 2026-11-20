//! A new device recovering an identity through its guardians
//! (`identity.md#how-guardians-act`, `hosts.md#restore`), for a person who
//! lost every admin device and the recovery words.
//!
//! 1. `cardinal recover start CODE [--key KEY]`: the
//!    device makes a new phrase, and so a new root and recovery key, and
//!    reaches the guardian's device the code names. That device proposes
//!    parents and the policy; this one signs the `recover`, naming its own
//!    link key to receive shares, and keeping the host on the sheet, if one
//!    is given, so that it stays one of the person's devices. The guardian's
//!    device appends it and passes it on. The same `recover` goes to every
//!    other guardian whose code the person brings.
//! 2. The person reads the fingerprint to each guardian, who endorse, wait,
//!    and confirm (`guardians.rs`).
//! 3. `cardinal recover finish --host ADDR --key KEY`: once the recovery
//!    is in effect at the host, this device proves the new root to it, as a
//!    restore from the words does, adds itself with the root, rebuilds the
//!    guardian key from the shares sealed to it and opens the encryption
//!    key, and sets a fresh one. It shows the new words.
//!
//! What it holds meanwhile, the new words above all, is kept in
//! `recovering.json`, readable by this user only, until it is done.

use std::sync::Arc;
use std::time::Duration;

use cardinal_crypto::{HybridPublicKey, RecoveryPhrase};
use cardinal_encoding::{Record, Value};
use cardinal_identity::guardians::fingerprint;
use cardinal_identity::{EntryBuilder, EntryId, IdentityEntry, IdentityOp, KeyId};
use cardinal_link::{CarrierKind, Priority, Session, Target};
use cardinal_sync::identity_log_label;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as Json};
use tokio::io::AsyncWriteExt;

use crate::daemon::{Daemon, PairState};
use crate::guardians::{HelpCode, ASK, PROPOSAL, RECOVER, REFUSED, TAKEN};
use crate::net::{self, Access};

/// A recovery under way on this device.
#[derive(Serialize, Deserialize)]
struct Under {
    /// The new recovery words.
    words: String,
    /// The identity (hex).
    identity: String,
    /// The signed `recover` (hex), once there is one.
    entry: Option<String>,
}

fn load(d: &Daemon) -> Option<Under> {
    let b = std::fs::read(d.paths.recovering()).ok()?;
    serde_json::from_slice(&b).ok()
}

fn save(d: &Daemon, u: &Under) -> anyhow::Result<()> {
    crate::paths::write_private(&d.paths.recovering(), &serde_json::to_vec(u)?, 0o600)?;
    Ok(())
}

fn phrase_of(u: &Under) -> anyhow::Result<RecoveryPhrase> {
    RecoveryPhrase::parse(&u.words).map_err(|e| anyhow::anyhow!("the recovery under way: {e}"))
}

fn the_fingerprint(d: &Daemon, phrase: &RecoveryPhrase) -> String {
    fingerprint(
        &phrase.root_signing_key().public_key(),
        Some(d.keys.link.public_key()),
    )
}

/// `cardinal recover`: what is under way on this device.
pub fn status(d: &Daemon) -> anyhow::Result<Json> {
    let Some(u) = load(d) else {
        return Ok(json!({"under_way": false}));
    };
    let phrase = phrase_of(&u)?;
    Ok(json!({
        "under_way": true,
        "identity": u.identity,
        "asked": u.entry.is_some(),
        "fingerprint": the_fingerprint(d, &phrase),
    }))
}

/// Dials a guardian's device with a help code.
async fn reach(d: &Arc<Daemon>, code: &HelpCode) -> anyhow::Result<Session> {
    let mut last = anyhow::anyhow!("the help code names no address");
    for addr in &code.addrs {
        let target = |c: CarrierKind| {
            Target::invitation(*addr, c, code.static_key, &code.secret)
                .within(Duration::from_secs(5))
        };
        match d.dial(target).await {
            Ok(s) => return Ok(s),
            Err(e) => {
                last = anyhow::anyhow!("could not reach the guardian's device at {addr} ({e})")
            }
        }
    }
    Err(last)
}

async fn ask(s: &Session, msg: Record) -> anyhow::Result<Record> {
    let mut st = s.open_stream(crate::guardians::service(), Priority::Interactive)?;
    st.send_message(&Value::Record(msg)).await?;
    let reply = tokio::time::timeout(Duration::from_secs(30), st.recv_message_max(256 * 1024))
        .await
        .map_err(|_| anyhow::anyhow!("the guardian's device did not answer"))??
        .ok_or_else(|| anyhow::anyhow!("the guardian's device closed the connection"))?;
    let _ = st.shutdown().await;
    let r = reply
        .as_record()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("the guardian's device sent something unexpected"))?;
    if r.get(0).and_then(Value::as_uint) == Some(REFUSED) {
        let why = r
            .get(1)
            .and_then(Value::as_text)
            .unwrap_or("no reason given");
        anyhow::bail!("the guardian's device said no: {why}");
    }
    Ok(r)
}

/// `cardinal recover start CODE`: asks the guardian's device the code
/// names to take this device's `recover`. `host` is the address and key of
/// a host on the recovery sheet, kept by the recovery.
pub async fn via(d: &Arc<Daemon>, code: &str, host_key: Option<&str>) -> anyhow::Result<Json> {
    if d.core().identity.is_some() {
        anyhow::bail!("this device already belongs to someone. Nothing was changed.");
    }
    let code = HelpCode::from_text(code).ok_or_else(|| {
        anyhow::anyhow!(
            "that is not a help code; it starts with {}",
            crate::guardians::HELP_PREFIX
        )
    })?;
    let keep_link = match host_key {
        Some(k) => Some(crate::host::read_sheet_key(k).ok_or_else(|| {
            anyhow::anyhow!("that key does not check out; a character was probably mistyped")
        })?),
        None => None,
    };
    let mut under = match load(d) {
        Some(u) => {
            anyhow::ensure!(
                u.identity == hex::encode(code.identity),
                "this device is recovering someone else; that code is for another person"
            );
            u
        }
        None => Under {
            words: RecoveryPhrase::generate().to_words().to_string(),
            identity: hex::encode(code.identity),
            entry: None,
        },
    };
    save(d, &under)?;
    let phrase = phrase_of(&under)?;
    let s = reach(d, &code).await?;
    let entry = match &under.entry {
        Some(hex) => hex::decode(hex)?,
        None => {
            let p = ask(&s, Record::new().with(0, ASK)).await?;
            anyhow::ensure!(
                p.get(0).and_then(Value::as_uint) == Some(PROPOSAL),
                "the guardian's device sent something unexpected"
            );
            anyhow::ensure!(
                p.bytes_n::<32>(1).ok() == Some(code.identity),
                "the guardian's device proposed someone else's recovery"
            );
            let parents: Vec<EntryId> = p
                .list(2)?
                .iter()
                .filter_map(|v| v.as_bytes().and_then(|b| b.try_into().ok()))
                .collect();
            let policy: EntryId = p.bytes_n(3)?;
            // keep the host on the sheet: it is still the person's
            let keep: Vec<KeyId> = p
                .list(4)?
                .iter()
                .filter_map(|v| {
                    let r = v.as_record()?;
                    let key: KeyId = r.bytes_n(1).ok()?;
                    let link: [u8; 32] = r.bytes_n(2).ok()?;
                    (Some(link) == keep_link).then_some(key)
                })
                .collect();
            anyhow::ensure!(
                keep_link.is_none() || !keep.is_empty(),
                "the host with that key is not one of your devices any more"
            );
            let root = phrase.root_signing_key();
            let e = recover_entry(
                &code.identity,
                &parents,
                &root,
                &keep,
                d.keys.link.public_key(),
                policy,
                phrase.recovery_key_pair().public_key(),
            )?;
            e.encode()
        }
    };
    let r = ask(&s, Record::new().with(0, RECOVER).with(1, entry.clone())).await?;
    anyhow::ensure!(
        r.get(0).and_then(Value::as_uint) == Some(TAKEN),
        "the guardian's device sent something unexpected"
    );
    s.close("done");
    under.entry = Some(hex::encode(&entry));
    save(d, &under)?;
    Ok(json!({"fingerprint": the_fingerprint(d, &phrase)}))
}

fn recover_entry(
    identity: &EntryId,
    parents: &[EntryId],
    root: &cardinal_crypto::SigningKey,
    keep: &[KeyId],
    link: &HybridPublicKey,
    policy: EntryId,
    recovery_key: &HybridPublicKey,
) -> anyhow::Result<IdentityEntry> {
    Ok(EntryBuilder::new(*identity, parents)
        .op(IdentityOp::recover(
            root.public_key(),
            keep,
            link,
            policy,
            recovery_key,
        ))
        .sign(root)?)
}

/// `cardinal recover finish --host ADDR --key KEY`: becomes the person's
/// device, through a host, once the recovery is in effect there.
pub async fn finish(d: &Arc<Daemon>, at: &str, key: &str) -> anyhow::Result<Json> {
    if d.core().identity.is_some() {
        anyhow::bail!("this device already belongs to someone. Nothing was changed.");
    }
    let under = load(d).ok_or_else(|| {
        anyhow::anyhow!("no recovery is under way here; start one with a guardian's help code")
    })?;
    let phrase = phrase_of(&under)?;
    let root = phrase.root_signing_key();
    let identity: [u8; 32] = hex::decode(&under.identity)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("the recovery under way is damaged"))?;
    let (s, addr, host, host_key) = crate::host::open_restore(d, at, key).await?;
    let proven = crate::host::send_proof(&s, &root).await?;
    if proven != Some(identity) {
        s.close("not yet");
        anyhow::bail!(
            "that host does not know this device as yours yet: your guardians have not all \
             confirmed the recovery, or their confirmations have not reached it. Try again \
             later."
        );
    }
    *d.pairing.lock().unwrap_or_else(|e| e.into_inner()) = PairState::Joining {
        identity,
        admin_static: host,
        admin_name: at.to_owned(),
        admin_key: host_key,
        admin_addr: Some(addr),
    };
    d.on_session(s.clone());
    let label = identity_log_label(&identity);
    net::reconcile(d, &s, label).await?;
    let log = d
        .core()
        .joining_log(&identity)
        .ok_or_else(|| anyhow::anyhow!("that device did not send the identity log"))?;
    let keys = d.keys.clone();
    let entries =
        tokio::task::spawn_blocking(move || crate::core::recovered_entries(log, &keys, &root))
            .await??;
    for (entry, id) in &entries {
        net::deliver(&s, label, entry.clone(), *id).await?;
    }
    d.ingest(
        label,
        entries.into_iter().map(|(e, _)| e).collect(),
        Access::Join(identity),
    )?;
    let _ = std::fs::remove_file(d.paths.recovering());
    Ok(json!({"at": at, "words": under.words}))
}

/// `cardinal keep-work [NAME]`: keeps what removed devices wrote that no
/// device of this person built on before the removal, as after a recovery
/// that kept none of their keys. NAME, as the account space names the
/// device, limits it to that one.
pub fn keep_work(d: &Arc<Daemon>, name: Option<&str>) -> anyhow::Result<Json> {
    let only: Option<Vec<KeyId>> = match name {
        None => None,
        Some(n) => {
            let w = n.trim().to_lowercase();
            let keys: Vec<KeyId> = d
                .core()
                .device_names()
                .into_iter()
                .filter(|(k, v)| v.to_lowercase() == w || hex::encode(k).starts_with(&w))
                .map(|(k, _)| k)
                .collect();
            anyhow::ensure!(!keys.is_empty(), "no device was called {n:?}");
            Some(keys)
        }
    };
    let (written, kept) = d.core().keep_work(only.as_deref())?;
    for (space, bytes) in written {
        d.push(&space, vec![bytes]);
    }
    d.bump();
    Ok(json!({"kept": kept}))
}
