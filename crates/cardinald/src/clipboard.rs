//! A clipboard shared between this person's own devices (Basics,
//! `basics/clipboard.md`, a draft): what is copied on one can be pasted on
//! the others for a few minutes. It is an ephemeral message
//! (`spaces.md#ephemeral-messages`) labeled with the account space, whose
//! only members are this person's devices, so nobody else is sent it and
//! nothing of it is stored: spaces only grow, and every copy would be kept.
//!
//! The message is `{0: name, 1: account space id, 2: text, 3: time}`, time
//! in milliseconds since 1970. Its name is the document's hash once
//! published; until then the clients agree on [`DRAFT`].

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cardinal_encoding::{Record, Value};
use cardinal_link::{Priority, Service, Session};
use serde_json::{json, Value as Json};
use tokio::io::AsyncWriteExt;

use crate::daemon::{Daemon, PeerKind};

/// The most text a copy carries: what goes on a clipboard by hand, not files.
pub const MAX_TEXT: usize = 64 * 1024;

/// How long a copy can be pasted elsewhere.
pub const KEEP: Duration = Duration::from_secs(10 * 60);

/// What names a clipboard message until the document is published.
pub fn draft_name() -> [u8; 32] {
    cardinal_crypto::hash(b"cardinal basics clipboard, draft 1")
}

/// The last thing copied on any of this person's devices.
#[derive(Clone, Debug)]
pub struct Clip {
    pub text: String,
    /// The device it was copied on.
    pub from: String,
    pub at: u64,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Whether an ephemeral message is a clipboard's: its first field names it.
pub fn is_clip(v: &Value) -> bool {
    v.as_record()
        .and_then(|r| r.get(0))
        .and_then(|n| n.as_bytes())
        .is_some_and(|n| n == draft_name())
}

fn account_id(d: &Daemon) -> Option<cardinal_space::SpaceId> {
    d.core().account().map(|h| h.id)
}

/// What this person's devices call one of theirs, by its signing key.
fn device_named(d: &Daemon, key: &[u8; 32]) -> String {
    let names = d.core().device_names();
    names
        .get(key)
        .cloned()
        .unwrap_or_else(|| cardinal_space::account::short_key(key))
}

/// This device's name, as its person's devices list it.
fn this_device(d: &Daemon) -> String {
    d.config
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .name
        .clone()
}

/// Copies `text` to this person's other devices that are online, and keeps
/// it here too.
pub async fn copy(d: &Arc<Daemon>, text: &str) -> anyhow::Result<Json> {
    anyhow::ensure!(!text.is_empty(), "nothing to copy");
    anyhow::ensure!(
        text.len() <= MAX_TEXT,
        "too much for the clipboard: {} KiB at most; share a file instead",
        MAX_TEXT / 1024
    );
    let space =
        account_id(d).ok_or_else(|| anyhow::anyhow!("this device belongs to nobody yet"))?;
    let at = now_ms();
    *d.clip.lock().unwrap_or_else(|e| e.into_inner()) = Some(Clip {
        text: text.to_owned(),
        from: this_device(d),
        at,
    });
    let message = Record::new()
        .with(0, draft_name())
        .with(1, space)
        .with(2, text.as_bytes().to_vec())
        .with(3, at);
    let mut sent = 0;
    for s in d.own_sessions() {
        if send(&s, &message).await.is_ok() {
            sent += 1;
        }
    }
    Ok(json!({"devices": sent}))
}

async fn send(s: &Session, message: &Record) -> anyhow::Result<()> {
    let mut st = s.open_stream(Service::EPHEMERAL, Priority::Interactive)?;
    st.send_message(&Value::Record(message.clone())).await?;
    st.shutdown().await?;
    Ok(())
}

/// The last copy on any of this person's devices, while it can be pasted.
pub fn paste(d: &Daemon) -> Json {
    let clip = d.clip.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let now = now_ms();
    match clip.filter(|c| now.saturating_sub(c.at) <= KEEP.as_millis() as u64) {
        Some(c) => {
            json!({"text": c.text, "from": c.from, "seconds": now.saturating_sub(c.at) / 1000})
        }
        None => json!({"text": null}),
    }
}

/// A copy from another of this person's devices. Anyone else's is not
/// taken, nor one for another space, nor one too large.
pub fn take(d: &Daemon, s: &Session, v: &Value) {
    let PeerKind::Own(key) = d.classify(s) else {
        return;
    };
    let from = device_named(d, &key);
    let Some(r) = v.as_record() else { return };
    let space = r.get(1).and_then(|x| x.as_bytes());
    if space.is_none() || space != account_id(d).as_ref().map(|a| &a[..]) {
        return;
    }
    let Some(text) = r.get(2).and_then(|x| x.as_bytes()) else {
        return;
    };
    if text.len() > MAX_TEXT {
        return;
    }
    let Ok(text) = String::from_utf8(text.to_vec()) else {
        return;
    };
    // Its own time, unless that is ahead of this device's: then now.
    let now = now_ms();
    let at = r.get(3).and_then(|x| x.as_uint()).unwrap_or(now).min(now);
    let mut clip = d.clip.lock().unwrap_or_else(|e| e.into_inner());
    // Two copies at once on two devices: the later wins everywhere.
    if clip.as_ref().is_some_and(|c| c.at > at) {
        return;
    }
    *clip = Some(Clip { text, from, at });
    drop(clip);
    d.bump();
}
