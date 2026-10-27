//! Sessions with this person's other devices, and the `sync` and `blob`
//! services over them (`sync.md`).
//!
//! Every request opens its own stream. The opener's first message names
//! the conversation:
//!
//! - `reconcile`: a dialogue on the stream until a side's message holds
//!   only skips; each side then fetches what it lacks with `want`.
//! - `want`: answered with `objects` messages, then the stream ends.
//! - `objects`: pushed after a write (entries under 900 bytes).
//! - `heads`: pushed after a write; the receiver wants what it lacks.
//!
//! On the `blob` service, one request and one reply per stream.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use cardinal_encoding::Value;
use cardinal_link::{Priority, Service, Session, Stream};
use cardinal_sync::{
    identity_log_label, want_messages, BlobReply, BlobRequest, Label, MemSet, Message, Reconciler,
};
use tokio::io::AsyncWriteExt;

use crate::core::{short, SetExt};
use crate::daemon::{Daemon, PeerKind};

/// Pushed entries larger than this travel as `heads` (`sync.md#when-to-sync`).
const PUSH_LIMIT: usize = 900;
/// Largest message accepted on a stream.
const MAX_MESSAGE: usize = 48 * 1024 * 1024;
/// Ids per blob request: 16 chunks of at most 256 KiB.
const BLOB_BATCH: usize = 16;
/// Blob requests in flight per peer.
const BLOB_PARALLEL: usize = 4;
/// How long one request may take.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
/// How long one blob request (at most 4 MiB) may take before it is
/// retried.
const BLOB_TIMEOUT: Duration = Duration::from_secs(20);
/// Rounds over the online devices before giving up on some ids.
const BLOB_ROUNDS: usize = 3;

fn to_value(m: &Message) -> Value {
    Value::Record(m.to_record())
}

fn from_value(v: Value) -> anyhow::Result<Message> {
    match v {
        Value::Record(r) => Ok(Message::from_record(&r)?),
        _ => anyhow::bail!("a sync message must be a record"),
    }
}

/// What a peer may do with a label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// One of this person's devices: everything.
    Full,
    /// The admin device this device just paired with: only its identity
    /// log, which this device is about to join.
    Join([u8; 32]),
    /// Nothing; answer as if the set were empty.
    None,
}

impl Daemon {
    /// What `kind` may do with `label`.
    pub fn access(&self, kind: PeerKind, label: &Label) -> Access {
        match kind {
            PeerKind::Own(_) => {
                if self.core().identity.is_some() {
                    Access::Full
                } else {
                    Access::None
                }
            }
            PeerKind::PairingAdmin(identity) => {
                if *label == identity_log_label(&identity) {
                    Access::Join(identity)
                } else {
                    Access::None
                }
            }
            PeerKind::Stranger => Access::None,
        }
    }
}

/// Serves the streams a peer opens, until the session closes.
pub async fn serve(d: Arc<Daemon>, s: Session, gen: u64) {
    let mut periodic = tokio::time::interval(Duration::from_secs(180));
    periodic.tick().await;
    loop {
        tokio::select! {
            st = s.accept_stream() => {
                let Some(st) = st else { break };
                let d2 = d.clone();
                let s2 = s.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_stream(&d2, &s2, st).await {
                        tracing::debug!("stream from {}: {e:#}", short(&s2.peer_static()));
                    }
                });
            }
            _ = periodic.tick() => {
                let d2 = d.clone();
                let s2 = s.clone();
                tokio::spawn(async move { sync_all(&d2, &s2).await });
            }
        }
    }
    d.session_closed(&s.peer_static(), gen);
}

/// Reconciles every set with a peer: identity log first, then spaces.
pub async fn sync_all(d: &Arc<Daemon>, s: &Session) {
    let labels = d.core().labels();
    for label in labels {
        if let Err(e) = reconcile(d, s, label).await {
            tracing::debug!(
                "reconcile {} with {}: {e:#}",
                short(&label),
                short(&s.peer_static())
            );
        }
    }
}

async fn handle_stream(d: &Arc<Daemon>, s: &Session, mut st: Stream) -> anyhow::Result<()> {
    if st.service() == Service::BLOB {
        tracing::trace!("blob stream {} accepted", st.id());
        return serve_blob(d, st).await;
    }
    let kind = d.classify(s);
    if st.service() != Service::SYNC {
        st.reset(0);
        return Ok(());
    }
    let Some(v) = st.recv_message_max(MAX_MESSAGE).await? else {
        return Ok(());
    };
    match from_value(v)? {
        Message::Reconcile { label, ranges } => {
            let access = d.access(kind, &label);
            let set = if access == Access::None {
                MemSet::new()
            } else {
                d.core().set(&label)
            };
            let mut rec = Reconciler::new(label, set);
            let mut ranges = ranges;
            let mut rounds = 0u32;
            while let Some(reply) = rec.receive(&ranges)? {
                st.send_message(&to_value(&reply)).await?;
                if rec.is_done() {
                    break;
                }
                let Some(v) = st.recv_message_max(MAX_MESSAGE).await? else {
                    break;
                };
                match from_value(v)? {
                    Message::Reconcile { ranges: r, .. } => ranges = r,
                    _ => anyhow::bail!("expected reconcile"),
                }
                rounds += 1;
                if rounds > 100_000 {
                    anyhow::bail!("reconciliation does not end");
                }
            }
            let _ = st.shutdown().await;
            let wanted = rec.take_wanted();
            if access != Access::None && !wanted.is_empty() {
                fetch_objects(d, s, label, wanted, access).await?;
            }
        }
        Message::Want { label, ids } => {
            if d.access(kind, &label) == Access::Full {
                let msgs = {
                    let core = d.core();
                    cardinal_sync::answer_want(label, &ids, |id| core.get(&label, id))
                };
                for m in msgs {
                    st.send_message(&to_value(&m)).await?;
                }
            }
            let _ = st.shutdown().await;
        }
        Message::Objects { label, objects } => {
            let access = d.access(kind, &label);
            if access != Access::None {
                ingest(d, s, label, objects, access).await?;
            }
        }
        Message::Heads { space, ids } => {
            if d.access(kind, &space) == Access::Full {
                let missing: Vec<[u8; 32]> = {
                    let core = d.core();
                    ids.into_iter().filter(|i| !core.has(&space, i)).collect()
                };
                if !missing.is_empty() {
                    fetch_objects(d, s, space, missing, Access::Full).await?;
                }
            }
        }
    }
    Ok(())
}

/// Runs a reconciliation of `label` with a peer and fetches what this
/// side lacks. (Boxed: fetching can lead to another reconciliation.)
pub fn reconcile<'a>(
    d: &'a Arc<Daemon>,
    s: &'a Session,
    label: Label,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + 'a>> {
    Box::pin(reconcile_inner(d, s, label))
}

async fn reconcile_inner(d: &Arc<Daemon>, s: &Session, label: Label) -> anyhow::Result<()> {
    let kind = d.classify(s);
    let access = d.access(kind, &label);
    if access == Access::None {
        return Ok(());
    }
    let set = d.core().set(&label);
    let mut rec = Reconciler::new(label, set);
    let mut st = s.open_stream(Service::SYNC, Priority::Background)?;
    st.send_message(&to_value(&rec.initiate())).await?;
    let mut rounds = 0u32;
    while !rec.is_done() {
        let Some(v) = tokio::time::timeout(REQUEST_TIMEOUT, st.recv_message_max(MAX_MESSAGE))
            .await
            .map_err(|_| anyhow::anyhow!("timed out"))??
        else {
            break;
        };
        let Message::Reconcile { ranges, .. } = from_value(v)? else {
            anyhow::bail!("expected reconcile");
        };
        match rec.receive(&ranges)? {
            Some(reply) => st.send_message(&to_value(&reply)).await?,
            None => break,
        }
        rounds += 1;
        if rounds > 100_000 {
            anyhow::bail!("reconciliation does not end");
        }
    }
    let _ = st.shutdown().await;
    let wanted = rec.take_wanted();
    if !wanted.is_empty() {
        tracing::debug!(
            "reconcile {}: fetching {} from {}",
            short(&label),
            wanted.len(),
            short(&s.peer_static())
        );
        fetch_objects(d, s, label, wanted, access).await?;
    }
    Ok(())
}

/// Fetches objects of a set by id with `want`, and ingests them.
pub async fn fetch_objects(
    d: &Arc<Daemon>,
    s: &Session,
    label: Label,
    ids: Vec<[u8; 32]>,
    access: Access,
) -> anyhow::Result<()> {
    let wanted: HashSet<[u8; 32]> = ids.iter().copied().collect();
    let mut got: Vec<Vec<u8>> = Vec::new();
    for msg in want_messages(label, &ids) {
        let mut st = s.open_stream(Service::SYNC, Priority::Background)?;
        st.send_message(&to_value(&msg)).await?;
        let _ = st.shutdown().await;
        loop {
            let v = tokio::time::timeout(REQUEST_TIMEOUT, st.recv_message_max(MAX_MESSAGE))
                .await
                .map_err(|_| anyhow::anyhow!("timed out"))??;
            let Some(v) = v else { break };
            if let Message::Objects { objects, .. } = from_value(v)? {
                got.extend(objects);
            }
        }
    }
    // Check every object against the ids asked for.
    let is_identity = matches!(access, Access::Join(_)) || Some(label) == d.core().identity_label();
    got.retain(|b| {
        let id = if is_identity {
            match cardinal_identity::IdentityEntry::decode(b) {
                Ok(e) => e.id(),
                Err(_) => return false,
            }
        } else {
            *blake3::hash(b).as_bytes()
        };
        wanted.contains(&id)
    });
    if !got.is_empty() {
        ingest(d, s, label, got, access).await?;
    }
    Ok(())
}

/// Ingests objects of a set from a peer.
async fn ingest(
    d: &Arc<Daemon>,
    s: &Session,
    label: Label,
    objects: Vec<Vec<u8>>,
    access: Access,
) -> anyhow::Result<()> {
    let d2 = d.clone();
    let outcome = tokio::task::spawn_blocking(move || d2.ingest(label, objects, access)).await??;
    if outcome.missing_parents {
        let d2 = d.clone();
        let s2 = s.clone();
        tokio::spawn(async move {
            if let Err(e) = reconcile(&d2, &s2, label).await {
                tracing::debug!("reconcile for missing parents: {e:#}");
            }
        });
    }
    Ok(())
}

/// Sends new entries of a space to one peer: the entries themselves if
/// small, else the heads.
pub async fn push_space(
    s: &Session,
    space: [u8; 32],
    entries: &[Vec<u8>],
    heads: Vec<[u8; 32]>,
) -> anyhow::Result<()> {
    let total: usize = entries.iter().map(|e| e.len()).sum();
    let msg = if total <= PUSH_LIMIT {
        Message::Objects {
            label: space,
            objects: entries.to_vec(),
        }
    } else {
        Message::Heads { space, ids: heads }
    };
    let mut st = s.open_stream(Service::SYNC, Priority::Background)?;
    st.send_message(&to_value(&msg)).await?;
    st.shutdown().await?;
    Ok(())
}

/// Sends identity entries to one peer.
pub async fn push_identity(s: &Session, label: Label, entries: Vec<Vec<u8>>) -> anyhow::Result<()> {
    for m in cardinal_sync::objects_messages(label, entries) {
        let mut st = s.open_stream(Service::SYNC, Priority::Background)?;
        st.send_message(&to_value(&m)).await?;
        st.shutdown().await?;
    }
    Ok(())
}

async fn serve_blob(d: &Arc<Daemon>, mut st: Stream) -> anyhow::Result<()> {
    let Some(v) = st.recv_message_max(1 << 20).await? else {
        return Ok(());
    };
    let req = BlobRequest::decode(&v.encode())?;
    tracing::trace!("serving {} blob objects", req.ids.len());
    let store = d.store.clone();
    let reply = tokio::task::spawn_blocking(move || {
        req.serve(|id| {
            use cardinal_blob::ObjectStore;
            store.get(id).ok().flatten()
        })
    })
    .await?;
    let bytes = reply.encode();
    let v = cardinal_encoding::decode(&bytes)?;
    st.send_message(&v).await?;
    st.shutdown().await?;
    tracing::trace!("blob stream {} served {} bytes", st.id(), bytes.len());
    Ok(())
}

async fn blob_request(
    s: &Session,
    ids: Vec<[u8; 32]>,
    priority: Priority,
) -> anyhow::Result<Vec<([u8; 32], Vec<u8>)>> {
    let req = BlobRequest { ids };
    let mut st = s.open_stream(Service::BLOB, priority)?;
    st.send_message(&cardinal_encoding::decode(&req.encode())?)
        .await?;
    st.shutdown().await?;
    tracing::trace!("blob request on stream {}", st.id());
    let v = tokio::time::timeout(BLOB_TIMEOUT, st.recv_message_max(MAX_MESSAGE))
        .await
        .map_err(|_| anyhow::anyhow!("timed out"))??
        .ok_or_else(|| anyhow::anyhow!("no reply"))?;
    let reply = BlobReply::decode(&v.encode())?;
    let got = reply.verified();
    tracing::trace!("got {} blob objects", got.len());
    Ok(got)
}

/// Fetches chunks and indexes from this person's online devices. Returns
/// what was found; ids no device holds are left out.
pub async fn fetch_blobs(
    d: &Arc<Daemon>,
    ids: &[[u8; 32]],
    priority: Priority,
) -> Vec<([u8; 32], Vec<u8>)> {
    let mut remaining: Vec<[u8; 32]> = {
        let mut seen = HashSet::new();
        ids.iter().filter(|i| seen.insert(**i)).copied().collect()
    };
    let mut out = Vec::new();
    for round in 0..BLOB_ROUNDS {
        let sessions = d.own_sessions();
        tracing::trace!(
            "fetching {} objects from {} devices (round {round})",
            remaining.len(),
            sessions.len()
        );
        let mut any_failed = false;
        for s in sessions {
            if remaining.is_empty() {
                break;
            }
            let mut set = tokio::task::JoinSet::new();
            let mut batches = remaining.chunks(BLOB_BATCH).map(|c| c.to_vec());
            let mut failures = 0;
            loop {
                while set.len() < BLOB_PARALLEL && failures < 3 {
                    let Some(b) = batches.next() else { break };
                    let s2 = s.clone();
                    set.spawn(async move { blob_request(&s2, b, priority).await });
                }
                let Some(r) = set.join_next().await else {
                    break;
                };
                match r {
                    Ok(Ok(items)) => out.extend(items),
                    Ok(Err(e)) => {
                        tracing::debug!("blob request to {}: {e:#}", short(&s.peer_static()));
                        failures += 1;
                        any_failed = true;
                    }
                    Err(_) => {
                        failures += 1;
                        any_failed = true;
                    }
                }
            }
            let got: HashSet<[u8; 32]> = out.iter().map(|(i, _)| *i).collect();
            remaining.retain(|i| !got.contains(i));
        }
        if remaining.is_empty() || !any_failed {
            break;
        }
    }
    out
}

/// Whether a set holds every id.
pub fn holds_all(set: &MemSet, ids: &[[u8; 32]]) -> bool {
    ids.iter().all(|i| set.contains_id(i))
}
