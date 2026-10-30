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

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cardinal_encoding::Value;
use cardinal_link::{Priority, Service, Session, Stream};
use cardinal_sync::{
    identity_log_label, want_messages, BlobReply, BlobRequest, Label, MemSet, Message, Reconciler,
};
use tokio::io::AsyncWriteExt;

use crate::core::{short, SetExt};
use crate::daemon::{Daemon, PeerKind};
use crate::sched::{PeerStats, Scheduler};

/// Pushed entries larger than this travel as `heads` (`sync.md#when-to-sync`).
const PUSH_LIMIT: usize = 900;
/// Largest message accepted on a stream.
const MAX_MESSAGE: usize = 48 * 1024 * 1024;
/// How long one request may take.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
/// How long one blob request (at most 4 MiB) may take before it is
/// retried.
const BLOB_TIMEOUT: Duration = Duration::from_secs(20);

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
    if st.service() == crate::speedtest::service() && crate::speedtest::offered() {
        return crate::speedtest::serve(d, s, st).await;
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
        Message::Heads { label, ids } => {
            if d.access(kind, &label) == Access::Full {
                let (missing, waiting): (Vec<[u8; 32]>, bool) = {
                    let core = d.core();
                    let missing = ids.into_iter().filter(|i| !core.has(&label, i)).collect();
                    (missing, core.is_waiting(&label))
                };
                if !missing.is_empty() {
                    fetch_objects(d, s, label, missing, Access::Full).await?;
                } else if waiting {
                    // this peer may have what was missing by now
                    reconcile(d, s, label).await?;
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
    d.pass_on(label, outcome.complete, outcome.objects, s.peer_static());
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

/// Sends one peer a notice (`sync.md#notices`): the objects, if there are
/// any and they are small, else the heads.
pub async fn notice(
    s: &Session,
    label: Label,
    objects: &[Vec<u8>],
    heads: Vec<[u8; 32]>,
) -> anyhow::Result<()> {
    let total: usize = objects.iter().map(|e| e.len()).sum();
    let msg = if !objects.is_empty() && total <= PUSH_LIMIT {
        Message::Objects {
            label,
            objects: objects.to_vec(),
        }
    } else {
        Message::Heads { label, ids: heads }
    };
    let mut st = s.open_stream(Service::SYNC, Priority::Interactive)?;
    st.send_message(&to_value(&msg)).await?;
    st.shutdown().await?;
    Ok(())
}

/// For tests: `CARDINAL_TEST_BLOB_DELAY_MS` delays every blob reply this
/// daemon sends, one reply at a time and in proportion to its size, to
/// stand in for a slow link (the delay is per MiB; a reply is typically
/// about 1 MiB, an index or a "not held" much less).
fn test_blob_delay() -> Option<u64> {
    static DELAY: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
    *DELAY.get_or_init(|| {
        std::env::var("CARDINAL_TEST_BLOB_DELAY_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|ms| *ms > 0)
    })
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
    let bytes = tokio::task::spawn_blocking(move || reply.encode()).await?;
    if let Some(ms) = test_blob_delay() {
        static SLOW_LINK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
        let _one_at_a_time = SLOW_LINK.lock().await;
        let mib = bytes.len() as f64 / (1 << 20) as f64;
        tokio::time::sleep(Duration::from_secs_f64(ms as f64 / 1000.0 * mib)).await;
    }
    st.send_message_bytes(&bytes).await?;
    st.shutdown().await?;
    tracing::trace!("blob stream {} served {} bytes", st.id(), bytes.len());
    Ok(())
}

/// Asks one device for objects on the `blob` service: one request, one
/// reply. Used by fetches and by copy checks alike.
pub(crate) async fn blob_request(
    s: &Session,
    ids: Vec<[u8; 32]>,
    priority: Priority,
) -> anyhow::Result<BlobReply> {
    let req = BlobRequest { ids };
    let mut st = s.open_stream(Service::BLOB, priority)?;
    st.send_message(&cardinal_encoding::decode(&req.encode())?)
        .await?;
    st.shutdown().await?;
    tracing::trace!("blob request on stream {}", st.id());
    let body = tokio::time::timeout(BLOB_TIMEOUT, st.recv_message_bytes_max(MAX_MESSAGE))
        .await
        .map_err(|_| anyhow::anyhow!("timed out"))??
        .ok_or_else(|| anyhow::anyhow!("no reply"))?;
    Ok(BlobReply::decode(&body)?)
}

/// Fetches chunks and indexes from this person's online devices. Returns
/// what was found; ids no device holds are left out.
pub async fn fetch_blobs(
    d: &Arc<Daemon>,
    ids: &[[u8; 32]],
    priority: Priority,
) -> Vec<([u8; 32], Vec<u8>)> {
    let mut f = BlobFetch::new(d.clone(), priority);
    let mut seen = HashSet::new();
    for id in ids {
        if seen.insert(*id) {
            f.push(*id);
        }
    }
    let mut out = Vec::new();
    while let Some(ev) = f.next().await {
        if let BlobEvent::Got(items) = ev {
            out.extend(items);
        }
    }
    out
}

/// What [`BlobFetch::next`] reports.
#[derive(Debug)]
pub enum BlobEvent {
    /// Objects received, verified against their ids.
    Got(Vec<([u8; 32], Vec<u8>)>),
    /// Ids that no online device holds (or that every device holding them
    /// failed to send).
    Unavailable(Vec<[u8; 32]>),
}

/// A finished request.
struct BlobDone {
    request: u64,
    peer: [u8; 32],
    result: anyhow::Result<BlobReply>,
}

/// Fetches blob objects from all online devices at once, following
/// [`crate::sched::Scheduler`]: work goes to the devices that are fast
/// now, objects one device lacks are asked of the others at once, and
/// slow requests are hedged. Ids can be added while it runs, so a caller
/// can keep the link busy across files. Per-device estimates live in the
/// daemon and carry over between fetches.
pub struct BlobFetch {
    d: Arc<Daemon>,
    priority: Priority,
    sched: Scheduler,
    sessions: HashMap<[u8; 32], Session>,
    peers_checked: Option<Instant>,
    inflight: tokio::task::JoinSet<BlobDone>,
    ready: VecDeque<BlobEvent>,
}

impl BlobFetch {
    /// An empty fetch at `priority`.
    pub fn new(d: Arc<Daemon>, priority: Priority) -> BlobFetch {
        BlobFetch {
            d,
            priority,
            sched: Scheduler::new(),
            sessions: HashMap::new(),
            peers_checked: None,
            inflight: tokio::task::JoinSet::new(),
            ready: VecDeque::new(),
        }
    }

    /// Adds an id to fetch, after those added before.
    pub fn push(&mut self, id: [u8; 32]) {
        self.sched.push(id);
    }

    /// Adds an id to fetch, before those of a higher rank.
    pub fn push_ranked(&mut self, id: [u8; 32], rank: crate::sched::Rank) {
        self.sched.push_ranked(id, rank);
    }

    /// Ids wanted and not received yet.
    pub fn wanted(&self) -> usize {
        self.sched.wanted()
    }

    /// Requests in flight.
    pub fn in_flight(&self) -> usize {
        self.inflight.len()
    }

    /// Whether [`next`](Self::next) has nothing left to report.
    pub fn is_idle(&self) -> bool {
        self.sched.is_idle() && self.inflight.is_empty() && self.ready.is_empty()
    }

    fn refresh_peers(&mut self) {
        if self
            .peers_checked
            .is_some_and(|t| t.elapsed() < Duration::from_millis(500))
        {
            return;
        }
        self.peers_checked = Some(Instant::now());
        let sessions = self.d.own_sessions();
        let stats = self.d.blob_stats.lock().unwrap_or_else(|e| e.into_inner());
        let peers: Vec<([u8; 32], PeerStats)> = sessions
            .iter()
            .map(|s| {
                let k = s.peer_static();
                (k, stats.get(&k).copied().unwrap_or_default())
            })
            .collect();
        drop(stats);
        self.sched.set_peers(&peers);
        self.sessions = sessions.into_iter().map(|s| (s.peer_static(), s)).collect();
    }

    fn start_requests(&mut self) {
        self.refresh_peers();
        for r in self.sched.poll(Instant::now()) {
            let Some(s) = self.sessions.get(&r.peer).cloned() else {
                self.sched.failed(r.id, Instant::now());
                continue;
            };
            if r.hedge {
                tracing::debug!(
                    "asking {} too for {} objects (slow request)",
                    short(&r.peer),
                    r.ids.len()
                );
            }
            let priority = self.priority;
            self.inflight.spawn(async move {
                let result = blob_request(&s, r.ids, priority).await;
                BlobDone {
                    request: r.id,
                    peer: r.peer,
                    result,
                }
            });
        }
        let gone = self.sched.take_unavailable();
        if !gone.is_empty() {
            self.ready.push_back(BlobEvent::Unavailable(gone));
        }
    }

    fn done(&mut self, r: BlobDone) {
        let now = Instant::now();
        let mut received = 0;
        match r.result {
            Ok(reply) => {
                let got = reply.verified();
                let ids: Vec<[u8; 32]> = got.iter().map(|(i, _)| *i).collect();
                let bytes: u64 = got.iter().map(|(_, b)| b.len() as u64).sum();
                received = bytes;
                let out = self.sched.reply(r.request, &ids, bytes, now);
                let keep: HashSet<[u8; 32]> = out.accepted.into_iter().collect();
                let got: Vec<_> = got.into_iter().filter(|(i, _)| keep.contains(i)).collect();
                if !got.is_empty() {
                    self.ready.push_back(BlobEvent::Got(got));
                }
            }
            Err(e) => {
                tracing::debug!("blob request to {}: {e:#}", short(&r.peer));
                self.sched.failed(r.request, now);
            }
        }
        if let Some(mut st) = self.sched.stats(&r.peer) {
            let mut all = self.d.blob_stats.lock().unwrap_or_else(|e| e.into_inner());
            // Estimates are this fetch's latest; the total adds up every
            // fetch's replies (several run at once, each with its own copy).
            st.bytes_total = all.get(&r.peer).map_or(0, |s| s.bytes_total) + received;
            all.insert(r.peer, st);
        }
    }

    /// The next objects received, or ids found unavailable; `None` once
    /// everything pushed has been reported.
    pub async fn next(&mut self) -> Option<BlobEvent> {
        loop {
            if let Some(ev) = self.ready.pop_front() {
                return Some(ev);
            }
            self.start_requests();
            if let Some(ev) = self.ready.pop_front() {
                return Some(ev);
            }
            if self.inflight.is_empty() {
                if self.sched.is_idle() {
                    return None;
                }
                // Devices that may have the rest are busy or gone: look
                // again shortly.
                self.peers_checked = None;
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            let deadline = self
                .sched
                .next_deadline()
                .unwrap_or_else(|| Instant::now() + Duration::from_secs(1))
                .max(Instant::now() + Duration::from_millis(5));
            tokio::select! {
                r = self.inflight.join_next() => match r {
                    Some(Ok(r)) => self.done(r),
                    Some(Err(e)) => tracing::debug!("blob request task: {e}"),
                    None => {}
                },
                _ = tokio::time::sleep_until(deadline.into()) => {}
            }
        }
    }
}

/// Whether a set holds every id.
pub fn holds_all(set: &MemSet, ids: &[[u8; 32]]) -> bool {
    ids.iter().all(|i| set.contains_id(i))
}
