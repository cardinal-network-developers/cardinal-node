//! Sessions with this person's other devices, and the `sync` and `blob`
//! services over them (`sync.md`).
//!
//! Every request opens its own stream. The opener's first message names
//! the conversation:
//!
//! - `reconcile`: a dialogue on the stream, in turns of one or more
//!   messages, until a side's turn holds only skips; each side fetches what
//!   it lacks with `want` as soon as it learns of it, spread across the
//!   peers reconciling the set at once.
//! - `summary`: on a long-delay link, the opener's short ids; answered with
//!   the objects it lacks, then a `reconcile` the answerer opens.
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
use cardinal_space::SpaceId;
use cardinal_sync::{
    identity_log_label, want_messages, BlobReply, BlobRequest, Label, MemSet, Message, Reconciler,
    SetStore,
};
use tokio::io::AsyncWriteExt;

use crate::core::{short, SetExt};
use crate::daemon::{Daemon, PeerKind};
use crate::sched::{PeerStats, Scheduler};

/// Pushed entries larger than this travel as `heads` (`sync.md#when-to-sync`).
const PUSH_LIMIT: usize = 900;
/// Largest message accepted on a stream.
const MAX_MESSAGE: usize = 48 * 1024 * 1024;
/// How many ids a reconcile with someone else's device may learn before this
/// side fetches them. The rest come with the next reconcile.
const MAX_WANTED: usize = 64 * 1024;
/// How many of a contact's streams are served at once. The rest wait their
/// turn, unread, so too many slow only that session.
const CONTACT_STREAMS: usize = 32;
/// The most a `fetch_objects` holds at once. What is left comes with the next
/// reconcile.
const MAX_FETCHED: usize = 64 * 1024 * 1024;
/// How long one request may take.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

pub(crate) fn to_value(m: &Message) -> Value {
    Value::Record(m.to_record())
}

pub(crate) fn from_value(v: Value) -> anyhow::Result<Message> {
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
    /// A contact's identity log: to be kept, not joined.
    Other([u8; 32]),
    /// What a delivery token is for, the one space and its owner's identity
    /// log: to fetch, and nothing more, since only the owner's devices may
    /// send a host objects.
    Read,
    /// A space a contact offered this person, not open here yet: what they
    /// send is taken, and nothing is given (`spaces.md#holding-a-space`).
    Offered,
    /// Nothing; answer as if the set were empty.
    None,
}

impl Access {
    /// Whether a peer may fetch objects of the set from this device.
    fn may_fetch(self) -> bool {
        matches!(self, Access::Full | Access::Other(_) | Access::Read)
    }

    /// Whether this device takes objects of the set from a peer.
    fn takes_objects(self) -> bool {
        !matches!(self, Access::None | Access::Read)
    }
}

/// What a token holder may do with `label`, if the token was given out in
/// `space`: fetch that space, and the log of the identity it belongs to,
/// without which what is written there cannot be judged, and which is no
/// secret. Nothing else.
fn token_access(space: Option<SpaceId>, owner_log: Option<Label>, label: &Label) -> Access {
    if space == Some(*label) || owner_log == Some(*label) {
        Access::Read
    } else {
        Access::None
    }
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
            PeerKind::Proven => {
                if self.core().identity_label() == Some(*label) {
                    Access::Full
                } else {
                    Access::None
                }
            }
            PeerKind::Contact(identity, device) => {
                let core = self.core();
                if *label == identity_log_label(&identity) {
                    Access::Other(identity)
                } else if Some(*label) == core.identity_label()
                    || core.shares(&identity, label)
                    || core.recovered_owns(&identity, &device, label)
                    || core.own_fallen_with(label).contains(&identity)
                {
                    Access::Full
                } else if core.held_given(&identity).contains(label) {
                    // a copy this person gives them to hold (D80)
                    Access::Read
                } else if core.held_taken(&identity).contains(label) {
                    // one they give this person to hold
                    Access::Offered
                } else if core.offered_here(&identity, label) {
                    Access::Offered
                } else if let Some(m) = core
                    .members_shared_with(&identity)
                    .into_iter()
                    .find(|m| identity_log_label(m) == *label)
                {
                    // Another member's log, for what they write to be judged.
                    Access::Other(m)
                } else {
                    Access::None
                }
            }
            // Not a contact yet, and possibly not who they say: this log to
            // read, and the one space made for this invitation. Theirs this
            // device fetches for itself, and nothing is taken unasked.
            PeerKind::Inviting(_, space) => {
                if Some(*label) == self.core().identity_label() {
                    Access::Read
                } else if space == Some(*label) {
                    Access::Full
                } else {
                    Access::None
                }
            }
            PeerKind::Token(token) => {
                let core = self.core();
                // a token serves what stands in place of its space, and
                // the space it was given in
                let space = core.space_of_token(&token);
                let serves = space.is_some_and(|s| core.current(label) == s);
                let space = if serves { Some(*label) } else { space };
                token_access(space, core.identity_label(), label)
            }
            PeerKind::Restoring | PeerKind::Stranger => Access::None,
        }
    }
}

/// Serves the streams a peer opens, until the session closes.
pub async fn serve(d: Arc<Daemon>, s: Session, gen: u64) {
    let mut periodic = tokio::time::interval(Duration::from_secs(180));
    periodic.tick().await;
    let token_streams = Arc::new(tokio::sync::Semaphore::new(crate::mailbox::TOKEN_STREAMS));
    let contact_streams = Arc::new(tokio::sync::Semaphore::new(CONTACT_STREAMS));
    loop {
        tokio::select! {
            st = s.accept_stream() => {
                let Some(mut st) = st else { break };
                let permit = if d.mailbox.token_of(&s).is_some() {
                    let Ok(permit) = token_streams.clone().try_acquire_owned() else {
                        st.reset(0);
                        continue;
                    };
                    Some(permit)
                } else {
                    None
                };
                let turns = matches!(
                    d.session_kind(&s.peer_static()),
                    Some(PeerKind::Contact(..) | PeerKind::Inviting(..))
                )
                .then(|| contact_streams.clone());
                let d2 = d.clone();
                let s2 = s.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let _turn = match turns {
                        Some(turns) => turns.acquire_owned().await.ok(),
                        None => None,
                    };
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
    let (labels, member) = match d.classify(s) {
        PeerKind::Contact(identity, device) => {
            let core = d.core();
            let mut labels = core.labels_with(&identity);
            // after their recovery, what they started, for their keeps
            let theirs: Vec<Label> = core
                .spaces
                .keys()
                .filter(|l| !labels.contains(*l) && core.recovered_owns(&identity, &device, l))
                .copied()
                .collect();
            labels.extend(theirs);
            (labels, Some(identity))
        }
        PeerKind::Token(_) | PeerKind::Stranger => return,
        _ => (d.core().labels(), None),
    };
    let device = match d.classify(s) {
        PeerKind::Own(k) | PeerKind::Contact(_, k) => Some(k),
        _ => None,
    };
    let mut read = false;
    for label in labels {
        let mine = crate::mailbox::written_here(d, &label);
        let done = reconcile(d, s, label).await;
        // One set reconciled with no protocol error: whatever could not be
        // read before can be now (`unreadable.rs`). Another set failing
        // for its own reasons, such as access, says nothing of that.
        if let Some(k) = device.filter(|_| !read && done.is_ok()) {
            if crate::unreadable::reads_again(s.close_reason().as_ref()) {
                read = true;
                if d.unreadable.synced(&k) {
                    tracing::info!("{} reads this device again", short(&s.peer_static()));
                }
            }
        }
        match done {
            Ok(()) => {
                if let Some(member) = member {
                    d.mailbox.mark_sent(&label, &member, &mine);
                }
            }
            Err(e) => tracing::debug!(
                "reconcile {} with {}: {e:#}",
                short(&label),
                short(&s.peer_static())
            ),
        }
    }
    // After this person's recovery: what they started and offered this
    // contact, and their relationship, not here yet, asked of them alone,
    // taken only in answer and served to nobody (`hosts.md#restore`, D81).
    // Each contact is asked until they answer, for a while after the
    // finish, and nothing that came once is asked for again.
    let Some(member) = member else {
        return;
    };
    let Some(asks) = crate::recovering::asks_of(d, &member) else {
        return;
    };
    let mut through = true;
    for label in &asks {
        if let Err(e) = reconcile_as(d, s, *label, Access::Offered).await {
            through = false;
            tracing::debug!(
                "asking {} for {}: {e:#}",
                short(&s.peer_static()),
                short(label)
            );
        }
    }
    crate::recovering::asked(d, &member, &asks, through);
}

async fn handle_stream(d: &Arc<Daemon>, s: &Session, mut st: Stream) -> anyhow::Result<()> {
    if st.service() == Service::STORAGE {
        return crate::host::serve(d, s, st).await;
    }
    if crate::host::is_unproven(d, s) {
        s.close(crate::host::PROVE_FIRST);
        return Ok(());
    }
    if st.service() == Service::RENDEZVOUS || st.service() == Service::RELAY {
        return crate::rendezvous::serve(d, s, st).await;
    }
    if st.service() == Service::CONTACT {
        return crate::contacts::serve(d, s, st).await;
    }
    if st.service() == Service::EPHEMERAL {
        // One message: a clipboard's, named by its first field, or a call's.
        // Who sends it decides how much is read, before any of it is: only
        // this person's own devices may send a copy, and to anyone else a
        // call's signal is all there is. A stranger's is not read at all.
        let most = match d.classify(s) {
            PeerKind::Own(_) => crate::clipboard::MAX_TEXT + 256,
            PeerKind::Contact(..) | PeerKind::Inviting(_, Some(_)) => crate::calls::MAX_SIGNAL,
            _ => {
                st.reset(0);
                return Ok(());
            }
        };
        let Some(v) = st.recv_message_max(most).await? else {
            return Ok(());
        };
        if crate::clipboard::is_clip(&v) {
            crate::clipboard::take(d, s, &v);
            return Ok(());
        }
        return crate::calls::serve(d, s, st, v).await;
    }
    if st.service() == Service::MAILBOX {
        return crate::mailbox::serve(d, s, st).await;
    }
    if st.service() == Service::BLOB {
        // Who it is now: an invitation's session is a contact's once the
        // two have met, and goes on as theirs.
        let kind = match d.session_kind(&s.peer_static()) {
            k if may_fetch_blobs(k) => k,
            _ => Some(d.classify(s)),
        };
        if !may_fetch_blobs(kind) {
            tracing::debug!("no blobs for {} ({kind:?})", short(&s.peer_static()));
            st.reset(0);
            return Ok(());
        }
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
    let longest = longest_from(kind);
    let Some(v) = st.recv_message_max(longest).await? else {
        return Ok(());
    };
    match from_value(v)? {
        m @ Message::Reconcile { .. } => {
            let label = *m.label();
            let access = d.access(kind, &label);
            let set = if access == Access::None {
                MemSet::new()
            } else {
                d.core().set(&label)
            };
            let mut rec = Reconciler::new(label, set);
            let mut fetcher = Fetcher::start(d, s, label, access);
            let talk = Talk {
                kind,
                peer: s.peer_static(),
                access,
                longest,
                wait: None,
                objects_first: false,
            };
            let r = converse(d, &mut st, &mut rec, Some(m), &talk, &mut fetcher).await;
            let _ = st.shutdown().await;
            r?;
            fetcher.finish().await?;
        }
        m @ Message::Summary { .. } => answer_summary(d, s, st, kind, m).await?,
        Message::Want { label, ids } => {
            if d.access(kind, &label).may_fetch() {
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
            if access.takes_objects() {
                ingest(d, s, label, objects, access).await?;
            }
        }
        Message::Heads { label, ids } => {
            let access = d.access(kind, &label);
            if matches!(access, Access::Full | Access::Other(_) | Access::Offered) {
                let (missing, waiting): (Vec<[u8; 32]>, bool) = {
                    let core = d.core();
                    let missing = ids.into_iter().filter(|i| !core.has(&label, i)).collect();
                    (missing, core.is_waiting(&label))
                };
                if !missing.is_empty() {
                    fetch_objects(d, s, label, missing, access).await?;
                } else if waiting {
                    // this peer may have what was missing by now
                    reconcile(d, s, label).await?;
                }
            }
        }
    }
    Ok(())
}

/// Whether a peer is someone else's device, and so is not trusted with this
/// device's memory.
fn is_someone_else(kind: PeerKind) -> bool {
    matches!(
        kind,
        PeerKind::Token(_) | PeerKind::Contact(..) | PeerKind::Inviting(..) | PeerKind::Stranger
    )
}

/// The longest message a peer may send unasked. Someone else has no need of
/// much: what opens a stream is short, a reconcile 64 KiB at most.
fn longest_from(kind: PeerKind) -> usize {
    if is_someone_else(kind) {
        crate::mailbox::TOKEN_MESSAGE
    } else {
        MAX_MESSAGE
    }
}

/// Runs a reconciliation of `label` with a peer and fetches what this
/// side lacks. (Boxed: fetching can lead to another reconciliation.)
pub fn reconcile<'a>(
    d: &'a Arc<Daemon>,
    s: &'a Session,
    label: Label,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + 'a>> {
    Box::pin(async move {
        let access = d.access(d.classify(s), &label);
        reconcile_inner(d, s, label, access).await
    })
}

/// [`reconcile`] on a session this device opened for one purpose, which says
/// what it is for: the other end's say does not come into it.
pub async fn reconcile_as(
    d: &Arc<Daemon>,
    s: &Session,
    label: Label,
    access: Access,
) -> anyhow::Result<()> {
    Box::pin(reconcile_inner(d, s, label, access)).await
}

async fn reconcile_inner(
    d: &Arc<Daemon>,
    s: &Session,
    label: Label,
    access: Access,
) -> anyhow::Result<()> {
    let kind = d.classify(s);
    if !access.takes_objects() {
        return Ok(());
    }
    let long = long_delay(s);
    let r = Box::pin(reconcile_once(d, s, label, access, kind, long)).await;
    match r {
        // an answer to the summary beyond what one may carry: refused, and
        // reconciled as on any link
        Err(e) if long && e.downcast_ref::<TooMuchUnasked>().is_some() => {
            tracing::debug!("{e}: reconciling {} turn by turn", short(&label));
            Box::pin(reconcile_once(d, s, label, access, kind, false)).await
        }
        r => r,
    }
}

/// A summary's answer brought more objects than one may carry
/// ([`SUMMARY_ANSWER_FROM_OTHERS`]).
#[derive(Debug)]
struct TooMuchUnasked;

impl std::fmt::Display for TooMuchUnasked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("an answer to a summary beyond what one may carry")
    }
}

impl std::error::Error for TooMuchUnasked {}

/// The most objects, and bytes of them, taken unasked as the answer to
/// this side's summary: from someone else's device as many as a
/// drill-down may learn of ([`MAX_WANTED`]); from this person's own, 16
/// times that. Beyond, the stream is reset and the set reconciled turn by
/// turn, its objects asked for.
const SUMMARY_ANSWER_FROM_OTHERS: (usize, usize) = (MAX_WANTED, 256 << 20);
const SUMMARY_ANSWER_FROM_OWN: (usize, usize) = (16 * MAX_WANTED, 4 << 30);

/// `CARDINAL_TEST_SUMMARY_ANSWER_MAX`, where tests set it: the most
/// objects a summary's answer may carry, in place of the limits above.
fn test_answer_max() -> Option<usize> {
    std::env::var("CARDINAL_TEST_SUMMARY_ANSWER_MAX")
        .ok()
        .and_then(|v| v.parse().ok())
}

async fn reconcile_once(
    d: &Arc<Daemon>,
    s: &Session,
    label: Label,
    access: Access,
    kind: PeerKind,
    long: bool,
) -> anyhow::Result<()> {
    let set = d.core().set(&label);
    let mut st = s.open_stream(Service::SYNC, Priority::Background)?;
    if long {
        // One turn of short ids, so that the other sends at once what this
        // side lacks; the drill-down it then opens is the backstop.
        let bits = cardinal_sync::summary_bits(set.len());
        let nonce = cardinal_crypto::random_bytes::<32>();
        tracing::debug!(
            "reconcile {} with {}: a summary of {} ids, {bits} bits each",
            short(&label),
            short(&s.peer_static()),
            set.len()
        );
        for m in
            cardinal_sync::summary_messages(label, &set, nonce, bits, cardinal_sync::MAX_MESSAGE)
        {
            st.send_message(&to_value(&m)).await?;
        }
    }
    let mut rec = Reconciler::new(label, set);
    if !long {
        st.send_message(&to_value(&rec.initiate())).await?;
    }
    let mut fetcher = Fetcher::start(d, s, label, access);
    let talk = Talk {
        kind,
        peer: s.peer_static(),
        access,
        // What answers a summary is objects asked for, as large as any.
        longest: if long {
            MAX_MESSAGE
        } else {
            longest_from(kind)
        },
        wait: Some(patience(s)),
        objects_first: long,
    };
    let r = converse(d, &mut st, &mut rec, None, &talk, &mut fetcher).await;
    let _ = st.shutdown().await;
    r?;
    fetcher.finish().await
}

/// Above this measured round trip a link is long, and a reconciliation
/// opens with a summary (`sync.md#long-delays`).
const LONG_DELAY: Duration = Duration::from_secs(2);

/// The most bytes of short ids a summary may hold: from someone else's
/// device, about a million ids of 8 bytes; from this person's own, 64 MiB.
const SUMMARY_FROM_OTHERS: usize = 8 << 20;
const SUMMARY_FROM_OWN: usize = 64 << 20;

/// Whether the link to a peer is long: its measured round trip is above
/// [`LONG_DELAY`], or above `CARDINAL_TEST_SUMMARY_RTT_MS` where tests set
/// it (0: every link).
fn long_delay(s: &Session) -> bool {
    let limit = test_summary_rtt().unwrap_or(LONG_DELAY);
    limit.is_zero() || s.stats().srtt.is_some_and(|rtt| rtt > limit)
}

fn test_summary_rtt() -> Option<Duration> {
    static LIMIT: std::sync::OnceLock<Option<Duration>> = std::sync::OnceLock::new();
    *LIMIT.get_or_init(|| {
        std::env::var("CARDINAL_TEST_SUMMARY_RTT_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .map(Duration::from_millis)
    })
}

/// How long to wait for a peer's next message: [`REQUEST_TIMEOUT`], or
/// four round trips on a link slower than that.
fn patience(s: &Session) -> Duration {
    let rtt = s.stats().srtt.unwrap_or_default();
    REQUEST_TIMEOUT.max(rtt * 4)
}

/// How a reconciliation on one stream goes.
struct Talk {
    kind: PeerKind,
    /// The peer's static key.
    peer: [u8; 32],
    access: Access,
    /// The longest message taken from the peer.
    longest: usize,
    /// How long to wait for each message, if not for ever.
    wait: Option<Duration>,
    /// Whether objects may come before the peer's first reconcile message:
    /// the answer to this side's summary.
    objects_first: bool,
}

/// Carries a reconciliation on `st` until a turn of only skips ends it:
/// takes each message of the peer's turns, sends this side's turns, and
/// hands what it learns this side lacks to `fetcher` at once
/// (`sync.md#range-reconciliation`). `first` is a message already read.
/// Objects that answer this side's summary are taken in before the
/// drill-down begins, and added to the set reconciled, so the backstop
/// does not ask for them again.
async fn converse(
    d: &Arc<Daemon>,
    st: &mut Stream,
    rec: &mut Reconciler<MemSet>,
    mut first: Option<Message>,
    talk: &Talk,
    fetcher: &mut Fetcher,
) -> anyhow::Result<()> {
    let mut messages = 0u32;
    let mut objects_ok = talk.objects_first;
    let mut arrived: Vec<Vec<u8>> = Vec::new();
    let mut arrived_bytes = 0usize;
    let (most, most_bytes) = if is_someone_else(talk.kind) {
        SUMMARY_ANSWER_FROM_OTHERS
    } else {
        SUMMARY_ANSWER_FROM_OWN
    };
    let most = test_answer_max().unwrap_or(most);
    let (mut unasked, mut unasked_bytes) = (0usize, 0usize);
    loop {
        let m = match first.take() {
            Some(m) => m,
            None => {
                let next = st.recv_message_max(talk.longest);
                let v = match talk.wait {
                    Some(w) => tokio::time::timeout(w, next)
                        .await
                        .map_err(|_| anyhow::anyhow!("timed out"))??,
                    None => next.await?,
                };
                let Some(v) = v else { break };
                from_value(v)?
            }
        };
        match m {
            Message::Objects { objects, .. } if objects_ok => {
                let bytes = objects.iter().map(Vec::len).sum::<usize>();
                unasked += objects.len();
                unasked_bytes += bytes;
                if unasked > most || unasked_bytes > most_bytes {
                    st.reset(0);
                    return Err(TooMuchUnasked.into());
                }
                arrived_bytes += bytes;
                arrived.extend(objects);
                if arrived_bytes >= INGEST_BATCH {
                    arrived_bytes = 0;
                    take_in(d, talk, rec, std::mem::take(&mut arrived)).await?;
                }
            }
            m @ Message::Reconcile { .. } => {
                if objects_ok {
                    objects_ok = false;
                    take_in(d, talk, rec, std::mem::take(&mut arrived)).await?;
                }
                let turn = rec.handle(&m)?;
                for out in &turn {
                    st.send_message(&to_value(out)).await?;
                }
                let wanted = rec.take_wanted();
                if talk.access.takes_objects() {
                    fetcher.learn(wanted);
                }
                if rec.is_done() {
                    break;
                }
                if is_someone_else(talk.kind) && fetcher.learned >= MAX_WANTED {
                    break;
                }
            }
            _ => anyhow::bail!("expected reconcile"),
        }
        messages += 1;
        if messages > 100_000 {
            anyhow::bail!("reconciliation does not end");
        }
    }
    Ok(())
}

/// How many bytes of objects that came together are taken in at once:
/// taking in rebuilds what is held, so not one message at a time.
const INGEST_BATCH: usize = 16 << 20;

/// Takes in the objects that answered this side's summary, and adds what
/// is now held to the set being reconciled.
async fn take_in(
    d: &Arc<Daemon>,
    talk: &Talk,
    rec: &mut Reconciler<MemSet>,
    objects: Vec<Vec<u8>>,
) -> anyhow::Result<()> {
    let access = talk.access;
    if objects.is_empty() || !access.takes_objects() {
        return Ok(());
    }
    let label = *rec.label();
    let ids = object_ids(d, label, access, &objects);
    let d2 = d.clone();
    let outcome = tokio::task::spawn_blocking(move || d2.ingest(label, objects, access)).await??;
    d.pass_on(label, outcome.complete, outcome.objects, talk.peer);
    let core = d.core();
    for id in ids.into_iter().flatten() {
        if core.has(&label, &id) {
            rec.set_mut().insert(id);
        }
    }
    Ok(())
}

/// Answers a summary (`sync.md#long-delays`): reads the rest of it, sends
/// every object whose short id is absent from it (or, when chance matches
/// are likely enough, every object), and then opens the exact drill-down
/// as its initiator. A malformed summary resets the stream.
async fn answer_summary(
    d: &Arc<Daemon>,
    s: &Session,
    mut st: Stream,
    kind: PeerKind,
    first: Message,
) -> anyhow::Result<()> {
    let label = *first.label();
    let access = d.access(kind, &label);
    let limit = if is_someone_else(kind) {
        SUMMARY_FROM_OTHERS
    } else {
        SUMMARY_FROM_OWN
    };
    let longest = longest_from(kind);
    let mut reader = cardinal_sync::SummaryReader::new(label, limit);
    let mut m = first;
    let summary = loop {
        match reader.push(&m) {
            Ok(Some(summary)) => break summary,
            Ok(None) => {}
            Err(e) => {
                st.reset(0);
                return Err(e.into());
            }
        }
        // the rest of it, waited for in proportion to the round trip
        let next = tokio::time::timeout(patience(s), st.recv_message_max(longest));
        let Some(v) = next
            .await
            .map_err(|_| anyhow::anyhow!("summary: the rest of it timed out"))??
        else {
            return Ok(());
        };
        m = match from_value(v) {
            Ok(m @ Message::Summary { .. }) => m,
            _ => {
                st.reset(0);
                anyhow::bail!("summary: a message that is not one in the middle");
            }
        };
    };
    let set = if access == Access::None {
        MemSet::new()
    } else {
        d.core().set(&label)
    };
    if access.may_fetch() {
        let everything = summary.sends_everything(set.len());
        let (summary2, set2) = (summary.clone(), set.clone());
        let ids = tokio::task::spawn_blocking(move || summary2.to_send(&set2)).await?;
        tracing::debug!(
            "answering a summary of {} from {}: {} ids against {}, {} bits; sending {}{}",
            short(&label),
            short(&s.peer_static()),
            summary.count,
            set.len(),
            summary.bits,
            ids.len(),
            if everything { ", everything" } else { "" }
        );
        for chunk in ids.chunks(cardinal_sync::MAX_WANT) {
            let msgs = {
                let core = d.core();
                cardinal_sync::objects_messages(
                    label,
                    chunk.iter().filter_map(|id| core.get(&label, id)),
                )
            };
            for m in msgs {
                st.send_message(&to_value(&m)).await?;
            }
        }
    }
    let mut rec = Reconciler::new(label, set);
    st.send_message(&to_value(&rec.initiate())).await?;
    let mut fetcher = Fetcher::start(d, s, label, access);
    let talk = Talk {
        kind,
        peer: s.peer_static(),
        access,
        longest,
        wait: Some(patience(s)),
        objects_first: false,
    };
    let r = converse(d, &mut st, &mut rec, None, &talk, &mut fetcher).await;
    let _ = st.shutdown().await;
    r?;
    fetcher.finish().await
}

/// Fetches what one reconciliation learns this side lacks, as it learns it
/// (`sync.md#fetching-objects`). The ids go to the daemon's [`Spread`]:
/// a worker for this peer takes batches nobody else is being asked for, so
/// a set reconciled with several peers at once comes from all of them. A
/// fetcher dropped unfinished lets its worker run out on its own.
///
/// [`Spread`]: cardinal_sync::Spread
struct Fetcher {
    d: Arc<Daemon>,
    label: Label,
    peer: [u8; 32],
    wake: Arc<tokio::sync::Notify>,
    ended: Arc<std::sync::atomic::AtomicBool>,
    task: Option<tokio::task::JoinHandle<anyhow::Result<()>>>,
    /// How many ids it was told of.
    learned: usize,
}

impl Fetcher {
    fn start(d: &Arc<Daemon>, s: &Session, label: Label, access: Access) -> Fetcher {
        let wake = Arc::new(tokio::sync::Notify::new());
        let ended = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let task = access.takes_objects().then(|| {
            d.spread.lock().unwrap().join(label, s.peer_static());
            let (d, s, wake, ended) = (d.clone(), s.clone(), wake.clone(), ended.clone());
            tokio::spawn(async move { fetch_worker(&d, &s, label, access, &wake, &ended).await })
        });
        Fetcher {
            d: d.clone(),
            label,
            peer: s.peer_static(),
            wake,
            ended,
            task,
            learned: 0,
        }
    }

    /// The peer holds `ids`, which this side lacked when it learned them.
    fn learn(&mut self, ids: Vec<[u8; 32]>) {
        if self.task.is_none() || ids.is_empty() {
            return;
        }
        let ids: Vec<[u8; 32]> = {
            let core = self.d.core();
            ids.into_iter()
                .filter(|id| !core.has(&self.label, id))
                .collect()
        };
        self.learned += ids.len();
        self.d
            .spread
            .lock()
            .unwrap()
            .learn(self.label, self.peer, ids);
        self.wake.notify_one();
    }

    /// The reconciliation has ended: waits until everything learned has
    /// come, from this peer or another.
    async fn finish(mut self) -> anyhow::Result<()> {
        self.end();
        match self.task.take() {
            Some(t) => t.await?,
            None => Ok(()),
        }
    }

    fn end(&self) {
        self.ended.store(true, std::sync::atomic::Ordering::Release);
        self.wake.notify_one();
    }
}

impl Drop for Fetcher {
    fn drop(&mut self) {
        self.end();
    }
}

/// Takes batches of what `s`'s peer holds and this side lacks, asks for
/// them, and takes the objects in, until the reconciliation has ended and
/// nothing it learned is left: nothing for this peer, and nothing another
/// peer is being asked for that this one could give if that one does not.
async fn fetch_worker(
    d: &Arc<Daemon>,
    s: &Session,
    label: Label,
    access: Access,
    wake: &tokio::sync::Notify,
    ended: &std::sync::atomic::AtomicBool,
) -> anyhow::Result<()> {
    let peer = s.peer_static();
    let mut got: Vec<Vec<u8>> = Vec::new();
    let mut bytes = 0usize;
    let mut asked: Vec<[u8; 32]> = Vec::new();
    let r: anyhow::Result<()> = async {
        loop {
            let over = ended.load(std::sync::atomic::Ordering::Acquire);
            let batch = d
                .spread
                .lock()
                .unwrap()
                .take(&label, peer, cardinal_sync::MAX_WANT);
            if batch.is_empty() {
                if !got.is_empty() {
                    // Nothing more to ask for now: take in what came.
                    bytes = 0;
                    let objects = std::mem::take(&mut got);
                    let ids = std::mem::take(&mut asked);
                    let r = ingest_from(d, s, label, objects, access, over).await;
                    settle(d, &label, peer, &ids);
                    r?;
                    continue;
                }
                if !over {
                    wake.notified().await;
                } else if d.spread.lock().unwrap().waits_on_others(&label, peer) {
                    // Another peer is asked for something this one holds:
                    // if it does not give it, this one is asked next.
                    let _ = tokio::time::timeout(Duration::from_millis(200), wake.notified()).await;
                } else {
                    return Ok(());
                }
                continue;
            }
            let r = fetch_raw(d, s, label, &batch, access).await;
            asked.extend_from_slice(&batch);
            match r {
                Ok(objects) => {
                    bytes += objects.iter().map(Vec::len).sum::<usize>();
                    got.extend(objects);
                }
                Err(e) => {
                    let objects = std::mem::take(&mut got);
                    let _ = ingest_from(d, s, label, objects, access, true).await;
                    settle(d, &label, peer, &std::mem::take(&mut asked));
                    return Err(e);
                }
            }
            if bytes >= INGEST_BATCH {
                bytes = 0;
                let objects = std::mem::take(&mut got);
                let ids = std::mem::take(&mut asked);
                let r = ingest_from(d, s, label, objects, access, false).await;
                settle(d, &label, peer, &ids);
                r?;
            }
        }
    }
    .await;
    d.spread.lock().unwrap().leave(&label, peer);
    if r.is_ok() && d.spread.lock().unwrap().len(&label) == 0 {
        tracing::trace!("reconcile {}: all fetched", short(&label));
    }
    r
}

/// The answer for `ids` has come and been taken in: what is held now is
/// done with, the rest goes to another holder.
fn settle(d: &Daemon, label: &Label, peer: [u8; 32], ids: &[[u8; 32]]) {
    let core = d.core();
    d.spread
        .lock()
        .unwrap()
        .settle(label, peer, ids, |id| core.has(label, id));
}

/// Fetches objects of a set by id with `want`, and ingests them.
pub async fn fetch_objects(
    d: &Arc<Daemon>,
    s: &Session,
    label: Label,
    ids: Vec<[u8; 32]>,
    access: Access,
) -> anyhow::Result<()> {
    if !access.takes_objects() {
        return Ok(());
    }
    let got = fetch_raw(d, s, label, &ids, access).await?;
    if !got.is_empty() {
        ingest(d, s, label, got, access).await?;
    }
    Ok(())
}

/// Asks for objects of a set by id with `want`, and gives what came that
/// is one of them.
async fn fetch_raw(
    d: &Arc<Daemon>,
    s: &Session,
    label: Label,
    ids: &[[u8; 32]],
    access: Access,
) -> anyhow::Result<Vec<Vec<u8>>> {
    let wanted: HashSet<[u8; 32]> = ids.iter().copied().collect();
    let mut got: Vec<Vec<u8>> = Vec::new();
    let mut bytes = 0;
    let wait = patience(s);
    'asking: for msg in want_messages(label, ids) {
        let mut st = s.open_stream(Service::SYNC, Priority::Background)?;
        st.send_message(&to_value(&msg)).await?;
        let _ = st.shutdown().await;
        loop {
            let v = tokio::time::timeout(wait, st.recv_message_max(MAX_MESSAGE))
                .await
                .map_err(|_| anyhow::anyhow!("timed out"))??;
            let Some(v) = v else { break };
            if let Message::Objects { objects, .. } = from_value(v)? {
                bytes += objects.iter().map(Vec::len).sum::<usize>();
                got.extend(objects);
                if bytes > MAX_FETCHED {
                    break 'asking;
                }
            }
        }
    }
    // Check every object against the ids asked for.
    let found = object_ids(d, label, access, &got);
    let mut found = found.into_iter();
    got.retain(|_| {
        found
            .next()
            .flatten()
            .is_some_and(|id| wanted.contains(&id))
    });
    Ok(got)
}

/// The id of each object of a set, as the layer that owns the set makes
/// it: an identity entry's, or the BLAKE3 of the bytes. `None` for one
/// that is not even an entry.
fn object_ids(
    d: &Daemon,
    label: Label,
    access: Access,
    objects: &[Vec<u8>],
) -> Vec<Option<[u8; 32]>> {
    let is_identity = matches!(access, Access::Join(_) | Access::Other(_)) || {
        let core = d.core();
        Some(label) == core.identity_label() || core.other_of_label(&label).is_some()
    };
    objects
        .iter()
        .map(|b| {
            if is_identity {
                cardinal_identity::IdentityEntry::decode(b)
                    .ok()
                    .map(|e| e.id())
            } else {
                Some(*blake3::hash(b).as_bytes())
            }
        })
        .collect()
}

/// Ingests objects of a set from a peer.
async fn ingest(
    d: &Arc<Daemon>,
    s: &Session,
    label: Label,
    objects: Vec<Vec<u8>>,
    access: Access,
) -> anyhow::Result<()> {
    ingest_from(d, s, label, objects, access, true).await
}

/// [`ingest`], reconciling again with the peer for missing parents only if
/// `follow`: not while more of the same set is still coming.
async fn ingest_from(
    d: &Arc<Daemon>,
    s: &Session,
    label: Label,
    objects: Vec<Vec<u8>>,
    access: Access,
    follow: bool,
) -> anyhow::Result<()> {
    if objects.is_empty() {
        return Ok(());
    }
    let d2 = d.clone();
    let outcome = tokio::task::spawn_blocking(move || d2.ingest(label, objects, access)).await??;
    d.pass_on(label, outcome.complete, outcome.objects, s.peer_static());
    // A contact this device just learned of: it needs their log to tell
    // which of their writes count, whatever came in the same reconcile.
    let missing = d.core().missing_logs();
    for label in missing {
        let (d2, s2) = (d.clone(), s.clone());
        tokio::spawn(async move {
            if let Err(e) = reconcile(&d2, &s2, label).await {
                tracing::debug!("reconcile {}: {e:#}", short(&label));
            }
        });
    }
    if outcome.missing_parents && follow {
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

/// Sends objects of a set to a peer unasked, in one message, in the order
/// given: entries that belong together, such as a guardian's log up to what
/// it did (`identity.md#distribution`).
pub async fn send_objects(s: &Session, label: Label, objects: Vec<Vec<u8>>) -> anyhow::Result<()> {
    let msg = Message::Objects { label, objects };
    let mut st = s.open_stream(Service::SYNC, Priority::Interactive)?;
    st.send_message(&to_value(&msg)).await?;
    st.shutdown().await?;
    Ok(())
}

/// Sends one object to a peer and waits until it holds it: a peer serves
/// only what it has stored.
pub async fn deliver(
    s: &Session,
    label: Label,
    object: Vec<u8>,
    id: [u8; 32],
) -> anyhow::Result<()> {
    let msg = Message::Objects {
        label,
        objects: vec![object],
    };
    let mut st = s.open_stream(Service::SYNC, Priority::Interactive)?;
    st.send_message(&to_value(&msg)).await?;
    st.shutdown().await?;
    for _ in 0..100 {
        let mut st = s.open_stream(Service::SYNC, Priority::Interactive)?;
        let want = Message::Want {
            label,
            ids: vec![id],
        };
        st.send_message(&to_value(&want)).await?;
        let _ = st.shutdown().await;
        while let Some(v) = st.recv_message_max(MAX_MESSAGE).await? {
            if matches!(from_value(v)?, Message::Objects { objects, .. } if !objects.is_empty()) {
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    anyhow::bail!("that device did not take the entry")
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

/// Whether a peer may ask for objects by id (`sync.md#blob-transfer`):
/// chunk ids are unguessable and chunks useless without the key in a
/// reference, so knowing an id is the right to fetch it, from a device with
/// a session: the person's own devices, and contacts, whatever space the
/// reference came in or none ("send this file to Ben"). Not a token's
/// session, which reaches this device as a host: a host serves token
/// holders only the stored sets the owner allowed, and this one keeps none
/// for anyone. Nor someone not a contact yet.
fn may_fetch_blobs(kind: Option<PeerKind>) -> bool {
    matches!(
        kind,
        Some(PeerKind::Own(_) | PeerKind::Proven | PeerKind::Contact(..))
    )
}

/// Serves blob objects: whatever this device holds of those asked for.
async fn serve_blob(d: &Arc<Daemon>, mut st: Stream) -> anyhow::Result<()> {
    let Some(v) = st.recv_message_max(1 << 20).await? else {
        return Ok(());
    };
    let req = BlobRequest::decode(&v.encode())?;
    tracing::trace!("serving {} blob objects", req.ids.len());
    let store = d.store.clone();
    let leaving = d.leaving.clone();
    let reply = tokio::task::spawn_blocking(move || {
        use cardinal_blob::ObjectStore;
        // An answer may be counted as a copy (`blobs.md#dropping-a-chunk`):
        // only what is flushed is given.
        if req.ids.iter().any(|id| store.pending(id)) {
            if let Err(e) = store.sync() {
                tracing::warn!("cannot flush stored objects: {e}");
                return cardinal_sync::BlobRequest { ids: Vec::new() }.serve(|_| None);
            }
        }
        req.serve(|id| {
            use cardinal_blob::ObjectStore;
            // being dropped: not counted as a copy by whoever asks
            if leaving
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains(id)
            {
                return None;
            }
            store.get(id).ok().flatten()
        })
    })
    .await?;
    let held = reply
        .items
        .iter()
        .filter(|i| matches!(i, cardinal_sync::BlobItem::Held { .. }))
        .count();
    tracing::debug!("serving {held} of {} objects asked for", reply.items.len());
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
/// reply. Used by fetches and by copy checks alike. It waits as long as
/// the session lasts: there is no reply for busy, and no fixed time;
/// the caller moves on by what it learned of the device
/// ([`crate::sched::PeerStats::expect`]).
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
    let body = st
        .recv_message_bytes_max(MAX_MESSAGE)
        .await?
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
    fetch_blobs_from(d, ids, priority, None).await
}

/// The same, asking a contact's devices too.
pub async fn fetch_blobs_from(
    d: &Arc<Daemon>,
    ids: &[[u8; 32]],
    priority: Priority,
    contact: Option<[u8; 32]>,
) -> Vec<([u8; 32], Vec<u8>)> {
    let mut f = BlobFetch::new(d.clone(), priority);
    if let Some(who) = contact {
        f = f.from_contact(who);
    }
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
    /// The requests in flight, to drop one whose objects all came from
    /// elsewhere.
    handles: HashMap<u64, tokio::task::AbortHandle>,
    ready: VecDeque<BlobEvent>,
    /// A contact whose devices may hold what is wanted too.
    from: Option<[u8; 32]>,
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
            handles: HashMap::new(),
            ready: VecDeque::new(),
            from: None,
        }
    }

    /// Asks a contact's devices as well as this person's.
    pub fn from_contact(mut self, who: [u8; 32]) -> BlobFetch {
        self.from = Some(who);
        self
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
        let mut sessions = self.d.own_sessions();
        if let Some(who) = self.from {
            let theirs = self.d.sessions_of(&who);
            tracing::debug!(
                "fetching from {} of {}'s devices too",
                theirs.len(),
                short(&who)
            );
            sessions.extend(theirs);
        }
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
            let h = self.inflight.spawn(async move {
                let result = blob_request(&s, r.ids, priority).await;
                BlobDone {
                    request: r.id,
                    peer: r.peer,
                    result,
                }
            });
            self.handles.insert(r.id, h);
        }
        // A late request whose objects all came from another holder: its
        // stream is dropped, and its device's room freed.
        for rid in self.sched.moot() {
            if let Some(h) = self.handles.remove(&rid) {
                h.abort();
            }
            self.sched.cancel(rid, Instant::now());
        }
        let gone = self.sched.take_unavailable();
        if !gone.is_empty() {
            self.ready.push_back(BlobEvent::Unavailable(gone));
        }
    }

    fn done(&mut self, r: BlobDone) {
        self.handles.remove(&r.request);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_fetches_one_space_and_sends_nothing() {
        let (space, log, private) = ([1; 32], [2; 32], [3; 32]);
        for label in [space, log] {
            let granted = token_access(Some(space), Some(log), &label);
            assert!(granted.may_fetch());
            assert!(
                !granted.takes_objects(),
                "only owner devices send a host objects"
            );
        }
        let elsewhere = token_access(Some(space), Some(log), &private);
        assert!(!elsewhere.may_fetch(), "any other set looks empty");
        assert!(!elsewhere.takes_objects());
        assert_eq!(token_access(None, None, &private), Access::None);
    }

    #[test]
    fn own_devices_and_contacts_may_fetch_blobs() {
        let someone = [1u8; 32];
        assert!(may_fetch_blobs(Some(PeerKind::Own(someone))));
        assert!(may_fetch_blobs(Some(PeerKind::Proven)));
        assert!(may_fetch_blobs(Some(PeerKind::Contact(someone, someone))));
        assert!(!may_fetch_blobs(Some(PeerKind::Inviting(someone, None))));
        assert!(!may_fetch_blobs(Some(PeerKind::Token([1; 16]))));
        assert!(!may_fetch_blobs(Some(PeerKind::Restoring)));
        assert!(!may_fetch_blobs(Some(PeerKind::Stranger)));
        assert!(!may_fetch_blobs(None));
    }
}
