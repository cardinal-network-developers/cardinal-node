//! Calls (`profiles.md#calls`). A call needs no new mechanism: a `ring` on the
//! ephemeral service to the other person's online devices, and audio on a
//! datagram channel of their session, in the real-time class. What is in the
//! audio is the client's business: this carries it and looks at none of it.
//!
//! A person is on one call at a time, between two people or in a group. A
//! group call has no centre (`profiles.md#calls`): each device on it links
//! with the others it has sessions with, and its sound travels the links as
//! [`crate::mesh`] decides, so no device carries everyone's traffic. A device
//! that is plugged in and not metered carries the calls of its groups for
//! others, whether or not its own person is on them, so that two members who
//! have no session with each other still hear each other.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use cardinal_encoding::{Record, Value};
use cardinal_link::{Priority, Service, Session, Stream};
use cardinal_space::SpaceId;
use serde_json::{json, Value as Json};
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::sync::watch;

use crate::contacts;
use crate::daemon::{Daemon, PeerKind};
use crate::mesh::{self, Frame, LinkId, Tree, Voice, Word};
use crate::transport::{Reader, Writer};
use cardinal_space::account::ContactRecord;

const RING: u64 = 1;
const ANSWER: u64 = 2;
const END: u64 = 3;
/// In a group call: this device is on it, or carries it, and the session it
/// came on is one of the call's links.
const JOIN: u64 = 4;
/// In a group: a call is going on in it already, this one.
const ONGOING: u64 = 5;

/// How often a group call's routing looks at its links.
const TICK: Duration = Duration::from_millis(250);
/// How often, in ticks, a device on a group call says it is there, speaking
/// or not: a frame with no sound, passed on as any other, that no client
/// hears. Five seconds.
const HERE_EVERY: u64 = 20;
/// How often, in ticks, every link hears something: two seconds.
const KEEPALIVE_EVERY: u64 = 8;
/// How often, in ticks, a device asks the member devices it has sessions
/// with, and is not linked with, to link: five seconds.
const RELINK_EVERY: u64 = 20;
/// How long before the same session is asked to link again.
const ASK_AGAIN: Duration = Duration::from_secs(30);
/// A device only carrying a call leaves it after this long with fewer than
/// two links, since it joins nobody.
const THIN_FOR: Duration = Duration::from_secs(20);
/// Or once nobody on it has been heard for this long: it is over.
const QUIET_FOR: Duration = Duration::from_secs(15);
/// How often the signing keys of a group's devices are read again, for a
/// voice not known.
const KEYS_EVERY: Duration = Duration::from_secs(1);
/// How long a signal on a group call's behalf may take to go.
const SIGNAL_WITHIN: Duration = Duration::from_secs(3);
/// The most group calls a device carries for others at once.
const MAX_CARRIED: usize = 4;
/// How long a device that called waits, linked to a call it was told is
/// going on, to hear someone on it.
const PROBE_FOR: Duration = Duration::from_secs(8);
/// How often a device answers a `join` on a link it already has.
const ANSWER_AGAIN: Duration = Duration::from_secs(5);

/// The longest signal: a kind, a space, a call, a number and an identity.
pub const MAX_SIGNAL: usize = 192;
/// How long a call rings before it stops.
const RINGS_FOR: Duration = Duration::from_secs(45);
/// How often a call looks at whether its session is still there.
const SESSION_CHECK: Duration = Duration::from_secs(5);
/// How long sessions get to answer before a call looks past them.
const ANSWER_WITHIN: Duration = Duration::from_millis(1500);
/// How long a session that did not answer has to end before the call looks
/// again: the link's answer timeout.
const GONE_WITHIN: Duration = Duration::from_secs(12);
/// On an `end` a caller sends the called person's other devices, `3:`
/// says why their ringing stops: another of their devices answered the call,
/// or said no to it. Without it, nobody answered.
const ANSWERED_ELSEWHERE: u64 = 1;
const DECLINED_ELSEWHERE: u64 = 2;
/// On an `end` a device sends a caller as it turns a ring away, `3:` 3 says
/// it was busy (on another call, or rung too often), not that its person
/// said no: their other devices' ringing then ends as unanswered.
const BUSY: u64 = 3;

/// Turns a ring away as busy.
async fn busy(s: &Session, space: &SpaceId, id: &[u8; 16]) -> anyhow::Result<()> {
    let end = Signal {
        kind: END,
        space: *space,
        id: *id,
        flag: Some(BUSY),
        caller: None,
        formats: None,
    };
    send(s, &end).await
}

/// When a call looks again, past the gap between two looks for one person.
const LOOK_AGAIN: Duration = Duration::from_secs(6);
/// How many times one person can ring in `RINGS_WITHIN`. Past that a ring
/// finds this person busy, and nothing rings.
const MAX_RINGS: usize = 5;
const RINGS_WITHIN: Duration = Duration::from_secs(120);

/// Whether `who` may ring now, and if so, counts it.
fn may_ring(d: &Daemon, who: &[u8; 32]) -> bool {
    let mut rang = d.rang.lock().unwrap_or_else(|e| e.into_inner());
    let lately = rang.entry(*who).or_default();
    while lately.front().is_some_and(|t| t.elapsed() > RINGS_WITHIN) {
        lately.pop_front();
    }
    if lately.len() >= MAX_RINGS {
        return false;
    }
    lately.push_back(Instant::now());
    true
}

/// Where a call stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// This person called, and is waiting.
    Calling,
    /// Someone is calling this person.
    Ringing,
    /// They are talking.
    Live,
}

/// How a call ended here, as the service tells whoever looks after it has
/// gone: so a window can tell a call missed from one taken on another of
/// its person's devices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ending {
    /// It rang here, and nobody answered it anywhere.
    Missed,
    /// Another of this person's devices answered it.
    AnsweredElsewhere,
    /// Another of this person's devices said no to it.
    DeclinedElsewhere,
    /// This person said no to it here.
    Declined,
    /// It was live, and is over.
    Over,
    /// This person called, and nobody answered.
    NotAnswered,
    /// This person called, and they said no.
    TheyDeclined,
    /// This person called, and they were busy.
    Busy,
    /// This person called, and hung up before anyone answered.
    Cancelled,
}

impl Ending {
    pub fn name(self) -> &'static str {
        match self {
            Ending::Missed => "missed",
            Ending::AnsweredElsewhere => "answered_elsewhere",
            Ending::DeclinedElsewhere => "declined_elsewhere",
            Ending::Declined => "declined",
            Ending::Over => "over",
            Ending::NotAnswered => "not_answered",
            Ending::TheyDeclined => "they_declined",
            Ending::Busy => "busy",
            Ending::Cancelled => "cancelled",
        }
    }
}

/// The call this person is on.
pub struct Call {
    id: [u8; 16],
    who: [u8; 32],
    name: String,
    space: SpaceId,
    standing: Standing,
    /// The session the audio goes on: the one that rang, or that answered.
    session: Option<Session>,
    /// Audio is being carried.
    carrying: bool,
    live_since: Option<Instant>,
    /// True once the call is over. It holds that for whoever looks later.
    over: watch::Sender<bool>,
    /// A call in a group, whose sound goes through its [`Group`].
    group: bool,
    /// What the ring offered, if it named formats.
    offered: Option<Vec<Format>>,
    /// What the answer took, if it named formats.
    taken: Option<Vec<Format>>,
}

impl Call {
    fn new(
        id: [u8; 16],
        who: [u8; 32],
        name: String,
        space: SpaceId,
        standing: Standing,
        session: Option<Session>,
    ) -> Call {
        Call {
            id,
            who,
            name,
            space,
            standing,
            session,
            carrying: false,
            live_since: None,
            over: watch::channel(false).0,
            group: false,
            offered: None,
            taken: None,
        }
    }

    fn close(&self) {
        self.over.send_replace(true);
    }
}

/// A call that has left this device: over for whoever waits on it, and how
/// it ended kept for whoever looks.
fn finished(d: &Daemon, call: &Call, how: Ending) {
    call.close();
    let ended = json!({
        "id": hex::encode(call.id),
        "who": hex::encode(&call.who[..8]),
        "name": call.name,
        "group": call.group.then(|| hex::encode(call.space)),
        "how": how.name(),
    });
    *d.call_ended.lock().unwrap_or_else(|e| e.into_inner()) = Some(ended);
    d.bump();
}

/// How a call that was ringing here ends when it gives way to one this
/// person makes, or the like: unanswered, so missed.
fn gave_way(call: &Call) -> Ending {
    match call.standing {
        Standing::Ringing => Ending::Missed,
        Standing::Calling => Ending::Cancelled,
        Standing::Live => Ending::Over,
    }
}

/// A group call this device is on, or carries for others.
pub struct Group {
    space: SpaceId,
    tree: Tree,
    /// The session of each link, and which time it was linked, so that a
    /// link's task that outlived it touches nothing.
    sessions: HashMap<LinkId, (Session, u64)>,
    linked: u64,
    /// The signing keys of the group's devices, by voice, and when read.
    keys: HashMap<Voice, [u8; 32]>,
    keys_at: Option<Instant>,
    /// The number of this device's next frame.
    next: u32,
    /// Its person called, and nobody else is on it yet.
    waiting: bool,
    /// When each session was last asked to link, by handshake.
    asked: HashMap<[u8; 32], Instant>,
    /// When each session was last answered on a link it already had.
    answered: HashMap<[u8; 32], Instant>,
    /// Since when, while only carrying, it has had fewer than two links.
    thin_since: Option<Instant>,
    /// Linked only to see whether someone is on it, as another device said:
    /// until when, and that device's voice.
    probe: Option<(Instant, Voice)>,
    /// Frames that came on its links, and how many of them were new.
    frames_in: u64,
    frames_new: u64,
    since: Instant,
    over: watch::Sender<bool>,
}

fn lock(d: &Daemon) -> std::sync::MutexGuard<'_, Option<Call>> {
    d.call.lock().unwrap_or_else(|e| e.into_inner())
}

fn groups(d: &Daemon) -> std::sync::MutexGuard<'_, HashMap<[u8; 16], Group>> {
    d.group_calls.lock().unwrap_or_else(|e| e.into_inner())
}

/// The channel of a call: `first16(BLAKE3(space id || call id))`.
fn channel_label(space: &SpaceId, id: &[u8; 16]) -> [u8; 16] {
    let mut h = blake3::Hasher::new();
    h.update(space);
    h.update(id);
    let mut label = [0; 16];
    label.copy_from_slice(&h.finalize().as_bytes()[..16]);
    label
}

/// The channel a group call's routing words go on:
/// `first16(BLAKE3(space id || call id || "routing"))`.
fn routing_label(space: &SpaceId, id: &[u8; 16]) -> [u8; 16] {
    let mut h = blake3::Hasher::new();
    h.update(space);
    h.update(id);
    h.update(b"routing");
    let mut label = [0; 16];
    label.copy_from_slice(&h.finalize().as_bytes()[..16]);
    label
}

/// A signal: `{0: kind, 1: space, 2: call}`, and in a group, `3:` a number
/// (for `join`, 1 when the device only carries the call; for `ongoing`, 1
/// when two or more are on it) and `4:` who called, on a `ring`.
#[derive(Debug, PartialEq, Eq)]
struct Signal {
    kind: u64,
    space: SpaceId,
    id: [u8; 16],
    flag: Option<u64>,
    caller: Option<[u8; 32]>,
    /// The formats a `ring` offers (field 5) or an `answer` takes (field 4),
    /// each by its document's name. None: software from before, voice only.
    formats: Option<Vec<Format>>,
}

/// A call's format: the name of the document that says what its frames hold.
pub type Format = [u8; 32];

/// The provisional name of a draft format, until its document is published.
pub fn draft_format(short: &str) -> Format {
    *blake3::hash(format!("cardinal draft format: {short}").as_bytes()).as_bytes()
}

/// Voice (`basics/voice.md`): its frames keep the call's first channel.
pub fn voice() -> Format {
    draft_format("voice 1")
}

/// Formats in their order, each once.
fn dedup(formats: impl IntoIterator<Item = Format>) -> Vec<Format> {
    let mut out: Vec<Format> = Vec::new();
    for f in formats {
        if !out.contains(&f) {
            out.push(f);
        }
    }
    out
}

/// What an answer takes of what was offered: those it names, in the order
/// offered; naming none, as software from before formats does, voice only.
fn taking(offered: &[Format], named: Option<&[Format]>) -> Vec<Format> {
    match named {
        Some(named) => offered
            .iter()
            .filter(|f| named.contains(f))
            .copied()
            .collect(),
        None => offered.iter().filter(|f| **f == voice()).copied().collect(),
    }
}

/// The most formats a ring offers, so that it stays small enough for the
/// software before this, which takes a signal of at most 192 bytes.
const MAX_FORMATS: usize = 2;

/// The datagram channel of one of a call's formats other than voice.
fn format_label(space: &SpaceId, id: &[u8; 16], format: &Format) -> [u8; 16] {
    let mut h = blake3::Hasher::new();
    h.update(space);
    h.update(id);
    h.update(format);
    let mut label = [0; 16];
    label.copy_from_slice(&h.finalize().as_bytes()[..16]);
    label
}

impl Signal {
    fn record(&self) -> Record {
        let mut r = Record::new()
            .with(0, self.kind)
            .with(1, self.space)
            .with(2, self.id);
        if let Some(f) = self.flag {
            r = r.with(3, f);
        }
        if let Some(c) = self.caller {
            r = r.with(4, c);
        }
        if let Some(f) = &self.formats {
            let field = if self.kind == RING { 5 } else { 4 };
            r = r.with(field, Value::list(f.iter().map(|f| Value::from(*f))));
        }
        r
    }

    fn of(v: &Value) -> Option<Signal> {
        let r = v.as_record()?;
        Some(Signal {
            kind: r.get(0)?.as_uint()?,
            space: r.get(1)?.as_bytes()?.try_into().ok()?,
            id: r.get(2)?.as_bytes()?.try_into().ok()?,
            flag: r.get(3).and_then(|f| f.as_uint()),
            caller: r
                .get(4)
                .and_then(|c| c.as_bytes())
                .and_then(|c| c.try_into().ok()),
            formats: {
                let kind = r.get(0)?.as_uint()?;
                let field = match kind {
                    RING => Some(5),
                    ANSWER => Some(4),
                    _ => None,
                };
                field
                    .and_then(|f| r.get(f))
                    .and_then(|l| l.as_list())
                    .map(|l| {
                        dedup(
                            l.iter()
                                .filter_map(|f| f.as_bytes()?.try_into().ok())
                                .take(8),
                        )
                    })
            },
        })
    }
}

async fn tell(s: &Session, kind: u64, space: &SpaceId, id: &[u8; 16]) -> anyhow::Result<()> {
    let signal = Signal {
        kind,
        space: *space,
        id: *id,
        flag: None,
        caller: None,
        formats: None,
    };
    send(s, &signal).await
}

/// A `ring` or `answer` that names formats.
async fn tell_formats(
    s: &Session,
    kind: u64,
    space: &SpaceId,
    id: &[u8; 16],
    formats: Option<&[Format]>,
) -> anyhow::Result<()> {
    let signal = Signal {
        kind,
        space: *space,
        id: *id,
        flag: None,
        caller: None,
        formats: formats.map(<[Format]>::to_vec),
    };
    send(s, &signal).await
}

async fn send(s: &Session, signal: &Signal) -> anyhow::Result<()> {
    let mut st = s.open_stream(Service::EPHEMERAL, Priority::RealTime)?;
    st.send_message(&Value::Record(signal.record())).await?;
    st.shutdown().await?;
    Ok(())
}

/// Ends a call that has run out of time, if it is still that call.
fn ring_out(d: &Arc<Daemon>, id: [u8; 16]) {
    let d = d.clone();
    tokio::spawn(async move {
        tokio::time::sleep(RINGS_FOR).await;
        let unanswered = lock(&d)
            .as_ref()
            .is_some_and(|c| c.id == id && c.standing != Standing::Live);
        if unanswered {
            let _ = end_call(&d, false, true).await;
        }
    });
}

/// Rings a contact. Ringing here does not stop this person calling someone:
/// a call that is only ringing gives way.
pub async fn start(
    d: &Arc<Daemon>,
    who: &str,
    formats: Option<Vec<Format>>,
) -> anyhow::Result<Json> {
    let formats = formats.map(dedup);
    if let Some(f) = &formats {
        anyhow::ensure!(!f.is_empty(), "a call offers at least one format");
        anyhow::ensure!(
            f.len() <= MAX_FORMATS,
            "a call offers at most {MAX_FORMATS} formats"
        );
    }
    let contact = contacts::listed(d, who)?;
    let mut theirs = d.sessions_of(&contact.identity);
    // A session that looks open may be one left on a network their device
    // has since left (`profiles.md#calls-guidance`): each is asked for an
    // answer, and one that gives none is looked past.
    let asked = Instant::now();
    for s in &theirs {
        s.check();
    }
    while !theirs.is_empty()
        && asked.elapsed() < ANSWER_WITHIN
        && theirs.iter().any(|s| s.last_heard() < asked)
    {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    for s in theirs.iter().filter(|s| s.last_heard() < asked) {
        d.rendezvous.suspect(&s.peer_static());
    }
    if theirs.is_empty() && contact.connects() {
        crate::rendezvous::reach_now(d, contact.identity, contact.space).await;
        theirs = d.sessions_of(&contact.identity);
    }
    anyhow::ensure!(
        !theirs.is_empty(),
        "{} cannot be reached right now",
        contact.petname
    );
    let id: [u8; 16] = cardinal_crypto::random_bytes();
    let mut call = Call::new(
        id,
        contact.identity,
        contact.petname.clone(),
        contact.space,
        Standing::Calling,
        None,
    );
    call.offered = formats.clone();
    let gave_way = {
        let mut held = lock(d);
        let ringing = held
            .as_ref()
            .is_some_and(|c| c.standing == Standing::Ringing);
        anyhow::ensure!(held.is_none() || ringing, "you are already on a call");
        held.replace(call)
    };
    if let Some(old) = gave_way {
        finished(d, &old, self::gave_way(&old));
        if let Some(s) = &old.session {
            let _ = tell(s, END, &old.space, &old.id).await;
        }
    }
    d.bump();
    for s in &theirs {
        if let Err(e) = tell_formats(s, RING, &contact.space, &id, formats.as_deref()).await {
            tracing::debug!("ringing: {e:#}");
        }
    }
    if contact.connects() {
        let rung: Vec<[u8; 32]> = theirs.iter().map(Session::handshake_hash).collect();
        tokio::spawn(ring_where_found(d.clone(), contact, id, rung, formats));
    }
    ring_out(d, id);
    Ok(json!({}))
}

/// Looks for the person called while it rings, at once and again once any
/// session that gave no answer has had time to end, and rings each device
/// found that was not rung.
async fn ring_where_found(
    d: Arc<Daemon>,
    contact: ContactRecord,
    id: [u8; 16],
    mut rung: Vec<[u8; 32]>,
    formats: Option<Vec<Format>>,
) {
    for wait in [Duration::ZERO, LOOK_AGAIN, GONE_WITHIN - LOOK_AGAIN] {
        tokio::time::sleep(wait).await;
        crate::rendezvous::reach_now(&d, contact.identity, contact.space).await;
        let calling = lock(&d)
            .as_ref()
            .is_some_and(|c| c.id == id && c.standing == Standing::Calling);
        if !calling {
            return;
        }
        for s in d.sessions_of(&contact.identity) {
            if rung.contains(&s.handshake_hash()) {
                continue;
            }
            rung.push(s.handshake_hash());
            if let Err(e) = tell_formats(&s, RING, &contact.space, &id, formats.as_deref()).await {
                tracing::debug!("ringing: {e:#}");
            }
        }
    }
}

/// Takes the call that is ringing here.
pub async fn answer(d: &Arc<Daemon>, formats: Option<Vec<Format>>) -> anyhow::Result<Json> {
    let group = lock(d)
        .as_ref()
        .filter(|c| c.standing == Standing::Ringing && c.group)
        .map(|c| (c.space, c.id));
    if let Some((space, id)) = group {
        if let Some(c) = lock(d).as_mut() {
            c.standing = Standing::Live;
            c.live_since = Some(Instant::now());
        }
        take_part(d, id, space, false);
        d.bump();
        relink(d, &id, &space, true).await;
        return Ok(json!({}));
    }
    let (s, space, id, taken) = {
        let mut call = lock(d);
        let c = call
            .as_mut()
            .filter(|c| c.standing == Standing::Ringing)
            .ok_or_else(|| anyhow::anyhow!("nothing is ringing"))?;
        // Taken now, so a second answer finds nothing ringing.
        c.standing = Standing::Live;
        // Only what was offered can be taken; a ring that named nothing is
        // voice, and its answer names nothing either.
        c.taken = c
            .offered
            .as_deref()
            .map(|offered| taking(offered, formats.as_deref()));
        let s = c.session.clone();
        (
            s.ok_or_else(|| anyhow::anyhow!("that call has gone"))?,
            c.space,
            c.id,
            c.taken.clone(),
        )
    };
    if let Err(e) = tell_formats(&s, ANSWER, &space, &id, taken.as_deref()).await {
        let _ = end(d).await;
        return Err(e);
    }
    go_live(d, &s, id);
    Ok(json!({}))
}

/// Hangs up, or says no.
pub async fn end(d: &Arc<Daemon>) -> anyhow::Result<Json> {
    end_call(d, true, false).await
}

/// Hangs up. In a group this device leaves, and the others go on; with
/// `may_carry`, a device that helps others goes on carrying the call for
/// them while it joins two or more of them. With `timed_out`, it rang or
/// called for as long as a call rings, unanswered.
async fn end_call(d: &Arc<Daemon>, may_carry: bool, timed_out: bool) -> anyhow::Result<Json> {
    let Some(call) = lock(d).take() else {
        return Ok(json!({}));
    };
    let how = match (call.standing, timed_out) {
        (Standing::Ringing, true) => Ending::Missed,
        (Standing::Ringing, false) => Ending::Declined,
        (Standing::Calling, true) => Ending::NotAnswered,
        (Standing::Calling, false) => Ending::Cancelled,
        (Standing::Live, _) => Ending::Over,
    };
    finished(d, &call, how);
    if call.group {
        // Saying no to a ring is this person's: what the device carries
        // goes on.
        if call.standing == Standing::Ringing {
            return Ok(json!({}));
        }
        let carry_on = may_carry
            && d.conditions.helps()
            && groups(d).get(&call.id).is_some_and(|g| g.tree.links() >= 2);
        if !carry_on {
            leave(d, &call.id).await;
            return Ok(json!({}));
        }
        let links: Vec<Session> = {
            let mut gs = groups(d);
            let Some(g) = gs.get_mut(&call.id) else {
                return Ok(json!({}));
            };
            g.tree.set_own(None);
            g.waiting = false;
            g.sessions.values().map(|(s, _)| s.clone()).collect()
        };
        for s in links {
            let _ = join(&s, &call.space, &call.id, true).await;
        }
        return Ok(json!({}));
    }
    let told = match call.session {
        Some(s) => vec![s],
        None => d.sessions_of(&call.who),
    };
    for s in told {
        let _ = tell(&s, END, &call.space, &call.id).await;
    }
    Ok(json!({}))
}

/// Forgets a call that has ended by itself.
fn forget(d: &Daemon, id: &[u8; 16], how: Ending) {
    let gone = {
        let mut call = lock(d);
        let same = call.as_ref().is_some_and(|c| c.id == *id);
        if same {
            call.take()
        } else {
            None
        }
    };
    if let Some(call) = gone {
        finished(d, &call, how);
    }
}

/// Starts carrying the audio of the call `id` on a session, if that is still
/// the call under way and nothing is carrying it.
fn go_live(d: &Arc<Daemon>, s: &Session, id: [u8; 16]) {
    let (mut channel, mut over) = {
        let mut call = lock(d);
        let Some(c) = call.as_mut().filter(|c| c.id == id && !c.carrying) else {
            return;
        };
        c.standing = Standing::Live;
        c.carrying = true;
        c.session = Some(s.clone());
        c.live_since = Some(Instant::now());
        let label = channel_label(&c.space, &c.id);
        let others: Vec<Format> = c
            .taken
            .iter()
            .flatten()
            .filter(|f| **f != voice())
            .copied()
            .collect();
        for format in others {
            let mut ch = s.channel(
                format_label(&c.space, &c.id, &format),
                Priority::Interactive,
            );
            let mut over = c.over.subscribe();
            let d = d.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = over.wait_for(|over| *over) => return,
                        heard = ch.recv() => match heard {
                            Some(frame) => {
                                let _ = d.call_video.send((id, format, frame));
                            }
                            None => return,
                        },
                    }
                }
            });
        }
        (s.channel(label, Priority::RealTime), c.over.subscribe())
    };
    d.bump();
    let d = d.clone();
    let s = s.clone();
    tokio::spawn(async move {
        let mut check = tokio::time::interval(SESSION_CHECK);
        loop {
            tokio::select! {
                _ = over.wait_for(|over| *over) => return,
                heard = channel.recv() => match heard {
                    Some(audio) => {
                        let _ = d.call_audio.send((id, None, audio));
                    }
                    None => break,
                },
                _ = check.tick() => {
                    if s.is_closed() {
                        break;
                    }
                }
            }
        }
        // The session went, and the call with it.
        forget(&d, &id, Ending::Over);
    });
}

/// What is known of the call under way.
pub fn current(d: &Daemon) -> Json {
    let ended = d
        .call_ended
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let (offered, taken) = {
        let call = lock(d);
        let hexes = |l: &Option<Vec<Format>>| {
            l.as_ref()
                .map(|l| l.iter().map(hex::encode).collect::<Vec<_>>())
        };
        call.as_ref()
            .map_or((None, None), |c| (hexes(&c.offered), hexes(&c.taken)))
    };
    let (who, name, standing, seconds, space, group, id) = {
        let call = lock(d);
        let Some(c) = call.as_ref() else {
            return json!({"call": null, "ended": ended});
        };
        let standing = match c.standing {
            Standing::Calling => "calling",
            Standing::Ringing => "ringing",
            Standing::Live => "live",
        };
        (
            c.who,
            c.name.clone(),
            standing,
            c.live_since.map(|t| t.elapsed().as_secs()),
            c.space,
            c.group,
            c.id,
        )
    };
    let (linked, people, frames) = if group {
        let gs = groups(d);
        let g = gs.get(&id);
        (
            Some(g.map_or(0, |g| g.tree.links())),
            Some(g.map_or(1, |g| g.tree.on_it(Instant::now()))),
            g.map(|g| json!({"in": g.frames_in, "new": g.frames_new})),
        )
    } else {
        (None, None, None)
    };
    // the picture this person sees for them, if any
    let picture = {
        let contacts = d.core().contacts();
        let c = contacts.into_iter().find(|c| c.identity == who);
        c.and_then(|c| crate::names::shown(d, &c).remove("picture"))
    };
    json!({"call": {
        "id": hex::encode(id),
        "who": hex::encode(&who[..8]),
        "name": name,
        "picture": picture,
        "state": standing,
        "seconds": seconds,
        "group": group.then(|| hex::encode(space)),
        "linked": linked,
        "people": people,
        "frames": frames,
        "offered": offered,
        "taken": taken,
    }, "ended": ended})
}

/// How many group calls this device carries for others, without its person.
pub fn carried(d: &Daemon) -> usize {
    groups(d)
        .values()
        .filter(|g| g.tree.own().is_none() && g.probe.is_none())
        .count()
}

/// This device's voice in group calls: who it is, without saying.
fn origin_of(d: &Daemon) -> Voice {
    mesh::voice_of(&d.keys.key())
}

/// Whether someone is on a group call, as far as this device can tell: its
/// own person, or anyone heard lately.
fn someone_on(g: &Group, now: Instant) -> bool {
    g.tree.own().is_some() && !g.waiting || g.tree.others(now) >= 1
}

/// Rings a group: each member device this one has a session with, and
/// each of those passes the ring on to theirs. If a call with someone on it
/// is going on in it already, that is the one this person joins.
pub async fn start_group(d: &Arc<Daemon>, group: &str) -> anyhow::Result<Json> {
    let (space, name) = crate::groups::joined_group(d, group)?;
    let now = Instant::now();
    let (going, stale) = {
        let gs = groups(d);
        let in_it: Vec<(&[u8; 16], &Group)> = gs.iter().filter(|(_, g)| g.space == space).collect();
        let going = in_it
            .iter()
            .find(|(_, g)| g.probe.is_none() && someone_on(g, now))
            .map(|(id, _)| **id);
        let stale: Vec<[u8; 16]> = in_it
            .iter()
            .filter(|(id, _)| Some(**id) != going)
            .map(|(id, _)| **id)
            .collect();
        (going, stale)
    };
    // A call nobody is heard on is over, whatever this device carried.
    for old in stale {
        leave(d, &old).await;
    }
    let theirs = crate::groups::member_sessions(d, &space);
    anyhow::ensure!(
        going.is_some() || !theirs.is_empty(),
        "nobody in {name} can be reached right now"
    );
    let id = going.unwrap_or_else(cardinal_crypto::random_bytes);
    let mut call = Call::new(id, space, name, space, Standing::Calling, None);
    call.group = true;
    if going.is_some() {
        call.standing = Standing::Live;
        call.live_since = Some(Instant::now());
    }
    {
        let mut held = lock(d);
        let ringing = held
            .as_ref()
            .is_some_and(|c| c.standing == Standing::Ringing);
        anyhow::ensure!(held.is_none() || ringing, "you are already on a call");
        if let Some(old) = held.replace(call) {
            finished(d, &old, gave_way(&old));
        }
    }
    take_part(d, id, space, going.is_none());
    d.bump();
    if going.is_some() {
        relink(d, &id, &space, true).await;
        return Ok(json!({}));
    }
    let me = contacts::identity(d).ok();
    remember(&d.rung_calls, id);
    remember(&d.passed_rings, id);
    for s in &theirs {
        let ring = Signal {
            kind: RING,
            space,
            id,
            flag: None,
            caller: me,
            formats: None,
        };
        if let Err(e) = send(s, &ring).await {
            tracing::debug!("ringing: {e:#}");
        }
    }
    ring_out(d, id);
    Ok(json!({}))
}

/// Remembers a call among the last few; whether it was there already.
fn remember(list: &std::sync::Mutex<std::collections::VecDeque<[u8; 16]>>, id: [u8; 16]) -> bool {
    let mut l = list.lock().unwrap_or_else(|e| e.into_inner());
    if l.contains(&id) {
        return true;
    }
    l.push_back(id);
    if l.len() > 64 {
        l.pop_front();
    }
    false
}

/// This device's person is on group call `id`: its voice goes out, and it
/// hears the others. The call's routing starts if it was not going already.
fn take_part(d: &Arc<Daemon>, id: [u8; 16], space: SpaceId, waiting: bool) {
    let own = origin_of(d);
    let mut gs = groups(d);
    if let Some(g) = gs.get_mut(&id) {
        g.tree.set_own(Some(own));
        g.waiting = waiting && !g.tree.any_person();
        g.thin_since = None;
        g.probe = None;
        return;
    }
    gs.insert(id, new_group(space, Some(own), waiting));
    let over = gs[&id].over.subscribe();
    drop(gs);
    tokio::spawn(drive(d.clone(), id, over));
}

fn new_group(space: SpaceId, own: Option<Voice>, waiting: bool) -> Group {
    Group {
        space,
        tree: Tree::new(own),
        sessions: HashMap::new(),
        linked: 0,
        keys: HashMap::new(),
        keys_at: None,
        next: mesh::first_number(),
        waiting,
        asked: HashMap::new(),
        answered: HashMap::new(),
        thin_since: None,
        probe: None,
        frames_in: 0,
        frames_new: 0,
        since: Instant::now(),
        over: watch::channel(false).0,
    }
}

/// Carries group call `id` for others, if this device helps others, has
/// sessions with two or more member devices, and carries no call with
/// anyone on it in that group already. A device carries one call in each
/// group, and a few in all.
async fn maybe_carry(d: &Arc<Daemon>, id: [u8; 16], space: SpaceId) {
    if !d.conditions.helps() || groups(d).contains_key(&id) {
        return;
    }
    if crate::groups::member_sessions(d, &space).len() < 2 {
        return;
    }
    let now = Instant::now();
    let (over, stale) = {
        let mut gs = groups(d);
        if gs.contains_key(&id) {
            return;
        }
        let here = gs.iter().find(|(_, g)| g.space == space);
        let stale = match here {
            // One nobody is heard on gives way to the new one.
            Some((other, g))
                if g.tree.own().is_none() && g.probe.is_none() && !someone_on(g, now) =>
            {
                Some(*other)
            }
            Some(_) => return,
            None => None,
        };
        let carried = gs
            .values()
            .filter(|g| g.tree.own().is_none() && g.probe.is_none())
            .count();
        if stale.is_none() && carried >= MAX_CARRIED {
            return;
        }
        let stale = stale.and_then(|s| gs.remove(&s).map(|g| (s, g)));
        gs.insert(id, new_group(space, None, false));
        (gs[&id].over.subscribe(), stale)
    };
    if let Some((old, g)) = stale {
        g.over.send_replace(true);
        for (s, _) in g.sessions.values() {
            let _ = tokio::time::timeout(SIGNAL_WITHIN, tell(s, END, &g.space, &old)).await;
        }
    }
    tracing::debug!("carrying a group call for others");
    tokio::spawn(drive(d.clone(), id, over));
    relink(d, &id, &space, true).await;
    d.bump();
}

/// Leaves group call `id`: tells its links, and stops carrying it.
async fn leave(d: &Arc<Daemon>, id: &[u8; 16]) {
    let Some(g) = groups(d).remove(id) else {
        return;
    };
    g.over.send_replace(true);
    for (s, _) in g.sessions.values() {
        let _ = tokio::time::timeout(SIGNAL_WITHIN, tell(s, END, &g.space, id)).await;
    }
    d.bump();
}

async fn join(s: &Session, space: &SpaceId, id: &[u8; 16], carrying: bool) -> anyhow::Result<()> {
    let signal = Signal {
        kind: JOIN,
        space: *space,
        id: *id,
        flag: Some(u64::from(carrying)),
        caller: None,
        formats: None,
    };
    send(s, &signal).await
}

/// Asks the member devices this one has sessions with, and is not linked
/// with, to link: at once those never asked or on a new session, and again
/// now and then. With `all`, every one of them, as when its person joins.
async fn relink(d: &Arc<Daemon>, id: &[u8; 16], space: &SpaceId, all: bool) {
    let sessions = crate::groups::member_sessions(d, space);
    let (ask, carrying) = {
        let mut gs = groups(d);
        let Some(g) = gs.get_mut(id) else { return };
        if g.probe.is_some() {
            return;
        }
        let now = Instant::now();
        let mut ask = Vec::new();
        for s in sessions {
            let linked = g
                .sessions
                .get(&s.peer_static())
                .is_some_and(|(l, _)| l.handshake_hash() == s.handshake_hash() && !l.is_closed());
            if linked && !all {
                continue;
            }
            let lately = g
                .asked
                .get(&s.handshake_hash())
                .is_some_and(|t| now.duration_since(*t) < ASK_AGAIN);
            if lately && !all {
                continue;
            }
            g.asked.insert(s.handshake_hash(), now);
            ask.push(s);
        }
        g.asked
            .retain(|_, t| now.duration_since(*t) < ASK_AGAIN * 4);
        g.answered
            .retain(|_, t| now.duration_since(*t) < ANSWER_AGAIN);
        (ask, g.tree.own().is_none())
    };
    // Each on its own, so that a session that cannot take it now holds up
    // nothing else.
    for s in ask {
        let (space, id) = (*space, *id);
        tokio::spawn(async move {
            let asked = tokio::time::timeout(SIGNAL_WITHIN, join(&s, &space, &id, carrying));
            if let Ok(Err(e)) = asked.await {
                tracing::debug!("linking: {e:#}");
            }
        });
    }
}

/// The identities of a group's members who have not left it, this person
/// among them.
fn members(d: &Daemon, space: &SpaceId) -> std::collections::HashSet<[u8; 32]> {
    let core = d.core();
    core.spaces
        .get(space)
        .and_then(|h| h.space.as_ref())
        .map(|sp| sp.present().into_iter().collect())
        .unwrap_or_default()
}

/// Runs a group call's routing here until it is over: haves and presence
/// on the links, links that went silent let go, sessions asked to link, and
/// a device only carrying it gone once it joins nobody.
async fn drive(d: Arc<Daemon>, id: [u8; 16], mut over: watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(TICK);
    let mut n: u64 = 0;
    loop {
        tokio::select! {
            _ = over.wait_for(|over| *over) => return,
            _ = tick.tick() => {}
        }
        let now = Instant::now();
        let keepalive = n % KEEPALIVE_EVERY == 0;
        let here = n % HERE_EVERY == 0;
        let relinking = n % RELINK_EVERY == 0;
        n += 1;
        // Read before the call's lock: neither waits on it.
        let helps = d.conditions.helps();
        let on_it = lock(&d)
            .as_ref()
            .is_some_and(|c| c.id == id && c.group && c.standing != Standing::Ringing);
        let space = groups(&d).get(&id).map(|g| g.space);
        let Some(space) = space else { return };
        let members = relinking.then(|| members(&d, &space));
        let mut out: Vec<(Session, [u8; 16], Vec<u8>)> = Vec::new();
        let mut silent = Vec::new();
        let mut done = false;
        {
            let mut gs = groups(&d);
            let Some(g) = gs.get_mut(&id) else { return };
            let label = channel_label(&g.space, &id);
            let routing = routing_label(&g.space, &id);
            // Its person is not on it after all, as when they hung up in
            // the moment it was joining: it says nothing for them.
            if g.tree.own().is_some() && !on_it {
                g.tree.set_own(None);
            }
            // A device no longer in the group hears no more of it.
            if let Some(members) = &members {
                let gone: Vec<LinkId> = g
                    .sessions
                    .iter()
                    .filter(|(_, (s, _))| {
                        s.peer_identity()
                            .is_none_or(|p| !members.contains(&p.identity))
                    })
                    .map(|(l, _)| *l)
                    .collect();
                for l in gone {
                    g.tree.remove_link(&l);
                    g.sessions.remove(&l);
                }
            }
            for (l, w) in g.tree.haves(keepalive, now) {
                if let Some((s, _)) = g.sessions.get(&l) {
                    out.push((s.clone(), routing, w.encode()));
                }
            }
            for l in g.tree.silent(now) {
                g.tree.remove_link(&l);
                if let Some((s, _)) = g.sessions.remove(&l) {
                    // Asked to link again at the next look, not later.
                    g.asked.remove(&s.handshake_hash());
                    silent.push(s);
                }
            }
            if let (true, Some(own)) = (here, g.tree.own()) {
                let f = mesh::frame(&d.keys.signing, &id, &own, g.next, &[]);
                g.tree.sent(g.next, now);
                g.next = g.next.wrapping_add(1);
                for l in g.tree.own_targets(true) {
                    if let Some((s, _)) = g.sessions.get(&l) {
                        out.push((s.clone(), label, f.clone()));
                    }
                }
            }
            if let Some((until, _)) = g.probe {
                done = now >= until;
            } else if g.tree.own().is_none() {
                let thin = g.tree.links() < 2;
                match (thin, g.thin_since) {
                    (true, None) => g.thin_since = Some(now),
                    (false, _) => g.thin_since = None,
                    _ => {}
                }
                let thin_long = g
                    .thin_since
                    .is_some_and(|t| now.duration_since(t) >= THIN_FOR);
                let heard = g.tree.last_fresh().unwrap_or(g.since).max(g.since);
                let quiet = now.duration_since(heard) >= QUIET_FOR;
                done = thin_long || quiet || !helps;
            }
        }
        for (s, l, b) in out {
            let _ = s.send_datagram(l, Priority::RealTime, b);
        }
        if !silent.is_empty() {
            // Its session may be gone too: it is asked, and linked again
            // once there is one.
            for s in &silent {
                s.check();
            }
            d.bump();
        }
        if done {
            tracing::debug!("no longer carrying a group call");
            leave(&d, &id).await;
            return;
        }
        if relinking {
            relink(&d, &id, &space, false).await;
            // Those on a call with this device are in use: looked for if
            // their session goes (`sync.md#neighbours`).
            crate::groups::use_members(&d, &space);
        }
    }
}

/// A signal about a call in a group this person is in.
async fn group_signal(
    d: &Arc<Daemon>,
    s: &Session,
    them: [u8; 32],
    sig: Signal,
    name: String,
) -> anyhow::Result<()> {
    let (kind, space, id) = (sig.kind, sig.space, sig.id);
    let me = contacts::identity(d).ok();
    let own_device = Some(them) == me;
    // A call by this id in another group is no business of this one.
    if groups(d).get(&id).is_some_and(|g| g.space != space) {
        return Ok(());
    }
    let now = Instant::now();
    match kind {
        RING => {
            // Rings from one member, passed on or not, only so often.
            if !own_device && !may_ring(d, &them) {
                return Ok(());
            }
            // A call with someone on it already going on here in this
            // group: the ringer joins that one instead.
            let going = groups(d)
                .iter()
                .find(|(other, g)| {
                    g.space == space && **other != id && g.probe.is_none() && someone_on(g, now)
                })
                .map(|(other, g)| (*other, g.tree.on_it(now) >= 2));
            if let Some((going, busy)) = going {
                let says = Signal {
                    kind: ONGOING,
                    space,
                    id: going,
                    flag: Some(u64::from(busy)),
                    caller: None,
                    formats: None,
                };
                send(s, &says).await?;
                return Ok(());
            }
            // Passed on once, to the members only this device reaches,
            // whether or not it rings here.
            if !remember(&d.passed_rings, id) {
                for other in crate::groups::member_sessions(d, &space) {
                    if other.peer_static() != s.peer_static() {
                        let on = Signal {
                            kind: RING,
                            space,
                            id,
                            flag: None,
                            caller: sig.caller,
                            formats: None,
                        };
                        let _ = tokio::time::timeout(SIGNAL_WITHIN, send(&other, &on)).await;
                    }
                }
            }
            // A call this person made, as one of their own devices says.
            let mine = own_device && sig.caller.is_some() && sig.caller == me;
            if mine {
                remember(&d.rung_calls, id);
            } else {
                // Rung once for a call is enough: it can come again by
                // another member, after this person said no.
                let rang_before = d
                    .rung_calls
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .contains(&id);
                let fresh = !rang_before && {
                    let mut call = lock(d);
                    if call.is_some() {
                        false
                    } else {
                        let mut c =
                            Call::new(id, space, name, space, Standing::Ringing, Some(s.clone()));
                        c.group = true;
                        *call = Some(c);
                        true
                    }
                };
                if fresh {
                    remember(&d.rung_calls, id);
                    d.bump();
                    ring_out(d, id);
                }
            }
            maybe_carry(d, id, space).await;
        }
        JOIN => {
            let carrying = sig.flag == Some(1);
            // This person answered on another of their devices: this one
            // stops ringing, whether or not it carries the call.
            if !carrying && own_device {
                let ringing = lock(d).as_ref().is_some_and(|c| {
                    c.id == id && c.space == space && c.standing == Standing::Ringing
                });
                if ringing {
                    forget(d, &id, Ending::AnsweredElsewhere);
                }
            }
            if !groups(d).contains_key(&id) {
                maybe_carry(d, id, space).await;
            }
            let (added, answer, went_live, linked) = {
                let mut gs = groups(d);
                let Some(g) = gs.get_mut(&id).filter(|g| g.space == space) else {
                    return Ok(());
                };
                let ps = s.peer_static();
                let same = g.sessions.get(&ps).is_some_and(|(l, _)| {
                    l.handshake_hash() == s.handshake_hash() && !l.is_closed()
                });
                if !same {
                    g.tree.remove_link(&ps);
                    g.sessions.remove(&ps);
                }
                let added = g.tree.add_link(ps, !carrying, now);
                if added {
                    g.linked += 1;
                    g.sessions.insert(ps, (s.clone(), g.linked));
                }
                // One it has a link with already may have lost its own end
                // of it: answered again, but not more than now and then.
                let lately = g
                    .answered
                    .get(&s.handshake_hash())
                    .is_some_and(|t| now.duration_since(*t) < ANSWER_AGAIN);
                let answer = added || !lately;
                if answer {
                    g.answered.insert(s.handshake_hash(), now);
                }
                if carrying {
                    // Its person has left, or was never on it.
                    if let Some(p) = s.peer_identity() {
                        g.tree.forget(&mesh::voice_of(&p.signing_key));
                    }
                }
                let went_live = !carrying && g.waiting;
                if went_live {
                    g.waiting = false;
                }
                (added, answer, went_live, g.linked)
            };
            if went_live {
                live_now(d, &id);
            }
            if added {
                carry_link(d, s, space, id, linked);
            }
            if answer {
                // Said back, and if its person is on it, that it is there,
                // so the other counts it at once.
                let here = {
                    let mut gs = groups(d);
                    gs.get_mut(&id).map(|g| {
                        let f = g.tree.own().filter(|_| added).map(|own| {
                            let f = mesh::frame(&d.keys.signing, &id, &own, g.next, &[]);
                            g.tree.sent(g.next, now);
                            g.next = g.next.wrapping_add(1);
                            f
                        });
                        (g.tree.own().is_none(), f)
                    })
                };
                if let Some((carrying_here, here)) = here {
                    join(s, &space, &id, carrying_here).await?;
                    if let Some(f) = here {
                        let _ = s.send_datagram(channel_label(&space, &id), Priority::RealTime, f);
                    }
                }
            }
            d.bump();
        }
        END => {
            {
                let mut gs = groups(d);
                if let Some(g) = gs.get_mut(&id) {
                    let ps = s.peer_static();
                    g.tree.remove_link(&ps);
                    g.sessions.remove(&ps);
                    // That device has left.
                    if let Some(p) = s.peer_identity() {
                        g.tree.forget(&mesh::voice_of(&p.signing_key));
                    }
                }
            }
            d.bump();
        }
        ONGOING => {
            // This person is calling while the group has a call with people
            // on it going on: this device links to it, and once it hears
            // someone on it other than the device that said so, joins it.
            if sig.flag != Some(1) {
                return Ok(());
            }
            let calling = lock(d).as_ref().is_some_and(|c| {
                c.group && c.space == space && c.standing == Standing::Calling && c.id != id
            });
            let Some(sender) = s.peer_identity().map(|p| mesh::voice_of(&p.signing_key)) else {
                return Ok(());
            };
            if !calling {
                return Ok(());
            }
            let confirmed = {
                let mut gs = groups(d);
                match gs.get_mut(&id) {
                    Some(g) if g.tree.others_but(&sender, now) >= 1 => true,
                    Some(g) => {
                        if g.tree.own().is_none() {
                            g.probe = Some((now + PROBE_FOR, sender));
                        }
                        false
                    }
                    None => {
                        let mut g = new_group(space, None, false);
                        g.probe = Some((now + PROBE_FOR, sender));
                        let over = g.over.subscribe();
                        gs.insert(id, g);
                        tokio::spawn(drive(d.clone(), id, over));
                        false
                    }
                }
            };
            if confirmed {
                switch_to(d.clone(), id).await;
            } else {
                join(s, &space, &id, true).await?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// This person, calling with nobody else on their call yet, joins call
/// `id` in the same group instead, which has someone on it.
async fn switch_to(d: Arc<Daemon>, id: [u8; 16]) {
    let (old, space) = {
        let mut call = lock(&d);
        let Some(c) = call
            .as_mut()
            .filter(|c| c.group && c.standing == Standing::Calling && c.id != id)
        else {
            return;
        };
        let old = c.id;
        c.id = id;
        c.standing = Standing::Live;
        c.live_since = Some(Instant::now());
        (old, c.space)
    };
    leave(&d, &old).await;
    take_part(&d, id, space, false);
    d.bump();
    relink(&d, &id, &space, true).await;
}

/// This person's call, which waited, has someone else on it.
fn live_now(d: &Daemon, id: &[u8; 16]) {
    let mut call = lock(d);
    if let Some(c) = call
        .as_mut()
        .filter(|c| c.id == *id && c.standing == Standing::Calling)
    {
        c.standing = Standing::Live;
        c.live_since = Some(Instant::now());
        drop(call);
        d.bump();
    }
}

/// Carries a group call on one link, until the call is over, the session
/// goes, or the link is made again.
fn carry_link(d: &Arc<Daemon>, s: &Session, space: SpaceId, id: [u8; 16], linked: u64) {
    let mut sound = s.channel(channel_label(&space, &id), Priority::RealTime);
    let mut words = s.channel(routing_label(&space, &id), Priority::RealTime);
    let (d, s) = (d.clone(), s.clone());
    let over = groups(&d).get(&id).map(|g| g.over.subscribe());
    let Some(mut over) = over else { return };
    tokio::spawn(async move {
        let mut check = tokio::time::interval(SESSION_CHECK);
        loop {
            tokio::select! {
                _ = over.wait_for(|over| *over) => return,
                frame = sound.recv() => match frame {
                    Some(frame) => passed(&d, &s, &id, frame),
                    None => break,
                },
                word = words.recv() => match word {
                    Some(word) => said(&d, &s, &id, &word),
                    None => break,
                },
                _ = check.tick() => {
                    if s.is_closed() {
                        break;
                    }
                }
            }
        }
        {
            let mut gs = groups(&d);
            if let Some(g) = gs.get_mut(&id) {
                let ps = s.peer_static();
                if g.sessions.get(&ps).is_some_and(|(_, n)| *n == linked) {
                    g.sessions.remove(&ps);
                    g.tree.remove_link(&ps);
                    g.asked.remove(&s.handshake_hash());
                }
            }
        }
        d.bump();
    });
}

/// The signing key of a voice in group call `id`, reading the group's
/// devices again if it is not known and they were not read just now.
fn key_of(d: &Daemon, id: &[u8; 16], voice: &Voice) -> Option<[u8; 32]> {
    let space = {
        let gs = groups(d);
        let g = gs.get(id)?;
        if let Some(k) = g.keys.get(voice) {
            return Some(*k);
        }
        if g.keys_at.is_some_and(|t| t.elapsed() < KEYS_EVERY) {
            return None;
        }
        g.space
    };
    let keys = device_keys(d, &space);
    let found = keys.get(voice).copied();
    if let Some(g) = groups(d).get_mut(id) {
        g.keys = keys;
        g.keys_at = Some(Instant::now());
    }
    found
}

/// The signing keys of the devices of a group's members, by voice, from
/// their logs as held here.
fn device_keys(d: &Daemon, space: &SpaceId) -> HashMap<Voice, [u8; 32]> {
    let core = d.core();
    let mut out = HashMap::new();
    let Some(sp) = core.spaces.get(space).and_then(|h| h.space.as_ref()) else {
        return out;
    };
    for m in sp.present() {
        let state = match core.identity.as_ref() {
            Some(i) if i.id() == m => i.log.state(),
            _ => match core.others.get(&m) {
                Some(o) => o.log.state(),
                None => continue,
            },
        };
        if state.frozen {
            continue;
        }
        for k in state.keys.values().filter(|k| k.link_key.is_some()) {
            out.insert(mesh::voice_of(&k.key), k.key);
        }
    }
    out
}

/// One frame of a group call, come on the link `from`.
fn passed(d: &Arc<Daemon>, from: &Session, id: &[u8; 16], bytes: Bytes) {
    let Some(f) = Frame::parse(&bytes) else {
        return;
    };
    let (voice, n, here) = (f.voice, f.n, f.here());
    let ps = from.peer_static();
    let now = Instant::now();
    let new = {
        let mut gs = groups(d);
        let Some(g) = gs.get_mut(id) else { return };
        // Past its share of frames a link's are dropped unread.
        if !g.tree.admit(&ps, now) {
            return;
        }
        g.tree.is_new(&voice, n)
    };
    // Only a frame not seen here is worth checking, and every one that is
    // gets checked, even one straight from the device whose voice it is,
    // since it is passed on to devices that will check it.
    let key = new
        .then(|| {
            from.peer_identity()
                .map(|p| p.signing_key)
                .filter(|k| mesh::voice_of(k) == voice)
                .or_else(|| key_of(d, id, &voice))
        })
        .flatten();
    let genuine = key.is_some_and(|k| mesh::signed_by(&f, id, &k));
    // A device passes on only what it checked, so a frame that fails against
    // a key known here was made up by the device that sent it: that link is
    // let go. One whose key is not known here yet only goes nowhere.
    let forged = new && !genuine && key.is_some();
    let (got, to, hear, went_live, confirmed, label, routing) = {
        let mut gs = groups(d);
        let Some(g) = gs.get_mut(id) else { return };
        if forged {
            tracing::info!("a group call's link sent a frame it made up: letting it go");
            g.tree.remove_link(&ps);
            g.sessions.remove(&ps);
            return;
        }
        let got = g.tree.on_frame(&ps, voice, n, here, genuine, now);
        g.frames_in += 1;
        g.frames_new += u64::from(got.fresh);
        let to: Vec<Session> = got
            .forward
            .iter()
            .filter_map(|l| g.sessions.get(l).map(|(s, _)| s.clone()))
            .collect();
        let hear = got.fresh && !here && g.tree.own().is_some();
        let went_live = got.fresh && g.waiting;
        if went_live {
            g.waiting = false;
        }
        // Someone other than the device that said this call was going on
        // is on it: this person can join it.
        let confirmed = got.fresh && g.probe.is_some_and(|(_, sender)| sender != voice);
        if confirmed {
            g.probe = None;
        }
        let label = channel_label(&g.space, id);
        let routing = routing_label(&g.space, id);
        (got, to, hear, went_live, confirmed, label, routing)
    };
    if got.prune {
        let _ = from.send_datagram(routing, Priority::RealTime, Word::Prune(voice).encode());
    }
    for l in to {
        let _ = l.send_datagram(label, Priority::RealTime, bytes.clone());
    }
    if hear {
        let _ = d
            .call_audio
            .send((*id, Some(voice), bytes.slice(mesh::HEADER..)));
    }
    if went_live {
        live_now(d, id);
    }
    if confirmed {
        tokio::spawn(switch_to(d.clone(), *id));
    }
}

/// A routing word on the link `from`. Only words about the voices of the
/// group's devices count.
fn said(d: &Daemon, from: &Session, id: &[u8; 16], bytes: &[u8]) {
    let Some(word) = Word::decode(bytes) else {
        return;
    };
    for v in word.voices() {
        let known = groups(d).get(id).is_some_and(|g| g.keys.contains_key(&v));
        if !known {
            key_of(d, id, &v);
        }
    }
    let (graft, routing) = {
        let mut gs = groups(d);
        let Some(g) = gs.get_mut(id) else { return };
        let Some(word) = word.only(|v| g.keys.contains_key(v)) else {
            return;
        };
        let graft = g.tree.on_word(&from.peer_static(), word, Instant::now());
        (graft, routing_label(&g.space, id))
    };
    for v in graft {
        let _ = from.send_datagram(routing, Priority::RealTime, Word::Graft(v).encode());
    }
}

/// Serves the `ephemeral` service. Only someone this person shares the space
/// with may ring them in it (`spaces.md#ephemeral-messages`); this person's
/// own devices speak only of group calls.
pub async fn serve(d: &Arc<Daemon>, s: &Session, mut st: Stream, v: Value) -> anyhow::Result<()> {
    let them = match d.classify(s) {
        PeerKind::Contact(them, _) | PeerKind::Inviting(them, Some(_)) => them,
        PeerKind::Own(_) => match contacts::identity(d) {
            Ok(me) => me,
            Err(_) => {
                st.reset(0);
                return Ok(());
            }
        },
        _ => {
            st.reset(0);
            return Ok(());
        }
    };
    // A call's signal is small; the service reads larger messages for others.
    if v.encode().len() > MAX_SIGNAL {
        st.reset(0);
        return Ok(());
    }
    let Some(sig) = Signal::of(&v) else {
        st.reset(0);
        return Ok(());
    };
    let (kind, space, id) = (sig.kind, sig.space, sig.id);
    if let Some(name) = crate::groups::shared_group(d, &space, &them) {
        return group_signal(d, s, them, sig, name).await;
    }
    let contacts = d.core().contacts();
    let found = contacts
        .iter()
        .find(|c| c.identity == them && c.space == space);
    let Some(contact) = found.filter(|c| !c.refused) else {
        st.reset(0);
        return Ok(());
    };
    match kind {
        // The call already ringing here, rung again over another session
        // (one made since, or another found): not busy, and not another
        // ring. The newer session is the one to answer on.
        RING if again(d, &id, &them) => {
            if let Some(c) = lock(d).as_mut().filter(|c| c.id == id && c.who == them) {
                c.session = Some(s.clone());
            }
        }
        RING if !may_ring(d, &them) => {
            busy(s, &space, &id).await?;
        }
        RING => {
            // They turned to this person: look for them if this session goes.
            d.rendezvous.use_contact(&them);
            let busy = {
                let mut call = lock(d);
                let busy = call.is_some();
                if !busy {
                    let name = contact.petname.clone();
                    let ringing = Standing::Ringing;
                    let session = Some(s.clone());
                    let mut c = Call::new(id, them, name, space, ringing, session);
                    c.offered = sig.formats.clone();
                    *call = Some(c);
                }
                busy
            };
            if busy {
                self::busy(s, &space, &id).await?;
            } else {
                d.bump();
                ring_out(d, id);
            }
        }
        ANSWER => {
            // Checked and taken at once: the call may end, and another
            // begin, between two looks.
            let expected = {
                let mut call = lock(d);
                let found = call
                    .as_mut()
                    .filter(|c| c.id == id && c.who == them && c.standing == Standing::Calling);
                found.is_some_and(|c| {
                    // Only what was offered counts as taken.
                    c.taken = c
                        .offered
                        .as_deref()
                        .map(|offered| taking(offered, sig.formats.as_deref()));
                    true
                })
            };
            if !expected {
                // Too late, or never was: they are not to think they are on a call.
                tell(s, END, &space, &id).await?;
                return Ok(());
            }
            go_live(d, s, id);
            // Their other devices can stop ringing.
            told_the_others(d, s, &them, &space, &id, Some(ANSWERED_ELSEWHERE)).await;
        }
        END => {
            let ended = {
                let mut call = lock(d);
                let same = call.as_ref().is_some_and(|c| c.id == id && c.who == them);
                let on_it = call.as_ref().is_some_and(|c| {
                    let session = c.session.as_ref();
                    session.is_some_and(|c| c.peer_static() == s.peer_static())
                });
                let live = call.as_ref().is_some_and(|c| c.standing == Standing::Live);
                // A device that is not on a live call has no say in it.
                if same && (on_it || !live) {
                    call.take()
                } else {
                    None
                }
            };
            if let Some(call) = ended {
                let how = match (call.standing, sig.flag) {
                    (Standing::Ringing, Some(ANSWERED_ELSEWHERE)) => Ending::AnsweredElsewhere,
                    (Standing::Ringing, Some(DECLINED_ELSEWHERE)) => Ending::DeclinedElsewhere,
                    (Standing::Ringing, _) => Ending::Missed,
                    (Standing::Calling, Some(BUSY)) => Ending::Busy,
                    (Standing::Calling, _) => Ending::TheyDeclined,
                    (Standing::Live, _) => Ending::Over,
                };
                finished(d, &call, how);
                // A no on one device stops the others ringing.
                if call.standing == Standing::Calling {
                    // busy is not a no: to their other devices, it went unanswered
                    let why = (sig.flag != Some(BUSY)).then_some(DECLINED_ELSEWHERE);
                    told_the_others(d, s, &them, &space, &id, why).await;
                }
            }
        }
        _ => st.reset(0),
    }
    Ok(())
}

/// Whether `id` from `them` is the call already ringing here.
fn again(d: &Daemon, id: &[u8; 16], them: &[u8; 32]) -> bool {
    lock(d)
        .as_ref()
        .is_some_and(|c| c.id == *id && c.who == *them && c.standing == Standing::Ringing)
}

/// Ends the ring on a person's devices other than the one that spoke,
/// saying why (`ANSWERED_ELSEWHERE` or `DECLINED_ELSEWHERE`), or nothing:
/// nobody answered.
async fn told_the_others(
    d: &Daemon,
    s: &Session,
    them: &[u8; 32],
    space: &SpaceId,
    id: &[u8; 16],
    why: Option<u64>,
) {
    let end = Signal {
        kind: END,
        space: *space,
        id: *id,
        flag: why,
        caller: None,
        formats: None,
    };
    for other in d.sessions_of(them) {
        if other.peer_static() != s.peer_static() {
            let _ = send(&other, &end).await;
        }
    }
}

/// Audio for and from a client, one `{"audio": hex}` line per frame, until
/// the client goes or the call does.
pub async fn media(d: &Arc<Daemon>, mut lines: tokio::io::Lines<BufReader<Reader>>, mut w: Writer) {
    let mut heard = d.call_audio.subscribe();
    let mut seen = d.call_video.subscribe();
    let mut stopping = d.stopping.subscribe();
    let mut changed = d.changed.subscribe();
    let Some(call) = lock(d).as_ref().map(|c| c.id) else {
        return;
    };
    let current = |d: &Daemon| lock(d).as_ref().is_some_and(|c| c.id == call);
    loop {
        tokio::select! {
            _ = stopping.changed() => return,
            c = changed.changed() => {
                if c.is_err() || !current(d) {
                    return;
                }
            }
            frame = heard.recv() => {
                let Ok((of, voice, frame)) = frame else { continue };
                if of != call {
                    continue;
                }
                let mut out = match voice {
                    Some(v) => json!({"audio": hex::encode(&frame), "from": hex::encode(v)}),
                    None => json!({"audio": hex::encode(&frame)}),
                }
                .to_string();
                out.push('\n');
                if w.write_all(out.as_bytes()).await.is_err() {
                    return;
                }
            }
            frame = seen.recv() => {
                let Ok((of, format, frame)) = frame else { continue };
                if of != call {
                    continue;
                }
                let mut out = json!({"frame": hex::encode(&frame), "format": hex::encode(format)})
                    .to_string();
                out.push('\n');
                if w.write_all(out.as_bytes()).await.is_err() {
                    return;
                }
            }
            line = lines.next_line() => {
                let Ok(Some(line)) = line else { return };
                let Ok(v) = serde_json::from_str::<Json>(&line) else { continue };
                if let Some(frame) = v["frame"].as_str().and_then(|h| hex::decode(h).ok()) {
                    let format = v["format"]
                        .as_str()
                        .and_then(|h| hex::decode(h).ok())
                        .and_then(|f| <Format>::try_from(f.as_slice()).ok());
                    if let Some(format) = format {
                        send_frame(d, format, frame);
                    }
                    continue;
                }
                let Some(frame) = v["audio"].as_str().and_then(|h| hex::decode(h).ok()) else {
                    continue;
                };
                send_audio(d, frame);
            }
        }
    }
}

/// A frame of one of the call's formats other than voice, between two people:
/// sent on that format's channel, if the call took it.
fn send_frame(d: &Daemon, format: Format, frame: Vec<u8>) {
    if format == voice() {
        send_audio(d, frame);
        return;
    }
    let (session, label) = {
        let call = lock(d);
        let Some(c) = call
            .as_ref()
            .filter(|c| c.standing == Standing::Live && !c.group)
        else {
            return;
        };
        if !c.taken.as_ref().is_some_and(|t| t.contains(&format)) {
            return;
        }
        (c.session.clone(), format_label(&c.space, &c.id, &format))
    };
    let Some(s) = session else { return };
    if frame.len() > cardinal_link::MAX_DATAGRAM_PAYLOAD {
        return;
    }
    if let Err(e) = s.send_datagram(label, Priority::Interactive, Bytes::from(frame)) {
        tracing::trace!("frame: {e}");
    }
}

fn send_audio(d: &Daemon, frame: Vec<u8>) {
    let (id, group, session, label) = {
        let call = lock(d);
        let Some(c) = call.as_ref().filter(|c| c.standing == Standing::Live) else {
            return;
        };
        (
            c.id,
            c.group,
            c.session.clone(),
            channel_label(&c.space, &c.id),
        )
    };
    if !group {
        let Some(s) = session else { return };
        if let Err(e) = s.send_datagram(label, Priority::RealTime, Bytes::from(frame)) {
            tracing::trace!("audio: {e}");
        }
        return;
    }
    // A frame with nothing in it is presence, which the routing sends.
    if frame.is_empty() || mesh::HEADER + frame.len() > cardinal_link::MAX_DATAGRAM_PAYLOAD {
        return;
    }
    let (out, to) = {
        let mut gs = groups(d);
        let Some(g) = gs.get_mut(&id) else { return };
        let Some(own) = g.tree.own() else { return };
        let out = Bytes::from(mesh::frame(&d.keys.signing, &id, &own, g.next, &frame));
        g.tree.sent(g.next, Instant::now());
        g.next = g.next.wrapping_add(1);
        let to: Vec<Session> = g
            .tree
            .own_targets(false)
            .iter()
            .filter_map(|l| g.sessions.get(l).map(|(s, _)| s.clone()))
            .collect();
        (out, to)
    };
    for s in &to {
        if let Err(e) = s.send_datagram(label, Priority::RealTime, out.clone()) {
            tracing::trace!("audio: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_answer_naming_nothing_takes_voice_only_and_formats_come_once() {
        let video = draft_format("video vp8 1");
        let offered = [voice(), video];
        assert_eq!(taking(&offered, None), vec![voice()]);
        assert_eq!(taking(&[video], None), Vec::<Format>::new());
        assert_eq!(taking(&offered, Some(&[video, [9; 32]])), vec![video]);
        assert_eq!(dedup([video, voice(), video]), vec![video, voice()]);
    }

    /// A ring offering the most formats, from a group, still fits what the
    /// software before formats takes, and reads back with them.
    #[test]
    fn a_ring_with_formats_fits_the_old_limit() {
        let s = Signal {
            kind: RING,
            space: [1; 32],
            id: [2; 16],
            flag: None,
            caller: Some([3; 32]),
            formats: Some(vec![voice(), draft_format("video vp8 1")]),
        };
        let v = Value::Record(s.record());
        assert!(v.encode().len() <= MAX_SIGNAL, "{}", v.encode().len());
        assert_eq!(Signal::of(&v), Some(s));
        let answer = Signal {
            kind: ANSWER,
            space: [1; 32],
            id: [2; 16],
            flag: None,
            caller: None,
            formats: Some(vec![voice()]),
        };
        let v = Value::Record(answer.record());
        assert_eq!(Signal::of(&v), Some(answer));
    }

    #[test]
    fn signals_read_back_whole_and_old_ones_still_read() {
        let s = Signal {
            kind: RING,
            space: [1; 32],
            id: [2; 16],
            flag: Some(1),
            caller: Some([3; 32]),
            formats: None,
        };
        let v = Value::Record(s.record());
        assert!(v.encode().len() <= MAX_SIGNAL, "{}", v.encode().len());
        assert_eq!(Signal::of(&v), Some(s));
        let old = Value::Record(
            Record::new()
                .with(0, END)
                .with(1, [1u8; 32])
                .with(2, [2u8; 16]),
        );
        let o = Signal::of(&old).unwrap();
        assert_eq!((o.kind, o.flag, o.caller), (END, None, None));
    }
}
