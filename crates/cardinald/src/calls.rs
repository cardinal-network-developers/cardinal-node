//! Calls (`profiles.md#calls`). A call needs no new mechanism: a `ring` on the
//! ephemeral service to the other person's online devices, and audio on a
//! datagram channel of their session, in the real-time class. What is in the
//! audio is the client's business: this carries it and looks at none of it.
//!
//! This handles one call at a time, between two people or in a group. A
//! group call has no centre (`profiles.md#calls`): each device on it links
//! with the others on it that it has sessions with, passes on what it hears
//! to the rest of its links once, and passes on only a few voices at once,
//! so no device carries everyone's traffic and a group's stays flat.

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
use crate::transport::{Reader, Writer};
use cardinal_space::account::ContactRecord;

const RING: u64 = 1;
const ANSWER: u64 = 2;
const END: u64 = 3;
/// In a group call: this device is on it, and the session it came on
/// carries the call's sound.
const JOIN: u64 = 4;

/// How many voices a device passes on at once in a group call: those that
/// began first, of those heard lately (`profiles.md#calls`).
const MOST_VOICES: usize = 6;
/// How long a voice counts as speaking after its last frame.
const VOICE_FOR: Duration = Duration::from_millis(500);
/// How many frames a device remembers having passed on, so that one coming
/// round another way is dropped.
const SEEN: usize = 4096;

/// The longest signal: a kind, a space and a call.
const MAX_SIGNAL: usize = 128;
/// How long a call rings before it stops.
const RINGS_FOR: Duration = Duration::from_secs(45);
/// How often a call looks at whether its session is still there.
const SESSION_CHECK: Duration = Duration::from_secs(5);
/// How long sessions get to answer before a call looks past them.
const ANSWER_WITHIN: Duration = Duration::from_millis(1500);
/// How long a session that did not answer has to end before the call looks
/// again: the link's answer timeout.
const GONE_WITHIN: Duration = Duration::from_secs(12);
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

/// The call under way.
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
    /// A group call: the sessions with the others on it that carry its
    /// sound, and what has gone through.
    group: Option<Mesh>,
}

/// What a device on a group call keeps.
#[derive(Default)]
struct Mesh {
    links: Vec<Session>,
    /// This device's voice, and the number of its next frame.
    origin: [u8; 8],
    next: u32,
    seen: std::collections::HashSet<([u8; 8], u32)>,
    order: std::collections::VecDeque<([u8; 8], u32)>,
    /// When each voice began speaking, and was last heard.
    voices: std::collections::HashMap<[u8; 8], (Instant, Instant)>,
    /// When each voice was last heard at all, to count who is on the call.
    heard: std::collections::HashMap<[u8; 8], Instant>,
}

impl Mesh {
    fn new(origin: [u8; 8]) -> Mesh {
        Mesh {
            origin,
            ..Mesh::default()
        }
    }

    /// Whether a frame is new here, remembering it if so.
    fn fresh(&mut self, key: ([u8; 8], u32)) -> bool {
        if !self.seen.insert(key) {
            return false;
        }
        self.order.push_back(key);
        if self.order.len() > SEEN {
            if let Some(old) = self.order.pop_front() {
                self.seen.remove(&old);
            }
        }
        true
    }

    /// Whether a voice is one of the few passed on now.
    fn passes(&mut self, voice: [u8; 8]) -> bool {
        let now = Instant::now();
        self.voices
            .retain(|_, (_, last)| now.duration_since(*last) < VOICE_FOR);
        let began = self.voices.get(&voice).map_or(now, |(began, _)| *began);
        self.voices.insert(voice, (began, now));
        let earlier = self.voices.values().filter(|(b, _)| *b < began).count();
        earlier < MOST_VOICES
    }
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
            group: None,
        }
    }

    fn close(&self) {
        self.over.send_replace(true);
    }
}

fn lock(d: &Daemon) -> std::sync::MutexGuard<'_, Option<Call>> {
    d.call.lock().unwrap_or_else(|e| e.into_inner())
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

async fn tell(s: &Session, kind: u64, space: &SpaceId, id: &[u8; 16]) -> anyhow::Result<()> {
    let mut st = s.open_stream(Service::EPHEMERAL, Priority::RealTime)?;
    let signal = Record::new().with(0, kind).with(1, *space).with(2, *id);
    st.send_message(&Value::Record(signal)).await?;
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
            let _ = end(&d).await;
        }
    });
}

/// Rings a contact. Ringing here does not stop this person calling someone:
/// a call that is only ringing gives way.
pub async fn start(d: &Arc<Daemon>, who: &str) -> anyhow::Result<Json> {
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
    let call = Call::new(
        id,
        contact.identity,
        contact.petname.clone(),
        contact.space,
        Standing::Calling,
        None,
    );
    let gave_way = {
        let mut held = lock(d);
        let ringing = held
            .as_ref()
            .is_some_and(|c| c.standing == Standing::Ringing);
        anyhow::ensure!(held.is_none() || ringing, "you are already on a call");
        held.replace(call)
    };
    if let Some(old) = gave_way {
        old.close();
        if let Some(s) = &old.session {
            let _ = tell(s, END, &old.space, &old.id).await;
        }
    }
    d.bump();
    for s in &theirs {
        if let Err(e) = tell(s, RING, &contact.space, &id).await {
            tracing::debug!("ringing: {e:#}");
        }
    }
    if contact.connects() {
        let rung: Vec<[u8; 32]> = theirs.iter().map(Session::handshake_hash).collect();
        tokio::spawn(ring_where_found(d.clone(), contact, id, rung));
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
            if let Err(e) = tell(&s, RING, &contact.space, &id).await {
                tracing::debug!("ringing: {e:#}");
            }
        }
    }
}

/// Takes the call that is ringing here.
pub async fn answer(d: &Arc<Daemon>) -> anyhow::Result<Json> {
    let group = lock(d)
        .as_ref()
        .filter(|c| c.standing == Standing::Ringing && c.group.is_some())
        .map(|c| (c.space, c.id));
    if let Some((space, id)) = group {
        if let Some(c) = lock(d).as_mut() {
            c.standing = Standing::Live;
            c.live_since = Some(Instant::now());
        }
        d.bump();
        join_all(d, &space, &id).await;
        return Ok(json!({}));
    }
    let (s, space, id) = {
        let mut call = lock(d);
        let c = call
            .as_mut()
            .filter(|c| c.standing == Standing::Ringing)
            .ok_or_else(|| anyhow::anyhow!("nothing is ringing"))?;
        // Taken now, so a second answer finds nothing ringing.
        c.standing = Standing::Live;
        let s = c.session.clone();
        (
            s.ok_or_else(|| anyhow::anyhow!("that call has gone"))?,
            c.space,
            c.id,
        )
    };
    if let Err(e) = tell(&s, ANSWER, &space, &id).await {
        let _ = end(d).await;
        return Err(e);
    }
    go_live(d, &s, id);
    Ok(json!({}))
}

/// Hangs up, or says no.
pub async fn end(d: &Arc<Daemon>) -> anyhow::Result<Json> {
    let Some(call) = lock(d).take() else {
        return Ok(json!({}));
    };
    call.close();
    d.bump();
    let told = match (&call.group, call.session) {
        // In a group, this device leaves: the others go on.
        (Some(mesh), _) => mesh.links.clone(),
        (None, Some(s)) => vec![s],
        (None, None) => d.sessions_of(&call.who),
    };
    for s in told {
        let _ = tell(&s, END, &call.space, &call.id).await;
    }
    Ok(json!({}))
}

/// Forgets a call that has ended by itself.
fn forget(d: &Daemon, id: &[u8; 16]) {
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
        call.close();
        d.bump();
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
        forget(&d, &id);
    });
}

/// What is known of the call under way.
pub fn current(d: &Daemon) -> Json {
    let call = lock(d);
    let Some(c) = call.as_ref() else {
        return json!({"call": null});
    };
    let standing = match c.standing {
        Standing::Calling => "calling",
        Standing::Ringing => "ringing",
        Standing::Live => "live",
    };
    let group = c.group.as_ref();
    json!({"call": {
        "who": hex::encode(&c.who[..8]),
        "name": c.name,
        "state": standing,
        "seconds": c.live_since.map(|t| t.elapsed().as_secs()),
        "group": group.map(|_| hex::encode(c.space)),
        "linked": group.map(|m| m.links.iter().filter(|s| !s.is_closed()).count()),
        "people": group.map(on_the_call),
    }})
}

/// This device's voice in group calls: who it is, without saying.
fn origin_of(d: &Daemon) -> [u8; 8] {
    voice_of(&d.keys.key())
}

fn voice_of(key: &[u8; 32]) -> [u8; 8] {
    let h = blake3::hash(key);
    let mut o = [0; 8];
    o.copy_from_slice(&h.as_bytes()[..8]);
    o
}

/// How many are on a group call, as far as this device can tell: itself,
/// those it is linked with, and every voice heard lately through them.
fn on_the_call(m: &Mesh) -> usize {
    let lately = Duration::from_secs(30);
    let mut voices: std::collections::HashSet<[u8; 8]> = m
        .heard
        .iter()
        .filter(|(_, t)| t.elapsed() < lately)
        .map(|(v, _)| *v)
        .collect();
    for l in m.links.iter().filter(|l| !l.is_closed()) {
        if let Some(p) = l.peer_identity() {
            voices.insert(voice_of(&p.signing_key));
        }
    }
    voices.remove(&m.origin);
    voices.len() + 1
}

/// Rings a group: each member device this one has a session with, and
/// each of those passes the ring on to theirs.
pub async fn start_group(d: &Arc<Daemon>, group: &str) -> anyhow::Result<Json> {
    let (space, name) = crate::groups::joined_group(d, group)?;
    let theirs = crate::groups::member_sessions(d, &space);
    anyhow::ensure!(
        !theirs.is_empty(),
        "nobody in {name} can be reached right now"
    );
    let id: [u8; 16] = cardinal_crypto::random_bytes();
    let mut call = Call::new(id, space, name, space, Standing::Calling, None);
    call.group = Some(Mesh::new(origin_of(d)));
    {
        let mut held = lock(d);
        let ringing = held
            .as_ref()
            .is_some_and(|c| c.standing == Standing::Ringing);
        anyhow::ensure!(held.is_none() || ringing, "you are already on a call");
        if let Some(old) = held.replace(call) {
            old.close();
        }
    }
    d.bump();
    for s in &theirs {
        if let Err(e) = tell(s, RING, &space, &id).await {
            tracing::debug!("ringing: {e:#}");
        }
    }
    ring_out(d, id);
    Ok(json!({}))
}

/// A signal about a call in a group this person is in.
async fn group_signal(
    d: &Arc<Daemon>,
    s: &Session,
    them: [u8; 32],
    kind: u64,
    space: SpaceId,
    id: [u8; 16],
    name: String,
) -> anyhow::Result<()> {
    let ours = |c: &Call| c.id == id && c.group.is_some();
    match kind {
        RING => {
            let fresh = {
                let mut call = lock(d);
                if call.is_some() || !may_ring(d, &them) {
                    false
                } else {
                    let mut c =
                        Call::new(id, space, name, space, Standing::Ringing, Some(s.clone()));
                    c.group = Some(Mesh::new(origin_of(d)));
                    *call = Some(c);
                    true
                }
            };
            if fresh {
                d.bump();
                ring_out(d, id);
                // The ring goes on to the members only this device reaches.
                for other in crate::groups::member_sessions(d, &space) {
                    if other.peer_static() != s.peer_static() {
                        let _ = tell(&other, RING, &space, &id).await;
                    }
                }
            }
        }
        JOIN => {
            let added = {
                let mut call = lock(d);
                let Some(c) = call.as_mut().filter(|c| ours(c)) else {
                    return Ok(());
                };
                if c.standing == Standing::Ringing {
                    return Ok(());
                }
                if c.standing == Standing::Calling {
                    c.standing = Standing::Live;
                    c.live_since = Some(Instant::now());
                }
                let mesh = c.group.as_mut().expect("a group call");
                let new = !mesh
                    .links
                    .iter()
                    .any(|l| l.peer_static() == s.peer_static() && !l.is_closed());
                if new {
                    mesh.links.retain(|l| l.peer_static() != s.peer_static());
                    mesh.links.push(s.clone());
                }
                new
            };
            if added {
                d.bump();
                carry_link(d, s, space, id);
                tell(s, JOIN, &space, &id).await?;
            }
        }
        END => {
            let mut call = lock(d);
            if let Some(mesh) = call
                .as_mut()
                .filter(|c| ours(c))
                .and_then(|c| c.group.as_mut())
            {
                mesh.links.retain(|l| l.peer_static() != s.peer_static());
            }
            drop(call);
            d.bump();
        }
        _ => {}
    }
    Ok(())
}

/// Tells every member device this one has a session with that it is on the
/// call: those on it link back.
async fn join_all(d: &Arc<Daemon>, space: &SpaceId, id: &[u8; 16]) {
    for s in crate::groups::member_sessions(d, space) {
        let _ = tell(&s, JOIN, space, id).await;
    }
}

/// Carries a group call's sound on one link: each frame that comes is
/// heard here, unless it is this device's own, and passed on to the other
/// links once, if its voice is one of the few passed on now.
fn carry_link(d: &Arc<Daemon>, s: &Session, space: SpaceId, id: [u8; 16]) {
    let mut channel = s.channel(channel_label(&space, &id), Priority::RealTime);
    let (d, s) = (d.clone(), s.clone());
    let over = lock(&d).as_ref().map(|c| c.over.subscribe());
    let Some(mut over) = over else { return };
    tokio::spawn(async move {
        let mut check = tokio::time::interval(SESSION_CHECK);
        loop {
            tokio::select! {
                _ = over.wait_for(|over| *over) => return,
                frame = channel.recv() => match frame {
                    Some(frame) => passed(&d, &s, &id, frame),
                    None => break,
                },
                _ = check.tick() => {
                    if s.is_closed() {
                        break;
                    }
                }
            }
        }
        let mut call = lock(&d);
        if let Some(mesh) = call
            .as_mut()
            .filter(|c| c.id == id)
            .and_then(|c| c.group.as_mut())
        {
            mesh.links.retain(|l| l.peer_static() != s.peer_static());
        }
        drop(call);
        d.bump();
    });
}

/// One frame of a group call, come on the link `from`.
fn passed(d: &Daemon, from: &Session, id: &[u8; 16], frame: Bytes) {
    if frame.len() < 12 {
        return;
    }
    let mut voice = [0; 8];
    voice.copy_from_slice(&frame[..8]);
    let n = u32::from_be_bytes([frame[8], frame[9], frame[10], frame[11]]);
    let (onward, label) = {
        let mut call = lock(d);
        let Some(c) = call
            .as_mut()
            .filter(|c| c.id == *id && c.standing == Standing::Live)
        else {
            return;
        };
        let label = channel_label(&c.space, &c.id);
        let Some(mesh) = c.group.as_mut() else { return };
        if voice == mesh.origin || !mesh.fresh((voice, n)) {
            return;
        }
        mesh.heard.insert(voice, Instant::now());
        if !mesh.passes(voice) {
            return;
        }
        let onward: Vec<Session> = mesh
            .links
            .iter()
            .filter(|l| l.peer_static() != from.peer_static() && !l.is_closed())
            .cloned()
            .collect();
        (onward, label)
    };
    let _ = d.call_audio.send((*id, Some(voice), frame.slice(12..)));
    for l in onward {
        let _ = l.send_datagram(label, Priority::RealTime, frame.clone());
    }
}

fn signal_of(v: &Value) -> Option<(u64, SpaceId, [u8; 16])> {
    let r = v.as_record()?;
    let kind = r.get(0)?.as_uint()?;
    let space = r.get(1)?.as_bytes()?.try_into().ok()?;
    let id = r.get(2)?.as_bytes()?.try_into().ok()?;
    Some((kind, space, id))
}

/// Serves the `ephemeral` service. Only someone this person shares the space
/// with may ring them in it (`spaces.md#ephemeral-messages`).
pub async fn serve(d: &Arc<Daemon>, s: &Session, mut st: Stream) -> anyhow::Result<()> {
    let them = match d.classify(s) {
        PeerKind::Contact(them, _) | PeerKind::Inviting(them, Some(_)) => them,
        _ => {
            st.reset(0);
            return Ok(());
        }
    };
    let Some(v) = st.recv_message_max(MAX_SIGNAL).await? else {
        return Ok(());
    };
    let Some((kind, space, id)) = signal_of(&v) else {
        st.reset(0);
        return Ok(());
    };
    if let Some(name) = crate::groups::shared_group(d, &space, &them) {
        return group_signal(d, s, them, kind, space, id, name).await;
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
        RING if !may_ring(d, &them) => {
            tell(s, END, &space, &id).await?;
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
                    *call = Some(Call::new(id, them, name, space, ringing, session));
                }
                busy
            };
            if busy {
                tell(s, END, &space, &id).await?;
            } else {
                d.bump();
                ring_out(d, id);
            }
        }
        ANSWER => {
            let expected = lock(d)
                .as_ref()
                .is_some_and(|c| c.id == id && c.who == them && c.standing == Standing::Calling);
            if !expected {
                // Too late, or never was: they are not to think they are on a call.
                tell(s, END, &space, &id).await?;
                return Ok(());
            }
            go_live(d, s, id);
            // Their other devices can stop ringing.
            told_the_others(d, s, &them, &space, &id).await;
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
                call.close();
                d.bump();
                // A no on one device stops the others ringing.
                if call.standing == Standing::Calling {
                    told_the_others(d, s, &them, &space, &id).await;
                }
            }
        }
        _ => st.reset(0),
    }
    Ok(())
}

/// Ends the ring on a person's devices other than the one that spoke.
async fn told_the_others(d: &Daemon, s: &Session, them: &[u8; 32], space: &SpaceId, id: &[u8; 16]) {
    for other in d.sessions_of(them) {
        if other.peer_static() != s.peer_static() {
            let _ = tell(&other, END, space, id).await;
        }
    }
}

/// Audio for and from a client, one `{"audio": hex}` line per frame, until
/// the client goes or the call does.
pub async fn media(d: &Arc<Daemon>, mut lines: tokio::io::Lines<BufReader<Reader>>, mut w: Writer) {
    let mut heard = d.call_audio.subscribe();
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
            line = lines.next_line() => {
                let Ok(Some(line)) = line else { return };
                let Ok(v) = serde_json::from_str::<Json>(&line) else { continue };
                let Some(frame) = v["audio"].as_str().and_then(|h| hex::decode(h).ok()) else {
                    continue;
                };
                send_audio(d, frame);
            }
        }
    }
}

fn send_audio(d: &Daemon, frame: Vec<u8>) {
    let mut call = lock(d);
    let live = call.as_mut().filter(|c| c.standing == Standing::Live);
    let Some(c) = live else { return };
    let label = channel_label(&c.space, &c.id);
    if let Some(mesh) = c.group.as_mut() {
        // This device's voice, numbered, to every link.
        let n = mesh.next;
        mesh.next = mesh.next.wrapping_add(1);
        let mut out = Vec::with_capacity(12 + frame.len());
        out.extend_from_slice(&mesh.origin);
        out.extend_from_slice(&n.to_be_bytes());
        out.extend_from_slice(&frame);
        let out = Bytes::from(out);
        for l in mesh.links.iter().filter(|l| !l.is_closed()) {
            if let Err(e) = l.send_datagram(label, Priority::RealTime, out.clone()) {
                tracing::trace!("audio: {e}");
            }
        }
        return;
    }
    let Some(s) = c.session.as_ref() else { return };
    if let Err(e) = s.send_datagram(label, Priority::RealTime, Bytes::from(frame)) {
        tracing::trace!("audio: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_coming_round_again_is_dropped() {
        let mut m = Mesh::new([9; 8]);
        assert!(m.fresh(([1; 8], 7)));
        assert!(!m.fresh(([1; 8], 7)));
        assert!(m.fresh(([2; 8], 7)));
        for n in 0..SEEN as u32 {
            m.fresh(([3; 8], n));
        }
        // Forgotten after enough others: a number used long ago comes again.
        assert!(m.fresh(([1; 8], 7)));
    }

    /// However many speak at once, only the first few voices go on, until
    /// one of them stops.
    #[test]
    fn only_a_few_voices_go_on_at_once() {
        let mut m = Mesh::new([0; 8]);
        let voices: Vec<[u8; 8]> = (1..=8u8).map(|v| [v; 8]).collect();
        for v in &voices {
            m.passes(*v);
            std::thread::sleep(Duration::from_millis(2));
        }
        let going: Vec<bool> = voices.iter().map(|v| m.passes(*v)).collect();
        assert_eq!(
            going.iter().filter(|g| **g).count(),
            MOST_VOICES,
            "{going:?}"
        );
        assert!(going[0] && !going[7], "{going:?}");
        // The first falls silent, and the next who speaks goes on.
        std::thread::sleep(VOICE_FOR + Duration::from_millis(50));
        for v in &voices[1..] {
            m.passes(*v);
        }
        assert!(m.passes(voices[6]), "a seventh voice is held back still");
    }
}
