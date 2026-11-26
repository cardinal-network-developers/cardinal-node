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
use tokio::io::AsyncWriteExt;
use tokio::sync::watch;

use crate::contacts;
use crate::daemon::{Daemon, PeerKind};
use crate::mesh::{self, Frame, LinkId, Tree, Voice, Word};
use crate::pictures::{self, Ask, KeyTo, Pictures, Size, Want};
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

/// A `3:` that is not a number: none of the numbers any signal names.
const NOT_A_NUMBER: u64 = u64::MAX;
/// On a `ring` in a group, `3:` 1: for the devices it is sent to and nobody
/// else, never passed on (`profiles.md#calls-guidance`, Ringing some).
const FOR_SOME: u64 = 1;

/// What a `ring` in a group is, by its `3:`: `Some(false)` one for the
/// whole group, `Some(true)` one for some only, and `None` one with any
/// other `3:`, which is ignored.
fn ring_kind(sig: &Signal) -> Option<bool> {
    match sig.flag {
        None => Some(false),
        Some(FOR_SOME) => Some(true),
        Some(_) => None,
    }
}

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
    /// What this device takes of it, if the ring named formats: what its
    /// answer took, or the other side's, until this one answers again.
    taken: Option<Vec<Format>>,
    /// What the other side takes, and so what this device sends it: what
    /// the answer took, until they answer again (`basics/video.md`).
    they_take: Option<Vec<Format>>,
    /// The shape of this person's window, while one shows the call: told to
    /// those who send it video (`basics/video.md`), and never kept.
    viewport: Option<Viewport>,
    /// This person's camera is on, as their window says: told to the others
    /// on the call (`basics/video.md#cameras`), and never kept.
    camera: bool,
    /// Between two people, when the other side last said its camera is on;
    /// `None` while it is off, or was not said again in time.
    their_camera: Option<Instant>,
    /// In a group, who rang this device: known only once a `ring` for the
    /// call came from one of the caller's own devices.
    caller: Option<[u8; 32]>,
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
            they_take: None,
            viewport: None,
            camera: false,
            their_camera: None,
            caller: None,
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
    let at = crate::core::now_ms();
    let ended = json!({
        "id": hex::encode(call.id),
        "who": hex::encode(&call.who[..8]),
        "name": call.name,
        "group": call.group.then(|| hex::encode(call.space)),
        "how": how.name(),
        "at": at,
    });
    *d.call_ended.lock().unwrap_or_else(|e| e.into_inner()) = Some(ended);
    // A group's last call, kept on this device for itself (D92).
    if call.group {
        let last = crate::core::LastCall {
            id: hex::encode(call.id),
            who: hex::encode(&call.who[..8]),
            name: call.name.clone(),
            how: how.name().to_owned(),
            at,
        };
        // written outside the core's lock, and off this task
        let save = d.core().note_last_call(&call.space, last);
        if let Some(save) = save {
            save.write_later();
        }
    }
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
    /// The members last seen in the group: when they change, as when
    /// someone leaves, the keys are read again.
    members: std::collections::HashSet<[u8; 32]>,
    /// The number of this device's next frame.
    next: u32,
    /// Its person called, and nobody else is on it yet.
    waiting: bool,
    /// The devices this one rang for the call, by their link key, each
    /// with the session it was rung on: told when its person gives up
    /// (`profiles.md#calls-guidance`, A caller who gives up).
    rang: HashMap<[u8; 32], Session>,
    /// When each session was last asked to link, by handshake.
    asked: HashMap<[u8; 32], Instant>,
    /// When each session was last answered on a link it already had.
    answered: HashMap<[u8; 32], Instant>,
    /// Since when, while only carrying, it has had fewer than two links.
    thin_since: Option<Instant>,
    /// Linked only to see whether someone is on it, as another device said:
    /// until when, and that device's voice.
    probe: Option<(Instant, Voice)>,
    /// The number of the newest viewport of each voice seen here, this
    /// device's own among them.
    viewports: HashMap<Voice, u32>,
    /// The newest word of each voice on whether its camera is on
    /// (`basics/video.md#cameras`), this device's own among them.
    cameras: HashMap<Voice, Camera>,
    /// Its pictures (`basics/video.md#groups`): what is asked of whom.
    pictures: Pictures,
    /// The number of this device's next picture of each size.
    picture_next: [u32; 2],
    /// The sizes its window was last told are asked of it.
    wanted: Option<Want>,
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

/// The channel a group call's words about pictures go on:
/// `first16(BLAKE3(space id || call id || format name || "asks"))`
/// (`basics/video.md#groups`).
fn asks_label(space: &SpaceId, id: &[u8; 16]) -> [u8; 16] {
    let mut h = blake3::Hasher::new();
    h.update(space);
    h.update(id);
    h.update(&video());
    h.update(b"asks");
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

/// Video (`basics/video.md`): of its frames this service reads only the
/// viewports, which it repeats and, in a group, passes on.
pub fn video() -> Format {
    draft_format("video vp8 1")
}

/// The shape of a window that shows someone's video: its width and height.
pub type Viewport = (u16, u16);

/// A frame of one of a call's other formats, for this person's window: the
/// call, the format, and in a group whose picture it is and its size
/// (`basics/video.md#groups`).
#[derive(Clone, Debug)]
pub struct Shown {
    pub call: [u8; 16],
    pub format: Format,
    pub from: Option<Voice>,
    pub size: Option<Size>,
    pub frame: Bytes,
}

/// A viewport on the video channel is `1 || width (2) || height (2)`,
/// big-endian, which no RTP packet is: RTP's first byte starts with bits 10.
const VIEWPORT: u8 = 1;

fn viewport_frame((w, h): Viewport) -> [u8; 5] {
    let (w, h) = (w.to_be_bytes(), h.to_be_bytes());
    [VIEWPORT, w[0], w[1], h[0], h[1]]
}

/// The viewport a frame on the video channel is, if it is one.
fn viewport_in(b: &[u8]) -> Option<Viewport> {
    let [VIEWPORT, w0, w1, h0, h1] = *b else {
        return None;
    };
    let v = (u16::from_be_bytes([w0, w1]), u16::from_be_bytes([h0, h1]));
    (v.0 > 0 && v.1 > 0).then_some(v)
}

/// Whether a device's camera is on, on the video channel: `3 || on (1)`,
/// on 0 or 1 (`basics/video.md#cameras`). No RTP packet, viewport or picture
/// begins so.
const CAMERA: u8 = 3;
/// How long a camera said to be on is taken to be, unless said again.
const CAMERA_FOR: Duration = Duration::from_secs(12);

fn camera_frame(on: bool) -> [u8; 2] {
    [CAMERA, u8::from(on)]
}

/// Whether the camera is on, if a frame on the video channel says so.
fn camera_in(b: &[u8]) -> Option<bool> {
    match *b {
        [CAMERA, 0] => Some(false),
        [CAMERA, 1] => Some(true),
        _ => None,
    }
}

/// The newest word of one voice on a group call about its camera.
struct Camera {
    n: u32,
    on: bool,
    at: Instant,
}

impl Camera {
    fn on(&self, now: Instant) -> bool {
        self.on && now.duration_since(self.at) < CAMERA_FOR
    }
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
            // one that is not a number is none of the numbers a kind has
            flag: r.get(3).map(|f| f.as_uint().unwrap_or(NOT_A_NUMBER)),
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
    ring_out_after(d, id, RINGS_FOR);
}

/// [`ring_out`], after `rings_for`.
fn ring_out_after(d: &Arc<Daemon>, id: [u8; 16], rings_for: Duration) {
    let d = d.clone();
    tokio::spawn(async move {
        tokio::time::sleep(rings_for).await;
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
        // A ring in a group is said no to by nothing sent: there may be
        // nothing the person accepted there to say it in.
        if let Some(s) = old.session.as_ref().filter(|_| !old.group) {
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

/// Takes the call that is ringing here; on a call already live between two
/// people, changes what this device takes of what was offered
/// ([`answer_again`]).
///
/// In a group only offered to this person, answering joins it first, as
/// `group-join` does, with `reach` their answer about their hosts, and only
/// with `join` true, their word that answering joins it: consent to join is
/// said, not implied. Every condition that let the call ring there is
/// looked at again first (`profiles.md#calls-guidance`, "Someone only
/// offered the group"); where any no longer holds, or the group cannot be
/// joined, as when the answer about hosts is needed and not given, nothing
/// is written and nothing is joined. `reach` and `join` are refused for a
/// call between two people, and change nothing in a group joined already.
pub async fn answer(
    d: &Arc<Daemon>,
    formats: Option<Vec<Format>>,
    reach: Option<bool>,
    join_too: Option<bool>,
) -> anyhow::Result<Json> {
    let two = lock(d).as_ref().is_some_and(|c| !c.group);
    anyhow::ensure!(
        !(two && reach.is_some()),
        "`reach` is for a call in a group: a call between two people joins nothing"
    );
    anyhow::ensure!(
        !(two && join_too.is_some()),
        "`join` is for a call that rings in a group only offered to you: a call between two \
         people joins nothing"
    );
    let live = lock(d)
        .as_ref()
        .is_some_and(|c| c.standing == Standing::Live && !c.group);
    if live {
        return answer_again(d, formats).await;
    }
    let group = lock(d)
        .as_ref()
        .filter(|c| c.standing == Standing::Ringing && c.group)
        .map(|c| (c.space, c.id, c.caller, c.name.clone()));
    if let Some((space, id, caller, name)) = group {
        // Answering is accepting the group: joined first, or not answered.
        if crate::groups::only_offered(d, &space) {
            anyhow::ensure!(
                join_too == Some(true),
                "answering this call adds you to {name}: say so with `join`. Nothing was \
                 written, and the call goes on ringing"
            );
            let still =
                caller.is_some_and(|c| crate::groups::offered_ring(d, &space, &c).is_some());
            if !still {
                offered_ring_still(d);
                anyhow::bail!(
                    "{name} can no longer be joined by answering this call, so it was not \
                     answered and nothing was written"
                );
            }
            crate::groups::join_exact(d, &space, reach).await?;
        }
        // In a group joined already, as when another of this person's
        // devices joined it meanwhile, `join` and `reach` change nothing.
        let still = {
            let mut call = lock(d);
            match call.as_mut().filter(|c| {
                c.id == id && c.space == space && c.group && c.standing == Standing::Ringing
            }) {
                Some(c) => {
                    c.standing = Standing::Live;
                    c.live_since = Some(Instant::now());
                    true
                }
                None => false,
            }
        };
        anyhow::ensure!(still, "that call has stopped ringing");
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
        let formats = with_video(c, formats);
        c.taken = c
            .offered
            .as_deref()
            .map(|offered| taking(offered, formats.as_deref()));
        c.they_take = c.taken.clone();
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

/// A new `answer` on a live call between two people (`basics/video.md`):
/// what this device takes now, of what the ring offered. The other side is
/// told, and sends only that from then on; what this device no longer takes
/// is not given to its window either.
async fn answer_again(d: &Arc<Daemon>, formats: Option<Vec<Format>>) -> anyhow::Result<Json> {
    let (s, space, id, taken) = {
        let mut call = lock(d);
        let c = call
            .as_mut()
            .filter(|c| c.standing == Standing::Live && !c.group)
            .ok_or_else(|| anyhow::anyhow!("there is no call to answer"))?;
        let offered = c
            .offered
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("this call offered only voice"))?;
        let formats = with_video(c, formats);
        let taken = taking(offered, formats.as_deref());
        c.taken = Some(taken.clone());
        let s = c.session.clone();
        (
            s.ok_or_else(|| anyhow::anyhow!("that call has gone"))?,
            c.space,
            c.id,
            taken,
        )
    };
    d.bump();
    tell_formats(&s, ANSWER, &space, &id, Some(&taken)).await?;
    // Taking video again, the sender has this window's shape at once.
    send_viewport(d);
    Ok(json!({}))
}

/// What an answer takes, with video added while this person's camera is
/// on: a device whose camera is on takes the others' video
/// (`basics/video.md#cameras`). An answer naming nothing is voice.
fn with_video(c: &Call, formats: Option<Vec<Format>>) -> Option<Vec<Format>> {
    if !c.camera || !c.offered.as_ref().is_some_and(|o| o.contains(&video())) {
        return formats;
    }
    let mut f = formats.unwrap_or_else(|| vec![voice()]);
    f.push(video());
    Some(f)
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
        gave_up(d, &call).await;
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

/// A caller who leaves group call `call` having heard nobody else on it
/// tells each device it rang, with an `end` with no `3:`, so that they stop
/// ringing (`profiles.md#calls-guidance`, A caller who gives up). Where
/// someone else was heard, leaving ends nothing for those still ringing.
async fn gave_up(d: &Daemon, call: &Call) {
    let rang: Vec<Session> = {
        let gs = groups(d);
        match gs.get(&call.id) {
            Some(g) if g.waiting => g.rang.values().cloned().collect(),
            _ => Vec::new(),
        }
    };
    for s in rang {
        let _ = tokio::time::timeout(SIGNAL_WITHIN, tell(&s, END, &call.space, &call.id)).await;
    }
}

/// A ringing device takes an `end` for group call `id` from `them` as its
/// caller giving up only where `them` is who rang it, from one of their own
/// devices: the call is then one nobody answered. A ring kept for it is
/// dropped. An `end` from anyone else stops no ringing.
fn caller_gave_up(d: &Daemon, from: &Session, them: &[u8; 32], space: &SpaceId, id: &[u8; 16]) {
    drop_after_call(d, them, space, id);
    {
        let mut kept = d.kept_rings.lock().unwrap_or_else(|e| e.into_inner());
        if kept
            .get(them)
            .is_some_and(|k| k.id == *id && k.space == *space)
        {
            kept.remove(them);
        }
    }
    let theirs = lock(d).as_ref().is_some_and(|c| {
        c.id == *id
            && c.group
            && c.space == *space
            && c.standing == Standing::Ringing
            && c.caller == Some(*them)
    });
    // A device that carries the call and hears others on it takes the
    // `end` as the caller leaving a call going on, which ends nothing.
    let sender = from.peer_identity().map(|p| mesh::voice_of(&p.signing_key));
    let others = groups(d).get(id).is_some_and(|g| match &sender {
        Some(v) => g.tree.others_but(v, Instant::now()) >= 1,
        None => g.tree.others(Instant::now()) >= 1,
    });
    if theirs && !others {
        forget(d, id, Ending::Missed);
    }
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
        // Every format offered has its channel, since an answer may take it
        // later; what comes of one this device does not take now is dropped.
        let others: Vec<Format> = c
            .offered
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
                            Some(frame) => match viewport_in(&frame) {
                                Some(v) if format == video() => {
                                    let _ = d.call_viewport.send((id, None, v));
                                }
                                // Heard whether or not this side takes video:
                                // it is what its window asks by.
                                _ if format == video() && camera_in(&frame).is_some() => {
                                    their_camera(&d, &id, camera_in(&frame) == Some(true));
                                }
                                _ if !takes(&d, &id, &format) => {}
                                _ => {
                                    let _ = d.call_video.send(Shown {
                                        call: id,
                                        format,
                                        from: None,
                                        size: None,
                                        frame,
                                    });
                                }
                            },
                            None => return,
                        },
                    }
                }
            });
        }
        (s.channel(label, Priority::RealTime), c.over.subscribe())
    };
    d.bump();
    // A camera already on is said at once.
    send_camera(d, false);
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
                    // Said again, for one that was lost.
                    send_viewport(&d);
                    send_camera(&d, false);
                    their_camera_lapsed(&d, &id);
                }
            }
        }
        // The session went, and the call with it.
        forget(&d, &id, Ending::Over);
    });
}

/// The other side of the call `id`, between two people, says whether its
/// camera is on.
fn their_camera(d: &Daemon, id: &[u8; 16], on: bool) {
    let changed = {
        let mut call = lock(d);
        let Some(c) = call.as_mut().filter(|c| c.id == *id && !c.group) else {
            return;
        };
        let was = c.their_camera.is_some();
        c.their_camera = on.then(Instant::now);
        was != on
    };
    if changed {
        d.bump();
    }
}

/// The other side's camera, not said to be on again in time, is taken to
/// be off.
fn their_camera_lapsed(d: &Daemon, id: &[u8; 16]) {
    let lapsed = {
        let mut call = lock(d);
        let Some(c) = call.as_mut().filter(|c| c.id == *id) else {
            return;
        };
        let lapsed = c.their_camera.is_some_and(|t| t.elapsed() >= CAMERA_FOR);
        if lapsed {
            c.their_camera = None;
        }
        lapsed
    };
    if lapsed {
        d.bump();
    }
}

/// Whether this device takes `format` on the call `id` now.
fn takes(d: &Daemon, id: &[u8; 16], format: &Format) -> bool {
    lock(d)
        .as_ref()
        .is_some_and(|c| c.id == *id && c.taken.as_ref().is_some_and(|t| t.contains(format)))
}

/// What is known of the call under way.
pub fn current(d: &Daemon) -> Json {
    let ended = d
        .call_ended
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let (offered, taken, they_take, camera, own_camera) = {
        let call = lock(d);
        let hexes = |l: &Option<Vec<Format>>| {
            l.as_ref()
                .map(|l| l.iter().map(hex::encode).collect::<Vec<_>>())
        };
        call.as_ref().map_or((None, None, None, None, false), |c| {
            // between two, whether the other side's camera is on
            let camera = (!c.group && c.standing == Standing::Live)
                .then(|| c.their_camera.is_some_and(|t| t.elapsed() < CAMERA_FOR));
            (
                hexes(&c.offered),
                hexes(&c.taken),
                hexes(&c.they_take),
                camera,
                c.camera,
            )
        })
    };
    let (who, name, standing, seconds, space, group, id, caller) = {
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
            c.caller,
        )
    };
    let (linked, people, frames, heard, cameras) = if group {
        let gs = groups(d);
        let g = gs.get(&id);
        let now = Instant::now();
        // whose cameras are on: this device's own as its window says
        let cameras: std::collections::HashSet<Voice> = g.map_or_else(Default::default, |g| {
            let own = g.tree.own();
            g.cameras
                .iter()
                .filter(|(v, c)| Some(**v) != own && c.on(now))
                .map(|(v, _)| *v)
                .chain(own.filter(|_| own_camera))
                .collect()
        });
        (
            Some(g.map_or(0, |g| g.tree.links())),
            Some(g.map_or(1, |g| g.tree.on_it(now))),
            g.map(|g| json!({"in": g.frames_in, "new": g.frames_new})),
            g.map(|g| g.tree.others_heard(now)),
            cameras,
        )
    } else {
        (None, None, None, None, Default::default())
    };
    let voices = heard.map(|heard| voices(d, &space, &heard, &cameras));
    // the picture this person sees for them, if any
    let picture = {
        let contacts = d.core().contacts();
        let c = contacts.into_iter().find(|c| c.identity == who);
        c.and_then(|c| crate::names::shown(d, &c).remove("picture"))
    };
    let mut call = json!({
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
        "voices": voices,
        "offered": offered,
        "taken": taken,
        "they_take": they_take,
        "camera": camera,
    });
    // In a group: its name, whether it was made for a call, who looks after
    // it, who rang, and whether answering joins it (D92, D93).
    if group {
        let about = crate::groups::call_json(d, &space, caller.as_ref());
        if let Some(about) = about.as_object() {
            for (k, v) in about {
                if k == "name" && v.as_str().is_some_and(str::is_empty) {
                    continue;
                }
                call[k] = v.clone();
            }
        }
    }
    json!({"call": call, "ended": ended})
}

/// Who each voice heard on a group call is, as this person knows them:
/// `voice`, as a frame's `from` says it; `identity`, the start of the
/// person's id, as `contacts` and `group-members` give it; `name`, this
/// person's name for them, or else the group's; `contact`; `picture`,
/// a contact's; `you`, a device of this person's own; and `camera`, whether
/// its camera is on (`basics/video.md#cameras`). A voice is named
/// only for a device key in the log of a member of the group, as held here,
/// the key its frames were checked against: a voice heard that no member's
/// log has a key for is left out, since nothing says whose it is.
fn voices(
    d: &Daemon,
    space: &SpaceId,
    heard: &[Voice],
    cameras: &std::collections::HashSet<Voice>,
) -> Vec<Json> {
    let owners = device_owners(d, space);
    let core = d.core();
    let Some(sp) = core.spaces.get(space).and_then(|h| h.space.as_ref()) else {
        return Vec::new();
    };
    let Some(me) = core.identity.as_ref().map(|i| i.id()) else {
        return Vec::new();
    };
    let members = cardinal_space::group::members(sp);
    let contacts = core.contacts();
    heard
        .iter()
        .filter_map(|v| {
            let who = owners.get(v)?;
            let you = *who == me;
            // named as `group-members` names them: "You", this person's
            // name for a contact not refused, or else the group's
            let name = crate::groups::name_of(&me, &contacts, &members, who);
            let known = (!you && !cardinal_space::account::refused(&contacts, who))
                .then(|| contacts.iter().find(|c| c.identity == *who))
                .flatten();
            let picture = known.and_then(|c| crate::names::shown(d, c).remove("picture"));
            Some(json!({
                "voice": hex::encode(v),
                "identity": hex::encode(&who[..8]),
                "name": name,
                "contact": known.is_some(),
                "picture": picture,
                "you": you,
                "camera": cameras.contains(v),
            }))
        })
        .collect()
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

/// Whether a group call has people on it, as a ring is answered: two heard
/// lately, its own person among them; or its own person and a device that
/// linked to it as one whose person is on it, which counts before its
/// first frame comes.
fn has_people(g: &Group, now: Instant) -> bool {
    g.tree.on_it(now) >= 2 || g.tree.own().is_some() && !g.waiting && g.tree.any_person()
}

/// Whether someone is on a group call, as far as this device can tell: its
/// own person, or anyone heard lately.
fn someone_on(g: &Group, now: Instant) -> bool {
    g.tree.own().is_some() && !g.waiting || g.tree.others(now) >= 1
}

/// Rings a group: each member device this one has a session with, and
/// each of those passes the ring on to theirs. If a call with someone on it
/// is going on in it already, that is the one this person joins.
///
/// With `ring`, only those members are rung, with a `ring` for some that
/// nobody passes on (`profiles.md#calls-guidance`, Ringing some): into the
/// group's call where this person is on it already, and otherwise into the
/// call this starts or joins. Each must be a member who has not left, not
/// this person, and their contact; where any is not, nobody is rung.
pub async fn start_group(
    d: &Arc<Daemon>,
    group: &str,
    ring: Option<&[String]>,
) -> anyhow::Result<Json> {
    let (space, name) = crate::groups::joined_group(d, group)?;
    let some = match ring {
        Some(named) => Some(crate::groups::to_ring(d, &space, named)?),
        None => None,
    };
    // On the group's call already: those named are rung into it.
    let on_it = lock(d)
        .as_ref()
        .filter(|c| c.group && c.space == space && c.standing != Standing::Ringing)
        .map(|c| c.id);
    if let Some(id) = on_it {
        if let Some(named) = some {
            ring_some(d, space, id, named);
            return Ok(json!({}));
        }
    }
    // Refused before anything is touched: the call this person is on, or
    // the one they are calling alone, keeps its routing.
    {
        let held = lock(d);
        let ringing = held
            .as_ref()
            .is_some_and(|c| c.standing == Standing::Ringing);
        anyhow::ensure!(held.is_none() || ringing, "you are already on a call");
    }
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
    // Ringing some is refused only as the specification says
    // (`apps.md`, `call-start`): those not reachable now are looked for
    // once the request has been answered.
    if some.is_none() {
        anyhow::ensure!(
            going.is_some() || !theirs.is_empty(),
            "nobody in {name} can be reached right now"
        );
    }
    let id = going.unwrap_or_else(cardinal_crypto::random_bytes);
    let mut call = Call::new(id, space, name, space, Standing::Calling, None);
    call.group = true;
    if going.is_some() {
        call.standing = Standing::Live;
        call.live_since = Some(Instant::now());
    }
    let gave = {
        let mut held = lock(d);
        let ringing = held
            .as_ref()
            .is_some_and(|c| c.standing == Standing::Ringing);
        anyhow::ensure!(held.is_none() || ringing, "you are already on a call");
        held.replace(call)
    };
    if let Some(old) = gave {
        finished(d, &old, gave_way(&old));
    }
    take_part(d, id, space, going.is_none());
    d.bump();
    if going.is_some() {
        relink(d, &id, &space, true).await;
        if let Some(named) = some {
            ring_some(d, space, id, named);
        }
        return Ok(json!({}));
    }
    let me = contacts::identity(d).ok();
    remember(&d.rung_calls, id);
    remember(&d.passed_rings, id);
    if let Some(named) = some {
        ring_some(d, space, id, named);
        ring_out(d, id);
        return Ok(json!({}));
    }
    for s in &theirs {
        rang_on(d, &id, s);
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

/// Rings `named` into group call `id` with a `ring` for some, once to each
/// of their devices for this asking, on one session however many it has
/// with that device (`profiles.md#calls-guidance`, Ringing some). Nothing
/// waits on it: those with a session are rung at once, and each named who
/// has none is looked for meanwhile, without holding the request. Before
/// each ring goes out, the call is checked to be still this person's.
fn ring_some(d: &Arc<Daemon>, space: SpaceId, id: [u8; 16], named: Vec<ContactRecord>) {
    let sent = Arc::new(std::sync::Mutex::new(std::collections::HashSet::new()));
    for c in named {
        let (d, sent) = (d.clone(), sent.clone());
        tokio::spawn(async move {
            let now = d.sessions_of(&c.identity);
            if !now.is_empty() || !c.connects() {
                send_some(&d, space, id, &now, &sent).await;
                return;
            }
            crate::rendezvous::reach_now(&d, c.identity, c.space).await;
            send_some(&d, space, id, &d.sessions_of(&c.identity), &sent).await;
        });
    }
}

/// Whether group call `id` in `space` is still the call this person made or
/// is on: a ring for it goes out only then.
fn still_mine(d: &Daemon, space: &SpaceId, id: &[u8; 16]) -> bool {
    lock(d).as_ref().is_some_and(|c| {
        c.id == *id && c.group && c.space == *space && c.standing != Standing::Ringing
    })
}

/// Sends a `ring` for some, `3:` 1, naming this person as the caller, on
/// one of `sessions` for each device, where none was sent to that device
/// for this asking (`sent`, by link key).
async fn send_some(
    d: &Arc<Daemon>,
    space: SpaceId,
    id: [u8; 16],
    sessions: &[Session],
    sent: &std::sync::Mutex<std::collections::HashSet<[u8; 32]>>,
) {
    let me = contacts::identity(d).ok();
    for s in sessions {
        if !still_mine(d, &space, &id) {
            return;
        }
        let first = sent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(s.peer_static());
        if !first {
            continue;
        }
        let ring = Signal {
            kind: RING,
            space,
            id,
            flag: Some(FOR_SOME),
            caller: me,
            formats: None,
        };
        rang_on(d, &id, s);
        let sent = tokio::time::timeout(SIGNAL_WITHIN, send(s, &ring)).await;
        if let Ok(Err(e)) = sent {
            tracing::debug!("ringing: {e:#}");
        }
    }
}

/// Notes that this device rang a device for group call `id` on `s`.
fn rang_on(d: &Daemon, id: &[u8; 16], s: &Session) {
    if let Some(g) = groups(d).get_mut(id) {
        g.rang.insert(s.peer_static(), s.clone());
    }
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
        members: std::collections::HashSet::new(),
        next: mesh::first_number(),
        waiting,
        rang: HashMap::new(),
        asked: HashMap::new(),
        answered: HashMap::new(),
        thin_since: None,
        probe: None,
        viewports: HashMap::new(),
        cameras: HashMap::new(),
        pictures: Pictures::default(),
        picture_next: [mesh::first_number(); 2],
        wanted: None,
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
        let mut rekey = false;
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
                if g.members != *members {
                    g.members.clone_from(members);
                    rekey = true;
                }
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
                    g.pictures.remove_link(&l);
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
                g.pictures.remove_link(&l);
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
        // The group's members changed: its devices' keys, which video,
        // viewports and levels are checked against, are read again.
        if rekey {
            let keys = device_keys(&d, &space);
            if let Some(g) = groups(&d).get_mut(&id) {
                g.keys = keys;
                g.keys_at = Some(Instant::now());
            }
        }
        for (s, l, b) in out {
            let _ = s.send_datagram(l, Priority::RealTime, b);
        }
        if here && on_it {
            send_viewport(&d);
            send_camera(&d, false);
        }
        // A camera not said to be on again in time is taken to be off; its
        // number is kept, so that an old word is not taken again.
        let lapsed = groups(&d).get_mut(&id).is_some_and(|g| {
            let own = g.tree.own();
            let mut lapsed = false;
            for (v, c) in &mut g.cameras {
                if Some(*v) != own && c.on && !c.on(now) {
                    c.on = false;
                    lapsed = true;
                }
            }
            lapsed
        });
        if lapsed && on_it {
            d.bump();
        }
        if keepalive || here {
            say_asks(&d, &id, keepalive, here && on_it);
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
            // A `3:` other than 1 makes the ring ignored; one for some is
            // taken only from a device of the caller it names.
            let Some(some) = ring_kind(&sig) else {
                return Ok(());
            };
            if some && sig.caller != Some(them) {
                return Ok(());
            }
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
                .map(|(other, g)| (*other, has_people(g, now)));
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
            // whether or not it rings here; one for some, never.
            if !some && !remember(&d.passed_rings, id) {
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
                // Who rang is known only from the caller's own device: one
                // that passed the ring on could name anyone.
                let caller = sig.caller.filter(|c| *c == them && !own_device);
                // Rung once for a call is enough: it can come again by
                // another member, after this person said no. A ring for
                // some is its caller asking, each time.
                let rang_before = !some
                    && d.rung_calls
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .contains(&id);
                let rings = !rang_before && ring_here(d, s, id, space, name, caller, RINGS_FOR);
                if !rings && caller.is_some() {
                    caller_known(d, &id, caller);
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
                    g.pictures.remove_link(&ps);
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
            if !own_device {
                caller_gave_up(d, s, &them, &space, &id);
            }
            {
                let mut gs = groups(d);
                if let Some(g) = gs.get_mut(&id) {
                    let ps = s.peer_static();
                    g.tree.remove_link(&ps);
                    g.pictures.remove_link(&ps);
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
            // One of this person's own devices on it says so whatever the
            // count: the call is theirs already.
            if sig.flag != Some(1) && !own_device {
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

/// The ring kept on a device on a call between two, from the person it is
/// on that call with, until that call ends (`profiles.md#calls-guidance`,
/// "A ring that comes before a call has ended"): only the last one, told
/// from those it replaced by how many came before it.
#[derive(Default)]
pub struct AfterCall {
    count: u64,
    kept: Option<([u8; 16], SpaceId, [u8; 32])>,
}

/// Rings here for group call `id`, for `rings_for`, if no call is held:
/// whether it does. Where the call held is one between this person and
/// `caller`, rung from `caller`'s own device, it is the call they are
/// ending: the ring is kept, the last such one alone, until that call ends,
/// and rings then for what is left of `rings_for`; where the call has not
/// ended by then, it is dropped and nothing rings. Kept counts as ringing.
fn ring_here(
    d: &Arc<Daemon>,
    s: &Session,
    id: [u8; 16],
    space: SpaceId,
    name: String,
    caller: Option<[u8; 32]>,
    rings_for: Duration,
) -> bool {
    let ending = {
        let call = lock(d);
        call.as_ref()
            .filter(|c| !c.group && caller.is_some_and(|w| c.who == w))
            .map(|c| c.over.subscribe())
    };
    let (Some(mut over), Some(them)) = (ending, caller) else {
        return ring_now(d, s, id, space, name, caller, rings_for);
    };
    let mine = {
        let mut after = d.after_call.lock().unwrap_or_else(|e| e.into_inner());
        after.count += 1;
        after.kept = Some((id, space, them));
        after.count
    };
    let (d, s) = (d.clone(), s.clone());
    tokio::spawn(async move {
        let began = Instant::now();
        let ended = tokio::time::timeout(rings_for, over.wait_for(|o| *o)).await;
        let left = rings_for.saturating_sub(began.elapsed());
        // still the one kept: not replaced by a later ring, nor dropped by
        // its caller's `end`
        let kept = {
            let mut after = d.after_call.lock().unwrap_or_else(|e| e.into_inner());
            let still = after.count == mine && after.kept.is_some();
            if still {
                after.kept = None;
            }
            still
        };
        // over, or gone: either way that call is not held now. Whatever let
        // the ring ring must hold still.
        let holds = crate::groups::shared_group(&d, &space, &them).is_some()
            || crate::groups::offered_ring(&d, &space, &them).is_some();
        if kept && ended.is_ok() && left > Duration::ZERO && holds {
            ring_now(&d, &s, id, space, name, caller, left);
        }
    });
    true
}

/// Drops the ring kept until a call between two ends, where it is for
/// group call `id` in `space` and `them` rang it.
fn drop_after_call(d: &Daemon, them: &[u8; 32], space: &SpaceId, id: &[u8; 16]) {
    let mut after = d.after_call.lock().unwrap_or_else(|e| e.into_inner());
    if after.kept == Some((*id, *space, *them)) {
        after.kept = None;
    }
}

/// [`ring_here`], where nothing is waited for.
fn ring_now(
    d: &Arc<Daemon>,
    s: &Session,
    id: [u8; 16],
    space: SpaceId,
    name: String,
    caller: Option<[u8; 32]>,
    rings_for: Duration,
) -> bool {
    let fresh = {
        let mut call = lock(d);
        if call.is_some() {
            false
        } else {
            let mut c = Call::new(id, space, name, space, Standing::Ringing, Some(s.clone()));
            c.group = true;
            c.caller = caller;
            *call = Some(c);
            true
        }
    };
    if fresh {
        remember(&d.rung_calls, id);
        d.bump();
        ring_out_after(d, id, rings_for);
    }
    fresh
}

/// Who rang for group call `id` here is known now, from the caller's own
/// device: a change to `watch`. Only while it rings here: on the device
/// that made the call, and on one already on it, as one that joined
/// without being rung, a ring for some from another member changes
/// nothing (`apps.md`, `call`).
fn caller_known(d: &Daemon, id: &[u8; 16], caller: Option<[u8; 32]>) {
    let changed = {
        let mut call = lock(d);
        match call.as_mut().filter(|c| {
            c.id == *id && c.group && c.caller.is_none() && c.standing == Standing::Ringing
        }) {
            Some(c) => {
                c.caller = caller;
                true
            }
            None => false,
        }
    };
    if changed {
        d.bump();
    }
}

/// The person declined group `space` here: a call there that rings stops,
/// as one they said no to (`profiles.md#calls-guidance`). With `here`
/// false, the decline came from another of their devices.
pub(crate) fn stop_ringing_in(d: &Daemon, space: &SpaceId, here: bool) {
    let ringing = lock(d)
        .as_ref()
        .filter(|c| c.group && c.space == *space && c.standing == Standing::Ringing)
        .map(|c| c.id);
    if let Some(id) = ringing {
        let how = match here {
            true => Ending::Declined,
            false => Ending::DeclinedElsewhere,
        };
        forget(d, &id, how);
    }
}

/// A call ringing in a group only offered to this person rings only while
/// all that let it ring still holds (`profiles.md#calls-guidance`, "Someone
/// only offered the group"): where the person has declined the group since,
/// on any device, or whoever rang has left it, or it has ended, it stops.
/// Looked at whenever something changes.
fn offered_ring_still(d: &Daemon) {
    let ringing = lock(d)
        .as_ref()
        .filter(|c| c.group && c.standing == Standing::Ringing)
        .map(|c| (c.id, c.space, c.caller));
    let Some((id, space, caller)) = ringing else {
        return;
    };
    if !crate::groups::only_offered(d, &space) {
        return;
    }
    let holds = caller.is_some_and(|c| crate::groups::offered_ring(d, &space, &c).is_some());
    if holds {
        return;
    }
    if d.core().is_declined(&space) {
        stop_ringing_in(d, &space, false);
    } else {
        forget(d, &id, Ending::Missed);
    }
}

/// A ring kept for a group offered to this person, until the offer has
/// come and the group opened (`profiles.md#calls-guidance`).
pub struct Kept {
    space: SpaceId,
    id: [u8; 16],
    some: bool,
    session: Session,
    at: Instant,
}

/// A signal about a call in a group this person has been offered and has
/// not accepted, from `them`, the contact who offered it: only their
/// `ring` reaches the person, and only from a device of theirs, naming
/// them as its caller. Nothing is passed on, linked or carried.
async fn offered_signal(
    d: &Arc<Daemon>,
    s: &Session,
    them: [u8; 32],
    sig: Signal,
    name: String,
) -> anyhow::Result<()> {
    if sig.kind == END {
        caller_gave_up(d, s, &them, &sig.space, &sig.id);
        return Ok(());
    }
    if sig.kind != RING {
        return Ok(());
    }
    let Some(some) = ring_kind(&sig) else {
        return Ok(());
    };
    if sig.caller != Some(them) || !may_ring(d, &them) {
        return Ok(());
    }
    offered_ring_here(d, s, them, sig.space, sig.id, some, name, RINGS_FOR);
    Ok(())
}

/// Rings for a call in a group only offered to this person, rung by `them`
/// who offered it.
#[allow(clippy::too_many_arguments)]
fn offered_ring_here(
    d: &Arc<Daemon>,
    s: &Session,
    them: [u8; 32],
    space: SpaceId,
    id: [u8; 16],
    some: bool,
    name: String,
    rings_for: Duration,
) {
    let rang_before = !some
        && d.rung_calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&id);
    if !rang_before && !ring_here(d, s, id, space, name, Some(them), rings_for) {
        caller_known(d, &id, Some(them));
    }
}

/// Keeps a `ring` from a contact for a group not yet offered here, or not
/// yet open: the last from each, for as long as a call rings. Whether it
/// was one to keep.
fn keep(d: &Daemon, s: &Session, them: [u8; 32], sig: &Signal) -> bool {
    let Some(some) = (sig.kind == RING).then(|| ring_kind(sig)).flatten() else {
        return false;
    };
    if sig.caller != Some(them) || !crate::groups::may_be_offered(d, &sig.space, &them) {
        return false;
    }
    if !may_ring(d, &them) {
        return true;
    }
    let kept = Kept {
        space: sig.space,
        id: sig.id,
        some,
        session: s.clone(),
        at: Instant::now(),
    };
    d.kept_rings
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(them, kept);
    d.bump();
    true
}

/// Rings each kept ring once the rest holds: its offer has come, and its
/// group has opened showing both as members. Looked at whenever something
/// changes, and each is let go once it has rung as long as a call rings.
pub fn ring_kept(d: Arc<Daemon>) {
    tokio::spawn(async move {
        let mut changed = d.changed.subscribe();
        loop {
            let waiting = {
                let mut kept = d.kept_rings.lock().unwrap_or_else(|e| e.into_inner());
                kept.retain(|_, k| k.at.elapsed() < RINGS_FOR);
                !kept.is_empty()
            };
            let next = if waiting {
                Duration::from_secs(1)
            } else {
                Duration::from_secs(3600)
            };
            tokio::select! {
                c = changed.changed() => if c.is_err() { return },
                _ = tokio::time::sleep(next) => {}
            }
            let all: Vec<([u8; 32], SpaceId)> = d
                .kept_rings
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .map(|(w, k)| (*w, k.space))
                .collect();
            offered_ring_still(&d);
            for (them, space) in all {
                let Some(name) = crate::groups::offered_ring(&d, &space, &them) else {
                    continue;
                };
                // Taken only where it is still the ring for the space just
                // checked: one kept since in its place waits for its own
                // check.
                let k = {
                    let mut kept = d.kept_rings.lock().unwrap_or_else(|e| e.into_inner());
                    match kept.get(&them) {
                        Some(k) if k.space == space => kept.remove(&them),
                        _ => None,
                    }
                };
                let Some(k) = k else {
                    continue;
                };
                let left = RINGS_FOR.saturating_sub(k.at.elapsed());
                if left > Duration::ZERO {
                    offered_ring_here(&d, &k.session, them, k.space, k.id, k.some, name, left);
                }
            }
        }
    });
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
    // Part of the new call before the old one is left, so that at no
    // moment is it a call this device only carries.
    take_part(&d, id, space, false);
    leave(&d, &old).await;
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
    let mut views = s.channel(format_label(&space, &id, &video()), Priority::RealTime);
    let mut asks = s.channel(asks_label(&space, &id), Priority::RealTime);
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
                view = views.recv() => match view {
                    Some(view) => viewed(&d, &s, &id, view),
                    None => break,
                },
                ask = asks.recv() => match ask {
                    Some(ask) => asked(&d, &s, &id, &ask),
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
                    g.pictures.remove_link(&ps);
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
    member_devices(d, space)
        .into_iter()
        .map(|(v, key, _)| (v, key))
        .collect()
}

/// The member whose device each voice of a group is, from their logs as
/// held here: the same keys [`device_keys`] checks frames against.
fn device_owners(d: &Daemon, space: &SpaceId) -> HashMap<Voice, [u8; 32]> {
    member_devices(d, space)
        .into_iter()
        .map(|(v, _, who)| (v, who))
        .collect()
}

/// Each device of a group's members: its voice, its signing key, and the
/// member, from their logs as held here.
fn member_devices(d: &Daemon, space: &SpaceId) -> Vec<(Voice, [u8; 32], [u8; 32])> {
    let core = d.core();
    let mut out = Vec::new();
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
            out.push((mesh::voice_of(&k.key), k.key, m));
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
    // a voice newly on the call changes who `call` says is on it
    let mut came = false;
    let (got, to, hear, went_live, confirmed, label, routing) = {
        let mut gs = groups(d);
        let Some(g) = gs.get_mut(id) else { return };
        if forged {
            tracing::info!("a group call's link sent a frame it made up: letting it go");
            g.tree.remove_link(&ps);
            g.pictures.remove_link(&ps);
            g.sessions.remove(&ps);
            return;
        }
        let was = g.tree.heard_lately(&voice, now);
        let got = g.tree.on_frame(&ps, voice, n, here, genuine, now);
        if got.fresh {
            g.pictures.came(voice, ps, now);
            came = !was && g.tree.own().is_some();
        }
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
        // is on it: this person can join it. The probe stays until they
        // take part: without it, and with nobody of its own on it yet, the
        // call would look carried here, and a device that does not help
        // others would leave it at its next tick.
        let confirmed = got.fresh && g.probe.is_some_and(|(_, sender)| sender != voice);
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
    if came {
        d.bump();
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

/// A viewport of a group call, come on the link `from` (`basics/video.md`):
/// the newest of its voice, signed by its device, is passed on to every other
/// link and given to this person's window.
fn viewed(d: &Daemon, from: &Session, id: &[u8; 16], bytes: Bytes) {
    let Some(f) = Frame::parse(&bytes) else {
        return;
    };
    if f.payload.first() == Some(&pictures::PICTURE_KIND) {
        pictured(d, from, id, &f, &bytes);
        return;
    }
    if let Some(on) = camera_in(f.payload) {
        camera_came(d, from, id, &f, on, &bytes);
        return;
    }
    let Some(v) = viewport_in(f.payload) else {
        return;
    };
    let ps = from.peer_static();
    let newest = |g: &Group| {
        g.viewports
            .get(&f.voice)
            .is_none_or(|m| mesh::after(f.n, *m))
    };
    {
        let mut gs = groups(d);
        let Some(g) = gs.get_mut(id) else { return };
        if !g.tree.admit(&ps, Instant::now()) || !newest(g) {
            return;
        }
    }
    let Some(key) = key_of(d, id, &f.voice) else {
        return;
    };
    if !mesh::signed_as(mesh::VIEWPORT, &f, id, &key) {
        return;
    }
    let (to, label, show) = {
        let mut gs = groups(d);
        let Some(g) = gs.get_mut(id) else { return };
        // Another link may have brought it while it was checked, or this
        // one been dropped.
        if !newest(g) || !on_call(g, &ps) {
            return;
        }
        g.viewports.insert(f.voice, f.n);
        g.pictures.came(f.voice, ps, Instant::now());
        let to: Vec<Session> = g
            .sessions
            .iter()
            .filter(|(l, _)| **l != ps)
            .map(|(_, (s, _))| s.clone())
            .collect();
        let show = g.tree.own().is_some_and(|own| own != f.voice);
        (to, format_label(&g.space, id, &video()), show)
    };
    for s in to {
        let _ = s.send_datagram(label, Priority::RealTime, bytes.clone());
    }
    if show {
        let _ = d.call_viewport.send((*id, Some(f.voice), v));
    }
}

/// A group call's word on whether a voice's camera is on, come on the link
/// `from` (`basics/video.md#cameras`): the newest of its voice, signed by its
/// device, is kept and passed on to every other link, as a viewport is.
fn camera_came(d: &Daemon, from: &Session, id: &[u8; 16], f: &Frame<'_>, on: bool, bytes: &Bytes) {
    let ps = from.peer_static();
    let newest = |g: &Group| {
        g.cameras
            .get(&f.voice)
            .is_none_or(|c| mesh::after(f.n, c.n))
    };
    {
        let mut gs = groups(d);
        let Some(g) = gs.get_mut(id) else { return };
        if !g.tree.admit(&ps, Instant::now()) || !newest(g) {
            return;
        }
    }
    let Some(key) = key_of(d, id, &f.voice) else {
        return;
    };
    if !mesh::signed_as(mesh::CAMERA, f, id, &key) {
        return;
    }
    let now = Instant::now();
    let (to, label, changed) = {
        let mut gs = groups(d);
        let Some(g) = gs.get_mut(id) else { return };
        if !newest(g) || !on_call(g, &ps) {
            return;
        }
        let was = g.cameras.get(&f.voice).is_some_and(|c| c.on(now));
        g.cameras.insert(
            f.voice,
            Camera {
                n: f.n,
                on,
                at: now,
            },
        );
        g.pictures.came(f.voice, ps, now);
        let to: Vec<Session> = g
            .sessions
            .iter()
            .filter(|(l, _)| **l != ps)
            .map(|(_, (s, _))| s.clone())
            .collect();
        let changed = was != on && g.tree.own().is_some_and(|own| own != f.voice);
        (to, format_label(&g.space, id, &video()), changed)
    };
    for s in to {
        let _ = s.send_datagram(label, Priority::RealTime, bytes.clone());
    }
    if changed {
        d.bump();
    }
}

/// A picture of a group call, come on the link `from`
/// (`basics/video.md#groups`): checked, passed on to the links whose levels
/// select its size, and given to this person's window if its level does.
fn pictured(d: &Daemon, from: &Session, id: &[u8; 16], f: &Frame<'_>, bytes: &Bytes) {
    let [_, size, rtp @ ..] = f.payload else {
        return;
    };
    let size = *size;
    if !matches!(size, pictures::SMALL | pictures::LARGE) || rtp.is_empty() {
        return;
    }
    let ps = from.peer_static();
    let now = Instant::now();
    {
        let mut gs = groups(d);
        let Some(g) = gs.get_mut(id) else { return };
        // A link no longer on the call sends nothing; past its share of
        // pictures a link's are dropped unread.
        if !admits_picture(g, &ps, &f.voice, size, f.n, now) {
            return;
        }
    }
    let Some(key) = key_of(d, id, &f.voice) else {
        return;
    };
    if !mesh::signed_as(pictures::PICTURE, f, id, &key) {
        return;
    }
    let (to, label, show) = {
        let mut gs = groups(d);
        let Some(g) = gs.get_mut(id) else { return };
        // It may have been dropped while the picture was checked.
        if !on_call(g, &ps) {
            return;
        }
        let Some(passed) = g.pictures.on_picture(ps, f.voice, size, f.n, now) else {
            return;
        };
        let to: Vec<Session> = passed
            .forward
            .iter()
            .filter_map(|l| g.sessions.get(l).map(|(s, _)| s.clone()))
            .collect();
        let show = passed.show && g.tree.own().is_some_and(|own| own != f.voice);
        (to, format_label(&g.space, id, &video()), show)
    };
    for s in to {
        let _ = s.send_datagram(label, Priority::Interactive, bytes.clone());
    }
    if show {
        let _ = d.call_video.send(Shown {
            call: *id,
            format: video(),
            from: Some(f.voice),
            size: Some(size),
            frame: bytes.slice(mesh::HEADER + 2..),
        });
    }
}

/// Whether `link` is still one of the call's links: one dropped sends
/// nothing that is taken. A link is in the tree just while it has a session.
fn on_call(g: &Group, link: &LinkId) -> bool {
    g.tree.has_link(link)
}

/// Whether a picture on `link` is looked at: the link is on the call, within
/// its share of pictures, and the picture not seen here.
fn admits_picture(
    g: &mut Group,
    link: &LinkId,
    voice: &Voice,
    size: Size,
    n: u32,
    now: Instant,
) -> bool {
    on_call(g, link) && g.pictures.admit(link, now) && g.pictures.is_new(voice, size, n)
}

/// The link of each device of the group linked with this one, by its voice.
fn direct_links(g: &Group) -> HashMap<Voice, LinkId> {
    g.sessions
        .iter()
        .filter_map(|(l, (s, _))| {
            s.peer_identity()
                .map(|p| (mesh::voice_of(&p.signing_key), *l))
        })
        .collect()
}

/// A word about pictures on the link `from` (`basics/video.md#groups`):
/// everything it asks of this device, or a key picture it wants. Only words
/// about the voices of the group's devices count.
fn asked(d: &Daemon, from: &Session, id: &[u8; 16], bytes: &[u8]) {
    let Some(ask) = Ask::decode(bytes) else {
        return;
    };
    for v in ask.voices() {
        let known = groups(d).get(id).is_some_and(|g| g.keys.contains_key(&v));
        if !known {
            key_of(d, id, &v);
        }
    }
    let ps = from.peer_static();
    let now = Instant::now();
    let key = {
        let mut gs = groups(d);
        let Some(g) = gs.get_mut(id) else { return };
        if !g.sessions.contains_key(&ps) {
            return;
        }
        match ask {
            Ask::Levels(list) => {
                let list: Vec<(Voice, u8)> = list
                    .into_iter()
                    .filter(|(v, _)| g.keys.contains_key(v))
                    .collect();
                g.pictures.on_levels(ps, &list, now);
                None
            }
            Ask::Key(v, size) => {
                if !g.keys.contains_key(&v) {
                    return;
                }
                let direct = direct_links(g);
                let own = g.tree.own();
                match g.pictures.on_key(Some(&ps), v, size, own, &direct, now) {
                    Some(to) => Some((to, v, size)),
                    None => return,
                }
            }
        }
    };
    match key {
        Some((to, v, size)) => send_key(d, id, to, v, size),
        None => say_asks(d, id, false, false),
    }
}

/// Asks for a key picture of `voice`'s `size`: of this device's window, if
/// the voice is its own, or of the link that sender's pictures come on.
fn send_key(d: &Daemon, id: &[u8; 16], to: KeyTo, voice: Voice, size: Size) {
    match to {
        KeyTo::Window => {
            let _ = d.call_wants.send((*id, Want::Key(size)));
        }
        KeyTo::Link(l) => {
            let (s, label) = {
                let gs = groups(d);
                let Some(g) = gs.get(id) else { return };
                let Some((s, _)) = g.sessions.get(&l) else {
                    return;
                };
                (s.clone(), asks_label(&g.space, id))
            };
            let ask = Ask::Key(voice, size).encode();
            let _ = s.send_datagram(label, Priority::RealTime, Bytes::from(ask));
        }
    }
}

/// Says to each link what this device asks of it of the call's pictures,
/// if that changed or with `again`; tells this person's window the sizes
/// asked of it, if that changed or with `remind`.
fn say_asks(d: &Daemon, id: &[u8; 16], again: bool, remind: bool) {
    let now = Instant::now();
    let (out, want, label) = {
        let mut gs = groups(d);
        let Some(g) = gs.get_mut(id) else { return };
        let own = g.tree.own();
        let direct = direct_links(g);
        let said = g.pictures.to_say(own, &direct, again, now);
        let out: Vec<(Session, Vec<u8>)> = said
            .iter()
            .filter_map(|(l, a)| g.sessions.get(l).map(|(s, _)| (s.clone(), a.encode())))
            .collect();
        let want = own
            .map(|_| g.pictures.wanted(own))
            .filter(|w| remind || g.wanted != Some(*w));
        if want.is_some() {
            g.wanted = want;
        }
        (out, want, asks_label(&g.space, id))
    };
    for (s, b) in out {
        let _ = s.send_datagram(label, Priority::RealTime, Bytes::from(b));
    }
    if let Some(w) = want {
        let _ = d.call_wants.send((*id, w));
    }
}

/// The group call this person is on, if any.
fn group_call(d: &Daemon) -> Option<[u8; 16]> {
    lock(d)
        .as_ref()
        .filter(|c| c.group && c.standing != Standing::Ringing)
        .map(|c| c.id)
}

/// This person's window asks a sender on the group call for a level.
fn set_level(d: &Daemon, voice: Voice, level: u8) {
    let Some(id) = group_call(d) else { return };
    if let Some(g) = groups(d).get_mut(&id) {
        g.pictures.set_window(voice, level);
    }
    say_asks(d, &id, false, false);
}

/// This person's window wants a key picture of a sender's size.
fn window_key(d: &Daemon, voice: Voice, size: Size) {
    let Some(id) = group_call(d) else { return };
    let to = {
        let mut gs = groups(d);
        let Some(g) = gs.get_mut(&id) else { return };
        let direct = direct_links(g);
        let own = g.tree.own();
        g.pictures
            .on_key(None, voice, size, own, &direct, Instant::now())
    };
    if let Some(to) = to {
        send_key(d, &id, to, voice, size);
    }
}

/// A picture of this person's on a group call: signed, and sent to the
/// links whose levels select its size.
fn send_picture(d: &Daemon, size: Size, rtp: &[u8]) {
    if !matches!(size, pictures::SMALL | pictures::LARGE)
        || rtp.is_empty()
        || mesh::HEADER + 2 + rtp.len() > cardinal_link::MAX_DATAGRAM_PAYLOAD
    {
        return;
    }
    let live = lock(d)
        .as_ref()
        .filter(|c| c.group && c.standing == Standing::Live)
        .map(|c| c.id);
    let Some(id) = live else { return };
    let (out, to, label) = {
        let mut gs = groups(d);
        let Some(g) = gs.get_mut(&id) else { return };
        let Some(own) = g.tree.own() else { return };
        let targets = g.pictures.sent_own(own, size, Instant::now());
        if targets.is_empty() {
            return;
        }
        let next = &mut g.picture_next[usize::from(size - 1)];
        let n = *next;
        *next = n.wrapping_add(1);
        let mut payload = Vec::with_capacity(2 + rtp.len());
        payload.extend_from_slice(&[pictures::PICTURE_KIND, size]);
        payload.extend_from_slice(rtp);
        let out = mesh::frame_of(pictures::PICTURE, &d.keys.signing, &id, &own, n, &payload);
        let to: Vec<Session> = targets
            .iter()
            .filter_map(|l| g.sessions.get(l).map(|(s, _)| s.clone()))
            .collect();
        (Bytes::from(out), to, format_label(&g.space, &id, &video()))
    };
    for s in to {
        if let Err(e) = s.send_datagram(label, Priority::Interactive, out.clone()) {
            tracing::trace!("picture: {e}");
        }
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
    let own = matches!(d.classify(s), PeerKind::Own(_));
    // A group only offered to this person: from their own devices, only
    // that one of them answered (`join`), which stops the ringing here.
    if own && crate::groups::only_offered(d, &space) {
        let answered = kind == JOIN && sig.flag != Some(1);
        if answered
            && lock(d)
                .as_ref()
                .is_some_and(|c| c.id == id && c.space == space && c.standing == Standing::Ringing)
        {
            forget(d, &id, Ending::AnsweredElsewhere);
        }
        return Ok(());
    }
    if !own {
        if let Some(name) = crate::groups::offered_ring(d, &space, &them) {
            return offered_signal(d, s, them, sig, name).await;
        }
    }
    let contacts = d.core().contacts();
    let found = contacts
        .iter()
        .find(|c| c.identity == them && c.space == space);
    // A ring from a contact before the offer of its group, or before the
    // group opened, is kept a while; its caller's `end` drops it.
    if found.is_none() && !own && keep(d, s, them, &sig) {
        return Ok(());
    }
    if found.is_none() && !own && kind == END {
        caller_gave_up(d, s, &them, &space, &id);
        return Ok(());
    }
    // a recovery's relationship is for the recovery alone (`guardians.rs`)
    let Some(contact) = found.filter(|c| !c.refused && c.recovery_of.is_none()) else {
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
        ANSWER if answered_again(d, s, &them, &sig) => {}
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
                    c.they_take = c.taken.clone();
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
            // A caller whose camera is on takes the video they answered
            // without.
            take_video_if_camera(d).await;
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

/// Whether `sig` is a new `answer` on the live call between two people
/// that its session carries: if so, what the other side takes is now what
/// it names of what was offered, and this device sends only that.
fn answered_again(d: &Daemon, s: &Session, them: &[u8; 32], sig: &Signal) -> bool {
    let changed = {
        let mut call = lock(d);
        let Some(c) = call.as_mut().filter(|c| {
            c.id == sig.id
                && c.who == *them
                && c.standing == Standing::Live
                // not yet carrying, as when this side answered a moment
                // ago and the caller, its camera on, answers again at once
                && !c.group
                && c.session
                    .as_ref()
                    .is_some_and(|on| on.peer_static() == s.peer_static())
        }) else {
            return false;
        };
        c.they_take = c
            .offered
            .as_deref()
            .map(|offered| taking(offered, sig.formats.as_deref()));
        true
    };
    if changed {
        d.bump();
    }
    changed
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

/// Audio and the call's other formats for and from a client, one frame per
/// message (`apps.md#the-local-interface`), after a reply that there is a
/// call to carry; until the client goes or the call does.
pub async fn media(d: &Arc<Daemon>, spec: &crate::api::Request, r: Reader, w: Writer) {
    carry_media(d, spec, r, w).await;
    // The window's viewport goes with it, and what it asked for.
    let (group, camera) = lock(d).as_mut().map_or((None, false), |c| {
        c.viewport = None;
        let camera = std::mem::take(&mut c.camera);
        (c.group.then_some(c.id), camera)
    });
    // A window that has gone sends nothing.
    if camera {
        d.bump();
        send_camera(d, true);
    }
    if let Some(id) = group {
        if let Some(g) = groups(d).get_mut(&id) {
            g.pictures.clear_window();
            g.wanted = None;
        }
        say_asks(d, &id, false, false);
    }
}

async fn carry_media(d: &Arc<Daemon>, spec: &crate::api::Request, mut r: Reader, mut w: Writer) {
    use cardinal_encoding::Record;
    let mut heard = d.call_audio.subscribe();
    let mut seen = d.call_video.subscribe();
    let mut views = d.call_viewport.subscribe();
    let mut wants = d.call_wants.subscribe();
    let mut stopping = d.stopping.subscribe();
    let mut changed = d.changed.subscribe();
    let Some(call) = lock(d).as_ref().map(|c| c.id) else {
        let no = crate::api::error_reply(crate::api::status::FAILED, "there is no call");
        let _ = w.send(&no).await;
        return;
    };
    if w.send(&crate::api::encode_reply(spec, Ok(&json!({}))))
        .await
        .is_err()
    {
        return;
    }
    if let Some(id) = group_call(d).filter(|id| *id == call) {
        if let Some(g) = groups(d).get_mut(&id) {
            g.wanted = None;
        }
        say_asks(d, &id, false, false);
    }
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
                // `apps.md`, Calls' media: audio is frame 1, `from` key 3
                let out = Record::new()
                    .with(0, crate::api::frame::AUDIO)
                    .with(1, frame.to_vec())
                    .with_opt(3, voice.map(|v| v.to_vec()));
                if w.send(&out.encode()).await.is_err() {
                    return;
                }
            }
            frame = seen.recv() => {
                let Ok(shown) = frame else { continue };
                if shown.call != call {
                    continue;
                }
                let out = Record::new()
                    .with(0, crate::api::frame::OTHER)
                    .with(1, shown.frame.to_vec())
                    .with(2, shown.format.to_vec())
                    .with_opt(3, shown.from.map(|v| v.to_vec()))
                    .with_opt(4, shown.size.map(u64::from));
                if w.send(&out.encode()).await.is_err() {
                    return;
                }
            }
            want = wants.recv() => {
                let Ok((of, want)) = want else { continue };
                if of != call {
                    continue;
                }
                // `basics/video.md#groups`: the sizes asked of this window,
                // or a key picture of one
                let out = match want {
                    Want::Sizes { small, large } => Record::new()
                        .with(0, crate::api::frame::ASKED)
                        .with(1, small)
                        .with(2, large),
                    Want::Key(size) => Record::new()
                        .with(0, crate::api::frame::KEY)
                        .with(4, u64::from(size)),
                };
                if w.send(&out.encode()).await.is_err() {
                    return;
                }
            }
            view = views.recv() => {
                let Ok((of, voice, (width, height))) = view else { continue };
                if of != call {
                    continue;
                }
                let out = Record::new()
                    .with(0, crate::api::frame::VIEWPORT)
                    .with(1, u64::from(width))
                    .with(2, u64::from(height))
                    .with_opt(3, voice.map(|v| v.to_vec()));
                if w.send(&out.encode()).await.is_err() {
                    return;
                }
            }
            got = r.recv() => {
                let Ok(Some(got)) = got else { return };
                let crate::transport::Received::Message(msg) = got else { continue };
                let Ok(rec) = Record::decode(&msg) else { continue };
                let kind = rec.get(0).and_then(cardinal_encoding::Value::as_uint);
                if kind == Some(crate::api::frame::CAMERA) {
                    if let Some(on) = rec.get(1).and_then(cardinal_encoding::Value::as_bool) {
                        set_camera(d, on).await;
                    }
                    continue;
                }
                if kind == Some(crate::api::frame::VIEWPORT) {
                    let side = |k| {
                        rec.get(k)
                            .and_then(cardinal_encoding::Value::as_uint)
                            .and_then(|n| u16::try_from(n).ok())
                            .filter(|n| *n > 0)
                    };
                    if let (Some(width), Some(height)) = (side(1), side(2)) {
                        set_viewport(d, (width, height));
                    }
                    continue;
                }
                let from = rec
                    .get(3)
                    .and_then(cardinal_encoding::Value::as_bytes)
                    .and_then(|v| Voice::try_from(v).ok());
                let small_uint = |k| {
                    rec.get(k)
                        .and_then(cardinal_encoding::Value::as_uint)
                        .map(|n| u8::try_from(n.min(255)).unwrap_or(255))
                };
                if kind == Some(crate::api::frame::LEVEL) {
                    if let (Some(from), Some(level)) = (from, small_uint(1)) {
                        set_level(d, from, level);
                    }
                    continue;
                }
                if kind == Some(crate::api::frame::KEY) {
                    if let (Some(from), Some(size)) = (from, small_uint(4)) {
                        window_key(d, from, size);
                    }
                    continue;
                }
                let Some(bytes) = rec.get(1).and_then(cardinal_encoding::Value::as_bytes) else {
                    continue;
                };
                match kind {
                    Some(crate::api::frame::AUDIO) => send_audio(d, bytes.to_vec()),
                    Some(crate::api::frame::OTHER) => {
                        let format = rec
                            .get(2)
                            .and_then(cardinal_encoding::Value::as_bytes)
                            .and_then(|f| <Format>::try_from(f).ok());
                        if let Some(format) = format {
                            send_frame(d, format, bytes.to_vec(), small_uint(4));
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

/// The shape of this person's window changed: those sending it video are
/// told now, and again every five seconds.
fn set_viewport(d: &Daemon, v: Viewport) {
    if let Some(c) = lock(d).as_mut() {
        c.viewport = Some(v);
    }
    send_viewport(d);
}

/// Tells those on the call the shape of this person's window, if one shows
/// it (`basics/video.md`): between two people on the video channel, if the
/// call took video; in a group, signed, to every link.
fn send_viewport(d: &Daemon) {
    let (id, group, session, label, v) = {
        let call = lock(d);
        let Some(c) = call.as_ref().filter(|c| c.standing != Standing::Ringing) else {
            return;
        };
        let Some(v) = c.viewport else { return };
        if !c.group && !c.taken.as_ref().is_some_and(|t| t.contains(&video())) {
            return;
        }
        let label = format_label(&c.space, &c.id, &video());
        (c.id, c.group, c.session.clone(), label, viewport_frame(v))
    };
    if !group {
        if let Some(s) = session {
            let _ = s.send_datagram(label, Priority::RealTime, Bytes::copy_from_slice(&v));
        }
        return;
    }
    let (out, to) = {
        let mut gs = groups(d);
        let Some(g) = gs.get_mut(&id) else { return };
        let Some(own) = g.tree.own() else { return };
        let n = g
            .viewports
            .get(&own)
            .map_or_else(mesh::first_number, |n| n.wrapping_add(1));
        g.viewports.insert(own, n);
        let out = mesh::frame_of(mesh::VIEWPORT, &d.keys.signing, &id, &own, n, &v);
        let to: Vec<Session> = g.sessions.values().map(|(s, _)| s.clone()).collect();
        (Bytes::from(out), to)
    };
    for s in to {
        let _ = s.send_datagram(label, Priority::RealTime, out.clone());
    }
}

/// This person's window says whether their camera is on: those on the
/// call are told now, and again every five seconds while it is. Between two
/// people, a device whose camera comes on takes the other side's video, if
/// the call offered it and it took none, so that its person is not asked
/// (`basics/video.md#cameras`).
async fn set_camera(d: &Arc<Daemon>, on: bool) {
    let changed = {
        let mut call = lock(d);
        let Some(c) = call.as_mut() else { return };
        let changed = c.camera != on;
        c.camera = on;
        changed
    };
    if !changed {
        return;
    }
    d.bump();
    send_camera(d, true);
    take_video_if_camera(d).await;
}

/// Between two people, on a live call whose ring offered video: while this
/// person's camera is on, this device takes the other side's video, and
/// answers again to do so if it took none.
async fn take_video_if_camera(d: &Arc<Daemon>) {
    let take = lock(d).as_ref().and_then(|c| {
        let take = c.camera
            && !c.group
            && c.standing == Standing::Live
            && c.offered.as_ref().is_some_and(|o| o.contains(&video()))
            && !c.taken.as_ref().is_some_and(|t| t.contains(&video()));
        take.then(|| c.taken.clone().unwrap_or_default())
    });
    if let Some(taken) = take {
        if let Err(e) = answer_again(d, Some(taken)).await {
            tracing::debug!("taking video as the camera is on: {e}");
        }
    }
}

/// Tells those on the call whether this person's camera is on: between two
/// people on the video channel, if the call offered video; in a group,
/// signed, to every link. Said when it changes (`change`), and otherwise
/// again only while it is on.
fn send_camera(d: &Daemon, change: bool) {
    let (id, group, session, label, on) = {
        let call = lock(d);
        let Some(c) = call.as_ref().filter(|c| c.standing == Standing::Live) else {
            return;
        };
        if !change && !c.camera {
            return;
        }
        if !c.group && !c.offered.as_ref().is_some_and(|o| o.contains(&video())) {
            return;
        }
        let label = format_label(&c.space, &c.id, &video());
        (c.id, c.group, c.session.clone(), label, c.camera)
    };
    let word = camera_frame(on);
    if !group {
        if let Some(s) = session {
            let _ = s.send_datagram(label, Priority::RealTime, Bytes::copy_from_slice(&word));
        }
        return;
    }
    let (out, to) = {
        let mut gs = groups(d);
        let Some(g) = gs.get_mut(&id) else { return };
        let Some(own) = g.tree.own() else { return };
        let n = g
            .cameras
            .get(&own)
            .map_or_else(mesh::first_number, |c| c.n.wrapping_add(1));
        g.cameras.insert(
            own,
            Camera {
                n,
                on,
                at: Instant::now(),
            },
        );
        let out = mesh::frame_of(mesh::CAMERA, &d.keys.signing, &id, &own, n, &word);
        let to: Vec<Session> = g.sessions.values().map(|(s, _)| s.clone()).collect();
        (Bytes::from(out), to)
    };
    for s in to {
        let _ = s.send_datagram(label, Priority::RealTime, out.clone());
    }
}

/// A frame of one of the call's formats other than voice: between two
/// people, sent on that format's channel, if the call took it; in a group, a
/// picture of the size given (`basics/video.md#groups`).
fn send_frame(d: &Daemon, format: Format, frame: Vec<u8>, size: Option<Size>) {
    if format == voice() {
        send_audio(d, frame);
        return;
    }
    if lock(d).as_ref().is_some_and(|c| c.group) {
        if let (true, Some(size)) = (format == video(), size) {
            send_picture(d, size, &frame);
        }
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
        // Sent only what the other side takes (`basics/video.md`).
        if !c.they_take.as_ref().is_some_and(|t| t.contains(&format)) {
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

    /// A link dropped from a call, as one that sent a forged frame is, has
    /// its pictures refused and becomes no sender's source.
    #[test]
    fn a_dropped_link_sends_no_pictures() {
        let now = Instant::now();
        let space: SpaceId = [7; 32];
        let mut g = new_group(space, Some([1; 8]), false);
        let link = [3; 32];
        let ben: Voice = [2; 8];
        g.tree.add_link(link, true, now);
        assert!(admits_picture(&mut g, &link, &ben, pictures::SMALL, 1, now));
        g.tree.remove_link(&link);
        g.pictures.remove_link(&link);
        g.sessions.remove(&link);
        assert!(!on_call(&g, &link));
        assert!(!admits_picture(
            &mut g,
            &link,
            &ben,
            pictures::SMALL,
            2,
            now
        ));
        assert!(!admits_picture(
            &mut g,
            &[4; 32],
            &ben,
            pictures::SMALL,
            2,
            now
        ));
    }

    /// A word on a camera reads back, is neither a viewport nor RTP, and
    /// one signed for a group is neither a viewport nor sound.
    #[test]
    fn a_camera_word_is_told_apart_from_viewports_and_video() {
        assert_eq!(camera_frame(true), [3, 1]);
        assert_eq!(camera_in(&camera_frame(true)), Some(true));
        assert_eq!(camera_in(&camera_frame(false)), Some(false));
        assert_eq!(camera_in(&[3, 2]), None);
        assert_eq!(camera_in(&[3]), None);
        assert_eq!(viewport_in(&camera_frame(true)), None);
        assert_eq!(camera_in(&viewport_frame((3, 1))), None);
        assert_eq!(camera_in(&[0x80, 1]), None);
        let key = cardinal_crypto::SigningKey::generate();
        let own = mesh::voice_of(&key.public_key());
        let f = mesh::frame_of(mesh::CAMERA, &key, &[7; 16], &own, 3, &camera_frame(true));
        let f = Frame::parse(&f).unwrap();
        assert!(mesh::signed_as(
            mesh::CAMERA,
            &f,
            &[7; 16],
            &key.public_key()
        ));
        assert!(!mesh::signed_as(
            mesh::VIEWPORT,
            &f,
            &[7; 16],
            &key.public_key()
        ));
        assert!(!mesh::signed_by(&f, &[7; 16], &key.public_key()));
    }

    /// A viewport reads back, is never an RTP packet, and a viewport signed
    /// for a group is not a frame of sound.
    #[test]
    fn a_viewport_is_told_apart_from_video_and_sound() {
        let b = viewport_frame((9, 16));
        assert_eq!(b, [1, 0, 9, 0, 16]);
        assert_eq!(viewport_in(&b), Some((9, 16)));
        assert_eq!(viewport_in(&[1, 0, 0, 0, 16]), None, "no side is zero");
        // RTP version 2, payload type 96, the size of a viewport
        assert_eq!(viewport_in(&[0x80, 96, 0, 1, 2]), None);
        assert_eq!(viewport_in(&b[..4]), None);
        let key = cardinal_crypto::SigningKey::generate();
        let own = mesh::voice_of(&key.public_key());
        let f = mesh::frame_of(mesh::VIEWPORT, &key, &[7; 16], &own, 3, &b);
        let f = Frame::parse(&f).unwrap();
        assert!(mesh::signed_as(
            mesh::VIEWPORT,
            &f,
            &[7; 16],
            &key.public_key()
        ));
        assert!(!mesh::signed_by(&f, &[7; 16], &key.public_key()));
        assert!(!mesh::signed_as(
            mesh::VIEWPORT,
            &f,
            &[8; 16],
            &key.public_key()
        ));
    }

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
