//! Calls (`profiles.md#calls`). A call needs no new mechanism: a `ring` on the
//! ephemeral service to the other person's online devices, and audio on a
//! datagram channel of their session, in the real-time class. What is in the
//! audio is the client's business: this carries it and looks at none of it.
//!
//! This handles one call at a time, between two people.

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

const RING: u64 = 1;
const ANSWER: u64 = 2;
const END: u64 = 3;

/// The longest signal: a kind, a space and a call.
const MAX_SIGNAL: usize = 128;
/// How long a call rings before it stops.
const RINGS_FOR: Duration = Duration::from_secs(45);
/// How often a call looks at whether its session is still there.
const SESSION_CHECK: Duration = Duration::from_secs(5);

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
    let theirs = d.sessions_of(&contact.identity);
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
    ring_out(d, id);
    Ok(json!({}))
}

/// Takes the call that is ringing here.
pub async fn answer(d: &Arc<Daemon>) -> anyhow::Result<Json> {
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
                        let _ = d.call_audio.send((id, audio));
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
    json!({"call": {
        "who": hex::encode(&c.who[..8]),
        "name": c.name,
        "state": standing,
        "seconds": c.live_since.map(|t| t.elapsed().as_secs()),
    }})
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
    let contacts = d.core().contacts();
    let found = contacts
        .iter()
        .find(|c| c.identity == them && c.space == space);
    let Some(contact) = found.filter(|c| !c.refused) else {
        st.reset(0);
        return Ok(());
    };
    match kind {
        RING => {
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
                let Ok((of, frame)) = frame else { continue };
                if of != call {
                    continue;
                }
                let mut out = json!({"audio": hex::encode(&frame)}).to_string();
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
    let call = lock(d);
    let live = call.as_ref().filter(|c| c.standing == Standing::Live);
    let Some(c) = live else { return };
    let Some(s) = c.session.as_ref() else { return };
    let label = channel_label(&c.space, &c.id);
    if let Err(e) = s.send_datagram(label, Priority::RealTime, Bytes::from(frame)) {
        tracing::trace!("audio: {e}");
    }
}
