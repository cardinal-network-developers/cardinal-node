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
use tokio::sync::Notify;

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
    live_since: Option<Instant>,
    over: Arc<Notify>,
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

/// Rings a contact.
pub async fn start(d: &Arc<Daemon>, who: &str) -> anyhow::Result<Json> {
    let contact = contacts::listed(d, who)?;
    anyhow::ensure!(lock(d).is_none(), "you are already on a call");
    let theirs = d.sessions_of(&contact.identity);
    anyhow::ensure!(
        !theirs.is_empty(),
        "{} cannot be reached right now",
        contact.petname
    );
    let id: [u8; 16] = cardinal_crypto::random_bytes();
    let over = Arc::new(Notify::new());
    *lock(d) = Some(Call {
        id,
        who: contact.identity,
        name: contact.petname.clone(),
        space: contact.space,
        standing: Standing::Calling,
        session: None,
        live_since: None,
        over,
    });
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
        let call = lock(d);
        let c = call
            .as_ref()
            .filter(|c| c.standing == Standing::Ringing)
            .ok_or_else(|| anyhow::anyhow!("nothing is ringing"))?;
        let s = c.session.clone();
        (
            s.ok_or_else(|| anyhow::anyhow!("that call has gone"))?,
            c.space,
            c.id,
        )
    };
    tell(&s, ANSWER, &space, &id).await?;
    go_live(d, &s);
    Ok(json!({}))
}

/// Hangs up, or says no.
pub async fn end(d: &Arc<Daemon>) -> anyhow::Result<Json> {
    let Some(call) = lock(d).take() else {
        return Ok(json!({}));
    };
    call.over.notify_waiters();
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

/// Starts carrying audio on a session.
fn go_live(d: &Arc<Daemon>, s: &Session) {
    let (mut channel, id, over) = {
        let mut call = lock(d);
        let Some(c) = call.as_mut() else { return };
        c.standing = Standing::Live;
        c.session = Some(s.clone());
        c.live_since = Some(Instant::now());
        let label = channel_label(&c.space, &c.id);
        (s.channel(label, Priority::RealTime), c.id, c.over.clone())
    };
    d.bump();
    let d = d.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = over.notified() => return,
                heard = channel.recv() => match heard {
                    Some(audio) => {
                        let _ = d.call_audio.send(audio);
                    }
                    None => break,
                },
            }
        }
        // The session went, and the call with it.
        let mut call = lock(&d);
        if call.as_ref().is_some_and(|c| c.id == id) {
            *call = None;
            drop(call);
            d.bump();
        }
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
                    *call = Some(Call {
                        id,
                        who: them,
                        name: contact.petname.clone(),
                        space,
                        standing: Standing::Ringing,
                        session: Some(s.clone()),
                        live_since: None,
                        over: Arc::new(Notify::new()),
                    });
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
            if expected {
                go_live(d, s);
                // Their other devices can stop ringing.
                for other in d.sessions_of(&them) {
                    if other.peer_static() != s.peer_static() {
                        let _ = tell(&other, END, &space, &id).await;
                    }
                }
            }
        }
        END => {
            let ended = {
                let mut call = lock(d);
                let same = call.as_ref().is_some_and(|c| c.id == id && c.who == them);
                let taken = if same { call.take() } else { None };
                taken
            };
            if let Some(call) = ended {
                call.over.notify_waiters();
                d.bump();
            }
        }
        _ => st.reset(0),
    }
    Ok(())
}

/// Audio for and from a client, one `{"audio": hex}` line per frame, until
/// the client goes or the call does.
pub async fn media(d: &Arc<Daemon>, mut lines: tokio::io::Lines<BufReader<Reader>>, mut w: Writer) {
    let mut heard = d.call_audio.subscribe();
    let mut stopping = d.stopping.subscribe();
    let mut changed = d.changed.subscribe();
    loop {
        tokio::select! {
            _ = stopping.changed() => return,
            c = changed.changed() => {
                if c.is_err() || lock(d).is_none() {
                    return;
                }
            }
            frame = heard.recv() => {
                let Ok(frame) = frame else { continue };
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
