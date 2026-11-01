//! Other people (`contact.md`): invitations, the relationship space two
//! people get from one, and the conversation in it.
//!
//! An invitation is a secret that lets one session through. The two devices
//! say who they are, take each other's identity logs, and the inviter creates
//! a space with both as owners. After that they are contacts. If each trusts
//! the other, their devices may open sessions with each other, for what they
//! share and nothing else. If not, the session ends there, and a device
//! answers the other's as it answers a stranger's.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use cardinal_contact::{ContactMessage, EndpointAddr, Invitation};
use cardinal_encoding::Value;
use cardinal_link::{CarrierKind, Priority, SecretEntry, Service, Session, Stream, Target};
use cardinal_space::account::{self, ContactRecord, Regard};
use cardinal_space::{relationship, SpaceId};
use cardinal_sync::identity_log_label;
use serde_json::{json, Value as Json};
use tokio::io::AsyncWriteExt;

use crate::core::{now_ms, short};
use crate::daemon::{Daemon, PeerKind};
use crate::net::Access;
use crate::{mailbox, net};

/// The longest message here: a sealed genesis wrapped for two.
const MAX_MESSAGE: usize = 64 * 1024;
/// How long an exchange may take.
const EXCHANGE_WITHIN: Duration = Duration::from_secs(20);
/// The most text that is sure to fit in an envelope, with all an entry holds
/// besides.
const LEFT_AT_A_HOST: usize = 400;
/// How long `done` may take to arrive, before a session that ends with it
/// goes.
const DONE_WITHIN: Duration = Duration::from_secs(3);
/// How many times to look for a session to confirm a message on. After that
/// the next session, or a host, does it.
const CONFIRM_TRIES: usize = 6;
const CONFIRM_AGAIN: Duration = Duration::from_millis(500);

fn identity(d: &Daemon) -> anyhow::Result<[u8; 32]> {
    d.core()
        .identity
        .as_ref()
        .map(|i| i.id())
        .ok_or_else(|| anyhow::anyhow!("this device does not belong to anyone"))
}

/// Makes an invitation to this device. `address` is where the other person
/// can reach it, by default its address on the local network.
pub fn invite(
    d: &Arc<Daemon>,
    address: Option<&str>,
    name: Option<&str>,
    regard: Regard,
) -> anyhow::Result<Json> {
    let me = identity(d)?;
    let port = d
        .endpoint
        .udp_addr()
        .or(d.endpoint.tcp_addr())
        .map_or(0, |a| a.port());
    let addr: SocketAddr = match address {
        Some(a) => a.parse().map_err(|_| {
            anyhow::anyhow!("{a} is not an address; it looks like 203.0.113.9:7171")
        })?,
        None => {
            let ip = crate::daemon::local_ips()
                .into_iter()
                .next()
                .ok_or_else(|| anyhow::anyhow!("this device has no address to give"))?;
            SocketAddr::new(ip, port)
        }
    };
    let responder = *d.keys.link.public_key().x25519();
    let endpoint = EndpointAddr::new(CarrierKind::Udp, addr);
    let mut invitation = Invitation::new(me, responder, endpoint);
    invitation.name = name.map(str::to_owned);
    let secret = d.endpoint.add_secret(SecretEntry::new(&invitation.secret));
    d.invitation_made(secret, regard);
    Ok(json!({"code": invitation.to_text()}))
}

/// Takes up an invitation, and becomes a contact of whoever gave it.
pub async fn accept(
    d: &Arc<Daemon>,
    code: &str,
    name: Option<&str>,
    regard: Regard,
) -> anyhow::Result<Json> {
    let invitation = Invitation::from_text(code.trim())
        .map_err(|_| anyhow::anyhow!("that is not an invitation"))?;
    let me = identity(d)?;
    anyhow::ensure!(invitation.inviter != me, "that invitation is your own");
    anyhow::ensure!(
        !is_refused(d, &invitation.inviter),
        "you have refused whoever made that invitation"
    );
    anyhow::ensure!(
        !is_contact(d, &invitation.inviter),
        "you already know whoever made that invitation"
    );
    let addr = invitation
        .endpoint
        .socket_addr()
        .ok_or_else(|| anyhow::anyhow!("that invitation has no address this version can use"))?;
    let s = d
        .dial(|c| Target::invitation(addr, c, invitation.responder_static, &invitation.secret))
        .await
        .map_err(|e| anyhow::anyhow!("could not reach them at {addr} ({e})"))?;
    d.on_session(s.clone());
    let petname = name
        .map(str::to_owned)
        .or(invitation.name.clone())
        .unwrap_or_else(|| account::short_key(&invitation.inviter));
    let exchange = accept_exchange(d, &s, me, &invitation, &petname, regard);
    let done = tokio::time::timeout(EXCHANGE_WITHIN, exchange)
        .await
        .map_err(|_| anyhow::anyhow!("they stopped answering"))
        .and_then(|done| done);
    if done.is_err() {
        s.abandon();
    }
    done?;
    Ok(json!({"name": petname}))
}

async fn accept_exchange(
    d: &Arc<Daemon>,
    s: &Session,
    me: [u8; 32],
    invitation: &Invitation,
    petname: &str,
    regard: Regard,
) -> anyhow::Result<()> {
    let proven = s.peer_identity().map(|p| p.identity);
    anyhow::ensure!(
        proven == Some(invitation.inviter),
        "the device at that address is not the one who invited you"
    );
    let mut st = s.open_stream(Service::CONTACT, Priority::Interactive)?;
    let hello = ContactMessage::Hello {
        identity: me,
        name: d.config().name.clone(),
    };
    send(&mut st, &hello).await?;
    let Some(ContactMessage::Genesis(genesis)) = receive(&mut st).await? else {
        anyhow::bail!("they did not go on");
    };
    let label = identity_log_label(&invitation.inviter);
    net::reconcile_as(d, s, label, Access::Other(invitation.inviter)).await?;
    anyhow::ensure!(
        proven_by_log(d, s, &invitation.inviter),
        "the device at that address is not the one who invited you"
    );
    let space = d
        .core()
        .accept_relationship(&genesis, &invitation.inviter)?;
    d.invited_to(s, space);
    mailbox::write_reach(d, &space).await?;
    net::reconcile(d, s, space).await?;
    record_contact(d, &invitation.inviter, petname, &space, regard)?;
    mailbox::met(d, &space, &invitation.inviter);
    send(&mut st, &ContactMessage::Done).await?;
    st.shutdown().await?;
    remember(d, s);
    d.identity_changed();
    catch_up(d, &space);
    if !regard.trusted {
        let _ = tokio::time::timeout(DONE_WITHIN, receive(&mut st)).await;
        s.abandon();
    }
    Ok(())
}

/// Whether the device at the other end of `s` is one of `who`'s, by that
/// person's own log. Until it is, `who` is only what the device said.
fn proven_by_log(d: &Daemon, s: &Session, who: &[u8; 32]) -> bool {
    let key = s.peer_identity().map(|p| p.signing_key);
    key.is_some_and(|key| d.core().has_device(who, &key, &s.peer_static()))
}

/// Announces a new contact's space. A session counts as a contact's only
/// from here on, so anything written since the contact was recorded was
/// told to no one.
fn catch_up(d: &Arc<Daemon>, space: &SpaceId) {
    d.notify(*space, Vec::new(), &Default::default());
}

/// Keeps where a new contact's device is. Over UDP a session's address is the
/// one it listens on; over TCP it is a port of the moment, and says nothing.
fn remember(d: &Daemon, s: &Session) {
    let device = s.peer_identity().map(|p| p.signing_key);
    if let (Some(device), Some(CarrierKind::Udp), Some(addr)) =
        (device, s.carrier(), s.remote_addr())
    {
        d.learn_addr(&device, addr);
    }
}

/// Serves the `contact` service, for a session opened with an invitation.
pub async fn serve(d: &Arc<Daemon>, s: &Session, mut st: Stream) -> anyhow::Result<()> {
    let PeerKind::Inviting(them, _) = d.classify(s) else {
        st.reset(0);
        return Ok(());
    };
    if !d.exchange_begins(s) || is_contact(d, &them) {
        s.abandon();
        return Ok(());
    }
    let Some(regard) = d.invitation_of(s) else {
        st.reset(0);
        return Ok(());
    };
    let Some(ContactMessage::Hello { identity, name }) = receive(&mut st).await? else {
        return Ok(());
    };
    anyhow::ensure!(identity == them, "not who the session says");
    let label = identity_log_label(&them);
    net::reconcile_as(d, s, label, Access::Other(them)).await?;
    if !proven_by_log(d, s, &them) {
        s.abandon();
        return Ok(());
    }
    let (space, genesis) = d.core().create_relationship(&them)?;
    d.invited_to(s, space);
    mailbox::write_reach(d, &space).await?;
    send(&mut st, &ContactMessage::Genesis(genesis)).await?;
    let done = tokio::time::timeout(EXCHANGE_WITHIN, receive(&mut st)).await;
    if matches!(done, Ok(Ok(Some(ContactMessage::Done)))) {
        net::reconcile(d, s, space).await?;
        record_contact(d, &them, &name, &space, regard)?;
        mailbox::met(d, &space, &them);
        d.invitation_finished(s);
        remember(d, s);
        d.identity_changed();
        catch_up(d, &space);
        tracing::info!("{name} ({}) is a contact now", short(&them));
        if !regard.trusted {
            let _ = st.shutdown().await;
            s.abandon();
        }
    }
    Ok(())
}

fn is_contact(d: &Daemon, who: &[u8; 32]) -> bool {
    d.core().contacts().iter().any(|c| c.identity == *who)
}

fn is_refused(d: &Daemon, who: &[u8; 32]) -> bool {
    let contacts = d.core().contacts();
    contacts.iter().any(|c| c.identity == *who && c.refused)
}

fn record_contact(
    d: &Arc<Daemon>,
    who: &[u8; 32],
    petname: &str,
    space: &SpaceId,
    regard: Regard,
) -> anyhow::Result<()> {
    let account = d
        .core()
        .account_id()
        .ok_or_else(|| anyhow::anyhow!("the account space is not here yet"))?;
    let op = account::create_contact(who, petname, space, regard);
    d.write_and_push(&account, vec![op])?;
    Ok(())
}

/// Changes how this person regards a contact. Only their own devices hear of
/// it, and the contact is told nothing.
pub fn set(d: &Arc<Daemon>, who: &str, setting: &str) -> anyhow::Result<Json> {
    let contact = find(d, who)?;
    let (key, value) = match setting {
        "trust" => (account::TRUSTED, true),
        "hosts-only" => (account::TRUSTED, false),
        "introductions" => (account::INTRODUCTIONS, true),
        "no-introductions" => (account::INTRODUCTIONS, false),
        "refuse" => (account::REFUSED, true),
        "unrefuse" => (account::REFUSED, false),
        _ => anyhow::bail!("{setting:?} is not a setting"),
    };
    let account = d
        .core()
        .account_id()
        .ok_or_else(|| anyhow::anyhow!("the account space is not here yet"))?;
    d.write_and_push(&account, vec![account::set_field(contact.node, key, value)])?;
    d.peers_changed();
    Ok(json!({}))
}

async fn send(st: &mut Stream, m: &ContactMessage) -> anyhow::Result<()> {
    st.send_message(&Value::Record(m.to_record())).await?;
    Ok(())
}

async fn receive(st: &mut Stream) -> anyhow::Result<Option<ContactMessage>> {
    let Some(v) = st.recv_message_max(MAX_MESSAGE).await? else {
        return Ok(None);
    };
    let r = v
        .as_record()
        .ok_or_else(|| anyhow::anyhow!("not a record"))?;
    ContactMessage::from_record(r)
        .map(Some)
        .map_err(|_| anyhow::anyhow!("not a contact message"))
}

/// This person's contacts, and with `all` those they have refused.
pub fn list(d: &Daemon, all: bool) -> Json {
    let connected = d.connected_people();
    let contacts: Vec<Json> = d
        .core()
        .contacts()
        .iter()
        .filter(|c| all || !c.refused)
        .map(|c| {
            json!({
                "name": c.petname,
                "identity": hex::encode(&c.identity[..8]),
                "trusted": c.regard.trusted,
                "introductions": c.regard.introductions,
                "refused": c.refused,
                "connected": connected.contains(&c.identity),
            })
        })
        .collect();
    json!({"contacts": contacts})
}

/// The contact called `who`.
fn find(d: &Daemon, who: &str) -> anyhow::Result<ContactRecord> {
    let w = who.to_lowercase();
    let contacts = d.core().contacts();
    let named =
        |c: &ContactRecord| c.petname.to_lowercase() == w || hex::encode(&c.identity[..8]) == w;
    let mut found = contacts.into_iter().filter(named);
    let contact = found
        .next()
        .ok_or_else(|| anyhow::anyhow!("no contact called {who:?}; see `cardinal contacts`"))?;
    // A name is what someone suggested, and it may be a name already here.
    anyhow::ensure!(
        found.next().is_none(),
        "more than one contact is called {who:?}; use the id `cardinal contacts` shows"
    );
    Ok(contact)
}

/// The contact called `who`, unless this person has refused them.
pub(crate) fn listed(d: &Daemon, who: &str) -> anyhow::Result<ContactRecord> {
    let contact = find(d, who)?;
    anyhow::ensure!(!contact.refused, "you have refused {who}");
    Ok(contact)
}

/// Writes a message to a contact.
pub fn say(d: &Arc<Daemon>, who: &str, text: &str) -> anyhow::Result<Json> {
    let contact = listed(d, who)?;
    let space = contact.space;
    let conversation = {
        let core = d.core();
        core.spaces
            .get(&space)
            .and_then(|h| h.space.as_ref())
            .and_then(relationship::conversation)
    };
    let conversation = conversation.ok_or_else(|| anyhow::anyhow!("that space is not open yet"))?;
    let op = relationship::create_message(conversation, text);
    d.write_and_push(&space, vec![op])?;
    confirm(d, space, contact.identity);
    Ok(json!({"reachable": reachable(d, &contact, text)}))
}

/// A notice is not acknowledged, and a session that looks open may be gone, so
/// a message counts as with someone only once a reconcile with one of their
/// devices has gone through.
fn confirm(d: &Arc<Daemon>, space: SpaceId, member: [u8; 32]) {
    let d = d.clone();
    tokio::spawn(async move {
        // Just after two people meet, a session may still be settling.
        for _ in 0..CONFIRM_TRIES {
            for s in d.sessions_of(&member) {
                let mine = mailbox::written_here(&d, &space);
                if net::reconcile(&d, &s, space).await.is_ok() {
                    d.mailbox.mark_sent(&space, &member, &mine);
                    d.bump();
                    return;
                }
            }
            tokio::time::sleep(CONFIRM_AGAIN).await;
        }
    });
}

/// Whether something written now can get to a contact without the two
/// connecting: left at their host, or, if too long for that, fetched from
/// this person's.
fn reachable(d: &Daemon, contact: &ContactRecord, text: &str) -> bool {
    let core = d.core();
    let me = core.identity.as_ref().map(|i| i.id());
    let hosted = me.is_some_and(|me| core.reach_of(&contact.space, &me).is_some());
    let theirs = core.reach_of(&contact.space, &contact.identity).is_some();
    contact.connects() || (theirs && (hosted || text.len() <= LEFT_AT_A_HOST))
}

/// The state of a message of this person's: `read` once their marker has
/// passed it, `waiting` until a reconcile or a deposit says it got somewhere,
/// else `sent`. Only what this device wrote can be waiting here: another
/// device of this person's is keeping count of its own.
fn state_of(read: bool, waiting: bool) -> &'static str {
    if read {
        "read"
    } else if waiting {
        "waiting"
    } else {
        "sent"
    }
}

/// The conversation with a contact, oldest first.
pub fn messages(d: &Daemon, who: &str) -> anyhow::Result<Json> {
    let contact = listed(d, who)?;
    let (space, them) = (contact.space, contact.identity);
    let here = mailbox::written_here(d, &space);
    let unsent = d.mailbox.not_sent(&space, &them, here);
    let core = d.core();
    let me = core.identity.as_ref().map(|i| i.id());
    let open = core.spaces.get(&space).and_then(|h| h.space.as_ref());
    let open = open.ok_or_else(|| anyhow::anyhow!("that space is not open yet"))?;
    let all = relationship::messages(open);
    let read = relationship::read_by(open, &them, &all);
    let said: Vec<Json> = all
        .iter()
        .zip(read)
        .map(|(m, read)| {
            let mine = Some(m.author) == me;
            json!({
                "id": hex::encode(m.id),
                "mine": mine,
                "text": m.text,
                "time": m.time,
                "state": mine.then(|| state_of(read, unsent.contains(&m.entry))),
            })
        })
        .collect();
    Ok(json!({"messages": said}))
}

/// Everyone this person talks to, the most recent first: what they last said
/// and how many messages from them are not yet read here.
pub fn conversations(d: &Daemon) -> Json {
    let connected = d.connected_people();
    let core = d.core();
    let me = core.identity.as_ref().map(|i| i.id());
    let contacts = core.contacts();
    let mut found: Vec<(Option<u64>, Json)> = contacts
        .iter()
        .filter(|c| !c.refused)
        .map(|c| {
            let open = core.spaces.get(&c.space).and_then(|h| h.space.as_ref());
            let said = open.map(relationship::messages).unwrap_or_default();
            let read = match (open, me) {
                (Some(open), Some(me)) => relationship::read_by(open, &me, &said),
                _ => vec![false; said.len()],
            };
            let both = said.iter().zip(read);
            let unread = both.filter(|(m, read)| Some(m.author) != me && !read);
            let last = said.last();
            // The author's own clock: it may not pin them to the top.
            let when = last.and_then(|m| m.time).map(|t| t.min(now_ms()));
            let conversation = json!({
                "name": c.petname,
                "id": hex::encode(&c.identity[..8]),
                "trusted": c.regard.trusted,
                "introductions": c.regard.introductions,
                "connected": connected.contains(&c.identity),
                "unread": unread.count(),
                "last": last.map(|m| json!({
                    "mine": Some(m.author) == me,
                    "text": m.text,
                    "time": m.time,
                })),
            });
            (when, conversation)
        })
        .collect();
    found.sort_by_key(|(when, _)| std::cmp::Reverse(*when));
    let conversations: Vec<Json> = found.into_iter().map(|(_, c)| c).collect();
    json!({"conversations": conversations})
}

/// Marks a conversation read up to its last message from the contact. Their
/// devices see the marker too (`profiles.md#relationship`).
pub fn mark_read(d: &Arc<Daemon>, who: &str) -> anyhow::Result<Json> {
    let contact = listed(d, who)?;
    let me = identity(d)?;
    let op = {
        let core = d.core();
        let open = core
            .spaces
            .get(&contact.space)
            .and_then(|h| h.space.as_ref());
        let open = open.ok_or_else(|| anyhow::anyhow!("that space is not open yet"))?;
        let all = relationship::messages(open);
        let read = relationship::read_by(open, &me, &all);
        let new = all
            .iter()
            .zip(&read)
            .any(|(m, read)| m.author != me && !read);
        let theirs = all.iter().rposition(|m| m.author != me);
        match theirs {
            Some(at) if new => {
                let last = all[at].id;
                match relationship::read_marker(open, &me) {
                    Some(marker) => Some(relationship::set_read_marker(marker, last)),
                    None => relationship::conversation(open)
                        .map(|c| relationship::create_read_marker(c, last)),
                }
            }
            _ => None,
        }
    };
    if let Some(op) = op {
        d.write_and_push(&contact.space, vec![op])?;
    }
    Ok(json!({}))
}
