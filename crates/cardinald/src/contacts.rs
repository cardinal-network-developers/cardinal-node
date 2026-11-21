//! Other people (`contact.md`): invitations, the relationship space two
//! people get from one, and the conversation in it.
//!
//! An invitation is a secret that lets one session through. The two devices
//! say who they are, take each other's identity logs, and the inviter creates
//! a space with both as writers and no owner. After that they are contacts.
//! If each trusts the other, their devices may open sessions with each
//! other, for what they share and nothing else. If not, the session ends
//! there, and a device answers the other's as it answers a stranger's.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use std::collections::HashSet;

use cardinal_blob::{BlobReader, BlobRef, BlobWriter, ConvergenceSecret, NoFetch};
use cardinal_contact::{ContactMessage, EndpointAddr, Invitation};
use cardinal_encoding::Value;
use cardinal_link::{CarrierKind, Priority, SecretEntry, Service, Session, Stream, Target};
use cardinal_space::account::{self, ContactRecord, Regard};
use cardinal_space::{relationship, SpaceId, SpaceOp};
use cardinal_sync::identity_log_label;
use serde_json::{json, Value as Json};
use tokio::io::AsyncWriteExt;

use crate::core::{now_ms, short, Core};
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

pub(crate) fn identity(d: &Daemon) -> anyhow::Result<[u8; 32]> {
    d.core()
        .identity
        .as_ref()
        .map(|i| i.id())
        .ok_or_else(|| anyhow::anyhow!("this device does not belong to anyone"))
}

/// Makes an invitation. With `address`, it is to this device there. Without,
/// it is to this person's host if they have one, which is always on and which
/// anyone can reach, and to this device on its local network if not. It is
/// kept in the account space, so every device of this person answers it.
pub fn invite(
    d: &Arc<Daemon>,
    address: Option<&str>,
    name: Option<&str>,
    regard: Regard,
) -> anyhow::Result<Json> {
    let invitation = invite_for(d, address, name, regard, None, None)?;
    Ok(json!({"code": invitation.to_text()}))
}

/// Makes an invitation, for one identity alone if `for_identity` is given,
/// and noting how whoever uses it will have met this person.
pub(crate) fn invite_for(
    d: &Arc<Daemon>,
    address: Option<&str>,
    name: Option<&str>,
    regard: Regard,
    for_identity: Option<[u8; 32]>,
    met: Option<&account::Met>,
) -> anyhow::Result<Invitation> {
    let me = identity(d)?;
    let here = *d.keys.link.public_key().x25519();
    let port = d
        .endpoint
        .udp_addr()
        .or(d.endpoint.tcp_addr())
        .map_or(0, |a| a.port());
    let (responder, addr): ([u8; 32], SocketAddr) = match address {
        Some(a) => (
            here,
            a.parse().map_err(|_| {
                anyhow::anyhow!("{a} is not an address; it looks like 203.0.113.9:7171")
            })?,
        ),
        None => match own_host(d) {
            Some(host) => host,
            None => {
                // A device that listens on one address gives that one.
                let bound = d.endpoint.udp_addr().or(d.endpoint.tcp_addr());
                let ip = bound
                    .map(|a| a.ip())
                    .filter(|ip| !ip.is_unspecified())
                    .or_else(|| crate::daemon::local_ips().into_iter().next())
                    .ok_or_else(|| anyhow::anyhow!("this device has no address to give"))?;
                (here, SocketAddr::new(ip, port))
            }
        },
    };
    let endpoint = EndpointAddr::new(CarrierKind::Udp, addr);
    let mut invitation = Invitation::new(me, responder, endpoint);
    // the name this person suggests for themselves, unless told another
    invitation.name = Some(name.map_or_else(|| crate::names::my_name(d), str::to_owned));
    invitation.for_identity = for_identity;
    let account = d
        .core()
        .account_id()
        .ok_or_else(|| anyhow::anyhow!("the account space is not here yet"))?;
    let op = account::create_invitation_met(invitation.to_record(), regard, met);
    d.write_and_push(&account, vec![op])?;
    admit_invitations(d);
    Ok(invitation)
}

/// This person's host, by static key, at an address that is not a name.
fn own_host(d: &Daemon) -> Option<([u8; 32], SocketAddr)> {
    let hosts = d.core().mailboxes();
    hosts.iter().find_map(|(grant, _)| {
        let at = grant.endpoints.iter().find_map(|e| e.socket_addr())?;
        Some((*grant.link_key.x25519(), at))
    })
}

/// How long an invitation lasts, by the clock of the device that made it:
/// expiry is each person's own policy (`contact.md#invitations`).
const INVITATION_LASTS: u64 = 30 * 24 * 60 * 60 * 1000;

/// An invitation this person made, and where it stands.
struct Made {
    record: account::InvitationRecord,
    invitation: Invitation,
    /// When, by the clock of the device that made it.
    at: Option<u64>,
}

impl Made {
    fn outstanding(&self) -> bool {
        let left = (self.record.used as u64) < self.invitation.uses;
        !self.record.cancelled && left && !self.expired()
    }

    fn expired(&self) -> bool {
        self.at
            .is_some_and(|at| now_ms().saturating_sub(at) > INVITATION_LASTS)
    }
}

/// The invitations this person made.
fn made(d: &Daemon) -> Vec<Made> {
    let core = d.core();
    let Some(space) = core.account().and_then(|a| a.space.as_ref()) else {
        return Vec::new();
    };
    let all = account::invitations(space.state()).into_iter();
    all.filter_map(|record| {
        let invitation = Invitation::from_record(&record.invitation).ok()?;
        let at = space.dag().get(&record.entry).and_then(|e| e.time());
        Some(Made {
            record,
            invitation,
            at,
        })
    })
    .collect()
}

/// The invitations this person made, as a window shows them.
pub fn invitations(d: &Daemon) -> Json {
    let all: Vec<Json> = made(d)
        .iter()
        .map(|m| {
            json!({
                "id": hex::encode(m.record.node),
                "name": m.invitation.name,
                "made": m.at,
                "used": m.record.used,
                "uses": m.invitation.uses,
                "hosts_only": !m.record.regard.trusted,
                "outstanding": m.outstanding(),
                "cancelled": m.record.cancelled,
                "expired": m.expired(),
            })
        })
        .collect();
    json!({"invitations": all})
}

/// Cancels an invitation on every device of this person.
pub fn cancel_invitation(d: &Arc<Daemon>, id: &str) -> anyhow::Result<Json> {
    let node = hex::decode(id).ok();
    let node = node.and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok());
    let node = node.ok_or_else(|| anyhow::anyhow!("that is not an invitation"))?;
    anyhow::ensure!(
        made(d).iter().any(|m| m.record.node == node),
        "there is no such invitation"
    );
    let account = d
        .core()
        .account_id()
        .ok_or_else(|| anyhow::anyhow!("the account space is not here yet"))?;
    d.write_and_push(&account, vec![account::cancel_invitation(node)])?;
    admit_invitations(d);
    Ok(json!({}))
}

/// Lets in whoever holds an invitation this person has outstanding, on this
/// device as on all their others, and stops for one that is used up,
/// cancelled or too old, wherever that happened.
pub fn admit_invitations(d: &Daemon) {
    let outstanding: Vec<(Invitation, Regard)> = made(d)
        .into_iter()
        .filter(Made::outstanding)
        .map(|m| (m.invitation, m.record.regard))
        .collect();
    let wanted: std::collections::HashSet<[u8; 16]> =
        outstanding.iter().map(|(i, _)| i.secret).collect();
    let mut admitted = d.admitted_invitations();
    admitted.retain(|secret, id| {
        let keep = wanted.contains(secret);
        if !keep {
            d.endpoint.remove_secret(*id);
            d.invitation_done(*id);
        }
        keep
    });
    for (invitation, regard) in outstanding {
        if admitted.contains_key(&invitation.secret) {
            continue;
        }
        // The link would count a use for any session that confirms, though
        // nothing came of it. The account counts what is done, and an
        // exchange holds a use while it runs (`take_a_use`).
        let mut entry = SecretEntry::new(&invitation.secret);
        entry.uses = None;
        let id = d.endpoint.add_secret(entry);
        d.invitation_made(id, regard);
        admitted.insert(invitation.secret, id);
    }
}

/// One of an invitation's uses, held by an exchange under way on this device.
/// It goes back when the exchange ends; if that went through, the account
/// counts the use by then.
struct Using<'a> {
    d: &'a Daemon,
    secret: u64,
}

impl Drop for Using<'_> {
    fn drop(&mut self) {
        let mut using = self.d.invitations_using();
        if let Some(n) = using.get_mut(&self.secret) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                using.remove(&self.secret);
            }
        }
    }
}

/// Takes one of the uses left on the invitation that let `s` in, if any is.
/// The link counts a use only once a session is confirmed, so two handshakes
/// at once would both get through to here.
fn take_a_use<'a>(d: &'a Daemon, s: &Session) -> Option<Using<'a>> {
    let cardinal_link::Admission::Secret { id, .. } = s.admission() else {
        return None;
    };
    let admitted = d.admitted_invitations();
    let secret = admitted.iter().find(|(_, i)| **i == id).map(|(s, _)| *s);
    drop(admitted);
    let secret = secret?;
    let invitation = made(d)
        .into_iter()
        .find(|m| m.invitation.secret == secret && m.outstanding())?;
    let left = invitation.invitation.uses - invitation.record.used as u64;
    let mut using = d.invitations_using();
    let under_way = using.entry(id).or_insert(0);
    if u64::from(*under_way) >= left {
        return None;
    }
    *under_way += 1;
    Some(Using { d, secret: id })
}

/// The invitation of this person's that let `s` in.
fn invitation_of_session(d: &Daemon, s: &Session) -> Option<Invitation> {
    let cardinal_link::Admission::Secret { id, .. } = s.admission() else {
        return None;
    };
    let admitted = d.admitted_invitations();
    let secret = admitted.iter().find(|(_, i)| **i == id).map(|(s, _)| *s)?;
    drop(admitted);
    made(d)
        .into_iter()
        .map(|m| m.invitation)
        .find(|i| i.secret == secret)
}

/// Records that `who` used the invitation that let `s` in, so that every
/// device of this person counts it.
fn invitation_used(d: &Arc<Daemon>, s: &Session, who: &[u8; 32]) -> anyhow::Result<()> {
    let cardinal_link::Admission::Secret { id, .. } = s.admission() else {
        return Ok(());
    };
    let secret = d
        .admitted_invitations()
        .iter()
        .find(|(_, i)| **i == id)
        .map(|(secret, _)| *secret);
    let Some(secret) = secret else {
        return Ok(());
    };
    let (account, node) = {
        let core = d.core();
        let Some(space) = core.account().and_then(|a| a.space.as_ref()) else {
            return Ok(());
        };
        let made = account::invitations(space.state());
        let mine = made
            .iter()
            .find(|i| Invitation::from_record(&i.invitation).is_ok_and(|inv| inv.secret == secret));
        let Some(i) = mine else {
            return Ok(());
        };
        (core.account_id(), i.node)
    };
    if let Some(account) = account {
        d.write_and_push(&account, vec![account::create_invitation_use(node, who)])?;
    }
    admit_invitations(d);
    Ok(())
}

/// Takes up an invitation, and becomes a contact of whoever gave it.
pub async fn accept(
    d: &Arc<Daemon>,
    code: &str,
    name: Option<&str>,
    regard: Regard,
    met: account::Met,
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
    let exchange = accept_exchange(d, &s, me, &invitation, &petname, regard, &met);
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
    met: &account::Met,
) -> anyhow::Result<()> {
    let proven = s.peer_identity().map(|p| p.identity);
    anyhow::ensure!(
        proven == Some(invitation.inviter),
        "the device at that address is not the one who invited you"
    );
    let mut st = s.open_stream(Service::CONTACT, Priority::Interactive)?;
    let hello = ContactMessage::Hello {
        identity: me,
        name: crate::names::my_name(d),
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
    mailbox::on_meeting(d, &space).await?;
    net::reconcile(d, s, space).await?;
    let suggested = invitation.name.as_deref();
    record_contact(
        d,
        &invitation.inviter,
        petname,
        suggested,
        &space,
        regard,
        Some(met),
    )?;
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
    // Held until the exchange ends: two at once cannot both use one use.
    let Some(using) = take_a_use(d, s) else {
        s.abandon();
        return Ok(());
    };
    // A use is held only while something comes of it.
    let hello = tokio::time::timeout(EXCHANGE_WITHIN, receive(&mut st)).await;
    let Ok(Ok(Some(ContactMessage::Hello { identity, name }))) = hello else {
        s.abandon();
        return Ok(());
    };
    anyhow::ensure!(identity == them, "not who the session says");
    // One made for someone, as an introduction's is, is theirs alone.
    let bound = invitation_of_session(d, s).and_then(|i| i.for_identity);
    if bound.is_some_and(|f| f != them) {
        s.abandon();
        return Ok(());
    }
    let label = identity_log_label(&them);
    net::reconcile_as(d, s, label, Access::Other(them)).await?;
    if !proven_by_log(d, s, &them) {
        s.abandon();
        return Ok(());
    }
    let (space, genesis) = d.core().create_relationship(&them)?;
    d.invited_to(s, space);
    mailbox::on_meeting(d, &space).await?;
    send(&mut st, &ContactMessage::Genesis(genesis)).await?;
    let done = tokio::time::timeout(EXCHANGE_WITHIN, receive(&mut st)).await;
    if matches!(done, Ok(Ok(Some(ContactMessage::Done)))) {
        net::reconcile(d, s, space).await?;
        let met = met_by_invitation(d, s).unwrap_or(account::Met {
            how: account::MET_MY_INVITATION,
            ..Default::default()
        });
        // The use first: whoever sees them listed sees it used.
        if let Err(e) = invitation_used(d, s, &them) {
            tracing::debug!("counting an invitation's use: {e:#}");
        }
        record_contact(d, &them, &name, Some(&name), &space, regard, Some(&met))?;
        // The account counts it now.
        drop(using);
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

/// How whoever used the invitation that let `s` in met this person, if the
/// invitation says: one made for an introduction does.
fn met_by_invitation(d: &Daemon, s: &Session) -> Option<account::Met> {
    let inv = invitation_of_session(d, s)?;
    let core = d.core();
    let space = core.account().and_then(|a| a.space.as_ref())?;
    let made = account::invitations(space.state());
    let found = made
        .into_iter()
        .find(|i| Invitation::from_record(&i.invitation).is_ok_and(|x| x.secret == inv.secret));
    found?.met
}

fn record_contact(
    d: &Arc<Daemon>,
    who: &[u8; 32],
    petname: &str,
    suggested: Option<&str>,
    space: &SpaceId,
    regard: Regard,
    met: Option<&account::Met>,
) -> anyhow::Result<()> {
    let account = d
        .core()
        .account_id()
        .ok_or_else(|| anyhow::anyhow!("the account space is not here yet"))?;
    let op = account::create_contact_suggesting(who, petname, suggested, space, regard, met);
    d.write_and_push(&account, vec![op])?;
    // Just met: they will want to talk.
    d.rendezvous.use_contact(who);
    Ok(())
}

/// Changes how this person regards a contact. Only their own devices hear of
/// it, and the contact is told nothing.
///
/// Refusing someone answers with `reach`: the groups they are in where
/// this person's reach node names their hosts, each with its `name` and
/// `what` they can see there. They still read it, and software asks about
/// that as part of refusing, on this device, and nowhere else afterwards
/// (`hosts.md#telling-others-where-to-reach-you`): `group-reach` with
/// `share` false stops it in a group.
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
    if setting == "refuse" {
        let reach = crate::groups::naming_hosts_to(&d.core(), &contact.identity);
        return Ok(json!({"reach": reach}));
    }
    Ok(json!({}))
}

/// The person says, in their relationship with a contact, whether the
/// contact may have where their hosts are: `name-hosts` names each host
/// of theirs (a host that cannot be reached now is named once it can),
/// and `no-hosts` empties the list. Nothing else writes a yes where the
/// list is empty, so this is how a list emptied before is filled.
pub async fn name_hosts(d: &Arc<Daemon>, who: &str, share: bool) -> anyhow::Result<Json> {
    let contact = find(d, who)?;
    anyhow::ensure!(!contact.refused, "you have refused {who}");
    if !share {
        mailbox::say_reach(d, &contact.space, false).await?;
        return Ok(json!({"named": "none"}));
    }
    let shared = mailbox::share_reach(d, &contact.space).await?;
    Ok(json!({"named": match shared {
        mailbox::Shared::Named => "named",
        mailbox::Shared::NoHost => "no host",
        mailbox::Shared::Waiting => "waiting",
    }}))
}

/// Changes what this person calls a contact. Only their own devices hear of
/// it, and the contact is told nothing. An empty name clears the petname:
/// the contact is then shown by the name they suggest, as theirs.
pub fn rename(d: &Arc<Daemon>, who: &str, name: &str) -> anyhow::Result<Json> {
    let contact = find(d, who)?;
    let name = name.trim();
    if name.is_empty() {
        let account = d
            .core()
            .account_id()
            .ok_or_else(|| anyhow::anyhow!("the account space is not here yet"))?;
        // Empty, not absent: a release before this one reads a contact
        // without a petname as no contact at all.
        let op = account::set_field(contact.node, account::PETNAME, "");
        d.write_and_push(&account, vec![op])?;
        let c = find(d, &hex::encode(&contact.identity[..8]))?;
        return Ok(Json::Object(crate::names::shown(d, &c)));
    }
    anyhow::ensure!(!name.contains('\n'), "a name is one line");
    // Two people with one name could be told apart only by their ids.
    let taken =
        d.core().contacts().into_iter().any(|c| {
            c.identity != contact.identity && c.petname.to_lowercase() == name.to_lowercase()
        });
    anyhow::ensure!(!taken, "you already call someone else {name:?}");
    let account = d
        .core()
        .account_id()
        .ok_or_else(|| anyhow::anyhow!("the account space is not here yet"))?;
    let op = account::set_field(contact.node, account::PETNAME, name);
    d.write_and_push(&account, vec![op])?;
    Ok(json!({"name": name}))
}

/// Lists a contact under another category, such as `Family`, which is the
/// folder their shared folder appears in.
pub fn set_category(d: &Arc<Daemon>, who: &str, category: &str) -> anyhow::Result<Json> {
    let contact = find(d, who)?;
    let category = category.trim();
    anyhow::ensure!(!category.is_empty(), "a category cannot be empty");
    anyhow::ensure!(
        !category.contains('/') && category != "." && category != "..",
        "a category is a folder's name, so it cannot be {category:?}"
    );
    let account = d
        .core()
        .account_id()
        .ok_or_else(|| anyhow::anyhow!("the account space is not here yet"))?;
    let op = account::set_field(contact.node, account::CATEGORY, category);
    d.write_and_push(&account, vec![op])?;
    Ok(json!({"category": category}))
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
    let relayed = d.relayed_people();
    let everyone = d.core().contacts();
    let group_names: Vec<(SpaceId, String)> = {
        let core = d.core();
        let spaces = core.spaces.iter();
        spaces
            .filter_map(|(id, h)| {
                let sp = h.space.as_ref()?;
                (sp.profile() == cardinal_space::group::GROUP)
                    .then(|| (*id, cardinal_space::group::name(sp)))
            })
            .collect()
    };
    let contacts: Vec<Json> = everyone
        .iter()
        .filter(|c| all || !c.refused)
        .map(|c| {
            let v = json!({
                "met": c.met.as_ref().map(|m| met_json(m, &everyone, &group_names)),
                "identity": hex::encode(&c.identity[..8]),
                "trusted": c.regard.trusted,
                "introductions": c.regard.introductions,
                "refused": c.refused,
                "category": c.category,
                "connected": connected.contains(&c.identity),
                "relayed": relayed.contains(&c.identity),
            });
            crate::names::with_shown(d, c, v)
        })
        .collect();
    json!({"contacts": contacts})
}

/// How two people met, as a window shows it.
fn met_json(m: &account::Met, contacts: &[ContactRecord], groups: &[(SpaceId, String)]) -> Json {
    let how = match m.how {
        account::MET_THEIR_INVITATION => "their invitation",
        account::MET_MY_INVITATION => "your invitation",
        account::MET_INTRODUCED => "introduced",
        _ => "their front door",
    };
    let by = m.introducer.map(|i| {
        let c = contacts.iter().find(|c| c.identity == i);
        c.map_or_else(|| account::short_key(&i), |c| c.petname.clone())
    });
    let group = m.group.and_then(|g| {
        groups
            .iter()
            .find(|(id, _)| *id == g)
            .map(|(_, n)| n.clone())
    });
    json!({"how": how, "by": by, "group": group, "via": m.via})
}

/// The contact called `who`.
pub(crate) fn find(d: &Daemon, who: &str) -> anyhow::Result<ContactRecord> {
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
/// A contact this person turns to, by what they call them: they are in use
/// from now on (`sync.md#neighbours`), and so looked for.
pub(crate) fn listed(d: &Daemon, who: &str) -> anyhow::Result<ContactRecord> {
    let contact = find(d, who)?;
    anyhow::ensure!(!contact.refused, "you have refused {who}");
    d.rendezvous.use_contact(&contact.identity);
    Ok(contact)
}

/// Writes a message to a contact.
pub async fn say(
    d: &Arc<Daemon>,
    who: &str,
    text: &str,
    reply_to: Option<&str>,
    attach: &[String],
) -> anyhow::Result<Json> {
    let contact = listed(d, who)?;
    let to = match reply_to {
        Some(id) => Some(message_in(d, &contact, id)?.id),
        None => None,
    };
    let attachments = encode_attachments(d, &contact.space, attach).await?;
    let space = contact.space;
    let conversation = {
        let core = d.core();
        core.spaces
            .get(&space)
            .and_then(|h| h.space.as_ref())
            .and_then(relationship::conversation)
    };
    let conversation = conversation.ok_or_else(|| anyhow::anyhow!("that space is not open yet"))?;
    let mut ops = vec![relationship::create_with(
        conversation,
        text,
        to,
        &attachments,
    )];
    ops.extend(relationship::shared_files(&attachments, Some(now_ms())));
    d.write_and_push(&space, ops)?;
    confirm(d, space, contact.identity);
    Ok(json!({"reachable": reachable(d, &contact, text) && attachments.is_empty()}))
}

/// What kind of file a name says it is, by its ending.
pub(crate) fn media_type(name: &str) -> &'static str {
    let ending = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase());
    match ending.as_deref() {
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("png") => "image/png",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("heic") => "image/heic",
        Some("pdf") => "application/pdf",
        Some("txt") => "text/plain",
        Some("mp4") => "video/mp4",
        Some("mov") => "video/quicktime",
        Some("mp3") => "audio/mpeg",
        Some("m4a") => "audio/mp4",
        Some("ogg" | "opus") => "audio/ogg",
        Some("zip") => "application/zip",
        _ => "application/octet-stream",
    }
}

/// Encodes files to attach to a message, with the key of the space's current
/// epoch, so only those in the space can read them.
pub(crate) async fn encode_attachments(
    d: &Arc<Daemon>,
    space: &SpaceId,
    paths: &[String],
) -> anyhow::Result<Vec<relationship::Attachment>> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    let secret = {
        let core = d.core();
        let open = core.spaces.get(space).and_then(|h| h.space.as_ref());
        let open = open.ok_or_else(|| anyhow::anyhow!("that space is not open yet"))?;
        let epoch = open.current_epoch();
        let key = epoch.and_then(|e| open.keyring().get(&e));
        let key = key.ok_or_else(|| anyhow::anyhow!("that space has no key yet"))?;
        ConvergenceSecret::from_epoch_key(key.bytes())
    };
    let (d, paths) = (d.clone(), paths.to_vec());
    tokio::task::spawn_blocking(move || {
        let mut out = Vec::new();
        for p in &paths {
            let path = std::path::Path::new(p);
            let mut file =
                std::fs::File::open(path).map_err(|e| anyhow::anyhow!("cannot read {p}: {e}"))?;
            anyhow::ensure!(file.metadata()?.is_file(), "{p} is not a file");
            let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
            let name = name.ok_or_else(|| anyhow::anyhow!("{p} has no name"))?;
            let mut w = BlobWriter::new(&secret, &*d.store);
            std::io::copy(&mut file, &mut w)?;
            let (blob, _) = w.finish()?;
            out.push(relationship::Attachment {
                media_type: media_type(&name).to_owned(),
                name,
                blob: blob.to_record(),
            });
        }
        Ok(out)
    })
    .await?
}

/// The objects of the files this person attached in the space shared with
/// `who`: all a contact may fetch from here (`sync.md#blob-transfer`). Only
/// this person's own: a reference the contact wrote could name anything.
/// Worked out again only when the space has grown, and away from the runtime.
pub async fn shared_blobs(d: &Arc<Daemon>, who: &[u8; 32]) -> Arc<HashSet<[u8; 32]>> {
    let size = {
        let core = d.core();
        let contacts = core.contacts();
        let space = contacts
            .iter()
            .find(|c| c.identity == *who)
            .map(|c| c.space);
        // And the groups the two are in: what a group's messages carry is
        // every member's, whoever sent it, since members who do not know
        // each other get it through one who knows both.
        let groups = core.groups_shared_with(who);
        let seen: usize = groups
            .iter()
            .filter_map(|g| core.spaces.get(g))
            .map(|h| h.set_len())
            .sum();
        // What this device holds of other members' files changes with no
        // new entry, so with groups the answer is worked out again every few
        // seconds.
        let lately = if groups.is_empty() {
            0
        } else {
            (crate::core::now_ms() / 5000) as usize
        };
        space
            .and_then(|s| core.spaces.get(&s))
            .map(|h| (h.id, (h.set_len() + seen) ^ (lately << 24), groups))
    };
    let Some((space, size, groups)) = size else {
        return Arc::default();
    };
    {
        let cache = d.shared_blobs.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((_, ids)) = cache.get(who).filter(|(was, _)| *was == size) {
            return ids.clone();
        }
    }
    let (d, who) = (d.clone(), *who);
    let worked_out = tokio::task::spawn_blocking(move || {
        let blobs = shared_refs(&d.core(), &space, &groups);
        let (mut files, mut ids) = (HashSet::new(), HashSet::new());
        for blob in blobs {
            // The same file attached again is the same objects.
            if !files.insert(blob.id) {
                continue;
            }
            // What this device holds of it: an index it has not got names nothing.
            let mut reader = BlobReader::new(&*d.store, &NoFetch, blob);
            let _ = reader.for_each_object(|id| {
                ids.insert(*id);
            });
        }
        let ids = Arc::new(ids);
        let mut cache = d.shared_blobs.lock().unwrap_or_else(|e| e.into_inner());
        cache.insert(who, (size, ids.clone()));
        ids
    });
    worked_out.await.unwrap_or_default()
}

/// The blobs a contact may fetch from here: those of the files this person
/// attached in the relationship `space`, of what they put in its shared
/// folder, and of whatever else they wrote there that current state
/// references, which is the content of kinds this build does not know and
/// the other's devices fetch all the same (`blobs.md#retention`). Only
/// this person's own: a reference the contact wrote could name anything.
/// And of each of `groups`, everything its messages carry and its current
/// state references, whoever wrote it.
pub fn shared_refs(core: &Core, space: &SpaceId, groups: &[SpaceId]) -> Vec<BlobRef> {
    let me = core.identity.as_ref().map(|i| i.id());
    let open = core.spaces.get(space).and_then(|h| h.space.as_ref());
    let all = open.map(relationship::messages).unwrap_or_default();
    let mine = all.into_iter().filter(|m| Some(m.author) == me);
    let attached = mine
        .flat_map(|m| m.attachments)
        .filter_map(|a| BlobRef::from_record(&a.blob).ok());
    // and what this person put in the shared folder
    let put = open
        .map(|sp| shared_folder_content(sp, me))
        .unwrap_or_default();
    let other = match (open, me) {
        (Some(sp), Some(me)) => crate::fetch::state_blobs_by(sp, Some(me)),
        _ => Vec::new(),
    };
    let spaces = groups.iter();
    let spaces = spaces.filter_map(|g| core.spaces.get(g).and_then(|h| h.space.as_ref()));
    let in_groups = spaces.flat_map(|sp| {
        let carried = relationship::messages(sp).into_iter();
        let carried = carried
            .flat_map(|m| m.attachments)
            .filter_map(|a| BlobRef::from_record(&a.blob).ok());
        carried.chain(crate::fetch::state_blobs(sp))
    });
    let own = attached.chain(put).chain(other);
    own.chain(in_groups).collect()
}

/// The content versions of the shared folder's files that `me` wrote.
fn shared_folder_content(space: &cardinal_space::Space, me: Option<[u8; 32]>) -> Vec<BlobRef> {
    use cardinal_space::files::{Content, FileKind, Files};
    let files = Files::new(space);
    let mut out = Vec::new();
    let mut stack = vec![cardinal_space::ROOT];
    while let Some(dir) = stack.pop() {
        for e in files.list(&dir) {
            match e.kind {
                FileKind::Folder => stack.push(e.node),
                FileKind::File if e.conflict_version.is_none() => {
                    for v in files.content(&e.node) {
                        if let (Some(Content::Blob(b)), true) = (v.content, Some(v.author) == me) {
                            out.push(crate::fetch::blob_ref(&b));
                        }
                    }
                }
                _ => {}
            }
        }
    }
    out
}

/// Writes a whole blob to `out`, and says how much.
pub(crate) fn write_out<S: cardinal_blob::ObjectStore, F: cardinal_blob::Fetch>(
    reader: &mut BlobReader<'_, S, F>,
    out: &mut std::fs::File,
) -> anyhow::Result<u64> {
    use std::io::Write;
    let size = reader.size();
    let mut at = 0u64;
    while at < size {
        let piece = match reader.read_range(at, 1 << 20) {
            Ok(p) if !p.is_empty() => p,
            Ok(_) => {
                anyhow::bail!("part of it could not be fetched; try again when they are online")
            }
            Err(e) => {
                tracing::debug!("reading an attachment: {e}");
                anyhow::bail!("part of it could not be fetched; try again when they are online")
            }
        };
        out.write_all(&piece)?;
        at += piece.len() as u64;
    }
    Ok(size)
}

/// Saves a file attached to a message at `to`, fetching from this person's
/// devices and the contact's whatever is not here. Nothing is left at `to`
/// unless all of it arrived.
pub async fn save_attachment(
    d: &Arc<Daemon>,
    who: &str,
    id: &str,
    index: usize,
    to: &str,
) -> anyhow::Result<Json> {
    let contact = listed(d, who)?;
    let m = message_in(d, &contact, id)?;
    let a = m.attachments.get(index);
    let a = a.ok_or_else(|| anyhow::anyhow!("that message has no such attachment"))?;
    let blob = BlobRef::from_record(&a.blob)
        .map_err(|_| anyhow::anyhow!("that attachment cannot be read"))?;
    let to = std::path::PathBuf::from(to);
    let (d, them) = (d.clone(), contact.identity);
    let written = to.clone();
    let size = tokio::task::spawn_blocking(move || -> anyhow::Result<u64> {
        let fetch = crate::fetch::Fetcher::from_contact(&d, Priority::Interactive, them);
        let mut reader = BlobReader::new(&*d.store, &fetch, blob);
        write_new(&written, |out| write_out(&mut reader, out))
    })
    .await??;
    Ok(json!({"path": to, "size": size}))
}

/// Writes a new file at `to` with what `fill` writes. It is written beside,
/// as `to.part`, and gone again whatever happens: nothing that was there is
/// touched, and nothing is followed.
pub(crate) fn write_new(
    to: &std::path::Path,
    fill: impl FnOnce(&mut std::fs::File) -> anyhow::Result<u64>,
) -> anyhow::Result<u64> {
    anyhow::ensure!(!to.exists(), "{} is there already", to.display());
    let mut part = to.to_path_buf().into_os_string();
    part.push(".part");
    let part = std::path::PathBuf::from(part);
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&part)?;
    let wrote = fill(&mut out).and_then(|size| {
        out.sync_all()?;
        // A link, unlike a rename, will not replace a file that came to
        // be there meanwhile.
        match std::fs::hard_link(&part, to) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                anyhow::bail!("{} is there already", to.display())
            }
            // No hard links here (Android's app storage): a rename, if
            // nothing is in the way.
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::Unsupported
                ) =>
            {
                anyhow::ensure!(!to.exists(), "{} is there already", to.display());
                std::fs::rename(&part, to)?;
            }
            Err(e) => anyhow::bail!("cannot save it at {}: {e}", to.display()),
        }
        Ok(size)
    });
    let _ = std::fs::remove_file(&part);
    wrote
}

/// A message in the conversation with a contact, by the id `messages` gives.
fn message_in(
    d: &Daemon,
    contact: &ContactRecord,
    id: &str,
) -> anyhow::Result<relationship::Message> {
    let id = hex::decode(id).ok();
    let id = id.and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok());
    let id = id.ok_or_else(|| anyhow::anyhow!("that is not a message"))?;
    let core = d.core();
    let open = core
        .spaces
        .get(&contact.space)
        .and_then(|h| h.space.as_ref());
    let open = open.ok_or_else(|| anyhow::anyhow!("that space is not open yet"))?;
    let all = relationship::messages(open);
    let found = all.into_iter().find(|m| m.id == id);
    found.ok_or_else(|| anyhow::anyhow!("there is no such message"))
}

/// A message of this person's own in the conversation with `who`: only that
/// can be changed or taken back, which the space itself holds to as well.
fn own_message(
    d: &Daemon,
    who: &str,
    id: &str,
) -> anyhow::Result<(ContactRecord, relationship::Message)> {
    let contact = listed(d, who)?;
    let m = message_in(d, &contact, id)?;
    anyhow::ensure!(
        Some(m.author) == d.core().identity.as_ref().map(|i| i.id()),
        "only what you wrote can be changed"
    );
    Ok((contact, m))
}

/// Changes what a message of this person's says.
pub fn edit_message(d: &Arc<Daemon>, who: &str, id: &str, text: &str) -> anyhow::Result<Json> {
    let (contact, m) = own_message(d, who, id)?;
    anyhow::ensure!(!text.trim().is_empty(), "a message cannot be empty");
    let op = relationship::edit_message(m.id, text);
    d.write_and_push(&contact.space, vec![op])?;
    confirm(d, contact.space, contact.identity);
    Ok(json!({}))
}

/// Takes back a message of this person's. The other person may have read it
/// already, and the space's history keeps it.
pub fn delete_message(d: &Arc<Daemon>, who: &str, id: &str) -> anyhow::Result<Json> {
    let (contact, m) = own_message(d, who, id)?;
    d.write_and_push(&contact.space, vec![SpaceOp::delete(m.id)])?;
    confirm(d, contact.space, contact.identity);
    Ok(json!({}))
}

/// The longest reaction: an emoji, or a few of them.
const MAX_REACTION: usize = 16;

/// Reacts to a message, replacing this person's reaction, or taking it away
/// with nothing.
pub fn react(d: &Arc<Daemon>, who: &str, id: &str, text: &str) -> anyhow::Result<Json> {
    let contact = listed(d, who)?;
    let m = message_in(d, &contact, id)?;
    let text = text.trim();
    anyhow::ensure!(
        text.chars().count() <= MAX_REACTION,
        "that is too long for a reaction"
    );
    let me = d.core().identity.as_ref().map(|i| i.id());
    // The one shown is the last of this person's (`reactions_of`); any
    // others, from devices apart, go when this one changes.
    let mine: Vec<&relationship::Reaction> = m
        .reactions
        .iter()
        .filter(|r| Some(r.author) == me)
        .collect();
    let mut ops: Vec<SpaceOp> = Vec::new();
    match (mine.last(), text.is_empty()) {
        (Some(_), true) => ops.extend(mine.iter().map(|r| SpaceOp::delete(r.id))),
        (Some(r), false) => {
            ops.extend(mine[..mine.len() - 1].iter().map(|r| SpaceOp::delete(r.id)));
            if r.text != text {
                ops.push(relationship::set_reaction(r.id, text));
            }
        }
        (None, true) => {}
        (None, false) => ops.push(relationship::create_reaction(m.id, text)),
    }
    if ops.is_empty() {
        return Ok(json!({}));
    }
    d.write_and_push(&contact.space, ops)?;
    confirm(d, contact.space, contact.identity);
    Ok(json!({}))
}

/// Reactions as a window shows them: each one once, with how many gave it
/// and whether this person did.
pub(crate) fn reactions_of(m: &relationship::Message, me: Option<[u8; 32]>) -> Vec<Json> {
    // One for each person, the last they gave, however many they wrote, and
    // no longer than this software lets anyone make one.
    let mut theirs: Vec<&relationship::Reaction> = Vec::new();
    for r in &m.reactions {
        match theirs.iter_mut().find(|x| x.author == r.author) {
            Some(x) => *x = r,
            None => theirs.push(r),
        }
    }
    let mut shown: Vec<(String, usize, bool)> = Vec::new();
    for r in theirs {
        let mine = Some(r.author) == me;
        let text: String = r.text.chars().take(MAX_REACTION).collect();
        match shown.iter_mut().find(|(t, ..)| *t == text) {
            Some((_, n, m)) => {
                *n += 1;
                *m |= mine;
            }
            None => shown.push((text, 1, mine)),
        }
    }
    shown
        .into_iter()
        .map(|(text, count, mine)| json!({"text": text, "count": count, "mine": mine}))
        .collect()
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
    let hosted = me.is_some_and(|me| !core.reach_of(&contact.space, &me).is_empty());
    let theirs = !core.reach_of(&contact.space, &contact.identity).is_empty();
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
                "reply_to": m.reply_to.map(hex::encode),
                "attachments": m.attachments.iter().map(|a| json!({
                    "name": a.name,
                    "type": a.media_type,
                    "size": BlobRef::from_record(&a.blob).map(|b| b.size).ok(),
                })).collect::<Vec<_>>(),
                "edited": m.edited,
                "reactions": reactions_of(m, me),
            })
        })
        .collect();
    Ok(json!({"messages": said}))
}

/// Everyone this person talks to, the most recent first: what they last said
/// and how many messages from them are not yet read here.
pub fn conversations(d: &Daemon) -> Json {
    let connected = d.connected_people();
    let relayed = d.relayed_people();
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
                "id": hex::encode(&c.identity[..8]),
                "trusted": c.regard.trusted,
                "introductions": c.regard.introductions,
                "connected": connected.contains(&c.identity),
                "relayed": relayed.contains(&c.identity),
                "unread": unread.count(),
                "last": last.map(|m| json!({
                    "mine": Some(m.author) == me,
                    "text": m.text,
                    "time": m.time,
                })),
            });
            (when, crate::names::with_shown(d, c, conversation))
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

/// A length of time in words, to the largest unit that matters.
pub(crate) fn span(t: Duration) -> String {
    let s = t.as_secs();
    match s {
        0..=59 => format!("{s} s"),
        60..=3599 => format!("{} min", s / 60),
        3600..=86_399 => format!("{} h {} min", s / 3600, s % 3600 / 60),
        _ => format!("{} days", s / 86_400),
    }
}

/// What a reach node entry's endpoint is good for here: `None` if it is
/// tried, or else why not.
fn not_tried(e: &cardinal_space::grant::Endpoint) -> Option<&'static str> {
    match e.socket_addr() {
        Some(_) => None,
        None if e
            .host()
            .is_some_and(|h| h.parse::<std::net::IpAddr>().is_err()) =>
        {
            Some("a name: names are for the recovery sheet, and are not looked up")
        }
        None => Some("an address this version cannot use"),
    }
}

/// Whether an address works only on the network it belongs to.
fn local_only(a: &SocketAddr) -> bool {
    match a.ip() {
        std::net::IpAddr::V4(ip) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
        std::net::IpAddr::V6(ip) => {
            ip.is_loopback()
                || (ip.segments()[0] & 0xfe00) == 0xfc00
                || (ip.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn reach_json(
    d: &Daemon,
    reach: &[relationship::Reach],
    theirs: &[([u8; 32], [u8; 32])],
) -> Vec<Json> {
    let me = *d.keys.link.public_key().x25519();
    reach
        .iter()
        .map(|r| {
            let device = theirs
                .iter()
                .find(|(x, _)| *x == r.host)
                .map(|(_, k)| hex::encode(&k[..8]));
            let endpoints: Vec<Json> = r
                .endpoints
                .iter()
                .map(|e| {
                    let why = not_tried(e);
                    let local = e.socket_addr().is_some_and(|a| local_only(&a));
                    json!({
                        "endpoint": e.to_string(),
                        "tried": why.is_none(),
                        "why_not": why,
                        "local": local,
                    })
                })
                .collect();
            json!({
                "host": hex::encode(&r.host[..8]),
                "device": device,
                "this_device": r.host == me,
                "session": d.session_kind(&r.host).is_some(),
                "endpoints": endpoints,
            })
        })
        .collect()
}

fn step_json(s: &crate::rendezvous::Step) -> Json {
    json!({"at": s.at, "ok": s.ok, "text": s.text})
}

/// Everything this device knows of reaching one contact: their devices and
/// the sessions with them, what their reach node says and what became of
/// each address, how they were last looked for, and what this person's own
/// reach node tells them. With `look`, looks for them first.
pub async fn status(
    d: &Arc<Daemon>,
    who: &str,
    look: bool,
    at: Option<SocketAddr>,
) -> anyhow::Result<Json> {
    let c = find(d, who)?;
    if let Some(addr) = at {
        anyhow::ensure!(
            c.connects(),
            "you do not trust {who}, so your devices do not connect to theirs"
        );
        crate::rendezvous::try_at(d, c.identity, addr).await;
    } else if look && c.connects() {
        crate::rendezvous::reach_now(d, c.identity, c.space).await;
    }
    let (theirs, reach, mine, name_of, nearby) = {
        let core = d.core();
        let theirs: Vec<([u8; 32], [u8; 32])> = core
            .others
            .get(&c.identity)
            .map(|o| {
                let st = o.log.state();
                st.keys
                    .values()
                    .filter_map(|k| Some((*k.link_key.as_ref()?.x25519(), k.key)))
                    .collect()
            })
            .unwrap_or_default();
        let reach = core.reach_of(&c.space, &c.identity);
        let mine = core
            .me()
            .map(|me| core.reach_of(&c.space, &me))
            .unwrap_or_default();
        // Whether each gave the other a presence secret here (D74).
        let sp = core.spaces.get(&c.space).and_then(|h| h.space.as_ref());
        let gives = |who: &[u8; 32]| {
            sp.is_some_and(|sp| !relationship::presence_of(sp.state(), who).is_empty())
        };
        let nearby = json!({
            "they_give_secret": gives(&c.identity),
            "you_give_secret": core.me().is_some_and(|me| gives(&me)),
        });
        (theirs, reach, mine, core.device_names(), nearby)
    };
    let label = |x: &[u8; 32]| -> String {
        if let Some(k) = d.core().is_own_device(x) {
            return format!(
                "your {}",
                name_of
                    .get(&k)
                    .cloned()
                    .unwrap_or_else(|| account::short_key(&k))
            );
        }
        if reach.iter().any(|r| r.host == *x) {
            return "their host".into();
        }
        short(x)
    };
    let standing: HashSet<[u8; 32]> = crate::rendezvous::standing(d)
        .into_iter()
        .map(|(k, _)| k)
        .collect();
    let devices: Vec<Json> = theirs
        .iter()
        .map(|(x, k)| {
            let Some((s, open_for)) = d.session_since(x) else {
                return json!({
                    "key": hex::encode(&k[..8]),
                    "online": false,
                    "kept_in_touch": standing.contains(k),
                });
            };
            let st = s.stats();
            let relayed = s.is_relayed();
            json!({
                "key": hex::encode(&k[..8]),
                "online": true,
                "kept_in_touch": standing.contains(k),
                "route": if relayed { "relay" } else { "direct" },
                "carrier": d.session_carrier(x),
                "addr": (!relayed).then(|| s.remote_addr()).flatten().map(|a| a.to_string()),
                "through": d.relayed_through(x).map(|h| label(&h)),
                "opened_by": if s.role() == cardinal_link::Role::Initiator { "you" } else { "them" },
                "open_for_s": open_for.as_secs(),
                "heard_ms_ago": s.last_heard().elapsed().as_millis() as u64,
                "rtt_ms": st.srtt.map(|t| t.as_millis() as u64),
                "bytes_sent": st.bytes_sent,
                "bytes_received": st.bytes_received,
                "packets_lost": st.packets_lost,
                "packets_dropped": st.packets_dropped,
                "they_see_you_at": s.observed_addr().map(|a| a.to_string()),
            })
        })
        .collect();
    let (looked, looking) = d.rendezvous.looked(&c.identity);
    let trail = d.rendezvous.trail(&c.identity);
    let in_use = d.rendezvous.in_use_left(&c.identity);
    let looked_for = if !c.connects() {
        "never: you do not trust them, so your devices reach them only through hosts"
    } else if in_use.is_some() {
        "while in use, every 30 s, until each of their devices has a session"
    } else {
        "only when you message or call them, until you do"
    };
    let v = json!({
        "identity": hex::encode(&c.identity[..8]),
        "trusted": c.regard.trusted,
        "introductions": c.regard.introductions,
        "refused": c.refused,
        "direct_sessions": c.connects(),
        "devices": devices,
        "their_reach": reach_json(d, &reach, &theirs),
        "nearby": nearby,
        "your_reach": reach_json(d, &mine, &[]),
        "in_use_for_s": in_use.map(|t| t.as_secs()),
        "looked_for": looked_for,
        "look_every_s": crate::rendezvous::Rendezvous::look_every().as_secs(),
        "looked_s_ago": looked.map(|t| t.as_secs()),
        "looking": looking,
        "looks_without_session": trail.looks,
        "looking_since": trail.looking_since,
        "last_look": trail.look.iter().map(step_json).collect::<Vec<_>>(),
        "sessions": trail.events.iter().map(step_json).collect::<Vec<_>>(),
        "router": crate::portmap::status(d),
    });
    Ok(crate::names::with_shown(d, &c, v))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn made(at: Option<u64>, used: usize, cancelled: bool) -> Made {
        let addr: SocketAddr = "127.0.0.1:7171".parse().unwrap();
        let invitation =
            Invitation::new([1; 32], [2; 32], EndpointAddr::new(CarrierKind::Udp, addr));
        Made {
            record: account::InvitationRecord {
                met: None,
                node: [3; 16],
                entry: [4; 32],
                invitation: invitation.to_record(),
                regard: Regard::default(),
                cancelled,
                used,
            },
            invitation,
            at,
        }
    }

    #[test]
    fn an_invitation_ends_when_used_cancelled_or_old() {
        let now = now_ms();
        assert!(made(Some(now), 0, false).outstanding());
        assert!(
            made(None, 0, false).outstanding(),
            "no clock is no reason to end it"
        );
        assert!(!made(Some(now), 1, false).outstanding());
        assert!(!made(Some(now), 0, true).outstanding());
        let old = now - INVITATION_LASTS - 1000;
        assert!(made(Some(old), 0, false).expired());
        assert!(!made(Some(old), 0, false).outstanding());
    }
}
