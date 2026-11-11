//! Groups (`profiles.md#group`): a space with one owner, whoever made it,
//! and any number of members, each offered it through a relationship they
//! already have, and a conversation everyone in it reads.
//!
//! A group only grows. Its owner and its admins add people; nobody is taken
//! out of it, and no role is lowered. Taking someone out is the owner
//! succeeding the group with one that leaves them out, which this software
//! cannot write or follow yet, so `group-remove` says so and does nothing.
//!
//! Leaving is a member's own statement (`spaces.md#members-and-roles`). It
//! changes nothing about what is valid. Whoever left stops using the group
//! and ends the tokens they gave out in it; the others see that they left,
//! send them nothing more, and whoever writes next starts a new key that
//! is not wrapped for them.
//!
//! A member who is not a trusted contact of another reaches them through a
//! member connected to both, who passes on what they write, or through their
//! hosts (`spaces.md#holding-a-space`): being in a group opens no connection.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cardinal_blob::BlobRef;
use cardinal_link::Priority;
use cardinal_space::account::ContactRecord;
use cardinal_space::group::{self, Member};
use cardinal_space::{relationship, Space, SpaceId, SpaceOp};
use serde_json::{json, Value as Json};

use crate::contacts::{self, identity};
use crate::core::now_ms;
use crate::daemon::Daemon;

/// How far apart one offered group is fetched from whoever offered it.
const FETCH_GAP: Duration = Duration::from_secs(10);

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// A group this device holds, by its id, a prefix of it, or its name.
struct Found {
    id: SpaceId,
    name: String,
    joined: bool,
}

fn find(d: &Daemon, group: &str) -> anyhow::Result<Found> {
    let me = identity(d)?;
    let core = d.core();
    let mut found: Vec<Found> = Vec::new();
    for (id, h) in &core.spaces {
        let Some(sp) = h.space.as_ref() else {
            continue;
        };
        // A group this person left is not theirs to find, until someone
        // adds them again.
        if sp.profile() != group::GROUP || sp.has_left(&me) {
            continue;
        }
        let name = group::name(sp);
        let by_id = group.len() >= 8 && hex::encode(id).starts_with(&group.to_ascii_lowercase());
        if by_id || name == group {
            found.push(Found {
                id: *id,
                name,
                joined: group::joined(sp, &me),
            });
        }
    }
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => anyhow::bail!("there is no group {group}"),
        _ => anyhow::bail!("more than one group is called {group}: use its id"),
    }
}

/// A joined group, to write in.
fn joined(d: &Daemon, group: &str) -> anyhow::Result<Found> {
    let g = find(d, group)?;
    anyhow::ensure!(g.joined, "you have not joined {}", g.name);
    Ok(g)
}

/// Whether this person may add to a group and change what it is called: its
/// owner, and its admins.
fn may_manage(sp: &Space, me: &[u8; 32]) -> bool {
    group::role_of(sp, me).is_some_and(|r| r >= group::ADMIN)
}

/// Contacts by what this person calls them; refused ones are not offered
/// anything.
fn people(d: &Daemon, who: &[String]) -> anyhow::Result<Vec<ContactRecord>> {
    who.iter().map(|w| contacts::listed(d, w)).collect()
}

/// Puts an offer of a group in the relationship space with each of `to`.
fn offer(d: &Arc<Daemon>, id: &SpaceId, name: &str, to: &[ContactRecord]) -> anyhow::Result<()> {
    for c in to {
        let op = group::create_offer(id, name, 4);
        d.write_and_push(&c.space, vec![op])?;
    }
    Ok(())
}

/// Makes a group of this person and `who`, and offers it to each of them.
pub fn create(d: &Arc<Daemon>, name: &str, who: &[String]) -> anyhow::Result<Json> {
    let name = name.trim();
    anyhow::ensure!(!name.is_empty(), "a group needs a name");
    let theirs = people(d, who)?;
    let me_as = d.config().name.clone();
    let members: Vec<([u8; 32], String)> = theirs
        .iter()
        .map(|c| (c.identity, c.petname.clone()))
        .collect();
    let id = d.core().create_group(name, &me_as, &members)?;
    let genesis = {
        let core = d.core();
        let open = core.spaces.get(&id).and_then(|h| h.space.as_ref());
        open.and_then(|s| s.sealed(&id).map(|s| s.encode()))
    };
    offer(d, &id, name, &theirs)?;
    if let Some(g) = genesis {
        d.push(&id, vec![g]);
    }
    d.bump();
    Ok(json!({"group": hex::encode(id), "name": name}))
}

/// Adds contacts to a group, with the names the others will see, and offers
/// it to them.
pub fn add(
    d: &Arc<Daemon>,
    group: &str,
    who: &[String],
    shown: Option<&str>,
) -> anyhow::Result<Json> {
    let g = joined(d, group)?;
    let me = identity(d)?;
    {
        let core = d.core();
        let sp = core.spaces.get(&g.id).and_then(|h| h.space.as_ref());
        let sp = sp.ok_or_else(|| anyhow::anyhow!("that group is not open yet"))?;
        anyhow::ensure!(
            may_manage(sp, &me),
            "only an admin of {} can add people",
            g.name
        );
    }
    let theirs = people(d, who)?;
    let members: Vec<([u8; 32], String)> = theirs
        .iter()
        .map(|c| {
            let name = shown.filter(|_| theirs.len() == 1).unwrap_or(&c.petname);
            (c.identity, name.to_owned())
        })
        .collect();
    let bytes = d.core().add_to_group(&g.id, &members)?;
    d.push(&g.id, vec![bytes]);
    offer(d, &g.id, &g.name, &theirs)?;
    d.bump();
    Ok(json!({}))
}

/// The member of a group someone means: a contact by their petname, or
/// anyone by the name the group shows for them.
fn member_named(contacts: &[ContactRecord], sp: &Space, who: &str) -> anyhow::Result<[u8; 32]> {
    let in_it = |id: &[u8; 32]| sp.validity().members.iter().any(|m| m.identity == *id);
    if let Some(c) = contacts
        .iter()
        .find(|c| c.petname == who && in_it(&c.identity))
    {
        return Ok(c.identity);
    }
    let found: Vec<Member> = group::members(sp)
        .into_iter()
        .filter(|m| m.name.as_deref() == Some(who))
        .collect();
    match found.as_slice() {
        [m] => Ok(m.identity),
        [] => anyhow::bail!("nobody in it is called {who}"),
        _ => anyhow::bail!("more than one in it is called {who}"),
    }
}

/// Taking someone out of a group. Nothing in a space removes a member: the
/// owner succeeds the group with one that leaves them out, and the others'
/// devices follow (`profiles.md#group`). This software cannot write or
/// follow a succession yet, so it says so, and changes nothing.
pub fn remove(d: &Arc<Daemon>, group: &str, who: &str) -> anyhow::Result<Json> {
    let g = joined(d, group)?;
    let me = identity(d)?;
    let (them, owner) = {
        let core = d.core();
        let contacts = core.contacts();
        let sp = core.spaces.get(&g.id).and_then(|h| h.space.as_ref());
        let sp = sp.ok_or_else(|| anyhow::anyhow!("that group is not open yet"))?;
        (member_named(&contacts, sp, who)?, sp.owner())
    };
    anyhow::ensure!(them != me, "to leave {}, leave it", g.name);
    anyhow::ensure!(
        owner == Some(me),
        "only the owner of {} can take someone out of it",
        g.name
    );
    anyhow::bail!(
        "{who} cannot be taken out of {} yet: that is done by replacing the group with one \
         that leaves them out, which this version cannot do",
        g.name
    )
}

/// Leaves a group: says so in it, and ends the tokens this person gave out
/// there. From then on this device does nothing with the group, and the
/// others send it nothing more.
pub fn leave(d: &Arc<Daemon>, group: &str) -> anyhow::Result<Json> {
    let g = joined(d, group)?;
    let me = identity(d)?;
    {
        let core = d.core();
        let sp = core.spaces.get(&g.id).and_then(|h| h.space.as_ref());
        let sp = sp.ok_or_else(|| anyhow::anyhow!("that group is not open yet"))?;
        anyhow::ensure!(sp.role_of(&me).is_some(), "you are not in {}", g.name);
    }
    d.write_and_push(&g.id, vec![SpaceOp::leave()])?;
    crate::mailbox::revoke_left(d, &g.id);
    d.bump();
    Ok(json!({}))
}

/// Joins a group offered to this person: its first entry of theirs, where
/// to reach them if they have a host, or a read marker if not.
pub async fn join(d: &Arc<Daemon>, group: &str) -> anyhow::Result<Json> {
    let g = find(d, group)?;
    if g.joined {
        return Ok(json!({}));
    }
    let me = identity(d)?;
    let hosted = !d.core().mailboxes().is_empty();
    if hosted {
        crate::mailbox::write_reach(d, &g.id).await?;
    }
    let joined_now = {
        let core = d.core();
        let sp = core.spaces.get(&g.id).and_then(|h| h.space.as_ref());
        sp.is_some_and(|sp| group::joined(sp, &me))
    };
    if !joined_now {
        let op = {
            let core = d.core();
            let sp = core.spaces.get(&g.id).and_then(|h| h.space.as_ref());
            let sp = sp.ok_or_else(|| anyhow::anyhow!("that group is not open yet"))?;
            let c = relationship::conversation(sp)
                .ok_or_else(|| anyhow::anyhow!("that group has no conversation"))?;
            let last = relationship::messages(sp).last().map_or(c, |m| m.id);
            relationship::create_read_marker(c, last)
        };
        d.write_and_push(&g.id, vec![op])?;
    }
    d.bump();
    Ok(json!({"group": hex::encode(g.id), "name": g.name}))
}

/// Says no to a group offered to this person. Nothing is written in it, and
/// it is not offered again.
pub fn decline(d: &Arc<Daemon>, group: &str) -> anyhow::Result<Json> {
    let g = find(d, group)?;
    anyhow::ensure!(!g.joined, "you are in {}: leave it instead", g.name);
    let account = d
        .core()
        .account_id()
        .ok_or_else(|| anyhow::anyhow!("the account space is not here yet"))?;
    let op = cardinal_space::account::create_declined(&g.id, &g.name);
    d.write_and_push(&account, vec![op])?;
    d.bump();
    Ok(json!({}))
}

/// What this person calls a member: themselves, a contact's petname, or the
/// name the group shows.
fn name_of(
    me: &[u8; 32],
    contacts: &[ContactRecord],
    members: &[Member],
    who: &[u8; 32],
) -> String {
    if who == me {
        return "You".into();
    }
    if let Some(c) = contacts.iter().find(|c| c.identity == *who && !c.refused) {
        return c.petname.clone();
    }
    let shown = members
        .iter()
        .find(|m| m.identity == *who)
        .and_then(|m| m.name.clone());
    shown.unwrap_or_else(|| "Someone".into())
}

/// The groups this person is in, the most recent first, and those offered.
pub fn list(d: &Daemon) -> Json {
    let Ok(me) = identity(d) else {
        return json!({"groups": [], "offers": []});
    };
    let declined = d.core().declined();
    let contacts = d.core().contacts();
    let mut groups: Vec<(Option<u64>, Json)> = Vec::new();
    let mut offered: Vec<Json> = Vec::new();
    let held: Vec<SpaceId> = {
        let core = d.core();
        let groups = core.spaces.iter().filter(|(_, h)| {
            h.space
                .as_ref()
                .is_some_and(|s| s.profile() == group::GROUP)
        });
        groups.map(|(id, _)| *id).collect()
    };
    for id in held {
        let core = d.core();
        let Some(sp) = core.spaces.get(&id).and_then(|h| h.space.as_ref()) else {
            continue;
        };
        if sp.has_left(&me) {
            continue;
        }
        let members = group::members(sp);
        let in_it = members.iter().any(|m| m.identity == me);
        let name = group::name(sp);
        if !group::joined(sp, &me) {
            if in_it && !declined.contains(&id) {
                let from = sp.creator();
                offered.push(json!({
                    "group": hex::encode(id),
                    "name": name,
                    "from": name_of(&me, &contacts, &members, &from),
                    "members": members.len(),
                }));
            }
            continue;
        }
        if !in_it {
            continue;
        }
        let said = relationship::messages(sp);
        let read = relationship::read_by(sp, &me, &said);
        let unread = said
            .iter()
            .zip(read)
            .filter(|(m, read)| m.author != me && !read)
            .count();
        let last = said.last().cloned();
        let admin = may_manage(sp, &me);
        let introductions = group::introductions(sp);
        drop(core);
        let when = last.as_ref().and_then(|m| m.time).map(|t| t.min(now_ms()));
        groups.push((
            when,
            json!({
                "group": hex::encode(id),
                "name": name,
                "members": members.len(),
                "admin": admin,
                "introductions": introductions,
                "unread": unread,
                "last": last.map(|m| json!({
                    "mine": m.author == me,
                    "from": name_of(&me, &contacts, &members, &m.author),
                    "text": m.text,
                    "time": m.time,
                })),
            }),
        ));
    }
    groups.sort_by_key(|(when, _)| std::cmp::Reverse(*when));
    let groups: Vec<Json> = groups.into_iter().map(|(_, g)| g).collect();
    json!({"groups": groups, "offers": offered})
}

/// Who is in a group, as the others see them.
pub fn members(d: &Daemon, group: &str) -> anyhow::Result<Json> {
    let g = find(d, group)?;
    let me = identity(d)?;
    let core = d.core();
    let sp = core.spaces.get(&g.id).and_then(|h| h.space.as_ref());
    let sp = sp.ok_or_else(|| anyhow::anyhow!("that group is not open yet"))?;
    let members = group::members(sp);
    let contacts = core.contacts();
    let out: Vec<Json> = members
        .iter()
        .map(|m| {
            let contact = contacts
                .iter()
                .any(|c| c.identity == m.identity && !c.refused);
            json!({
                "name": name_of(&me, &contacts, &members, &m.identity),
                "shown": m.name,
                "id": hex::encode(&m.identity[..8]),
                "you": m.identity == me,
                "contact": contact,
                "role": match m.role {
                    group::OWNER => "owner",
                    group::ADMIN => "admin",
                    group::READER => "reader",
                    _ => "member",
                },
                "introduce": m.introduce,
                "left": m.left,
            })
        })
        .collect();
    Ok(json!({"group": hex::encode(g.id), "name": g.name, "members": out}))
}

/// This person turned to a group: its members who are trusted contacts are
/// in use, and so looked for (`sync.md#neighbours`).
pub(crate) fn use_members(d: &Daemon, id: &SpaceId) {
    let core = d.core();
    let Some(sp) = core.spaces.get(id).and_then(|h| h.space.as_ref()) else {
        return;
    };
    let contacts = core.contacts();
    for m in sp.present() {
        if contacts.iter().any(|c| c.identity == m && c.connects()) {
            d.rendezvous.use_contact(&m);
        }
    }
}

/// Writes a message to a group.
pub async fn say(
    d: &Arc<Daemon>,
    group: &str,
    text: &str,
    reply_to: Option<&str>,
    attach: &[String],
) -> anyhow::Result<Json> {
    let g = joined(d, group)?;
    use_members(d, &g.id);
    let to = match reply_to {
        Some(id) => Some(message_in(d, &g.id, id)?.id),
        None => None,
    };
    let attachments = contacts::encode_attachments(d, &g.id, attach).await?;
    let conversation = {
        let core = d.core();
        let sp = core.spaces.get(&g.id).and_then(|h| h.space.as_ref());
        sp.and_then(relationship::conversation)
    };
    let conversation = conversation.ok_or_else(|| anyhow::anyhow!("that group is not open yet"))?;
    let mut ops = vec![relationship::create_with(
        conversation,
        text,
        to,
        &attachments,
    )];
    ops.extend(relationship::shared_files(&attachments, Some(now_ms())));
    d.write_and_push(&g.id, ops)?;
    Ok(json!({}))
}

fn message_in(d: &Daemon, space: &SpaceId, id: &str) -> anyhow::Result<relationship::Message> {
    let id = hex::decode(id).ok();
    let id = id.and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok());
    let id = id.ok_or_else(|| anyhow::anyhow!("that is not a message"))?;
    let core = d.core();
    let sp = core.spaces.get(space).and_then(|h| h.space.as_ref());
    let sp = sp.ok_or_else(|| anyhow::anyhow!("that group is not open yet"))?;
    let found = relationship::messages(sp).into_iter().find(|m| m.id == id);
    found.ok_or_else(|| anyhow::anyhow!("there is no such message"))
}

/// The conversation of a group, oldest first, with who said each thing and
/// how many of the others have read what this person said.
pub fn messages(d: &Daemon, group: &str) -> anyhow::Result<Json> {
    let g = find(d, group)?;
    use_members(d, &g.id);
    let me = identity(d)?;
    let core = d.core();
    let sp = core.spaces.get(&g.id).and_then(|h| h.space.as_ref());
    let sp = sp.ok_or_else(|| anyhow::anyhow!("that group is not open yet"))?;
    let all = relationship::messages(sp);
    let members = group::members(sp);
    // someone who left reads nothing more, and is not waited for
    let others: Vec<[u8; 32]> = members
        .iter()
        .filter(|m| m.identity != me && !m.left)
        .map(|m| m.identity)
        .collect();
    let mut read_by: HashMap<[u8; 32], Vec<bool>> = HashMap::new();
    for m in &others {
        read_by.insert(*m, relationship::read_by(sp, m, &all));
    }
    let contacts = core.contacts();
    let said: Vec<Json> = all
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let mine = m.author == me;
            let read = others.iter().filter(|o| read_by[*o][i]).count();
            json!({
                "id": hex::encode(m.id),
                "mine": mine,
                "from": name_of(&me, &contacts, &members, &m.author),
                "text": m.text,
                "time": m.time,
                "state": mine.then_some(if read == others.len() && !others.is_empty() { "read" } else { "sent" }),
                "read_by": mine.then_some(read),
                "reply_to": m.reply_to.map(hex::encode),
                "attachments": m.attachments.iter().map(|a| json!({
                    "name": a.name,
                    "type": a.media_type,
                    "size": BlobRef::from_record(&a.blob).map(|b| b.size).ok(),
                })).collect::<Vec<_>>(),
                "edited": m.edited,
                "reactions": contacts::reactions_of(m, Some(me)),
            })
        })
        .collect();
    Ok(json!({"group": hex::encode(g.id), "name": g.name, "messages": said}))
}

/// Saves a file that came with a message in a group, fetching it from the
/// members in touch: its sender if they are, or anyone else who has it.
pub async fn save_attachment(
    d: &Arc<Daemon>,
    group: &str,
    id: &str,
    index: usize,
    to: &str,
) -> anyhow::Result<Json> {
    let g = find(d, group)?;
    let m = message_in(d, &g.id, id)?;
    let a = m.attachments.get(index);
    let a = a.ok_or_else(|| anyhow::anyhow!("that message has no such attachment"))?;
    let blob = BlobRef::from_record(&a.blob)
        .map_err(|_| anyhow::anyhow!("that attachment cannot be read"))?;
    let members: Vec<[u8; 32]> = {
        let core = d.core();
        let sp = core.spaces.get(&g.id).and_then(|h| h.space.as_ref());
        sp.map(|sp| sp.present()).unwrap_or_default()
    };
    let in_touch = d.people_in_touch();
    let mut from: Vec<[u8; 32]> = members
        .into_iter()
        .filter(|w| in_touch.contains(w))
        .collect();
    // The sender first.
    from.sort_by_key(|w| *w != m.author);
    let to = std::path::PathBuf::from(to);
    let mut last = anyhow::anyhow!("nobody who has it is in touch right now");
    for who in from.into_iter().map(Some).chain([None]) {
        let (d, written) = (d.clone(), to.clone());
        let got = tokio::task::spawn_blocking(move || -> anyhow::Result<u64> {
            let fetch = match who {
                Some(w) => crate::fetch::Fetcher::from_contact(&d, Priority::Interactive, w),
                None => crate::fetch::Fetcher::new(&d, Priority::Interactive),
            };
            let mut reader = cardinal_blob::BlobReader::new(&*d.store, &fetch, blob);
            contacts::write_new(&written, |out| contacts::write_out(&mut reader, out))
        })
        .await?;
        match got {
            Ok(size) => return Ok(json!({"path": to, "size": size})),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// A message of this person's own in a group: only that can be changed or
/// taken back.
fn own_message(d: &Daemon, space: &SpaceId, id: &str) -> anyhow::Result<relationship::Message> {
    let m = message_in(d, space, id)?;
    anyhow::ensure!(
        m.author == identity(d)?,
        "only what you wrote can be changed"
    );
    Ok(m)
}

/// Changes what a message of this person's in a group says.
pub fn edit_message(d: &Arc<Daemon>, group: &str, id: &str, text: &str) -> anyhow::Result<Json> {
    let g = joined(d, group)?;
    let m = own_message(d, &g.id, id)?;
    anyhow::ensure!(!text.trim().is_empty(), "a message cannot be empty");
    d.write_and_push(&g.id, vec![relationship::edit_message(m.id, text)])?;
    Ok(json!({}))
}

/// Takes back a message of this person's in a group.
pub fn delete_message(d: &Arc<Daemon>, group: &str, id: &str) -> anyhow::Result<Json> {
    let g = joined(d, group)?;
    let m = own_message(d, &g.id, id)?;
    d.write_and_push(&g.id, vec![SpaceOp::delete(m.id)])?;
    Ok(json!({}))
}

/// Reacts to a message in a group, replacing this person's reaction, or
/// taking it away with nothing.
pub fn react(d: &Arc<Daemon>, group: &str, id: &str, text: &str) -> anyhow::Result<Json> {
    let g = joined(d, group)?;
    let m = message_in(d, &g.id, id)?;
    let text = text.trim();
    anyhow::ensure!(
        text.chars().count() <= 16,
        "that is too long for a reaction"
    );
    let me = identity(d)?;
    let mine: Vec<&relationship::Reaction> =
        m.reactions.iter().filter(|r| r.author == me).collect();
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
    if !ops.is_empty() {
        d.write_and_push(&g.id, ops)?;
    }
    Ok(json!({}))
}

/// Marks a group's conversation read up to its last message from anyone else.
pub fn mark_read(d: &Arc<Daemon>, group: &str) -> anyhow::Result<Json> {
    let g = joined(d, group)?;
    let me = identity(d)?;
    let op = {
        let core = d.core();
        let sp = core.spaces.get(&g.id).and_then(|h| h.space.as_ref());
        let sp = sp.ok_or_else(|| anyhow::anyhow!("that group is not open yet"))?;
        let all = relationship::messages(sp);
        let read = relationship::read_by(sp, &me, &all);
        let new = all
            .iter()
            .zip(&read)
            .any(|(m, read)| m.author != me && !read);
        let theirs = all.iter().rposition(|m| m.author != me);
        match theirs {
            Some(at) if new => {
                let last = all[at].id;
                match relationship::read_marker(sp, &me) {
                    Some(marker) => Some(relationship::set_read_marker(marker, last)),
                    None => relationship::conversation(sp)
                        .map(|c| relationship::create_read_marker(c, last)),
                }
            }
            _ => None,
        }
    };
    if let Some(op) = op {
        d.write_and_push(&g.id, vec![op])?;
    }
    Ok(json!({}))
}

/// Renames a group, or says whether its members are introduced through it.
pub fn set(
    d: &Arc<Daemon>,
    group: &str,
    name: Option<&str>,
    introductions: Option<bool>,
) -> anyhow::Result<Json> {
    let g = joined(d, group)?;
    let me = identity(d)?;
    let ops = {
        let core = d.core();
        let sp = core.spaces.get(&g.id).and_then(|h| h.space.as_ref());
        let sp = sp.ok_or_else(|| anyhow::anyhow!("that group is not open yet"))?;
        anyhow::ensure!(
            may_manage(sp, &me),
            "only an admin of {} can change it",
            g.name
        );
        let c = relationship::conversation(sp)
            .ok_or_else(|| anyhow::anyhow!("that group has no conversation"))?;
        let mut ops = Vec::new();
        if let Some(n) = name.map(str::trim).filter(|n| !n.is_empty()) {
            ops.push(group::rename(c, n));
        }
        if let Some(on) = introductions {
            ops.push(group::set_introductions(c, on));
        }
        ops
    };
    if !ops.is_empty() {
        d.write_and_push(&g.id, ops)?;
    }
    d.bump();
    Ok(json!({}))
}

/// Changes what the others see a member called, or whether they are
/// introduced through the group.
pub fn set_member(
    d: &Arc<Daemon>,
    group: &str,
    who: &str,
    shown: Option<&str>,
    introduce: Option<bool>,
) -> anyhow::Result<Json> {
    let g = joined(d, group)?;
    let me = identity(d)?;
    let ops = {
        let core = d.core();
        let sp = core.spaces.get(&g.id).and_then(|h| h.space.as_ref());
        let sp = sp.ok_or_else(|| anyhow::anyhow!("that group is not open yet"))?;
        anyhow::ensure!(
            may_manage(sp, &me),
            "only an admin of {} can change that",
            g.name
        );
        let them = member_named(&core.contacts(), sp, who)?;
        let node = group::members(sp)
            .into_iter()
            .find(|m| m.identity == them)
            .and_then(|m| m.node);
        let mut ops = Vec::new();
        match node {
            Some(node) => {
                if let Some(n) = shown {
                    ops.push(group::set_member_name(node, n));
                }
                if let Some(i) = introduce {
                    ops.push(group::set_member_introduce(node, i));
                }
            }
            None => ops.push(group::create_member(
                &them,
                shown.unwrap_or(who),
                introduce.unwrap_or(true),
            )),
        }
        ops
    };
    d.write_and_push(&g.id, ops)?;
    d.bump();
    Ok(json!({}))
}

/// A group this person is in, by id or name, with its name: for a call.
pub(crate) fn joined_group(d: &Daemon, group: &str) -> anyhow::Result<(SpaceId, String)> {
    let g = joined(d, group)?;
    Ok((g.id, g.name))
}

/// The name of a group this person joined that `who` is in, if `space` is
/// one: what a call in it is called.
pub(crate) fn shared_group(d: &Daemon, space: &SpaceId, who: &[u8; 32]) -> Option<String> {
    let me = identity(d).ok()?;
    let core = d.core();
    let sp = core.spaces.get(space)?.space.as_ref()?;
    let ours = sp.profile() == group::GROUP
        && group::joined(sp, &me)
        && sp.role_of(who).is_some()
        && !sp.has_left(who);
    ours.then(|| group::name(sp))
}

/// The sessions with the devices of a group's members: the other members',
/// and this person's own other devices.
pub(crate) fn member_sessions(d: &Daemon, space: &SpaceId) -> Vec<cardinal_link::Session> {
    let members: Vec<[u8; 32]> = {
        let core = d.core();
        let me = core.identity.as_ref().map(|i| i.id());
        let sp = core.spaces.get(space).and_then(|h| h.space.as_ref());
        sp.map(|sp| {
            let present = sp.present().into_iter();
            present.filter(|m| Some(*m) != me).collect()
        })
        .unwrap_or_default()
    };
    if members.is_empty() {
        return Vec::new();
    }
    let mut out = d.own_sessions();
    for (who, s) in d.contacts_in_touch() {
        if members.contains(&who) {
            out.push(s);
        }
    }
    out
}

/// Whether a group is one this person has not joined: nothing of theirs is
/// written in it until they do (`spaces.md#holding-a-space`).
pub fn not_joined(d: &Daemon, space: &SpaceId) -> bool {
    let core = d.core();
    let me = core.identity.as_ref().map(|i| i.id());
    let sp = core.spaces.get(space).and_then(|h| h.space.as_ref());
    match (sp, me) {
        (Some(sp), Some(me)) => sp.profile() == group::GROUP && !group::joined(sp, &me),
        _ => false,
    }
}

/// Fetches each group offered to this person that is not here yet from
/// whoever offered it, whenever something changes: the offer and the group
/// arrive separately, in either order.
pub fn start(d: Arc<Daemon>) {
    let fetched: Arc<Mutex<HashMap<SpaceId, Instant>>> = Default::default();
    tokio::spawn(async move {
        let mut changed = d.changed.subscribe();
        loop {
            if changed.changed().await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
            let wanted: Vec<(SpaceId, [u8; 32])> = {
                let core = d.core();
                let contacts = core.contacts();
                let mut v = Vec::new();
                for c in contacts.iter().filter(|c| !c.refused) {
                    for o in core.offers_from(&c.identity) {
                        let open = core.spaces.get(&o.space).is_some_and(|h| h.space.is_some());
                        if !open {
                            v.push((o.space, c.identity));
                        }
                    }
                }
                v
            };
            for (space, from) in wanted {
                {
                    let mut f = lock(&fetched);
                    if f.get(&space).is_some_and(|t| t.elapsed() < FETCH_GAP) {
                        continue;
                    }
                    f.insert(space, Instant::now());
                }
                for s in d.sessions_of(&from) {
                    if let Err(e) = crate::net::reconcile(&d, &s, space).await {
                        tracing::debug!("fetching an offered group: {e:#}");
                    }
                }
            }
        }
    });
}
