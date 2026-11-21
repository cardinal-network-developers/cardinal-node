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
use crate::core::{now_ms, Core};
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
    find_among(d, group, false)
}

/// [`find`], or with `in_it` among the groups this person is in alone:
/// what they write goes to a group they joined, whatever they have been
/// offered under the same name since.
fn find_among(d: &Daemon, group: &str, in_it: bool) -> anyhow::Result<Found> {
    let me = identity(d)?;
    let core = d.core();
    let mut all: Vec<Found> = Vec::new();
    for (id, h) in &core.spaces {
        let Some(sp) = h.space.as_ref() else {
            continue;
        };
        // A group this person left is not theirs to find, until someone
        // adds them again.
        if sp.profile() != group::GROUP || sp.has_left(&me) {
            continue;
        }
        all.push(Found {
            id: *id,
            name: group::name(sp),
            joined: core.is_joined(id),
        });
    }
    all.retain(|g| g.joined || !in_it);
    pick(all, group, &core.declined())
}

/// Which of the groups held is meant by `asked`: its id, the start of its
/// id in eight hex digits or more, or its name. An id is nobody's to
/// choose and a name is its admins', so a group found by its id is that
/// group, whatever another is called. By name, a group this person said no
/// to is not meant.
fn pick(all: Vec<Found>, asked: &str, declined: &[SpaceId]) -> anyhow::Result<Found> {
    let start = asked.to_ascii_lowercase();
    let by_id = |g: &Found| asked.len() >= 8 && hex::encode(g.id).starts_with(&start);
    let (mut ids, named): (Vec<Found>, Vec<Found>) = all.into_iter().partition(by_id);
    match ids.len() {
        0 => {}
        1 => return Ok(ids.remove(0)),
        _ => anyhow::bail!("more than one group's id starts with {asked}: give more of it"),
    }
    let called = |g: &Found| g.name == asked && !declined.contains(&g.id);
    let mut found: Vec<Found> = named.into_iter().filter(called).collect();
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => anyhow::bail!("there is no group {asked}"),
        _ => anyhow::bail!("more than one group is called {asked}: use its id"),
    }
}

/// A joined group, to write in.
fn joined(d: &Daemon, group: &str) -> anyhow::Result<Found> {
    match find_among(d, group, true) {
        Ok(g) => Ok(g),
        // say which it is: not there at all, or there and not joined
        Err(none) => match find(d, group) {
            Ok(g) => anyhow::bail!("you have not joined {}", g.name),
            Err(_) => Err(none),
        },
    }
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

/// The name the others in a group are shown for a contact, unless the adder
/// says another: the one they suggest for themselves, since a petname is
/// this person's own (`profiles.md#account`). A contact recorded before
/// that was kept is shown by the petname, which began as the same.
fn offered_as(c: &ContactRecord) -> &str {
    c.suggested.as_deref().unwrap_or(&c.petname)
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
    let me_as = crate::names::my_name(d);
    let members: Vec<([u8; 32], String)> = theirs
        .iter()
        .map(|c| (c.identity, offered_as(c).to_owned()))
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
            let name = shown.filter(|_| theirs.len() == 1).unwrap_or(offered_as(c));
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

/// Leaves a group: says so in it, and in the same entry sets this person's
/// reach node to an empty list, so that the group stops naming their hosts
/// to whoever is in it or comes to it later
/// (`spaces.md#members-and-roles`). It ends the tokens they gave out
/// there. The empty list is all that is left of what they said about
/// their hosts there: an offer of the group asks afresh. From then on this
/// device does nothing with the group, and the others send it nothing
/// more.
pub fn leave(d: &Arc<Daemon>, group: &str) -> anyhow::Result<Json> {
    let g = joined(d, group)?;
    let me = identity(d)?;
    {
        let core = d.core();
        let sp = core.spaces.get(&g.id).and_then(|h| h.space.as_ref());
        let sp = sp.ok_or_else(|| anyhow::anyhow!("that group is not open yet"))?;
        anyhow::ensure!(sp.role_of(&me).is_some(), "you are not in {}", g.name);
    }
    d.write_and_push(&g.id, relationship::leave_ops(&me))?;
    // The account's node for it goes, and with it any "no hosts here" or
    // "not this host here": an offer made again asks afresh (D75).
    let gone = {
        let core = d.core();
        let acc = core
            .account()
            .and_then(|a| a.space.as_ref().map(|s| (a.id, s)));
        acc.map(|(id, st)| {
            let nodes = cardinal_space::account::spaces(st.state()).into_iter();
            let ops: Vec<_> = nodes
                .filter(|r| r.space == g.id && !r.declined)
                .map(|r| SpaceOp::delete(r.node))
                .collect();
            (id, ops)
        })
    };
    if let Some((account, ops)) = gone.filter(|(_, ops)| !ops.is_empty()) {
        d.write_and_push(&account, ops)?;
    }
    crate::mailbox::revoke_left(d, &g.id);
    d.bump();
    Ok(json!({}))
}

/// What is said of this person's reach node in a group, for a client to
/// show: the members by the names this person sees.
fn telling_json(core: &Core, id: &SpaceId, me: &[u8; 32]) -> Json {
    let t = core.telling(id);
    let contacts = core.contacts();
    let open = core.spaces.get(id).and_then(|h| h.space.as_ref());
    let members = open.map(group::members).unwrap_or_default();
    let names = |who: &[[u8; 32]]| -> Vec<String> {
        who.iter()
            .map(|m| name_of(me, &contacts, &members, m))
            .collect()
    };
    json!({
        "shared": t.shared,
        "ask": t.ask(),
        "who": names(&t.who),
        "what": t.what,
        "added": names(t.added()),
        "public": t.public,
        "waiting": t.waiting,
        "said_no": t.said_no,
        "set": t.set,
    })
}

/// The groups where someone this person refuses still reads where their
/// hosts are, for a client to ask about as part of refusing: each group's
/// id and name, and what is seen there.
pub fn naming_hosts_to(core: &Core, who: &[u8; 32]) -> Json {
    let groups = core.groups_naming_hosts_to(who).into_iter();
    let all: Vec<Json> = groups
        .filter_map(|id| {
            let sp = core.spaces.get(&id)?.space.as_ref()?;
            let name = group::name(sp);
            Some(json!({"group": hex::encode(id), "name": name, "what": core.telling(&id).what}))
        })
        .collect();
    json!(all)
}

/// What the person has to be asked, in words.
fn question(reach: &Json, name: &str) -> String {
    let list = |v: &Json| -> Vec<String> {
        let all = v.as_array().into_iter().flatten();
        all.filter_map(|x| x.as_str().map(str::to_owned)).collect()
    };
    let who = list(&reach["who"]);
    let what = list(&reach["what"]).join(", ");
    // A public space is read by anyone at all, whoever is in it now, and
    // the question says so.
    if reach["public"] == true {
        return format!(
            "{name} is public: anyone at all can read it, and would learn where your host is \
             ({what}), now and whoever joins it later. Say whether to share it there: with \
             it the members can leave you messages while you are away, and without it they reach you only through someone \
             in touch with both"
        );
    }
    format!(
        "{} in {name} {} not a contact of yours, and would learn where your host is ({what}), \
         as would anyone added later. Say whether to share it there: with it they can leave you messages while you \
         are away, and without it they reach you only through someone in touch with both",
        who.join(", "),
        if who.len() == 1 { "is" } else { "are" },
    )
}

/// Joins a group offered to this person with a first entry of theirs there
/// (`profiles.md#group`): their reach node set to their hosts, or to an
/// empty list where they do not want every member to have them, which the
/// account records as their no (D75). With no host to name, and no no,
/// the list is left unset and the entry is empty. Where someone in the
/// group is not a contact of theirs, and they have a host, that is theirs
/// to say: `reach` is their answer, and without it nothing is written.
/// Anywhere, among contacts too, `reach` is their answer if they give one.
/// `shared` in what comes back says whether the list names a host.
pub async fn join(d: &Arc<Daemon>, group: &str, reach: Option<bool>) -> anyhow::Result<Json> {
    let g = find(d, group)?;
    if g.joined {
        return Ok(json!({}));
    }
    let me = identity(d)?;
    let (t, telling) = {
        let core = d.core();
        (core.telling(&g.id), telling_json(&core, &g.id, &me))
    };
    anyhow::ensure!(
        !t.ask() || reach.is_some(),
        "{}",
        question(&telling, &g.name)
    );
    let share = t.joins_sharing(reach);
    // A no is the person's to say: with no host and nothing said, there is
    // nothing to say, and joining leaves the list unset (D75).
    let no = !share && (t.hosted || reach == Some(false));
    let shared = match share || no {
        true => crate::mailbox::say_reach(d, &g.id, share).await?,
        false => false,
    };
    if !d.core().is_joined(&g.id) {
        // With nothing to say in the group, nothing is written there: the
        // joining is kept in the account, as a node for the space (D75).
        let account = d
            .core()
            .account_id()
            .ok_or_else(|| anyhow::anyhow!("the account space is not here yet"))?;
        let op = cardinal_space::account::create_space(&g.id, &g.name);
        d.write_and_push(&account, vec![op])?;
    }
    // A yes with a host that could not be reached for a token is kept on
    // this device, against the list as it is, and finished later.
    let waiting = share && !shared && t.hosted;
    if waiting {
        d.core().keep_yes(&g.id);
    }
    d.bump();
    let (group, name) = (hex::encode(g.id), g.name);
    Ok(json!({"group": group, "name": name, "shared": shared, "waiting": waiting}))
}

/// Says whether the members of a group have where this person's hosts are,
/// by setting their reach node there: to their hosts, or to an empty list.
/// The list is their answer, and nothing else keeps one. A person may say
/// no anywhere, among contacts too, and no device of theirs then fills it
/// in again. A yes where the hosts are named already writes nothing in
/// the group. Either way the person has now been told of everyone added
/// there, and this device notes it: `added` is empty here afterwards.
/// With no host a yes has nothing to share, and fails saying so: nothing
/// is kept for when there is one. With a host that cannot be reached now
/// the yes is kept on this device, and `waiting` says so.
pub async fn set_reach(d: &Arc<Daemon>, group: &str, share: bool) -> anyhow::Result<Json> {
    use crate::mailbox::Shared;
    let g = joined(d, group)?;
    if !share {
        // Written even where the list is empty already: a yes that
        // another of their devices keeps for later gives way to a list
        // set after it, and to nothing else.
        crate::mailbox::say_reach(d, &g.id, false).await?;
        d.core().drop_yes(&g.id);
        d.core().told_of_all(&g.id);
        d.bump();
        return Ok(json!({"shared": false, "waiting": false}));
    }
    let waiting = match crate::mailbox::share_reach(d, &g.id).await? {
        Shared::Named => false,
        Shared::Waiting => true,
        Shared::NoHost => anyhow::bail!(
            "you have no always-on device, so there is nothing to share with {}. Nothing was \
             changed, and nothing is kept for later: say so again once you have one",
            g.name
        ),
    };
    d.core().told_of_all(&g.id);
    d.bump();
    Ok(json!({"shared": !waiting, "waiting": waiting}))
}

/// The person takes one host of theirs out of a group's list (D75): the
/// account records "not this host here", so it does not name itself there
/// again until they say `share`.
pub async fn no_host(d: &Arc<Daemon>, group: &str, host: &str) -> anyhow::Result<Json> {
    let g = joined(d, group)?;
    let key = crate::mailbox::host_by_name(d, host)?;
    let named = crate::mailbox::take_out_host(d, &g.id, &key).await?;
    d.bump();
    Ok(json!({"taken_out": named}))
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
    list_of(&d.core())
}

/// [`list`], from what a device holds: each group and each offer says
/// whether the group is public, and what this person's reach node tells
/// there and whom.
pub fn list_of(core: &Core) -> Json {
    let Some(me) = core.identity.as_ref().map(|i| i.id()) else {
        return json!({"groups": [], "offers": []});
    };
    let declined = core.declined();
    let contacts = core.contacts();
    let mut groups: Vec<(Option<u64>, Json)> = Vec::new();
    let mut offered: Vec<Json> = Vec::new();
    for (id, h) in &core.spaces {
        let Some(sp) = h.space.as_ref().filter(|s| s.profile() == group::GROUP) else {
            continue;
        };
        if sp.has_left(&me) {
            continue;
        }
        let members = group::members(sp);
        let in_it = members.iter().any(|m| m.identity == me);
        // how many are in it: someone who has left is not
        let how_many = members.iter().filter(|m| !m.left).count();
        let name = group::name(sp);
        if !core.is_joined(id) {
            if in_it && !declined.contains(id) {
                let from = sp.added_by(&me).unwrap_or(sp.creator());
                offered.push(json!({
                    "group": hex::encode(id),
                    "name": name,
                    "from": name_of(&me, &contacts, &members, &from),
                    "members": how_many,
                    "public": sp.is_public(),
                    "reach": telling_json(core, id, &me),
                }));
            }
            continue;
        }
        if !in_it {
            continue;
        }
        let said = relationship::messages(sp);
        let read = core.read_here(id, &said);
        let unread = said
            .iter()
            .zip(read)
            .filter(|(m, read)| m.author != me && !read)
            .count();
        let last = said.last().cloned();
        let when = last.as_ref().and_then(|m| m.time).map(|t| t.min(now_ms()));
        let group = json!({
            "group": hex::encode(id),
            "name": name,
            "members": how_many,
            "public": sp.is_public(),
            "reach": telling_json(core, id, &me),
            "admin": may_manage(sp, &me),
            "introductions": group::introductions(sp),
            "unread": unread,
            "last": last.map(|m| json!({
                "mine": m.author == me,
                "from": name_of(&me, &contacts, &members, &m.author),
                "text": m.text,
                "time": m.time,
            })),
        });
        groups.push((when, group));
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
            let known = contacts
                .iter()
                .find(|c| c.identity == m.identity && !c.refused);
            let contact = known.is_some();
            let v = json!({
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
            });
            // a contact's as this person sees them: own name, picture
            match known {
                Some(c) => {
                    let mut v = crate::names::with_shown(d, c, v);
                    v["name"] = json!(name_of(&me, &contacts, &members, &m.identity));
                    v
                }
                None => v,
            }
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
            let picture = contacts
                .iter()
                .find(|c| c.identity == m.author && !c.refused && !mine)
                .and_then(|c| crate::names::shown(d, c).remove("picture"));
            json!({
                "picture": picture,
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
    contacts::mark_read_in(d, &g.id, &g.name)
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
    identity(d).ok()?;
    let core = d.core();
    let sp = core.spaces.get(space)?.space.as_ref()?;
    let ours = sp.profile() == group::GROUP
        && core.is_joined(space)
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
        (Some(sp), Some(_)) => sp.profile() == group::GROUP && !core.is_joined(space),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// P12. A group's id is nobody's to choose, and its name is its
    /// admins'. So a group found by its id is that group, whatever another
    /// is called: someone who offers a group named after the id of one of
    /// this person's does not make theirs unaddressable.
    #[test]
    fn a_group_named_after_another_s_id_does_not_hide_it() {
        let (mine, theirs, other) = (
            [0xa1; 32],
            [0xb2; 32],
            [0xa1, 0xa1, 0xa1, 0xa1, 0xff, 0, 0, 0],
        );
        let mut second = [0u8; 32];
        second[..8].copy_from_slice(&other);
        let all = || {
            let group = |id: SpaceId, name: &str, joined: bool| Found {
                id,
                name: name.to_owned(),
                joined,
            };
            vec![
                group(mine, "Choir", true),
                group(theirs, &hex::encode(mine), false),
                group(second, "Band", true),
                group([0xc3; 32], "Club", false),
            ]
        };
        let found = |asked: &str, declined: &[SpaceId]| pick(all(), asked, declined).map(|g| g.id);
        let id = hex::encode(mine);
        assert_eq!(found(&id, &[]).unwrap(), mine);
        assert_eq!(found(&id.to_uppercase(), &[]).unwrap(), mine);
        assert_eq!(found(&id[..16], &[]).unwrap(), mine);
        assert_eq!(found("Choir", &[]).unwrap(), mine);
        // theirs is still found, by its own id
        assert_eq!(found(&hex::encode(theirs)[..8], &[]).unwrap(), theirs);
        // a prefix that two ids share names neither
        let why = found(&id[..8], &[]).unwrap_err().to_string();
        assert!(
            why.contains("more than one group's id starts with"),
            "{why}"
        );
        // fewer than eight digits are a name, and nothing is called that
        assert!(found(&id[..6], &[]).is_err());
        // a group this person said no to is not meant by its name
        assert_eq!(found("Club", &[]).unwrap(), [0xc3; 32]);
        assert!(found("Club", &[[0xc3; 32]]).is_err());
        assert_eq!(
            found(&hex::encode([0xc3u8; 32]), &[[0xc3; 32]]).unwrap(),
            [0xc3; 32]
        );
    }
}
