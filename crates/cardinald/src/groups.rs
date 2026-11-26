//! Groups (`profiles.md#group`): a space with one owner, whoever made it,
//! and any number of members, each offered it through a relationship they
//! already have, and a conversation everyone in it reads.
//!
//! A group only grows. Its owner and its admins add people; nobody is taken
//! out of it in place, and no role is lowered in place. Taking someone out,
//! or making an admin an ordinary member again, is the owner succeeding the
//! group with one whose genesis says so (`spaces.md#succession`): everyone
//! else's devices follow, and the group goes on under another id. A group
//! is found by any id it has had: the old one names the group that stands
//! in its place.
//!
//! Leaving is a member's own statement (`spaces.md#members-and-roles`). It
//! changes nothing about what is valid. Whoever left stops using the group
//! and ends the tokens they gave out in it; the others see that they left,
//! send them nothing more, and whoever writes next starts a new key that
//! is not wrapped for them.
//!
//! Software asks before a leave (D89): an owner names who looks after the
//! group if nobody else does, and whoever's devices have been passing
//! messages between two members who name no host there is told they may
//! not reach each other after. Each member's own device says whom nothing
//! connects it with. A leave takes no role away, so an owner or admin who
//! left can come back.
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

use crate::api::{self, Ref};
use crate::contacts::{self, identity};
use crate::core::{now_ms, Core};
use crate::daemon::Daemon;

/// How far apart one offered group is fetched from whoever offered it.
const FETCH_GAP: Duration = Duration::from_secs(10);

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// A group this device holds, by its id, a prefix of it, or its name.
#[derive(Clone)]
struct Found {
    id: SpaceId,
    name: String,
    joined: bool,
}

fn find(d: &Daemon, group: &str) -> anyhow::Result<Found> {
    find_among(d, api::reference(group), false)
}

/// [`find`], or with `in_it` among the groups this person is in alone:
/// what they write goes to a group they joined, whatever they have been
/// offered under the same name since.
fn find_among(d: &Daemon, group: Ref<'_>, in_it: bool) -> anyhow::Result<Found> {
    let me = identity(d)?;
    let core = d.core();
    let mut all: Vec<Found> = Vec::new();
    // what an id this group had before stands for
    let mut was: Vec<(SpaceId, SpaceId)> = Vec::new();
    for (id, h) in &core.spaces {
        let Some(sp) = h.space.as_ref() else {
            continue;
        };
        // A group this person left is not theirs to find, until someone
        // adds them again.
        if sp.profile() != group::GROUP || sp.has_left(&me) {
            continue;
        }
        if core.is_superseded(id) {
            was.push((*id, core.current(id)));
            continue;
        }
        all.push(Found {
            id: *id,
            name: group::name(sp),
            joined: core.is_joined(id),
        });
    }
    all.retain(|g| g.joined || !in_it);
    // given as bytes: the group whose id it is, or the one in its place
    let group = match group {
        Ref::Typed(t) => t,
        asked @ Ref::Id(_) => {
            let now = was
                .iter()
                .find(|(old, _)| asked.is_id(old))
                .map(|(_, now)| *now);
            let id = now.or_else(|| all.iter().find(|g| asked.is_id(&g.id)).map(|g| g.id));
            return id
                .and_then(|id| all.into_iter().find(|g| g.id == id))
                .ok_or_else(|| anyhow::anyhow!("there is no group {asked}"));
        }
    };
    let start = group.to_ascii_lowercase();
    if group.len() >= 8 {
        let now = was
            .iter()
            .filter(|(old, _)| hex::encode(old).starts_with(&start));
        let now: Vec<SpaceId> = now.map(|(_, now)| *now).collect();
        if let Some(g) = now.first().and_then(|n| all.iter().find(|g| g.id == *n)) {
            return Ok(g.clone());
        }
    }
    pick(all, group, &core.declined())
}

/// Which of the groups held is meant by `asked`: its id, the start of its
/// id in eight hex digits or more, or its name. An id is nobody's to
/// choose and a name is its admins', so a group found by its id is that
/// group, whatever another is called. By name, a group this person said no
/// to is not meant.
fn pick(all: Vec<Found>, asked: &str, declined: &[SpaceId]) -> anyhow::Result<Found> {
    // given as bytes: the group whose id it is, and nothing else
    if let id @ Ref::Id(_) = api::reference(asked) {
        return all
            .into_iter()
            .find(|g| id.is_id(&g.id))
            .ok_or_else(|| anyhow::anyhow!("there is no group {}", api::shown(asked)));
    }
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

/// [`pick`], by a `ref` as it came.
fn pick_ref(all: Vec<Found>, asked: Ref<'_>, declined: &[SpaceId]) -> anyhow::Result<Found> {
    match asked {
        Ref::Typed(t) => pick(all, t, declined),
        id @ Ref::Id(_) => all
            .into_iter()
            .find(|g| id.is_id(&g.id))
            .ok_or_else(|| anyhow::anyhow!("there is no group {id}")),
    }
}

/// A joined group, to write in.
fn joined(d: &Daemon, group: &str) -> anyhow::Result<Found> {
    match find_among(d, api::reference(group), true) {
        Ok(g) => {
            // one that ended and has nothing here in its place
            if let (Some(why), _) = d.core().succession_news(&g.id) {
                anyhow::bail!("{} has ended: {why}", g.name);
            }
            Ok(g)
        }
        // say which it is: not there at all, or there and not joined
        Err(none) => match find(d, group) {
            Ok(g) => anyhow::bail!("you have not joined {}", g.name),
            Err(_) => Err(none),
        },
    }
}

/// [`joined`], by a `ref` as it came.
fn joined_ref(d: &Daemon, group: Ref<'_>) -> anyhow::Result<Found> {
    match find_among(d, group, true) {
        Ok(g) => {
            // one that ended and has nothing here in its place
            if let (Some(why), _) = d.core().succession_news(&g.id) {
                anyhow::bail!("{} has ended: {why}", g.name);
            }
            Ok(g)
        }
        // say which it is: not there at all, or there and not joined
        Err(none) => match find_among(d, group, false) {
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
fn people(d: &Daemon, who: &[api::typed::Reference]) -> anyhow::Result<Vec<ContactRecord>> {
    who.iter()
        .map(|w| contacts::listed_ref(d, w.as_ref()))
        .collect()
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

/// Offers the group `id` to each of `who` who is a contact of this
/// person's (and not refused): those a succession named back in it, who
/// hold nothing that leads to it.
pub(crate) fn offer_to(d: &Arc<Daemon>, id: &SpaceId, who: &[[u8; 32]]) -> anyhow::Result<()> {
    let (name, to) = {
        let core = d.core();
        let sp = core.spaces.get(id).and_then(|h| h.space.as_ref());
        let name = sp.map(group::name).unwrap_or_default();
        let to: Vec<ContactRecord> = core
            .contacts()
            .into_iter()
            .filter(|c| who.contains(&c.identity) && !c.refused && c.recovery_of.is_none())
            .collect();
        (name, to)
    };
    offer(d, id, &name, &to)
}

/// Makes a group of this person and `who`, and offers it to each of them.
/// With `for_call` it is one [made for a call](`profiles.md#a-group-made-for-a-call`),
/// and with `history` false its policy does not share its history with
/// those added later; left out, it shares it, as before.
pub fn create(
    d: &Arc<Daemon>,
    name: &str,
    who: &[api::typed::Reference],
    for_call: bool,
    history: bool,
) -> anyhow::Result<api::GroupCreateReply> {
    let name = name.trim();
    anyhow::ensure!(!name.is_empty(), "a group needs a name");
    let theirs = people(d, who)?;
    let me_as = crate::names::my_name(d);
    let members: Vec<([u8; 32], String)> = theirs
        .iter()
        .map(|c| (c.identity, offered_as(c).to_owned()))
        .collect();
    let id = d
        .core()
        .create_group_with(name, &me_as, &members, for_call, history)?;
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
    Ok(api::GroupCreateReply {
        group: id,
        name: name.to_owned(),
    })
}

/// Adds contacts to a group, with the names the others will see, and offers
/// it to them.
pub fn add(
    d: &Arc<Daemon>,
    group: Ref<'_>,
    who: &[api::typed::Reference],
    shown: Option<&str>,
) -> anyhow::Result<()> {
    let g = joined_ref(d, group)?;
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
        shares_history(sp, &g.name)?;
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
    Ok(())
}

/// Nobody is added to a group whose policy does not share its history, nor
/// added back (`profiles.md#a-group-made-for-a-call`): someone added
/// without the history could not judge it.
fn shares_history(sp: &Space, name: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        sp.policy().history_shared,
        "{name} does not share its history with those added later, so nobody can be added to \
         it: make a new group for them instead"
    );
    Ok(())
}

/// [`member_named`], by a `ref` as it came.
fn member_named_ref(
    contacts: &[ContactRecord],
    sp: &Space,
    who: Ref<'_>,
) -> anyhow::Result<[u8; 32]> {
    let in_it = |id: &[u8; 32]| sp.validity().members.iter().any(|m| m.identity == *id);
    let who = match who {
        Ref::Typed(t) => t,
        asked @ Ref::Id(_) => {
            // one identity may be named with several roles
            let mut found: Vec<[u8; 32]> =
                sp.validity().members.iter().map(|m| m.identity).collect();
            found.retain(|id| asked.is_id(id));
            found.sort();
            found.dedup();
            return match found.as_slice() {
                [id] => Ok(*id),
                [] => anyhow::bail!("nobody in it has the id {asked}"),
                _ => anyhow::bail!("more than one in it has an id starting {asked}: give it whole"),
            };
        }
    };
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

/// The members a successor of a group names when it is to leave `out` out
/// and give `lowered` the role with it: everyone else in it who has not
/// left, each with the highest role they hold. Someone who left is not
/// named: the next key is not theirs either (`spaces.md#members-and-roles`).
fn staying(
    sp: &Space,
    out: Option<&[u8; 32]>,
    lowered: Option<(&[u8; 32], u64)>,
) -> Vec<([u8; 32], u64)> {
    let mut named = Vec::new();
    for m in group::members(sp) {
        if Some(&m.identity) == out || m.left {
            continue;
        }
        let role = match lowered {
            Some((who, role)) if *who == m.identity => role,
            _ => m.role,
        };
        named.push((m.identity, role));
    }
    named
}

/// Takes someone out of a group. Nothing in a space removes a member: the
/// owner succeeds the group with one that leaves them out, and the others'
/// devices follow (`profiles.md#group`). The group goes on under a new id;
/// the old one still finds it here.
pub async fn remove(
    d: &Arc<Daemon>,
    group: Ref<'_>,
    who: &api::typed::Reference,
) -> anyhow::Result<api::GroupRemoveReply> {
    let g = joined_ref(d, group)?;
    let me = identity(d)?;
    let (them, owner) = {
        let core = d.core();
        let contacts = core.contacts();
        let sp = core.spaces.get(&g.id).and_then(|h| h.space.as_ref());
        let sp = sp.ok_or_else(|| anyhow::anyhow!("that group is not open yet"))?;
        (member_named_ref(&contacts, sp, who.as_ref())?, sp.owner())
    };
    anyhow::ensure!(them != me, "to leave {}, leave it", g.name);
    anyhow::ensure!(
        owner == Some(me),
        "only the owner of {} can take someone out of it",
        g.name
    );
    // An old oddity, kept to the byte (DEVIATIONS.md, Old oddities kept):
    // they are named as the way by name held them, NUL first as bytes.
    let held = who.held();
    let done = crate::following::succeed(d, &g.id, |sp| {
        anyhow::ensure!(
            sp.role_of(&them).is_some(),
            "{held} is not in {} any more",
            g.name
        );
        Ok(staying(sp, Some(&them), None))
    })
    .await?;
    Ok(api::GroupRemoveReply {
        group: done.new,
        left_out: done.left_out,
        was: g.id,
    })
}

/// The role a client names, as `group-members` says them: `reader`,
/// `member` (a writer), or `admin`, and nothing else.
fn role_named(role: &str) -> anyhow::Result<u64> {
    match role {
        "reader" => Ok(group::READER),
        "member" => Ok(group::WRITER),
        "admin" => Ok(group::ADMIN),
        "owner" => anyhow::bail!("a group has one owner, whoever made it, for good"),
        _ => anyhow::bail!("a role is reader, member or admin"),
    }
}

/// Gives a member of a group a role. A higher one is given in place, by an
/// admin or the owner, as an addition is: roles are only given. A lower one
/// is the owner succeeding the group with one that names them with it
/// (`profiles.md#group`, "Making an admin an ordinary member again").
pub async fn set_role(
    d: &Arc<Daemon>,
    group: Ref<'_>,
    who: &api::typed::Reference,
    role: &str,
) -> anyhow::Result<api::GroupRoleReply> {
    let role = role_named(role)?;
    let g = joined_ref(d, group)?;
    let me = identity(d)?;
    let (them, now, owner, mine) = {
        let core = d.core();
        let contacts = core.contacts();
        let sp = core.spaces.get(&g.id).and_then(|h| h.space.as_ref());
        let sp = sp.ok_or_else(|| anyhow::anyhow!("that group is not open yet"))?;
        let them = member_named_ref(&contacts, sp, who.as_ref())?;
        // Someone who left comes back by `group-add` or `group-rejoin`,
        // never by being given a role (`apps.md`, `group-role`).
        anyhow::ensure!(
            !sp.has_left(&them),
            "{} has left {}: a role is not given to someone who left. They come back by being \
             added again, or by rejoining",
            who.as_ref(),
            g.name
        );
        (them, sp.role_of(&them), sp.owner(), sp.role_of(&me))
    };
    anyhow::ensure!(them != me, "you cannot change your own role");
    // An old oddity, kept to the byte (DEVIATIONS.md, Old oddities kept):
    // they are named as the way by name held them, NUL first as bytes.
    let now = now.ok_or_else(|| anyhow::anyhow!("{} is not in {}", who.held(), g.name))?;
    if role == now {
        return Ok(api::GroupRoleReply::new(g.id));
    }
    if role > now {
        anyhow::ensure!(
            mine.is_some_and(|r| r >= group::ADMIN),
            "only an admin of {} can give someone a role",
            g.name
        );
        d.write_and_push(&g.id, vec![SpaceOp::add_member(them, role)])?;
        d.bump();
        return Ok(api::GroupRoleReply::new(g.id));
    }
    anyhow::ensure!(
        owner == Some(me),
        "only the owner of {} can lower someone's role",
        g.name
    );
    let done = crate::following::succeed(d, &g.id, |sp| Ok(staying(sp, None, Some((&them, role)))))
        .await?;
    Ok(api::GroupRoleReply {
        group: done.new,
        was: Some(g.id),
    })
}

/// Posts again in a group what this device wrote before it moved on and
/// held back, because someone is there it was written without: its person
/// says to (`spaces.md#what-the-successor-does-not-carry`).
pub fn post_again(d: &Arc<Daemon>, group: &str) -> anyhow::Result<Json> {
    let g = joined(d, group)?;
    let held = d.core().held_back(&g.id);
    anyhow::ensure!(held > 0, "nothing of yours is held back from {}", g.name);
    let n = crate::following::post_held_back(d, &g.id);
    Ok(json!({"posted": n}))
}

/// Leaves a group: says so in it, and in the same entry sets this person's
/// reach node to an empty list, so that the group stops naming their hosts
/// to whoever is in it or comes to it later
/// (`spaces.md#members-and-roles`). It ends the tokens they gave out
/// there. The empty list is all that is left of what they said about
/// their hosts there: an offer of the group asks afresh. From then on this
/// device does nothing with the group, and the others send it nothing
/// more.
///
/// Software asks first (D89). An owner leaves others behind only with
/// someone among them who looks after it: `admins` are made admins, in
/// the entry that leaves, and without one where nobody else is, leaving
/// is refused with the question. And whoever's devices have lately been
/// passing messages between two others who name no host there is told so
/// by name, and leaves only `anyway`.
pub fn leave(
    d: &Arc<Daemon>,
    group: Ref<'_>,
    admins: &[api::typed::Reference],
    anyway: bool,
) -> anyhow::Result<api::GroupLeaveReply> {
    let g = joined_ref(d, group)?;
    let me = identity(d)?;
    let (made, names) = {
        let core = d.core();
        let sp = core.spaces.get(&g.id).and_then(|h| h.space.as_ref());
        let sp = sp.ok_or_else(|| anyhow::anyhow!("that group is not open yet"))?;
        anyhow::ensure!(sp.role_of(&me).is_some(), "you are not in {}", g.name);
        let contacts = core.contacts();
        let members = group::members(sp);
        let mut made: Vec<[u8; 32]> = Vec::new();
        for who in admins {
            let them = member_named_ref(&contacts, sp, who.as_ref())?;
            anyhow::ensure!(them != me, "you are leaving {}: name someone else", g.name);
            // An old oddity, kept to the byte (DEVIATIONS.md, Old oddities
            // kept): named as the way by name held them, NUL first as bytes.
            anyhow::ensure!(
                !sp.has_left(&them),
                "{} has left {}: name someone still in it",
                who.held(),
                g.name
            );
            if !made.contains(&them) {
                made.push(them);
            }
        }
        anyhow::ensure!(
            made.is_empty() || may_manage(sp, &me),
            "only an admin of {} can make someone an admin",
            g.name
        );
        let names: Vec<String> = made
            .iter()
            .map(|m| name_of(&me, &contacts, &members, m))
            .collect();
        let left = Leaving::of(&core, &g.id, sp, &me);
        if left.choose_admin && made.is_empty() {
            let others: Vec<String> = left.others.iter().map(|(_, n)| n.clone()).collect();
            anyhow::bail!(
                "Who looks after {name}? You own it, and once you leave nobody in it can add \
                 anyone, you included. Choose one or more of {who} to be its admins: \
                 cardinal group leave {name} --admin <member>",
                name = g.name,
                who = others.join(", "),
            );
        }
        if !left.relayed_for.is_empty() && !anyway {
            anyhow::bail!(
                "{} Introduce them first (cardinal introduce <who> <to>), or leave {} anyway: \
                 --anyway",
                relayed_warning(&left.relayed_for, &g.name),
                g.name
            );
        }
        (made, names)
    };
    let mut ops: Vec<SpaceOp> = made
        .iter()
        .map(|m| SpaceOp::add_member(*m, group::ADMIN))
        .collect();
    ops.extend(relationship::leave_ops(&me));
    d.write_and_push(&g.id, ops)?;
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
    Ok(api::GroupLeaveReply { admins: names })
}

/// How what this person writes in a group gets to another member, as
/// their own device sees it (D89): only what this device itself can tell.
/// It knows whom its person's devices talk to, and who names a host in the
/// group; whether two others are each other's contacts lives in their own
/// relationships, which the group never sees, and is nothing it guesses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Way {
    /// A trusted contact: their devices talk.
    Contact,
    /// They name a host in the group's reach node.
    Host,
    /// Not directly, but what this person writes goes to this member, a
    /// contact or one who names a host, who holds the group and passes it
    /// on. Whether it reaches them from there is not this device's to know.
    Through([u8; 32]),
    /// Nothing at all carries it from here: they are not a contact and name
    /// no host, and nobody else in the group is either.
    None,
}

/// What this device knows of a group's members, for [`Way`]: its own
/// person, whom the person's devices talk to, who names a host, and who is
/// in it, joined and not left.
pub(crate) struct Seen {
    pub me: [u8; 32],
    pub others: Vec<[u8; 32]>,
    pub contacts: Vec<[u8; 32]>,
    pub hosted: Vec<[u8; 32]>,
}

impl Seen {
    pub fn of(core: &Core, sp: &Space, me: &[u8; 32]) -> Seen {
        let all = core.contacts();
        let others: Vec<[u8; 32]> = sp
            .present()
            .into_iter()
            .filter(|m| m != me && sp.accepted_by(m))
            .collect();
        let contacts = others
            .iter()
            .filter(|m| cardinal_space::account::connects(&all, m))
            .copied()
            .collect();
        let mut hosted: Vec<[u8; 32]> = others.clone();
        hosted.push(*me);
        hosted.retain(|m| !relationship::reach_of(sp, m).is_empty());
        Seen {
            me: *me,
            others,
            contacts,
            hosted,
        }
    }

    /// How what this person writes gets to `who`.
    pub fn way_to(&self, who: &[u8; 32]) -> Way {
        if self.contacts.contains(who) {
            return Way::Contact;
        }
        if self.hosted.contains(who) {
            return Way::Host;
        }
        let carries =
            |m: &&[u8; 32]| *m != who && (self.contacts.contains(m) || self.hosted.contains(m));
        match self.others.iter().find(carries) {
            Some(m) => Way::Through(*m),
            None => Way::None,
        }
    }

    /// Whether anything could carry what `who` writes to this person: they
    /// are a contact, or this person names a host there, or some other
    /// contact of theirs is in it to pass it on. Without any of these
    /// nothing does, for certain.
    pub fn reaches_me(&self, who: &[u8; 32]) -> bool {
        self.contacts.contains(who)
            || self.hosted.contains(&self.me)
            || self.contacts.iter().any(|m| m != who)
    }
}

/// Two members, by identity and by what this person calls them.
type Named = ([u8; 32], String);

/// Two others this person's devices have been passing messages between.
pub(crate) struct RelayedFor {
    pub a: Named,
    pub b: Named,
}

/// What leaving a group would leave behind (D89).
pub(crate) struct Leaving {
    /// The others still in it, offered or joined.
    pub others: Vec<Named>,
    /// Those among them who look after it: its owner and admins.
    pub admins: Vec<Named>,
    /// Whether this person must choose someone to look after it first: they
    /// own it, others are in it, and none of them is an admin.
    pub choose_admin: bool,
    /// Pairs of others still in it whom this person's devices passed
    /// messages between lately ([`crate::core::RELAYED_FOR_MS`]), neither
    /// of whom names a host there: they may not reach each other once
    /// this person goes. A leaver cannot know whether two others are
    /// contacts; this is only what their devices saw.
    pub relayed_for: Vec<RelayedFor>,
}

impl Leaving {
    pub fn of(core: &Core, id: &SpaceId, sp: &Space, me: &[u8; 32]) -> Leaving {
        let contacts = core.contacts();
        let members = group::members(sp);
        let named = |id: &[u8; 32]| (*id, name_of(me, &contacts, &members, id));
        let others: Vec<&Member> = members
            .iter()
            .filter(|m| m.identity != *me && !m.left)
            .collect();
        let admins: Vec<Named> = others
            .iter()
            .filter(|m| m.role >= group::ADMIN)
            .map(|m| named(&m.identity))
            .collect();
        let owner = sp.owner() == Some(*me);
        let seen = Seen::of(core, sp, me);
        let relayed_for = core
            .relayed_for(id)
            .into_iter()
            .filter(|(a, b)| {
                let here = |m: &[u8; 32]| seen.others.contains(m) && !seen.hosted.contains(m);
                here(a) && here(b)
            })
            .map(|(a, b)| RelayedFor {
                a: named(&a),
                b: named(&b),
            })
            .collect();
        Leaving {
            choose_admin: owner && !others.is_empty() && admins.is_empty(),
            others: others.iter().map(|m| named(&m.identity)).collect(),
            admins,
            relayed_for,
        }
    }
}

/// What leaving a group would leave behind, for a client to ask about
/// before it leaves (D89): who looks after it, whether the person must
/// choose someone to, and whom their devices have been passing messages
/// between.
pub fn leaving(d: &Daemon, group: &str) -> anyhow::Result<Json> {
    let g = joined(d, group)?;
    let me = identity(d)?;
    let core = d.core();
    let sp = core.spaces.get(&g.id).and_then(|h| h.space.as_ref());
    let sp = sp.ok_or_else(|| anyhow::anyhow!("that group is not open yet"))?;
    let l = Leaving::of(&core, &g.id, sp, &me);
    let pairs: Vec<Json> = l
        .relayed_for
        .iter()
        .map(|o| {
            json!({
                "a": o.a.1, "a_id": hex::encode(&o.a.0[..8]),
                "b": o.b.1, "b_id": hex::encode(&o.b.0[..8]),
            })
        })
        .collect();
    let admins: Vec<&String> = l.admins.iter().map(|(_, n)| n).collect();
    Ok(json!({
        "group": hex::encode(g.id),
        "name": g.name,
        "admins": admins,
        "choose_admin": l.choose_admin,
        "relayed_for": pairs,
    }))
}

/// What a person leaving is told of those their devices have been passing
/// messages between (D89).
fn relayed_warning(pairs: &[RelayedFor], group: &str) -> String {
    let each: Vec<String> = pairs
        .iter()
        .map(|p| {
            format!(
                "Your devices have been passing messages between {} and {}, and neither has \
                 named a host in {group}. They may not reach each other once you leave.",
                p.a.1, p.b.1
            )
        })
        .collect();
    each.join(" ")
}

/// The groups this person left and may add themselves back to: they own
/// them, or were an admin, and this device still holds them (D89).
fn left_groups(core: &Core, me: &[u8; 32]) -> Vec<Found> {
    let mut out = Vec::new();
    for (id, h) in &core.spaces {
        let Some(sp) = h.space.as_ref() else {
            continue;
        };
        if sp.profile() != group::GROUP || !sp.has_left(me) || core.is_superseded(id) {
            continue;
        }
        if may_manage(sp, me) && !sp.ended() {
            out.push(Found {
                id: *id,
                name: group::name(sp),
                joined: false,
            });
        }
    }
    out
}

/// The groups [`rejoin`] can take this person back to, for `groups`.
fn rejoinable_json(core: &Core, me: &[u8; 32]) -> Vec<Json> {
    left_groups(core, me)
        .into_iter()
        .map(|g| {
            let sp = core.spaces.get(&g.id).and_then(|h| h.space.as_ref());
            let members = sp.map_or(0, |sp| sp.present().len());
            json!({"group": hex::encode(g.id), "name": g.name, "members": members})
        })
        .collect()
}

/// An owner, or an admin, who left a group comes back: a leave takes no
/// role away, so they add themselves again, by an `add_member` that
/// descends from their leave, and have accepted it by doing so
/// (`spaces.md#holding-a-space`). Their reach node stays the empty list
/// the leave left there until they share their host again. Whoever writes
/// next in it starts a key that is theirs too, and with it they read what
/// was written while they were away.
pub fn rejoin(
    d: &Arc<Daemon>,
    group: &api::typed::Reference,
) -> anyhow::Result<api::GroupCreateReply> {
    let (held, group) = (group.held(), group.as_ref());
    let me = identity(d)?;
    let (found, left_some) = {
        let core = d.core();
        let found = pick_ref(left_groups(&core, &me), group, &[]);
        (found, left_any(&core, &me, group))
    };
    let g = match found {
        Ok(g) => g,
        Err(e) => {
            if let Ok(g) = find_among(d, group, false) {
                anyhow::bail!("you are in {} already", g.name);
            }
            // left, and not one who looks after it; an old oddity, kept to
            // the byte (DEVIATIONS.md, Old oddities kept): the group named
            // as the way by name held it, NUL first as bytes
            anyhow::ensure!(
                !left_some,
                "only an owner or admin of {held} can add themselves back: ask one of them \
                 to add you"
            );
            return Err(e);
        }
    };
    {
        let core = d.core();
        let sp = core.spaces.get(&g.id).and_then(|h| h.space.as_ref());
        let sp = sp.ok_or_else(|| anyhow::anyhow!("that group is not open yet"))?;
        shares_history(sp, &g.name)?;
    }
    d.write_and_push(&g.id, vec![SpaceOp::add_member(me, group::ADMIN)])?;
    d.bump();
    Ok(api::GroupCreateReply {
        group: g.id,
        name: g.name,
    })
}

/// Whether this person left a group `group` names, whatever their role.
fn left_any(core: &Core, me: &[u8; 32], group: Ref<'_>) -> bool {
    let all: Vec<Found> = core
        .spaces
        .iter()
        .filter_map(|(id, h)| {
            let sp = h.space.as_ref()?;
            (sp.profile() == group::GROUP && sp.has_left(me) && !core.is_superseded(id)).then(
                || Found {
                    id: *id,
                    name: group::name(sp),
                    joined: false,
                },
            )
        })
        .collect();
    pick_ref(all, group, &[]).is_ok()
}

/// What is said of this person's reach node in a group, for a client to
/// show: the members by the names this person sees.
fn telling_of(core: &Core, id: &SpaceId, me: &[u8; 32]) -> api::GroupReach {
    let t = core.telling(id);
    let contacts = core.contacts();
    let open = core.spaces.get(id).and_then(|h| h.space.as_ref());
    let members = open.map(group::members).unwrap_or_default();
    let names = |who: &[[u8; 32]]| -> Vec<String> {
        who.iter()
            .map(|m| name_of(me, &contacts, &members, m))
            .collect()
    };
    api::GroupReach {
        shared: t.shared,
        ask: t.ask(),
        who: names(&t.who),
        added: names(t.added()),
        public: t.public,
        waiting: t.waiting,
        said_no: t.said_no,
        set: t.set,
        what: t.what,
        named: None,
    }
}

/// [`telling_of`], by name, for the requests not yet typed.
fn telling_json(core: &Core, id: &SpaceId, me: &[u8; 32]) -> Json {
    let t = telling_of(core, id, me);
    json!({
        "shared": t.shared,
        "ask": t.ask,
        "who": t.who,
        "what": t.what,
        "added": t.added,
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
fn question(reach: &api::GroupReach, name: &str) -> String {
    let who = &reach.who;
    let what = reach.what.join(", ");
    // A public space is read by anyone at all, whoever is in it now, and
    // the question says so.
    if reach.public {
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
pub async fn join(
    d: &Arc<Daemon>,
    group: Ref<'_>,
    reach: Option<bool>,
) -> anyhow::Result<api::GroupJoinReply> {
    let g = find_among(d, group, false)?;
    join_found(d, g, reach).await
}

/// [`join`], of the group whose id is exactly `id`, and no other: not the
/// one in its place, nor one found by name, as answering a call there joins
/// that group alone (`profiles.md#calls-guidance`).
pub(crate) async fn join_exact(
    d: &Arc<Daemon>,
    id: &SpaceId,
    reach: Option<bool>,
) -> anyhow::Result<api::GroupJoinReply> {
    let me = identity(d)?;
    let g = {
        let core = d.core();
        let sp = core.spaces.get(id).and_then(|h| h.space.as_ref());
        let sp = sp.filter(|sp| sp.profile() == group::GROUP && !sp.has_left(&me));
        let sp = sp.filter(|_| !core.is_superseded(id));
        let sp = sp.ok_or_else(|| anyhow::anyhow!("that group is not here to join"))?;
        Found {
            id: *id,
            name: group::name(sp),
            joined: core.is_joined(id),
        }
    };
    join_found(d, g, reach).await
}

async fn join_found(
    d: &Arc<Daemon>,
    g: Found,
    reach: Option<bool>,
) -> anyhow::Result<api::GroupJoinReply> {
    if g.joined {
        return Ok(api::GroupJoinReply::new());
    }
    let me = identity(d)?;
    let (t, telling) = {
        let core = d.core();
        (core.telling(&g.id), telling_of(&core, &g.id, &me))
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
    Ok(api::GroupJoinReply {
        group: Some(g.id),
        name: Some(g.name),
        shared: Some(shared),
        waiting: Some(waiting),
    })
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
pub async fn set_reach(
    d: &Arc<Daemon>,
    group: Ref<'_>,
    share: bool,
) -> anyhow::Result<api::GroupReachReply> {
    use crate::mailbox::Shared;
    let g = joined_ref(d, group)?;
    if !share {
        // Written even where the list is empty already: a yes that
        // another of their devices keeps for later gives way to a list
        // set after it, and to nothing else.
        crate::mailbox::say_reach(d, &g.id, false).await?;
        d.core().drop_yes(&g.id);
        d.core().told_of_all(&g.id);
        d.bump();
        return Ok(api::GroupReachReply {
            shared: Some(false),
            waiting: Some(false),
            taken_out: None,
        });
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
    Ok(api::GroupReachReply {
        shared: Some(!waiting),
        waiting: Some(waiting),
        taken_out: None,
    })
}

/// The person takes one host of theirs out of a group's list (D75): the
/// account records "not this host here", so it does not name itself there
/// again until they say `share`.
pub async fn no_host(
    d: &Arc<Daemon>,
    group: Ref<'_>,
    host: &str,
) -> anyhow::Result<api::GroupReachReply> {
    let g = joined_ref(d, group)?;
    let key = crate::mailbox::host_by_name(d, host)?;
    let named = crate::mailbox::take_out_host(d, &g.id, &key).await?;
    d.bump();
    Ok(api::GroupReachReply {
        shared: None,
        waiting: None,
        taken_out: Some(named),
    })
}

/// Says no to a group offered to this person. Nothing is written in it, and
/// it is not offered again.
pub fn decline(d: &Arc<Daemon>, group: Ref<'_>) -> anyhow::Result<()> {
    let g = find_among(d, group, false)?;
    anyhow::ensure!(!g.joined, "you are in {}: leave it instead", g.name);
    let account = d
        .core()
        .account_id()
        .ok_or_else(|| anyhow::anyhow!("the account space is not here yet"))?;
    let op = cardinal_space::account::create_declined(&g.id, &g.name);
    d.write_and_push(&account, vec![op])?;
    // A call there that rings stops: a ring in a declined group does not
    // ring (`profiles.md#calls-guidance`). The person's other devices stop
    // once the decline reaches them.
    crate::calls::stop_ringing_in(d, &g.id, true);
    d.bump();
    Ok(())
}

/// What this person calls a member: themselves, a contact's petname, or the
/// name the group shows.
/// The members of a group and those taken out of it, for naming whoever
/// wrote what is there: someone taken out is still shown by the name the
/// others saw (`group::taken_out`).
fn named_in(sp: &Space) -> Vec<Member> {
    let mut all = group::members(sp);
    all.extend(group::taken_out(sp));
    all
}

/// How a client names a role.
fn role_name(role: u64) -> &'static str {
    match role {
        group::OWNER => "owner",
        group::ADMIN => "admin",
        group::READER => "reader",
        _ => "member",
    }
}

/// What a successor changed, as this person names those it concerns:
/// `taken_out`, names, and `roles`, each `{name, from, to}`.
fn change_json(
    core: &Core,
    me: &[u8; 32],
    contacts: &[ContactRecord],
    named: &[Member],
    succ: &SpaceId,
) -> Json {
    let Some((out, roles)) = core.changes_of(succ) else {
        return json!({"taken_out": [], "roles": []});
    };
    // the old space knows them all by name
    let old = core
        .spaces
        .get(succ)
        .and_then(|h| h.space.as_ref()?.succeeds());
    let old = old.and_then(|o| core.spaces.get(&o)?.space.as_ref());
    let mut all: Vec<Member> = named.to_vec();
    if let Some(o) = old {
        all.extend(named_in(o));
    }
    let name = |w: &[u8; 32]| name_of(me, contacts, &all, w);
    json!({
        "taken_out": out.iter().map(name).collect::<Vec<_>>(),
        "roles": roles.iter().map(|(w, from, to)| json!({
            "name": name(w),
            "from": role_name(*from),
            "to": role_name(*to),
        })).collect::<Vec<_>>(),
    })
}

/// A group change kept after a recovery by guardians (D84): another of
/// the person's old devices made it and one confirmed it before the loss,
/// so it stands, and the recovered device lists it for the person to undo
/// if they do not recognise it. `group`, the group it left, and `to`, the
/// one it moved to (what `recover-undo` takes); who and which device, when,
/// what it changed, who it was handed on to if it was, whether undo can
/// put it right and what undo does, in words, and `undone`, the group an
/// undo made.
pub(crate) fn kept_change_json(
    core: &Core,
    old: &SpaceId,
    new: &SpaceId,
    undone: Option<&str>,
) -> Option<Json> {
    let me = core.me()?;
    let contacts = core.contacts();
    let sp = core.spaces.get(new)?.space.as_ref()?;
    let mut all = named_in(sp);
    if let Some(o) = core.spaces.get(old).and_then(|h| h.space.as_ref()) {
        all.extend(named_in(o));
    }
    let mut c = change_json(core, &me, &contacts, &all, new);
    let name = |w: &[u8; 32]| name_of(&me, &contacts, &all, w);
    let group_name = group::name(sp);
    let handed = sp.owner().filter(|o| *o != me).map(|o| name(&o));
    let undo = match &handed {
        Some(h) => format!(
            "Undo cannot take {group_name} back: it was handed on to {h}, who holds it now. \
             Only they can hand it back."
        ),
        None => {
            let mut parts = Vec::new();
            let out: Vec<String> = c["taken_out"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            if !out.is_empty() {
                parts.push(format!("adds back {}", out.join(", ")));
            }
            for r in c["roles"].as_array().into_iter().flatten() {
                parts.push(format!(
                    "gives {} back the role of {}",
                    r["name"].as_str().unwrap_or("Someone"),
                    r["from"].as_str().unwrap_or("member")
                ));
            }
            format!(
                "Undo moves {group_name} on again: it {}.",
                parts.join(", and ")
            )
        }
    };
    c["group"] = json!(hex::encode(old));
    c["to"] = json!(hex::encode(new));
    c["name"] = json!(group_name);
    c["by"] = json!(name(&sp.creator()));
    c["at"] = json!(sp.entry(new).and_then(|g| g.time()));
    c["device"] = json!(core.moved_by_device(new));
    c["handed_to"] = json!(handed);
    c["can_undo"] = json!(handed.is_none());
    c["undo"] = json!(undo);
    c["undone"] = json!(undone);
    Some(c)
}

/// How long the note of how a group moved stays, unless cleared first.
const MOVED_FOR_MS: u64 = 7 * 24 * 3600 * 1000;

/// That this person may write in a group: a writer, an admin or its owner.
/// A reader reads.
fn may_write_in(d: &Daemon, g: &Found) -> anyhow::Result<()> {
    let me = identity(d)?;
    let core = d.core();
    let sp = core.spaces.get(&g.id).and_then(|h| h.space.as_ref());
    let sp = sp.ok_or_else(|| anyhow::anyhow!("that group is not open yet"))?;
    let role = sp.role_of(&me);
    anyhow::ensure!(
        role.is_some_and(|r| r >= group::WRITER),
        "you can read {} but not write in it: its owner made you a reader",
        g.name
    );
    Ok(())
}

/// The person cleared the note of how a group moved.
pub fn moved_seen(d: &Daemon, group: &str) -> anyhow::Result<Json> {
    let g = find(d, group)?;
    d.core().moved_seen(&g.id);
    d.bump();
    Ok(json!({}))
}

/// The person's OK to how another of their devices moved a group
/// (`spaces.md#a-succession-by-a-device-that-is-later-removed`, "Kept when
/// the person confirms it"): keeps each succession `moves` names (by the
/// earlier group it left, and in `to`, beside it, the group it moved to,
/// as `to_confirm` gives them) that still awaits their word, a `keep` of
/// the `succeed` and of the genesis it names, and clears the note as
/// [`moved_seen`] does. A move the person was not shown, one that arrived
/// after, is not kept. Without `to`, a move is named by the group it left
/// alone, which is refused where the person's devices moved that group to
/// two places. Answers how many entries it wrote.
pub fn confirm_move(
    d: &Arc<Daemon>,
    group: &str,
    moves: &[String],
    to: &[String],
) -> anyhow::Result<Json> {
    let g = find(d, group)?;
    anyhow::ensure!(
        !moves.is_empty(),
        "say which moves the person saw (moves: the groups to_confirm gives)"
    );
    anyhow::ensure!(
        to.is_empty() || to.len() == moves.len(),
        "to names where each move went, one for each of moves"
    );
    let id_of = |m: &String| -> anyhow::Result<SpaceId> {
        let id: Option<SpaceId> = hex::decode(m).ok().and_then(|b| b.try_into().ok());
        id.ok_or_else(|| anyhow::anyhow!("a move is a group id in hex: {m}"))
    };
    let seen = moves
        .iter()
        .map(id_of)
        .collect::<anyhow::Result<Vec<_>>>()?;
    let written = if to.is_empty() {
        d.core().confirm_moves(&g.id, &seen)?
    } else {
        let to = to.iter().map(id_of).collect::<anyhow::Result<Vec<_>>>()?;
        let pairs: Vec<(SpaceId, SpaceId)> = seen.into_iter().zip(to).collect();
        d.core().confirm_moves_to(&g.id, &pairs)?
    };
    let kept = written.len();
    for (space, bytes) in written {
        d.push(&space, vec![bytes]);
    }
    d.bump();
    Ok(json!({ "kept": kept }))
}

/// Each move on the way to `id` that awaits this person's word, nearest
/// first: `group`, the earlier group it left (what `group-confirm-move`
/// takes), `to`, the group it moved to, who moved it and on which device,
/// when, and what it changed.
fn to_confirm_json(
    core: &Core,
    me: &[u8; 32],
    contacts: &[ContactRecord],
    named: &[Member],
    id: &SpaceId,
) -> Vec<Json> {
    core.moves_to_confirm(id)
        .iter()
        .filter_map(|(old, new)| {
            let new = *new;
            let sp = core.spaces.get(&new)?.space.as_ref()?;
            let mut c = change_json(core, me, contacts, named, &new);
            c["group"] = json!(hex::encode(old));
            c["to"] = json!(hex::encode(new));
            c["by"] = json!(name_of(me, contacts, named, &sp.creator()));
            c["at"] = json!(sp.entry(&new).and_then(|g| g.time()));
            c["seen"] = json!(core.spaces.get(&new).and_then(|h| h.notes().first_seen_ms));
            c["device"] = json!(core.moved_by_device(&new));
            Some(c)
        })
        .collect()
}

pub(crate) fn name_of(
    me: &[u8; 32],
    contacts: &[ContactRecord],
    members: &[Member],
    who: &[u8; 32],
) -> String {
    if who == me {
        return "You".into();
    }
    // two records of one contact: refused if either is (the cautious
    // answer), and then not named by this person's name for them
    if !cardinal_space::account::refused(contacts, who) {
        if let Some(c) = contacts.iter().find(|c| c.identity == *who) {
            return c.petname.clone();
        }
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
        // Another stands in its place, and is listed instead.
        if sp.has_left(&me) || core.is_superseded(id) {
            continue;
        }
        let members = group::members(sp);
        let named = named_in(sp);
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
                    "for_call": group::for_call(sp),
                    "last_call": core.last_call(id),
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
        let (ended, mut lost) = core.succession_news(id);
        // what did not stand is noted in the space it would have succeeded
        if let Some(o) = sp.succeeds() {
            lost.extend(core.succession_news(&o).1);
        }
        // who moved it here, and what that changed, until it is cleared or
        // a week has gone
        let notes = core.spaces.get(id).map(|h| h.notes());
        let at = sp.entry(id).and_then(|g| g.time());
        // aged from when this device first held it, not by the mover's clock
        let seen = notes.and_then(|n| n.first_seen_ms);
        let fresh = seen.is_none_or(|t| now_ms().saturating_sub(t) < MOVED_FOR_MS);
        // what another device of the person's moved, until they say OK
        let to_confirm = to_confirm_json(core, &me, &contacts, &named, id);
        let confirm: Vec<Json> = to_confirm.iter().map(|c| c["group"].clone()).collect();
        let told = fresh && !notes.is_some_and(|n| n.moved_seen);
        let moved = (sp.succeeds().is_some() && (told || !confirm.is_empty())).then(|| {
            let mut c = change_json(core, &me, &contacts, &named, id);
            c["by"] = json!(name_of(&me, &contacts, &named, &sp.creator()));
            c["at"] = json!(at);
            c["seen"] = json!(seen);
            c["device"] = json!(core.moved_by_device(id));
            c
        });
        let lost_ids: Vec<String> = lost.iter().map(hex::encode).collect();
        let lost: Vec<Json> = lost
            .iter()
            .map(|l| {
                let mut c = change_json(core, &me, &contacts, &named, l);
                c["group"] = json!(hex::encode(l));
                c
            })
            .collect();
        let group = json!({
            "ended": ended,
            "moved": moved,
            "confirm": confirm,
            "to_confirm": to_confirm,
            "did_not_stand": lost_ids,
            "did_not_stand_changes": lost,
            "held_back": core.held_back(id),
            "not_posted": core.spaces.get(id).map_or(0, |h| h.notes().not_posted),
            "was": sp.succeeds().map(hex::encode),
            "group": hex::encode(id),
            "name": name,
            "members": how_many,
            "public": sp.is_public(),
            "reach": telling_json(core, id, &me),
            "admin": may_manage(sp, &me),
            "role": sp.role_of(&me).map(role_name),
            "introductions": group::introductions(sp),
            "for_call": group::for_call(sp),
            "last_call": core.last_call(id),
            "unread": unread,
            "last": last.map(|m| json!({
                "mine": m.author == me,
                "from": name_of(&me, &contacts, &named, &m.author),
                "text": m.text,
                "time": m.time,
            })),
        });
        groups.push((when, group));
    }
    groups.sort_by_key(|(when, _)| std::cmp::Reverse(*when));
    let groups: Vec<Json> = groups.into_iter().map(|(_, g)| g).collect();
    let rejoin = rejoinable_json(core, &me);
    json!({"groups": groups, "offers": offered, "rejoin": rejoin})
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
    let seen = Seen::of(&core, sp, &me);
    let out: Vec<Json> = members
        .iter()
        .map(|m| {
            let known = contacts
                .iter()
                .find(|c| c.identity == m.identity && !c.refused);
            let mut v = member_fields(&me, &contacts, &members, m);
            // what carries what this person writes to them, and theirs back
            // (D89): for someone in it who has joined, not this person
            if seen.others.contains(&m.identity) {
                let (reach, through) = match seen.way_to(&m.identity) {
                    Way::Contact => ("contact", None),
                    Way::Host => ("host", None),
                    Way::Through(t) => ("through", Some(name_of(&me, &contacts, &members, &t))),
                    Way::None => ("none", None),
                };
                v["reach"] = json!(reach);
                v["through"] = json!(through);
                v["reaches_you"] = json!(seen.reaches_me(&m.identity));
            }
            shown_as_contact(d, &me, &contacts, &members, known, &m.identity, v)
        })
        .collect();
    // and whoever was taken out when it moved, marked: by the name the
    // others saw
    let named = named_in(sp);
    let mut out = out;
    for m in group::taken_out(sp) {
        out.push(json!({
            "name": name_of(&me, &contacts, &named, &m.identity),
            "shown": m.name,
            "id": hex::encode(&m.identity[..8]),
            "you": m.identity == me,
            "contact": contacts.iter().any(|c| c.identity == m.identity && !c.refused),
            "role": "taken out",
            "taken_out": true,
            "introduce": false,
            "left": false,
        }));
    }
    Ok(json!({"group": hex::encode(g.id), "name": g.name, "members": out}))
}

/// A *member* as `group-members` gives one, without how they are reached.
fn member_of(
    me: &[u8; 32],
    contacts: &[ContactRecord],
    members: &[Member],
    m: &Member,
) -> api::Member {
    let contact = contacts
        .iter()
        .any(|c| c.identity == m.identity && !c.refused);
    api::Member {
        name: name_of(me, contacts, members, &m.identity),
        shown: m.name.clone(),
        id: api::short_id(&m.identity),
        you: m.identity == *me,
        contact,
        role: match m.role {
            group::OWNER => "owner",
            group::ADMIN => "admin",
            group::READER => "reader",
            _ => "member",
        }
        .into(),
        introduce: m.introduce,
        left: m.left,
        own: None,
        picture: None,
        suggested: None,
        taken_out: None,
        reach: None,
        reaches_you: None,
        through: None,
    }
}

/// [`member_of`], by name, for the requests not yet typed.
fn member_fields(
    me: &[u8; 32],
    contacts: &[ContactRecord],
    members: &[Member],
    m: &Member,
) -> Json {
    let m = member_of(me, contacts, members, m);
    json!({
        "name": m.name,
        "shown": m.shown,
        "id": hex::encode(m.id),
        "you": m.you,
        "contact": m.contact,
        "role": m.role,
        "introduce": m.introduce,
        "left": m.left,
    })
}

/// A contact's member record as this person sees them: their own name for
/// them, and the picture.
fn shown_as_contact(
    d: &Daemon,
    me: &[u8; 32],
    contacts: &[ContactRecord],
    members: &[Member],
    known: Option<&ContactRecord>,
    who: &[u8; 32],
    v: Json,
) -> Json {
    match known {
        Some(c) => {
            let mut v = crate::names::with_shown(d, c, v);
            v["name"] = json!(name_of(me, contacts, members, who));
            v
        }
        None => v,
    }
}

/// [`shown_as_contact`], typed.
fn known_as_contact(
    d: &Daemon,
    me: &[u8; 32],
    contacts: &[ContactRecord],
    members: &[Member],
    known: Option<&ContactRecord>,
    mut m: api::Member,
) -> api::Member {
    if let Some(c) = known {
        m.own = Some(c.own);
        m.suggested = c.suggested.clone();
        m.picture = crate::names::picture(d, c);
        m.name = name_of(me, contacts, members, &c.identity);
    }
    m
}

/// What a ringing or live call in a group says of it (`apps.md`, *call*):
/// `name`, the group's; `for_call`; `admins`, its owner and its admins who
/// have not left, the owner first, each a *member* without how they are
/// reached; `caller`, who rang, as one, where given; and where the group is
/// only offered to this person, `joins` true and the offer's `reach`.
pub(crate) fn call_about(
    d: &Daemon,
    space: &SpaceId,
    caller: Option<&[u8; 32]>,
) -> Option<CallAbout> {
    let me = identity(d).ok()?;
    let core = d.core();
    let sp = core.spaces.get(space).and_then(|h| h.space.as_ref())?;
    let members = group::members(sp);
    let contacts = core.contacts();
    let person = |m: &Member| {
        let known = contacts
            .iter()
            .find(|c| c.identity == m.identity && !c.refused);
        let v = member_of(&me, &contacts, &members, m);
        known_as_contact(d, &me, &contacts, &members, known, v)
    };
    let mut admins: Vec<&Member> = members
        .iter()
        .filter(|m| m.role >= group::ADMIN && !m.left)
        .collect();
    admins.sort_by_key(|m| std::cmp::Reverse(m.role == group::OWNER));
    let admins: Vec<api::Member> = admins.into_iter().map(person).collect();
    let caller = caller.and_then(|c| members.iter().find(|m| m.identity == *c).map(person));
    let joins = !core.is_joined(space);
    Some(CallAbout {
        name: group::name(sp),
        for_call: group::for_call(sp),
        admins,
        caller,
        joins,
        reach: joins.then(|| telling_of(&core, space, &me)),
    })
}

/// What a call in a group says of the group (D92, D93), for [`call_about`].
pub(crate) struct CallAbout {
    pub name: String,
    pub for_call: bool,
    pub admins: Vec<api::Member>,
    pub caller: Option<api::Member>,
    pub joins: bool,
    pub reach: Option<api::GroupReach>,
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
    group: Ref<'_>,
    text: &str,
    reply_to: Option<Ref<'_>>,
    attach: &[String],
) -> anyhow::Result<()> {
    let g = joined_ref(d, group)?;
    may_write_in(d, &g)?;
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
    Ok(())
}

fn message_in(d: &Daemon, space: &SpaceId, id: Ref<'_>) -> anyhow::Result<relationship::Message> {
    let id = contacts::message_id(id).ok_or_else(|| anyhow::anyhow!("that is not a message"))?;
    let core = d.core();
    let sp = core.spaces.get(space).and_then(|h| h.space.as_ref());
    let sp = sp.ok_or_else(|| anyhow::anyhow!("that group is not open yet"))?;
    // a message posted again has a new id, and the old one names it
    let now = sp.state().now_called(&id).unwrap_or(id);
    let found = relationship::messages(sp).into_iter().find(|m| m.id == now);
    found.ok_or_else(|| anyhow::anyhow!("there is no such message"))
}

/// The conversation of a group, oldest first, with who said each thing and
/// how many of the others have read what this person said. All of it: the
/// request's page is cut from it.
pub fn messages(
    d: &Daemon,
    group: Ref<'_>,
    before: Option<Ref<'_>>,
) -> anyhow::Result<api::MessagesReply> {
    let g = find_among(d, group, false)?;
    use_members(d, &g.id);
    let me = identity(d)?;
    let core = d.core();
    let sp = core.spaces.get(&g.id).and_then(|h| h.space.as_ref());
    let sp = sp.ok_or_else(|| anyhow::anyhow!("that group is not open yet"))?;
    let all = relationship::messages(sp);
    let members = group::members(sp);
    let named = named_in(sp);
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
    let upto = contacts::upto(sp, &all, before)?;
    let messages: Vec<api::Message> = all
        .into_iter()
        .take(upto)
        .enumerate()
        .map(|(i, m)| {
            let mine = m.author == me;
            let read = others.iter().filter(|o| read_by[*o][i]).count();
            let picture = contacts
                .iter()
                .find(|c| c.identity == m.author && !c.refused && !mine)
                .and_then(|c| crate::names::picture(d, c));
            let state = if read == others.len() && !others.is_empty() {
                "read"
            } else {
                "sent"
            };
            api::Message {
                picture,
                id: m.id,
                mine,
                from: Some(name_of(&me, &contacts, &named, &m.author)),
                state: mine.then_some(state.into()),
                read_by: mine.then_some(read as u64),
                reply_to: m.reply_to,
                attachments: contacts::attachments_of(&m),
                edited: m.edited,
                reactions: contacts::reactions_of(&m, Some(me)),
                text: m.text,
                time: m.time,
            }
        })
        .collect();
    Ok(api::MessagesReply {
        group: Some(g.id),
        name: Some(g.name),
        messages,
        // the page says
        more: false,
        next: None,
    })
}

/// Saves a file that came with a message in a group, fetching it from the
/// members in touch: its sender if they are, or anyone else who has it.
pub async fn save_attachment(
    d: &Arc<Daemon>,
    group: Ref<'_>,
    id: Ref<'_>,
    index: usize,
    to: &str,
) -> anyhow::Result<api::SaveReply> {
    let g = find_among(d, group, false)?;
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
    let shown = to.to_owned();
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
            Ok(size) => return Ok(api::SaveReply { path: shown, size }),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// A message of this person's own in a group: only that can be changed or
/// taken back.
fn own_message(d: &Daemon, space: &SpaceId, id: Ref<'_>) -> anyhow::Result<relationship::Message> {
    let m = message_in(d, space, id)?;
    anyhow::ensure!(
        m.author == identity(d)?,
        "only what you wrote can be changed"
    );
    Ok(m)
}

/// Changes what a message of this person's in a group says.
pub fn edit_message(
    d: &Arc<Daemon>,
    group: Ref<'_>,
    id: Ref<'_>,
    text: &str,
) -> anyhow::Result<()> {
    let g = joined_ref(d, group)?;
    may_write_in(d, &g)?;
    let m = own_message(d, &g.id, id)?;
    anyhow::ensure!(!text.trim().is_empty(), "a message cannot be empty");
    d.write_and_push(&g.id, vec![relationship::edit_message(m.id, text)])?;
    Ok(())
}

/// Takes back a message of this person's in a group.
pub fn delete_message(d: &Arc<Daemon>, group: Ref<'_>, id: Ref<'_>) -> anyhow::Result<()> {
    let g = joined_ref(d, group)?;
    may_write_in(d, &g)?;
    let m = own_message(d, &g.id, id)?;
    d.write_and_push(&g.id, vec![SpaceOp::delete(m.id)])?;
    Ok(())
}

/// Reacts to a message in a group, replacing this person's reaction, or
/// taking it away with nothing.
pub fn react(d: &Arc<Daemon>, group: Ref<'_>, id: Ref<'_>, text: &str) -> anyhow::Result<()> {
    let g = joined_ref(d, group)?;
    may_write_in(d, &g)?;
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
    Ok(())
}

/// Marks a group's conversation read up to its last message from anyone else.
pub fn mark_read(d: &Arc<Daemon>, group: Ref<'_>) -> anyhow::Result<api::MarkReadReply> {
    let g = joined_ref(d, group)?;
    contacts::mark_read_in(d, &g.id, &g.name)
}

/// Renames a group, or says whether its members are introduced through it.
pub fn set(
    d: &Arc<Daemon>,
    group: Ref<'_>,
    name: Option<&str>,
    introductions: Option<bool>,
    for_call: Option<bool>,
) -> anyhow::Result<()> {
    // Only a genesis makes a group one made for a call: refused before
    // anything is written.
    anyhow::ensure!(
        for_call != Some(true),
        "only a new group is made for a call: make one with group-create"
    );
    let g = joined_ref(d, group)?;
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
        // "Keep this group": where it is not one made for a call, nothing
        if for_call == Some(false) && group::for_call(sp) {
            ops.push(group::keep_group(c));
        }
        ops
    };
    if !ops.is_empty() {
        d.write_and_push(&g.id, ops)?;
    }
    d.bump();
    Ok(())
}

/// Why a group was not renamed.
#[derive(Debug)]
pub enum NotAdmin {
    /// Only its owner and its admins name it.
    No(anyhow::Error),
    /// Anything else.
    Other(anyhow::Error),
}

/// Renames a group, by its id: what renaming its folder does (D88). Anyone
/// but its owner and its admins is refused, and says so.
pub fn rename(d: &Arc<Daemon>, group: &SpaceId, name: &str) -> Result<(), NotAdmin> {
    let me = identity(d).map_err(NotAdmin::Other)?;
    if name.trim().is_empty() {
        return Err(NotAdmin::Other(anyhow::anyhow!("a group needs a name")));
    }
    {
        let core = d.core();
        let sp = core.spaces.get(group).and_then(|h| h.space.as_ref());
        let sp =
            sp.ok_or_else(|| NotAdmin::Other(anyhow::anyhow!("that group is not open yet")))?;
        if !may_manage(sp, &me) {
            let called = group::name(sp);
            return Err(NotAdmin::No(anyhow::anyhow!(
                "only an admin of {called} can rename it"
            )));
        }
    }
    let id = hex::encode(group);
    set(d, Ref::Typed(&id), Some(name), None, None).map_err(NotAdmin::Other)?;
    Ok(())
}

/// Changes what the others see a member called, or whether they are
/// introduced through the group.
pub fn set_member(
    d: &Arc<Daemon>,
    group: Ref<'_>,
    who: &api::typed::Reference,
    shown: Option<&str>,
    introduce: Option<bool>,
) -> anyhow::Result<()> {
    let g = joined_ref(d, group)?;
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
        let them = member_named_ref(&core.contacts(), sp, who.as_ref())?;
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
            // An old oddity, kept to the byte (DEVIATIONS.md, Old oddities
            // kept): without `shown`, the member is shown by the ref as the
            // way by name held it, NUL and hex where it came as bytes.
            None => ops.push(group::create_member(
                &them,
                shown.unwrap_or(&who.held()),
                introduce.unwrap_or(true),
            )),
        }
        ops
    };
    d.write_and_push(&g.id, ops)?;
    d.bump();
    Ok(())
}

/// That this person may write in a group they are in, by its id, and its
/// members are being reached: before files are put in its folder.
pub(crate) fn ready_to_write(d: &Daemon, id: &SpaceId) -> anyhow::Result<()> {
    let g = joined(d, &hex::encode(id))?;
    may_write_in(d, &g)?;
    use_members(d, &g.id);
    Ok(())
}

/// A group this person is in, by id or name, with its name: for a call.
pub(crate) fn joined_group(d: &Daemon, group: &str) -> anyhow::Result<(SpaceId, String)> {
    let g = joined(d, group)?;
    Ok((g.id, g.name))
}

/// [`joined_group`], by a `ref` as it came.
pub(crate) fn joined_group_ref(d: &Daemon, group: Ref<'_>) -> anyhow::Result<(SpaceId, String)> {
    let g = joined_ref(d, group)?;
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

/// Those `call-start` `ring` names in group `space`, as contacts: each a
/// member who has not left, not this person, and their contact, not
/// refused. Where any is not, the request is refused, saying who and why
/// (`apps.md`, `call-start`).
pub(crate) fn to_ring(
    d: &Daemon,
    space: &SpaceId,
    named: &[api::typed::Reference],
) -> anyhow::Result<Vec<ContactRecord>> {
    anyhow::ensure!(!named.is_empty(), "`ring` names someone to ring");
    let me = identity(d)?;
    let core = d.core();
    let sp = core.spaces.get(space).and_then(|h| h.space.as_ref());
    let sp = sp.ok_or_else(|| anyhow::anyhow!("that group is not open yet"))?;
    let contacts = core.contacts();
    let mut out: Vec<ContactRecord> = Vec::new();
    for who in named {
        let who = who.as_ref();
        let shown = who;
        let them = member_named_ref(&contacts, sp, who)
            .map_err(|e| anyhow::anyhow!("{shown} cannot be rung: {e}"))?;
        anyhow::ensure!(them != me, "{shown} is you: you are not rung");
        anyhow::ensure!(
            !sp.has_left(&them),
            "{shown} has left {}, and is not rung",
            group::name(sp)
        );
        let c = contacts
            .iter()
            .find(|c| c.identity == them && !c.refused && c.recovery_of.is_none())
            .ok_or_else(|| {
                anyhow::anyhow!("{shown} is not a contact of yours: only your contacts are rung")
            })?;
        if !out.iter().any(|o| o.identity == them) {
            out.push(c.clone());
        }
    }
    Ok(out)
}

/// Where a `ring` in `space`, a group this person has been offered and has
/// not accepted, rings (`profiles.md#calls-guidance`, "Someone only offered
/// the group"): `from` is a contact, not refused, who wrote an offer of it
/// in the relationship the two share, and whose entry added this person in
/// the space that offer names; `space` is that space, or the successor of
/// it that this device follows, since an offer of a group is an offer of
/// the group that succeeds it, and nothing stands in its place here: a
/// ring naming a space that has ended does not ring; the person has not
/// declined it, nor joined it; and this device holds it open, showing them
/// both as members who have not left. Then the group's name. `None` where
/// any of that does not hold, as before the offer or the group has come.
///
/// An offer node alone says only that its author wrote it, which any
/// member who is a contact can do: who added this person is read from the
/// group itself.
pub(crate) fn offered_ring(d: &Daemon, space: &SpaceId, from: &[u8; 32]) -> Option<String> {
    let me = identity(d).ok()?;
    let core = d.core();
    core.contacts()
        .into_iter()
        .find(|c| c.identity == *from && !c.refused && c.recovery_of.is_none())?;
    if core.is_superseded(space) || core.is_declined(space) || core.is_joined(space) {
        return None;
    }
    let sp = core.spaces.get(space)?.space.as_ref()?;
    let member = |sp: &Space, w: &[u8; 32]| sp.role_of(w).is_some() && !sp.has_left(w);
    if sp.profile() != group::GROUP || sp.ended() || !member(sp, &me) || !member(sp, from) {
        return None;
    }
    // offers_from leaves out what was declined
    let offered = core.offers_from(from).into_iter().any(|o| {
        let named = core.spaces.get(&o.space).and_then(|h| h.space.as_ref());
        let added = named.is_some_and(|n| n.added_by_and_not_left(&me, from));
        added && core.current(&o.space) == *space && !core.is_declined(&o.space)
    });
    offered.then(|| group::name(sp))
}

/// Whether `space` could still become a group whose ring from `from` rings
/// here: it is not one this person declined, or joined, or holds open as
/// something else, or holds as one that has ended. A ring for it is kept a
/// while (`profiles.md#calls-guidance`).
pub(crate) fn may_be_offered(d: &Daemon, space: &SpaceId, from: &[u8; 32]) -> bool {
    let core = d.core();
    let contact = core
        .contacts()
        .into_iter()
        .any(|c| c.identity == *from && !c.refused && c.recovery_of.is_none());
    if !contact || core.is_declined(space) || core.is_joined(space) {
        return false;
    }
    if core.is_superseded(space) {
        return false;
    }
    match core.spaces.get(space).and_then(|h| h.space.as_ref()) {
        Some(sp) => sp.profile() == group::GROUP && !sp.ended(),
        None => true,
    }
}

/// Whether `space` is a group held here that this person has not joined.
pub(crate) fn only_offered(d: &Daemon, space: &SpaceId) -> bool {
    let core = d.core();
    let group = core
        .spaces
        .get(space)
        .and_then(|h| h.space.as_ref())
        .is_some_and(|sp| sp.profile() == group::GROUP);
    group && !core.is_joined(space)
}

/// The sessions with the devices of a group's members: the other members',
/// and this person's own other devices.
pub(crate) fn member_sessions(d: &Daemon, space: &SpaceId) -> Vec<cardinal_link::Session> {
    let members: Vec<[u8; 32]> = {
        let core = d.core();
        let me = core.identity.as_ref().map(|i| i.id());
        let sp = core.spaces.get(space).and_then(|h| h.space.as_ref());
        let mut members: Vec<[u8; 32]> = sp
            .map(|sp| {
                let present = sp.present().into_iter();
                present.filter(|m| Some(*m) != me).collect()
            })
            .unwrap_or_default();
        // what the person started before a recovery, which nobody is in
        // here until it stands again
        members.extend(core.own_fallen_with(space));
        members
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
                    // and the logs of everyone it names that are not here:
                    // without the owner's, the group cannot be judged, nor
                    // the offer shown (`spaces.md#holding-a-space`)
                    for w in core.offer_logs(&c.identity) {
                        if !core.others.contains_key(&w) {
                            v.push((cardinal_sync::identity_log_label(&w), c.identity));
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

    fn seen(me: u8, others: &[u8], contacts: &[u8], hosted: &[u8]) -> Seen {
        let id = |n: &u8| [*n; 32];
        Seen {
            me: [me; 32],
            others: others.iter().map(id).collect(),
            contacts: contacts.iter().map(id).collect(),
            hosted: hosted.iter().map(id).collect(),
        }
    }

    /// D89, Test Group, as Kids (2) sees it: Daniel (1) is a contact, and
    /// Claude (3) is not and names no host. While Daniel is in it, what
    /// Kids writes goes to him, who passes it on; once he has left,
    /// nothing carries it either way, and that is certain.
    #[test]
    fn a_member_sees_whom_nothing_connects_them_with() {
        let s = seen(2, &[1, 3], &[1], &[]);
        assert_eq!(s.way_to(&[1; 32]), Way::Contact);
        assert_eq!(s.way_to(&[3; 32]), Way::Through([1; 32]));
        assert!(s.reaches_me(&[3; 32]));
        // Daniel has left
        let s = seen(2, &[3], &[], &[]);
        assert_eq!(s.way_to(&[3; 32]), Way::None);
        assert!(!s.reaches_me(&[3; 32]));
        // Claude names a host: Kids reaches him there, and hears nothing
        // back, since Kids names none
        let s = seen(2, &[3], &[], &[3]);
        assert_eq!(s.way_to(&[3; 32]), Way::Host);
        assert!(!s.reaches_me(&[3; 32]));
        // Kids names one too
        let s = seen(2, &[3], &[], &[2, 3]);
        assert!(s.reaches_me(&[3; 32]));
        // someone else who names a host may pass it on
        let s = seen(2, &[3, 4], &[], &[4]);
        assert_eq!(s.way_to(&[3; 32]), Way::Through([4; 32]));
    }
}

// ---- The handlers as they were by name ----
//
// What main had, whole, kept only to show that the typed handlers send the
// same bytes (`control::typed::answering`, `api/same_bytes.rs`), and to
// measure the two. They go with the way by name.

/// `find` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
fn find_by_name(d: &Daemon, group: &str) -> anyhow::Result<Found> {
    find_among_by_name(d, group, false)
}

/// `find_among` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
fn find_among_by_name(d: &Daemon, group: &str, in_it: bool) -> anyhow::Result<Found> {
    let me = identity(d)?;
    let core = d.core();
    let mut all: Vec<Found> = Vec::new();
    // what an id this group had before stands for
    let mut was: Vec<(SpaceId, SpaceId)> = Vec::new();
    for (id, h) in &core.spaces {
        let Some(sp) = h.space.as_ref() else {
            continue;
        };
        // A group this person left is not theirs to find, until someone
        // adds them again.
        if sp.profile() != group::GROUP || sp.has_left(&me) {
            continue;
        }
        if core.is_superseded(id) {
            was.push((*id, core.current(id)));
            continue;
        }
        all.push(Found {
            id: *id,
            name: group::name(sp),
            joined: core.is_joined(id),
        });
    }
    all.retain(|g| g.joined || !in_it);
    // given as bytes: the group whose id it is, or the one in its place
    if let asked @ Ref::Id(_) = api::reference(group) {
        let now = was
            .iter()
            .find(|(old, _)| asked.is_id(old))
            .map(|(_, now)| *now);
        let id = now.or_else(|| all.iter().find(|g| asked.is_id(&g.id)).map(|g| g.id));
        return id
            .and_then(|id| all.into_iter().find(|g| g.id == id))
            .ok_or_else(|| anyhow::anyhow!("there is no group {}", api::shown(group)));
    }
    let start = group.to_ascii_lowercase();
    if group.len() >= 8 {
        let now = was
            .iter()
            .filter(|(old, _)| hex::encode(old).starts_with(&start));
        let now: Vec<SpaceId> = now.map(|(_, now)| *now).collect();
        if let Some(g) = now.first().and_then(|n| all.iter().find(|g| g.id == *n)) {
            return Ok(g.clone());
        }
    }
    pick(all, group, &core.declined())
}

/// `joined` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
fn joined_by_name(d: &Daemon, group: &str) -> anyhow::Result<Found> {
    match find_among_by_name(d, group, true) {
        Ok(g) => {
            // one that ended and has nothing here in its place
            if let (Some(why), _) = d.core().succession_news(&g.id) {
                anyhow::bail!("{} has ended: {why}", g.name);
            }
            Ok(g)
        }
        // say which it is: not there at all, or there and not joined
        Err(none) => match find_by_name(d, group) {
            Ok(g) => anyhow::bail!("you have not joined {}", g.name),
            Err(_) => Err(none),
        },
    }
}

/// `joined_group` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
pub(crate) fn joined_group_by_name(d: &Daemon, group: &str) -> anyhow::Result<(SpaceId, String)> {
    let g = joined_by_name(d, group)?;
    Ok((g.id, g.name))
}

/// `telling_json` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
fn telling_json_by_name(core: &Core, id: &SpaceId, me: &[u8; 32]) -> Json {
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

/// `member_fields` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
fn member_fields_by_name(
    me: &[u8; 32],
    contacts: &[ContactRecord],
    members: &[Member],
    m: &Member,
) -> Json {
    let contact = contacts
        .iter()
        .any(|c| c.identity == m.identity && !c.refused);
    json!({
        "name": name_of(me, contacts, members, &m.identity),
        "shown": m.name,
        "id": hex::encode(&m.identity[..8]),
        "you": m.identity == *me,
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
}

/// `call_json` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
pub(crate) fn call_json_by_name(d: &Daemon, space: &SpaceId, caller: Option<&[u8; 32]>) -> Json {
    let Ok(me) = identity(d) else {
        return json!({});
    };
    let core = d.core();
    let Some(sp) = core.spaces.get(space).and_then(|h| h.space.as_ref()) else {
        return json!({});
    };
    let members = group::members(sp);
    let contacts = core.contacts();
    let person = |m: &Member| {
        let known = contacts
            .iter()
            .find(|c| c.identity == m.identity && !c.refused);
        let v = member_fields_by_name(&me, &contacts, &members, m);
        shown_as_contact(d, &me, &contacts, &members, known, &m.identity, v)
    };
    let mut admins: Vec<&Member> = members
        .iter()
        .filter(|m| m.role >= group::ADMIN && !m.left)
        .collect();
    admins.sort_by_key(|m| std::cmp::Reverse(m.role == group::OWNER));
    let admins: Vec<Json> = admins.into_iter().map(person).collect();
    let caller = caller.and_then(|c| members.iter().find(|m| m.identity == *c).map(person));
    let joins = !core.is_joined(space);
    json!({
        "name": group::name(sp),
        "for_call": group::for_call(sp),
        "admins": admins,
        "caller": caller,
        "joins": joins.then_some(true),
        "reach": joins.then(|| telling_json_by_name(&core, space, &me)),
    })
}

/// `messages` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
pub fn messages_by_name(d: &Daemon, group: &str, before: Option<&str>) -> anyhow::Result<Json> {
    let g = find_by_name(d, group)?;
    use_members(d, &g.id);
    let me = identity(d)?;
    let core = d.core();
    let sp = core.spaces.get(&g.id).and_then(|h| h.space.as_ref());
    let sp = sp.ok_or_else(|| anyhow::anyhow!("that group is not open yet"))?;
    let all = relationship::messages(sp);
    let members = group::members(sp);
    let named = named_in(sp);
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
    let upto = contacts::upto_by_name(sp, &all, before)?;
    let said: Vec<Json> = all
        .iter()
        .take(upto)
        .enumerate()
        .map(|(i, m)| {
            let mine = m.author == me;
            let read = others.iter().filter(|o| read_by[*o][i]).count();
            let picture = contacts
                .iter()
                .find(|c| c.identity == m.author && !c.refused && !mine)
                .and_then(|c| crate::names::shown_by_name(d, c).remove("picture"));
            json!({
                "picture": picture,
                "id": hex::encode(m.id),
                "mine": mine,
                "from": name_of(&me, &contacts, &named, &m.author),
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
                "reactions": contacts::reactions_of_by_name(m, Some(me)),
            })
        })
        .collect();
    Ok(json!({"group": hex::encode(g.id), "name": g.name, "messages": said}))
}

/// `to_ring` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
pub(crate) fn to_ring_by_name(
    d: &Daemon,
    space: &SpaceId,
    named: &[String],
) -> anyhow::Result<Vec<ContactRecord>> {
    anyhow::ensure!(!named.is_empty(), "`ring` names someone to ring");
    let me = identity(d)?;
    let core = d.core();
    let sp = core.spaces.get(space).and_then(|h| h.space.as_ref());
    let sp = sp.ok_or_else(|| anyhow::anyhow!("that group is not open yet"))?;
    let contacts = core.contacts();
    let mut out: Vec<ContactRecord> = Vec::new();
    for who in named {
        let shown = api::shown(who);
        let them = member_named_by_name(&contacts, sp, who)
            .map_err(|e| anyhow::anyhow!("{shown} cannot be rung: {e}"))?;
        anyhow::ensure!(them != me, "{shown} is you: you are not rung");
        anyhow::ensure!(
            !sp.has_left(&them),
            "{shown} has left {}, and is not rung",
            group::name(sp)
        );
        let c = contacts
            .iter()
            .find(|c| c.identity == them && !c.refused && c.recovery_of.is_none())
            .ok_or_else(|| {
                anyhow::anyhow!("{shown} is not a contact of yours: only your contacts are rung")
            })?;
        if !out.iter().any(|o| o.identity == them) {
            out.push(c.clone());
        }
    }
    Ok(out)
}

/// `people` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
fn people_by_name(d: &Daemon, who: &[String]) -> anyhow::Result<Vec<ContactRecord>> {
    who.iter().map(|w| contacts::listed_by_name(d, w)).collect()
}

/// `create` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
pub fn create_by_name(
    d: &Arc<Daemon>,
    name: &str,
    who: &[String],
    for_call: bool,
    history: bool,
) -> anyhow::Result<Json> {
    let name = name.trim();
    anyhow::ensure!(!name.is_empty(), "a group needs a name");
    let theirs = people_by_name(d, who)?;
    let me_as = crate::names::my_name(d);
    let members: Vec<([u8; 32], String)> = theirs
        .iter()
        .map(|c| (c.identity, offered_as(c).to_owned()))
        .collect();
    let id = d
        .core()
        .create_group_with(name, &me_as, &members, for_call, history)?;
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

/// `add` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
pub fn add_by_name(
    d: &Arc<Daemon>,
    group: &str,
    who: &[String],
    shown: Option<&str>,
) -> anyhow::Result<Json> {
    let g = joined_by_name(d, group)?;
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
        shares_history(sp, &g.name)?;
    }
    let theirs = people_by_name(d, who)?;
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

/// `member_named` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
fn member_named_by_name(
    contacts: &[ContactRecord],
    sp: &Space,
    who: &str,
) -> anyhow::Result<[u8; 32]> {
    let in_it = |id: &[u8; 32]| sp.validity().members.iter().any(|m| m.identity == *id);
    if let asked @ Ref::Id(_) = api::reference(who) {
        // one identity may be named with several roles
        let mut found: Vec<[u8; 32]> = sp.validity().members.iter().map(|m| m.identity).collect();
        found.retain(|id| asked.is_id(id));
        found.sort();
        found.dedup();
        let who = api::shown(who);
        return match found.as_slice() {
            [id] => Ok(*id),
            [] => anyhow::bail!("nobody in it has the id {who}"),
            _ => anyhow::bail!("more than one in it has an id starting {who}: give it whole"),
        };
    }
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

/// `remove` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
pub async fn remove_by_name(d: &Arc<Daemon>, group: &str, who: &str) -> anyhow::Result<Json> {
    let g = joined_by_name(d, group)?;
    let me = identity(d)?;
    let (them, owner) = {
        let core = d.core();
        let contacts = core.contacts();
        let sp = core.spaces.get(&g.id).and_then(|h| h.space.as_ref());
        let sp = sp.ok_or_else(|| anyhow::anyhow!("that group is not open yet"))?;
        (member_named_by_name(&contacts, sp, who)?, sp.owner())
    };
    anyhow::ensure!(them != me, "to leave {}, leave it", g.name);
    anyhow::ensure!(
        owner == Some(me),
        "only the owner of {} can take someone out of it",
        g.name
    );
    let done = crate::following::succeed(d, &g.id, |sp| {
        anyhow::ensure!(
            sp.role_of(&them).is_some(),
            "{who} is not in {} any more",
            g.name
        );
        Ok(staying(sp, Some(&them), None))
    })
    .await?;
    Ok(json!({
        "group": hex::encode(done.new),
        "was": hex::encode(g.id),
        "left_out": done.left_out.iter().map(hex::encode).collect::<Vec<_>>(),
    }))
}

/// `set_role` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
pub async fn set_role_by_name(
    d: &Arc<Daemon>,
    group: &str,
    who: &str,
    role: &str,
) -> anyhow::Result<Json> {
    let role = role_named(role)?;
    let g = joined_by_name(d, group)?;
    let me = identity(d)?;
    let (them, now, owner, mine) = {
        let core = d.core();
        let contacts = core.contacts();
        let sp = core.spaces.get(&g.id).and_then(|h| h.space.as_ref());
        let sp = sp.ok_or_else(|| anyhow::anyhow!("that group is not open yet"))?;
        let them = member_named_by_name(&contacts, sp, who)?;
        // Someone who left comes back by `group-add` or `group-rejoin`,
        // never by being given a role (`apps.md`, `group-role`).
        anyhow::ensure!(
            !sp.has_left(&them),
            "{} has left {}: a role is not given to someone who left. They come back by being \
             added again, or by rejoining",
            api::shown(who),
            g.name
        );
        (them, sp.role_of(&them), sp.owner(), sp.role_of(&me))
    };
    anyhow::ensure!(them != me, "you cannot change your own role");
    let now = now.ok_or_else(|| anyhow::anyhow!("{who} is not in {}", g.name))?;
    if role == now {
        return Ok(json!({"group": hex::encode(g.id)}));
    }
    if role > now {
        anyhow::ensure!(
            mine.is_some_and(|r| r >= group::ADMIN),
            "only an admin of {} can give someone a role",
            g.name
        );
        d.write_and_push(&g.id, vec![SpaceOp::add_member(them, role)])?;
        d.bump();
        return Ok(json!({"group": hex::encode(g.id)}));
    }
    anyhow::ensure!(
        owner == Some(me),
        "only the owner of {} can lower someone's role",
        g.name
    );
    let done = crate::following::succeed(d, &g.id, |sp| Ok(staying(sp, None, Some((&them, role)))))
        .await?;
    Ok(json!({"group": hex::encode(done.new), "was": hex::encode(g.id)}))
}

/// `leave` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
pub fn leave_by_name(
    d: &Arc<Daemon>,
    group: &str,
    admins: &[String],
    anyway: bool,
) -> anyhow::Result<Json> {
    let g = joined_by_name(d, group)?;
    let me = identity(d)?;
    let (made, names) = {
        let core = d.core();
        let sp = core.spaces.get(&g.id).and_then(|h| h.space.as_ref());
        let sp = sp.ok_or_else(|| anyhow::anyhow!("that group is not open yet"))?;
        anyhow::ensure!(sp.role_of(&me).is_some(), "you are not in {}", g.name);
        let contacts = core.contacts();
        let members = group::members(sp);
        let mut made: Vec<[u8; 32]> = Vec::new();
        for who in admins {
            let them = member_named_by_name(&contacts, sp, who)?;
            anyhow::ensure!(them != me, "you are leaving {}: name someone else", g.name);
            anyhow::ensure!(
                !sp.has_left(&them),
                "{who} has left {}: name someone still in it",
                g.name
            );
            if !made.contains(&them) {
                made.push(them);
            }
        }
        anyhow::ensure!(
            made.is_empty() || may_manage(sp, &me),
            "only an admin of {} can make someone an admin",
            g.name
        );
        let names: Vec<String> = made
            .iter()
            .map(|m| name_of(&me, &contacts, &members, m))
            .collect();
        let left = Leaving::of(&core, &g.id, sp, &me);
        if left.choose_admin && made.is_empty() {
            let others: Vec<String> = left.others.iter().map(|(_, n)| n.clone()).collect();
            anyhow::bail!(
                "Who looks after {name}? You own it, and once you leave nobody in it can add \
                 anyone, you included. Choose one or more of {who} to be its admins: \
                 cardinal group leave {name} --admin <member>",
                name = g.name,
                who = others.join(", "),
            );
        }
        if !left.relayed_for.is_empty() && !anyway {
            anyhow::bail!(
                "{} Introduce them first (cardinal introduce <who> <to>), or leave {} anyway: \
                 --anyway",
                relayed_warning(&left.relayed_for, &g.name),
                g.name
            );
        }
        (made, names)
    };
    let mut ops: Vec<SpaceOp> = made
        .iter()
        .map(|m| SpaceOp::add_member(*m, group::ADMIN))
        .collect();
    ops.extend(relationship::leave_ops(&me));
    d.write_and_push(&g.id, ops)?;
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
    Ok(json!({"admins": names}))
}

/// `left_any` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
fn left_any_by_name(core: &Core, me: &[u8; 32], group: &str) -> bool {
    let all: Vec<Found> = core
        .spaces
        .iter()
        .filter_map(|(id, h)| {
            let sp = h.space.as_ref()?;
            (sp.profile() == group::GROUP && sp.has_left(me) && !core.is_superseded(id)).then(
                || Found {
                    id: *id,
                    name: group::name(sp),
                    joined: false,
                },
            )
        })
        .collect();
    pick(all, group, &[]).is_ok()
}

/// `rejoin` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
pub fn rejoin_by_name(d: &Arc<Daemon>, group: &str) -> anyhow::Result<Json> {
    let me = identity(d)?;
    let (found, left_some) = {
        let core = d.core();
        let found = pick(left_groups(&core, &me), group, &[]);
        (found, left_any_by_name(&core, &me, group))
    };
    let g = match found {
        Ok(g) => g,
        Err(e) => {
            if let Ok(g) = find_by_name(d, group) {
                anyhow::bail!("you are in {} already", g.name);
            }
            // left, and not one who looks after it
            anyhow::ensure!(
                !left_some,
                "only an owner or admin of {group} can add themselves back: ask one of them \
                 to add you"
            );
            return Err(e);
        }
    };
    {
        let core = d.core();
        let sp = core.spaces.get(&g.id).and_then(|h| h.space.as_ref());
        let sp = sp.ok_or_else(|| anyhow::anyhow!("that group is not open yet"))?;
        shares_history(sp, &g.name)?;
    }
    d.write_and_push(&g.id, vec![SpaceOp::add_member(me, group::ADMIN)])?;
    d.bump();
    Ok(json!({"group": hex::encode(g.id), "name": g.name}))
}

/// `question` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
fn question_by_name(reach: &Json, name: &str) -> String {
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

/// `join` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
pub async fn join_by_name(
    d: &Arc<Daemon>,
    group: &str,
    reach: Option<bool>,
) -> anyhow::Result<Json> {
    let g = find_by_name(d, group)?;
    join_found_by_name(d, g, reach).await
}

/// `join_exact` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
pub(crate) async fn join_exact_by_name(
    d: &Arc<Daemon>,
    id: &SpaceId,
    reach: Option<bool>,
) -> anyhow::Result<Json> {
    let me = identity(d)?;
    let g = {
        let core = d.core();
        let sp = core.spaces.get(id).and_then(|h| h.space.as_ref());
        let sp = sp.filter(|sp| sp.profile() == group::GROUP && !sp.has_left(&me));
        let sp = sp.filter(|_| !core.is_superseded(id));
        let sp = sp.ok_or_else(|| anyhow::anyhow!("that group is not here to join"))?;
        Found {
            id: *id,
            name: group::name(sp),
            joined: core.is_joined(id),
        }
    };
    join_found_by_name(d, g, reach).await
}

/// `join_found` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
async fn join_found_by_name(
    d: &Arc<Daemon>,
    g: Found,
    reach: Option<bool>,
) -> anyhow::Result<Json> {
    if g.joined {
        return Ok(json!({}));
    }
    let me = identity(d)?;
    let (t, telling) = {
        let core = d.core();
        (core.telling(&g.id), telling_json_by_name(&core, &g.id, &me))
    };
    anyhow::ensure!(
        !t.ask() || reach.is_some(),
        "{}",
        question_by_name(&telling, &g.name)
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

/// `set_reach` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
pub async fn set_reach_by_name(d: &Arc<Daemon>, group: &str, share: bool) -> anyhow::Result<Json> {
    use crate::mailbox::Shared;
    let g = joined_by_name(d, group)?;
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

/// `no_host` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
pub async fn no_host_by_name(d: &Arc<Daemon>, group: &str, host: &str) -> anyhow::Result<Json> {
    let g = joined_by_name(d, group)?;
    let key = crate::mailbox::host_by_name(d, host)?;
    let named = crate::mailbox::take_out_host(d, &g.id, &key).await?;
    d.bump();
    Ok(json!({"taken_out": named}))
}

/// `decline` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
pub fn decline_by_name(d: &Arc<Daemon>, group: &str) -> anyhow::Result<Json> {
    let g = find_by_name(d, group)?;
    anyhow::ensure!(!g.joined, "you are in {}: leave it instead", g.name);
    let account = d
        .core()
        .account_id()
        .ok_or_else(|| anyhow::anyhow!("the account space is not here yet"))?;
    let op = cardinal_space::account::create_declined(&g.id, &g.name);
    d.write_and_push(&account, vec![op])?;
    // A call there that rings stops: a ring in a declined group does not
    // ring (`profiles.md#calls-guidance`). The person's other devices stop
    // once the decline reaches them.
    crate::calls::stop_ringing_in(d, &g.id, true);
    d.bump();
    Ok(json!({}))
}

/// `set` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
pub fn set_by_name(
    d: &Arc<Daemon>,
    group: &str,
    name: Option<&str>,
    introductions: Option<bool>,
    for_call: Option<bool>,
) -> anyhow::Result<Json> {
    // Only a genesis makes a group one made for a call: refused before
    // anything is written.
    anyhow::ensure!(
        for_call != Some(true),
        "only a new group is made for a call: make one with group-create"
    );
    let g = joined_by_name(d, group)?;
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
        // "Keep this group": where it is not one made for a call, nothing
        if for_call == Some(false) && group::for_call(sp) {
            ops.push(group::keep_group(c));
        }
        ops
    };
    if !ops.is_empty() {
        d.write_and_push(&g.id, ops)?;
    }
    d.bump();
    Ok(json!({}))
}

/// `set_member` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
pub fn set_member_by_name(
    d: &Arc<Daemon>,
    group: &str,
    who: &str,
    shown: Option<&str>,
    introduce: Option<bool>,
) -> anyhow::Result<Json> {
    let g = joined_by_name(d, group)?;
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
        let them = member_named_by_name(&core.contacts(), sp, who)?;
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

/// `say` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
pub async fn say_by_name(
    d: &Arc<Daemon>,
    group: &str,
    text: &str,
    reply_to: Option<&str>,
    attach: &[String],
) -> anyhow::Result<Json> {
    let g = joined_by_name(d, group)?;
    may_write_in(d, &g)?;
    use_members(d, &g.id);
    let to = match reply_to {
        Some(id) => Some(message_in_by_name(d, &g.id, id)?.id),
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

/// `message_in` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
fn message_in_by_name(
    d: &Daemon,
    space: &SpaceId,
    id: &str,
) -> anyhow::Result<relationship::Message> {
    let id = hex::decode(api::id_hex(id)).ok();
    let id = id.and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok());
    let id = id.ok_or_else(|| anyhow::anyhow!("that is not a message"))?;
    let core = d.core();
    let sp = core.spaces.get(space).and_then(|h| h.space.as_ref());
    let sp = sp.ok_or_else(|| anyhow::anyhow!("that group is not open yet"))?;
    // a message posted again has a new id, and the old one names it
    let now = sp.state().now_called(&id).unwrap_or(id);
    let found = relationship::messages(sp).into_iter().find(|m| m.id == now);
    found.ok_or_else(|| anyhow::anyhow!("there is no such message"))
}

/// `save_attachment` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
pub async fn save_attachment_by_name(
    d: &Arc<Daemon>,
    group: &str,
    id: &str,
    index: usize,
    to: &str,
) -> anyhow::Result<Json> {
    let g = find_by_name(d, group)?;
    let m = message_in_by_name(d, &g.id, id)?;
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

/// `own_message` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
fn own_message_by_name(
    d: &Daemon,
    space: &SpaceId,
    id: &str,
) -> anyhow::Result<relationship::Message> {
    let m = message_in_by_name(d, space, id)?;
    anyhow::ensure!(
        m.author == identity(d)?,
        "only what you wrote can be changed"
    );
    Ok(m)
}

/// `edit_message` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
pub fn edit_message_by_name(
    d: &Arc<Daemon>,
    group: &str,
    id: &str,
    text: &str,
) -> anyhow::Result<Json> {
    let g = joined_by_name(d, group)?;
    may_write_in(d, &g)?;
    let m = own_message_by_name(d, &g.id, id)?;
    anyhow::ensure!(!text.trim().is_empty(), "a message cannot be empty");
    d.write_and_push(&g.id, vec![relationship::edit_message(m.id, text)])?;
    Ok(json!({}))
}

/// `delete_message` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
pub fn delete_message_by_name(d: &Arc<Daemon>, group: &str, id: &str) -> anyhow::Result<Json> {
    let g = joined_by_name(d, group)?;
    may_write_in(d, &g)?;
    let m = own_message_by_name(d, &g.id, id)?;
    d.write_and_push(&g.id, vec![SpaceOp::delete(m.id)])?;
    Ok(json!({}))
}

/// `react` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
pub fn react_by_name(d: &Arc<Daemon>, group: &str, id: &str, text: &str) -> anyhow::Result<Json> {
    let g = joined_by_name(d, group)?;
    may_write_in(d, &g)?;
    let m = message_in_by_name(d, &g.id, id)?;
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

/// `mark_read` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
pub fn mark_read_by_name(d: &Arc<Daemon>, group: &str) -> anyhow::Result<Json> {
    let g = joined_by_name(d, group)?;
    contacts::mark_read_in_by_name(d, &g.id, &g.name)
}
