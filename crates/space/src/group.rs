//! The group profile (`profiles.md#group`): any number of members, the
//! relationship kinds, and a member node for each with the name the others
//! see. The offer of a group goes in a relationship space.

use cardinal_encoding::{Record, Value};

use crate::entry::{IdentityId, NodeId, NodeKind, Profile, SpaceId, SpaceOp};
use crate::relationship::{conversation, CONVERSATION};
use crate::space::Space;
use crate::state::{Node, State, ROOT};

/// The group profile.
pub const GROUP: Profile = Profile::Core(4);
/// Offer kind, in a relationship space.
pub const OFFER: u64 = 10;
/// Member kind.
pub const MEMBER: u64 = 11;
/// The reader role.
pub const READER: u64 = 0;
/// The writer role: what someone added is, unless made more.
pub const WRITER: u64 = 1;
/// The admin role.
pub const ADMIN: u64 = 2;
/// The owner role.
pub const OWNER: u64 = 3;

/// What a group's genesis holds besides its members: the conversation,
/// named for the group.
pub fn genesis_ops(name: &str) -> Vec<SpaceOp> {
    vec![SpaceOp::create(
        NodeKind::Uint(CONVERSATION),
        ROOT,
        "conversation",
        Record::new().with(1, name),
    )]
}

/// `create` of a member node: the name the others see, and whether they are
/// to be introduced through the group.
pub fn create_member(who: &IdentityId, name: &str, introduce: bool) -> SpaceOp {
    let fields = Record::new().with(1, *who).with(2, name);
    let fields = if introduce {
        fields
    } else {
        fields.with(3, false)
    };
    SpaceOp::create(NodeKind::Uint(MEMBER), ROOT, "member", fields)
}

/// Changes the name the others see for a member.
pub fn set_member_name(member: NodeId, name: &str) -> SpaceOp {
    SpaceOp::set(member, 2, Some(Value::from(name)))
}

/// Says whether a member is introduced through the group.
pub fn set_member_introduce(member: NodeId, introduce: bool) -> SpaceOp {
    SpaceOp::set(member, 3, Some(Value::from(introduce)))
}

/// Renames the group.
pub fn rename(conversation: NodeId, name: &str) -> SpaceOp {
    SpaceOp::set(conversation, 1, Some(Value::from(name)))
}

/// Says whether members are introduced through the group.
pub fn set_introductions(conversation: NodeId, on: bool) -> SpaceOp {
    SpaceOp::set(conversation, 2, Some(Value::from(on)))
}

/// `create` of an offer of a space, in a relationship space.
pub fn create_offer(space: &SpaceId, name: &str, profile: u64) -> SpaceOp {
    SpaceOp::create(
        NodeKind::Uint(OFFER),
        ROOT,
        "offer",
        Record::new().with(1, *space).with(2, name).with(3, profile),
    )
}

/// An offer of a space, as a relationship space holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Offer {
    /// Its node.
    pub node: NodeId,
    /// The space offered.
    pub space: SpaceId,
    /// Its name, as whoever made the offer gives it.
    pub name: String,
    /// Who made it.
    pub from: IdentityId,
}

/// The offers in a relationship space.
pub fn offers(state: &State) -> Vec<Offer> {
    let nodes = state.children(&ROOT).into_iter();
    nodes
        .filter(|n| n.kind == NodeKind::Uint(OFFER) && !n.deleted)
        .filter_map(|n| {
            let space: SpaceId = last(n, 1)?.as_bytes()?.try_into().ok()?;
            let name = last(n, 2).and_then(Value::as_text).unwrap_or("").to_owned();
            Some(Offer {
                node: n.id,
                space,
                name,
                from: n.creator,
            })
        })
        .collect()
}

/// A field's current value, the last by entry when in conflict.
fn last(n: &Node, key: u64) -> Option<&Value> {
    n.values(key).iter().rev().find_map(|v| v.value.as_ref())
}

/// The role of `who` in a space now: the highest of their memberships.
pub fn role_of(space: &Space, who: &IdentityId) -> Option<u64> {
    let members = space.validity().members.iter();
    members.filter(|m| m.identity == *who).map(|m| m.role).max()
}

/// A field's current value among those an admin or owner set: nobody else's
/// say counts on a member node or the group's settings.
fn admins_value<'a>(space: &'a Space, n: &'a Node, key: u64) -> Option<&'a Value> {
    let dag = space.dag();
    n.values(key).iter().rev().find_map(|v| {
        let author = dag.get(&v.entry)?.author();
        let counts = role_of(space, &author).is_some_and(|r| r >= ADMIN) || author == space.owner();
        counts.then_some(v.value.as_ref()).flatten()
    })
}

/// A member of a group, as the others see them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    /// Their identity.
    pub identity: IdentityId,
    /// Their role.
    pub role: u64,
    /// The name an admin gave them, if one did.
    pub name: Option<String>,
    /// Whether they are introduced through the group.
    pub introduce: bool,
    /// Their member node, to change.
    pub node: Option<NodeId>,
}

/// The members of a group, with the names and settings admins gave them.
pub fn members(space: &Space) -> Vec<Member> {
    let state = space.state();
    let nodes: Vec<&Node> = state
        .children(&ROOT)
        .into_iter()
        .filter(|n| n.kind == NodeKind::Uint(MEMBER) && !n.deleted)
        .collect();
    let mut out: Vec<Member> = Vec::new();
    for m in &space.validity().members {
        if let Some(seen) = out.iter_mut().find(|x| x.identity == m.identity) {
            seen.role = seen.role.max(m.role);
            continue;
        }
        let node = nodes.iter().find(|n| {
            admins_value(space, n, 1)
                .and_then(Value::as_bytes)
                .is_some_and(|b| b == m.identity.as_slice())
        });
        let name = node
            .and_then(|n| admins_value(space, n, 2))
            .and_then(Value::as_text)
            .map(str::to_owned);
        let introduce = node
            .and_then(|n| admins_value(space, n, 3))
            .and_then(Value::as_bool)
            .unwrap_or(true);
        out.push(Member {
            identity: m.identity,
            role: m.role,
            name,
            introduce,
            node: node.map(|n| n.id),
        });
    }
    out
}

/// A group's name.
pub fn name(space: &Space) -> String {
    let Some(c) = conversation(space) else {
        return String::new();
    };
    let state = space.state();
    let Some(n) = state.node(&c) else {
        return String::new();
    };
    admins_value(space, n, 1)
        .and_then(Value::as_text)
        .unwrap_or("")
        .to_owned()
}

/// Whether members are introduced through the group.
pub fn introductions(space: &Space) -> bool {
    let Some(c) = conversation(space) else {
        return true;
    };
    let state = space.state();
    let n = state.node(&c);
    n.and_then(|n| admins_value(space, n, 2))
        .and_then(Value::as_bool)
        .unwrap_or(true)
}

/// Whether `who` has written anything in a space: that is joining it
/// (`spaces.md#holding-a-space`).
pub fn joined(space: &Space, who: &IdentityId) -> bool {
    space.owner() == *who
        || space
            .dag()
            .iter()
            .any(|(id, e)| e.author() == *who && space.validity().is_valid(id))
}
