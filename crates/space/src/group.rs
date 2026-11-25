//! The group profile (`profiles.md#group`): one owner, whoever made it, and
//! any number of members with the other roles; the relationship kinds, and
//! a member node for each with the name the others see. The offer of a group
//! goes in a relationship space.

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
pub use crate::entry::{ADMIN, OWNER, READER, WRITER};

/// What a group's genesis holds besides `start`: whoever makes it as its
/// owner, the conversation, named for the group, and then the members it
/// starts with.
pub fn genesis_ops(owner: IdentityId, name: &str) -> Vec<SpaceOp> {
    genesis_ops_for(owner, name, false)
}

/// [`genesis_ops`], and with `for_call` a group [made for a
/// call](`profiles.md#a-group-made-for-a-call`): the conversation node is
/// created with field 3 true.
pub fn genesis_ops_for(owner: IdentityId, name: &str, for_call: bool) -> Vec<SpaceOp> {
    let fields = Record::new().with(1, name);
    let fields = if for_call {
        fields.with(FOR_CALL, true)
    } else {
        fields
    };
    vec![
        SpaceOp::add_member(owner, OWNER),
        SpaceOp::create(NodeKind::Uint(CONVERSATION), ROOT, "conversation", fields),
    ]
}

/// The conversation node's field that says a group was made for a call.
pub const FOR_CALL: u64 = 3;

/// Whether a group was [made for a call](`profiles.md#a-group-made-for-a-call`):
/// field 3 of its conversation node holds exactly one value, the group's
/// own genesis (the entry whose id is the space's) wrote it, and it is the
/// bool true. Any other write there, by anyone and of any value, a clearing
/// `set` among them, makes it an ordinary group; and a value a successor
/// carried was written in another space, so counts for nothing here.
pub fn for_call(space: &Space) -> bool {
    let Some(c) = conversation(space) else {
        return false;
    };
    let state = space.state();
    let Some(n) = state.node(&c) else {
        return false;
    };
    match n.values(FOR_CALL) {
        [only] => only.entry == space.id() && only.value == Some(Value::from(true)),
        _ => false,
    }
}

/// "Keep this group": field 3 of the conversation node set to false, which
/// nothing in the group undoes.
pub fn keep_group(conversation: NodeId) -> SpaceOp {
    SpaceOp::set(conversation, FOR_CALL, Some(Value::from(false)))
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

/// `create` of an offer of a space of any profile, in a relationship
/// space: field 3 a core profile's number or an application's name.
pub fn create_offer_of(space: &SpaceId, name: &str, profile: Profile) -> SpaceOp {
    let profile = match profile {
        Profile::Core(n) => Value::from(n),
        Profile::Named(h) => Value::from(h),
    };
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

/// The role of `who` in a space: the highest a valid entry gave them.
pub fn role_of(space: &Space, who: &IdentityId) -> Option<u64> {
    space.role_of(who)
}

/// A field's current value among those an admin or the owner set: nobody
/// else's say counts on a member node or the group's settings.
fn admins_value<'a>(space: &'a Space, n: &'a Node, key: u64) -> Option<&'a Value> {
    let dag = space.dag();
    n.values(key).iter().rev().find_map(|v| {
        // A value a successor carried was judged where it was written,
        // and the owner, who wrote the successor, stands behind it
        // (`spaces.md#what-comes-across`).
        // A value a successor carried counts for nothing by itself: who
        // wrote it is not here to judge. The owner sets these fields again,
        // as the old space resolved them, in the successor's genesis
        // ([`reassert_ops`]).
        let counts = match dag.get(&v.entry) {
            Some(e) => role_of(space, &e.author()).is_some_and(|r| r >= ADMIN),
            None => false,
        };
        counts.then_some(v.value.as_ref()).flatten()
    })
}

/// What the owner writes in the genesis of a successor of the group `old`, whose
/// initial state is `carried`: each field on which only an admin's say
/// counts (the group's name and introductions, and each member node's
/// identity, name and introduction), set to what `old` resolves it to, or
/// cleared where nothing an admin said stands. A value the successor
/// carried counts for nothing by itself, since who wrote it cannot be told
/// there; without this, what a writer set on those fields would count
/// after any succession.
pub fn reassert_ops(old: &Space, carried: &State) -> Vec<SpaceOp> {
    let state = old.state();
    let mut fields: Vec<(&Node, &[u64])> = Vec::new();
    if let Some(c) = conversation(old).and_then(|c| state.node(&c)) {
        fields.push((c, &[1, 2]));
    }
    for n in state.children(&ROOT) {
        if n.kind == NodeKind::Uint(MEMBER) && !n.deleted {
            fields.push((n, &[1, 2, 3]));
        }
    }
    let mut ops = Vec::new();
    // Made for a call at the cut, the successor is one too, by its own
    // genesis: what it carried there counts for nothing.
    if for_call(old) {
        if let Some(c) = conversation(old).filter(|c| carried.node(c).is_some()) {
            ops.push(SpaceOp::set(c, FOR_CALL, Some(Value::from(true))));
        }
    }
    for (n, keys) in fields {
        let Some(there) = carried.node(&n.id) else {
            continue;
        };
        for key in keys {
            if there.values(*key).is_empty() {
                continue;
            }
            ops.push(SpaceOp::set(
                n.id,
                *key,
                admins_value(old, n, *key).cloned(),
            ));
        }
    }
    ops
}

/// A member of a group, as the others see them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    /// Their identity.
    pub identity: IdentityId,
    /// Their role: the highest they were given.
    pub role: u64,
    /// They said they have left, and nobody has added them since.
    pub left: bool,
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
            left: space.has_left(&m.identity),
            name,
            introduce,
            node: node.map(|n| n.id),
        });
    }
    out
}

/// Those a group has a member node for who are not its members: people
/// taken out of it when it was succeeded, whose node the successor carried
/// (`spaces.md#what-comes-across`). Display only: the name the others saw,
/// so that what they wrote before still shows who wrote it. Their role is
/// none here, and is given as a reader's; they have not left, they were
/// taken out.
pub fn taken_out(space: &Space) -> Vec<Member> {
    let state = space.state();
    let mut out: Vec<Member> = Vec::new();
    for n in state.children(&ROOT) {
        if n.kind != NodeKind::Uint(MEMBER) || n.deleted {
            continue;
        }
        let who = admins_value(space, n, 1).and_then(Value::as_bytes);
        let Some(who) = who.and_then(|b| IdentityId::try_from(b).ok()) else {
            continue;
        };
        if space.role_of(&who).is_some() || out.iter().any(|m| m.identity == who) {
            continue;
        }
        out.push(Member {
            identity: who,
            role: READER,
            left: false,
            name: admins_value(space, n, 2)
                .and_then(Value::as_text)
                .map(str::to_owned),
            introduce: false,
            node: Some(n.id),
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

/// Whether `who` is in a group by their own doing: they wrote something
/// valid in it, which is joining it (`spaces.md#holding-a-space`), and have
/// not left it since. Someone who left and was added again has been offered
/// it again, and has not joined until they write in it again.
pub fn joined(space: &Space, who: &IdentityId) -> bool {
    space.accepted_by(who)
}
