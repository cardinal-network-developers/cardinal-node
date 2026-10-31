//! The relationship profile (`profiles.md#relationship`): two identities,
//! both owners, and a conversation between them.

use cardinal_encoding::{Record, Value};

use crate::account::short_key;
use crate::entry::{IdentityId, NodeId, NodeKind, SpaceOp};
use crate::grant::Endpoint;
use crate::space::Space;
use crate::state::{Node, State, AUTHOR_OWNED_FIELD, ROOT};

/// Conversation kind.
pub const CONVERSATION: u64 = 1;
/// Message kind.
pub const MESSAGE: u64 = 2;
/// The owner role (`spaces.md#memberships`).
pub const OWNER: u64 = 3;
/// Reach kind.
pub const REACH: u64 = 9;

/// One of a member's hosts, and how anyone else uses it
/// (`profiles.md#reach`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reach {
    /// Where the host listens.
    pub endpoints: Vec<Endpoint>,
    /// The host's X25519 static key.
    pub host: [u8; 32],
    /// A delivery token for this space.
    pub token: [u8; 16],
}

fn reach_list(reach: &[Reach]) -> Value {
    Value::list(reach.iter().map(|r| {
        let endpoints = r.endpoints.iter().map(|e| Value::Record(e.to_record()));
        Value::Record(
            Record::new()
                .with(1, Value::list(endpoints))
                .with(2, r.host)
                .with(3, r.token),
        )
    }))
}

fn read_reach(r: &Record) -> Option<Reach> {
    let endpoints = r.record_list(1).ok()?;
    Some(Reach {
        endpoints: endpoints
            .into_iter()
            .filter_map(Endpoint::from_record)
            .collect(),
        host: r.get(2)?.as_bytes()?.try_into().ok()?,
        token: r.get(3)?.as_bytes()?.try_into().ok()?,
    })
}

/// `create` of this member's reach node.
pub fn create_reach(author: &IdentityId, reach: &[Reach]) -> SpaceOp {
    SpaceOp::create(
        NodeKind::Uint(REACH),
        ROOT,
        &short_key(author),
        Record::new()
            .with(1, reach_list(reach))
            .with(AUTHOR_OWNED_FIELD, 1u64),
    )
}

/// Replaces what a reach node says.
pub fn set_reach(node: NodeId, reach: &[Reach]) -> SpaceOp {
    SpaceOp::set(node, 1, Some(reach_list(reach)))
}

/// The reach node `who` wrote, with where it says they are.
pub fn reach_of(state: &State, who: &IdentityId) -> Option<(NodeId, Vec<Reach>)> {
    let nodes = state.children(&ROOT).into_iter();
    let mut mine = nodes.filter(|n| n.kind == NodeKind::Uint(REACH) && !n.deleted);
    let node = mine.find(|n| n.creator == *who)?;
    let list = node.field(1).and_then(Value::as_list).unwrap_or_default();
    let reach = list.iter().filter_map(|v| read_reach(v.as_record()?));
    Some((node.id, reach.collect()))
}

/// What a relationship's genesis entry holds besides `start`: the other
/// identity, as an owner, and the one conversation.
pub fn genesis_ops(other: IdentityId) -> Vec<SpaceOp> {
    vec![
        SpaceOp::add_member(other, OWNER),
        SpaceOp::create(
            NodeKind::Uint(CONVERSATION),
            ROOT,
            "conversation",
            Record::new(),
        ),
    ]
}

/// `create` of a message.
pub fn create_message(conversation: NodeId, text: &str) -> SpaceOp {
    SpaceOp::create(
        NodeKind::Uint(MESSAGE),
        conversation,
        "message",
        Record::new().with(1, text),
    )
}

/// A message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// Who wrote it.
    pub author: IdentityId,
    /// Its text.
    pub text: String,
    /// The author's clock, for display only.
    pub time: Option<u64>,
}

/// The conversation of a relationship space.
pub fn conversation(space: &Space) -> Option<NodeId> {
    let state = space.state();
    let found = state.children(&ROOT).into_iter().find(is_conversation);
    found.map(|n| n.id)
}

fn is_conversation(n: &&Node) -> bool {
    n.kind == NodeKind::Uint(CONVERSATION) && !n.deleted
}

/// The messages of a relationship space, in log order, which every device
/// computes the same way (`profiles.md#relationship`).
pub fn messages(space: &Space) -> Vec<Message> {
    let Some(conversation) = conversation(space) else {
        return Vec::new();
    };
    let state = space.state();
    let mut found: Vec<(usize, Message)> = state
        .children(&conversation)
        .into_iter()
        .filter(|n| n.kind == NodeKind::Uint(MESSAGE) && !n.deleted)
        .filter_map(|n| {
            let e = space.dag().get(&n.created_in)?;
            let text = n.values(1).iter().rev().find_map(|v| v.value.as_ref())?;
            let message = Message {
                author: n.creator,
                text: text.as_text()?.to_owned(),
                time: e.time(),
            };
            Some((space.dag().position(&n.created_in)?, message))
        })
        .collect();
    found.sort_by_key(|(at, _)| *at);
    found.into_iter().map(|(_, m)| m).collect()
}
