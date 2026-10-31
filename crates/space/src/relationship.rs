//! The relationship profile (`profiles.md#relationship`): two identities,
//! both owners, and a conversation between them.

use cardinal_encoding::Record;

use crate::entry::{IdentityId, NodeId, NodeKind, SpaceOp};
use crate::space::Space;
use crate::state::{Node, ROOT};

/// Conversation kind.
pub const CONVERSATION: u64 = 1;
/// Message kind.
pub const MESSAGE: u64 = 2;
/// The owner role (`spaces.md#memberships`).
pub const OWNER: u64 = 3;

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
