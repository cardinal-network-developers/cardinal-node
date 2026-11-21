//! The relationship profile (`profiles.md#relationship`): two identities,
//! both writers and neither an owner, and a conversation between them.

use std::collections::HashSet;

use cardinal_encoding::{Record, Value};
use cardinal_identity::EntryId;

use crate::entry::{IdentityId, NodeId, NodeKind, SpaceOp, WRITER};
use crate::grant::Endpoint;
use crate::space::Space;
use crate::state::{reach_node_id, Node, State, AUTHOR_OWNED_FIELD, ROOT};

/// Conversation kind.
pub const CONVERSATION: u64 = 1;
/// Message kind.
pub const MESSAGE: u64 = 2;
/// Read marker kind.
pub const READ_MARKER: u64 = 4;
/// Reaction kind, under a message.
pub const REACTION: u64 = 3;
/// Introduction kind (`contact.md#introductions`).
pub const INTRODUCTION: u64 = 8;

/// `create` of an introduction: `introducer` would like the other member of
/// this space to meet `introduced`, by the name `name`. Made by the
/// introducer; or, with `introducer` another, a request that they make one,
/// by someone who would like to meet `introduced` (`profiles.md#group`).
pub fn create_introduction(
    introducer: &IdentityId,
    introduced: &IdentityId,
    name: &str,
    note: Option<&str>,
    group: Option<&crate::entry::SpaceId>,
    invitation: Option<Record>,
) -> SpaceOp {
    SpaceOp::create(
        NodeKind::Uint(INTRODUCTION),
        ROOT,
        "introduction",
        Record::new()
            .with(1, *introducer)
            .with(2, *introduced)
            .with(3, name)
            .with_opt(4, note)
            .with_opt(5, invitation.map(Value::Record))
            .with_opt(6, group.copied()),
    )
}

/// An introduction, as a relationship space holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Introduction {
    /// Its node.
    pub node: NodeId,
    /// Who made the node.
    pub creator: IdentityId,
    /// Who introduces.
    pub introducer: IdentityId,
    /// Who is introduced.
    pub introduced: IdentityId,
    /// The name suggested for them.
    pub name: String,
    /// What the introducer says.
    pub note: Option<String>,
    /// The invitation, once the other side said yes.
    pub invitation: Option<Record>,
    /// The group it comes through.
    pub group: Option<crate::entry::SpaceId>,
    /// The member it was for said no.
    pub declined: bool,
}

/// The introductions in a relationship space. What one says, who
/// introduces whom and how, counts only as its maker wrote it; saying no
/// counts only from the other member. The invitation is whoever's: what it
/// is good for is for the one who uses it to check (`contact.md#introductions`).
pub fn introductions(space: &Space) -> Vec<Introduction> {
    let state = space.state();
    let dag = space.dag();
    let nodes = state.children(&ROOT).into_iter();
    nodes
        .filter(|n| n.kind == NodeKind::Uint(INTRODUCTION) && !n.deleted)
        .filter_map(|n| {
            let by = |k: u64, maker: bool| {
                n.values(k).iter().rev().find_map(|v| {
                    let author = dag.get(&v.entry)?.author();
                    ((author == n.creator) == maker)
                        .then_some(v.value.as_ref())
                        .flatten()
                })
            };
            let field = |k| by(k, true);
            let id = |k| -> Option<IdentityId> { field(k)?.as_bytes()?.try_into().ok() };
            let invitation = n.values(5).iter().rev().find_map(|v| v.value.as_ref());
            Some(Introduction {
                node: n.id,
                creator: n.creator,
                introducer: id(1)?,
                introduced: id(2)?,
                name: field(3).and_then(Value::as_text).unwrap_or("").to_owned(),
                note: field(4).and_then(Value::as_text).map(str::to_owned),
                invitation: invitation.and_then(Value::as_record).cloned(),
                group: field(6)
                    .and_then(Value::as_bytes)
                    .and_then(|b| b.try_into().ok()),
                declined: by(7, false).and_then(Value::as_bool).unwrap_or(false),
            })
        })
        .collect()
}

/// Puts the invitation in an introduction, with the name to suggest.
pub fn answer_introduction(node: NodeId, invitation: Record, name: Option<&str>) -> Vec<SpaceOp> {
    let mut ops = vec![SpaceOp::set(node, 5, Some(Value::Record(invitation)))];
    if let Some(n) = name {
        ops.push(SpaceOp::set(node, 3, Some(Value::from(n))));
    }
    ops
}

/// Says no to an introduction.
pub fn decline_introduction(node: NodeId) -> SpaceOp {
    SpaceOp::set(node, 7, Some(Value::from(true)))
}

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
        // each as it came: one this version cannot use is skipped by
        // whoever looks for an address, and written again as it is
        endpoints: endpoints.into_iter().map(Endpoint::from_record).collect(),
        host: r.get(2)?.as_bytes()?.try_into().ok()?,
        token: r.get(3)?.as_bytes()?.try_into().ok()?,
    })
}

/// Sets where `author` is reached about this space: field 1 of their reach
/// node, which is theirs from the start and is never created
/// (`state.md#nodes`). An empty list says there is nowhere, or that the
/// others are not to have it.
pub fn set_reach(author: &IdentityId, reach: &[Reach]) -> SpaceOp {
    SpaceOp::set(reach_node_id(author), 1, Some(reach_list(reach)))
}

/// What the entry holds by which `who` leaves a space: `leave`, and a
/// `set` of their reach node to an empty list, so that the space stops
/// naming their hosts to whoever is in it or comes to it later
/// (`spaces.md#members-and-roles`). A reader may write both.
pub fn leave_ops(who: &IdentityId) -> Vec<SpaceOp> {
    vec![SpaceOp::leave(), set_reach(who, &[])]
}

/// Whether `who` has said where they are reached, if only that it is
/// nowhere.
pub fn reach_is_set(state: &State, who: &IdentityId) -> bool {
    !state.reach_values(who, 1).is_empty()
}

/// The hosts `who` gives in their reach node, those their person prefers
/// first (`profiles.md#reach`). Where two of their devices set it at the
/// same moment it holds both lists:
///
/// - if either is empty, cleared or not a list, it is empty. An empty
///   list is how a person says no, and a no stands against whatever was
///   set beside it (`hosts.md#telling-others-where-to-reach-you`);
/// - otherwise both count, the one set later in log order first. A host
///   named in both, with one token or two, is one host: it is given once,
///   where it first stands, with the token it has there. Every token it
///   was given for the space serves until revoked ([`reach_ever`]), so
///   whichever is read is good.
///
/// Nobody writes only to make two lists one. This is the one reading of a
/// reach node: whoever looks up a host of someone's goes through it, as
/// does whatever shows the list, and a device that writes its own entry
/// writes the others as this gives them.
pub fn reach_of(space: &crate::Space, who: &IdentityId) -> Vec<Reach> {
    let dag = space.dag();
    let mut lists: Vec<_> = Vec::new();
    for v in space.state().reach_values(who, 1) {
        let list = v
            .value
            .as_ref()
            .and_then(Value::as_list)
            .unwrap_or_default();
        if list.is_empty() {
            return Vec::new();
        }
        lists.push((dag.position(&v.entry), v.op, list));
    }
    lists.sort_by_key(|(at, op, _)| std::cmp::Reverse((*at, *op)));
    let mut all: Vec<Reach> = Vec::new();
    // Told from those taken already by looking it up: comparing with each
    // of them is the square of a list its member, a reader as well, may
    // make as long as an entry holds.
    let mut seen: std::collections::HashSet<[u8; 32]> = Default::default();
    for (_, _, list) in lists {
        for r in list.iter().filter_map(|v| read_reach(v.as_record()?)) {
            if seen.insert(r.host) {
                all.push(r);
            }
        }
    }
    all
}

/// The entries with which `who` began naming hosts in a space, as their
/// list stands: each `set` of a list that names a host where the list
/// before it was empty or had never been set, and from which what the
/// list holds now descends through lists that all named one. None if the
/// list names no host now.
///
/// Setting the list again to keep it current, as for an address that
/// changed, begins nothing: whoever came to the space while its hosts
/// were named is whoever no such entry has in its past, however often the
/// list was set since (`hosts.md#telling-others-where-to-reach-you`).
pub fn naming_began(space: &crate::Space, who: &IdentityId) -> Vec<EntryId> {
    if reach_of(space, who).is_empty() {
        return Vec::new();
    }
    let (dag, state) = (space.dag(), space.state());
    let node = reach_node_id(who);
    // every list they set that counts, latest in log order first, and
    // whether it was empty
    let mut sets: Vec<(usize, EntryId, bool)> = Vec::new();
    for (id, e) in dag.iter().filter(|(_, e)| e.author() == *who) {
        let mut lists = e.ops().iter().filter_map(|op| match op.body() {
            crate::SpaceOpBody::Set {
                node: n,
                key: 1,
                value,
                ..
            } if *n == node => Some(value.as_ref().and_then(Value::as_list).unwrap_or_default()),
            _ => None,
        });
        let Some(list) = lists.next_back() else {
            continue;
        };
        if let Some(at) = dag.position(id).filter(|_| state.is_accepted(id)) {
            sets.push((at, *id, list.is_empty()));
        }
    }
    sets.sort_by_key(|(at, ..)| std::cmp::Reverse(*at));
    let mut began = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut todo: Vec<EntryId> = state.reach_values(who, 1).iter().map(|v| v.entry).collect();
    while let Some(e) = todo.pop() {
        if !seen.insert(e) {
            continue;
        }
        // the lists this one replaced: those before it that no other
        // before it came after
        let mut before: Vec<&(usize, EntryId, bool)> = Vec::new();
        for s in sets.iter().filter(|(_, p, _)| dag.is_ancestor(p, &e)) {
            if !before.iter().any(|(_, q, _)| dag.is_ancestor(&s.1, q)) {
                before.push(s);
            }
        }
        if before.is_empty() || before.iter().any(|(_, _, empty)| *empty) {
            began.push(e);
        } else {
            todo.extend(before.iter().map(|(_, p, _)| *p));
        }
    }
    began
}

/// Every host and token `who` ever gave in their reach node in a space:
/// from each value they wrote there, whatever the node says now. A token
/// serves until it is revoked, named in the current list or not
/// (`profiles.md#reach`): this is where a host finds the space of a token
/// something was left under, and the tokens to end when the list is
/// emptied or a contact refused.
pub fn reach_ever(space: &crate::Space, who: &IdentityId) -> Vec<Reach> {
    space.reach_written_by(who).to_vec()
}

/// The reach lists one entry writes in its author's reach node: what the
/// space keeps for [`reach_ever`] as entries arrive.
pub fn reach_written(e: &crate::SpaceEntry) -> Vec<Reach> {
    let node = reach_node_id(&e.author());
    let mut all: Vec<Reach> = Vec::new();
    for op in e.ops() {
        let crate::SpaceOpBody::Set {
            node: n,
            key: 1,
            value: Some(v),
            ..
        } = op.body()
        else {
            continue;
        };
        if *n != node {
            continue;
        }
        let list = v.as_list().unwrap_or_default();
        all.extend(list.iter().filter_map(|v| read_reach(v.as_record()?)));
    }
    all
}

/// What a relationship's genesis entry holds besides `start`: both
/// identities as writers, and the one conversation. It names no owner, so
/// neither can add anyone and neither can end it alone
/// (`spaces.md#members-and-roles`).
pub fn genesis_ops(author: IdentityId, other: IdentityId) -> Vec<SpaceOp> {
    vec![
        SpaceOp::add_member(author, WRITER),
        SpaceOp::add_member(other, WRITER),
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
    create_reply(conversation, text, None)
}

/// `create` of a message in reply to another. A message is its author's
/// alone: nobody else can change or delete it.
pub fn create_reply(conversation: NodeId, text: &str, to: Option<NodeId>) -> SpaceOp {
    create_with(conversation, text, to, &[])
}

/// `create` of a message with files attached, in reply to another if given.
pub fn create_with(
    conversation: NodeId,
    text: &str,
    to: Option<NodeId>,
    attachments: &[Attachment],
) -> SpaceOp {
    let attached = (!attachments.is_empty()).then(|| {
        Value::list(attachments.iter().map(|a| {
            Value::Record(
                Record::new()
                    .with(1, a.name.as_str())
                    .with(2, Value::Record(a.blob.clone()))
                    .with(3, a.media_type.as_str()),
            )
        }))
    });
    SpaceOp::create(
        NodeKind::Uint(MESSAGE),
        conversation,
        "message",
        Record::new()
            .with(1, text)
            .with_opt(2, attached)
            .with_opt(3, to)
            .with(AUTHOR_OWNED_FIELD, 1u64),
    )
}

/// The files a message carries, put in the shared folder as well
/// (`profiles.md#shared-folder`): one `create` each, under the root, for the
/// same entry as the message.
pub fn shared_files(attachments: &[Attachment], mtime_ms: Option<u64>) -> Vec<SpaceOp> {
    attachments
        .iter()
        .filter_map(|a| {
            let blob = crate::files::BlobRef::from_record(&a.blob)?;
            Some(crate::files::Kinds::SHARED.create_file(
                ROOT,
                &a.name,
                &crate::files::Content::Blob(blob),
                0o644,
                mtime_ms,
            ))
        })
        .collect()
}

/// A file attached to a message.
#[derive(Clone, Debug, PartialEq)]
pub struct Attachment {
    /// What the sender called it.
    pub name: String,
    /// Its blob reference (`blobs.md#references`).
    pub blob: Record,
    /// What kind of file it is, such as `image/jpeg`.
    pub media_type: String,
}

fn read_attachments(v: Option<&Value>) -> Vec<Attachment> {
    let list = v.and_then(Value::as_list).unwrap_or_default();
    list.iter()
        .filter_map(|a| {
            let r = a.as_record()?;
            Some(Attachment {
                name: r.get(1)?.as_text()?.to_owned(),
                blob: r.get(2)?.as_record()?.clone(),
                media_type: r.get(3).and_then(Value::as_text).unwrap_or("").to_owned(),
            })
        })
        .collect()
}

/// Changes what a message says. Its history keeps what it said before.
pub fn edit_message(message: NodeId, text: &str) -> SpaceOp {
    SpaceOp::set(message, 1, Some(Value::from(text)))
}

/// `create` of a reaction, such as an emoji, to a message.
pub fn create_reaction(message: NodeId, text: &str) -> SpaceOp {
    SpaceOp::create(
        NodeKind::Uint(REACTION),
        message,
        "reaction",
        Record::new().with(1, text).with(AUTHOR_OWNED_FIELD, 1u64),
    )
}

/// Changes a reaction.
pub fn set_reaction(reaction: NodeId, text: &str) -> SpaceOp {
    SpaceOp::set(reaction, 1, Some(Value::from(text)))
}

/// `create` of a member's read marker, at the message `last`.
pub fn create_read_marker(conversation: NodeId, last: NodeId) -> SpaceOp {
    SpaceOp::create(
        NodeKind::Uint(READ_MARKER),
        conversation,
        "read",
        Record::new().with(1, last).with(AUTHOR_OWNED_FIELD, 1u64),
    )
}

/// Moves a read marker to the message `last`.
pub fn set_read_marker(marker: NodeId, last: NodeId) -> SpaceOp {
    SpaceOp::set(marker, 1, Some(last.into()))
}

fn is_marker_of<'a>(who: &'a IdentityId) -> impl Fn(&&Node) -> bool + 'a {
    move |n| n.kind == NodeKind::Uint(READ_MARKER) && !n.deleted && n.creator == *who
}

/// A read marker of `who`'s, to move rather than make another. Their devices
/// may each have made one while apart.
pub fn read_marker(space: &Space, who: &IdentityId) -> Option<NodeId> {
    let conversation = conversation(space)?;
    let state = space.state();
    let markers = state.children(&conversation).into_iter();
    let mut found: Vec<NodeId> = markers.filter(is_marker_of(who)).map(|n| n.id).collect();
    found.sort();
    found.first().copied()
}

/// Which of `messages` `who` has read. A marker says it had read all that the
/// entry writing it had seen, so what arrives beside it, or is deleted after it,
/// changes nothing, and two devices moving one marker apart add up.
pub fn read_by(space: &Space, who: &IdentityId, messages: &[Message]) -> Vec<bool> {
    let dag = space.dag();
    let mut seen: HashSet<EntryId> = HashSet::new();
    if let Some(conversation) = conversation(space) {
        let state = space.state();
        let markers = state.children(&conversation).into_iter();
        for marker in markers.filter(is_marker_of(who)) {
            let mut going: Vec<EntryId> = marker.values(1).iter().map(|v| v.entry).collect();
            while let Some(entry) = going.pop() {
                if seen.insert(entry) {
                    going.extend_from_slice(dag.parents(&entry));
                }
            }
        }
    }
    messages.iter().map(|m| seen.contains(&m.entry)).collect()
}

/// A message.
#[derive(Clone, Debug, PartialEq)]
pub struct Message {
    /// Its node.
    pub id: NodeId,
    /// The entry that wrote it.
    pub entry: EntryId,
    /// Who wrote it.
    pub author: IdentityId,
    /// Its text.
    pub text: String,
    /// The author's clock, for display only.
    pub time: Option<u64>,
    /// The message it answers.
    pub reply_to: Option<NodeId>,
    /// It was changed after it was written.
    pub edited: bool,
    /// What each member reacted with.
    pub reactions: Vec<Reaction>,
    /// Files that came with it.
    pub attachments: Vec<Attachment>,
}

/// A member's reaction to a message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reaction {
    /// Its node.
    pub id: NodeId,
    /// Who reacted.
    pub author: IdentityId,
    /// With what.
    pub text: String,
}

/// The current text of a node's field 1, the last by entry when in conflict.
fn text_of(n: &Node) -> Option<String> {
    let text = n.values(1).iter().rev().find_map(|v| v.value.as_ref())?;
    Some(text.as_text()?.to_owned())
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
            let reply_to = n.values(3).iter().rev().find_map(|v| v.value.as_ref());
            let reply_to = reply_to.and_then(Value::as_bytes);
            let reactions = state.children(&n.id).into_iter();
            let reactions = reactions
                .filter(|r| r.kind == NodeKind::Uint(REACTION) && !r.deleted)
                .filter_map(|r| {
                    Some(Reaction {
                        id: r.id,
                        author: r.creator,
                        text: text_of(r)?,
                    })
                })
                .collect();
            let message = Message {
                id: n.id,
                entry: n.created_in,
                author: n.creator,
                text: text_of(n)?,
                time: e.time(),
                reply_to: reply_to.and_then(|b| NodeId::try_from(b).ok()),
                edited: n.values(1).iter().any(|v| v.entry != n.created_in),
                reactions,
                attachments: read_attachments(
                    n.values(2).iter().rev().find_map(|v| v.value.as_ref()),
                ),
            };
            Some((space.dag().position(&n.created_in)?, message))
        })
        .collect();
    found.sort_by_key(|(at, _)| *at);
    found.into_iter().map(|(_, m)| m).collect()
}

// ---- Recovery (`identity.md#how-guardians-act`) ---------------------------
//
// A relationship between a recovery helper and a guardian carries the
// recovery: what the guardian's device proposes, and identity entries each
// side carries to the other. The specification says they travel through the
// relationship, not how; these two node kinds are this implementation's
// (DEVIATIONS.md, Guardians).

/// Recovery proposal kind: what a guardian's device proposes for a
/// `recover`. Not in the specification.
pub const RECOVERY_PROPOSAL: u64 = 16;
/// Carried entry kind: one identity entry, carried for a recovery. Not in
/// the specification.
pub const CARRIED: u64 = 17;

/// A guardian's proposal, as a relationship space holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proposal {
    /// Its node.
    pub node: NodeId,
    /// Who wrote it.
    pub author: IdentityId,
    /// The identity being recovered.
    pub identity: IdentityId,
    /// The parents of the `recover`.
    pub parents: Vec<EntryId>,
    /// The policy it acts under.
    pub policy: EntryId,
}

/// `create` of a recovery proposal, its author's alone. A `recover` keeps
/// no old key, so it proposes no hosts.
pub fn create_proposal(identity: &IdentityId, parents: &[EntryId], policy: &EntryId) -> SpaceOp {
    SpaceOp::create(
        NodeKind::Uint(RECOVERY_PROPOSAL),
        ROOT,
        "recovery",
        Record::new()
            .with(1, *identity)
            .with(2, Value::list(parents.iter().map(|p| Value::from(*p))))
            .with(3, *policy)
            .with(AUTHOR_OWNED_FIELD, 1u64),
    )
}

/// A field of a node as its creator wrote it when creating it.
fn as_created(n: &Node, key: u64) -> Option<&Value> {
    n.values(key)
        .iter()
        .find(|v| v.entry == n.created_in)
        .and_then(|v| v.value.as_ref())
}

/// The recovery proposals in a relationship space, as their authors wrote
/// them, in the order they were made.
pub fn proposals(space: &Space) -> Vec<Proposal> {
    let dag = space.dag();
    let mut found: Vec<(Option<usize>, Proposal)> = space
        .state()
        .children(&ROOT)
        .into_iter()
        .filter(|n| n.kind == NodeKind::Uint(RECOVERY_PROPOSAL) && !n.deleted)
        .filter_map(|n| {
            let id = |k| -> Option<[u8; 32]> { as_created(n, k)?.as_bytes()?.try_into().ok() };
            let list = |k| {
                as_created(n, k)
                    .and_then(Value::as_list)
                    .unwrap_or_default()
            };
            let p = Proposal {
                node: n.id,
                author: n.creator,
                identity: id(1)?,
                parents: list(2)
                    .iter()
                    .filter_map(|v| v.as_bytes()?.try_into().ok())
                    .collect(),
                policy: id(3)?,
            };
            Some((dag.position(&n.created_in), p))
        })
        .collect();
    found.sort_by_key(|(at, _)| *at);
    found.into_iter().map(|(_, p)| p).collect()
}

/// `create` of a carried identity entry, its author's alone.
pub fn create_carried(identity: &IdentityId, entry: &[u8]) -> SpaceOp {
    SpaceOp::create(
        NodeKind::Uint(CARRIED),
        ROOT,
        "carried",
        Record::new()
            .with(1, *identity)
            .with(2, entry.to_vec())
            .with(AUTHOR_OWNED_FIELD, 1u64),
    )
}

/// An identity entry carried for a recovery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Carried {
    /// Who carried it.
    pub author: IdentityId,
    /// The identity recovered.
    pub identity: IdentityId,
    /// The entry, encoded.
    pub entry: Vec<u8>,
}

/// The identity entries carried in a relationship space, in the order
/// they were carried.
pub fn carried(space: &Space) -> Vec<Carried> {
    let dag = space.dag();
    let mut found: Vec<(Option<usize>, Carried)> = space
        .state()
        .children(&ROOT)
        .into_iter()
        .filter(|n| n.kind == NodeKind::Uint(CARRIED) && !n.deleted)
        .filter_map(|n| {
            let c = Carried {
                author: n.creator,
                identity: as_created(n, 1)?.as_bytes()?.try_into().ok()?,
                entry: as_created(n, 2)?.as_bytes()?.to_vec(),
            };
            Some((dag.position(&n.created_in), c))
        })
        .collect();
    found.sort_by_key(|(at, _)| *at);
    found.into_iter().map(|(_, c)| c).collect()
}
