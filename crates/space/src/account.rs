//! The account profile (`profiles.md#account`): the parts the first
//! milestone needs — device nodes, and space nodes with their placements.

use cardinal_encoding::{Record, Value};
use cardinal_identity::{EntryId, KeyId};

use crate::entry::{IdentityId, NodeId, NodeKind, SpaceId, SpaceOp};
use crate::state::{State, ROOT};

/// Contact kind.
pub const CONTACT: u64 = 1;
/// Space kind.
pub const SPACE: u64 = 2;
/// Host kind.
pub const HOST: u64 = 3;
/// Device kind.
pub const DEVICE: u64 = 4;
/// Secret kind.
pub const SECRET: u64 = 5;
/// Setting kind.
pub const SETTING: u64 = 6;
/// Placement kind (under a space node).
pub const PLACEMENT: u64 = 7;
/// Invitation kind.
pub const INVITATION: u64 = 10;
/// Invitation use kind (under an invitation node).
pub const INVITATION_USE: u64 = 11;
/// Self kind: the name this person suggests for themselves.
pub const SELF: u64 = 13;
/// "Not this host here" kind, under a space node (D75).
pub const NOT_THIS_HOST: u64 = 14;
/// Network kind (D76).
pub const NETWORK: u64 = 15;
/// Persona kind (`profiles.md#account`, D78).
pub const PERSONA: u64 = 16;
/// Node kind: whom a policy's commitments name (`profiles.md#account`).
pub const GUARDIANS: u64 = 17;

/// A space node's field: this person said no to naming their hosts in
/// it, "no hosts here" (D75, `hosts.md#telling-others-where-to-reach-you`).
pub const NO_HOSTS: u64 = 5;

/// A space node's field: the space this one succeeded, written by the
/// device that followed it (`profiles.md#account`).
pub const SUCCEEDED: u64 = 4;

/// A space node's field: the last message this person read there, kept
/// while read markers are off (`profiles.md#relationship`), seen only by
/// their own devices.
pub const READ_UP_TO: u64 = 6;

/// The read positions the account keeps for `space`: every value of field
/// 6 on every node for it.
pub fn read_up_to(state: &State, space: &SpaceId) -> Vec<NodeId> {
    let nodes = state.children(&ROOT).into_iter().filter(|n| {
        n.kind == NodeKind::Uint(SPACE)
            && !n.deleted
            && last(n, 1).and_then(Value::as_bytes) == Some(&space[..])
    });
    nodes
        .flat_map(|n| n.values(READ_UP_TO).iter())
        .filter_map(|v| v.value.as_ref()?.as_bytes()?.try_into().ok())
        .collect()
}

/// What keeps `message` as the last read in `space`: a `set` on each node
/// the account has for it, or a new node.
pub fn read_up_to_ops(
    state: &State,
    space: &SpaceId,
    local_name: &str,
    message: &NodeId,
) -> Vec<SpaceOp> {
    let was = hosts_no(state, space);
    if was.nodes.is_empty() {
        return vec![SpaceOp::create(
            NodeKind::Uint(SPACE),
            ROOT,
            local_name,
            Record::new()
                .with(1, *space)
                .with(2, local_name)
                .with(READ_UP_TO, *message),
        )];
    }
    was.nodes
        .iter()
        .map(|n| set_field(*n, READ_UP_TO, *message))
        .collect()
}

/// An invitation's field: the inviter cancelled it.
pub const CANCELLED: u64 = 2;

/// A contact's field: what this person calls them.
pub const PETNAME: u64 = 2;
/// A contact's field: accept introductions from them.
pub const INTRODUCTIONS: u64 = 6;
/// Contact field: this person named them a guardian (`identity.md#hidden-guardians`).
pub const GUARDIAN: u64 = 5;
/// A contact's field: they are trusted.
pub const TRUSTED: u64 = 7;
/// A contact's field: they are refused.
pub const REFUSED: u64 = 8;
/// A contact's field: where the relationship is listed.
pub const CATEGORY: u64 = 9;
/// Contact field: how the two met.
pub const MET: u64 = 10;
/// Contact field: this person's own picture for them (a blob reference).
pub const PICTURE: u64 = 11;
/// Contact field: the name they suggest for themselves, as last heard.
pub const SUGGESTED: u64 = 12;
/// Contact field: the identity this relationship is a recovery of. Not in
/// the specification, which says only that guardian software shows such a
/// relationship as "recovery for" the person, never as a contact
/// (`identity.md#how-guardians-act`; DEVIATIONS.md, Guardians).
pub const RECOVERY_OF: u64 = 13;
/// Where a relationship is listed when nothing else is said.
pub const PEOPLE: &str = "People";

/// How a person starts out regarding someone
/// (`contact.md#who-a-person-knows`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Regard {
    /// They are trusted, which a direct session needs from both sides.
    pub trusted: bool,
    /// Things may reach this person through them.
    pub introductions: bool,
}

impl Default for Regard {
    /// What an invitation makes of someone.
    fn default() -> Regard {
        Regard {
            trusted: true,
            introductions: true,
        }
    }
}

/// Where a device keeps a space's content (`blobs.md#retention`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Retention {
    /// Keep every chunk referenced by current state.
    Full = 0,
    /// Keep what was opened recently.
    OnDemand = 1,
    /// Also keep chunks referenced only by older versions.
    History = 2,
}

impl Retention {
    fn from_u64(v: u64) -> Option<Retention> {
        Some(match v {
            0 => Retention::Full,
            1 => Retention::OnDemand,
            2 => Retention::History,
            _ => return None,
        })
    }
}

/// The first bytes of a key in hex, as a fallback device name.
pub fn short_key(k: &KeyId) -> String {
    k[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// A device node's name (field 2).
pub const DEVICE_NAME: u64 = 2;

/// `create` of a device node.
pub fn create_device(key: &KeyId, name: &str, always_on: bool, is_host: bool) -> SpaceOp {
    SpaceOp::create(
        NodeKind::Uint(DEVICE),
        ROOT,
        &short_key(key),
        Record::new()
            .with(1, *key)
            .with(2, name)
            .with(3, always_on)
            .with(4, is_host),
    )
}

/// `create` of a contact node.
pub fn create_contact(
    identity: &IdentityId,
    petname: &str,
    space: &SpaceId,
    regard: Regard,
) -> SpaceOp {
    create_contact_met(identity, petname, space, regard, None)
}

/// `create` of a contact node, with how the two met.
pub fn create_contact_met(
    identity: &IdentityId,
    petname: &str,
    space: &SpaceId,
    regard: Regard,
    met: Option<&Met>,
) -> SpaceOp {
    create_contact_suggesting(identity, petname, None, space, regard, met)
}

/// `create` of a contact node, with how the two met and the name they
/// suggested for themselves (field 12).
pub fn create_contact_suggesting(
    identity: &IdentityId,
    petname: &str,
    suggested: Option<&str>,
    space: &SpaceId,
    regard: Regard,
    met: Option<&Met>,
) -> SpaceOp {
    create_contact_for(identity, petname, suggested, space, regard, met, None)
}

/// [`create_contact_suggesting`], for a relationship that is a recovery of
/// `recovery_of` if given.
pub fn create_contact_for(
    identity: &IdentityId,
    petname: &str,
    suggested: Option<&str>,
    space: &SpaceId,
    regard: Regard,
    met: Option<&Met>,
    recovery_of: Option<&IdentityId>,
) -> SpaceOp {
    SpaceOp::create(
        NodeKind::Uint(CONTACT),
        ROOT,
        &short_key(identity),
        Record::new()
            .with(1, *identity)
            .with(2, petname)
            .with(3, *space)
            .with(INTRODUCTIONS, regard.introductions)
            .with(TRUSTED, regard.trusted)
            .with_opt(MET, met.map(|m| Value::Record(m.to_record())))
            .with_opt(SUGGESTED, suggested.filter(|s| !s.trim().is_empty()))
            .with_opt(RECOVERY_OF, recovery_of.copied()),
    )
}

/// `create` of a setting node (`profiles.md#account`, kind 6).
pub fn create_setting(name: &str, value: impl Into<Value>) -> SpaceOp {
    SpaceOp::create(
        NodeKind::Uint(SETTING),
        ROOT,
        "setting",
        Record::new().with(1, name).with(2, value.into()),
    )
}

/// The settings that are not deleted, by name, each with its value.
pub fn settings(state: &State) -> Vec<(String, Value)> {
    state
        .children(&ROOT)
        .into_iter()
        .filter(|n| n.kind == NodeKind::Uint(SETTING) && !n.deleted)
        .filter_map(|n| {
            let name = last(n, 1)?.as_text()?.to_owned();
            Some((name, last(n, 2)?.clone()))
        })
        .collect()
}

/// [`settings`], each with when the node was made, by its writer's clock.
pub fn settings_made(state: &State) -> Vec<(String, Value, Option<u64>)> {
    state
        .children(&ROOT)
        .into_iter()
        .filter(|n| n.kind == NodeKind::Uint(SETTING) && !n.deleted)
        .filter_map(|n| {
            let name = last(n, 1)?.as_text()?.to_owned();
            Some((name, last(n, 2)?.clone(), n.created))
        })
        .collect()
}

/// `create` of the self node (`profiles.md#account`): the name this
/// person suggests for themselves.
pub fn create_self(name: &str) -> SpaceOp {
    SpaceOp::create(
        NodeKind::Uint(SELF),
        ROOT,
        "self",
        Record::new().with(1, name),
    )
}

/// The self node, and the name it holds: where there are two, made at
/// once, the one with the lowest node id.
pub fn self_node(state: &State) -> Option<(NodeId, String)> {
    let mut all: Vec<_> = state
        .children(&ROOT)
        .into_iter()
        .filter(|n| n.kind == NodeKind::Uint(SELF) && !n.deleted)
        .collect();
    all.sort_by_key(|n| n.id);
    let n = all.first()?;
    let name = last(n, 1).and_then(Value::as_text).unwrap_or("").trim();
    Some((n.id, name.to_owned()))
}

/// How two people met (`profiles.md#account`): kept so that if an
/// introducer or a channel proves unreliable, everyone who came through it
/// can be found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Met {
    /// 1 their invitation, 2 this person's, 3 an introduction, 4 their front door.
    pub how: u64,
    /// Who introduced them.
    pub introducer: Option<IdentityId>,
    /// The group an introduction came through.
    pub group: Option<SpaceId>,
    /// How an invitation travelled, as software says: a QR code, pasted.
    pub via: Option<String>,
}

/// They gave this person an invitation, which this person used.
pub const MET_THEIR_INVITATION: u64 = 1;
/// This person gave them an invitation.
pub const MET_MY_INVITATION: u64 = 2;
/// Someone introduced them.
pub const MET_INTRODUCED: u64 = 3;

impl Met {
    fn to_record(&self) -> Record {
        Record::new()
            .with(1, self.how)
            .with_opt(2, self.introducer)
            .with_opt(3, self.group)
            .with_opt(4, self.via.as_deref())
    }

    fn from_record(r: &Record) -> Option<Met> {
        Some(Met {
            how: r.get(1)?.as_uint()?,
            introducer: r
                .get(2)
                .and_then(Value::as_bytes)
                .and_then(|b| b.try_into().ok()),
            group: r
                .get(3)
                .and_then(Value::as_bytes)
                .and_then(|b| b.try_into().ok()),
            via: r.get(4).and_then(Value::as_text).map(str::to_owned),
        })
    }
}

/// `create` of a host node: one that keeps `grant` (`hosts.md#grants`).
pub fn create_host(grant: &[u8]) -> SpaceOp {
    SpaceOp::create(
        NodeKind::Uint(HOST),
        ROOT,
        "host",
        Record::new().with(1, grant.to_vec()),
    )
}

/// `create` of a space node.
pub fn create_space(space: &SpaceId, local_name: &str) -> SpaceOp {
    SpaceOp::create(
        NodeKind::Uint(SPACE),
        ROOT,
        local_name,
        Record::new().with(1, *space).with(2, local_name),
    )
}

/// What a device writes in the account when it follows a successor
/// (`profiles.md#account`, "A successor takes its place"): a space node
/// for it, whose field 4 names the space it succeeded, with what was
/// recorded for that space: its local name, "no hosts here", where the
/// person had read up to, each placement and each "not this host here".
///
/// Where a node for the successor is there already, written by another
/// device of the person's that followed first, what it lacks of the
/// person's no is set on it: field 4, "no hosts here", and each "not this
/// host here" (D75). A no said in the old space after that device
/// followed is not lost.
pub fn successor_ops(
    state: &State,
    old: &SpaceId,
    new: &SpaceId,
    local_name: &str,
) -> Vec<SpaceOp> {
    let named = |n: &crate::state::Node, s: &SpaceId| {
        n.kind == NodeKind::Uint(SPACE)
            && !n.deleted
            && last(n, 1).and_then(Value::as_bytes) == Some(&s[..])
    };
    let roots = state.children(&ROOT);
    let there: Vec<&crate::state::Node> = roots.iter().copied().filter(|n| named(n, new)).collect();
    if !there.is_empty() {
        return successor_missing(state, &there, old);
    }
    let was: Vec<&crate::state::Node> = roots.into_iter().filter(|n| named(n, old)).collect();
    let name = was
        .iter()
        .find_map(|n| last(n, 2).and_then(Value::as_text))
        .unwrap_or(local_name);
    let mut fields = Record::new()
        .with(1, *new)
        .with(2, name)
        .with(SUCCEEDED, *old);
    let no = was.iter().flat_map(|n| n.values(NO_HOSTS).iter());
    if no.filter_map(|v| v.value.as_ref()?.as_bool()).any(|b| b) {
        fields = fields.with(NO_HOSTS, true);
    }
    if let Some(read) = was.iter().find_map(|n| last(n, READ_UP_TO)) {
        fields = fields.with(READ_UP_TO, read.clone());
    }
    let mut ops = vec![SpaceOp::create(NodeKind::Uint(SPACE), ROOT, name, fields)];
    for n in &was {
        for c in state.children(&n.id) {
            let kept =
                c.kind == NodeKind::Uint(PLACEMENT) || c.kind == NodeKind::Uint(NOT_THIS_HOST);
            if !kept || c.deleted {
                continue;
            }
            let mut f = Record::new();
            for (k, vs) in &c.fields {
                if let Some(v) = vs.iter().rev().find_map(|v| v.value.as_ref()) {
                    f = f.with(*k, v.clone());
                }
            }
            ops.push(SpaceOp::create(c.kind, ROOT, &c.name, f).with_parent(0u32));
        }
    }
    ops
}

/// What the successor's nodes `there` lack of what the account records
/// for `old`: field 4 on each node without it, "no hosts here" on each
/// where none of them says it and `old` does, and under the first, each
/// "not this host here" of `old`'s that none of them has.
fn successor_missing(state: &State, there: &[&crate::state::Node], old: &SpaceId) -> Vec<SpaceOp> {
    let mut ops = Vec::new();
    for n in there {
        if n.values(SUCCEEDED).is_empty() {
            ops.push(set_field(n.id, SUCCEEDED, *old));
        }
    }
    let said = |nodes: &[NodeId]| {
        nodes.iter().filter_map(|n| state.node(n)).any(|n| {
            let no = n.values(NO_HOSTS).iter();
            no.filter_map(|v| v.value.as_ref()?.as_bool()).any(|b| b)
        })
    };
    let ids: Vec<NodeId> = there.iter().map(|n| n.id).collect();
    let was = hosts_no(state, old);
    if was.no_hosts && !said(&ids) {
        ops.extend(ids.iter().map(|n| set_field(*n, NO_HOSTS, true)));
    }
    let mut has: Vec<[u8; 32]> = Vec::new();
    for n in &ids {
        has.extend(not_these_under(state, n).into_iter().map(|(_, h)| h));
    }
    let first = ids.iter().min().expect("a node");
    for (_, host) in was.not_these {
        if !has.contains(&host) {
            has.push(host);
            let fields = Record::new().with(1, host);
            let name = hex_of(&host[..4]);
            ops.push(SpaceOp::create(
                NodeKind::Uint(NOT_THIS_HOST),
                *first,
                &name,
                fields,
            ));
        }
    }
    ops
}

/// The "not this host here" nodes under one space node, with their hosts.
fn not_these_under(state: &State, node: &NodeId) -> Vec<(NodeId, [u8; 32])> {
    let mut out = Vec::new();
    for c in state.children(node) {
        if c.kind != NodeKind::Uint(NOT_THIS_HOST) || c.deleted {
            continue;
        }
        if let Some(host) = last(c, 1).and_then(Value::as_bytes) {
            if let Ok(host) = host.try_into() {
                out.push((c.id, host));
            }
        }
    }
    out
}

/// `space`, then the space it succeeded, and so on, as the account
/// records it: field 4 of a space node for each (`profiles.md#account`).
pub fn succeeded_chain(state: &State, space: &SpaceId) -> Vec<SpaceId> {
    let all = spaces(state);
    let mut out = vec![*space];
    while out.len() < 64 {
        let at = out.last().expect("one");
        let next = all
            .iter()
            .filter(|r| r.space == *at)
            .find_map(|r| r.succeeded);
        match next {
            Some(n) if !out.contains(&n) => out.push(n),
            _ => break,
        }
    }
    out
}

/// The successor this person's devices followed from `space`, by the
/// account: a space node whose field 4 names it.
pub fn followed_from(state: &State, space: &SpaceId) -> Vec<SpaceId> {
    let mut out: Vec<SpaceId> = spaces(state)
        .into_iter()
        .filter(|r| r.succeeded == Some(*space))
        .map(|r| r.space)
        .collect();
    out.sort();
    out.dedup();
    out
}

/// `create` of a space node for an offer this person said no to.
pub fn create_declined(space: &SpaceId, local_name: &str) -> SpaceOp {
    SpaceOp::create(
        NodeKind::Uint(SPACE),
        ROOT,
        local_name,
        Record::new()
            .with(1, *space)
            .with(2, local_name)
            .with(3, true),
    )
}

/// `create` of a placement under a space node.
pub fn create_placement(
    space_node: NodeId,
    device: &KeyId,
    retention: Retention,
    path: Option<&str>,
    light: bool,
) -> SpaceOp {
    SpaceOp::create(
        NodeKind::Uint(PLACEMENT),
        space_node,
        &short_key(device),
        Record::new()
            .with(1, *device)
            .with(2, retention as u32)
            .with_opt(3, path)
            .with(4, light),
    )
}

/// `set` of a field of an account node.
pub fn set_field(node: NodeId, key: u64, value: impl Into<Value>) -> SpaceOp {
    SpaceOp::set(node, key, Some(value.into()))
}

/// What this person's account records of their no to naming their hosts
/// in one space (D75): seen only by their own devices, which it stops
/// from naming themselves there. What was recorded for a space it
/// succeeded holds for it too (`profiles.md#account`, "A successor takes
/// its place").
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostsNo {
    /// The space nodes the account has for the space.
    pub nodes: Vec<NodeId>,
    /// The space nodes the account has for the spaces it succeeds.
    pub before: Vec<NodeId>,
    /// "No hosts here": any of them says so, in any of its values. A no
    /// is never overridden, so where two devices set it at once, one yes
    /// and one no, it is a no.
    pub no_hosts: bool,
    /// "Not this host here", by the host's static X25519 key, with the
    /// node that records it.
    pub not_these: Vec<(NodeId, [u8; 32])>,
}

impl HostsNo {
    /// Whether the person took this host out of the space by hand.
    pub fn not_this(&self, host: &[u8; 32]) -> bool {
        self.not_these.iter().any(|(_, h)| h == host)
    }
}

/// What the account records of a no to naming hosts in `space`, and in
/// the spaces it succeeds as the account records them.
pub fn hosts_no(state: &State, space: &SpaceId) -> HostsNo {
    hosts_no_in(state, &succeeded_chain(state, space))
}

/// What the account records of a no to naming hosts in `chain[0]`, and in
/// the rest of `chain`: the spaces it succeeds, the nearest first.
pub fn hosts_no_in(state: &State, chain: &[SpaceId]) -> HostsNo {
    let mut out = HostsNo::default();
    for (i, space) in chain.iter().enumerate() {
        let nodes = state.children(&ROOT).into_iter().filter(|n| {
            n.kind == NodeKind::Uint(SPACE)
                && !n.deleted
                && last(n, 1).and_then(Value::as_bytes) == Some(&space[..])
        });
        for n in nodes {
            match i {
                0 => out.nodes.push(n.id),
                _ => out.before.push(n.id),
            }
            let no = n.values(NO_HOSTS).iter();
            out.no_hosts |= no.filter_map(|v| v.value.as_ref()?.as_bool()).any(|b| b);
            out.not_these.extend(not_these_under(state, &n.id));
        }
    }
    out.nodes.sort();
    out.before.sort();
    out
}

/// What records the person's no to naming any host of theirs in `space`
/// ("no hosts here"): a `set` on each node the account has for it, or a
/// new node if it has none.
pub fn say_no_ops(state: &State, space: &SpaceId, local_name: &str) -> Vec<SpaceOp> {
    let was = hosts_no(state, space);
    if was.nodes.is_empty() {
        return vec![SpaceOp::create(
            NodeKind::Uint(SPACE),
            ROOT,
            local_name,
            Record::new()
                .with(1, *space)
                .with(2, local_name)
                .with(NO_HOSTS, true),
        )];
    }
    was.nodes
        .iter()
        .map(|n| set_field(*n, NO_HOSTS, true))
        .collect()
}

/// What records that the person took `host` out of `chain[0]` by hand
/// ("not this host here"), under the space's node, made if there is none.
/// Nothing where it is recorded already, for it or for a space it
/// succeeds (the rest of `chain`).
pub fn not_this_host_ops(
    state: &State,
    chain: &[SpaceId],
    local_name: &str,
    host: &[u8; 32],
) -> Vec<SpaceOp> {
    let was = hosts_no_in(state, chain);
    if was.not_this(host) {
        return Vec::new();
    }
    let fields = Record::new().with(1, *host);
    let name = hex_of(&host[..4]);
    match was.nodes.first() {
        Some(node) => vec![SpaceOp::create(
            NodeKind::Uint(NOT_THIS_HOST),
            *node,
            &name,
            fields,
        )],
        None => vec![
            SpaceOp::create(
                NodeKind::Uint(SPACE),
                ROOT,
                local_name,
                Record::new().with(1, chain[0]).with(2, local_name),
            ),
            SpaceOp::create(NodeKind::Uint(NOT_THIS_HOST), ROOT, &name, fields).with_parent(0u32),
        ],
    }
}

/// What a yes by hand takes out of the record (D75): "no hosts here" on
/// every node the account has for `chain[0]` and for the spaces it
/// succeeds (the rest of `chain`), and "not this host here" for each of
/// `hosts`, wherever in the chain it is: what is recorded for a space it
/// succeeds holds for it, and would hold the no up otherwise.
pub fn yes_ops(state: &State, chain: &[SpaceId], hosts: &[[u8; 32]]) -> Vec<SpaceOp> {
    let was = hosts_no_in(state, chain);
    let mut ops = Vec::new();
    for n in was.nodes.iter().chain(&was.before) {
        let has = state
            .node(n)
            .is_some_and(|n| !n.values(NO_HOSTS).is_empty());
        if has {
            ops.push(SpaceOp::set(*n, NO_HOSTS, None));
        }
    }
    for (node, host) in &was.not_these {
        if hosts.contains(host) {
            ops.push(SpaceOp::delete(*node));
        }
    }
    ops
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A device node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceRecord {
    /// The node.
    pub node: NodeId,
    /// The device key.
    pub key: KeyId,
    /// Its name (the value last in log order if in conflict).
    pub name: String,
    /// Whether it is always on.
    pub always_on: bool,
    /// Whether it is a host for this identity.
    pub is_host: bool,
}

/// A host node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostRecord {
    /// The node.
    pub node: NodeId,
    /// The signed grant.
    pub grant: Vec<u8>,
}

/// A placement: where one device keeps one space.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlacementRecord {
    /// The node.
    pub node: NodeId,
    /// The device.
    pub device: KeyId,
    /// Retention.
    pub retention: Retention,
    /// Where the device shows the space.
    pub path: Option<String>,
    /// Whether the device is a light holder.
    pub light: bool,
}

/// A space node with its placements.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpaceRecord {
    /// The node.
    pub node: NodeId,
    /// The space.
    pub space: SpaceId,
    /// Its local name.
    pub name: String,
    /// Placements.
    pub placements: Vec<PlacementRecord>,
    /// An offer of it that this person said no to (`profiles.md#group`).
    pub declined: bool,
    /// The space it succeeded, if it is a successor this person's device
    /// followed (field 4).
    pub succeeded: Option<SpaceId>,
}

/// Whether every value of a flag is true, `absent` where it has none (or
/// a value is cleared).
fn every(n: &crate::state::Node, key: u64, absent: bool) -> bool {
    let vs = n.values(key);
    let one = |v: &crate::state::FieldValue| v.value.as_ref().map_or(Some(absent), Value::as_bool);
    match vs.is_empty() {
        true => absent,
        false => vs.iter().all(|v| one(v) == Some(true)),
    }
}

/// Whether any value of a flag is true.
fn some(n: &crate::state::Node, key: u64) -> bool {
    n.values(key)
        .iter()
        .any(|v| v.value.as_ref().and_then(Value::as_bool) == Some(true))
}

fn last(n: &crate::state::Node, key: u64) -> Option<&Value> {
    // the value with the greatest entry id, for display when in conflict
    n.values(key).iter().rev().find_map(|v| v.value.as_ref())
}

/// `create` of an invitation node: the invitation record, and how its person
/// will regard whoever uses it, in the fields a contact keeps that in.
pub fn create_invitation(invitation: Record, regard: Regard) -> SpaceOp {
    create_invitation_met(invitation, regard, None)
}

/// `create` of an invitation node that says how whoever uses it will have
/// met this person: through an introduction, for one made for that.
pub fn create_invitation_met(invitation: Record, regard: Regard, met: Option<&Met>) -> SpaceOp {
    SpaceOp::create(
        NodeKind::Uint(INVITATION),
        ROOT,
        "invitation",
        Record::new()
            .with(1, Value::Record(invitation))
            .with(INTRODUCTIONS, regard.introductions)
            .with(TRUSTED, regard.trusted)
            .with_opt(MET, met.map(|m| Value::Record(m.to_record()))),
    )
}

/// Cancels an invitation, on every device.
pub fn cancel_invitation(invitation: NodeId) -> SpaceOp {
    set_field(invitation, CANCELLED, true)
}

/// `create` of a use of an invitation, by `who`.
pub fn create_invitation_use(invitation: NodeId, who: &IdentityId) -> SpaceOp {
    SpaceOp::create(
        NodeKind::Uint(INVITATION_USE),
        invitation,
        &short_key(who),
        Record::new().with(1, *who),
    )
}

/// An invitation this person made.
#[derive(Clone, Debug)]
pub struct InvitationRecord {
    /// How whoever uses it will have met this person, if not by invitation.
    pub met: Option<Met>,
    /// The invitation node.
    pub node: NodeId,
    /// The entry that made it.
    pub entry: EntryId,
    /// The invitation itself (`contact.md#invitations`).
    pub invitation: Record,
    /// How whoever uses it will be regarded.
    pub regard: Regard,
    /// The inviter cancelled it.
    pub cancelled: bool,
    /// How many times it has been used, on any device.
    pub used: usize,
}

/// Invitation nodes that are not deleted.
pub fn invitations(state: &State) -> Vec<InvitationRecord> {
    let nodes = state.children(&ROOT).into_iter();
    let made = nodes.filter(|n| n.kind == NodeKind::Uint(INVITATION) && !n.deleted);
    made.filter_map(|n| {
        let flag = |key| last(n, key).and_then(Value::as_bool);
        let uses = state.children(&n.id).into_iter();
        let used = uses
            .filter(|u| u.kind == NodeKind::Uint(INVITATION_USE) && !u.deleted)
            .count();
        Some(InvitationRecord {
            node: n.id,
            entry: n.created_in,
            invitation: last(n, 1)?.as_record()?.clone(),
            regard: Regard {
                trusted: flag(TRUSTED).unwrap_or(true),
                introductions: flag(INTRODUCTIONS).unwrap_or(true),
            },
            cancelled: flag(CANCELLED).unwrap_or(false),
            used,
            met: last(n, MET)
                .and_then(Value::as_record)
                .and_then(Met::from_record),
        })
    })
    .collect()
}

/// A person this identity has a relationship with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactRecord {
    /// The contact node.
    pub node: NodeId,
    /// Their identity.
    pub identity: IdentityId,
    /// What this person sees them as: their petname, or where they have
    /// none the name they suggest, or else the start of their id.
    pub petname: String,
    /// Whether `petname` is this person's own (field 2), and not the name
    /// they suggest for themselves.
    pub own: bool,
    /// The name they suggest for themselves, as last heard (field 12).
    pub suggested: Option<String>,
    /// This person's own picture for them (field 11): a blob reference.
    pub picture: Option<Record>,
    /// The relationship space.
    pub space: SpaceId,
    /// How this person regards them.
    pub regard: Regard,
    /// This person wants nothing to do with them.
    pub refused: bool,
    /// Where the relationship is listed, such as `People`.
    pub category: String,
    /// How the two met, if that was kept.
    pub met: Option<Met>,
    /// This person named them a guardian (field 5).
    pub guardian: bool,
    /// The relationship is between a recovery helper and a guardian of
    /// this identity, and is no contact (field [`RECOVERY_OF`]).
    pub recovery_of: Option<IdentityId>,
}

impl ContactRecord {
    /// Whether a device may open a session with theirs. Whether one opens
    /// is up to them as well.
    pub fn connects(&self) -> bool {
        self.regard.trusted && !self.refused
    }
}

/// The contact nodes this person has for `who`. Two devices that made one
/// at the same moment made two: they are one contact.
pub fn nodes_of<'a>(contacts: &'a [ContactRecord], who: &IdentityId) -> Vec<&'a ContactRecord> {
    contacts.iter().filter(|c| c.identity == *who).collect()
}

/// Whether a device may open a session with `who`'s, judged by every
/// node this person has for them: each says they are trusted, and none
/// refuses them. With none, they are no contact.
pub fn connects(contacts: &[ContactRecord], who: &IdentityId) -> bool {
    let nodes = nodes_of(contacts, who);
    !nodes.is_empty() && nodes.iter().all(|c| c.connects())
}

/// Whether any node this person has for `who` refuses them.
pub fn refused(contacts: &[ContactRecord], who: &IdentityId) -> bool {
    nodes_of(contacts, who).iter().any(|c| c.refused)
}

/// Contact nodes that are not deleted.
pub fn contacts(state: &State) -> Vec<ContactRecord> {
    state
        .children(&ROOT)
        .into_iter()
        .filter(|n| n.kind == NodeKind::Uint(CONTACT) && !n.deleted)
        .filter_map(|n| {
            let (all, any) = (|key, absent| every(n, key, absent), |key| some(n, key));
            let text = |key| {
                last(n, key)
                    .and_then(Value::as_text)
                    .map(str::trim)
                    .filter(|t| !t.is_empty())
                    .map(str::to_owned)
            };
            let identity: IdentityId = last(n, 1)?.as_bytes()?.try_into().ok()?;
            let own = text(PETNAME);
            let suggested = text(SUGGESTED);
            Some(ContactRecord {
                node: n.id,
                identity,
                own: own.is_some(),
                petname: own
                    .or_else(|| suggested.clone())
                    .unwrap_or_else(|| short_key(&identity)),
                suggested,
                picture: last(n, PICTURE).and_then(Value::as_record).cloned(),
                space: last(n, 3)?.as_bytes()?.try_into().ok()?,
                // a field in conflict is read as two records are: the
                // cautious answer
                regard: Regard {
                    trusted: all(TRUSTED, false),
                    introductions: all(INTRODUCTIONS, true),
                },
                refused: any(REFUSED),
                category: last(n, CATEGORY)
                    .and_then(Value::as_text)
                    .map(str::trim)
                    .filter(|c| !c.is_empty())
                    .unwrap_or(PEOPLE)
                    .to_owned(),
                met: last(n, MET)
                    .and_then(Value::as_record)
                    .and_then(Met::from_record),
                guardian: all(GUARDIAN, false),
                recovery_of: last(n, RECOVERY_OF)
                    .and_then(Value::as_bytes)
                    .and_then(|b| b.try_into().ok()),
            })
        })
        .collect()
}

/// Device nodes that are not deleted.
pub fn devices(state: &State) -> Vec<DeviceRecord> {
    let mut v: Vec<DeviceRecord> = state
        .children(&ROOT)
        .into_iter()
        .filter(|n| n.kind == NodeKind::Uint(DEVICE) && !n.deleted)
        .filter_map(|n| {
            Some(DeviceRecord {
                node: n.id,
                key: last(n, 1)?.as_bytes()?.try_into().ok()?,
                name: last(n, 2)
                    .and_then(|v| v.as_text())
                    .unwrap_or("")
                    .to_owned(),
                always_on: last(n, 3).and_then(|v| v.as_bool()).unwrap_or(false),
                is_host: last(n, 4).and_then(|v| v.as_bool()).unwrap_or(false),
            })
        })
        .collect();
    v.sort_by_key(|a| a.key);
    v
}

/// Every host node.
pub fn hosts(state: &State) -> Vec<HostRecord> {
    state
        .children(&ROOT)
        .into_iter()
        .filter(|n| n.kind == NodeKind::Uint(HOST) && !n.deleted)
        .filter_map(|n| {
            Some(HostRecord {
                node: n.id,
                grant: last(n, 1)?.as_bytes()?.to_vec(),
            })
        })
        .collect()
}

/// The name of a device, if the account space has one.
pub fn device_name(state: &State, key: &KeyId) -> Option<String> {
    devices(state)
        .into_iter()
        .find(|d| &d.key == key)
        .map(|d| d.name)
}

/// Space nodes that are not deleted, with their placements.
pub fn spaces(state: &State) -> Vec<SpaceRecord> {
    state
        .children(&ROOT)
        .into_iter()
        .filter(|n| n.kind == NodeKind::Uint(SPACE) && !n.deleted)
        .filter_map(|n| {
            let placements = state
                .children(&n.id)
                .into_iter()
                .filter(|p| p.kind == NodeKind::Uint(PLACEMENT) && !p.deleted)
                .filter_map(|p| {
                    Some(PlacementRecord {
                        node: p.id,
                        device: last(p, 1)?.as_bytes()?.try_into().ok()?,
                        retention: Retention::from_u64(last(p, 2)?.as_uint()?)?,
                        path: last(p, 3).and_then(|v| v.as_text()).map(str::to_owned),
                        light: last(p, 4).and_then(|v| v.as_bool()).unwrap_or(false),
                    })
                })
                .collect();
            Some(SpaceRecord {
                node: n.id,
                space: last(n, 1)?.as_bytes()?.try_into().ok()?,
                name: last(n, 2)
                    .and_then(|v| v.as_text())
                    .unwrap_or("")
                    .to_owned(),
                placements,
                declined: last(n, 3).and_then(|v| v.as_bool()).unwrap_or(false),
                succeeded: last(n, SUCCEEDED)
                    .and_then(Value::as_bytes)
                    .and_then(|b| b.try_into().ok()),
            })
        })
        .collect()
}

/// A persona this person holds (`identity.md#personas`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersonaRecord {
    /// The persona node.
    pub node: NodeId,
    /// Its purpose: `guardian`, `agent`, or another.
    pub purpose: String,
    /// The entropy its root is made from.
    pub entropy: [u8; 32],
    /// Its identity id.
    pub identity: IdentityId,
    /// The identity it serves, such as the person it guards.
    pub for_identity: Option<IdentityId>,
    /// It was burned: its purpose is over.
    pub burned: bool,
}

/// The persona purpose of guarding one person.
pub const GUARDIAN_PURPOSE: &str = "guardian";
/// Persona field 5: burned.
pub const BURNED: u64 = 5;

/// `create` of a persona node.
pub fn create_persona(
    purpose: &str,
    entropy: &[u8; 32],
    identity: &IdentityId,
    for_identity: Option<&IdentityId>,
) -> SpaceOp {
    SpaceOp::create(
        NodeKind::Uint(PERSONA),
        ROOT,
        &short_key(identity),
        Record::new()
            .with(1, purpose)
            .with(2, entropy.to_vec())
            .with(3, *identity)
            .with_opt(4, for_identity.copied()),
    )
}

/// The persona nodes that are not deleted.
pub fn personas(state: &State) -> Vec<PersonaRecord> {
    state
        .children(&ROOT)
        .into_iter()
        .filter(|n| n.kind == NodeKind::Uint(PERSONA) && !n.deleted)
        .filter_map(|n| {
            Some(PersonaRecord {
                node: n.id,
                purpose: last(n, 1)?.as_text()?.to_owned(),
                entropy: last(n, 2)?.as_bytes()?.try_into().ok()?,
                identity: last(n, 3)?.as_bytes()?.try_into().ok()?,
                for_identity: last(n, 4)
                    .and_then(Value::as_bytes)
                    .and_then(|b| b.try_into().ok()),
                burned: last(n, BURNED).and_then(Value::as_bool).unwrap_or(false),
            })
        })
        .collect()
}

/// The ops of a change to `who`'s contact: `changes`, a value (or `None`,
/// to clear) for each field, set on every record of theirs but a
/// recovery's. Where two or more records name the same relationship space
/// as the one with the lowest node id, they are merged into it first, in
/// the same ops (`profiles.md#account`, "Two records of one contact"): it is
/// set to the cautious value of fields 6 to 8 (trusted and taking
/// introductions only if every record is, refused if any is) and to the
/// petname written last, by the times its entries give; it keeps its other
/// fields, filling any it lacks from the others, newest first; and the
/// others are deleted. A record that names another relationship is left as
/// it is, and set like the rest: deleting it would take that relationship
/// out of the person's contacts. Nothing where they have no record.
pub fn contact_change(
    sp: &crate::Space,
    who: &IdentityId,
    changes: &[(u64, Option<Value>)],
) -> Vec<SpaceOp> {
    let state = sp.state();
    let mut records: Vec<&crate::state::Node> = state
        .children(&ROOT)
        .into_iter()
        .filter(|n| n.kind == NodeKind::Uint(CONTACT) && !n.deleted)
        .filter(|n| last(n, 1).and_then(Value::as_bytes) == Some(&who[..]))
        .filter(|n| n.values(RECOVERY_OF).iter().all(|v| v.value.is_none()))
        .collect();
    records.sort_by_key(|n| n.id);
    let Some(target) = records.first().copied() else {
        return Vec::new();
    };
    let space_of = |n: &crate::state::Node| last(n, 3).cloned();
    let (merged, apart): (Vec<&crate::state::Node>, Vec<&crate::state::Node>) = records
        .iter()
        .copied()
        .partition(|n| space_of(n) == space_of(target));
    let changed = |key: u64| changes.iter().any(|(k, _)| *k == key);
    let mut ops = Vec::new();
    if merged.len() > 1 {
        // when each value was written: the time its entry gives, then log order
        let when = |v: &crate::state::FieldValue| {
            let time = sp.dag().get(&v.entry).and_then(|e| e.time());
            (time, sp.dag().position(&v.entry))
        };
        let flags = [
            (TRUSTED, merged.iter().all(|n| every(n, TRUSTED, false))),
            (
                INTRODUCTIONS,
                merged.iter().all(|n| every(n, INTRODUCTIONS, true)),
            ),
            (REFUSED, merged.iter().any(|n| some(n, REFUSED))),
        ];
        for (key, want) in flags {
            let has = match key {
                REFUSED => some(target, key),
                INTRODUCTIONS => every(target, key, true),
                _ => every(target, key, false),
            };
            if !changed(key) && (has != want || target.in_conflict(key)) {
                ops.push(set_field(target.id, key, want));
            }
        }
        // the petname written last
        let newest = |key: u64| {
            merged
                .iter()
                .flat_map(|n| n.values(key).iter())
                .max_by_key(|v| when(v))
                .cloned()
        };
        if let Some(name) = newest(PETNAME) {
            let same = target.values(PETNAME).len() == 1 && target.values(PETNAME)[0] == name;
            if !changed(PETNAME) && !same {
                ops.push(SpaceOp::set(target.id, PETNAME, name.value));
            }
        }
        // what the target lacks, from the others
        let keys: std::collections::BTreeSet<u64> = merged[1..]
            .iter()
            .flat_map(|n| n.fields.keys().copied())
            .collect();
        for key in keys {
            let ours = [1, 3, PETNAME, INTRODUCTIONS, TRUSTED, REFUSED, RECOVERY_OF];
            if ours.contains(&key) || changed(key) || !target.values(key).is_empty() {
                continue;
            }
            if let Some(v) = newest(key).and_then(|v| v.value) {
                ops.push(SpaceOp::set(target.id, key, Some(v)));
            }
        }
        ops.extend(merged[1..].iter().map(|n| SpaceOp::delete(n.id)));
    }
    for n in std::iter::once(target).chain(apart) {
        for (key, value) in changes {
            ops.push(SpaceOp::set(n.id, *key, value.clone()));
        }
    }
    ops
}

/// Whom one recovery policy of this person's names: a guardians node
/// (`profiles.md#account`, kind 17).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardiansRecord {
    /// The node.
    pub node: NodeId,
    /// The `set_recovery` entry of this identity.
    pub policy: EntryId,
    /// For each commitment of that policy, in its order: the guardian's
    /// identity, as their contact names it, and the persona they guard this
    /// person through.
    pub named: Vec<(IdentityId, IdentityId)>,
    /// When the entry that made it says it was made.
    pub made: Option<u64>,
}

/// `create` of a guardians node: `named`, for each commitment of `policy`
/// in its order, the guardian and their persona.
pub fn create_guardians(policy: &EntryId, named: &[(IdentityId, IdentityId)]) -> SpaceOp {
    let item =
        |(g, p): &(IdentityId, IdentityId)| Value::Record(Record::new().with(1, *g).with(2, *p));
    SpaceOp::create(
        NodeKind::Uint(GUARDIANS),
        ROOT,
        "",
        Record::new()
            .with(1, *policy)
            .with(2, Value::List(named.iter().map(item).collect())),
    )
}

/// The guardians nodes that are not deleted and are written as their
/// table says; one that is not is no record of anything.
pub fn guardians_named(state: &State) -> Vec<GuardiansRecord> {
    let id32 = |v: &Value| -> Option<[u8; 32]> { v.as_bytes()?.try_into().ok() };
    state
        .children(&ROOT)
        .into_iter()
        .filter(|n| n.kind == NodeKind::Uint(GUARDIANS) && !n.deleted)
        .filter_map(|n| {
            let policy = n.field(1).and_then(id32)?;
            let named = n
                .field(2)?
                .as_list()?
                .iter()
                .map(|v| {
                    let r = v.as_record()?;
                    Some((r.get(1).and_then(id32)?, r.get(2).and_then(id32)?))
                })
                .collect::<Option<Vec<_>>>()?;
            Some(GuardiansRecord {
                node: n.id,
                policy,
                named,
                made: n.created,
            })
        })
        .collect()
}
