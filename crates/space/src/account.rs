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
/// Persona kind (`profiles.md#account`, D78).
pub const PERSONA: u64 = 16;

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

/// Contact nodes that are not deleted.
pub fn contacts(state: &State) -> Vec<ContactRecord> {
    state
        .children(&ROOT)
        .into_iter()
        .filter(|n| n.kind == NodeKind::Uint(CONTACT) && !n.deleted)
        .filter_map(|n| {
            let flag = |key| last(n, key).and_then(Value::as_bool);
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
                regard: Regard {
                    trusted: flag(TRUSTED).unwrap_or(false),
                    introductions: flag(INTRODUCTIONS).unwrap_or(true),
                },
                refused: flag(REFUSED).unwrap_or(false),
                category: last(n, CATEGORY)
                    .and_then(Value::as_text)
                    .map(str::trim)
                    .filter(|c| !c.is_empty())
                    .unwrap_or(PEOPLE)
                    .to_owned(),
                met: last(n, MET)
                    .and_then(Value::as_record)
                    .and_then(Met::from_record),
                guardian: flag(GUARDIAN).unwrap_or(false),
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
