//! The account profile (`profiles.md#account`): the parts the first
//! milestone needs — device nodes, and space nodes with their placements.

use cardinal_encoding::{Record, Value};
use cardinal_identity::KeyId;

use crate::entry::{NodeId, NodeKind, SpaceId, SpaceOp};
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
}

fn last(n: &crate::state::Node, key: u64) -> Option<&Value> {
    // the value with the greatest entry id, for display when in conflict
    n.values(key).iter().rev().find_map(|v| v.value.as_ref())
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
            })
        })
        .collect()
}
