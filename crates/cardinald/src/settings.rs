//! On-or-off settings kept in the person's account (`profiles.md#account`,
//! kind 6: `1: name, 2: value`), so that each holds on every device of
//! theirs: asking routers (D76) and read markers.
//!
//! A setting is on unless a node of that name says false, in any of its
//! values: where two devices set it at once, off and on, it is off.

use std::sync::Arc;

use cardinal_encoding::{Record, Value};
use cardinal_space::account;
use cardinal_space::entry::{NodeKind, SpaceOp};
use cardinal_space::ROOT;
use serde_json::{json, Value as Json};

use crate::core::Core;
use crate::daemon::Daemon;

/// The setting that lets others see what this person has read
/// (`profiles.md#relationship`, "Read markers are the person's to give").
pub const READ_MARKERS: &str = "read markers";

fn nodes<'a>(
    state: &'a cardinal_space::State,
    name: &'a str,
) -> impl Iterator<Item = &'a cardinal_space::Node> + 'a {
    state
        .children(&ROOT)
        .into_iter()
        .filter(|n| n.kind == NodeKind::Uint(account::SETTING) && !n.deleted)
        .filter(move |n| n.field(1).and_then(Value::as_text) == Some(name))
}

/// Whether the setting `name` is on.
pub fn on(state: &cardinal_space::State, name: &str) -> bool {
    let off = nodes(state, name)
        .flat_map(|n| n.values(2).iter())
        .any(|v| v.value.as_ref().and_then(Value::as_bool) == Some(false));
    !off
}

/// What sets `name`: a `set` on each node of that name, or a new node.
pub fn set_ops(state: &cardinal_space::State, name: &str, on: bool) -> Vec<SpaceOp> {
    let ids: Vec<_> = nodes(state, name).map(|n| n.id).collect();
    if ids.is_empty() {
        let fields = Record::new().with(1, name).with(2, on);
        return vec![SpaceOp::create(
            NodeKind::Uint(account::SETTING),
            ROOT,
            name,
            fields,
        )];
    }
    ids.into_iter()
        .map(|n| account::set_field(n, 2, on))
        .collect()
}

/// Whether this person's devices create and move read markers: on unless
/// they turned it off.
pub fn read_markers_on(core: &Core) -> bool {
    let acc = core.account().and_then(|a| a.space.as_ref());
    acc.is_none_or(|a| on(a.state(), READ_MARKERS))
}

/// `read-markers`: whether others see what this person has read, and with
/// `on`, the person's answer, for every device of theirs.
pub fn read_markers(d: &Arc<Daemon>, set: Option<bool>) -> anyhow::Result<Json> {
    if let Some(want) = set {
        let (account, ops) = {
            let core = d.core();
            let acc = core
                .account()
                .ok_or_else(|| anyhow::anyhow!("the account space is not here yet"))?;
            let st = acc
                .space
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("the account space is not open yet"))?
                .state();
            (acc.id, set_ops(st, READ_MARKERS, want))
        };
        d.write_and_push(&account, ops)?;
    }
    Ok(json!({"on": read_markers_on(&d.core())}))
}

/// What `mark-read` answers where read markers are off: nothing written,
/// and why.
pub fn markers_off() -> Json {
    json!({
        "marked": false,
        "why": "read markers are off: others do not see what you have read",
    })
}
