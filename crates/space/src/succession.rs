//! Succession across two spaces (`spaces.md#succession`): the identity
//! logs a cut is judged with, whether a device follows a successor, and
//! what it posts again there.
//!
//! What one space's validity needs of a succession (a `succeed` closes what
//! descends from it, one successor stands) is in [`crate::validity`]; the
//! state at a cut and a successor's initial state are in [`Space`]. This
//! module is what lies between two spaces, and holds nothing of its own:
//! a device keeps what it needs to remember beside the spaces.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use cardinal_encoding::{Record, Value};
use cardinal_identity::{EntryId, IdentityLog, IdentityState};

use crate::entry::{derived_id, IdentityId, NodeId, SpaceOpBody, OWNER, WRITER};
use crate::space::Space;
use crate::state::{node_field, reach_node_id, State, ROOT};
use crate::SpaceOp;

/// `log` as it was at `heads`: its genesis and every entry of its own that
/// is one of them or in their causal past. Heads it does not hold, and the
/// heads of other identities' logs held under its label, are passed over;
/// what is held under its label (a guardian's entries) is kept whole.
pub fn pinned_log(log: &IdentityLog, heads: &[EntryId]) -> IdentityLog {
    let dag = log.dag();
    let own: Vec<EntryId> = heads.iter().filter(|h| dag.contains(h)).copied().collect();
    let mut past = dag.ancestors_of(&own);
    past.extend(own.iter().copied());
    let genesis = log.get(&log.id()).expect("a log holds its genesis").clone();
    let mut pinned = IdentityLog::from_genesis(genesis).expect("a held genesis is checked");
    for x in dag.log_order() {
        if *x != log.id() && past.contains(x) {
            let _ = pinned.insert(dag.get(x).expect("held").clone());
        }
    }
    for other in log.attached() {
        for e in other.entries() {
            let _ = pinned.attach(e.clone());
        }
    }
    pinned
}

/// The identities that wrote an entry of `cut` or of its causal past, in
/// `space`, sorted.
pub fn authors_at(space: &Space, cut: &[EntryId]) -> Vec<IdentityId> {
    let dag = space.dag();
    let mut past = dag.ancestors_of(cut);
    past.extend(cut.iter().copied());
    let mut who: Vec<IdentityId> = past
        .iter()
        .filter_map(|x| dag.get(x).map(|e| e.author()))
        .collect();
    who.sort();
    who.dedup();
    who
}

/// What a successor's genesis pins (`start` field 8): for each author of
/// an entry of the cut or its causal past whose log `log_of` gives, the
/// heads of everything held under that identity's label.
pub fn judged_with<'a>(
    space: &Space,
    cut: &[EntryId],
    log_of: impl Fn(&IdentityId) -> Option<&'a IdentityLog>,
) -> Vec<(IdentityId, Vec<EntryId>)> {
    let mut out = Vec::new();
    for who in authors_at(space, cut) {
        if let Some(log) = log_of(&who) {
            let mut heads = log.all_heads();
            heads.sort();
            out.push((who, heads));
        }
    }
    out
}

/// The identity logs a cut is judged with, evaluated together, as
/// `judged_with` pins them. `None` while a pinned log is not held here, or
/// is held without a head it pins: the state at the cut cannot be worked
/// out yet.
pub fn pinned_states<'a>(
    judged_with: &[(IdentityId, Vec<EntryId>)],
    log_of: impl Fn(&IdentityId) -> Option<&'a IdentityLog>,
) -> Option<Vec<Arc<IdentityState>>> {
    let mut logs = Vec::new();
    for (who, heads) in judged_with {
        let log = log_of(who)?;
        let held = |h: &EntryId| log.dag().contains(h) || log.has_attached(h);
        if !heads.iter().all(held) {
            return None;
        }
        logs.push(pinned_log(log, heads));
    }
    let refs: Vec<&IdentityLog> = logs.iter().collect();
    let states = cardinal_identity::log::evaluate_together(&refs);
    Some(states.into_iter().map(Arc::new).collect())
}

/// The members a space's genesis names, each with the highest role it
/// gives them, sorted: whom a successor names (`spaces.md#following`,
/// condition 4), read from the genesis alone.
pub fn genesis_members(space: &Space) -> Vec<(IdentityId, u64)> {
    let Some(g) = space.entry(&space.id()) else {
        return Vec::new();
    };
    let mut out: HashMap<IdentityId, u64> = HashMap::new();
    for op in g.ops() {
        if let SpaceOpBody::AddMember { identity, role, .. } = op.body() {
            let r = out.entry(*identity).or_insert(*role);
            *r = (*r).max(*role);
        }
    }
    let mut v: Vec<(IdentityId, u64)> = out.into_iter().collect();
    v.sort();
    v
}

/// What a member's device makes of a successor that stands
/// (`spaces.md#following`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Conditions 1, 2, 4 and 5 hold. It follows once its initial state is
    /// the state at the cut, as the device works it out (condition 3).
    Follow,
    /// The genesis does not name this member: it has been removed.
    LeftOut,
    /// Another owner, or none: the owner handing the space on, shown as an
    /// offer and not followed.
    HandedOn,
    /// Written by an owner this device knows to be frozen: shown as a
    /// space handed on.
    FrozenOwner,
    /// Public where the old space was not: shown as an offer.
    MadePublic,
    /// It does not name the old space, or its cut is not behind every
    /// `succeed` that names it: the device tells its person, and follows
    /// nothing.
    NotWhatItSays(&'static str),
    /// The old space has no owner: its members end it together, each by
    /// hand, and nothing follows on its own.
    NoOwner,
}

/// Judges `new`, the successor that stands, against `old`, the space it
/// succeeds, for the member `me`: every condition of following but the
/// third, which needs the initial state worked out and compared
/// (`spaces.md#following`). `frozen` says whether this device knows the
/// old owner to be frozen.
pub fn verdict(old: &Space, new: &Space, me: &IdentityId, frozen: bool) -> Verdict {
    let Some(owner) = old.owner() else {
        return Verdict::NoOwner;
    };
    let Some(from) = new.succession() else {
        return Verdict::NotWhatItSays("it does not say it succeeds the space");
    };
    if from.succeeds != Some(old.id()) {
        return Verdict::NotWhatItSays("it succeeds another space");
    }
    let dag = old.dag();
    let naming = old.succeeds_naming(&new.id());
    if naming.is_empty() {
        return Verdict::NotWhatItSays("nothing valid names it");
    }
    for s in &naming {
        if from.cut.iter().any(|c| !dag.is_ancestor(c, s)) {
            return Verdict::NotWhatItSays("its cut is not behind the end of the space");
        }
    }
    let members = genesis_members(new);
    let names_owner = members.iter().any(|(w, r)| *w == owner && *r == OWNER);
    if new.creator() != owner || !names_owner {
        return Verdict::HandedOn;
    }
    if frozen {
        return Verdict::FrozenOwner;
    }
    if new.is_public() && !old.is_public() {
        return Verdict::MadePublic;
    }
    if !members.iter().any(|(w, _)| w == me) {
        return Verdict::LeftOut;
    }
    Verdict::Follow
}

/// The entries whose values or positions a state carried from an earlier
/// space: what everything in a space with that initial state descends
/// from.
pub fn carried_entries(state: &State) -> HashSet<EntryId> {
    let mut out = HashSet::new();
    for n in state.nodes() {
        if !state.is_carried(&n.id) {
            continue;
        }
        out.insert(n.position_writer);
        for vs in n.fields.values() {
            out.extend(vs.iter().map(|v| v.entry));
        }
    }
    for (_, fields) in state.reach_nodes() {
        for vs in fields.values() {
            out.extend(vs.iter().map(|v| v.entry));
        }
    }
    out
}

/// An entry to post again: the ops to write, in one new entry, and the
/// original it stands for.
#[derive(Clone, Debug, PartialEq)]
pub struct Repost {
    /// The entry posted again, in the space it was written in.
    pub source: EntryId,
    /// The ops of the new entry: its application ops, in their order, with
    /// node ids as the successor has them.
    pub ops: Vec<SpaceOp>,
}

/// What posting an entry again comes to, as things stand.
#[derive(Clone, Debug, PartialEq)]
pub enum Plan {
    /// Post these ops.
    Post(Repost),
    /// It names a node someone in the successor created, whose `create`
    /// has not come there yet: try again when it has.
    Wait,
    /// Nothing in it is posted again: it holds control ops alone, or a
    /// `set` of a reach node, which each member sets afresh.
    Nothing,
}

/// Plans the posting again of `entry`, written in `from`, into `into`
/// (`spaces.md#what-the-successor-does-not-carry`).
///
/// - Control ops, a `set` of a reach node and a `checkpoint` are left out.
/// - A `create` carries in field 5 every id its node has had, and an op
///   that named a node by any of them names it by the id it has in `into`.
///   A parent created earlier in the same entry is named by its index in
///   the new entry.
/// - A node someone else created, and that `into` neither carried nor
///   has had posted again, is waited for while its creator is a member of
///   `into`. Otherwise what stands is posted without it: a `create` goes
///   under the nearest node above it that `into` has, a field naming it is
///   left out, and an op on it is left out.
/// - A `set` is posted beside unless every value the field has in `into`
///   was written by an entry the original had seen; a `delete` is posted
///   beside if anything the original had not seen touches the node there.
///
/// `origin` gives, for an entry of `into` that is a posting again, the
/// entry it stands for: such an entry was seen by the original if what it
/// stands for was.
pub fn plan_repost(
    from: &Space,
    entry: &EntryId,
    into: &Space,
    origin: &dyn Fn(&EntryId) -> Option<EntryId>,
) -> Plan {
    let Some(e) = from.entry(entry) else {
        return Plan::Nothing;
    };
    let carried_from = from
        .initial_state()
        .map(carried_entries)
        .unwrap_or_default();
    // Whether the original had seen what `x` wrote.
    let seen_in_from = |x: &EntryId| -> bool {
        if from.dag().contains(x) {
            from.dag().is_ancestor_or_self(x, entry)
        } else {
            carried_from.contains(x)
        }
    };
    let seen = |x: &EntryId| -> bool {
        if into.dag().contains(x) {
            origin(x).is_some_and(|o| seen_in_from(&o))
        } else {
            seen_in_from(x)
        }
    };
    let members: HashSet<IdentityId> = into.validity().identities().into_iter().collect();
    let in_into: HashSet<IdentityId> = genesis_members(into)
        .into_iter()
        .map(|(w, _)| w)
        .chain(members)
        .collect();
    let target = into.state();
    let source = from.state();
    let profile = into.profile();
    // places of creates of this entry that are kept, by their old place
    let mut made_here: HashMap<NodeId, u32> = HashMap::new();
    let mut ops: Vec<SpaceOp> = Vec::new();
    enum Named {
        Is(Value),
        Gone,
        Wait,
    }
    let name = |n: &NodeId, made_here: &HashMap<NodeId, u32>| -> Named {
        if *n == ROOT {
            return Named::Is(Value::from(ROOT));
        }
        if let Some(i) = made_here.get(n) {
            return Named::Is(Value::from(*i as u64));
        }
        if let Some(now) = target.now_called(n) {
            return Named::Is(Value::from(now));
        }
        let creator = source.node(n).map(|x| x.creator);
        match creator {
            Some(c) if in_into.contains(&c) => Named::Wait,
            Some(_) => Named::Gone,
            None => Named::Gone,
        }
    };
    // the nearest node above `n` in `from` that `into` has, or the root
    let nearest = |n: &NodeId, made_here: &HashMap<NodeId, u32>| -> Value {
        let mut cur = *n;
        for _ in 0..=source.len() {
            if let Some(i) = made_here.get(&cur) {
                return Value::from(*i as u64);
            }
            if let Some(now) = target.now_called(&cur) {
                return Value::from(now);
            }
            match source.node(&cur) {
                Some(x) if x.parent != ROOT => cur = x.parent,
                _ => break,
            }
        }
        Value::from(ROOT)
    };
    let all_seen = |node: &NodeId, key: u64| -> bool {
        let vals = match target.node(node) {
            Some(n) => n.values(key),
            None => return true,
        };
        vals.iter().all(|v| seen(&v.entry))
    };
    let touched_unseen = |node: &NodeId| -> bool {
        let mut todo = vec![*node];
        let mut n = 0;
        while let Some(x) = todo.pop() {
            n += 1;
            if n > target.len() + 1 {
                break;
            }
            let Some(nd) = target.node(&x) else { continue };
            let moved = !target.is_carried(&x) || nd.position_writer != nd.created_in;
            if moved && !seen(&nd.position_writer) && !seen(&nd.created_in) {
                return true;
            }
            if nd.fields.values().flatten().any(|v| !seen(&v.entry)) {
                return true;
            }
            todo.extend(target.children(&x).iter().map(|c| c.id));
        }
        false
    };
    let own_reach = reach_node_id(&e.author());
    for (i, op) in e.ops().iter().enumerate() {
        let record = op.record().clone();
        let number = record.get(0).and_then(|v| v.as_uint()).unwrap_or(0);
        if number < 32 || number == 37 {
            continue;
        }
        let at = ops.len() as u32;
        match op.body() {
            SpaceOpBody::Create {
                kind,
                parent,
                fields,
                was,
                ..
            } => {
                let parent = match name(parent, &made_here) {
                    Named::Is(v) => v,
                    Named::Wait => return Plan::Wait,
                    Named::Gone => nearest(parent, &made_here),
                };
                let mut fields = fields.clone();
                if let Some(f) = node_field(profile, *kind) {
                    if let Some(id) = fields.get(f).and_then(node_of) {
                        match name(&id, &made_here) {
                            Named::Is(v) if v.as_bytes().is_some() => fields = fields.with(f, v),
                            Named::Wait => return Plan::Wait,
                            _ => fields = without(fields, f),
                        }
                    }
                }
                let mut had: Vec<NodeId> = was.clone();
                had.push(derived_id(entry, i));
                had.sort();
                had.dedup();
                let ids = Value::list(had.iter().map(|x| Value::from(*x)));
                made_here.insert(derived_id(entry, i), at);
                ops.push(SpaceOp::from_record(
                    record.with(2, parent).with(4, fields).with(5, ids),
                ));
            }
            SpaceOpBody::Set {
                node,
                key,
                value,
                beside,
            } => {
                // a reach node: each member sets its own afresh
                if *node == own_reach {
                    continue;
                }
                let now = match name(node, &made_here) {
                    Named::Is(v) => v,
                    Named::Wait => return Plan::Wait,
                    Named::Gone => continue,
                };
                let Some(now_id) = node_of(&now) else {
                    continue;
                };
                let mut value = value.clone();
                let kind = target
                    .node(&now_id)
                    .or_else(|| source.node(node))
                    .map(|n| n.kind);
                if kind.and_then(|k| node_field(profile, k)) == Some(*key) {
                    if let Some(id) = value.as_ref().and_then(node_of) {
                        match name(&id, &made_here) {
                            Named::Is(v) if v.as_bytes().is_some() => value = Some(v),
                            Named::Wait => return Plan::Wait,
                            _ => value = None,
                        }
                    }
                }
                let beside = *beside || !all_seen(&now_id, *key);
                let mut r = record.with(1, now).with_opt(3, value.clone());
                if value.is_none() {
                    r = without(r, 3);
                }
                if beside {
                    r = r.with(4, true);
                }
                ops.push(SpaceOp::from_record(r));
            }
            SpaceOpBody::Delete { node, beside } => {
                let now = match name(node, &made_here) {
                    Named::Is(v) => v,
                    Named::Wait => return Plan::Wait,
                    Named::Gone => continue,
                };
                let beside = *beside || node_of(&now).is_some_and(|n| touched_unseen(&n));
                let mut r = record.with(1, now);
                if beside {
                    r = r.with(2, true);
                }
                ops.push(SpaceOp::from_record(r));
            }
            SpaceOpBody::Move { node, parent, .. } => {
                let now = match name(node, &made_here) {
                    Named::Is(v) => v,
                    Named::Wait => return Plan::Wait,
                    Named::Gone => continue,
                };
                let parent = match name(parent, &made_here) {
                    Named::Is(v) => v,
                    Named::Wait => return Plan::Wait,
                    Named::Gone => nearest(parent, &made_here),
                };
                ops.push(SpaceOp::from_record(record.with(1, now).with(2, parent)));
            }
            SpaceOpBody::Restore { node } => {
                let now = match name(node, &made_here) {
                    Named::Is(v) => v,
                    Named::Wait => return Plan::Wait,
                    Named::Gone => continue,
                };
                ops.push(SpaceOp::from_record(record.with(1, now)));
            }
            // an application op nothing here reads: as it was
            _ => ops.push(SpaceOp::from_record(record)),
        }
    }
    if ops.is_empty() {
        return Plan::Nothing;
    }
    Plan::Post(Repost {
        source: *entry,
        ops,
    })
}

/// The node a value names, if it is a node id.
fn node_of(v: &Value) -> Option<NodeId> {
    v.as_bytes().and_then(|b| NodeId::try_from(b).ok())
}

/// `r` without the field `key`.
fn without(r: Record, key: u64) -> Record {
    let mut out = Record::new();
    for (k, v) in r.iter() {
        if *k != key {
            out = out.with(*k, v.clone());
        }
    }
    out
}

/// Whether `who` may post work again in `into`: a writer or above there.
pub fn may_post(into: &Space, who: &IdentityId) -> bool {
    into.role_of(who).is_some_and(|r| r >= WRITER)
}
