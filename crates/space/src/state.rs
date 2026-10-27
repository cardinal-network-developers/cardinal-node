//! The state tree (`state.md`): nodes, multi-value register fields, moves
//! in log order (Kleppmann et al.), deletes that yield to concurrent work,
//! and the canonical state (kind 13).
//!
//! # Computation and cost
//!
//! [`State::compute`] processes the valid entries in log order in three
//! passes:
//!
//! 1. **Acceptance.** Whether an entry is accepted for state depends only
//!    on which nodes exist in its causal past, their kinds and creators, so
//!    it is decided in one pass with a registry of created nodes. O(ops),
//!    plus an ancestor check per named node.
//! 2. **Deletes.** Each `delete` is decided against the positions in its
//!    own causal past and the ops of concurrent accepted entries. This
//!    replays creates and moves of the delete's past, and scans the entries
//!    concurrent with it: O(n) per delete.
//! 3. **Application.** Creates, sets, moves, deletes, and restores are
//!    applied in log order. A set drops the values whose entries are its
//!    ancestors; a move that would make a node its own ancestor is skipped.
//!
//! [`State::append`] applies an entry that descends from every entry
//! already applied, which therefore comes last in log order, without
//! recomputing: its deletes have no concurrent work, and the state so far
//! is the state of its causal past. Any other arrival recomputes from
//! scratch, which is O(n log n + deletes × n).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use cardinal_encoding::kind::CANONICAL_STATE;
use cardinal_encoding::{Record, Value};
use cardinal_identity::dag::Dag;
use cardinal_identity::EntryId;

use crate::entry::{derived_id, IdentityId, NodeId, NodeKind, Profile, SpaceEntry, SpaceOpBody};

/// The root node's id: sixteen zero bytes.
pub const ROOT: NodeId = [0; 16];

/// The field that marks a node author-owned (`profiles.md#shared-rules-normative`).
pub const AUTHOR_OWNED_FIELD: u64 = 15;

/// One value of a multi-value register.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldValue {
    /// The entry that wrote it.
    pub entry: EntryId,
    /// The op's position in that entry.
    pub op: u32,
    /// The value, or `None` if the field was cleared.
    pub value: Option<Value>,
}

/// A node of the state tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    /// Its id.
    pub id: NodeId,
    /// Its kind.
    pub kind: NodeKind,
    /// Its parent.
    pub parent: NodeId,
    /// Its name.
    pub name: String,
    /// Fields: each key's current values, sorted by entry id. More than one
    /// value is a conflict.
    pub fields: BTreeMap<u64, Vec<FieldValue>>,
    /// Whether it is deleted.
    pub deleted: bool,
    /// Whether a delete of it was touched by concurrent work.
    pub delete_conflict: bool,
    /// The entry whose `create` or `move` set the current position.
    pub position_writer: EntryId,
    /// The identity that created it.
    pub creator: IdentityId,
    /// The entry that created it.
    pub created_in: EntryId,
    deleted_by: Option<(EntryId, u32)>,
}

impl Node {
    /// The field's single value, if it is settled and set.
    pub fn field(&self, key: u64) -> Option<&Value> {
        match self.fields.get(&key).map(|v| v.as_slice()) {
            Some([one]) => one.value.as_ref(),
            _ => None,
        }
    }

    /// Every value of the field.
    pub fn values(&self, key: u64) -> &[FieldValue] {
        self.fields.get(&key).map_or(&[], |v| v.as_slice())
    }

    /// Whether the field has more than one value.
    pub fn in_conflict(&self, key: u64) -> bool {
        self.values(key).len() > 1
    }

    /// Whether the node is author-owned.
    pub fn author_owned(&self) -> bool {
        self.values(AUTHOR_OWNED_FIELD)
            .iter()
            .any(|v| v.value.as_ref().and_then(|x| x.as_uint()) == Some(1))
    }
}

/// What a profile allows to be created where (`profiles.md`).
pub fn may_place(profile: Profile, kind: NodeKind, parent: Option<NodeKind>) -> bool {
    let NodeKind::Uint(k) = kind else {
        return !matches!(profile, Profile::Core(1) | Profile::Core(2));
    };
    let p = match parent {
        None => None,
        Some(NodeKind::Uint(p)) => Some(p),
        Some(NodeKind::Named(_)) => Some(u64::MAX),
    };
    match profile {
        // files: folders, files, links, under the root or a folder
        Profile::Core(2) => (1..=3).contains(&k) && matches!(p, None | Some(1)),
        // account
        Profile::Core(1) => match k {
            1..=6 | 10 => p.is_none(),
            7 => p == Some(2),
            8 | 9 => p == Some(3),
            11 => p == Some(10),
            _ => false,
        },
        _ => true,
    }
}

#[derive(Clone, Debug)]
struct Meta {
    kind: NodeKind,
    created_in: EntryId,
    creator: IdentityId,
    author_owned: bool,
}

/// The nodes named by an op (`state.md#operations`): target, parent, and
/// new parent.
pub fn named_nodes(op: &SpaceOpBody) -> Vec<NodeId> {
    match op {
        SpaceOpBody::Create { parent, .. } => vec![*parent],
        SpaceOpBody::Set { node, .. }
        | SpaceOpBody::Delete { node }
        | SpaceOpBody::Restore { node } => vec![*node],
        SpaceOpBody::Move { node, parent, .. } => vec![*node, *parent],
        _ => Vec::new(),
    }
}

/// The state tree of a space.
#[derive(Clone, Debug)]
pub struct State {
    profile: Profile,
    nodes: HashMap<NodeId, Node>,
    children: HashMap<NodeId, BTreeSet<NodeId>>,
    registry: HashMap<NodeId, Meta>,
    accepted: HashSet<EntryId>,
    rejected: HashSet<EntryId>,
    applied: Vec<EntryId>,
}

/// The effect of one delete op, decided against the whole set.
#[derive(Clone, Debug, Default)]
struct DeleteEffect {
    delete: Vec<NodeId>,
    conflict: bool,
}

impl State {
    /// An empty state (only the root).
    pub fn new(profile: Profile) -> State {
        State {
            profile,
            nodes: HashMap::new(),
            children: HashMap::new(),
            registry: HashMap::new(),
            accepted: HashSet::new(),
            rejected: HashSet::new(),
            applied: Vec::new(),
        }
    }

    /// The profile.
    pub fn profile(&self) -> Profile {
        self.profile
    }

    /// Computes the state of the `valid` entries of `dag`.
    pub fn compute(profile: Profile, dag: &Dag<SpaceEntry>, valid: &HashSet<EntryId>) -> State {
        let mut st = State::new(profile);
        let order: Vec<EntryId> = dag
            .log_order()
            .iter()
            .filter(|x| valid.contains(*x))
            .copied()
            .collect();
        // pass 1: acceptance
        for x in &order {
            let e = dag.get(x).expect("entry");
            if st.accept(dag, e) {
                st.accepted.insert(*x);
            } else {
                st.rejected.insert(*x);
            }
        }
        let accepted: Vec<EntryId> = order
            .iter()
            .filter(|x| st.accepted.contains(*x))
            .copied()
            .collect();
        // pass 2: deletes
        let mut effects: HashMap<(EntryId, u32), DeleteEffect> = HashMap::new();
        for x in &accepted {
            let e = dag.get(x).expect("entry");
            for (i, op) in e.ops().iter().enumerate() {
                if let SpaceOpBody::Delete { node } = op.body() {
                    effects.insert((*x, i as u32), st.delete_effect(dag, &accepted, x, node));
                }
            }
        }
        // pass 3: application
        for x in &accepted {
            let e = dag.get(x).expect("entry");
            st.apply(dag, e, &mut |k| effects.remove(&k).unwrap_or_default());
        }
        st
    }

    /// Applies an entry that descends from every entry already applied
    /// (and is valid). Returns whether it was accepted for state.
    pub fn append(&mut self, dag: &Dag<SpaceEntry>, e: &SpaceEntry) -> bool {
        if !self.accept(dag, e) {
            self.rejected.insert(e.id());
            return false;
        }
        self.accepted.insert(e.id());
        // its deletes see the state of its causal past: everything so far
        let mut effects: HashMap<u32, DeleteEffect> = HashMap::new();
        for (i, op) in e.ops().iter().enumerate() {
            if let SpaceOpBody::Delete { node } = op.body() {
                effects.insert(
                    i as u32,
                    DeleteEffect {
                        delete: self.subtree(node),
                        conflict: false,
                    },
                );
            }
        }
        self.apply(dag, e, &mut |(_, i)| effects.remove(&i).unwrap_or_default());
        true
    }

    fn kind_of(&self, n: &NodeId, local: &HashMap<NodeId, Meta>) -> Option<NodeKind> {
        local
            .get(n)
            .or_else(|| self.registry.get(n))
            .map(|m| m.kind)
    }

    /// Whether an entry is accepted for state; registers its nodes if so.
    fn accept(&mut self, dag: &Dag<SpaceEntry>, e: &SpaceEntry) -> bool {
        let id = e.id();
        let mut local: HashMap<NodeId, Meta> = HashMap::new();
        let known = |n: &NodeId, local: &HashMap<NodeId, Meta>, reg: &HashMap<NodeId, Meta>| {
            *n == ROOT
                || local.contains_key(n)
                || reg
                    .get(n)
                    .is_some_and(|m| dag.is_ancestor_or_self(&m.created_in, &id))
        };
        let owned_ok =
            |n: &NodeId, local: &HashMap<NodeId, Meta>, reg: &HashMap<NodeId, Meta>| match local
                .get(n)
                .or_else(|| reg.get(n))
            {
                Some(m) => !m.author_owned || m.creator == e.author(),
                None => false,
            };
        for (i, op) in e.ops().iter().enumerate() {
            let ok = match op.body() {
                SpaceOpBody::Create {
                    kind,
                    parent,
                    fields,
                    ..
                } => {
                    let ok = known(parent, &local, &self.registry)
                        && may_place(
                            self.profile,
                            *kind,
                            if *parent == ROOT {
                                None
                            } else {
                                self.kind_of(parent, &local)
                            },
                        );
                    let owned = fields.get(AUTHOR_OWNED_FIELD).and_then(|v| v.as_uint()) == Some(1);
                    local.insert(
                        derived_id(&id, i),
                        Meta {
                            kind: *kind,
                            created_in: id,
                            creator: e.author(),
                            author_owned: owned,
                        },
                    );
                    ok
                }
                SpaceOpBody::Set { node, .. }
                | SpaceOpBody::Delete { node }
                | SpaceOpBody::Restore { node } => {
                    *node != ROOT
                        && known(node, &local, &self.registry)
                        && owned_ok(node, &local, &self.registry)
                }
                SpaceOpBody::Move { node, parent, .. } => {
                    *node != ROOT
                        && known(node, &local, &self.registry)
                        && known(parent, &local, &self.registry)
                        && owned_ok(node, &local, &self.registry)
                        && self.kind_of(node, &local).is_some_and(|k| {
                            may_place(
                                self.profile,
                                k,
                                if *parent == ROOT {
                                    None
                                } else {
                                    self.kind_of(parent, &local)
                                },
                            )
                        })
                }
                SpaceOpBody::Unknown { number } => number.is_none_or(|n| n < 32),
                _ => true,
            };
            if !ok {
                return false;
            }
        }
        self.registry.extend(local);
        true
    }

    /// The nodes beneath `n` (and `n`) in the current tree.
    fn subtree(&self, n: &NodeId) -> Vec<NodeId> {
        let mut out = vec![*n];
        let mut i = 0;
        while i < out.len() {
            if let Some(cs) = self.children.get(&out[i]) {
                out.extend(cs.iter().copied());
            }
            i += 1;
        }
        out
    }

    fn delete_effect(
        &self,
        dag: &Dag<SpaceEntry>,
        accepted: &[EntryId],
        d: &EntryId,
        n: &NodeId,
    ) -> DeleteEffect {
        // positions in the delete's causal past
        let past = dag.ancestors(d);
        let mut parent: HashMap<NodeId, NodeId> = HashMap::new();
        for x in accepted.iter().filter(|x| past.contains(*x)) {
            let e = dag.get(x).expect("entry");
            for (i, op) in e.ops().iter().enumerate() {
                match op.body() {
                    SpaceOpBody::Create { parent: p, .. } => {
                        parent.insert(derived_id(x, i), *p);
                    }
                    SpaceOpBody::Move {
                        node, parent: p, ..
                    } if !would_cycle(&parent, node, p) => {
                        parent.insert(*node, *p);
                    }
                    _ => {}
                }
            }
        }
        let beneath = |m: &NodeId| -> Option<Vec<NodeId>> {
            // the chain from m up to n, if m is n or beneath it
            let mut chain = vec![*m];
            let mut cur = *m;
            let mut steps = 0;
            while cur != *n {
                cur = *parent.get(&cur)?;
                chain.push(cur);
                steps += 1;
                if steps > parent.len() + 1 {
                    return None;
                }
            }
            Some(chain)
        };
        let mut sub: Vec<NodeId> = parent
            .keys()
            .copied()
            .filter(|m| beneath(m).is_some())
            .collect();
        if !sub.contains(n) {
            sub.push(*n);
        }
        // ops of concurrent accepted entries that touch a node of the
        // subtree touch it and everything above it, up to n
        let mut touched: HashSet<NodeId> = HashSet::new();
        for c in accepted {
            if c == d || past.contains(c) || dag.is_ancestor(d, c) {
                continue;
            }
            for op in dag.get(c).expect("entry").ops() {
                for z in named_nodes(op.body()) {
                    if let Some(chain) = beneath(&z) {
                        touched.extend(chain);
                    }
                }
            }
        }
        DeleteEffect {
            delete: sub.into_iter().filter(|m| !touched.contains(m)).collect(),
            conflict: touched.contains(n),
        }
    }

    fn is_beneath(&self, m: &NodeId, n: &NodeId) -> bool {
        let mut cur = *m;
        let mut steps = 0;
        loop {
            if cur == *n {
                return true;
            }
            match self.nodes.get(&cur) {
                Some(node) => cur = node.parent,
                None => return false,
            }
            steps += 1;
            if steps > self.nodes.len() + 1 {
                return false;
            }
        }
    }

    fn set_parent(&mut self, node: NodeId, new_parent: NodeId) {
        if let Some(old) = self.nodes.get(&node).map(|n| n.parent) {
            if let Some(cs) = self.children.get_mut(&old) {
                cs.remove(&node);
            }
        }
        self.children.entry(new_parent).or_default().insert(node);
    }

    fn apply(
        &mut self,
        dag: &Dag<SpaceEntry>,
        e: &SpaceEntry,
        effect: &mut dyn FnMut((EntryId, u32)) -> DeleteEffect,
    ) {
        let id = e.id();
        for (i, op) in e.ops().iter().enumerate() {
            let i = i as u32;
            match op.body() {
                SpaceOpBody::Create {
                    kind,
                    parent,
                    name,
                    fields,
                } => {
                    let nid = derived_id(&id, i as usize);
                    let fields = fields
                        .iter()
                        .map(|(k, v)| {
                            (
                                *k,
                                vec![FieldValue {
                                    entry: id,
                                    op: i,
                                    value: Some(v.clone()),
                                }],
                            )
                        })
                        .collect();
                    self.children.entry(*parent).or_default().insert(nid);
                    self.nodes.insert(
                        nid,
                        Node {
                            id: nid,
                            kind: *kind,
                            parent: *parent,
                            name: name.clone(),
                            fields,
                            deleted: false,
                            delete_conflict: false,
                            position_writer: id,
                            creator: e.author(),
                            created_in: id,
                            deleted_by: None,
                        },
                    );
                }
                SpaceOpBody::Set { node, key, value } => {
                    if let Some(n) = self.nodes.get_mut(node) {
                        let vals = n.fields.entry(*key).or_default();
                        vals.retain(|v| !dag.is_ancestor_or_self(&v.entry, &id));
                        vals.push(FieldValue {
                            entry: id,
                            op: i,
                            value: value.clone(),
                        });
                        vals.sort_by_key(|a| (a.entry, a.op));
                    }
                }
                SpaceOpBody::Move { node, parent, name } => {
                    if !self.nodes.contains_key(node) || self.is_beneath(parent, node) {
                        continue; // a move that would make a cycle is skipped
                    }
                    self.set_parent(*node, *parent);
                    let n = self.nodes.get_mut(node).expect("node");
                    n.parent = *parent;
                    n.name = name.clone();
                    n.position_writer = id;
                }
                SpaceOpBody::Delete { node } => {
                    let eff = effect((id, i));
                    for m in eff.delete {
                        if let Some(n) = self.nodes.get_mut(&m) {
                            n.deleted = true;
                            n.delete_conflict = false;
                            n.deleted_by = Some((id, i));
                        }
                    }
                    if eff.conflict {
                        if let Some(n) = self.nodes.get_mut(node) {
                            n.delete_conflict = true;
                        }
                    }
                }
                SpaceOpBody::Restore { node } => {
                    let by = self.nodes.get(node).and_then(|n| n.deleted_by);
                    for m in self.subtree(node) {
                        if let Some(n) = self.nodes.get_mut(&m) {
                            if m == *node || (by.is_some() && n.deleted_by == by) {
                                n.deleted = false;
                                n.delete_conflict = false;
                                n.deleted_by = None;
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        self.applied.push(id);
    }

    /// A node (not the root).
    pub fn node(&self, id: &NodeId) -> Option<&Node> {
        self.nodes.get(id)
    }

    /// Every node.
    pub fn nodes(&self) -> impl Iterator<Item = &Node> {
        self.nodes.values()
    }

    /// The number of nodes, not counting the root.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether only the root exists.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// The children of a node, deleted or not, sorted by name then id.
    pub fn children(&self, id: &NodeId) -> Vec<&Node> {
        let mut v: Vec<&Node> = self
            .children
            .get(id)
            .into_iter()
            .flatten()
            .filter_map(|c| self.nodes.get(c))
            .collect();
        v.sort_by(|a, b| (&a.name, a.id).cmp(&(&b.name, b.id)));
        v
    }

    /// Whether a node and every node above it are not deleted.
    pub fn is_visible(&self, id: &NodeId) -> bool {
        let mut cur = *id;
        let mut steps = 0;
        while cur != ROOT {
            match self.nodes.get(&cur) {
                Some(n) if !n.deleted => cur = n.parent,
                _ => return false,
            }
            steps += 1;
            if steps > self.nodes.len() + 1 {
                return false;
            }
        }
        true
    }

    /// Whether an entry was accepted for state.
    pub fn is_accepted(&self, e: &EntryId) -> bool {
        self.accepted.contains(e)
    }

    /// Valid entries that were not accepted for state.
    pub fn rejected(&self) -> impl Iterator<Item = &EntryId> {
        self.rejected.iter()
    }

    /// Entries applied, in log order.
    pub fn applied(&self) -> &[EntryId] {
        &self.applied
    }

    /// Nodes with a field in conflict, or a delete conflict.
    pub fn conflicts(&self) -> Vec<&Node> {
        let mut v: Vec<&Node> = self
            .nodes
            .values()
            .filter(|n| n.delete_conflict || n.fields.values().any(|vs| vs.len() > 1))
            .collect();
        v.sort_by_key(|n| n.id);
        v
    }

    /// The canonical state record `{0: 13, 1: node records}`.
    pub fn canonical(&self) -> Record {
        let mut ids: Vec<&NodeId> = self.nodes.keys().collect();
        ids.sort();
        let nodes = ids.into_iter().map(|id| {
            let n = &self.nodes[id];
            let fields =
                n.fields
                    .iter()
                    .filter(|(_, vs)| !vs.is_empty())
                    .map(|(k, vs)| {
                        Record::new().with(1, *k as u32).with(
                            2,
                            Value::list(vs.iter().map(|v| {
                                Record::new().with(1, v.entry).with_opt(2, v.value.clone())
                            })),
                        )
                    });
            Record::new()
                .with(1, n.id)
                .with(2, n.kind.to_value())
                .with(3, n.parent)
                .with(4, n.name.as_str())
                .with(5, Value::list(fields))
                .with(6, n.deleted)
                .with(7, n.position_writer)
                .with(8, n.delete_conflict)
                .with(9, n.creator)
        });
        Record::new()
            .with(0, CANONICAL_STATE as u32)
            .with(1, Value::list(nodes))
    }

    /// `BLAKE3` of the canonical state's encoding: a checkpoint's state
    /// root.
    pub fn root_hash(&self) -> [u8; 32] {
        *blake3::hash(&self.canonical().encode()).as_bytes()
    }
}

fn would_cycle(parent: &HashMap<NodeId, NodeId>, node: &NodeId, new_parent: &NodeId) -> bool {
    let mut cur = *new_parent;
    let mut steps = 0;
    loop {
        if cur == *node {
            return true;
        }
        match parent.get(&cur) {
            Some(p) => cur = *p,
            None => return false,
        }
        steps += 1;
        if steps > parent.len() + 1 {
            return true;
        }
    }
}
