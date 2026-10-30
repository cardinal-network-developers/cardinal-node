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
//!    own causal past and the ops of concurrent accepted entries
//!    (`delete_effect` is the definition). Deletes in one entry share that
//!    work, and the log up to where an entry's past stops being unbroken
//!    is replayed once for all: O(ops), plus the entries around each entry
//!    with deletes that may be concurrent with it.
//! 3. **Application.** Creates, sets, moves, deletes, and restores are
//!    applied in log order. A set drops the values whose entries are its
//!    ancestors; a move that would make a node its own ancestor is skipped.
//!
//! [`State::append`] applies an entry that descends from every entry
//! already applied, which therefore comes last in log order, without
//! recomputing: its deletes have no concurrent work, and the state so far
//! is the state of its causal past. Any other arrival recomputes from
//! scratch, which is O(n log n + ops), plus that concurrent work.

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

/// The delete ops' effects, by entry and op.
type Effects = HashMap<(EntryId, u32), DeleteEffect>;

/// Where nodes are after some entries' creates and moves.
#[derive(Default)]
struct Positions {
    parent: HashMap<NodeId, NodeId>,
    children: HashMap<NodeId, HashSet<NodeId>>,
}

impl Positions {
    /// Replays an entry's creates and moves, noting in `undo` what they
    /// replaced.
    fn replay(&mut self, x: &EntryId, e: &SpaceEntry, undo: &mut Vec<(NodeId, Option<NodeId>)>) {
        for (i, op) in e.ops().iter().enumerate() {
            let (n, p) = match op.body() {
                SpaceOpBody::Create { parent, .. } => (derived_id(x, i), *parent),
                SpaceOpBody::Move { node, parent, .. }
                    if !would_cycle(&self.parent, node, parent) =>
                {
                    (*node, *parent)
                }
                _ => continue,
            };
            undo.push((n, self.parent.get(&n).copied()));
            self.place(n, p);
        }
    }

    /// Takes back replays noted in `undo`, newest first.
    fn undo(&mut self, undo: &mut Vec<(NodeId, Option<NodeId>)>) {
        while let Some((n, was)) = undo.pop() {
            match was {
                Some(p) => self.place(n, p),
                None => {
                    if let Some(old) = self.parent.remove(&n) {
                        if let Some(cs) = self.children.get_mut(&old) {
                            cs.remove(&n);
                        }
                    }
                }
            }
        }
    }

    fn place(&mut self, n: NodeId, p: NodeId) {
        if let Some(old) = self.parent.insert(n, p) {
            if let Some(cs) = self.children.get_mut(&old) {
                cs.remove(&n);
            }
        }
        self.children.entry(p).or_default().insert(n);
    }

    /// `n` and the nodes beneath it. (Accepted entries name only nodes
    /// from their past and moves that would cycle are skipped, so this is
    /// a tree; the bound is for safety against what others send.)
    fn subtree(&self, n: &NodeId) -> Vec<NodeId> {
        let mut out = vec![*n];
        let mut i = 0;
        while i < out.len() && i <= self.parent.len() {
            if let Some(cs) = self.children.get(&out[i]) {
                out.extend(cs.iter().copied());
            }
            i += 1;
        }
        out
    }
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
        State::compute_with(profile, dag, valid, State::delete_effects)
    }

    /// [`State::compute`] with each delete decided on its own by the
    /// definition, to test the faster way against.
    #[doc(hidden)]
    pub fn compute_by_definition(
        profile: Profile,
        dag: &Dag<SpaceEntry>,
        valid: &HashSet<EntryId>,
    ) -> State {
        State::compute_with(profile, dag, valid, |st, dag, accepted| {
            let mut effects = HashMap::new();
            for x in accepted {
                let e = dag.get(x).expect("entry");
                for (i, op) in e.ops().iter().enumerate() {
                    if let SpaceOpBody::Delete { node } = op.body() {
                        effects.insert((*x, i as u32), st.delete_effect(dag, accepted, x, node));
                    }
                }
            }
            effects
        })
    }

    fn compute_with(
        profile: Profile,
        dag: &Dag<SpaceEntry>,
        valid: &HashSet<EntryId>,
        deletes: impl FnOnce(&State, &Dag<SpaceEntry>, &[EntryId]) -> Effects,
    ) -> State {
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
        let mut effects = deletes(&st, dag, &accepted);
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

    /// The effect of every delete in `accepted`: what `delete_effect`
    /// gives each, sharing the work. The log up to where an entry's past
    /// stops being unbroken ([`Dag::prefix`]) is replayed once; then only
    /// the entries around it, where others can be concurrent with it.
    fn delete_effects(&self, dag: &Dag<SpaceEntry>, accepted: &[EntryId]) -> Effects {
        let mut effects = Effects::new();
        let order = dag.log_order();
        let index = |x: &EntryId| dag.position(x).expect("entry");
        let mut is_accepted = vec![false; order.len()];
        for x in accepted {
            is_accepted[index(x)] = true;
        }
        let deletes_of = |e: &SpaceEntry| -> Vec<(u32, NodeId)> {
            e.ops()
                .iter()
                .enumerate()
                .filter_map(|(i, op)| match op.body() {
                    SpaceOpBody::Delete { node } => Some((i as u32, *node)),
                    _ => None,
                })
                .collect()
        };
        // Entries with deletes, by the unbroken start of their past: replay
        // only goes forward.
        let mut todo: Vec<(usize, usize)> = accepted
            .iter()
            .filter(|x| !deletes_of(dag.get(x).expect("entry")).is_empty())
            .map(|x| (dag.prefix()[index(x)].min(index(x)), index(x)))
            .collect();
        todo.sort_unstable();
        // By log position: the least prefix from here on. Everything from
        // the first position above `i` descends from the entry at `i`.
        let mut least = dag.prefix().to_vec();
        for j in (1..least.len()).rev() {
            least[j - 1] = least[j - 1].min(least[j]);
        }
        // `related[y] == mark`: y is in the past of the current entry, is
        // that entry, or is after it.
        let mut related = vec![usize::MAX; order.len()];
        let mut at = Positions::default();
        let mut undo = Vec::new();
        let mut replayed = 0;
        for (mark, (start, i)) in todo.into_iter().enumerate() {
            while replayed < start {
                if is_accepted[replayed] {
                    let x = &order[replayed];
                    at.replay(x, dag.get(x).expect("entry"), &mut undo);
                }
                replayed += 1;
            }
            undo.clear();
            let x = &order[i];
            let mut past = Vec::new();
            let mut walk: Vec<usize> = dag.parents(x).iter().map(index).collect();
            while let Some(y) = walk.pop() {
                if y >= start && related[y] != mark {
                    related[y] = mark;
                    past.push(y);
                    walk.extend(dag.parents(&order[y]).iter().map(index));
                }
            }
            past.sort_unstable();
            for y in past.into_iter().filter(|y| is_accepted[*y]) {
                let e = dag.get(&order[y]).expect("entry");
                at.replay(&order[y], e, &mut undo);
            }
            related[i] = mark;
            let end = least.partition_point(|n| *n <= i);
            let mut walk: Vec<usize> = dag.children(x).iter().map(index).collect();
            while let Some(y) = walk.pop() {
                if y < end && related[y] != mark {
                    related[y] = mark;
                    walk.extend(dag.children(&order[y]).iter().map(index));
                }
            }
            // Ops of concurrent entries touch what they name and everything
            // above it, up to a deleted node.
            let deletes = deletes_of(dag.get(x).expect("entry"));
            let deleted: HashSet<NodeId> = deletes.iter().map(|(_, n)| *n).collect();
            let named: HashSet<NodeId> = (start..end)
                .filter(|y| related[*y] != mark && is_accepted[*y])
                .flat_map(|y| dag.get(&order[y]).expect("entry").ops())
                .flat_map(|op| named_nodes(op.body()))
                .collect();
            let mut touched: HashMap<NodeId, HashSet<NodeId>> = HashMap::new();
            for z in named {
                let mut chain = vec![z];
                let mut cur = z;
                loop {
                    if deleted.contains(&cur) {
                        touched.entry(cur).or_default().extend(&chain);
                    }
                    match at.parent.get(&cur) {
                        Some(p) if chain.len() <= at.parent.len() => cur = *p,
                        _ => break,
                    }
                    chain.push(cur);
                }
            }
            for (op, n) in deletes {
                let t = touched.get(&n);
                effects.insert(
                    (*x, op),
                    DeleteEffect {
                        delete: at
                            .subtree(&n)
                            .into_iter()
                            .filter(|m| !t.is_some_and(|t| t.contains(m)))
                            .collect(),
                        conflict: t.is_some(),
                    },
                );
            }
            at.undo(&mut undo);
        }
        effects
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
