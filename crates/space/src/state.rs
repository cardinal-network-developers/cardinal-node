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

use crate::entry::{
    derived_id, IdentityId, NodeId, NodeKind, Profile, SpaceEntry, SpaceOp, SpaceOpBody,
};

/// The root node's id: sixteen zero bytes.
pub const ROOT: NodeId = [0; 16];

/// The id of an identity's reach node, in every space: the first 16 bytes
/// of `derive("reach node", identity id)` (`state.md#nodes`). Like the root
/// it always exists and is never created; it has no kind and no position,
/// and only that identity writes to it, and only with `set`.
pub fn reach_node_id(identity: &IdentityId) -> NodeId {
    let d = cardinal_crypto::derive(cardinal_crypto::Purpose::ReachNode, identity);
    d[..16].try_into().expect("16 bytes")
}

/// The field that marks a node author-owned (`profiles.md#shared-rules-normative`).
pub const AUTHOR_OWNED_FIELD: u64 = 15;

/// The largest key a field may have: the largest integer
/// (`encoding.md#values`).
pub const MAX_FIELD_KEY: u64 = (1 << 60) - 1;

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
    /// The time of the entry that created it, if that entry gave one.
    pub created: Option<u64>,
    /// The position of its `create` in that entry.
    created_op: u32,
    /// The delete that set its deleted flag, if it is set.
    deleted_by: Option<Took>,
    /// The delete of it that yielded to concurrent work and flagged it a
    /// delete conflict, which may have taken what was beneath it: a
    /// restore of it brings that back.
    conflict_by: Option<Took>,
}

/// The delete that took a node (`state.md#deletion-yields-to-concurrent-work`):
/// the place of a `delete` op in this space, or, for a node a successor's
/// initial state carried deleted, the number that state gave the delete,
/// which every node that one delete took shares
/// (`state.md#canonical-state`, field 6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Took {
    Op(EntryId, u32),
    Carried(u64),
}

impl Node {
    /// The field's single value, if it is settled and set.
    pub fn field(&self, key: u64) -> Option<&Value> {
        match self.fields.get(&key).map(|v| v.as_slice()) {
            Some([one]) => one.value.as_ref(),
            _ => None,
        }
    }

    /// The entry whose `delete` took it, where it is deleted and that
    /// delete is in this space's log: on it, or on a node above it. `None`
    /// where it is not deleted, or where a successor's initial state
    /// carried it deleted.
    pub fn deleted_in(&self) -> Option<EntryId> {
        match self.deleted_by {
            Some(Took::Op(e, _)) if self.deleted => Some(e),
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

#[derive(Clone, Debug)]
struct Meta {
    kind: NodeKind,
    created_in: EntryId,
    creator: IdentityId,
    author_owned: bool,
}

/// The field of a node of `kind` that a profile declares to hold a node id,
/// which names that node as surely as an op does (`state.md#state-tree`): a
/// message's "in reply to", and the message a read marker stands at.
pub(crate) fn node_field(profile: Profile, kind: NodeKind) -> Option<u64> {
    if profile != Profile::RELATIONSHIP {
        return None;
    }
    match kind {
        NodeKind::Uint(2) => Some(3),
        NodeKind::Uint(4) => Some(1),
        _ => None,
    }
}

/// Whether a value in a field that holds a node id names a node that is
/// known. The root is not one to name here: it is only ever a parent
/// (`state.md#nodes`).
fn names_known(value: Option<&Value>, known: impl Fn(&NodeId) -> bool) -> bool {
    match value {
        None => true,
        Some(v) => v
            .as_bytes()
            .and_then(|b| NodeId::try_from(b).ok())
            .is_some_and(|n| n != ROOT && known(&n)),
    }
}

/// The nodes named by an op (`state.md#operations`): target, parent, and
/// new parent.
pub fn named_nodes(op: &SpaceOpBody) -> Vec<NodeId> {
    match op {
        SpaceOpBody::Create { parent, .. } => vec![*parent],
        SpaceOpBody::Set { node, .. }
        | SpaceOpBody::Delete { node, .. }
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
    /// The fields of the reach nodes that have any, by node id. A reach
    /// node is no part of the tree.
    reach: BTreeMap<NodeId, BTreeMap<u64, Vec<FieldValue>>>,
    accepted: HashSet<EntryId>,
    rejected: HashSet<EntryId>,
    applied: Vec<EntryId>,
    /// The nodes a successor's initial state carried, with the rank each
    /// had there (`state.md#canonical-state`, field 10). They need no
    /// `create`, come first in the order nodes were made in, and the
    /// entries that wrote their values and positions are not in this
    /// space: the genesis counts as descending from each of them
    /// (`spaces.md#the-successor`).
    carried: HashMap<NodeId, u64>,
    /// Each earlier id a node posted again has had (`create` field 5), and
    /// the node that has it now: what a device posting again an op that
    /// named the node by one of them writes in its place
    /// (`spaces.md#what-the-successor-does-not-carry`).
    was: HashMap<NodeId, NodeId>,
}

/// The effect of one delete op, decided against the whole set.
#[derive(Clone, Debug, Default)]
struct DeleteEffect {
    delete: Vec<NodeId>,
    conflict: bool,
}

/// What a delete op does, asked as the application comes to it.
type Decide<'a> = &'a mut dyn FnMut(u32, &NodeId) -> DeleteEffect;

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
        self.replay_ops(x, e, 0..e.ops().len(), undo);
    }

    /// Replays the creates and moves among some of an entry's ops, by
    /// their places. Says whether anything was placed.
    fn replay_ops(
        &mut self,
        x: &EntryId,
        e: &SpaceEntry,
        places: std::ops::Range<usize>,
        undo: &mut Vec<(NodeId, Option<NodeId>)>,
    ) -> bool {
        let mut placed = false;
        for (i, op) in e
            .ops()
            .iter()
            .enumerate()
            .take(places.end)
            .skip(places.start)
        {
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
            placed = true;
        }
        placed
    }

    /// Takes back replays noted in `undo`, newest first.
    fn undo(&mut self, undo: &mut Vec<(NodeId, Option<NodeId>)>) {
        self.undo_to(undo, 0);
    }

    /// Takes back the replays noted in `undo` after its first `keep`.
    fn undo_to(&mut self, undo: &mut Vec<(NodeId, Option<NodeId>)>, keep: usize) {
        while undo.len() > keep {
            let Some((n, was)) = undo.pop() else { break };
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

/// The effect of every delete among the accepted entries, worked out one
/// op at a time as the application comes to it: what `State::delete_effect`
/// gives each, sharing the work. A delete takes everything beneath its
/// node, so what all of them take, held at once, is the number of deletes
/// times the size of what they delete, which two small entries can make
/// gigabytes. Here one is held at a time.
///
/// The log up to where an entry's past stops being unbroken
/// ([`Dag::prefix`]) is replayed as a prefix, which moves on, or back, to
/// where the next entry needs it; then only the entries around that one are
/// replayed, where others can be concurrent with it.
struct Deletes<'a> {
    dag: &'a Dag<SpaceEntry>,
    is_accepted: Vec<bool>,
    /// By log position: the least prefix from there on. Everything from
    /// the first position above `i` descends from the entry at `i`.
    least: Vec<usize>,
    /// `related[y] == mark`: y is in the past of the entry in hand, is
    /// that entry, or is after it.
    related: Vec<usize>,
    mark: usize,
    at: Positions,
    /// What the prefix replaced, and where each log position's part of it
    /// begins.
    prefix: Vec<(NodeId, Option<NodeId>)>,
    prefix_marks: Vec<usize>,
    /// What the entry in hand replayed beyond the prefix.
    undo: Vec<(NodeId, Option<NodeId>)>,
    /// The nodes that entries concurrent with the one in hand name, and
    /// the nodes it deletes.
    named: HashSet<NodeId>,
    deleted: HashSet<NodeId>,
    /// How many of its ops have been replayed, and what was touched as the
    /// positions stood then.
    done: usize,
    touched: Option<HashSet<NodeId>>,
}

impl<'a> Deletes<'a> {
    fn new(
        dag: &'a Dag<SpaceEntry>,
        accepted: &[EntryId],
        base: &[(NodeId, NodeId)],
    ) -> Deletes<'a> {
        let order = dag.log_order();
        let mut is_accepted = vec![false; order.len()];
        for x in accepted {
            is_accepted[dag.position(x).expect("entry")] = true;
        }
        let mut least = dag.prefix().to_vec();
        for j in (1..least.len()).rev() {
            least[j - 1] = least[j - 1].min(least[j]);
        }
        let mut at = Positions::default();
        for (n, p) in base {
            at.place(*n, *p);
        }
        Deletes {
            dag,
            is_accepted,
            least,
            related: vec![usize::MAX; order.len()],
            mark: 0,
            at,
            prefix: Vec::new(),
            prefix_marks: Vec::new(),
            undo: Vec::new(),
            named: HashSet::new(),
            deleted: HashSet::new(),
            done: 0,
            touched: None,
        }
    }

    /// Takes up the accepted entry `x`: the positions become those of its
    /// causal past.
    fn begin(&mut self, x: &EntryId) {
        let dag = self.dag;
        let order = dag.log_order();
        let index = |x: &EntryId| dag.position(x).expect("entry");
        let i = index(x);
        let start = dag.prefix()[i].min(i);
        while self.prefix_marks.len() > start {
            let keep = self.prefix_marks.pop().expect("a mark");
            self.at.undo_to(&mut self.prefix, keep);
        }
        while self.prefix_marks.len() < start {
            let k = self.prefix_marks.len();
            self.prefix_marks.push(self.prefix.len());
            if self.is_accepted[k] {
                let e = dag.get(&order[k]).expect("entry");
                self.at.replay(&order[k], e, &mut self.prefix);
            }
        }
        let mark = self.mark;
        self.mark += 1;
        let mut past = Vec::new();
        let mut walk: Vec<usize> = dag.parents(x).iter().map(index).collect();
        while let Some(y) = walk.pop() {
            if y >= start && self.related[y] != mark {
                self.related[y] = mark;
                past.push(y);
                walk.extend(dag.parents(&order[y]).iter().map(index));
            }
        }
        past.sort_unstable();
        for y in past.into_iter().filter(|y| self.is_accepted[*y]) {
            let e = dag.get(&order[y]).expect("entry");
            self.at.replay(&order[y], e, &mut self.undo);
        }
        self.related[i] = mark;
        let end = self.least.partition_point(|n| *n <= i);
        let mut walk: Vec<usize> = dag.children(x).iter().map(index).collect();
        while let Some(y) = walk.pop() {
            if y < end && self.related[y] != mark {
                self.related[y] = mark;
                walk.extend(dag.children(&order[y]).iter().map(index));
            }
        }
        // Ops of concurrent entries touch what they name and everything
        // above it, up to a deleted node.
        let entry = dag.get(x).expect("entry");
        let deletes = entry.ops().iter().filter_map(|op| match op.body() {
            // one written beside deletes nothing
            SpaceOpBody::Delete {
                node,
                beside: false,
            } => Some(*node),
            _ => None,
        });
        self.deleted = deletes.collect();
        let concurrent = (start..end).filter(|y| self.related[*y] != mark && self.is_accepted[*y]);
        self.named = concurrent
            .flat_map(|y| dag.get(&order[y]).expect("entry").ops())
            .flat_map(|op| named_nodes(op.body()))
            .collect();
        self.done = 0;
        self.touched = None;
    }

    /// What concurrent entries touch, as the positions stand: every node
    /// they name and every node above one. A node of it that is beneath a
    /// deleted node, or is that node, is what the delete leaves, so one set
    /// answers for every delete of the entry; a chain kept for each deleted
    /// node on a path is the square of the path's length.
    fn touched_now(&self) -> HashSet<NodeId> {
        let at = &self.at;
        let mut touched: HashSet<NodeId> = HashSet::new();
        for z in &self.named {
            let mut cur = *z;
            // what is above a node already in is in: a path is walked once
            while touched.insert(cur) {
                match at.parent.get(&cur) {
                    Some(p) => cur = *p,
                    None => break,
                }
            }
        }
        touched
    }

    /// What the delete of `n` at place `op` of the entry in hand, `x`,
    /// does. What is beneath a node is read from the delete's causal past
    /// and the ops before it in its own entry, so the positions move on as
    /// the deletes are gone through, and what is touched is worked out
    /// again only when they have moved.
    fn effect(&mut self, x: &EntryId, op: u32, n: &NodeId) -> DeleteEffect {
        let entry = self.dag.get(x).expect("entry");
        let places = self.done..op as usize;
        let moved = self.at.replay_ops(x, entry, places, &mut self.undo);
        self.done = op as usize;
        if moved || self.touched.is_none() {
            self.touched = Some(self.touched_now());
        }
        let t = self.touched.as_ref().expect("worked out above");
        let beneath = self.at.subtree(n).into_iter();
        DeleteEffect {
            delete: beneath.filter(|m| !t.contains(m)).collect(),
            conflict: t.contains(n),
        }
    }

    /// Lets go of the entry in hand.
    fn end(&mut self) {
        self.at.undo(&mut self.undo);
        self.touched = None;
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
            reach: BTreeMap::new(),
            accepted: HashSet::new(),
            rejected: HashSet::new(),
            applied: Vec::new(),
            carried: HashMap::new(),
            was: HashMap::new(),
        }
    }

    /// The state a successor starts from: a canonical state
    /// (`state.md#canonical-state`), read back. Every node it records is
    /// carried, under the id, creator, position, values and rank it had,
    /// and so is every reach node it records. A record that cannot be read
    /// fails the whole.
    pub fn from_canonical(profile: Profile, canonical: &Record) -> Result<State, crate::Error> {
        let bad = crate::Error::Malformed("canonical state");
        if canonical.opt_uint(0)? != Some(CANONICAL_STATE) {
            return Err(bad);
        }
        let mut st = State::new(profile);
        let id16 = |v: &Value| -> Option<NodeId> { v.as_bytes()?.try_into().ok() };
        let id32 = |v: &Value| -> Option<EntryId> { v.as_bytes()?.try_into().ok() };
        let fields_of = |r: &Record| -> Result<BTreeMap<u64, Vec<FieldValue>>, crate::Error> {
            let mut out = BTreeMap::new();
            for f in r.opt_list(5)?.unwrap_or(&[]) {
                let f = f.as_record().ok_or(bad.clone())?;
                let key = f.uint(1)?;
                let mut vals: Vec<FieldValue> = Vec::new();
                for v in f.list(2)? {
                    let v = v.as_record().ok_or(bad.clone())?;
                    let entry = v.get(1).and_then(id32).ok_or(bad.clone())?;
                    // The place of the op that wrote it is not recorded:
                    // values of one entry keep the order they are listed in.
                    let op = vals.iter().filter(|x| x.entry == entry).count() as u32;
                    vals.push(FieldValue {
                        entry,
                        op,
                        value: v.get(2).cloned(),
                    });
                }
                out.insert(key, vals);
            }
            Ok(out)
        };
        let mut seen: HashSet<NodeId> = HashSet::new();
        let mut numbers: Vec<u64> = Vec::new();
        for r in canonical.opt_list(1)?.unwrap_or(&[]) {
            let r = r.as_record().ok_or(bad.clone())?;
            let id = r.get(1).and_then(id16).ok_or(bad.clone())?;
            if id == ROOT || !seen.insert(id) {
                return Err(bad);
            }
            let fields = fields_of(r)?;
            let Some(kind) = r.get(2) else {
                // a reach node: fields 1 and 5 alone
                st.reach.insert(id, fields);
                continue;
            };
            let kind = NodeKind::from_value(kind).ok_or(bad.clone())?;
            let parent = r.get(3).and_then(id16).ok_or(bad.clone())?;
            let writer = r.get(7).and_then(id32).ok_or(bad.clone())?;
            let creator = r.get(9).and_then(id32).ok_or(bad.clone())?;
            let rank = r.uint(10)?;
            // the delete that took it, if it is deleted; or, for a node a
            // delete conflict kept, the delete that yielded there, so that
            // a restore of it brings back what that delete took beneath it
            let number = Some(r.uint(6)?).filter(|t| *t != 0);
            if let Some(t) = number.filter(|t| !numbers.contains(t)) {
                numbers.push(t);
            }
            let delete_conflict = r.opt_bool(8)?.unwrap_or(false);
            let took = number.filter(|_| !delete_conflict);
            let author_owned = fields.get(&AUTHOR_OWNED_FIELD).is_some_and(|vs| {
                vs.iter()
                    .any(|v| v.value.as_ref().and_then(|x| x.as_uint()) == Some(1))
            });
            st.registry.insert(
                id,
                Meta {
                    kind,
                    created_in: writer,
                    creator,
                    author_owned,
                },
            );
            st.children.entry(parent).or_default().insert(id);
            st.nodes.insert(
                id,
                Node {
                    id,
                    kind,
                    parent,
                    name: r.opt_text(4)?.unwrap_or("").to_owned(),
                    fields,
                    deleted: took.is_some(),
                    delete_conflict,
                    position_writer: writer,
                    creator,
                    // Carried: the entry that made it is in an earlier
                    // space. Nothing here names it, and its rank says
                    // where it comes.
                    created_in: writer,
                    created: r.opt_uint(11)?,
                    created_op: 0,
                    deleted_by: took.map(Took::Carried),
                    conflict_by: number.filter(|_| delete_conflict).map(Took::Carried),
                },
            );
            st.carried.insert(id, rank);
        }
        // The deletes are numbered from 1 in the order the records list the
        // first node each took: what a state computed from entries numbers.
        if numbers != (1..=numbers.len() as u64).collect::<Vec<_>>() {
            return Err(bad);
        }
        // Every parent is a node it records, or the root, and no node is
        // its own ancestor: what a tree computed from entries always is.
        for n in st.nodes.values() {
            let mut cur = n.parent;
            let mut steps = 0;
            while cur != ROOT {
                let Some(p) = st.nodes.get(&cur) else {
                    return Err(bad);
                };
                steps += 1;
                if cur == n.id || steps > st.nodes.len() {
                    return Err(bad);
                }
                cur = p.parent;
            }
        }
        Ok(st)
    }

    /// The same state with no entry of this space applied yet: what a
    /// successor starts from, as [`State::from_canonical`] reads it.
    fn initial_copy(&self) -> State {
        State {
            profile: self.profile,
            nodes: self.nodes.clone(),
            children: self.children.clone(),
            registry: self.registry.clone(),
            reach: self.reach.clone(),
            accepted: HashSet::new(),
            rejected: HashSet::new(),
            applied: Vec::new(),
            carried: self.carried.clone(),
            was: self.was.clone(),
        }
    }

    /// Leaves out the reach node of every identity but `named`: what the
    /// state at a cut does for those a successor's genesis does not name,
    /// since someone who is not there could never empty it
    /// (`spaces.md#the-successor`).
    pub fn keep_reach_of(&mut self, named: &[IdentityId]) {
        let keep: HashSet<NodeId> = named.iter().map(reach_node_id).collect();
        self.reach.retain(|id, _| keep.contains(id));
    }

    /// Whether a node came with the space's initial state.
    pub fn is_carried(&self, node: &NodeId) -> bool {
        self.carried.contains_key(node)
    }

    /// Where the initial state ranked a node it carried.
    pub fn carried_rank(&self, node: &NodeId) -> Option<u64> {
        self.carried.get(node).copied()
    }

    /// The node that has, or has had, the id `id`: itself, or one posted
    /// again whose `create` lists it as an id it had
    /// (`spaces.md#what-the-successor-does-not-carry`).
    pub fn now_called(&self, id: &NodeId) -> Option<NodeId> {
        if self.nodes.contains_key(id) {
            return Some(*id);
        }
        self.was.get(id).copied()
    }

    /// The ids a node has had before this one, when it was posted again.
    pub fn was_of(&self, node: &NodeId) -> Vec<NodeId> {
        let mut out: Vec<NodeId> = self
            .was
            .iter()
            .filter(|(_, now)| *now == node)
            .map(|(was, _)| *was)
            .collect();
        out.sort();
        out
    }

    /// The profile.
    pub fn profile(&self) -> Profile {
        self.profile
    }

    /// Computes the state of the `valid` entries of `dag`.
    pub fn compute(profile: Profile, dag: &Dag<SpaceEntry>, valid: &HashSet<EntryId>) -> State {
        State::compute_with(profile, None, dag, valid, false)
    }

    /// Computes the state of the `valid` entries of `dag`, starting from
    /// `initial`: a successor's initial state, whose nodes need no
    /// `create` and whose values every entry here descends from.
    pub fn compute_from(
        profile: Profile,
        initial: Option<&State>,
        dag: &Dag<SpaceEntry>,
        valid: &HashSet<EntryId>,
    ) -> State {
        State::compute_with(profile, initial, dag, valid, false)
    }

    /// [`State::compute`] with each delete decided on its own by the
    /// definition, to test the faster way against.
    #[doc(hidden)]
    pub fn compute_by_definition(
        profile: Profile,
        dag: &Dag<SpaceEntry>,
        valid: &HashSet<EntryId>,
    ) -> State {
        State::compute_with(profile, None, dag, valid, true)
    }

    fn compute_with(
        profile: Profile,
        initial: Option<&State>,
        dag: &Dag<SpaceEntry>,
        valid: &HashSet<EntryId>,
        by_definition: bool,
    ) -> State {
        let mut st = match initial {
            Some(i) => i.initial_copy(),
            None => State::new(profile),
        };
        // where the carried nodes are before anything here moves them
        let base: Vec<(NodeId, NodeId)> = st.nodes.values().map(|n| (n.id, n.parent)).collect();
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
        // pass 2: application, each delete decided as its turn comes, so
        // that what one takes is let go before the next is worked out
        let mut shared = (!by_definition).then(|| Deletes::new(dag, &accepted, &base));
        for x in &accepted {
            let e = dag.get(x).expect("entry");
            let deletes =
                |op: &SpaceOp| matches!(op.body(), SpaceOpBody::Delete { beside: false, .. });
            if !e.ops().iter().any(deletes) {
                st.apply(dag, e, None);
                continue;
            }
            match shared.as_mut() {
                Some(shared) => {
                    shared.begin(x);
                    st.apply(dag, e, Some(&mut |op, n| shared.effect(x, op, n)));
                    shared.end();
                }
                None => {
                    let mut decide = |op: u32, n: &NodeId| {
                        State::delete_effect(dag, &accepted, &base, x, op as usize, n)
                    };
                    st.apply(dag, e, Some(&mut decide));
                }
            }
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
        // Nothing is concurrent with it, and the state so far is the state
        // of its causal past: each of its deletes takes what is beneath
        // the node when its turn comes, the ops before it in the entry
        // applied.
        self.apply(dag, e, None);
        true
    }

    fn kind_of(&self, n: &NodeId, local: &HashMap<NodeId, Meta>) -> Option<NodeKind> {
        local
            .get(n)
            .or_else(|| self.registry.get(n))
            .map(|m| m.kind)
    }

    /// Whether an entry is accepted for state; registers its nodes if so.
    ///
    /// A reach node is in no registry, so every op that names one is
    /// refused as naming a node that was never created, but one: its own
    /// identity's `set`.
    fn accept(&mut self, dag: &Dag<SpaceEntry>, e: &SpaceEntry) -> bool {
        let id = e.id();
        let own_reach = reach_node_id(&e.author());
        let mut local: HashMap<NodeId, Meta> = HashMap::new();
        let known = |n: &NodeId, local: &HashMap<NodeId, Meta>, reg: &HashMap<NodeId, Meta>| {
            *n == ROOT
                || local.contains_key(n)
                || reg.get(n).is_some_and(|m| {
                    // a carried node's maker is in an earlier space, and
                    // everything here descends from it
                    !dag.contains(&m.created_in) || dag.is_ancestor_or_self(&m.created_in, &id)
                })
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
                    // A kind is not like an op: a `create` is accepted
                    // whatever its kind and wherever it puts the node
                    // (`state.md#operations`). What a kind means, and
                    // where, is for whoever shows the space to say.
                    let names = node_field(self.profile, *kind).map(|f| fields.get(f));
                    // A field key is an integer, below 2^60, though a
                    // record's own keys may be larger: a larger one
                    // violates the profile (`state.md#nodes`).
                    let keys = fields.iter().all(|(k, _)| *k <= MAX_FIELD_KEY);
                    let ok = keys
                        && known(parent, &local, &self.registry)
                        && names
                            .is_none_or(|v| names_known(v, |n| known(n, &local, &self.registry)));
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
                SpaceOpBody::Set { node, .. } if *node == own_reach => true,
                SpaceOpBody::Set {
                    node, key, value, ..
                } => {
                    let field = self
                        .kind_of(node, &local)
                        .and_then(|k| node_field(self.profile, k));
                    *node != ROOT
                        && known(node, &local, &self.registry)
                        && owned_ok(node, &local, &self.registry)
                        && (field != Some(*key)
                            || names_known(value.as_ref(), |n| known(n, &local, &self.registry)))
                }
                SpaceOpBody::Delete { node, .. } | SpaceOpBody::Restore { node } => {
                    *node != ROOT
                        && known(node, &local, &self.registry)
                        && owned_ok(node, &local, &self.registry)
                }
                SpaceOpBody::Move { node, parent, .. } => {
                    *node != ROOT
                        && known(node, &local, &self.registry)
                        && known(parent, &local, &self.registry)
                        && owned_ok(node, &local, &self.registry)
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

    /// The effect of the delete of `n` that is the op at place `at` of the
    /// entry `d`, by the definition
    /// (`state.md#deletion-yields-to-concurrent-work`).
    fn delete_effect(
        dag: &Dag<SpaceEntry>,
        accepted: &[EntryId],
        base: &[(NodeId, NodeId)],
        d: &EntryId,
        at: usize,
        n: &NodeId,
    ) -> DeleteEffect {
        // positions in the delete's causal past, and after the ops before
        // it in its own entry, from where the carried nodes were
        let past = dag.ancestors(d);
        let mut parent: HashMap<NodeId, NodeId> = base.iter().copied().collect();
        let before = accepted.iter().filter(|x| past.contains(*x));
        for (x, ops) in before.map(|x| (x, usize::MAX)).chain([(d, at)]) {
            let e = dag.get(x).expect("entry");
            for (i, op) in e.ops().iter().enumerate().take(ops) {
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

    /// Applies an accepted entry's ops in their order. `effects` says what
    /// each of its deletes does, decided against the whole set, when its
    /// turn comes; with none, nothing is concurrent with the entry, and a
    /// delete takes what is beneath its node as the tree stands then.
    fn apply(&mut self, dag: &Dag<SpaceEntry>, e: &SpaceEntry, mut effects: Option<Decide<'_>>) {
        let id = e.id();
        // The entry's past is the same for all its ops. Whether an entry
        // that left a value is in it is asked once; a field's standing
        // values are gone through at its first plain `set` here, after
        // which only this entry's own values, at the end, are superseded;
        // and a field is put in order once, when the ops are done.
        let mut in_past: HashMap<EntryId, bool> = HashMap::new();
        let mut settled: HashMap<(NodeId, u64), usize> = HashMap::new();
        let mut set: HashSet<(NodeId, u64)> = HashSet::new();
        for (i, op) in e.ops().iter().enumerate() {
            let i = i as u32;
            match op.body() {
                SpaceOpBody::Create {
                    kind,
                    parent,
                    name,
                    fields,
                    was,
                } => {
                    let nid = derived_id(&id, i as usize);
                    for w in was {
                        // the first node to say it had an id keeps it
                        self.was.entry(*w).or_insert(nid);
                    }
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
                            created: e.time(),
                            created_op: i,
                            deleted_by: None,
                            conflict_by: None,
                        },
                    );
                }
                SpaceOpBody::Set {
                    node,
                    key,
                    value,
                    beside,
                } => {
                    let fields = match self.nodes.get_mut(node) {
                        Some(n) => Some(&mut n.fields),
                        None if *node == reach_node_id(&e.author()) => {
                            Some(self.reach.entry(*node).or_default())
                        }
                        None => None,
                    };
                    if let Some(fields) = fields {
                        let vals = fields.entry(*key).or_default();
                        // one written beside supersedes nothing: its value
                        // is added, and is superseded like any other
                        if !*beside {
                            match settled.get(&(*node, *key)) {
                                // what this entry added since is its own
                                Some(others) => vals.truncate(*others),
                                None => {
                                    vals.retain(|v| {
                                        !*in_past.entry(v.entry).or_insert_with(|| {
                                            // a carried value's entry is in
                                            // an earlier space, and the
                                            // genesis descends from it
                                            !dag.contains(&v.entry)
                                                || dag.is_ancestor_or_self(&v.entry, &id)
                                        })
                                    });
                                    settled.insert((*node, *key), vals.len());
                                }
                            }
                        }
                        set.insert((*node, *key));
                        vals.push(FieldValue {
                            entry: id,
                            op: i,
                            value: value.clone(),
                        });
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
                SpaceOpBody::Delete { node, beside: true } => {
                    // deletes nothing, and flags the node as a delete that
                    // concurrent work had touched does
                    if let Some(n) = self.nodes.get_mut(node).filter(|n| !n.deleted) {
                        n.delete_conflict = true;
                    }
                }
                SpaceOpBody::Delete {
                    node,
                    beside: false,
                } => {
                    // A delete of a node already deleted does nothing: what
                    // was made beneath it since comes back with the restore
                    // of the delete that took it.
                    if self.nodes.get(node).is_some_and(|n| n.deleted) {
                        continue;
                    }
                    let eff = match effects.as_mut() {
                        Some(decide) => decide(i, node),
                        None => DeleteEffect {
                            delete: self.subtree(node),
                            conflict: false,
                        },
                    };
                    // each flag remembers the delete that set it: one
                    // already set stays as it was, so a restore of this
                    // node does not bring back what was deleted on its own
                    // before (`state.md#deletion-yields-to-concurrent-work`)
                    for m in eff.delete {
                        if let Some(n) = self.nodes.get_mut(&m).filter(|n| !n.deleted) {
                            n.deleted = true;
                            n.delete_conflict = false;
                            n.deleted_by = Some(Took::Op(id, i));
                        }
                    }
                    if eff.conflict {
                        if let Some(n) = self.nodes.get_mut(node) {
                            n.delete_conflict = true;
                            n.conflict_by = Some(Took::Op(id, i));
                        }
                    }
                }
                SpaceOpBody::Restore { node } => {
                    // the node's flag, and those its delete set beneath it
                    // or, where its delete yielded, what that delete took
                    // beneath it
                    let by = self
                        .nodes
                        .get(node)
                        .and_then(|n| n.deleted_by.or(n.conflict_by));
                    for m in self.subtree(node) {
                        if let Some(n) = self.nodes.get_mut(&m) {
                            if m == *node || (by.is_some() && n.deleted_by == by) {
                                n.deleted = false;
                                n.delete_conflict = false;
                                n.deleted_by = None;
                                n.conflict_by = None;
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        for (node, key) in set {
            let fields = match self.nodes.get_mut(&node) {
                Some(n) => Some(&mut n.fields),
                None => self.reach.get_mut(&node),
            };
            if let Some(vals) = fields.and_then(|f| f.get_mut(&key)) {
                vals.sort_by_key(|a| (a.entry, a.op));
            }
        }
        self.applied.push(id);
    }

    /// A node (not the root).
    pub fn node(&self, id: &NodeId) -> Option<&Node> {
        self.nodes.get(id)
    }

    /// The values of a field of an identity's reach node: none if it never
    /// set that field, and more than one if its devices set it at the same
    /// moment.
    pub fn reach_values(&self, who: &IdentityId, key: u64) -> &[FieldValue] {
        let fields = self.reach.get(&reach_node_id(who));
        fields
            .and_then(|f| f.get(&key))
            .map_or(&[], |v| v.as_slice())
    }

    /// The reach nodes that have any field set, by node id, with their
    /// fields: for looking at what a space holds (`cardinald` inspection).
    pub fn reach_nodes(&self) -> impl Iterator<Item = (&NodeId, &BTreeMap<u64, Vec<FieldValue>>)> {
        self.reach.iter()
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

    /// The one identity that may set, move, delete or restore a node: its
    /// creator, if it was created author-owned
    /// (`profiles.md#shared-rules-normative`). `None` for any other node,
    /// which whoever may write in the space may change.
    pub fn owner_of(&self, node: &NodeId) -> Option<IdentityId> {
        let made = self.registry.get(node).filter(|m| m.author_owned);
        made.map(|m| m.creator)
    }

    /// Whether an entry was accepted for state.
    pub fn is_accepted(&self, e: &EntryId) -> bool {
        self.accepted.contains(e)
    }

    /// The entries accepted for state.
    pub fn accepted(&self) -> impl Iterator<Item = &EntryId> {
        self.accepted.iter()
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

    /// The canonical state record `{0: 13, 1: node records}`, sorted by
    /// node id. The root has no record, and a reach node has one only while
    /// it has a field to record, holding fields 1 and 5 alone
    /// (`state.md#canonical-state`). Every other node's record says where
    /// it comes in the order the nodes were created in (field 10) and when
    /// its creating entry says it was made (field 11), so that a device
    /// starting from a canonical state can show them as they were made; and
    /// a deleted node's, the number of the delete that took it (field 6),
    /// which every node that delete took shares.
    pub fn canonical(&self) -> Record {
        fn fields(fields: &BTreeMap<u64, Vec<FieldValue>>) -> Value {
            let set = fields.iter().filter(|(_, vs)| !vs.is_empty());
            Value::list(set.map(|(k, vs)| {
                Record::new().with(1, *k).with(
                    2,
                    Value::list(
                        vs.iter()
                            .map(|v| Record::new().with(1, v.entry).with_opt(2, v.value.clone())),
                    ),
                )
            }))
        }
        // A node's rank is its place in the order the nodes were created
        // in: log order, and within an entry the order of its ops.
        // The nodes an initial state carried come first, in the order it
        // ranked them.
        let at: HashMap<&EntryId, usize> = self.applied.iter().zip(0..).collect();
        let mut made: Vec<(usize, usize, u32, NodeId)> = self
            .nodes
            .values()
            .map(|n| match self.carried.get(&n.id) {
                Some(r) => (0, *r as usize, 0, n.id),
                None => (1, at[&n.created_in], n.created_op, n.id),
            })
            .collect();
        made.sort_unstable();
        let rank: HashMap<NodeId, u64> = made.iter().map(|(_, _, _, id)| *id).zip(0..).collect();
        // Each delete that took a node is numbered from 1, in the order the
        // records list the first node it took: so a restore in a successor
        // clears exactly the flags one delete set. A node that a delete
        // conflict kept has the number of the delete that yielded there,
        // so a restore of it brings back what that delete took beneath it.
        let took = |n: &Node| {
            if n.deleted {
                n.deleted_by
            } else {
                n.conflict_by.filter(|_| n.delete_conflict)
            }
        };
        let mut ids: Vec<&NodeId> = self.nodes.keys().collect();
        ids.sort_unstable();
        let mut number: HashMap<Took, u64> = HashMap::new();
        for id in ids {
            if let Some(t) = took(&self.nodes[id]) {
                let next = number.len() as u64 + 1;
                number.entry(t).or_insert(next);
            }
        }
        let mut records: Vec<(NodeId, Record)> = Vec::new();
        for (id, n) in &self.nodes {
            let took = took(n).map_or(0, |t| number[&t]);
            let r = Record::new()
                .with(1, n.id)
                .with(2, n.kind.to_value())
                .with(3, n.parent)
                .with(4, n.name.as_str())
                .with(5, fields(&n.fields))
                .with(6, took)
                .with(7, n.position_writer)
                .with(8, n.delete_conflict)
                .with(9, n.creator)
                .with(10, rank[id])
                .with_opt(11, n.created);
            records.push((*id, r));
        }
        for (id, f) in &self.reach {
            if f.values().any(|vs| !vs.is_empty()) {
                records.push((*id, Record::new().with(1, *id).with(5, fields(f))));
            }
        }
        records.sort_by_key(|(id, _)| *id);
        Record::new()
            .with(0, CANONICAL_STATE as u32)
            .with(1, Value::list(records.into_iter().map(|(_, r)| r)))
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
