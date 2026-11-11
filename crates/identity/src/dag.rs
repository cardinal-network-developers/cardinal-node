//! A causal graph of entries named by 32-byte ids (`identity.md#entries`):
//! parents, ancestors, concurrency, heads, and log order.
//!
//! Entries whose parents are missing are held until they arrive. Log order
//! is a topological order in which, among entries whose parents have all
//! been placed, the smallest id (compared as bytes) comes next. It is kept
//! incrementally. A new entry has no descendants yet, so it moves nothing
//! else: it goes after its last parent, before the first entry from there
//! on with a larger id. An entry whose last parent is last in the order is
//! appended in O(1), whatever other heads there are, and any other costs
//! what lies after its place in the order. Heads that nothing builds on,
//! such as entries a space holds to be invalid, therefore cost nothing.

use std::collections::{BTreeSet, BinaryHeap, HashMap, HashSet};

/// An entry id.
pub type Id = [u8; 32];

struct Node<T> {
    parents: Vec<Id>,
    children: Vec<Id>,
    /// Longest path from a root, counting the root as 0. Ancestors always
    /// have a smaller depth, which prunes ancestor searches.
    depth: u64,
    value: T,
}

/// The outcome of [`Dag::insert`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Inserted {
    /// Already present (or already held).
    Duplicate,
    /// Held until these parents arrive.
    Held(Vec<Id>),
    /// Added, together with any held entries it released, in the order
    /// they were added.
    Added(Vec<Id>),
}

/// A causal graph of entries.
pub struct Dag<T> {
    nodes: HashMap<Id, Node<T>>,
    held: HashMap<Id, (Vec<Id>, T)>,
    /// Held entry ids by a missing parent.
    waiting: HashMap<Id, Vec<Id>>,
    heads: BTreeSet<Id>,
    order: Vec<Id>,
    position: HashMap<Id, usize>,
    /// By log position: how many entries from the start of the log order
    /// are all this entry or its ancestors. Most ancestor checks are of an
    /// old entry against a recent one, and end here without a walk.
    prefix: Vec<usize>,
}

impl<T> Default for Dag<T> {
    fn default() -> Self {
        Dag {
            nodes: HashMap::new(),
            held: HashMap::new(),
            waiting: HashMap::new(),
            heads: BTreeSet::new(),
            order: Vec::new(),
            position: HashMap::new(),
            prefix: Vec::new(),
        }
    }
}

impl<T> Dag<T> {
    /// An empty graph.
    pub fn new() -> Dag<T> {
        Dag::default()
    }

    /// The number of entries present (not held).
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether no entry is present.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Whether `id` is present (not held).
    pub fn contains(&self, id: &Id) -> bool {
        self.nodes.contains_key(id)
    }

    /// Whether `id` is held waiting for parents.
    pub fn is_held(&self, id: &Id) -> bool {
        self.held.contains_key(id)
    }

    /// The ids of held entries.
    pub fn held(&self) -> impl Iterator<Item = &Id> {
        self.held.keys()
    }

    /// The value of a present entry.
    pub fn get(&self, id: &Id) -> Option<&T> {
        self.nodes.get(id).map(|n| &n.value)
    }

    /// The parents of a present entry.
    pub fn parents(&self, id: &Id) -> &[Id] {
        self.nodes.get(id).map_or(&[], |n| &n.parents)
    }

    /// The children of a present entry.
    pub fn children(&self, id: &Id) -> &[Id] {
        self.nodes.get(id).map_or(&[], |n| &n.children)
    }

    /// Entries with no children, sorted.
    pub fn heads(&self) -> Vec<Id> {
        self.heads.iter().copied().collect()
    }

    /// Whether `heads` are exactly the current heads.
    pub fn is_heads(&self, ids: &[Id]) -> bool {
        ids.len() == self.heads.len() && ids.iter().all(|h| self.heads.contains(h))
    }

    /// Whether an entry with these parents descends from every head, so
    /// that it would come last in log order.
    pub fn descends_from_all_heads(&self, parents: &[Id]) -> bool {
        self.heads.iter().all(|h| parents.contains(h))
    }

    /// Inserts an entry, or holds it until its parents arrive.
    pub fn insert(&mut self, id: Id, parents: Vec<Id>, value: T) -> Inserted {
        if self.nodes.contains_key(&id) || self.held.contains_key(&id) {
            return Inserted::Duplicate;
        }
        let missing: Vec<Id> = parents
            .iter()
            .copied()
            .filter(|p| !self.nodes.contains_key(p))
            .collect();
        if !missing.is_empty() {
            for m in &missing {
                self.waiting.entry(*m).or_default().push(id);
            }
            self.held.insert(id, (parents, value));
            return Inserted::Held(missing);
        }
        let mut added = Vec::new();
        self.place(id, parents, value);
        added.push(id);
        let mut i = 0;
        while i < added.len() {
            let x = added[i];
            i += 1;
            for w in self.waiting.remove(&x).unwrap_or_default() {
                let ready = self
                    .held
                    .get(&w)
                    .is_some_and(|(ps, _)| ps.iter().all(|p| self.nodes.contains_key(p)));
                if ready {
                    let (ps, v) = self.held.remove(&w).expect("held");
                    self.place(w, ps, v);
                    added.push(w);
                }
            }
        }
        Inserted::Added(added)
    }

    fn place(&mut self, id: Id, mut parents: Vec<Id>, value: T) {
        parents.sort_unstable();
        parents.dedup();
        let depth = parents
            .iter()
            .map(|p| self.nodes[p].depth + 1)
            .max()
            .unwrap_or(0);
        // Where it goes in log order. It is ready once its last parent is
        // placed, and from then on is taken as soon as it is the smallest
        // of what is ready: before the first entry after that parent with a
        // larger id. It has no descendants, so nothing else moves.
        let from = parents.iter().map(|p| self.position[p] + 1).max();
        let from = from.unwrap_or(0);
        let at = (from..self.order.len())
            .find(|j| self.order[*j] > id)
            .unwrap_or(self.order.len());
        // How much of the order before it is all its ancestors: as far as a
        // parent's reaches, and further while what follows is an ancestor.
        let mut n = parents
            .iter()
            .map(|p| self.prefix[self.position[p]])
            .max()
            .unwrap_or(0);
        if parents.len() > 1 {
            // one parent: what stopped its prefix stops this one too
            let behind = |x: &Id| {
                parents
                    .iter()
                    .any(|p| p == x || self.reaches(x, p, &self.prefix))
            };
            while n < at && behind(&self.order[n]) {
                n += 1;
            }
        }
        let prefix = if n == at { at + 1 } else { n };
        for p in &parents {
            self.nodes.get_mut(p).expect("parent").children.push(id);
            self.heads.remove(p);
        }
        self.heads.insert(id);
        self.nodes.insert(
            id,
            Node {
                parents,
                children: Vec::new(),
                depth,
                value,
            },
        );
        self.order.insert(at, id);
        self.prefix.insert(at, prefix);
        self.position.insert(id, at);
        // What comes after it moved up by one, and it is an ancestor of
        // none of that.
        for j in at + 1..self.order.len() {
            self.position.insert(self.order[j], j);
            if self.prefix[j] > at {
                self.prefix[j] = at;
            }
        }
    }

    /// [`Dag::prefix`], worked out from nothing: what the tests hold the
    /// one kept as entries arrive against.
    #[cfg(test)]
    fn compute_prefix(&self) -> Vec<usize> {
        let mut out: Vec<usize> = Vec::with_capacity(self.order.len());
        for (i, x) in self.order.iter().enumerate() {
            let parents = &self.nodes[x].parents;
            let mut n = parents
                .iter()
                .map(|p| out[self.position[p]])
                .max()
                .unwrap_or(0);
            // one parent: what stopped its prefix stops this one too
            if parents.len() > 1 {
                while n < i && self.reaches(&self.order[n], x, &out) {
                    n += 1;
                }
            }
            out.push(if n == i { i + 1 } else { n });
        }
        out
    }

    /// Every present entry in log order.
    pub fn log_order(&self) -> &[Id] {
        &self.order
    }

    /// The position of an entry in log order.
    pub fn position(&self, id: &Id) -> Option<usize> {
        self.position.get(id).copied()
    }

    /// By log position: how many entries from the start of the log order
    /// are all that entry or its ancestors.
    pub fn prefix(&self) -> &[usize] {
        &self.prefix
    }

    /// Whether `a` comes before `b` in log order.
    pub fn before(&self, a: &Id, b: &Id) -> bool {
        self.position(a) < self.position(b)
    }

    /// The log order of a subset, which must be causally closed.
    pub fn log_order_of(&self, subset: &HashSet<Id>) -> Vec<Id> {
        self.compute_order(Some(subset))
    }

    fn compute_order(&self, subset: Option<&HashSet<Id>>) -> Vec<Id> {
        use std::cmp::Reverse;
        let inside = |x: &Id| subset.is_none_or(|s| s.contains(x));
        let mut waiting: HashMap<Id, usize> = HashMap::new();
        let mut ready = BinaryHeap::new();
        for (id, n) in &self.nodes {
            if !inside(id) {
                continue;
            }
            let k = n.parents.iter().filter(|p| inside(p)).count();
            if k == 0 {
                ready.push(Reverse(*id));
            } else {
                waiting.insert(*id, k);
            }
        }
        let mut out = Vec::with_capacity(self.nodes.len());
        while let Some(Reverse(x)) = ready.pop() {
            out.push(x);
            for c in &self.nodes[&x].children {
                if let Some(w) = waiting.get_mut(c) {
                    *w -= 1;
                    if *w == 0 {
                        waiting.remove(c);
                        ready.push(Reverse(*c));
                    }
                }
            }
        }
        out
    }

    /// Whether `a` is a strict ancestor of `b`.
    pub fn is_ancestor(&self, a: &Id, b: &Id) -> bool {
        self.reaches(a, b, &self.prefix)
    }

    /// [`Dag::is_ancestor`], with `prefix` for as far as it is known.
    fn reaches(&self, a: &Id, b: &Id, prefix: &[usize]) -> bool {
        if a == b {
            return false;
        }
        let (Some(na), Some(nb)) = (self.nodes.get(a), self.nodes.get(b)) else {
            return false;
        };
        if na.depth >= nb.depth {
            return false;
        }
        let at = self.position[a];
        let mut seen = HashSet::new();
        let mut todo = vec![*b];
        while let Some(x) = todo.pop() {
            if prefix.get(self.position[&x]).is_some_and(|n| at < *n) {
                return true;
            }
            for p in &self.nodes[&x].parents {
                if p == a {
                    return true;
                }
                let d = self.nodes[p].depth;
                if d > na.depth && seen.insert(*p) {
                    todo.push(*p);
                }
            }
        }
        false
    }

    /// Whether `a` is `b` or an ancestor of it.
    pub fn is_ancestor_or_self(&self, a: &Id, b: &Id) -> bool {
        a == b || self.is_ancestor(a, b)
    }

    /// Whether neither of `a` and `b` is an ancestor of the other.
    pub fn concurrent(&self, a: &Id, b: &Id) -> bool {
        a != b && !self.is_ancestor(a, b) && !self.is_ancestor(b, a)
    }

    /// The strict ancestors of `x`.
    pub fn ancestors(&self, x: &Id) -> HashSet<Id> {
        self.ancestors_of(self.parents(x))
    }

    /// Every entry that is one of `ids` or an ancestor of one.
    pub fn ancestors_of(&self, ids: &[Id]) -> HashSet<Id> {
        let mut out = HashSet::new();
        let mut todo: Vec<Id> = ids
            .iter()
            .copied()
            .filter(|x| self.nodes.contains_key(x))
            .collect();
        while let Some(x) = todo.pop() {
            if out.insert(x) {
                todo.extend(self.nodes[&x].parents.iter().copied());
            }
        }
        out
    }

    /// The strict descendants of `x`.
    pub fn descendants(&self, x: &Id) -> HashSet<Id> {
        let mut out = HashSet::new();
        let mut todo: Vec<Id> = self.children(x).to_vec();
        while let Some(y) = todo.pop() {
            if out.insert(y) {
                todo.extend(self.nodes[&y].children.iter().copied());
            }
        }
        out
    }

    /// Present entries and their values, in log order.
    pub fn iter(&self) -> impl Iterator<Item = (&Id, &T)> {
        self.order.iter().map(|id| (id, &self.nodes[id].value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> Id {
        [n; 32]
    }

    #[test]
    fn order_ancestors_and_holding() {
        let mut d: Dag<()> = Dag::new();
        assert_eq!(d.insert(id(1), vec![], ()), Inserted::Added(vec![id(1)]));
        // 5 and 3 concurrent after 1; 4 merges them; 9 held for 8
        assert_eq!(
            d.insert(id(9), vec![id(8)], ()),
            Inserted::Held(vec![id(8)])
        );
        d.insert(id(5), vec![id(1)], ());
        d.insert(id(3), vec![id(1)], ());
        d.insert(id(4), vec![id(5), id(3)], ());
        assert_eq!(d.log_order(), &[id(1), id(3), id(5), id(4)]);
        assert_eq!(d.heads(), vec![id(4)]);
        assert!(d.is_ancestor(&id(1), &id(4)));
        assert!(d.concurrent(&id(3), &id(5)));
        assert!(!d.is_ancestor(&id(4), &id(1)));
        assert_eq!(
            d.insert(id(8), vec![id(4)], ()),
            Inserted::Added(vec![id(8), id(9)])
        );
        assert_eq!(d.log_order().last(), Some(&id(9)));
        assert_eq!(d.ancestors(&id(9)).len(), 5);
        assert_eq!(d.descendants(&id(5)), [id(4), id(8), id(9)].into());
        // a concurrent entry with a small id lands in the middle
        d.insert(id(2), vec![id(1)], ());
        assert_eq!(
            d.log_order(),
            &[id(1), id(2), id(3), id(5), id(4), id(8), id(9)]
        );
        assert_eq!(d.heads(), vec![id(2), id(9)]);
    }

    #[test]
    fn an_entry_nothing_builds_on_stays_where_it_is() {
        // A head that stays a head, as an entry held to be invalid does.
        // With a small id it sorts early and what follows is appended; with
        // a large one it sorts last, and each new entry goes in before it.
        for stray in [2u8, 200] {
            let mut d: Dag<()> = Dag::new();
            d.insert(id(1), vec![], ());
            d.insert(id(stray), vec![id(1)], ());
            d.insert(id(3), vec![id(1)], ());
            for n in 4..100u8 {
                d.insert(id(n), vec![id(n - 1)], ());
                assert_eq!(d.order, d.compute_order(None));
                assert_eq!(d.prefix, d.compute_prefix());
            }
            assert_eq!(d.heads(), vec![id(99.min(stray)), id(99.max(stray))]);
            let at = if stray == 2 { 1 } else { 98 };
            assert_eq!(d.position(&id(stray)), Some(at));
            assert!(d.is_ancestor(&id(1), &id(99)) && d.is_ancestor(&id(50), &id(99)));
            assert!(d.concurrent(&id(stray), &id(99)));
            assert!(!d.descends_from_all_heads(&[id(99)]));
        }
    }

    #[test]
    fn ancestor_checks_match_a_walk() {
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut below = move |n: usize| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x % n as u64) as usize
        };
        for round in 0..200 {
            let size = 2 + below(40);
            let reach = 1 + below(6);
            // random ids, so log order is not insertion order
            let ids: Vec<Id> = (0..size)
                .map(|i| {
                    let mut a = [below(256) as u8; 32];
                    a[1] = i as u8;
                    a
                })
                .collect();
            let mut todo: Vec<(Id, Vec<Id>)> = (0..size)
                .map(|i| {
                    let parents = (0..=below(3))
                        .filter(|_| i > 0)
                        .map(|_| ids[i - 1 - below(i.min(reach))])
                        .collect();
                    (ids[i], parents)
                })
                .collect();
            // half arrive out of order, and wait for their parents
            if round % 2 == 1 {
                for i in (1..todo.len()).rev() {
                    let j = below(i + 1);
                    todo.swap(i, j);
                }
            }
            let mut d: Dag<()> = Dag::new();
            for (n, (i, parents)) in todo.into_iter().enumerate() {
                d.insert(i, parents, ());
                // the order kept as entries arrive is the order worked out
                // from nothing, and so is what is kept beside it
                assert_eq!(d.order, d.compute_order(None), "round {round}");
                assert_eq!(d.prefix, d.compute_prefix(), "round {round}");
                for (at, x) in d.order.iter().enumerate() {
                    assert_eq!(d.position[x], at);
                }
                if n % 4 == 0 || n + 1 == size {
                    for b in d.log_order() {
                        let walked = d.ancestors(b);
                        for a in d.log_order() {
                            assert_eq!(d.is_ancestor(a, b), walked.contains(a));
                        }
                    }
                }
            }
        }
    }
}
