//! Spreading `want`s across peers (`sync.md#fetching-objects`).
//!
//! A device reconciling one set with several peers asks each for part of
//! what it lacks. Each reconciliation tells the [`Spread`] which of the
//! ids it learned the peer holds; each peer's fetcher takes a batch no
//! other peer is being asked for, and settles it when the answer comes.
//! What one peer did not give goes back for another holder to take.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::hash::Hash;

use crate::{Id, Label};

struct Wanted<P> {
    /// Peers known to hold the id.
    holders: HashSet<P>,
    /// The peer being asked for it, if any.
    asked: Option<P>,
}

/// One set's wanted ids.
struct Set<P> {
    ids: HashMap<Id, Wanted<P>>,
    /// For each peer, the ids it holds that nobody is being asked for, so
    /// that taking a batch does not look through every id.
    free: HashMap<P, BTreeSet<Id>>,
}

impl<P: Copy + Eq + Hash> Set<P> {
    /// `id`, no longer asked of anyone, goes back to each holder.
    fn release(&mut self, id: &Id) {
        if let Some(w) = self.ids.get(id) {
            for h in &w.holders {
                self.free.entry(*h).or_default().insert(*id);
            }
        }
    }
}

/// Ids this device lacks, by set: who holds each and who is being asked.
pub struct Spread<P> {
    sets: HashMap<Label, Set<P>>,
    /// Reconciliations under way, by set and peer: two with one peer at
    /// once (each side opened one) share what they learn.
    active: HashMap<(Label, P), usize>,
}

impl<P> Default for Spread<P> {
    fn default() -> Self {
        Spread {
            sets: HashMap::new(),
            active: HashMap::new(),
        }
    }
}

impl<P: Copy + Eq + Hash> Spread<P> {
    /// Nothing wanted.
    pub fn new() -> Spread<P> {
        Spread::default()
    }

    /// A reconciliation of `label` with `peer` begins; it ends with
    /// [`leave`](Spread::leave).
    pub fn join(&mut self, label: Label, peer: P) {
        *self.active.entry((label, peer)).or_default() += 1;
    }

    /// `peer` holds `ids` of `label`, which this device lacks.
    pub fn learn(&mut self, label: Label, peer: P, ids: impl IntoIterator<Item = Id>) {
        let set = self.sets.entry(label).or_insert_with(|| Set {
            ids: HashMap::new(),
            free: HashMap::new(),
        });
        for id in ids {
            let w = set.ids.entry(id).or_insert_with(|| Wanted {
                holders: HashSet::new(),
                asked: None,
            });
            w.holders.insert(peer);
            if w.asked.is_none() {
                set.free.entry(peer).or_default().insert(id);
            }
        }
    }

    /// Up to `max` ids of `label` that `peer` holds and nobody is being
    /// asked for, now asked of `peer`, ascending.
    pub fn take(&mut self, label: &Label, peer: P, max: usize) -> Vec<Id> {
        let Some(set) = self.sets.get_mut(label) else {
            return Vec::new();
        };
        let Some(free) = set.free.get_mut(&peer) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        while out.len() < max {
            let Some(id) = free.pop_first() else { break };
            out.push(id);
        }
        for id in &out {
            if let Some(w) = set.ids.get_mut(id) {
                w.asked = Some(peer);
                for h in &w.holders {
                    if let Some(f) = set.free.get_mut(h) {
                        f.remove(id);
                    }
                }
            }
        }
        out
    }

    /// The answer to `peer` for `ids` has come: those `held` now are done
    /// with; the rest `peer` turned out not to give, and go back for
    /// another holder.
    pub fn settle(&mut self, label: &Label, peer: P, ids: &[Id], held: impl Fn(&Id) -> bool) {
        let Some(set) = self.sets.get_mut(label) else {
            return;
        };
        for id in ids {
            if held(id) {
                if let Some(w) = set.ids.remove(id) {
                    for h in &w.holders {
                        if let Some(f) = set.free.get_mut(h) {
                            f.remove(id);
                        }
                    }
                }
            } else if let Some(w) = set.ids.get_mut(id) {
                if w.asked != Some(peer) {
                    continue;
                }
                w.asked = None;
                w.holders.remove(&peer);
                if w.holders.is_empty() {
                    set.ids.remove(id);
                } else {
                    set.release(id);
                }
            }
        }
        if set.ids.is_empty() {
            self.sets.remove(label);
        }
    }

    /// A reconciliation of `label` with `peer` is over. Once none is left
    /// with that peer, what it was asked for goes back to other holders,
    /// and what nobody else holds is forgotten, for the next reconciliation
    /// to find.
    pub fn leave(&mut self, label: &Label, peer: P) {
        if let Some(n) = self.active.get_mut(&(*label, peer)) {
            *n -= 1;
            if *n > 0 {
                return;
            }
            self.active.remove(&(*label, peer));
        }
        let Some(set) = self.sets.get_mut(label) else {
            return;
        };
        set.free.remove(&peer);
        let mut freed = Vec::new();
        set.ids.retain(|id, w| {
            w.holders.remove(&peer);
            if w.asked == Some(peer) {
                w.asked = None;
                freed.push(*id);
            }
            !w.holders.is_empty()
        });
        for id in freed {
            set.release(&id);
        }
        if set.ids.is_empty() {
            self.sets.remove(label);
        }
    }

    /// How many ids of `label` are wanted.
    pub fn len(&self, label: &Label) -> usize {
        self.sets.get(label).map_or(0, |s| s.ids.len())
    }

    /// Whether `peer` holds an id of `label` that another peer is being
    /// asked for: an answer that may yet free it for `peer` to take.
    pub fn waits_on_others(&self, label: &Label, peer: P) -> bool {
        self.sets.get(label).is_some_and(|set| {
            set.ids
                .values()
                .any(|w| w.asked.is_some_and(|a| a != peer) && w.holders.contains(&peer))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> Id {
        [n; 32]
    }

    #[test]
    fn two_peers_share_the_work() {
        let mut s = Spread::new();
        let l = [0; 32];
        s.learn(l, 'a', (0..10).map(id));
        s.learn(l, 'b', (0..10).map(id));
        let a = s.take(&l, 'a', 4);
        let b = s.take(&l, 'b', 4);
        assert_eq!(a.len(), 4);
        assert_eq!(b.len(), 4);
        assert!(a.iter().all(|i| !b.contains(i)));
        assert!(s.waits_on_others(&l, 'a'));
        // Alpha gives all but one; that one goes to beta.
        let missing = a[0];
        s.settle(&l, 'a', &a, |i| *i != missing);
        let a2 = s.take(&l, 'a', 10);
        assert!(!a2.contains(&missing));
        let b2 = s.take(&l, 'b', 10);
        assert!(b2.contains(&missing));
        assert_eq!(a2.len() + b2.len() + b.len(), 10 - 3);
    }

    #[test]
    fn leaving_frees_what_was_asked() {
        let mut s = Spread::new();
        let l = [0; 32];
        s.learn(l, 'a', (0..4).map(id));
        s.learn(l, 'b', (2..6).map(id));
        let a = s.take(&l, 'a', 10);
        assert_eq!(a, (0..4).map(id).collect::<Vec<_>>());
        assert!(s.take(&l, 'b', 10).len() == 2);
        s.leave(&l, 'a');
        // 0 and 1 only alpha held: forgotten. 2 and 3 go to beta.
        assert_eq!(s.take(&l, 'b', 10), vec![id(2), id(3)]);
        s.leave(&l, 'b');
        assert_eq!(s.len(&l), 0);
    }

    #[test]
    fn two_reconciliations_with_one_peer() {
        let mut s = Spread::new();
        let l = [0; 32];
        s.join(l, 'a');
        s.join(l, 'a');
        s.learn(l, 'a', (0..4).map(id));
        let first = s.take(&l, 'a', 2);
        // One of the two ends; what the other may yet fetch stays.
        s.leave(&l, 'a');
        assert_eq!(s.take(&l, 'a', 10), vec![id(2), id(3)]);
        s.settle(&l, 'a', &first, |_| true);
        s.leave(&l, 'a');
        assert_eq!(s.len(&l), 0);
    }
}
