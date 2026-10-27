//! Sorted id sets with fast range sums.

use std::sync::OnceLock;

use crate::fingerprint::{fingerprint, Fingerprint, Sum};
use crate::Id;

/// A sorted set of ids, as reconciliation needs to see it: by position.
///
/// Position `i` is the `i`-th smallest id. A range `[lower, upper)` of ids
/// is the positions `rank(lower) .. rank(upper)`. Implementations backed by
/// a database answer these with an order-statistic index; [`MemSet`] keeps
/// cached prefix sums so a range fingerprint costs a binary search and a
/// few hundred additions, whatever the set's size.
pub trait SetStore {
    /// Number of ids.
    fn len(&self) -> usize;

    /// Whether the set is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Number of ids less than `bound`.
    fn rank(&self, bound: &Id) -> usize;

    /// The id at position `i < len()`.
    fn at(&self, i: usize) -> Id;

    /// The sum of the ids at positions `a .. b`.
    fn sum(&self, a: usize, b: usize) -> Sum;

    /// The ids at positions `a .. b`.
    fn ids(&self, a: usize, b: usize) -> Vec<Id> {
        (a..b).map(|i| self.at(i)).collect()
    }

    /// Whether `id` is in the set.
    fn contains(&self, id: &Id) -> bool {
        let r = self.rank(id);
        r < self.len() && self.at(r) == *id
    }

    /// The fingerprint of positions `a .. b`.
    fn fingerprint(&self, a: usize, b: usize) -> Fingerprint {
        fingerprint(self.sum(a, b), (b - a) as u64)
    }
}

impl<S: SetStore + ?Sized> SetStore for &S {
    fn len(&self) -> usize {
        (**self).len()
    }
    fn rank(&self, bound: &Id) -> usize {
        (**self).rank(bound)
    }
    fn at(&self, i: usize) -> Id {
        (**self).at(i)
    }
    fn sum(&self, a: usize, b: usize) -> Sum {
        (**self).sum(a, b)
    }
    fn ids(&self, a: usize, b: usize) -> Vec<Id> {
        (**self).ids(a, b)
    }
    fn contains(&self, id: &Id) -> bool {
        (**self).contains(id)
    }
}

/// The empty set: what a side reconciles against for a label it does not
/// hold or may not reconcile with this peer (`sync.md#sets`).
#[derive(Clone, Copy, Debug, Default)]
pub struct EmptySet;

impl SetStore for EmptySet {
    fn len(&self) -> usize {
        0
    }
    fn rank(&self, _bound: &Id) -> usize {
        0
    }
    fn at(&self, _i: usize) -> Id {
        panic!("EmptySet has no ids")
    }
    fn sum(&self, _a: usize, _b: usize) -> Sum {
        Sum::ZERO
    }
}

/// Ids per block, at most. Blocks split in half when they exceed it.
const BLOCK: usize = 512;

/// Prefix counts and sums over blocks, rebuilt lazily after changes.
struct Cache {
    /// `counts[i]` = ids in blocks `0..i`.
    counts: Vec<usize>,
    /// `sums[i]` = sum of ids in blocks `0..i`.
    sums: Vec<Sum>,
}

/// An in-memory sorted set: a list of sorted blocks of at most 512 ids.
///
/// Inserting and removing cost O(512 + blocks). Range queries use prefix
/// sums over blocks, rebuilt once after any change (O(blocks)), plus at
/// most one partial block at each end. A million ids is about 2,000 blocks.
#[derive(Default)]
pub struct MemSet {
    blocks: Vec<Vec<Id>>,
    len: usize,
    cache: OnceLock<Cache>,
}

impl Clone for MemSet {
    fn clone(&self) -> Self {
        MemSet {
            blocks: self.blocks.clone(),
            len: self.len,
            cache: OnceLock::new(),
        }
    }
}

impl std::fmt::Debug for MemSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MemSet({} ids)", self.len)
    }
}

impl MemSet {
    /// An empty set.
    pub fn new() -> MemSet {
        MemSet::default()
    }

    /// A set from ids in any order, with duplicates removed.
    pub fn from_unsorted(mut ids: Vec<Id>) -> MemSet {
        ids.sort_unstable();
        ids.dedup();
        MemSet::from_sorted(ids)
    }

    /// A set from strictly ascending ids.
    pub fn from_sorted(ids: Vec<Id>) -> MemSet {
        debug_assert!(ids.windows(2).all(|w| w[0] < w[1]));
        let len = ids.len();
        let blocks = ids.chunks(BLOCK / 2).map(|c| c.to_vec()).collect();
        MemSet {
            blocks,
            len,
            cache: OnceLock::new(),
        }
    }

    /// The block that holds, or would hold, `id`.
    fn block_for(&self, id: &Id) -> usize {
        // The first block whose last id is >= id; or the last block.
        let b = self
            .blocks
            .partition_point(|blk| blk.last().is_some_and(|l| l < id));
        b.min(self.blocks.len().saturating_sub(1))
    }

    /// Adds `id`. Returns whether it was new.
    pub fn insert(&mut self, id: Id) -> bool {
        if self.blocks.is_empty() {
            self.blocks.push(vec![id]);
            self.len = 1;
            self.cache = OnceLock::new();
            return true;
        }
        let b = self.block_for(&id);
        let blk = &mut self.blocks[b];
        match blk.binary_search(&id) {
            Ok(_) => false,
            Err(pos) => {
                blk.insert(pos, id);
                if blk.len() > BLOCK {
                    let tail = blk.split_off(BLOCK / 2);
                    self.blocks.insert(b + 1, tail);
                }
                self.len += 1;
                self.cache = OnceLock::new();
                true
            }
        }
    }

    /// Removes `id`. Returns whether it was present.
    pub fn remove(&mut self, id: &Id) -> bool {
        if self.blocks.is_empty() {
            return false;
        }
        let b = self.block_for(id);
        let blk = &mut self.blocks[b];
        match blk.binary_search(id) {
            Ok(pos) => {
                blk.remove(pos);
                if blk.is_empty() {
                    self.blocks.remove(b);
                }
                self.len -= 1;
                self.cache = OnceLock::new();
                true
            }
            Err(_) => false,
        }
    }

    /// Adds many ids at once, faster than inserting one by one when the
    /// batch is large.
    pub fn extend_from(&mut self, ids: impl IntoIterator<Item = Id>) {
        let mut new: Vec<Id> = ids.into_iter().collect();
        if new.len() < 64 {
            for id in new {
                self.insert(id);
            }
            return;
        }
        new.sort_unstable();
        new.dedup();
        let old = std::mem::take(&mut self.blocks);
        let mut merged = Vec::with_capacity(self.len + new.len());
        let mut a = old.into_iter().flatten().peekable();
        let mut b = new.into_iter().peekable();
        loop {
            match (a.peek(), b.peek()) {
                (Some(x), Some(y)) => {
                    if x < y {
                        merged.push(a.next().unwrap());
                    } else if y < x {
                        merged.push(b.next().unwrap());
                    } else {
                        merged.push(a.next().unwrap());
                        b.next();
                    }
                }
                (Some(_), None) => merged.push(a.next().unwrap()),
                (None, Some(_)) => merged.push(b.next().unwrap()),
                (None, None) => break,
            }
        }
        *self = MemSet::from_sorted(merged);
    }

    /// Every id, ascending.
    pub fn iter(&self) -> impl Iterator<Item = &Id> {
        self.blocks.iter().flatten()
    }

    fn cache(&self) -> &Cache {
        self.cache.get_or_init(|| {
            let mut counts = Vec::with_capacity(self.blocks.len() + 1);
            let mut sums = Vec::with_capacity(self.blocks.len() + 1);
            let mut c = 0;
            let mut s = Sum::ZERO;
            counts.push(0);
            sums.push(s);
            for blk in &self.blocks {
                c += blk.len();
                for id in blk {
                    s = s.add_id(id);
                }
                counts.push(c);
                sums.push(s);
            }
            Cache { counts, sums }
        })
    }

    /// (block, offset in block) of position `i <= len`.
    fn locate(&self, i: usize) -> (usize, usize) {
        let c = self.cache();
        // The last block whose start count is <= i.
        let b = c.counts.partition_point(|&n| n <= i) - 1;
        (b, i - c.counts[b])
    }

    /// Sum of the ids at positions `0 .. i`.
    fn prefix_sum(&self, i: usize) -> Sum {
        let (b, off) = self.locate(i);
        let c = self.cache();
        if b >= self.blocks.len() {
            return c.sums[b];
        }
        let blk = &self.blocks[b];
        // Add from the nearer end of the block.
        if off <= blk.len() / 2 {
            blk[..off].iter().fold(c.sums[b], |s, id| s.add_id(id))
        } else {
            blk[off..]
                .iter()
                .fold(c.sums[b + 1], |s, id| s.minus(Sum::of(id)))
        }
    }
}

impl FromIterator<Id> for MemSet {
    fn from_iter<T: IntoIterator<Item = Id>>(iter: T) -> MemSet {
        MemSet::from_unsorted(iter.into_iter().collect())
    }
}

impl SetStore for MemSet {
    fn len(&self) -> usize {
        self.len
    }

    fn rank(&self, bound: &Id) -> usize {
        if self.blocks.is_empty() {
            return 0;
        }
        let b = self
            .blocks
            .partition_point(|blk| blk.last().is_some_and(|l| l < bound));
        if b == self.blocks.len() {
            return self.len;
        }
        self.cache().counts[b] + self.blocks[b].partition_point(|id| id < bound)
    }

    fn at(&self, i: usize) -> Id {
        let (b, off) = self.locate(i);
        self.blocks[b][off]
    }

    fn sum(&self, a: usize, b: usize) -> Sum {
        if a >= b {
            return Sum::ZERO;
        }
        // Within one block, add directly.
        let (ba, oa) = self.locate(a);
        if ba < self.blocks.len() && oa + (b - a) <= self.blocks[ba].len() {
            return self.blocks[ba][oa..oa + (b - a)]
                .iter()
                .fold(Sum::ZERO, |s, id| s.add_id(id));
        }
        self.prefix_sum(b).minus(self.prefix_sum(a))
    }

    fn ids(&self, a: usize, b: usize) -> Vec<Id> {
        let mut out = Vec::with_capacity(b.saturating_sub(a));
        if a >= b {
            return out;
        }
        let (mut blk, mut off) = self.locate(a);
        while out.len() < b - a {
            let block = &self.blocks[blk];
            let take = (b - a - out.len()).min(block.len() - off);
            out.extend_from_slice(&block[off..off + take]);
            blk += 1;
            off = 0;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u64) -> Id {
        *blake3::hash(&n.to_le_bytes()).as_bytes()
    }

    #[test]
    fn matches_sorted_vec() {
        let mut s = MemSet::new();
        let mut v: Vec<Id> = Vec::new();
        for n in 0..5000u64 {
            let x = id(n % 4000);
            let new = s.insert(x);
            assert_eq!(new, !v.contains(&x));
            if new {
                v.push(x);
            }
            if n % 7 == 0 {
                let y = id(n / 2);
                let had = v.contains(&y);
                assert_eq!(s.remove(&y), had);
                v.retain(|z| *z != y);
            }
        }
        v.sort();
        assert_eq!(s.len(), v.len());
        assert_eq!(s.iter().copied().collect::<Vec<_>>(), v);
        for (i, x) in v.iter().enumerate().step_by(37) {
            assert_eq!(s.at(i), *x);
            assert_eq!(s.rank(x), i);
            assert!(s.contains(x));
        }
        for (a, b) in [(0, 0), (0, v.len()), (10, 700), (511, 513), (1000, 1001)] {
            let expect = v[a..b].iter().fold(Sum::ZERO, |s, x| s.add_id(x));
            assert_eq!(s.sum(a, b), expect, "{a}..{b}");
            assert_eq!(s.ids(a, b), v[a..b].to_vec());
        }
        assert_eq!(s.rank(&[0xff; 32]), v.len());
        assert_eq!(s.rank(&[0; 32]), 0);
        let mut t = MemSet::from_sorted(v[..100].to_vec());
        t.extend_from(v[50..].iter().copied());
        assert_eq!(t.iter().copied().collect::<Vec<_>>(), v);
    }
}
