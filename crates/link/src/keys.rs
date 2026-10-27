//! Transport keys, data packet sealing, the replay window, and a small
//! range set.

use std::collections::BTreeMap;

use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Tag};

use crate::packet::{data_header, data_nonce, DATA_HEADER_LEN, TAG_LEN};

/// One direction's transport key in one key phase.
#[derive(Clone)]
pub(crate) struct DirKey {
    cipher: ChaCha20Poly1305,
    pub phase: u8,
}

impl DirKey {
    pub fn new(key: &[u8; 32], phase: u8) -> DirKey {
        DirKey {
            cipher: ChaCha20Poly1305::new(&(*key).into()),
            phase,
        }
    }

    /// Seals a packet in place. `buf` holds 16 header bytes (overwritten
    /// here), the plaintext, and 16 bytes of room for the tag.
    pub fn seal(&self, receiver: u32, counter: u64, buf: &mut [u8]) {
        let header = data_header(self.phase, receiver, counter);
        buf[..DATA_HEADER_LEN].copy_from_slice(&header);
        let n = buf.len();
        let (head, rest) = buf.split_at_mut(DATA_HEADER_LEN);
        let (body, tag_out) = rest.split_at_mut(n - DATA_HEADER_LEN - TAG_LEN);
        let tag = self
            .cipher
            .encrypt_inout_detached(&data_nonce(counter).into(), head, body.into())
            .expect("packet within AEAD limits");
        tag_out.copy_from_slice(&tag);
    }

    /// Opens a packet in place, returning the plaintext range.
    pub fn open(&self, counter: u64, buf: &mut [u8]) -> Option<std::ops::Range<usize>> {
        let n = buf.len();
        if n < DATA_HEADER_LEN + TAG_LEN {
            return None;
        }
        let (head, rest) = buf.split_at_mut(DATA_HEADER_LEN);
        let (body, tag) = rest.split_at_mut(n - DATA_HEADER_LEN - TAG_LEN);
        let tag = Tag::try_from(&*tag).ok()?;
        self.cipher
            .decrypt_inout_detached(&data_nonce(counter).into(), head, body.into(), &tag)
            .ok()?;
        Some(DATA_HEADER_LEN..n - TAG_LEN)
    }
}

/// Size of the replay window in counters.
pub const REPLAY_WINDOW: u64 = 4096;
const WORDS: usize = (REPLAY_WINDOW / 64) as usize;

/// A sliding replay window (RFC 6479 style), as in WireGuard. It is only
/// updated after a packet authenticates.
#[derive(Clone)]
pub(crate) struct ReplayWindow {
    /// One more than the largest counter accepted (0: none yet).
    top: u64,
    bits: Box<[u64; WORDS]>,
}

impl ReplayWindow {
    pub fn new() -> ReplayWindow {
        ReplayWindow {
            top: 0,
            bits: Box::new([0; WORDS]),
        }
    }

    fn bit(c: u64) -> (usize, u64) {
        let i = c % REPLAY_WINDOW;
        ((i / 64) as usize, 1u64 << (i % 64))
    }

    /// Whether `c` may be new.
    pub fn check(&self, c: u64) -> bool {
        if c >= self.top {
            return true;
        }
        if c + REPLAY_WINDOW < self.top {
            return false;
        }
        let (w, m) = Self::bit(c);
        self.bits[w] & m == 0
    }

    /// Marks `c` as seen. Call only after `check(c)` and authentication.
    pub fn update(&mut self, c: u64) {
        if c >= self.top {
            let advance = c + 1 - self.top;
            if advance >= REPLAY_WINDOW {
                self.bits.iter_mut().for_each(|w| *w = 0);
            } else {
                for x in self.top..=c {
                    let (w, m) = Self::bit(x);
                    self.bits[w] &= !m;
                }
            }
            self.top = c + 1;
        }
        let (w, m) = Self::bit(c);
        self.bits[w] |= m;
    }
}

/// A set of disjoint half-open `u64` ranges.
#[derive(Clone, Debug, Default)]
pub(crate) struct RangeSet {
    /// start -> end (exclusive).
    map: BTreeMap<u64, u64>,
}

impl RangeSet {
    pub fn new() -> RangeSet {
        RangeSet::default()
    }

    pub fn insert(&mut self, mut start: u64, mut end: u64) {
        if start >= end {
            return;
        }
        // Merge with a range that starts before and reaches start.
        if let Some((&s, &e)) = self.map.range(..=start).next_back() {
            if e >= start {
                if e >= end {
                    return;
                }
                start = s;
                self.map.remove(&s);
            }
        }
        // Absorb ranges starting within [start, end].
        while let Some((&s, &e)) = self.map.range(start..=end).next() {
            self.map.remove(&s);
            if e > end {
                end = e;
            }
        }
        self.map.insert(start, end);
    }

    #[cfg(test)]
    pub fn contains(&self, x: u64) -> bool {
        self.map
            .range(..=x)
            .next_back()
            .is_some_and(|(_, &e)| x < e)
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Ranges from the highest down.
    pub fn iter_desc(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.map.iter().rev().map(|(&s, &e)| (s, e))
    }

    /// Ranges from the lowest up.
    pub fn iter(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.map.iter().map(|(&s, &e)| (s, e))
    }

    /// Removes the lowest range.
    pub fn pop_lowest(&mut self) -> Option<(u64, u64)> {
        self.map.pop_first()
    }

    /// The end of the range starting at or below `x` that contains `x`, if any.
    pub fn end_of_run(&self, x: u64) -> Option<u64> {
        self.map
            .range(..=x)
            .next_back()
            .filter(|(_, &e)| x < e)
            .map(|(_, &e)| e)
    }

    /// Removes everything below `x`.
    pub fn remove_below(&mut self, x: u64) {
        while let Some((&s, &e)) = self.map.iter().next() {
            if e <= x {
                self.map.remove(&s);
            } else if s < x {
                self.map.remove(&s);
                self.map.insert(x, e);
                break;
            } else {
                break;
            }
        }
    }

    /// Removes `[start, end)`.
    pub fn remove(&mut self, start: u64, end: u64) {
        if start >= end {
            return;
        }
        let overlapping: Vec<(u64, u64)> = self
            .map
            .range(..end)
            .filter(|(_, &e)| e > start)
            .map(|(&s, &e)| (s, e))
            .collect();
        for (s, e) in overlapping {
            self.map.remove(&s);
            if s < start {
                self.map.insert(s, start);
            }
            if e > end {
                self.map.insert(end, e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_window() {
        let mut w = ReplayWindow::new();
        assert!(w.check(0));
        w.update(0);
        assert!(!w.check(0));
        w.update(5);
        assert!(w.check(3));
        assert!(!w.check(5));
        w.update(3);
        assert!(!w.check(3));
        w.update(5000);
        assert!(!w.check(5000));
        assert!(w.check(4999));
        assert!(w.check(5000 - 4095));
        assert!(!w.check(5000 - 4096));
        assert!(!w.check(3));
        // Window of at least 2048.
        w.update(10_000);
        assert!(w.check(10_000 - 2048));
        w.update(10_000 - 2048);
        assert!(!w.check(10_000 - 2048));
    }

    #[test]
    fn range_set() {
        let mut r = RangeSet::new();
        r.insert(10, 20);
        r.insert(30, 40);
        r.insert(20, 30);
        assert_eq!(r.iter().collect::<Vec<_>>(), vec![(10, 40)]);
        r.insert(5, 12);
        r.insert(45, 50);
        assert_eq!(r.iter().collect::<Vec<_>>(), vec![(5, 40), (45, 50)]);
        assert!(r.contains(39));
        assert!(!r.contains(40));
        r.remove(8, 12);
        assert_eq!(
            r.iter().collect::<Vec<_>>(),
            vec![(5, 8), (12, 40), (45, 50)]
        );
        r.remove_below(20);
        assert_eq!(r.iter().collect::<Vec<_>>(), vec![(20, 40), (45, 50)]);
        assert_eq!(r.end_of_run(25), Some(40));
        assert_eq!(r.end_of_run(42), None);
    }

    #[test]
    fn seal_open() {
        let k = DirKey::new(&[1; 32], 1);
        let mut buf = vec![0u8; 16 + 5 + 16];
        buf[16..21].copy_from_slice(b"hello");
        k.seal(9, 77, &mut buf);
        assert_eq!(buf[1], 1);
        let mut copy = buf.clone();
        let r = k.open(77, &mut copy).unwrap();
        assert_eq!(&copy[r], b"hello");
        let mut bad = buf.clone();
        bad[5] ^= 1; // header is authenticated
        assert!(k.open(77, &mut bad).is_none());
    }
}
