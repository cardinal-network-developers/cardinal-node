//! Range-based set reconciliation (`sync.md#range-reconciliation`).

use crate::message::check_ranges;
use crate::{Id, Label, Message, Mode, Range, SetStore, SyncError};

/// A side lists its ids in a range instead of splitting it when it holds
/// at most this many.
pub const LIST_THRESHOLD: usize = 32;

/// A mismatched range is split into this many subranges.
pub const SPLIT: usize = 16;

/// The size a reconcile message should not exceed.
pub const MAX_MESSAGE: usize = 64 * 1024;

/// Bytes of a reconcile message besides its ranges: the record header, op,
/// label, and the list header of the ranges.
const MESSAGE_OVERHEAD: usize = 48;

/// The largest range this side emits other than "you lack": a list of 32
/// ids (about 1,100 bytes), with slack.
const MAX_SUMMARY: usize = 1200;

/// The largest range an echo emits: a fingerprint with an upper bound.
const ECHO_MAX: usize = 64;

/// Room kept free before answering one more range: the largest answer to a
/// fingerprint (16 fingerprint ranges, or a list of 32 ids), plus the
/// remainder range that may end the message after it.
const RESERVE: usize = 2 * MAX_SUMMARY;

/// Encoded size of one id in a list.
const ID_LEN: usize = 34;

/// Counters for one reconciliation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Reconcile messages received.
    pub received: u64,
    /// Reconcile messages produced (including the initial one).
    pub sent: u64,
    /// Messages that had to be truncated to stay under the size limit.
    pub truncated: u64,
}

/// One side of a reconciliation of one set.
///
/// Holds no state that matters between sessions: only the ids learned so
/// far. Either side may start with [`initiate`](Reconciler::initiate); the
/// other creates its reconciler when the first message arrives.
///
/// Replies never exceed [`MAX_MESSAGE`] (configurable). When a reply would,
/// the ranges that fit are answered in full; the next ones are answered
/// with this side's own fingerprint of the same range, not split, so the
/// peer splits them in the next round; and if even that does not fit, the
/// rest of the id space is sent as one range (a fingerprint, or a list if
/// this side holds at most 32 ids there). Each message therefore still
/// covers every id, and each message gets exactly one reply until one
/// consists only of skips.
pub struct Reconciler<S: SetStore> {
    label: Label,
    set: S,
    wanted: Vec<Id>,
    they_lack: Vec<Id>,
    done: bool,
    max_message: usize,
    stats: Stats,
}

/// Replies being built, with adjacent skips merged.
struct Out {
    ranges: Vec<Range>,
    bytes: usize,
}

impl Out {
    fn push(&mut self, r: Range) {
        if let (Mode::Skip, Some(last)) = (&r.mode, self.ranges.last_mut()) {
            if last.mode == Mode::Skip {
                self.bytes -= last.encoded_len();
                last.upper = r.upper;
                self.bytes += last.encoded_len();
                return;
            }
        }
        self.bytes += r.encoded_len();
        self.ranges.push(r);
    }

    fn only_skips(&self) -> bool {
        self.ranges.iter().all(|r| r.mode == Mode::Skip)
    }
}

impl<S: SetStore> Reconciler<S> {
    /// A reconciler of the set `label`, whose ids are `set`.
    pub fn new(label: Label, set: S) -> Reconciler<S> {
        Reconciler {
            label,
            set,
            wanted: Vec::new(),
            they_lack: Vec::new(),
            done: false,
            max_message: MAX_MESSAGE,
            stats: Stats::default(),
        }
    }

    /// Changes the message size limit (at least 4 KiB).
    pub fn with_max_message(mut self, bytes: usize) -> Reconciler<S> {
        self.max_message = bytes.max(4096);
        self
    }

    /// The set's label.
    pub fn label(&self) -> &Label {
        &self.label
    }

    /// The set being reconciled.
    pub fn set(&self) -> &S {
        &self.set
    }

    /// Whether the reconciliation has ended: this side sent or received a
    /// message of only skips.
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Counters.
    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// Ids learned so far that this side lacks, sorted and deduplicated,
    /// leaving the list empty. Safe to call before the end, to start
    /// fetching early.
    pub fn take_wanted(&mut self) -> Vec<Id> {
        let mut w = std::mem::take(&mut self.wanted);
        w.sort_unstable();
        w.dedup();
        w
    }

    /// Ids this side has told the peer it lacks, sorted and deduplicated,
    /// leaving the list empty. The peer will `want` them.
    pub fn take_they_lack(&mut self) -> Vec<Id> {
        let mut w = std::mem::take(&mut self.they_lack);
        w.sort_unstable();
        w.dedup();
        w
    }

    fn message(&mut self, ranges: Vec<Range>) -> Message {
        self.stats.sent += 1;
        Message::Reconcile {
            label: self.label,
            ranges,
        }
    }

    /// A list of this side's ids in positions `a..b` if few, else their
    /// fingerprint, as a range up to `upper`.
    fn summary(&self, a: usize, b: usize, upper: Option<Id>) -> Range {
        let mode = if b - a <= LIST_THRESHOLD {
            Mode::List(self.set.ids(a, b))
        } else {
            Mode::Fingerprint(self.set.fingerprint(a, b))
        };
        Range { upper, mode }
    }

    /// The first message: one range covering everything, a list if this
    /// side holds at most 32 ids, otherwise a fingerprint.
    pub fn initiate(&mut self) -> Message {
        self.done = false;
        let r = self.summary(0, self.set.len(), None);
        self.message(vec![r])
    }

    /// Handles a whole incoming message: a reconcile message for this
    /// label. Other messages are not this state machine's to handle.
    pub fn handle(&mut self, msg: &Message) -> Result<Option<Message>, SyncError> {
        match msg {
            Message::Reconcile { label, ranges } if *label == self.label => self.receive(ranges),
            Message::Reconcile { .. } => Err(SyncError::BadRanges("message for another label")),
            _ => Err(SyncError::BadRanges("not a reconcile message")),
        }
    }

    /// Answers the ranges of one incoming reconcile message. Returns the
    /// reply to send, or `None` if the message held only skips, which ends
    /// the reconciliation.
    pub fn receive(&mut self, ranges: &[Range]) -> Result<Option<Message>, SyncError> {
        check_ranges(ranges)?;
        self.stats.received += 1;
        if ranges.iter().all(|r| r.mode == Mode::Skip) {
            self.done = true;
            return Ok(None);
        }
        let budget = self.max_message - MESSAGE_OVERHEAD;
        let mut out = Out {
            ranges: Vec::new(),
            bytes: 0,
        };
        let mut lower: Option<Id> = None; // None: the start of the id space.
        let mut lower_rank = 0usize;
        let mut truncated = false;
        for r in ranges {
            let upper_rank = match &r.upper {
                Some(u) => self.set.rank(u),
                None => self.set.len(),
            };
            let in_range = |id: &Id| {
                lower.as_ref().is_none_or(|l| id >= l) && r.upper.as_ref().is_none_or(|u| id < u)
            };
            let learn = |wanted: &mut Vec<Id>, set: &S| {
                if let Mode::List(ids) | Mode::YouLack(ids) = &r.mode {
                    for id in ids.iter().filter(|id| in_range(id)) {
                        if !set.contains(id) {
                            wanted.push(*id);
                        }
                    }
                }
            };
            let room = budget.saturating_sub(out.bytes);
            if truncated {
                // Past the cut: still learn from what the peer told us.
                learn(&mut self.wanted, &self.set);
            } else if room < MAX_SUMMARY + ECHO_MAX {
                // No room for anything but one range covering the rest.
                truncated = true;
                out.push(self.summary(lower_rank, self.set.len(), None));
                learn(&mut self.wanted, &self.set);
            } else if room < RESERVE {
                // Echo: answer cheaply without splitting, so the peer
                // continues the work and the structure of the ranges is
                // kept for the next round.
                learn(&mut self.wanted, &self.set);
                let mode = match &r.mode {
                    Mode::Skip | Mode::YouLack(_) => Mode::Skip,
                    Mode::Fingerprint(_) | Mode::List(_) => {
                        let mine = self.set.fingerprint(lower_rank, upper_rank);
                        if upper_rank == lower_rank {
                            Mode::List(Vec::new())
                        } else if matches!(&r.mode, Mode::Fingerprint(fp) if *fp == mine) {
                            Mode::Skip
                        } else {
                            Mode::Fingerprint(mine)
                        }
                    }
                };
                out.push(Range {
                    upper: r.upper,
                    mode,
                });
            } else {
                match &r.mode {
                    Mode::Skip => out.push(Range {
                        upper: r.upper,
                        mode: Mode::Skip,
                    }),
                    Mode::Fingerprint(fp) => {
                        let count = upper_rank - lower_rank;
                        if self.set.fingerprint(lower_rank, upper_rank) == *fp {
                            out.push(Range {
                                upper: r.upper,
                                mode: Mode::Skip,
                            });
                        } else if count <= LIST_THRESHOLD {
                            out.push(Range {
                                upper: r.upper,
                                mode: Mode::List(self.set.ids(lower_rank, upper_rank)),
                            });
                        } else {
                            let mut starts = Vec::with_capacity(SPLIT + 1);
                            for i in 0..SPLIT {
                                starts.push(lower_rank + count * i / SPLIT);
                            }
                            starts.push(upper_rank);
                            for i in 0..SPLIT {
                                let upper = if i + 1 == SPLIT {
                                    r.upper
                                } else {
                                    Some(self.set.at(starts[i + 1]))
                                };
                                out.push(Range {
                                    upper,
                                    mode: Mode::Fingerprint(
                                        self.set.fingerprint(starts[i], starts[i + 1]),
                                    ),
                                });
                            }
                        }
                    }
                    Mode::List(theirs) => {
                        let mut theirs: Vec<Id> =
                            theirs.iter().filter(|id| in_range(id)).copied().collect();
                        theirs.sort_unstable();
                        theirs.dedup();
                        for id in &theirs {
                            if !self.set.contains(id) {
                                self.wanted.push(*id);
                            }
                        }
                        // Our ids absent from theirs, as many as fit with
                        // room left for a remainder range.
                        let room = budget.saturating_sub(out.bytes + MAX_SUMMARY + 64);
                        let cap = (room / ID_LEN).max(1);
                        let mut lack = Vec::new();
                        let mut cut_at = None;
                        let mut pos = lower_rank;
                        'scan: while pos < upper_rank {
                            let end = upper_rank.min(pos + 1024);
                            for id in self.set.ids(pos, end) {
                                if theirs.binary_search(&id).is_err() {
                                    if lack.len() == cap {
                                        cut_at = Some((id, pos));
                                        break 'scan;
                                    }
                                    lack.push(id);
                                }
                                pos += 1;
                            }
                        }
                        self.they_lack.extend_from_slice(&lack);
                        match cut_at {
                            None => out.push(Range {
                                upper: r.upper,
                                mode: Mode::YouLack(lack),
                            }),
                            Some((id, rank)) => {
                                out.push(Range {
                                    upper: Some(id),
                                    mode: Mode::YouLack(lack),
                                });
                                out.push(self.summary(rank, self.set.len(), None));
                                truncated = true;
                            }
                        }
                    }
                    Mode::YouLack(ids) => {
                        for id in ids.iter().filter(|id| in_range(id)) {
                            if !self.set.contains(id) {
                                self.wanted.push(*id);
                            }
                        }
                        out.push(Range {
                            upper: r.upper,
                            mode: Mode::Skip,
                        });
                    }
                }
            }
            lower = r.upper;
            lower_rank = upper_rank;
        }
        if truncated {
            self.stats.truncated += 1;
        }
        self.done = out.only_skips();
        Ok(Some(self.message(out.ranges)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemSet;

    fn id(n: u64) -> Id {
        *blake3::hash(&n.to_le_bytes()).as_bytes()
    }

    fn run(a: &MemSet, b: &MemSet, max: usize) -> (Vec<Id>, Vec<Id>, u64) {
        let mut ra = Reconciler::new([0; 32], a).with_max_message(max);
        let mut rb = Reconciler::new([0; 32], b).with_max_message(max);
        let mut msg = Some(ra.initiate());
        let mut to_b = true;
        let mut n = 0;
        while let Some(m) = msg {
            let bytes = m.encode();
            assert!(bytes.len() <= max, "{} > {max}", bytes.len());
            let m = Message::decode(&bytes).unwrap();
            msg = if to_b {
                rb.handle(&m).unwrap()
            } else {
                ra.handle(&m).unwrap()
            };
            to_b = !to_b;
            n += 1;
            assert!(n < 10_000, "no convergence");
        }
        assert!(ra.is_done() && rb.is_done());
        (ra.take_wanted(), rb.take_wanted(), n)
    }

    fn diff(x: &MemSet, y: &MemSet) -> Vec<Id> {
        x.iter().filter(|i| !y.contains(i)).copied().collect()
    }

    #[test]
    fn small_cases() {
        let empty = MemSet::new();
        let ten: MemSet = (0..10).map(id).collect();
        let many: MemSet = (0..1000).map(id).collect();
        for (a, b) in [
            (&empty, &empty),
            (&empty, &ten),
            (&ten, &empty),
            (&ten, &ten),
            (&many, &many),
            (&many, &empty),
            (&empty, &many),
            (&ten, &many),
            (&many, &ten),
        ] {
            let (wa, wb, _) = run(a, b, MAX_MESSAGE);
            assert_eq!(wa, diff(b, a));
            assert_eq!(wb, diff(a, b));
        }
    }

    #[test]
    fn identical_sets_take_one_round_trip() {
        let s: MemSet = (0..10_000).map(id).collect();
        let (_, _, n) = run(&s, &s, MAX_MESSAGE);
        assert_eq!(n, 2);
    }

    #[test]
    fn tiny_messages_still_converge() {
        let a: MemSet = (0..3000).map(id).collect();
        let b: MemSet = (1500..6000).map(id).collect();
        let (wa, wb, _) = run(&a, &b, 4096);
        assert_eq!(wa, diff(&b, &a));
        assert_eq!(wb, diff(&a, &b));
    }

    #[test]
    fn extreme_ids() {
        let a: MemSet = [[0u8; 32], [0xff; 32]]
            .into_iter()
            .chain((0..100).map(id))
            .collect();
        let b: MemSet = (50..150).map(id).collect();
        let (wa, wb, _) = run(&a, &b, MAX_MESSAGE);
        assert_eq!(wa, diff(&b, &a));
        assert_eq!(wb, diff(&a, &b));
    }
}
