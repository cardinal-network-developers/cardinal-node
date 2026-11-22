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

/// What one turn of this side says, at most, before it answers the rest of
/// the peer's turn more coarsely: sixteen messages.
pub const MAX_TURN: usize = 16 * MAX_MESSAGE;

/// Bytes of a reconcile message besides its ranges: the record header, op,
/// label, the list header of the ranges, and the end-of-turn mark.
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
    /// Turns this side sent, including the first.
    pub turns: u64,
    /// Turns that had to be answered coarsely to stay under the turn limit.
    pub truncated: u64,
}

/// One side of a reconciliation of one set.
///
/// Holds no state that matters between sessions: only the ids learned so
/// far, and how far the peer's current turn has got. Either side may start
/// with [`initiate`](Reconciler::initiate); the other creates its
/// reconciler when the first message arrives.
///
/// The two sides take turns (`sync.md#messages`). A turn is one or more
/// reconcile messages whose ranges together cover every id, the last marked
/// as ending it. [`receive`](Reconciler::receive) takes each message of the
/// peer's turn as it comes, learning from it at once what this side lacks,
/// and returns this side's whole turn once the peer's has ended, as
/// messages of at most [`MAX_MESSAGE`] (configurable) each.
///
/// A turn says at most about [`MAX_TURN`] (configurable). When answering
/// would go past that, the ranges that fit are answered in full; the next
/// ones with this side's own fingerprint of the same range, not split, so
/// the peer splits them next turn; and if even that does not fit, the rest
/// of the id space as one range (a fingerprint, or a list if this side holds
/// at most 32 ids there). A turn therefore still covers every id. Setting
/// the turn limit to the message limit gives one-message turns, which
/// interoperate with longer ones.
pub struct Reconciler<S: SetStore> {
    label: Label,
    set: S,
    wanted: Vec<Id>,
    they_lack: Vec<Id>,
    done: bool,
    max_message: usize,
    max_turn: usize,
    stats: Stats,
    /// The peer's turn under way, and this side's answer so far.
    turn: Option<Turn>,
}

/// Where the peer's turn has got, and this side's answer to it.
struct Turn {
    out: Out,
    /// Where the previous message stopped: `None` for the start.
    lower: Option<Id>,
    lower_rank: usize,
    truncated: bool,
    /// Whether the peer's turn so far holds only skips.
    only_skips: bool,
}

impl Turn {
    fn new() -> Turn {
        Turn {
            out: Out {
                ranges: Vec::new(),
                bytes: 0,
            },
            lower: None,
            lower_rank: 0,
            truncated: false,
            only_skips: true,
        }
    }
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
            max_turn: MAX_TURN,
            stats: Stats::default(),
            turn: None,
        }
    }

    /// Changes the message size limit (at least 4 KiB). The turn limit is
    /// kept at least as large.
    pub fn with_max_message(mut self, bytes: usize) -> Reconciler<S> {
        self.max_message = bytes.max(4096);
        self.max_turn = self.max_turn.max(self.max_message);
        self
    }

    /// Changes how much one turn says (at least one message): the message
    /// limit gives one-message turns.
    pub fn with_max_turn(mut self, bytes: usize) -> Reconciler<S> {
        self.max_turn = bytes.max(self.max_message);
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

    /// The set being reconciled, to add what arrived while the
    /// reconciliation went on (objects a summary's answer brought, say), so
    /// that it is not asked for again.
    pub fn set_mut(&mut self) -> &mut S {
        &mut self.set
    }

    /// Whether the reconciliation has ended: a turn of only skips was sent
    /// or received.
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Whether the peer's turn is under way: some of its messages came, the
    /// last not yet.
    pub fn in_turn(&self) -> bool {
        self.turn.is_some()
    }

    /// Counters.
    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// How many ids have been learned and not yet taken, to bound what a
    /// peer can make this side remember.
    pub fn wanted_count(&self) -> usize {
        self.wanted.len()
    }

    /// Ids learned so far that this side lacks, sorted and deduplicated,
    /// leaving the list empty. Meant to be called after every message, to
    /// fetch them as soon as they are known (`sync.md#fetching-objects`).
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

    /// This side's turn as messages: ranges packed in order, each message
    /// at most the message limit, the last marked as ending the turn.
    fn pack(&mut self, ranges: Vec<Range>) -> Vec<Message> {
        let mut out = Vec::new();
        let mut cur: Vec<Range> = Vec::new();
        let mut bytes = MESSAGE_OVERHEAD;
        for r in ranges {
            let len = r.encoded_len();
            if !cur.is_empty() && bytes + len > self.max_message {
                out.push(Message::Reconcile {
                    label: self.label,
                    ranges: std::mem::take(&mut cur),
                    end: false,
                });
                bytes = MESSAGE_OVERHEAD;
            }
            bytes += len;
            cur.push(r);
        }
        out.push(Message::Reconcile {
            label: self.label,
            ranges: cur,
            end: true,
        });
        self.stats.sent += out.len() as u64;
        self.stats.turns += 1;
        out
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

    /// The first turn: one message of one range covering everything, a
    /// list if this side holds at most 32 ids, otherwise a fingerprint.
    pub fn initiate(&mut self) -> Message {
        self.done = false;
        self.turn = None;
        let r = self.summary(0, self.set.len(), None);
        let mut m = self.pack(vec![r]);
        m.pop().expect("one message")
    }

    /// Handles one incoming reconcile message for this label, as
    /// [`receive`](Reconciler::receive). Other messages are not this state
    /// machine's to handle.
    pub fn handle(&mut self, msg: &Message) -> Result<Vec<Message>, SyncError> {
        match msg {
            Message::Reconcile { label, ranges, end } if *label == self.label => {
                self.receive(ranges, *end)
            }
            Message::Reconcile { .. } => Err(SyncError::BadRanges("message for another label")),
            _ => Err(SyncError::BadRanges("not a reconcile message")),
        }
    }

    /// Takes one message of the peer's turn: its ranges, and whether it
    /// ends the turn. Learns at once what this side lacks
    /// ([`take_wanted`](Reconciler::take_wanted)). Returns nothing until the
    /// turn ends; then this side's turn, to send in order, or nothing if the
    /// peer's turn held only skips, which ends the reconciliation. After
    /// this side's turn of only skips, too, [`is_done`](Reconciler::is_done)
    /// holds.
    pub fn receive(&mut self, ranges: &[Range], end: bool) -> Result<Vec<Message>, SyncError> {
        check_ranges(ranges, end)?;
        if self.done {
            return Err(SyncError::BadRanges("the reconciliation has ended"));
        }
        let mut t = self.turn.take().unwrap_or_else(Turn::new);
        if let (Some(l), Some(u)) = (&t.lower, &ranges[0].upper) {
            if u <= l {
                return Err(SyncError::BadRanges(
                    "a message must go on where the one before it stopped",
                ));
            }
        }
        self.stats.received += 1;
        t.only_skips &= ranges.iter().all(|r| r.mode == Mode::Skip);
        self.answer(&mut t, ranges);
        if !end {
            self.turn = Some(t);
            return Ok(Vec::new());
        }
        if t.only_skips {
            self.done = true;
            return Ok(Vec::new());
        }
        if t.truncated {
            self.stats.truncated += 1;
        }
        self.done = t.out.only_skips();
        Ok(self.pack(t.out.ranges))
    }

    /// Answers the ranges of one message of the peer's turn into `t`.
    fn answer(&mut self, t: &mut Turn, ranges: &[Range]) {
        let parts = self.max_turn / self.max_message + 1;
        let budget = self.max_turn - (MESSAGE_OVERHEAD * parts).min(self.max_turn / 2);
        // A "you lack" range goes in pieces that each fit a message.
        let piece = ((self.max_message - MESSAGE_OVERHEAD - 128) / ID_LEN).max(1);
        let out = &mut t.out;
        let mut lower = t.lower;
        let mut lower_rank = t.lower_rank;
        let mut truncated = t.truncated;
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
                // kept for the next turn.
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
                        let last_upper = match cut_at {
                            None => r.upper,
                            Some((id, _)) => Some(id),
                        };
                        // In pieces, each ending where the next begins.
                        let n = lack.len().div_ceil(piece).max(1);
                        for i in 0..n {
                            let a = i * piece;
                            let b = lack.len().min(a + piece);
                            let upper = if i + 1 == n {
                                last_upper
                            } else {
                                Some(lack[b])
                            };
                            out.push(Range {
                                upper,
                                mode: Mode::YouLack(lack[a..b].to_vec()),
                            });
                        }
                        if let Some((_, rank)) = cut_at {
                            out.push(self.summary(rank, self.set.len(), None));
                            truncated = true;
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
        t.lower = lower;
        t.lower_rank = lower_rank;
        t.truncated = truncated;
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
        run_turns(a, b, max, MAX_TURN, MAX_TURN)
    }

    /// Reconciles with each side's own turn limit; returns what each
    /// learned it lacks and how many turns went across.
    fn run_turns(
        a: &MemSet,
        b: &MemSet,
        max: usize,
        turn_a: usize,
        turn_b: usize,
    ) -> (Vec<Id>, Vec<Id>, u64) {
        let mut ra = Reconciler::new([0; 32], a)
            .with_max_message(max)
            .with_max_turn(turn_a);
        let mut rb = Reconciler::new([0; 32], b)
            .with_max_message(max)
            .with_max_turn(turn_b);
        let mut turn = vec![ra.initiate()];
        let mut to_b = true;
        let mut n = 0;
        let (mut wa, mut wb) = (Vec::new(), Vec::new());
        while !turn.is_empty() {
            let mut reply = Vec::new();
            for m in turn {
                let bytes = m.encode();
                assert!(bytes.len() <= max, "{} > {max}", bytes.len());
                let m = Message::decode(&bytes).unwrap();
                let (r, w) = if to_b {
                    (&mut rb, &mut wb)
                } else {
                    (&mut ra, &mut wa)
                };
                assert!(reply.is_empty(), "a reply before the turn ended");
                reply = r.handle(&m).unwrap();
                w.extend(r.take_wanted());
            }
            turn = reply;
            to_b = !to_b;
            n += 1;
            assert!(n < 10_000, "no convergence");
        }
        assert!(ra.is_done() && rb.is_done());
        wa.sort();
        wa.dedup();
        wb.sort();
        wb.dedup();
        (wa, wb, n)
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

    #[test]
    fn long_turns_meet_one_message_turns() {
        let a: MemSet = (0..5000).map(id).collect();
        let b: MemSet = (2500..9000).map(id).collect();
        let (wa, wb, long) = run_turns(&a, &b, 4096, 64 * 4096, 64 * 4096);
        assert_eq!(wa, diff(&b, &a));
        assert_eq!(wb, diff(&a, &b));
        for (ta, tb) in [(4096, 64 * 4096), (64 * 4096, 4096), (4096, 4096)] {
            let (wa, wb, n) = run_turns(&a, &b, 4096, ta, tb);
            assert_eq!(wa, diff(&b, &a), "{ta} {tb}");
            assert_eq!(wb, diff(&a, &b), "{ta} {tb}");
            assert!(n >= long, "{n} turns against {long}");
        }
    }

    #[test]
    fn several_message_turns_save_round_trips() {
        let a: MemSet = (0..3000).map(id).collect();
        let b: MemSet = (1500..6000).map(id).collect();
        let (_, _, one) = run_turns(&a, &b, 4096, 4096, 4096);
        let (_, _, many) = run_turns(&a, &b, 4096, MAX_TURN, MAX_TURN);
        assert!(many * 4 < one, "{many} turns against {one}");
    }

    #[test]
    fn a_turn_must_go_on_in_order() {
        let a: MemSet = (0..100).map(id).collect();
        let mut r = Reconciler::new([0; 32], &a);
        let mid = id(5);
        let first = [Range {
            upper: Some(mid),
            mode: Mode::Fingerprint([0; 16]),
        }];
        assert!(r.receive(&first, false).unwrap().is_empty());
        assert!(r.in_turn());
        // Back before where the last message stopped.
        let back = [
            Range {
                upper: Some(mid),
                mode: Mode::Skip,
            },
            Range {
                upper: None,
                mode: Mode::Skip,
            },
        ];
        assert!(r.receive(&back, true).is_err());
        // A message not ending its turn may not be open-ended, and the
        // last of a turn must be.
        assert!(r
            .receive(
                &[Range {
                    upper: None,
                    mode: Mode::Skip
                }],
                false
            )
            .is_err());
        assert!(r
            .receive(
                &[Range {
                    upper: Some([0xff; 32]),
                    mode: Mode::Skip
                }],
                true
            )
            .is_err());
    }

    #[test]
    fn learns_before_the_turn_ends() {
        let a: MemSet = (0..10).map(id).collect();
        let mut r = Reconciler::new([0; 32], &a);
        let mut theirs: Vec<Id> = (100..110).map(id).collect();
        theirs.sort();
        let part = [Range {
            upper: Some([0x80; 32]),
            mode: Mode::List(theirs.iter().filter(|i| i[0] < 0x80).copied().collect()),
        }];
        assert!(r.receive(&part, false).unwrap().is_empty());
        let early = r.take_wanted();
        assert!(!early.is_empty());
        assert!(early.iter().all(|i| i[0] < 0x80));
    }
}
