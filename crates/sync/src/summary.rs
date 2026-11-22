//! Summaries, for links whose round trip is long (`sync.md#long-delays`).
//!
//! A summary gives every id the sender holds in a few bytes each: the
//! first `b`/8 bytes of `BLAKE3.keyed_hash(nonce, id)`, sorted. The
//! responder sends every object whose short id is absent from it, or, when
//! chance matches are likely enough to matter, every object it holds; and
//! then opens an ordinary reconciliation as its initiator, the exact
//! backstop.

use crate::{Id, Label, Message, SetStore, SyncError};

/// Bytes of a summary message besides its short ids.
const SUMMARY_OVERHEAD: usize = 128;

/// How large a set a sender assumes the other may hold when it chooses the
/// length of its short ids: 2^32 ids.
pub const ASSUMED_OTHER_BITS: u32 = 32;

/// The short id of `id` under `nonce`: the first `width` bytes of
/// `BLAKE3.keyed_hash(nonce, id)`.
pub fn short_id(nonce: &[u8; 32], id: &Id, width: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..width].copy_from_slice(&blake3::keyed_hash(nonce, id).as_bytes()[..width]);
    out
}

/// The length of short ids, in bits, for a sender holding `n` ids: enough
/// that against a set of up to 2^[`ASSUMED_OTHER_BITS`] ids the expected
/// number of chance matches stays at most 2^-20, so the responder sends
/// only what is absent. A multiple of 8, from 8 to 256.
pub fn summary_bits(n: usize) -> u32 {
    let mine = usize::BITS - n.leading_zeros(); // n < 2^mine
    let want = mine + ASSUMED_OTHER_BITS + 20;
    want.div_ceil(8).clamp(1, 32) * 8
}

/// Whether a responder holding `n_mine` ids sends every one of them in
/// answer to a summary of `n_theirs` short ids of `bits` bits: whether
/// `E = n_mine × n_theirs / 2^bits` is more than 2^-20.
pub fn sends_everything(n_mine: u64, n_theirs: u64, bits: u32) -> bool {
    let p = u128::from(n_mine) * u128::from(n_theirs);
    if bits < 20 {
        return p > 0;
    }
    let shift = bits - 20;
    shift < 128 && p > (1u128 << shift)
}

/// A summary of every id `set` holds, as messages of at most `max_message`
/// bytes, the last marking the end of the turn. A set with no ids gives
/// one message with a count of 0: "I hold nothing".
pub fn summary_messages(
    label: Label,
    set: &impl SetStore,
    nonce: [u8; 32],
    bits: u32,
    max_message: usize,
) -> Vec<Message> {
    let width = (bits / 8) as usize;
    let n = set.len();
    let mut shorts: Vec<[u8; 32]> = Vec::with_capacity(n);
    let mut pos = 0;
    while pos < n {
        let end = n.min(pos + 4096);
        shorts.extend(
            set.ids(pos, end)
                .iter()
                .map(|id| short_id(&nonce, id, width)),
        );
        pos = end;
    }
    shorts.sort_unstable();
    let per = ((max_message.saturating_sub(SUMMARY_OVERHEAD)) / width).max(1);
    let mut out: Vec<Message> = shorts
        .chunks(per)
        .map(|c| Message::Summary {
            label,
            count: n as u64,
            nonce,
            bits,
            short_ids: c.iter().flat_map(|s| s[..width].iter().copied()).collect(),
            end: false,
        })
        .collect();
    if out.is_empty() {
        out.push(Message::Summary {
            label,
            count: 0,
            nonce,
            bits,
            short_ids: Vec::new(),
            end: false,
        });
    }
    if let Some(Message::Summary { end, .. }) = out.last_mut() {
        *end = true;
    }
    out
}

/// A whole summary, as received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Summary {
    /// How many ids the sender holds.
    pub count: u64,
    /// The nonce of its short ids.
    pub nonce: [u8; 32],
    /// Their length in bits.
    pub bits: u32,
    /// The short ids, ascending, one after another.
    short_ids: Vec<u8>,
}

impl Summary {
    fn width(&self) -> usize {
        (self.bits / 8) as usize
    }

    /// Whether the sender gave `short` (a short id of this summary's
    /// width).
    fn holds(&self, short: &[u8]) -> bool {
        let w = self.width();
        let (mut lo, mut hi) = (0usize, self.short_ids.len() / w);
        while lo < hi {
            let mid = (lo + hi) / 2;
            match self.short_ids[mid * w..(mid + 1) * w].cmp(short) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
                std::cmp::Ordering::Equal => return true,
            }
        }
        false
    }

    /// Whether a responder holding `n_mine` ids sends them all
    /// ([`sends_everything`]).
    pub fn sends_everything(&self, n_mine: usize) -> bool {
        sends_everything(n_mine as u64, self.count, self.bits)
    }

    /// The answer of a responder whose ids are `set`: the ids of the
    /// objects to send, ascending. Every id it holds if
    /// [`sends_everything`](Summary::sends_everything), otherwise every id
    /// whose short id is absent from the summary.
    pub fn to_send(&self, set: &impl SetStore) -> Vec<Id> {
        let n = set.len();
        let everything = self.sends_everything(n);
        let w = self.width();
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < n {
            let end = n.min(pos + 4096);
            for id in set.ids(pos, end) {
                if everything || !self.holds(&short_id(&self.nonce, &id, w)[..w]) {
                    out.push(id);
                }
            }
            pos = end;
        }
        out
    }
}

/// Reads a summary spread over messages, checking what spans them: fields
/// 1 to 4 repeated, short ids ascending across messages, and `count` of
/// them in all when the last message comes. Whatever breaks these is
/// malformed, and the stream it came on is to be reset.
pub struct SummaryReader {
    label: Label,
    limit: usize,
    head: Option<(u64, [u8; 32], u32)>,
    short_ids: Vec<u8>,
    done: bool,
}

impl SummaryReader {
    /// A reader of a summary of `label` that holds at most `limit` bytes of
    /// short ids, this device's bound on what a peer can make it hold.
    pub fn new(label: Label, limit: usize) -> SummaryReader {
        SummaryReader {
            label,
            limit,
            head: None,
            short_ids: Vec::new(),
            done: false,
        }
    }

    /// Takes one message of the summary. Returns the whole summary once its
    /// last message has come.
    pub fn push(&mut self, msg: &Message) -> Result<Option<Summary>, SyncError> {
        let Message::Summary {
            label,
            count,
            nonce,
            bits,
            short_ids,
            end,
        } = msg
        else {
            return Err(SyncError::BadSummary("not a summary"));
        };
        if self.done {
            return Err(SyncError::BadSummary("the summary has ended"));
        }
        if *label != self.label {
            return Err(SyncError::BadSummary("message for another label"));
        }
        let head = (*count, *nonce, *bits);
        match self.head {
            None => self.head = Some(head),
            Some(h) if h != head => return Err(SyncError::BadSummary("fields 1 to 4 must repeat")),
            Some(_) => {}
        }
        let w = (*bits / 8) as usize;
        if let (Some(last), Some(first)) = (
            self.short_ids
                .len()
                .checked_sub(w)
                .map(|i| &self.short_ids[i..]),
            short_ids.get(..w),
        ) {
            if last > first {
                return Err(SyncError::BadSummary("short ids must ascend"));
            }
        }
        let total = (self.short_ids.len() + short_ids.len()) / w;
        if total as u64 > *count {
            return Err(SyncError::BadSummary("more short ids than the count"));
        }
        if self.short_ids.len() + short_ids.len() > self.limit {
            return Err(SyncError::BadSummary("larger than this device takes"));
        }
        self.short_ids.extend_from_slice(short_ids);
        if !*end {
            return Ok(None);
        }
        self.done = true;
        if total as u64 != *count {
            return Err(SyncError::BadSummary("fewer short ids than the count"));
        }
        Ok(Some(Summary {
            count: *count,
            nonce: *nonce,
            bits: *bits,
            short_ids: std::mem::take(&mut self.short_ids),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemSet;

    fn id(n: u64) -> Id {
        *blake3::hash(&n.to_le_bytes()).as_bytes()
    }

    fn read(msgs: &[Message]) -> Result<Summary, SyncError> {
        let mut r = SummaryReader::new([1; 32], 1 << 30);
        let mut out = None;
        for m in msgs {
            let m = Message::decode(&m.encode())?;
            out = r.push(&m)?;
        }
        out.ok_or(SyncError::BadSummary("unfinished"))
    }

    #[test]
    fn bits_grow_with_the_set() {
        assert_eq!(summary_bits(0), 56);
        assert_eq!(summary_bits(1), 56);
        assert_eq!(summary_bits(50_000), 72);
        assert_eq!(summary_bits(10_000_000), 80);
        assert_eq!(summary_bits(usize::MAX), 120);
        for n in [1usize, 1000, 50_000, 10_000_000] {
            assert!(!sends_everything(n as u64, 1 << 32, summary_bits(n)));
        }
    }

    #[test]
    fn the_rule_for_everything() {
        // E = 2^-20 exactly is not more than it.
        assert!(!sends_everything(1, 1, 20));
        assert!(sends_everything(2, 1, 20));
        assert!(sends_everything(1, 1, 8));
        assert!(!sends_everything(0, 1000, 8));
        assert!(!sends_everything(1000, 0, 8));
        assert!(!sends_everything(u64::MAX, u64::MAX, 256));
        // The spec's examples: 32 bits for 50,000 a side is E ≈ 0.58.
        assert!(sends_everything(50_000, 50_000, 32));
    }

    #[test]
    fn answers_what_is_absent() {
        let a: MemSet = (0..3000).map(id).collect();
        let b: MemSet = (1000..5000).map(id).collect();
        let msgs = summary_messages([1; 32], &a, [9; 32], summary_bits(a.len()), 4096);
        assert!(msgs.len() > 1);
        let s = read(&msgs).unwrap();
        assert_eq!(s.count, 3000);
        let send = s.to_send(&b);
        let expect: Vec<Id> = b.iter().filter(|i| !a.contains(i)).copied().collect();
        assert_eq!(send, expect);
    }

    #[test]
    fn nothing_held() {
        let empty = MemSet::new();
        let b: MemSet = (0..100).map(id).collect();
        let msgs = summary_messages([1; 32], &empty, [9; 32], summary_bits(0), 4096);
        assert_eq!(msgs.len(), 1);
        let s = read(&msgs).unwrap();
        assert_eq!(s.count, 0);
        assert_eq!(s.to_send(&b).len(), 100);
    }

    #[test]
    fn short_bits_send_everything() {
        let a: MemSet = (0..3000).map(id).collect();
        let b: MemSet = (0..3000).map(id).collect();
        let s = read(&summary_messages([1; 32], &a, [9; 32], 16, 4096)).unwrap();
        assert!(s.sends_everything(b.len()));
        assert_eq!(s.to_send(&b).len(), 3000);
    }

    #[test]
    fn malformed() {
        let a: MemSet = (0..3000).map(id).collect();
        let msgs = summary_messages([1; 32], &a, [9; 32], 64, 4096);
        assert!(read(&msgs).is_ok());
        // Cut short: fewer short ids than the count.
        let mut short = msgs.clone();
        short.remove(1);
        assert!(read(&short).is_err());
        // Out of order across messages.
        let mut swapped = msgs.clone();
        swapped.swap(0, 1);
        assert!(read(&swapped).is_err());
        // A field that does not repeat.
        let mut changed = msgs.clone();
        if let Message::Summary { nonce, .. } = &mut changed[1] {
            *nonce = [8; 32];
        }
        assert!(read(&changed).is_err());
        // More than the count.
        let mut more = msgs.clone();
        if let Message::Summary { count, .. } = &mut more[0] {
            *count = 1;
        }
        assert!(read(&more[..1]).is_err());
        // Past a limit this device sets.
        let mut r = SummaryReader::new([1; 32], 100);
        assert!(r.push(&msgs[0]).is_err());
        // Something after the end.
        let mut r = SummaryReader::new([1; 32], 1 << 30);
        let one = summary_messages([1; 32], &MemSet::new(), [9; 32], 8, 4096);
        assert!(r.push(&one[0]).unwrap().is_some());
        assert!(r.push(&one[0]).is_err());
    }
}
