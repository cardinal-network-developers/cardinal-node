//! How a stream from each of several devices reaches all the others with no
//! centre (`profiles.md#calls`): the routing part, which only decides, and
//! sends nothing itself. Calls carry their sound with it.
//!
//! Every device starts out passing each frame it has not seen to all its
//! links. A frame that comes again on another link shows that link is not
//! needed for that voice: once a device has two links it takes a voice from,
//! it tells any other that sends it that voice to stop (a prune), and that
//! link only says now and then how far it has the voice (a have). A device
//! that hears of frames it lacks asks for the voice again on that link (a
//! graft). So each voice settles into a tree along the quickest paths, held
//! twice over, and heals when a link goes, all from what each device sees
//! itself (Plumtree, Leitão, Pereira and Rodrigues, SRDS 2007).

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

/// Whose a frame is: `first8(BLAKE3(device signing key))`.
pub type Voice = [u8; 8];
/// A link, by the other device's static key.
pub type LinkId = [u8; 32];

/// How many links a device takes each voice from: two, so that losing one
/// loses nothing.
pub const KEEP: usize = 2;
/// How many voices a device passes on at once: those that began first, of
/// those heard lately.
pub const MOST_VOICES: usize = 6;
/// How long a voice counts as speaking after its last frame.
pub const VOICE_FOR: Duration = Duration::from_millis(500);
/// How many frames a device remembers, so that one coming round another way
/// is dropped.
pub const SEEN: usize = 4096;
/// A frame this far behind the newest of its voice is old, whatever it says.
pub const STALE: u32 = 500;
/// How far behind a link's have a device may be before it asks for the
/// voice on that link: ten frames, a fifth of a second of sound.
pub const LAG: u32 = 10;
/// A link that has sent nothing for this long is gone, though its session
/// may not know it yet.
pub const SILENT_FOR: Duration = Duration::from_secs(12);
/// How long a device counts as on the call after it was last heard.
pub const ON_IT_FOR: Duration = Duration::from_secs(12);
/// A prune or graft for one voice on one link is sent at most this often.
const ASK_EVERY: Duration = Duration::from_secs(1);
/// A voice heard this lately is told of in haves.
const HAVE_FOR: Duration = Duration::from_millis(500);

/// The bytes before what a frame carries: voice, number, signature.
pub const HEADER: usize = 8 + 4 + 64;

/// A frame as it travels: `voice (8) || number (4, big-endian) || signature
/// (64) || payload`. A frame with no payload says only that its device is
/// on the call.
#[derive(Debug)]
pub struct Frame<'a> {
    pub voice: Voice,
    pub n: u32,
    pub signature: [u8; 64],
    pub payload: &'a [u8],
}

impl<'a> Frame<'a> {
    pub fn parse(b: &'a [u8]) -> Option<Frame<'a>> {
        if b.len() < HEADER {
            return None;
        }
        Some(Frame {
            voice: b[..8].try_into().ok()?,
            n: u32::from_be_bytes(b[8..12].try_into().ok()?),
            signature: b[12..HEADER].try_into().ok()?,
            payload: &b[HEADER..],
        })
    }

    /// Whether this says only that its device is there.
    pub fn here(&self) -> bool {
        self.payload.is_empty()
    }
}

/// What a frame's signature covers, so that it holds for this call only.
pub fn signed_part(call: &[u8; 16], voice: &Voice, n: u32, payload: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(32 + 16 + 12 + payload.len());
    m.extend_from_slice(b"cardinal call frame v1");
    m.extend_from_slice(call);
    m.extend_from_slice(voice);
    m.extend_from_slice(&n.to_be_bytes());
    m.extend_from_slice(payload);
    m
}

/// A frame, signed.
pub fn frame(
    key: &cardinal_crypto::SigningKey,
    call: &[u8; 16],
    voice: &Voice,
    n: u32,
    payload: &[u8],
) -> Vec<u8> {
    let signature = key.sign(&signed_part(call, voice, n, payload));
    let mut out = Vec::with_capacity(HEADER + payload.len());
    out.extend_from_slice(voice);
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(&signature);
    out.extend_from_slice(payload);
    out
}

/// Whether a frame is signed by `key`.
pub fn signed_by(f: &Frame<'_>, call: &[u8; 16], key: &[u8; 32]) -> bool {
    let m = signed_part(call, &f.voice, f.n, f.payload);
    cardinal_crypto::sign::verify(key, &m, &f.signature).is_ok()
}

pub fn voice_of(key: &[u8; 32]) -> Voice {
    let h = blake3::hash(key);
    let mut v = [0; 8];
    v.copy_from_slice(&h.as_bytes()[..8]);
    v
}

/// Words between two devices about a call's routing, as datagrams on the
/// call's second channel: `kind (1) || body`.
#[derive(Debug, PartialEq, Eq)]
pub enum Word {
    /// Send me no more of this voice: I have it elsewhere.
    Prune(Voice),
    /// Send me this voice again.
    Graft(Voice),
    /// How far I have each of these voices, which I do not send you. Empty,
    /// it says only that the link is there.
    Have(Vec<(Voice, u32)>),
}

impl Word {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Word::Prune(v) => [&[1u8][..], v].concat(),
            Word::Graft(v) => [&[2u8][..], v].concat(),
            Word::Have(list) => {
                let mut out = vec![3u8];
                for (v, n) in list.iter().take(64) {
                    out.extend_from_slice(v);
                    out.extend_from_slice(&n.to_be_bytes());
                }
                out
            }
        }
    }

    pub fn decode(b: &[u8]) -> Option<Word> {
        let (kind, body) = b.split_first()?;
        match kind {
            1 | 2 if body.len() == 8 => {
                let v: Voice = body.try_into().ok()?;
                Some(if *kind == 1 {
                    Word::Prune(v)
                } else {
                    Word::Graft(v)
                })
            }
            3 if body.len() % 12 == 0 && body.len() <= 64 * 12 => Some(Word::Have(
                body.chunks_exact(12)
                    .map(|c| {
                        let v: Voice = c[..8].try_into().expect("8 bytes");
                        (v, u32::from_be_bytes(c[8..].try_into().expect("4 bytes")))
                    })
                    .collect(),
            )),
            _ => None,
        }
    }
}

struct Link {
    /// Voices this link asked not to be sent.
    lazy: HashSet<Voice>,
    /// When this device last asked it to stop, or to start, each voice.
    asked: HashMap<Voice, Instant>,
    /// When anything last came on it.
    heard: Instant,
    /// Its device's person is on the call; otherwise it only carries it.
    person: bool,
}

/// A link a voice is taken from.
#[derive(Clone, Copy)]
struct Parent {
    /// When it last brought a frame first.
    first: Option<Instant>,
}

/// What came of a frame.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Got {
    /// It was new here.
    pub fresh: bool,
    /// The links to pass it to.
    pub forward: Vec<LinkId>,
    /// The link it came on is to be told to stop sending this voice.
    pub prune: bool,
}

/// One call's routing, as one device sees it.
pub struct Tree {
    /// This device's voice, while its person is on the call.
    own: Option<Voice>,
    links: HashMap<LinkId, Link>,
    seen: HashSet<(Voice, u32)>,
    order: VecDeque<(Voice, u32)>,
    /// The newest number of each voice, and when it came.
    newest: HashMap<Voice, (u32, Instant)>,
    /// When each voice began speaking, and was last heard speaking.
    speaking: HashMap<Voice, (Instant, Instant)>,
    /// When each voice was last heard at all.
    heard: HashMap<Voice, Instant>,
    parents: HashMap<Voice, HashMap<LinkId, Parent>>,
}

impl Tree {
    pub fn new(own: Option<Voice>) -> Tree {
        Tree {
            own,
            links: HashMap::new(),
            seen: HashSet::new(),
            order: VecDeque::new(),
            newest: HashMap::new(),
            speaking: HashMap::new(),
            heard: HashMap::new(),
            parents: HashMap::new(),
        }
    }

    pub fn own(&self) -> Option<Voice> {
        self.own
    }

    /// Its person joins the call here, or leaves it while this device
    /// carries on.
    pub fn set_own(&mut self, own: Option<Voice>) {
        self.own = own;
    }

    /// Adds a link; whether it was new.
    pub fn add_link(&mut self, id: LinkId, person: bool, now: Instant) -> bool {
        if let Some(l) = self.links.get_mut(&id) {
            l.person = person;
            return false;
        }
        self.links.insert(
            id,
            Link {
                lazy: HashSet::new(),
                asked: HashMap::new(),
                heard: now,
                person,
            },
        );
        true
    }

    pub fn remove_link(&mut self, id: &LinkId) {
        self.links.remove(id);
        for p in self.parents.values_mut() {
            p.remove(id);
        }
    }

    pub fn has_link(&self, id: &LinkId) -> bool {
        self.links.contains_key(id)
    }

    pub fn links(&self) -> usize {
        self.links.len()
    }

    /// Whether any link's device has its person on the call.
    pub fn any_person(&self) -> bool {
        self.links.values().any(|l| l.person)
    }

    /// Forgets a voice, whose device left the call.
    pub fn forget(&mut self, voice: &Voice) {
        self.heard.remove(voice);
        self.speaking.remove(voice);
    }

    /// Whether this frame has not been seen here: only such a frame is worth
    /// checking the signature of.
    pub fn is_new(&self, voice: &Voice, n: u32) -> bool {
        Some(*voice) != self.own
            && !self.seen.contains(&(*voice, n))
            && self
                .newest
                .get(voice)
                .is_none_or(|(newest, _)| n.saturating_add(STALE) >= *newest)
    }

    /// A frame came on link `from`. `genuine` says whether its signature
    /// holds, and matters only for one that is new.
    pub fn on_frame(
        &mut self,
        from: &LinkId,
        voice: Voice,
        n: u32,
        here: bool,
        genuine: bool,
        now: Instant,
    ) -> Got {
        let Some(link) = self.links.get_mut(from) else {
            return Got::default();
        };
        link.heard = now;
        let fresh = self.is_new(&voice, n);
        if fresh && !genuine {
            return Got::default();
        }
        if Some(voice) == self.own {
            // Its own voice, come round: that link need not send it.
            return Got {
                prune: !here && self.may_ask(from, voice, now),
                ..Got::default()
            };
        }
        if fresh {
            self.seen.insert((voice, n));
            self.order.push_back((voice, n));
            if self.order.len() > SEEN {
                if let Some(old) = self.order.pop_front() {
                    self.seen.remove(&old);
                }
            }
            let e = self.newest.entry(voice).or_insert((n, now));
            if n >= e.0 {
                *e = (n, now);
            }
            self.heard.insert(voice, now);
        }
        // Presence goes everywhere, and settles nothing.
        if here {
            if !fresh {
                return Got::default();
            }
            let forward = self.links.keys().filter(|l| *l != from).copied().collect();
            return Got {
                fresh,
                forward,
                prune: false,
            };
        }
        let prune = self.choose(from, voice, fresh, now);
        if !fresh || !self.passes(voice, now) {
            return Got {
                fresh,
                forward: Vec::new(),
                prune,
            };
        }
        let forward = self
            .links
            .iter()
            .filter(|(id, l)| *id != from && !l.lazy.contains(&voice))
            .map(|(id, _)| *id)
            .collect();
        Got {
            fresh,
            forward,
            prune,
        }
    }

    /// Keeps the links a voice comes on first, two of them, and says whether
    /// the one it came on is to stop sending it.
    fn choose(&mut self, from: &LinkId, voice: Voice, fresh: bool, now: Instant) -> bool {
        let first = fresh.then_some(now);
        let parents = self.parents.entry(voice).or_default();
        if let Some(p) = parents.get_mut(from) {
            if first.is_some() {
                p.first = first;
            }
            // More than enough, after a graft: the one that has been first
            // longest ago goes.
            if parents.len() > KEEP && !fresh {
                let slowest = parents
                    .iter()
                    .min_by_key(|(_, p)| p.first)
                    .map(|(id, _)| *id);
                if slowest == Some(*from) {
                    parents.remove(from);
                    return self.may_ask(from, voice, now);
                }
            }
            return false;
        }
        if parents.len() < KEEP {
            parents.insert(*from, Parent { first });
            return false;
        }
        if fresh {
            // Quicker than one it is taken from: that one goes, and is told
            // so when its copy comes.
            if let Some(slowest) = parents
                .iter()
                .min_by_key(|(_, p)| p.first)
                .map(|(id, _)| *id)
            {
                parents.remove(&slowest);
            }
            parents.insert(*from, Parent { first });
            return false;
        }
        self.may_ask(from, voice, now)
    }

    /// Whether this device may ask `link` about `voice` now.
    fn may_ask(&mut self, link: &LinkId, voice: Voice, now: Instant) -> bool {
        let Some(l) = self.links.get_mut(link) else {
            return false;
        };
        let lately = l
            .asked
            .get(&voice)
            .is_some_and(|t| now.duration_since(*t) < ASK_EVERY);
        if lately {
            return false;
        }
        l.asked.insert(voice, now);
        true
    }

    /// Whether a voice is one of the few passed on now.
    fn passes(&mut self, voice: Voice, now: Instant) -> bool {
        self.speaking
            .retain(|_, (_, last)| now.duration_since(*last) < VOICE_FOR);
        let began = self.speaking.get(&voice).map_or(now, |(began, _)| *began);
        self.speaking.insert(voice, (began, now));
        let earlier = self.speaking.values().filter(|(b, _)| *b < began).count();
        earlier < MOST_VOICES
    }

    /// A word came on link `from`. What to say back: grafts, for voices it
    /// has further than this device does.
    pub fn on_word(&mut self, from: &LinkId, word: Word, now: Instant) -> Vec<Voice> {
        let Some(link) = self.links.get_mut(from) else {
            return Vec::new();
        };
        link.heard = now;
        match word {
            Word::Prune(v) => {
                link.lazy.insert(v);
                Vec::new()
            }
            Word::Graft(v) => {
                link.lazy.remove(&v);
                Vec::new()
            }
            Word::Have(list) => {
                let mut graft = Vec::new();
                for (v, n) in list {
                    if Some(v) == self.own {
                        continue;
                    }
                    let behind = self
                        .newest
                        .get(&v)
                        .is_none_or(|(mine, _)| n > mine.saturating_add(LAG));
                    if behind && self.may_ask(from, v, now) {
                        self.parents
                            .entry(v)
                            .or_default()
                            .insert(*from, Parent { first: None });
                        graft.push(v);
                    }
                }
                graft
            }
        }
    }

    /// The links this device's own frames go to: all but those that asked
    /// not to have its voice, and all of them for presence.
    pub fn own_targets(&self, here: bool) -> Vec<LinkId> {
        let own = self.own;
        self.links
            .iter()
            .filter(|(_, l)| here || own.is_none_or(|v| !l.lazy.contains(&v)))
            .map(|(id, _)| *id)
            .collect()
    }

    /// The haves to send: to each link, the voices heard lately that it
    /// asked not to be sent. With `keepalive`, an empty one to every link
    /// with nothing else, so that a link with nothing to carry is not taken
    /// for gone.
    pub fn haves(&self, keepalive: bool, now: Instant) -> Vec<(LinkId, Word)> {
        let lately: Vec<(Voice, u32)> = self
            .newest
            .iter()
            .filter(|(_, (_, t))| now.duration_since(*t) < HAVE_FOR)
            .map(|(v, (n, _))| (*v, *n))
            .collect();
        let mut out = Vec::new();
        for (id, l) in &self.links {
            let list: Vec<(Voice, u32)> = lately
                .iter()
                .filter(|(v, _)| l.lazy.contains(v))
                .copied()
                .collect();
            if !list.is_empty() || keepalive {
                out.push((*id, Word::Have(list)));
            }
        }
        out
    }

    /// The links nothing has come on for too long.
    pub fn silent(&self, now: Instant) -> Vec<LinkId> {
        self.links
            .iter()
            .filter(|(_, l)| now.duration_since(l.heard) >= SILENT_FOR)
            .map(|(id, _)| *id)
            .collect()
    }

    /// How many are on the call, as far as this device can tell: every
    /// voice heard lately, and its own person if on it.
    pub fn on_it(&self, now: Instant) -> usize {
        let others = self
            .heard
            .iter()
            .filter(|(v, t)| Some(**v) != self.own && now.duration_since(**t) < ON_IT_FOR)
            .count();
        others + usize::from(self.own.is_some())
    }

    /// When anything new last came, of any voice.
    pub fn last_fresh(&self) -> Option<Instant> {
        self.heard.values().max().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(n: u8) -> LinkId {
        [n; 32]
    }

    fn tree(links: &[u8]) -> (Tree, Instant) {
        let now = Instant::now();
        let mut t = Tree::new(Some([0; 8]));
        for l in links {
            t.add_link(link(*l), true, now);
        }
        (t, now)
    }

    #[test]
    fn a_frame_coming_round_again_is_dropped() {
        let (mut t, now) = tree(&[1, 2, 3]);
        let v = [7; 8];
        let got = t.on_frame(&link(1), v, 5, false, true, now);
        assert!(got.fresh);
        let mut to = got.forward.clone();
        to.sort();
        assert_eq!(to, vec![link(2), link(3)]);
        let again = t.on_frame(&link(2), v, 5, false, true, now);
        assert!(!again.fresh && again.forward.is_empty(), "{again:?}");
        // Long behind the newest of its voice, it is old whatever it says.
        t.on_frame(&link(1), v, 5 + STALE + 2, false, true, now);
        assert!(!t.is_new(&v, 1));
    }

    #[test]
    fn a_frame_whose_signature_fails_goes_nowhere_and_is_not_remembered() {
        let (mut t, now) = tree(&[1, 2]);
        let v = [7; 8];
        let forged = t.on_frame(&link(1), v, 9, false, false, now);
        assert_eq!(forged, Got::default());
        // The real one, coming after, is still new.
        assert!(t.on_frame(&link(2), v, 9, false, true, now).fresh);
    }

    #[test]
    fn signatures_bind_the_voice_the_number_and_the_call() {
        let key = cardinal_crypto::SigningKey::generate();
        let v = voice_of(&key.public_key());
        let call = [4; 16];
        let b = frame(&key, &call, &v, 3, b"sound");
        let f = Frame::parse(&b).unwrap();
        assert!(signed_by(&f, &call, &key.public_key()));
        assert!(!signed_by(&f, &[5; 16], &key.public_key()));
        let mut moved = b.clone();
        moved[11] ^= 1;
        let f = Frame::parse(&moved).unwrap();
        assert!(!signed_by(&f, &call, &key.public_key()));
        let other = cardinal_crypto::SigningKey::generate();
        let f = Frame::parse(&b).unwrap();
        assert!(!signed_by(&f, &call, &other.public_key()));
    }

    /// With three links bringing the same voice, the third is told to stop
    /// once two bring it; the two kept are those that brought it first.
    #[test]
    fn a_third_link_bringing_a_voice_is_pruned() {
        let (mut t, now) = tree(&[1, 2, 3, 4]);
        let v = [7; 8];
        for n in 0..3u32 {
            assert!(!t.on_frame(&link(1), v, n, false, true, now).prune);
            assert!(!t.on_frame(&link(2), v, n, false, true, now).prune);
            let third = t.on_frame(&link(3), v, n, false, true, now);
            // Asked once, not with every frame.
            assert_eq!(third.prune, n == 0, "frame {n}");
        }
        // Told, link 3 sends it no more; this device does not send it there
        // either once 3 asks.
        t.on_word(&link(3), Word::Prune(v), now);
        let mut to = t.on_frame(&link(1), v, 10, false, true, now).forward;
        to.sort();
        assert_eq!(to, vec![link(2), link(4)]);
    }

    /// A link that brings a voice first takes the place of the slower of
    /// the two, which is pruned when its copy comes.
    #[test]
    fn a_quicker_link_takes_the_place_of_a_slower_one() {
        let (mut t, now) = tree(&[1, 2, 3]);
        let v = [7; 8];
        t.on_frame(&link(1), v, 0, false, true, now);
        t.on_frame(&link(2), v, 0, false, true, now);
        let later = now + Duration::from_millis(20);
        // Link 3 now brings frame 1 first, then 1 brings it, then 2.
        assert!(t.on_frame(&link(3), v, 1, false, true, later).fresh);
        assert!(!t.on_frame(&link(1), v, 1, false, true, later).prune);
        assert!(t.on_frame(&link(2), v, 1, false, true, later).prune);
    }

    /// Losing a link loses nothing, and a have from a link that was pruned
    /// shows frames are missing: the voice is asked for again there.
    #[test]
    fn a_have_ahead_of_this_device_grafts_the_link() {
        let (mut t, now) = tree(&[1, 2, 3]);
        let v = [7; 8];
        for n in 0..5 {
            t.on_frame(&link(1), v, n, false, true, now);
            t.on_frame(&link(2), v, n, false, true, now);
            t.on_frame(&link(3), v, n, false, true, now);
        }
        // Close behind: nothing to do.
        assert!(t
            .on_word(&link(3), Word::Have(vec![(v, 4 + LAG)]), now)
            .is_empty());
        // Both parents go quiet, and link 3 is well ahead. (It was told to
        // stop at first, and is not asked again within a second of that.)
        let later = now + Duration::from_millis(1200);
        assert_eq!(
            t.on_word(&link(3), Word::Have(vec![(v, 30)]), later),
            vec![v]
        );
        // Asked once a second at most.
        assert!(t
            .on_word(&link(3), Word::Have(vec![(v, 31)]), later)
            .is_empty());
        // A voice never heard here is asked for too.
        let w = [8; 8];
        assert_eq!(
            t.on_word(&link(1), Word::Have(vec![(w, 3)]), later),
            vec![w]
        );
    }

    #[test]
    fn this_devices_own_voice_coming_back_is_pruned() {
        let (mut t, now) = tree(&[1]);
        let got = t.on_frame(&link(1), [0; 8], 3, false, true, now);
        assert!(got.prune && !got.fresh);
        t.on_word(&link(1), Word::Prune([0; 8]), now);
        assert!(t.own_targets(false).is_empty());
        assert_eq!(t.own_targets(true), vec![link(1)]);
    }

    #[test]
    fn presence_goes_everywhere_and_counts_who_is_on() {
        let (mut t, now) = tree(&[1, 2, 3]);
        t.on_word(&link(2), Word::Prune([7; 8]), now);
        let got = t.on_frame(&link(1), [7; 8], 1, true, true, now);
        let mut to = got.forward;
        to.sort();
        assert_eq!(to, vec![link(2), link(3)]);
        t.on_frame(&link(2), [8; 8], 1, true, true, now);
        assert_eq!(t.on_it(now), 3);
        t.forget(&[8; 8]);
        assert_eq!(t.on_it(now), 2);
        assert_eq!(t.on_it(now + ON_IT_FOR), 1);
    }

    #[test]
    fn haves_tell_only_of_voices_a_link_asked_not_to_have() {
        let (mut t, now) = tree(&[1, 2]);
        let v = [7; 8];
        t.on_frame(&link(1), v, 4, false, true, now);
        t.on_word(&link(2), Word::Prune(v), now);
        let h = t.haves(false, now);
        assert_eq!(h, vec![(link(2), Word::Have(vec![(v, 4)]))]);
        let mut all = t.haves(true, now);
        all.sort_by_key(|(l, _)| *l);
        assert_eq!(all[0], (link(1), Word::Have(vec![])));
        assert!(t.haves(false, now + HAVE_FOR).is_empty());
    }

    #[test]
    fn a_link_with_nothing_on_it_is_gone() {
        let (mut t, now) = tree(&[1, 2]);
        let later = now + SILENT_FOR;
        t.on_word(&link(1), Word::Have(vec![]), later);
        assert_eq!(t.silent(later), vec![link(2)]);
        t.remove_link(&link(2));
        assert_eq!(t.links(), 1);
    }

    #[test]
    fn words_read_back_whole() {
        for w in [
            Word::Prune([1; 8]),
            Word::Graft([2; 8]),
            Word::Have(vec![]),
            Word::Have(vec![([3; 8], 9), ([4; 8], 70000)]),
        ] {
            assert_eq!(Word::decode(&w.encode()), Some(w));
        }
        assert_eq!(Word::decode(&[1, 2, 3]), None);
        assert_eq!(Word::decode(&[]), None);
    }

    /// However many speak at once, only the first few voices go on, until
    /// one of them stops.
    #[test]
    fn only_a_few_voices_go_on_at_once() {
        let (mut t, now) = tree(&[1, 2]);
        let voices: Vec<Voice> = (1..=8u8).map(|v| [v; 8]).collect();
        for (i, v) in voices.iter().enumerate() {
            t.on_frame(
                &link(1),
                *v,
                0,
                false,
                true,
                now + Duration::from_millis(i as u64),
            );
        }
        let at = now + Duration::from_millis(20);
        let going: Vec<bool> = voices
            .iter()
            .map(|v| {
                !t.on_frame(&link(1), *v, 1, false, true, at)
                    .forward
                    .is_empty()
            })
            .collect();
        assert_eq!(
            going.iter().filter(|g| **g).count(),
            MOST_VOICES,
            "{going:?}"
        );
        assert!(going[0] && !going[7], "{going:?}");
        // The first falls silent, and the next who speaks goes on.
        let later = at + VOICE_FOR + Duration::from_millis(50);
        for v in &voices[1..] {
            t.on_frame(&link(1), *v, 2, false, true, later);
        }
        let seventh = t.on_frame(&link(1), voices[6], 3, false, true, later);
        assert!(
            !seventh.forward.is_empty(),
            "a seventh voice is held back still"
        );
    }
}
