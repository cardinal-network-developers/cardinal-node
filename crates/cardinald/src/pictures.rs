//! Video in a group call (`basics/video.md#groups`): the deciding part,
//! which sends nothing itself. Each sender encodes two sizes; each receiver
//! asks each sender for a level (0 none, 1 small, 2 large), a ceiling, not a
//! demand; and a device passes a picture on only to the links that asked
//! for it, never decoding it, as it passes on voices.
//!
//! A device takes a sender's pictures from one link, and asks there every
//! level it needs: its own window's and each its links ask of it. To each
//! link that asked it passes, for each level asked, the largest size it has
//! up to that level, so nobody is sent more than they asked, and a link that
//! asked for nothing is sent nothing.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::mesh::{LinkId, Seen, Voice};

/// A picture's size: small (about 320 pixels wide) or large (about 960).
pub type Size = u8;
pub const SMALL: Size = 1;
pub const LARGE: Size = 2;

/// What a picture's signature says it is.
pub const PICTURE: &[u8] = b"cardinal call picture v1";
/// The first byte of a picture after its frame's signature: a viewport's is 1.
pub const PICTURE_KIND: u8 = 2;

/// A device has a size of a sender when a picture of it came, or for its
/// own was sent, this lately.
pub const HAS_FOR: Duration = Duration::from_secs(1);
/// The link that first brought a sender's newest frame is where its
/// pictures are asked for, if that frame came this lately.
pub const FIRST_FOR: Duration = Duration::from_secs(12);
/// A link's levels not said again for this long are forgotten.
pub const LEVELS_FOR: Duration = Duration::from_secs(6);
/// The most pictures a device takes from one link in a second.
pub const MOST_PICTURES: u32 = 1000;
/// A key picture of one sender's size is asked for at most this often.
const KEY_EVERY: Duration = Duration::from_secs(1);
/// The most voices one `levels` names.
pub const MOST_ASKED: usize = 64;

/// The levels asked of one sender, a bit for each: 1 for small, 2 for large.
type Levels = u8;

fn bit(level: u8) -> Levels {
    match level {
        0 => 0,
        1 => 1,
        // A level above large, from a later version, counts as large.
        _ => 2,
    }
}

/// Words between neighbours about pictures, on the call's asks channel.
#[derive(Debug, PartialEq, Eq)]
pub enum Ask {
    /// `1 || (voice (8) || level (1))*`: everything asked of the link.
    Levels(Vec<(Voice, u8)>),
    /// `2 || voice (8) || size (1)`: a key picture of that size is wanted.
    Key(Voice, Size),
}

impl Ask {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Ask::Levels(list) => {
                let mut out = vec![1u8];
                for (v, l) in list.iter().take(MOST_ASKED) {
                    out.extend_from_slice(v);
                    out.push(*l);
                }
                out
            }
            Ask::Key(v, s) => [&[2u8][..], v, &[*s]].concat(),
        }
    }

    pub fn decode(b: &[u8]) -> Option<Ask> {
        let (kind, body) = b.split_first()?;
        match kind {
            1 if body.len() % 9 == 0 && body.len() <= MOST_ASKED * 9 => Some(Ask::Levels(
                body.chunks_exact(9)
                    .map(|c| (c[..8].try_into().expect("8 bytes"), c[8]))
                    .collect(),
            )),
            2 if body.len() == 9 && matches!(body[8], SMALL | LARGE) => {
                Some(Ask::Key(body[..8].try_into().ok()?, body[8]))
            }
            _ => None,
        }
    }

    /// The voices it speaks of.
    pub fn voices(&self) -> Vec<Voice> {
        match self {
            Ask::Levels(list) => list.iter().map(|(v, _)| *v).collect(),
            Ask::Key(v, _) => vec![*v],
        }
    }
}

/// What a window is told.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Want {
    /// The sizes asked of it.
    Sizes { small: bool, large: bool },
    /// Its next picture of this size is to be a key picture.
    Key(Size),
}

/// Where a key picture's ask goes.
#[derive(Debug, PartialEq, Eq)]
pub enum KeyTo {
    Window,
    Link(LinkId),
}

/// What came of a picture.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Passed {
    /// The links to pass it to.
    pub forward: Vec<LinkId>,
    /// Whether this device's window is given it.
    pub show: bool,
}

struct Asked {
    levels: HashMap<Voice, Levels>,
    at: Instant,
}

/// One group call's pictures, as one device sees them.
#[derive(Default)]
pub struct Pictures {
    /// What each link asks of this device.
    links: HashMap<LinkId, Asked>,
    /// Pictures each link sent in the second that began then.
    budget: HashMap<LinkId, (u32, Instant)>,
    /// The level this device's window asks of each sender.
    window: HashMap<Voice, u8>,
    /// When each sender's size was last had here.
    has: HashMap<(Voice, Size), Instant>,
    seen: HashMap<(Voice, Size), Seen>,
    /// The link that first brought each voice's newest frame, and when.
    first: HashMap<Voice, (LinkId, Instant)>,
    /// What this device last asked of each link.
    told: HashMap<LinkId, Vec<(Voice, u8)>>,
    /// When a key picture of each sender's size was last asked for.
    keys: HashMap<(Voice, Size), Instant>,
}

impl Pictures {
    /// A frame of `voice` came first on `link`: where its pictures come from
    /// best, unless it is linked to this device itself.
    pub fn came(&mut self, voice: Voice, link: LinkId, now: Instant) {
        self.first.insert(voice, (link, now));
    }

    /// A link said everything it asks of this device.
    pub fn on_levels(&mut self, link: LinkId, list: &[(Voice, u8)], now: Instant) {
        let mut levels: HashMap<Voice, Levels> = HashMap::new();
        for (v, l) in list {
            *levels.entry(*v).or_default() |= bit(*l);
        }
        levels.retain(|_, l| *l != 0);
        if levels.is_empty() {
            self.links.remove(&link);
        } else {
            self.links.insert(link, Asked { levels, at: now });
        }
    }

    /// This device's window asks a sender for a level; 0 stops it.
    pub fn set_window(&mut self, voice: Voice, level: u8) {
        if level == 0 {
            self.window.remove(&voice);
        } else {
            self.window.insert(voice, level.min(LARGE));
        }
    }

    /// The window went: it asks for nothing.
    pub fn clear_window(&mut self) {
        self.window.clear();
    }

    pub fn remove_link(&mut self, link: &LinkId) {
        self.links.remove(link);
        self.budget.remove(link);
        self.told.remove(link);
        self.first.retain(|_, (l, _)| l != link);
    }

    /// Forgets the levels of links that have not said them again.
    pub fn expire(&mut self, now: Instant) {
        self.links
            .retain(|_, a| now.duration_since(a.at) < LEVELS_FOR);
    }

    /// Whether `link` may send another picture now; counts it.
    pub fn admit(&mut self, link: &LinkId, now: Instant) -> bool {
        let (count, since) = self.budget.entry(*link).or_insert((0, now));
        if now.duration_since(*since) >= Duration::from_secs(1) {
            *since = now;
            *count = 0;
        }
        *count += 1;
        *count <= MOST_PICTURES
    }

    /// Whether this picture has not been seen here.
    pub fn is_new(&self, voice: &Voice, size: Size, n: u32) -> bool {
        self.seen.get(&(*voice, size)).is_none_or(|s| s.fresh(n))
    }

    /// The largest size of `voice` had here up to `level`.
    fn best(&self, voice: &Voice, level: u8, now: Instant) -> Option<Size> {
        (SMALL..=level.min(LARGE)).rev().find(|s| {
            self.has
                .get(&(*voice, *s))
                .is_some_and(|t| now.duration_since(*t) < HAS_FOR)
        })
    }

    /// Whether levels `asked` of `voice` select a picture of `size`.
    fn selects(&self, asked: Levels, voice: &Voice, size: Size, now: Instant) -> bool {
        [SMALL, LARGE]
            .into_iter()
            .filter(|l| asked & bit(*l) != 0)
            .any(|l| self.best(voice, l, now) == Some(size))
    }

    fn targets(
        &self,
        from: Option<&LinkId>,
        voice: &Voice,
        size: Size,
        now: Instant,
    ) -> Vec<LinkId> {
        let mut out: Vec<LinkId> = self
            .links
            .iter()
            .filter(|(l, _)| Some(*l) != from)
            .filter(|(_, a)| {
                a.levels
                    .get(voice)
                    .is_some_and(|asked| self.selects(*asked, voice, size, now))
            })
            .map(|(l, _)| *l)
            .collect();
        out.sort();
        out
    }

    /// A picture of another's came on `from`, its signature checked: where
    /// it goes, or `None` if it was seen already.
    pub fn on_picture(
        &mut self,
        from: LinkId,
        voice: Voice,
        size: Size,
        n: u32,
        now: Instant,
    ) -> Option<Passed> {
        match self.seen.get_mut(&(voice, size)) {
            Some(s) if !s.fresh(n) => return None,
            Some(s) => s.mark(n, now),
            None => {
                self.seen.insert((voice, size), Seen::new(n, now));
            }
        }
        self.has.insert((voice, size), now);
        self.came(voice, from, now);
        let show = self
            .window
            .get(&voice)
            .is_some_and(|l| self.selects(bit(*l), &voice, size, now));
        Some(Passed {
            forward: self.targets(Some(&from), &voice, size, now),
            show,
        })
    }

    /// This device's window sent a picture of `size`: the links it goes to.
    pub fn sent_own(&mut self, own: Voice, size: Size, now: Instant) -> Vec<LinkId> {
        self.has.insert((own, size), now);
        self.targets(None, &own, size, now)
    }

    /// The sizes asked of this device's own pictures.
    pub fn wanted(&self, own: Option<Voice>) -> Want {
        let asked = own.map_or(0, |own| {
            self.links
                .values()
                .filter_map(|a| a.levels.get(&own))
                .fold(0, |all, l| all | l)
        });
        Want::Sizes {
            small: asked & bit(SMALL) != 0,
            large: asked & bit(LARGE) != 0,
        }
    }

    /// The link a sender's pictures are asked of: its own device's, if
    /// linked with this one, or else the one that first brought its newest
    /// frame lately, unless that link asks this device for it.
    fn source(
        &self,
        voice: &Voice,
        direct: &HashMap<Voice, LinkId>,
        now: Instant,
    ) -> Option<LinkId> {
        if let Some(l) = direct.get(voice) {
            return Some(*l);
        }
        let (l, at) = self.first.get(voice)?;
        let asks_us = self
            .links
            .get(l)
            .is_some_and(|a| a.levels.contains_key(voice));
        (now.duration_since(*at) < FIRST_FOR && !asks_us).then_some(*l)
    }

    /// What this device asks of each link now: for each sender but itself,
    /// every level its window and its links ask of it.
    fn upstream(
        &self,
        own: Option<Voice>,
        direct: &HashMap<Voice, LinkId>,
        now: Instant,
    ) -> HashMap<LinkId, Vec<(Voice, u8)>> {
        let mut need: HashMap<Voice, Levels> = HashMap::new();
        for (v, l) in &self.window {
            *need.entry(*v).or_default() |= bit(*l);
        }
        for a in self.links.values() {
            for (v, l) in &a.levels {
                *need.entry(*v).or_default() |= *l;
            }
        }
        let mut out: HashMap<LinkId, Vec<(Voice, u8)>> = HashMap::new();
        for (v, levels) in need {
            if Some(v) == own || levels == 0 {
                continue;
            }
            let Some(l) = self.source(&v, direct, now) else {
                continue;
            };
            let list = out.entry(l).or_default();
            for level in [SMALL, LARGE] {
                if levels & bit(level) != 0 {
                    list.push((v, level));
                }
            }
        }
        for list in out.values_mut() {
            list.sort();
            list.truncate(MOST_ASKED);
        }
        out
    }

    /// The `levels` to say: to each link, what this device asks of it, if
    /// that changed or with `again`; an empty one to a link it asks nothing
    /// of any more. `direct` is the link of each sender linked with this
    /// device.
    pub fn to_say(
        &mut self,
        own: Option<Voice>,
        direct: &HashMap<Voice, LinkId>,
        again: bool,
        now: Instant,
    ) -> Vec<(LinkId, Ask)> {
        self.expire(now);
        let up = self.upstream(own, direct, now);
        let mut out = Vec::new();
        for (l, list) in &up {
            if again || self.told.get(l) != Some(list) {
                out.push((*l, Ask::Levels(list.clone())));
            }
        }
        for l in self.told.keys() {
            if !up.contains_key(l) {
                out.push((*l, Ask::Levels(Vec::new())));
            }
        }
        self.told = up;
        out.sort_by_key(|(l, _)| *l);
        out
    }

    /// A key picture of `voice`'s `size` is asked for, by link `from` or by
    /// this device's window (`None`): where the ask goes, if anywhere. A
    /// link's is heeded only if it asks this device for that sender.
    pub fn on_key(
        &mut self,
        from: Option<&LinkId>,
        voice: Voice,
        size: Size,
        own: Option<Voice>,
        direct: &HashMap<Voice, LinkId>,
        now: Instant,
    ) -> Option<KeyTo> {
        if let Some(from) = from {
            let asks = self
                .links
                .get(from)
                .is_some_and(|a| a.levels.contains_key(&voice));
            if !asks {
                return None;
            }
        }
        let to = if Some(voice) == own {
            KeyTo::Window
        } else {
            KeyTo::Link(self.source(&voice, direct, now)?)
        };
        let lately = self
            .keys
            .get(&(voice, size))
            .is_some_and(|t| now.duration_since(*t) < KEY_EVERY);
        if lately {
            return None;
        }
        self.keys.insert((voice, size), now);
        Some(to)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(n: u8) -> LinkId {
        [n; 32]
    }

    const BEN: Voice = [2; 8];

    /// Ben's pictures come on link 2, his own device's; links 3, 4 and 5
    /// ask for large, small and nothing.
    fn relay() -> (Pictures, HashMap<Voice, LinkId>, Instant) {
        let now = Instant::now();
        let mut p = Pictures::default();
        p.on_levels(link(3), &[(BEN, 2)], now);
        p.on_levels(link(4), &[(BEN, 1)], now);
        p.on_levels(link(5), &[(BEN, 0)], now);
        (p, HashMap::from([(BEN, link(2))]), now)
    }

    #[test]
    fn asks_read_back_whole() {
        for a in [
            Ask::Levels(vec![]),
            Ask::Levels(vec![([1; 8], 2), ([1; 8], 1), ([3; 8], 0)]),
            Ask::Key([4; 8], LARGE),
        ] {
            assert_eq!(Ask::decode(&a.encode()), Some(a));
        }
        assert_eq!(
            Ask::decode(&[2, 1, 1, 1, 1, 1, 1, 1, 1, 3]),
            None,
            "no size 3"
        );
        assert_eq!(Ask::decode(&[1, 1, 2]), None);
        assert_eq!(Ask::decode(&[]), None);
        let many = Ask::Levels(vec![([1; 8], 1); 100]).encode();
        assert_eq!(many.len(), 1 + MOST_ASKED * 9);
    }

    /// A relay asks the sender for every level its links want, and passes
    /// each the size it asked for: large to one, small to the other, and
    /// nothing to the one that asked for none.
    #[test]
    fn a_relay_asks_for_both_and_gives_each_what_it_asked() {
        let (mut p, direct, now) = relay();
        assert_eq!(
            p.to_say(None, &direct, false, now),
            vec![(link(2), Ask::Levels(vec![(BEN, 1), (BEN, 2)]))]
        );
        assert!(p.to_say(None, &direct, false, now).is_empty(), "said once");
        assert_eq!(p.to_say(None, &direct, true, now).len(), 1, "and again");
        let large = p.on_picture(link(2), BEN, LARGE, 7, now).unwrap();
        assert_eq!(large.forward, vec![link(3)]);
        let small = p.on_picture(link(2), BEN, SMALL, 7, now).unwrap();
        assert_eq!(small.forward, vec![link(4)]);
        assert!(!large.show && !small.show, "no window asked");
        assert_eq!(p.on_picture(link(2), BEN, SMALL, 7, now), None, "seen");
    }

    /// Asked for large, a device gives small while small is all it has; asked
    /// for small, it never gives large.
    #[test]
    fn a_level_is_a_ceiling_not_a_demand() {
        let (mut p, _, now) = relay();
        let small = p.on_picture(link(2), BEN, SMALL, 1, now).unwrap();
        assert_eq!(small.forward, vec![link(3), link(4)]);
        let large = p.on_picture(link(2), BEN, LARGE, 1, now).unwrap();
        assert_eq!(large.forward, vec![link(3)]);
        // Large is had now: link 3 has it in place of small.
        let small = p.on_picture(link(2), BEN, SMALL, 2, now).unwrap();
        assert_eq!(small.forward, vec![link(4)]);
        // Large stops coming: after a second, link 3 has small again.
        let later = now + HAS_FOR;
        let small = p.on_picture(link(2), BEN, SMALL, 3, later).unwrap();
        assert_eq!(small.forward, vec![link(3), link(4)]);
    }

    #[test]
    fn a_window_is_given_only_the_size_it_asked_for() {
        let (mut p, direct, now) = relay();
        p.set_window(BEN, 1);
        p.on_picture(link(2), BEN, SMALL, 1, now);
        assert!(!p.on_picture(link(2), BEN, LARGE, 1, now).unwrap().show);
        assert!(p.on_picture(link(2), BEN, SMALL, 2, now).unwrap().show);
        p.to_say(None, &direct, false, now);
        p.set_window(BEN, 2);
        assert!(p.on_picture(link(2), BEN, LARGE, 2, now).unwrap().show);
        assert!(!p.on_picture(link(2), BEN, SMALL, 3, now).unwrap().show);
        p.clear_window();
        p.on_levels(link(3), &[], now);
        p.on_levels(link(4), &[], now);
        assert_eq!(
            p.to_say(None, &direct, false, now),
            vec![(link(2), Ask::Levels(vec![]))],
            "an empty one when it asks nothing any more"
        );
        assert!(p.to_say(None, &direct, true, now).is_empty());
    }

    /// The sender is told the sizes asked of it, and sends each picture only
    /// to the links whose levels select it.
    #[test]
    fn a_sender_sends_each_size_only_where_asked() {
        let (mut p, _, now) = relay();
        assert_eq!(
            p.wanted(Some(BEN)),
            Want::Sizes {
                small: true,
                large: true
            }
        );
        assert_eq!(
            p.wanted(Some([9; 8])),
            Want::Sizes {
                small: false,
                large: false
            }
        );
        assert_eq!(p.sent_own(BEN, SMALL, now), vec![link(3), link(4)]);
        assert_eq!(p.sent_own(BEN, LARGE, now), vec![link(3)]);
        assert_eq!(p.sent_own(BEN, SMALL, now), vec![link(4)]);
    }

    /// With no link to the sender, its pictures are asked of the link that
    /// brought its frames first, unless that link is one asking for them.
    #[test]
    fn a_sender_not_linked_is_asked_for_where_its_frames_come_from() {
        let now = Instant::now();
        let mut p = Pictures::default();
        p.set_window(BEN, 2);
        let none = HashMap::new();
        assert!(
            p.to_say(None, &none, false, now).is_empty(),
            "not heard yet"
        );
        p.came(BEN, link(7), now);
        assert_eq!(
            p.to_say(None, &none, false, now),
            vec![(link(7), Ask::Levels(vec![(BEN, 2)]))]
        );
        p.on_levels(link(7), &[(BEN, 1)], now);
        assert_eq!(
            p.to_say(None, &none, false, now),
            vec![(link(7), Ask::Levels(vec![]))],
            "never asked of a link that asks for it"
        );
        p.remove_link(&link(7));
        p.came(BEN, link(8), now);
        let said = p.to_say(None, &none, false, now);
        assert_eq!(said, vec![(link(8), Ask::Levels(vec![(BEN, 2)]))]);
        let later = now + FIRST_FOR;
        assert_eq!(
            p.to_say(None, &none, false, later),
            vec![(link(8), Ask::Levels(vec![]))],
            "heard of too long ago"
        );
    }

    #[test]
    fn levels_not_said_again_are_forgotten() {
        let (mut p, direct, now) = relay();
        p.to_say(None, &direct, false, now);
        let later = now + LEVELS_FOR;
        assert_eq!(
            p.to_say(None, &direct, false, later),
            vec![(link(2), Ask::Levels(vec![]))]
        );
        p.has.insert((BEN, SMALL), later);
        assert!(p.sent_own(BEN, SMALL, later).is_empty());
    }

    #[test]
    fn a_link_may_send_only_so_many_pictures_a_second() {
        let now = Instant::now();
        let mut p = Pictures::default();
        let sent = (0..MOST_PICTURES + 50)
            .filter(|_| p.admit(&link(1), now))
            .count();
        assert_eq!(sent as u32, MOST_PICTURES);
        assert!(p.admit(&link(1), now + Duration::from_secs(1)));
    }

    /// A key picture is asked for along the way the pictures come, by links
    /// that asked for them only, at most once a second.
    #[test]
    fn a_key_picture_is_asked_of_the_sender() {
        let (mut p, direct, now) = relay();
        let ask = |p: &mut Pictures, from: Option<u8>, own, at| {
            p.on_key(from.map(link).as_ref(), BEN, LARGE, own, &direct, at)
        };
        assert_eq!(ask(&mut p, Some(5), None, now), None, "asked for none");
        assert_eq!(ask(&mut p, Some(3), None, now), Some(KeyTo::Link(link(2))));
        assert_eq!(ask(&mut p, Some(4), None, now), None, "once a second");
        let later = now + KEY_EVERY;
        assert_eq!(ask(&mut p, Some(4), Some(BEN), later), Some(KeyTo::Window));
        assert_eq!(
            ask(&mut p, None, None, later + KEY_EVERY),
            Some(KeyTo::Link(link(2)))
        );
    }
}
