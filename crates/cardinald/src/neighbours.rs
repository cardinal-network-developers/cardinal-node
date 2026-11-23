//! Neighbours (`sync.md#neighbours`, D86): the trusted contacts' devices
//! this device keeps live sessions with, so that news in a group reaches
//! every member's devices in a few hops without anyone looking for anyone.
//!
//! In each group it is in (a space with three or more members), a device
//! keeps sessions with about six devices of trusted contacts who are
//! members, three if it does not help others, chosen at random and replaced
//! from time to time. One session serves every space both devices hold, so
//! a device already in touch counts for each of them. Whatever its groups,
//! it keeps at least eight (three if it does not help) with trusted
//! contacts' devices as lifelines, mixing those of the contacts last talked
//! to with random ones; and at most 32 in all (eight if it does not help).
//! A two-person space adds nothing beyond the lifelines: its two people
//! reach each other by their known paths.
//!
//! A device that does not help sends no keepalives of its own: its
//! anchors keep its sessions alive, and it only answers. Only when none of
//! its sessions is kept alive by an anchor does it ping its neighbours, and
//! then about every two minutes. Nor does it dial its neighbours on a
//! timer: only when it wakes, when its network changes, or when its person
//! turns to someone; between, its anchors and the sessions others open to
//! it are its neighbours. In touch with nobody, it dials them a few times
//! an hour at most (`redial.rs`).
//!
//! A neighbour not reached is let go and rests, ten minutes at first and
//! twice as long each time it is not reached again, up to four hours, and
//! is not chosen again while it rests.

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use cardinal_crypto::random_bytes;
use cardinal_identity::KeyId;

use crate::daemon::Daemon;

/// Neighbours per group, for a device that helps others.
pub const PER_GROUP: usize = 6;
/// For one that does not.
pub const PER_GROUP_SPARING: usize = 3;
/// Lifelines, at least, for a device that helps others.
pub const LEAST: usize = 8;
/// For one that does not.
pub const LEAST_SPARING: usize = 3;
/// Neighbours in all, at most, for a device that helps others.
pub const MOST: usize = 32;
/// For one that does not.
pub const MOST_SPARING: usize = 8;
/// How long a neighbour may go without a session before another is tried
/// in its place.
const REACH_WITHIN: Duration = Duration::from_secs(60);
/// A neighbour is replaced after between this long and twice it.
const KEEP_FOR: Duration = Duration::from_secs(20 * 60);
/// How long one replaced, or not reached, rests before it may be chosen
/// again: one not reached rests twice as long each time, up to
/// `REST_MOST`.
const REST_FOR: Duration = Duration::from_secs(10 * 60);
/// The longest rest.
const REST_MOST: Duration = Duration::from_secs(4 * 60 * 60);
/// How often a device that does not help pings a neighbour, and only when
/// no anchor keeps any of its sessions alive: each ping wakes a phone's
/// radio, and anchors carry reliability.
pub const SPARING_KEEPALIVE: Duration = Duration::from_secs(120);
/// A session the other side pinged twice within this is kept alive by an
/// anchor, which pings every 20 s or so; a phone's two minutes never show.
pub const ANCHOR_PINGS_WITHIN: Duration = Duration::from_secs(60);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// How many neighbours a device keeps.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Bounds {
    pub per_group: usize,
    pub least: usize,
    pub most: usize,
}

impl Bounds {
    pub fn new(helps: bool) -> Bounds {
        if helps {
            Bounds {
                per_group: PER_GROUP,
                least: LEAST,
                most: MOST,
            }
        } else {
            Bounds {
                per_group: PER_GROUP_SPARING,
                least: LEAST_SPARING,
                most: MOST_SPARING,
            }
        }
    }
}

/// A trusted contact's device that could be a neighbour.
#[derive(Clone, Debug)]
pub struct Candidate {
    pub device: KeyId,
    /// A session with it is open: it serves every space at once.
    pub open: bool,
    /// Named as their host in a reach node.
    pub host: bool,
    /// When its person was last turned to here.
    pub used: Option<Instant>,
    /// Not reached lately, and its rest is over: chosen only when no other
    /// is left.
    pub rested: bool,
}

/// Chooses the neighbours: those `kept` that are still candidates, then,
/// in each group in turn, until each has `per_group` or all its members'
/// devices, then lifelines up to `least`, alternately the devices of the
/// contact last turned to and random ones; never more than `most`.
/// `groups` lists each group's candidates by device. Among others, one
/// with an open session goes first, then one named as a host, then by
/// `seed`; one rested goes last.
pub fn choose(
    all: &[Candidate],
    groups: &[Vec<KeyId>],
    kept: &[KeyId],
    b: Bounds,
    seed: [u8; 32],
) -> Vec<KeyId> {
    let by: HashMap<KeyId, &Candidate> = all.iter().map(|c| (c.device, c)).collect();
    let mut chosen: Vec<KeyId> = Vec::new();
    for k in kept {
        if chosen.len() < b.most && by.get(k).is_some_and(|c| !c.rested) && !chosen.contains(k) {
            chosen.push(*k);
        }
    }
    let random = |k: &KeyId| *blake3::keyed_hash(&seed, k).as_bytes();
    let rank = |c: &Candidate| (c.rested, !c.open, !c.host, random(&c.device));
    let best = |from: &mut dyn Iterator<Item = &KeyId>, chosen: &[KeyId]| {
        from.filter(|k| !chosen.contains(k))
            .filter_map(|k| by.get(k).copied())
            .min_by_key(|c| rank(c))
            .map(|c| c.device)
    };
    let mut order: Vec<&Vec<KeyId>> = groups.iter().collect();
    order.sort_by_key(|g| g.first().map(&random));
    loop {
        let mut more = false;
        for g in &order {
            if chosen.len() >= b.most {
                break;
            }
            let have = g.iter().filter(|k| chosen.contains(k)).count();
            if have >= b.per_group.min(g.len()) {
                continue;
            }
            if let Some(k) = best(&mut g.iter(), &chosen) {
                chosen.push(k);
                more = true;
            }
        }
        if !more || chosen.len() >= b.most {
            break;
        }
    }
    let mut recent = true;
    while chosen.len() < b.least.min(b.most) {
        let next = if recent {
            all.iter()
                .filter(|c| !chosen.contains(&c.device))
                .min_by_key(|c| (c.rested, std::cmp::Reverse(c.used), rank(c)))
                .map(|c| c.device)
        } else {
            all.iter()
                .filter(|c| !chosen.contains(&c.device))
                .min_by_key(|c| (c.rested, random(&c.device)))
                .map(|c| c.device)
        };
        let Some(k) = next else { break };
        chosen.push(k);
        recent = !recent;
    }
    chosen
}

/// A neighbour chosen.
struct Chosen {
    /// Its static key.
    x: [u8; 32],
    /// When it was first dialled since a session with it was last seen
    /// open, if it was.
    tried: Option<Instant>,
    /// When it is replaced.
    until: Instant,
}

/// A device let go: when it may be chosen again, and how many times in a
/// row it was not reached.
#[derive(Clone, Copy, Debug)]
struct Rest {
    until: Instant,
    misses: u32,
}

/// How long a device rests after it was not reached `misses` times in a
/// row: ten minutes, doubling, up to four hours.
fn rest_for(misses: u32) -> Duration {
    REST_FOR
        .saturating_mul(1 << misses.saturating_sub(1).min(16))
        .min(REST_MOST)
}

/// The neighbours this device keeps.
#[derive(Default)]
pub struct Neighbours {
    chosen: Mutex<HashMap<KeyId, Chosen>>,
    rested: Mutex<HashMap<KeyId, Rest>>,
}

impl Neighbours {
    /// The static keys of the neighbours chosen.
    pub fn statics(&self) -> HashSet<[u8; 32]> {
        lock(&self.chosen).values().map(|c| c.x).collect()
    }

    /// The devices chosen.
    pub fn devices(&self) -> HashSet<KeyId> {
        lock(&self.chosen).keys().copied().collect()
    }

    /// Whether a device is a neighbour.
    pub fn is(&self, device: &KeyId) -> bool {
        lock(&self.chosen).contains_key(device)
    }

    /// Tests: chooses a device, as a tick would.
    #[cfg(test)]
    pub(crate) fn choose_now(&self, device: KeyId, x: [u8; 32], now: Instant) {
        let until = now + KEEP_FOR;
        let c = Chosen {
            x,
            tried: None,
            until,
        };
        lock(&self.chosen).insert(device, c);
    }

    /// A neighbour is being dialled.
    pub fn dialling(&self, device: &KeyId) {
        if let Some(c) = lock(&self.chosen).get_mut(device) {
            c.tried.get_or_insert_with(Instant::now);
        }
    }

    /// Lets go of the neighbours dialled and not reached within a minute,
    /// and of those kept long enough, which rest; `open` says whether a
    /// session with a device is open, which ends its rest. Gives those
    /// kept.
    fn let_go(&self, now: Instant, open: impl Fn(&[u8; 32]) -> bool) -> Vec<KeyId> {
        let mut chosen = lock(&self.chosen);
        let mut rested = lock(&self.rested);
        chosen.retain(|k, c| {
            if open(&c.x) {
                c.tried = None;
                rested.remove(k);
            }
            let unreached = c
                .tried
                .is_some_and(|t| now.duration_since(t) >= REACH_WITHIN);
            if unreached {
                let misses = rested.get(k).map_or(1, |r| r.misses + 1);
                let until = now + rest_for(misses);
                rested.insert(*k, Rest { until, misses });
                return false;
            }
            if now >= c.until {
                let misses = rested.get(k).map_or(0, |r| r.misses);
                let until = now + REST_FOR;
                rested.insert(*k, Rest { until, misses });
                return false;
            }
            true
        });
        chosen.keys().copied().collect()
    }

    /// Whether a device rests now, and whether it was not reached lately.
    fn resting(&self, device: &KeyId, now: Instant) -> (bool, bool) {
        lock(&self.rested)
            .get(device)
            .map_or((false, false), |r| (now < r.until, r.misses > 0))
    }
}

/// One trusted contact's device, as the tick sees it.
pub struct Theirs {
    pub who: [u8; 32],
    pub device: KeyId,
    pub x: [u8; 32],
    pub host: bool,
}

/// The groups this device's person is in: spaces with three or more
/// members, each by the devices of its members who are trusted contacts.
fn groups(d: &Daemon, theirs: &[Theirs]) -> Vec<Vec<KeyId>> {
    let core = d.core();
    let Some(me) = core.me() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for h in core.spaces.values() {
        let Some(sp) = h.space.as_ref() else {
            continue;
        };
        let members = sp.present();
        if members.len() < 3 || !members.contains(&me) {
            continue;
        }
        let devices: Vec<KeyId> = theirs
            .iter()
            .filter(|t| members.contains(&t.who))
            .map(|t| t.device)
            .collect();
        if !devices.is_empty() {
            out.push(devices);
        }
    }
    out
}

/// One pass: neighbours not reached for a while, or kept long enough, are
/// replaced, and the rest chosen again.
pub fn tick(d: &Daemon, theirs: &[Theirs]) {
    let now = Instant::now();
    let n = &d.neighbours;
    let groups = groups(d, theirs);
    let used = d.rendezvous.used_at();
    {
        // a device seen in a session rests no longer; one gone, at all
        let mut rested = lock(&n.rested);
        rested.retain(|k, _| {
            theirs
                .iter()
                .any(|t| t.device == *k && d.session(&t.x).is_none())
        });
    }
    let kept = n.let_go(now, |x| d.session(x).is_some());
    // One resting is not chosen at all, even with no other left: a phone
    // that is off is not dialled every minute.
    let all: Vec<Candidate> = theirs
        .iter()
        .filter_map(|t| {
            let (resting, missed) = n.resting(&t.device, now);
            (!resting).then(|| Candidate {
                device: t.device,
                open: d.session(&t.x).is_some(),
                host: t.host,
                used: used.get(&t.who).copied(),
                rested: missed,
            })
        })
        .collect();
    let picked = choose(
        &all,
        &groups,
        &kept,
        Bounds::new(d.conditions.helps()),
        random_bytes(),
    );
    let mut chosen = lock(&n.chosen);
    chosen.retain(|k, _| picked.contains(k));
    for k in picked {
        let Some(t) = theirs.iter().find(|t| t.device == k) else {
            continue;
        };
        chosen.entry(k).or_insert_with(|| {
            let spread = u64::from(u16::from_le_bytes(random_bytes())) % KEEP_FOR.as_secs();
            Chosen {
                x: t.x,
                tried: None,
                until: now + KEEP_FOR + Duration::from_secs(spread),
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cands(n: u8) -> Vec<Candidate> {
        (0..n)
            .map(|i| Candidate {
                device: [i; 32],
                open: false,
                host: false,
                used: None,
                rested: false,
            })
            .collect()
    }

    fn per_group_count(chosen: &[KeyId], g: &[KeyId]) -> usize {
        g.iter().filter(|k| chosen.contains(k)).count()
    }

    #[test]
    fn each_group_gets_its_neighbours_within_the_bounds() {
        // Twenty groups of ten devices each, some shared between groups.
        let all = cands(200);
        let groups: Vec<Vec<KeyId>> = (0..20u8)
            .map(|g| (0..10u8).map(|i| [g * 9 + i; 32]).collect())
            .collect();
        for helps in [true, false] {
            let b = Bounds::new(helps);
            let c = choose(&all, &groups, &[], b, [7; 32]);
            assert_eq!(c.len(), b.most, "helps {helps}");
            let unique: HashSet<_> = c.iter().collect();
            assert_eq!(unique.len(), c.len());
        }
        // Few enough groups: each has its share, or all of its members.
        let few = &groups[..2];
        for helps in [true, false] {
            let b = Bounds::new(helps);
            let c = choose(&all, few, &[], b, [7; 32]);
            for g in few {
                assert!(per_group_count(&c, g) >= b.per_group, "helps {helps}");
            }
            assert!(c.len() <= b.most);
        }
        let small = vec![vec![[1; 32], [2; 32]]];
        let c = choose(&all[..3], &small, &[], Bounds::new(true), [7; 32]);
        assert!(c.contains(&[1; 32]) && c.contains(&[2; 32]));
    }

    #[test]
    fn one_session_serves_every_group_it_is_in() {
        let mut all = cands(20);
        all[5].open = true;
        // Device 5 is in both groups and already in touch: it counts for each.
        let groups = vec![
            (0..10u8).map(|i| [i; 32]).collect::<Vec<_>>(),
            std::iter::once([5; 32])
                .chain((10..19u8).map(|i| [i; 32]))
                .collect::<Vec<_>>(),
        ];
        let b = Bounds::new(false);
        let c = choose(&all, &groups, &[], b, [3; 32]);
        assert!(c.contains(&[5; 32]));
        assert_eq!(c.len(), 2 * b.per_group - 1, "{c:?}");
    }

    #[test]
    fn without_groups_only_the_lifelines_are_kept() {
        let now = Instant::now();
        let mut all = cands(40);
        all[17].used = Some(now);
        all[30].used = Some(now - Duration::from_secs(60));
        let b = Bounds::new(false);
        let c = choose(&all, &[], &[], b, [9; 32]);
        assert_eq!(c.len(), LEAST_SPARING);
        assert_eq!(c[0], [17; 32], "the contact last talked to first");
        assert!(c.contains(&[30; 32]), "then, beside a random one, the next");
        let c = choose(&all, &[], &[], Bounds::new(true), [9; 32]);
        assert_eq!(c.len(), LEAST);
        // Fewer contacts than that: all of them.
        assert_eq!(choose(&all[..2], &[], &[], b, [9; 32]).len(), 2);
        assert!(choose(&[], &[], &[], b, [9; 32]).is_empty());
    }

    #[test]
    fn a_rested_neighbour_is_replaced_while_others_are_left() {
        let mut all = cands(4);
        all[0].rested = true;
        let groups = vec![(0..4u8).map(|i| [i; 32]).collect::<Vec<_>>()];
        let b = Bounds::new(false);
        let c = choose(&all, &groups, &[[0; 32]], b, [1; 32]);
        assert!(!c.contains(&[0; 32]), "{c:?}");
        // When no other is left it is tried again.
        let c = choose(&all[..1], &groups, &[], b, [1; 32]);
        assert_eq!(c, vec![[0; 32]]);
    }

    #[test]
    fn those_kept_stay_while_they_may() {
        let all = cands(30);
        let groups = vec![(0..30u8).map(|i| [i; 32]).collect::<Vec<_>>()];
        let b = Bounds::new(true);
        let first = choose(&all, &groups, &[], b, [1; 32]);
        let again = choose(&all, &groups, &first, b, [2; 32]);
        assert_eq!(first, again);
    }

    /// Review M4. A neighbour dialled and not reached rests ten minutes,
    /// then twice as long each time it is not reached again, up to four
    /// hours, and is not chosen while it rests; a session with it ends the
    /// rest. One never dialled is not let go for not being reached.
    #[test]
    fn a_neighbour_not_reached_rests_ever_longer() {
        assert_eq!(rest_for(1), REST_FOR);
        assert_eq!(rest_for(2), 2 * REST_FOR);
        assert_eq!(rest_for(3), 4 * REST_FOR);
        assert_eq!(rest_for(9), REST_MOST);
        assert_eq!(rest_for(u32::MAX), REST_MOST);
        let n = Neighbours::default();
        let (k, x) = ([1; 32], [2; 32]);
        let mut now = Instant::now();
        n.choose_now(k, x, now);
        // never dialled, as by a phone between wakes: kept
        let later = now + 10 * REACH_WITHIN;
        let kept = n.let_go(later, |_| false);
        assert_eq!(kept, vec![k]);
        let mut rests = Vec::new();
        for _ in 0..8 {
            n.choose_now(k, x, now);
            lock(&n.chosen).get_mut(&k).unwrap().tried = Some(now);
            now += REACH_WITHIN;
            assert!(n.let_go(now, |_| false).is_empty(), "it was not reached");
            let (resting, missed) = n.resting(&k, now);
            assert!(resting && missed);
            let until = lock(&n.rested)[&k].until;
            rests.push(until - now);
            assert!(n.resting(&k, until - Duration::from_secs(1)).0);
            assert!(!n.resting(&k, until).0);
            now = until;
        }
        assert_eq!(rests[0], REST_FOR);
        assert_eq!(rests[1], 2 * REST_FOR);
        assert_eq!(*rests.last().unwrap(), REST_MOST);
        // Seen in a session: its rest ends, and it starts again from ten
        // minutes.
        n.choose_now(k, x, now);
        n.let_go(now, |o| *o == x);
        assert!(!n.resting(&k, now).1);
        lock(&n.chosen).get_mut(&k).unwrap().tried = Some(now);
        now += REACH_WITHIN;
        n.let_go(now, |_| false);
        assert_eq!(lock(&n.rested)[&k].until - now, REST_FOR);
    }
}
