//! How often a device dials the devices it has no session with
//! (`hosts.md#staying-reachable`, D86).
//!
//! A device that helps others (plugged in, unmetered) dials them from the
//! reconnect loop. One it does not reach waits before the next try, a
//! second at first and twice as long each time after, up to [`MOST`]; a
//! session with it, its person turning to it, or a network change starts
//! that over.
//!
//! A device that does not help spends no radio wakeups on upkeep: each
//! dial wakes a phone's radio, and its anchors carry the reliability. It
//! dials when it wakes, when its network changes and when its person turns
//! to someone, and otherwise only answers. The one exception is a device in
//! touch with nobody, with no session with any of its own devices and no
//! anchor keeping one of its sessions: it dials its own devices and its
//! neighbours on a slow timer, [`SPARING_FIRST`] after it was left alone,
//! then twice as long each time, up to [`SPARING_MOST`]. That is four
//! rounds in the first hour, and one an hour after.

use std::time::{Duration, Instant};

/// A device that helps: the first wait after a device was not reached.
pub const FIRST: Duration = Duration::from_secs(1);
/// A device that helps: the longest wait between tries of one device.
pub const MOST: Duration = Duration::from_secs(20 * 60);
/// A device that does not help, alone: the wait before its first round.
pub const SPARING_FIRST: Duration = Duration::from_secs(2 * 60);
/// A device that does not help, alone: the longest wait between rounds.
pub const SPARING_MOST: Duration = Duration::from_secs(60 * 60);

/// The wait after a device that helps did not reach a device, given the
/// wait before.
pub fn after(was: Option<Duration>) -> Duration {
    was.map_or(FIRST, |w| (w * 2).clamp(FIRST, MOST))
}

/// The slow rounds of a device that does not help.
#[derive(Clone, Copy, Debug)]
pub struct Sparing {
    next: Instant,
    wait: Duration,
}

impl Sparing {
    pub fn new(now: Instant) -> Sparing {
        Sparing {
            next: now + SPARING_FIRST,
            wait: SPARING_FIRST,
        }
    }

    /// Woken, its network changed, its person turned to someone, or it is
    /// in touch again: the next round, if it comes to one, is the first.
    pub fn start_over(&mut self, now: Instant) {
        *self = Sparing::new(now);
    }

    /// Whether a round is due at `now`, `alone` saying whether the device
    /// is in touch with nobody. A device in touch dials nothing, and starts
    /// over.
    pub fn due(&mut self, now: Instant, alone: bool) -> bool {
        if !alone {
            self.start_over(now);
            return false;
        }
        if now < self.next {
            return false;
        }
        self.wait = (self.wait * 2).min(SPARING_MOST);
        self.next = now + self.wait;
        true
    }

    /// When it dials next, and the wait, as `status` gives them.
    pub fn shown(&self, now: Instant) -> crate::api::Sparing {
        crate::api::Sparing {
            next_s: self.next.saturating_duration_since(now).as_secs(),
            wait_s: self.wait.as_secs(),
        }
    }

    /// [`Sparing::shown`] as main had it, by name.
    #[cfg(any(test, debug_assertions, feature = "by-name"))]
    pub fn json(&self, now: Instant) -> serde_json::Value {
        serde_json::json!({
            "next_s": self.next.saturating_duration_since(now).as_secs(),
            "wait_s": self.wait.as_secs(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rounds a device alone makes in `hours`, its loop passing every
    /// two seconds.
    fn rounds(s: &mut Sparing, from: Instant, hours: u64) -> Vec<Duration> {
        let mut out = Vec::new();
        let mut t = Duration::ZERO;
        while t < Duration::from_secs(hours * 3600) {
            if s.due(from + t, true) {
                out.push(t);
            }
            t += Duration::from_secs(2);
        }
        out
    }

    #[test]
    fn a_phone_alone_dials_a_few_times_an_hour() {
        let now = Instant::now();
        let mut s = Sparing::new(now);
        let first = rounds(&mut s, now, 1);
        assert_eq!(first.len(), 4, "{first:?}");
        assert!(first[0] >= SPARING_FIRST, "{first:?}");
        // later, once an hour
        let mut s2 = Sparing::new(now);
        let day = rounds(&mut s2, now, 24);
        let last_hours = day.iter().filter(|t| t.as_secs() >= 23 * 3600).count();
        assert!(last_hours <= 1, "{day:?}");
        assert!(day.len() <= 4 + 24, "{}", day.len());
    }

    #[test]
    fn a_phone_in_touch_dials_nothing_and_starts_over() {
        let now = Instant::now();
        let mut s = Sparing::new(now);
        let mut t = Duration::ZERO;
        while t < Duration::from_secs(3 * 3600) {
            assert!(!s.due(now + t, false));
            t += Duration::from_secs(2);
        }
        // left alone after three hours in touch: the first wait again
        assert!(!s.due(now + t, false));
        let rounds = rounds(&mut s, now + t, 1);
        assert_eq!(rounds[0], SPARING_FIRST, "{rounds:?}");
        // and starting over puts the wait back
        s.start_over(now);
        assert_eq!(s.wait, SPARING_FIRST);
    }

    #[test]
    fn an_anchors_wait_for_a_device_not_reached_grows_to_tens_of_minutes() {
        let mut w = after(None);
        assert_eq!(w, FIRST);
        let mut waits = vec![w];
        for _ in 0..20 {
            w = after(Some(w));
            waits.push(w);
        }
        assert!(waits.windows(2).all(|p| p[1] >= p[0]), "{waits:?}");
        assert!(waits.iter().any(|w| *w > Duration::from_secs(10 * 60)));
        assert_eq!(*waits.last().unwrap(), MOST);
        // so an anchor tries a device that is off a few times an hour
        let mut tries = 0;
        let (mut t, mut wait) = (Duration::ZERO, None);
        while t < Duration::from_secs(5 * 3600) {
            tries += 1;
            let w = after(wait);
            t += w;
            wait = Some(w);
        }
        assert!(tries <= 11 + 3 * 5, "{tries}");
    }
}
