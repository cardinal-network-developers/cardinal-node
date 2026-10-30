//! Passing news on (`sync.md#notices`). A device tells peers of what it
//! wrote and of what was new to it, so a device that one peer cannot reach
//! hears through another. Objects a device already holds are not news,
//! which is what ends a notice's travel.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cardinal_link::Session;
use cardinal_sync::Label;

use crate::core::short;
use crate::daemon::Daemon;
use crate::net;

/// How long news waits, so that one notice covers a burst. Long enough to
/// gather what arrives together, too short for a person to notice.
const WAIT: Duration = Duration::from_millis(30);

/// How many peers a notice goes to, when a device has more.
const PEERS: usize = 8;

/// News waiting to be passed on.
#[derive(Default)]
pub struct News {
    objects: Vec<Vec<u8>>,
    /// Not everything new is in `objects`: the notice names the heads.
    partial: bool,
    /// Who told this device, while that is one peer.
    from: Option<[u8; 32]>,
    /// More than one peer did.
    mixed: bool,
}

impl News {
    /// Adds what `from` told this device.
    fn add(&mut self, complete: usize, objects: Vec<Vec<u8>>, from: [u8; 32]) {
        self.partial |= objects.len() != complete;
        self.objects.extend(objects);
        self.mixed |= self.from.is_some_and(|f| f != from);
        self.from = Some(from);
    }

    /// Who needs no notice: a peer that told this device all of it. One
    /// that told it only a part lacks the rest.
    fn told_all(&self) -> HashSet<[u8; 32]> {
        match self.from {
            Some(f) if !self.mixed => HashSet::from([f]),
            _ => HashSet::new(),
        }
    }
}

/// News by set.
pub type Waiting = HashMap<Label, News>;

impl Daemon {
    /// Peers to tell, leaving out `not`: all of them, or a random few.
    fn notice_peers(&self, not: &HashSet<[u8; 32]>) -> Vec<Session> {
        let mut peers: Vec<Session> = self
            .own_sessions()
            .into_iter()
            .filter(|s| !not.contains(&s.peer_static()))
            .collect();
        if peers.len() > PEERS {
            let seed = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |t| t.as_nanos());
            peers.sort_by_key(|s| {
                let mut h = blake3::Hasher::new();
                h.update(&seed.to_le_bytes());
                h.update(&s.peer_static());
                *h.finalize().as_bytes()
            });
            peers.truncate(PEERS);
        }
        peers
    }

    /// Sends a notice about `label` to peers other than `not`: `objects`
    /// if they are all that is new and they fit, else the heads.
    pub fn notify(self: &Arc<Self>, label: Label, objects: Vec<Vec<u8>>, not: &HashSet<[u8; 32]>) {
        let peers = self.notice_peers(not);
        if peers.is_empty() {
            return;
        }
        let heads = self.core().heads(&label);
        let objects = Arc::new(objects);
        for s in peers {
            let (objects, heads) = (objects.clone(), heads.clone());
            self.rt.spawn(async move {
                if let Err(e) = net::notice(&s, label, &objects, heads).await {
                    tracing::debug!("notice to {}: {e:#}", short(&s.peer_static()));
                }
            });
        }
    }

    /// Passes on `complete` objects of `label` that `from` told this device
    /// of, `objects` being those that can go as they are. An identity log's
    /// go at once, so revocations travel first; others wait a moment.
    pub fn pass_on(
        self: &Arc<Self>,
        label: Label,
        complete: usize,
        objects: Vec<Vec<u8>>,
        from: [u8; 32],
    ) {
        if complete == 0 {
            return;
        }
        let first = {
            let mut waiting = self.news.lock().unwrap_or_else(|e| e.into_inner());
            let first = !waiting.contains_key(&label);
            waiting
                .entry(label)
                .or_default()
                .add(complete, objects, from);
            first
        };
        if !first {
            return;
        }
        let at_once = self.core().identity_label() == Some(label);
        let d = self.clone();
        self.rt.spawn(async move {
            if !at_once {
                tokio::time::sleep(WAIT).await;
            }
            let n = d
                .news
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&label);
            let Some(n) = n else { return };
            let not = n.told_all();
            let objects = if n.partial { Vec::new() } else { n.objects };
            d.notify(label, objects, &not);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn news_from_two_peers_goes_back_to_both() {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        let mut n = News::default();
        n.add(1, vec![vec![1]], a);
        n.add(1, vec![vec![2]], a);
        assert_eq!(n.told_all(), HashSet::from([a]), "a told it everything");
        n.add(1, vec![vec![3]], b);
        assert!(n.told_all().is_empty(), "each lacks what the other told");
        n.add(1, vec![vec![4]], a);
        assert!(n.told_all().is_empty());
        assert_eq!(n.objects.len(), 4);
        assert!(!n.partial);
    }

    #[test]
    fn news_not_all_in_hand_goes_as_heads() {
        let mut n = News::default();
        n.add(2, vec![vec![1]], [1u8; 32]);
        assert!(n.partial);
    }
}
