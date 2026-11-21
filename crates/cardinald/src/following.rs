//! Succession over the network (`spaces.md#succession`): what the core
//! writes and follows ([`crate::core::Core::succeed`],
//! [`crate::core::Core::follow`]), sent to whoever holds the spaces.
//!
//! A device reconciles a space with a peer before it sends anyone a
//! `succeed` for it, so that one which was away does not unseat what the
//! others moved to (`spaces.md#ending-a-space`). Here that is done before
//! the `succeed` is written: if the space ended meanwhile, this device
//! follows, and does there what the person asked.

use std::sync::Arc;

use cardinal_space::SpaceId;

use crate::core::{short, Succeeded};
use crate::daemon::Daemon;

/// Follows every successor that stands and can be checked, posts again
/// what is to be posted again, and sends what that wrote.
///
/// What this device holds of a space it has just followed is fetched from
/// the members in touch, whatever they wrote there before it came; and so
/// is the old space's set where it ended and the successor's genesis is
/// not here.
///
/// A persona's service, or a recovery helper's, run inside this person's
/// device, does none of it: it holds relationships and copies for the
/// guardians' work, and nothing of a group's.
pub fn follow(d: &Arc<Daemon>) {
    if d.config().this_run.inside() {
        return;
    }
    let open = |d: &Daemon| -> Vec<SpaceId> {
        let core = d.core();
        let held = core.spaces.iter().filter(|(_, h)| h.space.is_some());
        held.map(|(id, _)| *id).collect()
    };
    let before = open(d);
    let written = d.core().follow(&*d.store);
    let any = !written.is_empty();
    for (space, entries) in written {
        d.push(&space, entries);
    }
    fetch_initial(d);
    let mut new: Vec<SpaceId> = open(d)
        .into_iter()
        .filter(|s| !before.contains(s))
        .collect();
    // and the trail of a space that ended, where it is not all here
    new.extend(d.core().trail_wanted());
    if !new.is_empty() {
        let d2 = d.clone();
        d.rt.spawn(async move {
            for space in new {
                reconcile_with_peers(&d2, &space).await;
            }
        });
    }
    if any {
        d.bump();
    }
}

/// The successors whose initial state is being fetched.
static FETCHING: std::sync::Mutex<Vec<SpaceId>> = std::sync::Mutex::new(Vec::new());

/// Fetches the initial state of each successor held here that waits for
/// it and whose old space is not held, from whoever has it in touch, and
/// opens the successor on it.
fn fetch_initial(d: &Arc<Daemon>) {
    let wanted = d.core().initial_wanted();
    for (space, reference) in wanted {
        {
            let mut busy = FETCHING.lock().unwrap_or_else(|e| e.into_inner());
            if busy.contains(&space) {
                continue;
            }
            busy.push(space);
        }
        let d2 = d.clone();
        d.rt.spawn_blocking(move || {
            let got = fetch_blob(&d2, &reference);
            match got.and_then(|bytes| d2.core().take_initial(&space, &bytes)) {
                Ok(()) => {
                    tracing::info!("space {}: opened on its initial state", short(&space));
                    d2.bump();
                }
                Err(e) => tracing::debug!("space {}: its initial state: {e:#}", short(&space)),
            }
            let mut busy = FETCHING.lock().unwrap_or_else(|e| e.into_inner());
            busy.retain(|s| *s != space);
        });
    }
}

/// A whole blob, from this person's devices or a contact's in touch.
fn fetch_blob(d: &Arc<Daemon>, reference: &cardinal_encoding::Record) -> anyhow::Result<Vec<u8>> {
    use cardinal_link::Priority;
    let blob = cardinal_blob::BlobRef::from_record(reference)
        .map_err(|e| anyhow::anyhow!("not a blob reference: {e}"))?;
    let contacts: Vec<[u8; 32]> = d.contacts_in_touch().into_iter().map(|(w, _)| w).collect();
    let mut last = anyhow::anyhow!("nobody who has it is in touch");
    for who in [None].into_iter().chain(contacts.into_iter().map(Some)) {
        let fetch = match who {
            Some(w) => crate::fetch::Fetcher::from_contact(d, Priority::Background, w),
            None => crate::fetch::Fetcher::new(d, Priority::Background),
        };
        let mut reader = cardinal_blob::BlobReader::new(&*d.store, &fetch, blob);
        let mut out = Vec::new();
        match std::io::copy(&mut reader, &mut out) {
            Ok(_) => return Ok(out),
            Err(e) => last = e.into(),
        }
    }
    Err(last)
}

/// Posts again the work held back from `space`, its person having said so.
pub fn post_held_back(d: &Arc<Daemon>, space: &SpaceId) -> usize {
    let written = d.core().post_again_all(true);
    let mut n = 0;
    for (into, entries) in written {
        if into == *space {
            n += entries.len();
        }
        d.push(&into, entries);
    }
    d.bump();
    n
}

/// Reconciles `space` with every peer in touch that holds it: this
/// person's own devices, and members who are. Says whether one answered.
async fn reconcile_with_peers(d: &Arc<Daemon>, space: &SpaceId) -> bool {
    let sessions = crate::groups::member_sessions(d, space);
    let mut any = false;
    for s in sessions {
        let done = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            crate::net::reconcile(d, &s, *space),
        )
        .await;
        if matches!(done, Ok(Ok(()))) {
            any = true;
        }
    }
    any
}

/// Whether this person has a device besides this one: only another of the
/// owner's devices can have named a rival successor.
fn has_other_devices(d: &Daemon) -> bool {
    let core = d.core();
    let Some(ident) = core.identity.as_ref() else {
        return false;
    };
    let st = ident.state();
    let here = d.keys.key();
    let mut keys: Vec<_> = st
        .effective_at()
        .map(|(k, _)| *k)
        .filter(|k| *k != here && !st.is_removed(k))
        .collect();
    keys.sort();
    keys.dedup();
    !keys.is_empty()
}

/// Succeeds `space` with one naming `named` (`who` and role, this person as
/// owner among them), once it is known to be open: reconciled with a peer
/// that holds it, where another of this person's devices could have ended
/// it. Where it has ended meanwhile, this device follows first, and does
/// it in the space that stands: `named` reads the members and roles to
/// name from the space that is succeeded. Sends what was written.
pub async fn succeed(
    d: &Arc<Daemon>,
    space: &SpaceId,
    named: impl Fn(&cardinal_space::Space) -> anyhow::Result<Vec<([u8; 32], u64)>>,
) -> anyhow::Result<Succeeded> {
    anyhow::ensure!(
        !d.config().this_run.inside(),
        "a persona's service succeeds nothing"
    );
    if has_other_devices(d) {
        anyhow::ensure!(
            reconcile_with_peers(d, space).await,
            "nobody who holds it is in touch, so this device cannot check that another of yours \
             has not changed it already: try again when one is"
        );
    } else {
        // nobody could have ended it, but what others wrote is best in the
        // cut
        reconcile_with_peers(d, space).await;
    }
    follow(d);
    let done = {
        let mut core = d.core();
        let now = core.current(space);
        let sp = core.spaces.get(&now).and_then(|h| h.space.as_ref());
        let sp = sp.ok_or_else(|| anyhow::anyhow!("that space is not open here"))?;
        let named = named(sp)?;
        core.succeed(&*d.store, &now, &named)?
    };
    let from = {
        let core = d.core();
        let sp = core.spaces.get(&done.new).and_then(|h| h.space.as_ref());
        sp.and_then(|s| s.succeeds())
    };
    if let Some(from) = from {
        d.push(&from, done.old_entries.clone());
    }
    d.push(&done.new, done.new_entries.clone());
    if let Some((acc, entries)) = &done.account {
        d.push(acc, entries.clone());
    }
    d.bump();
    Ok(done)
}
