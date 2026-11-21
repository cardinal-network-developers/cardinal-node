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

use crate::core::Succeeded;
use crate::daemon::Daemon;

/// Follows every successor that stands and can be checked, posts again
/// what is to be posted again, and sends what that wrote.
///
/// What this device holds of a space it has just followed is fetched from
/// the members in touch, whatever they wrote there before it came; and so
/// is the old space's set where it ended and the successor's genesis is
/// not here.
pub fn follow(d: &Arc<Daemon>) {
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
