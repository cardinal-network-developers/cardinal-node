//! Local retention of chunks (`blobs.md#retention`).
//!
//! Which objects a device keeps is a local decision. The policy is set per
//! space in the account space; the space layer knows which blobs current
//! state and older versions reference, and passes that knowledge here as a
//! predicate.

use std::io;

use crate::store::ObjectStore;
use crate::Id;

/// A per-space retention policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Retention {
    /// Keep every chunk referenced by current state.
    Full,
    /// Keep what was opened recently, up to a size budget in bytes.
    OnDemand {
        /// The most bytes to keep of objects not otherwise pinned.
        budget: u64,
    },
    /// Keep chunks referenced by current state and by older versions.
    History,
}

/// What an eviction pass did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Evicted {
    /// Objects deleted.
    pub objects: u64,
    /// Bytes freed.
    pub bytes: u64,
}

/// Deletes objects that `keep` does not protect, least recently used first,
/// until the unprotected objects total at most `budget` bytes. With a
/// budget of 0 this is plain garbage collection: everything unprotected
/// goes.
///
/// Under [`Retention::Full`] and [`Retention::History`], `keep` is "named
/// by current state" or "named by any version", and the budget is 0. Under
/// [`Retention::OnDemand`], `keep` protects pinned files and the budget is
/// the policy's.
pub fn evict<S: ObjectStore + ?Sized>(
    store: &S,
    keep: impl Fn(&Id) -> bool,
    budget: u64,
) -> io::Result<Evicted> {
    let mut candidates: Vec<_> = store.list()?.into_iter().filter(|o| !keep(&o.id)).collect();
    let mut total: u64 = candidates.iter().map(|o| o.size).sum();
    candidates.sort_by_key(|o| o.used);
    let mut out = Evicted::default();
    for o in candidates {
        if total <= budget {
            break;
        }
        if store.delete(&o.id)? {
            out.objects += 1;
            out.bytes += o.size;
        }
        total -= o.size;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{object_id, MemStore};

    #[test]
    fn evicts_oldest_unprotected() {
        let s = MemStore::new();
        let objs: Vec<Vec<u8>> = (0..5u8).map(|i| vec![i; 100]).collect();
        for o in &objs {
            s.put(&object_id(o), o).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        let pinned = object_id(&objs[0]);
        // Touch object 1 so it becomes the most recent.
        s.touch(&object_id(&objs[1])).unwrap();
        let ev = evict(&s, |id| *id == pinned, 200).unwrap();
        assert_eq!(
            ev,
            Evicted {
                objects: 2,
                bytes: 200
            }
        );
        assert!(s.has(&pinned).unwrap());
        assert!(s.has(&object_id(&objs[1])).unwrap());
        assert!(s.has(&object_id(&objs[4])).unwrap());
        assert!(!s.has(&object_id(&objs[2])).unwrap());
        let ev = evict(&s, |id| *id == pinned, 0).unwrap();
        assert_eq!(ev.objects, 2);
        assert_eq!(s.usage().objects, 1);
    }
}
