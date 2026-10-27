//! Fetching objects after reconciliation (`sync.md#fetching-objects`).

use crate::reconcile::MAX_MESSAGE;
use crate::{Id, Label, Message};

/// The most ids one `want` message names.
pub const MAX_WANT: usize = 256;

/// `want` messages for `ids`, at most [`MAX_WANT`] ids each.
pub fn want_messages(label: Label, ids: &[Id]) -> Vec<Message> {
    ids.chunks(MAX_WANT)
        .map(|c| Message::Want {
            label,
            ids: c.to_vec(),
        })
        .collect()
}

/// Packs objects into `objects` messages of at most 64 KiB where possible:
/// an object larger than that (a sealed entry may be 256 KiB) travels
/// alone.
pub fn objects_messages(label: Label, objects: impl IntoIterator<Item = Vec<u8>>) -> Vec<Message> {
    let mut out = Vec::new();
    let mut cur: Vec<Vec<u8>> = Vec::new();
    let mut size = 48;
    for o in objects {
        let len = o.len() + 5;
        if !cur.is_empty() && size + len > MAX_MESSAGE {
            out.push(Message::Objects {
                label,
                objects: std::mem::take(&mut cur),
            });
            size = 48;
        }
        size += len;
        cur.push(o);
    }
    if !cur.is_empty() {
        out.push(Message::Objects {
            label,
            objects: cur,
        });
    }
    out
}

/// Answers a `want`: the objects this side still holds, in `objects`
/// messages. Objects it no longer holds, or holds only by id as a light
/// holder, are omitted (`get` returns `None` for them).
pub fn answer_want(
    label: Label,
    ids: &[Id],
    mut get: impl FnMut(&Id) -> Option<Vec<u8>>,
) -> Vec<Message> {
    objects_messages(label, ids.iter().take(MAX_WANT).filter_map(&mut get))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batching() {
        let ids: Vec<Id> = (0..600u32)
            .map(|i| {
                let mut id = [0u8; 32];
                id[..4].copy_from_slice(&i.to_le_bytes());
                id
            })
            .collect();
        let w = want_messages([1; 32], &ids);
        assert_eq!(w.len(), 3);
        let big = vec![vec![0u8; 30_000]; 5];
        let m = objects_messages([1; 32], big);
        assert_eq!(m.len(), 3);
        for msg in &m {
            assert!(msg.encode().len() <= MAX_MESSAGE);
        }
        let huge = objects_messages([1; 32], vec![vec![0u8; 200_000], vec![1u8; 10]]);
        assert_eq!(huge.len(), 2);
        let answered = answer_want([1; 32], &ids[..3], |id| (id[0] != 1).then(|| id.to_vec()));
        let Message::Objects { objects, .. } = &answered[0] else {
            panic!()
        };
        assert_eq!(objects.len(), 2);
    }
}
