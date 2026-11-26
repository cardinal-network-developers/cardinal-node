//! The history of the one folder's files: every earlier version of a file,
//! and what was deleted from a folder, with bringing either back
//! (`profiles.md#mapping-to-a-disk-guidance`). A version comes back as a
//! `set` of the old value, a deleted file or folder as a `restore` of its
//! node (`state.md#deletion-yields-to-concurrent-work`). Paths are those of
//! the one folder, as `files` takes them, so the shared folders in `People`
//! and `Groups` have their history as the person's own files do.

use std::collections::HashSet;
use std::sync::Arc;

use cardinal_identity::EntryId;
use cardinal_link::Priority;
use cardinal_space::files::{self, Content, FileKind, Files, FILE_CONTENT};
use cardinal_space::{account, group, NodeId, Space, SpaceOp, SpaceOpBody};
use serde_json::{json, Value as Json};

use crate::daemon::Daemon;
use crate::fetch::{Fetcher, Others};
use crate::onefolder::{self, At, Place};

/// One content version of a file: the entry that wrote it, and its content.
pub struct Written {
    /// The entry.
    pub entry: EntryId,
    /// Its author's clock.
    pub time: Option<u64>,
    /// The identity that wrote it.
    pub author: [u8; 32],
    /// The device key that signed it.
    pub device: [u8; 32],
    /// What it wrote, if anything.
    pub content: Option<Content>,
}

/// The content versions of a node, oldest first: version `n` of `history`
/// is the `n`th, from 1.
pub fn versions(sp: &Space, node: &NodeId) -> Vec<Written> {
    let f = Files::new(sp);
    let mut out = Vec::new();
    for h in f.history(node) {
        let c = match &h.op {
            SpaceOpBody::Create { fields, .. } => {
                fields.get(FILE_CONTENT).and_then(Content::from_value)
            }
            SpaceOpBody::Set { key, value, .. } if *key == FILE_CONTENT => {
                value.as_ref().and_then(Content::from_value)
            }
            _ => continue,
        };
        out.push(Written {
            entry: h.entry,
            time: h.time,
            author: h.author,
            device: h.device,
            content: c,
        });
    }
    out
}

/// Version `version` (from 1) of the node, or why there is none.
pub fn version_of(sp: &Space, node: &NodeId, path: &str, version: u64) -> anyhow::Result<Content> {
    let mut vs = versions(sp, node);
    let n = vs.len();
    if version == 0 || version as usize > n {
        anyhow::bail!("{path} has versions 1 to {n}; see `cardinal history {path}`");
    }
    vs.swap_remove(version as usize - 1)
        .content
        .ok_or_else(|| anyhow::anyhow!("version {version} of {path} has no content"))
}

/// Something in a space, by its path in the one folder.
fn in_space(d: &Daemon, path: &str) -> anyhow::Result<At> {
    match onefolder::resolve(d, path)? {
        Place::In(at) => Ok(at),
        Place::Category(c) => anyhow::bail!("{c} lists shared folders; it has no history"),
    }
}

/// What this person calls whoever wrote something in `at`'s space: a
/// contact's petname, or in a group what the group calls them.
fn person(core: &crate::core::Core, sp: &Space, at: &At, who: &[u8; 32]) -> String {
    let contacts = core.contacts();
    let me = core.identity.as_ref().map(|i| i.id()).unwrap_or_default();
    if at.shared.as_ref().and_then(|s| s.group()).is_some() {
        return crate::groups::name_of(&me, &contacts, &group::members(sp), who);
    }
    contacts
        .iter()
        .find(|c| &c.identity == who)
        .map(|c| c.petname.clone())
        .unwrap_or_else(|| account::short_key(who))
}

/// The versions of a file of the one folder, oldest first.
pub fn history(d: &Daemon, path: &str) -> anyhow::Result<Json> {
    let at = in_space(d, path)?;
    let core = d.core();
    let names = core.device_names();
    let me = core.identity.as_ref().map(|i| i.id());
    let sp = onefolder::open(&core, &at.space)?;
    let current: HashSet<EntryId> = Files::new(sp)
        .content(&at.node)
        .iter()
        .map(|v| v.entry)
        .collect();
    let list: Vec<Json> = versions(sp, &at.node)
        .iter()
        .enumerate()
        .map(|(i, w)| {
            let mut v = json!({
                "version": i + 1,
                "time": w.time,
                "device": names.get(&w.device).cloned()
                    .unwrap_or_else(|| account::short_key(&w.device)),
                "size": w.content.as_ref().map(|c| c.size()),
                "current": current.contains(&w.entry),
                // whether its content is on this device (`cleanup.rs`)
                "here": match &w.content {
                    Some(Content::Blob(b)) => {
                        cardinal_blob::ObjectStore::has(&*d.store, &b.id).unwrap_or(false)
                    }
                    _ => true,
                },
            });
            if Some(w.author) != me {
                v["by"] = json!(person(&core, sp, &at, &w.author));
            }
            v
        })
        .collect();
    Ok(json!({"path": path, "versions": list}))
}

/// Saves what is pending in the mounted folder, so that what is written
/// next descends from it.
async fn flush_mount(d: &Arc<Daemon>) -> anyhow::Result<()> {
    let d2 = d.clone();
    tokio::task::spawn_blocking(move || {
        let m = d2.mount.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(m) = m.as_ref() {
            let _ = m.flush();
        }
    })
    .await?;
    Ok(())
}

/// Brings back an earlier version of a file: a `set` of the old value.
pub async fn restore(
    d: &Arc<Daemon>,
    path: &str,
    version: u64,
) -> anyhow::Result<crate::api::RestoreReply> {
    flush_mount(d).await?;
    let at = in_space(d, path)?;
    anyhow::ensure!(at.kind == FileKind::File, "{path} is not a file");
    let content = {
        let core = d.core();
        version_of(onefolder::open(&core, &at.space)?, &at.node, path, version)?
    };
    // Its content may have been freed here (`cleanup.rs`): get all of it
    // first, or the restored file could not be read.
    if let Content::Blob(b) = &content {
        let (d2, b, others) = (d.clone(), crate::fetch::blob_ref(b), at.others());
        let missing =
            tokio::task::spawn_blocking(move || held_or_fetched(&d2, b, others)).await??;
        if missing > 0 {
            anyhow::bail!(
                "version {version} of {path} is no longer kept: this device freed it, and no \
                 device online now has all of it"
            );
        }
    }
    d.write_and_push(&at.space, vec![files::set_content(at.node, &content)])?;
    Ok(crate::api::RestoreReply {
        path: path.to_owned(),
        version,
    })
}

/// The deleted children of a folder of the one folder, by name: files,
/// folders and links whose own node is deleted. What a deleted folder
/// holds comes back with it, and is not listed.
fn deleted_in(sp: &Space, at: &At) -> Vec<NodeId> {
    let f = Files::new(sp);
    let kinds = f.kinds();
    sp.state()
        .children(&at.node)
        .into_iter()
        .filter(|n| n.deleted && kinds.file_kind(n.kind) != FileKind::Other)
        .map(|n| n.id)
        .collect()
}

/// What was deleted from a folder of the one folder: each file, folder and
/// link, with when, by whom, and its size. A name starting with `.` is
/// left out unless `hidden` asks for it: such names are mostly what
/// programs make and remove again, as a lock file is (D91).
pub fn deleted(d: &Daemon, path: &str, hidden: bool) -> anyhow::Result<Json> {
    let at = onefolder::folder(d, path)?;
    let core = d.core();
    let names = core.device_names();
    let me = core.identity.as_ref().map(|i| i.id());
    let sp = onefolder::open(&core, &at.space)?;
    let f = Files::new(sp);
    let st = sp.state();
    let mut out: Vec<(Option<u64>, Json)> = Vec::new();
    for id in deleted_in(sp, &at) {
        let Some(n) = st.node(&id) else { continue };
        if !hidden && n.name.starts_with('.') {
            continue;
        }
        let kind = f.kinds().file_kind(n.kind);
        let mut v = json!({
            "id": hex::encode(id),
            "name": n.name,
            "folder": kind == FileKind::Folder,
        });
        if kind == FileKind::File {
            v["size"] = json!(f.stat(&id).and_then(|s| s.size));
        }
        // when, and by whom: the entry whose delete took it
        let by = n.deleted_in().and_then(|e| sp.entry(&e));
        let time = by.and_then(|e| e.time());
        if let Some(e) = by {
            v["time"] = json!(time);
            let mine = Some(e.author()) == me;
            v["mine"] = json!(mine);
            v["by"] = json!(if mine {
                names
                    .get(&e.signer())
                    .cloned()
                    .unwrap_or_else(|| account::short_key(&e.signer()))
            } else {
                person(&core, sp, &at, &e.author())
            });
        }
        out.push((time, v));
    }
    // the most recently deleted first; those with no time last
    out.sort_by(|(a, x), (b, y)| {
        b.cmp(a)
            .then_with(|| x["name"].as_str().cmp(&y["name"].as_str()))
            .then_with(|| x["id"].as_str().cmp(&y["id"].as_str()))
    });
    let files: Vec<Json> = out.into_iter().map(|(_, v)| v).collect();
    Ok(json!({"path": path, "files": files}))
}

/// Brings back a deleted file, folder or link: a `restore` of its node,
/// which brings back what the same delete took beneath it. `path` is the
/// folder and the name it had; `id`, as `deleted` gives it or the start of
/// it, picks one where more than one of that name was deleted there. Back
/// beside another of its name, it is shown as the folder shows any two
/// nodes of one name, and the reply says the path it is shown at.
pub async fn undelete(d: &Arc<Daemon>, path: &str, id: Option<&str>) -> anyhow::Result<Json> {
    flush_mount(d).await?;
    let (parent, name) = onefolder::split_last(path)?;
    let at = onefolder::folder(d, &parent)?;
    let node = {
        let core = d.core();
        let sp = onefolder::open(&core, &at.space)?;
        let st = sp.state();
        let named: Vec<NodeId> = deleted_in(sp, &at)
            .into_iter()
            .filter(|n| st.node(n).is_some_and(|n| n.name == name))
            .collect();
        let picked: Vec<NodeId> = match id {
            None => named,
            Some(asked) => {
                let (exact, hex_given) = match crate::api::reference(asked) {
                    crate::api::Ref::Id(h) => (true, h.hex().to_ascii_lowercase()),
                    crate::api::Ref::Typed(h) => (false, h.to_ascii_lowercase()),
                };
                anyhow::ensure!(!hex_given.is_empty(), "name the id to bring back");
                named
                    .into_iter()
                    .filter(|n| {
                        let h = hex::encode(n);
                        if exact {
                            h == hex_given
                        } else {
                            h.starts_with(&hex_given)
                        }
                    })
                    .collect()
            }
        };
        match picked.as_slice() {
            [one] => *one,
            [] if id.is_some() => anyhow::bail!(
                "no deleted {name} in {} has that id; see `cardinal deleted {parent}`",
                shown_folder(&parent)
            ),
            [] => anyhow::bail!(
                "nothing named {name} was deleted in {}; see `cardinal deleted {parent}`",
                shown_folder(&parent)
            ),
            more => anyhow::bail!(
                "{} deleted items in {} were named {name}: say which by its id, as \
                 `cardinal deleted {parent}` gives it",
                more.len(),
                shown_folder(&parent)
            ),
        }
    };
    d.write_and_push(&at.space, vec![SpaceOp::restore(node)])?;
    // where it is shown now
    let shown = {
        let core = d.core();
        let sp = onefolder::open(&core, &at.space)?;
        let entries = Files::new(sp).list(&at.node);
        entries
            .into_iter()
            .find(|e| e.node == node && e.conflict_version.is_none())
            .map(|e| e.name)
            .unwrap_or(name)
    };
    let path = if parent.is_empty() {
        shown
    } else {
        format!("{parent}/{shown}")
    };
    Ok(json!({"path": path, "id": hex::encode(node)}))
}

fn shown_folder(parent: &str) -> &str {
    if parent.is_empty() {
        "your files"
    } else {
        parent
    }
}

/// Makes sure every object of `b` is on this device, fetching what is
/// missing from the person's online devices, and those of `others` where
/// it is theirs too (blocking). Returns how many objects are still missing.
pub fn held_or_fetched(
    d: &Arc<Daemon>,
    b: cardinal_blob::BlobRef,
    others: Option<Others>,
) -> anyhow::Result<usize> {
    use cardinal_blob::{BlobReader, Fetch, ObjectStore};
    let fetcher = Fetcher::from_others(d, Priority::Interactive, others);
    // Listing fetches and keeps the indexes.
    let mut chunks = Vec::new();
    let listed = BlobReader::new(d.store.clone(), &fetcher, b).for_each_entry(|e, chunk| {
        if chunk {
            chunks.push(e.id)
        }
    });
    if listed.is_err() {
        return Ok(1);
    }
    let mut missing: Vec<[u8; 32]> = Vec::new();
    for id in chunks {
        if !d.store.has(&id)? {
            missing.push(id);
        }
    }
    for batch in missing.chunks(256) {
        for (id, ct) in fetcher.fetch(batch)? {
            if blake3::hash(&ct).as_bytes() == &id {
                d.store.put(&id, &ct)?;
            }
        }
    }
    let mut left = 0;
    for id in &missing {
        if !d.store.has(id)? {
            left += 1;
        }
    }
    Ok(left)
}

// ---- The handlers as they were by name ----
//
// What main had, whole, kept only to show that the typed handlers send the
// same bytes (`control::typed::answering`, `api/same_bytes.rs`), and to
// measure the two. They go with the way by name.

/// `restore` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
pub async fn restore_by_name(d: &Arc<Daemon>, path: &str, version: u64) -> anyhow::Result<Json> {
    flush_mount(d).await?;
    let at = in_space(d, path)?;
    anyhow::ensure!(at.kind == FileKind::File, "{path} is not a file");
    let content = {
        let core = d.core();
        version_of(onefolder::open(&core, &at.space)?, &at.node, path, version)?
    };
    // Its content may have been freed here (`cleanup.rs`): get all of it
    // first, or the restored file could not be read.
    if let Content::Blob(b) = &content {
        let (d2, b, others) = (d.clone(), crate::fetch::blob_ref(b), at.others());
        let missing =
            tokio::task::spawn_blocking(move || held_or_fetched(&d2, b, others)).await??;
        if missing > 0 {
            anyhow::bail!(
                "version {version} of {path} is no longer kept: this device freed it, and no \
                 device online now has all of it"
            );
        }
    }
    d.write_and_push(&at.space, vec![files::set_content(at.node, &content)])?;
    Ok(json!({"path": path, "version": version}))
}
