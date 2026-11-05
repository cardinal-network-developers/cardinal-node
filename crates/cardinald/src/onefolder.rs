//! The one folder (`profiles.md#one-folder-for-everything-guidance`). Its root
//! is the person's files space; beside that space's own entries it holds a
//! folder for each category of relationship, and in each, every relationship's
//! shared folder under the contact's petname. Every window, and every way of
//! showing files, goes through here, so they all show the same tree.

use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use cardinal_blob::{BlobReader, BlobWriter, ConvergenceSecret, INLINE_LIMIT};
use cardinal_identity::EntryId;
use cardinal_link::Priority;
use cardinal_space::account::ContactRecord;
use cardinal_space::files::{self, Content, FileKind, Files, Kinds};
use cardinal_space::{relationship, NodeId, Space, SpaceId, SpaceOp, ROOT};
use serde_json::{json, Value as Json};

use crate::core::now_ms;
use crate::daemon::Daemon;
use crate::fetch::{blob_ref, Fetcher};

/// A relationship's folder, as the one folder shows it.
#[derive(Clone, Debug)]
pub struct Shown {
    /// The category folder it is in.
    pub category: String,
    /// Its folder's name: the petname, made unique in the category.
    pub name: String,
    /// Whose.
    pub contact: ContactRecord,
}

impl Shown {
    /// Its path in the one folder.
    pub fn path(&self) -> String {
        format!("{}/{}", self.category, self.name)
    }

    /// The contact's id, as the local interface names people.
    pub fn who(&self) -> String {
        hex::encode(&self.contact.identity[..8])
    }
}

/// A name as a folder can carry it.
pub fn folder_name(name: &str) -> String {
    let n: String = name
        .trim()
        .chars()
        .map(|c| if c == '/' || c == '\0' { '-' } else { c })
        .collect();
    if n.is_empty() || n == "." || n == ".." {
        format!("_{n}")
    } else {
        n
    }
}

/// Each relationship the one folder lists. Refused contacts are left out, and
/// a second of one name in a category is `name (2)`, in an order that does not
/// change while the contacts do not.
pub fn relationships(d: &Daemon) -> Vec<Shown> {
    let mut contacts: Vec<ContactRecord> = d
        .core()
        .contacts()
        .into_iter()
        .filter(|c| !c.refused)
        .collect();
    let key = |c: &ContactRecord| {
        (
            folder_name(&c.category),
            folder_name(&c.petname),
            c.identity,
        )
    };
    contacts.sort_by_key(key);
    let mut taken = HashSet::new();
    contacts
        .into_iter()
        .map(|c| {
            let category = folder_name(&c.category);
            let base = folder_name(&c.petname);
            let mut name = base.clone();
            let mut n = 2;
            while !taken.insert((category.clone(), name.clone())) {
                name = format!("{base} ({n})");
                n += 1;
            }
            Shown {
                category,
                name,
                contact: c,
            }
        })
        .collect()
}

/// The categories with someone in them, in order.
pub fn categories(shown: &[Shown]) -> Vec<String> {
    let mut c: Vec<String> = shown.iter().map(|s| s.category.clone()).collect();
    c.sort();
    c.dedup();
    c
}

fn split_ext(name: &str) -> (&str, &str) {
    match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    }
}

/// The files space's root entries as the one folder names them: one whose name
/// a category has is `name (2)`, or the next number free.
fn root_entries(files: &Files, categories: &[String]) -> Vec<(String, files::DirEntry)> {
    let entries = files.list(&ROOT);
    let mut taken: HashSet<String> = entries
        .iter()
        .map(|e| e.name.clone())
        .chain(categories.iter().cloned())
        .collect();
    entries
        .into_iter()
        .map(|e| {
            if !categories.contains(&e.name) {
                return (e.name.clone(), e);
            }
            let (stem, ext) = split_ext(&e.name);
            let mut n = 2;
            let mut name = format!("{stem} ({n}){ext}");
            while taken.contains(&name) {
                n += 1;
                name = format!("{stem} ({n}){ext}");
            }
            taken.insert(name.clone());
            (name, e)
        })
        .collect()
}

/// Where a path of the one folder leads.
// One is made per request, so its size costs nothing worth a box.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum Place {
    /// A category's folder.
    Category(String),
    /// Something in a space: the person's files, or a shared folder.
    In(At),
}

/// A place in a space.
#[derive(Clone, Debug)]
pub struct At {
    /// The space.
    pub space: SpaceId,
    /// The node; the root for the one folder's root or a relationship's folder.
    pub node: NodeId,
    /// For a copy of a file in conflict, the version it shows.
    pub version: Option<EntryId>,
    /// What it is.
    pub kind: FileKind,
    /// The relationship, in a shared folder.
    pub shared: Option<Shown>,
}

impl At {
    fn is_folder(&self) -> bool {
        self.kind == FileKind::Folder && self.version.is_none()
    }

    /// A relationship's own folder, which only renaming the contact moves.
    fn is_relationship(&self) -> bool {
        self.shared.is_some() && self.node == ROOT
    }

    /// Whose devices may hold what is here besides this person's.
    fn contact(&self) -> Option<[u8; 32]> {
        self.shared.as_ref().map(|s| s.contact.identity)
    }
}

fn open<'a>(core: &'a crate::core::Core, space: &SpaceId) -> anyhow::Result<&'a Space> {
    core.spaces
        .get(space)
        .and_then(|h| h.space.as_ref())
        .ok_or_else(|| anyhow::anyhow!("that space is not here yet"))
}

fn walk(
    files: &Files,
    from: NodeId,
    parts: &[&str],
) -> Option<(NodeId, Option<EntryId>, FileKind)> {
    let mut cur = (from, None, FileKind::Folder);
    for p in parts {
        if cur.1.is_some() || cur.2 != FileKind::Folder {
            return None;
        }
        let e = files.list(&cur.0).into_iter().find(|e| e.name == *p)?;
        cur = (e.node, e.conflict_version, e.kind);
    }
    Some(cur)
}

fn parts(path: &str) -> Vec<&str> {
    path.split('/').filter(|p| !p.is_empty()).collect()
}

/// What a path of the one folder names.
pub fn resolve(d: &Daemon, path: &str) -> anyhow::Result<Place> {
    let parts = parts(path);
    let shown = relationships(d);
    let cats = categories(&shown);
    let core = d.core();
    let mine = core
        .files_id()
        .ok_or_else(|| anyhow::anyhow!("your files are not here yet"))?;
    let missing = || anyhow::anyhow!("{path} is not in your files");
    let Some(first) = parts.first() else {
        return Ok(Place::In(At {
            space: mine,
            node: ROOT,
            version: None,
            kind: FileKind::Folder,
            shared: None,
        }));
    };
    if cats.iter().any(|c| c == first) {
        let Some(second) = parts.get(1) else {
            return Ok(Place::Category(first.to_string()));
        };
        let rel = shown
            .into_iter()
            .find(|s| s.category == *first && s.name == *second)
            .ok_or_else(missing)?;
        let files = Files::new(open(&core, &rel.contact.space)?);
        let (node, version, kind) = walk(&files, ROOT, &parts[2..]).ok_or_else(missing)?;
        return Ok(Place::In(At {
            space: rel.contact.space,
            node,
            version,
            kind,
            shared: Some(rel),
        }));
    }
    let files = Files::new(open(&core, &mine)?);
    let (_, top) = root_entries(&files, &cats)
        .into_iter()
        .find(|(n, _)| n == first)
        .ok_or_else(missing)?;
    let (node, version, kind) = if parts.len() == 1 {
        (top.node, top.conflict_version, top.kind)
    } else if top.conflict_version.is_none() && top.kind == FileKind::Folder {
        walk(&files, top.node, &parts[1..]).ok_or_else(missing)?
    } else {
        return Err(missing());
    };
    Ok(Place::In(At {
        space: mine,
        node,
        version,
        kind,
        shared: None,
    }))
}

/// A folder of the one folder: the person's files, a category, or a shared
/// folder, folders first.
pub fn list(d: &Daemon, path: &str) -> anyhow::Result<Json> {
    let place = resolve(d, path)?;
    let shown = relationships(d);
    let mut found: Vec<(bool, Json)> = Vec::new();
    match &place {
        Place::Category(c) => {
            for s in shown.iter().filter(|s| &s.category == c) {
                found.push((
                    false,
                    json!({"name": s.name, "folder": true, "who": s.who()}),
                ));
            }
        }
        Place::In(at) => {
            anyhow::ensure!(at.is_folder(), "{path} is not a folder");
            let cats = categories(&shown);
            let core = d.core();
            let me = core.identity.as_ref().map(|i| i.id());
            let files = Files::new(open(&core, &at.space)?);
            let at_root = at.shared.is_none() && at.node == ROOT;
            if at_root {
                for c in &cats {
                    found.push((false, json!({"name": c, "folder": true, "category": true})));
                }
            }
            let entries = if at_root {
                root_entries(&files, &cats)
            } else {
                files
                    .list(&at.node)
                    .into_iter()
                    .map(|e| (e.name.clone(), e))
                    .collect()
            };
            for (name, e) in entries {
                let is_folder = e.kind == FileKind::Folder;
                let versions = files.content(&e.node);
                let shown = match e.conflict_version {
                    Some(v) => versions.iter().find(|x| x.entry == v),
                    None => versions.last(),
                };
                let mut entry = json!({
                    "name": name,
                    "folder": is_folder,
                    "size": shown.and_then(|v| v.content.as_ref()).map(|c| c.size()),
                    "time": shown.and_then(|v| v.time),
                    "versions": versions.len(),
                });
                if at.shared.is_some() {
                    entry["mine"] = json!(shown.is_some_and(|v| Some(v.author) == me));
                }
                found.push((!is_folder, entry));
            }
        }
    }
    found.sort_by_key(|(is_file, e)| (*is_file, e["name"].as_str().map(str::to_lowercase)));
    let files: Vec<Json> = found.into_iter().map(|(_, e)| e).collect();
    // What the folder is, so a window need not work it out.
    let place = match &place {
        Place::Category(c) => json!({"kind": "category", "name": c}),
        Place::In(At {
            shared: Some(s), ..
        }) => json!({"kind": "shared", "who": s.who(), "name": s.contact.petname}),
        Place::In(_) => json!({"kind": "mine"}),
    };
    Ok(json!({"path": path, "place": place, "files": files}))
}

/// The folder and the last name of a path.
fn split_last(path: &str) -> anyhow::Result<(String, String)> {
    let p = parts(path);
    let (last, rest) = p
        .split_last()
        .ok_or_else(|| anyhow::anyhow!("name something in the folder"))?;
    name_ok(last)?;
    Ok((rest.join("/"), last.to_string()))
}

fn name_ok(name: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        !name.is_empty() && name != "." && name != ".." && !name.contains('/'),
        "{name:?} cannot be a name"
    );
    Ok(())
}

/// The folder at `path`, to put something in.
fn folder(d: &Daemon, path: &str) -> anyhow::Result<At> {
    match resolve(d, path)? {
        Place::In(at) if at.is_folder() => Ok(at),
        Place::Category(c) => {
            anyhow::bail!("{c} lists the people you know: put files in the folder of one of them")
        }
        Place::In(_) => anyhow::bail!("{path} is not a folder"),
    }
}

/// Refuses a name at the one folder's root that a category has.
fn not_a_category(d: &Daemon, at: &At, name: &str) -> anyhow::Result<()> {
    if at.shared.is_none() && at.node == ROOT {
        let cats = categories(&relationships(d));
        anyhow::ensure!(
            !cats.iter().any(|c| c == name),
            "{name} is where the people you know are listed; choose another name"
        );
    }
    Ok(())
}

fn kinds(d: &Daemon, space: &SpaceId) -> anyhow::Result<Kinds> {
    let core = d.core();
    Ok(Kinds::of(open(&core, space)?.profile()))
}

/// The key content is stored under in a space now.
fn secret(d: &Daemon, space: &SpaceId) -> anyhow::Result<ConvergenceSecret> {
    let core = d.core();
    let sp = open(&core, space)?;
    let key = sp.current_epoch().and_then(|e| sp.keyring().get(&e));
    let key = key.ok_or_else(|| anyhow::anyhow!("that space has no key yet"))?;
    Ok(ConvergenceSecret::from_epoch_key(key.bytes()))
}

/// Writes `ops` and says the node each one created, in order.
fn write_creating(
    d: &Arc<Daemon>,
    space: &SpaceId,
    ops: Vec<SpaceOp>,
) -> anyhow::Result<Vec<NodeId>> {
    let batches: Vec<usize> = crate::core::split_ops(ops.clone())
        .iter()
        .map(Vec::len)
        .collect();
    let ids = d.write_and_push(space, ops)?;
    anyhow::ensure!(
        ids.len() == batches.len(),
        "the write was split unexpectedly"
    );
    Ok(ids
        .iter()
        .zip(batches)
        .flat_map(|(id, n)| (0..n).map(move |i| files::created_node(id, i)))
        .collect())
}

/// Makes a folder.
pub fn mkdir(d: &Arc<Daemon>, path: &str) -> anyhow::Result<Json> {
    let (parent, name) = split_last(path)?;
    let at = folder(d, &parent)?;
    not_a_category(d, &at, &name)?;
    let op = kinds(d, &at.space)?.create_folder(at.node, &name);
    d.write_and_push(&at.space, vec![op])?;
    Ok(json!({"path": path}))
}

/// Removes a file or a folder. Removing a copy of a file in conflict keeps
/// the main version, which settles the conflict (`profiles.md#files`).
pub fn remove(d: &Arc<Daemon>, path: &str) -> anyhow::Result<Json> {
    let at = match resolve(d, path)? {
        Place::In(at) if at.is_relationship() => {
            anyhow::bail!("{path} is what you share with them, and goes only if you refuse them")
        }
        Place::In(at) if at.node != ROOT => at,
        _ => anyhow::bail!("{path} cannot be removed"),
    };
    let op = match at.version {
        Some(_) => {
            let core = d.core();
            let files = Files::new(open(&core, &at.space)?);
            let main = files.content(&at.node).pop().and_then(|v| v.content);
            let main = main.ok_or_else(|| anyhow::anyhow!("{path} has no version to keep"))?;
            files::set_content(at.node, &main)
        }
        None => SpaceOp::delete(at.node),
    };
    d.write_and_push(&at.space, vec![op])?;
    Ok(json!({"path": path}))
}

/// Whether `node` is `ancestor` or inside it.
fn within(d: &Daemon, space: &SpaceId, node: NodeId, ancestor: NodeId) -> bool {
    let core = d.core();
    let Ok(sp) = open(&core, space) else {
        return false;
    };
    let st = sp.state();
    let mut cur = node;
    for _ in 0..4096 {
        if cur == ancestor {
            return true;
        }
        if cur == ROOT {
            return false;
        }
        match st.node(&cur) {
            Some(n) => cur = n.parent,
            None => return false,
        }
    }
    false
}

/// Moves or renames. A relationship's folder moves only by renaming the
/// contact or listing them under another category; between spaces, the
/// content is copied and the original removed.
pub async fn move_to(d: &Arc<Daemon>, from: &str, to: &str) -> anyhow::Result<Json> {
    let src = resolve(d, from)?;
    let (parent, name) = split_last(to)?;
    let dst = resolve(d, &parent)?;
    match (src, dst) {
        (Place::In(s), Place::Category(c)) if s.is_relationship() => {
            let shown = s.shared.expect("shared");
            if name != shown.name {
                crate::contacts::rename(d, &shown.who(), &name)?;
            }
            if c != shown.category {
                crate::contacts::set_category(d, &shown.who(), &c)?;
            }
        }
        (Place::In(s), Place::In(p)) if s.node != ROOT && s.version.is_none() && p.is_folder() => {
            not_a_category(d, &p, &name)?;
            if s.space == p.space {
                anyhow::ensure!(
                    !within(d, &p.space, p.node, s.node),
                    "a folder cannot go inside itself"
                );
                d.write_and_push(&s.space, vec![SpaceOp::mv(s.node, p.node, &name)])?;
            } else {
                copy_into(d, &s, &p, &name).await?;
                d.write_and_push(&s.space, vec![SpaceOp::delete(s.node)])?;
            }
        }
        _ => anyhow::bail!("{from} cannot be moved there"),
    }
    Ok(json!({"path": to}))
}

/// What is copied: a tree read out of a space.
enum Item {
    Folder(String, Vec<Item>),
    File {
        name: String,
        content: Content,
        mode: u32,
        mtime: Option<u64>,
    },
    Link(String, String),
}

fn read_tree(files: &Files, node: NodeId, version: Option<EntryId>, name: &str) -> Option<Item> {
    let st = files.stat(&node)?;
    Some(match st.kind {
        FileKind::Folder => Item::Folder(
            name.to_owned(),
            files
                .list(&node)
                .into_iter()
                .filter_map(|e| read_tree(files, e.node, e.conflict_version, &e.name))
                .collect(),
        ),
        FileKind::File => {
            let versions = files.content(&node);
            let v = match version {
                Some(at) => versions.into_iter().find(|v| v.entry == at),
                None => versions.into_iter().last(),
            };
            Item::File {
                name: name.to_owned(),
                content: v.and_then(|v| v.content)?,
                mode: st.mode.unwrap_or(0o644) as u32,
                mtime: st.mtime,
            }
        }
        FileKind::Link => Item::Link(name.to_owned(), st.target.unwrap_or_default()),
        FileKind::Other => return None,
    })
}

/// Content as another space stores it: read, fetching what is not here, and
/// written again under that space's key.
fn transfer(
    d: &Arc<Daemon>,
    content: &Content,
    from: Option<[u8; 32]>,
    secret: &ConvergenceSecret,
    always_blob: bool,
) -> anyhow::Result<Content> {
    let blob = match content {
        Content::Inline(b) if !always_blob => return Ok(Content::Inline(b.clone())),
        Content::Inline(b) => {
            return encode(
                &mut std::io::Cursor::new(b.clone()),
                secret,
                d,
                b.len() as u64,
                true,
            )
        }
        Content::Blob(b) => b.clone(),
    };
    let fetcher = match from {
        Some(who) => Fetcher::from_contact(d, Priority::Interactive, who),
        None => Fetcher::new(d, Priority::Interactive),
    };
    let mut reader = BlobReader::new(&*d.store, &fetcher, blob_ref(&blob));
    let size = blob.size;
    let mut source = Reading {
        reader: &mut reader,
        at: 0,
        size,
    };
    encode(&mut source, secret, d, size, always_blob)
}

/// A blob read front to back, failing if part of it cannot be fetched.
struct Reading<'a, 'b, S: cardinal_blob::ObjectStore, F: cardinal_blob::Fetch> {
    reader: &'a mut BlobReader<'b, S, F>,
    at: u64,
    size: u64,
}

impl<S: cardinal_blob::ObjectStore, F: cardinal_blob::Fetch> Read for Reading<'_, '_, S, F> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.at >= self.size {
            return Ok(0);
        }
        let n = self.reader.read_at(self.at, buf)?;
        if n == 0 {
            return Err(std::io::Error::other(
                "part of it could not be fetched; try again when a device that has it is on",
            ));
        }
        self.at += n as u64;
        Ok(n)
    }
}

/// Stores what `source` gives as content: inline when it is small enough,
/// unless a blob is needed.
fn encode(
    source: &mut dyn Read,
    secret: &ConvergenceSecret,
    d: &Daemon,
    size: u64,
    always_blob: bool,
) -> anyhow::Result<Content> {
    if !always_blob && size < INLINE_LIMIT as u64 {
        let mut b = Vec::new();
        source.read_to_end(&mut b)?;
        return Ok(Content::Inline(b));
    }
    let mut w = BlobWriter::new(secret, &*d.store);
    std::io::copy(source, &mut w)?;
    let (r, _) = w.finish()?;
    Ok(Content::Blob(files::BlobRef {
        id: r.id,
        key: r.key,
        size: r.size,
        levels: r.levels,
    }))
}

/// Writes a tree into a folder, a level at a time, since a folder's node is
/// known only once the entry that creates it is written.
fn write_tree(
    d: &Arc<Daemon>,
    space: &SpaceId,
    parent: NodeId,
    items: Vec<Item>,
    mut store: impl FnMut(&Content) -> anyhow::Result<Content>,
) -> anyhow::Result<()> {
    let kinds = kinds(d, space)?;
    let mut level: Vec<(NodeId, Vec<Item>)> = vec![(parent, items)];
    while !level.is_empty() {
        let mut ops = Vec::new();
        let mut below: Vec<Option<Vec<Item>>> = Vec::new();
        for (p, items) in level {
            for item in items {
                match item {
                    Item::Folder(name, kids) => {
                        ops.push(kinds.create_folder(p, &name));
                        below.push(Some(kids));
                    }
                    Item::File {
                        name,
                        content,
                        mode,
                        mtime,
                    } => {
                        let c = store(&content)?;
                        ops.push(kinds.create_file(p, &name, &c, mode, mtime));
                        below.push(None);
                    }
                    Item::Link(name, target) => {
                        ops.push(kinds.create_link(p, &name, &target));
                        below.push(None);
                    }
                }
            }
        }
        if ops.is_empty() {
            break;
        }
        let made = write_creating(d, space, ops)?;
        level = made
            .into_iter()
            .zip(below)
            .filter_map(|(node, kids)| kids.map(|k| (node, k)))
            .collect();
    }
    Ok(())
}

/// Copies what `src` names into the folder `dst`, as `name`.
async fn copy_into(d: &Arc<Daemon>, src: &At, dst: &At, name: &str) -> anyhow::Result<()> {
    let item = {
        let core = d.core();
        let files = Files::new(open(&core, &src.space)?);
        read_tree(&files, src.node, src.version, name)
            .ok_or_else(|| anyhow::anyhow!("there is nothing to copy there"))?
    };
    let same = src.space == dst.space;
    let secret = secret(d, &dst.space)?;
    let (d, from, space, parent) = (d.clone(), src.contact(), dst.space, dst.node);
    tokio::task::spawn_blocking(move || {
        write_tree(&d, &space, parent, vec![item], |c| {
            if same {
                Ok(c.clone())
            } else {
                transfer(&d, c, from, &secret, false)
            }
        })
    })
    .await?
}

/// Copies a file or folder into the folder `to`, keeping its name.
pub async fn copy(d: &Arc<Daemon>, from: &str, to: &str) -> anyhow::Result<Json> {
    let src = match resolve(d, from)? {
        Place::In(at) => at,
        Place::Category(_) => anyhow::bail!("{from} lists people, and is no folder to copy"),
    };
    let name = parts(from)
        .last()
        .map(|n| n.to_string())
        .ok_or_else(|| anyhow::anyhow!("name something to copy"))?;
    let dst = folder(d, to)?;
    not_a_category(d, &dst, &name)?;
    if src.space == dst.space && src.version.is_none() && src.kind == FileKind::Folder {
        anyhow::ensure!(
            !within(d, &dst.space, dst.node, src.node),
            "a folder cannot be copied into itself"
        );
    }
    copy_into(d, &src, &dst, &name).await?;
    Ok(json!({"path": format!("{}/{name}", to.trim_end_matches('/'))}))
}

fn read_local(path: &Path, name: &str) -> anyhow::Result<LocalItem> {
    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
    if meta.is_dir() {
        let mut kids = Vec::new();
        for e in std::fs::read_dir(path)? {
            let e = e?;
            let n = e.file_name().to_string_lossy().into_owned();
            kids.push(read_local(&e.path(), &n)?);
        }
        Ok(LocalItem::Folder(name.to_owned(), kids))
    } else if meta.file_type().is_symlink() {
        let target = std::fs::read_link(path)?.to_string_lossy().into_owned();
        Ok(LocalItem::Link(name.to_owned(), target))
    } else {
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|t| t.as_millis() as u64);
        Ok(LocalItem::File(
            name.to_owned(),
            path.to_path_buf(),
            mode_of(&meta),
            mtime,
        ))
    }
}

#[cfg(unix)]
fn mode_of(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o7777
}

/// Windows has no mode bits: a file is read-only or not.
#[cfg(not(unix))]
fn mode_of(meta: &std::fs::Metadata) -> u32 {
    if meta.permissions().readonly() {
        0o444
    } else {
        0o644
    }
}

/// A file or folder on this device's disk, to put in the one folder.
enum LocalItem {
    Folder(String, Vec<LocalItem>),
    File(String, PathBuf, u32, Option<u64>),
    Link(String, String),
}

/// Copies a file or folder from this device's disk into the folder `to`.
pub async fn put(d: &Arc<Daemon>, from: &str, to: &str) -> anyhow::Result<Json> {
    let path = PathBuf::from(from);
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .ok_or_else(|| anyhow::anyhow!("{from} has no name"))?;
    let dst = folder(d, to)?;
    not_a_category(d, &dst, &name)?;
    let secret = secret(d, &dst.space)?;
    let d = d.clone();
    tokio::task::spawn_blocking(move || {
        let local = read_local(&path, &name)?;
        // Read now, so a file that cannot be read stops it before anything
        // is written.
        fn items(l: LocalItem, d: &Daemon, secret: &ConvergenceSecret) -> anyhow::Result<Item> {
            Ok(match l {
                LocalItem::Folder(n, kids) => Item::Folder(
                    n,
                    kids.into_iter()
                        .map(|k| items(k, d, secret))
                        .collect::<anyhow::Result<_>>()?,
                ),
                LocalItem::File(n, p, mode, mtime) => {
                    let mut f = std::fs::File::open(&p)
                        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", p.display()))?;
                    let size = f.metadata()?.len();
                    Item::File {
                        name: n,
                        content: encode(&mut f, secret, d, size, false)?,
                        mode,
                        mtime,
                    }
                }
                LocalItem::Link(n, t) => Item::Link(n, t),
            })
        }
        let item = items(local, &d, &secret)?;
        write_tree(&d, &dst.space, dst.node, vec![item], |c| Ok(c.clone()))?;
        Ok(json!({"path": format!("{}/{name}", dst_path_hint(&dst))}))
    })
    .await?
}

fn dst_path_hint(at: &At) -> String {
    at.shared.as_ref().map(Shown::path).unwrap_or_default()
}

/// Makes the file at `path` hold what `from` on this device's disk holds: a
/// new version of it if it is there, and a new file if not. This is how an
/// application that edited a copy saves it back.
pub async fn write(d: &Arc<Daemon>, from: &str, path: &str) -> anyhow::Result<Json> {
    let (parent, name) = split_last(path)?;
    let dst = folder(d, &parent)?;
    let existing = {
        let core = d.core();
        let files = Files::new(open(&core, &dst.space)?);
        files
            .list(&dst.node)
            .into_iter()
            .find(|e| e.name == name && e.conflict_version.is_none())
            .map(|e| (e.node, e.kind))
    };
    let secret = secret(d, &dst.space)?;
    let (d2, local) = (d.clone(), PathBuf::from(from));
    let content = tokio::task::spawn_blocking(move || -> anyhow::Result<Content> {
        let mut f = std::fs::File::open(&local)
            .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", local.display()))?;
        let size = f.metadata()?.len();
        encode(&mut f, &secret, &d2, size, false)
    })
    .await??;
    match existing {
        Some((node, FileKind::File)) => {
            let ops = vec![
                files::set_content(node, &content),
                files::set_mtime(node, now_ms()),
            ];
            d.write_and_push(&dst.space, ops)?;
        }
        Some(_) => anyhow::bail!("{path} is a folder"),
        None => {
            not_a_category(d, &dst, &name)?;
            let op =
                kinds(d, &dst.space)?.create_file(dst.node, &name, &content, 0o644, Some(now_ms()));
            d.write_and_push(&dst.space, vec![op])?;
        }
    }
    Ok(json!({"path": path}))
}

/// Writes a file of the one folder to `to` on this device's disk, fetching
/// what is not here.
pub async fn save(d: &Arc<Daemon>, path: &str, to: &str) -> anyhow::Result<Json> {
    let at = match resolve(d, path)? {
        Place::In(at) if at.kind == FileKind::File => at,
        _ => anyhow::bail!("{path} is not a file; save one file at a time"),
    };
    let content = {
        let core = d.core();
        let files = Files::new(open(&core, &at.space)?);
        let versions = files.content(&at.node);
        let v = match at.version {
            Some(e) => versions.into_iter().find(|v| v.entry == e),
            None => versions.into_iter().last(),
        };
        v.and_then(|v| v.content)
            .ok_or_else(|| anyhow::anyhow!("{path} has nothing in it to save"))?
    };
    let to = PathBuf::from(to);
    let (d, from, written) = (d.clone(), at.contact(), to.clone());
    let size = tokio::task::spawn_blocking(move || -> anyhow::Result<u64> {
        crate::contacts::write_new(&written, |out| match &content {
            Content::Inline(b) => {
                std::io::Write::write_all(out, b)?;
                Ok(b.len() as u64)
            }
            Content::Blob(b) => {
                let fetcher = match from {
                    Some(who) => Fetcher::from_contact(&d, Priority::Interactive, who),
                    None => Fetcher::new(&d, Priority::Interactive),
                };
                let mut reader = BlobReader::new(&*d.store, &fetcher, blob_ref(b));
                crate::contacts::write_out(&mut reader, out)
            }
        })
    })
    .await??;
    Ok(json!({"path": to, "size": size}))
}

/// Puts files of the one folder in the folder shared with `who`. With
/// `text`, they go in a message too, whose entry creates them in the folder
/// (`profiles.md#shared-folder`); folders are only put in the folder.
pub async fn share(
    d: &Arc<Daemon>,
    who: &str,
    paths: &[String],
    text: Option<&str>,
) -> anyhow::Result<Json> {
    let contact = crate::contacts::listed(d, who)?;
    let shown = relationships(d)
        .into_iter()
        .find(|s| s.contact.identity == contact.identity)
        .ok_or_else(|| anyhow::anyhow!("{who} is not listed"))?;
    let dst = At {
        space: contact.space,
        node: ROOT,
        version: None,
        kind: FileKind::Folder,
        shared: Some(shown.clone()),
    };
    let mut sources = Vec::new();
    for p in paths {
        match resolve(d, p)? {
            Place::In(at) if !(at.shared.is_none() && at.node == ROOT) => sources.push((p, at)),
            _ => anyhow::bail!("{p} cannot be shared"),
        }
    }
    anyhow::ensure!(!sources.is_empty(), "name something to share");
    let text = text.map(str::trim).filter(|t| !t.is_empty());
    let Some(text) = text else {
        for (p, at) in &sources {
            let name = parts(p).last().map(|n| n.to_string()).unwrap_or_default();
            copy_into(d, at, &dst, &name).await?;
        }
        return Ok(json!({"path": shown.path(), "message": false}));
    };
    // The files of a message are blobs, whatever their size.
    let secret = secret(d, &contact.space)?;
    let mut attachments = Vec::new();
    for (p, at) in &sources {
        let name = parts(p).last().map(|n| n.to_string()).unwrap_or_default();
        if at.kind != FileKind::File {
            copy_into(d, at, &dst, &name).await?;
            continue;
        }
        let content = {
            let core = d.core();
            let files = Files::new(open(&core, &at.space)?);
            let versions = files.content(&at.node);
            let v = match at.version {
                Some(e) => versions.into_iter().find(|v| v.entry == e),
                None => versions.into_iter().last(),
            };
            v.and_then(|v| v.content)
                .ok_or_else(|| anyhow::anyhow!("{p} has nothing in it to share"))?
        };
        let (d2, from, secret) = (d.clone(), at.contact(), secret.clone());
        let blob =
            tokio::task::spawn_blocking(move || transfer(&d2, &content, from, &secret, true))
                .await??;
        let Content::Blob(blob) = blob else {
            anyhow::bail!("{p} could not be stored to send");
        };
        attachments.push(relationship::Attachment {
            media_type: crate::contacts::media_type(&name).to_owned(),
            name,
            blob: blob.to_record(),
        });
    }
    let conversation = {
        let core = d.core();
        relationship::conversation(open(&core, &contact.space)?)
    };
    let conversation = conversation.ok_or_else(|| anyhow::anyhow!("that space is not open yet"))?;
    let mut ops = vec![relationship::create_with(
        conversation,
        text,
        None,
        &attachments,
    )];
    ops.extend(relationship::shared_files(&attachments, Some(now_ms())));
    d.write_and_push(&contact.space, ops)?;
    Ok(json!({"path": shown.path(), "message": true}))
}
