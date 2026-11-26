//! The one folder (`profiles.md#one-folder-for-everything-guidance`). Its root
//! is the person's files space; beside that space's own entries it holds a
//! folder for each category of relationship, and in each, every relationship's
//! shared folder under the contact's petname, and `Groups`, with each group's
//! shared folder under the group's name (D88). Every window, and every way of
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
use cardinal_space::{group, relationship, NodeId, Space, SpaceId, SpaceOp, ROOT};
#[cfg(any(test, debug_assertions, feature = "by-name"))]
use serde_json::{json, Value as Json};

use crate::api::short_id;
use crate::api::table::{self as api, File, FilesReply};
use crate::api::PathReply;
use crate::core::now_ms;
use crate::daemon::Daemon;
use crate::fetch::{blob_ref, Fetcher, Others};

/// The category folder of the person's groups. It is the groups' own: a
/// contact category of that name is shown as `Groups (2)` (D88).
pub const GROUPS: &str = "Groups";

/// What a group with no name is shown as.
const NO_NAME: &str = "Group";

/// A shared folder, as the one folder shows it.
#[derive(Clone, Debug)]
pub struct Shown {
    /// The category folder it is in.
    pub category: String,
    /// Its folder's name: the petname or the group's name, made unique in
    /// the category.
    pub name: String,
    /// The space whose folder it is.
    pub space: SpaceId,
    /// Whose it is besides this person's.
    pub whose: Whose,
}

/// Whose a shared folder is besides this person's.
#[derive(Clone, Debug)]
pub enum Whose {
    /// A relationship's: the contact's.
    Contact(Box<ContactRecord>),
    /// A group's, by its name as the group gives it.
    Group(String),
}

impl Shown {
    /// Its path in the one folder.
    pub fn path(&self) -> String {
        format!("{}/{}", self.category, self.name)
    }

    /// The contact, for a relationship's folder.
    pub fn contact(&self) -> Option<&ContactRecord> {
        match &self.whose {
            Whose::Contact(c) => Some(c.as_ref()),
            Whose::Group(_) => None,
        }
    }

    /// The group, for a group's folder.
    pub fn group(&self) -> Option<SpaceId> {
        matches!(self.whose, Whose::Group(_)).then_some(self.space)
    }

    /// The contact's id, as the local interface names people.
    pub fn who(&self) -> Option<String> {
        self.who_id().map(hex::encode)
    }

    /// The contact's id as the local interface names people: its first
    /// eight bytes.
    pub fn who_id(&self) -> Option<[u8; 8]> {
        self.contact().map(|c| short_id(&c.identity))
    }

    /// What the folder is named after: the contact's petname, or the
    /// group's name.
    pub fn called(&self) -> &str {
        match &self.whose {
            Whose::Contact(c) => &c.petname,
            Whose::Group(n) => n,
        }
    }

    /// Whose devices may hold what is in it besides this person's.
    pub fn others(&self) -> Others {
        match &self.whose {
            Whose::Contact(c) => Others::Contact(c.identity),
            Whose::Group(_) => Others::Group(self.space),
        }
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

/// `name` made unique among `taken`: `name (2)`, or the next number free,
/// before any extension.
fn numbered(name: &str, taken: &HashSet<String>) -> String {
    let (stem, ext) = split_ext(name);
    let mut n = 2;
    let mut out = format!("{stem} ({n}){ext}");
    while taken.contains(&out) {
        n += 1;
        out = format!("{stem} ({n}){ext}");
    }
    out
}

/// Each shared folder the one folder lists: every relationship's, by
/// category, refused contacts left out, and every group's the person is in,
/// in `Groups`. A second of one name in a category is `name (2)`, in an order
/// that does not change while the contacts and groups do not.
pub fn relationships(d: &Daemon) -> Vec<Shown> {
    let core = d.core();
    let mut contacts: Vec<ContactRecord> = core
        .contacts()
        .into_iter()
        // a recovery's relationship is no contact (`guardians.rs`)
        .filter(|c| !c.refused && c.recovery_of.is_none())
        .collect();
    let key = |c: &ContactRecord| {
        (
            folder_name(&c.category),
            folder_name(&c.petname),
            c.identity,
        )
    };
    contacts.sort_by_key(key);
    let groups = groups_in(&core);
    drop(core);
    // A contact category named as the groups' is shown as a files space
    // entry of that name would be.
    let typed: HashSet<String> = contacts.iter().map(|c| folder_name(&c.category)).collect();
    let mut aside = typed.clone();
    aside.insert(GROUPS.to_owned());
    let moved_aside = numbered(GROUPS, &aside);
    let category_of = |c: &ContactRecord| {
        let typed = folder_name(&c.category);
        if typed == GROUPS {
            moved_aside.clone()
        } else {
            typed
        }
    };
    let mut taken = HashSet::new();
    let mut unique = |category: &str, base: &str| {
        let mut name = base.to_owned();
        let mut n = 2;
        while !taken.insert((category.to_owned(), name.clone())) {
            name = format!("{base} ({n})");
            n += 1;
        }
        name
    };
    let mut out: Vec<Shown> = contacts
        .into_iter()
        .map(|c| {
            let category = category_of(&c);
            let name = unique(&category, &folder_name(&c.petname));
            Shown {
                category,
                name,
                space: c.space,
                whose: Whose::Contact(Box::new(c)),
            }
        })
        .collect();
    for (_, name, space) in groups {
        let base = match name.trim() {
            "" => NO_NAME.to_owned(),
            n => folder_name(n),
        };
        out.push(Shown {
            category: GROUPS.to_owned(),
            name: unique(GROUPS, &base),
            space,
            whose: Whose::Group(name),
        });
    }
    out
}

/// The groups that have a folder: those the person joined and has not left,
/// that another does not stand in place of here, and that have not ended
/// with nothing in their place. Each with the id it was first made with, as
/// far back as this device knows, and its name; sorted, so that two of one
/// name are numbered the same way across a succession.
fn groups_in(core: &crate::core::Core) -> Vec<(SpaceId, String, SpaceId)> {
    let Some(me) = core.me() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, h) in &core.spaces {
        let Some(sp) = h.space.as_ref().filter(|s| s.profile() == group::GROUP) else {
            continue;
        };
        if sp.has_left(&me)
            || sp.role_of(&me).is_none()
            || !core.is_joined(id)
            || core.is_superseded(id)
            || core.succession_news(id).0.is_some()
        {
            continue;
        }
        let mut first = *id;
        let mut at = sp;
        for _ in 0..64 {
            let Some(before) = at.succeeds() else {
                break;
            };
            first = before;
            match core.spaces.get(&before).and_then(|h| h.space.as_ref()) {
                Some(b) => at = b,
                None => break,
            }
        }
        out.push((first, group::name(sp), *id));
    }
    out.sort_by(|a, b| {
        let name = |x: &(SpaceId, String, SpaceId)| match x.1.trim() {
            "" => NO_NAME.to_owned(),
            n => folder_name(n),
        };
        (name(a), a.0).cmp(&(name(b), b.0))
    });
    out
}

/// The categories with someone in them, in order.
pub fn categories(shown: &[Shown]) -> Vec<String> {
    let mut c: Vec<String> = shown.iter().map(|s| s.category.clone()).collect();
    c.sort();
    c.dedup();
    c
}

/// The category a contact is listed under for the category folder shown
/// as `shown`: the category typed for those already in it, or the name
/// itself.
fn category_typed(shown: &[Shown], folder: &str) -> String {
    shown
        .iter()
        .filter(|s| s.category == folder)
        .find_map(|s| s.contact().map(|c| c.category.clone()))
        .unwrap_or_else(|| folder.to_owned())
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
            let name = numbered(&e.name, &taken);
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

    /// A relationship's or a group's own folder, which only renaming the
    /// contact or the group moves.
    fn is_relationship(&self) -> bool {
        self.shared.is_some() && self.node == ROOT
    }

    /// Whose devices may hold what is here besides this person's.
    pub(crate) fn others(&self) -> Option<Others> {
        self.shared.as_ref().map(Shown::others)
    }
}

pub(crate) fn open<'a>(core: &'a crate::core::Core, space: &SpaceId) -> anyhow::Result<&'a Space> {
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

pub(crate) fn parts(path: &str) -> Vec<&str> {
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
        let files = Files::new(open(&core, &rel.space)?);
        let (node, version, kind) = walk(&files, ROOT, &parts[2..]).ok_or_else(missing)?;
        return Ok(Place::In(At {
            space: rel.space,
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
/// folder, folders first. All of it: the request's page is cut from it.
pub fn list(d: &Daemon, path: &str) -> anyhow::Result<FilesReply> {
    let place = resolve(d, path)?;
    let shown = relationships(d);
    // each with whether it is a file, folders first
    let mut found: Vec<(bool, File)> = Vec::new();
    match &place {
        Place::Category(c) => {
            for s in shown.iter().filter(|s| &s.category == c) {
                let group = s.group();
                found.push((
                    false,
                    File {
                        name: s.name.clone(),
                        folder: true,
                        group,
                        who: group.is_none().then(|| s.who_id()).flatten(),
                        added_by: None,
                        category: None,
                        mine: None,
                        size: None,
                        time: None,
                        versions: None,
                    },
                ));
            }
        }
        Place::In(at) => {
            anyhow::ensure!(at.is_folder(), "{path} is not a folder");
            let cats = categories(&shown);
            let core = d.core();
            let me = core.identity.as_ref().map(|i| i.id());
            let files = Files::new(open(&core, &at.space)?);
            // Who added a file, where it was someone else: by what this
            // person calls them.
            let contacts = core.contacts();
            let called = |who: &[u8; 32]| {
                contacts
                    .iter()
                    .find(|c| &c.identity == who)
                    .map(|c| c.petname.clone())
                    .unwrap_or_else(|| cardinal_space::account::short_key(who))
            };
            let at_root = at.shared.is_none() && at.node == ROOT;
            if at_root {
                for c in &cats {
                    found.push((
                        false,
                        File {
                            name: c.clone(),
                            folder: true,
                            category: Some(true),
                            added_by: None,
                            mine: None,
                            size: None,
                            time: None,
                            versions: None,
                            who: None,
                            group: None,
                        },
                    ));
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
                let first = versions.first().filter(|v| Some(v.author) != me);
                found.push((
                    !is_folder,
                    File {
                        name,
                        folder: is_folder,
                        size: shown.and_then(|v| v.content.as_ref()).map(|c| c.size()),
                        time: shown.and_then(|v| v.time),
                        versions: Some(versions.len() as u64),
                        mine: at
                            .shared
                            .is_some()
                            .then(|| shown.is_some_and(|v| Some(v.author) == me)),
                        added_by: first.map(|v| called(&v.author)),
                        category: None,
                        who: None,
                        group: None,
                    },
                ));
            }
        }
    }
    found.sort_by_cached_key(|(is_file, e)| (*is_file, e.name.to_lowercase()));
    let files: Vec<File> = found.into_iter().map(|(_, e)| e).collect();
    // What the folder is, so a window need not work it out.
    let place = match &place {
        Place::Category(c) => api::Place {
            kind: "category".into(),
            name: Some(c.clone()),
            who: None,
            group: None,
        },
        Place::In(At {
            shared: Some(s), ..
        }) => {
            let group = s.group();
            api::Place {
                kind: "shared".into(),
                name: Some(s.called().to_owned()),
                group,
                who: group.is_none().then(|| s.who_id()).flatten(),
            }
        }
        Place::In(_) => api::Place {
            kind: "mine".into(),
            name: None,
            who: None,
            group: None,
        },
    };
    Ok(FilesReply {
        files,
        path: path.to_owned(),
        place,
        more: false,
        next: None,
    })
}

/// The folder and the last name of a path.
pub(crate) fn split_last(path: &str) -> anyhow::Result<(String, String)> {
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
pub(crate) fn folder(d: &Daemon, path: &str) -> anyhow::Result<At> {
    match resolve(d, path)? {
        Place::In(at) if at.is_folder() => Ok(at),
        Place::Category(c) => {
            anyhow::bail!("{c} lists shared folders: put files in one of them")
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
            "{name} is where shared folders are listed; choose another name"
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
pub fn mkdir(d: &Arc<Daemon>, path: &str) -> anyhow::Result<PathReply> {
    let (parent, name) = split_last(path)?;
    let at = folder(d, &parent)?;
    not_a_category(d, &at, &name)?;
    let op = kinds(d, &at.space)?.create_folder(at.node, &name);
    d.write_and_push(&at.space, vec![op])?;
    Ok(PathReply {
        path: path.to_string(),
    })
}

/// Removes a file or a folder. Removing a copy of a file in conflict keeps
/// the main version, which settles the conflict (`profiles.md#files`).
pub fn remove(d: &Arc<Daemon>, path: &str) -> anyhow::Result<PathReply> {
    let at = match resolve(d, path)? {
        Place::In(at) if at.is_relationship() => match at.shared.and_then(|s| s.group()) {
            Some(_) => anyhow::bail!("{path} is the group's, and goes only if you leave it"),
            None => {
                anyhow::bail!(
                    "{path} is what you share with them, and goes only if you refuse them"
                )
            }
        },
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
    Ok(PathReply {
        path: path.to_string(),
    })
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
pub async fn move_to(d: &Arc<Daemon>, from: &str, to: &str) -> anyhow::Result<PathReply> {
    let src = resolve(d, from)?;
    let (parent, name) = split_last(to)?;
    let dst = resolve(d, &parent)?;
    match (src, dst) {
        (Place::In(s), Place::Category(c)) if s.is_relationship() => {
            let shown = s.shared.expect("shared");
            rename_shared(d, &shown, &c, &name)?;
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
    Ok(PathReply {
        path: to.to_string(),
    })
}

/// Renames a shared folder, or moves it to the category folder `category`:
/// renaming a relationship's renames the contact and moving it lists them
/// there; renaming a group's renames the group, which only its owner and
/// its admins may do (D88).
pub fn rename_shared(
    d: &Arc<Daemon>,
    shown: &Shown,
    category: &str,
    name: &str,
) -> Result<(), Refused> {
    let into_groups = category == GROUPS;
    match shown.group() {
        Some(g) => {
            if !into_groups {
                return Err(Refused::NotPermitted(anyhow::anyhow!(
                    "{} is a group's folder, and stays in {GROUPS}",
                    shown.name
                )));
            }
            if name != shown.name {
                crate::groups::rename(d, &g, name)?;
            }
        }
        None => {
            if into_groups && shown.category != GROUPS {
                return Err(Refused::NotPermitted(anyhow::anyhow!(
                    "{GROUPS} holds your groups' folders; a contact's goes in another"
                )));
            }
            let who = shown.who().unwrap_or_default();
            if name != shown.name {
                crate::contacts::rename(d, crate::api::Ref::Typed(&who), name)
                    .map_err(Refused::Other)?;
            }
            if category != shown.category {
                // `Groups (2)` lists them under `Groups` again
                let typed = category_typed(&relationships(d), category);
                crate::contacts::set_category(d, crate::api::Ref::Typed(&who), &typed)
                    .map_err(Refused::NotPermitted)?;
            }
        }
    }
    Ok(())
}

/// Why a rename of a shared folder was refused, as a folder says it.
#[derive(Debug)]
pub enum Refused {
    /// This person may not: a group's name is its admins'.
    Denied(anyhow::Error),
    /// Nobody may: the folder does not go there.
    NotPermitted(anyhow::Error),
    /// Anything else, such as a name already taken.
    Other(anyhow::Error),
}

impl From<Refused> for anyhow::Error {
    fn from(r: Refused) -> anyhow::Error {
        match r {
            Refused::Denied(e) | Refused::NotPermitted(e) | Refused::Other(e) => e,
        }
    }
}

impl From<crate::groups::NotAdmin> for Refused {
    fn from(e: crate::groups::NotAdmin) -> Refused {
        match e {
            crate::groups::NotAdmin::No(e) => Refused::Denied(e),
            crate::groups::NotAdmin::Other(e) => Refused::Other(e),
        }
    }
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
    from: Option<Others>,
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
    let fetcher = Fetcher::from_others(d, Priority::Interactive, from);
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
    let (d, from, space, parent) = (d.clone(), src.others(), dst.space, dst.node);
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
pub async fn copy(d: &Arc<Daemon>, from: &str, to: &str) -> anyhow::Result<PathReply> {
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
    Ok(PathReply {
        path: format!("{}/{name}", to.trim_end_matches('/')),
    })
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
pub async fn put(d: &Arc<Daemon>, from: &str, to: &str) -> anyhow::Result<PathReply> {
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
        Ok(PathReply {
            path: format!("{}/{name}", dst_path_hint(&dst)),
        })
    })
    .await?
}

fn dst_path_hint(at: &At) -> String {
    at.shared.as_ref().map(Shown::path).unwrap_or_default()
}

/// Makes the file at `path` hold what `from` on this device's disk holds: a
/// new version of it if it is there, and a new file if not. This is how an
/// application that edited a copy saves it back.
pub async fn write(d: &Arc<Daemon>, from: &str, path: &str) -> anyhow::Result<PathReply> {
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
    Ok(PathReply {
        path: path.to_string(),
    })
}

/// Writes a file of the one folder to `to` on this device's disk, fetching
/// what is not here: the version shown, or with `version` an earlier one,
/// numbered as `history` numbers them, which changes nothing in the folder.
pub async fn save(
    d: &Arc<Daemon>,
    path: &str,
    to: &str,
    version: Option<u64>,
) -> anyhow::Result<crate::api::SaveReply> {
    let at = match resolve(d, path)? {
        Place::In(at) if at.kind == FileKind::File => at,
        _ => anyhow::bail!("{path} is not a file; save one file at a time"),
    };
    let content = {
        let core = d.core();
        let sp = open(&core, &at.space)?;
        match version {
            Some(n) => crate::file_history::version_of(sp, &at.node, path, n)?,
            None => {
                let versions = Files::new(sp).content(&at.node);
                let v = match at.version {
                    Some(e) => versions.into_iter().find(|v| v.entry == e),
                    None => versions.into_iter().last(),
                };
                v.and_then(|v| v.content)
                    .ok_or_else(|| anyhow::anyhow!("{path} has nothing in it to save"))?
            }
        }
    };
    let shown = to.to_owned();
    let to = PathBuf::from(to);
    let (d, from, written) = (d.clone(), at.others(), to.clone());
    let size = tokio::task::spawn_blocking(move || -> anyhow::Result<u64> {
        crate::contacts::write_new(&written, |out| match &content {
            Content::Inline(b) => {
                std::io::Write::write_all(out, b)?;
                Ok(b.len() as u64)
            }
            Content::Blob(b) => {
                let fetcher = Fetcher::from_others(&d, Priority::Interactive, from);
                let mut reader = BlobReader::new(&*d.store, &fetcher, blob_ref(b));
                crate::contacts::write_out(&mut reader, out)
            }
        })
    })
    .await??;
    Ok(crate::api::SaveReply { path: shown, size })
}

/// Puts files of the one folder in the folder shared with `who`, a contact
/// or a group, or with `group`. With `text`, they go in a message too, in
/// that relationship's or that group's conversation, whose entry creates
/// them in the folder (`profiles.md#shared-folder`); folders are only put
/// in the folder. A name that is both a contact's and a group's is refused:
/// which is meant is the person's to say, by `group` or an id.
pub async fn share(
    d: &Arc<Daemon>,
    who: Option<&str>,
    group: Option<&str>,
    paths: &[String],
    text: Option<&str>,
) -> anyhow::Result<crate::api::ShareReply> {
    let space = match (who, group) {
        (Some(_), Some(_)) => anyhow::bail!("share with a contact or a group, not both"),
        (None, None) => anyhow::bail!("name whom to share with: a contact or a group"),
        (None, Some(g)) => crate::groups::joined_group(d, g)?.0,
        (Some(w), None) => {
            let contact = crate::contacts::find(d, w);
            let in_group = crate::groups::joined_group(d, w);
            match (contact, in_group) {
                (Ok(_), Ok(_)) => anyhow::bail!(
                    "{w} is both a contact and a group: say which, with --group for the \
                     group, or by the contact's id"
                ),
                (Ok(_), Err(_)) => crate::contacts::listed(d, w)?.space,
                (Err(_), Ok((g, _))) => g,
                (Err(e), Err(_)) => return Err(e),
            }
        }
    };
    let shown = relationships(d)
        .into_iter()
        .find(|s| s.space == space)
        .ok_or_else(|| anyhow::anyhow!("that folder is not listed"))?;
    if let Some(g) = shown.group() {
        crate::groups::ready_to_write(d, &g)?;
    }
    let dst = At {
        space,
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
        return Ok(crate::api::ShareReply {
            path: shown.path(),
            message: false,
        });
    };
    // The files of a message are blobs, whatever their size.
    let secret = secret(d, &space)?;
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
        let (d2, from, secret) = (d.clone(), at.others(), secret.clone());
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
        relationship::conversation(open(&core, &space)?)
    };
    let conversation = conversation.ok_or_else(|| anyhow::anyhow!("that space is not open yet"))?;
    let mut ops = vec![relationship::create_with(
        conversation,
        text,
        None,
        &attachments,
    )];
    ops.extend(relationship::shared_files(&attachments, Some(now_ms())));
    d.write_and_push(&space, ops)?;
    Ok(crate::api::ShareReply {
        path: shown.path(),
        message: true,
    })
}

// ---- The handlers as they were by name ----
//
// What main had, whole, kept only to show that the typed handlers send the
// same bytes (`control::typed::answering`, `api/same_bytes.rs`), and to
// measure the two. They go with the way by name.

/// `list` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
pub fn list_by_name(d: &Daemon, path: &str) -> anyhow::Result<Json> {
    let place = resolve(d, path)?;
    let shown = relationships(d);
    let mut found: Vec<(bool, Json)> = Vec::new();
    match &place {
        Place::Category(c) => {
            for s in shown.iter().filter(|s| &s.category == c) {
                let mut e = json!({"name": s.name, "folder": true});
                match s.group() {
                    Some(g) => e["group"] = json!(hex::encode(g)),
                    None => e["who"] = json!(s.who()),
                }
                found.push((false, e));
            }
        }
        Place::In(at) => {
            anyhow::ensure!(at.is_folder(), "{path} is not a folder");
            let cats = categories(&shown);
            let core = d.core();
            let me = core.identity.as_ref().map(|i| i.id());
            let files = Files::new(open(&core, &at.space)?);
            // Who added a file, where it was someone else: by what this
            // person calls them.
            let called = |who: &[u8; 32]| {
                core.contacts()
                    .into_iter()
                    .find(|c| &c.identity == who)
                    .map(|c| c.petname)
                    .unwrap_or_else(|| cardinal_space::account::short_key(who))
            };
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
                if let Some(first) = versions.first().filter(|v| Some(v.author) != me) {
                    entry["added_by"] = json!(called(&first.author));
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
        }) => match s.group() {
            Some(g) => json!({"kind": "shared", "group": hex::encode(g), "name": s.called()}),
            None => json!({"kind": "shared", "who": s.who(), "name": s.called()}),
        },
        Place::In(_) => json!({"kind": "mine"}),
    };
    Ok(json!({"path": path, "place": place, "files": files}))
}

/// `mkdir` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
pub fn mkdir_by_name(d: &Arc<Daemon>, path: &str) -> anyhow::Result<Json> {
    let (parent, name) = split_last(path)?;
    let at = folder(d, &parent)?;
    not_a_category(d, &at, &name)?;
    let op = kinds(d, &at.space)?.create_folder(at.node, &name);
    d.write_and_push(&at.space, vec![op])?;
    Ok(json!({"path": path}))
}

/// `remove` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
pub fn remove_by_name(d: &Arc<Daemon>, path: &str) -> anyhow::Result<Json> {
    let at = match resolve(d, path)? {
        Place::In(at) if at.is_relationship() => match at.shared.and_then(|s| s.group()) {
            Some(_) => anyhow::bail!("{path} is the group's, and goes only if you leave it"),
            None => {
                anyhow::bail!(
                    "{path} is what you share with them, and goes only if you refuse them"
                )
            }
        },
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

/// `move_to` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
pub async fn move_to_by_name(d: &Arc<Daemon>, from: &str, to: &str) -> anyhow::Result<Json> {
    let src = resolve(d, from)?;
    let (parent, name) = split_last(to)?;
    let dst = resolve(d, &parent)?;
    match (src, dst) {
        (Place::In(s), Place::Category(c)) if s.is_relationship() => {
            let shown = s.shared.expect("shared");
            rename_shared(d, &shown, &c, &name)?;
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

/// `copy` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
pub async fn copy_by_name(d: &Arc<Daemon>, from: &str, to: &str) -> anyhow::Result<Json> {
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

/// `put` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
pub async fn put_by_name(d: &Arc<Daemon>, from: &str, to: &str) -> anyhow::Result<Json> {
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

/// `write` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
pub async fn write_by_name(d: &Arc<Daemon>, from: &str, path: &str) -> anyhow::Result<Json> {
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

/// `save` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
pub async fn save_by_name(
    d: &Arc<Daemon>,
    path: &str,
    to: &str,
    version: Option<u64>,
) -> anyhow::Result<Json> {
    let at = match resolve(d, path)? {
        Place::In(at) if at.kind == FileKind::File => at,
        _ => anyhow::bail!("{path} is not a file; save one file at a time"),
    };
    let content = {
        let core = d.core();
        let sp = open(&core, &at.space)?;
        match version {
            Some(n) => crate::file_history::version_of(sp, &at.node, path, n)?,
            None => {
                let versions = Files::new(sp).content(&at.node);
                let v = match at.version {
                    Some(e) => versions.into_iter().find(|v| v.entry == e),
                    None => versions.into_iter().last(),
                };
                v.and_then(|v| v.content)
                    .ok_or_else(|| anyhow::anyhow!("{path} has nothing in it to save"))?
            }
        }
    };
    let to = PathBuf::from(to);
    let (d, from, written) = (d.clone(), at.others(), to.clone());
    let size = tokio::task::spawn_blocking(move || -> anyhow::Result<u64> {
        crate::contacts::write_new(&written, |out| match &content {
            Content::Inline(b) => {
                std::io::Write::write_all(out, b)?;
                Ok(b.len() as u64)
            }
            Content::Blob(b) => {
                let fetcher = Fetcher::from_others(&d, Priority::Interactive, from);
                let mut reader = BlobReader::new(&*d.store, &fetcher, blob_ref(b));
                crate::contacts::write_out(&mut reader, out)
            }
        })
    })
    .await??;
    Ok(json!({"path": to, "size": size}))
}

/// `share` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
pub async fn share_by_name(
    d: &Arc<Daemon>,
    who: Option<&str>,
    group: Option<&str>,
    paths: &[String],
    text: Option<&str>,
) -> anyhow::Result<Json> {
    let space = match (who, group) {
        (Some(_), Some(_)) => anyhow::bail!("share with a contact or a group, not both"),
        (None, None) => anyhow::bail!("name whom to share with: a contact or a group"),
        (None, Some(g)) => crate::groups::joined_group_by_name(d, g)?.0,
        (Some(w), None) => {
            let contact = crate::contacts::find_by_name(d, w);
            let in_group = crate::groups::joined_group_by_name(d, w);
            match (contact, in_group) {
                (Ok(_), Ok(_)) => anyhow::bail!(
                    "{w} is both a contact and a group: say which, with --group for the \
                     group, or by the contact's id"
                ),
                (Ok(_), Err(_)) => crate::contacts::listed_by_name(d, w)?.space,
                (Err(_), Ok((g, _))) => g,
                (Err(e), Err(_)) => return Err(e),
            }
        }
    };
    let shown = relationships(d)
        .into_iter()
        .find(|s| s.space == space)
        .ok_or_else(|| anyhow::anyhow!("that folder is not listed"))?;
    if let Some(g) = shown.group() {
        crate::groups::ready_to_write(d, &g)?;
    }
    let dst = At {
        space,
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
    let secret = secret(d, &space)?;
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
        let (d2, from, secret) = (d.clone(), at.others(), secret.clone());
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
        relationship::conversation(open(&core, &space)?)
    };
    let conversation = conversation.ok_or_else(|| anyhow::anyhow!("that space is not open yet"))?;
    let mut ops = vec![relationship::create_with(
        conversation,
        text,
        None,
        &attachments,
    )];
    ops.extend(relationship::shared_files(&attachments, Some(now_ms())));
    d.write_and_push(&space, ops)?;
    Ok(json!({"path": shown.path(), "message": true}))
}
