//! The one folder as one mount (`onefolder.rs`): the person's files at the
//! root, and beside them a folder for each category of relationship holding
//! each relationship's shared folder.
//!
//! Each space is a part with its own tree and committer, as a mount of that
//! one space would have. A part's inodes start at a base of its own, so a
//! request goes to its part by the inode alone and the part answers it as
//! before. Only the root, the category folders, and moves between parts are
//! answered here.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

use cardinal_space::SpaceId;
use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, Request, TimeOrNow,
};
use libc::{EEXIST, EINVAL, EISDIR, ENOENT, EPERM, EXDEV};

use super::commit;
use super::ops::CardinalFs;
use super::tree::{Inval, Kind, Snapshot, Tree, ROOT_INO};
use crate::daemon::Daemon;
use crate::onefolder::{self, Shown};

/// How many bits of an inode number are a part's own.
const PART_BITS: u32 = 40;
/// The part number of the category folders, which are no space's.
const CATEGORIES: u64 = (1 << 23) - 1;
const TTL: Duration = Duration::from_secs(1);

fn part_of(ino: u64) -> u64 {
    ino >> PART_BITS
}

fn category_ino(index: usize) -> u64 {
    (CATEGORIES << PART_BITS) + index as u64 + 1
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// One space of the mount.
pub struct Part {
    /// The space.
    pub space: SpaceId,
    /// Its tree.
    pub tree: Arc<Mutex<Tree>>,
    fs: CardinalFs,
    /// Stops its committer.
    pub stop: Arc<AtomicBool>,
    /// Its committer.
    pub scheduler: Option<std::thread::JoinHandle<()>>,
}

impl Part {
    /// Opens a part numbered `number` for `space`, shared with `contact`
    /// if it is a relationship's.
    pub fn open(d: &Arc<Daemon>, number: u64, space: SpaceId, contact: Option<[u8; 32]>) -> Part {
        let (staging, local) = match number {
            0 => (d.paths.staging(), d.paths.local()),
            _ => {
                let name = hex::encode(&space[..8]);
                (
                    d.paths.staging().join("shared").join(&name),
                    d.paths.home.join("local-shared").join(&name),
                )
            }
        };
        let _ = std::fs::create_dir_all(&staging);
        let tree = Tree::with_base(staging, local, number << PART_BITS);
        let tree = Arc::new(Mutex::new(tree));
        {
            let core = d.core();
            let h = core.spaces.get(&space);
            let mut t = lock(&tree);
            if let Some(sp) = h.and_then(|h| h.space.as_ref()) {
                let snap =
                    Snapshot::take(sp, h.map(|h| h.version).unwrap_or(0), &core.device_names());
                t.apply(&snap);
            }
            // What `.cardinalignore` keeps on this device (`local.rs`).
            t.load_local(h.and_then(|h| h.space.as_ref()));
            t.ignore_seen = Some(t.ignore_texts(&d.store));
        }
        let fs = CardinalFs::shared_with(d.clone(), tree.clone(), contact);
        let stop = Arc::new(AtomicBool::new(false));
        let scheduler = commit::spawn_scheduler(d.clone(), tree.clone(), space, stop.clone());
        Part {
            space,
            tree,
            fs,
            stop,
            scheduler: Some(scheduler),
        }
    }
}

/// Every part of the mount, and how the folders between them are named.
pub struct Parts {
    /// Parts by number; 0 is the person's own files.
    pub parts: HashMap<u64, Part>,
    by_space: HashMap<SpaceId, u64>,
    next: u64,
    /// Category folders by index, kept while mounted so inodes stay put.
    categories: Vec<String>,
    /// What is listed now: the category's index, the folder's name, the part.
    listed: Vec<(usize, String, u64)>,
}

impl Parts {
    /// The person's own files, as part 0.
    pub fn new(mine: Part) -> Parts {
        let space = mine.space;
        Parts {
            parts: HashMap::from([(0, mine)]),
            by_space: HashMap::from([(space, 0)]),
            next: 1,
            categories: Vec::new(),
            listed: Vec::new(),
        }
    }

    /// The categories someone is listed in, with their indexes.
    fn shown_categories(&self) -> Vec<(usize, &str)> {
        let mut out: Vec<(usize, &str)> = self
            .categories
            .iter()
            .enumerate()
            .filter(|(i, _)| self.listed.iter().any(|(c, _, _)| c == i))
            .map(|(i, c)| (i, c.as_str()))
            .collect();
        out.sort_by(|a, b| a.1.cmp(b.1));
        out
    }

    fn category_named(&self, name: &str) -> Option<usize> {
        self.shown_categories()
            .into_iter()
            .find(|(_, c)| *c == name)
            .map(|(i, _)| i)
    }

    fn category_of(&self, ino: u64) -> Option<usize> {
        let i = (ino - (CATEGORIES << PART_BITS)).checked_sub(1)? as usize;
        self.shown_categories()
            .into_iter()
            .any(|(c, _)| c == i)
            .then_some(i)
    }

    fn listed_in(&self, category: usize, name: &str) -> Option<u64> {
        self.listed
            .iter()
            .find(|(c, n, _)| *c == category && n == name)
            .map(|(_, _, p)| *p)
    }

    /// The root's own entries, as the one folder names them: one whose name
    /// a category has shows as `name (2)` (`onefolder.rs`).
    fn root_names(&self) -> Vec<(String, String)> {
        let cats: Vec<String> = self
            .shown_categories()
            .into_iter()
            .map(|(_, c)| c.to_owned())
            .collect();
        let t = lock(&self.parts[&0].tree);
        let names: Vec<String> = t.inodes[&t.root].children.keys().cloned().collect();
        let mut taken: std::collections::HashSet<String> =
            names.iter().cloned().chain(cats.iter().cloned()).collect();
        names
            .into_iter()
            .map(|n| {
                if !cats.contains(&n) {
                    return (n.clone(), n);
                }
                let (stem, ext) = match n.rfind('.') {
                    Some(i) if i > 0 => (&n[..i], &n[i..]),
                    _ => (n.as_str(), ""),
                };
                let mut k = 2;
                let mut shown = format!("{stem} ({k}){ext}");
                while taken.contains(&shown) {
                    k += 1;
                    shown = format!("{stem} ({k}){ext}");
                }
                taken.insert(shown.clone());
                (shown, n)
            })
            .collect()
    }

    /// The root entry a name shows, if it is one of the person's own.
    fn own_at_root(&self, shown: &str) -> Option<String> {
        if self.category_named(shown).is_some() {
            return None;
        }
        self.root_names()
            .into_iter()
            .find(|(s, _)| s == shown)
            .map(|(_, n)| n)
    }

    /// Whether a new entry at the root may take this name.
    fn free_at_root(&self, name: &str) -> bool {
        self.category_named(name).is_none() && !self.root_names().iter().any(|(s, _)| s == name)
    }
}

/// Brings the parts in line with the relationships listed now: new ones are
/// opened, and the kernel is told of names that went or came.
pub fn update(d: &Arc<Daemon>, parts: &Mutex<Parts>) -> Vec<Inval> {
    let shown = onefolder::relationships(d);
    let missing: Vec<Shown> = {
        let g = lock(parts);
        shown
            .iter()
            .filter(|s| !g.by_space.contains_key(&s.contact.space))
            .filter(|s| {
                d.core()
                    .spaces
                    .get(&s.contact.space)
                    .is_some_and(|h| h.space.is_some())
            })
            .cloned()
            .collect()
    };
    // Opened without the lock: it reads the space and starts a committer.
    let mut opened = Vec::new();
    for s in missing {
        let number = {
            let mut g = lock(parts);
            let n = g.next;
            g.next += 1;
            n
        };
        tracing::debug!(
            "showing {} at {}",
            hex::encode(&s.contact.space[..4]),
            s.path()
        );
        opened.push((
            number,
            Part::open(d, number, s.contact.space, Some(s.contact.identity)),
        ));
    }
    let mut g = lock(parts);
    for (number, p) in opened {
        g.by_space.insert(p.space, number);
        g.parts.insert(number, p);
    }
    let before_root: Vec<String> = g.root_names().into_iter().map(|(s, _)| s).collect();
    let before_cats: Vec<String> = g
        .shown_categories()
        .into_iter()
        .map(|(_, c)| c.to_owned())
        .collect();
    let before = std::mem::take(&mut g.listed);
    let mut listed = Vec::new();
    for s in &shown {
        let Some(&part) = g.by_space.get(&s.contact.space) else {
            continue;
        };
        let index = match g.categories.iter().position(|c| *c == s.category) {
            Some(i) => i,
            None => {
                g.categories.push(s.category.clone());
                g.categories.len() - 1
            }
        };
        listed.push((index, s.name.clone(), part));
    }
    g.listed = listed;
    let mut invals = Vec::new();
    for (c, name, part) in &before {
        if !g.listed.contains(&(*c, name.clone(), *part)) {
            invals.push(Inval::Entry(category_ino(*c), name.clone()));
        }
    }
    let after_cats: Vec<String> = g
        .shown_categories()
        .into_iter()
        .map(|(_, c)| c.to_owned())
        .collect();
    if after_cats != before_cats {
        for name in before_root.into_iter().chain(before_cats).chain(after_cats) {
            invals.push(Inval::Entry(ROOT_INO, name));
        }
    }
    invals
}

/// The one folder's filesystem.
pub struct OneFs {
    d: Arc<Daemon>,
    parts: Arc<Mutex<Parts>>,
    made: SystemTime,
}

impl OneFs {
    /// The mount's filesystem over `parts`.
    pub fn new(d: Arc<Daemon>, parts: Arc<Mutex<Parts>>) -> OneFs {
        OneFs {
            d,
            parts,
            made: SystemTime::now(),
        }
    }

    fn category_attr(&self, ino: u64, owner: (u32, u32)) -> FileAttr {
        FileAttr {
            ino,
            size: 4096,
            blocks: 8,
            atime: self.made,
            mtime: self.made,
            ctime: self.made,
            crtime: self.made,
            kind: FileType::Directory,
            // Writable, since renaming someone's folder renames them; what
            // else is asked of it is refused here.
            perm: 0o755,
            nlink: 2,
            uid: owner.0,
            gid: owner.1,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }
}

fn name_str(name: &OsStr) -> Option<&str> {
    std::str::from_utf8(name.as_bytes()).ok()
}

/// Sends a request to the part an inode belongs to.
macro_rules! route {
    ($self:ident, $ino:expr, $reply:ident, |$fs:ident| $call:expr) => {{
        let mut g = lock(&$self.parts);
        match g.parts.get_mut(&part_of($ino)) {
            Some(p) => {
                let $fs = &mut p.fs;
                $call
            }
            None => $reply.error(ENOENT),
        }
    }};
}

impl Filesystem for OneFs {
    fn lookup(&mut self, req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let Some(n) = name_str(name) else {
            return reply.error(ENOENT);
        };
        let mut g = lock(&self.parts);
        if parent == ROOT_INO {
            if let Some(i) = g.category_named(n) {
                let owner = g.parts.get(&0).map(|p| p.fs.owner()).unwrap_or_default();
                return reply.entry(&TTL, &self.category_attr(category_ino(i), owner), 0);
            }
            let Some(own) = g.own_at_root(n) else {
                return reply.error(ENOENT);
            };
            let p = g.parts.get_mut(&0).expect("mine");
            return p.fs.lookup(req, parent, OsStr::new(&own), reply);
        }
        if part_of(parent) == CATEGORIES {
            let part = g.category_of(parent).and_then(|c| g.listed_in(c, n));
            return match part.and_then(|p| g.parts.get_mut(&p)) {
                Some(p) => p.fs.root_entry(reply),
                None => reply.error(ENOENT),
            };
        }
        match g.parts.get_mut(&part_of(parent)) {
            Some(p) => p.fs.lookup(req, parent, name, reply),
            None => reply.error(ENOENT),
        }
    }

    fn forget(&mut self, req: &Request<'_>, ino: u64, nlookup: u64) {
        if part_of(ino) == CATEGORIES {
            return;
        }
        let mut g = lock(&self.parts);
        if let Some(p) = g.parts.get_mut(&part_of(ino)) {
            p.fs.forget(req, ino, nlookup);
        }
    }

    fn getattr(&mut self, req: &Request<'_>, ino: u64, fh: Option<u64>, reply: ReplyAttr) {
        if part_of(ino) == CATEGORIES {
            let g = lock(&self.parts);
            if g.category_of(ino).is_none() {
                return reply.error(ENOENT);
            }
            let owner = g.parts.get(&0).map(|p| p.fs.owner()).unwrap_or_default();
            return reply.attr(&TTL, &self.category_attr(ino, owner));
        }
        route!(self, ino, reply, |fs| fs.getattr(req, ino, fh, reply))
    }

    fn setattr(
        &mut self,
        req: &Request<'_>,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        ctime: Option<SystemTime>,
        fh: Option<u64>,
        crtime: Option<SystemTime>,
        chgtime: Option<SystemTime>,
        bkuptime: Option<SystemTime>,
        flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        if part_of(ino) == CATEGORIES {
            return reply.error(EPERM);
        }
        route!(self, ino, reply, |fs| fs.setattr(
            req, ino, mode, uid, gid, size, atime, mtime, ctime, fh, crtime, chgtime, bkuptime,
            flags, reply
        ))
    }

    fn readlink(&mut self, req: &Request<'_>, ino: u64, reply: ReplyData) {
        route!(self, ino, reply, |fs| fs.readlink(req, ino, reply))
    }

    fn mknod(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
        rdev: u32,
        reply: ReplyEntry,
    ) {
        if let Err(e) = self.may_create(parent, name) {
            return reply.error(e);
        }
        route!(self, parent, reply, |fs| fs
            .mknod(req, parent, name, mode, umask, rdev, reply))
    }

    fn mkdir(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
        reply: ReplyEntry,
    ) {
        if let Err(e) = self.may_create(parent, name) {
            return reply.error(e);
        }
        route!(self, parent, reply, |fs| fs
            .mkdir(req, parent, name, mode, umask, reply))
    }

    fn unlink(&mut self, req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        match self.own_name(parent, name) {
            Ok(n) => route!(self, parent, reply, |fs| fs.unlink(
                req,
                parent,
                OsStr::new(&n),
                reply
            )),
            Err(e) => reply.error(e),
        }
    }

    fn rmdir(&mut self, req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        match self.own_name(parent, name) {
            Ok(n) => route!(self, parent, reply, |fs| fs.rmdir(
                req,
                parent,
                OsStr::new(&n),
                reply
            )),
            Err(e) => reply.error(e),
        }
    }

    fn symlink(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        link_name: &OsStr,
        target: &Path,
        reply: ReplyEntry,
    ) {
        if let Err(e) = self.may_create(parent, link_name) {
            return reply.error(e);
        }
        route!(self, parent, reply, |fs| fs
            .symlink(req, parent, link_name, target, reply))
    }

    fn rename(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        flags: u32,
        reply: ReplyEmpty,
    ) {
        let (Some(n), Some(nn)) = (name_str(name), name_str(newname)) else {
            return reply.error(EINVAL);
        };
        let (from, to) = (part_of(parent), part_of(newparent));
        if from == CATEGORIES || to == CATEGORIES {
            // Only a relationship's folder moves here, and only by renaming
            // the contact or listing them under another category.
            if from != to {
                return reply.error(EPERM);
            }
            return match self.rename_relationship(parent, n, newparent, nn) {
                Ok(()) => reply.ok(),
                Err(e) => reply.error(e),
            };
        }
        if from != to {
            // Between spaces content is copied: `mv` does that on EXDEV.
            return reply.error(EXDEV);
        }
        let n = match self.own_name(parent, name) {
            Ok(n) => n,
            Err(e) => return reply.error(e),
        };
        if newparent == ROOT_INO {
            let g = lock(&self.parts);
            if g.category_named(nn).is_some() {
                return reply.error(EEXIST);
            }
        }
        let nn = if newparent == ROOT_INO {
            lock(&self.parts)
                .own_at_root(nn)
                .unwrap_or_else(|| nn.to_owned())
        } else {
            nn.to_owned()
        };
        route!(self, parent, reply, |fs| fs.rename(
            req,
            parent,
            OsStr::new(&n),
            newparent,
            OsStr::new(&nn),
            flags,
            reply
        ))
    }

    fn link(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _newparent: u64,
        _newname: &OsStr,
        reply: ReplyEntry,
    ) {
        reply.error(EPERM);
    }

    fn open(&mut self, req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        if part_of(ino) == CATEGORIES {
            return reply.error(EISDIR);
        }
        route!(self, ino, reply, |fs| fs.open(req, ino, flags, reply))
    }

    fn create(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        if let Err(e) = self.may_create(parent, name) {
            return reply.error(e);
        }
        route!(self, parent, reply, |fs| fs
            .create(req, parent, name, mode, umask, flags, reply))
    }

    fn read(
        &mut self,
        req: &Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        flags: i32,
        lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        route!(self, ino, reply, |fs| fs
            .read(req, ino, fh, offset, size, flags, lock_owner, reply))
    }

    fn write(
        &mut self,
        req: &Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        write_flags: u32,
        flags: i32,
        lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        route!(self, ino, reply, |fs| fs.write(
            req,
            ino,
            fh,
            offset,
            data,
            write_flags,
            flags,
            lock_owner,
            reply
        ))
    }

    fn flush(&mut self, req: &Request<'_>, ino: u64, fh: u64, lo: u64, reply: ReplyEmpty) {
        if part_of(ino) == CATEGORIES {
            return reply.ok();
        }
        route!(self, ino, reply, |fs| fs.flush(req, ino, fh, lo, reply))
    }

    fn release(
        &mut self,
        req: &Request<'_>,
        ino: u64,
        fh: u64,
        flags: i32,
        lock_owner: Option<u64>,
        flush: bool,
        reply: ReplyEmpty,
    ) {
        route!(self, ino, reply, |fs| fs
            .release(req, ino, fh, flags, lock_owner, flush, reply))
    }

    fn fsync(&mut self, req: &Request<'_>, ino: u64, fh: u64, ds: bool, reply: ReplyEmpty) {
        route!(self, ino, reply, |fs| fs.fsync(req, ino, fh, ds, reply))
    }

    fn opendir(&mut self, req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        if part_of(ino) == CATEGORIES {
            return reply.opened(0, 0);
        }
        route!(self, ino, reply, |fs| fs.opendir(req, ino, flags, reply))
    }

    fn readdir(
        &mut self,
        req: &Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let g = lock(&self.parts);
        let entries: Vec<(u64, FileType, String)> = if ino == ROOT_INO {
            let mut e = vec![
                (ROOT_INO, FileType::Directory, ".".to_owned()),
                (ROOT_INO, FileType::Directory, "..".to_owned()),
            ];
            for (i, c) in g.shown_categories() {
                e.push((category_ino(i), FileType::Directory, c.to_owned()));
            }
            let names = g.root_names();
            let t = lock(&g.parts[&0].tree);
            let root = &t.inodes[&t.root];
            for (shown, own) in names {
                let Some(&c) = root.children.get(&own) else {
                    continue;
                };
                let k = match t.inodes.get(&c).map(|x| x.kind) {
                    Some(Kind::Dir) => FileType::Directory,
                    Some(Kind::Symlink) => FileType::Symlink,
                    Some(_) => FileType::RegularFile,
                    None => continue,
                };
                e.push((c, k, shown));
            }
            e
        } else if part_of(ino) == CATEGORIES {
            let Some(c) = g.category_of(ino) else {
                return reply.error(ENOENT);
            };
            let mut e = vec![
                (ino, FileType::Directory, ".".to_owned()),
                (ROOT_INO, FileType::Directory, "..".to_owned()),
            ];
            let mut people: Vec<&(usize, String, u64)> =
                g.listed.iter().filter(|(x, _, _)| *x == c).collect();
            people.sort_by(|a, b| a.1.cmp(&b.1));
            for (_, name, part) in people {
                if let Some(p) = g.parts.get(part) {
                    let root = lock(&p.tree).root;
                    e.push((root, FileType::Directory, name.clone()));
                }
            }
            e
        } else {
            drop(g);
            return route!(self, ino, reply, |fs| fs
                .readdir(req, ino, fh, offset, reply));
        };
        for (n, (i, k, name)) in entries.into_iter().enumerate().skip(offset.max(0) as usize) {
            if reply.add(i, (n + 1) as i64, k, &name) {
                break;
            }
        }
        reply.ok();
    }

    fn statfs(&mut self, req: &Request<'_>, _ino: u64, reply: ReplyStatfs) {
        route!(self, ROOT_INO, reply, |fs| fs.statfs(req, ROOT_INO, reply))
    }

    fn access(&mut self, req: &Request<'_>, ino: u64, mask: i32, reply: ReplyEmpty) {
        if part_of(ino) == CATEGORIES {
            let g = lock(&self.parts);
            return match g.category_of(ino) {
                Some(_) => reply.ok(),
                None => reply.error(ENOENT),
            };
        }
        route!(self, ino, reply, |fs| fs.access(req, ino, mask, reply))
    }
}

impl OneFs {
    /// Whether something new may be named `name` in `parent`: nothing new
    /// goes in a category, and a category's name is taken at the root.
    fn may_create(&self, parent: u64, name: &OsStr) -> Result<(), i32> {
        if part_of(parent) == CATEGORIES {
            return Err(EPERM);
        }
        if parent == ROOT_INO {
            let n = name_str(name).ok_or(EINVAL)?;
            if !lock(&self.parts).free_at_root(n) {
                return Err(EEXIST);
            }
        }
        Ok(())
    }

    /// The name a part knows an entry of `parent` by.
    fn own_name(&self, parent: u64, name: &OsStr) -> Result<String, i32> {
        let n = name_str(name).ok_or(ENOENT)?;
        if part_of(parent) == CATEGORIES {
            return Err(EPERM);
        }
        if parent == ROOT_INO {
            let g = lock(&self.parts);
            if g.category_named(n).is_some() {
                return Err(EPERM);
            }
            return g.own_at_root(n).ok_or(ENOENT);
        }
        Ok(n.to_owned())
    }

    /// Renames a relationship's folder: what the contact is called, or the
    /// category they are listed under.
    fn rename_relationship(
        &self,
        parent: u64,
        name: &str,
        newparent: u64,
        newname: &str,
    ) -> Result<(), i32> {
        let (who, category) = {
            let g = lock(&self.parts);
            let from = g.category_of(parent).ok_or(ENOENT)?;
            let to = g.category_of(newparent).ok_or(ENOENT)?;
            let part = g.listed_in(from, name).ok_or(ENOENT)?;
            if g.listed_in(to, newname).is_some_and(|p| p != part) {
                return Err(EEXIST);
            }
            let space = g.parts.get(&part).ok_or(ENOENT)?.space;
            (space, (from != to).then(|| g.categories[to].clone()))
        };
        let shown = onefolder::relationships(&self.d)
            .into_iter()
            .find(|s| s.contact.space == who)
            .ok_or(ENOENT)?;
        if newname != shown.name {
            crate::contacts::rename(&self.d, &shown.who(), newname).map_err(|e| {
                tracing::info!("cannot rename {}: {e:#}", shown.name);
                EEXIST
            })?;
        }
        if let Some(c) = category {
            crate::contacts::set_category(&self.d, &shown.who(), &c).map_err(|e| {
                tracing::info!("cannot move {}: {e:#}", shown.name);
                EPERM
            })?;
        }
        update(&self.d, &self.parts);
        Ok(())
    }
}
