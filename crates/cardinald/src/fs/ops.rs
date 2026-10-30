//! The FUSE filesystem over [`Tree`].

use std::collections::HashMap;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

use cardinal_blob::{BlobReader, FsStore};
use cardinal_space::files::Content;
use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, Request, TimeOrNow,
};
use libc::{c_int, EACCES, EEXIST, EINVAL, EIO, EISDIR, ENOENT, ENOTDIR, ENOTEMPTY, EPERM, EXDEV};

use super::local::IGNORE_FILE;
use super::tree::{Kind, Staged, Tree, ROOT_INO};
use crate::daemon::Daemon;
use crate::fetch::{blob_ref, Fetcher};

const TTL: Duration = Duration::from_secs(1);
const BLOCK: u64 = 4096;

type Reader = BlobReader<'static, Arc<FsStore>, Fetcher>;

struct Handle {
    ino: u64,
    write: bool,
    reader: Arc<Mutex<Option<Reader>>>,
}

/// The filesystem.
pub struct CardinalFs {
    pub(crate) d: Arc<Daemon>,
    pub(crate) tree: Arc<Mutex<Tree>>,
    fetcher: &'static Fetcher,
    handles: HashMap<u64, Handle>,
    next_fh: u64,
    uid: u32,
    gid: u32,
}

/// Logs a local I/O failure and returns its errno, so the application
/// reports the real cause ("No space left on device", not "I/O error").
fn errno(what: &str, e: std::io::Error) -> c_int {
    tracing::warn!("{what}: {e}");
    e.raw_os_error().unwrap_or(EIO)
}

fn lock(t: &Mutex<Tree>) -> MutexGuard<'_, Tree> {
    t.lock().unwrap_or_else(|e| e.into_inner())
}

fn name_str(name: &OsStr) -> Result<&str, c_int> {
    std::str::from_utf8(name.as_bytes()).map_err(|_| EINVAL)
}

impl CardinalFs {
    /// A filesystem over `tree`.
    pub fn new(d: Arc<Daemon>, tree: Arc<Mutex<Tree>>) -> CardinalFs {
        let fetcher: &'static Fetcher = Box::leak(Box::new(Fetcher::new(
            &d,
            cardinal_link::Priority::Interactive,
        )));
        CardinalFs {
            d,
            tree,
            fetcher,
            handles: HashMap::new(),
            next_fh: 1,
            // SAFETY: getuid and getgid cannot fail.
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        }
    }

    fn attr(&self, t: &Tree, ino: u64) -> Option<FileAttr> {
        let i = t.inodes.get(&ino)?;
        let kind = match i.kind {
            Kind::Dir => FileType::Directory,
            Kind::File | Kind::Conflict(_) => FileType::RegularFile,
            Kind::Symlink => FileType::Symlink,
        };
        let size = match i.kind {
            Kind::Dir => 4096,
            Kind::Symlink => i.target.len() as u64,
            _ => i.size,
        };
        Some(FileAttr {
            ino,
            size,
            blocks: size.div_ceil(512),
            atime: i.mtime,
            mtime: i.mtime,
            ctime: i.ctime,
            crtime: i.ctime,
            kind,
            perm: i.perm,
            nlink: if i.kind == Kind::Dir { 2 } else { 1 },
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: BLOCK as u32,
            flags: 0,
        })
    }

    /// Makes sure a file has staged content holding its current bytes.
    fn stage(&self, t: &mut Tree, ino: u64) -> Result<Arc<Staged>, c_int> {
        if let Some(s) = t.inodes.get(&ino).and_then(|i| i.staged.clone()) {
            return Ok(s);
        }
        let content = t.inodes.get(&ino).ok_or(ENOENT)?.content.clone();
        let st = t
            .new_staged()
            .map_err(|e| errno("cannot stage a change", e))?;
        match content {
            None => {}
            Some(Content::Inline(b)) => st
                .write_all_at(&b, 0)
                .map_err(|e| errno("cannot stage a change", e))?,
            Some(Content::Blob(r)) => {
                let mut rd = BlobReader::new(self.d.store.clone(), self.fetcher, blob_ref(&r));
                let mut buf = vec![0u8; 1 << 20];
                let mut off = 0u64;
                loop {
                    let n = rd.read_at(off, &mut buf).map_err(|e| {
                        tracing::warn!("cannot read {} to change it: {e}", t.path(ino));
                        EIO
                    })?;
                    if n == 0 {
                        break;
                    }
                    st.write_all_at(&buf[..n], off)
                        .map_err(|e| errno("cannot stage a change", e))?;
                    off += n as u64;
                }
            }
        }
        t.inodes.get_mut(&ino).ok_or(ENOENT)?.staged = Some(st.clone());
        Ok(st)
    }

    fn new_child(
        &mut self,
        parent: u64,
        name: &OsStr,
        kind: Kind,
        perm: u16,
    ) -> Result<(u64, FileAttr), c_int> {
        let name = name_str(name)?;
        let mut t = lock(&self.tree);
        let p = t.inodes.get(&parent).ok_or(ENOENT)?;
        if p.kind != Kind::Dir || p.parent == 0 {
            return Err(ENOTDIR);
        }
        if p.children.contains_key(name) {
            return Err(EEXIST);
        }
        let local = t.ignored(&self.d.store, parent, name, kind == Kind::Dir);
        let ino = t.alloc(kind);
        {
            let i = t.inodes.get_mut(&ino).expect("new");
            i.perm = perm;
            if kind == Kind::File {
                i.content = Some(Content::Inline(Vec::new()));
            }
            i.nlookup = 1;
            i.local = local;
        }
        t.attach(ino, parent, name);
        if local {
            if let Err(e) = make_local(&mut t, ino) {
                t.detach(ino);
                t.gc(ino);
                return Err(errno("cannot keep a file on this device", e));
            }
        }
        if let Some(p) = t.inodes.get_mut(&parent) {
            p.mtime = SystemTime::now();
        }
        if !local {
            t.touch();
        }
        let a = self.attr(&t, ino).expect("attr");
        Ok((ino, a))
    }

    fn open_handle(&mut self, ino: u64, write: bool) -> u64 {
        let fh = self.next_fh;
        self.next_fh += 1;
        self.handles.insert(
            fh,
            Handle {
                ino,
                write,
                reader: Arc::new(Mutex::new(None)),
            },
        );
        fh
    }

    fn truncate(&self, t: &mut Tree, ino: u64, size: u64) -> Result<(), c_int> {
        let kind = t.inodes.get(&ino).ok_or(ENOENT)?.kind;
        match kind {
            Kind::File => {}
            Kind::Dir => return Err(EISDIR),
            _ => return Err(EACCES),
        }
        let local = t.inodes[&ino].local;
        let st = if size == 0 && !local {
            let st = t
                .new_staged()
                .map_err(|e| errno("cannot stage a change", e))?;
            t.inodes.get_mut(&ino).expect("ino").staged = Some(st.clone());
            st
        } else {
            self.stage(t, ino)?
        };
        st.set_len(size)
            .map_err(|e| errno("cannot change a file's size", e))?;
        let i = t.inodes.get_mut(&ino).expect("ino");
        i.size = size;
        i.write_gen += 1;
        i.mtime = SystemTime::now();
        i.ctime = i.mtime;
        if !local {
            i.dirty.content = true;
            t.touch();
        }
        Ok(())
    }
}

/// Creates the real file or folder of a new local item
/// (`fs/local.rs`); a link's is made once its target is known.
fn make_local(t: &mut Tree, ino: u64) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let path = t.local_place(ino)?;
    let (kind, perm) = {
        let i = &t.inodes[&ino];
        (
            i.kind,
            std::fs::Permissions::from_mode(t.inodes[&ino].perm.into()),
        )
    };
    match kind {
        Kind::Dir => {
            std::fs::create_dir_all(&path)?;
            std::fs::set_permissions(&path, perm)?;
        }
        Kind::File => {
            let f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(&path)?;
            std::fs::set_permissions(&path, perm)?;
            t.inodes.get_mut(&ino).expect("ino").staged = Some(Staged::local_open(path, f));
        }
        _ => {}
    }
    Ok(())
}

/// Deletes a local item's real file, link or (empty) folder. An open
/// file stays readable until it is closed.
fn remove_local(t: &Tree, ino: u64) -> std::io::Result<()> {
    let i = &t.inodes[&ino];
    let Some(path) = t.local_path(ino) else {
        return Ok(());
    };
    if let (Some(st), true) = (&i.staged, i.opens > 0) {
        st.keep_open()?;
    }
    let r = match i.kind {
        Kind::Dir => std::fs::remove_dir(&path),
        _ => std::fs::remove_file(&path),
    };
    match r {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        r => r?,
    }
    t.prune(&path);
    Ok(())
}

/// Sets a local item's modified time on its real file.
fn set_local_mtime(t: &Tree, ino: u64, when: SystemTime) {
    let i = &t.inodes[&ino];
    let r = match (i.kind, &i.staged) {
        (Kind::File, Some(st)) => st.set_modified(when),
        (Kind::Dir, _) => t.local_path(ino).map_or(Ok(()), |p| {
            std::fs::File::open(p).and_then(|f| f.set_modified(when))
        }),
        _ => Ok(()),
    };
    if let Err(e) = r {
        tracing::debug!("cannot set the time of {}: {e}", t.path(ino));
    }
}

/// A synced file or link, just moved to a local place, becomes local: it
/// is deleted from the space and kept here, its content in `staged`.
fn synced_to_local(t: &mut Tree, ino: u64, staged: Option<Arc<Staged>>) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    // Local first: its real path is beneath its parent's.
    t.inodes.get_mut(&ino).expect("ino").local = true;
    let made = (|| {
        let path = t.local_place(ino)?;
        let (kind, perm, mtime, target) = {
            let i = &t.inodes[&ino];
            (i.kind, i.perm, i.mtime, i.target.clone())
        };
        match kind {
            Kind::File => {
                let st = staged.ok_or_else(|| std::io::Error::from_raw_os_error(EIO))?;
                std::fs::rename(st.path(), &path)?;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(perm.into()))?;
                let st = st.moved(path);
                let _ = st.set_modified(mtime);
                t.inodes.get_mut(&ino).expect("ino").staged = Some(st);
            }
            Kind::Symlink => std::os::unix::fs::symlink(&target, &path)?,
            _ => return Err(std::io::Error::from_raw_os_error(EXDEV)),
        }
        Ok(())
    })();
    if let Err(e) = made {
        t.inodes.get_mut(&ino).expect("ino").local = false;
        return Err(e);
    }
    let i = t.inodes.get_mut(&ino).expect("ino");
    let node = i.node.take();
    let seen = i.seen.clone();
    i.dirty = Default::default();
    if let Some(n) = node {
        t.by_node.remove(&n);
        t.delete_node(n, Some(seen));
    }
    Ok(())
}

impl CardinalFs {
    /// After a `.cardinalignore` changed here: local items it no longer
    /// names become synced.
    fn ignores_changed(&self, t: &mut Tree) {
        t.reevaluate(&self.d.store);
    }
}

impl Filesystem for CardinalFs {
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let Ok(name) = name_str(name) else {
            return reply.error(ENOENT);
        };
        let mut t = lock(&self.tree);
        let Some(ino) = t.child(parent, name) else {
            return reply.error(ENOENT);
        };
        if let Some(i) = t.inodes.get_mut(&ino) {
            i.nlookup += 1;
        }
        match self.attr(&t, ino) {
            Some(a) => reply.entry(&TTL, &a, 0),
            None => reply.error(ENOENT),
        }
    }

    fn forget(&mut self, _req: &Request<'_>, ino: u64, nlookup: u64) {
        let mut t = lock(&self.tree);
        if let Some(i) = t.inodes.get_mut(&ino) {
            i.nlookup = i.nlookup.saturating_sub(nlookup);
        }
        t.gc(ino);
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let t = lock(&self.tree);
        match self.attr(&t, ino) {
            Some(a) => reply.attr(&TTL, &a),
            None => reply.error(ENOENT),
        }
    }

    fn setattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let mut t = lock(&self.tree);
        let Some(kind) = t.inodes.get(&ino).map(|i| i.kind) else {
            return reply.error(ENOENT);
        };
        if matches!(kind, Kind::Conflict(_)) && (size.is_some() || mode.is_some()) {
            return reply.error(EACCES);
        }
        if let Some(s) = size {
            if let Err(e) = self.truncate(&mut t, ino, s) {
                return reply.error(e);
            }
        }
        if let Some(m) = mode {
            let p = (m & 0o7777) as u16;
            if t.inodes[&ino].local && t.inodes[&ino].kind != Kind::Symlink {
                if let Some(path) = t.local_path(ino) {
                    use std::os::unix::fs::PermissionsExt;
                    let r =
                        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(p.into()));
                    if let Err(e) = r {
                        return reply.error(errno("cannot change a file's mode", e));
                    }
                }
            }
            let i = t.inodes.get_mut(&ino).expect("ino");
            if p != i.perm {
                i.perm = p;
                i.ctime = SystemTime::now();
                if i.kind == Kind::File && !i.local {
                    i.dirty.mode = true;
                    t.touch();
                }
            }
        }
        if let Some(mt) = mtime {
            let when = match mt {
                TimeOrNow::Now => SystemTime::now(),
                TimeOrNow::SpecificTime(x) => x,
            };
            if t.inodes[&ino].local {
                set_local_mtime(&t, ino, when);
            }
            let i = t.inodes.get_mut(&ino).expect("ino");
            if !matches!(i.kind, Kind::Conflict(_)) && i.mtime != when {
                i.mtime = when;
                if i.kind == Kind::File && !i.local {
                    i.dirty.mtime = true;
                    t.touch();
                }
            }
        }
        match self.attr(&t, ino) {
            Some(a) => reply.attr(&TTL, &a),
            None => reply.error(ENOENT),
        }
    }

    fn readlink(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyData) {
        let t = lock(&self.tree);
        match t.inodes.get(&ino) {
            Some(i) if i.kind == Kind::Symlink => reply.data(i.target.as_bytes()),
            Some(_) => reply.error(EINVAL),
            None => reply.error(ENOENT),
        }
    }

    fn mknod(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
        _rdev: u32,
        reply: ReplyEntry,
    ) {
        if mode & libc::S_IFMT != libc::S_IFREG {
            return reply.error(EPERM);
        }
        match self.new_child(parent, name, Kind::File, ((mode & !umask) & 0o7777) as u16) {
            Ok((_, a)) => reply.entry(&TTL, &a, 0),
            Err(e) => reply.error(e),
        }
    }

    fn mkdir(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
        reply: ReplyEntry,
    ) {
        match self.new_child(parent, name, Kind::Dir, ((mode & !umask) & 0o7777) as u16) {
            Ok((_, a)) => reply.entry(&TTL, &a, 0),
            Err(e) => reply.error(e),
        }
    }

    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let Ok(name) = name_str(name) else {
            return reply.error(ENOENT);
        };
        let mut t = lock(&self.tree);
        let Some(ino) = t.child(parent, name) else {
            return reply.error(ENOENT);
        };
        let (kind, node) = {
            let i = &t.inodes[&ino];
            (i.kind, i.node)
        };
        match kind {
            Kind::Dir => return reply.error(EISDIR),
            Kind::Conflict(_) => {
                // Deleting a conflict copy keeps the version shown under
                // the file's own name.
                if let Some(n) = node {
                    t.settle.insert(n, None);
                }
            }
            _ => {}
        }
        let local = t.inodes[&ino].local;
        if local {
            if let Err(e) = remove_local(&t, ino) {
                return reply.error(errno("cannot delete a file", e));
            }
        }
        t.remove(ino);
        if let Some(p) = t.inodes.get_mut(&parent) {
            p.mtime = SystemTime::now();
        }
        if !local {
            t.touch();
        }
        if name == IGNORE_FILE {
            self.ignores_changed(&mut t);
        }
        reply.ok();
    }

    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let Ok(name) = name_str(name) else {
            return reply.error(ENOENT);
        };
        let mut t = lock(&self.tree);
        let Some(ino) = t.child(parent, name) else {
            return reply.error(ENOENT);
        };
        let i = &t.inodes[&ino];
        if i.kind != Kind::Dir {
            return reply.error(ENOTDIR);
        }
        if !i.children.is_empty() {
            return reply.error(ENOTEMPTY);
        }
        let local = i.local;
        if local {
            if let Err(e) = remove_local(&t, ino) {
                return reply.error(errno("cannot delete a folder", e));
            }
        }
        t.remove(ino);
        if !local {
            t.touch();
        }
        reply.ok();
    }

    fn symlink(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        link_name: &OsStr,
        target: &Path,
        reply: ReplyEntry,
    ) {
        let Some(target) = target.to_str().map(str::to_owned) else {
            return reply.error(EINVAL);
        };
        match self.new_child(parent, link_name, Kind::Symlink, 0o777) {
            Ok((ino, _)) => {
                let mut t = lock(&self.tree);
                if t.inodes[&ino].local {
                    let r = t
                        .local_place(ino)
                        .and_then(|p| std::os::unix::fs::symlink(&target, p));
                    if let Err(e) = r {
                        t.detach(ino);
                        t.gc(ino);
                        return reply.error(errno("cannot keep a link on this device", e));
                    }
                }
                let i = t.inodes.get_mut(&ino).expect("new");
                i.size = target.len() as u64;
                i.target = target;
                let a = self.attr(&t, ino).expect("attr");
                reply.entry(&TTL, &a, 0)
            }
            Err(e) => reply.error(e),
        }
    }

    fn rename(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        flags: u32,
        reply: ReplyEmpty,
    ) {
        let (Ok(name), Ok(newname)) = (name_str(name), name_str(newname)) else {
            return reply.error(EINVAL);
        };
        if flags & libc::RENAME_EXCHANGE != 0 {
            return reply.error(EINVAL);
        }
        let mut t = lock(&self.tree);
        let Some(src) = t.child(parent, name) else {
            return reply.error(ENOENT);
        };
        match t.inodes.get(&newparent) {
            Some(p) if p.kind == Kind::Dir && p.parent != 0 => {}
            Some(_) => return reply.error(ENOTDIR),
            None => return reply.error(ENOENT),
        }
        let skind = t.inodes[&src].kind;
        if let Kind::Conflict(v) = skind {
            // Renaming a conflict copy onto the file's own name picks that
            // version; anything else is a copy (EXDEV makes `mv` copy).
            let node = t.inodes[&src].node;
            let main = node.and_then(|n| t.by_node.get(&n).copied());
            if Some(newparent) == main.map(|m| t.inodes[&m].parent)
                && main.is_some_and(|m| t.inodes[&m].name == newname)
            {
                if let Some(n) = node {
                    t.settle.insert(n, Some(v));
                }
                t.remove(src);
                t.touch();
                return reply.ok();
            }
            return reply.error(EXDEV);
        }
        if skind == Kind::Dir && t.is_ancestor(src, newparent) {
            return reply.error(EINVAL);
        }
        let dst = t.child(newparent, newname);
        if dst == Some(src) {
            return reply.ok();
        }
        // Where it goes: a local place or a synced one (`fs/local.rs`).
        let store = self.d.store.clone();
        let src_local = t.inodes[&src].local;
        let to_local = t.ignored(&store, newparent, newname, skind == Kind::Dir);
        if !src_local && to_local && skind == Kind::Dir {
            // A synced folder does not become local in one step: `mv`
            // copies it instead.
            return reply.error(EXDEV);
        }
        if let Some(dst) = dst {
            if flags & libc::RENAME_NOREPLACE != 0 {
                return reply.error(EEXIST);
            }
            match (skind, t.inodes[&dst].kind) {
                (_, Kind::Conflict(_)) => return reply.error(EPERM),
                (Kind::Dir, Kind::Dir) if !t.inodes[&dst].children.is_empty() => {
                    return reply.error(ENOTEMPTY)
                }
                (Kind::Dir, Kind::Dir) => {}
                (Kind::Dir, _) => return reply.error(ENOTDIR),
                (_, Kind::Dir) => return reply.error(EISDIR),
                _ => {}
            }
        }
        let old_local = if src_local { t.local_path(src) } else { None };
        // A synced file going local: its content first (it may be fetched).
        let going_local = if !src_local && to_local && skind == Kind::File {
            match self.stage(&mut t, src) {
                Ok(st) => Some(st),
                Err(e) => return reply.error(e),
            }
        } else {
            None
        };
        // A local file going synced is staged in place first, so that it
        // replaces a synced file as an edit of it.
        if src_local && !to_local && skind != Kind::Dir {
            let Some(old) = old_local.clone() else {
                return reply.error(ENOENT);
            };
            if let Err(e) = t.local_to_synced(&store, src, old) {
                return reply.error(errno("cannot sync a file", e));
            }
        }
        // Local to local: the real file moves first (replacing a local
        // destination), so a failure changes nothing.
        if src_local && to_local {
            let (Some(old), Some(new)) =
                (old_local.clone(), t.local_child_path(newparent, newname))
            else {
                return reply.error(ENOENT);
            };
            let r = new
                .parent()
                .map_or(Ok(()), std::fs::create_dir_all)
                .and_then(|()| std::fs::rename(&old, &new));
            if let Err(e) = r {
                return reply.error(errno("cannot move a file", e));
            }
            t.prune(&old);
        }
        let mut took_over = false;
        if let Some(dst) = dst {
            let dlocal = t.inodes[&dst].local;
            if dlocal && !(src_local && to_local) {
                if let Err(e) = remove_local(&t, dst) {
                    return reply.error(errno("cannot replace a file", e));
                }
            }
            let (dkind, dnode) = (t.inodes[&dst].kind, t.inodes[&dst].node);
            let take_over = match dnode {
                Some(dn) if !to_local && skind == Kind::File && dkind == Kind::File => Some(dn),
                _ => None,
            };
            if let Some(dn) = take_over {
                // Replacing a file keeps the replaced file's identity, so
                // the change is an edit of it (history, conflicts): the
                // source inode takes over the destination's node.
                let snode = t.inodes[&src].node;
                let ddirty = t.inodes[&dst].dirty;
                let dseen = t.inodes[&dst].seen.clone();
                // forget the destination without deleting its node
                t.detach(dst);
                if let Some(di) = t.inodes.get_mut(&dst) {
                    di.node = None;
                    di.dirty = Default::default();
                }
                t.gc(dst);
                if let Some(sn) = snode {
                    t.by_node.remove(&sn);
                    t.delete_node(sn, None);
                }
                t.detach(src);
                t.by_node.insert(dn, src);
                let s = t.inodes.get_mut(&src).expect("src");
                s.node = Some(dn);
                s.seen = dseen;
                s.dirty.content = true;
                s.dirty.mode = true;
                s.dirty.mtime = true;
                s.dirty.pos = ddirty.pos;
                s.write_gen += 1;
                t.attach(src, newparent, newname);
                took_over = true;
            } else {
                t.remove(dst);
            }
        }
        if !took_over {
            t.detach(src);
            t.attach(src, newparent, newname);
            if src_local && to_local {
                t.repath_local(src);
            } else if src_local && skind == Kind::Dir {
                // a local folder going synced, with what is in it
                if let Some(old) = old_local {
                    if let Err(e) = t.local_to_synced(&store, src, old) {
                        tracing::warn!("cannot sync {}: {e}", t.path(src));
                    }
                }
            } else if !src_local && to_local {
                if let Err(e) = synced_to_local(&mut t, src, going_local) {
                    return reply.error(errno("cannot keep a file on this device", e));
                }
            } else if let Some(s) = t.inodes.get_mut(&src) {
                if s.node.is_some() {
                    s.dirty.pos = true;
                }
            }
            if let Some(s) = t.inodes.get_mut(&src) {
                s.ctime = SystemTime::now();
            }
            let now = SystemTime::now();
            for p in [parent, newparent] {
                if let Some(pi) = t.inodes.get_mut(&p) {
                    pi.mtime = now;
                }
            }
        }
        t.touch();
        if name == IGNORE_FILE || newname == IGNORE_FILE {
            self.ignores_changed(&mut t);
        }
        reply.ok();
    }

    fn link(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _newparent: u64,
        _newname: &OsStr,
        reply: ReplyEntry,
    ) {
        // Hard links do not exist in a files space; git falls back to
        // rename.
        reply.error(EPERM);
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        let write = flags & libc::O_ACCMODE != libc::O_RDONLY;
        let mut t = lock(&self.tree);
        let Some(i) = t.inodes.get(&ino) else {
            return reply.error(ENOENT);
        };
        match i.kind {
            Kind::Dir => return reply.error(EISDIR),
            Kind::Conflict(_) if write => return reply.error(EACCES),
            _ => {}
        }
        if write && flags & libc::O_TRUNC != 0 {
            if let Err(e) = self.truncate(&mut t, ino, 0) {
                return reply.error(e);
            }
        }
        let i = t.inodes.get_mut(&ino).expect("ino");
        i.opens += 1;
        if write {
            i.writers += 1;
        }
        // A local file stays readable while open, even once deleted.
        if i.local {
            if let Some(st) = &i.staged {
                if let Err(e) = st.keep_open() {
                    i.opens -= 1;
                    if write {
                        i.writers -= 1;
                    }
                    return reply.error(errno("cannot open a file", e));
                }
            }
        }
        drop(t);
        let fh = self.open_handle(ino, write);
        reply.opened(fh, 0);
    }

    fn create(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        let perm = ((mode & !umask) & 0o7777) as u16;
        match self.new_child(parent, name, Kind::File, perm) {
            Ok((ino, a)) => {
                let write = flags & libc::O_ACCMODE != libc::O_RDONLY;
                {
                    let mut t = lock(&self.tree);
                    let i = t.inodes.get_mut(&ino).expect("new");
                    i.opens += 1;
                    if write {
                        i.writers += 1;
                    }
                }
                let fh = self.open_handle(ino, write);
                reply.created(&TTL, &a, 0, fh, 0)
            }
            Err(e) => reply.error(e),
        }
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let offset = offset.max(0) as u64;
        let (staged, content) = {
            let t = lock(&self.tree);
            let Some(i) = t.inodes.get(&ino) else {
                return reply.error(ENOENT);
            };
            (i.staged.clone(), i.content.clone())
        };
        if let Some(st) = staged {
            let mut buf = vec![0u8; size as usize];
            let mut got = 0usize;
            while got < buf.len() {
                match st.read_at(&mut buf[got..], offset + got as u64) {
                    Ok(0) => break,
                    Ok(n) => got += n,
                    Err(e) => return reply.error(errno("cannot read a changed file", e)),
                }
            }
            return reply.data(&buf[..got]);
        }
        match content {
            None => reply.data(&[]),
            Some(Content::Inline(b)) => {
                let s = (offset as usize).min(b.len());
                let e = (s + size as usize).min(b.len());
                reply.data(&b[s..e])
            }
            Some(Content::Blob(r)) => {
                let Some(h) = self.handles.get(&fh) else {
                    return reply.error(EIO);
                };
                let slot = h.reader.clone();
                let store = self.d.store.clone();
                let fetcher = self.fetcher;
                let br = blob_ref(&r);
                self.d.rt.spawn_blocking(move || {
                    let mut g = slot.lock().unwrap_or_else(|e| e.into_inner());
                    if g.as_ref().is_none_or(|rd| rd.reference() != &br) {
                        *g = Some(BlobReader::new(store, fetcher, br));
                    }
                    let rd = g.as_mut().expect("reader");
                    match rd.read_range(offset, size as usize) {
                        Ok(b) => reply.data(&b),
                        Err(e) => {
                            tracing::warn!("cannot read a file: {e} (is a device with it online?)");
                            reply.error(EIO)
                        }
                    }
                });
            }
        }
    }

    fn write(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        let mut t = lock(&self.tree);
        if matches!(t.inodes.get(&ino).map(|i| i.kind), Some(Kind::Conflict(_))) {
            return reply.error(EACCES);
        }
        let st = match self.stage(&mut t, ino) {
            Ok(s) => s,
            Err(e) => return reply.error(e),
        };
        let offset = offset.max(0) as u64;
        if let Err(e) = st.write_all_at(data, offset) {
            return reply.error(errno("cannot save a write", e));
        }
        let i = t.inodes.get_mut(&ino).expect("ino");
        i.size = i.size.max(offset + data.len() as u64);
        i.write_gen += 1;
        i.last_write = Some(Instant::now());
        i.mtime = SystemTime::now();
        i.ctime = i.mtime;
        if !i.local {
            i.dirty.content = true;
            t.touch();
        }
        reply.written(data.len() as u32);
    }

    fn flush(&mut self, _req: &Request<'_>, _ino: u64, _fh: u64, _lo: u64, reply: ReplyEmpty) {
        reply.ok();
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        let h = self.handles.remove(&fh);
        let mut t = lock(&self.tree);
        if let Some(i) = t.inodes.get_mut(&ino) {
            i.opens = i.opens.saturating_sub(1);
            if i.opens == 0 {
                if let Some(st) = &i.staged {
                    st.close();
                }
            }
            let mut ignores = false;
            if h.as_ref().is_some_and(|h| h.write) {
                i.writers = i.writers.saturating_sub(1);
                ignores = i.name == IGNORE_FILE;
                if i.dirty.content {
                    // a closed file is quiet now
                    i.last_write = None;
                    t.touch();
                }
            }
            if ignores {
                self.ignores_changed(&mut t);
            }
        }
        t.gc(ino);
        let _ = h.map(|h| h.ino);
        reply.ok();
    }

    fn fsync(&mut self, _req: &Request<'_>, ino: u64, _fh: u64, _ds: bool, reply: ReplyEmpty) {
        let st = lock(&self.tree)
            .inodes
            .get(&ino)
            .and_then(|i| i.staged.clone());
        if let Some(st) = st {
            let _ = st.sync_data();
        }
        reply.ok();
    }

    fn opendir(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
        let t = lock(&self.tree);
        match t.inodes.get(&ino) {
            Some(i) if i.kind == Kind::Dir => reply.opened(0, 0),
            Some(_) => reply.error(ENOTDIR),
            None => reply.error(ENOENT),
        }
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let t = lock(&self.tree);
        let Some(i) = t.inodes.get(&ino) else {
            return reply.error(ENOENT);
        };
        let mut entries: Vec<(u64, FileType, String)> = vec![
            (ino, FileType::Directory, ".".into()),
            (
                if i.parent == 0 { ino } else { i.parent },
                FileType::Directory,
                "..".into(),
            ),
        ];
        for (name, c) in &i.children {
            let k = match t.inodes.get(c).map(|x| x.kind) {
                Some(Kind::Dir) => FileType::Directory,
                Some(Kind::Symlink) => FileType::Symlink,
                Some(_) => FileType::RegularFile,
                None => continue,
            };
            entries.push((*c, k, name.clone()));
        }
        for (n, (ino, k, name)) in entries.into_iter().enumerate().skip(offset.max(0) as usize) {
            if reply.add(ino, (n + 1) as i64, k, &name) {
                break;
            }
        }
        reply.ok();
    }

    fn statfs(&mut self, _req: &Request<'_>, _ino: u64, reply: ReplyStatfs) {
        let path =
            std::ffi::CString::new(self.d.paths.home.as_os_str().as_bytes()).unwrap_or_default();
        // SAFETY: statvfs fills the struct; the path is a valid C string.
        let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
        let ok = unsafe { libc::statvfs(path.as_ptr(), &mut s) } == 0;
        let n = lock(&self.tree).inodes.len() as u64;
        if ok {
            reply.statfs(
                s.f_blocks as u64,
                s.f_bfree as u64,
                s.f_bavail as u64,
                n + s.f_ffree as u64,
                s.f_ffree as u64,
                s.f_bsize as u32,
                255,
                s.f_frsize as u32,
            )
        } else {
            reply.statfs(0, 0, 0, n, 0, BLOCK as u32, 255, BLOCK as u32)
        }
    }

    fn access(&mut self, _req: &Request<'_>, ino: u64, _mask: i32, reply: ReplyEmpty) {
        if lock(&self.tree).inodes.contains_key(&ino) {
            reply.ok()
        } else {
            reply.error(ENOENT)
        }
    }
}

/// The inode of the root, for tests.
pub const ROOT: u64 = ROOT_INO;
