//! The FUSE filesystem over [`Tree`].

use std::collections::HashMap;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

use cardinal_blob::{BlobReader, FsStore};
use cardinal_space::files::Content;
use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
    ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, Request, TimeOrNow,
};
use libc::{c_int, EACCES, EEXIST, EINVAL, EIO, EISDIR, ENOENT, ENOTDIR, ENOTEMPTY, EPERM, EXDEV};

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
        let st = t.new_staged().map_err(|_| EIO)?;
        match content {
            None => {}
            Some(Content::Inline(b)) => st.file.write_all_at(&b, 0).map_err(|_| EIO)?,
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
                    st.file.write_all_at(&buf[..n], off).map_err(|_| EIO)?;
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
        let ino = t.alloc(kind);
        {
            let i = t.inodes.get_mut(&ino).expect("new");
            i.perm = perm;
            if kind == Kind::File {
                i.content = Some(Content::Inline(Vec::new()));
            }
            i.nlookup = 1;
        }
        t.attach(ino, parent, name);
        if let Some(p) = t.inodes.get_mut(&parent) {
            p.mtime = SystemTime::now();
        }
        t.touch();
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
        let st = if size == 0 {
            let st = t.new_staged().map_err(|_| EIO)?;
            t.inodes.get_mut(&ino).expect("ino").staged = Some(st.clone());
            st
        } else {
            self.stage(t, ino)?
        };
        st.file.set_len(size).map_err(|_| EIO)?;
        let i = t.inodes.get_mut(&ino).expect("ino");
        i.size = size;
        i.dirty.content = true;
        i.write_gen += 1;
        i.mtime = SystemTime::now();
        i.ctime = i.mtime;
        t.touch();
        Ok(())
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
            let i = t.inodes.get_mut(&ino).expect("ino");
            let p = (m & 0o7777) as u16;
            if p != i.perm {
                i.perm = p;
                i.ctime = SystemTime::now();
                if i.kind == Kind::File {
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
            let i = t.inodes.get_mut(&ino).expect("ino");
            if !matches!(i.kind, Kind::Conflict(_)) && i.mtime != when {
                i.mtime = when;
                if i.kind == Kind::File {
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
        t.remove(ino);
        if let Some(p) = t.inodes.get_mut(&parent) {
            p.mtime = SystemTime::now();
        }
        t.touch();
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
        t.remove(ino);
        t.touch();
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
        if let Some(dst) = dst {
            if flags & libc::RENAME_NOREPLACE != 0 {
                return reply.error(EEXIST);
            }
            let dkind = t.inodes[&dst].kind;
            match (skind, dkind) {
                (_, Kind::Conflict(_)) => return reply.error(EPERM),
                (Kind::Dir, Kind::Dir) => {
                    if !t.inodes[&dst].children.is_empty() {
                        return reply.error(ENOTEMPTY);
                    }
                    t.remove(dst);
                }
                (Kind::Dir, _) => return reply.error(ENOTDIR),
                (_, Kind::Dir) => return reply.error(EISDIR),
                (Kind::File, Kind::File) => {
                    // Replacing a file keeps the replaced file's identity,
                    // so the change is an edit of it (history, conflicts):
                    // the source inode takes over the destination's node.
                    let dnode = t.inodes[&dst].node;
                    let snode = t.inodes[&src].node;
                    let ddirty = t.inodes[&dst].dirty;
                    if dnode.is_some() {
                        // forget the destination without deleting its node
                        t.detach(dst);
                        if let Some(di) = t.inodes.get_mut(&dst) {
                            di.node = None;
                            di.dirty = Default::default();
                        }
                        t.gc(dst);
                        if let Some(sn) = snode {
                            t.by_node.remove(&sn);
                            t.deleted.push(sn);
                        }
                        t.detach(src);
                        let dn = dnode.expect("some");
                        t.by_node.insert(dn, src);
                        {
                            let s = t.inodes.get_mut(&src).expect("src");
                            s.node = Some(dn);
                            s.dirty.content = true;
                            s.dirty.mode = true;
                            s.dirty.mtime = true;
                            s.dirty.pos = ddirty.pos;
                            s.write_gen += 1;
                            if s.staged.is_none() {
                                // the content to commit is the source's
                                // committed content
                            }
                        }
                        t.attach(src, newparent, newname);
                        t.touch();
                        return reply.ok();
                    }
                    t.remove(dst);
                }
                _ => {
                    t.remove(dst);
                }
            }
        }
        t.detach(src);
        t.attach(src, newparent, newname);
        if let Some(s) = t.inodes.get_mut(&src) {
            if s.node.is_some() {
                s.dirty.pos = true;
            }
            s.ctime = SystemTime::now();
        }
        let now = SystemTime::now();
        for p in [parent, newparent] {
            if let Some(pi) = t.inodes.get_mut(&p) {
                pi.mtime = now;
            }
        }
        t.touch();
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
                match st.file.read_at(&mut buf[got..], offset + got as u64) {
                    Ok(0) => break,
                    Ok(n) => got += n,
                    Err(_) => return reply.error(EIO),
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
        if st.file.write_all_at(data, offset).is_err() {
            return reply.error(EIO);
        }
        let i = t.inodes.get_mut(&ino).expect("ino");
        i.size = i.size.max(offset + data.len() as u64);
        i.dirty.content = true;
        i.write_gen += 1;
        i.last_write = Some(Instant::now());
        i.mtime = SystemTime::now();
        i.ctime = i.mtime;
        t.touch();
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
            if h.as_ref().is_some_and(|h| h.write) {
                i.writers = i.writers.saturating_sub(1);
                if i.dirty.content {
                    // a closed file is quiet now
                    i.last_write = None;
                    t.touch();
                }
            }
        }
        t.gc(ino);
        let _ = h.map(|h| h.ino);
        reply.ok();
    }

    fn fsync(&mut self, _req: &Request<'_>, ino: u64, _fh: u64, _ds: bool, reply: ReplyEmpty) {
        let st = lock(&self.tree).inodes.get(&ino).and_then(|i| i.staged.clone());
        if let Some(st) = st {
            let _ = st.file.sync_data();
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
        let path = std::ffi::CString::new(self.d.paths.home.as_os_str().as_bytes())
            .unwrap_or_default();
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
