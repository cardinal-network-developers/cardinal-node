//! The tree the mount shows: the files space's state, overlaid with local
//! changes that have not been committed as an entry yet.
//!
//! Each inode maps to a node of the space once it has been created there
//! (`node`), or to one version of a file in conflict. Local changes set
//! dirty flags; the committer turns them into ops after the quiet period
//! and records the node ids that entries created. When entries arrive
//! from other devices, [`Tree::apply`] brings committed inodes up to date
//! without touching what is dirty.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cardinal_identity::{EntryId, KeyId};
use cardinal_space::files::{Content, FileKind, Files};
use cardinal_space::{NodeId, Space, ROOT};

/// The root inode.
pub const ROOT_INO: u64 = 1;

/// What an inode is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A folder.
    Dir,
    /// A file.
    File,
    /// A symbolic link.
    Symlink,
    /// A read-only view of another version of a file in conflict.
    Conflict(EntryId),
}

/// A file's content being written locally.
///
/// The staging file is opened on demand and closed when no application
/// has the file open, so copying many files does not hold one descriptor
/// per file until the next commit.
pub struct Staged {
    file: Mutex<Option<File>>,
    path: PathBuf,
}

impl Staged {
    fn with<R>(&self, f: impl FnOnce(&File) -> io::Result<R>) -> io::Result<R> {
        let mut g = self.file.lock().unwrap_or_else(|e| e.into_inner());
        if g.is_none() {
            *g = Some(OpenOptions::new().read(true).write(true).open(&self.path)?);
        }
        f(g.as_ref().expect("opened"))
    }

    pub fn read_at(&self, buf: &mut [u8], off: u64) -> io::Result<usize> {
        self.with(|f| f.read_at(buf, off))
    }

    pub fn read_exact_at(&self, buf: &mut [u8], off: u64) -> io::Result<()> {
        self.with(|f| f.read_exact_at(buf, off))
    }

    pub fn write_all_at(&self, buf: &[u8], off: u64) -> io::Result<()> {
        self.with(|f| f.write_all_at(buf, off))
    }

    pub fn set_len(&self, len: u64) -> io::Result<()> {
        self.with(|f| f.set_len(len))
    }

    pub fn len(&self) -> io::Result<u64> {
        Ok(std::fs::metadata(&self.path)?.len())
    }

    pub fn sync_data(&self) -> io::Result<()> {
        self.with(|f| f.sync_data())
    }

    /// Closes the staging file; the next access reopens it.
    pub fn close(&self) {
        self.file.lock().unwrap_or_else(|e| e.into_inner()).take();
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Local changes not yet committed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Dirty {
    /// Parent or name changed.
    pub pos: bool,
    /// Content changed.
    pub content: bool,
    /// Mode bits changed.
    pub mode: bool,
    /// Modified time changed.
    pub mtime: bool,
}

impl Dirty {
    fn any(&self) -> bool {
        self.pos || self.content || self.mode || self.mtime
    }
    fn all() -> Dirty {
        Dirty {
            pos: true,
            content: true,
            mode: true,
            mtime: true,
        }
    }
}

/// One inode.
pub struct Inode {
    /// Its number.
    pub ino: u64,
    /// Parent inode; 0 when detached (unlinked but still open).
    pub parent: u64,
    /// Name in the parent.
    pub name: String,
    /// What it is.
    pub kind: Kind,
    /// The space node, once created there.
    pub node: Option<NodeId>,
    /// Children by name (folders).
    pub children: BTreeMap<String, u64>,
    /// Permission bits.
    pub perm: u16,
    /// Modified time.
    pub mtime: SystemTime,
    /// Changed time.
    pub ctime: SystemTime,
    /// Size in bytes.
    pub size: u64,
    /// The committed content (files and conflict copies).
    pub content: Option<Content>,
    /// Local content, authoritative when present.
    pub staged: Option<Arc<Staged>>,
    /// Link target.
    pub target: String,
    /// Uncommitted changes.
    pub dirty: Dirty,
    /// Open handles that may write.
    pub writers: u32,
    /// Open handles.
    pub opens: u32,
    /// When it was last written.
    pub last_write: Option<Instant>,
    /// Bumped on every write.
    pub write_gen: u64,
    /// Kernel lookups outstanding.
    pub nlookup: u64,
}

impl Inode {
    fn new(ino: u64, kind: Kind) -> Inode {
        let now = SystemTime::now();
        Inode {
            ino,
            parent: 0,
            name: String::new(),
            kind,
            node: None,
            children: BTreeMap::new(),
            perm: match kind {
                Kind::Dir => 0o755,
                Kind::File => 0o644,
                Kind::Symlink => 0o777,
                Kind::Conflict(_) => 0o444,
            },
            mtime: now,
            ctime: now,
            size: 0,
            content: None,
            staged: None,
            target: String::new(),
            dirty: Dirty::default(),
            writers: 0,
            opens: 0,
            last_write: None,
            write_gen: 0,
            nlookup: 0,
        }
    }

    /// Whether it is being written right now (written within `quiet` and
    /// still open for writing).
    pub fn busy(&self, quiet: Duration) -> bool {
        self.writers > 0 && self.last_write.is_some_and(|t| t.elapsed() < quiet)
    }
}

/// A kernel cache entry to invalidate after a change from elsewhere.
#[derive(Clone, Debug)]
pub enum Inval {
    /// A name in a folder.
    Entry(u64, String),
    /// An inode's attributes and data.
    Inode(u64),
}

/// One node of the files space, as the mount shows it.
#[derive(Clone, Debug)]
pub struct SnapEntry {
    /// The parent's node (ROOT for the top).
    pub parent: NodeId,
    /// The display name.
    pub name: String,
    /// The node.
    pub node: NodeId,
    /// For a conflict copy, the version.
    pub version: Option<EntryId>,
    /// The kind.
    pub kind: FileKind,
    /// The content shown.
    pub content: Option<Content>,
    /// Mode bits.
    pub mode: Option<u64>,
    /// Modified time (ms).
    pub mtime: Option<u64>,
    /// Link target.
    pub target: Option<String>,
}

/// The state of a files space, flattened for [`Tree::apply`].
pub struct Snapshot {
    /// The holder's version when it was taken.
    pub version: u64,
    /// Entries, parents before children.
    pub entries: Vec<SnapEntry>,
}

impl Snapshot {
    /// Takes a snapshot of a space's state.
    pub fn take(space: &Space, version: u64, names: &HashMap<KeyId, String>) -> Snapshot {
        let files = Files::with_device_names(space, |k| {
            names
                .get(k)
                .cloned()
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| cardinal_space::account::short_key(k))
        });
        let mut entries = Vec::new();
        let mut stack = vec![ROOT];
        while let Some(dir) = stack.pop() {
            for e in files.list(&dir) {
                let mut se = SnapEntry {
                    parent: dir,
                    name: e.name.clone(),
                    node: e.node,
                    version: e.conflict_version,
                    kind: e.kind,
                    content: None,
                    mode: None,
                    mtime: None,
                    target: None,
                };
                match e.kind {
                    FileKind::Folder => stack.push(e.node),
                    FileKind::File => {
                        let versions = files.content(&e.node);
                        let v = match e.conflict_version {
                            Some(id) => versions.iter().find(|v| v.entry == id),
                            None => versions.last(),
                        };
                        se.content = v.and_then(|v| v.content.clone());
                        let st = files.stat(&e.node);
                        se.mode = st.as_ref().and_then(|s| s.mode);
                        se.mtime = match e.conflict_version {
                            Some(_) => v.and_then(|v| v.time),
                            None => st.as_ref().and_then(|s| s.mtime),
                        };
                    }
                    FileKind::Link => {
                        se.target = files.stat(&e.node).and_then(|s| s.target);
                    }
                    FileKind::Other => continue,
                }
                entries.push(se);
            }
        }
        Snapshot { version, entries }
    }
}

fn ms_to_time(ms: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(ms)
}

/// Milliseconds since the epoch of a time.
pub fn time_to_ms(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The mount's tree.
pub struct Tree {
    /// Inodes.
    pub inodes: HashMap<u64, Inode>,
    /// Committed node -> inode.
    pub by_node: HashMap<NodeId, u64>,
    /// Conflict copy (node, version) -> inode.
    pub by_conflict: HashMap<(NodeId, EntryId), u64>,
    next_ino: u64,
    next_stage: u64,
    staging: PathBuf,
    /// Nodes to delete at the next commit.
    pub deleted: Vec<NodeId>,
    /// Conflicts to settle at the next commit: the version to keep, or
    /// `None` for the one shown under the file's own name.
    pub settle: HashMap<NodeId, Option<EntryId>>,
    /// First uncommitted change.
    pub first_change: Option<Instant>,
    /// Last change.
    pub last_change: Option<Instant>,
    /// Snapshots older than this version are stale (a commit happened).
    pub min_version: u64,
    /// The version last applied.
    pub applied_version: u64,
}

impl Tree {
    /// An empty tree.
    pub fn new(staging: PathBuf) -> Tree {
        let mut inodes = HashMap::new();
        let mut root = Inode::new(ROOT_INO, Kind::Dir);
        root.node = Some(ROOT);
        root.parent = ROOT_INO;
        inodes.insert(ROOT_INO, root);
        let mut by_node = HashMap::new();
        by_node.insert(ROOT, ROOT_INO);
        Tree {
            inodes,
            by_node,
            by_conflict: HashMap::new(),
            next_ino: 2,
            next_stage: 1,
            staging,
            deleted: Vec::new(),
            settle: HashMap::new(),
            first_change: None,
            last_change: None,
            min_version: 0,
            applied_version: 0,
        }
    }

    /// Records a local change, for the quiet-period scheduler.
    pub fn touch(&mut self) {
        let now = Instant::now();
        self.first_change.get_or_insert(now);
        self.last_change = Some(now);
    }

    /// Whether anything waits to be committed.
    pub fn has_pending(&self) -> bool {
        !self.deleted.is_empty()
            || !self.settle.is_empty()
            || self
                .inodes
                .values()
                .any(|i| i.parent != 0 && (i.node.is_none() || i.dirty.any()))
    }

    /// Allocates a detached inode.
    pub fn alloc(&mut self, kind: Kind) -> u64 {
        let ino = self.next_ino;
        self.next_ino += 1;
        self.inodes.insert(ino, Inode::new(ino, kind));
        ino
    }

    /// A child by name.
    pub fn child(&self, parent: u64, name: &str) -> Option<u64> {
        self.inodes.get(&parent)?.children.get(name).copied()
    }

    /// Attaches a detached inode under `parent` as `name`.
    pub fn attach(&mut self, ino: u64, parent: u64, name: &str) {
        if let Some(i) = self.inodes.get_mut(&ino) {
            i.parent = parent;
            i.name = name.to_owned();
        }
        if let Some(p) = self.inodes.get_mut(&parent) {
            p.children.insert(name.to_owned(), ino);
        }
    }

    /// Detaches an inode from its parent.
    pub fn detach(&mut self, ino: u64) {
        let Some(i) = self.inodes.get(&ino) else {
            return;
        };
        let (parent, name) = (i.parent, i.name.clone());
        if let Some(p) = self.inodes.get_mut(&parent) {
            if p.children.get(&name) == Some(&ino) {
                p.children.remove(&name);
            }
        }
        if let Some(i) = self.inodes.get_mut(&ino) {
            i.parent = 0;
        }
    }

    /// Removes an inode from the tree as a deletion: its node is deleted
    /// at the next commit; the inode lives on while open or looked up.
    pub fn remove(&mut self, ino: u64) {
        self.detach(ino);
        let Some(i) = self.inodes.get_mut(&ino) else {
            return;
        };
        if let Some(n) = i.node.take() {
            match i.kind {
                Kind::Conflict(v) => {
                    self.by_conflict.remove(&(n, v));
                }
                _ => {
                    self.by_node.remove(&n);
                    self.deleted.push(n);
                }
            }
        }
        i.dirty = Dirty::default();
        self.gc(ino);
    }

    /// Frees a detached inode nobody refers to.
    pub fn gc(&mut self, ino: u64) {
        if ino == ROOT_INO {
            return;
        }
        let free = self
            .inodes
            .get(&ino)
            .is_some_and(|i| i.parent == 0 && i.opens == 0 && i.nlookup == 0);
        if free {
            if let Some(i) = self.inodes.remove(&ino) {
                if let Some(n) = i.node {
                    if self.by_node.get(&n) == Some(&ino) {
                        self.by_node.remove(&n);
                    }
                }
            }
        }
    }

    /// Whether `a` is `b` or an ancestor of `b`.
    pub fn is_ancestor(&self, a: u64, mut b: u64) -> bool {
        for _ in 0..10_000 {
            if a == b {
                return true;
            }
            if b == ROOT_INO || b == 0 {
                return false;
            }
            b = match self.inodes.get(&b) {
                Some(i) => i.parent,
                None => return false,
            };
        }
        false
    }

    /// A path of an inode, for messages.
    pub fn path(&self, mut ino: u64) -> String {
        let mut parts = Vec::new();
        while ino != ROOT_INO && ino != 0 {
            let Some(i) = self.inodes.get(&ino) else {
                break;
            };
            parts.push(i.name.clone());
            ino = i.parent;
        }
        parts.reverse();
        parts.join("/")
    }

    /// Creates a staging file holding `initial` bytes.
    pub fn new_staged(&mut self) -> std::io::Result<Arc<Staged>> {
        let n = self.next_stage;
        self.next_stage += 1;
        let path = self.staging.join(format!("{}-{n}", std::process::id()));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)?;
        Ok(Arc::new(Staged {
            file: Mutex::new(Some(file)),
            path,
        }))
    }

    /// Brings committed inodes up to date with a snapshot of the space,
    /// keeping local changes. Returns kernel caches to invalidate.
    pub fn apply(&mut self, snap: &Snapshot) -> Vec<Inval> {
        let mut inval = Vec::new();
        let mut seen: HashSet<u64> = HashSet::new();
        seen.insert(ROOT_INO);
        // desired parent inode and name for each committed inode
        let mut placed: Vec<(u64, u64, String)> = Vec::new();
        for e in &snap.entries {
            let Some(&pino) = self.by_node.get(&e.parent) else {
                continue;
            };
            let key_ino = match e.version {
                Some(v) => self.by_conflict.get(&(e.node, v)).copied(),
                None => self.by_node.get(&e.node).copied(),
            };
            let kind = match (e.kind, e.version) {
                (FileKind::File, Some(v)) => Kind::Conflict(v),
                (FileKind::File, None) => Kind::File,
                (FileKind::Folder, _) => Kind::Dir,
                (FileKind::Link, _) => Kind::Symlink,
                (FileKind::Other, _) => continue,
            };
            let ino = match key_ino {
                Some(i) if self.inodes.get(&i).is_some_and(|x| x.kind == kind) => i,
                _ => {
                    let i = self.alloc(kind);
                    self.inodes.get_mut(&i).expect("new").node = Some(e.node);
                    match e.version {
                        Some(v) => {
                            self.by_conflict.insert((e.node, v), i);
                        }
                        None => {
                            self.by_node.insert(e.node, i);
                        }
                    }
                    i
                }
            };
            seen.insert(ino);
            let inode = self.inodes.get_mut(&ino).expect("ino");
            if !inode.dirty.pos {
                placed.push((ino, pino, e.name.clone()));
            }
            match kind {
                Kind::File | Kind::Conflict(_) => {
                    if !inode.dirty.content && inode.content != e.content {
                        inode.content = e.content.clone();
                        inode.size = e.content.as_ref().map(|c| c.size()).unwrap_or(0);
                        inode.staged = None;
                        inode.ctime = SystemTime::now();
                        inval.push(Inval::Inode(ino));
                    }
                    if !inode.dirty.mode {
                        let p = match kind {
                            Kind::Conflict(_) => 0o444,
                            _ => e.mode.map(|m| (m & 0o7777) as u16).unwrap_or(0o644),
                        };
                        if p != inode.perm {
                            inode.perm = p;
                            inval.push(Inval::Inode(ino));
                        }
                    }
                    if !inode.dirty.mtime {
                        if let Some(m) = e.mtime {
                            let t = ms_to_time(m);
                            if t != inode.mtime {
                                inode.mtime = t;
                                inval.push(Inval::Inode(ino));
                            }
                        }
                    }
                }
                Kind::Symlink => {
                    let t = e.target.clone().unwrap_or_default();
                    if t != inode.target {
                        inode.size = t.len() as u64;
                        inode.target = t;
                        inval.push(Inval::Inode(ino));
                    }
                }
                Kind::Dir => {}
            }
        }

        // Committed inodes no longer in the state were deleted elsewhere.
        // Keep those with local changes (or local changes beneath them),
        // to be created again.
        let mut needed: HashSet<u64> = HashSet::new();
        for i in self.inodes.values() {
            if i.parent != 0 && (i.node.is_none() || i.dirty.content) {
                let mut p = i.ino;
                for _ in 0..10_000 {
                    if !needed.insert(p) || p == ROOT_INO {
                        break;
                    }
                    p = match self.inodes.get(&p) {
                        Some(x) => x.parent,
                        None => break,
                    };
                    if p == 0 {
                        break;
                    }
                }
            }
        }
        let gone: Vec<u64> = self
            .inodes
            .values()
            .filter(|i| i.node.is_some() && i.parent != 0 && !seen.contains(&i.ino))
            .map(|i| i.ino)
            .collect();
        for ino in gone {
            let keep = needed.contains(&ino)
                && !matches!(
                    self.inodes.get(&ino).map(|i| i.kind),
                    Some(Kind::Conflict(_))
                );
            let i = self.inodes.get_mut(&ino).expect("ino");
            let node = i.node.take().expect("committed");
            match i.kind {
                Kind::Conflict(v) => {
                    self.by_conflict.remove(&(node, v));
                }
                _ => {
                    if self.by_node.get(&node) == Some(&ino) {
                        self.by_node.remove(&node);
                    }
                }
            }
            if keep {
                tracing::info!(
                    "{} was deleted on another device while it had changes here; keeping it",
                    i.name
                );
                i.dirty = Dirty::all();
            } else {
                inval.push(Inval::Entry(i.parent, i.name.clone()));
                inval.push(Inval::Inode(ino));
                i.parent = 0;
                i.dirty = Dirty::default();
            }
        }

        // Positions.
        for (ino, pino, name) in placed {
            let i = self.inodes.get_mut(&ino).expect("ino");
            if i.parent != pino || i.name != name {
                if i.parent != 0 {
                    inval.push(Inval::Entry(i.parent, i.name.clone()));
                }
                i.parent = pino;
                i.name = name;
            }
        }
        self.rebuild_children();
        let detached: Vec<u64> = self
            .inodes
            .values()
            .filter(|i| i.parent == 0)
            .map(|i| i.ino)
            .collect();
        for ino in detached {
            self.gc(ino);
        }
        self.applied_version = snap.version;
        inval
    }

    /// Recomputes every folder's children from the inodes' positions. A
    /// name taken twice (a local new file and one from elsewhere) shows
    /// the later as `name (n)`.
    fn rebuild_children(&mut self) {
        for i in self.inodes.values_mut() {
            i.children.clear();
        }
        let mut items: Vec<(u64, u64, String, bool)> = self
            .inodes
            .values()
            .filter(|i| i.ino != ROOT_INO && i.parent != 0)
            .map(|i| {
                (
                    i.ino,
                    i.parent,
                    i.name.clone(),
                    i.node.is_none() || i.dirty.pos,
                )
            })
            .collect();
        // local changes first, so they keep their names
        items.sort_by_key(|(ino, _, _, local)| (!*local, *ino));
        for (ino, parent, name, _) in items {
            if !self.inodes.contains_key(&parent) {
                if let Some(i) = self.inodes.get_mut(&ino) {
                    i.parent = 0;
                }
                continue;
            }
            let mut final_name = name.clone();
            let mut n = 2;
            while self.inodes[&parent].children.contains_key(&final_name) {
                let (stem, ext) = match name.rfind('.') {
                    Some(i) if i > 0 => (&name[..i], &name[i..]),
                    _ => (name.as_str(), ""),
                };
                final_name = format!("{stem} ({n}){ext}");
                n += 1;
            }
            self.inodes
                .get_mut(&parent)
                .expect("parent")
                .children
                .insert(final_name.clone(), ino);
            self.inodes.get_mut(&ino).expect("ino").name = final_name;
        }
    }
}
