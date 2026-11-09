//! The tree the mount shows: the files space's state, overlaid with local
//! changes that have not been committed as an entry yet.
//!
//! Each inode maps to a node of the space once it has been created there
//! (`node`), or to one version of a file in conflict. Local changes set
//! dirty flags; the committer turns them into ops after the quiet period
//! and records the node ids that entries created. When entries arrive
//! from other devices, [`Tree::apply`] brings committed inodes up to date
//! without touching what is dirty.

use crate::fsat::FileExt;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io;
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
/// per file until the next commit. A local item's content
/// ([`Staged::local`]) is its real file under `local/`, which outlives
/// the `Staged`.
pub struct Staged {
    file: Mutex<Option<File>>,
    path: PathBuf,
    keep: bool,
    /// Kept on disk past the drop: named in the journal for the next start.
    retained: std::sync::atomic::AtomicBool,
}

impl Staged {
    /// The content of a local item: the real file at `path`, opened when
    /// first used.
    pub fn local(path: PathBuf) -> Arc<Staged> {
        Arc::new(Staged {
            file: Mutex::new(None),
            path,
            keep: true,
            retained: Default::default(),
        })
    }

    /// Where the content is.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Opens the file if it is not open, so it stays readable after its
    /// name is removed.
    pub fn keep_open(&self) -> io::Result<()> {
        self.with(|_| Ok(()))
    }

    fn with<R>(&self, f: impl FnOnce(&File) -> io::Result<R>) -> io::Result<R> {
        let mut g = self.file.lock().unwrap_or_else(|e| e.into_inner());
        if g.is_none() {
            let rw = OpenOptions::new().read(true).write(true).open(&self.path);
            *g = Some(match rw {
                // a read-only local file: the kernel refuses writes to it
                Err(e) if self.keep && e.kind() == io::ErrorKind::PermissionDenied => {
                    File::open(&self.path)?
                }
                r => r?,
            });
        }
        f(g.as_ref().expect("opened"))
    }

    /// The content of a local item just created as `file` at `path`.
    pub fn local_open(path: PathBuf, file: File) -> Arc<Staged> {
        Arc::new(Staged {
            file: Mutex::new(Some(file)),
            path,
            keep: true,
            retained: Default::default(),
        })
    }

    /// The same content, now at `path` (its file was moved there): a local
    /// item's, keeping the open file.
    pub fn moved(&self, path: PathBuf) -> Arc<Staged> {
        let file = self.file.lock().unwrap_or_else(|e| e.into_inner()).take();
        Arc::new(Staged {
            file: Mutex::new(file),
            path,
            keep: true,
            retained: Default::default(),
        })
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

    #[allow(clippy::len_without_is_empty)] // a length that can fail
    pub fn len(&self) -> io::Result<u64> {
        Ok(std::fs::metadata(&self.path)?.len())
    }

    pub fn sync_data(&self) -> io::Result<()> {
        self.with(|f| f.sync_data())
    }

    pub fn set_modified(&self, t: SystemTime) -> io::Result<()> {
        self.with(|f| f.set_modified(t))
    }

    /// Keeps the file when this is dropped: the journal names it.
    pub fn retain(&self) {
        self.retained
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Closes the staging file; the next access reopens it.
    pub fn close(&self) {
        self.file.lock().unwrap_or_else(|e| e.into_inner()).take();
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        if !self.keep && !self.retained.load(std::sync::atomic::Ordering::Relaxed) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// A journal record: a staging file an application flushed, and where.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct Flushed {
    path: Vec<String>,
    staged: String,
    perm: u16,
    /// The node it changes, if it was committed before (hex).
    #[serde(default)]
    node: Option<String>,
    /// The versions its content was written over (hex entry ids), so that
    /// a version from elsewhere it never saw is kept beside it.
    #[serde(default)]
    seen: Vec<String>,
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
    /// Whether anything changed (for diagnostics).
    pub fn any_change(&self) -> bool {
        self.any()
    }

    fn any(&self) -> bool {
        self.pos || self.content || self.mode || self.mtime
    }
    pub(crate) fn all() -> Dirty {
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
    /// The entries of the content versions the local view is based on:
    /// those last applied, or the entry that committed the local content.
    /// A local edit supersedes these and only these.
    pub seen: Vec<EntryId>,
    /// Local content, authoritative when present.
    pub staged: Option<Arc<Staged>>,
    /// Link target.
    pub target: String,
    /// The name in the state, when the item came from it. [`Inode::name`]
    /// may be the view's `name (2)`; created again, it takes this one.
    pub stored_name: Option<String>,
    /// Uncommitted changes.
    pub dirty: Dirty,
    /// Open handles that may write.
    pub writers: u32,
    /// Open handles.
    pub opens: u32,
    /// When it was last written.
    pub last_write: Option<Instant>,
    /// When the writes not yet committed began.
    pub first_write: Option<Instant>,
    /// Bumped on every write.
    pub write_gen: u64,
    /// The `write_gen` that [`Inode::content`] was encoded at.
    pub content_gen: u64,
    /// The journal's record of its flushed staging file, if it has one.
    pub journaled: Option<String>,
    /// Kernel lookups outstanding.
    pub nlookup: u64,
    /// Kept on this device only (`fs/local.rs`): never committed; its
    /// content and metadata are a real file or folder under `local/`.
    pub local: bool,
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
            seen: Vec::new(),
            staged: None,
            target: String::new(),
            stored_name: None,
            dirty: Dirty::default(),
            writers: 0,
            opens: 0,
            last_write: None,
            first_write: None,
            write_gen: 0,
            content_gen: 0,
            journaled: None,
            nlookup: 0,
            local: false,
        }
    }

    /// Whether it is being written right now (written within `quiet` and
    /// still open for writing).
    pub fn busy(&self, quiet: Duration) -> bool {
        self.writers > 0 && self.last_write.is_some_and(|t| t.elapsed() < quiet)
    }

    /// Records a change to its content.
    pub fn wrote(&mut self) {
        self.write_gen += 1;
        self.first_write.get_or_insert_with(Instant::now);
    }

    /// Whether its uncommitted writes began at least `longest` ago.
    pub fn overdue(&self, longest: Duration) -> bool {
        self.first_write.is_some_and(|t| t.elapsed() >= longest)
    }

    /// Whether a commit should wait for it: it is being written right now,
    /// but not yet for `longest`. A file written continuously is committed
    /// every `longest` as it stands, as a copy would take it
    /// (`profiles.md#mapping-to-a-disk-guidance`).
    pub fn held_back(&self, quiet: Duration, longest: Duration) -> bool {
        self.busy(quiet) && !self.overdue(longest)
    }

    /// After a commit of its content: clean if nothing was written since
    /// the content was encoded, otherwise still dirty, with a new burst.
    pub fn content_committed(&mut self) {
        if self.write_gen == self.content_gen {
            self.dirty.content = false;
            self.first_write = None;
        } else {
            self.dirty.content = true;
            self.first_write = Some(Instant::now());
        }
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
    /// The node's own name.
    pub stored_name: String,
    /// The node.
    pub node: NodeId,
    /// For a conflict copy, the version.
    pub version: Option<EntryId>,
    /// The kind.
    pub kind: FileKind,
    /// The content shown.
    pub content: Option<Content>,
    /// The entries of every current content version (files).
    pub versions: Vec<EntryId>,
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
    /// The space's heads when it was taken.
    pub heads: Vec<EntryId>,
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
                    stored_name: e.stored_name.clone(),
                    node: e.node,
                    version: e.conflict_version,
                    kind: e.kind,
                    content: None,
                    versions: Vec::new(),
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
                        se.versions = versions.iter().map(|v| v.entry).collect();
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
        Snapshot {
            version,
            heads: space.heads(),
            entries,
        }
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
    /// The root's inode: [`ROOT_INO`] for the person's own files, and
    /// above a base of its own for each shared folder beside them, so that
    /// one mount's inodes never collide (`fs/onefs.rs`).
    pub root: u64,
    /// Inodes.
    pub inodes: HashMap<u64, Inode>,
    /// Committed node -> inode.
    pub by_node: HashMap<NodeId, u64>,
    /// Conflict copy (node, version) -> inode.
    pub by_conflict: HashMap<(NodeId, EntryId), u64>,
    next_ino: u64,
    next_stage: u64,
    staging: PathBuf,
    /// Where local items live (`fs/local.rs`).
    pub local_dir: PathBuf,
    /// `.cardinalignore` matchers.
    pub ignores: super::local::Ignores,
    /// The `.cardinalignore` files' text as last applied
    /// ([`Tree::reevaluate`]).
    pub ignore_seen: Option<super::local::IgnoreTexts>,
    /// Nodes to delete at the next commit.
    pub deleted: Vec<Deleted>,
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
    /// The heads of the state this tree shows, apart from the remote
    /// changes to what has local changes (which [`Tree::apply`] skips):
    /// what a local change made now has seen.
    pub seen_heads: Vec<EntryId>,
    /// Kernel caches to invalidate from an apply made by the committer.
    pub pending_inval: Vec<Inval>,
}

/// A node deleted locally, not yet committed.
#[derive(Clone, Debug)]
pub struct Deleted {
    /// The node.
    pub node: NodeId,
    /// [`Tree::seen_heads`] when it was deleted: the delete has seen
    /// these entries and no others.
    pub base: Vec<EntryId>,
    /// For a file, the content versions it showed ([`Inode::seen`]): its
    /// remote changes may have been skipped while it had local ones.
    pub seen: Option<Vec<EntryId>>,
}

impl Tree {
    /// An empty tree, staging changes in `staging` and keeping local items
    /// in `local_dir`.
    pub fn new(staging: PathBuf, local_dir: PathBuf) -> Tree {
        Tree::with_base(staging, local_dir, 0)
    }

    /// The same, numbering its inodes from `base`.
    pub fn with_base(staging: PathBuf, local_dir: PathBuf, base: u64) -> Tree {
        let root_ino = base + ROOT_INO;
        let mut inodes = HashMap::new();
        let mut root = Inode::new(root_ino, Kind::Dir);
        root.node = Some(ROOT);
        root.parent = root_ino;
        inodes.insert(root_ino, root);
        let mut by_node = HashMap::new();
        by_node.insert(ROOT, root_ino);
        Tree {
            root: root_ino,
            inodes,
            by_node,
            by_conflict: HashMap::new(),
            next_ino: root_ino + 1,
            next_stage: 1,
            staging,
            local_dir,
            ignores: Default::default(),
            ignore_seen: None,
            deleted: Vec::new(),
            settle: HashMap::new(),
            first_change: None,
            last_change: None,
            min_version: 0,
            applied_version: 0,
            seen_heads: Vec::new(),
            pending_inval: Vec::new(),
        }
    }

    /// The journal of flushed staging files: what an application flushed
    /// (`fsync`) and is not committed yet, so a restart commits it
    /// (`profiles.md#mapping-to-a-disk-guidance`).
    fn journal(&self) -> PathBuf {
        self.staging.join("journal")
    }

    /// The journal's record for `ino`: where it is, its staging file, its
    /// mode, its node and the versions it was written over.
    fn journal_record(&self, ino: u64) -> Option<String> {
        let i = self.inodes.get(&ino)?;
        if i.local || i.kind != Kind::File {
            return None;
        }
        let staged = i.staged.as_ref()?.path().file_name()?.to_str()?.to_owned();
        let mut path = Vec::new();
        let mut at = ino;
        while at != self.root {
            let x = self.inodes.get(&at)?;
            if x.parent == 0 {
                return None; // detached
            }
            path.push(x.stored_name.clone().unwrap_or_else(|| x.name.clone()));
            at = x.parent;
        }
        path.reverse();
        let rec = Flushed {
            path,
            staged,
            perm: i.perm,
            node: i.node.map(hex::encode),
            seen: i.seen.iter().map(hex::encode).collect(),
        };
        serde_json::to_string(&rec).ok()
    }

    /// After `ino`'s staging file was flushed: records it in the journal,
    /// flushed too, unless the journal already says the same.
    pub fn journal_flushed(&mut self, ino: u64) -> io::Result<()> {
        let Some(rec) = self.journal_record(ino) else {
            return Ok(());
        };
        if self.inodes.get(&ino).and_then(|i| i.journaled.as_ref()) == Some(&rec) {
            return Ok(());
        }
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.journal())?;
        std::io::Write::write_all(&mut f, format!("{rec}\n").as_bytes())?;
        f.sync_data()?;
        // the staging file's own name, and the journal's
        File::open(&self.staging)?.sync_all()?;
        if let Some(i) = self.inodes.get_mut(&ino) {
            i.journaled = Some(rec);
        }
        Ok(())
    }

    /// Writes the journal again from what it should name now: every
    /// recorded file still dirty and attached, at its current place. A
    /// rename or delete is durable once this has run (`fsyncdir`).
    pub fn journal_rewrite(&mut self) -> io::Result<()> {
        let inos: Vec<u64> = self
            .inodes
            .values()
            .filter(|i| i.journaled.is_some())
            .map(|i| i.ino)
            .collect();
        let mut text = String::new();
        for ino in inos {
            let i = &self.inodes[&ino];
            let rec = (i.dirty.content || i.node.is_none())
                .then(|| self.journal_record(ino))
                .flatten();
            if let Some(rec) = &rec {
                text.push_str(rec);
                text.push('\n');
            }
            self.inodes.get_mut(&ino).expect("ino").journaled = rec;
        }
        if text.is_empty() {
            match std::fs::remove_file(self.journal()) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
                r => r?,
            }
        } else {
            let tmp = self.staging.join("journal.new");
            {
                let mut f = File::create(&tmp)?;
                std::io::Write::write_all(&mut f, text.as_bytes())?;
                f.sync_data()?;
            }
            std::fs::rename(&tmp, self.journal())?;
        }
        File::open(&self.staging)?.sync_all()
    }

    /// After a commit: writes the journal again if something it named is
    /// committed now, or gone.
    pub fn journal_committed(&mut self) -> io::Result<()> {
        let stale = self.inodes.values().any(|i| {
            i.journaled.is_some()
                && ((!i.dirty.content && i.node.is_some()) || i.staged.is_none() || i.parent == 0)
        });
        if stale {
            self.journal_rewrite()?;
        }
        Ok(())
    }

    /// Before the tree is dropped with changes it could not commit: names
    /// every dirty staging file in the journal and keeps the files, flushed,
    /// so the next start takes them up. An unmount keeps what was written.
    pub fn journal_all_dirty(&mut self) -> io::Result<()> {
        let inos: Vec<u64> = self
            .inodes
            .values()
            .filter(|i| {
                i.parent != 0
                    && !i.local
                    && i.kind == Kind::File
                    && i.staged.is_some()
                    && (i.dirty.content || i.node.is_none())
            })
            .map(|i| i.ino)
            .collect();
        for ino in &inos {
            let i = self.inodes.get_mut(ino).expect("ino");
            let st = i.staged.clone().expect("staged");
            st.sync_data()?;
            st.retain();
            i.journaled = Some(String::new()); // written below
        }
        if inos.is_empty() {
            return Ok(());
        }
        self.journal_rewrite()
    }

    /// At start, before anything is written: takes up every staging file the
    /// journal names, as uncommitted content of the node it changes, or of
    /// a new file at its path, and removes the staging files nothing names.
    /// A recorded edit that `own_since` says this device committed since is
    /// done. Returns how many it took up.
    pub fn replay_journal(&mut self, own_since: impl Fn(&EntryId) -> bool) -> usize {
        let text = std::fs::read_to_string(self.journal()).unwrap_or_default();
        // the last record for a staging file wins
        let mut recs: Vec<Flushed> = Vec::new();
        for line in text.lines() {
            let Ok(r) = serde_json::from_str::<Flushed>(line) else {
                continue; // a record cut short by the crash
            };
            recs.retain(|o| o.staged != r.staged);
            recs.push(r);
        }
        let unhex = |h: &str| -> Option<Vec<u8>> { hex::decode(h).ok() };
        let mut taken: HashSet<String> = HashSet::new();
        for r in recs {
            let file = self.staging.join(&r.staged);
            if r.path.is_empty() || r.staged.contains('/') || !file.is_file() {
                continue;
            }
            let seen: Vec<EntryId> = r
                .seen
                .iter()
                .filter_map(|h| unhex(h)?.try_into().ok())
                .collect();
            let node: Option<NodeId> = r.node.as_deref().and_then(|h| unhex(h)?.try_into().ok());
            // the node it changes, if it is still there
            let mut at = node
                .and_then(|n| self.by_node.get(&n).copied())
                .filter(|i| {
                    self.inodes
                        .get(i)
                        .is_some_and(|x| x.kind == Kind::File && !x.local)
                });
            if let Some(ino) = at {
                let since = &self.inodes[&ino].seen;
                if since.iter().any(|e| !seen.contains(e) && own_since(e)) {
                    continue; // committed here after the record: done
                }
            } else {
                // a new file, or one deleted elsewhere: a new file at its path
                let mut parent = self.root;
                let (last, dirs) = r.path.split_last().expect("not empty");
                for name in dirs {
                    parent = match self.child(parent, name) {
                        Some(c) if self.inodes[&c].kind == Kind::Dir => c,
                        _ => {
                            let n = self.alloc(Kind::Dir);
                            self.inodes.get_mut(&n).expect("new").perm = 0o755;
                            let shown = self.free_name(parent, name);
                            self.attach(n, parent, &shown);
                            if shown != *name {
                                self.inodes.get_mut(&n).expect("new").stored_name =
                                    Some(name.clone());
                            }
                            n
                        }
                    };
                }
                let n = self.alloc(Kind::File);
                let shown = self.free_name(parent, last);
                self.attach(n, parent, &shown);
                if shown != *last {
                    self.inodes.get_mut(&n).expect("new").stored_name = Some(last.clone());
                }
                at = Some(n);
            }
            let ino = at.expect("placed");
            let size = std::fs::metadata(&file).map(|m| m.len()).unwrap_or(0);
            let i = self.inodes.get_mut(&ino).expect("ino");
            i.staged = Some(Arc::new(Staged {
                file: Mutex::new(None),
                path: file,
                keep: false,
                retained: Default::default(),
            }));
            i.size = size;
            i.perm = r.perm;
            i.dirty.content = true;
            if i.node.is_some() {
                i.seen = seen;
            }
            i.mtime = SystemTime::now();
            i.ctime = i.mtime;
            i.wrote();
            i.journaled = Some(String::new()); // written below
            taken.insert(r.staged);
        }
        // staging files of earlier runs that nothing takes up
        if let Ok(rd) = std::fs::read_dir(&self.staging) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if e.file_type().is_ok_and(|t| t.is_file())
                    && !name.starts_with("journal")
                    && !taken.contains(&name)
                {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
        // what was taken up stays named until it is committed
        if let Err(e) = self.journal_rewrite() {
            tracing::warn!("cannot write the journal of flushed files: {e}");
        }
        if !taken.is_empty() {
            self.touch();
        }
        taken.len()
    }

    /// `name`, or `name (recovered)`, `name (recovered 2)` … if a child of
    /// `parent` has it.
    fn free_name(&self, parent: u64, name: &str) -> String {
        if self.child(parent, name).is_none() {
            return name.to_owned();
        }
        let (stem, ext) = match name.rfind('.') {
            Some(k) if k > 0 => (&name[..k], &name[k..]),
            _ => (name, ""),
        };
        (1..)
            .map(|n| match n {
                1 => format!("{stem} (recovered){ext}"),
                n => format!("{stem} (recovered {n}){ext}"),
            })
            .find(|c| self.child(parent, c).is_none())
            .expect("a free name")
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
                .any(|i| i.parent != 0 && !i.local && (i.node.is_none() || i.dirty.any()))
    }

    /// Records a node to delete at the next commit; `seen`, for a file,
    /// the content versions its view was based on.
    pub fn delete_node(&mut self, node: NodeId, seen: Option<Vec<EntryId>>) {
        self.deleted.push(Deleted {
            node,
            base: self.seen_heads.clone(),
            seen,
        });
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
            i.stored_name = None;
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
        let (node, kind) = (i.node.take(), i.kind);
        let seen = (kind == Kind::File).then(|| i.seen.clone());
        i.dirty = Dirty::default();
        if let Some(n) = node {
            match kind {
                Kind::Conflict(v) => {
                    self.by_conflict.remove(&(n, v));
                }
                _ => {
                    self.by_node.remove(&n);
                    self.delete_node(n, seen);
                }
            }
        }
        self.gc(ino);
    }

    /// Frees a detached inode nobody refers to.
    pub fn gc(&mut self, ino: u64) {
        if ino == self.root {
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
            if b == self.root || b == 0 {
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
        while ino != self.root && ino != 0 {
            let Some(i) = self.inodes.get(&ino) else {
                break;
            };
            parts.push(i.name.clone());
            ino = i.parent;
        }
        parts.reverse();
        parts.join("/")
    }

    /// A name for a new staging file that no file of this or an earlier
    /// run has: a process with the same id after a restart must not reuse
    /// a file the journal names.
    fn stage_name(&mut self) -> PathBuf {
        let n = self.next_stage;
        self.next_stage += 1;
        let r: [u8; 8] = cardinal_crypto::random_bytes();
        self.staging.join(format!(
            "{}-{n}-{:016x}",
            std::process::id(),
            u64::from_le_bytes(r)
        ))
    }

    /// Moves the file at `src` into staging, as staged content.
    pub fn stage_from(&mut self, src: &std::path::Path) -> std::io::Result<Arc<Staged>> {
        let path = self.stage_name();
        std::fs::rename(src, &path)?;
        Ok(Arc::new(Staged {
            file: Mutex::new(None),
            path,
            keep: false,
            retained: Default::default(),
        }))
    }

    /// Creates a staging file holding `initial` bytes.
    pub fn new_staged(&mut self) -> std::io::Result<Arc<Staged>> {
        let path = self.stage_name();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)?;
        Ok(Arc::new(Staged {
            file: Mutex::new(Some(file)),
            path,
            keep: false,
            retained: Default::default(),
        }))
    }

    /// Brings committed inodes up to date with a snapshot of the space,
    /// keeping local changes. Returns kernel caches to invalidate.
    pub fn apply(&mut self, snap: &Snapshot) -> Vec<Inval> {
        let mut inval = Vec::new();
        let mut seen: HashSet<u64> = HashSet::new();
        seen.insert(self.root);
        // desired parent inode and name for each committed inode
        let mut placed: Vec<(u64, u64, String)> = Vec::new();
        // deleted here and not committed yet: stays gone
        let deleting: HashSet<NodeId> = self.deleted.iter().map(|d| d.node).collect();
        for e in &snap.entries {
            if deleting.contains(&e.node) {
                continue;
            }
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
            inode.stored_name = Some(e.stored_name.clone());
            if !inode.dirty.pos {
                placed.push((ino, pino, e.name.clone()));
            }
            match kind {
                Kind::File | Kind::Conflict(_) => {
                    if !inode.dirty.content {
                        inode.seen = match e.version {
                            Some(v) => vec![v],
                            None => e.versions.clone(),
                        };
                    }
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
        // to be created again; the folder a move here went to is one. A
        // folder with only local items beneath it (`fs/local.rs`) becomes
        // local itself: kept here, not created again on every device.
        let mut needed: HashSet<u64> = HashSet::new();
        let mut needed_local: HashSet<u64> = HashSet::new();
        for i in self.inodes.values() {
            let changed = i.node.is_none() || i.dirty.content;
            if i.parent != 0 && (changed || i.dirty.pos) {
                let set = if i.local {
                    &mut needed_local
                } else {
                    &mut needed
                };
                let mut p = if changed { i.ino } else { i.parent };
                for _ in 0..10_000 {
                    if !set.insert(p) || p == self.root {
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
            let kind = self.inodes.get(&ino).map(|i| i.kind);
            let conflict = matches!(kind, Some(Kind::Conflict(_)));
            let keep = needed.contains(&ino) && !conflict;
            let to_local = !keep && kind == Some(Kind::Dir) && needed_local.contains(&ino);
            let i = self.inodes.get_mut(&ino).expect("ino");
            let node = i.node.take().expect("committed");
            let name = i.name.clone();
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
                    "{name} was deleted on another device while it had changes here; keeping it"
                );
                self.inodes.get_mut(&ino).expect("ino").dirty = Dirty::all();
                self.rekey_local(&node, ino);
            } else if to_local {
                tracing::info!(
                    "{name} was deleted on another device; keeping it on this device for what \
                     it holds that is not synced"
                );
                self.become_local(ino, &node);
            } else {
                let i = self.inodes.get_mut(&ino).expect("ino");
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
        self.seen_heads = snap.heads.clone();
        inval
    }

    /// Recomputes every folder's children from the inodes' positions. A
    /// name taken twice (a local new file and one from elsewhere) shows
    /// the later as `name (n)`.
    pub(crate) fn rebuild_children(&mut self) {
        for i in self.inodes.values_mut() {
            i.children.clear();
        }
        let mut items: Vec<(u64, u64, String, bool, Option<NodeId>)> = self
            .inodes
            .values()
            .filter(|i| i.ino != self.root && i.parent != 0)
            .map(|i| {
                (
                    i.ino,
                    i.parent,
                    i.name.clone(),
                    i.node.is_none() || i.dirty.pos,
                    i.node,
                )
            })
            .collect();
        // Local changes first, so they keep their names; then the rest by
        // name and node, so a name taken here makes the same choice on
        // every device and after every restart.
        items.sort_by(|a, b| {
            (!a.3, if a.3 { a.0 } else { 0 }, &a.2, a.4).cmp(&(
                !b.3,
                if b.3 { b.0 } else { 0 },
                &b.2,
                b.4,
            ))
        });
        for (ino, parent, name, _, _) in items {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_journal_takes_up_what_was_flushed_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let staging = dir.path().join("staging");
        std::fs::create_dir_all(&staging).unwrap();
        let mut t = Tree::new(staging.clone(), dir.path().join("local"));
        // a file in a folder neither of which is committed yet
        let folder = t.alloc(Kind::Dir);
        t.attach(folder, t.root, "notes");
        let f = t.alloc(Kind::File);
        t.attach(f, folder, "today.md");
        let st = t.new_staged().unwrap();
        st.write_all_at(b"flushed", 0).unwrap();
        st.sync_data().unwrap();
        t.inodes.get_mut(&f).unwrap().staged = Some(st.clone());
        t.inodes.get_mut(&f).unwrap().perm = 0o600;
        t.journal_flushed(f).unwrap();
        t.journal_flushed(f).unwrap();
        let journal = std::fs::read_to_string(staging.join("journal")).unwrap();
        assert_eq!(journal.lines().count(), 1, "the same record once");
        // a record the crash cut short, and a staging file nothing names
        std::fs::write(
            staging.join("journal"),
            format!("{journal}{{\"path\":[\"half"),
        )
        .unwrap();
        std::fs::write(staging.join("99999-1"), b"left over").unwrap();
        let staged_name = st.path().file_name().unwrap().to_owned();
        std::mem::forget(st); // the process died: its file stays
        std::mem::forget(t);

        let mut t = Tree::new(staging.clone(), dir.path().join("local"));
        assert_eq!(t.replay_journal(|_| false), 1);
        let folder = t.child(t.root, "notes").expect("folder made again");
        assert_eq!(t.inodes[&folder].kind, Kind::Dir);
        let f = t.child(folder, "today.md").expect("file taken up");
        let i = &t.inodes[&f];
        assert!(i.dirty.content && i.node.is_none() && i.perm == 0o600 && i.size == 7);
        let mut buf = [0u8; 7];
        i.staged
            .as_ref()
            .unwrap()
            .read_exact_at(&mut buf, 0)
            .unwrap();
        assert_eq!(&buf, b"flushed");
        assert!(!staging.join("99999-1").exists(), "a leftover is removed");
        assert!(staging.join(&staged_name).exists());
        assert!(t.has_pending() && t.first_change.is_some());

        // a second crash before the commit: still there
        std::mem::forget(t);
        let mut t = Tree::new(staging.clone(), dir.path().join("local"));
        assert_eq!(t.replay_journal(|_| false), 1, "the journal still names it");
        let f = t
            .child(t.child(t.root, "notes").unwrap(), "today.md")
            .unwrap();
        // a new staging file after a restart never reuses its name
        let other = t.new_staged().unwrap();
        other.write_all_at(b"something else", 0).unwrap();
        let mut buf = [0u8; 7];
        t.inodes[&f]
            .staged
            .as_ref()
            .unwrap()
            .read_exact_at(&mut buf, 0)
            .unwrap();
        assert_eq!(&buf, b"flushed");
        drop(other);

        // renamed, then flushed again: it comes back once, where it went
        let notes = t.child(t.root, "notes").unwrap();
        t.detach(f);
        t.attach(f, notes, "final.md");
        t.journal_flushed(f).unwrap();
        std::mem::forget(t);
        let mut t = Tree::new(staging.clone(), dir.path().join("local"));
        assert_eq!(t.replay_journal(|_| false), 1);
        let notes = t.child(t.root, "notes").unwrap();
        assert!(t.child(notes, "final.md").is_some());
        assert!(t.child(notes, "today.md").is_none());
    }
}
