//! Paths kept on this device only.
//!
//! A `.cardinalignore` file, in gitignore syntax, names paths in its
//! folder and below that stay on this device: they show in the mount like
//! anything else but are never committed, so other devices never see
//! them. As in git, the nearest file with a matching line decides, and a
//! `!` line brings a path back. The files themselves sync like any other.
//!
//! - A new item is local when its folder is local or its path is ignored.
//!   What is already synced stays synced where it is, even if a line now
//!   matches it; delete it once and what is made there next stays local.
//! - Moving a local item to where a new item would sync makes it synced;
//!   moving a synced file to where a new one would be local makes it local
//!   (and removes it from the other devices). A synced folder cannot move
//!   into a local place (`EXDEV`: `mv` copies instead).
//! - When a line stops matching a local item, it becomes synced.
//! - A synced folder deleted elsewhere that holds local items here becomes
//!   local here (see [`Tree::apply`]).
//!
//! Local items are real files, folders and links under `local/` in the
//! data directory. A local item whose parent is synced is
//! `local/<parent>/<name>`, where `<parent>` is the parent's node id in
//! hex, or `new-<inode>` until a new parent is committed; what is in a
//! local folder is in its real folder. So renaming a synced folder, here
//! or elsewhere, moves nothing on disk.

use std::collections::HashMap;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cardinal_blob::{BlobReader, FsStore, NoFetch};
use cardinal_space::files::Content;
use cardinal_space::{NodeId, Space, ROOT};
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use ignore::Match;

use super::tree::{Dirty, Inode, Kind, Staged, Tree, ROOT_INO};
use crate::fetch::blob_ref;

/// The name of the files that list paths to keep local.
pub const IGNORE_FILE: &str = ".cardinalignore";

/// The most of a `.cardinalignore` file that is read.
const MAX_IGNORE_FILE: u64 = 1 << 20;

/// Matchers built from `.cardinalignore` files, by the folder they are in
/// and their text.
#[derive(Default)]
pub struct Ignores {
    by_dir: HashMap<(u64, blake3::Hash), Arc<Gitignore>>,
}

/// The bytes of a small file as the mount shows it: staged, inline, or
/// from the store (never fetched: a file not here yet reads as empty).
pub fn read_small(store: &FsStore, i: &Inode) -> Vec<u8> {
    if let Some(st) = &i.staged {
        let n = i.size.min(MAX_IGNORE_FILE) as usize;
        let mut buf = vec![0u8; n];
        let mut got = 0;
        while got < n {
            match st.read_at(&mut buf[got..], got as u64) {
                Ok(0) | Err(_) => break,
                Ok(k) => got += k,
            }
        }
        buf.truncate(got);
        return buf;
    }
    match &i.content {
        Some(Content::Inline(b)) => b.clone(),
        Some(Content::Blob(r)) => {
            let n = r.size.min(MAX_IGNORE_FILE) as usize;
            BlobReader::new(store, &NoFetch, blob_ref(r))
                .read_range(0, n)
                .unwrap_or_default()
        }
        None => Vec::new(),
    }
}

fn matcher(root: &str, text: &[u8]) -> Gitignore {
    let mut b = GitignoreBuilder::new(root);
    for line in String::from_utf8_lossy(text).lines() {
        if let Err(e) = b.add_line(None, line) {
            tracing::debug!("{IGNORE_FILE} in /{root}: {e}");
        }
    }
    b.build().unwrap_or_else(|_| Gitignore::empty())
}

/// The storage key of a synced folder: where its local items live.
fn key(i: &Inode) -> String {
    match i.node {
        Some(n) => hex::encode(n),
        None => format!("new-{}", i.ino),
    }
}

fn mtime_of(m: &std::fs::Metadata) -> SystemTime {
    UNIX_EPOCH
        + Duration::new(
            m.mtime().max(0) as u64,
            m.mtime_nsec().clamp(0, 999_999_999) as u32,
        )
}

/// The text of every `.cardinalignore` file, by the folder it is in.
pub type IgnoreTexts = HashMap<u64, Vec<u8>>;

impl Tree {
    /// Whether a new item `name` in folder `parent` stays on this device.
    pub fn ignored(&mut self, store: &FsStore, parent: u64, name: &str, is_dir: bool) -> bool {
        let mut text_of = |t: &Tree, d: u64| {
            let f = t.child(d, IGNORE_FILE)?;
            let i = &t.inodes[&f];
            (i.kind == Kind::File).then(|| read_small(store, i))
        };
        self.ignored_by(&mut text_of, parent, name, is_dir)
    }

    /// [`Tree::ignored`] by the ignore files' text in `texts`.
    fn ignored_in(&mut self, texts: &IgnoreTexts, parent: u64, name: &str, is_dir: bool) -> bool {
        self.ignored_by(
            &mut |_: &Tree, d: u64| texts.get(&d).cloned(),
            parent,
            name,
            is_dir,
        )
    }

    /// The text of every `.cardinalignore` file now.
    pub fn ignore_texts(&self, store: &FsStore) -> IgnoreTexts {
        self.inodes
            .values()
            .filter(|i| i.parent != 0 && i.kind == Kind::File && i.name == IGNORE_FILE)
            .map(|i| (i.parent, read_small(store, i)))
            .collect()
    }

    /// Whether the ignore files whose text `text_of` gives, by folder,
    /// keep `name` in `parent` local.
    fn ignored_by(
        &mut self,
        text_of: &mut dyn FnMut(&Tree, u64) -> Option<Vec<u8>>,
        parent: u64,
        name: &str,
        is_dir: bool,
    ) -> bool {
        if self.inodes.get(&parent).is_some_and(|p| p.local) {
            return true;
        }
        let full = match self.path(parent) {
            p if p.is_empty() => format!("/{name}"),
            p => format!("/{p}/{name}"),
        };
        let mut ignores = std::mem::take(&mut self.ignores);
        let mut d = parent;
        let mut out = false;
        for _ in 0..10_000 {
            if let Some(text) = text_of(self, d) {
                {
                    let h = blake3::hash(&text);
                    let gi = match ignores.by_dir.get(&(d, h)) {
                        Some(gi) => gi.clone(),
                        None => {
                            let root = format!("/{}", self.path(d));
                            let gi = Arc::new(matcher(&root, &text));
                            if ignores.by_dir.len() > 4096 {
                                ignores.by_dir.clear();
                            }
                            ignores.by_dir.insert((d, h), gi.clone());
                            gi
                        }
                    };
                    match gi.matched_path_or_any_parents(&full, is_dir) {
                        Match::Ignore(_) => {
                            out = true;
                            break;
                        }
                        Match::Whitelist(_) => break,
                        Match::None => {}
                    }
                }
            }
            if d == ROOT_INO || d == 0 {
                break;
            }
            d = self.inodes.get(&d).map_or(0, |i| i.parent);
        }
        self.ignores = ignores;
        out
    }

    /// The real path of a local item (`None` when it is detached).
    pub fn local_path(&self, ino: u64) -> Option<PathBuf> {
        let mut names = Vec::new();
        let mut cur = ino;
        for _ in 0..10_000 {
            let i = self.inodes.get(&cur)?;
            if !i.local {
                let mut p = self.local_dir.join(key(i));
                for n in names.iter().rev() {
                    p.push(n);
                }
                return Some(p);
            }
            if i.parent == 0 {
                return None;
            }
            names.push(i.name.clone());
            cur = i.parent;
        }
        None
    }

    /// Where a local item `name` in folder `parent` would be.
    pub fn local_child_path(&self, parent: u64, name: &str) -> Option<PathBuf> {
        let p = self.inodes.get(&parent)?;
        Some(if p.local {
            self.local_path(parent)?.join(name)
        } else {
            self.local_dir.join(key(p)).join(name)
        })
    }

    /// After real files moved: every local file at or beneath `root`
    /// reads its content from where it is now.
    pub fn repath_local(&mut self, root: u64) {
        let mut stack = vec![root];
        let mut files = Vec::new();
        while let Some(x) = stack.pop() {
            let Some(i) = self.inodes.get(&x) else {
                continue;
            };
            if i.local && i.kind == Kind::File {
                files.push(x);
            }
            stack.extend(i.children.values().copied());
        }
        for x in files {
            let Some(p) = self.local_path(x) else {
                continue;
            };
            if let Some(i) = self.inodes.get_mut(&x) {
                if let Some(st) = &i.staged {
                    if st.path() != p {
                        i.staged = Some(st.moved(p));
                    }
                }
            }
        }
    }

    /// Makes room for the real file of a new local item: the folder it
    /// goes in. Returns its path.
    pub fn local_place(&self, ino: u64) -> io::Result<PathBuf> {
        let p = self
            .local_path(ino)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))?;
        if let Some(dir) = p.parent() {
            std::fs::create_dir_all(dir)?;
        }
        Ok(p)
    }

    /// A synced folder deleted elsewhere becomes a local one: what was
    /// stored under its node moves to its new place.
    pub(crate) fn become_local(&mut self, ino: u64, old: &NodeId) {
        if let Some(i) = self.inodes.get_mut(&ino) {
            i.local = true;
            i.dirty = Dirty::default();
        }
        let src = self.local_dir.join(hex::encode(old));
        let r = self.local_place(ino).and_then(|dest| {
            if src.exists() {
                std::fs::rename(&src, &dest)
            } else {
                std::fs::create_dir_all(&dest)
            }
        });
        if let Err(e) = r {
            tracing::warn!("cannot keep {} on this device: {e}", self.path(ino));
        }
        self.repath_local(ino);
    }

    /// A synced folder that will be created again as new: its local items'
    /// storage follows it.
    pub(crate) fn rekey_local(&mut self, old: &NodeId, ino: u64) {
        let src = self.local_dir.join(hex::encode(old));
        if src.exists() {
            let dest = self.local_dir.join(format!("new-{ino}"));
            if let Err(e) = std::fs::rename(&src, &dest) {
                tracing::warn!("cannot move local items of {}: {e}", self.path(ino));
            }
            self.repath_local(ino);
        }
    }

    /// A new folder was committed as `node`: its local items' storage
    /// follows it.
    pub fn committed_dir(&mut self, ino: u64, node: &NodeId) {
        let src = self.local_dir.join(format!("new-{ino}"));
        if src.exists() {
            let dest = self.local_dir.join(hex::encode(node));
            if let Err(e) = std::fs::rename(&src, &dest) {
                tracing::warn!("cannot move local items of {}: {e}", self.path(ino));
            }
            self.repath_local(ino);
        }
    }

    /// A local item (with what is in it) becomes synced: new to the
    /// space, its content staged for the next commit. What in it is still
    /// ignored stays local, now beneath a synced folder. `old` is where
    /// its real file is (it may have moved in the tree already).
    pub fn local_to_synced(&mut self, store: &FsStore, ino: u64, old: PathBuf) -> io::Result<()> {
        // Every real path first, from `old` down: they change as items
        // stop being local.
        let mut order = Vec::new();
        let mut paths: HashMap<u64, PathBuf> = HashMap::new();
        paths.insert(ino, old);
        let mut stack = vec![ino];
        while let Some(x) = stack.pop() {
            order.push(x);
            let base = paths[&x].clone();
            if let Some(i) = self.inodes.get(&x) {
                for (name, c) in &i.children {
                    if self.inodes[c].local {
                        paths.insert(*c, base.join(name));
                        stack.push(*c);
                    }
                }
            }
        }
        let mut dirs = Vec::new();
        for x in order {
            let (parent, name, kind) = {
                let i = &self.inodes[&x];
                (i.parent, i.name.clone(), i.kind)
            };
            let Some(old) = paths.get(&x) else { continue };
            // A parent that stays local keeps it local; beneath one that
            // became synced, the lines decide.
            if self.inodes.get(&parent).is_some_and(|p| p.local) {
                continue;
            }
            if x != ino && self.ignored(store, parent, &name, kind == Kind::Dir) {
                let dest = self.local_place(x)?;
                std::fs::rename(old, dest)?;
                self.repath_local(x);
                continue;
            }
            match kind {
                Kind::File => {
                    let st = self.stage_from(old)?;
                    let i = self.inodes.get_mut(&x).expect("ino");
                    i.staged = Some(st);
                }
                Kind::Symlink => std::fs::remove_file(old)?,
                Kind::Dir => dirs.push(old.clone()),
                Kind::Conflict(_) => {}
            }
            let i = self.inodes.get_mut(&x).expect("ino");
            i.local = false;
            i.dirty = Dirty::all();
        }
        // Deepest first: what was moved out leaves them empty.
        dirs.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
        for d in dirs {
            if let Err(e) = std::fs::remove_dir(&d) {
                tracing::warn!("cannot remove {}: {e}", d.display());
            }
        }
        if let Some(p) = paths.get(&ino) {
            self.prune(p);
        }
        self.touch();
        Ok(())
    }

    /// After the real item at `path` went: its synced parent's storage
    /// folder, if that is now empty.
    pub fn prune(&self, path: &Path) {
        if let Some(dir) = path.parent() {
            if dir.parent() == Some(self.local_dir.as_path()) {
                let _ = std::fs::remove_dir(dir);
            }
        }
    }

    /// After `.cardinalignore` files changed: local items that the lines
    /// as last seen named and the lines now do not become synced. Others
    /// stay as they are, such as a folder kept here because it was deleted
    /// elsewhere, which no line names. Returns whether any changed.
    pub fn reevaluate(&mut self, store: &FsStore) -> bool {
        let now = self.ignore_texts(store);
        let before = self.ignore_seen.take().unwrap_or_else(|| now.clone());
        let roots: Vec<(u64, u64, String, bool)> = self
            .inodes
            .values()
            .filter(|i| i.local && i.parent != 0)
            .filter(|i| self.inodes.get(&i.parent).is_some_and(|p| !p.local))
            .map(|i| (i.ino, i.parent, i.name.clone(), i.kind == Kind::Dir))
            .collect();
        let mut changed = false;
        for (ino, parent, name, is_dir) in roots {
            if self.ignored_in(&before, parent, &name, is_dir)
                && !self.ignored_in(&now, parent, &name, is_dir)
            {
                tracing::info!("{} is no longer ignored; syncing it", self.path(ino));
                let Some(old) = self.local_path(ino) else {
                    continue;
                };
                if let Err(e) = self.local_to_synced(store, ino, old) {
                    tracing::warn!("cannot sync {}: {e}", self.path(ino));
                }
                changed = true;
            }
        }
        self.ignore_seen = Some(now);
        changed
    }

    /// Adds what `local/` holds to a tree just built from the space. A
    /// local folder whose synced parent was deleted while this device was
    /// off is put back where that parent was, as local folders.
    pub fn load_local(&mut self, space: Option<&Space>) {
        let Ok(rd) = std::fs::read_dir(&self.local_dir) else {
            return;
        };
        // Folders still here first, so a deleted one's place is found
        // among what they hold; empty storage goes.
        let mut entries: Vec<std::fs::DirEntry> = rd
            .flatten()
            .filter(|e| std::fs::remove_dir(e.path()).is_err())
            .collect();
        entries.sort_by_key(|e| {
            let live = hex::decode(e.file_name().to_string_lossy().as_bytes())
                .ok()
                .and_then(|b| NodeId::try_from(b).ok())
                .is_some_and(|n| self.by_node.contains_key(&n));
            !live
        });
        for e in entries {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with("new-") {
                tracing::warn!(
                    "{} holds local items of a folder that was never saved; they are not shown",
                    e.path().display()
                );
                continue;
            }
            let Some(node) = hex::decode(&name)
                .ok()
                .and_then(|b| NodeId::try_from(b).ok())
            else {
                continue;
            };
            let dir = match self.by_node.get(&node).copied() {
                Some(ino) if self.inodes[&ino].kind == Kind::Dir => Some(ino),
                _ => self.place_orphan(&node, space),
            };
            let Some(dir) = dir else { continue };
            let path = match self.inodes[&dir].local {
                true => match self.local_path(dir) {
                    Some(p) => p,
                    None => continue,
                },
                false => e.path(),
            };
            if self.inodes[&dir].local {
                // the orphan's items move to the folder that stands for it
                let _ = std::fs::create_dir_all(path.parent().unwrap_or(&path));
                if let Err(err) = std::fs::rename(e.path(), &path) {
                    tracing::warn!("cannot keep local items of a deleted folder: {err}");
                    continue;
                }
            }
            self.load_dir(&path, dir);
        }
        self.rebuild_children();
    }

    /// A local folder for a deleted synced folder, at its old place
    /// beneath the nearest folder still here (local folders for any
    /// deleted between).
    fn place_orphan(&mut self, node: &NodeId, space: Option<&Space>) -> Option<u64> {
        let st = space?.state();
        if st.node(node).is_some_and(|n| {
            n.kind != cardinal_space::NodeKind::Uint(cardinal_space::files::FOLDER)
        }) {
            tracing::warn!(
                "local items under {} are not under a folder; not shown",
                hex::encode(node)
            );
            return None;
        }
        let mut chain = Vec::new();
        let mut cur = *node;
        let anchor = loop {
            if let Some(&ino) = self.by_node.get(&cur) {
                break ino;
            }
            if cur == ROOT {
                break ROOT_INO;
            }
            let n = st.node(&cur)?;
            chain.push(n.name.clone());
            cur = n.parent;
            if chain.len() > 10_000 {
                return None;
            }
        };
        let mut parent = anchor;
        for name in chain.into_iter().rev() {
            parent = match self.child(parent, &name) {
                Some(c) if self.inodes[&c].kind == Kind::Dir && self.inodes[&c].local => c,
                _ => {
                    let ino = self.alloc(Kind::Dir);
                    self.inodes.get_mut(&ino).expect("new").local = true;
                    self.attach(ino, parent, &name);
                    ino
                }
            };
        }
        tracing::info!(
            "{} was deleted on another device while this one was off; keeping it on this \
             device for what it holds that is not synced",
            self.path(parent)
        );
        Some(parent)
    }

    /// Adds the real folder `path`'s entries beneath `parent`, as local
    /// items.
    fn load_dir(&mut self, path: &Path, parent: u64) {
        let Ok(rd) = std::fs::read_dir(path) else {
            return;
        };
        for e in rd.flatten() {
            let Ok(m) = e.metadata() else { continue };
            let Some(name) = e.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let ft = m.file_type();
            let kind = if ft.is_dir() {
                Kind::Dir
            } else if ft.is_symlink() {
                Kind::Symlink
            } else if ft.is_file() {
                Kind::File
            } else {
                continue;
            };
            // a local folder already here (put back for a deleted one):
            // what this one holds joins it
            if let Some(c) = self.child(parent, &name) {
                if kind == Kind::Dir && self.inodes[&c].local && self.inodes[&c].kind == Kind::Dir {
                    self.load_dir(&e.path(), c);
                    continue;
                }
            }
            let ino = self.alloc(kind);
            {
                let i = self.inodes.get_mut(&ino).expect("new");
                i.local = true;
                i.perm = (m.permissions().mode() & 0o7777) as u16;
                i.mtime = mtime_of(&m);
                i.ctime = i.mtime;
                match kind {
                    Kind::File => {
                        i.size = m.len();
                        i.staged = Some(Staged::local(e.path()));
                    }
                    Kind::Symlink => {
                        i.target = std::fs::read_link(e.path())
                            .map(|t| t.to_string_lossy().into_owned())
                            .unwrap_or_default();
                        i.size = i.target.len() as u64;
                    }
                    _ => {}
                }
            }
            // a name taken by a synced item shows that one as `name (2)`
            if let Some(p) = self.inodes.get_mut(&parent) {
                if let Some(other) = p.children.remove(&name) {
                    if let Some(o) = self.inodes.get_mut(&other) {
                        o.parent = parent;
                    }
                }
            }
            self.attach(ino, parent, &name);
            if kind == Kind::Dir {
                self.load_dir(&e.path(), ino);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(dir: &Path) -> Tree {
        std::fs::create_dir_all(dir.join("staging")).unwrap();
        Tree::new(dir.join("staging"), dir.join("local"))
    }

    fn add(t: &mut Tree, parent: u64, name: &str, kind: Kind) -> u64 {
        let ino = t.alloc(kind);
        t.attach(ino, parent, name);
        ino
    }

    fn ignore_file(t: &mut Tree, parent: u64, text: &str) {
        let f = add(t, parent, IGNORE_FILE, Kind::File);
        t.inodes.get_mut(&f).unwrap().content = Some(Content::Inline(text.as_bytes().to_vec()));
    }

    #[test]
    fn lines_match_like_gitignore() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsStore::open(dir.path().join("blobs"), cardinal_blob::Fsync::Never).unwrap();
        let mut t = tree(dir.path());
        ignore_file(
            &mut t,
            ROOT_INO,
            "*.tmp\n/build/\n# a comment\n\nsecret.txt\n",
        );
        let proj = add(&mut t, ROOT_INO, "proj", Kind::Dir);
        ignore_file(&mut t, proj, "target/\n!keep.tmp\n");
        let src = add(&mut t, proj, "src", Kind::Dir);
        assert!(t.ignored(&store, ROOT_INO, "a.tmp", false));
        assert!(!t.ignored(&store, ROOT_INO, "a.txt", false));
        assert!(t.ignored(&store, src, "x.tmp", false), "from the top file");
        assert!(t.ignored(&store, ROOT_INO, "build", true));
        assert!(
            !t.ignored(&store, proj, "build", true),
            "anchored to the top"
        );
        assert!(!t.ignored(&store, ROOT_INO, "build", false), "folders only");
        assert!(t.ignored(&store, proj, "target", true));
        assert!(t.ignored(&store, src, "secret.txt", false));
        // the nearer file brings one back
        assert!(!t.ignored(&store, src, "keep.tmp", false));
        assert!(!t.ignored(&store, proj, "keep.tmp", false));
        assert!(t.ignored(&store, ROOT_INO, "keep.tmp", false));
        // inside a synced folder the line names, a new item is ignored too
        let target = add(&mut t, proj, "target", Kind::Dir);
        assert!(t.ignored(&store, target, "app", false));
        // changing a file changes the answer
        let f = t.child(proj, IGNORE_FILE).unwrap();
        t.inodes.get_mut(&f).unwrap().content = Some(Content::Inline(b"other/\n".to_vec()));
        assert!(!t.ignored(&store, proj, "target", true));
    }

    #[test]
    fn local_items_live_under_their_synced_parent() {
        let dir = tempfile::tempdir().unwrap();
        let mut t = tree(dir.path());
        let proj = add(&mut t, ROOT_INO, "proj", Kind::Dir);
        t.inodes.get_mut(&proj).unwrap().node = Some([7u8; 16]);
        t.by_node.insert([7u8; 16], proj);
        let target = add(&mut t, proj, "target", Kind::Dir);
        t.inodes.get_mut(&target).unwrap().local = true;
        let o = add(&mut t, target, "a.o", Kind::File);
        t.inodes.get_mut(&o).unwrap().local = true;
        let p = t.local_path(o).unwrap();
        assert_eq!(
            p,
            dir.path()
                .join("local")
                .join(hex::encode([7u8; 16]))
                .join("target/a.o")
        );
        // a new synced folder: keyed by inode until committed
        let n = add(&mut t, ROOT_INO, "new", Kind::Dir);
        let x = add(&mut t, n, "x", Kind::File);
        t.inodes.get_mut(&x).unwrap().local = true;
        assert!(t
            .local_path(x)
            .unwrap()
            .ends_with(format!("local/new-{n}/x")));
        std::fs::create_dir_all(dir.path().join(format!("local/new-{n}"))).unwrap();
        t.committed_dir(n, &[8u8; 16]);
        assert!(dir
            .path()
            .join("local")
            .join(hex::encode([8u8; 16]))
            .exists());
    }
}
