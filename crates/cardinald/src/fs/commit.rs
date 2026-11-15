//! Turning local changes into space entries (`profiles.md#files`):
//! after writes have been quiet for 200 ms, or after 2 seconds of
//! continuous activity, everything pending becomes one burst of entries.
//!
//! A new folder and what is put in it are one entry: no op can hold the
//! id of a node its own entry creates (the id follows from the entry's),
//! so what goes in a folder made earlier in the entry names it by the
//! place of its `create` there (`state.md#a-node-made-in-the-same-entry`).
//! A burst too large for one entry is cut where it has to be, and what
//! comes after a cut names by id what an earlier entry made.
//!
//! A local change supersedes only what the mount had shown when it was
//! made: see [`write_pending`].

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cardinal_blob::{BlobWriter, ConvergenceSecret, FsStore, ObjectStore, INLINE_LIMIT};
use cardinal_identity::EntryId;
use cardinal_space::files::{self, Content, Files};
use cardinal_space::state::named_nodes;
use cardinal_space::{NodeId, Space, SpaceId, SpaceOp, ROOT};

#[cfg(test)]
use super::tree::ROOT_INO;
use super::tree::{time_to_ms, Kind, Snapshot, Staged, Tree};
use crate::core::{split_ops, Core};
use crate::daemon::Daemon;

/// Quiet period before a burst is committed.
pub const QUIET: Duration = Duration::from_millis(200);
/// Longest a burst may run before it is committed anyway.
pub const MAX_BURST: Duration = Duration::from_secs(2);

fn lock(t: &Mutex<Tree>) -> std::sync::MutexGuard<'_, Tree> {
    t.lock().unwrap_or_else(|e| e.into_inner())
}

/// A store that defers durability to one [`ObjectStore::sync`] of the
/// real store after a whole burst is encoded: a blob writer syncs at the
/// end of every blob, which for thousands of small files is thousands of
/// rounds of `fsync`.
struct Unsynced<'a>(&'a FsStore);

impl ObjectStore for Unsynced<'_> {
    fn has(&self, id: &cardinal_blob::Id) -> std::io::Result<bool> {
        self.0.has(id)
    }
    fn get(&self, id: &cardinal_blob::Id) -> std::io::Result<Option<Vec<u8>>> {
        self.0.get(id)
    }
    fn put(&self, id: &cardinal_blob::Id, bytes: &[u8]) -> std::io::Result<bool> {
        self.0.put(id, bytes)
    }
    fn delete(&self, id: &cardinal_blob::Id) -> std::io::Result<bool> {
        self.0.delete(id)
    }
    fn list(&self) -> std::io::Result<Vec<cardinal_blob::ObjectInfo>> {
        self.0.list()
    }
    fn usage(&self) -> cardinal_blob::Usage {
        self.0.usage()
    }
    fn touch(&self, id: &cardinal_blob::Id) -> std::io::Result<()> {
        self.0.touch(id)
    }
    fn sync(&self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Files up to this size are encoded on one thread each, several files at
/// once; larger ones use the blob writer's own threads.
const SMALL: u64 = 4 << 20;

/// Encodes a staged file as content: inline under 1 KiB, else a blob.
/// The blob's objects are not synced: the caller syncs the store before
/// an entry names them.
fn encode(staged: &Staged, secret: &ConvergenceSecret, store: &FsStore) -> anyhow::Result<Content> {
    let len = staged.len()?;
    if len < INLINE_LIMIT as u64 {
        let mut b = vec![0u8; len as usize];
        staged.read_exact_at(&mut b, 0)?;
        return Ok(Content::Inline(b));
    }
    let mut w = BlobWriter::new(secret, Unsynced(store));
    if len <= SMALL {
        w = w.with_threads(1);
    }
    let mut buf = vec![0u8; len.clamp(1, 1 << 20) as usize];
    let mut off = 0u64;
    loop {
        let n = staged.read_at(&mut buf, off)?;
        if n == 0 {
            break;
        }
        std::io::Write::write_all(&mut w, &buf[..n])?;
        off += n as u64;
    }
    let (r, _) = w.finish()?;
    Ok(Content::Blob(files::BlobRef {
        id: r.id,
        key: r.key,
        size: r.size,
        levels: r.levels,
    }))
}

/// Encodes staged files, several at once, then makes every object they
/// stored durable (one batch of `fsync`s) before returning.
fn encode_all(
    items: Vec<(u64, u64, Arc<Staged>)>,
    secret: &ConvergenceSecret,
    store: &FsStore,
) -> anyhow::Result<Vec<(u64, u64, Content)>> {
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .clamp(1, 8)
        .min(items.len().max(1));
    let next = AtomicUsize::new(0);
    let items = &items;
    let results: Vec<anyhow::Result<Vec<(u64, u64, Content)>>> = std::thread::scope(|sc| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                sc.spawn(|| {
                    let mut out = Vec::new();
                    loop {
                        let k = next.fetch_add(1, Ordering::Relaxed);
                        let Some((ino, gen, st)) = items.get(k) else {
                            break;
                        };
                        let c = encode(st, secret, store);
                        st.close();
                        match c {
                            Ok(c) => out.push((*ino, *gen, c)),
                            // moved or removed since it was picked: the next
                            // commit finds it where it is now
                            Err(_) if !st.path().exists() => {}
                            Err(e) => return Err(e),
                        }
                    }
                    Ok(out)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("encoding thread panicked"))
            .collect()
    });
    let mut encoded = Vec::new();
    for r in results {
        encoded.extend(r?);
    }
    store.sync()?;
    Ok(encoded)
}

/// One commit at a time (the scheduler and `cardinal flush`).
static COMMITTING: Mutex<()> = Mutex::new(());

/// Runs `f` while no commit runs: a commit writes chunks before the entry
/// that names them, so freeing old versions (`cleanup.rs`) must not see
/// one half done.
pub fn without_commits<R>(f: impl FnOnce() -> R) -> R {
    let _one = COMMITTING.lock().unwrap_or_else(|e| e.into_inner());
    f()
}

/// Commits everything pending. Returns the number of entries written.
pub fn commit(d: &Arc<Daemon>, tree: &Mutex<Tree>, space: &SpaceId) -> anyhow::Result<usize> {
    let _one = COMMITTING.lock().unwrap_or_else(|e| e.into_inner());
    let start = Instant::now();
    if d.core().removed() {
        return Ok(0);
    }
    // Content is keyed by the epoch, so a new one must come first.
    let rotated = d.core().rotate_if_due(space)?;
    if let Some(entry) = rotated {
        d.push(space, vec![entry]);
    }
    // A: what needs encoding.
    let to_encode: Vec<(u64, u64, Arc<Staged>)> = {
        let t = lock(tree);
        t.inodes
            .values()
            .filter(|i| {
                i.parent != 0
                    && !i.local
                    && i.kind == Kind::File
                    && (i.dirty.content || i.node.is_none())
                    && !i.held_back(QUIET, MAX_BURST)
            })
            .filter_map(|i| Some((i.ino, i.write_gen, i.staged.clone()?)))
            .collect()
    };
    // B: encode, without holding the tree.
    let mut encoded = Vec::new();
    if !to_encode.is_empty() {
        let secret = {
            let core = d.core();
            let sp = core
                .spaces
                .get(space)
                .and_then(|h| h.space.as_ref())
                .ok_or_else(|| anyhow::anyhow!("files space not open"))?;
            let ep = sp
                .current_epoch()
                .ok_or_else(|| anyhow::anyhow!("no current epoch"))?;
            let key = sp
                .keyring()
                .get(&ep)
                .ok_or_else(|| anyhow::anyhow!("no epoch key"))?;
            ConvergenceSecret::from_epoch_key(key.bytes())
        };
        encoded = encode_all(to_encode, &secret, &d.store)?;
    }
    let files = encoded.len();
    let encoding = start.elapsed();

    // C: build ops and write, holding the space then the tree.
    let written = {
        let mut core = d.core();
        let mut t = lock(tree);
        write_pending(&mut core, &mut t, space, encoded)?
    };
    let n = written.len();
    if n > 0 {
        tracing::debug!(
            "committed {n} entries, {files} files encoded in {:?}, written in {:?}",
            encoding,
            start.elapsed() - encoding
        );
        d.push(space, written);
        d.bump();
    }
    Ok(n)
}

/// Ops that must not descend from some entries: local changes made
/// without having seen them.
#[derive(Default)]
struct Concurrent {
    ops: Vec<SpaceOp>,
    effects: Vec<Effect>,
}

/// The current content versions of `node` that the local view has not
/// seen (`seen` are the versions it was based on).
fn unseen_versions(sp: &Space, node: &NodeId, seen: &[EntryId]) -> Vec<EntryId> {
    Files::new(sp)
        .content(node)
        .into_iter()
        .map(|v| v.entry)
        .filter(|e| !seen.contains(e))
        .collect()
}

/// Entries not seen by a delete made after `base` that touch `node` or a
/// node beneath it (`state.md#deletion-yields-to-concurrent-work`).
fn unseen_touching(sp: &Space, base: &[EntryId], node: &NodeId) -> Vec<EntryId> {
    if base.is_empty() {
        return Vec::new();
    }
    let dag = sp.dag();
    let known = |x: &EntryId| base.iter().any(|b| dag.is_ancestor_or_self(x, b));
    // the entries since base: walk back from the heads to what base knew
    let mut new: Vec<EntryId> = Vec::new();
    let mut seen: HashSet<EntryId> = HashSet::new();
    let mut todo: Vec<EntryId> = sp.heads();
    while let Some(x) = todo.pop() {
        if !seen.insert(x) || known(&x) {
            continue;
        }
        new.push(x);
        todo.extend(dag.parents(&x).iter().copied());
    }
    if new.is_empty() {
        return Vec::new();
    }
    let st = sp.state();
    let mut under: HashSet<NodeId> = HashSet::new();
    let mut stack = vec![*node];
    while let Some(n) = stack.pop() {
        if under.insert(n) {
            stack.extend(st.children(&n).iter().map(|c| c.id));
        }
    }
    new.into_iter()
        .filter(|x| {
            dag.get(x).is_some_and(|e| {
                e.ops()
                    .iter()
                    .any(|op| named_nodes(op.body()).iter().any(|n| under.contains(n)))
            })
        })
        .collect()
}

/// Turns the tree's pending changes into entries in `core` (the commit's
/// step C; `encoded` is the content encoded for files, by inode and write
/// generation). Returns the sealed entries written, to push.
///
/// A local change is written so that it descends from what the tree had
/// shown when it was made, and from nothing else it would override: a
/// content edit whose file got another version from elsewhere in the
/// meantime (one the tree has not shown, because the file had local
/// changes or the change had not been applied yet) is written in an entry
/// concurrent with that version, so both are kept as a conflict; a delete
/// of something changed elsewhere unseen becomes a delete conflict.
pub fn write_pending(
    core: &mut Core,
    t: &mut Tree,
    space: &SpaceId,
    encoded: Vec<(u64, u64, Content)>,
) -> anyhow::Result<Vec<Vec<u8>>> {
    // Show the tree everything the space holds first, so that what it
    // has seen after this commit is everything (see Tree::seen_heads).
    if let Some(h) = core.spaces.get(space) {
        if let Some(sp) = h.space.as_ref() {
            if t.applied_version != h.version {
                let snap = Snapshot::take(sp, h.version, &core.device_names());
                let inval = t.apply(&snap);
                t.pending_inval.extend(inval);
            }
        }
    }
    let mut ready: HashSet<u64> = HashSet::new();
    for (ino, gen, c) in encoded {
        if let Some(i) = t.inodes.get_mut(&ino) {
            // Written while it was encoded: a burst that has run its length
            // is committed as it was read, and stays dirty for what came after.
            if i.write_gen == gen || i.overdue(MAX_BURST) {
                if i.write_gen == gen {
                    // later writes may have made it longer: the size stays theirs
                    i.size = c.size();
                }
                i.content = Some(c);
                i.content_gen = gen;
                ready.insert(ino);
            }
        }
    }
    // Without a staged file, the content held is the content written.
    for i in t.inodes.values_mut() {
        if i.staged.is_none() {
            i.content_gen = i.write_gen;
        }
    }
    let mut written: Vec<Vec<u8>> = Vec::new();
    let mut first = true;
    let mut rounds = 0;
    loop {
        rounds += 1;
        if rounds > 64 {
            break;
        }
        let sp = core
            .spaces
            .get(space)
            .and_then(|h| h.space.as_ref())
            .ok_or_else(|| anyhow::anyhow!("files space not open"))?;
        // a shared folder's nodes have kinds of their own
        let kinds = files::Kinds::of(sp.profile());
        // (op, what it does to which inode)
        let mut ops: Vec<SpaceOp> = Vec::new();
        let mut effects: Vec<Effect> = Vec::new();
        // By inode, the place among `ops` of the `create` this round
        // writes for it; and by the place of an op, the place of the
        // `create` of the parent it names, where this round makes that.
        let mut made: HashMap<u64, usize> = HashMap::new();
        let mut under: HashMap<usize, usize> = HashMap::new();
        // ops to write concurrent with the entries of the key
        let mut concurrent: BTreeMap<Vec<EntryId>, Concurrent> = BTreeMap::new();
        // What is new first, so that whatever is put in a new folder
        // finds its `create` earlier in the round; each in the order it
        // was made here, which has a folder before what was made in it.
        let mut inos: Vec<u64> = t.inodes.keys().copied().collect();
        inos.sort_unstable_by_key(|ino| (t.inodes[ino].node.is_some(), *ino));
        for ino in inos {
            if ino == t.root {
                continue;
            }
            let i = &t.inodes[&ino];
            // local items are never committed (`fs/local.rs`)
            if i.parent == 0 || i.local || matches!(i.kind, Kind::Conflict(_)) {
                continue;
            }
            // The parent: a node, or one an earlier op of this round
            // makes, for which the root stands until the ops are cut into
            // entries. One made by a later op waits for the next round.
            let parent = t.inodes.get(&i.parent).and_then(|p| p.node);
            let (pnode, made_at) = match (parent, made.get(&i.parent)) {
                (Some(node), _) => (node, None),
                (None, Some(place)) => (ROOT, Some(*place)),
                (None, None) => continue,
            };
            let content_ready = i.kind != Kind::File
                || i.staged.is_none()
                || ready.contains(&ino)
                || !(i.dirty.content || i.node.is_none());
            match i.node {
                None => {
                    if !content_ready || (i.kind == Kind::File && i.held_back(QUIET, MAX_BURST)) {
                        continue;
                    }
                    let name = i.stored_name.as_deref().unwrap_or(&i.name);
                    let op = match i.kind {
                        Kind::Dir => kinds.create_folder(pnode, name),
                        Kind::File => kinds.create_file(
                            pnode,
                            name,
                            i.content.as_ref().unwrap_or(&Content::Inline(Vec::new())),
                            i.perm as u32,
                            Some(time_to_ms(i.mtime)),
                        ),
                        Kind::Symlink => kinds.create_link(pnode, name, &i.target),
                        Kind::Conflict(_) => unreachable!(),
                    };
                    made.insert(ino, ops.len());
                    under.extend(made_at.map(|place| (ops.len(), place)));
                    effects.push(Effect::Created(ino));
                    ops.push(op);
                    // what was read is in this round's ops: once per commit
                    ready.remove(&ino);
                }
                Some(node) => {
                    if i.dirty.pos {
                        under.extend(made_at.map(|place| (ops.len(), place)));
                        ops.push(SpaceOp::mv(node, pnode, &i.name));
                        effects.push(Effect::Clean(ino, Flag::Pos));
                    }
                    let mut own: Vec<(SpaceOp, Effect)> = Vec::new();
                    let edit = i.kind == Kind::File
                        && i.dirty.content
                        && content_ready
                        && !i.held_back(QUIET, MAX_BURST);
                    if edit {
                        let c = i.content.clone().unwrap_or(Content::Inline(Vec::new()));
                        own.push((
                            files::set_content(node, &c),
                            Effect::Clean(ino, Flag::Content),
                        ));
                        // what was read is in this round's ops: once per commit
                        ready.remove(&ino);
                    }
                    if i.kind == Kind::File && i.dirty.mode {
                        own.push((
                            files::set_mode(node, i.perm as u32),
                            Effect::Clean(ino, Flag::Mode),
                        ));
                    }
                    if i.kind == Kind::File && i.dirty.mtime {
                        own.push((
                            files::set_mtime(node, time_to_ms(i.mtime)),
                            Effect::Clean(ino, Flag::Mtime),
                        ));
                    }
                    // A version from elsewhere this edit has not seen: keep
                    // both (with the file's mode and time, from the same
                    // view).
                    let unseen = if edit {
                        unseen_versions(sp, &node, &i.seen)
                    } else {
                        Vec::new()
                    };
                    if unseen.is_empty() {
                        for (op, eff) in own {
                            ops.push(op);
                            effects.push(eff);
                        }
                    } else {
                        let c = concurrent.entry(unseen).or_default();
                        for (op, eff) in own {
                            c.ops.push(op);
                            c.effects.push(eff);
                        }
                    }
                }
            }
        }
        if first {
            for del in std::mem::take(&mut t.deleted) {
                let mut unseen = unseen_touching(sp, &del.base, &del.node);
                if let Some(seen) = &del.seen {
                    for v in unseen_versions(sp, &del.node, seen) {
                        if !unseen.contains(&v) {
                            unseen.push(v);
                        }
                    }
                }
                unseen.sort();
                if unseen.is_empty() {
                    ops.push(SpaceOp::delete(del.node));
                    effects.push(Effect::None);
                } else {
                    let c = concurrent.entry(unseen).or_default();
                    c.ops.push(SpaceOp::delete(del.node));
                    c.effects.push(Effect::None);
                }
            }
            let settle: Vec<_> = t.settle.drain().collect();
            if !settle.is_empty() {
                let f = Files::new(sp);
                for (node, version) in settle {
                    let vs = f.content(&node);
                    if vs.len() < 2 {
                        continue;
                    }
                    let pick = match version {
                        Some(v) => vs.iter().find(|x| x.entry == v),
                        None => vs.last(),
                    };
                    if let Some(c) = pick.and_then(|p| p.content.clone()) {
                        ops.push(files::set_content(node, &c));
                        effects.push(Effect::None);
                    }
                }
            }
            first = false;
        }
        // Concurrent entries first, so the ordinary ones after them
        // descend from everything again.
        for (exclude, c) in concurrent {
            let sp = core
                .spaces
                .get(space)
                .and_then(|h| h.space.as_ref())
                .ok_or_else(|| anyhow::anyhow!("files space not open"))?;
            if !can_write_concurrent(sp, &exclude, &c.ops) {
                tracing::warn!(
                    "a change made here without seeing one from elsewhere cannot be kept \
                     apart from it; writing it after"
                );
                ops.extend(c.ops);
                effects.extend(c.effects);
                continue;
            }
            match core.write_entry_concurrent(space, &exclude, c.ops.clone()) {
                Ok((eid, bytes)) => {
                    tracing::info!(
                        "a file changed here and on another device: keeping both versions"
                    );
                    written.push(bytes);
                    finish(t, &eid, &c.effects);
                }
                Err(e) => {
                    tracing::warn!(
                        "cannot keep a concurrent change apart ({e:#}); writing it after"
                    );
                    ops.extend(c.ops);
                    effects.extend(c.effects);
                }
            }
        }
        if ops.is_empty() {
            break;
        }
        // write, one entry per batch, mapping created ops to node ids
        let mut idx = 0;
        let mut nodes: HashMap<usize, NodeId> = HashMap::new();
        for mut batch in split_ops(ops) {
            let n = batch.len();
            name_parents(&mut batch, idx, &under, &nodes);
            let (eid, bytes) = core.write_entry(space, batch)?;
            written.push(bytes);
            nodes.extend((0..n).map(|k| (idx + k, files::created_node(&eid, k))));
            finish(t, &eid, &effects[idx..idx + n]);
            idx += n;
        }
    }
    if let Some(sp) = core.spaces.get(space).and_then(|h| h.space.as_ref()) {
        t.seen_heads = sp.heads();
    }
    // Staged content that is committed and closed is no longer needed:
    // reads come from the blob store.
    for i in t.inodes.values_mut() {
        if i.staged.is_some() && i.writers == 0 && !i.dirty.content && i.node.is_some() {
            i.staged = None;
        }
    }
    if let Err(e) = t.journal_committed() {
        tracing::warn!("cannot update the journal of flushed files: {e}");
    }
    if t.has_pending() {
        // what is left (files still being written) waits for its own quiet
        t.first_change = Some(Instant::now());
    } else {
        t.first_change = None;
        t.last_change = None;
    }
    Ok(written)
}

/// Gives the ops of one entry the parents their round made
/// (`state.md#a-node-made-in-the-same-entry`). `batch` is the round's ops
/// from place `first` on, `under` says for an op's place in the round the
/// place of the `create` of its parent, and `nodes` what the entries
/// written so far made, by place. A parent made in this entry is named by
/// its index there, and one made in an earlier entry by its id.
fn name_parents(
    batch: &mut [SpaceOp],
    first: usize,
    under: &HashMap<usize, usize>,
    nodes: &HashMap<usize, NodeId>,
) {
    for (k, op) in batch.iter_mut().enumerate() {
        let Some(place) = under.get(&(first + k)) else {
            continue;
        };
        *op = match place.checked_sub(first) {
            Some(index) => op.with_parent(index as u32),
            None => op.with_parent(nodes[place]),
        };
    }
}

/// Whether ops can be written in an entry concurrent with `exclude`:
/// every node they name exists in that entry's past.
fn can_write_concurrent(sp: &Space, exclude: &[EntryId], ops: &[SpaceOp]) -> bool {
    let parents = sp.latest_excluding(exclude);
    if parents.is_empty() {
        return false;
    }
    let dag = sp.dag();
    ops.iter().all(|op| {
        named_nodes(op.body()).iter().all(|n| {
            *n == ROOT
                || sp.state().node(n).is_some_and(|x| {
                    parents
                        .iter()
                        .any(|p| dag.is_ancestor_or_self(&x.created_in, p))
                })
        })
    })
}

/// Records what an entry `eid` with these effects (one per op, in order)
/// did to the tree.
fn finish(t: &mut Tree, eid: &EntryId, effects: &[Effect]) {
    for (k, eff) in effects.iter().enumerate() {
        match eff {
            Effect::Created(ino) => {
                let node = files::created_node(eid, k);
                if let Some(i) = t.inodes.get_mut(ino) {
                    i.node = Some(node);
                    i.dirty = Default::default();
                    i.seen = vec![*eid];
                    if i.kind == Kind::File {
                        i.content_committed();
                    }
                }
                t.by_node.insert(node, *ino);
                t.committed_dir(*ino, &node);
            }
            Effect::Clean(ino, f) => {
                if let Some(i) = t.inodes.get_mut(ino) {
                    match f {
                        Flag::Pos => i.dirty.pos = false,
                        Flag::Content => {
                            i.content_committed();
                            i.seen = vec![*eid];
                        }
                        Flag::Mode => i.dirty.mode = false,
                        Flag::Mtime => i.dirty.mtime = false,
                    }
                }
            }
            Effect::None => {}
        }
    }
}

enum Flag {
    Pos,
    Content,
    Mode,
    Mtime,
}

enum Effect {
    Created(u64),
    Clean(u64, Flag),
    None,
}

/// Commits after each quiet period until `stop` is set.
pub fn spawn_scheduler(
    d: Arc<Daemon>,
    tree: Arc<Mutex<Tree>>,
    space: SpaceId,
    stop: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("cardinal-commit".into())
        .spawn(move || {
            let mut failures = 0u32;
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(20));
                let due = {
                    let t = lock(&tree);
                    match (t.first_change, t.last_change) {
                        (Some(f), Some(l)) => l.elapsed() >= QUIET || f.elapsed() >= MAX_BURST,
                        _ => false,
                    }
                };
                if !due {
                    continue;
                }
                match commit(&d, &tree, &space) {
                    Ok(_) => {
                        failures = 0;
                    }
                    Err(e) => {
                        failures += 1;
                        tracing::error!("cannot save changes: {e:#}");
                        std::thread::sleep(Duration::from_millis(500 * failures.min(20) as u64));
                    }
                }
            }
        })
        .expect("spawn committer")
}

#[cfg(test)]
mod tests {
    //! Local changes against changes from elsewhere the tree has not
    //! shown yet. A change "from elsewhere" is an entry written to the
    //! space directly, as an entry received from another device is: it
    //! descends from everything, and the tree has not applied it.

    use super::*;
    use crate::config::Config;
    use crate::keys::Keys;
    use crate::paths::Paths;
    use crate::setup;
    use cardinal_crypto::HybridKeyPair;
    use cardinal_encoding::Value;

    struct Fx {
        _dir: tempfile::TempDir,
        keys: Arc<Keys>,
        core: Core,
        space: SpaceId,
        t: Tree,
    }

    impl Fx {
        fn new() -> Fx {
            let dir = tempfile::tempdir().unwrap();
            let paths = Paths::at(dir.path());
            let p = setup::prepare(&paths).unwrap();
            setup::install(&paths, p, &Config::default()).unwrap();
            let keys = Arc::new(Keys::load_or_create(&paths.device_key()).unwrap());
            let core = Core::load(&paths, keys.clone()).unwrap();
            let space = core.files_id().unwrap();
            std::fs::create_dir_all(paths.staging()).unwrap();
            let t = Tree::new(paths.staging(), paths.local());
            let mut fx = Fx {
                _dir: dir,
                keys,
                core,
                space,
                t,
            };
            fx.refresh();
            fx
        }

        fn sp(&self) -> &Space {
            self.core.spaces[&self.space].space.as_ref().unwrap()
        }

        /// As a removal on another device does, once its log entry
        /// arrives: the identity moves to a new encryption key.
        fn new_identity_key(&mut self) {
            let keys = self.keys.clone();
            let ident = self.core.identity.as_mut().unwrap();
            let current = ident
                .enc
                .first()
                .map(|k| HybridKeyPair::from_secret_bytes(&k.secret_bytes()));
            let new = HybridKeyPair::generate();
            let e = ident
                .log
                .set_encryption_key(&keys.device.signing, &new, current.as_ref())
                .unwrap();
            ident.record_own(&e).unwrap();
            self.core.identity_updated();
        }

        /// What a restart loads from disk.
        fn restart(&mut self) {
            let paths = Paths::at(self._dir.path());
            self.core = Core::load(&paths, self.keys.clone()).unwrap();
        }

        /// What the mount's refresh does when entries arrive.
        fn refresh(&mut self) {
            let h = &self.core.spaces[&self.space];
            let snap = Snapshot::take(
                h.space.as_ref().unwrap(),
                h.version,
                &self.core.device_names(),
            );
            self.t.apply(&snap);
        }

        fn commit(&mut self) -> usize {
            write_pending(&mut self.core, &mut self.t, &self.space, Vec::new())
                .unwrap()
                .len()
        }

        /// Writes a file under `parent`, as an application would.
        fn write_in(&mut self, parent: u64, name: &str, bytes: &[u8]) -> u64 {
            let ino = match self.t.child(parent, name) {
                Some(i) => i,
                None => {
                    let i = self.t.alloc(Kind::File);
                    self.t.attach(i, parent, name);
                    i
                }
            };
            let i = self.t.inodes.get_mut(&ino).unwrap();
            i.content = Some(Content::Inline(bytes.to_vec()));
            i.size = bytes.len() as u64;
            i.dirty.content = true;
            i.wrote();
            self.t.touch();
            ino
        }

        fn write(&mut self, name: &str, bytes: &[u8]) -> u64 {
            self.write_in(ROOT_INO, name, bytes)
        }

        fn node(&self, ino: u64) -> NodeId {
            self.t.inodes[&ino].node.expect("committed")
        }

        /// A change from another device, not shown by the tree yet.
        fn remote(&mut self, op: SpaceOp) -> EntryId {
            self.core.write_entry(&self.space, vec![op]).unwrap().0
        }

        /// The content versions of a file, in log order.
        fn versions(&self, node: &NodeId) -> Vec<Vec<u8>> {
            Files::new(self.sp())
                .content(node)
                .into_iter()
                .map(|v| match v.content {
                    Some(Content::Inline(b)) => b,
                    other => panic!("unexpected content {other:?}"),
                })
                .collect()
        }

        /// The names the mount shows in the root.
        fn names(&self) -> Vec<String> {
            self.t.inodes[&ROOT_INO].children.keys().cloned().collect()
        }

        fn shown(&self, name: &str) -> Vec<u8> {
            let ino = self.t.child(ROOT_INO, name).expect(name);
            match &self.t.inodes[&ino].content {
                Some(Content::Inline(b)) => b.clone(),
                other => panic!("unexpected content {other:?}"),
            }
        }
    }

    fn sorted(mut v: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        v.sort();
        v
    }

    /// The reported bug: a remote edit that arrives in the quiet period
    /// before a local commit of the same file was overwritten.
    #[test]
    fn remote_edit_before_local_commit_is_kept_as_conflict() {
        let mut fx = Fx::new();
        let ino = fx.write("a.txt", b"v1");
        fx.commit();
        fx.refresh();
        let node = fx.node(ino);
        fx.remote(files::set_content(
            node,
            &Content::Inline(b"remote".to_vec()),
        ));
        fx.write("a.txt", b"local");
        fx.commit();
        assert_eq!(
            sorted(fx.versions(&node)),
            vec![b"local".to_vec(), b"remote".to_vec()]
        );
        fx.refresh();
        let names = fx.names();
        assert_eq!(names.len(), 2, "{names:?}");
        assert!(names.contains(&"a.txt".to_string()));
        assert!(
            names.iter().any(|n| n.starts_with("a (conflict, ")),
            "{names:?}"
        );
    }

    /// Same race, but the remote edit was applied to the tree (and skipped,
    /// the file having local changes) before the commit.
    #[test]
    fn remote_edit_applied_while_dirty_is_kept_as_conflict() {
        let mut fx = Fx::new();
        let ino = fx.write("a.txt", b"v1");
        fx.commit();
        fx.refresh();
        let node = fx.node(ino);
        fx.write("a.txt", b"local");
        fx.remote(files::set_content(
            node,
            &Content::Inline(b"remote".to_vec()),
        ));
        fx.refresh();
        assert_eq!(fx.shown("a.txt"), b"local", "local changes win in the view");
        fx.commit();
        assert_eq!(
            sorted(fx.versions(&node)),
            vec![b"local".to_vec(), b"remote".to_vec()]
        );
    }

    /// The other order: an edit made after the remote one was shown
    /// replaces it, with no conflict.
    #[test]
    fn edit_after_seeing_remote_edit_replaces_it() {
        let mut fx = Fx::new();
        let ino = fx.write("a.txt", b"v1");
        fx.commit();
        fx.refresh();
        let node = fx.node(ino);
        fx.remote(files::set_content(
            node,
            &Content::Inline(b"remote".to_vec()),
        ));
        fx.refresh();
        assert_eq!(fx.shown("a.txt"), b"remote");
        fx.write("a.txt", b"local");
        fx.commit();
        assert_eq!(fx.versions(&node), vec![b"local".to_vec()]);
    }

    /// Successive local commits, with or without a refresh between them,
    /// never conflict with each other.
    #[test]
    fn own_edits_do_not_conflict() {
        let mut fx = Fx::new();
        let ino = fx.write("a.txt", b"v1");
        fx.commit();
        let node = fx.node(ino);
        fx.write("a.txt", b"v2");
        fx.commit();
        fx.write("a.txt", b"v3");
        fx.commit();
        fx.refresh();
        fx.write("a.txt", b"v4");
        fx.commit();
        assert_eq!(fx.versions(&node), vec![b"v4".to_vec()]);
        assert_eq!(fx.sp().heads().len(), 1);
    }

    /// Editing the main file of a conflict that is shown settles it.
    #[test]
    fn editing_a_shown_conflict_settles_it() {
        let mut fx = Fx::new();
        let ino = fx.write("a.txt", b"v1");
        fx.commit();
        fx.refresh();
        let node = fx.node(ino);
        fx.remote(files::set_content(
            node,
            &Content::Inline(b"remote".to_vec()),
        ));
        fx.write("a.txt", b"local");
        fx.commit();
        fx.refresh();
        assert_eq!(fx.versions(&node).len(), 2);
        fx.write("a.txt", b"merged");
        fx.commit();
        assert_eq!(fx.versions(&node), vec![b"merged".to_vec()]);
        fx.refresh();
        assert_eq!(fx.names(), vec!["a.txt".to_string()]);
    }

    /// A local delete of a file edited elsewhere, unseen: a delete
    /// conflict; the file stays.
    #[test]
    fn delete_of_unseen_remote_edit_is_a_delete_conflict() {
        let mut fx = Fx::new();
        let ino = fx.write("a.txt", b"v1");
        fx.commit();
        fx.refresh();
        let node = fx.node(ino);
        fx.remote(files::set_content(
            node,
            &Content::Inline(b"remote".to_vec()),
        ));
        fx.t.remove(ino);
        fx.commit();
        let n = fx.sp().state().node(&node).unwrap();
        assert!(!n.deleted && n.delete_conflict, "{n:?}");
        fx.refresh();
        assert_eq!(fx.shown("a.txt"), b"remote");
    }

    /// An entry whose parents are missing waits, unannounced. Hearing of it
    /// again is the cue to look for them again, and when they come, the
    /// notice names the heads, which cover both.
    #[test]
    fn an_entry_waiting_for_parents_is_not_announced() {
        let mut fx = Fx::new();
        let dir = tempfile::tempdir().unwrap();
        let done = std::process::Command::new("cp")
            .args(["-a", &format!("{}/.", fx._dir.path().display())])
            .arg(dir.path())
            .status()
            .unwrap();
        assert!(done.success());
        let (_, first) = fx
            .core
            .write_entry(&fx.space, vec![files::create_folder(ROOT, "a")])
            .unwrap();
        let (_, second) = fx
            .core
            .write_entry(&fx.space, vec![files::create_folder(ROOT, "b")])
            .unwrap();
        let paths = Paths::at(dir.path());
        let keys = Arc::new(Keys::load_or_create(&paths.device_key()).unwrap());
        let mut other = Core::load(&paths, keys).unwrap();

        let out = other
            .ingest_space(fx.space, std::slice::from_ref(&second))
            .unwrap();
        assert_eq!((out.new, out.complete), (1, 0));
        assert!(out.missing_parents);

        let out = other
            .ingest_space(fx.space, std::slice::from_ref(&second))
            .unwrap();
        assert_eq!((out.new, out.complete), (0, 0));
        assert!(out.missing_parents, "still looking");
        assert!(other.is_waiting(&fx.space));

        let out = other.ingest_space(fx.space, &[first]).unwrap();
        assert_eq!(out.complete, 2);
        assert_eq!(out.objects.len(), 1, "the notice names the heads");
        assert!(!out.missing_parents);
        assert!(!other.is_waiting(&fx.space));
    }

    /// A file moved away while a commit encodes does not stop the others.
    #[test]
    fn a_file_gone_during_encoding_is_left_for_the_next_commit() {
        let mut fx = Fx::new();
        let gone = fx.t.new_staged().unwrap();
        gone.write_all_at(b"gone", 0).unwrap();
        gone.close();
        std::fs::remove_file(gone.path()).unwrap();
        let kept = fx.t.new_staged().unwrap();
        kept.write_all_at(b"kept", 0).unwrap();
        let secret = {
            let sp = fx.sp();
            let key = sp.keyring().get(&sp.current_epoch().unwrap()).unwrap();
            ConvergenceSecret::from_epoch_key(key.bytes())
        };
        let store = FsStore::open(
            fx._dir.path().join("test-blobs"),
            cardinal_blob::Fsync::Never,
        )
        .unwrap();
        let out = encode_all(vec![(1, 1, gone), (2, 1, kept)], &secret, &store).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, 2);
    }

    /// The same with the edit applied to the tree before the delete: the
    /// delete was made knowing it, and stands.
    #[test]
    fn delete_after_seeing_remote_edit_deletes() {
        let mut fx = Fx::new();
        let ino = fx.write("a.txt", b"v1");
        fx.commit();
        fx.refresh();
        let node = fx.node(ino);
        fx.remote(files::set_content(
            node,
            &Content::Inline(b"remote".to_vec()),
        ));
        fx.refresh();
        let ino = fx.t.child(ROOT_INO, "a.txt").unwrap();
        fx.t.remove(ino);
        fx.commit();
        assert!(fx.sp().state().node(&node).unwrap().deleted);
        fx.refresh();
        assert!(fx.names().is_empty());
    }

    /// A local edit and then delete of a file whose remote edit was
    /// skipped (the file had local changes): the delete has not seen it.
    #[test]
    fn delete_of_dirty_file_with_skipped_remote_edit_is_a_delete_conflict() {
        let mut fx = Fx::new();
        let ino = fx.write("a.txt", b"v1");
        fx.commit();
        fx.refresh();
        let node = fx.node(ino);
        fx.write("a.txt", b"local");
        fx.remote(files::set_content(
            node,
            &Content::Inline(b"remote".to_vec()),
        ));
        fx.refresh();
        fx.t.remove(ino);
        fx.commit();
        let n = fx.sp().state().node(&node).unwrap();
        assert!(!n.deleted && n.delete_conflict, "{n:?}");
    }

    /// A file moved into a folder deleted elsewhere, unseen: the folder is
    /// created again with the file in it, and nothing stays pending.
    #[test]
    fn move_into_a_folder_deleted_elsewhere_is_kept() {
        let mut fx = Fx::new();
        let dir = fx.t.alloc(Kind::Dir);
        fx.t.attach(dir, ROOT_INO, "d");
        fx.t.touch();
        let file = fx.write("a.txt", b"v1");
        fx.commit();
        fx.refresh();
        let dnode = fx.node(dir);
        let node = fx.node(file);
        fx.t.detach(file);
        fx.t.attach(file, dir, "a.txt");
        fx.t.inodes.get_mut(&file).unwrap().dirty.pos = true;
        fx.t.touch();
        fx.remote(SpaceOp::delete(dnode));
        fx.refresh();
        // ...and it stays through whatever arrives before the commit
        fx.remote(files::create_folder(ROOT, "other"));
        fx.refresh();
        fx.commit();
        fx.refresh();
        assert!(!fx.t.has_pending());
        let again = fx.t.child(ROOT_INO, "d").expect("the folder is back");
        assert_ne!(fx.node(again), dnode, "created again");
        assert_eq!(fx.t.child(again, "a.txt"), Some(file));
        let st = fx.sp().state();
        assert_eq!(st.node(&node).unwrap().parent, fx.node(again));
    }

    /// A folder shown as `d (2)`, deleted elsewhere while it holds a change
    /// here, is created again as `d`: the number belongs to the view.
    #[test]
    fn a_kept_folder_is_created_again_under_its_own_name() {
        let mut fx = Fx::new();
        let first = fx.remote(files::create_folder(ROOT, "d"));
        let second = fx.remote(files::create_folder(ROOT, "d"));
        let (first, second) = (
            files::created_node(&first, 0),
            files::created_node(&second, 0),
        );
        fx.refresh();
        assert_eq!(fx.names(), vec!["d".to_string(), "d (2)".to_string()]);
        let shown = fx.t.child(ROOT_INO, "d (2)").unwrap();
        assert_eq!(fx.node(shown), second);
        fx.write_in(shown, "a.txt", b"local");
        fx.remote(SpaceOp::delete(second));
        fx.refresh();
        fx.commit();
        fx.refresh();
        let again = fx.t.child(ROOT_INO, "d (2)").expect("shown as before");
        let node = fx.node(again);
        assert_ne!(node, second);
        assert_eq!(fx.sp().state().node(&node).unwrap().name, "d");
        // no number once the other one is gone
        fx.remote(SpaceOp::delete(first));
        fx.refresh();
        assert_eq!(fx.names(), vec!["d".to_string()]);
    }

    /// A local edit of a file deleted elsewhere, unseen: the edit is kept.
    #[test]
    fn edit_of_unseen_remote_delete_is_kept() {
        let mut fx = Fx::new();
        let ino = fx.write("a.txt", b"v1");
        fx.commit();
        fx.refresh();
        let node = fx.node(ino);
        fx.remote(SpaceOp::delete(node));
        fx.write("a.txt", b"local");
        fx.commit();
        fx.refresh();
        assert_eq!(fx.names(), vec!["a.txt".to_string()]);
        assert_eq!(fx.shown("a.txt"), b"local");
        let ino = fx.t.child(ROOT_INO, "a.txt").unwrap();
        let now = fx.node(ino);
        assert_eq!(fx.versions(&now), vec![b"local".to_vec()]);
    }

    /// A folder deleted here while a file was added to it elsewhere,
    /// unseen: the folder and the new file stay.
    #[test]
    fn folder_delete_yields_to_unseen_remote_create_inside() {
        let mut fx = Fx::new();
        let d = fx.t.alloc(Kind::Dir);
        fx.t.attach(d, ROOT_INO, "d");
        fx.t.touch();
        fx.commit();
        fx.refresh();
        let dnode = fx.node(d);
        let e = fx.remote(files::create_file(
            dnode,
            "x.txt",
            &Content::Inline(b"x".to_vec()),
            0o644,
            None,
        ));
        fx.t.remove(d);
        fx.commit();
        let st = fx.sp().state();
        assert!(!st.node(&dnode).unwrap().deleted);
        assert!(!st.node(&files::created_node(&e, 0)).unwrap().deleted);
    }

    /// A burst of new folders and files commits, with every file under
    /// its folder.
    #[test]
    fn a_file_written_continuously_is_committed_once_its_burst_has_run() {
        let mut fx = Fx::new();
        let f = fx.write("db", b"one");
        assert_eq!(fx.commit(), 1);
        let node = fx.node(f);
        // still open and written just now: it waits, while the burst is young
        fx.write("db", b"two");
        let i = fx.t.inodes.get_mut(&f).unwrap();
        i.writers = 1;
        i.last_write = Some(Instant::now());
        assert_eq!(fx.commit(), 0, "held back for its first {MAX_BURST:?}");
        assert!(fx.t.inodes[&f].dirty.content);
        // written for longer than that: committed as it stands
        let i = fx.t.inodes.get_mut(&f).unwrap();
        i.first_write = Some(Instant::now() - MAX_BURST - Duration::from_millis(100));
        i.last_write = Some(Instant::now());
        assert_eq!(fx.commit(), 1);
        assert_eq!(fx.versions(&node), vec![b"two".to_vec()]);
        assert!(!fx.t.inodes[&f].dirty.content);
    }

    #[test]
    fn a_snapshot_read_while_written_is_committed_once_and_keeps_the_size() {
        let mut fx = Fx::new();
        let f = fx.write("log", b"start");
        assert_eq!(fx.commit(), 1);
        let node = fx.node(f);
        // staged, written for longer than a burst, read at one point and
        // written again after, then closed before the commit is written
        let st = fx.t.new_staged().unwrap();
        st.write_all_at(b"0123456789abcdefghij", 0).unwrap();
        let i = fx.t.inodes.get_mut(&f).unwrap();
        i.staged = Some(st);
        i.dirty.content = true;
        i.wrote();
        let read_at = i.write_gen;
        i.wrote();
        i.size = 20;
        i.first_write = Some(Instant::now() - MAX_BURST - Duration::from_millis(100));
        let snapshot = Content::Inline(b"0123456789a".to_vec());
        let n = write_pending(
            &mut fx.core,
            &mut fx.t,
            &fx.space,
            vec![(f, read_at, snapshot)],
        )
        .unwrap()
        .len();
        assert_eq!(n, 1, "one entry for one snapshot");
        assert_eq!(fx.versions(&node), vec![b"0123456789a".to_vec()]);
        let i = &fx.t.inodes[&f];
        assert_eq!(i.size, 20, "the size is the file's, not the snapshot's");
        assert!(
            i.dirty.content,
            "what came after the read is still to commit"
        );
    }

    #[test]
    fn content_written_after_it_was_read_stays_dirty() {
        let mut i = Tree::new("/nonexistent".into(), "/nonexistent".into())
            .inodes
            .remove(&ROOT_INO)
            .unwrap();
        i.dirty.content = true;
        i.wrote();
        i.content_gen = i.write_gen;
        i.wrote();
        i.content_committed();
        assert!(
            i.dirty.content,
            "the second write is not in what was committed"
        );
        assert!(i.first_write.is_some(), "and starts a burst of its own");
        i.content_gen = i.write_gen;
        i.content_committed();
        assert!(!i.dirty.content && i.first_write.is_none());
    }

    #[test]
    fn burst_of_nested_creates() {
        let mut fx = Fx::new();
        for k in 0..20 {
            let d = fx.t.alloc(Kind::Dir);
            fx.t.attach(d, ROOT_INO, &format!("d{k}"));
            let e = fx.t.alloc(Kind::Dir);
            fx.t.attach(e, d, "e");
            for j in 0..10 {
                fx.write_in(e, &format!("f{j}"), format!("{k}/{j}").as_bytes());
            }
        }
        // New folders and what is in them are one entry.
        assert_eq!(fx.commit(), 1);
        assert!(!fx.t.has_pending());
        let list = Files::new(fx.sp()).list_path("d7/e").unwrap();
        assert_eq!(list.len(), 10);
        let last = *fx.sp().dag().log_order().last().unwrap();
        assert!(fx.sp().state().is_accepted(&last));
        let entry = fx.sp().entry(&last).unwrap();
        assert_eq!(entry.ops().len(), 20 * 12);
        // Each names its parent by the place of the op that made it, and
        // is kept as it was written; the state holds ids alone.
        let by_index = |op: &SpaceOp| op.record().get(2).and_then(|v| v.as_uint()).is_some();
        assert_eq!(
            entry.ops().iter().filter(|op| by_index(op)).count(),
            20 * 11
        );
        let d7 = fx.t.child(ROOT_INO, "d7").unwrap();
        let e = fx.t.child(d7, "e").unwrap();
        let f3 = fx.t.child(e, "f3").unwrap();
        let st = fx.sp().state();
        assert_eq!(st.node(&fx.node(f3)).unwrap().parent, fx.node(e));
        assert_eq!(st.node(&fx.node(e)).unwrap().parent, fx.node(d7));
        assert_eq!(st.node(&fx.node(d7)).unwrap().parent, ROOT);
        // Nothing is left to say: a second commit writes nothing.
        assert_eq!(fx.commit(), 0);
    }

    /// A burst too large for one entry is cut, and what comes after a cut
    /// names by id what an earlier entry made, and by index what its own
    /// entry makes.
    #[test]
    fn a_burst_cut_into_entries_names_each_parent_where_it_was_made() {
        let mut fx = Fx::new();
        let top = fx.t.alloc(Kind::Dir);
        fx.t.attach(top, ROOT_INO, "top");
        // Enough inline content that the files do not fit one entry.
        let body = vec![7u8; 900];
        let count = 2 * crate::core::MAX_ENTRY_OPS_BYTES / body.len();
        for j in 0..count {
            fx.write_in(top, &format!("f{j}"), &body);
        }
        let inner = fx.t.alloc(Kind::Dir);
        fx.t.attach(inner, top, "inner");
        let last = fx.write_in(inner, "last", b"x");
        let written = fx.commit();
        assert!(written >= 2, "{written}");
        assert!(!fx.t.has_pending());
        let ids: Vec<EntryId> = fx.sp().dag().log_order().to_vec();
        let ids = &ids[ids.len() - written..];
        assert!(ids.iter().all(|id| fx.sp().state().is_accepted(id)));
        let f = Files::new(fx.sp());
        assert_eq!(f.list_path("top").unwrap().len(), count + 1);
        assert_eq!(f.list_path("top/inner").unwrap().len(), 1);
        let st = fx.sp().state();
        assert_eq!(st.node(&fx.node(last)).unwrap().parent, fx.node(inner));
        assert_eq!(st.node(&fx.node(inner)).unwrap().parent, fx.node(top));
        // In the first entry the files name the folder by its place; in
        // the last they name it by the id the first gave it, and `last`
        // names `inner` by its place there.
        let parents = |id: &EntryId| -> Vec<Value> {
            let ops = fx.sp().entry(id).unwrap().ops().to_vec();
            let all = ops.iter().filter_map(|op| op.record().get(2).cloned());
            all.collect()
        };
        let first = parents(&ids[0]);
        assert_eq!(first[0], Value::from(ROOT));
        assert!(first[1..].iter().all(|p| *p == Value::from(0u32)));
        let end = parents(ids.last().unwrap());
        let n = end.len();
        assert!(end[..n - 2].iter().all(|p| *p == Value::from(fx.node(top))));
        assert_eq!(end[n - 1], Value::from((n - 2) as u32));
    }

    /// A new folder and what is moved into it are one entry: the move
    /// names the folder by the place of its `create`, which comes first
    /// whichever of the two is the older here.
    #[test]
    fn a_move_into_a_folder_made_in_the_same_burst_is_one_entry() {
        let mut fx = Fx::new();
        let file = fx.write("a.txt", b"v1");
        fx.commit();
        fx.refresh();
        let dir = fx.t.alloc(Kind::Dir);
        fx.t.attach(dir, ROOT_INO, "d");
        fx.t.detach(file);
        fx.t.attach(file, dir, "a.txt");
        fx.t.inodes.get_mut(&file).unwrap().dirty.pos = true;
        fx.t.touch();
        assert_eq!(fx.commit(), 1);
        let last = *fx.sp().dag().log_order().last().unwrap();
        let ops = fx.sp().entry(&last).unwrap().ops().to_vec();
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[1].record().get(2), Some(&Value::from(0u32)));
        let st = fx.sp().state();
        assert!(st.is_accepted(&last));
        assert_eq!(st.node(&fx.node(file)).unwrap().parent, fx.node(dir));
        fx.refresh();
        assert_eq!(fx.t.child(dir, "a.txt"), Some(file));
        assert!(!fx.t.has_pending());
        assert_eq!(fx.commit(), 0);
    }

    /// Nothing tells this device a removal happened, and it may restart
    /// first: the rule follows from the identity log, which every device
    /// has (`spaces.md#when-to-rotate`).
    #[test]
    fn the_next_write_after_the_identity_key_changed_starts_a_new_epoch() {
        let mut fx = Fx::new();
        let before = fx.sp().current_epoch().unwrap();
        fx.new_identity_key();
        fx.restart();
        assert_eq!(fx.sp().current_epoch(), Some(before));

        fx.write_in(ROOT_INO, "a", b"a");
        assert_eq!(fx.commit(), 1);
        let after = fx.sp().current_epoch().unwrap();
        assert_ne!(after, before);

        // Once is enough.
        fx.write_in(ROOT_INO, "b", b"b");
        fx.commit();
        assert_eq!(fx.sp().current_epoch(), Some(after));
        assert!(fx.core.rotate_if_due(&fx.space).unwrap().is_none());
    }

    /// D1. A rotation that comes due and is started in the entry a burst
    /// goes in takes no place in front of the burst's ops: each index was
    /// numbered, and each node's id worked out, from the burst's own first
    /// op (`state.md#a-node-made-in-the-same-entry`).
    #[test]
    fn a_rotation_started_with_a_burst_leaves_its_ops_where_they_were_numbered() {
        let mut fx = Fx::new();
        let before = fx.sp().current_epoch().unwrap();
        fx.new_identity_key();
        let dir = fx.t.alloc(Kind::Dir);
        fx.t.attach(dir, ROOT_INO, "Trip");
        let file = fx.write_in(dir, "plan.txt", b"hi");
        // `write_pending` is what a commit runs once it has encoded: by
        // then a rotation may have come due that was not when it began.
        assert_eq!(fx.commit(), 1);
        assert_ne!(fx.sp().current_epoch(), Some(before));
        let last = *fx.sp().dag().log_order().last().unwrap();
        let entry = fx.sp().entry(&last).unwrap();
        assert!(entry.starts_epoch());
        assert!(
            fx.sp().state().is_accepted(&last),
            "the burst is not in the state"
        );
        let st = fx.sp().state();
        let (d, f) = (fx.node(dir), fx.node(file));
        assert_eq!(st.node(&d).map(|n| n.parent), Some(ROOT));
        assert_eq!(st.node(&f).map(|n| n.parent), Some(d));
        let list = Files::new(fx.sp()).list_path("Trip").unwrap();
        assert_eq!(list.len(), 1);
        fx.refresh();
        assert_eq!(fx.t.child(dir, "plan.txt"), Some(file));
        assert!(!fx.t.has_pending());
    }

    /// Content is keyed by the epoch, so a commit asks for the rotation by
    /// itself before it encodes anything.
    #[test]
    fn a_rotation_due_can_be_written_on_its_own() {
        let mut fx = Fx::new();
        let before = fx.sp().current_epoch().unwrap();
        assert!(fx.core.rotate_if_due(&fx.space).unwrap().is_none());
        fx.new_identity_key();
        assert!(fx.core.rotate_if_due(&fx.space).unwrap().is_some());
        assert_ne!(fx.sp().current_epoch(), Some(before));
        assert!(fx.core.rotate_if_due(&fx.space).unwrap().is_none());
    }

    /// A change made without having seen others cannot go under an epoch
    /// that is due to end.
    #[test]
    fn nothing_is_written_beside_a_rotation_that_is_due() {
        let mut fx = Fx::new();
        let (first, _) = fx.core.write_entry(&fx.space, Vec::new()).unwrap();
        fx.new_identity_key();
        let refused = fx
            .core
            .write_entry_concurrent(&fx.space, &[first], Vec::new());
        assert!(refused.unwrap_err().to_string().contains("rotation"));
    }
}
