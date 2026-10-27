//! Turning local changes into space entries (`profiles.md#files`):
//! after writes have been quiet for 200 ms, or after 2 seconds of
//! continuous activity, everything pending becomes one burst of entries.
//!
//! A node created in an entry cannot be named by a later op of the same
//! entry (its id depends on the entry's id), so a burst that creates
//! folders and things inside them is written as one entry per level of
//! new folders (see DEVIATIONS.md).

use std::collections::HashSet;
use std::os::unix::fs::FileExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cardinal_blob::{BlobWriter, ConvergenceSecret, FsStore, INLINE_LIMIT};
use cardinal_space::files::{self, Content, Files};
use cardinal_space::{SpaceId, SpaceOp};

use super::tree::{time_to_ms, Kind, Staged, Tree, ROOT_INO};
use crate::core::split_ops;
use crate::daemon::Daemon;

/// Quiet period before a burst is committed.
pub const QUIET: Duration = Duration::from_millis(200);
/// Longest a burst may run before it is committed anyway.
pub const MAX_BURST: Duration = Duration::from_secs(2);

fn lock(t: &Mutex<Tree>) -> std::sync::MutexGuard<'_, Tree> {
    t.lock().unwrap_or_else(|e| e.into_inner())
}

/// Encodes a staged file as content: inline under 1 KiB, else a blob.
pub fn encode(
    staged: &Staged,
    secret: &ConvergenceSecret,
    store: Arc<FsStore>,
) -> anyhow::Result<Content> {
    let len = staged.file.metadata()?.len();
    if len < INLINE_LIMIT as u64 {
        let mut b = vec![0u8; len as usize];
        staged.file.read_exact_at(&mut b, 0)?;
        return Ok(Content::Inline(b));
    }
    let mut w = BlobWriter::new(secret, store);
    let mut buf = vec![0u8; 1 << 20];
    let mut off = 0u64;
    loop {
        let n = staged.file.read_at(&mut buf, off)?;
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

/// One commit at a time (the scheduler and `cardinal flush`).
static COMMITTING: Mutex<()> = Mutex::new(());

/// Commits everything pending. Returns the number of entries written.
pub fn commit(d: &Arc<Daemon>, tree: &Mutex<Tree>, space: &SpaceId) -> anyhow::Result<usize> {
    let _one = COMMITTING.lock().unwrap_or_else(|e| e.into_inner());
    // A: what needs encoding.
    let to_encode: Vec<(u64, u64, Arc<Staged>)> = {
        let t = lock(tree);
        t.inodes
            .values()
            .filter(|i| {
                i.parent != 0
                    && i.kind == Kind::File
                    && (i.dirty.content || i.node.is_none())
                    && !i.busy(QUIET)
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
        for (ino, gen, st) in to_encode {
            let c = encode(&st, &secret, d.store.clone())?;
            encoded.push((ino, gen, c));
        }
    }

    // C: build ops and write, holding the space then the tree.
    let mut core = d.core();
    let mut t = lock(tree);
    let mut ready: HashSet<u64> = HashSet::new();
    for (ino, gen, c) in encoded {
        if let Some(i) = t.inodes.get_mut(&ino) {
            if i.write_gen == gen {
                i.size = c.size();
                i.content = Some(c);
                ready.insert(ino);
            }
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
        // (op, what it does to which inode)
        let mut ops: Vec<SpaceOp> = Vec::new();
        let mut effects: Vec<Effect> = Vec::new();
        let mut inos: Vec<u64> = t.inodes.keys().copied().collect();
        inos.sort_unstable();
        for ino in inos {
            if ino == ROOT_INO {
                continue;
            }
            let i = &t.inodes[&ino];
            if i.parent == 0 || matches!(i.kind, Kind::Conflict(_)) {
                continue;
            }
            let Some(pnode) = t.inodes.get(&i.parent).and_then(|p| p.node) else {
                continue;
            };
            let content_ready = i.kind != Kind::File
                || i.staged.is_none()
                || ready.contains(&ino)
                || !(i.dirty.content || i.node.is_none());
            match i.node {
                None => {
                    if !content_ready || (i.kind == Kind::File && i.busy(QUIET)) {
                        continue;
                    }
                    let op = match i.kind {
                        Kind::Dir => files::create_folder(pnode, &i.name),
                        Kind::File => files::create_file(
                            pnode,
                            &i.name,
                            i.content.as_ref().unwrap_or(&Content::Inline(Vec::new())),
                            i.perm as u32,
                            Some(time_to_ms(i.mtime)),
                        ),
                        Kind::Symlink => files::create_link(pnode, &i.name, &i.target),
                        Kind::Conflict(_) => unreachable!(),
                    };
                    effects.push(Effect::Created(ino));
                    ops.push(op);
                }
                Some(node) => {
                    if i.dirty.pos {
                        ops.push(SpaceOp::mv(node, pnode, &i.name));
                        effects.push(Effect::Clean(ino, Flag::Pos));
                    }
                    if i.kind == Kind::File && i.dirty.content && content_ready && !i.busy(QUIET) {
                        let c = i.content.clone().unwrap_or(Content::Inline(Vec::new()));
                        ops.push(files::set_content(node, &c));
                        effects.push(Effect::Clean(ino, Flag::Content));
                    }
                    if i.kind == Kind::File && i.dirty.mode {
                        ops.push(files::set_mode(node, i.perm as u32));
                        effects.push(Effect::Clean(ino, Flag::Mode));
                    }
                    if i.kind == Kind::File && i.dirty.mtime {
                        ops.push(files::set_mtime(node, time_to_ms(i.mtime)));
                        effects.push(Effect::Clean(ino, Flag::Mtime));
                    }
                }
            }
        }
        if first {
            for n in std::mem::take(&mut t.deleted) {
                ops.push(SpaceOp::delete(n));
                effects.push(Effect::None);
            }
            let settle: Vec<_> = t.settle.drain().collect();
            if !settle.is_empty() {
                let sp = core.spaces.get(space).and_then(|h| h.space.as_ref());
                if let Some(sp) = sp {
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
            }
            first = false;
        }
        if ops.is_empty() {
            break;
        }
        // write, one entry per batch, mapping created ops to node ids
        let mut idx = 0;
        for batch in split_ops(ops) {
            let n = batch.len();
            let (eid, bytes) = core.write_entry(space, batch)?;
            written.push(bytes);
            for (k, eff) in effects[idx..idx + n].iter().enumerate() {
                match eff {
                    Effect::Created(ino) => {
                        let node = files::created_node(&eid, k);
                        if let Some(i) = t.inodes.get_mut(ino) {
                            i.node = Some(node);
                            i.dirty = Default::default();
                        }
                        t.by_node.insert(node, *ino);
                    }
                    Effect::Clean(ino, f) => {
                        if let Some(i) = t.inodes.get_mut(ino) {
                            match f {
                                Flag::Pos => i.dirty.pos = false,
                                Flag::Content => i.dirty.content = false,
                                Flag::Mode => i.dirty.mode = false,
                                Flag::Mtime => i.dirty.mtime = false,
                            }
                        }
                    }
                    Effect::None => {}
                }
            }
            idx += n;
        }
    }
    // Staged content that is committed and closed is no longer needed:
    // reads come from the blob store.
    for i in t.inodes.values_mut() {
        if i.staged.is_some() && i.writers == 0 && !i.dirty.content && i.node.is_some() {
            i.staged = None;
        }
    }
    if t.has_pending() {
        // what is left (files still being written) waits for its own quiet
        t.first_change = Some(Instant::now());
    } else {
        t.first_change = None;
        t.last_change = None;
    }
    drop(t);
    drop(core);
    let n = written.len();
    if n > 0 {
        d.push(space, written);
        d.bump();
    }
    Ok(n)
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
                    Ok(n) => {
                        failures = 0;
                        if n > 0 {
                            tracing::debug!("committed {n} entries");
                        }
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
