//! The files space as a folder, through FUSE.
//!
//! Mounting needs `/dev/fuse` and `fusermount3` (package `fuse3`); no
//! libfuse headers or library are linked.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use cardinal_space::SpaceId;
use fuser::MountOption;

use super::commit;
use super::onefs::{self, OneFs, Part, Parts};
use super::tree::{Inval, Snapshot, Tree};
use crate::daemon::Daemon;

/// The one folder, mounted (`fs/onefs.rs`).
pub struct Mounted {
    session: Option<fuser::BackgroundSession>,
    parts: Arc<Mutex<Parts>>,
    /// Stops applying changes from other devices.
    stop: Arc<AtomicBool>,
    d: Arc<Daemon>,
    /// Where.
    pub path: PathBuf,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Mounted {
    /// Commits what is pending now in every space shown (for `cardinal
    /// flush` and shutdown).
    pub fn flush(&self) -> anyhow::Result<usize> {
        let parts: Vec<(Arc<Mutex<Tree>>, SpaceId)> = lock(&self.parts)
            .parts
            .values()
            .map(|p| (p.tree.clone(), p.space))
            .collect();
        let mut n = 0;
        for (tree, space) in parts {
            n += commit::commit(&self.d, &tree, &space)?;
        }
        Ok(n)
    }

    /// Commits pending changes and unmounts.
    pub fn unmount(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let schedulers: Vec<_> = {
            let mut g = lock(&self.parts);
            g.parts
                .values_mut()
                .filter_map(|p| {
                    p.stop.store(true, Ordering::Relaxed);
                    p.scheduler.take()
                })
                .collect()
        };
        for h in schedulers {
            let _ = h.join();
        }
        // let files still open settle
        for p in lock(&self.parts).parts.values() {
            let mut t = lock(&p.tree);
            for i in t.inodes.values_mut() {
                i.last_write = None;
            }
        }
        if let Err(e) = self.flush() {
            tracing::error!("could not save the last changes: {e:#}");
        }
        // What is still not committed is kept for the next start, as a
        // disk keeps what was written before an unmount.
        for p in lock(&self.parts).parts.values() {
            if let Err(e) = lock(&p.tree).journal_all_dirty() {
                tracing::error!("could not keep the last changes for the next start: {e:#}");
            }
        }
        drop(self.session.take());
        tracing::info!("unmounted {}", self.path.display());
    }

    /// The tree of the person's own files.
    pub fn tree(&self) -> Arc<Mutex<Tree>> {
        lock(&self.parts).parts[&0].tree.clone()
    }

    /// Whether any space shown has changes not yet committed.
    pub fn has_pending(&self) -> bool {
        lock(&self.parts)
            .parts
            .values()
            .any(|p| lock(&p.tree).has_pending())
    }
}

/// Whether FUSE can be used here.
pub fn available() -> Result<(), String> {
    if !Path::new("/dev/fuse").exists() {
        return Err("/dev/fuse does not exist (is the fuse kernel module loaded?)".into());
    }
    let found = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join("fusermount3").exists()))
        .unwrap_or(false);
    if !found {
        return Err("fusermount3 is not installed (install the `fuse3` package)".into());
    }
    Ok(())
}

fn unmount_stale(path: &Path) {
    // A daemon that died leaves "Transport endpoint is not connected".
    if let Err(e) = std::fs::metadata(path) {
        if e.raw_os_error() == Some(libc::ENOTCONN) {
            tracing::info!("cleaning up a stale mount at {}", path.display());
            let _ = std::process::Command::new("fusermount3")
                .arg("-u")
                .arg("-z")
                .arg(path)
                .status();
        }
    }
}

/// Brings the tree up to date with the space and tells the kernel.
pub fn refresh(
    d: &Daemon,
    tree: &Mutex<Tree>,
    space: &SpaceId,
    notifier: Option<&fuser::Notifier>,
) {
    let invals = {
        let core = d.core();
        let Some(h) = core.spaces.get(space) else {
            return;
        };
        let Some(sp) = h.space.as_ref() else {
            return;
        };
        let mut t = tree.lock().unwrap_or_else(|e| e.into_inner());
        // what the committer applied
        let mut invals = std::mem::take(&mut t.pending_inval);
        if t.applied_version != h.version {
            let snap = Snapshot::take(sp, h.version, &core.device_names());
            invals.extend(t.apply(&snap));
            // A `.cardinalignore` that changed elsewhere may no longer name
            // what is local here.
            if t.ignore_seen.as_ref() != Some(&t.ignore_texts(&d.store)) {
                t.reevaluate(&d.store);
            }
        }
        invals
    };
    if let Some(n) = notifier {
        for i in invals {
            let _ = match i {
                Inval::Entry(p, name) => n.inval_entry(p, std::ffi::OsStr::new(&name)),
                Inval::Inode(ino) => n.inval_inode(ino, 0, 0),
            };
        }
    }
}

/// Mounts the one folder at `path`: the files space at its root, and each
/// relationship's shared folder beside it (`onefolder.rs`).
pub fn mount(d: Arc<Daemon>, space: SpaceId, path: &Path) -> anyhow::Result<Mounted> {
    available().map_err(|e| anyhow::anyhow!(e))?;
    unmount_stale(path);
    std::fs::create_dir_all(path)?;
    if std::fs::read_dir(path)?.next().is_some() {
        anyhow::bail!(
            "{} is not empty. Move its contents away, or choose another folder with \
             `cardinal mount <folder>`.",
            path.display()
        );
    }
    let parts = Arc::new(Mutex::new(Parts::new(Part::open(&d, 0, space, None))));
    onefs::update(&d, &parts);
    let fs = OneFs::new(d.clone(), parts.clone());
    let opts = [
        MountOption::FSName("cardinal".into()),
        MountOption::Subtype("cardinal".into()),
        MountOption::DefaultPermissions,
        MountOption::NoDev,
        MountOption::NoSuid,
        MountOption::RW,
    ];
    let session =
        fuser::Session::new(fs, path, &opts).map_err(|e| anyhow::anyhow!("mount failed: {e}"))?;
    let notifier = session.notifier();
    let bg = session.spawn()?;
    let stop = Arc::new(AtomicBool::new(false));
    // Apply changes from other devices as they arrive, and show
    // relationships as they come and change.
    {
        let (d2, parts2, stop2) = (d.clone(), parts.clone(), stop.clone());
        let mut changed = d.changed.subscribe();
        d.rt.spawn(async move {
            let notifier = Arc::new(notifier);
            loop {
                if changed.changed().await.is_err() || stop2.load(Ordering::Relaxed) {
                    break;
                }
                let (d3, p3, n3) = (d2.clone(), parts2.clone(), notifier.clone());
                let _ = tokio::task::spawn_blocking(move || {
                    let invals = onefs::update(&d3, &p3);
                    let each: Vec<(Arc<Mutex<Tree>>, SpaceId)> = lock(&p3)
                        .parts
                        .values()
                        .map(|p| (p.tree.clone(), p.space))
                        .collect();
                    for (tree, space) in each {
                        refresh(&d3, &tree, &space, Some(&n3));
                    }
                    for i in invals {
                        if let Inval::Entry(p, name) = i {
                            let _ = n3.inval_entry(p, std::ffi::OsStr::new(&name));
                        }
                    }
                })
                .await;
            }
        });
    }
    Ok(Mounted {
        session: Some(bg),
        parts,
        stop,
        d,
        path: path.to_path_buf(),
    })
}
