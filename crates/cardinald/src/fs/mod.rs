//! The files space as a folder, through FUSE.
//!
//! Mounting needs `/dev/fuse` and `fusermount3` (package `fuse3`); no
//! libfuse headers or library are linked.

pub mod commit;
pub mod ops;
pub mod tree;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use cardinal_space::SpaceId;
use fuser::MountOption;

use crate::daemon::Daemon;
use tree::{Inval, Snapshot, Tree};

/// A mounted files space.
pub struct Mounted {
    session: Option<fuser::BackgroundSession>,
    tree: Arc<Mutex<Tree>>,
    stop: Arc<AtomicBool>,
    scheduler: Option<std::thread::JoinHandle<()>>,
    d: Arc<Daemon>,
    space: SpaceId,
    /// Where.
    pub path: PathBuf,
}

impl Mounted {
    /// Commits what is pending now (for `cardinal flush` and shutdown).
    pub fn flush(&self) -> anyhow::Result<usize> {
        commit::commit(&self.d, &self.tree, &self.space)
    }

    /// Commits pending changes and unmounts.
    pub fn unmount(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.scheduler.take() {
            let _ = h.join();
        }
        // let files still open settle
        {
            let mut t = self.tree.lock().unwrap_or_else(|e| e.into_inner());
            for i in t.inodes.values_mut() {
                i.last_write = None;
            }
        }
        if let Err(e) = self.flush() {
            tracing::error!("could not save the last changes: {e:#}");
        }
        drop(self.session.take());
        tracing::info!("unmounted {}", self.path.display());
    }

    /// The tree.
    pub fn tree(&self) -> &Arc<Mutex<Tree>> {
        &self.tree
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

fn snapshot(d: &Daemon, space: &SpaceId) -> Option<Snapshot> {
    let core = d.core();
    let h = core.spaces.get(space)?;
    let sp = h.space.as_ref()?;
    Some(Snapshot::take(sp, h.version, &core.device_names()))
}

/// Brings the tree up to date with the space and tells the kernel.
pub fn refresh(d: &Daemon, tree: &Mutex<Tree>, space: &SpaceId, notifier: Option<&fuser::Notifier>) {
    let invals = {
        let core = d.core();
        let Some(h) = core.spaces.get(space) else {
            return;
        };
        let Some(sp) = h.space.as_ref() else {
            return;
        };
        let mut t = tree.lock().unwrap_or_else(|e| e.into_inner());
        if t.applied_version == h.version {
            return;
        }
        let snap = Snapshot::take(sp, h.version, &core.device_names());
        t.apply(&snap)
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

/// Mounts the files space at `path`.
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
    let tree = Arc::new(Mutex::new(Tree::new(d.paths.staging())));
    if let Some(s) = snapshot(&d, &space) {
        tree.lock().unwrap_or_else(|e| e.into_inner()).apply(&s);
    }
    let fs = ops::CardinalFs::new(d.clone(), tree.clone());
    let opts = [
        MountOption::FSName("cardinal".into()),
        MountOption::Subtype("cardinal".into()),
        MountOption::DefaultPermissions,
        MountOption::NoDev,
        MountOption::NoSuid,
        MountOption::RW,
    ];
    let session = fuser::Session::new(fs, path, &opts)
        .map_err(|e| anyhow::anyhow!("mount failed: {e}"))?;
    let notifier = session.notifier();
    let bg = session.spawn()?;
    let stop = Arc::new(AtomicBool::new(false));
    let scheduler = commit::spawn_scheduler(d.clone(), tree.clone(), space, stop.clone());
    // Apply changes from other devices as they arrive.
    {
        let d2 = d.clone();
        let tree2 = tree.clone();
        let stop2 = stop.clone();
        let mut changed = d.changed.subscribe();
        d.rt.spawn(async move {
            let notifier = Arc::new(notifier);
            loop {
                if changed.changed().await.is_err() || stop2.load(Ordering::Relaxed) {
                    break;
                }
                let (d3, t3, n3) = (d2.clone(), tree2.clone(), notifier.clone());
                let _ = tokio::task::spawn_blocking(move || refresh(&d3, &t3, &space, Some(&n3)))
                    .await;
            }
        });
    }
    Ok(Mounted {
        session: Some(bg),
        tree,
        stop,
        scheduler: Some(scheduler),
        d,
        space,
        path: path.to_path_buf(),
    })
}
