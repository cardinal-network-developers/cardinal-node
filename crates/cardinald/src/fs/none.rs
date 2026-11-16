//! A build with no way to show files as a folder: phones, and Windows until it
//! has one. Everything else still works; `status` says why there is no folder.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use cardinal_space::SpaceId;

use super::tree::Tree;
use crate::daemon::Daemon;

const NO_MOUNT: &str = "this build cannot show your files as a folder";

/// Never made: nothing mounts here.
pub struct Mounted {
    /// Where.
    pub path: PathBuf,
    tree: Arc<Mutex<Tree>>,
}

impl Mounted {
    /// Commits what is pending now.
    pub fn flush(&self) -> anyhow::Result<usize> {
        Ok(0)
    }

    /// Commits pending changes and unmounts.
    pub fn unmount(self) {}

    /// The tree of the person's own files.
    pub fn tree(&self) -> Arc<Mutex<Tree>> {
        self.tree.clone()
    }

    /// How many changes went into entries that were not accepted: none,
    /// since nothing is written through a folder here.
    pub fn refused_count(&self) -> usize {
        0
    }

    /// How many of those were undone: none.
    pub fn undone_count(&self) -> usize {
        0
    }

    /// Whether anything is waiting to be committed.
    pub fn has_pending(&self) -> bool {
        false
    }
}

/// Whether mounting can work here.
pub fn available() -> Result<(), String> {
    Err(NO_MOUNT.to_owned())
}

/// Mounts the files space.
pub fn mount(_d: Arc<Daemon>, _space: SpaceId, _path: &Path) -> anyhow::Result<Mounted> {
    anyhow::bail!(NO_MOUNT)
}
