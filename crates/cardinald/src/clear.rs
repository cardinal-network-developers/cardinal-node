//! Removing what the node wrote in a data directory (`cardinal clear`), so
//! that a device can start again in the same place.
//!
//! It works on a store of any format, because it parses none of it: it
//! counts files and removes them by name. It removes this device's keys,
//! the identity log, the spaces, the objects, files being written, other
//! people's logs, the mailbox, the state files and the format marker. It
//! leaves `config.toml`, and anything in the directory that the node did
//! not write. It leaves the files kept on this device only (`local/`,
//! `local-shared/`), which are the person's own and exist nowhere else,
//! unless it is told to remove them too.

use std::io;
use std::path::{Path, PathBuf};

use crate::paths::Paths;

/// The directories the node writes in a data directory, the two kept on
/// this device only aside.
const DIRS: [&str; 5] = ["spaces", "blobs", "staging", "others", "mailbox"];

/// What `.cardinalignore` keeps on this device only: the person's own
/// files, which exist nowhere else.
const LOCAL: [&str; 2] = ["local", "local-shared"];

/// The files the node writes there. Each may have a `.tmp` beside it, left
/// by a write that was interrupted.
const STATE: [&str; 8] = [
    "link.json",
    "guarding.json",
    "recovering.json",
    "in-use.json",
    "peers.json",
    "copies.json",
    "old-versions.json",
    "control.sock",
];

/// What is in a data directory, counted without reading any of it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Found {
    /// Whether this device's keys or an identity log are there.
    pub identity: bool,
    /// How many spaces.
    pub spaces: u64,
    /// How many objects, and their bytes.
    pub objects: (u64, u64),
    /// How many files being written that were never saved, and their bytes.
    pub staged: (u64, u64),
    /// How many files kept on this device only, and their bytes.
    pub local: (u64, u64),
    /// Whether anything else the node wrote is there.
    pub other: bool,
}

impl Found {
    /// Whether there is anything to remove.
    pub fn anything(&self, including_local: bool) -> bool {
        self.identity
            || self.spaces > 0
            || self.objects.0 > 0
            || self.staged.0 > 0
            || self.other
            || (including_local && self.local.0 > 0)
    }
}

/// Counts the regular files beneath `dir`, and their bytes. A link is
/// counted and never followed.
fn count(dir: &Path) -> (u64, u64) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return (0, 0);
    };
    let (mut files, mut bytes) = (0, 0);
    for e in rd.flatten() {
        match e.file_type() {
            Ok(t) if t.is_dir() => {
                let (f, b) = count(&e.path());
                files += f;
                bytes += b;
            }
            Ok(_) => {
                files += 1;
                bytes += e.metadata().map(|m| m.len()).unwrap_or(0);
            }
            Err(_) => {}
        }
    }
    (files, bytes)
}

fn exists(p: &Path) -> bool {
    p.symlink_metadata().is_ok()
}

/// What `cardinal clear` would find in a data directory.
pub fn found(paths: &Paths) -> Found {
    let home = &paths.home;
    let spaces = std::fs::read_dir(paths.spaces())
        .map(|rd| rd.flatten().count() as u64)
        .unwrap_or(0);
    let local = LOCAL.iter().map(|d| count(&home.join(d)));
    let local = local.fold((0, 0), |a, b| (a.0 + b.0, a.1 + b.1));
    let state = STATE.iter().map(|f| home.join(f));
    let dirs = DIRS.iter().map(|d| home.join(d));
    Found {
        identity: exists(&paths.device_key()) || exists(&paths.identity_log()),
        spaces,
        objects: count(&paths.blobs().join("objects")),
        staged: count(&paths.staging()),
        local,
        other: exists(&crate::format::marker(paths)) || state.chain(dirs).any(|p| exists(&p)),
    }
}

fn remove(p: &Path) -> io::Result<()> {
    let gone = |r: io::Result<()>| match r {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        r => r,
    };
    match p.symlink_metadata() {
        Ok(m) if m.is_dir() => gone(std::fs::remove_dir_all(p)),
        Ok(_) => gone(std::fs::remove_file(p)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Removes what the node wrote in a data directory, unless a service is
/// running on it: this takes the directory as a service does
/// ([`crate::lock`]) and holds it until it is done.
///
/// The marker goes first and the identity log last. If this is interrupted
/// the directory still holds an identity and has no marker, so nothing
/// opens it as it is, and running this again finishes the job.
pub fn clear(paths: &Paths, including_local: bool) -> io::Result<()> {
    if !paths.home.is_dir() {
        return Ok(());
    }
    let Some(lock) = crate::lock::take(paths)? else {
        let running = "a Cardinal service is running on this data";
        return Err(io::Error::new(io::ErrorKind::ResourceBusy, running));
    };
    let home = &paths.home;
    let tmp = |p: &Path| p.with_extension("tmp");
    let marker = crate::format::marker(paths);
    remove(&marker)?;
    remove(&tmp(&marker))?;
    let mut dirs: Vec<PathBuf> = DIRS.iter().map(|d| home.join(d)).collect();
    if including_local {
        dirs.extend(LOCAL.iter().map(|d| home.join(d)));
    }
    for d in dirs {
        remove(&d)?;
    }
    for f in STATE.iter().map(|f| home.join(f)) {
        remove(&f)?;
        remove(&tmp(&f))?;
    }
    for f in [paths.device_key(), paths.identity_log()] {
        remove(&tmp(&f))?;
        remove(&f)?;
    }
    drop(lock);
    // The lock is a file only on Windows. On Unix the directory itself was
    // held and nothing called `lock` is the node's: it stays (S8).
    #[cfg(windows)]
    remove(&crate::lock::file(paths))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::format::{self, Store};

    /// A data directory with one of everything in it.
    fn full() -> (tempfile::TempDir, Paths) {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path());
        let home = &paths.home;
        let put = |rel: &str, bytes: &[u8]| {
            let p = home.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, bytes).unwrap();
        };
        put("device.key", b"key");
        put("identity.log", b"log");
        put("format", b"2\n");
        put("spaces/aa/entries.log", b"entries");
        put("spaces/aa/epochs.json", b"{}");
        put("spaces/bb/entries.log", b"entries");
        put("blobs/objects/ab/cd/abcd", &[0; 10]);
        put("blobs/objects/ab/ce/abce", &[0; 20]);
        put("blobs/tmp/1-2-3", b"half");
        put("staging/1-1", &[0; 7]);
        put("others/cc", b"log");
        put("mailbox/state.json", b"{}");
        put("mailbox/1", b"envelope");
        for f in ["link.json", "in-use.json", "peers.json", "copies.json"] {
            put(f, b"{}");
        }
        put("old-versions.json", b"{}");
        put("peers.tmp", b"{");
        put("control.sock", b"");
        put("local/notes/draft.txt", &[0; 5]);
        put("local-shared/Bo/todo.txt", &[0; 6]);
        put("config.toml", b"[daemon]\nname = \"here\"\n");
        put("mine.txt", b"not the node's");
        (dir, paths)
    }

    fn names(home: &Path) -> Vec<String> {
        let rd = std::fs::read_dir(home).unwrap();
        let mut all: Vec<String> = rd
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        all.sort();
        all
    }

    #[test]
    fn it_says_what_is_there_without_reading_it() {
        let (_dir, paths) = full();
        let f = found(&paths);
        let all = Found {
            identity: true,
            spaces: 2,
            objects: (2, 30),
            staged: (1, 7),
            local: (2, 11),
            other: true,
        };
        assert_eq!(f, all);
        assert!(f.anything(false));
        // nothing was touched
        assert_eq!(names(&paths.home).len(), 19);
        let empty = tempfile::tempdir().unwrap();
        let none = found(&Paths::at(empty.path()));
        assert_eq!(none, Found::default());
        assert!(!none.anything(true));
        // a directory with only someone's own files in it
        std::fs::create_dir_all(empty.path().join("local")).unwrap();
        std::fs::write(empty.path().join("local/x"), b"mine").unwrap();
        let only = found(&Paths::at(empty.path()));
        assert!(!only.anything(false) && only.anything(true));
    }

    #[test]
    fn it_removes_what_the_node_wrote_and_nothing_else() {
        let (_dir, paths) = full();
        clear(&paths, false).unwrap();
        assert_eq!(
            names(&paths.home),
            ["config.toml", "local", "local-shared", "mine.txt"]
        );
        assert!(paths.home.join("local/notes/draft.txt").exists());
        assert!(paths.home.join("local-shared/Bo/todo.txt").exists());
        // the settings are as they were
        assert_eq!(Config::load(&paths.config()).unwrap().name, "here");
        // and it is no store any more: a device can be set up here again
        assert_eq!(format::of(&paths), Store::Empty);
        assert!(!found(&paths).anything(false));
        // again changes nothing
        clear(&paths, false).unwrap();
        assert_eq!(names(&paths.home).len(), 4);
    }

    /// S8. On Unix the directory itself is held and no `lock` file is ever
    /// made: something called `lock` there is not the node's, and stays.
    #[cfg(unix)]
    #[test]
    fn something_called_lock_is_not_the_nodes_here() {
        let (_dir, paths) = full();
        let kept = paths.home.join("lock/keep.txt");
        std::fs::create_dir_all(kept.parent().unwrap()).unwrap();
        std::fs::write(&kept, b"mine").unwrap();
        clear(&paths, true).unwrap();
        assert!(kept.exists(), "a folder called lock was removed");
        assert_eq!(names(&paths.home), ["config.toml", "lock", "mine.txt"]);
        let (_dir, paths) = full();
        std::fs::write(paths.home.join("lock"), b"mine").unwrap();
        clear(&paths, true).unwrap();
        assert!(
            paths.home.join("lock").exists(),
            "a file called lock was removed"
        );
    }

    #[test]
    fn the_persons_own_files_go_only_when_asked() {
        let (_dir, paths) = full();
        clear(&paths, true).unwrap();
        assert_eq!(names(&paths.home), ["config.toml", "mine.txt"]);
    }

    #[test]
    fn a_store_of_any_format_is_cleared() {
        // What 0.1.13 left: no marker, and nothing this version can parse.
        let (_dir, paths) = full();
        std::fs::remove_file(format::marker(&paths)).unwrap();
        std::fs::write(paths.identity_log(), [0xff; 64]).unwrap();
        assert_eq!(format::of(&paths), Store::Other(Some(1)));
        assert_eq!(found(&paths).spaces, 2);
        clear(&paths, false).unwrap();
        assert_eq!(format::of(&paths), Store::Empty);
        // One from a version yet to come.
        let (_dir, paths) = full();
        std::fs::write(format::marker(&paths), b"9\n").unwrap();
        clear(&paths, false).unwrap();
        assert_eq!(format::of(&paths), Store::Empty);
    }

    #[test]
    fn interrupted_it_leaves_a_directory_that_nothing_opens() {
        // The marker goes first and the identity log last: whatever is
        // left between the two is refused, and clearing again finishes.
        let (_dir, paths) = full();
        std::fs::remove_file(format::marker(&paths)).unwrap();
        std::fs::remove_dir_all(paths.spaces()).unwrap();
        std::fs::remove_dir_all(paths.blobs()).unwrap();
        std::fs::remove_file(paths.device_key()).unwrap();
        assert_eq!(format::of(&paths), Store::Other(Some(1)));
        assert!(format::check(&paths).is_err());
        clear(&paths, false).unwrap();
        assert_eq!(format::of(&paths), Store::Empty);
    }
}
