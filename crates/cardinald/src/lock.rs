//! One process at a time on a data directory.
//!
//! A service holds an exclusive lock on the file `lock` in its data
//! directory for as long as it runs, taken before it reads anything there.
//! Whatever removes a store takes the same lock first. So two services
//! never run on one directory, and none is cleared from under one. It does
//! not turn on what each was told the directory is called, or on where each
//! looks for the other's socket, or on whether the first has bound its
//! socket yet: a lock is held on the file, not on a name.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::PathBuf;

use crate::paths::Paths;

/// The data directory, held. Dropping it lets go.
#[derive(Debug)]
pub struct Lock(#[allow(dead_code)] File);

/// The lock file's path.
pub fn file(paths: &Paths) -> PathBuf {
    paths.home.join("lock")
}

#[cfg(unix)]
fn open(path: &std::path::Path, create: bool) -> io::Result<Option<File>> {
    use std::os::fd::AsRawFd;
    let f = OpenOptions::new()
        .create(create)
        .truncate(false)
        .write(true)
        .open(path)?;
    // SAFETY: `flock` on a descriptor this function owns.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(Some(f));
    }
    let e = io::Error::last_os_error();
    match e.kind() {
        io::ErrorKind::WouldBlock => Ok(None),
        _ => Err(e),
    }
}

/// On Windows a file opened sharing nothing is held: a second open fails
/// with a sharing violation.
#[cfg(windows)]
fn open(path: &std::path::Path, create: bool) -> io::Result<Option<File>> {
    use std::os::windows::fs::OpenOptionsExt;
    let opened = OpenOptions::new()
        .create(create)
        .truncate(false)
        .write(true)
        .share_mode(0)
        .open(path);
    match opened {
        Ok(f) => Ok(Some(f)),
        Err(e) if e.raw_os_error() == Some(32) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Takes the data directory for this process, making it and the lock file
/// if they are not there. `None` if another process holds it.
pub fn take(paths: &Paths) -> io::Result<Option<Lock>> {
    std::fs::create_dir_all(&paths.home)?;
    Ok(open(&file(paths), true)?.map(Lock))
}

/// Whether another process holds the data directory. Nothing is made
/// there: a directory with no lock file is held by nobody.
pub fn held(paths: &Paths) -> bool {
    matches!(open(&file(paths), false), Ok(None))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_directory_is_held_by_one_at_a_time_whatever_it_is_called() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path());
        // nothing there: held by nobody, and asking makes nothing
        assert!(!held(&paths));
        assert!(!file(&paths).exists());
        let first = take(&paths).unwrap().expect("free");
        assert!(held(&paths));
        assert!(take(&paths).unwrap().is_none());
        // by another name for the same directory
        let other = Paths::at(&dir.path().join("."));
        assert!(held(&other) && take(&other).unwrap().is_none());
        drop(first);
        assert!(!held(&paths));
        assert!(take(&paths).unwrap().is_some());
    }
}
