//! One process at a time on a data directory.
//!
//! A service holds an exclusive lock on its data directory for as long as
//! it runs, taken before it reads anything there. Whatever removes a store
//! takes the same lock first. So two services never run on one directory,
//! and none is cleared from under one. It does not turn on what each was
//! told the directory is called, or on where each looks for the other's
//! socket, or on whether the first has bound its socket yet: the lock is
//! held on the directory, not on a name.
//!
//! On Unix the lock is on the directory itself, so nothing is written
//! there to take it: a store this version cannot read is left exactly as
//! it was. On Windows it is a file in the directory, `lock`, opened
//! sharing nothing.

use std::fs::File;
use std::io;
use std::path::PathBuf;

use crate::paths::Paths;

/// The data directory, held. Dropping it lets go.
#[derive(Debug)]
pub struct Lock(#[allow(dead_code)] File);

/// The lock file's path, where there is one: on Unix nothing is ever
/// written to take the directory, and a `lock` there is not the node's.
pub fn file(paths: &Paths) -> PathBuf {
    paths.home.join("lock")
}

#[cfg(unix)]
fn open(paths: &Paths, _create: bool) -> io::Result<Option<File>> {
    use std::os::fd::AsRawFd;
    let f = File::open(&paths.home)?;
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
fn open(paths: &Paths, create: bool) -> io::Result<Option<File>> {
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;
    let opened = OpenOptions::new()
        .create(create)
        .truncate(false)
        .write(true)
        .share_mode(0)
        .open(file(paths));
    match opened {
        Ok(f) => Ok(Some(f)),
        Err(e) if e.raw_os_error() == Some(32) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Takes the data directory for this process, making it if it is not
/// there. `None` if another process holds it.
///
/// [`held`] takes the lock for an instant to answer, so a directory found
/// held is tried again for two seconds before it counts as another
/// process's: one asking is done long before then, and a service holds it
/// for as long as it runs.
pub fn take(paths: &Paths) -> io::Result<Option<Lock>> {
    std::fs::create_dir_all(&paths.home)?;
    let until = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        if let Some(f) = open(paths, true)? {
            return Ok(Some(Lock(f)));
        }
        if std::time::Instant::now() >= until {
            return Ok(None);
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

/// Whether another process holds the data directory. Nothing is made
/// there: a directory that is not there is held by nobody. One that is
/// there and cannot be looked at is an error, not "nobody": whoever asks
/// would otherwise be told that no service runs on data it never saw.
pub fn held(paths: &Paths) -> io::Result<bool> {
    match open(paths, false) {
        Ok(lock) => Ok(lock.is_none()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// Why a directory could not be taken or looked at, for a person: the
/// error alone ("No locks available") says nothing of what to do.
pub fn cannot(paths: &Paths, e: &io::Error) -> String {
    format!(
        "Cardinal cannot lock its data directory {} ({e}), which is how it keeps two services \
         off the same data. Some file systems do not allow it, network ones among them: keep \
         the data on a local disk (`CARDINAL_HOME`). Nothing was changed.",
        paths.home.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_directory_is_held_by_one_at_a_time_whatever_it_is_called() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path());
        // not there: held by nobody, and asking makes nothing
        let none = Paths::at(&dir.path().join("none"));
        let held = |p: &Paths| held(p).unwrap();
        assert!(!held(&none) && !none.home.exists());
        assert!(!held(&paths));
        let first = take(&paths).unwrap().expect("free");
        assert!(held(&paths));
        // taking it writes nothing there
        #[cfg(unix)]
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        assert!(take(&paths).unwrap().is_none());
        // by another name for the same directory
        let other = Paths::at(&dir.path().join("."));
        assert!(held(&other) && take(&other).unwrap().is_none());
        drop(first);
        assert!(!held(&paths));
        assert!(take(&paths).unwrap().is_some());
    }

    /// Asking whether a directory is held takes its lock for an instant. A
    /// service starting in that instant waits it out, instead of saying
    /// another is running: a window asks every few seconds while one starts.
    #[test]
    fn a_service_starting_while_someone_asks_waits_for_the_answer() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path());
        // Made as a service would have made it (on Windows the lock is a file).
        let asking = open(&paths, true).unwrap().expect("free");
        let answered = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(200));
            drop(asking);
        });
        assert!(take(&paths).unwrap().is_some());
        answered.join().unwrap();
    }

    /// S9. A directory that cannot be looked at is not "held by nobody":
    /// whoever asks is told that it could not be told.
    #[cfg(unix)]
    #[test]
    fn a_directory_that_cannot_be_opened_is_not_free() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir(&home).unwrap();
        let mode = |m| std::fs::set_permissions(&home, std::fs::Permissions::from_mode(m));
        mode(0o000).unwrap();
        if std::fs::read_dir(&home).is_ok() {
            // whoever runs this may open anything
            mode(0o700).unwrap();
            return;
        }
        let paths = Paths::at(&home);
        let asked = held(&paths);
        mode(0o700).unwrap();
        assert!(asked.is_err(), "{asked:?}");
        assert!(matches!(held(&paths), Ok(false)));
    }
}
