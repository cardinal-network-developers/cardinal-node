//! Atomic file replacement.
//!
//! Every file the installer writes is first written in full to a temporary
//! name in the same directory, flushed to disk, and then renamed over its
//! destination, so a crash leaves either the old file or the new one, never
//! a torn mixture. Renaming over a running executable is safe on Linux: the
//! running process keeps the old inode.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A fresh hidden temporary name next to `dest`.
pub fn temp_path(dest: &Path) -> PathBuf {
    let name = dest
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    dest.with_file_name(format!(".{name}.tmp-{}-{n}", std::process::id()))
}

/// A temporary file that is deleted unless [`TempFile::persist`] is called.
pub struct TempFile {
    path: PathBuf,
    file: Option<File>,
}

impl TempFile {
    /// Creates a new temporary file next to `dest` with permissions `mode`.
    pub fn new_for(dest: &Path, mode: u32) -> io::Result<TempFile> {
        let path = temp_path(dest);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&path)?;
        // The umask may have narrowed `mode`; set it exactly.
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        Ok(TempFile {
            path,
            file: Some(file),
        })
    }

    /// The temporary file's path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The open file, for writing.
    pub fn file(&mut self) -> &mut File {
        self.file.as_mut().expect("temp file already closed")
    }

    /// Flushes and closes the file, keeping it at [`TempFile::path`] until
    /// this value is dropped.
    pub fn finish(&mut self) -> io::Result<()> {
        if let Some(f) = self.file.take() {
            f.sync_all()?;
        }
        Ok(())
    }

    /// Flushes the file and renames it to `dest`.
    pub fn persist(mut self, dest: &Path) -> io::Result<()> {
        self.finish()?;
        fs::rename(&self.path, dest)?;
        sync_parent(dest);
        self.path = PathBuf::new();
        Ok(())
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if !self.path.as_os_str().is_empty() {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Atomically replaces `dest` with `contents`, mode `mode`.
pub fn write_atomic(dest: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    let mut t = TempFile::new_for(dest, mode)?;
    t.file().write_all(contents)?;
    t.persist(dest)
}

/// Best-effort fsync of `path`'s directory, so a rename is durable.
pub fn sync_parent(path: &Path) {
    if let Some(dir) = path.parent() {
        if let Ok(d) = File::open(dir) {
            let _ = d.sync_all();
        }
    }
}

/// Atomically makes `dest` a copy of `src` (hard link if possible).
fn clone_atomic(src: &Path, dest: &Path) -> io::Result<()> {
    let tmp = temp_path(dest);
    let _ = fs::remove_file(&tmp);
    if fs::hard_link(src, &tmp).is_err() {
        fs::copy(src, &tmp)?;
    }
    let r = fs::rename(&tmp, dest);
    // rename(2) is a no-op if both names are already the same file, which
    // leaves the temporary behind.
    let _ = fs::remove_file(&tmp);
    r?;
    sync_parent(dest);
    Ok(())
}

/// Installs `new` as `bin`, first keeping the current `bin` (if any) as
/// `previous`. Each step is atomic, so `bin` is always a complete binary.
pub fn swap_in(new: TempFile, bin: &Path, previous: &Path) -> io::Result<()> {
    if bin.exists() {
        clone_atomic(bin, previous)?;
    }
    new.persist(bin)
}

/// Puts `previous` back as `bin`. `previous` is kept.
pub fn roll_back(bin: &Path, previous: &Path) -> io::Result<()> {
    clone_atomic(previous, bin)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swap_keeps_previous_and_rolls_back() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("cardinal");
        let prev = dir.path().join("cardinal.previous");
        fs::write(&bin, b"old").unwrap();

        let mut t = TempFile::new_for(&bin, 0o755).unwrap();
        t.file().write_all(b"new").unwrap();
        swap_in(t, &bin, &prev).unwrap();
        assert_eq!(fs::read(&bin).unwrap(), b"new");
        assert_eq!(fs::read(&prev).unwrap(), b"old");
        assert_eq!(
            fs::metadata(&bin).unwrap().permissions().mode() & 0o777,
            0o755
        );

        roll_back(&bin, &prev).unwrap();
        assert_eq!(fs::read(&bin).unwrap(), b"old");
        assert_eq!(fs::read(&prev).unwrap(), b"old");
        // No temporaries left behind, even after the same-inode rename.
        roll_back(&bin, &prev).unwrap();
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names.len(), 2, "{names:?}");
    }

    #[test]
    fn dropped_temp_file_is_removed() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("x");
        let p = {
            let t = TempFile::new_for(&dest, 0o600).unwrap();
            t.path().to_path_buf()
        };
        assert!(!p.exists());
        write_atomic(&dest, b"hi", 0o600).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"hi");
    }
}
