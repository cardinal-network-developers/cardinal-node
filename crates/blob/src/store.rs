//! Content-addressed object stores for chunks and indexes.
//!
//! Every object is stored under `BLAKE3(bytes)`; [`ObjectStore::put`]
//! verifies that before storing, so a store never holds an object under the
//! wrong id (`blobs.md#fetching`).

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::SystemTime;

use crate::{object_id, Id};

/// What a store holds: object count and total stored bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    /// Number of objects.
    pub objects: u64,
    /// Sum of object lengths.
    pub bytes: u64,
}

/// One stored object, as listed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectInfo {
    /// Its id.
    pub id: Id,
    /// Its length in bytes.
    pub size: u64,
    /// When it was stored or last [touched](ObjectStore::touch).
    pub used: SystemTime,
}

/// A content-addressed store of encrypted chunks and indexes.
///
/// Implementations must be safe to share between threads.
pub trait ObjectStore: Send + Sync {
    /// Whether the store holds `id`.
    fn has(&self, id: &Id) -> io::Result<bool>;

    /// The bytes stored under `id`, if held.
    fn get(&self, id: &Id) -> io::Result<Option<Vec<u8>>>;

    /// Stores `bytes` under `id`. Fails with [`io::ErrorKind::InvalidData`]
    /// unless `BLAKE3(bytes) == id`. Returns whether the object is new.
    fn put(&self, id: &Id, bytes: &[u8]) -> io::Result<bool>;

    /// Removes `id`. Returns whether it was held.
    fn delete(&self, id: &Id) -> io::Result<bool>;

    /// Every stored object.
    fn list(&self) -> io::Result<Vec<ObjectInfo>>;

    /// Object count and bytes.
    fn usage(&self) -> Usage;

    /// Records that `id` was just used, for least-recently-used eviction.
    fn touch(&self, _id: &Id) -> io::Result<()> {
        Ok(())
    }

    /// Makes every completed `put` durable, for stores that defer it.
    fn sync(&self) -> io::Result<()> {
        Ok(())
    }
}

impl<S: ObjectStore + ?Sized> ObjectStore for &S {
    fn has(&self, id: &Id) -> io::Result<bool> {
        (**self).has(id)
    }
    fn get(&self, id: &Id) -> io::Result<Option<Vec<u8>>> {
        (**self).get(id)
    }
    fn put(&self, id: &Id, bytes: &[u8]) -> io::Result<bool> {
        (**self).put(id, bytes)
    }
    fn delete(&self, id: &Id) -> io::Result<bool> {
        (**self).delete(id)
    }
    fn list(&self) -> io::Result<Vec<ObjectInfo>> {
        (**self).list()
    }
    fn usage(&self) -> Usage {
        (**self).usage()
    }
    fn touch(&self, id: &Id) -> io::Result<()> {
        (**self).touch(id)
    }
    fn sync(&self) -> io::Result<()> {
        (**self).sync()
    }
}

impl<S: ObjectStore + ?Sized> ObjectStore for std::sync::Arc<S> {
    fn has(&self, id: &Id) -> io::Result<bool> {
        (**self).has(id)
    }
    fn get(&self, id: &Id) -> io::Result<Option<Vec<u8>>> {
        (**self).get(id)
    }
    fn put(&self, id: &Id, bytes: &[u8]) -> io::Result<bool> {
        (**self).put(id, bytes)
    }
    fn delete(&self, id: &Id) -> io::Result<bool> {
        (**self).delete(id)
    }
    fn list(&self) -> io::Result<Vec<ObjectInfo>> {
        (**self).list()
    }
    fn usage(&self) -> Usage {
        (**self).usage()
    }
    fn touch(&self, id: &Id) -> io::Result<()> {
        (**self).touch(id)
    }
    fn sync(&self) -> io::Result<()> {
        (**self).sync()
    }
}

fn check_id(id: &Id, bytes: &[u8]) -> io::Result<()> {
    if object_id(bytes) != *id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "object does not hash to its id",
        ));
    }
    Ok(())
}

/// An in-memory store, for tests and caches.
#[derive(Default)]
pub struct MemStore {
    objects: RwLock<HashMap<Id, (Vec<u8>, SystemTime)>>,
}

impl MemStore {
    /// An empty store.
    pub fn new() -> MemStore {
        MemStore::default()
    }
}

impl ObjectStore for MemStore {
    fn has(&self, id: &Id) -> io::Result<bool> {
        Ok(self.objects.read().unwrap().contains_key(id))
    }

    fn get(&self, id: &Id) -> io::Result<Option<Vec<u8>>> {
        Ok(self.objects.read().unwrap().get(id).map(|(b, _)| b.clone()))
    }

    fn put(&self, id: &Id, bytes: &[u8]) -> io::Result<bool> {
        if self.has(id)? {
            return Ok(false);
        }
        check_id(id, bytes)?;
        let mut map = self.objects.write().unwrap();
        Ok(map
            .insert(*id, (bytes.to_vec(), SystemTime::now()))
            .is_none())
    }

    fn delete(&self, id: &Id) -> io::Result<bool> {
        Ok(self.objects.write().unwrap().remove(id).is_some())
    }

    fn list(&self) -> io::Result<Vec<ObjectInfo>> {
        Ok(self
            .objects
            .read()
            .unwrap()
            .iter()
            .map(|(id, (b, t))| ObjectInfo {
                id: *id,
                size: b.len() as u64,
                used: *t,
            })
            .collect())
    }

    fn usage(&self) -> Usage {
        let map = self.objects.read().unwrap();
        Usage {
            objects: map.len() as u64,
            bytes: map.values().map(|(b, _)| b.len() as u64).sum(),
        }
    }

    fn touch(&self, id: &Id) -> io::Result<()> {
        if let Some(e) = self.objects.write().unwrap().get_mut(id) {
            e.1 = SystemTime::now();
        }
        Ok(())
    }
}

/// When a [`FsStore`] calls `fsync`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fsync {
    /// Every `put` syncs the file and its directory before returning.
    Always,
    /// `put` returns once the object is visible; [`ObjectStore::sync`]
    /// syncs everything put since the last sync. Writers call it once at
    /// the end of a blob, which is much faster than syncing every chunk.
    Deferred,
    /// Never sync; leave it to the operating system. For caches and tests.
    Never,
}

/// A store in a directory: `objects/ab/cd/<64 hex digits>`, written
/// atomically (temporary file, then a hard link that fails if the object
/// already exists, so concurrent writers of one object never conflict and
/// usage counts stay exact).
pub struct FsStore {
    root: PathBuf,
    fsync: Fsync,
    objects: AtomicU64,
    bytes: AtomicU64,
    dirty: Mutex<Vec<PathBuf>>,
    tmp_counter: AtomicU64,
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn hex_id(id: &Id) -> String {
    let mut s = String::with_capacity(64);
    for b in id {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 15) as usize] as char);
    }
    s
}

fn parse_hex_id(s: &str) -> Option<Id> {
    if s.len() != 64 {
        return None;
    }
    let mut id = [0u8; 32];
    let b = s.as_bytes();
    for (i, out) in id.iter_mut().enumerate() {
        let hi = (b[2 * i] as char).to_digit(16)?;
        let lo = (b[2 * i + 1] as char).to_digit(16)?;
        *out = (hi * 16 + lo) as u8;
    }
    // Only lowercase names are ours.
    if hex_id(&id) != s {
        return None;
    }
    Some(id)
}

/// From how many objects to sync [`FsStore::sync`] syncs the whole file
/// system instead of each object.
#[cfg(target_os = "linux")]
const SYNCFS_FROM: usize = 64;

#[cfg(target_os = "linux")]
fn syncfs(path: &Path) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let f = File::open(path)?;
    // SAFETY: syncfs only reads the descriptor, which `f` keeps open.
    if unsafe { libc::syncfs(f.as_raw_fd()) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn sync_dir(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

impl FsStore {
    /// Opens (creating if needed) a store rooted at `root`. Scans the
    /// existing objects to initialize usage, and removes leftover
    /// temporary files from an interrupted `put`.
    pub fn open(root: impl Into<PathBuf>, fsync: Fsync) -> io::Result<FsStore> {
        let root = root.into();
        fs::create_dir_all(root.join("objects"))?;
        let tmp = root.join("tmp");
        if tmp.exists() {
            fs::remove_dir_all(&tmp)?;
        }
        fs::create_dir_all(&tmp)?;
        let store = FsStore {
            root,
            fsync,
            objects: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            dirty: Mutex::new(Vec::new()),
            tmp_counter: AtomicU64::new(0),
        };
        let mut objects = 0;
        let mut bytes = 0;
        store.walk(|info| {
            objects += 1;
            bytes += info.size;
        })?;
        store.objects.store(objects, Ordering::Relaxed);
        store.bytes.store(bytes, Ordering::Relaxed);
        Ok(store)
    }

    /// The store's root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The path of an object, whether or not it is held.
    pub fn path_of(&self, id: &Id) -> PathBuf {
        let h = hex_id(id);
        self.root
            .join("objects")
            .join(&h[0..2])
            .join(&h[2..4])
            .join(h)
    }

    fn walk(&self, mut f: impl FnMut(ObjectInfo)) -> io::Result<()> {
        let objects = self.root.join("objects");
        for a in fs::read_dir(&objects)? {
            let a = a?;
            if !a.file_type()?.is_dir() {
                continue;
            }
            for b in fs::read_dir(a.path())? {
                let b = b?;
                if !b.file_type()?.is_dir() {
                    continue;
                }
                for o in fs::read_dir(b.path())? {
                    let o = o?;
                    let name = o.file_name();
                    let Some(id) = name.to_str().and_then(parse_hex_id) else {
                        continue;
                    };
                    let meta = match o.metadata() {
                        Ok(m) => m,
                        Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                        Err(e) => return Err(e),
                    };
                    f(ObjectInfo {
                        id,
                        size: meta.len(),
                        used: meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                    });
                }
            }
        }
        Ok(())
    }

    fn tmp_path(&self) -> PathBuf {
        let n = self.tmp_counter.fetch_add(1, Ordering::Relaxed);
        let r: [u8; 8] = cardinal_crypto::random_bytes();
        self.root.join("tmp").join(format!(
            "{}-{n}-{}",
            std::process::id(),
            u64::from_le_bytes(r)
        ))
    }
}

impl ObjectStore for FsStore {
    fn has(&self, id: &Id) -> io::Result<bool> {
        match fs::symlink_metadata(self.path_of(id)) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn get(&self, id: &Id) -> io::Result<Option<Vec<u8>>> {
        match fs::read(self.path_of(id)) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn put(&self, id: &Id, bytes: &[u8]) -> io::Result<bool> {
        let path = self.path_of(id);
        if self.has(id)? {
            return Ok(false);
        }
        check_id(id, bytes)?;
        let dir = path.parent().expect("object path has a parent");
        fs::create_dir_all(dir)?;
        let tmp = self.tmp_path();
        let result = (|| {
            let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
            f.write_all(bytes)?;
            if self.fsync == Fsync::Always {
                f.sync_data()?;
            }
            drop(f);
            match fs::hard_link(&tmp, &path) {
                Ok(()) => Ok(true),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(false),
                Err(e) => Err(e),
            }
        })();
        let _ = fs::remove_file(&tmp);
        let added = result?;
        if added {
            self.objects.fetch_add(1, Ordering::Relaxed);
            self.bytes.fetch_add(bytes.len() as u64, Ordering::Relaxed);
            match self.fsync {
                Fsync::Always => sync_dir(dir)?,
                Fsync::Deferred => self.dirty.lock().unwrap().push(path),
                Fsync::Never => {}
            }
        }
        Ok(added)
    }

    fn delete(&self, id: &Id) -> io::Result<bool> {
        let path = self.path_of(id);
        let size = match fs::symlink_metadata(&path) {
            Ok(m) => m.len(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e),
        };
        match fs::remove_file(&path) {
            Ok(()) => {
                self.objects.fetch_sub(1, Ordering::Relaxed);
                self.bytes.fetch_sub(size, Ordering::Relaxed);
                if self.fsync == Fsync::Always {
                    sync_dir(path.parent().unwrap())?;
                }
                Ok(true)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn list(&self) -> io::Result<Vec<ObjectInfo>> {
        let mut out = Vec::new();
        self.walk(|i| out.push(i))?;
        Ok(out)
    }

    fn usage(&self) -> Usage {
        Usage {
            objects: self.objects.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
        }
    }

    fn touch(&self, id: &Id) -> io::Result<()> {
        match File::options().write(true).open(self.path_of(id)) {
            Ok(f) => f.set_modified(SystemTime::now()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn sync(&self) -> io::Result<()> {
        let paths = std::mem::take(&mut *self.dirty.lock().unwrap());
        if paths.is_empty() {
            return Ok(());
        }
        // Many objects (a burst of small files): one `syncfs` of the
        // store's file system flushes them and their directories (new
        // ones included) in one journal commit, where thousands of
        // `fsync`s cost seconds.
        #[cfg(target_os = "linux")]
        if paths.len() >= SYNCFS_FROM && syncfs(&self.root).is_ok() {
            return Ok(());
        }
        // Many fsyncs in flight at once are far faster than one at a time
        // on SSDs; files first, then their directories.
        fn sync_all(paths: &[PathBuf], dir: bool) -> io::Result<()> {
            let threads = paths.len().clamp(1, 16);
            let per = paths.len().div_ceil(threads);
            std::thread::scope(|s| {
                let handles: Vec<_> = paths
                    .chunks(per)
                    .map(|part| {
                        s.spawn(move || -> io::Result<()> {
                            for p in part {
                                match File::open(p) {
                                    Ok(f) if dir => f.sync_all()?,
                                    Ok(f) => f.sync_data()?,
                                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                                    Err(e) => return Err(e),
                                }
                            }
                            Ok(())
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .try_for_each(|h| h.join().expect("fsync thread panicked"))
            })
        }
        sync_all(&paths, false)?;
        let mut dirs: Vec<PathBuf> = paths
            .iter()
            .map(|p| p.parent().unwrap().to_path_buf())
            .collect();
        dirs.sort();
        dirs.dedup();
        sync_all(&dirs, true)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn temp_dir(name: &str) -> PathBuf {
        let r: [u8; 8] = cardinal_crypto::random_bytes();
        let p =
            std::env::temp_dir().join(format!("cardinal-blob-{name}-{}", u64::from_le_bytes(r)));
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn exercise(store: &dyn ObjectStore) {
        let a = b"alpha".to_vec();
        let ida = object_id(&a);
        assert!(!store.has(&ida).unwrap());
        assert!(store.put(&ida, &a).unwrap());
        assert!(!store.put(&ida, &a).unwrap());
        assert!(store.has(&ida).unwrap());
        assert_eq!(store.get(&ida).unwrap().unwrap(), a);
        let bad = store.put(&[0u8; 32], b"x").unwrap_err();
        assert_eq!(bad.kind(), io::ErrorKind::InvalidData);
        let b = vec![7u8; 1000];
        let idb = object_id(&b);
        store.put(&idb, &b).unwrap();
        assert_eq!(
            store.usage(),
            Usage {
                objects: 2,
                bytes: 1005
            }
        );
        let mut l: Vec<_> = store.list().unwrap().into_iter().map(|i| i.id).collect();
        l.sort();
        let mut e = vec![ida, idb];
        e.sort();
        assert_eq!(l, e);
        store.touch(&ida).unwrap();
        assert!(store.delete(&ida).unwrap());
        assert!(!store.delete(&ida).unwrap());
        assert_eq!(store.get(&ida).unwrap(), None);
        assert_eq!(
            store.usage(),
            Usage {
                objects: 1,
                bytes: 1000
            }
        );
        store.sync().unwrap();
    }

    #[test]
    fn mem_store() {
        exercise(&MemStore::new());
    }

    #[test]
    fn fs_store() {
        for policy in [Fsync::Always, Fsync::Deferred, Fsync::Never] {
            let dir = temp_dir("store");
            {
                let s = FsStore::open(&dir, policy).unwrap();
                exercise(&s);
            }
            // Reopening recounts usage from disk.
            let s = FsStore::open(&dir, policy).unwrap();
            assert_eq!(
                s.usage(),
                Usage {
                    objects: 1,
                    bytes: 1000
                }
            );
            fs::remove_dir_all(&dir).unwrap();
        }
    }

    #[test]
    fn concurrent_puts_count_once() {
        let dir = temp_dir("concurrent");
        let s = FsStore::open(&dir, Fsync::Never).unwrap();
        let data: Vec<Vec<u8>> = (0..50u32).map(|i| i.to_le_bytes().repeat(100)).collect();
        std::thread::scope(|t| {
            for _ in 0..8 {
                t.spawn(|| {
                    for d in &data {
                        s.put(&object_id(d), d).unwrap();
                    }
                });
            }
        });
        assert_eq!(
            s.usage(),
            Usage {
                objects: 50,
                bytes: 50 * 400
            }
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
