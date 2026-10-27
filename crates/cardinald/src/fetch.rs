//! Getting file content onto this device: on demand when a file is read
//! (interactive priority), and in the background for every file under
//! "full" retention, or for pinned files under "on demand".

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use cardinal_blob::{BlobReader, BlobRef, Fetch, ObjectStore};
use cardinal_link::Priority;
use cardinal_space::files::{Content, FileKind, Files};
use cardinal_space::Space;

use crate::daemon::Daemon;

/// Fetches objects from this person's online devices, blocking. Used by
/// [`BlobReader`] from threads outside the runtime.
pub struct Fetcher {
    d: std::sync::Weak<Daemon>,
    priority: Priority,
}

impl Fetcher {
    /// A fetcher at `priority`.
    pub fn new(d: &Arc<Daemon>, priority: Priority) -> Fetcher {
        Fetcher {
            d: Arc::downgrade(d),
            priority,
        }
    }
}

impl Fetch for Fetcher {
    fn fetch(&self, ids: &[[u8; 32]]) -> std::io::Result<Vec<([u8; 32], Vec<u8>)>> {
        let Some(d) = self.d.upgrade() else {
            return Ok(Vec::new());
        };
        let rt = d.rt.clone();
        let got = rt.block_on(crate::net::fetch_blobs(&d, ids, self.priority));
        let n: usize = got.iter().map(|(_, b)| b.len()).sum();
        d.progress
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .bytes_fetched += n as u64;
        Ok(got)
    }
}

/// Converts the files profile's reference to the blob crate's.
pub fn blob_ref(r: &cardinal_space::files::BlobRef) -> BlobRef {
    BlobRef {
        id: r.id,
        key: r.key,
        size: r.size,
        levels: r.levels,
    }
}

/// Every blob the current state of a files space names (all versions of
/// files in conflict too), with a path for messages.
pub fn current_blobs(space: &Space) -> Vec<(String, BlobRef)> {
    let files = Files::new(space);
    let mut out = Vec::new();
    let mut stack = vec![(cardinal_space::ROOT, String::new())];
    while let Some((dir, path)) = stack.pop() {
        for e in files.list(&dir) {
            let p = if path.is_empty() {
                e.name.clone()
            } else {
                format!("{path}/{}", e.name)
            };
            match e.kind {
                FileKind::Folder => stack.push((e.node, p)),
                FileKind::File if e.conflict_version.is_none() => {
                    for v in files.content(&e.node) {
                        if let Some(Content::Blob(b)) = v.content {
                            out.push((p.clone(), blob_ref(&b)));
                        }
                    }
                }
                _ => {}
            }
        }
    }
    out
}

/// Starts the background fetcher.
pub fn start(d: Arc<Daemon>) {
    tokio::spawn(async move {
        let mut changed = d.changed.subscribe();
        let mut complete: HashSet<[u8; 32]> = HashSet::new();
        loop {
            if let Err(e) = pass(&d, &mut complete).await {
                tracing::debug!("background fetch: {e:#}");
                d.progress
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .last_error = Some(format!("{e:#}"));
            }
            // wait for a change, or retry in a while (devices come online)
            let _ = tokio::time::timeout(Duration::from_secs(10), changed.changed()).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
            if *d.stopping.borrow() {
                break;
            }
        }
    });
}

async fn pass(d: &Arc<Daemon>, complete: &mut HashSet<[u8; 32]>) -> anyhow::Result<()> {
    let (on_demand, pins) = {
        let c = d.config();
        (c.on_demand(), c.pins.clone())
    };
    let blobs: Vec<(String, BlobRef)> = {
        let core = d.core();
        let Some(files) = core.files_id() else {
            return Ok(());
        };
        let Some(space) = core.spaces.get(&files).and_then(|h| h.space.as_ref()) else {
            return Ok(());
        };
        current_blobs(space)
    };
    let wanted: Vec<(String, BlobRef)> = blobs
        .into_iter()
        .filter(|(p, _)| {
            !on_demand
                || pins
                    .iter()
                    .any(|pin| p == pin || p.starts_with(&format!("{pin}/")))
        })
        .filter(|(_, b)| !complete.contains(&b.id))
        .collect();
    {
        let mut pr = d.progress.lock().unwrap_or_else(|e| e.into_inner());
        pr.files_pending = wanted.len() as u64;
        pr.bytes_pending = wanted.iter().map(|(_, b)| b.size).sum();
    }
    if wanted.is_empty() {
        return Ok(());
    }
    let mut failures = 0;
    for (path, b) in wanted {
        // which objects are missing: walks the indexes, fetching them
        let d2 = d.clone();
        let b2 = b;
        let missing = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<[u8; 32]>> {
            let fetcher = Fetcher::new(&d2, Priority::Background);
            let mut r = BlobReader::new(d2.store.clone(), &fetcher, b2);
            let mut ids = Vec::new();
            r.for_each_object(|id| ids.push(*id))?;
            let mut missing = Vec::new();
            for id in ids {
                if !d2.store.has(&id)? {
                    missing.push(id);
                }
            }
            Ok(missing)
        })
        .await?;
        let missing = match missing {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!("{path}: cannot list its chunks yet: {e:#}");
                failures += 1;
                continue;
            }
        };
        let mut ok = true;
        for window in missing.chunks(256) {
            let got = crate::net::fetch_blobs(d, window, Priority::Background).await;
            let n = got.len();
            let bytes: usize = got.iter().map(|(_, x)| x.len()).sum();
            let store = d.store.clone();
            tokio::task::spawn_blocking(move || -> std::io::Result<()> {
                for (id, data) in &got {
                    store.put(id, data)?;
                }
                Ok(())
            })
            .await??;
            {
                let mut pr = d.progress.lock().unwrap_or_else(|e| e.into_inner());
                pr.bytes_fetched += bytes as u64;
                pr.bytes_pending = pr.bytes_pending.saturating_sub(bytes as u64);
            }
            if n < window.len() {
                ok = false;
                break;
            }
        }
        // one sync per file: syncing every window costs more than the
        // transfer
        let store = d.store.clone();
        tokio::task::spawn_blocking(move || store.sync()).await??;
        if ok {
            complete.insert(b.id);
            let mut pr = d.progress.lock().unwrap_or_else(|e| e.into_inner());
            pr.files_pending = pr.files_pending.saturating_sub(1);
        } else {
            failures += 1;
        }
        if *d.stopping.borrow() {
            break;
        }
    }
    if failures > 0 {
        anyhow::bail!("{failures} files could not be fetched yet (is another device online?)");
    }
    d.progress
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .last_error = None;
    Ok(())
}
