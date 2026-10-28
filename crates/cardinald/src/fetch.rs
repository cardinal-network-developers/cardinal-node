//! Getting file content onto this device: on demand when a file is read
//! (interactive priority), and in the background for every file under
//! "full" retention, or for pinned files under "on demand".

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use cardinal_blob::{BlobReader, BlobRef, Fetch, ObjectStore};
use cardinal_link::Priority;
use cardinal_space::files::{Content, FileKind, Files};
use cardinal_space::Space;

use crate::daemon::Daemon;
use crate::net::{BlobEvent, BlobFetch};

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

/// Starts the background fetcher, and the sampler of its rate.
pub fn start(d: Arc<Daemon>) {
    let d2 = d.clone();
    tokio::spawn(async move { sample_rate(d2).await });
    tokio::spawn(async move {
        let mut changed = d.changed.subscribe();
        let mut complete: HashSet<[u8; 32]> = HashSet::new();
        loop {
            let failed = match pass(&d, &mut complete).await {
                Ok(()) => false,
                Err(e) => {
                    tracing::debug!("background fetch: {e:#}");
                    lock(&d.progress).last_error = Some(format!("{e:#}"));
                    true
                }
            };
            if *d.stopping.borrow() {
                break;
            }
            // Wait for a change; after a failure, also for a device to
            // come online, and retry in a while regardless (the devices
            // that lacked something keep fetching too).
            let online = online_keys(&d);
            let wait = async {
                for _ in 0..20 {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    if failed && online_keys(&d) != online {
                        return;
                    }
                }
            };
            tokio::select! {
                _ = changed.changed() => {}
                _ = wait => {}
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            if *d.stopping.borrow() {
                break;
            }
        }
    });
}

fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn online_keys(d: &Daemon) -> Vec<[u8; 32]> {
    let mut v: Vec<[u8; 32]> = d.own_sessions().iter().map(|s| s.peer_static()).collect();
    v.sort();
    v
}

/// Keeps `progress.rate`: bytes per second fetched over the last 5 s.
async fn sample_rate(d: Arc<Daemon>) {
    const SAMPLES: usize = 5;
    let mut last: std::collections::VecDeque<u64> = std::collections::VecDeque::new();
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    while !*d.stopping.borrow() {
        tick.tick().await;
        let mut pr = lock(&d.progress);
        last.push_back(pr.bytes_fetched);
        if last.len() > SAMPLES + 1 {
            last.pop_front();
        }
        let span = (last.len() - 1) as u64;
        let fetched = last.back().copied().unwrap_or(0) - last.front().copied().unwrap_or(0);
        pr.rate = fetched.checked_div(span).unwrap_or(0);
    }
}

/// What the lister found about one file.
enum Listed {
    /// Its objects not in the store yet: chunk ids with their plaintext
    /// lengths (0 for indexes).
    Missing(usize, Vec<([u8; 32], u64)>),
    /// Its indexes could not be fetched.
    Failed(usize),
}

/// A file being fetched.
struct FileState {
    /// Objects still missing.
    remaining: usize,
    failed: bool,
}

/// Files listed ahead of the fetch, at most (bounds memory).
const LIST_AHEAD: usize = 64;
/// Ids waiting in the scheduler before listing pauses.
const QUEUE_AHEAD: usize = 4096;
/// Batches of objects being written to the store at once.
const PUTS: usize = 6;

/// One pass over the wanted files: lists their missing objects (a
/// blocking task walking the indexes, ahead of the transfer), fetches
/// them from every online device at once through one [`BlobFetch`], so
/// requests for several files are in flight together, writes them to the
/// store, and syncs the store in the background. A file counts as
/// complete only after a sync that covers all of its objects.
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
    let mut seen = HashSet::new();
    let all: Vec<(String, BlobRef)> = blobs
        .into_iter()
        .filter(|(p, _)| {
            !on_demand
                || pins
                    .iter()
                    .any(|pin| p == pin || p.starts_with(&format!("{pin}/")))
        })
        .filter(|(_, b)| seen.insert(b.id))
        .collect();
    let bytes_wanted: u64 = all.iter().map(|(_, b)| b.size).sum();
    let wanted: Vec<(String, BlobRef)> = all
        .into_iter()
        .filter(|(_, b)| !complete.contains(&b.id))
        .collect();
    {
        let mut pr = lock(&d.progress);
        pr.bytes_wanted = bytes_wanted;
        pr.files_pending = wanted.len() as u64;
        // Until a file is listed, all of it counts as missing.
        pr.bytes_pending = wanted.iter().map(|(_, b)| b.size).sum();
    }
    if wanted.is_empty() {
        lock(&d.progress).last_error = None;
        return Ok(());
    }

    // The lister.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Listed>(LIST_AHEAD);
    let refs: Vec<BlobRef> = wanted.iter().map(|(_, b)| *b).collect();
    let d2 = d.clone();
    let lister = tokio::task::spawn_blocking(move || {
        let fetcher = Fetcher::new(&d2, Priority::Background);
        for (i, b) in refs.into_iter().enumerate() {
            if *d2.stopping.borrow() {
                break;
            }
            let mut r = BlobReader::new(d2.store.clone(), &fetcher, b);
            let mut entries = Vec::new();
            let listed = r
                .for_each_entry(|e, chunk| entries.push((e.id, if chunk { e.len } else { 0 })))
                .map_err(anyhow::Error::from)
                .and_then(|()| {
                    let mut missing = Vec::new();
                    for (id, len) in entries {
                        if !d2.store.has(&id)? {
                            missing.push((id, len));
                        }
                    }
                    Ok(missing)
                });
            let msg = match listed {
                Ok(m) => Listed::Missing(i, m),
                Err(e) => {
                    tracing::debug!("{}: cannot list its chunks yet: {e:#}", hex8(&b.id));
                    Listed::Failed(i)
                }
            };
            if tx.blocking_send(msg).is_err() {
                break;
            }
        }
    });

    let mut files: Vec<FileState> = (0..wanted.len())
        .map(|_| FileState {
            remaining: 0,
            failed: false,
        })
        .collect();
    // Which files wait for an object, and its plaintext length.
    let mut waiting: HashMap<[u8; 32], (Vec<usize>, u64)> = HashMap::new();
    let mut fetch = BlobFetch::new(d.clone(), Priority::Background);
    let mut puts: tokio::task::JoinSet<std::io::Result<Vec<[u8; 32]>>> =
        tokio::task::JoinSet::new();
    let mut to_sync: Vec<usize> = Vec::new();
    let mut syncing: Option<tokio::task::JoinHandle<(Vec<usize>, std::io::Result<()>)>> = None;
    let mut listing = true;
    let mut failures = 0usize;
    let mut stop = d.stopping.subscribe();

    // An object is now in the store (or will never come this pass).
    fn arrived(
        id: &[u8; 32],
        ok: bool,
        files: &mut [FileState],
        waiting: &mut HashMap<[u8; 32], (Vec<usize>, u64)>,
        to_sync: &mut Vec<usize>,
        failures: &mut usize,
        pending_bytes: &mut u64,
    ) {
        let Some((fs, len)) = waiting.remove(id) else {
            return;
        };
        if ok {
            // counted as missing once per file that lists it
            *pending_bytes += len * fs.len() as u64;
        }
        for f in fs {
            let st = &mut files[f];
            if !ok && !st.failed {
                st.failed = true;
                *failures += 1;
            }
            st.remaining -= 1;
            if st.remaining == 0 && !st.failed {
                to_sync.push(f);
            }
        }
    }

    loop {
        // Sync what is ready, one sync at a time (a sync covers every put
        // before it, so syncs batch up while one runs).
        if syncing.is_none() && !to_sync.is_empty() {
            let batch = std::mem::take(&mut to_sync);
            let store = d.store.clone();
            syncing = Some(tokio::task::spawn_blocking(move || {
                let r = store.sync();
                (batch, r)
            }));
        }
        if !listing && fetch.is_idle() && puts.is_empty() && syncing.is_none() && to_sync.is_empty()
        {
            break;
        }
        let can_list = listing && fetch.wanted() < QUEUE_AHEAD;
        let can_fetch = !fetch.is_idle() && puts.len() < PUTS;
        tokio::select! {
            m = rx.recv(), if can_list => match m {
                None => listing = false,
                Some(Listed::Failed(i)) => {
                    files[i].failed = true;
                    failures += 1;
                }
                Some(Listed::Missing(i, missing)) => {
                    let size = wanted[i].1.size;
                    let missing_bytes: u64 = missing.iter().map(|(_, l)| *l).sum();
                    {
                        let mut pr = lock(&d.progress);
                        pr.bytes_pending = pr
                            .bytes_pending
                            .saturating_sub(size.saturating_sub(missing_bytes));
                    }
                    let mut n = 0;
                    for (id, len) in missing {
                        match waiting.get_mut(&id) {
                            Some((fs, _)) => {
                                if !fs.contains(&i) {
                                    fs.push(i);
                                    n += 1;
                                }
                            }
                            None => {
                                waiting.insert(id, (vec![i], len));
                                fetch.push(id);
                                n += 1;
                            }
                        }
                    }
                    files[i].remaining = n;
                    if n == 0 {
                        to_sync.push(i);
                    }
                }
            },
            ev = fetch.next(), if can_fetch => match ev {
                Some(BlobEvent::Got(items)) => {
                    let bytes: usize = items.iter().map(|(_, b)| b.len()).sum();
                    lock(&d.progress).bytes_fetched += bytes as u64;
                    let store = d.store.clone();
                    puts.spawn_blocking(move || {
                        let mut ids = Vec::with_capacity(items.len());
                        for (id, data) in &items {
                            store.put(id, data)?;
                            ids.push(*id);
                        }
                        Ok(ids)
                    });
                }
                Some(BlobEvent::Unavailable(ids)) => {
                    let mut done = 0;
                    for id in &ids {
                        arrived(id, false, &mut files, &mut waiting, &mut to_sync, &mut failures, &mut done);
                    }
                }
                None => {}
            },
            r = puts.join_next(), if !puts.is_empty() => {
                let ids = match r {
                    Some(Ok(r)) => r?,
                    Some(Err(e)) => return Err(e.into()),
                    None => continue,
                };
                let mut done = 0;
                for id in &ids {
                    arrived(id, true, &mut files, &mut waiting, &mut to_sync, &mut failures, &mut done);
                }
                let mut pr = lock(&d.progress);
                pr.bytes_pending = pr.bytes_pending.saturating_sub(done);
            },
            r = async { syncing.as_mut().expect("syncing").await }, if syncing.is_some() => {
                syncing = None;
                let (batch, res) = r?;
                res?;
                for f in &batch {
                    complete.insert(wanted[*f].1.id);
                }
                let mut pr = lock(&d.progress);
                pr.files_pending = pr.files_pending.saturating_sub(batch.len() as u64);
            },
            _ = stop.changed() => break,
        }
    }
    drop(rx);
    let _ = lister.await;
    if failures > 0 {
        anyhow::bail!(
            "{failures} files could not be fetched yet: no online device has all of them"
        );
    }
    lock(&d.progress).last_error = None;
    Ok(())
}

fn hex8(id: &[u8; 32]) -> String {
    id[..4].iter().map(|b| format!("{b:02x}")).collect()
}
