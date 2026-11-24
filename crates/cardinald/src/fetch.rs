//! Getting file content onto this device: on demand when a file is read
//! (interactive priority), and in the background for every file under
//! "full" retention, or for pinned files under "on demand".

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use cardinal_blob::{BlobReader, BlobRef, Fetch, ObjectStore};
use cardinal_link::Priority;
use cardinal_space::files::{Content, FileKind, Files};
use cardinal_space::{relationship, Space};

use crate::daemon::Daemon;
use crate::net::{BlobEvent, BlobFetch};
use crate::sched::Rank;

/// Fetches objects from this person's online devices, blocking. Used by
/// [`BlobReader`] from threads outside the runtime.
pub struct Fetcher {
    d: std::sync::Weak<Daemon>,
    priority: Priority,
    others: Option<Others>,
}

/// Whose devices besides this person's may hold what a shared folder holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Others {
    /// A contact's, in the relationship's folder.
    Contact([u8; 32]),
    /// The members' of a group, in its folder: whichever of them this
    /// device is in touch with when it asks.
    Group(cardinal_space::SpaceId),
}

impl Fetcher {
    /// A fetcher at `priority`.
    pub fn new(d: &Arc<Daemon>, priority: Priority) -> Fetcher {
        Fetcher {
            d: Arc::downgrade(d),
            priority,
            others: None,
        }
    }

    /// One that asks a contact's devices too, for what they shared.
    pub fn from_contact(d: &Arc<Daemon>, priority: Priority, who: [u8; 32]) -> Fetcher {
        Fetcher::from_others(d, priority, Some(Others::Contact(who)))
    }

    /// One that asks the devices of `others` too, if any.
    pub fn from_others(d: &Arc<Daemon>, priority: Priority, others: Option<Others>) -> Fetcher {
        Fetcher {
            others,
            ..Fetcher::new(d, priority)
        }
    }
}

/// A member of a group this device is in touch with now, other than its
/// own person: who is asked for what the group's folder holds.
fn member_in_touch(d: &Daemon, space: &cardinal_space::SpaceId) -> Option<[u8; 32]> {
    let members = {
        let core = d.core();
        let me = core.identity.as_ref().map(|i| i.id());
        let sp = core.spaces.get(space).and_then(|h| h.space.as_ref())?;
        let all = sp.present().into_iter();
        all.filter(|w| Some(*w) != me).collect::<Vec<_>>()
    };
    let in_touch = d.people_in_touch();
    members.into_iter().find(|w| in_touch.contains(w))
}

impl Fetch for Fetcher {
    fn fetch(&self, ids: &[[u8; 32]]) -> std::io::Result<Vec<([u8; 32], Vec<u8>)>> {
        let Some(d) = self.d.upgrade() else {
            return Ok(Vec::new());
        };
        let from = match self.others {
            Some(Others::Contact(who)) => Some(who),
            Some(Others::Group(space)) => member_in_touch(&d, &space),
            None => None,
        };
        let rt = d.rt.clone();
        let got = rt.block_on(crate::net::fetch_blobs_from(&d, ids, self.priority, from));
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

/// Every blob reference that a field of a node of the current state holds,
/// whatever the node's kind and wherever it is (`blobs.md#retention`). A
/// reference is known by its shape, so a device does not need to know a
/// kind to keep what it holds, and one that keeps a space in full fetches
/// and keeps the content of kinds it does not know. A node that is
/// deleted, or beneath one that is, is not current.
pub fn state_blobs(space: &Space) -> Vec<BlobRef> {
    state_blobs_by(space, None)
}

/// [`state_blobs`], or with `by` only those in a value that `by` wrote:
/// what one person put in a space, as against what the space holds.
pub fn state_blobs_by(space: &Space, by: Option<[u8; 32]>) -> Vec<BlobRef> {
    let st = space.state();
    let author = |entry: &[u8; 32]| space.entry(entry).map(|e| e.author());
    let mut out = HashSet::new();
    for n in st.nodes().filter(|n| st.is_visible(&n.id)) {
        for v in n.fields.values().flatten() {
            if by.is_some() && author(&v.entry) != by {
                continue;
            }
            if let Some(value) = &v.value {
                crate::cleanup::refs_in(value, &mut out);
            }
        }
    }
    out.into_iter().collect()
}

/// Everything that is current in a files space: what the folder shows, and
/// whatever else current state references. None of it is an old version,
/// and all of it counts where copies are counted.
pub fn current_refs(space: &Space) -> Vec<BlobRef> {
    let shown = current_blobs(space).into_iter();
    let mut refs: Vec<BlobRef> = shown.map(|(_, b)| b).collect();
    let listed: HashSet<[u8; 32]> = refs.iter().map(|b| b.id).collect();
    let all = state_blobs(space).into_iter();
    refs.extend(all.filter(|b| !listed.contains(&b.id)));
    refs
}

/// Where what is not shown is listed while it is fetched.
const NOT_SHOWN: &str = "(not shown)";

/// What the current state of a space references that `listed` does not
/// have: content of nodes this build shows nothing of. Each under a name
/// of its own, for the fetcher's lists.
fn unlisted(space: &Space, listed: &HashSet<[u8; 32]>) -> Vec<(String, BlobRef)> {
    let all = state_blobs(space).into_iter();
    let other = all.filter(|b| !listed.contains(&b.id));
    other
        .map(|b| (format!("{NOT_SHOWN}/{}", hex::encode(&b.id[..8])), b))
        .collect()
}

/// Whether something to fetch is what no view shows.
fn is_unshown(named: &(String, BlobRef)) -> bool {
    named.0.starts_with(NOT_SHOWN)
}

/// What a device fetches of a space: of what its views list (`shown`),
/// what its retention keeps, and where it keeps the space in full also
/// whatever else current state references, which is the content of kinds
/// it does not know (`blobs.md#retention`). On demand, what nothing shows
/// is never opened here, and is not fetched.
pub fn wanted(
    space: &Space,
    shown: Vec<(String, BlobRef)>,
    on_demand: bool,
    keep: &dyn Fn(&str, &BlobRef) -> bool,
) -> Vec<(String, BlobRef)> {
    let listed: HashSet<[u8; 32]> = shown.iter().map(|(_, b)| b.id).collect();
    let kept = shown.into_iter().filter(|(p, b)| !on_demand || keep(p, b));
    let mut out: Vec<(String, BlobRef)> = kept.collect();
    if !on_demand {
        out.extend(unlisted(space, &listed));
    }
    out
}

/// Something to fetch, under the name it is listed by meanwhile.
type Named = (String, BlobRef);

/// What a device fetches of a group it has joined, and from whose
/// devices: each file of a message from whoever sent it if this person
/// knows them, and through a member they know if not, who keeps it. What
/// current state references besides comes through such a member too.
pub fn wanted_of_group(
    space: &Space,
    base: &str,
    me: Option<[u8; 32]>,
    known: &dyn Fn(&[u8; 32]) -> bool,
    on_demand: bool,
    pinned: &dyn Fn(&str) -> bool,
) -> Vec<(Option<[u8; 32]>, Named)> {
    let through = space.present().into_iter().find(|w| known(w));
    let mut listed: HashSet<[u8; 32]> = HashSet::new();
    let mut out = Vec::new();
    for m in relationship::messages(space) {
        let from = if known(&m.author) {
            Some(m.author)
        } else {
            through
        };
        for a in m.attachments {
            let Ok(b) = BlobRef::from_record(&a.blob) else {
                continue;
            };
            let full = format!("{base}/{}", a.name);
            listed.insert(b.id);
            let keep = !on_demand || pinned(&full) || (is_image(&full) && b.size <= IMAGE_KEEP);
            if keep && Some(m.author) != me {
                out.push((from, (full, b)));
            }
        }
    }
    if !on_demand {
        out.extend(unlisted(space, &listed).into_iter().map(|x| (through, x)));
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
    /// lengths (0 for indexes) and ranks.
    Missing(usize, Vec<([u8; 32], u64, Rank)>),
    /// Its indexes could not be fetched.
    Failed(usize),
}

/// A file being fetched.
struct FileState {
    /// Objects still missing.
    remaining: usize,
    failed: bool,
}

/// The background fetch goes in runs of about this much content (64
/// chunks of average size, four requests): a few consecutive small files,
/// or consecutive chunks of a larger file.
const RUN_BYTES: u64 = 4 << 20;

/// Splits `items`, in their natural order, into runs of about
/// [`RUN_BYTES`] (an item that large is a run alone), each with this
/// device's rank for it: the hash of the run's first id keyed by this
/// device's key. See [`pass`].
fn ranked_runs<T>(
    key: &[u8; 32],
    items: Vec<T>,
    id: impl Fn(&T) -> [u8; 32],
    size: impl Fn(&T) -> u64,
) -> Vec<(Rank, Vec<T>)> {
    let mut runs: Vec<Vec<T>> = Vec::new();
    let mut run: Vec<T> = Vec::new();
    let mut bytes = 0u64;
    for item in items {
        let n = size(&item);
        if n >= RUN_BYTES && !run.is_empty() {
            runs.push(std::mem::take(&mut run));
            bytes = 0;
        }
        bytes += n;
        run.push(item);
        if bytes >= RUN_BYTES {
            runs.push(std::mem::take(&mut run));
            bytes = 0;
        }
    }
    if !run.is_empty() {
        runs.push(run);
    }
    runs.into_iter()
        .map(|r| (*blake3::keyed_hash(key, &id(&r[0])).as_bytes(), r))
        .collect()
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
///
/// The order is this device's own: the content is split into runs of
/// about [`RUN_BYTES`] (a few consecutive small files, or part of a larger
/// file) ranked by a hash keyed by this device's key. Files are listed in
/// the order of their groups' ranks, and the scheduler asks for the
/// lowest-ranked run it holds first. Devices that fetch the same new
/// content at the same time thus take different parts of it from the
/// source, and then much of the rest from each other (the scheduler asks
/// a quick device again before a slow one), instead of all asking the
/// source for the same objects at once. A run keeps objects together, so
/// a device that has one object of a run likely has the rest, and files
/// complete as they go. The order is stable across passes and restarts,
/// and costs nothing on disk: objects are stored by hash, so even a file
/// fetched front to back is scattered there. Reads through the mount
/// fetch in file order, at interactive priority.
async fn pass(d: &Arc<Daemon>, complete: &mut HashSet<[u8; 32]>) -> anyhow::Result<()> {
    let (on_demand, pins) = {
        let c = d.config();
        (c.on_demand(), c.pins.clone())
    };
    let pinned = |p: &str| {
        pins.iter()
            .any(|pin| p == pin || p.starts_with(&format!("{pin}/")))
    };
    // What to fetch, by whose devices may hold it besides this person's:
    // their own files, then each relationship's shared folder and the files
    // of its messages (`profiles.md#shared-folder`). Under on-demand
    // retention, images small enough to show are kept as they come.
    let mut sources: Vec<Source> = Vec::new();
    // the place among them of what the person's own folder does not show
    let mut quiet = usize::MAX;
    {
        let core = d.core();
        if let Some(space) = core
            .files_id()
            .and_then(|f| core.spaces.get(&f))
            .and_then(|h| h.space.as_ref())
        {
            let shown = current_blobs(space);
            let mine = wanted(space, shown, on_demand, &|p, _| pinned(p));
            // What no folder shows goes by itself: a reference there may
            // be to nothing anyone holds, and that is no news for the
            // person about their files.
            let (unshown, mine): (Vec<_>, Vec<_>) = mine.into_iter().partition(is_unshown);
            sources.push((None, mine));
            quiet = sources.len();
            sources.push((None, unshown));
        }
    }
    let shown = crate::onefolder::relationships(d);
    // where each group's folder is, which a pin names
    let group_paths: HashMap<cardinal_space::SpaceId, String> = shown
        .iter()
        .filter(|s| s.group().is_some())
        .map(|s| (s.space, s.path()))
        .collect();
    for s in shown {
        let Some(contact) = s.contact().map(|c| c.identity) else {
            continue;
        };
        let core = d.core();
        let Some(space) = core.spaces.get(&s.space).and_then(|h| h.space.as_ref()) else {
            continue;
        };
        let base = s.path();
        let keep = |p: &str, b: &BlobRef| pinned(p) || (is_image(p) && b.size <= IMAGE_KEEP);
        let mut shown = Vec::new();
        for (p, b) in current_blobs(space) {
            shown.push((format!("{base}/{p}"), b));
        }
        for m in relationship::messages(space) {
            for a in m.attachments {
                let Ok(b) = BlobRef::from_record(&a.blob) else {
                    continue;
                };
                shown.push((format!("{base}/{}", a.name), b));
            }
        }
        let theirs = wanted(space, shown, on_demand, &keep);
        sources.push((Some(contact), theirs));
    }
    // A group's messages: each file from whoever sent it if this person
    // knows them, and through a member they know if not, who keeps it.
    {
        let core = d.core();
        let me = core.identity.as_ref().map(|i| i.id());
        let contacts = core.contacts();
        let known = |w: &[u8; 32]| contacts.iter().any(|c| c.identity == *w && c.connects());
        let mut by: HashMap<Option<[u8; 32]>, Vec<(String, BlobRef)>> = HashMap::new();
        for (id, h) in &core.spaces {
            let Some(space) = h.space.as_ref() else {
                continue;
            };
            let joined = me.is_some_and(|me| cardinal_space::group::joined(space, &me));
            if space.profile() != cardinal_space::group::GROUP || !joined {
                continue;
            }
            let base = group_paths.get(id).cloned().unwrap_or_else(|| {
                let name = cardinal_space::group::name(space);
                format!("{}/{name}", crate::onefolder::GROUPS)
            });
            for (from, x) in wanted_of_group(space, &base, me, &known, on_demand, &pinned) {
                by.entry(from).or_default().push(x);
            }
        }
        sources.extend(by);
    }
    let mut seen = HashSet::new();
    for (_, blobs) in &mut sources {
        blobs.retain(|(_, b)| seen.insert(b.id));
    }
    {
        let mut pr = lock(&d.progress);
        pr.bytes_wanted = bytes_of(sources.iter().flat_map(|(_, b)| b));
        let pending = || {
            sources
                .iter()
                .flat_map(|(_, b)| b)
                .filter(|(_, b)| !complete.contains(&b.id))
        };
        pr.files_pending = pending().count() as u64;
        // Until a file is listed, all of it counts as missing.
        pr.bytes_pending = bytes_of(pending());
    }
    let mut first_error = None;
    for (at, (from, wanted)) in sources.into_iter().enumerate() {
        let got = fetch_set(d, complete, wanted, from).await;
        match (got, from) {
            (Err(e), None) if at == quiet => tracing::debug!("what is not shown: {e:#}"),
            (Err(e), None) => first_error = Some(e),
            // A contact's devices are often off; that is no failure here.
            (Err(e), Some(who)) => tracing::debug!("{}'s files: {e:#}", hex8(&who)),
            (Ok(()), _) => {}
        }
    }
    match first_error {
        Some(e) => Err(e),
        None => {
            lock(&d.progress).last_error = None;
            Ok(())
        }
    }
}

/// What some blobs come to, by the sizes their references claim.
fn bytes_of<'a>(blobs: impl Iterator<Item = &'a (String, BlobRef)>) -> u64 {
    blobs.fold(0u64, |all, (_, b)| all.saturating_add(b.size))
}

/// Whose devices may hold some files besides this person's, and the files.
type Source = (Option<[u8; 32]>, Vec<(String, BlobRef)>);

/// Images up to this size are kept as they come under on-demand retention,
/// so that a conversation can show them.
const IMAGE_KEEP: u64 = 16 << 20;

fn is_image(path: &str) -> bool {
    crate::contacts::media_type(path).starts_with("image/")
}

/// Fetches what `wanted` names that is not complete here, from this person's
/// online devices and, with `from`, a contact's.
async fn fetch_set(
    d: &Arc<Daemon>,
    complete: &mut HashSet<[u8; 32]>,
    wanted: Vec<(String, BlobRef)>,
    from: Option<[u8; 32]>,
) -> anyhow::Result<()> {
    // Groups of small files, and larger files, listed in rank order; each
    // file with its group's rank.
    let key = d.keys.key();
    let mut groups = ranked_runs(
        &key,
        wanted
            .into_iter()
            .filter(|(_, b)| !complete.contains(&b.id))
            .collect(),
        |(_, b)| b.id,
        |(_, b)| b.size,
    );
    groups.sort_by_key(|g| g.0);
    let (ranks, wanted): (Vec<Rank>, Vec<(String, BlobRef)>) = groups
        .into_iter()
        .flat_map(|(rank, files)| files.into_iter().map(move |f| (rank, f)))
        .unzip();
    if wanted.is_empty() {
        return Ok(());
    }

    // The lister.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Listed>(LIST_AHEAD);
    let refs: Vec<(BlobRef, Rank)> = wanted.iter().map(|(_, b)| *b).zip(ranks).collect();
    let d2 = d.clone();
    let lister = tokio::task::spawn_blocking(move || {
        let fetcher = match from {
            Some(who) => Fetcher::from_contact(&d2, Priority::Background, who),
            None => Fetcher::new(&d2, Priority::Background),
        };
        for (i, (b, rank)) in refs.into_iter().enumerate() {
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
                    // A smaller file goes with its group; a larger one
                    // in runs, each with its own rank.
                    Ok(if b.size < RUN_BYTES {
                        missing.into_iter().map(|(id, l)| (id, l, rank)).collect()
                    } else {
                        ranked_runs(&key, missing, |(id, _)| *id, |(_, l)| *l)
                            .into_iter()
                            .flat_map(|(r, run)| run.into_iter().map(move |(id, l)| (id, l, r)))
                            .collect()
                    })
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
    if let Some(who) = from {
        fetch = fetch.from_contact(who);
    }
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
                    let missing_bytes: u64 = missing.iter().map(|(_, l, _)| *l).sum();
                    {
                        let mut pr = lock(&d.progress);
                        pr.bytes_pending = pr
                            .bytes_pending
                            .saturating_sub(size.saturating_sub(missing_bytes));
                    }
                    let mut n = 0;
                    for (id, len, rank) in missing {
                        match waiting.get_mut(&id) {
                            Some((fs, _)) => {
                                if !fs.contains(&i) {
                                    fs.push(i);
                                    n += 1;
                                }
                            }
                            None => {
                                waiting.insert(id, (vec![i], len));
                                fetch.push_ranked(id, rank);
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
    Ok(())
}

fn hex8(id: &[u8; 32]) -> String {
    id[..4].iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u32) -> [u8; 32] {
        let mut i = [0u8; 32];
        i[..4].copy_from_slice(&n.to_le_bytes());
        i
    }

    fn num(i: &[u8; 32]) -> u32 {
        u32::from_le_bytes(i[..4].try_into().unwrap())
    }

    /// P14. A reference says how large its blob is, and anyone who writes
    /// in a space writes what they like there: sizes are added without
    /// trusting that they add up.
    #[test]
    fn sizes_a_reference_claims_are_added_without_overflow() {
        let claimed = |size: u64| {
            let blob = BlobRef {
                id: [1; 32],
                key: [2; 32],
                size,
                levels: 1,
            };
            ("x".to_owned(), blob)
        };
        let all = [
            claimed(u64::MAX / 2 + 7),
            claimed(u64::MAX / 2 + 7),
            claimed(5),
        ];
        assert_eq!(bytes_of(all.iter()), u64::MAX);
        assert_eq!(bytes_of(all[2..].iter()), 5);
    }

    #[test]
    fn runs_keep_objects_together_in_each_devices_order() {
        // Ten runs of 64 chunks of 64 KiB.
        let chunks: Vec<([u8; 32], u64)> = (0..640).map(|n| (id(n), 64 << 10)).collect();
        let order = |key: [u8; 32]| {
            let mut runs = ranked_runs(&key, chunks.clone(), |c| c.0, |c| c.1);
            assert_eq!(runs.len(), 10);
            for (k, (_, run)) in runs.iter().enumerate() {
                assert_eq!(run[..], chunks[k * 64..(k + 1) * 64]);
            }
            runs.sort_by_key(|r| r.0);
            runs.iter()
                .map(|(_, r)| num(&r[0].0) / 64)
                .collect::<Vec<_>>()
        };
        let a = order([1; 32]);
        assert_eq!(a, order([1; 32]), "the same device, the same order");
        assert_ne!(a, order([2; 32]), "another device, another order");
        assert_ne!(a, (0..10).collect::<Vec<_>>());
    }

    #[test]
    fn small_files_share_a_run_and_large_ones_stand_alone() {
        const MIB: u64 = 1 << 20;
        let sizes = [1, 1, 10, 1, 3, 1];
        let files: Vec<([u8; 32], u64)> = (0..sizes.len())
            .map(|i| (id(i as u32), sizes[i] * MIB))
            .collect();
        let runs: Vec<Vec<u32>> = ranked_runs(&[0; 32], files, |f| f.0, |f| f.1)
            .into_iter()
            .map(|(_, r)| r.iter().map(|f| num(&f.0)).collect())
            .collect();
        assert_eq!(runs, vec![vec![0, 1], vec![2], vec![3, 4], vec![5]]);
    }
}
