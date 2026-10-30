# cardinald — the Cardinal daemon

`cardinal daemon` runs this library. It holds one device's keys, identity
log, spaces, and content store; keeps link sessions with the person's other
devices and syncs with them; mounts the files space as a folder; and
answers the `cardinal` command on a local socket. This document records the
design decisions of the first milestone (one person, several Linux
devices, one synced folder).

## Where things live

| What | Where |
|---|---|
| data (keys, logs, chunks) | `$CARDINAL_HOME`, else `$CARDINAL_DATA_DIR` (set by the systemd unit), else `$XDG_DATA_HOME/cardinal`, else `~/.local/share/cardinal` |
| settings | `config.toml`, table `[daemon]`, in `$CARDINAL_HOME`, else `$CARDINAL_CONFIG_DIR`, else `$XDG_CONFIG_HOME/cardinal`, else `~/.config/cardinal`. `[update]` belongs to `cardinal-update`; saving keeps the other tables and their comments |
| control socket | `$CARDINAL_SOCKET`, else `$XDG_RUNTIME_DIR/cardinal.sock` (or `cardinal-<dir>-<hash>.sock` when `CARDINAL_HOME` is set, so two devices can run on one machine), else `<data>/control.sock`; mode 0600 |
| mount | `~/Cardinal` by default (`[daemon] mount`; `""` for none, which `cardinal unmount` saves). Without a usable `/dev/fuse` (containers) the daemon says so once and syncs without a mount |

In the data directory:

- `device.key` — the Ed25519 signing seed and the hybrid link key, JSON
  hex, **mode 0600**. Keeping them in the desktop keyring (Secret Service)
  or a TPM is future work.
- `identity.log` — the identity entries, an append-only file of
  length-prefixed records (`applog.rs`; a torn tail is cut on open).
- `spaces/<space id>/entries.log` — each space's sealed entries, likewise.
  On start, every space is rebuilt from its log: the genesis is opened,
  everything else added without an author (cheap), then evaluated once.
- `blobs/` — `FsStore` (chunks and indexes), `Fsync::Deferred`.
- `staging/` — files being written through the mount, before they are
  encoded as blobs. Large files are never held in memory: writes go to
  the staging file, reads come from it or stream from the blob store.
- `link.json` — the link's initiation counter (restored with a margin of
  1024) and confirmed counters per peer, saved every 30 s and on every new
  session (`Endpoint::{last_counter, set_confirmed_counter, ...}`).
- `peers.json` — addresses where each own device was reached.
- `copies.json` — what copy checks saw of each device meant to keep
  everything (see "Copies").

The recovery phrase is never stored: `cardinal init` shows it once and asks
for two of the words back (unless `--yes`). The identity encryption key is
not stored either: it is opened from the wrap in the identity log with the
device's link key on every start.

## Processes and threads

One tokio runtime. The core state (`core.rs`: identity log and spaces) is
behind one mutex; network handlers lock it briefly. The FUSE session runs
on its own thread (fuser 0.15, pure-Rust mount through `fusermount3`, no
libfuse headers); reads that need the blob store run on the blocking pool
so a slow fetch never stalls other file operations. A committer thread
turns local changes into entries. Lock order is core, then the mount's
tree; code holding the tree never takes the core (connection kinds are
cached in the session table for this reason).

## Identity and devices

- `cardinal init` (first device) creates the identity with this device as
  its first **admin** key, the account space (this device's node, a
  discovery secret node, the files space node, and a placement with this
  device's retention and mount path) and the files space.
- Adding a device follows `contact.md#pairing`: the **new** device runs
  `cardinal pair` and *shows* the code (it has no identity, and only a
  device without one makes a proof of possession); an admin device runs
  `cardinal pair <code>` and *types* it. The admin finds the new device by
  `_cardinal-pair._udp` multicast DNS, or `--at ip:port` printed next to
  the code. It then appends `add_key` (device power, or admin with
  `--admin` on both sides) with a wrap of the encryption key, names the
  device in the account space, and opens a link session with
  `derive("invite", K)`. Over it the new device fetches the identity log
  (it accepts only that log, only from that peer), joins, closes the
  session and reconnects as a member; then everything syncs. The new
  device writes its own device node and placement once it has the
  account space.
- A device keeps its placement's retention equal to its own setting:
  `cardinal retention` updates it (and a changed `config.toml` at the
  next start), so the others know what each device means to keep.
  Devices running 0.1.3 or earlier recorded only the retention they had
  when they were set up or paired.
- `cardinal remove-device` appends `remove_key` and a fresh encryption
  key, deletes the device node and its placements, and makes every space rotate its epoch at
  its next write. Sessions with the removed device close at once
  (`Endpoint::recheck_peers`).
- **The recovery words in place of an admin** (`recovery.rs`,
  `identity.md#recovery-phrase`). Adding a device and removing one are
  signed by this device when its power allows (an admin adds devices and
  admins and removes devices). Otherwise, and always to remove an admin,
  the request carries the 24 words: the daemon derives the root key,
  checks it is the identity's root, signs the entries with it, and drops
  it. Nothing derived from the words is stored.
- The link directory (`directory.rs`) is a snapshot of the devices in
  effect in the log; a session's peer is "own" if its static key is the
  link key of a device in effect.

## Sync

Over `sync.md`, with one stream per request:

- **On session open** both sides reconcile every set they hold: the
  identity log first, then each space. A responder that does not hold a
  label answers as if empty and fetches everything — this is how a device
  learns of spaces it did not know (only from its own devices).
- **On write** the new sealed entries go to every online device as
  `objects` if they total at most 900 bytes, else as `heads`; the receiver
  `want`s what it lacks, and reconciles if parents are missing.
- **Every 3 minutes** per session, a full reconciliation.
- Ingesting more than 16 entries at once, or entries for a space whose
  genesis just arrived, rebuilds the space from scratch (one evaluation
  instead of one per concurrent entry).
- Blobs: chunks and indexes are fetched by id on the `blob` service in
  requests of 16 ids, from **all** online devices at once (`sched.rs`, a
  pure scheduler driven by `net.rs::BlobFetch`). Per device it keeps a
  decaying estimate of throughput and latency (kept across fetches), and
  gives each request to the device expected to finish it first, with a
  window per device of about throughput × best latency, doubled (a new
  device gets one request as a probe). An object a device does not have is
  remembered for 30 s and asked of the others at once; it is unavailable
  only when every online device lacks it. Before such an object goes to a
  device at least twice as slow to answer, a device that lacked it more
  than 250 ms ago is asked again (it may be fetching the same content). A request outstanding more than
  4× its device's typical latency (at least 0.75 s) is hedged: its ids are
  asked of another device too and the first copy wins. At most 24
  requests are in flight (replies are ≤ 4 MiB, typically ~1 MiB), and a
  request unanswered for 20 s fails (three failures in a row leave the
  device out until it reconnects). **On demand** when a file is read
  through the mount (interactive priority), and **in the background** for
  every blob named by current state (all versions of files in conflict)
  under `full` retention, or for pinned paths under `on-demand`.
- The background fetch (`fetch.rs`) is a pipeline: a blocking task walks
  the files' indexes (fetching them) ahead of the transfer, the missing
  chunks of many files share one `BlobFetch`, received objects are written
  by a few blocking tasks, and the store is synced in the background, one
  sync covering everything written before it. A file counts as complete
  only after a sync that covers all its objects. Each device fetches in
  its own order: runs of about 4 MiB (a few consecutive small files, or
  part of a larger file) ranked by BLAKE3 keyed with the device's key over
  the run's first object id. Devices fetching the same new content at once
  thus take different parts from the source and most of the rest from
  each other, without coordinating. If some objects are on no
  online device, the pass ends with an error and is retried after a change,
  when a device comes online, or after 10 s. `cardinal status` shows files
  pending, bytes missing (files not examined yet count in full), the total
  wanted, and the rate over the last 5 s.

Connections: every 2 s, each own device that is not connected is tried at
its known addresses (from pairing, LAN discovery, earlier connections, and
manual peers), with exponential backoff to 60 s. `cardinal peer add
host:port` adds an address (a server over the internet); it is tried for
every unconnected device until one answers there, and then remembered as
that device's.

LAN discovery advertises `_cardinal._udp` with the rotating tag of
`hosts.md#local-discovery`, keyed by the discovery secret from the
account space. The advertised port is the **TCP** link port (the link
listens on TCP only by default; UDP is experimental and off).

## The mount

`fs/tree.rs` is the tree the kernel sees: the files space's state
(`Files` view: duplicate names as `name (2)`, conflicting versions as
`name (conflict, <device name>).ext`), overlaid with local changes not yet
committed. Each inode maps to a space node once created there.

- Writes go to a staging file; the content becomes a blob (or inline
  bytes under 1 KiB) when committed.
- **Commit** after 200 ms without changes, or after 2 s of continuous
  activity (`profiles.md#files`). A file still being written (open for
  writing and written in the last 200 ms) waits for its own quiet period.
  A burst becomes one entry per level of newly created folders (a node
  created in an entry cannot be named in the same entry), split further
  only when an entry would get large.
- `rename` over an existing file keeps the *replaced* file's node and
  writes its content, so editors' atomic saves (write temp, rename over)
  are edits of the file, with history and conflict detection, not a
  delete and a create.
- Deleting a conflict copy settles the conflict on the main version;
  renaming a conflict copy onto the file's name keeps that version;
  editing the main file settles too. Conflict copies are read-only;
  moving one elsewhere returns `EXDEV`, so `mv` copies it.
- Changes from other devices are applied when they arrive; local
  uncommitted changes win over them in the view. A local edit or delete
  is written as concurrent with any change to the same file (or beneath
  the deleted folder) that the mount had not shown when it was made — an
  entry whose parents exclude those entries — so it becomes a conflict
  copy or a delete conflict instead of silently replacing the other
  device's change. A file deleted elsewhere while it has local changes is
  kept (created again).
- A burst's files are encoded on up to 8 threads; their chunks are made
  durable together (one `syncfs` of the blob store when there are many,
  else one `fsync` each) before the entries naming them are written.
- Hard links are refused (`EPERM`; git falls back to rename). Extended
  attributes are not supported. Folder modes and times are not synced
  (the files profile has no such fields).

`git` and editors work: tested with `git init/add/commit/log/fsck`, vim
(swap files, rename saves), on one device and seen from the other.

## Copies

`copies.rs` counts copies of the files space by what it sees
(`blobs.md#counting-copies`, D45); `cardinal status` shows the count:

```
Copies: 3 — this device, saint-joseph, nuc (checked 4 minutes ago; files older than an hour)
```

- **Who should keep everything**: devices in effect whose placement of
  the files space says full retention (or history), and this device when
  its own setting is full.
- **Checks**: every 10 minutes (±20%) each online such device is asked,
  on the ordinary `blob` service at background priority, for 4 objects
  chosen at random: a blob of the current state weighted by its size,
  then down its indexes (those this device holds) in proportion to the
  bytes beneath, sometimes stopping at an index. Only blobs this device
  first saw more than an hour ago are sampled (the birth time of the top
  object in the store, or when this run first saw the reference), so a
  device still copying new files is not failed; the count is of copies
  of everything older than that. Answers are verified by hash and
  dropped. This device checks its own store the same way.
- **Failing**: a check fails when a piece comes back "not held" or does
  not hash to its id, and the device stops counting until it passes one.
  A check that gets no answer (timed out; a closed session is not a
  check) fails only when it is the second in a row. What other devices
  fetch is not watched: one rebuilding after a lost disk fails checks
  until it has the pieces again. Checks trust what comes back, however
  the device got it (D46).
- A passed check counts for 7 days, so a laptop that is asleep still
  counts, with the time it was last checked. Results are kept in
  `copies.json`: after a restart nothing is shown as unchecked that was
  checked before.
- `CARDINAL_TEST_CHECK_INTERVAL_MS` and `CARDINAL_TEST_CHECK_MIN_AGE_MS`
  shorten the interval and the age (tests).

## Freeing space

`cleanup.rs`, about every hour (the first a minute after start):

- **Old versions stay for a while.** A blob that stops being current
  (its file replaced or deleted) is kept for `keep_old` (30 days by
  default; `cardinal keep-old <days|forever>`), counted from when this
  device first saw it stop being current (`old-versions.json`). Then its
  chunks and indexes are deleted, except those a current or kept blob
  shares (identical content deduplicates). Objects no blob names are
  never deleted, and nothing stored or read in the last hour is.
- **`cardinal free-space`** deletes every old version on this device now,
  after saying how much and asking. `cardinal status` shows how much old
  versions take (`Old versions:`), and `cardinal history` marks versions
  not on this device.
- **Restoring** a version first gets all of it onto this device from the
  others, and refuses when none has it.
- **On demand**, objects of current files that are not pinned are also
  deleted, least recently used first, beyond `on_demand_budget` (2 GiB).
- **Forever** is history retention: the placement says so, for the other
  devices.
- `CARDINAL_TEST_FREE_INTERVAL_MS` and `CARDINAL_TEST_FREE_MIN_AGE_MS`
  shorten the hour and the age (tests).

## Speed test

`cardinal speedtest [DEVICE]` measures the encrypted link to one of the
person's devices (by default each online one in turn): 20 round trips,
then 10 s of the other device sending and 10 s of this one sending, from
memory, with no disk involved. It is a link service of this
implementation (`speedtest.rs`): the application service
`BLAKE3("cardinal-node speedtest 1")`, served only on sessions with the
person's own devices, one test at a time, for a length the serving
device sets (it resets a test that runs over), and at most two minutes
of tests in any ten. A device without it (0.1.3 and earlier) resets the
stream, which `cardinal speedtest` reports as an older version.
`CARDINAL_TEST_SPEEDTEST_MS` shortens each phase (tests).

The result is what Cardinal can move, which is often less than the
network can: the link encrypts every packet of about 1,150 bytes on its
own, which costs processor time (see DEVIATIONS.md, "Link implementation
notes"). `iperf3` between the same two machines shows what the network
carries; if it is much faster, the processor is the limit, not the
network.

## Control socket

One JSON object per line each way: `{"cmd": "status"}` →
`{"ok": true, ...}` or `{"ok": false, "error": "...", "needs_words":
bool}`; `needs_words` means the recovery words, as `words`, would let the
same request through. Commands: `status`, `devices`, `remove-device`,
`recovery-check` (`words`; changes nothing), `free-space` (`dry_run`),
`keep-old` (`keep`), `peer-add/remove/list`,
`mount`, `unmount`,
`history`, `restore`, `conflicts`, `pin`, `unpin`, `retention`,
`pair-show`, `pair-status`, `pair-type`, `speedtest` (one device, by
name or key), `reload` (after `init` while the daemon runs), `flush`
(commit now), `stop`. `status` includes `copies`: per device meant to
keep everything, whether it counts (`state`: passed, failed, stale,
unchecked), why not (`reason`), the times of its last check, pass, and
failure, and checks it left unanswered in a row (`missed`).

## Logs

`tracing` to stderr; under systemd (journald) without timestamps or
colours. `CARDINAL_LOG` or `RUST_LOG` sets the filter (`info` by default;
`cardinald=debug` for sync details). `cardinal log` runs
`journalctl --user -u cardinal`.

## Not done yet

- Folder ignore patterns are not applied.
- Hosts (mailbox, relay, storage), guardians, restoring from the phrase
  when every device is lost.
  Copies on hosts (host grants) are not counted.
- Epoch rotation after `rotate_after` entries (only after a device is
  removed).
