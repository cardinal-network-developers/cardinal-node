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
| mount | `~/Cardinal` by default (`[daemon] mount`; `""` for none) |

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
  session and reconnects as a member; then everything syncs.
- `cardinal remove-device` appends `remove_key` and a fresh encryption
  key, deletes the device node, and makes every space rotate its epoch at
  its next write. Sessions with the removed device close at once
  (`Endpoint::recheck_peers`).
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
  requests of 16 ids, 4 in flight per device; a request unanswered for
  20 s is retried (up to 3 rounds over the online devices). **On demand** when a file is read through the mount
  (interactive priority), and **in the background** for every blob named
  by current state (all versions of files in conflict) under `full`
  retention, or for pinned paths under `on-demand`.

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

## Control socket

One JSON object per line each way: `{"cmd": "status"}` →
`{"ok": true, ...}` or `{"ok": false, "error": "..."}`. Commands: `status`,
`devices`, `remove-device`, `peer-add/remove/list`, `mount`, `unmount`,
`history`, `restore`, `conflicts`, `pin`, `unpin`, `retention`,
`pair-show`, `pair-status`, `pair-type`, `reload` (after `init` while the
daemon runs), `flush` (commit now), `stop`.

## Logs

`tracing` to stderr; under systemd (journald) without timestamps or
colours. `CARDINAL_LOG` or `RUST_LOG` sets the filter (`info` by default;
`cardinald=debug` for sync details). `cardinal log` runs
`journalctl --user -u cardinal`.

## Not done yet

- Retention never deletes chunks: `full` keeps old versions' chunks too
  (as "history" would), and on-demand eviction by budget is not run.
- Folder ignore patterns are not applied.
- Hosts (mailbox, relay, storage), guardians, recovery from the phrase.
- Epoch rotation after `rotate_after` entries (only after a device is
  removed).
