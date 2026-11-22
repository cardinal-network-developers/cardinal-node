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

- `format` — which format the store is: one decimal number and a newline,
  `2` for this version (`format.rs`). It is written when a store is made
  (`init`, pairing in, restoring), before anything else. A directory that
  holds an identity, a space or an object and has no marker is format 1,
  what 0.1.13 and earlier wrote. The daemon, and `init`, refuse a store of
  another format before reading or writing anything in it, and every
  command then says so instead of only that no daemon is running.
  `cardinal clear` (`clear.rs`) removes what the node wrote here, whatever
  its format, so that `cardinal init` can start again; it leaves
  `config.toml` and, unless told otherwise, `local/` and `local-shared/`.
  A client that starts the service itself asks `cardinald --store` which
  store is here and what it holds, and clears one this version cannot
  read with `cardinald --clear` (`bin/cardinald.rs`): one line of JSON
  each.
- `device.key` — the Ed25519 signing seed and the hybrid link key, JSON
  hex, **mode 0600**. Keeping them in the desktop keyring (Secret Service)
  or a TPM is future work.
- `identity.log` — the identity entries, an append-only file of
  length-prefixed records (`applog.rs`; a torn tail is cut on open).
- `spaces/<space id>/entries.log` — each space's sealed entries, likewise.
  On start, every space is rebuilt from its log: the genesis is opened,
  everything else added without an author (cheap), then evaluated once.
- `spaces/<space id>/epochs.json` — for each epoch whose key this device
  holds, what it held when it first held that key: each member's
  encryption key (its fingerprint), and whom it knew to be frozen. The
  next write starts a new epoch when one of those has changed since
  (`spaces.md#when-to-rotate`).
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

LAN discovery advertises `_cardinal._udp` with the rotating tags of
`hosts.md#local-discovery`: `t=`, keyed by the discovery secret from the
account space, for the person's own devices, and `c=`, keyed by their
presence secret, for trusted contacts who were given it in the
relationship's reach node (D74, `presence.rs`). The advertised port is
the **TCP** link port (the link listens on TCP only by default; UDP is
experimental and off). A `c=` that matches a trusted contact's secret
has each of their devices dialled at that address; `cardinal contacts
NAME` shows the look.

Bluetooth Low Energy (`bluetooth.rs`, `carriers/ble.md`) carries the same
tags, and a one-time tag for each outstanding invitation this device
answers for, in an advertisement under the service UUID, and link packets
over L2CAP channels. It is off by default: `cardinal bluetooth
off|open|always` (`{"cmd": "bluetooth", "mode": ...}`; without `mode` it
asks the radio whether it can be used and says where it stands, as
`status` does under `bluetooth`). `open` is on while a client watches with
`{"cmd": "watch", "window": true}`. On Linux the radio is BlueZ over
D-Bus (`bluez.rs`, through zbus) and the kernel's L2CAP sockets, used
only with the controller's privacy on (`Privacy = device` under
`[General]` in `/etc/bluetooth/main.conf`, then restart bluetoothd):
without it the computer would send its fixed address. On
Android the app drives it, over the socket `CARDINAL_BLE_BRIDGE` names
(`contact/src/ble/bridge.rs`); tests set `CARDINAL_TEST_BLE_ETHER` to a
directory where simulated radios meet.

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
  A burst becomes one entry: what is put in a folder the same burst
  makes names it by the place of its `create` in the entry
  (`state.md#a-node-made-in-the-same-entry`). It is split only when an
  entry would get large.
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
Copies: 3 — this device, saint-joseph, nuc (files older than an hour, spot-checked 4 minutes ago)
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

## Paths kept on this device

`fs/local.rs` (`profiles.md#paths-kept-on-one-device`, D47):

- **What is local.** A `.cardinalignore` file (gitignore syntax; the
  nearest file with a matching line decides) names paths in its folder
  and below. A new item is local when its folder is local or a line names
  it. What is already synced stays synced where it is.
- **Where it lives.** Local items are real files, folders and links under
  `local/` in the data directory, beneath their nearest synced folder's
  node id in hex (`new-<inode>` until that folder is committed), so
  renaming synced folders moves nothing. They are loaded at mount.
- **Moving across the line.** Local to synced stages the content for the
  next commit (onto a synced file it is an edit of it). A synced file
  going local is deleted from the space and kept here. A synced folder
  going local is `EXDEV`, so `mv` copies it.
- **Changing lines.** When a `.cardinalignore` changes, here or
  elsewhere, local items the old lines named and the new ones do not
  become synced.
- **Deleted elsewhere.** A synced folder deleted on another device that
  holds local items here becomes local here, also when this device was
  off at the time (put back where it was, from the space's state).

## Freeing space

`cleanup.rs`, about every hour (the first a minute after start):

- **Old versions stay for a while.** A blob that stops being current
  (its file replaced or deleted) is kept for `keep_old` (30 days by
  default; `cardinal keep-old <days|forever>`), counted from when this
  device first saw it stop being current (`old-versions.json`). Then its
  chunks and indexes are deleted, except those a current or kept blob
  shares (identical content deduplicates). Objects no blob names are
  never deleted, and nothing stored or read in the last hour is.
- **`cardinal free-space --unnamed`** is the pass for those: it marks
  every object reachable from a blob reference in any entry of any space
  this device holds, through indexes at every level, and counts the rest
  (what a space it no longer holds left behind, or a save that never
  finished). `--delete` removes them. If a space cannot be opened, entries
  of one cannot be read, or an index it must follow is not here, what
  that names cannot be told from what nothing names: it says so, says the
  count may be too high, and deletes nothing. A device that keeps files
  on demand lacks most indexes, so there it only counts.
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

One base-encoded record per message each way, on a `SOCK_SEQPACKET`
socket (on Windows a named pipe in message mode), as
`apps.md#the-local-interface` says: a request's number in key 0 and its
arguments by number; a reply's status in key 0 (0 done, else an error
number, with why in key 1) and its fields from key 2. `src/api/table.rs`
numbers everything; inside, and in what follows, requests and fields go by
the names it gives them. Error 5 (`needs words`) means the recovery words,
as `words`, would let the same request through; 6 (`needs for`), that an
`accept` of a recovery invitation made for whomever the guardian names
needs `for`. `cardinal --trace <command>` shows a command's requests and
replies in the text rendering with these names, and `cardinal api-trace
--listen PATH` passes a client's messages on to the daemon and shows them.

A request whose answer grows with what the person holds answers a page of
it (`apps.md`, Pages; `table.rs` marks each with `paged!`): `limit`
items at most, as many as fit in a message (256 KiB) with the reply's
other fields, from a cursor on, with `more` and, when there is more,
`next`, the cursor of the next page. `messages` pages back from the
newest, `before` a message's id, the oldest of a page coming first; every
other one by position, `after` the items already had, through the
reply's lists in the order of their numbers. `api::page` cuts every such
reply as it leaves, from what the handler gave; an item that alone does
not fit is error 4, never cut short. The command line asks page after
page (`control::request`) and shows the whole, as before.
Requests: `status`, `devices`, `remove-device`,
`recovery-check` (`words`; changes nothing), `free-space` (`dry_run`; or
`unnamed`, with `delete`),
`keep-old` (`keep`), `peer-add/remove/list`,
`mount`, `unmount`,
`history`, `restore`, `conflicts`, `pin`, `unpin`, `retention`,
`pair-show`, `pair-status`, `pair-type` (both take `device`, a name for
the device being added), `setup-finish` (`name`, the person's; `device`),
`me` (`name` sets the name the person suggests for themselves),
`contact` (`name`, empty to clear; `picture`, a file, empty to clear;
`setting` `name-hosts` or `no-hosts`, or `no-host` with `host`, a device
name, which takes that one host out of the relationship's list and
records "not this host here" in the account, D75; answers `named`:
`named`, `waiting`, `no host`, `none`, `taken out` or `not named`),
`group-reach` (`share`; with `share` false, `host` takes out that one
host, answering `taken_out`; `groups` gives each group's `reach` with
`set` and `said_no`),
`group-remove` (`group`, `who`: the owner takes someone out, answering
`group`, the id the group has from then on, `was`, the one it had, and
`left_out`), `group-role` (`group`, `who`, `role`: `reader`, `member` or
`admin`; a higher role is given in place by an admin or the owner and
answers `group` as it was, a lower one is the owner's and answers like
`group-remove`), `group-post-again` (`group`: posts what this device
held back from the group, answering `posted`), `group-moved-seen`
(`group`: clears the group's `moved` note),
`router` (`on`, with `this_device` true for this device alone, else
for every device of the person's: the account's switch; answers what
`status` gives as `router`), `network` (with nothing: the network this
device is on, `{known, router, name, answered, mine, ask, routers}`;
with `mine` true or false, and `name`, the person's answer to "Is this
your network?" for it, kept in the account for all their devices, D76;
`ask` true is when a client shows that question, quietly; `status` gives
the same as `network`),
`read-markers` (with nothing: `{on}`, whether others see what this
person has read; with `on`, sets it in the account for every device of
theirs; `status` gives it as `read_markers`. Off, `mark-read` moves no
marker, keeps the position privately in the account instead and answers
`{marked: false, kept, why}`; on, it answers `{marked, kept: false}`.
`unread` counts from both), `conversations` and `contacts` (each person
with `nearby`: a direct session with one of their devices on the local
network, never from a tag; and in `conversations` `reach`: `{shared,
waiting, said_no, named}`, `named` by the device names `no-host` takes),
`speedtest` (one device, by
name or key), `reload` (after `init` while the daemon runs), `flush`
(commit now), `stop`. `status` includes `identity` (its first 16 hex digits, to show) and `identity_id` (all 64), and `copies`: per device meant to
keep everything, whether it counts (`state`: passed, failed, stale,
unchecked), why not (`reason`), the times of its last check, pass, and
failure, and checks it left unanswered in a row (`missed`).

### Guardians and recovery

A fingerprint is five words from the BIP-39 English list, separated by
single spaces, as `"wealth above drive initial couple"`; a request that
takes one reads it however it was typed (any case, any separator, four
letters a word suffice). The person: `guardians` → `{guardians,
threshold, delay, delay_text, data, names, recoveries: [{fingerprint,
endorsed, confirmed, in_effect, objected, id}], frozen}`; `guardians-set`
(`who`, `threshold`, `delay`; the words); `guardians-object`
(`fingerprint`, needed only when more than one is under way), for a
recovery or a change of guardians. `guardians` also gives `asked` (those
asked to be guardians who have not answered), `ready` (those who
accepted with a persona not named before, ready to be named), `changes`,
each change under way `{fingerprint, names, guardians, threshold, delay,
delay_text, confirm_delay, confirm_delay_text, confirmed, needed,
waits_until_ms, objected, id}` (`delay`: the change's own, for
recoveries under it; `confirm_delay`: the wait before the guardians in
office confirm it, the current policy's, doubled after an objection)
(`waits_until_ms`: when it was made, by this person's clock, plus the
wait; each guardian waits from when their device saw it, so it is a
guide), and `copy_full`, the guardians whose copy of the account reached
its cap. `guardians-set` naming someone with no fresh persona fails, and
asks them for one at once: an existing guardian kept in a change accepts
again. `guardians-set` refuses while a change is under way that
the person has not objected to.

The person asks with `guardians-ask` (`who`) → `{name}`. A guardian acts
through a persona per person guarded and per policy (D79), made by
`guarding-accept` (`who`) → `{name, persona (64 hex), already}`, which the
person then names with `guardians-set` (it fails, saying so, for a
contact with no persona not named before). With guardians in office,
`guardians-set` asks no words and replies `pending: true`: the change
takes effect once they confirm it. Errors of the guardians' and recovery requests, and of `accept`, start
with a capital letter and name no command: they are shown as they come.
Each person in `guarding` gives `persona_at`, where the persona's own
service listens (`ip:port`, null if it does not run on this device), for
`guarding-invite`'s `at`.

`guarding` → `{guarding: [{name, id (64
hex), persona, guardians, threshold, delay, delay_text, recoveries,
waiting, warning, never, helpers, account_copy, changes}], accepted:
[names], asked: [names], now_ms}`; `asked` lists those who asked this
person to guard them, unanswered; `accepted`, those this person accepted
to guard who have not named them yet; `named_in_change`, those who named
this person's persona in a change waiting for confirmation;
`no_longer_needed`, those whose guardians no longer name this person's
persona, `{name, id, at_ms, text}`, `text` saying so in words (D81);
`changes`, each change of the
person's guardians under way, `{id, guardians, threshold, delay_text,
confirmed, confirmed_by_me, in_effect, objected, confirm_from_ms,
caution, fingerprint, never}`, which `guarding-confirm-change` (`who`,
`understood`, `fingerprint`: needed when more than one is under way)
confirms, after the wait from when this device saw it; `guarding-never`
takes a change's fingerprint as well as a recovery's; `account_copy`, whether this device holds the
person's sealed account (D80). `recoveries` holds at most one: the one recovery of
that person shown at a time, `{fingerprint, endorsed, confirmed,
endorsed_by_me, confirmed_by_me, pending, confirm_from_ms, objected,
in_effect, keeps_keys, caution}` (`keeps_keys`: the `recover` keeps an
old key, and endorsing or confirming it fails). `caution` is the warning to show, in plain words,
before endorsing and again before confirming; a client shows it and asks
the guardian to go on. `waiting` counts other recoveries of that person
under way, which are not shown; `warning` is the text to show then, or
null. `never` lists the fingerprints the guardian said never to confirm;
`helpers`, the recovery relationships for that person.
`guarding-invite` (`who`, `at`: host:port, optional) → `{code, name}`:
an invitation for the person's new device, naming them in field 9.
`guarding-caution` (`who`) → `{name, caution}`: the warning to show before
endorsing or confirming, however `who` names the person.
`guarding-endorse` and `guarding-confirm` (`who`, `fingerprint`,
`understood`) → as `guarding`; both fail unless `understood` is true (the
guardian was shown `caution` and went on), and fail for a recovery that
waits behind the one shown, or that the guardian said never to. `guarding-never` (`who`,
`fingerprint`) → as `guarding`: never endorse or confirm it, on any of
the guardian's devices (an account setting); the recovery relationship
for it is retired (refused), as is any for another recovery once one is
in effect. `accept` of an invitation
that names someone in field 9 fails, with nothing sent, unless this
person guards them; for a guardian it replies `{name, recovery_of}`, and
the relationship is listed nowhere as a contact (`contacts`,
`conversations`, the one folder).

The new device: `recover` → `{under_way: true, identity, fingerprint,
helper, guardians, proposed, asked, endorsed, confirmed, threshold,
in_effect, held, lost_devices}` while one is under way (`held`: 1 once
the account is among what the guardians gave back; `lost_devices`, the
devices the recovery removes, `[{key, name: null}]`, so a window asks
when they were lost only if there are any); `{under_way: false, finished: true,
words, pair_again}` once, when `recover-finish` made the device the
person's but stopped before the end (show the words; the next `recover`
no longer has them); else `{under_way: false, pair_again}`. A recovery
keeps none of the old devices: `pair_again` lists them, `[{key, name}]`
(`key` the first 16 hex digits, `name` null unless the account remembers
one), to show under "pair them again". `recover-start` (`code`: a
guardian's recovery invitation, `identity`: 64 hex; both optional) →
`{fingerprint, identity}`: starts one if none is under way, and meets
that guardian. `recover-invite` (`at`, optional) → `{code, fingerprint}`:
an invitation for a guardian who is present to `accept`. Before any
guardian's invitation was used it is for whomever the guardian names:
`accept` then takes `for`, the person as the guardian's contacts call
them (without it, it fails with `needs_for`), and the new device learns whom it recovers from that guardian's
proposal.
`recover-cancel` → `{fingerprint}` (null if nothing was under way).
`recover-finish` (`without_account`, `lost_at`: ms, both optional) →
`{words, account, pair_again, lost_devices}`: refuses while no guardian
has given the account back, unless `without_account`; `lost_devices`
lists each removed device `{key, name, set_aside}` with how many of its
entries are set aside, to keep up to a time with `keep-work` (or now,
with `lost_at`, by those devices' own clocks). It takes the identity up
from what the guardians carried, and the account and relationships they
held (`account` true), or with new account and files spaces when none
held one; `words` are the new recovery words, to show once, and
`pair_again` the devices the account remembers, under "Pair your other
devices again".

`contacts` gives each contact `recovered`: the text to show when their log
has a recovery in effect ("was recovered by guardians they chose on
2026-11-21, after 7 days. If in doubt, check with them in person.", the
date being when this device first saw the policy, left out if it never
did), else null.

`accept` is the only request that takes a recovery invitation; an
introduction never uses one.

Removed (D77): `guarding-help` and `recover-via`, with the
`cardinal-help:` code they used; `recover-start` takes no `key` and
`recover-finish` no `at`, `key` or `without_hosts`.

## Groups that move on

Nobody is taken out of a space, and no role is lowered in it
(`spaces.md#members-and-roles`). `group-remove`, and `group-role` with a
lower role, have the owner's device succeed the group: a new group whose
genesis names who stays, with what role, and starts from the old group's
state, its conversation, files and member names under the ids they had.
The old group ends. Everyone else's devices follow on their own, once
they have checked it, and from then on the group has the new id;
whatever named the old one (a request, an offer, a token) finds the new
one. Whoever was left out is told, keeps the old group as it was, and
can open nothing of the new one.

A request that changes who is in a group reconciles it with a member
in touch first, where the owner has another device that could have
moved it already: with nobody in touch it fails, and changes nothing.

`groups` gives each group `was` (the id of the group it took the place
of, or null), `ended` (why, where a group ended and nothing here took its
place: its owner left this person out, handed it on, made it public, or
put something in its place that does not match it), `held_back` (how
much of what this device wrote before the group moved on waits for
`group-post-again`, since someone is in it now that it was written
without), `not_posted` (how much was not posted again because this
person's role there no longer allows it), `role` (this person's
there: `owner`, `admin`, `member` or `reader`), `moved` (until cleared
with `group-moved-seen`, or a week after this device first held the
group here: `{by, at, seen, taken_out: [names], roles: [{name, from,
to}]}`, who moved the group here, when by their clock, when this device
first held it, and what that changed; null otherwise), `did_not_stand`
(successors this person's devices made that another took the place of,
by id: they do again what each was for) and `did_not_stand_changes`
(the same, each `{group, taken_out, roles}`, as `moved` says them). `group-members` lists whoever was taken out too, by
the name the others saw, with `taken_out` true, `role` `taken out` and
`left` false (they did not leave);
what they wrote before shows them by that name. A reader's `say`,
`edit-message`, `delete-message` and `react` in a group fail, saying so.

A device posts again, in the group that stands, what it wrote that the
new group did not carry: a message written before it heard. It does so
only once it has reconciled the new group with someone who holds it,
so that it knows who is there. Only
application ops are posted again, by the device that wrote them, once.
A change made without seeing another stands beside it, in conflict.

## Inspection

For designing the data structures, not for applications: a read-only
look at everything the device holds, which `apps.md` says an application
never sees. Off until the person turns it on, on this device:
`cardinal inspect on [--minutes N]` (`inspect-on`, at most a day; it asks
first unless `--yes`) prints a token, `cardinal inspect off`
(`inspect-off`) ends it, and `status` says `inspection: {on, until}`. A
new grant ends the old token; the grant lives in memory only, so a
restart ends it too. Every request takes the `token`, and there is one
for each view: `inspect` (the overview), `inspect-identity` (`who`, `entry`,
`path`), `inspect-space` (`space`), `inspect-entries` (`space`, `view`:
`sealed` or `opened`), `inspect-entry` (`space`, `entry`
or `sealed_id`, `path` from `sealed`, `signed` or `entry`), `inspect-nodes`
(`space`, `kind`, `parent`), `inspect-node` (`space`, `node`, `path`);
each comes in pages, by `after` and `limit` (entries and nodes rendered
5,000 at most a page, which the cap then cuts), in place of
`inspect-entries`' and `inspect-nodes`' `offset` and `count`, which are no
longer read. `value_bytes` (once `limit`, under the same number) and
`items` say how much of each value to send (48 bytes and 24 items unless
asked). Values
come typed with their encoded length; no private key is ever sent: an
epoch key, a blob reference's key, a secret node's value, a reach
node's presence secret (field 2, D74) and an invitation's secret come as a value whose `t` is `secret`, with `what` and `len`, bytes that
encode one are withheld, and no `path` leads to one. The space explorer
(a separate program) draws all this. On a desktop without a sandbox this
guards against accident, not against a program running as the person
(`apps.md#the-limit`).

## Logs

`tracing` to stderr; under systemd (journald) without timestamps or
colours. `CARDINAL_LOG` or `RUST_LOG` sets the filter (`info` by default;
`cardinald=debug` for sync details). `cardinal log` runs
`journalctl --user -u cardinal`.

## Not done yet

- Hosts (mailbox, relay, storage), guardians, restoring from the phrase
  when every device is lost.
  Copies on hosts (host grants) are not counted.
- Epoch rotation after `rotate_after` entries (only after a device is
  removed).
