# Build plan: first milestone

Goal (from `../core/README.md`): one person, several Linux devices, a synced
folder with history and conflict copies, good enough to replace a real
rsync job. Dropbox-like: a FUSE mount that lists everything and fetches
content on demand. Easy install, easy update.

The specification in `../core` is the authority. When code and spec
disagree, fix one of them on purpose, and note it in `DEVIATIONS.md`.

## Layout

Rust workspace, one crate per spec concept. License MIT OR Apache-2.0.

| Crate | Spec | Milestone scope |
|---|---|---|
| `cardinal-encoding` | encoding.md | complete, with test vectors |
| `cardinal-crypto` | crypto.md | suite 1 complete: derive, seal, AEADs, Ed25519 (ZIP-215), X25519, ML-KEM-768, CPace, BIP-39 |
| `cardinal-identity` | identity.md, model/rules.md | entries, signing, log storage; validity by executing `model/rules.md` with an embedded stratified-Datalog evaluator, so the rules are never re-implemented by hand |
| `cardinal-space` | spaces.md, state.md | sealed entries, epochs, files-profile state tree (MVR fields, moves, deletes, conflicts); membership for a single-identity space natively |
| `cardinal-blob` | blobs.md | FastCDC, convergent encryption, indexes, on-disk store |
| `cardinal-sync` | sync.md | range-based reconciliation, want/objects/heads |
| `cardinal-link` | link.md | handshake, keys, frames; **TCP carrier first** (a spec-listed carrier, reliable for free); UDP with loss recovery and congestion control is the next milestone |
| `cardinal-contact` | contact.md | pairing own devices with CPace over the LAN; LAN discovery |
| `cardinald` | — | the daemon: stores, sync engine, link sessions, FUSE mount, local control socket |
| `cardinal` | — | CLI: `init`, `pair`, `devices`, `status`, `mount`, `install`, `update`, `uninstall`, `log` |

## Deployment

- Per-user install, no root: binary in `~/.local/bin`, systemd user unit,
  data in `~/.local/share/cardinal`, config in `~/.config/cardinal`.
- `cardinal install` installs itself; `install.sh` downloads and runs it.
- `cardinal update` fetches a release manifest, verifies its Ed25519
  signature against a release key compiled into the binary, swaps the
  binary atomically, and restarts the service. The release source is a URL
  or a local directory, so iteration works before any hosting exists.
- `scripts/release.sh` builds, packages, and signs a release.

## Order

1. Workspace, encoding, crypto (foundation; everything else depends on it).
2. In parallel: blob + sync; identity + space; link + contact.
3. Daemon, FUSE, CLI, installer, updater; two-device end-to-end test on one
   machine.
