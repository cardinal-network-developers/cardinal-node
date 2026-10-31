# Cardinal Node

An experimental implementation of the [Cardinal Core](https://github.com/cardinal-network-developers/cardinal-core)
specification. It is used to settle the specification, so for now it is
also the reference: where the two disagree, one of them is wrong, and
[DEVIATIONS.md](DEVIATIONS.md) records which.

**Status: alpha.** The cryptography has not been audited. Formats may change
between releases without migration. Keep other copies of anything you put
in it.

## What works

One person, several Linux devices, one folder that is the same everywhere:

- `cardinal init` on the first device: no account, 24 recovery words.
- `cardinal pair` on a new device shows a code; type it on the first one.
- Files appear in `~/Cardinal` on every device, fetched on demand, with
  history, restore, and conflict copies labeled by device.
- Devices on the same network find each other; others are added with
  `cardinal peer add host:7171`.
- A `.cardinalignore` file (gitignore syntax) lists paths that stay on
  the device where they are made, such as build output: they show in
  your folder there and are never synced.
- Deleted files and old versions are kept 30 days so you can restore them
  (`cardinal history`, `cardinal restore`), then freed. `cardinal
  free-space` frees them now; `cardinal keep-old 90` or `forever` changes
  the period on a device.
- Lost your admin device? On any device you still have, your recovery
  words stand in for it: `cardinal remove-device <name> --lost` removes the
  lost one, and `cardinal pair <code> --admin` (with `cardinal pair --admin` on
  the new device) adds an admin device in its place. Each asks for the
  words, uses them once, and keeps nothing. `cardinal recovery check`
  checks the words you wrote down.
- Lost every device? On a device that stays on, `cardinal host --address
  <host:port>` keeps a full copy of your files and shows what to add to
  your recovery sheet (`cardinal recovery sheet` shows it again). On a new
  device, `cardinal recovery restore --host <address> --key <key>` asks for
  the 24 words and brings everything back. Old versions follow that
  device's `cardinal keep-old`. Hosts run by others are not supported yet.

Not yet: guardians, mailboxes, relays and hosts run by others, sharing with
other people, UDP, platforms other than Linux. [PLAN.md](PLAN.md) has the
order of work.

## Install

Linux with FUSE 3 (`sudo apt install fuse3`) and a systemd user session;
older systems, such as a Synology NAS, get a static build. No root needed:

```sh
curl -fsSL https://github.com/cardinal-network-developers/cardinal-node/releases/latest/download/install.sh | sh
```

`cardinal update` fetches, verifies, and installs the next release, and
rolls back if it fails to start. See [docs/install.md](docs/install.md).

`install.sh` cannot check signatures itself. When it finishes it prints the
release key fingerprint compiled into the binary, which must be:

```text
2215 1e39 54f0 75a8 1e42 7c9b 72a0 ff7d
```

## Build

```sh
cargo build --release
cargo test --workspace
```

Releasing is described in [docs/releasing.md](docs/releasing.md).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT), at your option. Contributions are accepted under
the same terms; see [CONTRIBUTING.md](CONTRIBUTING.md).
