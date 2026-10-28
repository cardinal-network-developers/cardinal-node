# Installing Cardinal

Cardinal installs for one user, without root. It runs as a systemd user
service and keeps everything under your home directory.

| What | Where |
|---|---|
| Binary | `~/.local/bin/cardinal` (the one before the last update: `cardinal.previous`) |
| Service | `~/.config/systemd/user/cardinal.service` (runs `cardinal daemon`) |
| Data and keys | `~/.local/share/cardinal` |
| Settings | `~/.config/cardinal/config.toml` |

`XDG_BIN_HOME`, `XDG_DATA_HOME`, and `XDG_CONFIG_HOME` move these if set.

## Requirements

- Linux on x86_64 (static musl builds run on any distribution; glibc builds
  print the minimum glibc they need when released).
- FUSE 3 for mounting spaces: `/dev/fuse` and `fusermount3` (Debian/Ubuntu:
  `sudo apt install fuse3`; Fedora: `sudo dnf install fuse3`). Cardinal does
  not need `user_allow_other` in `/etc/fuse.conf`.
- systemd with a user manager (any desktop session; on servers see
  [Headless servers](#headless-servers)). Without it Cardinal still
  installs, and you can run `cardinal daemon` yourself.

## Install

From the project's GitHub releases:

```sh
curl -fsSL https://github.com/cardinal-network-developers/cardinal-node/releases/latest/download/install.sh | sh -s -- https://github.com/cardinal-network-developers/cardinal-node/releases/latest/download
```

or from a directory holding a release (`manifest`, `manifest.sig`, and the
binaries), e.g. a USB stick or a `dist/<version>` you built:

```sh
sh install.sh /path/to/release
```

`install.sh` picks the build for your machine, checks its size and hash
against the release manifest, and runs `cardinal install`, which:

1. copies the binary to `~/.local/bin/cardinal` (atomically);
2. creates the data and settings directories (mode 0700) and a commented
   `config.toml` if there is none;
3. writes the systemd user unit, then `systemctl --user daemon-reload` and
   `enable`, and starts the service;
4. warns about missing FUSE pieces, about `~/.local/bin` not being on your
   `PATH`, and about lingering (below).

Running `cardinal install` again is harmless. If a *different* binary is
already installed it asks before replacing it; `--force` replaces without
asking.

**What install.sh does and does not check.** A shell script cannot verify
Ed25519 signatures, so its hash check only proves the download is intact
and matches the manifest from the same place. You are trusting the script
and the site you got it from (over HTTPS). At the end it prints the release
key fingerprint compiled into the binary; compare it with the fingerprint
the project publishes. Every later `cardinal update` checks releases
against that key.

If `~/.local/bin` is not on your `PATH`, add to your shell profile:

```sh
export PATH="$HOME/.local/bin:$PATH"
```

## Headless servers

A user service normally stops when you log out. To keep it running on a
machine you only reach over SSH:

```sh
loginctl enable-linger "$USER"
```

## Updating

```sh
cardinal update --check     # is there a newer release?
cardinal update             # install it
cardinal update --from https://RELEASES     # or a directory
```

`cardinal update`:

1. fetches `manifest` and `manifest.sig` from the source and verifies the
   signature against the release key compiled into your binary; anything
   unsigned, tampered with, or signed by another key is refused;
2. refuses to go to an older version (which would let someone replay an old,
   vulnerable release) unless you set `CARDINAL_ALLOW_DOWNGRADE=1`;
3. downloads the binary for your machine and checks its size and BLAKE3 and
   SHA-256 hashes against the signed manifest, then checks that it runs and
   reports the expected version, all before touching the installed one;
4. swaps it in atomically, keeping the old one as `cardinal.previous`;
5. if the service was running, restarts it and waits (default 20 seconds;
   `CARDINAL_HEALTH_TIMEOUT` changes this) for it to come up and stay up.
   If it does not, the previous binary is put back, the service is
   restarted on it, and the command fails saying so. Look at
   `journalctl --user -u cardinal` to see why the new version failed.

### Where updates come from

Set the source once in `~/.config/cardinal/config.toml`:

```toml
[update]
source = "https://RELEASES"      # or a directory
auto_check = true                # the daemon may tell you about new releases
```

The source is either an `https://` URL or a local directory; plain `http://`
is refused except for `localhost`. With no source configured, a development
build (version `X.Y.Z-dev.N`) reads `~/.local/share/cardinal-dev-releases`,
where `scripts/dev-release.sh` publishes; a regular build uses the project's
GitHub releases, `https://github.com/cardinal-network-developers/cardinal-node/releases/latest/download`. `channel = "dev"` or `"stable"` overrides that choice.

## Version

```sh
cardinal version
```

prints the version, git commit, build date, target, and the fingerprint of
the release key it trusts.

## Uninstalling

```sh
cardinal uninstall
```

stops and disables the service and removes the unit and binaries. Your data
and settings stay, so reinstalling picks up where you left off.

```sh
cardinal uninstall --purge
```

also deletes `~/.local/share/cardinal` and `~/.config/cardinal`, including
this device's keys. Anything not synced to another device is gone for good,
so it asks you to type `delete` on the terminal; there is no flag to skip
that.

## Troubleshooting

- `systemctl --user status cardinal` and `journalctl --user -u cardinal -e`
  show the service.
- "`systemctl --user` is not available": you are in a session without a user
  manager (e.g. `su`, some containers). Log in normally or enable lingering,
  then `systemctl --user daemon-reload && systemctl --user enable --now
  cardinal.service`.
- Slow sync between two of your devices: `cardinal speedtest` measures the
  encrypted link to each of them (about 20 seconds per device, nothing
  written to disk). It shows what Cardinal can move, which is often less
  than the network can, since encrypting every packet takes processor
  time. To tell which is the limit, run `iperf3 -s` on one machine and
  `iperf3 -c <its address>` on the other: if iperf3 is much faster, the
  processor is the limit, not the network.
- To go back by hand after an update:
  `mv ~/.local/bin/cardinal.previous ~/.local/bin/cardinal && systemctl --user restart cardinal`.
