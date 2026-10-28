# Releasing Cardinal

## The release key

Every `cardinal` binary embeds one Ed25519 public key,
`packaging/release-key.pub`, and installs only releases whose `manifest` is
signed by the matching secret key. That secret key is the most sensitive
thing in the project: whoever holds it can push code to every installation.

- **Location:** `~/.config/cardinal-release/release.key` (hex seed, mode
  0600), outside the repository. `CARDINAL_RELEASE_KEY` points elsewhere.
- **Creation:** the first run of `scripts/release.sh` generates it, writes
  the public half to `packaging/release-key.pub`, and prints a notice. Commit
  the public key; never commit the secret key.
- **Backup:** immediately, offline (encrypted USB stick, password manager).
  If it is lost, installed binaries will refuse all future releases; users
  have to reinstall a binary that carries a new key.
- **Leak:** generate a new key (below), release a version carrying it signed
  with the *old* key so installations move to the new key, and tell users.
  An attacker with the old key can still sign updates for anyone who has not
  updated yet, so be loud about it.
- **Fingerprint:** `cardinal version` and
  `cardinal-release-sign fingerprint --public packaging/release-key.pub` show
  the same short fingerprint. Publish it somewhere independent of the
  release host (project page, README) so people who use `install.sh` can
  compare.

`scripts/release.sh` refuses to run if `packaging/release-key.pub` exists
but the secret key does not, so a missing backup is never silently replaced
by a new key. To rotate deliberately: move the old secret key aside, set
`CARDINAL_RELEASE_NEW_KEY=1`, run the script, and commit the new public key.

## Making a release

1. Set the version in the root `Cargo.toml` (`[workspace.package]
   version`), commit, and tag (`git tag v0.2.0`). Releases are built from a
   clean tree; a dirty one is marked `-dirty` in `cardinal version`.
2. Optionally `rustup target add x86_64-unknown-linux-musl` (and install
   `musl-tools`) for a static binary that runs on any distribution. Without
   it the release is glibc-only and the script prints the minimum glibc
   version it needs.
3. Run:

   ```sh
   scripts/release.sh
   ```

   This builds the signing helper (`cardinal-release-sign`), creates the key
   if needed, builds `cardinal` for each target with the version, commit,
   and date embedded, checks each binary reports that version and embeds
   the release key, then writes and signs:

   ```text
   dist/<version>/
     cardinal-<version>-x86_64-unknown-linux-musl   (if built)
     cardinal-<version>-x86_64-unknown-linux-gnu
     manifest        version, commit, date; per target: file, size, BLAKE3, SHA-256
     manifest.sig    Ed25519 over "cardinal release manifest v1\n" || manifest
   ```

4. Test it: `cardinal update --from dist/<version> --check`, or install it
   into a scratch account.

Artifacts are raw, stripped binaries (no archive), so `install.sh` needs
nothing beyond `curl`/`wget` and `sha256sum`.

## Publishing

A release source is just a directory served over HTTPS whose top level holds
the current `manifest`, `manifest.sig`, and the files the manifest names.
`cardinal update` fetches `<source>/manifest`, `<source>/manifest.sig`, and
`<source>/<file>`.

### Any static host

```sh
rsync -av dist/0.2.0/ host:/srv/www/cardinal/releases/0.2.0/
# Point "latest" at it: copy the binaries first, then the signature, then
# the manifest, so clients never see a manifest without its files.
ssh host 'cd /srv/www/cardinal/releases &&
  cp 0.2.0/cardinal-* . && cp 0.2.0/manifest.sig . && cp 0.2.0/manifest .'
scp install.sh host:/srv/www/cardinal/install.sh
```

Users then set `source = "https://host/cardinal/releases"`. Old versions can
stay in their subdirectories (`--from https://host/cardinal/releases/0.1.0`)
but clients refuse to downgrade unless `CARDINAL_ALLOW_DOWNGRADE=1`.

### GitHub Releases

GitHub serves the newest release's assets at a stable URL, which is a valid
source:

```sh
gh release create v0.2.0 dist/0.2.0/* install.sh --title v0.2.0 --notes-file NOTES.md
```

Source: `https://github.com/cardinal-network-developers/cardinal-node/releases/latest/download`, which is also the built-in default
(`DEFAULT_SOURCE` in `crates/update/src/ops.rs`).
Install: `curl -fsSL https://github.com/cardinal-network-developers/cardinal-node/releases/latest/download/install.sh | sh -s -- https://github.com/cardinal-network-developers/cardinal-node/releases/latest/download`.

GitHub redirects these URLs to its CDN over HTTPS, which `cardinal update`
follows.

## Development releases

```sh
scripts/dev-release.sh
cardinal update
```

builds version `<workspace version>-dev.<UTC timestamp>` for glibc only,
signs it with the release key, and publishes it into
`~/.local/share/cardinal-dev-releases` (keeping the newest three). A dev
build with no configured source updates from that directory, so the loop is
edit, `dev-release.sh`, `cardinal update`. Dev versions sort before the
release of the same number, so `0.2.0` replaces any `0.2.0-dev.*`.

## Tests

- `cargo test -p cardinal-update`: manifest parsing and signatures, hash and
  size mismatches, downgrade refusal, atomic swap and rollback, install,
  uninstall, and purge confirmation, all in temporary directories with a
  fake `systemctl`.
- `scripts/test-update-e2e.sh`: builds three dev releases with a throwaway
  key and walks install, update from the default dev source, a failing
  update that rolls back, downgrade refusal, a tampered manifest,
  `install.sh` from a directory, and uninstall, in a temporary `HOME` with
  `systemctl` stubbed. It uses the deployment-only front end
  `cardinal-deploy` unless `E2E_PACKAGE=cardinal E2E_BIN=cardinal`.

## Files

| File | Purpose |
|---|---|
| `packaging/release-key.pub` | Release public key compiled into binaries |
| `crates/update` | `install`, `update`, `uninstall`, `version`; `cardinal-release-sign` |
| `scripts/release.sh` | Build, package, sign |
| `scripts/dev-release.sh` | Development release into the local dev channel |
| `scripts/test-update-e2e.sh` | End-to-end test |
| `install.sh` | First install from a URL or directory |
