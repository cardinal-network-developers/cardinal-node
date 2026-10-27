#!/usr/bin/env bash
# Build a development release and publish it to the local dev channel.
#
#   scripts/dev-release.sh
#   cardinal update        # a dev build picks it up from the default dev source
#
# The version is <workspace version>-dev.<UTC timestamp>, so each build
# sorts after the previous one and before the eventual <workspace version>.
# The release is written to $CARDINAL_DEV_RELEASES (default:
# ${XDG_DATA_HOME:-~/.local/share}/cardinal-dev-releases)/<version>/ and its
# files are copied to the top of that directory, which is what
# `cardinal update` reads. Only the newest few versions are kept.
#
# Builds glibc only (fast) unless CARDINAL_RELEASE_TARGETS says otherwise.
# Signs with the release key, like scripts/release.sh.
#
# Environment: CARDINAL_DEV_VERSION overrides the version; everything
# scripts/release.sh accepts is passed through.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
data_home="${XDG_DATA_HOME:-$HOME/.local/share}"
case "$data_home" in /*) ;; *) data_home="$HOME/.local/share" ;; esac
dev_dir="${CARDINAL_DEV_RELEASES:-$data_home/cardinal-dev-releases}"
keep="${CARDINAL_DEV_KEEP:-3}"

base="$(sed -n '/^\[workspace.package\]/,/^\[/s/^version *= *"\(.*\)"/\1/p' "$repo/Cargo.toml")"
base="${base%%-*}"
version="${CARDINAL_DEV_VERSION:-$base-dev.$(date -u +%Y%m%d%H%M%S)}"

export CARDINAL_VERSION="$version"
export CARDINAL_RELEASE_TARGETS="${CARDINAL_RELEASE_TARGETS:-x86_64-unknown-linux-gnu}"
mkdir -p "$dev_dir"
"$repo/scripts/release.sh" --out "$dev_dir/$version" >/dev/null

# Publish: artifacts first, then the signature, then the manifest, so a
# concurrent `cardinal update` sees either the old release or the new one.
# (A reader that catches the manifest and signature mid-swap fails the
# signature check and changes nothing.)
for f in "$dev_dir/$version"/cardinal-*; do
    cp "$f" "$dev_dir/.tmp.$$" && mv "$dev_dir/.tmp.$$" "$dev_dir/$(basename "$f")"
done
cp "$dev_dir/$version/manifest.sig" "$dev_dir/.tmp.$$" && mv "$dev_dir/.tmp.$$" "$dev_dir/manifest.sig"
cp "$dev_dir/$version/manifest" "$dev_dir/.tmp.$$" && mv "$dev_dir/.tmp.$$" "$dev_dir/manifest"

# Prune old versions and their top-level artifacts.
mapfile -t old < <(find "$dev_dir" -mindepth 1 -maxdepth 1 -type d -name '*-dev.*' -printf '%f\n' | sort -V | head -n "-$keep")
for v in "${old[@]}"; do
    rm -rf "${dev_dir:?}/$v"
    rm -f "$dev_dir"/cardinal-"$v"-*
done

echo "dev release $version published to $dev_dir"
echo "update with: cardinal update   (or: cardinal update --from $dev_dir)"
