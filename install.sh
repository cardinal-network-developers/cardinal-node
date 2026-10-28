#!/bin/sh
# Install Cardinal for the current user (no root needed).
#
#   curl -fsSL https://github.com/cardinal-network-developers/cardinal-node/releases/latest/download/install.sh | sh
#   curl -fsSL https://example.org/cardinal/install.sh | sh -s -- https://example.org/cardinal/releases
#   sh install.sh /path/to/release/directory
#   CARDINAL_RELEASES=https://example.org/cardinal/releases sh install.sh
#
# Downloads the binary for this machine named in the release's `manifest`,
# checks its size and hash against the manifest (BLAKE3 with b3sum, else
# SHA-256), and runs `cardinal install`, which puts it in ~/.local/bin and
# starts the systemd user service. Extra arguments after the source are
# passed to `cardinal install` (e.g. --force).
#
# What this script does NOT do: verify the release signature. POSIX sh has
# no Ed25519, so the hash check here only catches corrupted or truncated
# downloads. You are trusting this script and the host you fetched it from
# (over HTTPS). From then on, every `cardinal update` verifies the signed
# manifest against the release key compiled into the binary. The script
# prints that key's fingerprint at the end: compare it with the one the
# project publishes.
set -eu

die() { echo "install.sh: $*" >&2; exit 1; }

base="${1:-${CARDINAL_RELEASES:-https://github.com/cardinal-network-developers/cardinal-node/releases/latest/download}}"
[ $# -gt 0 ] && shift
base="${base%/}"

[ "$(uname -s)" = Linux ] || die "only Linux is supported"
case "$(uname -m)" in
    x86_64|amd64) arch=x86_64 ;;
    aarch64|arm64) arch=aarch64 ;;
    *) die "unsupported architecture $(uname -m)" ;;
esac
# A static musl build runs anywhere; a glibc build is the fallback.
targets="$arch-unknown-linux-musl $arch-unknown-linux-gnu"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/cardinal-install.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT INT TERM

fetch() { # fetch NAME DEST
    case "$base" in
        https://*)
            if command -v curl >/dev/null 2>&1; then
                curl --proto '=https' --tlsv1.2 -fsSL "$base/$1" -o "$2" || die "could not download $base/$1"
            elif command -v wget >/dev/null 2>&1; then
                wget -q --https-only -O "$2" "$base/$1" || die "could not download $base/$1"
            else
                die "need curl or wget to download"
            fi
            ;;
        http://*) die "refusing plain http://; use https://" ;;
        file://*) cp "${base#file://}/$1" "$2" || die "could not read ${base#file://}/$1" ;;
        *://*) die "unsupported source $base" ;;
        *) cp "$base/$1" "$2" || die "could not read $base/$1" ;;
    esac
}

# value SECTION KEY: a quoted or bare value from the manifest.
value() {
    awk -v sec="[$1]" -v key="$2" '
        /^[ \t]*\[/ { inside = ($0 == sec); next }
        inside {
            line = $0
            sub(/^[ \t]*/, "", line)
            k = line; sub(/[ \t]*=.*/, "", k)
            if (k != key) next
            v = line; sub(/^[^=]*=[ \t]*/, "", v); sub(/[ \t]*$/, "", v)
            gsub(/"/, "", v)
            print v; exit
        }' "$tmp/manifest"
}

fetch manifest "$tmp/manifest"
version="$(awk -F'"' '/^version *=/ { print $2; exit }' "$tmp/manifest")"
[ -n "$version" ] || die "the manifest has no version"

file=""
for t in $targets; do
    file="$(value "artifact.$t" file)"
    if [ -n "$file" ]; then target="$t"; break; fi
done
[ -n "$file" ] || die "release $version has no build for $arch Linux"
case "$file" in
    ""|.*|*[!A-Za-z0-9._+-]*) die "unsafe file name in manifest: $file" ;;
esac
size="$(value "artifact.$target" size)"
b3="$(value "artifact.$target" blake3)"
sha="$(value "artifact.$target" sha256)"

echo "Downloading cardinal $version ($target)..."
fetch "$file" "$tmp/cardinal"

actual_size="$(wc -c <"$tmp/cardinal" | tr -d ' ')"
[ "$actual_size" = "$size" ] || die "size mismatch: got $actual_size bytes, manifest says $size"
if command -v b3sum >/dev/null 2>&1 && [ -n "$b3" ]; then
    got="$(b3sum --no-names "$tmp/cardinal")"; want="$b3"; algo=BLAKE3
elif [ -n "$sha" ] && command -v sha256sum >/dev/null 2>&1; then
    got="$(sha256sum "$tmp/cardinal" | cut -d' ' -f1)"; want="$sha"; algo=SHA-256
elif [ -n "$sha" ] && command -v shasum >/dev/null 2>&1; then
    got="$(shasum -a 256 "$tmp/cardinal" | cut -d' ' -f1)"; want="$sha"; algo=SHA-256
else
    die "need b3sum, sha256sum, or shasum to check the download"
fi
[ "$got" = "$want" ] || die "$algo mismatch for $file; refusing to install it"
echo "$algo hash matches the manifest."

chmod 755 "$tmp/cardinal"
"$tmp/cardinal" version || die "the downloaded binary does not run on this system"
"$tmp/cardinal" install "$@"

echo
echo "Release key fingerprint (compare with the one the project publishes):"
"$tmp/cardinal" version | sed -n 's/^release key: */  /p'
