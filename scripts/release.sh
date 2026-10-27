#!/usr/bin/env bash
# Build, package, and sign a Cardinal release.
#
#   scripts/release.sh [--out DIR]
#
# Produces DIR (default: dist/<version>) containing
#   cardinal-<version>-<target>   one raw binary per target built
#   manifest                      version, targets, sizes, BLAKE3 + SHA-256
#   manifest.sig                  Ed25519 signature over the manifest
#
# Targets: x86_64-unknown-linux-musl (static, preferred) when that rustup
# target is installed and builds, and x86_64-unknown-linux-gnu always.
#
# The release secret key lives OUTSIDE the repository, at
#   ${CARDINAL_RELEASE_KEY:-~/.config/cardinal-release/release.key}
# On first run it is generated (mode 0600) and its public half is written to
# packaging/release-key.pub, which is compiled into every binary.
#
# Environment:
#   CARDINAL_VERSION              version to release (default: workspace version)
#   CARDINAL_RELEASE_KEY          secret key path (see above)
#   CARDINAL_RELEASE_PUBKEY_FILE  public key path (default: packaging/release-key.pub)
#   CARDINAL_RELEASE_PACKAGE/BIN  cargo package and binary to ship
#                                 (default: cardinal / cardinal)
#   CARDINAL_RELEASE_TARGETS      space-separated targets, overriding detection
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"

out=""
while [ $# -gt 0 ]; do
    case "$1" in
        --out) out="$2"; shift 2 ;;
        -h|--help) sed -n '2,/^set -e/p' "$0" | sed 's/^# \{0,1\}//;$d'; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

workspace_version="$(sed -n '/^\[workspace.package\]/,/^\[/s/^version *= *"\(.*\)"/\1/p' Cargo.toml)"
version="${CARDINAL_VERSION:-$workspace_version}"
secret="${CARDINAL_RELEASE_KEY:-$HOME/.config/cardinal-release/release.key}"
public="${CARDINAL_RELEASE_PUBKEY_FILE:-$repo/packaging/release-key.pub}"
package="${CARDINAL_RELEASE_PACKAGE:-cardinal}"
bin="${CARDINAL_RELEASE_BIN:-cardinal}"
out="${out:-$repo/dist/$version}"
target_dir="${CARGO_TARGET_DIR:-$repo/target}"
export CARDINAL_RELEASE_PUBKEY_FILE="$public"

say() { printf '==> %s\n' "$*" >&2; }

# The signing helper. It does not need the release key to build.
say "building the signing helper"
cargo build --quiet --release -p cardinal-update --bin cardinal-release-sign
signer="$target_dir/release/cardinal-release-sign"

# The key.
if [ ! -f "$secret" ]; then
    if [ -f "$public" ] && [ -z "${CARDINAL_RELEASE_NEW_KEY:-}" ]; then
        echo "error: $public exists but the secret key $secret does not." >&2
        echo "Restore the secret key from your backup. To deliberately start over with a" >&2
        echo "NEW key (installed binaries will then reject your releases until users" >&2
        echo "reinstall), rerun with CARDINAL_RELEASE_NEW_KEY=1." >&2
        exit 1
    fi
    say "generating a release key"
    rm -f "$public"
    "$signer" keygen --secret "$secret" --public "$public"
    cat >&2 <<EOF

  ************************************************************************
  *  NEW RELEASE SIGNING KEY CREATED                                     *
  *                                                                      *
  *  Secret key: $secret
  *  Public key: $public
  *                                                                      *
  *  BACK UP THE SECRET KEY NOW (offline, e.g. an encrypted USB stick    *
  *  or a password manager). If it is lost, no installed binary will     *
  *  accept a future release. If it leaks, anyone can ship "updates".    *
  *  Commit the public key file; never commit the secret key.            *
  ************************************************************************

EOF
fi
perm="$(stat -c %a "$secret")"
if [ "$perm" != 600 ] && [ "$perm" != 400 ]; then
    echo "error: $secret has mode $perm; run: chmod 600 '$secret'" >&2
    exit 1
fi

# Targets.
if [ -n "${CARDINAL_RELEASE_TARGETS:-}" ]; then
    read -r -a targets <<<"$CARDINAL_RELEASE_TARGETS"
else
    targets=()
    if rustup target list --installed 2>/dev/null | grep -qx x86_64-unknown-linux-musl; then
        targets+=(x86_64-unknown-linux-musl)
    else
        say "x86_64-unknown-linux-musl is not installed; building glibc only"
        say "(for a portable static build: rustup target add x86_64-unknown-linux-musl)"
    fi
    targets+=(x86_64-unknown-linux-gnu)
fi

commit="$(git rev-parse --short=12 HEAD)"
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    commit="$commit-dirty"
    say "warning: the working tree has uncommitted changes"
fi
date="$(date -u +%Y-%m-%d)"
export CARDINAL_VERSION="$version" CARDINAL_GIT_COMMIT="$commit" CARDINAL_BUILD_DATE="$date"
export CARGO_PROFILE_RELEASE_STRIP=symbols

rm -rf "$out"
mkdir -p "$out"
specs=()
for t in "${targets[@]}"; do
    say "building $package ($bin) $version for $t"
    if ! cargo build --quiet --release --locked -p "$package" --bin "$bin" --target "$t"; then
        if [ "$t" = x86_64-unknown-linux-musl ] && [ -z "${CARDINAL_RELEASE_TARGETS:-}" ]; then
            say "warning: the musl build failed (is musl-tools installed?); skipping it"
            continue
        fi
        exit 1
    fi
    built="$target_dir/$t/release/$bin"
    file="cardinal-$version-$t"
    cp "$built" "$out/$file"
    chmod 755 "$out/$file"

    # The binary must carry the key we are about to sign with.
    reported="$("$out/$file" version)"
    want_fp="$("$signer" fingerprint --public "$public")"
    if ! grep -q "^release key: $want_fp\$" <<<"$reported"; then
        echo "error: $file does not embed the release key $want_fp:" >&2
        echo "$reported" >&2
        exit 1
    fi
    if ! grep -qx "cardinal $version" <<<"$(head -n1 <<<"$reported")"; then
        echo "error: $file reports '$(head -n1 <<<"$reported")', expected 'cardinal $version'" >&2
        exit 1
    fi
    case "$t" in
        *-linux-gnu)
            if command -v objdump >/dev/null; then
                glibc="$(objdump -T "$out/$file" | grep -o 'GLIBC_[0-9.]*' | sed 's/GLIBC_//' | sort -uV | tail -n1)"
                say "$file needs glibc >= ${glibc:-unknown}"
            fi
            ;;
    esac
    specs+=("$t=$out/$file")
done
if [ "${#specs[@]}" -eq 0 ]; then
    echo "error: nothing was built" >&2
    exit 1
fi

say "writing and signing the manifest"
"$signer" manifest --version "$version" --commit "$commit" --date "$date" \
    --out "$out/manifest" "${specs[@]}"
"$signer" sign --secret "$secret" --public "$public" "$out/manifest"
"$signer" verify --public "$public" "$out/manifest" >&2

say "release $version is in $out"
ls -l "$out" >&2
echo "$out"
