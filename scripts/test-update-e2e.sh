#!/usr/bin/env bash
# End-to-end test of release -> install -> update -> rollback -> uninstall.
#
# Everything happens under a temporary HOME with a throwaway release key and
# stub `systemctl`/`loginctl` first on PATH, so the real user session, the
# real ~/.local, and the real release key are never touched.
#
# By default it ships the `cardinal-deploy` stand-in front end (deployment
# commands only). Once the full CLI implements `version`, `install`,
# `update`, and `uninstall`, run with E2E_PACKAGE=cardinal E2E_BIN=cardinal.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
t="$(mktemp -d "${TMPDIR:-/tmp}/cardinal-e2e.XXXXXX")"
trap 'rm -rf "$t"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
step() { printf '\n=== %s\n' "$*" >&2; }

# Builds keep the real HOME (cargo and rustup live there) but use their own
# target directory, since the embedded key differs from a normal build.
export CARGO_TARGET_DIR="${E2E_TARGET_DIR:-$repo/target/e2e}"
export CARDINAL_RELEASE_KEY="$t/key/release.key"
export CARDINAL_RELEASE_PUBKEY_FILE="$t/key/release-key.pub"
export CARDINAL_RELEASE_NEW_KEY=1
export CARDINAL_RELEASE_PACKAGE="${E2E_PACKAGE:-cardinal-update}"
export CARDINAL_RELEASE_BIN="${E2E_BIN:-cardinal-deploy}"
export CARDINAL_RELEASE_TARGETS=x86_64-unknown-linux-gnu

home="$t/home"
devdir="$home/.local/share/cardinal-dev-releases"
mkdir -p "$home" "$t/stub"

v1=0.1.0-dev.1 v2=0.1.0-dev.2 v3=0.1.0-dev.3
step "building dev releases $v1, $v2 (healthy) and $v3 (fails health check)"
CARDINAL_DEV_VERSION=$v1 CARDINAL_DEV_RELEASES="$t/rel1" "$repo/scripts/dev-release.sh"
CARDINAL_DEV_VERSION=$v2 CARDINAL_DEV_RELEASES="$devdir" "$repo/scripts/dev-release.sh"
CARDINAL_DEV_VERSION=$v3 CARDINAL_DEV_RELEASES="$t/rel3" "$repo/scripts/dev-release.sh"
[ -f "$devdir/manifest" ] && [ -f "$devdir/manifest.sig" ] || fail "dev release not published"

# Stub systemctl: logs calls; the service is "failed" while the installed
# binary is $v3 and "active" otherwise.
cat >"$t/stub/systemctl" <<EOF
#!/bin/sh
echo "systemctl \$*" >>"$t/systemctl.log"
[ "\$1" = --user ] || { echo "stub: refusing non --user call" >&2; exit 1; }
case "\$2" in
  is-active)
    v=\$("$home/.local/bin/cardinal" version 2>/dev/null | head -n1)
    if [ "\$v" = "cardinal $v3" ]; then echo failed; exit 3; fi
    echo active ;;
esac
exit 0
EOF
printf '#!/bin/sh\necho no\n' >"$t/stub/loginctl"
chmod +x "$t/stub/systemctl" "$t/stub/loginctl"

# Run as the fake user: temp HOME, no inherited XDG overrides, stubs first.
as_user() {
    env -u XDG_DATA_HOME -u XDG_CONFIG_HOME -u XDG_BIN_HOME -u XDG_STATE_HOME \
        -u CARDINAL_ALLOW_DOWNGRADE \
        HOME="$home" PATH="$t/stub:$home/.local/bin:/usr/bin:/bin" \
        CARDINAL_HEALTH_TIMEOUT=3 "$@"
}
installed_version() { as_user "$home/.local/bin/cardinal" version | head -n1; }

step "install $v1 from its release directory"
art1="$t/rel1/cardinal-$v1-x86_64-unknown-linux-gnu"
as_user "$art1" install
[ "$(installed_version)" = "cardinal $v1" ] || fail "install: got $(installed_version)"
[ -f "$home/.config/systemd/user/cardinal.service" ] || fail "unit not written"
grep -q "enable cardinal.service" "$t/systemctl.log" || fail "unit not enabled"
as_user "$art1" install || fail "second install not idempotent"

step "check, then update to $v2 from the default dev source"
as_user cardinal update --check | grep -q "$v2" || fail "check did not report $v2"
[ "$(installed_version)" = "cardinal $v1" ] || fail "check changed the binary"
: >"$t/systemctl.log"
as_user cardinal update
[ "$(installed_version)" = "cardinal $v2" ] || fail "update: got $(installed_version)"
[ "$(as_user "$home/.local/bin/cardinal.previous" version | head -n1)" = "cardinal $v1" ] \
    || fail "previous binary not kept"
grep -q "restart cardinal.service" "$t/systemctl.log" || fail "service not restarted"
as_user cardinal update | grep -q "up to date" || fail "second update not a no-op"

step "update to $v3, whose service fails: expect rollback"
if as_user cardinal update --from "$t/rel3" 2>"$t/err"; then
    fail "update to a failing release succeeded"
fi
cat "$t/err" >&2
grep -q "Rolled back to $v2" "$t/err" || fail "no rollback message"
[ "$(installed_version)" = "cardinal $v2" ] || fail "rollback: got $(installed_version)"

step "refuse a downgrade to $v1; allow it when forced"
if as_user cardinal update --from "$t/rel1" 2>"$t/err"; then
    fail "downgrade was allowed"
fi
grep -q "refusing to downgrade" "$t/err" || fail "no downgrade message"
as_user env CARDINAL_ALLOW_DOWNGRADE=1 cardinal update --from "$t/rel1"
[ "$(installed_version)" = "cardinal $v1" ] || fail "forced downgrade: got $(installed_version)"

step "reject a tampered release"
cp -r "$devdir" "$t/tampered"
sed -i "s/$v2/0.1.0-dev.9/" "$t/tampered/manifest"
if as_user cardinal update --from "$t/tampered" 2>"$t/err"; then
    fail "tampered manifest accepted"
fi
grep -q "signature" "$t/err" || fail "no signature error"
[ "$(installed_version)" = "cardinal $v1" ] || fail "tampering changed the binary"

step "install.sh from a local directory"
as_user cardinal uninstall --keep-data
as_user sh "$repo/install.sh" "$devdir" </dev/null
[ "$(installed_version)" = "cardinal $v2" ] || fail "install.sh: got $(installed_version)"

step "uninstall keeps data; without a terminal only --keep-data goes ahead"
mkdir -p "$home/.local/share/cardinal"
echo precious >"$home/.local/share/cardinal/keys"
if as_user setsid -w cardinal uninstall --purge </dev/null 2>/dev/null; then
    fail "purge ran without confirmation"
fi
[ -x "$home/.local/bin/cardinal" ] || fail "refused purge removed the binary"
if as_user setsid -w cardinal uninstall </dev/null 2>/dev/null; then
    fail "uninstall ran without asking"
fi
[ -x "$home/.local/bin/cardinal" ] || fail "unanswered uninstall removed the binary"
as_user "$home/.local/bin/cardinal" uninstall --keep-data
[ ! -e "$home/.local/bin/cardinal" ] || fail "binary not removed"
[ ! -e "$home/.config/systemd/user/cardinal.service" ] || fail "unit not removed"
[ -f "$home/.local/share/cardinal/keys" ] || fail "data was removed"

printf '\nPASS: end-to-end install/update/rollback/uninstall\n' >&2
