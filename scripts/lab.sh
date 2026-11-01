#!/bin/sh
# Runs the network lab (lab.py) on a debug build. With no arguments it runs
# `punch` and `people`; `trace` adds a packet capture of the easiest case.
#
#   cargo build -p cardinal && scripts/lab.sh people
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
BIN=${CARDINAL_BIN:-$HERE/../target/debug/cardinal}
HOMES=$(mktemp -d)
trap 'rm -rf "$HOMES"' EXIT
unshare -Urnm --pid --fork --kill-child --mount-proc sh -c '
  mount -t tmpfs none /run
  mkdir -p /run/netns
  exec python3 -I "$0" "$@"
' "$HERE/lab.py" "$BIN" "$HOMES" "$@"
