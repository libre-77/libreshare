#!/usr/bin/env sh
# libreshare dev helper. Zero external deps for dev/test; `build` needs npm.
#
#   ./run.sh dev     start blossom-mock (:3000) + static web (:8080), Ctrl-C stops both
#   ./run.sh test    crypto + gift-wrap unit tests, then upload/download e2e
#   ./run.sh build   regenerate vendor/nostr-tools.js from vendor/_entry.js
#   ./run.sh help    this text
set -eu

ROOT=$(CDPATH= cd "$(dirname "$0")" && pwd)
cd "$ROOT"

WEB_PORT=${WEB_PORT:-8080}
STORE_PORT=${STORE_PORT:-3000}
NOSTR_VERSION=${NOSTR_VERSION:-2.23.9}

die() { echo "error: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

cmd_dev() {
  have node || die "node not found"
  pids=""
  # Kill both children on exit / Ctrl-C, even if one already died.
  trap 'echo; echo "stopping…"; for p in $pids; do kill "$p" 2>/dev/null || true; done; exit 0' INT TERM

  echo "storage  : http://localhost:$STORE_PORT   (blossom mock, no auth)"
  PORT="$STORE_PORT" node server/blossom-mock.js &
  pids="$pids $!"

  echo "web      : http://localhost:$WEB_PORT"
  PORT="$WEB_PORT" node server/static.js &
  pids="$pids $!"

  echo "open http://localhost:$WEB_PORT  —  Ctrl-C to stop"
  # Wait on children; exits when either server dies.
  wait
}

cmd_test() {
  have node || die "node not found"
  echo "== unit: crypto =="
  node test/crypto.test.mjs
  echo "== unit: descriptor =="
  node test/descriptor.test.mjs
  echo "== unit: gift-wrap =="
  node test/nostr.test.mjs

  echo "== e2e: upload/download =="
  e2e_port=${E2E_PORT:-3111}
  PORT="$e2e_port" node server/blossom-mock.js &
  e2e_pid=$!
  trap 'kill "$e2e_pid" 2>/dev/null || true' EXIT INT TERM
  # Give the mock a moment to bind the port.
  i=0
  while [ "$i" -lt 20 ]; do
    if have curl && curl -sf "http://localhost:$e2e_port/" >/dev/null 2>&1; then break; fi
    i=$((i + 1)); sleep 0.2
  done
  SERVER="http://localhost:$e2e_port" node test/e2e.test.mjs
  kill "$e2e_pid" 2>/dev/null || true
  trap - EXIT INT TERM
  echo "all tests passed"
}

cmd_build() {
  have npm || die "npm not found (needed only to rebuild the vendor bundle)"
  [ -f vendor/_entry.js ] || die "vendor/_entry.js missing"
  echo "installing nostr-tools@$NOSTR_VERSION + esbuild (no-save)…"
  npm install --no-save "nostr-tools@$NOSTR_VERSION" esbuild >/dev/null
  echo "bundling vendor/nostr-tools.js…"
  node_modules/.bin/esbuild vendor/_entry.js \
    --bundle --format=esm --minify --outfile=vendor/nostr-tools.js
  echo "done: $(wc -c < vendor/nostr-tools.js | tr -d ' ') bytes"
}

case "${1:-help}" in
  dev)   cmd_dev ;;
  test)  cmd_test ;;
  build) cmd_build ;;
  help|-h|--help) sed -n '2,7p' "$0" | sed 's/^# \{0,1\}//' ;;
  *)     die "unknown command '$1' (try: dev, test, build, help)" ;;
esac
