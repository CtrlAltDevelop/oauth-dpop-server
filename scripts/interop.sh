#!/usr/bin/env bash
# Runs the Dart dpop_client against a real server process and a real Redis:
# a throwaway SQLite database, a fresh confidential client, `runserver`, and
# interop/dart/bin/interop.dart. The pytest interop test does the same
# in-process; this is the version that exercises the whole stack.
#
#   REDIS_URL=redis://localhost:6379/15 scripts/interop.sh
#
# Needs: uv, the Dart SDK, a reachable Redis, and dpop_client checked out
# next to this repository (../dpop_client).
set -euo pipefail

cd "$(dirname "$0")/.."
PORT="${PORT:-8765}"
ISSUER="http://127.0.0.1:${PORT}"
WORK="$(mktemp -d)"
# Git Bash on Windows hands out /tmp paths Python cannot open.
NATIVE_WORK="${WORK}"
if command -v cygpath >/dev/null 2>&1; then NATIVE_WORK="$(cygpath -m "${WORK}")"; fi

export DJANGO_DEBUG=true
export DJANGO_SECRET_KEY="interop-only-$(date +%s)"
export DATABASE_URL="sqlite:///${NATIVE_WORK}/interop.sqlite3"
export REDIS_URL="${REDIS_URL:-redis://localhost:6379/15}"
export OAUTH_ISSUER="${ISSUER}"

server_pid=""
cleanup() {
  if [ -n "${server_pid}" ]; then
    kill "${server_pid}" 2>/dev/null || true
    wait "${server_pid}" 2>/dev/null || true
  fi
  rm -rf "${WORK}" 2>/dev/null || true
}
trap cleanup EXIT

uv run python manage.py migrate --noinput >/dev/null
credentials="$(uv run python manage.py create_client "Dart interop" \
  --grant client_credentials --scope orders:read --scope orders:write --json)"
field() { uv run python -c "import json,sys; print(json.loads(sys.argv[1])[sys.argv[2]])" "${credentials}" "$1"; }
client_id="$(field client_id)"
client_secret="$(field client_secret)"

uv run python manage.py runserver "127.0.0.1:${PORT}" --noreload >"${WORK}/server.log" 2>&1 &
server_pid=$!

for _ in $(seq 1 60); do
  if curl -fsS "${ISSUER}/.well-known/oauth-authorization-server" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

(
  cd interop/dart
  dart pub get >/dev/null
  dart run bin/interop.dart \
    --issuer "${ISSUER}" --client-id "${client_id}" --client-secret "${client_secret}"
) || { echo "--- server log ---"; cat "${WORK}/server.log"; exit 1; }
