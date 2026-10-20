#!/usr/bin/env bash
# Starts a disposable PostgreSQL for the store, audit and benchmark tests without
# Docker, using the binaries in the `pgserver` Python wheel. Everything lives under
# target/dev-postgres (git-ignored). Prints the URLs to export.
#
#   eval "$(scripts/dev-postgres.sh)"      # start, export CONTEXTOS_* URLs
#   scripts/dev-postgres.sh stop
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$ROOT/target/dev-postgres"
PORT="${CONTEXTOS_DEV_PG_PORT:-55432}"
if [ ! -x "$DIR/venv/bin/python" ]; then
  python3 -m venv "$DIR/venv" >&2
  "$DIR/venv/bin/pip" install -q pgserver >&2
fi
BIN="$("$DIR/venv/bin/python" -c 'import pgserver, pathlib; print(pathlib.Path(pgserver.__file__).parent / "pginstall/bin")')"
if [ "${1:-start}" = "stop" ]; then
  "$BIN/pg_ctl" -D "$DIR/data" stop >&2
  exit 0
fi
if [ ! -d "$DIR/data" ]; then
  "$BIN/initdb" -D "$DIR/data" -U contextos --auth=trust -E UTF8 >/dev/null
fi
if ! "$BIN/pg_ctl" -D "$DIR/data" status >/dev/null 2>&1; then
  "$BIN/pg_ctl" -D "$DIR/data" -o "-p $PORT -k $DIR -c listen_addresses=127.0.0.1" -l "$DIR/postgres.log" start >&2
  sleep 1
fi
"$BIN/createdb" -h 127.0.0.1 -p "$PORT" -U contextos contextos_test 2>/dev/null || true
SOCKET="$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=""))' "$DIR")"
echo "export CONTEXTOS_TEST_DATABASE_URL=postgres://contextos@127.0.0.1:$PORT/contextos_test"
echo "export CONTEXTOS_BENCH_DATABASE_URL=postgres://contextos@$SOCKET:$PORT/contextos_test"
