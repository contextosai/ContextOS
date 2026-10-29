#!/usr/bin/env bash
# Failure drill on PostgreSQL. CONTEXTOS_DRILL_DATABASE_URL names a database the drill
# may write to; CONTEXTOS_DRILL_PG_RESTART optionally restarts it mid-drill.
set -euo pipefail
cd "$(dirname "$0")/../.."
if [ -z "${CONTEXTOS_DRILL_DATABASE_URL:-}" ]; then
  echo "Set CONTEXTOS_DRILL_DATABASE_URL to a PostgreSQL database the drill may write to." >&2
  echo "See examples/postgres-drill/README.md for a disposable one." >&2
  exit 2
fi
source examples/binaries.sh
contextos_binaries release contextosd ctx
examples/doctor.sh --quiet contextosd ctx
exec python3 examples/postgres-drill/drill.py
