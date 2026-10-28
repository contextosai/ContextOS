#!/usr/bin/env bash
# Runs a release archive on its own, as a user would: unpacks it outside the checkout,
# starts each shipped executable, then runs the shared-guarantees demo with only
# /usr/bin and /bin on PATH (no cargo). Starting every executable matters: one built
# against a newer glibc than the host's fails before main, and the demo alone would
# not reach towerd. Needs Python 3.9+, Bash and curl.
#
#   scripts/smoke-archive.sh <archive.tar.gz>
set -euo pipefail
archive="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
tar xzf "$archive" -C "$work"
cd "$work"/*/
for bin in contextosd ctx towerd; do
    ./bin/"$bin" --version
done
env PATH="/usr/bin:/bin" ./examples/shared-guarantees/run.sh
