#!/usr/bin/env bash
# Packages a release archive from the current release build and Tower UI, unpacks it
# outside the checkout and runs the shared-guarantees demo from it without cargo on
# PATH. Run from the repo root after building both.
set -euo pipefail
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
scripts/package-release.sh "$WORK/contextos-check" target/release tower/dist
mkdir "$WORK/unpacked"
tar xzf "$WORK/contextos-check.tar.gz" -C "$WORK/unpacked"
cd "$WORK/unpacked/contextos-check"
# Every path the README's "Govern your own agent" section names ships.
for path in examples/dev-server.sh examples/support-refund/requests/run.json bindings/python/README.md \
    docs/GLOSSARY.md docs/integrations/README.md; do
  [ -e "$path" ] || { echo "release archive lacks $path" >&2; exit 1; }
done
env PATH="/usr/bin:/bin" ./examples/shared-guarantees/run.sh
env PATH="/usr/bin:/bin" ./examples/peer-coordination/run.sh
# The local server for your own agent starts from the archive and is reachable.
env PATH="/usr/bin:/bin" ./examples/dev-server.sh > "$WORK/dev-server.log" 2>&1 & DEV=$!
for _ in $(seq 100); do grep -q "is ready" "$WORK/dev-server.log" && break; sleep 0.1; done
url="$(sed -n 's/^  export CONTEXTOS_URL=//p' "$WORK/dev-server.log")"
kill -TERM $DEV; wait $DEV 2>/dev/null || true
[ -n "$url" ] || { cat "$WORK/dev-server.log" >&2; echo "dev-server did not start from the archive" >&2; exit 1; }
