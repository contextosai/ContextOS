#!/usr/bin/env bash
# Assembles a self-contained release archive: the binaries in bin/, the Tower UI in
# tower/dist, the Python HTTP client, the runnable examples and the docs, so the
# examples run with only Python 3.9+, Bash and curl (Node only for frameworks, which
# are not included). Run from the repo root:
#   scripts/package-release.sh <name> <binary-dir> <tower-dist>
# Writes <name>.tar.gz and <name>.tar.gz.sha256 beside <name>.
set -euo pipefail
NAME="${1:?usage: scripts/package-release.sh <name> <binary-dir> <tower-dist>}"
BIN="${2:?binary directory}"
UI="${3:?tower UI build directory}"
[ -f "$UI/index.html" ] || { echo "no Tower UI build in $UI (cd tower && npm ci && npm run build)" >&2; exit 1; }

rm -rf "$NAME"
mkdir -p "$NAME/bin" "$NAME/tower"
for binary in contextosd ctx towerd; do
  [ -x "$BIN/$binary" ] || { echo "$BIN/$binary is missing" >&2; exit 1; }
  cp "$BIN/$binary" "$NAME/bin/"
done
cp -R "$UI" "$NAME/tower/dist"
# Files git would commit (tracked or new, never ignored), so local caches and virtual
# environments never ship.
git ls-files -z --cached --others --exclude-standard -- \
  README.md SECURITY.md LICENSE LICENSE-docs NOTICE TRADEMARKS.md THIRD_PARTY_NOTICES.txt docs \
  examples/binaries.sh examples/dev-env.sh examples/doctor.sh examples/support-refund examples/shared-guarantees \
  examples/agent-loop examples/peer-coordination examples/compensation examples/why-not-a-row-lock examples/metering-proxy examples/tower \
  bindings/python/contextos/__init__.py bindings/python/contextos/client.py bindings/python/contextos/aio.py \
  | tar --null -T - -cf - | tar -xf - -C "$NAME"

# Members and the checksum line name only the archive's own directory.
(cd "$(dirname "$NAME")" && base="$(basename "$NAME")" \
  && tar czf "$base.tar.gz" "$base" && shasum -a 256 "$base.tar.gz" > "$base.tar.gz.sha256")
