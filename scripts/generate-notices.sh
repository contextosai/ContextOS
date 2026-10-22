#!/usr/bin/env bash
# Run after npm ci --prefix tower. Install cargo-about 0.9.2 with --features cli.
set -euo pipefail
cd "$(dirname "$0")/.."
output=$(mktemp)
trap 'rm -f "$output"' EXIT
cargo about generate --locked --all-features --workspace --fail third-party-notices.hbs > "$output"
node scripts/ui-notices.mjs >> "$output"
# Normalize line endings and trailing layout whitespace across dependency archives.
python3 - "$output" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
p.write_text("\n".join(line.rstrip(" \t\r") for line in p.read_text().split("\n")).rstrip("\n") + "\n")
PY
if [[ "${1:-}" == "--check" ]]; then
    diff -u THIRD_PARTY_NOTICES.txt "$output"
else
    cp "$output" THIRD_PARTY_NOTICES.txt
fi
