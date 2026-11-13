#!/usr/bin/env bash
# Offline pack checks: the built 5.3.0 pack matches its sources, and each pack meets
# its tests. Runs from a release archive or a checkout, from any directory. Uses ctx
# from $CTX, else $CONTEXTOS_BIN, else the archive's bin/, else this checkout's
# target/release or target/debug (cargo build -p ctx), else PATH.
set -euo pipefail
cd "$(dirname "$0")"
if [ -z "${CTX:-}" ]; then
    for candidate in "${CONTEXTOS_BIN:+$CONTEXTOS_BIN/ctx}" ../../bin/ctx ../../target/release/ctx ../../target/debug/ctx; do
        if [ -n "$candidate" ] && [ -x "$candidate" ]; then CTX="$candidate"; break; fi
    done
fi
[ -n "${CTX:-}" ] || CTX="$(command -v ctx || true)"
[ -n "$CTX" ] && [ -x "$CTX" ] || {
    echo "ctx not found: run from a release archive, build it (cargo build -p ctx) or set CTX" >&2
    exit 2
}
CTX="$(cd "$(dirname "$CTX")" && pwd)/$(basename "$CTX")"
"$CTX" build authoring/pack.source.json --check authoring/pack-5.3.0.json >/dev/null
"$CTX" test --pack pack.json pack_test.json >/dev/null
"$CTX" test --pack authoring/pack-5.3.0.json authoring/pack_test.json >/dev/null
# The pack-authoring skill's checks run on the example, so its commands stay real.
CTX="$CTX" bash ../../skills/contextos-pack-authoring/scripts/check_pack.sh --pack pack.json --tests pack_test.json \
    --run requests/run.json --roles support_agent,supervisor >/dev/null
CTX="$CTX" bash ../../skills/contextos-pack-authoring/scripts/check_pack.sh --pack authoring/pack-5.3.0.json \
    --tests authoring/pack_test.json --run requests/run.json >/dev/null
echo "example packs checked"
