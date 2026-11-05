#!/usr/bin/env bash
# Offline pack checks: the built 5.3.0 pack matches its sources, and each pack meets
# its tests. Needs a built ctx (cargo build --release -p ctx).
set -euo pipefail
cd "$(dirname "$0")"
CTX="$(cd "$(dirname "${CTX:-../../target/release/ctx}")" && pwd)/$(basename "${CTX:-../../target/release/ctx}")"
"$CTX" build authoring/pack.source.json --check authoring/pack-5.3.0.json >/dev/null
"$CTX" test --pack pack.json pack_test.json >/dev/null
"$CTX" test --pack authoring/pack-5.3.0.json authoring/pack_test.json >/dev/null
# The pack-authoring skill's checks run on the example, so its commands stay real.
CTX="$CTX" bash ../../skills/contextos-pack-authoring/scripts/check_pack.sh --pack pack.json --tests pack_test.json \
    --run requests/run.json --roles support_agent,supervisor >/dev/null
CTX="$CTX" bash ../../skills/contextos-pack-authoring/scripts/check_pack.sh --pack authoring/pack-5.3.0.json \
    --tests authoring/pack_test.json --run requests/run.json >/dev/null
echo "example packs checked"
