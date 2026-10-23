#!/usr/bin/env bash
# Tower over a live runtime: starts the quickstart contextosd, runs governed agents
# (including one the kill switch refuses), starts towerd on it and checks that Tower
# sees the fleet. With --serve, keeps both running: open http://127.0.0.1:8090/tower/
# and sign in with a key from examples/tower/towerd.toml. Run from the repo root.
set -euo pipefail
source examples/dev-env.sh
contextos_binaries release towerd
[ -f tower/dist/index.html ] || (cd tower && npm ci --no-audit --no-fund -s && npm run -s build)
OPS="dev-ops-0123456789abcdef0123456789abcdef"
api() { curl -sS -H 'content-type: application/json' "$@"; }

echo "== governed agent runs"
for _ in 1 2 3; do
  CONTEXTOS_TOKEN="$KEY" PYTHONPATH=bindings/python python3 examples/agent-loop/agent.py >/dev/null
done
echo "== kill switch refuses an agent's refund"
api -H "authorization: Bearer $OPS" -X POST "$CONTEXTOS_URL/v1/revocations" \
  -d '{"kind":"capability","target":"adp_payments.issue_refund","reason":"INC-7: refunds misfiring"}' >/dev/null
CONTEXTOS_TOKEN="$KEY" PYTHONPATH=bindings/python python3 examples/agent-loop/agent.py >/dev/null 2>&1 || true

TOWER_CONFIG="$(mktemp)"
sed -e "s|127.0.0.1:RUNTIME_PORT|${CONTEXTOS_URL#http://}|" examples/tower/towerd.toml > "$TOWER_CONFIG"
export TOWER_JOURNAL_SEED="$(python3 -c 'print("22"*32)')"   # development seed only
export TOWER_SOURCE_TOKEN="dev-tower-0123456789abcdef0123456789abcd"
export TOWER_CONTROL_TOKEN="$OPS"
TOWER_LOG="$(mktemp)"
"$CONTEXTOS_BIN/towerd" --config "$TOWER_CONFIG" > "$TOWER_LOG" 2>&1 & TOWER=$!
trap 'exec 2>/dev/null; kill $TOWER $SERVICES $SERVER; wait; rm -f "$CONFIG" "$LOG" "$TOWER_CONFIG" "$TOWER_LOG"' EXIT
CISO="dev-ciso-0123456789abcdef0123456789abcde"
for _ in $(seq 100); do
  POSTURE="$(curl -sf -H "authorization: Bearer $CISO" http://127.0.0.1:8090/api/posture || true)"
  echo "$POSTURE" | python3 -c 'import json,sys; p=json.load(sys.stdin); sys.exit(0 if p["agents"]["total"] >= 1 and p["sources"][0]["verified_to"] > 0 and p["sources"][0]["revoked"] >= 1 else 1)' 2>/dev/null && break
  sleep 0.2
done
echo "== Tower's view"
echo "$POSTURE" | python3 -c '
import json,sys
p=json.load(sys.stdin)
a=p["agents"]
print("agents", a["total"], "declared", a["declared"], "reviewed", a["reviewed"], "external effects", a["external_effects"])
print("findings", p["findings"]["by_severity"])
print("verified entries", p["sources"][0]["verified_to"], "revoked", p["sources"][0]["revoked"])
assert a["total"] >= 1 and a["declared"] == 0 and p["findings"]["by_severity"].get("critical", 0) >= 1, "expected an undeclared agent with critical findings"
print("tower sees the fleet")'
if [ "${1:-}" = "--serve" ]; then
  echo "Tower: http://127.0.0.1:8090/tower/  (keys in examples/tower/towerd.toml; Ctrl-C to stop)"
  wait $TOWER
fi
