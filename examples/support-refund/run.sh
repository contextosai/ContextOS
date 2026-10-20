#!/usr/bin/env bash
# Quickstart: admit a run and dispatch one governed refund. Run from the repo root.
set -euo pipefail
source examples/dev-env.sh

api() { curl -sS -H "authorization: Bearer $KEY" -H 'content-type: application/json' "$@"; }
echo "== admit run"
ADMITTED="$(api -X POST $CONTEXTOS_URL/v1/runs --data @examples/support-refund/requests/run.json)"
echo "$ADMITTED" | python3 -c 'import json,sys;r=json.load(sys.stdin);print({k:r[k] for k in ("run_id","executor_generation","features")})'
# The executor presents its generation with every effectful request; a takeover by
# another executor makes it stale.
GENERATION="$(echo "$ADMITTED" | python3 -c 'import json,sys;print(json.load(sys.stdin)["executor_generation"])')"
exe() { api -H "contextos-executor-generation: $GENERATION" "$@"; }
echo "== dispatch refund"
exe -X POST $CONTEXTOS_URL/v1/runs/run_demo_1/tool-calls --data @examples/support-refund/requests/tool_call.json \
  | python3 -c 'import json,sys;r=json.load(sys.stdin);print({"status":r["result"]["status"],"output":r["result"]["output"],"audit":r["report"]["audit_sequences"]})'
echo "== replay the same operation (must not refund twice)"
exe -X POST $CONTEXTOS_URL/v1/runs/run_demo_1/tool-calls --data @examples/support-refund/requests/tool_call.json \
  | python3 -c 'import json,sys;r=json.load(sys.stdin);print({"status":r["result"]["status"],"reasons":r["report"]["reason_codes"]})'
echo "== verify audit chain"
api $CONTEXTOS_URL/v1/audit/verify; echo
