#!/usr/bin/env bash
# Quickstart: admit a run and dispatch one governed refund. Run from the repo root.
set -euo pipefail
KEY="dev-key-0123456789abcdef0123456789abcdef"
cargo build --release -q -p contextosd -p ctx
CONFIG="$(mktemp)"
HASH="$(printf '%s\n' "$KEY" | ./target/release/ctx hash-key | python3 -c 'import json,sys;print(json.load(sys.stdin)["key_sha256"])')"
sed "s|sha256:REPLACED_BY_RUN_SH|$HASH|" examples/support-refund/contextosd.toml > "$CONFIG"
export CONTEXTOS_AUDIT_SEED="$(python3 -c 'print("11"*32)')"   # development seed; use your KMS in production

python3 examples/support-refund/dev_services.py & SERVICES=$!
./target/release/contextosd --config "$CONFIG" > /tmp/contextosd-quickstart.log 2>&1 & SERVER=$!
trap 'kill $SERVICES $SERVER 2>/dev/null; wait 2>/dev/null; rm -f "$CONFIG"' EXIT
for _ in $(seq 50); do curl -sf http://127.0.0.1:8080/readyz >/dev/null && break; sleep 0.1; done

api() { curl -sS -H "authorization: Bearer $KEY" -H 'content-type: application/json' "$@"; }
echo "== admit run"
ADMITTED="$(api -X POST http://127.0.0.1:8080/v1/runs --data @examples/support-refund/requests/run.json)"
echo "$ADMITTED" | python3 -c 'import json,sys;r=json.load(sys.stdin);print({k:r[k] for k in ("run_id","executor_generation","features")})'
# The executor presents its generation with every effectful request; a takeover by
# another executor makes it stale.
GENERATION="$(echo "$ADMITTED" | python3 -c 'import json,sys;print(json.load(sys.stdin)["executor_generation"])')"
exe() { api -H "contextos-executor-generation: $GENERATION" "$@"; }
echo "== dispatch refund"
exe -X POST http://127.0.0.1:8080/v1/runs/run_demo_1/tool-calls --data @examples/support-refund/requests/tool_call.json \
  | python3 -c 'import json,sys;r=json.load(sys.stdin);print({"status":r["result"]["status"],"output":r["result"]["output"],"audit":r["report"]["audit_sequences"]})'
echo "== replay the same operation (must not refund twice)"
exe -X POST http://127.0.0.1:8080/v1/runs/run_demo_1/tool-calls --data @examples/support-refund/requests/tool_call.json \
  | python3 -c 'import json,sys;r=json.load(sys.stdin);print({"status":r["result"]["status"],"reasons":r["report"]["reason_codes"]})'
echo "== verify audit chain"
api http://127.0.0.1:8080/v1/audit/verify; echo
