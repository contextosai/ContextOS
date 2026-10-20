#!/usr/bin/env bash
# Runs the governed agent loop against a local contextosd. Run from the repo root.
set -euo pipefail
KEY="dev-key-0123456789abcdef0123456789abcdef"
cargo build --release -q -p contextosd -p ctx
CONFIG="$(mktemp)"
HASH="$(printf '%s\n' "$KEY" | ./target/release/ctx hash-key | python3 -c 'import json,sys;print(json.load(sys.stdin)["key_sha256"])')"
sed "s|sha256:REPLACED_BY_RUN_SH|$HASH|" examples/support-refund/contextosd.toml > "$CONFIG"
export CONTEXTOS_AUDIT_SEED="$(python3 -c 'print("11"*32)')"   # development seed only
python3 examples/support-refund/dev_services.py >/dev/null & SERVICES=$!
./target/release/contextosd --config "$CONFIG" > /tmp/contextosd-agent.log 2>&1 & SERVER=$!
trap 'kill $SERVICES $SERVER 2>/dev/null; wait 2>/dev/null; rm -f "$CONFIG"' EXIT
for _ in $(seq 50); do curl -sf http://127.0.0.1:8080/readyz >/dev/null && break; sleep 0.1; done
CONTEXTOS_TOKEN="$KEY" PYTHONPATH=bindings/python python3 examples/agent-loop/agent.py
