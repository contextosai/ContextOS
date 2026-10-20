# Sourced by the examples: starts the development services and contextosd on free
# ports, waits until the server is ready (or exits with its log), and exports
# CONTEXTOS_URL, KEY and the cleanup trap. Run from the repo root.
KEY="dev-key-0123456789abcdef0123456789abcdef"
cargo build --release -q -p contextosd -p ctx
read -r SERVER_PORT P1 P2 P3 P4 < <(python3 -c '
import socket
socks = [socket.socket() for _ in range(5)]
for s in socks: s.bind(("127.0.0.1", 0))
print(*[s.getsockname()[1] for s in socks])
for s in socks: s.close()')
export CONTEXTOS_DEV_PORTS="$P1,$P2,$P3,$P4"
CONFIG="$(mktemp)"
LOG="$(mktemp)"
HASH="$(printf '%s\n' "$KEY" | ./target/release/ctx hash-key | python3 -c 'import json,sys;print(json.load(sys.stdin)["key_sha256"])')"
sed -e "s|sha256:REPLACED_BY_RUN_SH|$HASH|" -e "s|127.0.0.1:8080|127.0.0.1:$SERVER_PORT|" \
    -e "s|127.0.0.1:7701|127.0.0.1:$P1|g" -e "s|127.0.0.1:7702|127.0.0.1:$P2|g" \
    -e "s|127.0.0.1:7703|127.0.0.1:$P3|g" -e "s|127.0.0.1:7704|127.0.0.1:$P4|g" \
    examples/support-refund/contextosd.toml > "$CONFIG"
export CONTEXTOS_AUDIT_SEED="$(python3 -c 'print("11"*32)')"   # development seed only; use [audit.kms] in production
python3 examples/support-refund/dev_services.py >/dev/null & SERVICES=$!
./target/release/contextosd --config "$CONFIG" > "$LOG" 2>&1 & SERVER=$!
trap 'kill $SERVICES $SERVER 2>/dev/null; wait 2>/dev/null; rm -f "$CONFIG" "$LOG"' EXIT
export CONTEXTOS_URL="http://127.0.0.1:$SERVER_PORT"
READY=""
for _ in $(seq 100); do curl -sf "$CONTEXTOS_URL/readyz" >/dev/null && READY=1 && break; sleep 0.1; done
if [ -z "$READY" ]; then echo "contextosd did not become ready:" >&2; cat "$LOG" >&2; exit 1; fi
