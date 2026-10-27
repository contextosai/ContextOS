#!/usr/bin/env bash
# The full pre-commit gate: formatting, lint, every test suite, the Tower UI, both HTTP
# clients end to end, the examples (including Tower over a live runtime) and a release
# archive run on its own. Each step stops the script on failure.
set -euo pipefail
cd "$(dirname "$0")/.."
step() { echo "== $1"; }
fail() { echo "FAILED: $1"; exit 1; }

check_example() {
    local output
    # Wait for the producer and check its exit status before checking the marker.
    # Piping into grep -q can hide failure or terminate a successful producer early.
    if ! output=$(bash "$1" 2>&1); then
        printf '%s\n' "$output" >&2
        return 1
    fi
    if [[ "$output" != *"$2"* ]]; then
        printf '%s\nMissing expected output: %s\n' "$output" "$2" >&2
        return 1
    fi
}

step script-tests; python3 -m unittest discover -s scripts -p 'test_*.py' || fail "script tests"
step properties; python3 scripts/check_properties.py                    || fail "property catalog"
step fmt;     cargo fmt --all --check                                   || fail fmt
step clippy;  cargo clippy --workspace --all-targets -- -D warnings     || fail clippy
# The OTLP integration test observes INFO request spans, independently of shell logging preferences.
step tests;   RUST_LOG=info cargo test -q --workspace                    || fail tests
step build;   cargo build --release -q -p contextosd -p ctx -p towerd   || fail build
step tower;   (cd tower && npm ci --no-audit --no-fund -s && npm run -s build >/dev/null && npm test -s >/dev/null) || fail "tower console"
step python;  PYTHONPATH=bindings/python python3 bindings/python/tests/test_client.py >/dev/null || fail "python client"
step node;    node bindings/node/test_client.mjs >/dev/null             || fail "node client"
step quickstart; bash examples/support-refund/run.sh >/dev/null 2>&1    || fail quickstart
step shared-guarantees; check_example examples/shared-guarantees/run.sh "Offline audit verification:" || fail "shared guarantees"
step agent-loop; check_example examples/agent-loop/run.sh "run completed" || fail "agent loop"
step peer-coordination; check_example examples/peer-coordination/run.sh "peer coordination complete" || fail "peer coordination"
step compensation; check_example examples/compensation/run.sh "saga compensated" || fail "compensation"
step metering;   bash examples/metering-proxy/run.sh >/dev/null 2>&1   || fail "metering proxy"
step tower-e2e;  check_example examples/tower/run.sh "tower sees the fleet" || fail "tower example"
step archive;    check_example scripts/check-archive.sh "Offline audit verification:" || fail "release archive"
echo "ALL CHECKS PASSED"
