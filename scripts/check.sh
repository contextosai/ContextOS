#!/usr/bin/env bash
# The full pre-commit gate: formatting, lint, every test suite, both HTTP clients end to
# end and both examples. Each step stops the script on failure.
cd "$(dirname "$0")/.."
step() { echo "== $1"; }
fail() { echo "FAILED: $1"; exit 1; }

step fmt;     cargo fmt --all --check                                   || fail fmt
step clippy;  cargo clippy --workspace --all-targets -- -D warnings     || fail clippy
step tests;   cargo test -q --workspace                                 || fail tests
step build;   cargo build --release -q -p contextosd -p ctx             || fail build
step python;  PYTHONPATH=bindings/python python3 bindings/python/tests/test_client.py >/dev/null || fail "python client"
step node;    node bindings/node/test_client.mjs >/dev/null             || fail "node client"
step quickstart; bash examples/support-refund/run.sh >/dev/null 2>&1    || fail quickstart
step agent-loop; bash examples/agent-loop/run.sh 2>&1 | grep -q "run completed" || fail "agent loop"
step metering;   bash examples/metering-proxy/run.sh >/dev/null 2>&1   || fail "metering proxy"
echo "ALL CHECKS PASSED"
