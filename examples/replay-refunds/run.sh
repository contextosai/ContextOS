#!/usr/bin/env bash
# Replays an agent's refund tool calls through a local ContextOS gateway.
#   ./examples/replay-refunds/run.sh                       # the bundled sample
#   ./examples/replay-refunds/run.sh my-calls.jsonl --help  # your own calls: see the options
set -euo pipefail
cd "$(dirname "$0")/../.."
source examples/binaries.sh
contextos_binaries debug contextosd
examples/doctor.sh --quiet contextosd
if [ "$#" -eq 0 ]; then
  set -- examples/replay-refunds/sample.jsonl --refund-tool refund_payment \
    --order /order --amount /amount --customer /customer --amount-unit major --currency USD
fi
exec python3 examples/replay-refunds/replay_refunds.py "$@"
