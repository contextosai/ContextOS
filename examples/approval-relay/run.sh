#!/usr/bin/env bash
# The approval relay's unit tests, then a real gateway asking it for approvals.
set -euo pipefail
cd "$(dirname "$0")/../.."
source examples/binaries.sh
contextos_binaries debug contextosd
export CONTEXTOS_BIN
python3 -m unittest discover -s examples/approval-relay -p 'test_*.py'
python3 examples/approval-relay/e2e.py
