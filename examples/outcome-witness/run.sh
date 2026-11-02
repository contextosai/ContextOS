#!/usr/bin/env bash
# A refund is done when the refund ledger says it posted (an outcome contract).
set -euo pipefail
cd "$(dirname "$0")/../.."
source examples/binaries.sh
contextos_binaries debug contextosd ctx
exec python3 examples/outcome-witness/pilot.py
