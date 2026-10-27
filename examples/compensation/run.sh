#!/usr/bin/env bash
# A workflow fails halfway; its applied effects are compensated, newest first.
set -euo pipefail
cd "$(dirname "$0")/../.."
source examples/binaries.sh
contextos_binaries debug contextosd ctx
exec python3 examples/compensation/saga.py
