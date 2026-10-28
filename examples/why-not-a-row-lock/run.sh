#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
source examples/binaries.sh
contextos_binaries debug contextosd ctx
exec python3 examples/why-not-a-row-lock/demo.py
