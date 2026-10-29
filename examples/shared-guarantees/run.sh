#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
source examples/binaries.sh
contextos_binaries debug contextosd ctx
examples/doctor.sh --quiet contextosd ctx
exec python3 examples/shared-guarantees/demo.py
