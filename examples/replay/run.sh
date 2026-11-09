#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
source examples/binaries.sh
contextos_binaries debug contextosd
examples/doctor.sh --quiet contextosd
exec python3 examples/replay/demo.py
