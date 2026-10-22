#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
cargo build --quiet -p contextosd -p ctx
exec python3 examples/shared-guarantees/demo.py
