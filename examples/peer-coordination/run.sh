#!/usr/bin/env bash
# Two peers choose work on one admitted team's board; no model credentials needed.
set -euo pipefail
source examples/dev-env.sh
CONTEXTOS_TOKEN="$KEY" PYTHONPATH=bindings/python python3 examples/peer-coordination/peers.py
