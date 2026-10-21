#!/usr/bin/env bash
# Tests the metering proxy against a local contextosd and a fake model API. Run from
# the repo root.
set -euo pipefail
source examples/dev-env.sh
CONTEXTOS_TOKEN="$KEY" PYTHONPATH=bindings/python python3 examples/metering-proxy/test_proxy.py
