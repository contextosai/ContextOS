#!/usr/bin/env bash
# Runs the governed agent loop against a local contextosd. Run from the repo root.
set -euo pipefail
source examples/dev-env.sh
CONTEXTOS_TOKEN="$KEY" PYTHONPATH=bindings/python python3 examples/agent-loop/agent.py
