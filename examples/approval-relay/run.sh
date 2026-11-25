#!/usr/bin/env bash
# The approval relay's unit tests, then a real gateway asking it for approvals. Run from
# the repo root after building contextosd.
set -euo pipefail
python3 -m unittest discover -s examples/approval-relay -p 'test_*.py'
python3 examples/approval-relay/e2e.py
