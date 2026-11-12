#!/usr/bin/env bash
# An evaluation platform judges a candidate agent, and its verdicts gate the release.
set -euo pipefail
cd "$(dirname "$0")/../.."
source examples/binaries.sh
contextos_binaries debug contextosd ctx
exec python3 examples/evaluation-loop/pilot.py
