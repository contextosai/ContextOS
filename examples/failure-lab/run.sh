#!/usr/bin/env bash
# Records the Agent Failure Lab's story (lab/story.js) from a real contextosd run;
# with --check, fails instead if the runtime's behaviour no longer matches it.
set -euo pipefail
cd "$(dirname "$0")/../.."
source examples/binaries.sh
contextos_binaries debug contextosd ctx
examples/doctor.sh --quiet contextosd ctx
exec python3 examples/failure-lab/record.py "$@"
