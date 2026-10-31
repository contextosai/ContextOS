#!/usr/bin/env bash
# Runs contextosd locally with the quickstart's support pack and synthetic services
# (orders and payments providers, identity, controls and approvals), so you can point
# your own agent at it. Stops on Ctrl-C. Development only: fixed seed, loopback, fake
# providers. Run from the repo or release-archive root.
set -euo pipefail
cd "$(dirname "$0")/.."
source examples/dev-env.sh
cat <<INFO
contextosd is ready.

  export CONTEXTOS_URL=$CONTEXTOS_URL
  export CONTEXTOS_TOKEN=$KEY

Admit a run with the sample body, then call its governed tools:

  curl -s -X POST "\$CONTEXTOS_URL/v1/runs" -H "Authorization: Bearer \$CONTEXTOS_TOKEN" \\
       -H 'Content-Type: application/json' -d @examples/support-refund/requests/run.json

Pack: examples/support-refund/pack.json   Capabilities: examples/support-refund/capabilities/
Python client: PYTHONPATH=bindings/python (see bindings/python/README.md)
Press Ctrl-C to stop.
INFO
wait "$SERVER"
