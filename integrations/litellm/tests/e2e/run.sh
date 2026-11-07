#!/usr/bin/env bash
# End-to-end test of the LiteLLM metering callback: a real LiteLLM proxy, a live
# contextosd and a fake model provider. Run from the repository root.
#
# LITELLM_PYTHON names a Python that has the test requirements installed
# (integrations/litellm/requirements-test.txt); by default a virtual environment is
# made with uv in a temporary directory.
set -euo pipefail
source examples/dev-env.sh
PY="${LITELLM_PYTHON:-}"
if [ -z "$PY" ]; then
  VENV="$(mktemp -d)/venv"
  uv venv -q --python 3.12 "$VENV"
  uv pip install -q --python "$VENV/bin/python" -r integrations/litellm/requirements-test.txt
  PY="$VENV/bin/python"
fi
uv pip install -q --python "$PY" --no-deps -e integrations/litellm
CONTEXTOS_TOKEN="$KEY" PYTHONPATH=bindings/python "$PY" integrations/litellm/tests/e2e/metering_e2e.py
