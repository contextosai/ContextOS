#!/usr/bin/env bash
# Runs one framework example against a local contextosd. Run from the repo root:
#   ./examples/frameworks/run.sh langgraph [--approval]
# Each example gets its own environment (Python: .venv via uv; Node: node_modules) on
# first use. Without a provider API key an example uses a scripted model, so the
# governed path runs anywhere; set the key its README names to use a real model.
# --approval makes the refund wait for an exact approval, which a scripted reviewer
# grants through the framework's human-in-the-loop path.
set -euo pipefail
NAME="${1:?usage: examples/frameworks/run.sh <framework>}"
DIR="examples/frameworks/$NAME"
[ -d "$DIR" ] || { echo "no example $DIR" >&2; exit 1; }
if [ -f "$DIR/requirements.txt" ]; then
  command -v uv >/dev/null || { echo "the Python examples need uv: https://docs.astral.sh/uv/" >&2; exit 1; }
  [ -x "$DIR/.venv/bin/python" ] || uv venv -q --python 3.12 "$DIR/.venv"
  uv pip install -q --python "$DIR/.venv/bin/python" -r "$DIR/requirements.txt"
  CMD=("$DIR/.venv/bin/python" "$DIR/agent.py")
else
  command -v node >/dev/null || { echo "the TypeScript examples need Node.js 24" >&2; exit 1; }
  [ -d "$DIR/node_modules" ] || npm install --prefix "$DIR" --silent --no-audit --no-fund
  CMD=(node --experimental-strip-types --no-warnings "$DIR/$(cd "$DIR" && ls agent.* | head -1)")
fi
source examples/dev-env.sh
CONTEXTOS_TOKEN="$KEY" PYTHONPATH="bindings/python:examples/frameworks/_shared" "${CMD[@]}" "${@:2}"
