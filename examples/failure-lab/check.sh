#!/usr/bin/env bash
# Fails if the gateway's behaviour no longer matches the Agent Failure Lab's recording.
exec "$(dirname "$0")/run.sh" --check
