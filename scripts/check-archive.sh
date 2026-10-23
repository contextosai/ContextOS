#!/usr/bin/env bash
# Packages a release archive from the current release build and Tower UI, unpacks it
# outside the checkout and runs the shared-guarantees demo from it without cargo on
# PATH. Run from the repo root after building both.
set -euo pipefail
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
scripts/package-release.sh "$WORK/contextos-check" target/release tower/dist
mkdir "$WORK/unpacked"
tar xzf "$WORK/contextos-check.tar.gz" -C "$WORK/unpacked"
cd "$WORK/unpacked/contextos-check"
env PATH="/usr/bin:/bin" ./examples/shared-guarantees/run.sh
