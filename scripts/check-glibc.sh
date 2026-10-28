#!/usr/bin/env bash
# Fails if a Linux release executable needs a glibc newer than the supported baseline.
# A binary linked against a newer glibc starts only where that glibc is installed and
# fails before main with "GLIBC_x.y not found", so this is checked on the binaries
# themselves rather than inferred from the build image.
#
#   scripts/check-glibc.sh <dir with contextosd, ctx, towerd> <max version, e.g. 2.31>
set -euo pipefail
dir="$1"
max="$2"
status=0
for bin in contextosd ctx towerd; do
    needed=$(objdump -T "$dir/$bin" | grep -o 'GLIBC_[0-9][0-9.]*' | sed 's/GLIBC_//' | sort -uV | tail -1)
    if [[ -z "$needed" ]]; then
        echo "$bin: no versioned glibc symbols found" >&2
        status=1
    elif [[ "$(printf '%s\n%s\n' "$needed" "$max" | sort -V | tail -1)" != "$max" ]]; then
        echo "$bin needs glibc $needed; the supported baseline is $max" >&2
        status=1
    else
        echo "$bin: needs glibc $needed (baseline $max)"
    fi
done
exit "$status"
