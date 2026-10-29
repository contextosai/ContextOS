#!/usr/bin/env bash
# Preflight for the examples and a local runtime: checks this machine can run the
# binaries before anything is launched, and says what to do instead when it cannot.
# It only reads system facts and runs each binary's `--version` (and, with --config,
# `contextosd --check-config`); it downloads nothing and needs no privileges.
# Run from the repo or archive root:
#
#   examples/doctor.sh [--quiet] [--config <contextosd.toml>] [binary...]
#
# Binaries default to contextosd, ctx and towerd, found as the examples find them:
# CONTEXTOS_BIN, else an archive's bin/, else target/debug. Exits 1 if a check fails.
set -uo pipefail
quiet=false
config=
binaries=()
while [ $# -gt 0 ]; do
  case "$1" in
    --quiet) quiet=true ;;
    --config) config="${2:?--config needs a path}"; shift ;;
    -*) echo "usage: examples/doctor.sh [--quiet] [--config <path>] [binary...]" >&2; exit 2 ;;
    *) binaries+=("$1") ;;
  esac
  shift
done
[ ${#binaries[@]} -gt 0 ] || binaries=(contextosd ctx towerd)
if [ -z "${CONTEXTOS_BIN:-}" ]; then
  if [ -x bin/contextosd ]; then CONTEXTOS_BIN="$PWD/bin"; else CONTEXTOS_BIN="$PWD/target/debug"; fi
fi

failed=0
summary=()
ok() { $quiet || echo "ok:   $1"; summary+=("$1"); }
warn() { echo "warn: $1"; }
# Each failure names one fix; the fixes are listed once, after the checks.
fixes=()
fail() {
  echo "fail: $1"
  failed=1
  case " ${fixes[*]-} " in *" $2 "*) ;; *) fixes+=("$2") ;; esac
}
source_build="build_from_source"

# Platform. Release archives exist for Linux x86-64/ARM64 with glibc 2.28+ and macOS
# on Apple Silicon.
os="$(uname -s)" arch="$(uname -m)" platform_ok=true
platform="$os $arch"
if [ "$os" = Linux ]; then
  libc="$(getconf GNU_LIBC_VERSION 2>/dev/null)"
  if [ -z "$libc" ]; then
    fail "$platform without GNU libc (for example Alpine/musl): the Linux archives need glibc 2.28+" "$source_build"
    platform_ok=false
  else
    version="${libc#glibc }"
    if [ "$(printf '%s\n2.28\n' "$version" | sort -t. -k1,1n -k2,2n | head -1)" != 2.28 ]; then
      fail "$platform with glibc $version: the Linux archives need glibc 2.28+" "$source_build"
      platform_ok=false
    else
      platform="$platform, glibc $version"
      ok "$platform"
    fi
  fi
else
  ok "$platform"
fi

# Every binary starts. A binary built for a newer glibc or another platform fails
# before main, which is exactly what --version catches.
versions=()
for binary in "${binaries[@]}"; do
  path="$CONTEXTOS_BIN/$binary"
  if [ ! -x "$path" ]; then
    fail "$binary not found in $CONTEXTOS_BIN" find_binaries
    continue
  fi
  if ! $platform_ok; then
    echo "skip: $binary (unsupported platform)"
    continue
  fi
  if output="$("$path" --version 2>&1)"; then
    versions+=("${output##* }")
    ok "$output"
  elif [[ "$output" == *GLIBC_* ]]; then
    needed="$(grep -o 'GLIBC_[0-9.]*' <<<"$output" | sort -uV | tail -1)"
    fail "$binary needs ${needed/_/ } (this system: ${libc:-unknown})" "$source_build"
  else
    fail "$binary does not start: $(head -1 <<<"$output") (is this the $os $arch archive?)" "$source_build"
  fi
done
if [ ${#versions[@]} -gt 1 ] && [ "$(printf '%s\n' "${versions[@]}" | sort -u | wc -l)" -gt 1 ]; then
  fail "binaries report different versions (${versions[*]})" one_build
fi

# The examples are driven by Python 3.9+; some also use curl.
if command -v python3 >/dev/null 2>&1 && python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))' 2>/dev/null; then
  ok "$(python3 --version 2>&1)"
else
  fail "Python 3.9+ not found as python3: the examples need it" python
fi
command -v curl >/dev/null 2>&1 || warn "curl not found: the support-refund and Tower examples use it"

if [ -n "$config" ]; then
  if output="$("$CONTEXTOS_BIN/contextosd" --check-config "$config" 2>&1)"; then
    $quiet || echo "${output//ok: /ok:   }"
    summary+=("$config valid")
  else
    fail "$output" config
  fi
fi

if [ "$failed" -ne 0 ]; then
  echo "Preflight failed; nothing was started. To fix:"
  for fix in "${fixes[@]}"; do
    case "$fix" in
      build_from_source)
        echo "- Build from source: install the Rust toolchain named in rust-toolchain.toml, run"
        echo "  cargo build --release -p contextosd -p ctx -p towerd"
        echo "  then export CONTEXTOS_BIN=\$PWD/target/release" ;;
      find_binaries)
        echo "- Run from a release archive's root, set CONTEXTOS_BIN to the binaries' directory," \
          "or run an example's run.sh in a source checkout to build them with cargo." ;;
      one_build) echo "- Use the binaries from one archive or one build." ;;
      python) echo "- Install Python 3.9 or later and put python3 on PATH." ;;
      config) echo "- Fix the configuration reported above; see docs/GUIDE.md." ;;
    esac
  done
  exit 1
fi
if $quiet; then
  echo "Preflight passed: ContextOS ${versions[0]-} on ${summary[0]}; $(python3 --version 2>&1)."
else
  echo "Preflight passed."
fi
