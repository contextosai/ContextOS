# Sourced by the examples: `contextos_binaries <profile> <binary>...` exports
# CONTEXTOS_BIN, the directory holding those binaries. A release archive ships them in
# bin/, so its examples need no Rust toolchain; CONTEXTOS_BIN may also name your own
# directory. Otherwise they are built from source with cargo. Run from the repo or
# archive root.
contextos_binaries() {
  local profile="$1" binary
  shift
  if [ -z "${CONTEXTOS_BIN:-}" ]; then
    if [ -x bin/contextosd ]; then
      CONTEXTOS_BIN="$PWD/bin"
    else
      local target="${CARGO_TARGET_DIR:-$PWD/target}" other=release has_other=1
      [ "$profile" = release ] && other=debug
      for binary in "$@"; do [ -x "$target/$other/$binary" ] || has_other=""; done
      # Reuse a profile another example already built rather than compile a second.
      if [ -n "$has_other" ] && [ ! -x "$target/$profile/$1" ]; then profile="$other"; fi
      CONTEXTOS_BUILD_PROFILE="$profile"
      CONTEXTOS_BIN="$target/$profile"
    fi
  fi
  # Once building, later calls build what they need into the same profile.
  if [ -n "${CONTEXTOS_BUILD_PROFILE:-}" ]; then
    local packages=()
    for binary in "$@"; do packages+=(-p "$binary"); done
    echo "Building $* ($CONTEXTOS_BUILD_PROFILE); the first build takes a few minutes..." >&2
    if [ "$CONTEXTOS_BUILD_PROFILE" = release ]; then
      cargo build --release -q "${packages[@]}"
    else
      cargo build -q "${packages[@]}"
    fi
  fi
  for binary in "$@"; do
    if [ ! -x "$CONTEXTOS_BIN/$binary" ]; then
      echo "$binary not found in $CONTEXTOS_BIN (set CONTEXTOS_BIN or use a release archive)" >&2
      exit 1
    fi
  done
  export CONTEXTOS_BIN
}
