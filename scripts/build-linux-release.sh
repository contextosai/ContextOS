#!/usr/bin/env bash
# Builds the Linux release executables against glibc 2.28 (AlmaLinux 8, supported to
# 2029), so the archive runs on RHEL/Alma/Rocky 8+, Debian 10+ and Ubuntu 20.04+
# rather than only on the CI image. Run it inside almalinux:8 with the checkout
# mounted, as the release workflow does:
#
#   docker run --rm -v "$PWD:/src" -w /src almalinux:8 \
#       scripts/build-linux-release.sh x86_64-unknown-linux-gnu
#
# The executables land in ${CARGO_TARGET_DIR:-target}/<target>/release.
set -euo pipefail
target="$1"
baseline=2.28

# The official repository rather than the mirror list: a release should not depend on
# which mirror answers. Generous timeouts for its large metadata.
sed -i -e 's/^mirrorlist=/#mirrorlist=/' -e 's/^# *baseurl=/baseurl=/' /etc/yum.repos.d/almalinux*.repo
dnf install -y -q --setopt=retries=10 --setopt=timeout=300 --setopt=minrate=1 \
    gcc gcc-c++ make cmake perl binutils >/dev/null

# The pinned toolchain, from a rustup-init checked against its published digest.
toolchain=$(sed -n 's/^channel = "\(.*\)"/\1/p' rust-toolchain.toml)
url="https://static.rust-lang.org/rustup/dist/$target/rustup-init"
curl -sSfL -o /tmp/rustup-init "$url"
echo "$(curl -sSfL "$url.sha256" | awk '{print $1}')  /tmp/rustup-init" | sha256sum -c --quiet -
chmod +x /tmp/rustup-init
/tmp/rustup-init -y -q --no-modify-path --profile minimal --default-toolchain "$toolchain"
export PATH="$HOME/.cargo/bin:$PATH"
# Build with the pinned version only; the toolchain file's extra components and
# wasm target are for development, not for these executables.
export RUSTUP_TOOLCHAIN="$toolchain"

cargo build --release --locked --target "$target" -p contextosd -p ctx -p towerd
scripts/check-glibc.sh "${CARGO_TARGET_DIR:-target}/$target/release" "$baseline"
