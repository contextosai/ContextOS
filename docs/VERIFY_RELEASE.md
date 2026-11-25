# Verify a release

Every release asset can be checked three independent ways before you run it: its
checksum, its build provenance, and a Sigstore signature tied to this repository's
release workflow. None of them needs a key from us.

## Archives, SBOMs and packages

```sh
tag=v0.1.0-alpha.23
asset=contextos-$tag-aarch64-apple-darwin.tar.gz

# 1. The checksum published next to it.
shasum -a 256 -c "$asset.sha256"

# 2. Build provenance: built by this repository's release workflow, from the tag.
gh attestation verify "$asset" --repo contextosai/ContextOS

# 3. The Sigstore signature (keyless): signed by the release workflow on a tag.
cosign verify-blob "$asset" \
  --bundle "$asset.sigstore.json" \
  --certificate-identity-regexp '^https://github\.com/contextosai/ContextOS/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The SBOMs (`*.cdx.json`), wheels and the npm tarball attached to the release carry a
`.sigstore.json` bundle too, verified the same way. PyPI and npm publish the same files.

## Container image

```sh
image=ghcr.io/contextosai/contextosd:$tag
cosign verify "$image" \
  --certificate-identity-regexp '^https://github\.com/contextosai/ContextOS/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify "oci://$image" --repo contextosai/ContextOS
```

## Reproducibility

The `reproducibility` workflow builds `contextosd`, `ctx` and `towerd` twice for
`x86_64-unknown-linux-gnu`, from two different checkout paths, and compares the
binaries' digests. It runs weekly, on every release tag, and on demand; its summary
lists each binary's two digests and whether they match. It is a check that our build
does not depend on where or when it ran, not a promise that your own toolchain
produces identical bytes: rebuilding a release yourself needs the same Rust toolchain
(`rust-toolchain.toml`), target and glibc baseline as the release job.

## Advisories

Every pull request runs `cargo deny check advisories` against the RustSec database
(the same advisories `cargo audit` reads) and `npm audit` for the Tower UI and the
conformance tooling. The `advisories` workflow repeats both every day on `main`, so an
advisory published after a merge is seen without waiting for the next change.
