# Public release preparation

Publish the runtime as an alpha. The specification, runtime and Tower have distinct
roles described in the root README; synthetic conformance tests do not certify a
deployment. This checklist covers the visibility change, not production certification.

## Before changing visibility

- Merge the public-readiness runtime and specification changes through reviewed PRs.
- Obtain a green CI run for the exact launch commit. If GitHub reports an Actions
  billing/spending restriction, the account owner must resolve it; local checks do
  not replace the hosted job matrix.
- Keep `main` protected with all CI checks required. The reviewed settings are in
  `.github/branch-protection.json`; they require PRs, up-to-date checks and resolved
  conversations, and prohibit force pushes and deletion, including for administrators.
  With one maintainer, the review count is zero; add reviewer requirements when the
  maintainer team grows.
- Verify the checksums of the pinned TypeScript reference in `conformance/reference/`
  and the conformance CI job. Outside contributors must be able to regenerate the
  vectors using the committed snapshot and lockfile, as described in
  `conformance/README.md`.
- Review all branches, issues, attachments, Actions logs and artifacts for private
  material. Secret scans of the working files and Git history do not cover GitHub
  uploads or workflow logs. Rotate any exposed credential before removing it.
- Confirm that `security@contextosai.com` reaches the maintainers. The same private
  mailbox accepts conduct reports with a "Code of conduct" subject.
- Check the About description, website, topics, contribution guide and Discussions.

The repository remains private until the owner explicitly decides to open it. Do not
change visibility as a workaround for billing or to enable a security setting.

## After the authorized visibility change

Private vulnerability reporting is available for public repositories. Enable it,
then verify that **Report a vulnerability** appears under Security / Advisories:

```sh
gh api --method PUT repos/contextosai/ContextOS/private-vulnerability-reporting
gh api repos/contextosai/ContextOS/private-vulnerability-reporting
```

Verify secret scanning and push protection are enabled. Apply branch protection if
it needs to be restored:

```sh
gh api --method PUT repos/contextosai/ContextOS/branches/main/protection \
  --input .github/branch-protection.json
```

Run these commands from a GitHub account with repository administrator access. The
email reporting route in `SECURITY.md` works independently of the GitHub form.

## Before the first binary release

- Tag the reviewed commit; keep release notes explicit about alpha limitations.
- Verify the release archive and container include `LICENSE`, `LICENSE-docs`, `NOTICE`
  and `TRADEMARKS.md`, plus the generated `THIRD_PARTY_NOTICES.txt` bundle. CI must
  reproduce that bundle from the locked Rust and Tower dependency graphs.
- Verify the emitted SBOMs, artifact provenance and signed container as described by
  the release workflow; test the download and source-build instructions independently.
  The workflow builds the Linux executables on AlmaLinux 8 against glibc 2.28, fails if
  any needs a newer glibc (`scripts/check-glibc.sh`), and runs each unpacked archive
  (every executable's `--version`, then the shared-guarantees demo, without cargo) on
  its runner and, for Linux, on AlmaLinux 8 (`scripts/smoke-archive.sh`). CI runs the
  same baseline build and demo on every pull request. Also try the support-refund and
  Tower demos from a downloaded archive.
- Publish the draft release only after every gate passes.

## Cutting an alpha

Keep the workspace, Tower package, Python fallback and Helm chart versions aligned.
Add notes under `docs/releases/<tag>.md` and record the version in `CHANGELOG.md`.
The first release is `v0.1.0-alpha.1`; it is a prerelease, with evolving APIs and
storage formats. From 0.1.0-alpha.12 the client packages go to PyPI and npm (below);
crates.io stays unpublished.

Merge the preparation PR, obtain green CI for the exact commit to be tagged, and
create an annotated `v<workspace version>` tag at that commit. Pushing the tag runs
`.github/workflows/release.yml`. It validates the version and notes, builds and tests
the three platform archives, emits all-target/all-feature Rust source inventories,
attests the archives, signs the container, builds and smoke-tests the client
packages (three `contextos` platform wheels, the pure-Python `contextos` wheel and the
`contextos-client` npm tarball) and creates a draft with the checked-in notes. Alpha tags are marked as prereleases and are not marked Latest.

Before publishing, download the draft's assets and independently verify checksums,
the expected workflow/tag in provenance, archive contents and the runnable examples.
Check the Linux ABI requirements and macOS deployment target; do not infer support
for untested platforms. Verify the image signature and provenance by digest.

New GHCR packages start private even when their repository is public. Set the image
package to public and verify an anonymous pull before advertising it in a public
release. Keep the package linked to this repository for Actions access.

Publish the completed draft only after these checks pass. Record the exact source
commit, image digest and verification results with the release. Do not move published
tags or replace their assets; ship a new alpha for corrections. A failed candidate
can remain unpublished with its failure explained, rather than being presented as a
working release.

## Package registries

Publishing the draft release runs `.github/workflows/publish-packages.yml`. It
downloads the wheels and the npm tarball from the release, verifies their build
provenance against `release.yml`, and uploads them through trusted publishing: no
registry token lives in the repository. Versions already on a registry are skipped,
so a failed run can be repeated from the Actions tab (`workflow_dispatch` with the
tag). Do not upload packages by hand once trusted publishing is set up.

One-time setup, by an owner of the registry accounts:

1. GitHub: create the environments `pypi` and `npm` under Settings / Environments,
   each limited to tags `v*`. Add required reviewers if a second approval is wanted.
2. PyPI: under the project account, add a pending trusted publisher for project
   `contextos`: owner `contextosai`, repository `ContextOS`, workflow
   `publish-packages.yml`, environment `pypi`. The first run creates the project.
3. npm: trusted publishing can only be configured on a package that exists. Publish
   the first version once by hand from the release's tarball, with two-factor
   authentication: `npm publish contextos-client-<version>.tgz --access public`.
   Then, in the package's settings, add the trusted publisher (GitHub Actions,
   `contextosai/ContextOS`, workflow `publish-packages.yml`, environment `npm`),
   and set publishing access to require two-factor authentication and disallow
   tokens.

The release notes template line "This release does not publish packages to PyPI, npm
or crates.io" changes to name the two packages and their version.
