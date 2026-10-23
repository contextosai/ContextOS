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
- Verify that the pinned specification source can be obtained by outside contributors.
  Its asset licenses and GitHub visibility are separate decisions. The runtime builds
  and tests from its committed schemas and vectors without access to that repository.
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
  The workflow runs the shared-guarantees demo from each unpacked archive without
  cargo; also try the support-refund and Tower demos from a downloaded archive.
- Publish the draft release only after every gate passes.
