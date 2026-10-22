# Governance

## Roles

- **Maintainers** review and merge changes, cut releases and handle security reports.
  They are listed in `.github/CODEOWNERS`.
- **Contributors** are welcome to propose changes through pull requests
  (see [CONTRIBUTING.md](CONTRIBUTING.md)).

## Decisions

- Routine changes merge through a pull request with passing CI. A second maintainer
  reviews when available; the sole maintainer may merge their own pull request after
  completing the same checks. Maintainer access does not waive verification.
- Changes to protocols, decision semantics, storage or audit formats, public APIs, the
  threat model or the dependency policy need an ADR in `docs/adr/`, open for comment
  for at least five working days, and approval from two maintainers when there are two
  or more.
- The [ContextOS specification](https://contextosai.com) is normative. Where this
  runtime and the spec disagree, the spec wins until it is changed; the runtime does
  not ship divergent semantics.

## Releases and compatibility

- Versions follow Semantic Versioning. Before 1.0, minor versions may break APIs; every
  break is listed in `CHANGELOG.md`.
- Audit chains, ledgers and stored documents written by a release remain readable and
  verifiable by later releases. A format change ships with a migration and an ADR.
- The minimum supported Rust version is the one in `rust-toolchain.toml`; raising it is
  a minor-version change.
- Releases are built by CI from signed tags, with build provenance, SBOMs and a signed
  container image (see `.github/workflows/release.yml`).

## Security

Reports go to the address in [SECURITY.md](SECURITY.md) and are handled privately by
the maintainers. Fixes are released before details are published.
