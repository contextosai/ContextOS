# Contributing

Code is licensed under [Apache-2.0](LICENSE) and documentation prose under
[CC BY 4.0](LICENSE-docs). By submitting a contribution you license it under the same
terms (Apache-2.0, section 5, for code and code examples; CC BY 4.0 for prose), and
confirm you have the right to do so. Use of the name and logo is covered by
[TRADEMARKS.md](TRADEMARKS.md).

## Ground rules

ContextOS decides whether an agent's effect may happen. Changes are held to that bar:

1. **The spec is normative.** Behaviour must match the published schemas and the
   spec's reference semantics, checked by the parity vectors in `conformance/`. If the
   runtime should behave differently, change the spec first (in the spec repository),
   regenerate vectors, then change the runtime. Never edit vectors by hand.
2. **The kernel stays pure.** `contextos-kernel`, `contextos-policy` and
   `contextos-contract` do no I/O and read no clock or randomness. Time and observed
   facts are inputs.
3. **Fail closed, fail visibly.** Unknown or unverifiable facts block. Every refusal
   carries a stable `reason_code`; never turn an evaluation error into `false`.
4. **No new trust.** Nothing the model or a tool returns may widen authority, alter a
   bound action or skip a gate. New inputs from outside get a threat-model entry
   (`docs/security/THREAT_MODEL.md`) and tests that attack them.
5. **No `unsafe`** outside the WASM C-ABI shim (`crates/contextos-wasm`).
6. **Measure performance claims.** Hot-path changes come with before/after numbers
   from the benchmarks (`docs/PERFORMANCE.md`).

## Development

Requirements: the Rust toolchain in `rust-toolchain.toml` (installed automatically by
`rustup`); for the PostgreSQL tests, a disposable database; for bindings, Python 3.9+
with `maturin` and Node.js 20+.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
RUST_LOG=info cargo test --workspace
# PostgreSQL store, audit and benchmark paths (no Docker needed:
# `eval "$(scripts/dev-postgres.sh)"` starts a disposable server and exports the URLs)
CONTEXTOS_TEST_DATABASE_URL=postgres://… RUST_LOG=info cargo test --workspace
CONTEXTOS_BENCH_DATABASE_URL=postgres://… cargo bench -p contextos-gateway --bench dispatch -- postgres
# Property fuzzing of every kernel entry point
CONTEXTOS_FUZZ_CASES=20000 cargo test -p contextos-embed --test fuzz --release
# Supply chain
cargo deny check
```

When changing `Cargo.lock` or Tower's production dependencies, regenerate the bundled
dependency notices and include them in the change:

```sh
cargo install --locked --features cli cargo-about@0.9.2
npm ci --prefix tower --ignore-scripts
bash scripts/generate-notices.sh
```

CI regenerates the notices and rejects missing or stale attribution.

Regenerate parity vectors from the exact source revision recorded in
`conformance/source.json`, following [conformance/README.md](conformance/README.md).

## Changes

- Keep a change to one concern, with tests that fail without it.
- Write commit messages that explain why, in plain sentences.
- Design decisions that change protocols, semantics, storage formats or public APIs
  get an ADR in `docs/adr/` (see [GOVERNANCE.md](GOVERNANCE.md)).
- Update `docs/` and `CHANGELOG.md` in the same change when behaviour changes.

## Reporting security issues

Never in public issues. See [SECURITY.md](SECURITY.md).

## Before every commit

Run `scripts/check.sh`. It stops at the first failure and covers formatting, lint, every
test suite, both HTTP clients end to end and both examples; server changes often break
the clients and examples rather than the Rust tests.
