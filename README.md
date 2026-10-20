# ContextOS Runtime

The production runtime for [ContextOS](https://contextosai.com), an open contract for reliable agent harnesses: bounded context, authorized effects, typed outcomes, and the evidence needed to evaluate and replay agent work.

This repository implements the spec. The spec's TypeScript module is a conformance reference; this runtime reproduces its decisions exactly (checked against generated golden vectors) and adds what the reference leaves to implementers: protected stores, fencing, adapters, a gateway and a server.

> Status: pre-release, private. Kernel, stores, audit, gateway, adapters, server, CLI and bindings are implemented; hardening and performance work continue. See [docs/PLAN.md](docs/PLAN.md).

## Design

- **Pure decision kernel** (`contextos-kernel`): no I/O, clock or randomness. Time and verified observations are explicit inputs, so every verdict is deterministic and replayable, and the kernel embeds in any process.
- **Fail closed, fail visibly**: unknown or unverifiable facts block; policy evaluation errors are structured non-success, never a false predicate.
- **Exact bindings**: every effect is bound by an RFC 8785 digest of the complete proposal. Approvals, grants and observations bind to that digest, so any change to arguments, amount, evidence or policy voids them.
- **Durable effects**: stable operation identity separate from transport attempts, unknown outcomes reconciled before any retry, executor-generation fencing, and conserved budgets that resume never resets.

Stack rationale: [ADR-0001](docs/adr/0001-language-and-stack.md). JsonLogic semantics: [ADR-0002](docs/adr/0002-jsonlogic-semantics.md).

## Crates

| Crate | Contents |
|---|---|
| `contextos-contract` | Types for the published schemas, JSON Schema validation, RFC 8785 canonical JSON, contract time |
| `contextos-policy` | Bounded JsonLogic with `json-logic-js` parity |
| `contextos-store` | Compare-and-swap document store and append-only log: memory and PostgreSQL |
| `contextos-audit` | ed25519-signed hash-chained audit, DecisionRecords, replay packets |
| `contextos-gateway` | Governed Tool Gateway pipeline and run admission |
| `contextos-adapters` | MCP 2026-07-28 and HTTP adapters, remote fact providers |
| `contextosd` | HTTP server: compile, admit, dispatch, audit, metrics |
| `ctx` | Offline CLI |
| `contextos-embed`, `-py`, `-node`, `-wasm` | In-process bindings over one JSON facade |
| `contextos-kernel` | Context Pack compiler, ActionRisk, profile negotiation, authority/approval/authorization, execution boundary, data flow, memory lifecycle, run lifecycle and resume, operation ledger, budget ledger, conformance assessment |

## Start

- Run the quickstart: [examples/support-refund](examples/support-refund/README.md) (`./examples/support-refund/run.sh`)
- Embed, deploy and integrate: [docs/GUIDE.md](docs/GUIDE.md)
- Security: [SECURITY.md](SECURITY.md), [threat model](docs/security/THREAT_MODEL.md)
- Performance: [docs/PERFORMANCE.md](docs/PERFORMANCE.md)
- Contributing and governance: [CONTRIBUTING.md](CONTRIBUTING.md), [GOVERNANCE.md](GOVERNANCE.md), [CHANGELOG.md](CHANGELOG.md)

## Verify

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Parity vectors live in `conformance/vectors/` and are regenerated from the spec repo (see [conformance/README.md](conformance/README.md)). Passing them shows these semantics match the reference; it is not deployed conformance of any workflow.

## License

Not yet decided. No license is granted at this time.
