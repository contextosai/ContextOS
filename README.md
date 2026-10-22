# ContextOS Runtime

[![CI](https://github.com/contextosai/ContextOS/actions/workflows/ci.yml/badge.svg)](https://github.com/contextosai/ContextOS/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

An open-source Rust runtime and governance plane for AI agents, implementing the [ContextOS](https://contextosai.com) contract: bounded context, authorized effects, typed outcomes, and verifiable audit trails.

This repository implements the spec. The spec's TypeScript module is a conformance reference; this runtime reproduces its decisions exactly (checked against generated golden vectors) and adds what the reference leaves to implementers: protected stores, fencing, adapters, a gateway and a server.

> Status: alpha. APIs and storage formats are evolving; hardening and performance work continue. Evaluate the runtime against your workflow before production use. See [docs/PLAN.md](docs/PLAN.md), the [security policy](SECURITY.md), and [deployment guidance](docs/GUIDE.md).

## Quickstart

Install the Rust toolchain specified in [rust-toolchain.toml](rust-toolchain.toml),
Python 3.9 or newer, Bash and curl. The example uses local development services and
synthetic data; it needs no model API key or external payment account.

```sh
git clone https://github.com/contextosai/ContextOS.git
cd ContextOS
./examples/support-refund/run.sh
```

The script builds the server and CLI, starts services on loopback addresses, admits a
run, dispatches one simulated refund, refuses a duplicate, and verifies the audit
chain. Expect `status: completed`, then `retry_unsafe`, and a final `verified: true`.
See the [full quickstart](examples/support-refund/README.md) for sample output.

For the governance console, install Node.js 24 and run
`./examples/tower/run.sh --serve`; follow the [Tower guide](docs/tower/README.md).
Framework examples have their own prerequisites in [examples/frameworks](examples/frameworks/README.md).

## Project boundaries and support

- **Specification:** the [published contract](https://contextosai.com/docs/implementation/execution-contract)
  defines portable behavior. [Conformance provenance](conformance/README.md) identifies
  the source revision used for this runtime's schemas and reference vectors.
- **Runtime:** embed the deterministic kernel, run `contextosd` as a gateway, or use
  Python, Node.js and WebAssembly bindings. Durable execution requires the protected
  stores and gateway, beyond the embedded decision kernel.
- **Tower:** `towerd` and the web console review evidence across runtimes. Its optional
  AI assistance requires a provider key; deterministic governance and the local demo
  run without one.

Alpha support covers `main` only and carries no support SLA. Breaking changes are
recorded in [CHANGELOG.md](CHANGELOG.md). Contributions are welcome; use
[GitHub Discussions](https://github.com/contextosai/ContextOS/discussions) for questions,
the issue forms for bugs and proposals, and the [private security channel](SECURITY.md)
for vulnerabilities.

## Design

- **Pure decision kernel** (`contextos-kernel`): no I/O, clock or randomness. Time and verified observations are explicit inputs, so every verdict is deterministic and replayable, and the kernel embeds in any process.
- **Fail closed, fail visibly**: unknown or unverifiable facts block; policy evaluation errors are structured non-success, never a false predicate.
- **Exact bindings**: every effect is bound by an RFC 8785 digest of the complete proposal. Approvals, grants and observations bind to that digest, so any change to arguments, amount, evidence or policy voids them.
- **Durable effects**: stable operation identity separate from transport attempts, unknown outcomes reconciled before any retry, executor-generation fencing, and conserved budgets that resume never resets.

## What it governs

- **Every effect**: authority chain, policy, constraints, exact approvals, data flow and
  the execution boundary are checked for one bound action before anything is claimed;
  MCP hosts can use it as a governed tool server (`/v1/runs/{id}/mcp`).
- **Runs end to end**: admission against a negotiated execution contract, delegated
  child runs with sub-budgets, executor failover with generation fencing, input
  continuation, reconciliation of unknown outcomes, and governed memory.
- **Evidence**: signed, hash-chained audit; DecisionRecords with verified lineage and
  replay packets; scores from independent evaluators; conformance assessment against
  signed attestations.
- **Change**: release gates on replayed cases (`ctx gate`) and on scorecards
  (`ctx scorecard-gate`), staged rollout of pack versions with shadow governance
  diffs, and a kill switch for tenants, packs, principals, agents, adapters and
  capabilities.
- **Operation at scale**: cluster-wide tenant limits, overload shedding, OpenTelemetry
  traces, Prometheus metrics, erasure and retention of personal content, PostgreSQL
  storage, an OpenAPI 3.1 description ([openapi/](openapi/contextosd.v1.json)), and
  Python and TypeScript clients.

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
| `contextosd` | HTTP server: admission, dispatch, decisions, scoring, kill switch, rollouts, retention, conformance, audit, metrics |
| `ctx` | Offline CLI: validate, compile, negotiate, review manifests, release and scorecard gates |
| `contextos-embed`, `-py`, `-node`, `-wasm` | In-process bindings over one JSON facade |
| `contextos-kernel` | Context Pack compiler, ActionRisk, profile negotiation, authority/approval/authorization, execution boundary, data flow, memory lifecycle, run lifecycle and resume, operation ledger, budget ledger, conformance assessment |

## Start

- Run the quickstart: [examples/support-refund](examples/support-refund/README.md) (`./examples/support-refund/run.sh`)
- A full governed agent loop (plan, delegate, act, decide): [examples/agent-loop](examples/agent-loop/README.md)
- Govern an agent built with LangGraph, the OpenAI Agents SDK, Google ADK, the Claude Agent SDK, CrewAI, Pydantic AI, LlamaIndex, Microsoft Agent Framework, the Vercel AI SDK or Mastra: [docs/integrations](docs/integrations/README.md), with a runnable example for each in [examples/frameworks](examples/frameworks)
- Charge model calls what they used: [examples/metering-proxy](examples/metering-proxy/README.md)
- Govern every agent across runtimes: [Tower](docs/tower/README.md), the organisation's governance plane, with architecture, flows and a step-by-step guide (`./examples/tower/run.sh --serve`)
- Embed, deploy and integrate: [docs/GUIDE.md](docs/GUIDE.md)
- Security: [SECURITY.md](SECURITY.md), [threat model](docs/security/THREAT_MODEL.md)
- Public release checklist: [docs/PUBLIC_RELEASE.md](docs/PUBLIC_RELEASE.md)
- Performance: [docs/PERFORMANCE.md](docs/PERFORMANCE.md)
- Contributing and governance: [CONTRIBUTING.md](CONTRIBUTING.md), [GOVERNANCE.md](GOVERNANCE.md), [CHANGELOG.md](CHANGELOG.md)

## Verify

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
RUST_LOG=info cargo test --workspace
```

Parity vectors live in `conformance/vectors/` and are regenerated from the spec repo (see [conformance/README.md](conformance/README.md)). Passing them shows these semantics match the reference; it is not deployed conformance of any workflow.

## License

| Material | License |
|---|---|
| Runtime, bindings, CLI, schemas, examples, conformance tools and code examples in the docs | [Apache-2.0](LICENSE) |
| Documentation prose (`docs/`, guides) | [CC BY 4.0](LICENSE-docs) |
| The ContextOS name and logo | [Trademark policy](TRADEMARKS.md) |

Contributions are accepted under the same licenses (see [CONTRIBUTING.md](CONTRIBUTING.md)).
