# ContextOS

[![CI](https://github.com/contextosai/ContextOS/actions/workflows/ci.yml/badge.svg)](https://github.com/contextosai/ContextOS/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Shared business limits for AI agents.**

ContextOS coordinates the limits your agents share, enforces them before tools act,
and records signed evidence of confirmed and unresolved effects. Keep your agent
framework, identity provider and observability stack; place consequential tools
behind the ContextOS gateway.

Two agents can each be authorized to refund INR 800 while the order's shared ceiling
is INR 1,000. ContextOS reserves capacity atomically across their independent runs,
so only one effect reaches the provider. A pending effect continues to consume its
reservation until reconciled. New run IDs and server replicas do not reset capacity
when they share the same tenant and protected store.

The first implementation supports configured numeric ceilings per resource. Its
Rust runtime and Tower governance plane build on the [ContextOS](https://contextosai.com)
contract: bounded context, authorized effects, typed outcomes, and verifiable audit trails.

The normative spec's TypeScript module remains the conformance reference. This
runtime reproduces its decisions against golden vectors and adds protected stores,
fencing, adapters and shared business guarantees as an opt-in runtime extension.
The [research and strategy](docs/research/2026-10-22-value-proposition.md) explain the
chosen opportunity, competing approaches and unvalidated assumptions.

> Status: alpha. APIs and storage formats are evolving; hardening and performance work continue. The current version is [v0.1.0-alpha.8](docs/releases/v0.1.0-alpha.8.md). Evaluate the runtime against your workflow before production use. See [docs/PLAN.md](docs/PLAN.md), the [security policy](SECURITY.md), and [deployment guidance](docs/GUIDE.md).

## Quickstart

Install the Rust toolchain specified in [rust-toolchain.toml](rust-toolchain.toml),
Python 3.9 or newer, Bash and curl. The example uses local development services and
synthetic data; it needs no model API key or external payment account.

```sh
git clone https://github.com/contextosai/ContextOS.git
cd ContextOS
./examples/shared-guarantees/run.sh
```

The script builds the server and CLI, checks this machine can run them, and starts
synthetic services on loopback addresses. It races two agents against one order
ceiling, loses a provider response and shows its reservation held, blocks a further
effect, then resolves the held effects by provider query and by an operator citing the
provider's ledger. Each step prints `limit / committed / held / available`. The audit
log, keys and balances stay in `receipts/shared-guarantees/` with the command to verify
them yourself.
See the [shared guarantees demo](examples/shared-guarantees/README.md) and
[configuration and recovery guide](docs/SHARED_GUARANTEES.md).

Without Rust: download the archive for your platform from a
[release](https://github.com/contextosai/ContextOS/releases), check it with
`shasum -a 256 -c` and `gh attestation verify <archive> --repo contextosai/ContextOS`,
unpack it and run the same script from its directory. The archive carries `ctx`,
`contextosd`, `towerd`, the Tower UI and the examples below, so it needs only Python,
Bash and curl. Linux archives need glibc 2.28 or newer (RHEL, AlmaLinux or Rocky 8+,
Debian 10+, Ubuntu 20.04+); `examples/doctor.sh` checks that your system can run the
executables and names the alternative when it cannot.

For the original authorization and duplicate-operation walkthrough, run
`./examples/support-refund/run.sh`; see its [quickstart](examples/support-refund/README.md).

For the governance console, run `./examples/tower/run.sh --serve`; a source checkout
also needs Node.js 24 to build the UI, while release archives include it prebuilt.
Follow the [Tower guide](docs/tower/README.md).
Framework examples have their own prerequisites in [examples/frameworks](examples/frameworks/README.md).

Examples build `contextosd` and `ctx` from source on first use, which takes a few
minutes; later examples reuse that build.

### Govern your own agent

```sh
./examples/dev-server.sh          # prints CONTEXTOS_URL and CONTEXTOS_TOKEN; Ctrl-C stops it
export PYTHONPATH=$PWD/bindings/python
```

That serves the quickstart's support pack with synthetic providers on loopback. Admit
a run from [`run.json`](examples/support-refund/requests/run.json), wrap your tool
functions with `governed_tool`, and register them with your framework: the
[integration guides](docs/integrations/README.md) cover LangGraph, the OpenAI Agents
SDK, Google ADK, the Claude Agent SDK, CrewAI and six more, each with a runnable
example. To serve your own tools, write a Context Pack and capability manifests
([GUIDE section 3](docs/GUIDE.md#3-run-contextosd)); the [glossary](docs/GLOSSARY.md)
explains the terms. The Python client is not on PyPI yet: see
[bindings/python](bindings/python/README.md).

## Why not a database transaction?

If the refund is a write to a database you own and every caller goes through one
service, use `SELECT ... FOR UPDATE` and skip ContextOS for that limit. The lock wins
the race. Keep it even if you deploy ContextOS.

A refund is usually not a write to your database. The money moves at the payment
provider, and no provider joins your transaction. That breaks the row lock in three
places the race never tests:

- **Lost responses.** The provider applies the refund and the answer times out. Rolling
  back the counter forgets the money and the next refund passes. Keeping the counter
  blocks refunds forever when the call was in fact never applied. A correct design
  holds the amount as *unknown* until evidence resolves it. That needs attempt
  identity, fencing of delayed workers, no retries before reconciliation, and
  evidence. ContextOS already runs that ledger in front of every governed effect.
- **Limits that span systems.** Refunds, store credit and vouchers live in three
  databases. Each can lock its own row; none can enforce "compensation per order
  ≤ INR 1,000". One ContextOS guarantee can cover all three tools.
- **Tools you do not own.** Agents call third-party MCP servers and SaaS APIs. There
  is no row to lock; the call path is the only enforcement point.

`./examples/why-not-a-row-lock/run.sh` runs a careful row-lock refund service and
ContextOS against the same faults. The row lock overpays INR 1,600 against a
INR 1,000 limit; ContextOS holds, reconciles and stops at exactly INR 1,000. The
[full argument](docs/WHY_NOT_A_TRANSACTION.md) covers when to build this in your
service instead, and what ContextOS does not solve.

## Project boundaries and support

- **Specification:** the [published contract](https://contextosai.com/docs/implementation/execution-contract)
  defines portable behavior. [Conformance provenance](conformance/README.md) identifies
  the source revision used for this runtime's schemas and reference vectors.
  [Verified properties](docs/verification/PROPERTIES.md) lists the rules beyond the
  vectors that are checked on generated inputs, and how.
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

- **Shared business exposure**: configured resource ceilings across independent runs,
  agents and replicas on one protected store; unknown and partial outcomes retain
  capacity; exact-attempt dispatch activation, conservative recovery and read-only
  operator inspection. This extension is opt-in and covers mediated tools only.
- **Every effect**: authority chain, policy, constraints, exact approvals, data flow and
  the execution boundary are checked for one bound action before anything is claimed;
  MCP hosts can use it as a governed tool server (`/v1/runs/{id}/mcp`).
- **Runs end to end**: admission against a negotiated execution contract, delegated
  child runs with sub-budgets, executor failover with generation fencing, input
  continuation, reconciliation of unknown outcomes, and governed memory.
- **Peer work coordination**: an optional root-owned task board with dependency
  discovery, atomic leased claims and recovery across admitted peers. Task reports
  remain advisory; [limits and trust boundaries](docs/PEER_COORDINATION.md) apply.
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

- Coordinate two agents against one business ceiling: [examples/shared-guarantees](examples/shared-guarantees/README.md) (`./examples/shared-guarantees/run.sh`)
- Follow the original authorization quickstart: [examples/support-refund](examples/support-refund/README.md) (`./examples/support-refund/run.sh`)
- A full governed agent loop (plan, delegate, act, decide): [examples/agent-loop](examples/agent-loop/README.md)
- Peers choosing and recovering work, and falsifying each other's findings with recorded evidence: [examples/peer-coordination](examples/peer-coordination/README.md), [findings guide](docs/FINDINGS.md)
- Compare a row-lock refund service with ContextOS under lost responses and cross-system limits: [examples/why-not-a-row-lock](examples/why-not-a-row-lock/README.md) (`./examples/why-not-a-row-lock/run.sh`), [argument](docs/WHY_NOT_A_TRANSACTION.md)
- Drill the shared limit on PostgreSQL across separate processes, with SIGKILLs and a database restart: [examples/postgres-drill](examples/postgres-drill/README.md) (`./examples/postgres-drill/run.sh`), [results](docs/research/2026-10-29-postgres-shared-limit-drill.md)
- Undo a workflow that failed halfway, as governed compensations: [examples/compensation](examples/compensation/README.md) (`./examples/compensation/run.sh`), [guide](docs/COMPENSATION.md)
- Govern an agent built with LangGraph, the OpenAI Agents SDK, Google ADK, the Claude Agent SDK, CrewAI, Pydantic AI, LlamaIndex, Microsoft Agent Framework, the Vercel AI SDK or Mastra: [docs/integrations](docs/integrations/README.md), with a runnable example for each in [examples/frameworks](examples/frameworks)
- Charge model calls what they used: [examples/metering-proxy](examples/metering-proxy/README.md)
- Govern every agent across runtimes: [Tower](docs/tower/README.md), the organisation's governance plane, with architecture, flows and a step-by-step guide (`./examples/tower/run.sh --serve`)
- Embed, deploy and integrate: [docs/GUIDE.md](docs/GUIDE.md)
- Security: [SECURITY.md](SECURITY.md), [threat model](docs/security/THREAT_MODEL.md), [what ContextOS does not govern](docs/SCOPE.md)
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
