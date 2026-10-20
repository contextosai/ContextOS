# ContextOS runtime — delivery plan

Goal: a production-grade, open-source implementation of the ContextOS spec (contextosai.com) that teams can embed in-process or run as a gateway, with deterministic, replayable governance on every agent effect.

Source of truth: the published schemas (`schemas/`) and normative docs in the spec repo. The TS module `src/lib/contextos/` in the spec repo is the conformance oracle; it is not copied, it is reproduced and checked with golden vectors.

Stack and rationale: [ADR-0001](adr/0001-language-and-stack.md).

## Architecture

```
            ┌──────────────── agent frameworks (LangGraph, OpenAI Agents, ADK, Claude Agent SDK, …)
            │  in-process: contextos-py / contextos-node / contextos-wasm
            │  remote:     HTTP/JSON + gRPC (contextosd)
            ▼
┌──────────────────────────── contextosd (control plane + Tool Gateway) ────────────────────────────┐
│ admission: negotiate profiles ─ authenticate principal ─ compile Context Pack                     │
│ per effect: bind action (RFC 8785) ─ authorize (authority ∧ policy ∧ constraints ∧ approval)      │
│             ─ boundary readiness ─ data-flow check ─ reserve budget ─ claim operation (fenced)    │
│             ─ dispatch via adapter (MCP / OpenAPI / A2A / internal) ─ reconcile ─ settle          │
│ outcome:    DecisionRecord (hash-chained, signed) ─ OTEL trace ─ replay packet                    │
└───────────────┬─────────────────────────────┬──────────────────────────────┬──────────────────────┘
                │ contextos-kernel (pure)     │ contextos-store (ports)      │ adapters
                │ no I/O, no clock, no RNG    │ memory | postgres            │ mcp | http | a2a
```

## Crates

| Crate | Responsibility |
|---|---|
| `contextos-contract` | Serde types for every published schema + execution-contract types; RFC 8785 canonical JSON; legacy stable hash; identifier/timestamp validation; error taxonomy. |
| `contextos-policy` | Bounded deterministic JsonLogic; policy outcome composition. |
| `contextos-kernel` | Context Pack compiler (8 stages), ActionRisk evaluation/projection, profile negotiation, authority/approval/authorization, execution boundary + data flow + memory lifecycle, durable run/checkpoint transitions, operation ledger, budget ledger, conformance assessment. Pure functions. |
| `contextos-store` | Ports with CAS + fencing: operation ledger, budget ledger, approval redemption, checkpoints, audit chain, pack registry. In-memory and Postgres adapters; shared store conformance tests. |
| `contextos-audit` | DecisionRecord builder, hash chain, ed25519 signing, replay packets. |
| `contextos-gateway` | Async Tool Gateway pipeline (tower), adapter trait, MCP client adapter, HTTP/OpenAPI adapter, credential broker port, egress policy. |
| `contextosd` | Server binary: HTTP/JSON (axum) + gRPC (tonic), config, OTEL, metrics, health. |
| `ctx` | CLI: validate packs/envelopes, compile, negotiate, digest, replay, conformance report. |
| `contextos-py`, `contextos-node`, `contextos-wasm` | Bindings over the kernel and a thin client for the server. |

## Slices

Each slice lands with tests, docs and passing `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`.

| # | Slice | Done when |
|---|---|---|
| 0 | ADR, plan, workspace, CI, toolchain pin | `cargo test` green on empty workspace; CI workflow committed |
| 1 | `contextos-contract`: canonical JSON (RFC 8785), legacy stable hash, timestamps, identifiers, base types for the 9 published schemas | Golden vectors from the TS reference match byte-for-byte |
| 2 | `contextos-policy`: JsonLogic evaluator (json-logic-js semantics, bounded) | Operator conformance suite + TS parity vectors |
| 3 | Kernel: ActionRisk evaluation/projection + Context Pack compiler | `compiled_context_hash` parity with the TS compiler on fixtures |
| 4 | Kernel: profile registry + execution-contract negotiation | Registry digests and negotiation results match TS |
| 5 | Kernel: action binding digest, authority chain, policy composition, approvals, redemption, authorization | Parity + negative-case suite from the spec |
| 6 | Kernel: execution boundary, data flow (9 stages), memory lifecycle | Parity |
| 7 | Kernel: durable run/checkpoint transitions, operation ledger, budget ledger | Parity + property tests (budget conservation, no double effect) |
| 8 | Kernel: conformance assessment | Parity |
| 9 | `contextos-store`: ports + in-memory + Postgres with fencing | Shared store suite passes on both; concurrency tests |
| 10 | `contextos-audit`: DecisionRecord, hash chain, signatures, replay packets | Tamper-detection tests |
| 11 | `contextos-gateway`: governed tool-call pipeline + adapters (MCP, HTTP) | End-to-end refund workflow: deny, approval, allow, unknown-outcome reconciliation |
| 12 | `contextosd`: HTTP + gRPC APIs, config, OTEL, metrics, health | Integration tests; load test p99 budget |
| 13 | `ctx` CLI | Commands documented and tested |
| 14 | Python / Node / WASM bindings | Binding tests reproduce kernel vectors |
| 15 | Security hardening: threat model, fuzzing (cargo-fuzz), supply chain (cargo-deny, SBOM), signed releases | Fuzz targets in CI; deny.toml clean |
| 16 | Performance: criterion benches, load tests, tuning | Published numbers with method |
| 17 | Docs site + examples + adoption guide | Quickstart runs end-to-end |

## Progress

| Slice | Status |
|---|---|
| 0 Workspace, ADRs, CI | done |
| 1 Contract: canonical JSON, schemas, types | done — vector parity |
| 2 JsonLogic | done — 5 935/6 000 exact, 65 fail visibly by design (ADR-0002) |
| 3 Action risk + compiler | done — 43/43 compilations byte-identical incl. `compiled_context_hash` |
| 4 Profiles + negotiation | done — 3 000+ vectors |
| 5 Authority, policy composition, approvals, authorization | done — 2 659 vectors |
| 6 Execution boundary, data flow, memory lifecycle | done — 1 700 vectors + Node path / WHATWG origin corpora |
| 7 Run lifecycle, resume, operation ledger, budget ledger | done — 1 900 vectors |
| 8 Conformance assessment | done — 320 vectors |
| 9 Stores with CAS + fencing | done — memory + PostgreSQL; contention tests (budget conservation, single in-flight claim) |
| 10 Audit chain, signed DecisionRecords, replay packets | done — ed25519 hash chain, tamper/fork/rotation tests, open-gate commit refusal |
| 11a Tool Gateway governed pipeline | done — surface/bind/authorize/redeem/reserve/claim/dispatch/observe/settle/audit; 7 end-to-end tests incl. approval redemption, timeout reconciliation, 16-way duplicate race |
| 11b MCP (2026-07-28 stateless) and HTTP adapters | done — effect-knowledge classification, pinned HTTPS endpoints, no redirects, brokered credentials; 9 tests against live local servers |
| 12a contextosd: config, API-key auth + tenant binding, strict ingress, compile/negotiate/validate/audit, metrics, health, container | done |
| 12b Run admission + governed dispatch API, remote fact providers, pinned pack policy | done — derived workflow features, end-to-end HTTP tests with remote providers and MCP |
| 13 `ctx` CLI | done — validate, compile, digest, negotiate, manifest, profiles, hash-key; exit codes tested |
| 14 Python / Node / WASM bindings | done — one JSON facade; PyO3 abi3 (GIL released), N-API (async on thread pool), import-free WASM; all reproduce reference hashes; CI job |
| 15 Security hardening | done — threat model (17 threats → controls → tests), property fuzzing of every kernel entry point (80k cases clean), cargo-deny policy, security headers, SECURITY.md |
| 16 Performance | done — kernel and gateway benchmarks; authorization 161→63 µs; dispatch 1.2→0.74 ms via per-operation ledgers; budget rollover is an open spec decision |
| 17 Observability, docs, quickstart | done — dispatch tracing spans, HTTP trace layer, runnable quickstart (verified end to end), usage/integration/operations guide |
| 18a OIDC/JWT caller authentication | done — background JWKS refresh, rate-limited rotation, issuer-scoped tenants, asymmetric algorithms only, readiness gating |
| 18b Helm chart, release automation | done — hardened chart (non-root, read-only FS, no SA token, PDB, NetworkPolicy, HPA, ServiceMonitor) validated in CI; tag releases build attested binaries, per-crate CycloneDX SBOMs and a keyless-signed image with provenance |
| 18c OTLP trace export | done — OTLP/HTTP via the server's rustls client (no second TLS stack), W3C trace-context propagation, default `info` logging |
| 19 Load testing against PostgreSQL, MCP `input_required`/tasks continuation, open-source readiness (license, CONTRIBUTING, governance) | next |

## Non-negotiables carried from the spec

- Schema validity, caller labels and compilation never authorize an effect.
- Unknown or unverifiable required facts block; nothing fails open.
- Policy-expression errors are structured non-success, never a false predicate.
- Profile names are not certification; synthetic evidence never establishes deployed conformance.
- Unknown effect outcomes are reconciled before any retry that could duplicate them; cancellation does not erase effects; resume never resets original budgets.

## Open decisions for the maintainers

- **License.** The spec repo is "All rights reserved" and its maintainers recorded the license as an open stewardship decision. Crates are marked `publish = false` with no license grant until that decision is made.
