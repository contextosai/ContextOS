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
| 19a Effect reconciliation | done — MCP task handles kept as attempt references, `tasks/get` provider queries, evidenced operator assertions under a `reconcile` scope, kernel-recorded facts, budget settlement, audit |
| 19b MCP `input_required` continuation | done — definitive not-applied attempt, persisted single-use requests, re-authorized continuation bound to the same action digest, schema-checked answers, secret-field refusal, audited by digest |
| 20a Throughput | done — parallel benchmark found per-tenant audit appends serialized on lock handoffs (~1.9k effects/s flat); group commit with atomic batched log appends → ~7.2k effects/s single-tenant, CPU-bound; PostgreSQL benchmarks in CI; mimalloc |
| 20b Open-source readiness | done — CONTRIBUTING, GOVERNANCE, code of conduct, CHANGELOG, issue/PR templates, CODEOWNERS, Dependabot; security contact published. **Blocked on the owner: license choice.** |
| 21 Long runs and per-effect CPU | done — linear ledger validation, exact length counting, budget-ledger compaction (ADR-0003): runs beyond 64 effects, sequential 0.59→0.37 ms, ~10.4k effects/s single tenant |
| 22 Overload protection; spec proposal | done — load shedding, per-tenant rate and dispatch-concurrency limits; `docs/proposals/spec-0001` drafted for the spec maintainers |
| 23 Delegation (subagent lanes) | done — envelope binding and narrowing, parent-funded sub-budgets, attested run links, capacity-locking close, HTTP API |
| 24 Executor failover | done — kernel run lifecycle per run, generation-fenced effectful API (re-checked before claim), takeover via suspend/resume, generation forwarded to providers |
| 25 Run lifecycle | done — complete/fail/cancel via kernel transitions; outstanding effects and children tracked; recursive cancellation with dispatch-stop acknowledgement from the budget ledger |
| 26 Decisions and evidence | done — verified DecisionRecords with evidence-gate enforcement, replay packets, run evidence bundles, paged audit export |
| 27a Python HTTP client | done — stdlib-only client, typed outcomes, generation fencing, `governed_tool`, end-to-end test in CI |
| 27b TypeScript client | done — fetch-based, typed (`client.d.ts` checked with tsc), same flow tested end to end in CI |
| 28a Dispatch store reads | done — four reads per effect removed (one run-state read, compaction from the reserve's own state, reused fast-path read, outcome from the response) |
| 28b PostgreSQL validated | done — store suite and full gateway on PostgreSQL 16; 13→8 statements per effect, concurrent fact fetching, seeded transactions, no per-acquire ping; ~5,100 effects/s single tenant over a socket; `scripts/dev-postgres.sh` |
| 29 Audit batching | `AuditWriter::append_all` (consecutive entries in one batch). Deferring the authorization decision to share the claim's batch measured no gain on PostgreSQL (group commit already batches under load), so it was not adopted; per-run audit streams wait for a workload that needs them |
| 30 MCP gateway mode | done — per-run MCP server (tools/list of surfaced capabilities, governed tools/call, input_required passthrough, retry-safe operation identity); manifest input schemas enforced |
| 31 Security review | done — six findings fixed with regression tests (see the threat model's review log) |
| 32 Data permissions in dispatch | done — DataFlowProvider port, binding checks, kernel evaluate_data_flow, audited decisions, remote provider and config |
| 33 Active boundary | done — BoundaryProvider port; kernel readiness at start/resume and per dispatch; start no longer reports an unchecked boundary as ready when a controller exists |
| 34 Memory lifecycle | done — MemoryPolicyProvider port, kernel validate_memory_lifecycle, audited decisions, memory state, HTTP routes. Every kernel capability is now reachable through the server |
| 35 Agent loop example | done — plan, read-only delegated research lane, critic, governed effect, verified decision, completion and evidence over the Python client; runs in CI |
| 36 Release gate | done — kernel `release_gate` (capability, policy, evidence-gate widenings; compile regressions), `ctx gate`, replay-case export from runs |
| 37 API description | done — OpenAPI 3.1 for every route, bodies referencing the normative schemas by `$id`, served at `/v1/openapi.json`; tests keep it in step with the router and resolve every reference |
| 38 Independent scoring | done — `RunScore` scorecards for decisions from separate evaluator principals (`evaluate` scope, separation of duties enforced), runtime-measured cost, signed and in the evidence bundle |
| 39 Scorecard gate | done — kernel `scorecard_gate` and `ctx scorecard-gate`: floors per scorecard, no policy/safety regression, bounded utility/latency/cost deltas, missing/unmeasured/underpowered fail |
| 40 Kill switch | done — tenant/pack/agent/adapter/capability revocation (`control` scope), enforced in the concurrent authorization reads and at admission, audited before effect, restorable |
| 41 Cluster-wide limits | done — replica membership heartbeat (CAS on one document), per-replica share of tenant rate/burst/dispatch cap, no per-request store traffic, `contextos_replicas` gauge |
| 42 Erasure | done — operator erasure of a finished run's replay case and compiled context into audited tombstones (digest of removed content), 410 for erased cases; time-based retention next |
| 43 Retention | done — `DocumentStore::expiring` (age scan excluding tombstones, cursor-paged; PG index), leader-elected sweeper erasing finished runs after `run_content_days` |
| 44 Conformance over HTTP | done — `POST /v1/conformance/assess` with server-supplied identity, support, registry, clock and per-tenant trust anchors; outcomes audited |
| 45 Staged rollout | done — per-tenant baseline→candidate rollouts, sticky hash routing (children follow parents), shadow governance diffs off the request path, audited control-plane changes |
| 46 Next | next |

## Non-negotiables carried from the spec

- Schema validity, caller labels and compilation never authorize an effect.
- Unknown or unverifiable required facts block; nothing fails open.
- Policy-expression errors are structured non-success, never a false predicate.
- Profile names are not certification; synthetic evidence never establishes deployed conformance.
- Unknown effect outcomes are reconciled before any retry that could duplicate them; cancellation does not erase effects; resume never resets original budgets.

## Open decisions for the maintainers

- **License.** The spec repo is "All rights reserved" and its maintainers recorded the license as an open stewardship decision. Crates are marked `publish = false` with no license grant until that decision is made.
