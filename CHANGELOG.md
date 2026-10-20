# Changelog

All notable changes are listed here. Versions follow Semantic Versioning; before 1.0,
minor versions may break APIs and every break is listed.

## Unreleased

First release candidate of the ContextOS runtime.

### Decision kernel
- Context Pack compiler, ActionRisk evaluation, profile negotiation, authority and
  delegation validation, policy composition, approvals and authorization, execution
  boundary, data flow, memory lifecycle, run lifecycle and resume, operation and budget
  ledgers, and conformance assessment, matching the spec's reference on generated
  parity vectors.
- RFC 8785 canonical JSON and domain-separated digests; bounded JsonLogic with
  `json-logic-js` semantics and fail-visible errors.

### Runtime
- Compare-and-swap document stores and an append-only log (in-memory and PostgreSQL).
- Ed25519-signed, hash-chained audit with DecisionRecords and replay packets; group
  commit for parallel appends.
- Governed Tool Gateway: surface, bind, authorize, redeem approvals, reserve budget,
  claim the operation, dispatch, observe, settle and audit, failing closed throughout.
- Reconciliation of unknown effects by provider query (MCP `tasks/get`) or evidenced
  operator assertion.
- DecisionRecords over HTTP with lineage verified against the run's ledgers, the
  evidence gate enforced, signing into the audit chain and replay packets; per-run
  evidence bundles and paged audit export.
- Run completion, failure and cancellation through the kernel lifecycle: completion
  requires resolved effects and settled children; cancellation fences the executor,
  cancels and settles children and acknowledges once dispatch has stopped.
- Executor ownership and failover: runs start through the kernel lifecycle, effectful
  requests present the executor generation, and takeover fences the previous executor.
- Delegated child runs: narrowed tool surface, sub-budgets reserved from the parent,
  gateway-attested run links for kernel authority checks, and close that locks the
  child's remaining capacity before settling into the parent.
- Continuation of MCP tools that answer `input_required`, bound to the same action.
- MCP `2026-07-28` (stateless) and HTTP adapters with pinned HTTPS endpoints, no
  redirects and brokered credentials; remote authority, constraint and approval
  providers.

### Server and tools
- `contextosd`: compile, contract negotiation, schema validation, run admission,
  governed tool calls, input continuation, reconciliation, audit verification, health,
  readiness and Prometheus metrics; API keys and OIDC JWT callers bound to one tenant;
  strict JSON ingress; overload protection (global load shedding, per-tenant rate and
  concurrent-dispatch limits); OTLP trace export with W3C trace-context propagation.
- Conformance assessment over HTTP (`POST /v1/conformance/assess`): the deployment
  supplies identity, support, registry, clock and configured trust anchors; audited.
- Time-based retention (`[retention] run_content_days`, off by default): the leader
  replica erases finished runs' personal content after the configured period.
- Erasure of a finished run's personal content (`POST /v1/runs/{id}/erase`, `control`
  scope): audited tombstones replace the replay case and compiled context.
- Cluster-wide tenant limits: replicas heartbeat into the store and each enforces its
  share of every tenant's rate, burst and dispatch cap (`contextos_replicas` gauge).
- `ctx scorecards` collects evaluator scorecards from evidence bundles into
  `ctx scorecard-gate` input. Python and TypeScript clients gain `revoke`, `restore`
  and `revocations` for operators.
- Kill switch: operators (`control` scope) revoke a tenant, pack, agent, adapter or
  capability; dispatch and admission refuse it from the next call; audited, restorable.
- Scorecard release gate (`ctx scorecard-gate`): per-scorecard policy/safety floors,
  no per-case policy/safety regression, bounded utility/latency/cost deltas; missing
  cases and measurements fail, as do underpowered comparisons.
- Measured wall clock: admissions record `admitted_at`; decisions report
  `budget_usage.wall_clock_ms` and scores report latency from it.
- Independent run scoring: evaluators with the `evaluate` scope (and neither `admit`
  nor `dispatch`) score recorded decisions; cost is measured by the runtime; scores
  are signed and kept in the evidence bundle. Unknown API-key scopes are refused.
- OpenAPI 3.1 description of the HTTP API (`openapi/contextosd.v1.json`, served at
  `GET /v1/openapi.json`), kept in step with the router by a test.
- Release gate for Context Pack changes (`ctx gate`; acknowledgements name the exact
  capabilities, gates and cases they accept): replayed cases compiled under
  baseline and candidate; unacknowledged widenings and compile regressions fail. Runs
  export their admission inputs as replay cases.
- Governed memory lifecycle: propose, promote, correct and delete decided by the
  kernel against trusted memory policy, audited, with current state per memory.
- Active execution boundary: an optional boundary controller's facts are evaluated by
  the kernel at run start, resume and every dispatch.
- Data permissions in dispatch: an optional data-governance provider supplies flow
  facts and the kernel's data-flow policy decides, bound to the exact action.
- MCP gateway mode: every run is an MCP server whose tools are its governed
  capabilities; reviewed input schemas on manifests, enforced on every call.
- TypeScript/Node HTTP client (`@contextos/kernel/client`, no dependencies, typed).
- Python HTTP client (`contextos.client`, standard library only) with typed outcomes,
  fencing handled, and a `governed_tool` decorator for agent frameworks.
- `ctx` command line; Python, Node and WebAssembly bindings over one JSON facade.

### Operations
- Distroless non-root image, hardened Helm chart, signed releases with provenance and
  SBOMs, cargo-deny policy, property fuzzing, threat model, benchmarks.

- Budget-ledger compaction (ADR-0003): settled reservations move to chained archives
  with unchanged counters, so runs are no longer limited to about 64 effects and
  per-effect cost stays flat.

### Known limits
- At most 64 reservations can be open at once in one run.
