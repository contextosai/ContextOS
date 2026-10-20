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
- `ctx` command line; Python, Node and WebAssembly bindings over one JSON facade.

### Operations
- Distroless non-root image, hardened Helm chart, signed releases with provenance and
  SBOMs, cargo-deny policy, property fuzzing, threat model, benchmarks.

- Budget-ledger compaction (ADR-0003): settled reservations move to chained archives
  with unchanged counters, so runs are no longer limited to about 64 effects and
  per-effect cost stays flat.

### Known limits
- At most 64 reservations can be open at once in one run.
