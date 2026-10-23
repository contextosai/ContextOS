# Changelog

All notable changes are listed here. Versions follow Semantic Versioning; before 1.0,
minor versions may break APIs and every break is listed.

## Unreleased

First release candidate of the ContextOS runtime.

### Shared business guarantees
- Reposition ContextOS around numeric business-resource limits shared by independent
  agent runs. Research records current alternatives and the differentiation hypothesis.
- Add opt-in `[[guarantees]]`, protected resource exposure and stable definition pins;
  reserve and activate exact attempts before dispatch, retain unknown/partial
  exposure, seal definitive observations and audit contradictory/stale refusals.
- Add conservative settlement recovery, current-generation reconciliation after
  terminal runs, and `audit:read` guarantee/exposure inspection endpoints with OpenAPI.
- Add a synthetic multi-agent example and regression coverage for cross-replica
  contention, dispatch/recovery races and store/audit interruptions. Static ceilings,
  1,024 receipts per resource and orphaned active-dispatch recovery limits are explicit.

### Public release preparation
- The commit gate checks each example's exit status before accepting its success
  message; regression tests cover failing examples and output after the message.
- Release archives and the container carry the project's licenses, attribution and
  trademark notices, plus reproducible Rust and Tower dependency license texts.
- Alpha setup, support, contribution and private reporting guidance is explicit.
- Release archives are self-contained: `ctx`, `contextosd` and `towerd` in `bin/`, the
  Tower UI in `tower/dist`, the Python HTTP client, the runnable examples and the docs
  (`scripts/package-release.sh`). Examples use `bin/` (or `CONTEXTOS_BIN`) before
  building with cargo, so they run with Python, Bash and curl alone; the release
  workflow runs the shared-guarantees demo from each unpacked archive.

### Tower: the governance plane
- `towerd` governs an organisation's agents across ContextOS runtimes: it reads each
  runtime tenant with a read-only key, verifies every audit entry before using it, and
  maintains the agent inventory (with owner declarations), each agent's authority graph
  and the control profiles it requires, findings with fixes, organisation guardrails
  (JsonLogic over agent facts), time-boxed waivers, risk reviews with drift detection,
  anomalies against each agent's own baseline, and a fleet-wide kill switch. Roles
  (viewer, owner, risk, operator, admin) with separation of duties; every decision in a
  signed journal verifiable with `ctx audit-verify`.
- Optional intelligence with Claude: Ask Tower (read-only tools, checked citations),
  guardrail drafting checked against the inventory, intake review drafts, anomaly
  briefs and run explanations. Advisory only; every use is journalled.
- The Tower UI (`tower/`), served by `towerd`; `examples/tower`.
- Developer documentation in `docs/tower/`: concepts, architecture and flow diagrams, the
  governance model, intelligence, API, security, a step-by-step build guide and operations.
- Runtime: a `run_admitted` audit entry attributes each run to its agent, pack,
  contract, required controls, surfaced capabilities and release references;
  `GET /v1/deployment`, `GET /v1/packs`, and `head` on audit pages.
- Configuration review: a `config` scope (never with `admit` or `dispatch`),
  `GET /v1/config` and `POST /v1/config/validate`, which classifies every effective
  change as tightening, loosening or neutral for CI. Production refuses the published
  development keys.

### Licensing
- Code is licensed under Apache-2.0 and documentation prose under CC BY 4.0; the
  name and logo are covered by a separate trademark policy (`TRADEMARKS.md`).

### Decision kernel
- Context Pack compiler, ActionRisk evaluation, profile negotiation, authority and
  delegation validation, policy composition, approvals and authorization, execution
  boundary, data flow, memory lifecycle, run lifecycle and resume, operation and budget
  ledgers, and conformance assessment, matching the spec's reference on generated
  parity vectors.
- RFC 8785 canonical JSON and domain-separated digests; bounded JsonLogic with
  `json-logic-js` semantics and fail-visible errors.

### Runtime
- Contract hardening (spec H01–H03): HTTP 202/206/207 leave the effect unknown;
  provider idempotency keys are `ctxos:v1:<sha256>` over tenant, run and operation,
  persisted and reused on retry; MCP adapters may select the lossless
  `result_projection = "mcp_result_v1"` (`flat` stays the default).
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
- Accepted HTTP jobs can be reconciled by provider query when the manifest declares
  `recovery.completion` (status endpoint, state pointer, confirmed/partial/not-applied
  states); unlisted states, missing jobs and failed lookups stay unknown. HTTP tool
  names `.` and `..` are no longer dispatched.
- Task authorization: a run may be admitted with what its principal asked for
  (`task_authorization`, `AuthorityGrant` scopes bound to the root run). Every effect
  must fall inside it, checked on the actual binding; outside, the action is denied
  or (`out_of_scope = "ask"`) waits for an exact approval first. Decisions,
  approvals and attestations bind its pinned reference, delegations inherit it, and
  `[guards] require_task_authorization` refuses effectful runs without one. The
  kernel exposes `scope_mismatch` and `valid_authority_scope`; the Python and Node
  clients add builders.

### Server and tools
- `contextosd`: compile, contract negotiation, schema validation, run admission,
  governed tool calls, input continuation, reconciliation, audit verification, health,
  readiness and Prometheus metrics; API keys and OIDC JWT callers bound to one tenant;
  strict JSON ingress; overload protection (global load shedding, per-tenant rate and
  concurrent-dispatch limits); OTLP trace export with W3C trace-context propagation.
- A run cannot recall two promoted memories holding different values for one key
  (`memory_conflict`).
- Production mode refuses delegations whose `output_schema_ref` is not a registered
  `[[result_schemas]]` entry.
- Recalled memory superseded by a newer promotion or correction of its key is refused
  (`memory_superseded`).
- Tenth security review fixes: memory keys scoped by owner and namespace, taken only by
  newer claims, tombstoned on deletion; rejected children's effects hold the parent;
  decisions must name their model when a fallback is pinned.
- Model fallback is traceable: a decision names which pinned `model_profile` produced it
  (a pinned fallback), and an unpinned model is refused.
- Decisions record the model router's `routing_decision_id` in their lineage.
- Production turns on `completion_requires_scores` by default (policy 1.0, safety 0.9);
  the gate covers every applied effect and accepted children. Ninth security review fixes.
- `[guards] completion_requires_scores`: a run completes only when every effectful decision
  holds independent scores at or above the policy and safety floors.
- Production mode requires pinned `model_profile`/`evaluator_suite` release refs and a
  stated `user.role` by default (`[guards] required_release_refs`, `require_user_role`).
- Python and Node clients: `open_escalations`/`openEscalations`,
  `resolve_escalation`/`resolveEscalation`.
- Eighth security review fixes: output schemas govern every outcome's output; erasure
  cannot miss concurrent feedback; rollout waivers audited and never on feedback cases;
  delegated result checks fail closed; `ctx trajectory-gate --audit`; escalations
  reopen and are opened once.
- `ctx trajectory-gate`: compare baseline and candidate runs of the same cases by the
  capabilities used, decision outcomes, effects and tool calls; acknowledgements per case.
- `[guards] require_tool_schemas`: refuse to start with an effectful capability that lacks
  an input or output schema; a production checklist in the guide.
- Delegations: an accepted child's recorded decision outputs must conform to the schema
  its envelope names (`[[result_schemas]]`, `child_output_invalid`).
- Escalation records: an escalated call opens one per operation (audited), listed at
  `GET /v1/escalations` and resolved once by an operator; resolving grants nothing.
- Tool calls whose principal chain does not end with the run's agent, or which misstate
  the capability's approval mode, are refused (`principal_chain_mismatch`,
  `approval_mode_mismatch`); an adversarial corpus of nine attacks runs in CI.
- Metrics by capability, refusal reason, pack and decision status (bounded labels); spans
  for compile, admission, delegation, decisions, scores, memory and erasure.
  `contextos_dispatch_outcomes_total` gains a `capability` label.
- `docs/INCIDENT.md`: roles, severity matrix, containment with the kill switch, evidence
  collection, specific incidents (key compromise, failed verification, injection, data
  exposure, outages), recovery gated on feedback, and a postmortem template.
- Dispatch returns the policy's obligations with every verdict; an `escalate` verdict is a
  structured hand-off (`policy_escalation`, obligation `escalate`), not a bare block.
- Recalled memory is verified at admission against promoted, current memory state the
  run's user or agent may read
  (`memory_unverified`); production without memory governance refuses it unless
  `[guards] trust_supplied_memory`.
- Capability manifests take an `output_schema`: non-conforming tool output is withheld
  from the agent and audited, while the effect is still recorded.
- Tool results carry `risk_tags` (the action's effect and reversibility, `human_approved`
  when an approval was redeemed), `policy_decision_id`, and `metadata.instruction_treatment:
  data_only`; an injection regression test covers forged approvals in output.
- Decision lineage records the pinned model profile and evaluator suite (`release_refs`);
  `[guards] required_release_refs` makes them mandatory at admission.
- Rollouts: a candidate takes live traffic only after the server's release gate passes on
  named runs' replay cases and every open feedback case (`gate_runs`, `acknowledge`).
- Erasing a run redacts the free text of its operator feedback.
- `ctx gate --feedback`: the release gate fails while an open correction's replay case is
  missing from the corpus.
- Python and Node clients: `file_feedback`/`fileFeedback`, `open_feedback`/`openFeedback`,
  `close_feedback`/`closeFeedback`.
- Operator feedback for the improvement loop (`/v1/runs/{id}/feedback`, `/v1/feedback`):
  corrections bound to runs and decisions, replay obligations, closed only with evidence.
- KMS-held audit signing keys (`[audit.kms]`, Vault Transit protocol): one batched
  signing call per group commit, every signature verified before writing.
- Audit key rotation: `[audit] retired_keys` keeps entries signed with a previous key
  verifiable and published. `ctx audit-verify --continues` verifies only new entries
  from a trusted head.
- Independent audit verification: `GET /v1/audit/keys` publishes the signing keys and
  `ctx audit-verify` checks an exported chain offline.
- Orchestrator checkpoints (`/v1/runs/{id}/checkpoint`): fenced, optimistic on
  revision, audited by digest, read after takeover, erased with the run.
- Loop guard (`[guards] identical_tool_calls`, default 5): repeated identical tool
  calls in a run are refused with `loop_detected` and `change_approach`.
- Budgeted model calls and replans (`/v1/runs/{id}/usage/reserve|settle`): the same
  ledger as tool calls; metered usage (new `meter` scope) settles to what was
  measured, self-reported usage is charged in full.
- Staged rollout of pack versions (`/v1/rollouts`, `control` scope): sticky
  percentage routing from baseline to candidate, shadow governance diffs audited on
  live traffic, clear to roll back.
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

### Metered model usage
- A model request carries its run and reservation in `ContextOS-Run-Id` and
  `ContextOS-Usage-Reservation`; `metering_headers` / `meteringHeaders` produce them and
  `budgeted_model_call(..., metered=True)` leaves settlement to the metering gateway
  (settling in full only if the call fails before the gateway did).
- `examples/metering-proxy`: a reference metering gateway for OpenAI Chat Completions
  and Responses and Anthropic Messages, streamed or not, that settles each reservation
  with the reported tokens (and cost, given prices) under the `meter` scope and fails
  closed on missing or reused reservations and missing usage.

### Repeated effects
- A new operation whose effect is identical to one the run already applied, or may
  have applied, is refused with `effect_repeated` (obligation
  `reconcile_existing_operation`), whatever its idempotency key or route, so a host
  retrying under a fresh key or mixing keyed calls with derived-key MCP calls cannot
  apply an effect twice. Capabilities marked `repeatable` and `[guards]
  refuse_repeated_effects = false` opt out. The effect is claimed atomically before
  dispatch, so identical effects racing in parallel are sent once. **Behavior change:**
  identical effects under different keys in one run were previously each applied.

### Framework integrations
- Implementation guides (`docs/integrations/`) and runnable examples
  (`examples/frameworks/`) for LangGraph, the OpenAI Agents SDK (Python and
  TypeScript), Google ADK, the Claude Agent SDK, CrewAI, Pydantic AI, LlamaIndex,
  Microsoft Agent Framework, the Vercel AI SDK and Mastra. Each runs the framework's
  own agent loop with governed tools, a budget reservation around every model call and
  refusals the model can read; without a provider key it uses a scripted model.
- `ToolPaused.kind` in both clients says what a pause waits on (`approval`, `input`,
  `unknown_outcome`, `duplicate`), and `governed_tool` / `governedTool` take a
  `tool_call_id` derivation so a decision can cite the call.
- The development approval service records approval requests and grants an exact
  approval when a reviewer approves one; `examples/frameworks/run.sh <framework>
  --approval` pauses each framework example for approval, approves it through the
  framework's human-in-the-loop mechanism and redeems it with the identical call. CI
  runs every framework example in both modes.
- `contextos.aio`: the Python client for asyncio agents (`AsyncClient`, `AsyncRun`,
  async governed tools), still standard-library only. Both clients raise
  `BudgetExhausted` for a reservation the run cannot afford and have
  `budgeted_model_call` / `budgetedModelCall` to reserve and settle around one model
  call.
- MCP `tools/list` names tools as model APIs require (`[A-Za-z0-9_-]{1,64}`):
  `adp_payments.issue_refund` is listed as `adp_payments_issue_refund`, with the
  capability id in `title` and `_meta["io.contextos/capabilityId"]`; `tools/call` takes
  either name. **Behavior change:** hosts that matched listed names against capability
  ids see the new names.
- MCP `tools/call` accepts the host's call id in `_meta["io.contextos/toolCallId"]`,
  returns the call and operation ids in `_meta` on every result, and tells the model in
  the error text whether the refused call had any effect.

### Operations
- Distroless non-root image, hardened Helm chart, signed releases with provenance and
  SBOMs, cargo-deny policy, property fuzzing, threat model, benchmarks.

- Budget-ledger compaction (ADR-0003): settled reservations move to chained archives
  with unchanged counters, so runs are no longer limited to about 64 effects and
  per-effect cost stays flat.

### Known limits
- At most 64 reservations can be open at once in one run.
