# ContextOS Foundations: Implementer's Requirements Digest (for a Rust runtime harness)

I read all 13 files in full under /opt/contextosai/src/content/docs/: foundations.mdx and foundations/{cognitive-core, orchestration, memory, governance, adapter-mesh, harness-engineering, evaluation-observability, improvement-loop, identity-layer, agentic-context-engineering, ontology, knowledge-graph}.mdx.

**How normative language works in these docs.** I grepped the 13 files for uppercase RFC 2119 keywords (MUST/SHALL/SHOULD) and found none. The docs state obligations in lowercase prose ("must", "never", "cannot", "fail closed", "is rejected"). Below, **MUST** marks those prose obligations and is my interpretation. Several concrete schemas are owned by implementation docs that I was not asked to read: execution-contract, context-pack, api-contracts, decision-record, control-profiles and conformance. The foundations docs repeatedly say the repo ships only deterministic reference checks, and that production enforcement (stores, brokers, sandbox, fencing) needs runtime evidence.

**Non-normative / roadmap flags (grepped):**
- The orchestration `Session` JSON is "an illustrative application view, not a replacement for the additive `RunExecutionState`/`ExecutionCheckpoint` attachments".
- The governance approval-mode table column is titled "Illustrative migration baseline".
- "irreversibility budget" and `ReversalSpec` are a "future policy/schema extension, but neither is canonical today". They must not be used to bypass ActionRisk, approval, postcondition, receipt or recovery requirements.
- The six Improvement Loop records (`Insight`, `StrategyRule`, `FeedbackRecord`, `Note`, `ResearchTask`, `TuningProposal`) are "candidate profile records, not canonical exported ContextOS types". There are "no published schemas or exported types yet", so you version and validate them locally.
- The release manifest is "a documented protocol, not a new canonical core type".
- "Autonomy budget" is shorthand, "not a canonical runtime type".
- The example scorecard's `release_gate: "pass"` is illustrative and is not a `ConformanceReport`.
- The Astra paired-evaluation scenario is synthetic reference validation.
- The `ctxid/1` signed claim is an optional profile.
- `ExecutionContractEnvelope`, `BudgetLedger`, `MemoryLifecycleRecord`, `ActionBinding` and the operation ledger are "additive" attachments. They add no required fields to the closed v1 envelopes.

---

## 1. foundations.mdx (overview / cross-cutting)

**Foundation rule.** A run is acceptable only if it can answer five questions, each backed by an artifact:
- Intelligence: ontology version, CEIDs, graph evidence, promoted memory.
- Context: `ContextPack`, `CompiledContext`, source manifests, budget report.
- Decision: plan, critic verdicts, decision spec binding.
- Action: `ToolEnvelope`, stable operation identity, native action risk, recovery/postcondition evidence.
- Trust: grant/approval evidence, policy decision, evaluator result, trace id, `DecisionRecord`, replay handle.

A missing artifact narrows the conformance claim.

**Plane direction.** Intelligence → Context → Decision → Action, with Trust wrapping every boundary.

**Run sequence:**

| Step | Name | Contract produced |
|---|---|---|
| 1 | Capture | `RunContext` |
| 2 | Ground | CEIDs, graph evidence, memory candidates |
| 3 | Compile | `CompiledContext` |
| 4 | Decide | plan, verdicts, decision binding |
| 5 | Act | `ToolEnvelope` |
| 6 | Record | `DecisionRecord` |
| 7 | Improve | scorecard / proposal / pack version |

**End-to-end contract.** `invokeAgent(request_envelope, RunContext)` produces `DecisionRecord(evidence_refs, approvals, controls_active, trace_id, replay_id)`. Consolidation writes memory *proposals* through governed promotion, never direct durable writes.

**Cross-cutting primitives:**
- `RunContext`: `run_id`, `trace_id`, `session_id`, `tenant_id`, user delegation, agent workload identity, safety mode, run budget.
- `ActionRisk`: effect, authority, reversibility, interaction, data_scope, optional decision TTL. Each dimension is evaluated independently.
- `ApprovalMode`: `read_only | local_write | network | delegated | destructive`. This is the v1 compatibility projection and the `RunContext.safety_mode` ceiling, not a complete risk model.
- `ContextPack`: versioned, immutable; layers are evidence, policy, tools, memory, decision. Signatures are an optional profile.
- `CompiledContext`: prompt, manifests, omitted context, runtime controls, budget report.
- `ToolEnvelope`: request/result, policy decision, principal chain, native risk, v1 projection, idempotency, evidence, trace.
- `DecisionRecord`: outcome, evidence refs, approvals, controls active, policy decisions, confidence, trace id, replay handle.
- `ExecutionContractEnvelope`: exact profiles, required/optional controls, `release_refs`.
- `ActionBinding` plus authority/approval attachments. An id, hash, confidence score or model claim cannot grant permission.
- Boundary, data-flow and memory-lifecycle attachments.
- Run/operation/checkpoint and `BudgetLedger` attachments. Recovery cannot reset spending, widen authority or infer that an unknown effect did not happen.
- `ConformanceReport` vs `ReferenceValidationReport`. A reference pass is never runtime certification.

**Improvement invariant.** "The harness may be searched, but it must not silently mutate." Every proposal names a target metric, replay set, guardrails, owner and rollback target. Lifecycle: `proposed -> reviewed -> approved -> released`, plus recorded `rejected` and `superseded`.

**Per-plane invariants** (things that must not be tuned away):

| Plane | Invariants |
|---|---|
| Intelligence | CEID stability, provenance, classification, snapshot pinning |
| Context | required evidence coverage, redaction, policy manifest, tool manifest |
| Decision | DecisionSpec binding, approval gates, loop guards, replayable plan/verdict |
| Action | schema validation, ActionRisk ceiling, conservative v1 projection, credential exchange, stable operations, declared retry/reconciliation |
| Trust | safety/policy floors, human approval for promotion, append-only audit |

**Adoption checklist** (gates for production-ready):
- Entity model: types, CEIDs, relationship rules.
- Versioned ContextPack, plus compiler manifests, omissions, controls and budgets.
- Every external capability behind the Tool Gateway.
- Outputs bind to a DecisionSpec and produce a typed DecisionRecord.
- Policy lives outside agent code.
- Evidence refs exist for material claims.
- Replay against pinned context, policy, tools and evaluator.
- Failures become proposals, not prompt edits.
- An Autotune run declares target metric, guardrails, tunable surfaces, disjoint search/test sets and rollback target.
- Trusted feature admission selects the exact obligations, and each mandatory control has current verified evidence.

## 2. cognitive-core.mdx (Context + Decision)

**Inputs:**
- `invokeAgent` envelope.
- `RunContext` (`run_id`, `trace_id`, `session_id`, `tenant_id`, `safety_mode`, `run_budget`, `user`, `agent`).
- Pinned pack version(s).
- KG snapshot.
- Memory state (working / episodic / semantic / durable).

**Outputs:**
- `CompiledContext` (prompt, manifests, `runtime_controls`, `budget_report`).
- `DecisionRecord` (`decision_id`, `evidence_refs`, `approvals`, `controls_active`).
- Tool transcripts, evidence manifest, memory write proposals, trace bundle.

**Lifecycle:** `[compile, plan, verify, execute, score, consolidate]`.

**Turn layers, in order (logical state, not extra fields in the closed v1 `RunContext`):**

| Layer | Output |
|---|---|
| Runtime budget gate | `gate_decision`; emits heartbeat |
| Perception | `events[]` |
| Focus mode (optional) | `focus_state` |
| Attention/Salience | `focus`, `salience_scores` |
| Identity | `agent_self` |
| Goals/Intent | `intent`, `active_goals` |
| Judgment (the LLM call) | `candidate` |
| Policy gate (deterministic, before any side effect) | `verdict`, `obligations` |
| Action (via Tool Gateway) | `effects[]` |
| Consolidation | `proposals[]` |
| Reflection | `reflection` |

- Every layer emits OTEL spans tied to `trace_id`.
- `read_only` excludes mutating capabilities. Permitted reads still go through the gateway with authority, data and budget checks.
- Replay uses recorded observations and never repeats live effects.

**Compiler pipeline (pure, 8 stages):**
1. Intent classification against the Intent-Task Catalog.
2. Policy resolution. JsonLogic rules are evaluated against the RunContext and produce `must_refuse`, `must_escalate`, `requires_approval_gate`, `prohibited_capabilities`. An *applicable predicate exception* MUST throw a sanitized `ContextCompileError` (structured `policy_eval_error`) and stop. An ordinary false predicate keeps its false/else behaviour.
3. Tool surfacing: `Registry ∩ Permissions − Prohibitions`, then native-risk policy, then enforce the `RunContext.safety_mode` ceiling.
4. Evidence normalization. Verify content hashes and label source, integrity, freshness and covered requirements. A caller hash mismatch fails the compile visibly.
5. Memory recall: promoted memory only, never raw capture.
6. Token budget allocation across buckets `business`, `policy`, `tool`, `evidence`, `memory`, `session`.
7. Bucket admission and assembly. Assign `control` or `data_only`, reject ineligible evidence, record every budget omission.
8. Manifests and runtime controls: `evidence_manifest`, `context_admission`, per-decision `evidence_gates`.

**Two non-model gates:**
- **Admission.** Pack, policy and tool-registry material may be `control`. Retrieval and memory are always `data_only`, even when verified.
- **Evidence gating before commit.** `DecisionSpec.required_evidence` is satisfied only by admitted, current, verified, conflict-free evidence or by explicit structured request context. Untrusted, stale, unknown-freshness, budget-omitted, unresolved-conflict and resolution-superseded items go to `rejected_evidence`. A known unresolved conflict means `insufficient` and `commit_allowed: false`. The gateway MUST re-check actual arguments and their provenance right before execution.

**Triple-check governance, in order:** permission level (role), then rule level (intent), then situational level (current verified evidence). Compile-time prohibitions remove the tool. Dispatch-time checks still block later. `commit_allowed` is a sufficiency result, not execution authority.

**Budgets and loop guards (enforced deterministically):**
- Token budget per bucket.
- Tool-call budget per turn and per workflow.
- Wall-clock budget with heartbeat.
- Loop guard: repeated identical tool calls or no-progress reflection cycles MUST short-circuit with structured `loop_detected` returned to the planner.
- Re-plan budget.
- Budget updates MUST be atomic, so parallel lanes cannot race.
- `BudgetLedger` reserves root/child/retry/replan capacity against the original ceilings and a shared absolute deadline, in exact declared cost units.
- Resume cannot restore spent capacity. Uncertain usage keeps its reservation.

**Functional state** (`functional_state`; all values 0.0–1.0, plus `captured_at`):
- Signals: `budget_pressure`, `loop_pressure`, `evidence_pressure`, `gate_pressure`, `conflict_pressure`, `escalation_propensity` (a composite that includes the intent risk class).
- Captured at every turn boundary and persisted in the DecisionRecord `lineage` block.
- Read-only for the Judgment and Action layers; the model never sees the raw scalars. It never mutates policy.
- The Critic may prefer `escalate` over `replan` on a tie when propensity is elevated.

**Failure modes:**
- Silent truncation. Use an always-explicit `truncated` flag.
- Retrieved instructions gaining control.
- Stale or untrusted evidence closing a gate. This is a compiler defect.
- Required evidence losing the budget race. Record the omission and reject it for the gate.
- Hash mismatch.
- Stale cached policy. Use version pinning and a pack hash check.
- A throwing predicate.
- A loop guard tripped without a reason.
- A subagent lane mutating the parent RunContext. The lane MUST get an isolated copy.
- Reflection recommending a bypass of the policy gate.

**Operational:**
- A per-stage latency budget overrun converts to a Critic `escalate`.
- Tool timeout and retry budgets are enforced by the RunContext, not the adapter.
- Replay: deterministic artifacts compare exactly; model stages compare via declared properties or scorecards.

**Metrics:**
- Plan-verification pass rate per intent.
- Tool success and recovery rate.
- Evidence-backed output rate.
- Evidence-gate closure rate and unresolved-requirement distribution.
- Untrusted-evidence gate-satisfaction rate (target 0).
- Structured omission rate for required evidence.
- Policy-compliance rate.
- Mean time to safe completion.
- Loop-guard trip rate.

## 3. orchestration.mdx (Decision plane)

**Key types:** `Plan`, `DecisionRecord`, `ToolCall`, `ToolResult`, `AgentDelegationEnvelope`. Lifecycle: `[plan, verify, execute, score, consolidate]`.

**Roles:**
- **Planner:** typed plan only, no side effects, sees the full CompiledContext. Timeout 5–30s by task class.
- **Executor:** runs verified steps only and cannot extend the plan. On failure or unexpected evidence it returns to the Planner with a structured reason. Per-step adapter timeout.
- **Critic:** verifies the plan (allow-lists, evidence, capability bindings, native risk, v1 ceiling, decision rules), scores steps and the run, and emits `accept | retry | replan | escalate`. Agreement among model roles cannot waive authority, approval, boundaries, data policy or budget.

**Plan shape:**
- `plan_id`, `intent`.
- `steps[]` with `{id, tool, params, depends_on[], approval_mode, requires[]}`.
- `decision_checkpoints[]` with `{decision_id, after_step}`.

**Routing:**
- Inline execution only when policy, identity, evidence, data, destination, budget and approval checks all pass.
- A named approval obligation creates a propose → approve → execute sub-sequence with a frozen evidence/argument snapshot.
- Network does not imply human approval.
- A low v1 mode does not waive a gate selected from another dimension.
- A model cannot remove a gate or lower risk by relabelling.

**Subagent lanes:**
- Each lane gets its own RunContext, token budget, tool surface and trace span. Completion is a typed envelope, and lane traces are stitched into the parent.
- Lanes MUST NOT mutate the parent's `effects[]`; the parent Critic accepts or rejects their results. Loop guards trip independently per lane.
- Child authority narrows every ancestor's mandate (exact parent/child/root binding, revocation, inherited deadline).
- `reserveChildBudget` reserves from the parent pool before fan-out. Root calls, retries and replans use `reserveBudget` on the same pool. Verified cumulative terminal usage releases unused capacity; unknown usage retains it.
- **Per spawn the runtime MUST:**
  - bind the delegation envelope and enforce the child's scope, classification ceiling, expiry, tool surface and sub-budget;
  - apply context admission to copied material, preserving labels (copied history never becomes policy);
  - retain the context policy, parent checkpoint/artifact refs and admitted/omitted evidence in a versioned trace attachment;
  - keep output/effect acceptance separate from context inheritance.
- Context mode is not a new value of `AgentDelegationEnvelope.effect_policy`.
- An independent reviewer by default gets no author verdict, and later exposure is recorded.

**Deliberation protocol:** Isolate → Deliberate over evidence → Preserve minority (dissent stays attached) → Certify externally (assurance scales with ActionRisk) → Decide once (one parent owns the verdict and effect). Voting never replaces policy, approval or postconditions.

**Passive awareness channel:**
- Message fields: sender lane, parent run, subject, evidence refs, confidence/uncertainty, sensitivity, TTL, recipients.
- Delivered only at safe points and recorded in the recipient trajectory.
- Bounded in size and rate, deduplicated, backpressured.
- Recipients may accept, reject or ignore. A message cannot carry authority, approvals or capabilities.

**Durable session state machine** (for `mode: "long_running"` with `runtime.max_session_duration_ms` ≥ 1h):

| From | Allowed transitions |
|---|---|
| `created` | `running`, `cancel_requested`, `failed`, `expired` |
| `running` | `waiting_approval`, `waiting_external`, `suspended`, `cancel_requested`, `completed`, `failed`, `expired` |
| `waiting_approval`, `waiting_external`, `suspended` | `running` (after current checks), `cancel_requested`, `failed`, `expired` |
| `cancel_requested` | `cancelled` (after verified stop ack), `failed`, `expired` |

- Terminal states: `completed` (all required effects confirmed and children settled), `failed`, `expired`, `cancelled` (effect uncertainty may remain).
- Legacy labels map as `in_progress`→`running`, `awaiting_gate`→`waiting_approval`, `paused`→`suspended`.
- Approval denial is evidence driving a `fail` event, not a `RunStatus`. Gate expiry is not run expiry.

**Spawn:** the Conversation Manager persists the initial session row before any plane runs.

**Checkpoint:**
- Written after every Critic verdict (`ok` / `accept` / `replan`).
- Payload: `plan_id`, `tool_transcripts[]` ids, `evidence_refs[]`, an atomic `RunBudget` snapshot, step scores, next-step pointer.
- Append-only, content-addressed, immutable.
- `ExecutionCheckpoint` pins the contract, pack, policies, registries, releases, operation/budget ledgers, pending work and cancellation. The controller MUST atomically enforce expected revision and executor generation.

**Resume:**
- Missing or mismatched pins block. A newer registry version never silently applies; policy changes need explicit migration and reauthorization.
- Available capacity = original ceiling − used − reserved, with the deadline unchanged.
- MUST NOT redispatch confirmed effects. An unrecorded dispatch is `unknown`.
- Revalidate identity, revocation, delegation expiry, approval binding and preconditions before protected I/O.
- Reconcile uncertain effects through the adapter lookup/idempotency contract. If that fails, pause or escalate; never issue a fresh logical operation.
- A cancel ack does not certify prevention.

**Heartbeat:**
- The watchdog requests `suspended` after a missed threshold and fences stale ownership.
- TTL is hard. On expiry it emits `Session expired` and a terminal checkpoint.

**Progress envelope:** `session_id`, `progress_id`, `emitted_at`, `current_step`, `completed_step_count`, `total_step_count`, `budget_remaining{tokens, tool_calls, cost_cents, wall_clock_ms}`, `awaiting_gate`.

**Session failures:**
- Pin mismatch: refuse restore.
- Heartbeat loss: suspend and fence.
- Checkpoint write fails: stop dispatch and reconcile.
- Over budget: no new reservation or dispatch; escalate. Budget migration must retain consumed capacity.

**Replay:** from the recorded CompiledContext, Plan, transcripts, policy/evaluator/model-profile versions and KG/memory/registry snapshots, re-derive the verdict and DecisionRecord with no live tools.

**Execution model:**
- Idempotency depends on the provider's key/payload scope, retention and mismatch contract.
- Retry budgets per step and per workflow.
- A timeout after possible dispatch preserves `unknown`, with no blind retry and no weaker-boundary fallback.
- Compensation is a new governed operation, not a rollback.
- Step failure returns to the Planner under the re-plan budget. **Default re-plan budget is `2`.**

**Autotune limits:** no direct execution, approval bypass or untyped plans. A candidate must emit a replayable Plan, transcript expectations and a DecisionRecord diff.

**Metrics:**
- Plan-verification pass rate; step completion; retry/recovery rate.
- Escalation rate by risk tier.
- Lane success vs parent re-plan rate.
- MTTSC.
- Wrong-unanimous, disagreement, and minority-rescue vs minority-erasure rates.
- Effective agent count (correlation-adjusted).
- Counterfactual lane influence; cost per externally certified outcome.

**Verdict envelope:** `run_id`, `plan_id`, `verdict`, `step_scores[{step_id, scores{policy, utility}, approval_gate, approver}]`, `loop_guard_trips`, `replan_attempts`.

## 4. memory.mdx (Intelligence)

**Key types:** `MemoryPolicy`, `MemoryLayer`, `MemoryProposal`, `PromotedMemory`, `WriteClass`, `MemoryLifecycleRecord`, `MemoryLifecycleContext`.

**Pipeline:** `capture (immutable) → candidate → review queue → promoted → compiled context` (lifecycle `[capture, candidate, review, promoted, compiled]`).
- Capture is minimized and authorized. Credentials and unrestricted raw payloads MUST NOT be copied.
- Candidates carry `(entity, relation, value, evidence_refs, confidence)` and sit above a confidence floor. They are not visible to retrieval, and rejections are remembered.
- Promotion includes a contradiction check.
- Only promoted memory is compiled, re-filtered by tenant, role, classification and intent.

**Recall is reconstruction, not retrieval:**
- It joins current source state, stored memory, fresh evidence, current policy and current authority, then applies scope, freshness, contradiction, consent and applicability rules.
- Ranking is never a trust boundary.
- Unrefreshable source: explicitly omit, surface uncertainty, request evidence or escalate. Never treat the stored record as current truth.

**Tiers:** Working (minutes–hours), Episodic (hours–days), Semantic (long-lived, explicit deprecation), Durable (months–years, policy-driven).

**Promotion:**
- Auto-approval only for classes and conditions named by policy. Auto-promotion is not the default.
- Contradictions on the same entity/relation never silently overwrite. They emit a `memory.contradiction` event (or auto-resolve under an explicit rule).
- **Write classes:** `evidence_link`, `preference`, `decision_outcome`, `correction`. Each has its own allow-list, retention, risk policy, approvals and v1 projection.
- `correction` outranks prior records on the same key and emits a learning signal.
- Consent is checked at the candidate stage, and redaction happens before write.

**Poisoning lifecycle (5 boundaries):** Capture (labels, influence path) → Promotion → Recall → Action (memory informs but never authorizes) → Repair (quarantine, preserve influence history, replay affected runs, superseding correction or tombstone, verify, then restore eligibility). Memory is non-escalating across principal, delegation, scope, classification, amount, time, approval and ActionRisk ceiling.

**Consent record** (typed, append-only, tenant-scoped):
- Fields: `consent_id`, `subject_ceid`, `tenant_id`, `purpose`, `scope{predicates_allowed[], data_classifications_allowed[]}`, `basis`, `captured_at`, `valid_until`, `revoked_at`, `evidence_refs`, `auditor_id`.
- Lifecycle: `captured → active → revoked | expired → tombstoned`.
- Promotion of `preference` / `decision_outcome` / `correction` on a PII attribute MUST resolve a live `consent_id`, or be rejected at the candidate stage. The matched `consent_id` is recorded on the promoted record.
- Revocation is honoured on the next recall, tombstones existing records and emits `memory.consent_revoked`.
- Never modified in place; supersede via a `supersedes` link. Cross-tenant consent does not exist.
- Missing consent means recall returns no record, never a redacted stub.

**Namespaces and lifecycle:**
- A namespace binds tenant, owner, purpose and readers.
- `MemoryLifecycleRecord` covers `propose`, `promote`, `correct`, `delete`. `validateMemoryLifecycle` checks namespace/owner, provenance, bounded retention, review, data-flow and derived copies.
- Profile `memory.lifecycle@1` is required whenever persistent memory is admitted.
- Deletion propagation states: `pending`, `failed`, `external_unknown`, distinct from `completion_verified`. Completion needs verified receipts for the primary and every derived copy, plus a complete inventory.
- Retention expiry blocks new promotion/correction, not cleanup.
- Receipts bind intent, record, operation and artifact, and cannot be reused across operations.

**MemoryProposal shape:** `proposal_id`, `candidate{entity_ceid, predicate, value, evidence_refs, confidence}`, `class`, `tier_target`, `consent_check`, `contradiction_check{existing, verdict}` (e.g. `no_conflict`), `auto_promote_eligible`. `consent_check` and `auto_promote_eligible` MUST come from trusted policy, not the model.

**Outputs also include:**
- Recall decision records: admitted / omitted / stale / contradictory / quarantined, with reasons.
- Repair lineage.

**Metrics:**
- Hit rate; token reduction vs retrieval baseline.
- PII write-back violations (target 0).
- Contradiction resolution time; correction adoption; accuracy.
- Memory Decision Scorecard: eligibility precision/recall, contradiction handling, authority non-escalation, fallback correctness, provenance completeness.
- Poisoning detection-to-quarantine time; repair replay pass rate.

## 5. governance.mdx (Trust)

**Key types:** `PolicyBundle`, `ApprovalGate`, `ActionRisk`, `ActionRiskPolicy`, `ApprovalMode`, `DecisionAudit`. Lifecycle: `[intercept, evaluate, decide, gate, audit]`.

**ActionRisk dimensions (exact values):**

| Dimension | Allowed values |
|---|---|
| `effect` | `none`, `local_state`, `external_state`, `physical_world` |
| `authority` | `agent`, `service`, `user_delegated`, `human_approved` |
| `reversibility` | `read_only`, `reversible`, `compensatable`, `irreversible` |
| `interaction` | `api`, `browser`, `computer`, `agent_to_agent`, `human_handoff` |
| `data_scope` | `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED` |

- Optional `decision_ttl_seconds` (seen in the adapter-mesh example).
- Each dimension is a conjunctive policy input, not a score. The engine emits an effective vector plus the legacy projection.
- `ApprovalMode` is NOT a total order.
- A non-read effect should require an effect protocol: observable postcondition, idempotency, and one of rollback / retraction / compensation / explicit non-recoverability. The receipt is recorded and external state verified independently.

**Autonomy** is the intersection of identity/delegation, decisions, capabilities, scopes, amount/time, `RunBudget`, ActionRisk, evidence, gates and sandbox. Deny if any required constraint is absent. No dimension cancels another.

**v1 modes (illustrative baselines):**

| Mode | Baseline |
|---|---|
| `read_only` | audit |
| `local_write` | idempotency key + audit |
| `network` | egress policy + rate budget |
| `delegated` | user delegation token + per-call evidence |
| `destructive` | named approver when policy says, plus frozen evidence and post-audit |

- Policy may select a lower *effective* mode within the declared maximum. It cannot exceed the maximum or invent a mode.
- Record the effective mode and approver per execution.
- Validate that the legacy mode is a conservative projection of the vector.

**Enforcement boundary vs approval path:**
- The effective capability set = sandbox ∩ identity scopes ∩ policy ∩ surfaced manifest.
- An approval may select only a predeclared capability transition. It never replaces the sandbox, mints broader credentials, disables a deny or authorizes an undeclared tool.
- Machine reviewers are approvers only if policy names that automated principal. Parse failure, reviewer failure, missing evidence and timeout MUST fail closed. A named human cannot be substituted.

**Authority non-escalation:**
- Prompts, documents, memory, tool metadata/results, web pages, manifests and peer messages are evidence only.
- Every transition recomputes authority as the intersection of claims, parent delegation, manifest ceiling, policy, containment and approval.
- Conflict or missing claim fails closed.

**Boundary enforcement:**
- Intercept every `ToolCallEnvelope`.
- Refuse revoked registrations, expired or invalid claims, tenant mismatch, and child claims broader than parent or manifest.
- Enforce parameter constraints.
- Return structured denial obligations `escalate | request_approval | collect_evidence`.

**Generated-rule checks:** permissiveness drift, restrictiveness drift, unsatisfiable conditions.

**Policy lifecycle:** Author → Validate → Approve → Publish → Enforce → Audit. Checkpoints: compile (selection, guardrails), plan (steps, evidence, approvals), execute (just-in-time).

**Audit:**
- `policy_decision_id` plus matched `rule_ids[]` per verdict.
- Minimal claims/args evidence.
- `principal_chain` and opaque `auth_ref` per action; with the signed profile, subject, claim hash, key id and scope summary outside model context.
- Tie to the DecisionRecord.
- Approvals persist approver identity, frozen evidence snapshot hash and effective mode.

**Bundle shape:**
- `bundle_id`, `effective_from`, `priority`, `policy_dsl{language:"jsonlogic", rules[]}`, `prohibited_claims`.
- Rule: `rule_id`, `applies_to{intent}`, `if`, `then{allow, requires[], approval_mode, requires_approval_gate, arg_constraints{field:{max, min, enum, unless_approved, required, pattern}}}`, `else{allow, reason}`, `decision_binding`, `rationale`, `citations`.

**Approval workflow:**
1. Gate triggered (`requires_approval_gate`).
2. Freeze: canonical `ActionBinding` digest, proposal/request ids, evidence/policy/authority/release pins, stored validity interval.
3. Notify by role.
4. Record approve/deny with rationale.
5. Revalidate and redeem: authority/revocation, approver entitlement, preconditions, boundary, data and reserved budget; then **atomically redeem** under revision/ownership checks and dispatch.

An expired stored request blocks even if the decision object claims a later expiry. `approval.bound@1` supports standing mandates. Trigger text and notifications cannot create consent.

**Conflict resolution (`composePolicyOutcomes`):**
- Guardrails (must_refuse / must_escalate) are absolute and kept in a separate category.
- Higher-priority business allow can override a lower-priority deny.
- Equal priority: deny wins.
- A selected escalation or required approval still blocks dispatch.
- No applicable outcome → deny.
- Evaluation failure or conflicting duplicates → error.
- Obligations from losing rules are retained and discharged independently.

Mandate, tenant binding, attenuation, containment, data movement, budget and approval are each independent of business allow. Recheck revocation, expiry and freshness at dispatch and resume. A policy revision change suspends for reauthorization.

**Metrics:** compliance rate; approval latency/rate by native-risk slice and v1 mode; evidence attachment success; audit gap rate (target 0); permission-violation rate.

## 6. adapter-mesh.mdx (Action)

**Key types:** `ToolCallEnvelope`, `ToolResultEnvelope`, `AdapterDefinition`, `ToolPermission`, `ActionRisk`. The gateway is the only path to side effects.

**Registration:** capabilities, schemas, auth, native `ActionRisk`, authority/destination ceilings, v1 `approval_mode`.

**Supply-chain admission** (discovery is not admission). The manifest is pinned and verified:
- owner, publisher/signature, deps, version, schemas, endpoints, capability classes;
- ActionRisk ceiling, compat mode, identity/tenant behaviour, data/egress ceiling;
- retry/idempotency/compensation behaviour, security tests, operational owner, kill switch.

Generic proxy tools (arbitrary network/shell/browser/DB access from model text) are rejected. Read and write capabilities are discoverable separately.

**Gateway validation order (MUST):**
1. Pinned manifest and integrity.
2. Actor, workload, principal chain, tenant, freshness.
3. Intersect scopes with manifest, policy, sandbox and approval ceiling.
4. Validate args, destination, classification, budget and idempotency key.
5. Short-lived call-bound credential exchange.
6. Dispatch under current ownership.
7. Validate typed result, normalized effect, postcondition, citations and recovery receipt.

Redirects, retries, callbacks, resumes and A2A handoffs repeat the checks; there is no ambient authority.

**Operations and uncertain effects:**
- Persist the logical operation id and the complete normalized action before write dispatch. Retries reuse that identity.
- Write-capability admission must declare postcondition, idempotency scope/retention, mismatch behaviour, outcome lookup, and compensation or non-recoverability.
- Effect observations are confirmed effect / confirmed no effect / unresolved (not `ToolResultEnvelope.status` values).
- Operation ledger states: `not_dispatched`, `confirmed`, `not_applied`, `partial`, `unknown`.
- `claimOperation` requires current authorization. `recordEffectObservation` records late facts without granting ownership or settling budget.
- Retry only if the contract makes it safe and authority holds; otherwise stop and route to a recovery owner.

**Boundaries:**
- `ExecutionBoundaryRequirement` is evaluated against verified observations. Missing requirements block with no weaker fallback.
- `evaluateDataFlow` covers collection, inference, tool I/O, telemetry, cache, memory, export and delegation.

**`capability_class`:** `observe`, `recall`, `think_support`, `act`, `verify`. A `read_only`-intent plan MUST NOT include `act`. The compiler prefers `verify` over `observe` when evidence_refs are required.

**Skills:**
- Fields: `skill_id`, `version`, `purpose`, `required_capabilities[{capability_class, name}]`, `preconditions`, `postconditions`, `prompt_fragment_ref`, `evaluation_set_ref`, `owner_role`.
- Versioned and signed. Expanded inline as a typed sub-plan.
- Cannot exceed `tooling_layer.permissions`.
- Paired release gate: positive Skill Lift, activation/silence, no regressions.

**Cached read-only aliases:** allow-listed, discovery only, still executed via the gateway, revalidated on policy change.

**Invariants** (changing any requires a governed release): native-risk ceilings, conservative projections, arg constraints, credential exchange, tenant isolation, operation/retry guarantees.

**Protocols:** MCP 2026-07-28 profile; A2A 1.0 with narrowing delegation and policy at each hop; OpenAPI import. MCP and A2A boundaries stay explicit in the trace.

**ToolCallEnvelope fields:**
- `envelope_version: "contextos.tool_call.v1"`, `tool_call_id`, `run_id`, `trace_id`, `session_id`, `capability_id`.
- `approval_mode_requested`, `approval_mode_effective`, `approval_mode_highest`.
- `policy_decision_id`, `args`, `principal_chain[{kind, id, tenant_id}]`, `evidence_refs`, `idempotency_key`, `auth_ref`.

**Permission fields:** `permission_id`, `adapter_id`, `capability`, `allow`, `action_risk{…, decision_ttl_seconds}`, `approval_mode`, `arg_constraints`, `decision_binding`.

**Outputs:**
- `ToolResultEnvelope` with citations, normalized effect, mutation refs, postcondition evidence, recovery status, `policy_decision_id`, trace.
- Structured errors with retryability and remediation hints.

**Operational:**
- Egress rate budgets per `(tenant, capability)`.
- Per-tool latency enforced by the RunContext.
- Revalidate admission on publisher/signature/dependency/schema/endpoint/ownership change.

**Metrics:**
- Success by `(adapter, capability)`.
- Native-risk coverage, dimension-level denial accuracy, unsafe projection rate.
- Permission violations per 1k.
- Mean/p99 latency.
- Idempotent replay correctness under chaos duplicates.
- Postcondition verification rate; uncompensated partial-effect rate.
- Skill Lift.

## 7. harness-engineering.mdx (cross-plane)

**Eight properties a conforming harness must demonstrate:** Context-aware, Policy-governed, Tool-controlled, Validated, Observable, Reversible, Measurable, Continuously improving. Controls (authz, credential isolation, tenant, evidence, budget ceilings, reconciliation) are separate from compensating scaffolding (prompts, decompositions, resets, reviewers, skills). Removing scaffolding must not remove a control.

**Canonical loop:** Planner → Critic.verify → Executor → Critic.score → Consolidate. Roles do not require separate model calls.

**Release tuple:** runtime code + model route + prompt/skill versions + Context Pack + policy bundle + tool/adapter manifests + evaluator/rubric versions + environment/sandbox profile.
- A run with only a model name or SHA is not attributable.
- `ExecutionContractEnvelope.release_refs` carries it, and `ActionBinding`, approvals and checkpoints pin it.
- An unpinnable provider revision must be recorded as a limitation.
- Promotion records candidate, baseline, datasets, graders, deltas, approver and rollback target.

**Proof-carrying execution packet:** who/on whose behalf/intent; tuple, evidence, policy, authority, budget; decision, authorized request, external change; postcondition and durable writes; failures/uncertainty; remaining recovery path. Rule: "No artifact, no claim."

**Rollout stages (enum):**

| Stage | Gate to advance |
|---|---|
| `0%_shadow` | delta within bounds ≥ N runs |
| `1%_internal` | no safety/policy regression |
| `5%_low_risk` | correction adoption trending down |
| `25%_monitored` | scorecards stable |
| `100%` | prior version pinned; two-week clean canary |

Each stage has a kill switch that stops execution or restores the prior version and routing. Managed runtimes declare an achievable fallback.

**Security gate:** six phases (configuration, extension loading, runtime execution, persistence, external action, recovery). Critical classes need zero successful attacks.

**Reviewer agents:** Architecture, Security, Reliability, Product, Data, Cost, Compliance. Typed output: `status, findings, severity, policy_id, recommendation`.

**Smallest durable layer:** RunContext/plan → scoped AGENTS.md → versioned skill → validator/hook/policy/CI → scheduled runner. Do not schedule an unstable method.

**Managed runtime:**
- Owners must be named for session continuity, isolation, credentials, tool authz, reconciliation, outcome acceptance, retention and incidents.
- Must demonstrate delegation scope preservation, revocation during pause, lost-response reconciliation, cancellation races and retained evidence under interruption.

**Operational:**
- Kill switch operates on the whole tuple.
- Search/test sets disjoint.
- Interface validation runs before full eval.
- Trace retention follows data classification.

**Metrics:** pack adoption; eval pass rate; policy violation rate; human intervention rate; MTTR; change failure rate (retired ≤ 90d); rollback rate; cost per verified success (undefined when there are zero accepted outcomes); lead time from correction to StrategyRule.

**Key type:** `ReplayPacket`. The example DecisionRecord uses `status=DECIDED` and `ESCALATED`, and `lineage.effect_observation_ref`.

## 8. evaluation-observability.mdx (Trust)

**Key types:** `RunScore`, `DecisionScorecard`, `ReplayPacket`, `ReplayResultStatus`, `DecisionRecord`, `ConformanceReport`, `ReferenceValidationReport`.

**Five evaluator dimensions:** Policy, Utility, Latency, Safety, Economics. Deltas are tracked per intent, tenant and pack version. Policy and safety failures cannot be averaged away.

**Eval types:** Unit, Contract, Interface validation, Policy compliance (no unbound variables), Tool-use, Reasoning, Regression, Simulation, UX, Business, Safety (continuous, never optional).

**Observable trajectory:**
- Contents: release tuple, skills/tools, activation and file-read events, tool calls/results, errors, state diff, final response, subagent links, token/cache/latency/cost, security/policy events, grader version and raw verdict.
- No hidden chain-of-thought.
- A protocol card accompanies it.

**Comparison protocol card** must cover: task distribution, configuration, resources, comparison design, endpoints (accepted outcome, autonomous completion, prohibited effects, unresolved, latency, full cost, intervention), and uncertainty. Use three partitions: development, validation, protected final.

**Usage accounting:**
- Preserve raw provider usage and its semantic version.
- Never mix cache-inclusive and cache-exclusive conventions.
- Prevent parent/child double counting.
- **Missing usage is unknown, never zero.**
- `convertLegacyCostToUnits` converts exactly or rejects.
- Unknown or cancelled usage retains its reservation.

**OTEL:**
- W3C `traceparent` / `tracestate` across compiler → planner → critic → gateway → adapter.
- Baggage is allowlisted, with no credentials, PII or authority.
- Every span carries `trace_id` and `run_id`.
- Versioned ContextOS attributes: pack version, policy decision id, risk dimensions, v1 projection, evidence count, budget usage.
- **Tail sampling MUST keep** runs crossing approval/destructive gates, hitting loop guards, or failing scorecard thresholds.
- A trace attribute is not an attestation.

**Replay modes:**

| Mode | Side-effect rule |
|---|---|
| Audit | transcript-only |
| Regression | transcript-only or sandbox |
| Environment | sandbox only |
| Source-pressure | per packet |

`ReplayPacket` carries source ref, pinned pack, compiled-context hash, transcript-chain hash, side-effect policy and expected outcome. Schema: `/schemas/replay-packet.v1.schema.json`.

**Operational:** stratified sampling by intent, risk and tenant; agent self-confidence never decides whether a run escapes review; reviewer non-vacuity; evaluation cost budget separate from production budget.

**Metrics:** coverage; detection lead time; replay conformance; improvement adoption; MTTSC; Skill Lift; oversight non-vacuity; cost per trusted outcome emitted as **`contextos.budget.cost_per_verified_success`** (the only literal metric name in these docs).

**Scorecard example fields:** `scores{policy{score, violations}, utility{score, judge_rationale}, latency{wall_clock_ms, p99_target_ms}, safety{redaction_success, evidence_coverage, hallucination}, economics{tokens_used, tool_calls, cost_usd_cents}}`, `release_gate`, `improvement_proposals`.

## 9. improvement-loop.mdx (Trust; candidate profile, non-canonical)

**Steps:** Observe, capture corrections (`FeedbackStore`), pin source evidence (episode id, replay case id, baseline tuple, pack, state signature), Classify, Synthesize, Compile strategies, Queue research, Notes, Tune, Gate/release (the proposer never approves itself), Close source pressure (`fixed | still_failing | invalid | superseded`), Monitor (verdicts keep / roll back / supersede / retire).

**Three loops:**
- Execution must not rewrite its controls.
- Evaluation must not optimize or waive gates.
- Improvement must not promote itself.
- Evaluators, held-out cases, policy, approver and rollback target are pinned outside the candidate.
- A proposal cannot edit grants, raise budget ceilings, demote mandatory controls or reuse approvals.

**Closure rule:** an unreplayable pressure can yield only `Insight` or `ResearchTask`, never a closed improvement. A `ReplayPacket` is required before closure.

**Correction ladder** (smallest surface first): RunContext → scoped guidance → skill → validator/policy → scheduled runner. Retain `trace_id`, reference, recurrence count, target and replay obligation.

**Records and enums:**
- **Insight** `kind`: `failure_cluster`, `gap_detected`, `blocked_decision`, `common_detour`, `over-escalation`.
- **StrategyRule**:
  - `adjustment.layer`: `prompt`, `planner`, `retrieval`, `tool_selection`, `memory_recall`, `budget_allocation`;
  - status flow: `proposed → reviewed → approved → released → retired`.
- **FeedbackRecord** kinds: `correction`, `tip`, `escalation_rationale`, `gate_rationale`. A correction emits a `correction`-class memory proposal.
- **Note** kinds: `open_loop_aging`, `queue_backlog`, `repeated_escalation`, `eval_target_drift`, `recurring_correction`. Notes go to operators, never the planner.
- **ResearchTask:** `scope{domain, max_external_calls}`, `produces: knowledge_patch`. Exceeding scope is refused and emits a security event.
- **TuningProposal:**
  - must declare `target.intent`, `target.metric` (plus `direction`), `guardrails`, `baseline_tuple`, `tunable_surfaces`, `search_set`/`heldout_test_set`, `rollback_target`;
  - ranked on the evaluator vector; policy and safety are floors.

**Uniform lifecycle:** `proposed → reviewed → approved → released → (retired | superseded)`, plus `reviewed ↘ rejected`. The store is append-only.

**Metrics:** adoption rate; detection lead time; correction-to-proposal latency; time to close repeated issue; post-release rollback rate; retire rate (90d); notes acted on; research patch yield; configuration attribution coverage; gate independence (target 100%).

## 10. identity-layer.mdx (Intelligence + Trust)

**Key types:** `Principal`, `AgentURN`, `WorkloadIdentity`, `IdentityClaim`, `AgentDelegationEnvelope`; profile types `PrincipalRef`, `AuthorityGrant`.

**Identifier formats:**
- CEID: `ceid:{entity_type}:{slug}:{suffix}`. A stable handle, not a primary key; aliases remain resolvable.
- SID: `sid:{entity_type}:{sid_model_version}:{token_sequence}`. Never an audit handle.
- Agent URN: `agent:contextos/{slug}@{semver}`.

**Hard rules:** CEIDs (never SIDs) in planner outputs, agent-visible tool params, evidence/audit, memory and KG nodes. SIDs are for ranking and retrieval features.

**RunContext identity fields:**
- `run_context.user.delegation` (`auth_type`, `subject`, `scopes`).
- `run_context.agent.agent_urn`, `.workload_identity`, `.principal_chain` (oldest-first, narrowed at each hop), `.identity_claim`.
- Baseline `RunContext.agent`: `agent_id`, `workload_identity`, `role`.

**Gateway checks:** never treat the agent as the user; always check the workload; validate delegation when it is used.

**Lifecycle:**
- `active` / `deprecated` / `revoked`.
- `revoked`: no claims, discovery or A2A, and it fails closed.
- `deprecated`: replayable but not selected without a migration window.

**`ctxid/1` claim (optional):**
- Fields: `version`, `iss`, `sub`, `aud`, `run_id`, `tenant_id`, `principal_chain`, `scopes`, `nbf`, `exp`, `kid`, `claim_hash`, `sig`.
- Short-lived. Children are narrower and get no `agent:spawn`/`a2a:send` unless policy permits.
- Tool scopes = requested ∩ manifest ∩ user ∩ adapter ∩ risk policy ∩ v1 ceiling.
- Only hashes appear in traces.
- A caller-supplied `verification_status: "verified"` is not proof.

**`validateAuthority`** binds mandate, audience, tenant, root/child links, purpose, capability, resources, destinations, arg constraints, data labels, currency/amount and validity. A child grant intersects every ancestor, with bounded depth; a parent cannot mint budget.

**Credential exchange:**
1. Validate.
2. Policy.
3. Mint a single-action credential.
4. Invoke via the gateway.
5. Persist exchange metadata, policy id, claim hash, trace and receipt.

Never expose the bearer value. A broker or revocation outage blocks (cached authority only within a trusted freshness window).

**Effective authority:** principal chain ∩ live delegation ∩ manifest ceiling ∩ policy ∩ surfaced capability ∩ containment ∩ valid approval. Keep a baseline graph per release; new paths are drift. The kill switch is graph revocation, then verify zero alternate paths.

**Failure → required response:**

| Failure | Required response |
|---|---|
| CEID collision | block, reviewed alias |
| Missing mapping | typed `identity_unresolved` verdict |
| PII in slug | quarantine, rotate |
| Stale SID | pin |
| Delegation/workload mismatch | fail closed |
| Cross-tenant leak | block, alert, incident trace |
| Revoked agent | deny discovery, minting, execution |
| Child broader than parent | refuse, policy denial |
| Broker stale | block, route to owner |
| Missing claim hash under required profile | fail the profile |

**Metrics:** CEID collisions; resolution success/latency; alias coverage; CEID usage %; workload/delegation presence when `user_delegated`; claim failures by reason (expired, bad signature, missing scope, tenant mismatch); revoked denials; key rotation age; credential exchange failures; SID churn; cross-tenant denials; authority paths/drift; revocation propagation; post-kill reachable paths (target 0).

## 11. agentic-context-engineering.mdx (Context)

**Key types:** `ContextPack`, `CompiledContext`, `ContextProvenance`, `EvidenceConflictMarker`, `EvidenceGate`, `BudgetReport`, `ContextLedger`.

**Stage outputs:**
- Intent classification also outputs the action-risk dimensions and the v1 projection.
- Memory recall outputs admitted / omitted / uncertain candidates.
- The deterministic compiler makes no model call. Upstream model assistance is pinned as an input.

**`ContextProvenance` (on every material `ContextBlock`):**
- `source_refs`, `content_hash`.
- `origin`: pack, policy, tool registry, retrieval, memory, runtime.
- `integrity`: `authoritative` (only these may carry `control`), `verified`, `untrusted`.
- `freshness`: values seen are `current`, `stale`, `unknown`.
- `instruction_treatment`: `control` or `data_only`.
- `inclusion_reason`.

Integrity is separate from classification. Gate eligibility = admitted + `verified` + `current` + no unresolved conflict. Legacy string evidence is labelled untrusted/unknown and fails closed, with a migration warning.

**`EvidenceConflictMarker`:** conflicting refs plus affected requirements. Unresolved → `insufficient`. Resolved needs a `resolution_ref` and the selected refs, with the rejected branch kept.

**CompiledContext fields:**
- `compiled_prompt.context_blocks[{block_id, bucket, content, priority, provenance}]`.
- `manifests{policy_manifest[{bundle_id, rule_ids}], tool_manifest[{adapter_id, capabilities}], evidence_manifest[{evidence_ref, source_id, hash, integrity, freshness, instruction_treatment, satisfies}]}`.
- `runtime_controls{approval_gates_active, must_refuse, must_escalate, redaction_rules_active, context_admission{data_only_block_ids, untrusted_block_ids, privileged_sink_policy (e.g. "verified_or_user_intent")}, evidence_gates[{decision_key, required, satisfied, unresolved, rejected_evidence, conflicts, sufficiency, commit_allowed}]}`.
- `budget_report{tokens_used_at_compile, omissions, warnings}`.
- `context_ledger{pack_ref, evidence_refs, omissions, compiled_context_hash}`.
- `sufficiency` values seen: `insufficient` (the docs imply a sufficient counterpart; its exact literal is not shown here).

**Prompt contract** declares 7 items: objective, input trust labels, authority, decision procedure, tool contract, output schema, failure/stopping behaviour. The prompt release record pins model route, prompt/skill refs, schema versions, stable prefix/cache topology, datasets/graders, thresholds and rollback. Stable prefixes are separated from volatile blocks.

**Determinism:** the same pinned inputs MUST produce the same envelope. Cache keys MUST include every input that can change the envelope. Data-flow runtime requirements do not alter the CompiledContext hash.

**Autotune:** the compiler MUST refuse proposals outside the pack's declared tunable surfaces (retrieval `top_k` / `max_hops` / source priority / freshness; bucket budgets `evidence_tokens` / `memory_tokens` / `tool_tokens` / compression threshold; prompt fragments; memory recall filters; runtime controls).

**Failure → response:**

| Failure | Response |
|---|---|
| Missing evidence | `commit_allowed: false`; collect / replan / escalate |
| Stale or untrusted evidence | rejection reason |
| Conflict | keep both, `insufficient` |
| Hash mismatch | reject compile |
| Predicate throws | `ContextCompileError` |
| Tool conflicts with safety mode | exclude and record |
| Memory without promotion/consent | omit |
| Budget drops required evidence | omission, reject for gate, block or escalate |
| Unpinnable snapshot | replay incomplete; block high-risk decisions |

**Quality signals** (stored as diagnostics): relevance, integrity, freshness, density, coverage, sufficiency, conflict closure, pressure.

**Metrics:** compile latency by stage; coverage; gate closure by decision key; untrusted admission (target 0 for satisfying evidence); stale rejection; conflict rate/resolution; false-closure (target 0); legacy warnings and hash failures; omission by bucket/reason; tool eligibility mismatch; policy eval error rate; CompiledContext replay match; prompt-contract schema pass and prefix cache hit; recall correctness; budget pressure; quality delta.

## 12. ontology.mdx (Intelligence)

**Key types:** `IntelligenceRefs`, `EntityType`, `RelationshipType`.

**Elements:** `entity_type` (with CEID format), `relationship_type` (from/to, cardinality e.g. `many_to_one`), `attribute` (classification `PUBLIC` / `INTERNAL` / `CONFIDENTIAL` / `RESTRICTED`), `derived_field`, `constraint`, `lifecycle_state`. The ontology grants no authority.

**Change classes:**
- Additive: evaluate dependents.
- Refining: deprecation window; old packs compile with a warning.
- Breaking: major bump, aliasing, migration.

The runtime MUST refuse to compile a pack against an unsatisfied ontology version, with an error naming the element.

**Proposal classes:** `add_entity_type`, `add_relationship_type`, `refine_attribute`, `derived_field_candidate`. Breaking changes, downgrades, CEID format changes and relation removals are never auto-tunable.

**Derived fields:** pure functions. Time inputs use a pinned `evaluation_time` and never the wall clock. Provenance is retained. Validation violations surface as KG conflicts.

**Operational:** one pinned version per environment; atomic promotion across snapshot index, pack registry and Decision Catalog; checkpoints do not adopt new semantics.

**Metrics:** compile success vs active version; breaking changes per window; authored-to-prod time; migration completeness; sibling-environment drift (≤ 1 minor).

## 13. knowledge-graph.mdx (Intelligence)

**Key types:** `IntelligenceRefs`, `EvidenceBundle`, `EvidenceHop`, `EvidenceConflictMarker`, `RetrievedEvidence`.

**Data model:**
- Node: `entity_type`, `ceid`, `attributes`, `provenance`, `as_of`.
- Edge: `relationship_type`, `evidence_ref`, `confidence`, `direction`, `valid_from`, `valid_to`.
- Snapshot: monotonic `snapshot_version`, `ontology_version`, content hash.

**Write invariants:** no edge without `evidence_ref`; merges need evidence plus audit; relationship type must exist in the active ontology.

**Retrieval params:** `mode: "graphrag"`, `seed_strategy`, `max_hops`, `top_k`, `freshness_window`, `evidence_required`.
- The adapter enforces hop/query limits.
- Each hop carries an `evidence_ref`.
- The resolution threshold is configurable (e.g. ≥ 0.92) and is not authentication.

**Bundle:** `snapshot_version`, `ontology_version`, `seed`, `hops[{hop, edge, evidence_ref, to, confidence, as_of}]`, `conflicts`, `truncated` (planner MUST handle `truncated: true`).

**Access:** reads scoped by `tenant_id`, `data_classification` and role. Cross-tenant traversal is denied at the storage layer. Redact before compile. Apply `data.flow_policy@1` where required.

**Conflicts:**
- Contradictory `(subject, predicate)` returns both plus a marker `{conflict_id, evidence_refs, requirements, status: unresolved|resolved, subject, predicate, values}`.
- Never ranked away. The model cannot resolve it; only a source-priority rule, a fresh authoritative read, or a recorded reviewer can.

**Replay:** pin snapshot, ontology, query params and index/ranker/embedding config. Post-snapshot edges must not leak in. Reconcile the snapshot version on every read.

**Metrics:** evidence coverage; precision/recall; conflict rate/closure/latency by `(entity_type, relationship_type)`; unauthorized cross-tenant retrieval success (target 0); replay determinism.