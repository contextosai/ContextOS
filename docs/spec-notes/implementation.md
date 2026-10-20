# ContextOS implementer's requirements digest (Rust runtime/gateway)

**Sources.** I read all 12 requested files in full, under `/opt/contextosai/src/content/docs/`: `implementation/{api-contracts,execution-contract,context-pack,decision-record,memory-fabric,workflows,high-risk-workflow,decision-catalog,intent-task-catalog}.mdx`, `adapters/{mcp,build}.mdx` and `how-it-works.mdx`.

I also read three extra things, and they are marked **[schema]** or **[orch]** below:
- the enums and `required` arrays in `/opt/contextosai/public/schemas/*.json`
- the RunStatus transition table at `/opt/contextosai/src/content/docs/foundations/orchestration.mdx:153-168`

**How the docs describe their own status.** All docs say "Implementation Guide" or "Integration Guide", last reviewed 2026-10-16. They say the following plainly:
- The published JSON Schemas are the normative serialization.
- The TypeScript compiler is a "deterministic conformance reference—not a production runtime".
- Identity verification, brokers, sandboxing, atomic stores, schedulers and providers are "deployment responsibilities".
- The repo is all-rights-reserved and grants no reuse rights (execution-contract.mdx:122).

---

## 1. API operations

There are no HTTP routes. A grep for `POST /`, `GET /` and `/v1/` across these docs returned nothing. The operations are defined as function or envelope contracts.

### 1.1 Canonical loop (api-contracts.mdx:33-48)
```
invokeAgent(request_envelope, run_context)
  → resolve pack refs, tenant, identity, intent, safety mode
  → compile(packs, request, run_context) → CompiledContext
  → bind DecisionSpec
  → route model judgment through AI Gateway / LLM Router
  → loop { planner(CompiledContext)→Plan
           critic.verify(Plan) → ok | replan | reject | escalate
           executor(Plan, ToolGateway) → step_results + evidence_refs
           critic.score(step_results) → accept | retry | replan | escalate
           consolidate(effects, evidence) → memory_proposals }
  → emit DecisionRecord(evidence_refs, approvals, controls_active, trace_id, replay?)
  → emit replay packet and scorecard
```
- how-it-works.mdx inserts `admit(exact profiles, workflow features, implementation support)` before compile.
- **Inconsistency:** how-it-works lists `critic.verify → ok | replan | reject` without `escalate`.
- Replans are bounded by `max_replan_attempts`.
- Loop guard: "repeated identical tool calls" trips a blocking failure (how-it-works failure list). No threshold is given.

### 1.2 invokeAgent request envelope
Schema-required **[schema]**: `request_id, tenant_id, user, agent, context_pack_refs, input, mode, runtime, trace`.

Fields:
- `request_id` (required): globally unique.
- `session_id` (optional): if absent, the run is ephemeral.
- `tenant_id` (required).
- `user`:
  - `user_id` is required in `UserClaims`.
  - `user.delegation` is conditional. It is required when native `ActionRisk.authority == user_delegated` or policy requires on-behalf-of authority.
  - `UserDelegation` requires `auth_type, scopes, subject` and optionally carries `token_ref`.
  - `auth_type` ∈ `oauth2 | saml | oidc | service` **[schema]**.
- `agent`:
  - `AgentIdentity` requires `agent_id, workload_identity, role`.
  - `workload_identity` is a SPIFFE URI (e.g. `spiffe://contextos/agents/support`).
  - Optional: `agent_urn`, pattern `agent:contextos/<slug>@<version>`.
  - Optional: `identity_claim`. A profile may require `sig`, and audit exposes `claim_hash`.
- `context_pack_refs[]` (≥1): each entry is `pack_id@semver`. Unpinned refs (e.g. `ctxpack.support`) cause the invocation to be refused.
- `input`: requires `intent` and `message` **[schema]**. Optional: `channel`, `locale`, `context` (an object, e.g. `identity_verified`, `refund_amount`).
  - **Caveat:** `input.context` values are trusted-adapter inputs only. A caller-supplied `identity_verified: true` must not self-authenticate.
- `mode` (required) ∈ `stream | batch | long_running`.
  - `stream`: bidirectional event stream.
  - `batch`: single response envelope.
  - `long_running`: durable session with progress events and a heartbeat TTL.
- `runtime.*` (required) holds budget hints that are materialized into `RunContext.run_budget`: `plan_timeout_ms`, `max_session_duration_ms`, `max_tool_calls`, `max_payload_bytes`, `max_cost_cents`.
- `attachments[]`: each `Attachment` requires `artifact_id, media_type, sha256, uri`. The Gateway enforces tenant-scoped access. Hashes are recorded in `evidence_manifest` and the trace.
- `trace`: `InvokeTrace` requires `trace_id, span_id`. `trace_flags` is optional. This is W3C Trace Context.

Timeouts (guidance, not hard values):
- Planner: 5–30 s by task class.
- Tool step: 2–120 s, adapter-specific.
- `long_running`: up to hours, with heartbeat renewal.

Hard stop:
- Stop new dispatch.
- Fence ownership.
- Retain a checkpoint or failure observation where possible.
- Preserve unknown in-flight effects and route them to the escalation/reconciliation owner.

### 1.3 RunContext (constructed by the trusted runtime, not the caller)
Required **[schema]**: `run_id, trace_id, tenant_id, user, agent, safety_mode, run_budget`.

Also present: `session_id`, `intent`, `locale`, `metadata{}`.

Agent extras:
- `token_ref`
- `lifecycle` ∈ `active | deprecated | revoked` **[schema]**
- `principal_chain[]`: `Principal{kind,id,tenant_id?}`. `kind` ∈ `user | service | agent | automation` **[schema]**.
- `identity_claim`: requires `version` (`"ctxid/1"`), `iss, sub, run_id, tenant_id, principal_chain, scopes, nbf, exp, kid, claim_hash`.

`safety_mode` is a v1 `ApprovalMode` value and acts as the compatibility ceiling for tool filtering.

`RunBudget`:
- Required: `total_tokens, bucket_tokens{policy,tool,evidence,memory,business,session}, max_tool_calls, max_replan_attempts, wall_clock_ms, max_cost_cents`.
- Accumulators: `tokens_used, tool_calls_used, latency_ms_used, cost_cents_used`.
- `max_cost_cents` and `cost_cents_used` are fractional-cent numbers (legacy semantics).

The trace ID grants no authority. Baggage is optional, minimized and approved per destination.

### 1.4 ToolCallEnvelope (`envelope_version: "contextos.tool_call.v1"`)
Produced by the Executor and brokered by the Tool Gateway.

Required **[schema]**: `envelope_version, tool_call_id, run_id, trace_id, capability_id, args, principal_chain, approval_mode_requested, approval_mode_effective, approval_mode_highest, evidence_refs`.

Optional fields:
- `session_id`
- `action_risk_requested`, `action_risk_effective` (both `ActionRisk`)
- `policy_decision_id`
- `idempotency_key` (it also appears inside `args` in the example)
- `auth_ref` (e.g. `claim_hash:sha256:...`)
- `metadata{arg_schema_ref, requires_approval_gate, protocol, version}`

The example shows authority escalating from `user_delegated` (requested) to `human_approved` (effective) after approval.

`capability_id` format is `<adapter_id>.<capability>`, e.g. `adp_payments.issue_refund`.

### 1.5 ToolResultEnvelope (`envelope_version: "contextos.tool_result.v1"`)
Produced by the Gateway after the adapter returns.

Required **[schema]**: `envelope_version, tool_call_id, run_id, trace_id, capability_id, status, output, artifacts, citations, mutations, risk_tags, latency_ms`.

Optional fields:
- `session_id`, `error` (nullable string in examples), `policy_decision_id`.
- `metadata`, e.g. `approver, approval_evidence_snapshot_hash, tool_transcript_id, redaction_applied, retries, cost_cents, rule_ids`.

`status` values:

| status | meaning |
|---|---|
| `ok` | read-only or synchronous call returned with no side effects |
| `completed` | governed operation finished; side effects are listed in `mutations[]` |
| `paused` | approval, external dependency or continuation is pending (may mean pending reconciliation) |
| `blocked` | policy or consent blocked execution before the adapter ran |
| `rejected` | Gateway rejected a malformed, unauthorized or unsurfaced capability |
| `failed` | adapter, transport or runtime failure |
| `error` | normalized error; caller inspects `error` and `metadata` |

Rules:
- Emit `completed` only when the declared postcondition is established.
- `failed` or `error` may follow a committed effect whose response was lost.
- **Never invent an `unknown` v1 status.** Effect uncertainty belongs in the separate effect-outcome field (§4.3).
- `mutations[]` records only observed mutations. An empty list after a timeout is not proof that nothing changed.
- `citations[]` entries look like `{evidence_ref: "tool:<capability_id>:<tool_call_id>"}`.
- Example `risk_tags`: `destructive`, `policy_denied`.

### 1.6 AgentDelegationEnvelope (`"contextos.agent_delegation.v1"`)
Required **[schema]**: `envelope_version, delegation_id, parent_run_id, child_run_id, trace_id, tenant_id, issuer, subject, principal_chain, scope{allowed_intents, allowed_capabilities, data_classification_ceiling, output_schema_ref}, sub_budget (RunBudget shape), effect_policy, issued_at, expires_at, parent_claim_hash`.

`effect_policy` ∈ `read_only | isolate_until_accepted`, and only those two.
- **MUST NOT add `fork`.**
- Write-capable children use `isolate_until_accepted`.
- A `read_only` child cannot commit effects into the parent's lineage.

Narrowing rules:
- Reject the delegation if the capability set, classification ceiling, expiry or sub-budget exceeds the parent's.
- The parent reserves the child's budget before the child starts. The child cannot create a fresh spending pool.
- Children inherit an absolute deadline.

Context initialization (selection policy, parent checkpoint, artifact revisions, admitted evidence) is recorded in a separate, locally versioned trace attachment. Inherited history is not a credential.

The envelope itself does not prove its issuer. `AuthorityValidationInput` checks every ancestor's scope, expiry and revocation. Delegation is bounded to 16 grants.

### 1.7 Other named operations / validators (execution-contract.mdx)
These are reference validators. Production equivalents must be backed by atomic stores.

| Function | What it does |
|---|---|
| `negotiateExecutionContract` | Compatibility only; `accepted` ≠ authorization |
| `validateAuthority` | — |
| `composePolicyOutcomes` | — |
| `validateApprovalBinding` | — |
| `transitionApprovalRedemption` | — |
| `evaluateBoundaryReadiness` | — |
| `evaluateDataFlow` | — |
| `validateMemoryLifecycle(record, context, evaluationTime)` | — |
| `claimOperation` | — |
| `recordEffectObservation` | — |
| `transitionRun` | — |
| `validateResume` | — |
| `reserveBudget` / `reserveChildBudget` | — |
| `convertLegacyCostToUnits` | — |
| `digestActionBinding` | — |

`ContractNegotiationReasonCode` **[schema]**: `invalid_contract, feature_state_invalid, profile_unknown, profile_version_unsupported, control_unknown, control_version_unsupported, required_control_unsupported, conflicting_reference, artifact_binding_invalid, registry_expansion_invalid`.

---

## 2. Core enums (exact values)

| Type | Values |
|---|---|
| `ApprovalMode` (v1; ordered ceiling) | `read_only, local_write, network, delegated, destructive` |
| `ActionRisk.effect` (`ActionEffect`) | `none, local_state, external_state, physical_world` |
| `ActionRisk.authority` | `agent, service, user_delegated, human_approved` |
| `ActionRisk.reversibility` | `read_only, reversible, compensatable, irreversible` |
| `ActionRisk.interaction` | `api, browser, computer, agent_to_agent, human_handoff` |
| `ActionRisk.data_scope` / `DataClassification` | `PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED` |
| `ActionRisk.decision_ttl_seconds` | optional integer |
| capability `risk_level` (tool_manifest metadata) | `read, write, network, delegated, destructive` **[schema]**; the example uses the value `write_irreversible`, which is not in this enum (inconsistency) |
| `capability_metadata.kind` | e.g. `write` (from example) |
| `capability_class` (adapter manifest) | `observe, recall, verify, think_support, act` |
| DecisionRecord `status` | `DECIDED, DEFERRED, REJECTED, ESCALATED, IN_FLIGHT, CLOSED` |
| DecisionRecord `actor.type` | `USER, AGENT, SYSTEM` **[schema]** |
| policy_decisions `verdict` | `allow, deny, require_approval, escalate` |
| `AuthorizationVerdict` | `allow, deny, require_approval, escalate, error` **[schema]** |
| `decision_right` | `propose, recommend, execute, escalate` |
| Context bucket | `business, policy, tool, evidence, memory, session` |
| `provenance.origin` | `pack, policy, tool_registry, retrieval, memory, runtime` (the doc prose says "tool registry") |
| `provenance.integrity` | `authoritative, verified, untrusted` |
| `provenance.freshness` | `current, stale, unknown, not_applicable` |
| `instruction_treatment` | `control, data_only` |
| evidence `sufficiency` | `sufficient, insufficient` |
| conflict marker `status` | `unresolved, resolved` |
| `privileged_sink_policy` | example value `verified_or_user_intent` |
| omission `reason` | example `budget_exceeded`; the compiler also reports integrity and freshness omissions |
| Execution features (8) | `arbitrary_code, external_network, persistent_memory, external_effects, delegation, checkpoint_resume, proactive_triggers, sensitive_data` |
| `IsolationMode` | `broker_only, sandboxed_code, dedicated_environment` **[schema]** |
| `DataFlowStage` | `collection, inference, tool_input, tool_output, telemetry, cache, memory, export, delegation` **[schema]** |
| `AuthorityReasonCode` | `identity_unverified, tenant_mismatch, grant_invalid, grant_expired, grant_revoked, revocation_unknown, delegation_scope_expanded, scope_mismatch, precondition_stale, verification_unavailable` **[schema]** |
| Replay `side_effect_policy` | `transcript_only, sandbox, live_disallowed` **[schema]** |
| Replay `expected.status` | `not_run, replay_equal, replay_mismatch, fixed, still_failing, invalid, superseded` **[schema]** |
| Replay `source_kind` | `decision_record, quality_replay_case, environment_episode, operator_correction, golden_case` **[schema]** |
| Memory tier | `working, episodic, semantic, durable` |
| Memory write class | `evidence_link, preference, decision_outcome, correction` |
| Review operator actions | `approve, edit, reject` |
| Pack registry state | `draft, linted, reviewed, signed, published, pinned, deprecated, revoked` |
| Adapter registry `type` (pack) | examples `OPENAPI, INTERNAL`; the full set is not enumerated in these docs |

Profile IDs referenced: `contextos.enterprise@1`, `contextos.durable-delegated@1`, `contextos.high-assurance@1`, `contextos.personal-proactive` (version `"1"`).

---

## 3. State machines

### 3.1 RunStatus
Values (execution-contract.mdx:98): `created, running, waiting_approval, waiting_external, suspended, cancel_requested, completed, failed, cancelled, expired`.

Transitions **[orch]**:

| From | To |
|---|---|
| `created` | `running`, `cancel_requested`, `failed`, `expired` |
| `running` | `waiting_approval`, `waiting_external`, `suspended`, `cancel_requested`, `completed`, `failed`, `expired` |
| `waiting_approval` / `waiting_external` / `suspended` | `running` (only after current checks), `cancel_requested`, `failed`, `expired` |
| `cancel_requested` | `cancelled` (after verified stop acknowledgment), `failed`, `expired` |

Terminal states: `completed, failed, cancelled, expired`.

`RunEventKind` **[schema]**: `start, resume, wait_approval, wait_external, suspend, request_cancel, acknowledge_cancel, complete, fail, expire`.

Rules:
- `completed` requires every declared required effect to be confirmed and all active children settled.
- Cancellation order: stop new dispatch → fence old ownership → propagate to children. A confirmed stop can coexist with an `unknown` effect, and it must not be rewritten to `not_applied`.
- Approval denial is not a RunStatus. It is evidence that drives an event such as `fail`.
- Gate expiry does not imply that the run deadline expired.
- Legacy display labels map as `in_progress`→`running`, `awaiting_gate`→`waiting_approval`, `paused`→`suspended` **[orch]**.
- Approval wait/expiry, run deadline and effect outcome are separate facts.

### 3.2 Operation / effect
An operation has a stable identity across attempts.

| Item | Values |
|---|---|
| `RunEffectOutcome` | `not_dispatched, confirmed, not_applied, partial, unknown` |
| `OperationAttempt.dispatch_state` **[schema]** | `claimed → dispatched → settled` |
| `EffectObservation.finality` **[schema]** | `definitive, provisional` |
| `RecoveryStrategy` **[schema]** | `query, idempotent_retry, manual_reconcile, no_retry` |

Rules:
- A timeout after a possible provider commit is `unknown`.
- A late observation can settle an effect fact, but it does not grant executor ownership or release budget.
- The v1 ToolResult status is independent of the effect outcome.

### 3.3 Checkpoint / resume
`ExecutionCheckpoint` pins: contract, pack, policies, tool/profile registries, release artifacts, pending approvals/tasks, operation identity, budget state and `cancellation_state` ∈ `none, requested, acknowledged`.

`ResumeCheck`: `contract_support, authority, approval, boundary, external_preconditions, budget`.

`ResumeStoreObservation.target_fencing` ∈ `enforced, unsupported, unknown`. If fencing is required but unsupported, resume is blocked.

`validateResume`:
- verifies the pinned bytes against current owned store state, plus current ownership and executor generation
- revalidates authority, approval, boundary, external preconditions and budget
- requires explicit migration and reauthorization if the policy interpretation changed

A historical checkpoint cannot restore spent capacity or grant ownership to a stale executor. `session_id` locates a run but is not resume authority.

**[orch]** also says:
- persist a checkpoint after every Critic verdict (`ok`/`accept`/`replan`)
- storage is append-only, content-addressed and immutable
- `long_running` spawn with `max_session_duration_ms` ≥ 1h persists the initial session row first

### 3.4 Approval
There is **no single named approval state enum in these docs**. The approval-related pieces are:
- `ApprovalBinding.decision` ∈ `approved, denied` **[schema]**.
- Approval response `decision` ∈ `approve | deny`. The high-risk examples use both spellings.
- `ApprovalRedemptionResult.status` ∈ `redeem, existing` **[schema]**.
- `transitionApprovalRedemption` returns an intended CAS transition. The store persists it atomically with revision checks and operation ownership.
- It always returns `permits_new_effect: false`. Redemption recovery never authorizes another dispatch.

Sequence: propose (frozen evidence snapshot + complete `ActionBinding`) → approve/deny → current recheck → atomic redeem → dispatch.

Invariants:
- A stored request's expiry cannot be extended by a later decision.
- Approvers must be currently entitled, distinct for quorum, and independent where self-approval is prohibited.
- Any parameter change after approval needs a new approval.
- `proposed_action_hash` must equal `executed_action_hash`. On mismatch, abort and emit a security event.
- A weaker assertion method than the gate requires (e.g. password instead of WebAuthn) makes the gate refuse.
- Gate TTL elapsed → DecisionRecord `DEFERRED`. Resume then needs a fresh approval.
- If snapshot freshness was exceeded by the time of approval, re-take the snapshot and re-prompt.
- Standing grants may permit bounded actions without a fresh click when policy allows.

Approval gate contract (high-risk; an **illustrative profile, not a base schema**):
- `gate_id, request_id, decision_id, approval_mode_required, required_approver_role`
- `frozen_evidence_snapshot{hash, evidence_refs[], captured_at}`
- `proposed_action{tool, params}`
- `ttl_seconds, trace_context{traceparent, baggage}`

Approval response: `gate_id, decision, approver, approver_assertion{method, token_ref}, rationale, decided_at`.

Audit record (one per gate): `audit_record_id, gate_id, request_id, decision_id, approval_mode_effective, frozen_evidence_snapshot_hash, approver, approver_assertion, proposed_action_hash, executed_action_hash, match, decided_at, executed_at, reversal_token, trace_id`.

### 3.5 Budget ledger
| Item | Values |
|---|---|
| `BudgetReservationRecord.status` | `reserved → usage_unknown → settled`; `scope` ∈ `run, child` |
| `BudgetMutationReceipt.kind` | `reserve, settle` |
| Settlement `usage_status` | `known, unknown` |
| Settlement `execution_status` | `running, completed, cancelled, unknown` |

### 3.6 Memory propagation / lifecycle
| Item | Values |
|---|---|
| `MemoryPropagationState` | `pending, confirmed, failed, external_unknown` |
| `MemoryLifecycleOperation` | `propose, promote, correct, delete` |
| `derived_inventory_status` | `verified_complete, incomplete, external_unknown` |
| Flag | `completion_verified` |

### 3.7 MCP task states → ContextOS
| MCP state | ContextOS handling |
|---|---|
| `working` | continue under the pinned run/budget |
| `input_required` | pause and authorize the input independently |
| `completed` | normalize to ToolResultEnvelope |
| `failed` | typed failure plus retryability and partial-effect evidence |
| `cancelled` | terminal, unless the protocol exposes a new task |

---

## 4. Idempotency, retry and reconciliation

1. Write-class capabilities must declare a stable operation identity and a retry/reconciliation strategy. Persist `OperationIntent` before dispatch, with atomic revision/generation checks.
2. Retry is allowed only with either:
   - definitive non-application evidence, or
   - the exact provider idempotency contract: key, payload scope, retention, and currently verified provider guarantees.
   A key alone, or a transport error alone, never justifies a retry. If the provider dedup window has expired, the old key is not protective: reconcile or escalate.
3. Protocol request IDs are attempt IDs, not operation identity. A reissue uses a new request ID but keeps the operation identity and provider key.
4. Compensation is a new governed operation that needs fresh authority, policy, approval and budget. It preserves the original history and may fail or partially apply. `reversal_token` is a protected effect-ledger reference such as `effect-ledger-ref:...`; the raw token is never model-visible.
5. Required recovery acceptance cases (api-contracts.mdx:385-393):

| Case | Required behavior |
|---|---|
| Timeout before dispatch | Prove there was no dispatch before calling the effect absent |
| Provider commit, then response loss | Reconcile the original operation; no blind duplicate write |
| Duplicate request delivery | Reuse the operation identity, reject incompatible reuse, apply declared dedup |
| Provider dedup window expired | Reconcile or escalate |
| Approval or credential revoked during pause | Deny new effects |
| Cancellation races with a write | Report cancellation separately from the effect |
| Recovered session, postcondition unavailable | Keep the evidence unresolved; no accepted business outcome |

6. Adapter idempotency tests: duplicate, timeout then retry, concurrent duplicate, dedup expiry.
7. Manifest field example: `idempotency{required, dedup_window_seconds}`. Permission example: `arg_constraints.idempotency_key.required: true`.

---

## 5. Dispatch authorization (Gateway, immediately before every effect)

Dispatch needs the conjunction of all of these:
- current verified authority and revocation
- applicable policy
- exact stored approval with atomic redemption
- independent constraints
- an active execution boundary
- a permitted actual data flow (recipient, processor, purpose, labels)
- a reserved budget

A high-priority business allow cannot override a revoked grant, egress restriction or stale approval.

Enforcement owners and failure behavior (execution-contract.mdx:45-55):

| Area | Fails closed when |
|---|---|
| Admission | unknown revision, unsupported requirement or ambiguous feature state |
| Authority | stale, unavailable, revoked or expanding |
| Policy | evaluation errors give structured non-success |
| Approval | substitution, expiry, invalid approver or replay conflict |
| Boundary | missing, failed, stale or mismatched (`ExecutionBoundaryObservation.lifecycle_state` ∈ `ready, unavailable, terminated`); **no automatic fallback** |
| Data | unknown labels or prohibited destination |
| Memory | unauthorized promotion is denied |
| Effects | unsafe retry or stale executor → reject; unknown → reconciliation |
| Budget | exhaustion rejects new work; uncertain usage keeps its reservation |

`ActionRisk` policy:
- Evaluate every dimension against `action_risk_policy` using the actual arguments. A favorable dimension never cancels a denial in another.
- Verify the legacy `approval_mode` is no less conservative than the deterministic projection of the vector.
- A capability with no native risk under an active `action_risk_policy` fails closed.
- If the DecisionSpec or intent `risk_class` ceiling is lower than the capability projection, deny or escalate. Never silently lower.

`ActionBinding` covers:
- contract, run, operation, proposal, tenant, actor, authority refs, purpose
- exact capability revision and complete nested arguments
- resource and destination IDs
- evidence, policy, profile and release refs
- native risk and amount, with explicit currency and minor units

`digestActionBinding` uses RFC 8785 canonical JSON with domain `contextos.action_binding.v1`.

Credentials and network:
- Credentials stay outside model-visible state and are scoped to actor, capability, destination and lifetime.
- Egress mediation must cover DNS, redirects and rebinding.
- With no granted destinations, egress is deny-all.

Policy precedence:
- Business outcome: highest applicable priority wins; deny wins an equal-priority tie; all obligations are kept.
- Guardrails (deny, escalate, approval) compose separately and are evaluated before ordinary policy.
- The compiler's tool filter accumulates prohibitions across rules. Do not substitute priority resolution for it.

---

## 6. Context Pack and compiler

### 6.1 Pack (v2; `context-pack.v2.schema.json`; 10 required layers)
- `contract_meta{contract_name, contract_version, issuer, created_at, compatibility.requires{runtime, ontology}}`. Old runtimes must fail closed on `requires`.
- `pack_meta{pack_id, pack_version, tenant{tenant_id,name}, environment_defaults{language,timezone,currency,region}, ttl_seconds, data_classification}`
  - `pack_id@pack_version` is immutable.
  - The tenant must match the invocation unless the pack is explicitly shared.
  - The TTL governs cache freshness only.
- `intelligence_refs{ontology{namespace,version,entity_types,relationship_types}, knowledge_graph{snapshot_pin_rule e.g. "alias:prod"}, identity_layer{ceid_namespaces}, embedding_keys}`. Replay must resolve aliases to fixed snapshots.
- `business_context{summary{what_we_do,who_we_serve,differentiators}, non_negotiables[]}`
- `policy_layer`:
  - `policy_bundles[{bundle_id, priority, policy_dsl{language:"jsonlogic", rules[{rule_id, applies_to{intent}, if, then{allow, requires[], approval_mode, requires_approval_gate}, else{allow, reason}, decision_binding, rationale}]}}]`
  - `guardrails{must_refuse[], must_escalate[], redaction_rules[]}`
  - `approval_gates[{gate_id, when(JsonLogic), required_approver_role, ttl_seconds}]`
- `tooling_layer`:
  - `adapter_registry[{adapter_id, type, endpoint_ref, capabilities[], approval_mode, capability_risks{<cap>: ActionRisk}}]`
  - `permissions[{permission_id, adapter_id, capability, allow, requires_approval_gate?, arg_constraints{<arg>:{min,max,required,enum}}}]`
- `decision_layer.decision_specs[]` (§8)
- `memory_layer{memory_policy{tier_ttls{working,episodic,semantic,durable}, write_classes_allowed[], consent_gating{pii_write_back_allowed}}, promotion_thresholds{auto_promote_confidence}}`
- `evaluation_layer{eval_targets[{intent, policy, utility, latency_p99_ms, safety, economics_cents_per_decision}], release_gates[{metric, max_delta}]}`. Release gates must include policy and safety.
- `tone_and_comms{voice_attributes, do, dont}`

Binding graph (missing edge → fail validation before publish):
- `rules[].decision_binding` → `decision_specs[].decision_key`
- `then.requires_approval_gate` → `approval_gates[].gate_id`
- `permissions[].adapter_id` → `adapter_registry[].adapter_id`
- `permissions[].capability` → that adapter's `capabilities[]`
- `capability_risks` keys → declared capabilities
- `required_evidence` → request context, policy eval, tool result, evidence manifest or graph

Overlays:
- Allowed: endpoint refs, threshold tightening, locale/currency, evaluator tightening.
- Disallowed: granting a capability, lowering risk, silently changing outcomes, swapping ontology without a version bump, inserting secrets.

Versioning:
- patch = metadata
- minor = constraining change
- major = expanded or changed behavior
- unsafe = reject

### 6.2 Compiler resolution order (context-pack.mdx:514-525; 10 stages)
1. load the pinned `pack_id@semver`
2. verify schema, content identity, compatibility and signature profile
3. apply the environment overlay
4. resolve ontology, graph snapshot and identity namespaces
5. evaluate guardrails and policy bundles → `policy_manifest` and controls
6. compute the tool surface
7. label evidence and promoted memory
8. allocate token budgets and admit blocks → `compiled_prompt` and `budget_report.omissions[]`
9. evaluate evidence sufficiency after admission → `evidence_gates[]`
10. emit runtime controls

**Inconsistency:** how-it-works.mdx lists 8 stages instead:
1. intent classification
2. policy resolution
3. tool surfacing (`Registry ∩ Permissions − Prohibitions`, then native-risk policy, then the `safety_mode` ceiling)
4. evidence normalization
5. memory recall
6. token budget allocation across `run_budget.bucket_tokens`
7. bucket admission and assembly
8. manifests and runtime controls

Stages 1–4 of the 10-stage list (load, verify, overlay, registry auth) are deployment admission duties; the reference compiler takes an already-supplied typed pack.

### 6.3 Token buckets
Six buckets: `business, policy, tool, evidence, memory, session`. Allocation comes from `RunBudget.bucket_tokens`.

Blocks are admitted by `priority`. Example priorities: biz 90, policy 80, tool 70, evidence 60, memory 50, session 40.

Truncation must be visible. A silent truncation is a compiler bug and a release-gate failure.

`budget_report` required fields: `tokens_allocated, tokens_used_at_compile, tokens_used_by_bucket, bucket_truncations{bucket:bool}, dropped_block_ids{bucket:[ids]}, warnings`. Also: `omissions[]`, where `ContextOmission` requires `block_id, bucket, reason, estimated_tokens, priority, source_refs`.

`context_ledger` required **[schema]**: `pack_ref, intent, request_id, policy_bundles, policy_rule_ids, tools, evidence_refs, memory_refs, dropped_block_ids, budget{tokens_used_at_compile, truncated_buckets}, compiled_context_hash`. Doc examples also show `omissions`.

### 6.4 CompiledContext
Required: `compiled_prompt{system, developer, task, context_blocks[]}, manifests{policy_manifest[{bundle_id,rule_ids}], tool_manifest[{adapter_id,capabilities,capability_metadata?{<cap>:{kind,risk_level,approval_mode,source}}}], evidence_manifest[{evidence_ref, source_id?, hash?, integrity?, freshness?, instruction_treatment?, satisfies?}]}, runtime_controls{must_refuse, must_escalate, approval_gates_active, redaction_rules_active, context_admission?, evidence_gates?}, budget_report, context_ledger`.

`ContextBlock` requires `block_id, bucket, content, priority`. It may carry `provenance` and `provenance_refs`.

`ContextProvenance` requires `source_refs, origin, integrity, freshness, instruction_treatment, inclusion_reason, content_hash`.

`context_admission{data_only_block_ids, untrusted_block_ids, privileged_sink_policy}`.

`ActionRiskEvaluation` requires `verdict (allow|deny), policy_applied, approval_mode_projection, violations` **[schema]**.

Determinism:
- Identical pinned inputs give an identical `compiled_context_hash`.
- If replay produces a different manifest, block promotion and open an incident.
- This hash is **not** the action/approval binding.

### 6.5 Evidence admission and gates
Evidence candidate: `{evidence_ref, source_id, content, integrity, freshness, satisfies[], hash?}`.
- If a hash is supplied, it must match the content bytes or compilation throws.
- The compiler derives `content_hash` (`sha256:`) and forces `instruction_treatment: data_only`.

Trust rules:
- Only immutable pack, policy and tool-registry blocks may be `authoritative`.
- Evidence and memory are always `data_only`.
- Legacy string evidence is labeled `untrusted` + `unknown` freshness, emits a warning, and can never satisfy a gate.

`EvidenceConflictMarker`:
- requires `conflict_id, evidence_refs (≥2), requirements, status`; optional `subject, predicate, values`
- when resolved, adds `resolution{resolution_ref, selected_evidence_refs}`
- non-selected candidates are marked `superseded_by_resolution`
- the compiler never invents a resolution

Gate closure: a requirement closes only from explicit request context, or from an **admitted, current, verified, conflict-free** item whose `satisfies[]` names it. Everything else goes into `rejected_evidence`.

`EvidenceGate` requires `decision_key, required, satisfied, unresolved, rejected_evidence, commit_allowed`. `conflicts` and `sufficiency` are additive (always emitted by the current compiler).

Missing coverage or an unresolved conflict → `insufficient`. Only a sufficient gate allows `commit_allowed: true`.

### 6.6 Compile errors
`ContextCompileError` is thrown when an applicable predicate raises an exception. It is never treated as false, and no partial `CompiledContext` is produced. Safe serialization has exactly six fields:
```json
{"code":"policy_eval_error","stage":"policy_resolution","bundle_id":"...","rule_id":"...","expression_path":"if","message":"An applicable policy predicate could not be evaluated."}
```
It excludes the predicate, payload, stack and cause. An invalid evidence hash also stops compilation. Routing-expression errors (intent/template eligibility) are explicit non-success.

### 6.7 Pack failure behaviors
| Condition | Result |
|---|---|
| Unversioned ref | refuse invocation |
| Signature profile active and signature invalid | refuse invocation |
| `compatibility.requires` unmet | refuse invocation |
| Missing ontology version | fail compile before the model call |
| Required evidence unresolved | Critic returns `replan`, `reject` or `escalate` |

Refresh triggers: `POLICY_BUNDLE_UPDATED, ONTOLOGY_UPDATED, ADAPTER_SCHEMA_UPDATED, DECISION_CATALOG_UPDATED, MEMORY_POLICY_UPDATED, EVALUATOR_UPDATED, MODEL_CONFIG_UPDATED`.

---

## 7. DecisionRecord

Required **[schema]**: `record_id, decision_key, decision_version, timestamp, status, actor{type,id}, evidence_refs, policy_decisions[], approvals[], controls_active{must_refuse, must_escalate, approval_gates_active, redaction_rules_active, context_admission?, evidence_gates?}, budget_usage{tokens, tool_calls, cost_usd_cents, wall_clock_ms}, lineage{pack_version (required), policy_versions?, decision_spec?, kg_snapshot?, snapshot_version?, model_profile?, evaluator_suite?}, trace_id`.

Optional fields:
- `intent_ref` (required by the Intent-Task Catalog profile), `subject_ids`, `inputs_refs{request, session, attachment}`, `outputs`, `confidence`
- `rationale{strategy, alternatives_considered}` (typed; never chain-of-thought)
- `tool_lineage[{tool_call_id, tool_result_id, approval_mode_effective, idempotency_key, reversal_token}]`
- `scorecard` (requires `policy, utility, safety`; also `latency, cost`)
- `replay{replay_packet_id, compiled_context_hash, tool_transcript_chain_hash, last_status}`
- `audit{prev_hash, record_hash, signed_by}`: tamper-evidence profile, **optional**

Sub-shapes:
- `policy_decisions[]`: `{policy_decision_id, bundle_id?, rule_ids[], verdict?}`
- `approvals[]`: `{gate_id, approver, approval_mode_effective, evidence_snapshot_hash, decided_at}`

`status` meanings:

| status | meaning |
|---|---|
| `DECIDED` | outcome is in `allowed_outcomes` |
| `DEFERRED` | missing evidence or approval; resumable |
| `REJECTED` | critic or policy refused |
| `ESCALATED` | routed to a human or higher trust |
| `IN_FLIGHT` | long-running, not yet terminal |
| `CLOSED` | finalized or retired |

Emission and storage:
- One record per checkpoint is allowed, but there must be exactly one terminal record for the primary decision.
- Read-only decisions also need records.
- Append-only. Corrections are superseding records.

Validation (block if):
- `outputs` does not match the spec's output schema
- required evidence is absent, stale, unresolvable or from the wrong tenant
- a governed action has no policy decision, or uses an inactive policy version
- an approval obligation has no matching approval
- action/approval pins mismatch, or a required effect is unverified
- compile-time controls are missing from the record
- lineage is unpinned
- `trace_id` is missing or mismatched
- seal profile active and verification fails

Storage:
- Partition by `tenant_id` + time window.
- Index `decision_key, subject_ids[], status, approval_mode_effective, policy_decision_id, trace_id`.
- Hashing profile: canonical JSON excluding transport fields, plus `prev_hash`.
- Revoked signing keys stay queryable.
- Destructive, denied, escalated, failed-scorecard and incident records bypass sampling.

Meaning limits:
- `controls_active` is not an enforcement attestation; keep `ConformanceReport` evidence separately.
- `DECIDED` does not prove an effect happened.

Replay:
- Given a `trace_id`, fetch: request + RunContext, pack + overlays (version + hash), policy bundles + DecisionSpec, KG snapshot, tool transcripts, model profile + routing, evaluator suite, record.
- **No re-execution of side-effecting tools.**
- Deterministic artifacts must compare exactly. Model stages use property, scorecard or tolerance checks.
- A mismatch returns a typed diff: changed evidence, policy, tool transcript, compiled context, scorecard, or tampering.
- ReplayPacket requires `replay_packet_id, trace_id, source_kind, source_ref, context_pack_ref, compiled_context_hash, side_effect_policy, expected{status}`.

Cost accounting:
- `cost_usd_cents` keeps legacy fractional-cent semantics.
- New accounting uses `cost_unit{currency, units_per_cent}`, where `units_per_cent` is a power of ten from 1 to 10^15.
- `convertLegacyCostToUnits` is exact: 0.91¢ at 100 units per cent = 91; 0.911 is rejected (`cost_precision_unsupported`).
- No rounding, implicit FX or default currency.

---

## 8. DecisionSpec, Intent and TaskTemplate

**DecisionSpec:**
- Base: `decision_key, version, required_evidence[], allowed_outcomes[] (closed), approval_mode (required v1 ceiling)`.
- Optional: `owner_role, decision_right, inputs_schema_ref, outputs_schema_ref, eligibility_rules (JsonLogic), challenge_required (bool)`.
- An empty `required_evidence` is structurally legal; a missing field is rejected.
- An outcome outside `allowed_outcomes` is rejected by the runtime.

**Intent** (a catalog protocol, **not a base wire type**): `intent_id, version, owner_role, description, risk_class (ApprovalMode), accepted_channels, locale_support, eligible_task_templates`.

**TaskTemplate** (same caveat): `task_template_id, version, intent_id, owner_role, decision_bindings[{decision_key, checkpoint_after_step}], default_plan{steps[{id, tool, params_schema?, depends_on?, approval_mode?}]}, eligibility_rules`. The example also shows `highest_approval_mode`.

Routing:
- Resolve one intent, then evaluate eligibility against verified RunContext with a pinned resolver.
- Use a deterministic tie order (e.g. priority, semver, template ID).
- If ambiguous, return an explicit ambiguous/unsupported result.
- Store the selected intent and template in routing lineage or `RunContext.metadata`. **Do not add top-level `intent_id`/`task_template_id` to RunContext.**

**Plan:** `{plan_id, intent, steps[{id, tool, params, depends_on, approval_mode, requires[gate_ids]}], decision_checkpoints[{decision_id, after_step}]}`. `execute_when` is a deployment extension, not a base `PlanStep` field.

**Critic verify checks:**
- each tool is in `tool_manifest`
- arguments validate
- `approval_mode` does not understate the capability
- `ActionRisk` passes
- the checkpoint's gate is closable
- `data_only` blocks are preserved
- no guardrail violation

---

## 9. Memory Fabric

Pipeline: `capture → candidate → review queue → promoted → compiled context`.
- Recall returns only promoted memory.
- Raw captures are never queried by the compiler.

Review queue item: `proposal_id, candidate{entity_ceid, predicate, value, evidence_refs, confidence}, class, tier_target, consent_check, contradiction_check{existing, verdict e.g. "no_conflict"}, auto_promote_eligible`.
- Model-emitted `consent_check`, confidence and `auto_promote_eligible` grant nothing.
- `correction` writes require the illustrative `correction_writer` role.

Contradictions on the same `(entity, predicate)`:
- A fresh, higher-integrity record wins under a deterministic policy, and the old one is superseded with audit.
- Otherwise both are kept with `contradiction: true`, and the planner must handle the conflict.

Recall filtering: `tenant_id`, role, `data_classification`, freshness, confidence. Return provenance with each record. `low_confidence` is not a canonical freshness value.

Lifecycle:
- Bind each operation to `(tenant, owner, namespace, purpose)`.
- Keep personal and work namespaces separate.
- Expired retention blocks promotion and correction.
- Initial bounds: ≤128 derived copies and 129 propagation receipts.
- `completion_verified` only with a verified-complete inventory and per-target receipts. Unknown external copies stay `external_unknown`.
- Review hashes a domain-separated intent that excludes the review and propagation status.

---

## 10. MCP adapter requirements

**Version:** target MCP `2026-07-28`, which is stateless.
- **No** `initialize`, `notifications/initialized`, protocol sessions, `Mcp-Session-Id`, HTTP GET event stream, `Last-Event-ID` or SSE resume.
- `2025-11-25` is allowed only as a separately labeled and tested compatibility profile. Never blend the two.

**Negotiation:**
- `server/discover` is optional.
- Every request's `_meta` carries `io.modelcontextprotocol/protocolVersion` and client capabilities, plus client identity (recommended).
- Verify server identity and result metadata on every response.
- On `UnsupportedProtocolVersionError`, fail visibly; no downgrade.
- Cache per `ttlMs` and `cacheScope`, and invalidate on change notifications.

Pinned profile example: `{protocol:"mcp", protocol_version:"2026-07-28", transport:"streamable_http", server_features[...], extensions:["io.modelcontextprotocol/tasks"]}`.

**Discovery is untrusted.** Admission comes only from a pinned, reviewed adapter manifest. Annotations, descriptions, prompts and resources are metadata, not permission. ContextOS `session_id` is never an MCP session.

**Results:**
- The server returns `complete`, `input_required` (with `inputRequests`), or `resultType:"task"`.
- For `input_required`: persist the request state, validate supported types, apply consent/redaction/approval/identity, then retry the original request with `inputResponses` and a **new request ID** while keeping operation identity and provider key.
- Inputs cannot widen authority or rewrite an approved action. A changed action needs a new proposal and approval.

**Tasks extension** (`io.modelcontextprotocol/tasks`):
- Uses `tasks/get`, `tasks/update` and `tasks/cancel`. There is no `tasks/list` and no `tasks/result`.
- Authenticate and authorize each call.
- Handles must be high-entropy and scoped to user, tenant, client and resource. A handle is not a bearer capability.
- Cancellation is cooperative; an ack does not prove the work stopped.
- Resume does not reset budget or approval.

**Transport and auth:**
- stdio: JSON-RPC on stdin/stdout, logs on stderr, install consent, sandbox.
- Streamable HTTP: validate `Origin`, authenticate every request, required MCP headers, constrain egress and redirects, request/body/time limits.
- Bind tokens to the authorization-server issuer and resource.
- **No token passthrough** (`allow_token_passthrough:false`). Exchange for short-lived, capability-bound credentials.
- OAuth scope ≠ tenant eligibility, evidence sufficiency or gate completion.
- Trace: `traceparent`, `tracestate` and approved `baggage` go in `_meta`. No secrets or principal details in baggage.

**Deprecated (do not use in new adapters):**

| Feature | Use instead |
|---|---|
| Roots | explicit URIs |
| Sampling | AI Gateway |
| Logging | stderr / OTel |
| HTTP+SSE | Streamable HTTP |
| Dynamic Client Registration | Client ID Metadata Documents |

**Object mapping:**
- Tool → candidate capability.
- Resource → evidence candidate with source, classification, freshness, integrity and hash.
- Prompt → versioned artifact, never policy.
- MCP App → untrusted output.
- Skills over MCP → experimental, not a grant.

**Adapter manifest** (integration blueprint, **not a published schema**): `adapter_id, version, owner_role, protocol{kind, profile, transport, endpoint_ref, extensions}, auth{type, resource, issuer_allowlist, allow_token_passthrough}, capabilities[{capability_id, protocol_tool, capability_class, action_risk, approval_mode, requires_approval_gate?, arg_constraints?, idempotency{required, dedup_window_seconds}?, input_schema_ref, output_schema_ref, postcondition?, recovery?, evidence_keys}], observability{trace_context:"w3c", metrics[latency_ms, retry_count, upstream_status, cost_cents]}, kill_switch_ref`. Schemas use JSON Schema 2020-12.

**Supply chain** (pin and verify): publisher/owner, source revision, manifest and schema hashes, executable/image digest, dependencies and build provenance, protocol profile, requested destinations/scopes/data ceilings/local permissions, security and conformance results, owner, revocation path, rollback target. Re-admit on any change. A registry listing is not assurance.

**Adapter error model:**

| Failure | Handling |
|---|---|
| Protocol, version or framing error | fail, no model retry |
| Business validation | planner may repair |
| Auth or policy | Gateway refusal before the call |
| Needs input | pause and re-authorize |
| Long-running | task handle |
| Timeout, no known effect | retry only if the contract allows |
| Partial or ambiguous effect | escalate; never report a clean success or failure |

Test matrix classes: Contract, Protocol, Legacy isolation, Policy, Identity, Idempotency, Effect, Input flow, Durable task, Trace/replay (no live write on replay), Supply chain, Evaluation. Tests must go **through the Gateway**.

---

## 11. Limits and bounds (execution-contract v1)

- ≤16 selected profiles; ≤128 required controls, ≤128 optional controls and ≤128 artifact refs per array.
- Identifiers ≤256 Unicode characters.
- Profile expansion is acyclic, ≤8 levels and ≤128 effective controls.
- Delegation ≤16 grants. Finite exact scopes only; no wildcards or ranges.
- Canonical JSON:
  - reject non-JSON values, cycles, malformed Unicode and excess depth/size
  - **byte parsers must reject duplicate keys** (relevant for serde: default serde_json accepts duplicate keys, so a custom check is needed)
- Timestamps are UTC strings ending in `Z`, with exact fractional ordering. Validity intervals are half-open.
- Reference decisions never consult an ambient clock, randomness or the network.
- Budget ledger:
  - ≤128 mutation receipts
  - each open reservation holds one receipt slot and one revision increment
  - an empty ledger allows ≤64 concurrent reservations
  - `counter_exhausted` can be reached earlier
  - identical mutation recovery is read-only, even at capacity
  - new counters are non-negative safe integers
- Execution-contract attachment: `{envelope_version:"contextos.execution_contract.v1", contract_id, run_id, trace_id, tenant_id, profiles[{profile_id, profile_version}], required_controls[], optional_controls[], release_refs[{artifact_type, artifact_id, version, sha256}]}`.
  - All 8 feature booleans are derived by trusted admission. Unknown → block. A caller cannot set a feature to `false` to hide it.
  - Mandatory controls cannot become optional.
  - A legacy workflow without the attachment does not count as having passed any control.

---

## 12. Error codes found (exhaustive for these docs plus the listed schema enums)

- `policy_eval_error` (ContextCompileError, `stage: policy_resolution`)
- `counter_exhausted`
- `cost_precision_unsupported`, `budget_accounting_invalid` **[schema]**
- `ContractNegotiationReasonCode` and `AuthorityReasonCode` sets (above)
- `UnsupportedProtocolVersionError` (MCP)
- Workflow-example `error_code` values (illustrative only): `VALIDATION_ERROR`, `STALE_SNAPSHOT`
- Example error string prefix: `TAX_COMPLIANCE_BLOCK:`

No other error-code catalog exists in these files. I grepped for `error_code`.

---

## 13. Non-normative and inconsistency flags

**Illustrative only, not base schemas:**
- the approval gate, approval response and audit-record envelopes
- the adapter manifest format
- Intent and TaskTemplate wire shapes
- `execute_when`
- memory tier backings and retention ranges
- the `correction_writer` role
- the `0.7` threshold
- the `trace_context` telemetry projection
- the `Decision output (snippet)` `{decision_id, outcome, evidence_refs}`

**Optional deployment profiles:** pack signing, the DecisionRecord `audit` seal, `identity_claim.sig`.

**Experimental:** Skills over MCP.

**Inconsistencies:**
- 10-stage compiler order (context-pack) vs 8 stages (how-it-works).
- `critic.verify` outcomes differ: `escalate` appears in api-contracts only.
- The `risk_level` example `write_irreversible` is not in the schema enum (`read, write, network, delegated, destructive`).
- The api-contracts table marks `user.delegation` conditional, but the schema requires the `user` object itself.
- Approval decision spelling: `approve/deny` in the response vs `approved/denied` in `ApprovalBinding`.

**Not specified in these docs:**
- transition rules for the `approval` and `operation` states beyond the enum orders listed above
- loop-guard thresholds
- the semantics of the `privileged_sink_policy` values beyond `verified_or_user_intent`
- the full adapter `type` enum

Remaining enum details are in `/opt/contextosai/public/schemas/execution-contract.v1.schema.json` (149 KB). It is the authoritative source for the attachment types (`ExecutionCheckpoint`, `OperationAttempt`, `BudgetReservationRecord`, etc.), and I only extracted its enums and required fields.