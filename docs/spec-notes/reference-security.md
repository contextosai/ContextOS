# ContextOS implementer's requirements digest (for a Rust runtime, gateway and control plane)

I read all the requested docs in full (about 43k words) and listed the 9 schemas. I also pulled the exact enums and field lists noted below straight out of `/opt/contextosai/public/schemas/*.json`.

**Status labels**
- Reference: `control-profiles`, `conformance`, `reviewer-agents`.
- Reference Design: `architecture`, `control-plane-config`, `api-schemas`, `ai-gateway-llm-router`, `failure-playbooks`, `metrics-glossary`, all `components/*`.
- Explicitly **non-normative**: `deployment-blueprint`.
- Living Document: `security`. Research Note: `trusted-ai-agents-cloud`. Framework Revision: `evolution-2026`. Implementation Guide: `adopt-a-harness`.
- The repo only provides TypeScript validators, schemas and synthetic fixtures. It ships no production runtime and no certification.

---

## 0. Published schemas (`/opt/contextosai/public/schemas/`)

The docs say there are exactly 9 files: 8 base schemas plus 1 additive one.

| File | Summary |
|---|---|
| `run-context.v1.schema.json` | `RunContext`. Required: `run_id, trace_id, tenant_id, user, agent, safety_mode, run_budget`. Optional: `session_id, intent, locale, metadata`. |
| `invoke-agent.v1.schema.json` | `invokeAgent` entry envelope. Required: `request_id, tenant_id, user, agent, context_pack_refs, input, mode, runtime, trace`. Optional: `session_id, attachments`. Modes include stream, batch and `long_running`. |
| `agent-delegation.v1.schema.json` | `AgentDelegationEnvelope`, the parent-issued child authority. Required: `envelope_version, delegation_id, parent_run_id, child_run_id, trace_id, tenant_id, issuer, subject, principal_chain, scope, sub_budget, effect_policy, issued_at, expires_at, parent_claim_hash`. Optional: `cancellation_ref`. |
| `context-pack.v2.schema.json` | `ContextPack`, an immutable deploy unit. Required: `contract_meta, pack_meta, intelligence_refs, business_context, policy_layer, tooling_layer, decision_layer, memory_layer, evaluation_layer, tone_and_comms`. Signatures are not fields. |
| `compiled-context.v1.schema.json` | `CompiledContext`. Required: `compiled_prompt, manifests, runtime_controls, budget_report, context_ledger`. Provenance, admission, evidence-gate and omission fields are additive. |
| `tool-envelope.v1.schema.json` | `oneOf` `ToolCallEnvelope` / `ToolResultEnvelope`; `$defs`: `ApprovalMode, ActionRisk, Principal`. Call required: `envelope_version, tool_call_id, run_id, trace_id, capability_id, args, principal_chain, approval_mode_requested, approval_mode_effective, approval_mode_highest, evidence_refs`. Result `status` ∈ `ok, error, paused, completed, failed, rejected, blocked`. |
| `decision-record.v1.schema.json` | `DecisionRecord`. Required: `record_id, decision_key, decision_version, timestamp, status, actor, evidence_refs, policy_decisions, approvals, controls_active, budget_usage, lineage, trace_id`. Optional: `intent_ref, context_snapshot_hash, subject_ids, inputs_refs, outputs, tool_lineage, scorecard, confidence, rationale, replay, audit`. |
| `replay-packet.v1.schema.json` | `ReplayPacket`. Required: `replay_packet_id, trace_id, source_kind, source_ref, context_pack_ref, compiled_context_hash, side_effect_policy, expected`. `side_effect_policy` ∈ `transcript_only, sandbox, live_disallowed`. `source_kind` ∈ `decision_record, quality_replay_case, environment_episode, operator_correction, golden_case`. |
| `execution-contract.v1.schema.json` | `ExecutionContractEnvelope`, the additive attachment (149 KB, 122 `$defs`). Required: `envelope_version, contract_id, run_id, trace_id, tenant_id, profiles, required_controls, optional_controls, release_refs`. |

**Bounds and validation rules for `ExecutionContractEnvelope`**
- 1–16 profiles.
- At most 128 entries in each control or release array.
- Identifiers and revisions up to 256 characters.
- Objects are closed.
- Register the custom format `contextos-utc`. It accepts UTC with a `Z` suffix and any fractional precision, and rejects offsets and leap seconds. A validator that skips unknown formats fails the check.
- New bindings use RFC 8785 canonical JSON with domain separation. Limits: 64 nesting levels, 10,000 values, 1 MiB output. Reject duplicate keys before building objects.
- Schema validity proves nothing about semantics. Budget sums, attenuation, revocation and transition validity need separate validators.

**Execution-contract enums (taken from the schema)**
- `WorkflowFeatureSet` (8 required booleans): `arbitrary_code, external_network, persistent_memory, external_effects, delegation, checkpoint_resume, proactive_triggers, sensitive_data`.
- `RunStatus`: `created, running, waiting_approval, waiting_external, suspended, cancel_requested, completed, failed, cancelled, expired`.
- `RunEventKind`: `start, resume, wait_approval, wait_external, suspend, request_cancel, acknowledge_cancel, complete, fail, expire`.
- `RunEffectOutcome`: `not_dispatched, confirmed, not_applied, partial, unknown`.
- `DataFlowStage` (9 stages): `collection, inference, tool_input, tool_output, telemetry, cache, memory, export, delegation`.
- `MemoryPropagationState`: `pending, confirmed, failed, external_unknown`.
- `ControlEvidenceStatus`: `passed, failed, unsupported, not_evaluated`.
- `ConformanceOutcome`: `passed, failed, insufficient_evidence`.
- `VerificationStatus`: `verified, invalid, unavailable`.

**Key ledger fields**
- `OperationLedger`: `ledger_id, contract_id, run_id, tenant_id, revision, executor_generation, deadline, trusted_observers, operations`.
- `EffectObservation`: `…operation_id, attempt_id, action_digest, executor_generation, outcome, finality, external_ref, evidence_ref, verification_status, observer, observed_at, valid_until, evaluation_time`.
- `BudgetLedger`: `…parent_run_id, revision, executor_generation, deadline, cost_unit, original_limits(_ref), opening_usage(_ref), ceiling, used, reserved, unknown_usage_policy, mutations, trusted_observers, reservations`.
- `ExecutionCheckpoint`: `checkpoint_version, checkpoint_id, revision, contract_id, run_id, tenant_id, contract_ref, pack_ref, policy_refs, tool_registry_ref, profile_registry_ref, release_refs, run_state, operation_ledger_ref, budget_ledger_ref, operation_ids, budget_snapshot, pending_approval_refs, pending_task_refs, cancellation_state, executor_generation, require_target_fencing, digest`.
- `ActionBinding`: `binding_version, contract_id, run_id, tenant_id, operation_id, proposal_id, actor, authority_refs, purpose_id, capability_id, capability_version, arguments, resource_ids, destination_ids, evidence_refs, policy_refs, profile_refs, release_refs, action_risk, amount`.

**Attachment entry points**, by family (use `$id#/$defs/<Type>`)
- Selection: `ExecutionContractEnvelope, RuntimeSupportDeclaration, WorkflowFeatureSet, ContractNegotiationResult`.
- Registry: `ProfileRegistrySnapshot, ProfileDefinition, ControlDefinition, ArtifactRef`.
- Authority: `ActionBinding, AuthorityGrant, AuthorityScope, AuthorityValidationInput/Result`.
- Policy: `NormalizedPolicyOutcome, ComposedPolicyOutcome, ContextCompileErrorDetail`.
- Approval: `StoredActionProposal, ApprovalRequestRecord, ApprovalBinding, ApprovalValidationInput, ApprovalRedemptionInput`.
- Authorization: `AuthorizationInput, ConstraintObservation, AuthorizationOutcome`.
- Boundary: `ExecutionBoundaryRequirement, ExecutionBoundaryObservation, BoundaryReadinessResult`.
- Data: `DataFlowRequest, DataFlowPolicySnapshot, DataTransformationObservation, DataFlowDecision`.
- Memory: `MemoryLifecycleRecord/Context, MemoryReviewObservation, MemoryPropagationObservation`.
- Run: `RunExecutionState, RunEvent, RunTransitionResult`.
- Operations: `OperationIntent, OperationClaim, OperationLedger, EffectObservation, OperationTransitionResult`.
- Resume: `ExecutionCheckpoint, ResumeValidationInput, ResumeValidationResult`. The result is `accepted` or `rejected`, with `reason_codes` and `obligations`.
- Budget: `BudgetLedger, BudgetReservationRequest, BudgetSettlementRequest, BudgetMutationReceipt, BudgetTransitionResult`.
- Evidence: `ConformanceReport, ConformanceAssessmentInput, ConformanceAssessment, ReferenceValidationReport`.

---

## 1. Control profiles (all at revision `"1"`; TS registry `STANDARD_PROFILE_REGISTRY`)

**Mandatory controls per profile** (each stronger profile also includes `contextos.core@1`)

| Profile | Mandatory controls |
|---|---|
| `contextos.core` | `identity.authenticated, authority.scoped, policy.fail_visible, context.integrity, audit.correlated` |
| `contextos.personal-proactive` | core + `authority.revocation, approval.bound, isolation.required, credentials.brokered, data.flow_policy, budget.aggregate, operations.stop_recover` |
| `contextos.enterprise` | core + `authority.revocation, approval.bound, isolation.required, credentials.brokered, data.flow_policy, budget.aggregate, release.pinned, governance.separation, operations.stop_recover` |
| `contextos.durable-delegated` | core + `authority.revocation, approval.bound, isolation.required, effects.reconciled, execution.checkpointed, delegation.attenuated, budget.aggregate, operations.stop_recover` |
| `contextos.high-assurance` | core ∪ enterprise ∪ durable-delegated + `assurance.fault_evidence` |

**Feature-conditional controls** (apply under every profile; the trusted admission adapter derives the features)

| Feature | Added controls |
|---|---|
| `external_network` | `network.mediated` |
| `persistent_memory` | `memory.lifecycle` |
| `external_effects` | `effects.reconciled`, `approval.bound` |
| `delegation` | `delegation.attenuated`, `budget.aggregate` |
| `checkpoint_resume` | `execution.checkpointed` |
| `arbitrary_code` | `isolation.required` |
| `sensitive_data` | `data.flow_policy` |
| `proactive_triggers` | `authority.revocation`, `approval.bound`, `budget.aggregate`, `operations.stop_recover` |

**The 20 control IDs**
`identity.authenticated, authority.scoped, authority.revocation, policy.fail_visible, approval.bound, context.integrity, isolation.required, credentials.brokered, network.mediated, data.flow_policy, memory.lifecycle, effects.reconciled, execution.checkpointed, delegation.attenuated, budget.aggregate, audit.correlated, release.pinned, operations.stop_recover, governance.separation, assurance.fault_evidence`.

**Negotiation rules** (`negotiateExecutionContract`)
- Selecting several profiles means their union. There is no fallback to the weakest.
- Support is matched exactly by ID and revision. A schema-valid but unsupported revision is rejected.
- Unknown required controls, conflicting definitions, cycles or excess expansion are rejected, never truncated.
- An optional control can never demote a mandatory one.
- Unknown required state is rejected. A model or caller flag is not a trusted feature manifest.
- Registry, profile and control refs bind immutable payloads under distinct canonical hash domains. Each definition excludes its own ref when hashed.
- Adding a mandatory requirement creates a new revision.
- Durable-delegated requires demonstrated delegation support even when a run uses a single worker.

**Per-control behaviour, owner and blocking condition**
- `identity.authenticated`: verified principal/workload, tenant, audience and trust domain. Spoofed or mismatched identity blocks.
- `authority.scoped`: intersect purpose, capability/revision, resources, args, destination, amount and delegation. Scope expansion blocks.
- `authority.revocation`: revocation observations must be fresh within a bound. Unknown, unavailable or stale observations block protected work.
- `policy.fail_visible`: policy composition is explicit and failures are structured. An error never becomes allow or a silent false.
- `approval.bound`: binds the exact stored proposal, action and request, plus expiry, entitlement, quorum and atomic redemption. Substituted or expired requests block.
- `context.integrity`: pinned provenance, verified bytes, and separation of untrusted data from instructions. Untrusted content cannot create authority.
- `isolation.required`: the current active boundary must match the actual code, tools and trust domains. Missing or failed controls block, with no fallback.
- `credentials.brokered`: short-lived scoped credentials kept out of model-visible state, with real issuance and revocation. Missing mediation blocks.
- `network.mediated`: destination, DNS and redirect controls at the real egress point. Prohibited destinations block.
- `data.flow_policy`: purpose, source labels, recipients, processors/residency and approved transformations at every stage. A prohibited or unknown flow blocks.
- `memory.lifecycle`: owned namespace, provenance, reviewed promotion, retention, and propagation of corrections and deletions. Incomplete propagation stays visible.
- `effects.reconciled`: stable operations, provider-specific retry evidence, and honest partial or unknown outcomes. Blind retry blocks.
- `execution.checkpointed`: pinned artifacts, current authority/approval/budget, and owned fenced resume. A stale executor or changed interpretation blocks.
- `delegation.attenuated`: child identity, intersection with every ancestor plus their revocation, bounded outputs, and cancellation propagation. Child scope expansion blocks.
- `budget.aggregate`: one shared capacity for root, child, retry and replan work. Exact units, reservations, verified settlement and an inherited deadline. Exhaustion blocks; unknown usage keeps its capacity reserved.
- `audit.correlated`: run, trace, operation, decision and control correlation, plus minimisation, access control and retention.
- `release.pinned`: the evaluated artifact set, extension admission, protected changes and rollback limits. Drift requires impact review.
- `operations.stop_recover`: owned stop, escalation and reconciliation queues, with observed outage and recovery behaviour.
- `governance.separation`: independent approval and control roles. Self-authorised lowering of requirements blocks.
- `assurance.fault_evidence`: authorised fault and abuse tests plus a workflow-, release- and environment-specific assurance argument.

**Test case IDs:** each control registers `<control_id>.useful` and `<control_id>.denied`.

**Personal/proactive standing mandates**
- A mandate names: owner, authenticated trigger channel/device, purpose/tasks, capabilities, resources, destinations, budget, lifetime, escalation path and revocation.
- At every wake and dispatch, recheck provenance, authority, approval, budget and boundary.
- Notification is not consent. Trigger text is untrusted.
- Owners need controls to inspect, pause, revoke and stop, and to see effect state.
- Offline/edge: requires trusted time, bounded local authority and reconcile-on-reconnect. Suspend once revocation freshness cannot be established. Never blindly replay queued effects.

---

## 2. Conformance evidence model

**Three separate claims**
1. **Declared support:** compatibility only.
2. **Reference validation** (`ReferenceValidationReport`): outcome `reference_checks_passed` or `reference_checks_failed`. It is forced to `runtime_controls: "not_evaluated"` and can never use the runtime outcome `passed`.
3. **Runtime workflow conformance:** a trusted assessor with authenticated, current, deployment-verified evidence.

**`ConformanceReport` contents**
- Version/ID, implementation ID/revision, workflow ID, selected profiles, effective required controls.
- Registry, suite and release refs; environment description and config ref; observation interval; evaluator.
- Control rows (status ∈ `ControlEvidenceStatus`) with case results, evidence refs, reasons and limitations; utility rows; declared outcome.
- The report digest binds the canonical report under domain `contextos.conformance_report.v1`.
- Each evidence observation binds: that digest, the artifact and its bytes, provenance (`runtime` | `synthetic`), the trusted observer, and a validity interval.
- Adapters must authenticate observations and assessor identity before calling the pure assessor.

**`ConformanceAssessmentInput`**
- Contains: pinned contract, registry and support; trusted admitted feature set; expected workflow/implementation/release/environment scope; required utility-case IDs; explicit evaluation time; trusted assessors and observers; separate verification observations.
- A report cannot pick its own utility cases.

**Assessment algorithm**
1. Validate closed, bounded shapes and canonical serialisation. Error output must not echo the payload.
2. Negotiate profiles plus the feature union. An unsupported mandatory control means no admission.
3. Match the full scope. Verify the digest, the evaluator and that the interval is current.
4. Reject duplicate or conflicting rows. Each mandatory control needs current verified runtime evidence and every registered useful and denied case. A failed extra case cannot be hidden.
5. Every trusted utility case must pass. An always-deny implementation fails. Empty arrays cannot pass vacuously.
6. Keep optional unsupported controls and limitations visible. Output is `passed`, `failed` or `insufficient_evidence`.

**Outcome mapping**
- A verified failure gives `failed`.
- Missing, stale, unverified, unsupported, synthetic or `not_evaluated` mandatory evidence gives `insufficient_evidence`.
- A self-declared `passed` never overrides either.

**Evidence families each runtime must produce**

| Family | Must demonstrate |
|---|---|
| Identity/authority | Spoofed tenant, ancestor revocation, verifier outage |
| Policy/approvals | Predicate exception, proposal substitution, expired stored request, invalid quorum, redemption race |
| Context/extensions | Injected instructions, artifact drift, unapproved extension |
| Isolation/credentials/network | Forbidden filesystem/process/credential access, DNS/redirect escape, enforcement outage |
| Data/memory | Forbidden recipient/residency, label downgrade, expired retention, incomplete deletion propagation |
| Effects/recovery | Lost ack, partial commit, stale executor, cancellation race |
| Budgets/delegation | Competing reservations, child expansion, uncertain usage, retry/replan exhaustion |
| Audit/ops/governance | Outages, protected config change, stop/recovery drill |

**Release changes:** changes to policy, tools, model, extensions, processor routes or sandbox config need impact review and re-evaluation. Expired evidence must be renewed. Cross-runtime portability is not yet established; the docs name it as a roadmap exit criterion.

---

## 3. Security controls (`security.mdx`)

**Pipeline control points**
- **Compile:** `runtime_controls` `{must_refuse, must_escalate, approval_gates_active, redaction_rules_active}`; tools = `Registry ∩ Permissions − Prohibitions`.
- **Plan:** the Critic checks tools ⊆ surfaced, the intent shape (`read_only` excludes `act`), evidence, and the v1 ceiling.
- **Execute:** the Tool Gateway re-checks identity, schema, args, `ActionRisk`, approval, destination, data scope, budget, idempotency and the egress allow-list.
- **Sandbox:** the kernel enforces, not the adapter.
- **Memory write:** classification, consent and contradiction checks.
- **Audit:** OTEL plus DecisionRecord via `trace_id`.
- **Replay:** pinned inputs, live effects disabled.

**Threat model**
- Multi-principal under partial trust: agent provider, model provider, tool ecosystem (MCP/OpenAPI/A2A), cloud/runtime, and enterprise/user.
- The deployment must state its trusted computing base (TCB), assumptions, allowed effects and residual risks.
- Attack classes: prompt/context injection, excessive agency, credential exfiltration, tool-argument tampering, cross-tenant traversal, repeated/amplified calls, memory poisoning, supply chain, sandbox escape, audit tampering.
- OWASP Agentic ASI01–ASI10 mapping is informative.

**Prompt injection** (structural defence)
- Typed buckets: policy, tool, evidence, memory, business, session. Evidence and memory are advisory and `data_only`.
- Unsurfaced capabilities are rejected at the gateway even if the model names them.
- Policy is re-evaluated deterministically for every `ToolCallEnvelope`.
- `arg_constraints` support regex, enum, min/max and idempotency-key-required, e.g. `to_in: [...]` makes an attacker address `denied`.
- Redaction is a separate enforcer; the compiler only names obligations.
- Default deny everywhere. Unknown capability, scope or destination denies.
- `runtime_controls.context_admission` marks data-only blocks and requires privileged args to derive from verified sources or user intent.

**Identity**
- `run_context.agent.workload_identity` is a SPIFFE URI (`spiffe://contextos/agents/<role>`), required.
- `run_context.agent.agent_urn`, e.g. `agent:contextos/support-refund@1.2.0`.
- Optional `run_context.user.delegation` (token ref, scopes, subject). Required when authority is `user_delegated`.
- Optional `run_context.agent.identity_claim` (signed profile).
- The v1 `ToolCallEnvelope` carries `principal_chain` and an opaque `auth_ref`.
- Per-call STS-style exchange (RFC 8693). Scopes are the **intersection** of delegated, claim, permission and capability scopes.
- A2A never forwards tokens; the receiver re-attests.
- Attestation failure logs `security_event:workload_identity_attestation_failed` before policy evaluation.
- Log claim hashes and key IDs, never raw tokens.

**Credentials**
- A trusted broker owns secrets. Model-visible state carries only `token_ref` / `auth_ref`.
- Secrets bypass the compiler and are resolved at the gateway from `(tenant, capability)`.
- Sandbox `permitted_env_vars` is a closed allow-list.
- The registry refuses adapters without a declared rotation contract.

**Egress**
- Mediate every outbound path: inference, telemetry, code workers, children.
- Exact origins, ports and routes. Block private and metadata destinations.
- Verify DNS resolution and every redirect, including rebinding and CNAME changes.
- Optional TLS pinning via `pinned_sha256[]`.
- Per-`(tenant, capability)` rate limit returns `denied` with `error_code: rate_exceeded` and no queueing. The failure playbook uses `RATE_LIMITED` (see §8).
- An egress span carries `trace_id, policy_decision_id`, capability ID and destination.

**Data classes and stages**
- `PUBLIC` / `INTERNAL` / `CONFIDENTIAL` (redact-on-emit, memory promotion gated) / `RESTRICTED` (never in the prompt, never promoted). This default is illustrative.
- Enforce at all 9 `DataFlowStage`s. A declared region or redaction flag is not enough.
- A failed required transformation blocks the route.

**Sandbox**
- Profile JSON is illustrative, not a base type: `sandbox_profile_id, version, kernel(docker|e2b|firecracker|wasm), image_pin sha256, filesystem{host_mount,tmpfs_mb}, network{ingress,egress,allowlist}, compute{cpu_cores,memory_mb,wall_clock_ms}, stdio{*_max_bytes}, secrets.permitted_env_vars, result_classification`.
- Invariants: default deny; no inlined profiles; `host_mount` needs a versioned operator approval; no inbound network; hard caps enforced by the kernel.
- Tags `latest` / `stable` are refused.
- Output is governed data.
- Observe the config digest, enforcer identity and age at dispatch. A missing control blocks, with no fallback to the host or a weaker backend.
- Profile reviewer: `security_lead`.
- The canonical comparison is `ExecutionBoundaryRequirement` vs `ExecutionBoundaryObservation`.

**Supply chain**
- Packs are `pack_id@semver` and immutable. Adapters declare an image hash or repo+commit.
- Models record the provider ID and revision. Never claim a content hash for a hosted model.
- Sigstore-compatible provenance is an **optional profile**.
- Signing is optional; keys live in KMS; revoked keys stay queryable for replay.
- Hash-chained audit is **optional**.
- Attestation and confidential compute are **optional** (trusted-ai-agents-cloud is a Research Note).

**Tenant isolation**
- Storage-layer `tenant_id` scoping.
- The gateway rejects argument-derived tenant ≠ `run_context.tenant_id`.
- Security event `security_event:memory_cross_subject_denied`.
- Cache keys include tenant, owner, namespace and all policy pins.

**A2A**
- An Agent Card is discovery, not admission.
- Child authority is an `AgentDelegationEnvelope` that is a subset of the parent's.
- Typed `correlation_id`, `parent_decision_id`.
- Risk is recomputed per hop.
- The Orchestrator enforces depth and cycle limits, with `error_code: a2a_cycle_detected`.

**Security outputs**
- Allow/deny with reasons.
- Approval prompts with frozen evidence.
- Security events: cross-tenant denials, credential rotations, sandbox violations, attestation failures, A2A cycles.

**Incident response**
- Replay by `trace_id`; quarterly drill.
- Tail sampling retains runs that crossed a gate, had a material effect or security event, hit a loop guard, or failed a scorecard.
- Time-to-replay is a regression metric.

---

## 4. Control-plane config keys (`control-plane-config.mdx`; examples, not canonical)

**Policy bundle** (local authoring aggregate; in v2 `policy_layer.policy_bundles[]`, `.guardrails` and `.approval_gates` are siblings)
- Fields: `bundle_id, priority(≥0), effective_from, policy_dsl{language:"jsonlogic", rules[]}, guardrails{must_refuse[], must_escalate[], redaction_rules[]}, approval_gates[], prohibited_claims[]`.
- `Rule`: `rule_id, applies_to{intent,task}, if, then{allow, approval_mode, requires[], prohibits[], requires_approval_gate, arg_constraints}, else, decision_binding, rationale, citations[]`.
- `ApprovalGate`: `gate_id, when, required_approver_role, ttl_seconds(≥60)`.
- Rule IDs and gate IDs are separate, e.g. `R_HIGH_VALUE_REQUIRES_APPROVAL` vs `GATE_FINANCE_APPROVAL`.
- Runtime ID prefixes: `pol_…`, `tool_…`, `rp_…`.
- The v2 policy layer also has `PolicyLayer.action_risk_policy` (conjunctive per dimension).

**Composition semantics**
- Higher numeric priority wins. Deny wins at equal priority. Default is deny.
- Guardrail, escalation and approval requirements stay independent and conjunctive.
- Compiler prohibitions accumulate.
- An applicable predicate error throws `ContextCompileError`. There is no `non_enforcing` flag.

**Intent/Task catalog** (Decision-plane owned)
- `catalog_version, intents[]{intent_id, version, owner_role, description, risk_class, accepted_channels, locale_support, eligible_task_templates}, task_templates[]{task_template_id, version, intent_id, owner_role, decision_bindings[]{decision_key, checkpoint_after_step}, default_plan, eligibility_rules}`.

**Decision catalog**
- `catalog_version, decision_specs[]{decision_key, version, owner_role, required_evidence[], allowed_outcomes[], approval_mode, inputs_schema_ref, outputs_schema_ref, eligibility_rules, decision_right(propose|recommend|execute|escalate), challenge_required}`.

**Routing config**
- `model_profiles[]{model_profile_id, provider_adapter, deployment_ref, capabilities, limits, policy, status(healthy|degraded|disabled)}`.
- `routing_policies[]{policy_id, owner_role, default_profile, rules[]}`.

**Evaluation gates**
- `eval_version, eval_targets[]{intent, policy, utility, latency_p99_ms, safety, economics_cents_per_decision}`.
- `release_gates[]{metric, max_delta, verdict_on_breach(block|warn)}`.
- `warn` can never bypass mandatory controls or safety floors.

**`ApprovalMode`** = `read_only | local_write | network | delegated | destructive`. This is the v1 projection and ceiling only.

**`ActionRisk`**
- `effect{none,local_state,external_state,physical_world}`
- `authority{agent,service,user_delegated,human_approved}`
- `reversibility{read_only,reversible,compensatable,irreversible}`
- `interaction{api,browser,computer,agent_to_agent,human_handoff}`
- `data_scope{PUBLIC..RESTRICTED}`
- `decision_ttl_seconds?`

**`RunBudget`**
- Limits: `total_tokens, bucket_tokens{business,policy,tool,evidence,memory,session}, max_tool_calls, max_replan_attempts, wall_clock_ms, max_cost_cents`.
- Usage counters: `tokens_used, tool_calls_used, latency_ms_used, cost_cents_used`.
- Exact accounting uses a declared currency and a power-of-ten quantum.

---

## 5. Component responsibilities and interfaces

The deployment rule: the Compiler, AI Gateway, Tool Gateway and Policy Engine are platform services or platform-controlled modules, never optional libraries inside agent code.

**Plane dependency rules**
- Context reads Intelligence and never mutates it.
- Decision cannot add tools beyond `tool_manifest`.
- Model calls go only through the AI Gateway.
- Effects go only through the Tool Gateway.
- Intelligence writes go only through promotion.

**Three ledgers:** context, effect and decision, indexed by `DecisionRecord`. In addition, the durable run/checkpoint stores and `BudgetLedger` are required.

**Canonical loop**
`invokeAgent → resolve → admit(profiles, features, support) → compile → bind DecisionSpec → loop{planner→Plan; critic.verify→ok|replan|reject|escalate; executor via ToolGateway; critic.score→accept|retry|replan|escalate; consolidate→memory_proposals} → DecisionRecord → ReplayPacket + scorecard`.

### Conversation Manager
- **Input:** `invokeAgent`. **Output:** `RunContext`.
- Rejects unpinned `context_pack_refs[]`. Generates `run_id`; threads `trace.trace_id` and `session_id`.
- Channels: `app_chat, email, voice, api, webhook, sms`, normalised to `text_message | structured_request | event_envelope`. Channel signals go on `event.metadata.channel.*`; warnings on `event.warnings[]`.
- Channel metadata is never authentication.
- Errors: `pack_version_mismatch`; a `truncated` flag on back-pressure.
- Per-tenant rate limits are applied here.

### Intent / Risk Classifier
- **Output:** `intent_id`, v1 `risk_class`, `confidence`, `alternatives[]`.
- Deterministic tie order.
- Refuses when `risk_class` conflicts with `safety_mode`.
- Missing native risk under `action_risk_policy` fails closed.

### Context Pack Compiler
- Pure: no I/O, no clock, no globals.
- Eight stages: intent → policy resolution (JsonLogic) → tool surfacing (`Registry ∩ Permissions − Prohibitions`, native risk, `safety_mode` ceiling) → evidence normalisation (verify supplied hashes) → memory recall (promoted only) → token budget allocation → bucket admission/assembly → manifests + `runtime_controls`.
- **Output fields:** `compiled_prompt{system,developer,task,context_blocks[].provenance{source_refs,origin,integrity,freshness,instruction_treatment,inclusion_reason,content_hash}}`, `manifests{policy_manifest,tool_manifest[].capability_metadata,evidence_manifest}`, `runtime_controls{context_admission,evidence_gates[]{sufficiency,commit_allowed},…}`, `budget_report{allocations,usage,bucket_truncations,dropped_block_ids,omissions[],warnings}`, `context_ledger{…,compiled_context_hash}`.
- **Errors:** `ContextCompileError{code:"policy_eval_error", stage:"policy_resolution", expression_path:"if"}` with no raw expression or stack; `unsupported_action_risk`; hash mismatch rejects.
- Unresolved conflict gives `sufficiency: insufficient` and blocks commit. The losing branch is kept as `superseded_by_resolution`.
- Retrieval or memory blocks are never `control`.
- The cache key is the complete set of compile inputs.

### Policy Engine
- Pure function `(rules, eval_context) → PolicyDecision`.
- `PolicyDecision` is a **candidate profile**: `allowed, reason, action_risk_evaluation?, effective_approval_mode?, requires_approval_gate?, requires[], prohibits[], policy_decision_id, matched_rule_ids[]`.
- Canonical outcome types: `NormalizedPolicyOutcome / ComposedPolicyOutcome / AuthorizationOutcome`.
- `composePolicyOutcomes` uses `guardrail` and `business` categories.
- Checkpoints: compile, plan, execute, and wake/resume.
- Cache keyed by content-addressed bundle hash.
- Lint: unreachable rules, unsatisfiable rules, missing `decision_binding`.

### Orchestrator
- Runs the Planner/Executor/Critic triad. It may run in a single process.
- Steps: plan → verify → execute (pre-dispatch recheck of authority, approval redemption, boundary/data and reservation) → verify effect and score (`retry` is only a proposal) → consolidate → loop (capped by `max_replan_attempts`; the worked example uses 2, with no universal default).
- **Lanes:** child RunContext/identity, a reserved budget slice, narrowed tools, stitched traces. Lanes cannot mutate parent `effects[]`; an attempt is an invariant violation, lane termination and a security event.
- **Background sessions:** six resume checks — support, authority, approval, boundary, external preconditions, budget.
- Uses the `RunStatus` lifecycle. `completed` requires all required effects confirmed and all children settled. Cancellation is not rollback.
- Loop guard must set the reason `loop_detected`.

### Tool Manager (Tool Gateway)
- Lifecycle: `build, broker, gate, invoke, return`.
- Resolve the exact capability revision → schema validation → policy re-evaluation → bind `ActionBinding` and atomically redeem the approval → recheck authority, revocation, containment/egress, data route and reservation; broker credentials → atomically claim the operation under revision/generation and dispatch → emit `ToolResultEnvelope` plus separate effect/postcondition attachments.
- `idempotency_key` is required for writes, bound to the operation and persisted before dispatch. A cache miss is not permission to retry.
- Cached aliases `mcp_<server>_<tool>`: read-only, from cached discovery, still routed through the gateway, invalidated on bundle promotion.
- Errors: `VALIDATION_ERROR`, `RATE_LIMITED`. Expired credentials: refuse and request re-issuance.
- Step timeouts are enforced by the gateway, not the adapter.

### AI Gateway / LLM Router (Reference Design; northbound envelope is *not* a published schema)
- **Request:** `request_id, run_id, trace_id, tenant_id, intent_id, action_risk{…}, risk_class, operation (e.g. judge.plan), compiled_context_ref, input{instructions,messages}, requirements{structured_output,tool_calling,vision,max_input_tokens,max_output_tokens,latency_slo_ms,max_cost_usd,data_residency}, routing_hints{quality_tier,fallback_allowed,canary_allowed}`.
- **Response:** `status, output{type,value}, usage{input_tokens,output_tokens,estimated_cost_usd}, route{routing_decision_id, model_profile_id, provider_adapter, routing_rule_ids, fallback_index, explanation}`.
- **Model profile:** `capabilities{structured_output,tool_calling,vision,long_context,streaming}`, `limits{max_input_tokens,max_output_tokens,rpm,tpm}`, `policy{regions, data_classes_allowed, stores_provider_state, action_risk{allowed_effects,allowed_authorities,allowed_reversibility,allowed_interactions,data_scope_ceiling}, eligible_risk_classes}`, `score_hints`, `status`.
- **Routing rule (YAML):** `rule_id, priority, when{action_risk|risk_class,…}, require{data_residency, capabilities, max_fallbacks}, score{quality,reliability,latency,cost}, candidates[]`.
- **Algorithm:**
  1. Filter by native risk, residency, classification, capabilities, policy, health, quota and context size.
  2. Score.
  3. Select with deterministic ties: policy priority → quality band → lower p95 → lower cost → stable provider priority.
  4. Invoke.
  5. Record.
  - No ambient clock or random tie-breaks. A canary cohort is a stable input.
- **Fallback table:**
  - Timeout: retry once if idempotent, then fall back.
  - Rate limit: use the same policy band.
  - Budget: downgrade only if the quality floor holds, else `BUDGET_EXCEEDED`.
  - Schema failure: repair prompt if policy allows, else `SCHEMA_INVALID`.
  - Residency mismatch: never fall back.
  - Every attempt reserves from the root budget.
- **Streaming events:** `route.selected, output.delta, usage.delta, provider.warning, output.final, error.final`.
- **Spans:** `contextos.ai_gateway.invoke > contextos.llm_router.select > contextos.provider_adapter.invoke`.
- **Required span attributes:** `contextos.run_id, contextos.intent_id, contextos.routing_decision_id, contextos.model_profile_id, contextos.provider_adapter, contextos.fallback_index, contextos.estimated_cost_usd`.
- **Security:** redact before the provider; deny unsatisfiable residency; provider credentials stay inside the gateway; provider state is off by default; prompt caching is off by default; provider tool calls are proposals only; authority and routes are rechecked on every fallback.
- **`RoutingDecision`** is a **candidate profile, not canonical**: `routing_decision_id, request_id, run_id, trace_id, policy_version, selected_profile, candidate_profiles, rejected_profiles[]{model_profile_id,reason}, usage, fallback_index, created_at`. Link it via `DecisionRecord.lineage.routing_decision_id`.

### Observability
- W3C `traceparent` / `tracestate`. Baggage is not forwarded blindly.
- Span attributes: `contextos.run_id, contextos.context_pack_ref, contextos.action.{effect,authority,reversibility,interaction,data_scope,approval_mode_effective}, contextos.trust.policy_decision_id, contextos.intelligence.snapshot_version, contextos.budget.tokens_used`.
- The architecture page adds: `contextos.session_id, tenant_id, intent, policy_bundle_ids, approval_mode_required, decision_key, decision_record_id, replay_id`.
- Append-only audit indexed by `(trace_id, decision_key, time_window)`.
- Audit outage: declared fail-closed or bounded durable buffer.
- `TraceBundle` and `SecurityEvent` are candidate profiles.

### Evaluation Engine
- Evaluators P/U/L/S/E: Policy, Utility, Latency, Safety, Economics.
- Canonical outputs: `RunScore`, `ReplayPacket`. Candidates: `GoldenSet`, `ReleaseVerdict` (`pass` / `block`).
- Steps: score → replay (deterministic exact match, probabilistic by property) → gate (hard floors are not tradeable) → propose.
- Pin the judge model and rubric.
- Online evaluation consumes the run's budget; offline evaluation has its own root budget.

### Admin Console
- RBAC roles: `policy_writer`, `approver`, `correction_writer`.
- Optimistic concurrency on edits. Backend rejects self-approval, stale bindings and expired approvals.
- Surfaces include authority/running-work, recovery/accounting and the control/evidence registry.
- WebAuthn is optional.

### Knowledge Substrate
- `EvidenceBundle{snapshot_version, ontology_version, seed, hops[] with evidence_ref, conflicts[], truncated}`.
- Params: `mode, seed_strategy, max_hops, top_k, freshness_window, evidence_required`, plus `snapshot_pin_rule`.

### Reviewer agents (local profile)
- Seven reviewers: architecture, security, reliability, product, data, cost, compliance.
- Output envelope: `review_id, reviewer_agent, reviewer_version, subject{kind,…}, status, findings[]{finding_id, severity, file, issue, policy_id, recommendation}, evidence_refs, trace_id, completed_at`.
- Severity: `blocker, must-fix, should-fix, nit`.
- Reviewers may auto-deny but never auto-approve in the high-assurance reviewer profile. Rollout starts at `0%_shadow`.

---

## 6. Required metrics (exact names; `contextos.<plane>.<component>.<signal>`)

**Naming rules**
- Suffixes: `_duration_ms`, `_rate`, `_count`, `_total`, `_cost_usd` / `_cost_inr`.
- Latency rollups p50/p95/p99.
- No IDs or raw text in metric names.

**Required dimensions**
- Always: `tenant_id, environment, release_version, plane, component, component_version, workflow_id, intent_id, task_type, risk_class, run_id, trace_id`. High-cardinality IDs go on spans and exemplars.
- Conditional:
  - Routing: `model_profile_id, provider, routing_policy_id`.
  - Context: `pack_version, context_pack_id, evidence_source_type`.
  - Memory: `memory_tier, knowledge_snapshot_id`.
  - Tools: `tool_id, adapter_id, action_effect, action_authority, action_reversibility, action_interaction, action_data_scope, approval_mode_declared, approval_mode_effective`.
  - Policy: `policy_profile, policy_decision_id`.
  - Evaluation: `evaluator_id, golden_set_id, replay_dataset_id`.
  - UX: `channel, locale, user_cohort`.

**Minimum scorecard** (by tenant, intent, release and pack version)
`contextos.decision.task.verified_success_rate, contextos.decision.task.safe_completion_rate, contextos.run.end_to_end_duration_ms, contextos.run.first_useful_response_duration_ms, contextos.budget.cost_per_verified_success, contextos.context.answer.evidence_backed_rate, contextos.action.tool.success_rate, contextos.trust.policy.violation_rate, contextos.trust.trace.completeness_rate, contextos.trust.replay.conformance_rate`.

**Model side** (migrated from `contextos.intelligence.*` with an alias window)
- `contextos.decision.gateway.{availability_rate, request_duration_ms, cost_usd, cache_hit_rate}`
- `contextos.decision.provider.{error_rate, timeout_rate, request_duration_ms}`
- `contextos.decision.router.{decision_duration_ms, fallback_rate, model_switch_rate, policy_rejection_count}`
- `contextos.decision.output.{invalid_schema_rate, refusal_rate, repair_rate}`
- `contextos.decision.tokens.{input_total, output_total}`

**Context plane**
- `contextos.context.pack.{build_duration_ms, token_count, context_window_utilization_rate, evidence_coverage_rate}`
- `contextos.context.answer.evidence_backed_rate`, `contextos.context.claim.attribution_rate`
- `contextos.intelligence.retrieval.{precision_at_k, recall_at_k, stale_source_rate}`
- `contextos.intelligence.memory.{promotion_accept_rate, correction_rate, stale_read_rate}`
- `contextos.context.noise.irrelevant_token_rate`, `contextos.context.conflict.{detected_rate, resolved_rate}`, `contextos.context.poisoning.suspected_rate`

**Decision plane**
- `contextos.decision.plan.{validity_rate, feasibility_rate, revision_count}`
- `contextos.decision.executor.{step_success_rate, loop_guard_trigger_rate, escalation_rate}`
- `contextos.decision.critic.{veto_rate, repair_success_rate, false_pass_rate}`
- `contextos.decision.task.{success_rate, verified_success_rate, abandonment_rate}`
- `contextos.decision.record.{completeness_rate, evidence_ref_count, policy_ref_count}`

**Action plane**
- `contextos.action.tool.{success_rate, error_rate, request_duration_ms, retry_rate, evidence_return_rate, audit_link_rate}`
- `contextos.action.approval.{required_rate, honored_rate, denied_rate}`
- `contextos.action.risk.{declaration_coverage_rate, policy_denial_rate, v1_projection_mismatch_rate}`
- `contextos.action.idempotency.{replay_hit_rate, duplicate_effect_rate}`
- `contextos.action.adapter.{availability_rate, schema_validation_error_rate, version_drift_count}`

**Trust plane**
- `contextos.trust.policy.{violation_rate, must_refuse_coverage_rate, decision_duration_ms}`
- `contextos.trust.scorecard.coverage_rate`, `contextos.trust.eval.{pass_rate, regression_rate, judge_agreement_rate}`
- `contextos.trust.trace.{completeness_rate, fetch_duration_ms}`, `contextos.trust.audit.completeness_rate`
- `contextos.trust.replay.{conformance_rate, deterministic_match_rate, property_pass_rate, dataset_coverage_rate, duration_ms}`
- `contextos.trust.security.{event_count, cross_tenant_denial_count, redaction_failure_rate}`
- `contextos.trust.{user_correction_rate, operator_override_rate, human_escalation_rate}`

**Execution-control signal families** (no exact metric names are given)
- Admission/policy errors.
- Authority/approval failures and duplicate redemption.
- Boundary/data denials.
- Confirmed/partial/unknown operations and uncertainty age.
- Reconciliation backlog.
- Stale-generation denials.
- Aggregate-accounting conservation violations (target zero).
- Memory propagation states.
- Conformance evidence.

**Rule:** unknown effects and incomplete metering are reported separately and never counted as success.

**Security-page targets**
- Guardrail compliance: 100%.
- Approval honoured: 100%.
- Successful cross-tenant access: 0.
- Attack Success Rate: 0 on gated suites.
- Redaction failure on CONFIDENTIAL/RESTRICTED: 0%.

---

## 7. Runtime invariants

- Failures are typed. Silent fallback is a bug.
- Uncertainty survives timeout, cancel and restore.
- Budget is never replenished by restart, region change or checkpoint.
- Compensation is a new governed operation that can fail.
- Replay never reverses effects.

**Architecture failure table**

| Failure | Outcome |
|---|---|
| Unknown intent | `reject` or clarify |
| Missing evidence | `commit_allowed: false` |
| Policy expression error | `ContextCompileError` |
| Unsupported required control | Reject at admission |
| Tool not in manifest | `reject` |
| Argument schema mismatch | Reject |
| Approval timeout | `escalate` or `denied` |
| Policy denial | `refuse` or `escalate` |
| Budget exhaustion | Stop new work; keep effects and allow reconciliation |
| No eligible route | Fail closed or `escalate` |
| Unsafe output | Quarantine |
| Lost ack / stale worker | Keep `unknown`, reject stale ownership |
| Replay mismatch | Block promotion and open an incident |

## 8. Failure playbooks as runtime behaviours

**Intelligence plane**
- Edge without `evidence_ref`: reject the write.
- Stale snapshot: block current-decision use; re-pin explicitly; replay keeps the old pin.
- Entity-resolution false positive: quarantine.
- Embedding drift: re-embed with the pinned model version.
- Cross-tenant traversal: deny, emit a security event, page security on-call.
- Unbounded capture log: compaction plus a lag alert.

**Context plane**
- Pack referenced by name without version: refuse.
- Missing ontology, spec or adapter: fail closed.
- Truncation: set `budget_report.bucket_truncations[bucket] = true` explicitly.
- Predicate throws: `ContextCompileError` (`policy_eval_error` / `policy_resolution`).
- Tokenizer drift: reconcile plus alert.

**Decision plane**
- Disallowed tools: `replan` or `reject`, capped by `max_replan_attempts`.
- Loop guard: `loop_detected` reason, routed back to the Planner.
- Budget exhausted: stop new work and preserve operations and reservations.
- Lane mutates parent: terminate lane plus security event.
- Resume against a different pack: `pack_version_mismatch`.

**Action plane**
- Schema drift: `failed`, `error_code = VALIDATION_ERROR`, back to Planner within replan budget.
- Approval timeout: a v1 `paused` receipt is allowed, but fresh approval is needed. A session ID is not resume authority.
- Approval denied: record `REJECTED`, no dispatch.
- Lost ack or idempotency cache miss: stay `unknown`; retry only with verified provider idempotency or definitive absence, otherwise reconcile or escalate.
- Compensation: a new operation with fresh authority, approval and budget.
- Rate limited: `failed`, `error_code = RATE_LIMITED`; the Critic chooses backoff or `escalate`.
- Stale alias: invalidate on promotion; the first call re-validates.

**Trust plane**
- Stale policy cache: avoided by content-hash keys.
- Stale or unavailable revocation, identity or boundary evidence: block dispatch, wake and resume. Never fall back to model judgment or a weaker profile.
- Missing W3C headers: trace-coverage assertion fails the release gate.
- Judge drift: re-baseline and pin.
- Evidence store down: fail closed where durable audit is required.
- Cross-tenant read: return no data, not even redacted.

**Operator surface**
- Insufficient operator assurance: refuse.
- Promotion bypass: refused by RBAC plus a security event.
- Approval binding mismatch: reject and re-freeze. A stale screen cannot authorise a substitute action.

**Cross-plane**
- Resume needs: verified bytes and pins, current ownership (revision and generation), target fencing, plus the six checks.
- Cancel: stop dispatch, propagate to children, fence workers. Effect ledgers are retained.
- Data/retention failure: block the route; deletion is not complete until every propagation receipt is verified.

**Deployment-blueprint runbooks** (non-normative)
- Provider outage: eligible alternate route within residency, capability and budget.
- Latency spike: shrink budgets but never drop required evidence.
- Cost spike: never weaken risk controls.
- Audit store down: fail closed.
- Region loss or stop: stop, cancel, fence, verify.

---

## 9. Deployment topology recommendations (whole section is NON-NORMATIVE, illustrative and unbenchmarked)

**Placement**
- Intelligence: stateful, regional primary plus cross-region replica, tenant-partitioned.
- Context Compiler: stateless and regional.
- Decision: workers over durable run/operation/checkpoint/budget stores.
- Model boundary: stateless regional AI Gateway and Router.
- Action: one regional Tool Gateway over durable operation and reservation ledgers. The idempotency cache is not the source of truth.
- Trust: global, active-active with strict write controls.

**Multi-region**
- Active/active serving. Active/passive batch and embeddings.
- Replicate KG snapshots, audit, pack registry and the DecisionRecord store.
- Region pinning for regulated tenants. No cross-region replication for `RESTRICTED` (illustrative policy).
- Atomic stores need expected revisions and generation across failover. Declare quorum, lease and split-brain behaviour. A lagging replica cannot reset reservations.

**Caching**
- L1 compiled-context cache keyed by the full compile inputs.
- L2 regional cache with tenant namespaces.
- Invalidate on pack, snapshot, policy, model-profile or routing-policy promotion.
- Embedding cache key: `(model_version, text_hash, tenant_id)`.
- Prompt-response cache off by default.

**SLO wiring**
- Run Budget enforced at the Conversation Manager. Model budgets at the AI Gateway. Step timeouts at the Tool Gateway.
- Example targets (p95 / availability): Conversation Manager 100 ms / 99.95; Compiler 250 / 99.9; AI Gateway 300 / 99.95; Router 50 / 99.95; GraphRAG 500 / 99.9; Memory 200 / 99.9; Tool Gateway 1500 / 99.9; Policy Engine 100 / 99.95; Audit write 200 / 99.99.

**Stores**
- KG sharded by tenant. Vector indices rebuilt from the snapshot.
- Memory with WAL replication.
- Routing-lineage, DecisionRecord and audit stores are append-only and WORM-capable.

**Sizing tiers**
- Tier 1: 50 RPS. Tier 2: 300 RPS, active/active. Tier 3: 1000 RPS, hard isolation.
- Per-region pod sizes are given; all are examples.

---

## 10. Non-normative, roadmap or candidate items

**Candidate profiles, not canonical exported types:** `RoutingDecision`, `PolicyDecision`, `TraceBundle`, `SecurityEvent`, `ClassifierVerdict`, `SessionCheckpoint`, `GoldenSet`, `ReleaseVerdict`, `ReviewEnvelope`, `ImprovementProposal`, `PromotionRecord`, the Intent/TaskTemplate catalog service, the AI Gateway northbound envelope, the sandbox profile JSON, and the reviewer output envelope.

**Explicit non-goals until validated:** adding `EffectReceipt`, `OutcomeVerification`, `Trajectory` or `RoutingDecision` to core.

**Optional profiles:** signing/KMS, hash-chained audit, Sigstore/SLSA provenance, attestation/confidential compute, TLS pinning, WebAuthn, identity-claim signing.

**Future migration (undecided):** making `ActionRisk` required in a future major envelope. It is optional in v1 today; new adapters should emit both it and `ApprovalMode`.

**Evolution-2026 roadmap milestones (evidence-gated):**
1. Coherent adoption.
2. Portable conformance (at least two independent harnesses).
3. Operational acceptance.
4. Version decision.

Cross-runtime conformance is not yet established.

**Informative only:** OWASP ASI mapping and compliance crosswalks (NIST AI RMF, ISO 42001/27001, SOC 2, EU AI Act, GDPR/DPDP, MITRE ATLAS).

**Adoption sequence** (adopt-a-harness / evolution): inventory → observe → classify → enforce → durabilize → delegate → promote.
- Managed-runtime ownership rows to map: session/sandbox, identity/credentials, context/skills, authorization, outcome acceptance, evidence/ops, release/fallback.
- An unavailable hook narrows the conformance claim.
