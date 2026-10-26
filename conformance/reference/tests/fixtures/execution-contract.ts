import { sha256Canonical } from "@/lib/contextos/canonical-json";
import type { ProfileRegistrySnapshot, ExecutionContractEnvelope,
  RuntimeSupportDeclaration, WorkflowFeatureSet } from "@/lib/contextos/execution-contract-types";
import { digestActionBinding } from "@/lib/contextos/authorization";
import { STANDARD_PROFILE_REGISTRY } from "@/lib/contextos/profiles";
import type { ConformanceAssessmentInput } from "@/lib/contextos/conformance";
import type { ActionBinding, AuthorityValidationInput, ApprovalValidationInput, AuthorizationInput } from "@/lib/contextos/authorization";
import type { ExecutionBoundaryRequirement, ExecutionBoundaryObservation, DataFlowRequest,
  DataFlowPolicySnapshot } from "@/lib/contextos/execution-boundary";
import type { RunExecutionState, OperationClaim, OperationLedger, EffectObservation, ExecutionCheckpoint,
  ResumeValidationInput, ResumeCheck, BudgetLedger, BudgetReservationRequest, BudgetSettlementRequest,
  ResourceCounters } from "@/lib/contextos/durable-execution";

/** Re-address synthetic definitions after an intentional test edit. */
export function bindRegistry(registry: ProfileRegistrySnapshot): void {
  for (const definition of registry.controls) {
    const { definition_ref: ignored, ...payload } = definition;
    void ignored;
    definition.definition_ref = { artifact_type: "control_definition",
      artifact_id: definition.control.control_id, version: definition.control.control_version,
      sha256: sha256Canonical({ domain: "contextos.control_definition.v1", payload }) };
  }
  for (const definition of registry.profiles) {
    const { definition_ref: ignored, ...payload } = definition;
    void ignored;
    definition.definition_ref = { artifact_type: "profile_definition",
      artifact_id: definition.profile.profile_id, version: definition.profile.profile_version,
      sha256: sha256Canonical({ domain: "contextos.profile_definition.v1", payload }) };
  }
  registry.registry_ref.sha256 = sha256Canonical({ domain: "contextos.profile_registry.v1",
    payload: { profiles: registry.profiles, controls: registry.controls } });
}

export function coreFixture(): { contract: ExecutionContractEnvelope;
  support: RuntimeSupportDeclaration; registry: ProfileRegistrySnapshot; features: WorkflowFeatureSet } {
  const control = { control_id: "test.policy", control_version: "1" };
  const profile = { profile_id: "test.core", profile_version: "1" };
  const placeholder = { artifact_type: "pending", artifact_id: "pending", version: "1",
    sha256: `sha256:${"0".repeat(64)}` };
  const registry: ProfileRegistrySnapshot = {
    registry_ref: { ...placeholder, artifact_type: "profile_registry", artifact_id: "test.registry" },
    controls: [{ control, definition_ref: { ...placeholder }, evidence_obligations: ["test.policy.current"],
      positive_cases: ["test.policy.allow"], negative_cases: ["test.policy.deny"] }],
    profiles: [{ profile, includes: [], mandatory_controls: [control], conditional_controls: [],
      definition_ref: { ...placeholder } }],
  };
  bindRegistry(registry);
  return {
    contract: { envelope_version: "contextos.execution_contract.v1", contract_id: "contract_reference",
      run_id: "run_contract", trace_id: "trace_contract", tenant_id: "tenant_acme_prod",
      profiles: [{ ...profile }], required_controls: [], optional_controls: [], release_refs: [] },
    support: { implementation_id: "test.reference", implementation_version: "1",
      supported_profiles: [{ ...profile }], supported_controls: [{ ...control }] },
    registry,
    features: { arbitrary_code: false, external_network: false, persistent_memory: false,
      external_effects: false, delegation: false, checkpoint_resume: false,
      proactive_triggers: false, sensitive_data: false },
  };
}

/** Full synthetic support for selection tests, not a claim of runtime enforcement. */
export function standardProfileFixture(profileID = "contextos.core"): ReturnType<typeof coreFixture> {
  const f = coreFixture(); f.registry = structuredClone(STANDARD_PROFILE_REGISTRY);
  f.contract.profiles = [{ profile_id: profileID, profile_version: "1" }];
  f.support.supported_profiles = f.registry.profiles.map(p => ({ ...p.profile }));
  f.support.supported_controls = f.registry.controls.map(c => ({ ...c.control }));
  return f;
}

export function bindConformanceEvidence(input: ConformanceAssessmentInput): void {
  const digest = sha256Canonical({ domain: "contextos.conformance_report.v1", report: input.report });
  input.report_verification.report_digest = digest;
  input.evidence_observations.forEach(o => { o.report_digest = digest; });
}
/** Simulates post-verifier runtime facts to test aggregation only; never deployment evidence. */
export function conformanceFixture(): ConformanceAssessmentInput {
  const f = standardProfileFixture(), evaluator = { principal_id: "assessor_test", principal_type: "workload" as const,
    trust_domain: "contextos.test", tenant_id: f.contract.tenant_id };
  f.contract.release_refs = [fixtureArtifact("release", "synthetic_release")];
  const environment = fixtureArtifact("environment", "synthetic_environment");
  const proof = { verification_status: "verified" as const, observer: evaluator,
    observed_at: "2026-10-16T08:00:00Z", valid_until: "2026-10-16T09:00:00Z", evidence_kind: "runtime" as const };
  const control_results = f.registry.profiles[0].mandatory_controls.map(control => {
    const definition = f.registry.controls.find(c => c.control.control_id === control.control_id)!;
    return { control, status: "passed" as const, evidence_refs: [fixtureArtifact("control_evidence", control.control_id)], reason_codes: [], limitations: [],
      case_results: [...definition.positive_cases, ...definition.negative_cases].map(case_id => ({ case_id, status: "passed" as const,
        evidence_refs: [fixtureArtifact("case_evidence", case_id)] })) };
  });
  const utility_results = [{ case_id: "owner_scheduling.useful", status: "passed" as const, evidence_refs: [fixtureArtifact("utility_evidence", "owner_scheduling")] }];
  const report = { report_version: "contextos.conformance_report.v1" as const, report_id: "report_synthetic",
    implementation_id: f.support.implementation_id, implementation_version: f.support.implementation_version, workflow_id: "owner_scheduling",
    profiles: f.contract.profiles, effective_required_controls: control_results.map(c => c.control), registry_ref: f.registry.registry_ref,
    suite_ref: fixtureArtifact("conformance_suite", "suite_test"), release_refs: f.contract.release_refs,
    environment: { description: "Synthetic aggregation test only", configuration_ref: environment },
    evaluated_at: proof.observed_at, valid_until: proof.valid_until, evaluator, control_results, utility_results, outcome: "passed" as const };
  const evidence = [...control_results.flatMap(c => [...c.evidence_refs, ...c.case_results.flatMap(r => r.evidence_refs)]), ...utility_results.flatMap(r => r.evidence_refs)];
  const input: ConformanceAssessmentInput = { ...f, report, evaluation_time: "2026-10-16T08:01:00Z",
    scope: { workflow_id: report.workflow_id, implementation_id: report.implementation_id, implementation_version: report.implementation_version,
      release_refs: report.release_refs, environment_ref: environment, required_utility_case_ids: ["owner_scheduling.useful"] },
    trusted_assessors: [structuredClone(evaluator)], trusted_evidence_observers: [structuredClone(evaluator)],
    report_verification: { ...proof, report_digest: "", evidence_ref: fixtureArtifact("report_verification", "report_synthetic") },
    evidence_observations: evidence.map(evidence_ref => ({ ...proof, evidence_ref, actual_sha256: evidence_ref.sha256, report_digest: "" })) };
  bindConformanceEvidence(input); return input;
}

/** Synthetic snapshot bytes; their digests do not establish broker authenticity. */
export function fixtureArtifact(artifact_type: string, artifact_id: string, version = "1") {
  return { artifact_type, artifact_id, version, sha256: sha256Canonical({ artifact_type, artifact_id, version }) };
}

export function actionFixture(): ActionBinding {
  return {
    binding_version: "contextos.action_binding.v1", contract_id: "contract_reference", run_id: "run_contract",
    operation_id: "op_refund", proposal_id: "proposal_refund", tenant_id: "tenant_acme_prod",
    actor: { principal_id: "agt_support", principal_type: "workload", trust_domain: "contextos.test", tenant_id: "tenant_acme_prod" },
    authority_refs: [fixtureArtifact("authority_grant", "grant_refund")], purpose_id: "support.refund",
    capability_id: "adp_payments.issue_refund", capability_version: "1",
    arguments: { order_id: "ord_881", amount_inr: 4200 }, resource_ids: ["ord_881"], destination_ids: ["customer_771"],
    evidence_refs: [fixtureArtifact("evidence_snapshot", "order_881")],
    policy_refs: [fixtureArtifact("policy_bundle", "refund_policy")],
    profile_refs: [coreFixture().registry.registry_ref], release_refs: [fixtureArtifact("release", "test.reference")],
    action_risk: { effect: "external_state", authority: "service", reversibility: "compensatable",
      interaction: "api", data_scope: "CONFIDENTIAL" }, amount: { minor_units: 4200, currency: "INR" },
  };
}

/** Synthetic post-broker observations, never a signature-verification implementation. */
export function refreshGrantObservations(input: AuthorityValidationInput): void {
  input.observations = input.grants.map(grant => ({ grant_id: grant.grant_id, grant_revision: grant.grant_revision,
    grant_digest: sha256Canonical({ domain: "contextos.authority_grant.v1", grant }),
    verification_ref: grant.verification_ref, verification_status: "verified", revocation_status: "active",
    observed_at: "2026-10-16T07:00:00Z", valid_until: "2026-10-16T09:00:00Z",
    observer: input.authenticated.trusted_observers[0] }));
  input.binding.authority_refs = input.grants.map(grant => grant.verification_ref);
}

export function authorityFixture(): AuthorityValidationInput {
  const binding = actionFixture();
  const issuer = { ...binding.actor, principal_id: "mandate_broker" };
  const observer = { ...binding.actor, principal_id: "grant_observer" };
  const input: AuthorityValidationInput = {
    binding, evaluation_time: "2026-10-16T08:00:00Z", leaf_grant_ref: { grant_id: "grant_refund", grant_revision: "1" },
    authenticated: { principal: binding.actor, audience: "gateway.test", root_run_id: binding.run_id, run_id: binding.run_id,
      mandate_kind: "workload", trusted_issuers: [issuer], trusted_observers: [observer],
      verification_status: "verified", verification_ref: fixtureArtifact("authentication", "auth_support"),
      observed_at: "2026-10-16T07:00:00Z", valid_until: "2026-10-16T09:00:00Z" },
    grants: [{ grant_id: "grant_refund", grant_revision: "1", issuer, subject: binding.actor, audience: "gateway.test",
      scope: { root_run_id: binding.run_id, purpose_ids: [binding.purpose_id], capability_ids: [binding.capability_id],
        resource_ids: [...binding.resource_ids], destination_ids: [...binding.destination_ids], classification_labels: ["CONFIDENTIAL"],
        argument_constraints: [{ pointer: "/order_id", kind: "equals", value: "ord_881" },
          { pointer: "/amount_inr", kind: "max_integer", maximum: 5000 }], amount_ceiling: { currency: "INR", minor_units: 5000 } },
      not_before: "2026-10-16T00:00:00Z", expires_at: "2026-10-17T00:00:00Z", delegation_depth_remaining: 15,
      verification_ref: binding.authority_refs[0] }], observations: [], run_links: [],
  };
  refreshGrantObservations(input);
  return input;
}

export function refreshApprovalObservations(input: ApprovalValidationInput): void {
  input.verification_observations = input.decisions.map(decision => ({ approval_id: decision.approval_id,
    decision_digest: sha256Canonical({ domain: "contextos.approval_decision.v1", decision }),
    verification_ref: decision.verification_ref, verification_status: "verified",
    observer: input.trusted_observers[0], observed_at: "2026-10-16T07:30:00Z", valid_until: "2026-10-16T09:00:00Z" }));
}

export function approvalFixture(): ApprovalValidationInput {
  const binding = actionFixture(), authority = authorityFixture();
  const approver = { ...binding.actor, principal_id: "finance_lead", principal_type: "person" as const };
  const proposal = { request_id: "req_refund", proposal_id: binding.proposal_id, run_id: binding.run_id,
    tenant_id: binding.tenant_id, operation_id: binding.operation_id, action_digest: digestActionBinding(binding),
    policy_refs: binding.policy_refs, authority_refs: binding.authority_refs,
    not_before: "2026-10-16T07:00:00Z", expires_at: "2026-10-16T09:00:00Z" };
  const request = { ...proposal, approval_request_id: "approval_request_refund", requester: binding.actor,
    eligible_approvers: [approver], eligible_approver_roles: ["finance_lead"], required_approvals: 1,
    prohibit_self_approval: true, verification_ref: fixtureArtifact("approval_request", "approval_request_refund") };
  const input: ApprovalValidationInput = { binding, proposal, request,
    decisions: [{ ...proposal, approval_id: "approval_refund", approval_request_id: request.approval_request_id,
      approver, decision: "approved", decided_at: "2026-10-16T07:30:00Z",
      verification_ref: fixtureArtifact("approval_decision", "approval_refund") }],
    verification_observations: [], trusted_observers: authority.authenticated.trusted_observers,
    entitlements: [{ approver, role_id: "finance_lead", approval_request_id: request.approval_request_id,
      action_digest: proposal.action_digest, observer: authority.authenticated.trusted_observers[0],
      verification_status: "verified", verification_ref: fixtureArtifact("approver_entitlement", "finance_lead"),
      observed_at: "2026-10-16T07:00:00Z", valid_until: "2026-10-16T09:00:00Z" }],
    redemption_state: { approval_request_id: request.approval_request_id, revision: 0, operation_id: null, action_digest: null },
    evaluation_time: authority.evaluation_time };
  refreshApprovalObservations(input); return input;
}

export function authorizationFixture(): AuthorizationInput {
  const authority = authorityFixture(), binding = authority.binding, approval = approvalFixture();
  return { decision_id: "authorization_refund", authority,
    policy_outcomes: [{ category: "business", priority: 10, verdict: "require_approval", rule_id: "refund_approval",
      bundle_ref: binding.policy_refs[0], obligations: ["audit"] }], approval,
    required_constraints: [{ control_id: "isolation.required", control_version: "1" }],
    constraint_observations: [{ control: { control_id: "isolation.required", control_version: "1" },
      action_digest: digestActionBinding(binding), policy_refs: binding.policy_refs, verdict: "allow",
      verification_status: "verified", verification_ref: fixtureArtifact("boundary_observation", "boundary_refund"),
      observer: authority.authenticated.trusted_observers[0], observed_at: "2026-10-16T07:00:00Z", valid_until: "2026-10-16T09:00:00Z" }],
  };
}

export function boundaryFixture(): { requirement: ExecutionBoundaryRequirement;
  observation: ExecutionBoundaryObservation; evaluation_time: string } {
  const observer = { principal_id: "boundary_observer", principal_type: "workload" as const,
    tenant_id: "tenant_acme_prod", trust_domain: "contextos.test" };
  const requirement: ExecutionBoundaryRequirement = { contract_id: "contract_reference", run_id: "run_contract",
    tenant_id: "tenant_acme_prod", boundary_id: "boundary_broker", isolation_mode: "broker_only",
    configuration_ref: fixtureArtifact("boundary_configuration", "broker_configuration"), trust_domain: "contextos.test",
    required_controls: [{ control_id: "isolation.required", control_version: "1" }], filesystem_grants: [], network_grants: [],
    process_restrictions: { run_as: "contextos_broker", allow_privileged: false, allow_child_processes: false },
    resource_ceilings: { cpu_ms: 1000, memory_bytes: 134217728, pids: 1, wall_clock_ms: 30000,
      output_bytes: 1048576, scratch_bytes: 0 }, credential_broker_ref: fixtureArtifact("credential_broker", "test_broker"),
    trusted_observer: observer, maximum_observation_age_seconds: 10 };
  const observation: ExecutionBoundaryObservation = { contract_id: requirement.contract_id, run_id: requirement.run_id,
    tenant_id: requirement.tenant_id, boundary_id: requirement.boundary_id, isolation_mode: requirement.isolation_mode,
    actual_configuration_sha256: requirement.configuration_ref.sha256, trust_domain: requirement.trust_domain,
    active_controls: [...requirement.required_controls], failed_controls: [], observer,
    verification_status: "verified", evidence_ref: fixtureArtifact("boundary_observation", "test_broker_ready"),
    observed_at: "2026-10-16T07:59:59Z", valid_until: "2026-10-16T08:05:00Z", lifecycle_state: "ready",
    enforcement: { filesystem: false, process: false, network: true, resources: true, credentials: true } };
  return { requirement, observation, evaluation_time: "2026-10-16T08:00:00Z" };
}

export function sandboxBoundaryFixture() {
  const f = boundaryFixture(); f.requirement.isolation_mode = "sandboxed_code";
  f.requirement.boundary_id = "boundary_code";
  f.requirement.configuration_ref = fixtureArtifact("boundary_configuration", "sandbox_configuration");
  f.requirement.filesystem_grants = [{ root: "/workspace", path_format: "posix", access: "read_write" }];
  f.requirement.resource_ceilings.scratch_bytes = 1048576;
  f.observation.isolation_mode = "sandboxed_code"; f.observation.boundary_id = f.requirement.boundary_id;
  f.observation.actual_configuration_sha256 = f.requirement.configuration_ref.sha256;
  f.observation.enforcement.filesystem = true; f.observation.enforcement.process = true;
  return f;
}

export function dataFlowFixture(): { request: DataFlowRequest; policy: DataFlowPolicySnapshot; evaluation_time: string } {
  const observer = boundaryFixture().requirement.trusted_observer;
  const policyRef = fixtureArtifact("data_flow_policy", "support_data");
  const source = fixtureArtifact("evidence_snapshot", "order_881");
  const observation = { verification_status: "verified" as const, observer,
    evidence_ref: fixtureArtifact("source_classification", "order_label"),
    observed_at: "2026-10-16T07:59:59Z", valid_until: "2026-10-16T08:05:00Z" };
  return { evaluation_time: "2026-10-16T08:00:00Z",
    request: { contract_id: "contract_reference", run_id: "run_contract", tenant_id: "tenant_acme_prod",
      operation_id: "op_refund", action_digest: digestActionBinding(actionFixture()), policy_ref: policyRef,
      source_artifacts: [{ artifact_ref: source, classification: "CONFIDENTIAL" }], source_trust_domain: "contextos.test",
      destination_tenant_id: "tenant_acme_prod", destination_trust_domain: "contextos.test",
      destination_id: "adp_payments", purpose_id: "support.refund", stage: "tool_input",
      requested_classification: "CONFIDENTIAL", processor_id: "processor_payments", transformation: null,
      processor_observation: { ...observation, contract_id: "contract_reference", run_id: "run_contract",
        tenant_id: "tenant_acme_prod", processor_id: "processor_payments", destination_id: "adp_payments", destination_tenant_id: "tenant_acme_prod",
        destination_trust_domain: "contextos.test", residency_region: "region_test_a" } },
    policy: { policy_ref: policyRef, contract_id: "contract_reference", run_id: "run_contract", tenant_id: "tenant_acme_prod",
      not_before: "2026-10-16T00:00:00Z", expires_at: "2026-10-17T00:00:00Z",
      known_classifications: ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"], label_combinations: [],
      maximum_observation_age_seconds: 10, trusted_observers: [observer],
      source_observations: [{ ...observation, artifact_ref: source, classification: "CONFIDENTIAL",
        tenant_id: "tenant_acme_prod", trust_domain: "contextos.test" }],
      allowed_flows: [{ source_trust_domain: "contextos.test", destination_trust_domain: "contextos.test",
        destination_tenant_id: "tenant_acme_prod", destination_id: "adp_payments", purpose_id: "support.refund",
        stages: ["collection", "inference", "tool_input", "tool_output", "telemetry", "cache", "memory", "export", "delegation"],
        source_classifications: ["CONFIDENTIAL"], destination_classifications: ["CONFIDENTIAL", "PUBLIC"],
        processor_ids: ["processor_payments"], residency_regions: ["region_test_a"], transformation_ids: ["redact_order"] }] } };
}

export function runFixture(): RunExecutionState {
  return { contract_id: "contract_reference", run_id: "run_contract", tenant_id: "tenant_acme_prod",
    status: "running", revision: 1, executor_generation: 3, deadline: "2026-10-16T09:00:00Z",
    admission_ref: fixtureArtifact("run_admission", "run_contract"),
    trusted_observer: boundaryFixture().requirement.trusted_observer,
    outstanding_effects: [], child_run_ids: [], dispatch_stop_acknowledged: false, last_event_id: "event_started" };
}

export function operationFixture(): { intent: OperationClaim; ledger: OperationLedger;
  observation: EffectObservation; executor_generation: number } {
  const action = actionFixture(), run = runFixture();
  const stable = { contract_id: action.contract_id, run_id: action.run_id, tenant_id: action.tenant_id,
    operation_id: action.operation_id, action_digest: digestActionBinding(action), adapter_ref: fixtureArtifact("adapter", "payments"),
    capability_ref: fixtureArtifact("capability", action.capability_id), desired_effect: "refund_record_created",
    recovery_strategy: "manual_reconcile" as const, idempotency_key: null, idempotency_scope: null,
    provider_idempotency_ref: null, max_attempts: 2, retry_delays_seconds: [5], deadline: run.deadline,
    compensates_operation_id: null };
  const attempt = { attempt_id: "attempt_refund_1", operation_id: stable.operation_id, executor_generation: run.executor_generation,
    started_at: "2026-10-16T08:00:00Z", dispatch_state: "claimed" as const, last_observation_ref: null };
  return { intent: { ...stable, attempt, evaluation_time: attempt.started_at, provider_observation: null },
    executor_generation: run.executor_generation,
    ledger: { ledger_id: "operations_run_contract", contract_id: run.contract_id, run_id: run.run_id, tenant_id: run.tenant_id,
      revision: 1, executor_generation: run.executor_generation, deadline: run.deadline,
      trusted_observers: [run.trusted_observer], operations: [{ intent: stable, attempts: [attempt], observations: [],
        outcome: "not_dispatched", next_eligible_at: null, conflict: false }] },
    observation: { observation_id: "observation_refund_timeout", contract_id: run.contract_id, run_id: run.run_id, tenant_id: run.tenant_id,
      operation_id: stable.operation_id, attempt_id: attempt.attempt_id, action_digest: stable.action_digest,
      executor_generation: run.executor_generation, outcome: "unknown", finality: "provisional", external_ref: null,
      evidence_ref: fixtureArtifact("effect_observation", "timeout_refund"), verification_status: "verified",
      observer: run.trusted_observer, observed_at: "2026-10-16T08:00:01Z", valid_until: "2026-10-16T08:05:00Z",
      evaluation_time: "2026-10-16T08:00:01Z" } };
}

export function addressCheckpoint(checkpoint: ExecutionCheckpoint): void {
  const { digest: ignored, ...payload } = checkpoint; void ignored;
  checkpoint.digest = sha256Canonical({ domain: "contextos.checkpoint.v1", payload });
}
export function checkpointFixture(): ResumeValidationInput {
  const run = runFixture(); run.status = "suspended";
  const checkpoint: ExecutionCheckpoint = { checkpoint_version: "contextos.execution_checkpoint.v1",
    checkpoint_id: "checkpoint_contract", revision: 2, contract_id: run.contract_id, run_id: run.run_id, tenant_id: run.tenant_id,
    contract_ref: fixtureArtifact("execution_contract", run.contract_id), pack_ref: fixtureArtifact("context_pack", "support_pack"),
    policy_refs: actionFixture().policy_refs, tool_registry_ref: fixtureArtifact("tool_registry", "support_tools"),
    profile_registry_ref: coreFixture().registry.registry_ref, release_refs: actionFixture().release_refs,
    run_state: run, operation_ledger_ref: fixtureArtifact("operation_ledger", "operations_run_contract"),
    budget_ledger_ref: fixtureArtifact("budget_ledger", "budget_run_contract"), operation_ids: ["op_refund"],
    budget_snapshot: { ledger_revision: 3, cost_unit: { currency: "USD", units_per_cent: 100 },
      ceiling: { tokens: 12000, tool_calls: 8, replans: 2, cost_units: 2500 },
      used: { tokens: 100, tool_calls: 1, replans: 0, cost_units: 91 },
      reserved: { tokens: 200, tool_calls: 1, replans: 1, cost_units: 100 }, deadline: run.deadline },
    pending_approval_refs: [fixtureArtifact("approval_request", "approval_request_refund")], pending_task_refs: [],
    cancellation_state: "none", executor_generation: run.executor_generation, require_target_fencing: true,
    digest: `sha256:${"0".repeat(64)}` };
  addressCheckpoint(checkpoint);
  const observation = { verification_status: "verified" as const, observer: run.trusted_observer,
    evidence_ref: fixtureArtifact("resume_verification", "current_run_contract"),
    observed_at: "2026-10-16T07:59:59Z", valid_until: "2026-10-16T08:05:00Z" };
  const refs = [checkpoint.contract_ref, checkpoint.pack_ref, ...checkpoint.policy_refs, checkpoint.tool_registry_ref,
    checkpoint.profile_registry_ref, ...checkpoint.release_refs, checkpoint.operation_ledger_ref, checkpoint.budget_ledger_ref,
    ...checkpoint.pending_approval_refs, ...checkpoint.pending_task_refs];
  const checks: ResumeCheck[] = ["contract_support", "authority", "approval", "boundary", "external_preconditions", "budget"];
  return { checkpoint, run_id: run.run_id, tenant_id: run.tenant_id, executor_id: "worker_resume", executor_generation: run.executor_generation,
    expected_revision: checkpoint.revision, evaluation_time: "2026-10-16T08:00:00Z", trusted_observers: [run.trusted_observer],
    required_policy_refs: structuredClone(checkpoint.policy_refs),
    store_observation: { ...observation, checkpoint_id: checkpoint.checkpoint_id, checkpoint_revision: checkpoint.revision,
      checkpoint_digest: checkpoint.digest, contract_id: run.contract_id, run_id: run.run_id, tenant_id: run.tenant_id,
      executor_id: "worker_resume", executor_generation: run.executor_generation, lease_ref: fixtureArtifact("executor_lease", "worker_resume"),
      target_fencing: "enforced", run_status: run.status, cancellation_state: "none",
      operation_ledger_ref: checkpoint.operation_ledger_ref, budget_ledger_ref: checkpoint.budget_ledger_ref,
      operation_ids: [...checkpoint.operation_ids], budget_snapshot: structuredClone(checkpoint.budget_snapshot) },
    artifact_observations: refs.map(ref => ({ ...observation, artifact_ref: ref, actual_sha256: ref.sha256 })),
    current_observations: checks.map(check => ({ ...observation, check, status: "ready", run_id: run.run_id,
      tenant_id: run.tenant_id, checkpoint_digest: checkpoint.digest, executor_generation: run.executor_generation })) };
}

export function bindBudgetRefs(ledger: BudgetLedger): void {
  const identity = { ledger_id: ledger.ledger_id, contract_id: ledger.contract_id,
    parent_run_id: ledger.parent_run_id, tenant_id: ledger.tenant_id, cost_unit: ledger.cost_unit };
  ledger.original_limits_ref.sha256 = sha256Canonical({ domain: "contextos.budget_limits.v1",
    payload: { ...identity, original_limits: ledger.original_limits, deadline: ledger.deadline } });
  ledger.opening_usage_ref.sha256 = sha256Canonical({ domain: "contextos.budget_opening.v1",
    payload: { ...identity, opening_usage: ledger.opening_usage } });
}
export function budgetFixture(overrides: Partial<Record<keyof ResourceCounters,
  { ceiling?: number; used?: number; reserved?: number }>> = {}): BudgetLedger {
  const zero = (): ResourceCounters => ({ tokens: 0, tool_calls: 0, replans: 0, cost_units: 0 });
  const ceiling = { tokens: 12000, tool_calls: 8, replans: 2, cost_units: 2500 }, used = zero(), reserved = zero();
  for (const key of Object.keys(ceiling) as (keyof ResourceCounters)[]) {
    if (overrides[key]?.ceiling !== undefined) ceiling[key] = overrides[key]!.ceiling!;
    if (overrides[key]?.used !== undefined) used[key] = overrides[key]!.used!;
    if (overrides[key]?.reserved !== undefined) reserved[key] = overrides[key]!.reserved!;
  }
  const ledger: BudgetLedger = { ledger_id: "budget_run_contract", contract_id: "contract_reference",
    parent_run_id: "run_contract", tenant_id: "tenant_acme_prod", revision: 1, executor_generation: 3,
    deadline: "2026-10-16T09:00:00Z", cost_unit: { currency: "USD", units_per_cent: 100 },
    original_limits: { tokens: ceiling.tokens, tool_calls: ceiling.tool_calls, replans: ceiling.replans, cost_cents: ceiling.cost_units / 100 },
    original_limits_ref: fixtureArtifact("budget_limits", "budget_limits_contract"),
    opening_usage: structuredClone(used), opening_usage_ref: fixtureArtifact("budget_opening", "budget_opening_contract"),
    ceiling, used, reserved, unknown_usage_policy: "retain_reservation", mutations: [],
    trusted_observers: [runFixture().trusted_observer], reservations: [] };
  if (Object.values(reserved).some(value => value > 0)) ledger.reservations.push({ reservation_id: "reservation_existing",
    run_id: "run_existing", scope: "child", allocation: structuredClone(reserved), used: zero(),
    status: "reserved", deadline: ledger.deadline, settlement_ref: null });
  bindBudgetRefs(ledger); return ledger;
}
export function childReservation(allocation: Partial<ResourceCounters> = {}): BudgetReservationRequest {
  return { ledger_id: "budget_run_contract", contract_id: "contract_reference", parent_run_id: "run_contract", tenant_id: "tenant_acme_prod",
    mutation_id: "reserve_child_1", reservation_id: "reservation_child_1", scope: "child", run_id: "run_child_1",
    allocation: { tokens: 10, tool_calls: 1, replans: 0, cost_units: 100, ...allocation },
    cost_unit: { currency: "USD", units_per_cent: 100 }, deadline: "2026-10-16T08:30:00Z",
    expected_revision: 1, executor_generation: 3, evaluation_time: "2026-10-16T08:00:00Z" };
}
export function bindBudgetUsage(settlement: BudgetSettlementRequest): void {
  const { expected_revision: ignoredRevision, executor_generation: ignoredGeneration, evaluation_time: ignoredTime,
    usage_observation: ignoredObservation, ...intent } = settlement;
  void ignoredRevision; void ignoredGeneration; void ignoredTime; void ignoredObservation;
  settlement.usage_observation.intent_digest = sha256Canonical({ domain: "contextos.budget_settlement_intent.v1", intent });
}
export function childSettlement(ledger: BudgetLedger, usage: Partial<ResourceCounters> = {}): BudgetSettlementRequest {
  const reserved = ledger.reservations.find(record => record.reservation_id === "reservation_child_1")!;
  const settlement: BudgetSettlementRequest = { ledger_id: ledger.ledger_id, contract_id: ledger.contract_id,
    parent_run_id: ledger.parent_run_id, tenant_id: ledger.tenant_id, mutation_id: "settle_child_1", reservation_id: reserved.reservation_id,
    scope: reserved.scope, run_id: reserved.run_id, usage: { tokens: 6, tool_calls: 1, replans: 0, cost_units: 37, ...usage },
    cost_unit: { ...ledger.cost_unit }, usage_status: "known", execution_status: "completed",
    expected_revision: ledger.revision, executor_generation: ledger.executor_generation, evaluation_time: "2026-10-16T08:01:00Z",
    usage_observation: { intent_digest: "", verification_status: "verified", observer: ledger.trusted_observers[0],
      evidence_ref: fixtureArtifact("budget_usage", "usage_child_1"), observed_at: "2026-10-16T08:00:59Z", valid_until: "2026-10-16T08:05:00Z" } };
  bindBudgetUsage(settlement); return settlement;
}
