import { ContextPackCompiler } from "@/lib/contextos/compiler";
import { demoPack } from "@/lib/contextos/scenario";
import type { RunContext, InvokeRequest, AgentDelegationEnvelope, ToolCallEnvelope,
  ToolResultEnvelope, DecisionRecord, ReplayPacket } from "@/lib/contextos/types";
import { assessConformanceReport } from "@/lib/contextos/conformance";
import { composePolicyOutcomes, evaluateAuthorization, validateAuthority, validateApprovalBinding, transitionApprovalRedemption } from "@/lib/contextos/authorization";
import { evaluateBoundaryReadiness, evaluateDataFlow, validateMemoryLifecycle } from "@/lib/contextos/execution-boundary";
import type { MemoryLifecycleContext, MemoryLifecycleRecord } from "@/lib/contextos/execution-boundary";
import { convertLegacyCostToUnits, recordEffectObservation, reserveChildBudget, settleChildBudget, validateResume, transitionRun } from "@/lib/contextos/durable-execution";
import { negotiateExecutionContract } from "@/lib/contextos/execution-contract";
import { sha256Canonical } from "@/lib/contextos/canonical-json";
import { ContextCompileError } from "@/lib/contextos/errors";
import { authorityFixture, authorizationFixture, approvalFixture, budgetFixture, childReservation, childSettlement,
  checkpointFixture, conformanceFixture, dataFlowFixture, fixtureArtifact, operationFixture, sandboxBoundaryFixture,
  standardProfileFixture } from "./execution-contract";
import { delegatedResearchFixture, workflowEvent } from "./execution-workflows";

export const LEGACY_SCHEMA_FILES = ["run-context.v1.schema.json", "invoke-agent.v1.schema.json",
  "agent-delegation.v1.schema.json", "context-pack.v2.schema.json", "compiled-context.v1.schema.json",
  "tool-envelope.v1.schema.json", "decision-record.v1.schema.json", "replay-packet.v1.schema.json"] as const;

export async function legacySchemaFixtures() {
  const runContext: RunContext = {
    run_id: "run_schema", trace_id: "trace_schema", tenant_id: "tenant_acme_prod",
    user: { user_id: "usr_771", role: "support_agent" },
    agent: { agent_id: "agt_support", workload_identity: "spiffe://contextos/agents/support", role: "support_ops" },
    safety_mode: "destructive", run_budget: { total_tokens: 12000, bucket_tokens: {}, max_tool_calls: 8,
      max_replan_attempts: 2, wall_clock_ms: 30000, max_cost_cents: 25, tokens_used: 0,
      tool_calls_used: 0, latency_ms_used: 0, cost_cents_used: 0.91 },
  };
  const request: InvokeRequest = { request_id: "req_schema", tenant_id: runContext.tenant_id,
    user: runContext.user, agent: runContext.agent, context_pack_refs: ["ctxpack.support@5.2.0"],
    input: { intent: "support.refund", message: "Refund order ord_881.",
      context: { identity_verified: true, refund_amount: 4200 } }, mode: "batch", runtime: {},
    trace: { trace_id: runContext.trace_id, span_id: "span_schema" } };
  const compiled = await new ContextPackCompiler(demoPack).compile(request, runContext);
  const delegation: AgentDelegationEnvelope = { envelope_version: "contextos.agent_delegation.v1",
    delegation_id: "delegation_schema", parent_run_id: runContext.run_id, child_run_id: "run_child",
    trace_id: runContext.trace_id, tenant_id: runContext.tenant_id, issuer: "agent:contextos/support@1.0.0",
    subject: "agent:contextos/lookup@1.0.0", principal_chain: [{ kind: "user", id: "usr_771", tenant_id: runContext.tenant_id }],
    scope: { allowed_intents: ["data.lookup"], allowed_capabilities: ["orders.get"],
      data_classification_ceiling: "CONFIDENTIAL", output_schema_ref: "schema:order@1" },
    sub_budget: { ...runContext.run_budget }, effect_policy: "read_only",
    issued_at: "2026-10-16T10:00:00Z", expires_at: "2026-10-16T10:05:00Z", parent_claim_hash: "sha256:fixture" };
  const toolCall: ToolCallEnvelope = { envelope_version: "contextos.tool_call.v1", tool_call_id: "call_schema",
    run_id: runContext.run_id, trace_id: runContext.trace_id, capability_id: "orders.get", args: { order_id: "ord_881" },
    principal_chain: delegation.principal_chain, approval_mode_requested: "read_only", approval_mode_effective: "read_only",
    approval_mode_highest: "destructive", evidence_refs: [] };
  const toolResult: ToolResultEnvelope = { envelope_version: "contextos.tool_result.v1", tool_call_id: toolCall.tool_call_id,
    run_id: runContext.run_id, trace_id: runContext.trace_id, capability_id: toolCall.capability_id,
    status: "ok", output: { found: true }, artifacts: [], citations: [], mutations: [], risk_tags: [], latency_ms: 2 };
  const decision: DecisionRecord = { record_id: "decision_schema", decision_key: "support.refund", decision_version: "1",
    timestamp: "2026-10-16T10:00:00Z", status: "DEFERRED", actor: { type: "AGENT", id: runContext.agent.agent_id },
    evidence_refs: [], policy_decisions: [], approvals: [], controls_active: compiled.runtime_controls,
    budget_usage: { tokens: 0, tool_calls: 0, cost_usd_cents: 0.91, wall_clock_ms: 0 },
    lineage: { pack_version: "5.2.0" }, trace_id: runContext.trace_id };
  const replay: ReplayPacket = { replay_packet_id: "replay_schema", trace_id: runContext.trace_id,
    source_kind: "decision_record", source_ref: decision.record_id, context_pack_ref: request.context_pack_refs[0],
    compiled_context_hash: compiled.context_ledger.compiled_context_hash, side_effect_policy: "transcript_only",
    expected: { status: decision.status }, latest_result: { status: "not_run", updated_at: "2026-10-16T10:00:00Z" } };
  const payloads: Record<(typeof LEGACY_SCHEMA_FILES)[number], unknown> = {
    "run-context.v1.schema.json": runContext, "invoke-agent.v1.schema.json": request,
    "agent-delegation.v1.schema.json": delegation, "context-pack.v2.schema.json": demoPack,
    "compiled-context.v1.schema.json": compiled, "tool-envelope.v1.schema.json": toolCall,
    "decision-record.v1.schema.json": decision, "replay-packet.v1.schema.json": replay,
  };
  return { payloads, runContext, request, delegation, compiled, toolCall, toolResult, decision, replay };
}

/** Real typed module factories/results supply attachment examples; simulated observations remain reference-only. */
export function executionSchemaCorpus(): unknown[] {
  const core = standardProfileFixture(), authority = authorityFixture(), approval = approvalFixture(), authorization = authorizationFixture();
  const boundary = sandboxBoundaryFixture(), data = dataFlowFixture(), checkpoint = checkpointFixture(), conformance = conformanceFixture();
  boundary.requirement.network_grants = [{ origin: "https://api.example.test" }];
  const reservation = childReservation(), budget = reserveChildBudget(budgetFixture(), reservation), settlement = childSettlement(budget.state);
  const settled = settleChildBudget(budget.state, settlement), event = workflowEvent(checkpoint.checkpoint.run_state, "resume");
  const operation = operationFixture(), provider = fixtureArtifact("provider_idempotency_contract", "payments");
  operation.intent.provider_observation = { provider_contract_ref: provider, key: "stable_key", scope: "payments:tenant_acme_prod",
    operation_id: operation.intent.operation_id, action_digest: operation.intent.action_digest, same_payload_enforced: true,
    verification_status: "verified", observer: operation.ledger.trusted_observers[0], evidence_ref: fixtureArtifact("provider_observation", "payments"),
    observed_at: "2026-10-16T07:59:59Z", valid_until: "2026-10-16T08:05:00Z", not_before: "2026-10-16T07:00:00Z", retention_expires_at: "2026-10-16T08:30:00Z" };
  const memoryFlow = dataFlowFixture(); memoryFlow.request.stage = "memory"; memoryFlow.request.destination_id = "memory:support";
  memoryFlow.request.processor_observation.destination_id = "memory:support"; memoryFlow.policy.allowed_flows[0].destination_id = "memory:support";
  const context: MemoryLifecycleContext = { tenant_id: "tenant_acme_prod", owner_id: "usr_771", namespace: "support", purpose_id: "support.refund",
    allowed_readers: ["usr_771"], allowed_operations: ["propose", "promote", "correct", "delete"], requires_review: ["promote", "correct"],
    maximum_retention_expires_at: "2026-11-16T00:00:00Z", retention_exception: "none", trusted_observers: memoryFlow.policy.trusted_observers,
    access_observation: { tenant_id: "tenant_acme_prod", owner_id: "usr_771", namespace: "support", purpose_id: "support.refund", verification_status: "verified",
      observer: memoryFlow.policy.trusted_observers[0], evidence_ref: fixtureArtifact("memory_access", "owner_771"),
      observed_at: "2026-10-16T07:59:59Z", valid_until: "2026-10-16T08:05:00Z" }, data_flow_request: memoryFlow.request, data_policy: memoryFlow.policy,
    known_derived_copy_refs: [], derived_inventory_status: "verified_complete" };
  const record: MemoryLifecycleRecord = { record_id: "memory_lifecycle_771", memory_ref: fixtureArtifact("memory", "memory_771"),
    contract_id: memoryFlow.request.contract_id, run_id: memoryFlow.request.run_id, operation_id: memoryFlow.request.operation_id,
    action_digest: memoryFlow.request.action_digest, tenant_id: context.tenant_id, owner_id: context.owner_id, namespace: context.namespace,
    purpose_id: context.purpose_id, source_refs: memoryFlow.request.source_artifacts.map(s => s.artifact_ref), readers: ["usr_771"], operation: "promote",
    policy_ref: memoryFlow.policy.policy_ref, retention_expires_at: "2026-10-23T00:00:00Z", review: null, derived_copy_refs: [], propagation_entries: [], propagation_status: "pending" };
  const { review, propagation_entries, propagation_status, ...intent } = record; void review; void propagation_entries; void propagation_status;
  const recordDigest = sha256Canonical({ domain: "contextos.memory_lifecycle_intent.v1", intent });
  // Review observations have a closed shared verification shape, without namespace-access fields.
  const observed = { verification_status: "verified" as const, observer: context.trusted_observers[0], evidence_ref: fixtureArtifact("memory_review", "review_771"),
    observed_at: "2026-10-16T07:59:59Z", valid_until: "2026-10-16T08:05:00Z" };
  record.review = { ...observed, record_digest: recordDigest, decision: "approved" };
  const propagation = { ...observed, artifact_ref: record.memory_ref, status: "pending", record_id: record.record_id,
    operation_id: record.operation_id, record_digest: recordDigest };
  data.request.requested_classification = "PUBLIC";
  data.request.transformation = { ...observed, transformation_id: "redact_order", source_refs: data.request.source_artifacts.map(s => s.artifact_ref),
    result_ref: fixtureArtifact("redacted_evidence", "order_public"), result_classification: "PUBLIC", policy_ref: data.policy.policy_ref,
    purpose_id: data.request.purpose_id, destination_id: data.request.destination_id, destination_tenant_id: data.request.destination_tenant_id,
    destination_trust_domain: data.request.destination_trust_domain, operation_id: data.request.operation_id, action_digest: data.request.action_digest,
    processor_id: data.request.processor_id, stage: data.request.stage, release_status: "approved", approval_ref: fixtureArtifact("data_release", "order_release") };
  const negotiation = negotiateExecutionContract(core.contract, core.support, core.registry, core.features);
  const badSelection = structuredClone(core.contract); badSelection.profiles[0].profile_id = "unknown.profile";
  const deniedAuthority = authorityFixture(); deniedAuthority.observations[0].revocation_status = "revoked";
  const authorizationResult = evaluateAuthorization(authorization), boundaryResult = evaluateBoundaryReadiness(boundary.requirement, boundary.observation, boundary.evaluation_time);
  const dataResult = evaluateDataFlow(data.request, data.policy, data.evaluation_time), memoryResult = validateMemoryLifecycle(record, context, memoryFlow.evaluation_time);
  if (authorizationResult.verdict !== "allow" || !boundaryResult.allowed || !dataResult.allowed || !memoryResult.allowed || settled.status !== "accepted") throw new Error("Schema factories must satisfy their actual reference validators");
  const reference = { report_version: "contextos.reference_validation.v1", report_id: "reference_schema", implementation_id: core.support.implementation_id,
    implementation_version: core.support.implementation_version, workflow_id: "schema_reference", suite_ref: fixtureArtifact("reference_suite", "schema"),
    release_refs: [fixtureArtifact("release", "schema_reference")], fixture_refs: [fixtureArtifact("synthetic_fixture", "schema")],
    case_results: [{ case_id: "authorization.useful", status: "passed" }], runtime_controls: "not_evaluated", outcome: "reference_checks_passed" };
  return [core, authority, approval, authorization, boundary, data, operation, checkpoint, conformance, budget, reservation, settlement, settled,
    record, context, propagation, event, negotiation, authorizationResult, boundaryResult, dataResult, memoryResult, reference, delegatedResearchFixture().child_authority,
    validateAuthority(authority), validateAuthority(deniedAuthority), validateApprovalBinding(approval),
    composePolicyOutcomes(authorization.policy_outcomes), { approval, expected_revision: 0 }, transitionApprovalRedemption({ approval, expected_revision: 0 }),
    transitionRun(checkpoint.checkpoint.run_state, event, checkpoint.evaluation_time), validateResume(checkpoint), assessConformanceReport(conformance),
    recordEffectObservation(operation.ledger, operation.observation, operation.ledger.revision),
    negotiateExecutionContract(badSelection, core.support, core.registry, core.features), convertLegacyCostToUnits(0.91, budget.state.cost_unit),
    new ContextCompileError({ code: "policy_eval_error", stage: "policy_resolution", bundle_id: "test", rule_id: "test", expression_path: "if", message: "ignored" }).toJSON()];
}
