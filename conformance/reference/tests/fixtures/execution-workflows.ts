import { digestActionBinding } from "@/lib/contextos/authorization";
import { negotiateExecutionContract } from "@/lib/contextos/execution-contract";
import type { AuthorityValidationInput } from "@/lib/contextos/authorization";
import type { RunEvent, RunEventKind, RunExecutionState } from "@/lib/contextos/durable-execution";
import { authorizationFixture, boundaryFixture, budgetFixture, childReservation, conformanceFixture, dataFlowFixture,
  fixtureArtifact, operationFixture, refreshApprovalObservations, refreshGrantObservations, runFixture,
  sandboxBoundaryFixture, standardProfileFixture, bindConformanceEvidence } from "./execution-contract";

function workflowFixture(id: string, profile: string) {
  const selection = standardProfileFixture(profile), authorization = authorizationFixture();
  const boundary = boundaryFixture(), data = dataFlowFixture(), budget = budgetFixture(), run = runFixture();
  run.status = "created";
  selection.contract.release_refs = [fixtureArtifact("release", "workflow_reference")];
  authorization.authority.binding.release_refs = selection.contract.release_refs;
  authorization.authority.binding.profile_refs = [selection.registry.registry_ref];
  const reservation = childReservation(); reservation.scope = "run"; reservation.run_id = run.run_id;
  return { id, time: "2026-10-16T08:00:00Z", selection, authorization, boundary, data, budget, reservation, run,
    operation: operationFixture(), conformance: conformanceFixture(), child_authority: null as AuthorityValidationInput | null };
}
function bindWorkflow(f: ReturnType<typeof workflowFixture>) {
  const auth = f.authorization.authority, binding = auth.binding, digest = digestActionBinding(binding);
  f.authorization.constraint_observations.forEach(o => { o.action_digest = digest; o.policy_refs = binding.policy_refs; });
  if (f.authorization.approval) {
    const approval = f.authorization.approval; approval.binding = structuredClone(binding);
    const pins = { proposal_id: binding.proposal_id, run_id: binding.run_id, tenant_id: binding.tenant_id,
      operation_id: binding.operation_id, action_digest: digest, policy_refs: binding.policy_refs, authority_refs: binding.authority_refs };
    Object.assign(approval.proposal, pins); Object.assign(approval.request, pins);
    approval.decisions.forEach(d => { Object.assign(d, pins); });
    approval.entitlements.forEach(e => { e.action_digest = digest; }); refreshApprovalObservations(approval);
  }
  f.data.request.action_digest = digest; f.data.request.operation_id = binding.operation_id;
  f.data.request.purpose_id = binding.purpose_id;
  f.data.policy.allowed_flows.forEach(rule => { rule.purpose_id = binding.purpose_id; });
  const source = binding.evidence_refs[0]; f.data.request.source_artifacts[0].artifact_ref = source;
  f.data.policy.source_observations[0].artifact_ref = source;
  const operation = f.operation, intent = operation.ledger.operations[0].intent;
  Object.assign(intent, { operation_id: binding.operation_id, action_digest: digest,
    capability_ref: fixtureArtifact("capability", binding.capability_id) });
  operation.intent = { ...structuredClone(intent), attempt: { ...operation.intent.attempt, operation_id: binding.operation_id },
    evaluation_time: f.time, provider_observation: null };
  operation.ledger.operations[0].attempts = [structuredClone(operation.intent.attempt)];
  Object.assign(operation.observation, { operation_id: binding.operation_id, action_digest: digest });
  const c = f.conformance; c.contract = structuredClone(f.selection.contract); c.support = structuredClone(f.selection.support);
  c.registry = structuredClone(f.selection.registry); c.features = structuredClone(f.selection.features);
  const negotiated = negotiateExecutionContract(c.contract, c.support, c.registry, c.features);
  c.report.workflow_id = f.id; c.scope.workflow_id = f.id; c.report.profiles = c.contract.profiles;
  c.report.effective_required_controls = negotiated.effective_required_controls; c.report.registry_ref = c.registry.registry_ref;
  c.report.release_refs = c.contract.release_refs; c.scope.release_refs = c.contract.release_refs;
  c.report.control_results = negotiated.effective_required_controls.map(control => ({ control, status: "not_evaluated",
    case_results: [], evidence_refs: [], reason_codes: ["runtime_not_tested"], limitations: ["synthetic_reference_only"] }));
  c.report.utility_results = []; c.report.outcome = "insufficient_evidence"; c.report_verification.evidence_kind = "synthetic";
  c.evidence_observations = []; bindConformanceEvidence(c); return f;
}
export function enterpriseSupportFixture() {
  const f = workflowFixture("enterprise.refund", "contextos.enterprise");
  f.selection.features.external_effects = true; f.selection.features.sensitive_data = true;
  return bindWorkflow(f);
}
export function personalSchedulingFixture() {
  const f = workflowFixture("personal.proactive", "contextos.personal-proactive"), auth = f.authorization.authority;
  const owner = { ...auth.binding.actor, principal_id: "calendar_owner", principal_type: "person" as const };
  auth.authenticated.mandate_kind = "person_directed"; auth.authenticated.mandating_person = owner;
  auth.authenticated.trusted_issuers = [owner]; auth.grants[0].issuer = owner;
  const binding = auth.binding; binding.action_risk.authority = "user_delegated";
  binding.operation_id = "op_schedule"; binding.proposal_id = "proposal_schedule"; binding.purpose_id = "calendar.schedule";
  binding.capability_id = "calendar.create_event"; binding.arguments = { calendar_id: "calendar_owner", start: "2026-10-17T08:00:00Z" };
  binding.resource_ids = ["calendar_owner"]; binding.destination_ids = ["calendar_owner"];
  binding.evidence_refs = [fixtureArtifact("calendar_snapshot", "calendar_owner")]; delete binding.amount;
  Object.assign(auth.grants[0].scope, { purpose_ids: [binding.purpose_id], capability_ids: [binding.capability_id],
    resource_ids: binding.resource_ids, destination_ids: binding.destination_ids,
    argument_constraints: [{ pointer: "/calendar_id", kind: "equals", value: "calendar_owner" }] });
  delete auth.grants[0].scope.amount_ceiling; refreshGrantObservations(auth);
  f.authorization.approval = null; f.authorization.policy_outcomes[0].verdict = "allow";
  f.selection.features.proactive_triggers = true; f.selection.features.external_effects = true;
  f.data.request.destination_id = "calendar_api"; f.data.request.processor_observation.destination_id = "calendar_api";
  f.data.policy.allowed_flows[0].destination_id = "calendar_api";
  return bindWorkflow(f);
}
export function delegatedResearchFixture() {
  const f = workflowFixture("delegated.research", "contextos.durable-delegated"), auth = f.authorization.authority;
  auth.binding.purpose_id = "research.summarize"; auth.binding.capability_id = "research.fetch_source";
  auth.binding.arguments = { source_id: "source_public" }; auth.binding.resource_ids = ["source_public"];
  auth.binding.destination_ids = ["research_workspace"]; auth.binding.action_risk.effect = "none";
  auth.binding.action_risk.reversibility = "read_only"; delete auth.binding.amount;
  Object.assign(auth.grants[0].scope, { purpose_ids: [auth.binding.purpose_id], capability_ids: [auth.binding.capability_id],
    resource_ids: auth.binding.resource_ids, destination_ids: auth.binding.destination_ids,
    argument_constraints: [{ pointer: "/source_id", kind: "equals", value: "source_public" }] });
  delete auth.grants[0].scope.amount_ceiling; refreshGrantObservations(auth);
  f.authorization.approval = null; f.authorization.policy_outcomes[0].verdict = "allow";
  f.boundary = sandboxBoundaryFixture(); Object.assign(f.selection.features, { delegation: true, arbitrary_code: true, external_network: true });
  const child = structuredClone(auth), parent = child.grants[0], grant = structuredClone(parent);
  const worker = { ...parent.subject, principal_id: "research_child" };
  grant.grant_id = "grant_research_child"; grant.subject = worker; grant.issuer = parent.subject;
  grant.parent_grant_ref = { grant_id: parent.grant_id, grant_revision: parent.grant_revision };
  grant.delegation_depth_remaining = 14; grant.verification_ref = fixtureArtifact("authority_grant", grant.grant_id);
  child.grants.push(grant); child.leaf_grant_ref = { grant_id: grant.grant_id, grant_revision: grant.grant_revision };
  child.binding.actor = worker; child.binding.run_id = "run_child_1"; child.authenticated.principal = worker; child.authenticated.run_id = "run_child_1";
  child.run_links = [{ parent_run_id: f.run.run_id, child_run_id: "run_child_1", root_run_id: f.run.run_id, tenant_id: f.run.tenant_id,
    subject: worker, observer: child.authenticated.trusted_observers[0], verification_status: "verified",
    verification_ref: fixtureArtifact("run_link", "research_child"), observed_at: "2026-10-16T07:00:00Z", valid_until: "2026-10-16T09:00:00Z" }];
  refreshGrantObservations(child); f.child_authority = child;
  return bindWorkflow(f);
}
export function lostAcknowledgmentFixture() { const f = enterpriseSupportFixture(); f.id = "effects.lost_ack"; return bindWorkflow(f); }
export function highAssuranceFixture() {
  const f = workflowFixture("high_assurance.release", "contextos.high-assurance");
  f.selection.features.external_effects = true; return bindWorkflow(f);
}
export function workflowEvent(state: RunExecutionState, kind: RunEventKind): RunEvent {
  const observation = { run_id: state.run_id, tenant_id: state.tenant_id, executor_generation: state.executor_generation,
    observer: structuredClone(state.trusted_observer), verification_status: "verified" as const,
    evidence_ref: fixtureArtifact("synthetic_run_observation", kind), observed_at: "2026-10-16T07:59:59Z", valid_until: "2026-10-16T08:05:00Z" };
  return { event_id: `event_${kind}`, run_id: state.run_id, tenant_id: state.tenant_id, kind,
    expected_revision: state.revision, executor_generation: state.executor_generation,
    preconditions: { ...observation, admission_ref: state.admission_ref, checks: { admission: "ready", authority: "ready", boundary: "ready", budget: "ready" } },
    dispatch_stop_ack: { ...observation, child_run_ids: state.child_run_ids, dispatch_stopped: true, children_stop_recorded: true } };
}
