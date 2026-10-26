import { sha256Canonical } from "./canonical-json";
import type { ArtifactRef, ConditionalControlRequirement, ControlDefinition, ControlRef,
  ProfileDefinition, ProfileRegistrySnapshot, ProfileSelection, WorkflowFeatureSet } from "./execution-contract-types";

const control = (control_id: string): ControlRef => ({ control_id, control_version: "1" });
const profile = (profile_id: string): ProfileSelection => ({ profile_id, profile_version: "1" });
const EVIDENCE: [string, string[]][] = [
  ["identity.authenticated", ["Verified principal, workload, trust-domain and tenant binding; reject spoofed or mismatched identity."]],
  ["authority.scoped", ["Current purpose, capability, resource, argument and destination mandate; intersect every delegation ancestor."]],
  ["authority.revocation", ["Bounded-freshness revocation observations from trusted brokers; unknown or unavailable required authority blocks."]],
  ["policy.fail_visible", ["Structured non-success for applicable evaluation errors; explicit business priority and independent guardrail composition."]],
  ["approval.bound", ["Exact stored proposal, action and request binding, expiry, eligible approvers, quorum and controlled redemption.",
    "Policy may permit a standing grant without a per-action click; any required approval still binds exactly."]],
  ["context.integrity", ["Pinned artifact provenance and integrity; untrusted retrieved, tool and message content cannot become trusted instructions."]],
  ["isolation.required", ["Current verified active boundary appropriate to enabled execution, filesystem, process, resource and trust-domain requirements."]],
  ["credentials.brokered", ["Scoped credentials issued and revoked by a trusted broker outside model-visible state; evidence of actual runtime mediation."]],
  ["network.mediated", ["Enforced destination, DNS resolution and redirect restrictions independent of business authority; denied egress evidence."]],
  ["data.flow_policy", ["Purpose, classification, actual recipient, processor and residency checks across inference, tools, telemetry and other flow stages."]],
  ["memory.lifecycle", ["Owned namespace, source provenance, governed promotion, retention and correction/deletion propagation receipts with external-copy limits."]],
  ["effects.reconciled", ["Stable operation identity, provider-specific retry safety and recorded confirmed, partial, not-applied or unknown outcomes."]],
  ["execution.checkpointed", ["Verified artifact pins and current authority/budget checks on resume; bounded recovery, executor ownership and target fencing limitations."]],
  ["delegation.attenuated", ["Child identities, authority intersection and output boundaries; ancestor revocation and cancellation propagation evidence."]],
  ["budget.aggregate", ["Parent/root/child/retry/replan accounting, exact cost units, bounded reservations, verified settlement and inherited absolute deadline."]],
  ["audit.correlated", ["Run, trace, operation, decision and control evidence correlation with minimization, retention and restricted access."]],
  ["release.pinned", ["Versioned evaluated artifact set, admitted extensions, protected changes, rollback limits and release-specific evidence."]],
  ["operations.stop_recover", ["Owned stop, escalation and reconciliation paths; tested dependency failure behavior, cancellation and recovery drills."]],
  ["governance.separation", ["Independent approver and control roles; protected policy and release administration where the workflow requires separation."]],
  ["assurance.fault_evidence", ["Authorized fault and abuse tests, observed recovery results and a release/environment/workflow-specific assurance argument."]],
];
const CONDITIONAL: [keyof WorkflowFeatureSet, string[]][] = [
  ["external_network", ["network.mediated"]], ["persistent_memory", ["memory.lifecycle"]],
  ["external_effects", ["effects.reconciled", "approval.bound"]], ["delegation", ["delegation.attenuated", "budget.aggregate"]],
  ["checkpoint_resume", ["execution.checkpointed"]], ["arbitrary_code", ["isolation.required"]],
  ["sensitive_data", ["data.flow_policy"]],
  ["proactive_triggers", ["authority.revocation", "approval.bound", "budget.aggregate", "operations.stop_recover"]],
];
const MANDATORY: [string, string[]][] = [
  ["contextos.core", ["identity.authenticated", "authority.scoped", "policy.fail_visible", "context.integrity", "audit.correlated"]],
  ["contextos.personal-proactive", ["authority.revocation", "approval.bound", "isolation.required", "credentials.brokered", "data.flow_policy", "budget.aggregate", "operations.stop_recover"]],
  ["contextos.enterprise", ["authority.revocation", "approval.bound", "isolation.required", "credentials.brokered", "data.flow_policy", "budget.aggregate", "release.pinned", "governance.separation", "operations.stop_recover"]],
  ["contextos.durable-delegated", ["authority.revocation", "approval.bound", "isolation.required", "effects.reconciled", "execution.checkpointed", "delegation.attenuated", "budget.aggregate", "operations.stop_recover"]],
  ["contextos.high-assurance", ["assurance.fault_evidence"]],
];
function artifact(artifact_type: string, artifact_id: string, domain: string, payload: unknown): ArtifactRef {
  return { artifact_type, artifact_id, version: "1", sha256: sha256Canonical({ domain, payload }) };
}
function freeze<T>(value: T): T {
  if (value !== null && typeof value === "object") { Object.values(value).forEach(freeze); Object.freeze(value); }
  return value;
}
const controls: ControlDefinition[] = EVIDENCE.map(([id, evidence_obligations]) => {
  const payload = { control: control(id), evidence_obligations, positive_cases: [`${id}.useful`], negative_cases: [`${id}.denied`] };
  return { ...payload, definition_ref: artifact("control_definition", id, "contextos.control_definition.v1", payload) };
});
const profiles: ProfileDefinition[] = MANDATORY.map(([id, required]) => {
  const conditional_controls: ConditionalControlRequirement[] = CONDITIONAL.flatMap(([feature, ids]) => ids.map(id => ({ feature, equals: true, control: control(id) })));
  const payload = { profile: profile(id), includes: id === "contextos.core" ? [] : id === "contextos.high-assurance"
    ? [profile("contextos.core"), profile("contextos.enterprise"), profile("contextos.durable-delegated")] : [profile("contextos.core")],
  mandatory_controls: required.map(control), conditional_controls };
  return { ...payload, definition_ref: artifact("profile_definition", id, "contextos.profile_definition.v1", payload) };
});
/** Immutable obligations only. Support negotiation neither authenticates admission facts nor activates runtime enforcement. */
export const STANDARD_PROFILE_REGISTRY: ProfileRegistrySnapshot = freeze({ profiles, controls,
  registry_ref: artifact("profile_registry", "contextos.standard", "contextos.profile_registry.v1", { profiles, controls }) });
