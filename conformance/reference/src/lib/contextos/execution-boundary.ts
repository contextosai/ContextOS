import path from "node:path";
import { canonicalizeJson, sha256Canonical } from "./canonical-json";
import { hasExactKeys, isArtifactRef, isContractIdentifier, isControlRef, isContractTimestamp,
  isWithinContractInterval, compareContractTimes } from "./contract-validation";
import type { ArtifactRef, ControlRef } from "./execution-contract-types";
import type { PrincipalRef, VerificationStatus } from "./authorization";

export type IsolationMode = "broker_only" | "sandboxed_code" | "dedicated_environment";
export interface FilesystemGrant { root: string; path_format: "posix" | "windows"; access: "read" | "read_write" }
export interface NetworkGrant { origin: string }
export interface ProcessRestrictions { run_as: string; allow_privileged: boolean; allow_child_processes: boolean }
export interface BoundaryResourceCeilings { cpu_ms: number; memory_bytes: number; pids: number;
  wall_clock_ms: number; output_bytes: number; scratch_bytes: number }
export interface ExecutionBoundaryRequirement {
  contract_id: string; run_id: string; tenant_id: string; boundary_id: string; isolation_mode: IsolationMode;
  configuration_ref: ArtifactRef; trust_domain: string; required_controls: ControlRef[];
  filesystem_grants: FilesystemGrant[]; process_restrictions: ProcessRestrictions; network_grants: NetworkGrant[];
  resource_ceilings: BoundaryResourceCeilings; credential_broker_ref: ArtifactRef;
  trusted_observer: PrincipalRef; maximum_observation_age_seconds: number;
}
export interface ExecutionBoundaryObservation {
  contract_id: string; run_id: string; tenant_id: string; boundary_id: string; isolation_mode: IsolationMode;
  actual_configuration_sha256: string; trust_domain: string; active_controls: ControlRef[]; failed_controls: ControlRef[];
  observer: PrincipalRef; verification_status: VerificationStatus; evidence_ref: ArtifactRef;
  observed_at: string; valid_until: string; lifecycle_state: "ready" | "unavailable" | "terminated";
  enforcement: { filesystem: boolean; process: boolean; network: boolean; resources: boolean; credentials: boolean };
}
export interface BoundaryReadinessResult {
  allowed: boolean; reason_codes: string[]; boundary_id: string; evaluation_time: string;
  configuration_ref: ArtifactRef | null; evidence_ref: ArtifactRef | null; unsatisfied_obligations: string[];
}

const integer = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) >= 0;
const list = <T>(value: unknown, guard: (item: unknown) => item is T): value is T[] =>
  Array.isArray(value) && value.length <= 128 && value.every(guard);
const sameControlRef = (a: ControlRef, b: ControlRef) => a.control_id === b.control_id && a.control_version === b.control_version;
const mode = (value: unknown): value is IsolationMode => ["broker_only", "sandboxed_code", "dedicated_environment"].includes(value as string);
function principal(value: unknown): value is PrincipalRef {
  return hasExactKeys(value, ["principal_id", "principal_type", "trust_domain", "tenant_id"])
    && [value.principal_id, value.trust_domain, value.tenant_id].every(isContractIdentifier)
    && ["person", "workload", "agent"].includes(value.principal_type as string);
}
function filesystem(value: unknown): value is FilesystemGrant {
  if (!hasExactKeys(value, ["root", "path_format", "access"]) || typeof value.root !== "string"
    || value.root.length === 0 || value.root.length > 4096 || /[\0*]/u.test(value.root)
    || !["read", "read_write"].includes(value.access as string)) return false;
  const dialect = value.path_format === "posix" ? path.posix : value.path_format === "windows" ? path.win32 : undefined;
  return !!dialect && dialect.isAbsolute(value.root) && dialect.normalize(value.root) === value.root;
}
function network(value: unknown): value is NetworkGrant {
  if (!hasExactKeys(value, ["origin"]) || !isContractIdentifier(value.origin) || value.origin.includes("*")) return false;
  try {
    const url = new URL(value.origin);
    return ["https:", "http:", "wss:", "ws:"].includes(url.protocol) && !url.username && !url.password
      && url.origin === value.origin && url.pathname === "/" && !url.search && !url.hash;
  } catch { return false; }
}
function resources(value: unknown): value is BoundaryResourceCeilings {
  return hasExactKeys(value, ["cpu_ms", "memory_bytes", "pids", "wall_clock_ms", "output_bytes", "scratch_bytes"])
    && Object.values(value).every(integer) && (value.cpu_ms as number) > 0 && (value.memory_bytes as number) > 0
    && (value.pids as number) > 0 && (value.wall_clock_ms as number) > 0;
}
function requirement(value: unknown): value is ExecutionBoundaryRequirement {
  return hasExactKeys(value, ["contract_id", "run_id", "tenant_id", "boundary_id", "isolation_mode", "configuration_ref",
    "trust_domain", "required_controls", "filesystem_grants", "process_restrictions", "network_grants", "resource_ceilings",
    "credential_broker_ref", "trusted_observer", "maximum_observation_age_seconds"])
    && [value.contract_id, value.run_id, value.tenant_id, value.boundary_id, value.trust_domain].every(isContractIdentifier)
    && mode(value.isolation_mode) && isArtifactRef(value.configuration_ref) && isArtifactRef(value.credential_broker_ref)
    && list(value.required_controls, isControlRef) && value.required_controls.some(c => c.control_id === "isolation.required" && c.control_version === "1")
    && list(value.filesystem_grants, filesystem) && list(value.network_grants, network) && resources(value.resource_ceilings)
    && principal(value.trusted_observer) && integer(value.maximum_observation_age_seconds)
    && hasExactKeys(value.process_restrictions, ["run_as", "allow_privileged", "allow_child_processes"])
    && isContractIdentifier(value.process_restrictions.run_as) && typeof value.process_restrictions.allow_privileged === "boolean"
    && typeof value.process_restrictions.allow_child_processes === "boolean";
}
function observation(value: unknown): value is ExecutionBoundaryObservation {
  return hasExactKeys(value, ["contract_id", "run_id", "tenant_id", "boundary_id", "isolation_mode", "actual_configuration_sha256",
    "trust_domain", "active_controls", "failed_controls", "observer", "verification_status", "evidence_ref", "observed_at",
    "valid_until", "lifecycle_state", "enforcement"])
    && [value.contract_id, value.run_id, value.tenant_id, value.boundary_id, value.trust_domain].every(isContractIdentifier)
    && mode(value.isolation_mode) && typeof value.actual_configuration_sha256 === "string" && /^sha256:[a-f0-9]{64}$/.test(value.actual_configuration_sha256)
    && list(value.active_controls, isControlRef) && list(value.failed_controls, isControlRef) && principal(value.observer)
    && ["verified", "invalid", "unavailable"].includes(value.verification_status as string) && isArtifactRef(value.evidence_ref)
    && isContractTimestamp(value.observed_at) && isContractTimestamp(value.valid_until)
    && ["ready", "unavailable", "terminated"].includes(value.lifecycle_state as string)
    && hasExactKeys(value.enforcement, ["filesystem", "process", "network", "resources", "credentials"])
    && Object.values(value.enforcement).every(flag => typeof flag === "boolean");
}
/** Full calendar syntax is checked by the shared core validator before this exact elapsed-time calculation. */
function ageWithinLimit(time: string, observed: string, maximumSeconds: number): boolean {
  if (!isContractTimestamp(time) || !isContractTimestamp(observed) || !integer(maximumSeconds)) return false;
  const fraction = (value: string) => value.length > 20 ? value.slice(20, -1) : "";
  const a = fraction(time), b = fraction(observed), precision = Math.max(a.length, b.length);
  const scale = BigInt(10) ** BigInt(precision);
  // Parse only validated whole UTC seconds; retain all fractional digits separately.
  const whole = BigInt((Date.parse(`${time.slice(0, 19)}Z`) - Date.parse(`${observed.slice(0, 19)}Z`)) / 1000);
  const elapsed = whole * scale + BigInt(a.padEnd(precision, "0") || "0") - BigInt(b.padEnd(precision, "0") || "0");
  return elapsed >= BigInt(0) && elapsed <= BigInt(maximumSeconds) * scale;
}

/** Checks already verified normalized observations; does not provision or inspect an execution environment. */
export function evaluateBoundaryReadiness(required: ExecutionBoundaryRequirement,
  observed: ExecutionBoundaryObservation | null, evaluationTime: string): BoundaryReadinessResult {
  const reasons = new Set<string>(), obligations = new Set<string>();
  let boundaryId = "invalid", configurationRef: ArtifactRef | null = null, evidenceRef: ArtifactRef | null = null;
  const finish = (): BoundaryReadinessResult => ({ allowed: reasons.size === 0, reason_codes: [...reasons].sort(),
    boundary_id: boundaryId, evaluation_time: isContractTimestamp(evaluationTime) ? evaluationTime : "invalid",
    configuration_ref: configurationRef, evidence_ref: evidenceRef, unsatisfied_obligations: [...obligations].sort() });
  try { canonicalizeJson(required); canonicalizeJson(observed); } catch { reasons.add("configuration_invalid"); return finish(); }
  const resourcePolicyValid = required && typeof required === "object" && resources(required.resource_ceilings)
    && integer(required.maximum_observation_age_seconds);
  if (!requirement(required)) {
    reasons.add("configuration_invalid");
    if (!resourcePolicyValid) reasons.add("resource_limit_invalid");
    return finish();
  }
  boundaryId = required.boundary_id; configurationRef = { ...required.configuration_ref };
  if (!observed) { reasons.add("boundary_unavailable"); return finish(); }
  if (!observation(observed)) { reasons.add("observation_unverified"); return finish(); }
  evidenceRef = { ...observed.evidence_ref };
  if (["contract_id", "run_id", "tenant_id", "boundary_id", "isolation_mode"].some(key =>
    required[key as keyof ExecutionBoundaryRequirement] !== observed[key as keyof ExecutionBoundaryObservation])) reasons.add("boundary_binding_mismatch");
  if (observed.actual_configuration_sha256 !== required.configuration_ref.sha256) reasons.add("configuration_mismatch");
  if (observed.trust_domain !== required.trust_domain) reasons.add("trust_domain_mismatch");
  if (observed.verification_status !== "verified" || observed.observer.tenant_id !== required.tenant_id
    || canonicalizeJson(observed.observer) !== canonicalizeJson(required.trusted_observer)) reasons.add("observation_unverified");
  if (observed.lifecycle_state === "terminated") reasons.add("boundary_terminated");
  if (observed.lifecycle_state === "unavailable") reasons.add("boundary_unavailable");
  if (!isWithinContractInterval(evaluationTime, observed.observed_at, observed.valid_until)
    || !ageWithinLimit(evaluationTime, observed.observed_at, required.maximum_observation_age_seconds)) reasons.add("observation_stale");
  const revisions = new Map<string, string>();
  for (const control of required.required_controls) {
    if (revisions.has(control.control_id) && revisions.get(control.control_id) !== control.control_version) reasons.add("configuration_invalid");
    revisions.set(control.control_id, control.control_version);
    if (!observed.active_controls.some(active => sameControlRef(active, control))) {
      reasons.add("required_control_inactive"); obligations.add(`${control.control_id}@${control.control_version}`);
    }
  }
  for (const failed of observed.failed_controls) {
    reasons.add("required_control_inactive"); obligations.add(`${failed.control_id}@${failed.control_version}`);
  }
  const codeMode = required.isolation_mode !== "broker_only";
  const applicable = { filesystem: codeMode || required.filesystem_grants.length > 0,
    process: codeMode || required.process_restrictions.allow_child_processes || required.process_restrictions.allow_privileged,
    network: true, resources: true, credentials: true };
  for (const dimension of Object.keys(applicable) as (keyof typeof applicable)[]) {
    if (applicable[dimension] && !observed.enforcement[dimension]) {
      reasons.add("required_control_inactive"); obligations.add(`${dimension}_enforcement`);
    }
  }
  return finish();
}

export type DataFlowStage = "collection" | "inference" | "tool_input" | "tool_output" | "telemetry" | "cache" | "memory" | "export" | "delegation";
interface VerifiedDataObservation {
  verification_status: VerificationStatus; observer: PrincipalRef; evidence_ref: ArtifactRef;
  observed_at: string; valid_until: string;
}
export interface SourceClassificationObservation extends VerifiedDataObservation {
  artifact_ref: ArtifactRef; classification: string; tenant_id: string; trust_domain: string;
}
export interface ProcessorObservation extends VerifiedDataObservation {
  contract_id: string; run_id: string; tenant_id: string; processor_id: string;
  destination_id: string; destination_tenant_id: string; destination_trust_domain: string; residency_region: string;
}
export interface DataTransformationObservation extends VerifiedDataObservation {
  transformation_id: string; source_refs: ArtifactRef[]; result_ref: ArtifactRef; result_classification: string;
  policy_ref: ArtifactRef; purpose_id: string; destination_id: string; release_status: "approved" | "denied" | "unknown";
  approval_ref: ArtifactRef; destination_tenant_id: string; destination_trust_domain: string;
  operation_id: string; action_digest: string; processor_id: string; stage: DataFlowStage;
}
export interface DataFlowRequest {
  contract_id: string; run_id: string; tenant_id: string; operation_id: string; action_digest: string; policy_ref: ArtifactRef;
  source_artifacts: { artifact_ref: ArtifactRef; classification: string }[]; source_trust_domain: string;
  destination_tenant_id: string; destination_trust_domain: string; destination_id: string; purpose_id: string;
  stage: DataFlowStage; requested_classification: string; processor_id: string;
  processor_observation: ProcessorObservation; transformation: DataTransformationObservation | null;
}
export interface DataFlowRule {
  source_trust_domain: string; destination_trust_domain: string; destination_tenant_id: string; destination_id: string;
  purpose_id: string; stages: DataFlowStage[]; source_classifications: string[]; destination_classifications: string[];
  processor_ids: string[]; residency_regions: string[]; transformation_ids: string[];
}
/** A pinned policy and normalized broker observations; never accept this snapshot from model output. */
export interface DataFlowPolicySnapshot {
  policy_ref: ArtifactRef; contract_id: string; run_id: string; tenant_id: string; not_before: string; expires_at: string;
  known_classifications: string[]; label_combinations: { inputs: string[]; output: string }[];
  maximum_observation_age_seconds: number; trusted_observers: PrincipalRef[];
  source_observations: SourceClassificationObservation[]; allowed_flows: DataFlowRule[];
}
export interface DataFlowDecision {
  allowed: boolean; reason_codes: string[]; evaluation_time: string; policy_ref: ArtifactRef | null;
  artifact_refs: ArtifactRef[]; classification: string | null; unsatisfied_obligations: string[];
  contract_id: string | null; run_id: string | null; operation_id: string | null; action_digest: string | null;
  propagation_status?: MemoryPropagationState;
  completion_verified?: boolean;
}

const STAGES: readonly DataFlowStage[] = ["collection", "inference", "tool_input", "tool_output", "telemetry", "cache", "memory", "export", "delegation"];
const stage = (value: unknown): value is DataFlowStage => STAGES.includes(value as DataFlowStage);
const strings = (value: unknown): value is string[] => list(value, isContractIdentifier);
const artifactRefs = (value: unknown): value is ArtifactRef[] => list(value, isArtifactRef);
const OBSERVATION_KEYS = ["verification_status", "observer", "evidence_ref", "observed_at", "valid_until"];
const identical = (left: unknown, right: unknown) => canonicalizeJson(left) === canonicalizeJson(right);
function observationFields(value: Record<string, unknown>): boolean {
  return ["verified", "invalid", "unavailable"].includes(value.verification_status as string) && principal(value.observer)
    && isArtifactRef(value.evidence_ref) && isContractTimestamp(value.observed_at) && isContractTimestamp(value.valid_until);
}
function sourceObservation(value: unknown): value is SourceClassificationObservation {
  return hasExactKeys(value, [...OBSERVATION_KEYS, "artifact_ref", "classification", "tenant_id", "trust_domain"])
    && observationFields(value) && isArtifactRef(value.artifact_ref)
    && [value.classification, value.tenant_id, value.trust_domain].every(isContractIdentifier);
}
function processorObservation(value: unknown): value is ProcessorObservation {
  return hasExactKeys(value, [...OBSERVATION_KEYS, "contract_id", "run_id", "tenant_id", "processor_id", "destination_id",
    "destination_tenant_id", "destination_trust_domain", "residency_region"]) && observationFields(value)
    && [value.contract_id, value.run_id, value.tenant_id, value.processor_id, value.destination_id,
      value.destination_tenant_id, value.destination_trust_domain, value.residency_region].every(isContractIdentifier);
}
function transformationObservation(value: unknown): value is DataTransformationObservation {
  return hasExactKeys(value, [...OBSERVATION_KEYS, "transformation_id", "source_refs", "result_ref", "result_classification",
    "policy_ref", "purpose_id", "destination_id", "release_status", "approval_ref", "destination_tenant_id", "destination_trust_domain",
    "operation_id", "action_digest", "processor_id", "stage"]) && observationFields(value)
    && [value.transformation_id, value.result_classification, value.purpose_id, value.destination_id, value.destination_tenant_id,
      value.destination_trust_domain, value.operation_id, value.processor_id].every(isContractIdentifier)
    && typeof value.action_digest === "string" && /^sha256:[a-f0-9]{64}$/.test(value.action_digest) && stage(value.stage)
    && artifactRefs(value.source_refs) && value.source_refs.length > 0 && isArtifactRef(value.result_ref)
    && isArtifactRef(value.policy_ref) && isArtifactRef(value.approval_ref)
    && ["approved", "denied", "unknown"].includes(value.release_status as string);
}
function flowRequest(value: unknown): value is DataFlowRequest {
  return hasExactKeys(value, ["contract_id", "run_id", "tenant_id", "operation_id", "action_digest", "policy_ref", "source_artifacts",
    "source_trust_domain", "destination_tenant_id", "destination_trust_domain", "destination_id", "purpose_id", "stage",
    "requested_classification", "processor_id", "processor_observation", "transformation"])
    && [value.contract_id, value.run_id, value.tenant_id, value.operation_id, value.source_trust_domain,
      value.destination_tenant_id, value.destination_trust_domain, value.destination_id, value.purpose_id,
      value.requested_classification, value.processor_id].every(isContractIdentifier)
    && typeof value.action_digest === "string" && /^sha256:[a-f0-9]{64}$/.test(value.action_digest) && isArtifactRef(value.policy_ref)
    && list(value.source_artifacts, (item): item is DataFlowRequest["source_artifacts"][number] =>
      hasExactKeys(item, ["artifact_ref", "classification"]) && isArtifactRef(item.artifact_ref) && isContractIdentifier(item.classification))
    && value.source_artifacts.length > 0 && stage(value.stage) && processorObservation(value.processor_observation)
    && (value.transformation === null || transformationObservation(value.transformation));
}
function flowRule(value: unknown): value is DataFlowRule {
  return hasExactKeys(value, ["source_trust_domain", "destination_trust_domain", "destination_tenant_id", "destination_id", "purpose_id",
    "stages", "source_classifications", "destination_classifications", "processor_ids", "residency_regions", "transformation_ids"])
    && [value.source_trust_domain, value.destination_trust_domain, value.destination_tenant_id, value.destination_id,
      value.purpose_id].every(isContractIdentifier) && list(value.stages, stage)
    && [value.source_classifications, value.destination_classifications, value.processor_ids,
      value.residency_regions, value.transformation_ids].every(strings);
}
function flowPolicy(value: unknown): value is DataFlowPolicySnapshot {
  return hasExactKeys(value, ["policy_ref", "contract_id", "run_id", "tenant_id", "not_before", "expires_at", "known_classifications",
    "label_combinations", "maximum_observation_age_seconds", "trusted_observers", "source_observations", "allowed_flows"])
    && isArtifactRef(value.policy_ref) && [value.contract_id, value.run_id, value.tenant_id].every(isContractIdentifier)
    && isContractTimestamp(value.not_before) && isContractTimestamp(value.expires_at) && strings(value.known_classifications)
    && value.known_classifications.length > 0 && new Set(value.known_classifications).size === value.known_classifications.length
    && integer(value.maximum_observation_age_seconds) && list(value.trusted_observers, principal)
    && list(value.source_observations, sourceObservation) && list(value.allowed_flows, flowRule)
    && list(value.label_combinations, (entry): entry is DataFlowPolicySnapshot["label_combinations"][number] =>
      hasExactKeys(entry, ["inputs", "output"]) && strings(entry.inputs) && entry.inputs.length > 0 && isContractIdentifier(entry.output));
}
function sameArtifactRefs(left: ArtifactRef[], right: ArtifactRef[]): boolean {
  const a = new Set(left.map(ref => canonicalizeJson(ref))), b = new Set(right.map(ref => canonicalizeJson(ref)));
  return a.size === left.length && b.size === right.length && a.size === b.size && [...a].every(key => b.has(key));
}

/** Applies a trusted finite data policy at all stages; no network, broker verification or transformation is performed. */
export function evaluateDataFlow(request: DataFlowRequest, policy: DataFlowPolicySnapshot, evaluationTime: string): DataFlowDecision {
  const reasons = new Set<string>();
  let policyRef: ArtifactRef | null = null, classification: string | null = null, artifacts: ArtifactRef[] = [];
  let correlation: Pick<DataFlowDecision, "contract_id" | "run_id" | "operation_id" | "action_digest"> = {
    contract_id: null, run_id: null, operation_id: null, action_digest: null };
  const finish = (): DataFlowDecision => ({ allowed: reasons.size === 0, reason_codes: [...reasons].sort(),
    evaluation_time: isContractTimestamp(evaluationTime) ? evaluationTime : "invalid", policy_ref: policyRef,
    artifact_refs: artifacts.map(ref => ({ ...ref })), classification,
    unsatisfied_obligations: [...reasons].sort(), ...correlation });
  try { canonicalizeJson(policy); canonicalizeJson(request); } catch { reasons.add("policy_unavailable"); return finish(); }
  if (!flowPolicy(policy)) { reasons.add("policy_unavailable"); return finish(); }
  policyRef = { ...policy.policy_ref };
  if (!flowRequest(request)) { reasons.add("data_flow_invalid"); return finish(); }
  correlation = { contract_id: request.contract_id, run_id: request.run_id, operation_id: request.operation_id, action_digest: request.action_digest };
  if (!identical(request.policy_ref, policy.policy_ref) || !isWithinContractInterval(evaluationTime, policy.not_before, policy.expires_at)) reasons.add("policy_unavailable");
  if (request.contract_id !== policy.contract_id || request.run_id !== policy.run_id || request.tenant_id !== policy.tenant_id) reasons.add("tenant_mismatch");
  const knownLabels = new Set(policy.known_classifications);
  const validLabels = (labels: string[]) => labels.every(label => knownLabels.has(label));
  const combinationKeys = new Set<string>();
  for (const combination of policy.label_combinations) {
    const key = canonicalizeJson([...new Set(combination.inputs)].sort());
    if (combinationKeys.has(key) || !validLabels([...combination.inputs, combination.output])) reasons.add("policy_unavailable");
    combinationKeys.add(key);
  }
  if (policy.allowed_flows.some(rule => !validLabels([...rule.source_classifications, ...rule.destination_classifications]))) reasons.add("policy_unavailable");
  const current = (observed: VerifiedDataObservation) => observed.verification_status === "verified"
    && observed.observer.tenant_id === policy.tenant_id && policy.trusted_observers.some(trusted => identical(trusted, observed.observer))
    && isWithinContractInterval(evaluationTime, observed.observed_at, observed.valid_until)
    && ageWithinLimit(evaluationTime, observed.observed_at, policy.maximum_observation_age_seconds);
  const labels = new Set<string>();
  const sourceRefs = request.source_artifacts.map(source => source.artifact_ref);
  if (new Set(sourceRefs.map(ref => canonicalizeJson(ref))).size !== sourceRefs.length) reasons.add("classification_denied");
  for (const source of request.source_artifacts) {
    if (!knownLabels.has(source.classification)) reasons.add("classification_unknown");
    const matches = policy.source_observations.filter(observed => identical(observed.artifact_ref, source.artifact_ref));
    const observed = matches[0];
    if (matches.length !== 1 || !observed || !current(observed) || observed.tenant_id !== request.tenant_id
      || observed.trust_domain !== request.source_trust_domain || observed.classification !== source.classification) {
      reasons.add("classification_denied");
    }
    if (observed) { labels.add(observed.classification); if (!knownLabels.has(observed.classification)) reasons.add("classification_unknown"); }
  }
  const inputLabels = [...labels].sort();
  if (inputLabels.length === 1) classification = inputLabels[0];
  else {
    const combination = policy.label_combinations.find(rule => identical([...new Set(rule.inputs)].sort(), inputLabels));
    if (combination) classification = combination.output; else reasons.add("classification_denied");
  }
  if (!knownLabels.has(request.requested_classification)) reasons.add("classification_unknown");
  let candidates = policy.allowed_flows.filter(rule => rule.source_trust_domain === request.source_trust_domain
    && rule.destination_tenant_id === request.destination_tenant_id && rule.destination_trust_domain === request.destination_trust_domain
    && rule.destination_id === request.destination_id);
  if (!candidates.length) reasons.add("destination_denied");
  candidates = candidates.filter(rule => rule.purpose_id === request.purpose_id);
  if (!candidates.length) reasons.add("purpose_denied");
  candidates = candidates.filter(rule => rule.stages.includes(request.stage));
  if (!candidates.length) reasons.add("processing_stage_denied");
  candidates = candidates.filter(rule => classification !== null && rule.source_classifications.includes(classification)
    && rule.destination_classifications.includes(request.requested_classification));
  if (!candidates.length) reasons.add("classification_denied");
  const processor = request.processor_observation;
  if (!current(processor) || processor.contract_id !== request.contract_id || processor.run_id !== request.run_id
    || processor.tenant_id !== request.tenant_id || processor.processor_id !== request.processor_id
    || processor.destination_id !== request.destination_id || processor.destination_tenant_id !== request.destination_tenant_id
    || processor.destination_trust_domain !== request.destination_trust_domain) reasons.add("residency_unverified");
  candidates = candidates.filter(rule => rule.processor_ids.includes(processor.processor_id) && rule.residency_regions.includes(processor.residency_region));
  if (!candidates.length) reasons.add("residency_unverified");
  const transformation = request.transformation;
  if (transformation) {
    if (!current(transformation) || transformation.release_status !== "approved" || !identical(transformation.policy_ref, policy.policy_ref)
      || transformation.result_classification !== request.requested_classification || transformation.purpose_id !== request.purpose_id
      || transformation.destination_id !== request.destination_id || !sameArtifactRefs(transformation.source_refs, sourceRefs)
      || transformation.destination_tenant_id !== request.destination_tenant_id || transformation.destination_trust_domain !== request.destination_trust_domain
      || transformation.operation_id !== request.operation_id || transformation.action_digest !== request.action_digest
      || transformation.processor_id !== request.processor_id || transformation.stage !== request.stage
      || sourceRefs.some(ref => identical(ref, transformation.result_ref))
      || !candidates.some(rule => rule.transformation_ids.includes(transformation.transformation_id))) reasons.add("transformation_unverified");
    if (!reasons.size) { classification = transformation.result_classification; artifacts = [transformation.result_ref]; }
  } else if (classification !== request.requested_classification) reasons.add("transformation_unverified");
  if (!transformation && !reasons.size) artifacts = sourceRefs;
  return finish();
}

export type MemoryLifecycleOperation = "propose" | "promote" | "correct" | "delete";
export type MemoryPropagationState = "pending" | "confirmed" | "failed" | "external_unknown";
export interface MemoryReviewObservation extends VerifiedDataObservation { record_digest: string; decision: "approved" | "denied" }
export interface MemoryPropagationObservation extends VerifiedDataObservation {
  artifact_ref: ArtifactRef; status: MemoryPropagationState; record_id: string; operation_id: string; record_digest: string;
}
export interface MemoryAccessObservation extends VerifiedDataObservation { tenant_id: string; owner_id: string; namespace: string; purpose_id: string }
export interface MemoryLifecycleRecord {
  record_id: string; memory_ref: ArtifactRef; contract_id: string; run_id: string; operation_id: string; action_digest: string;
  tenant_id: string; owner_id: string; namespace: string; purpose_id: string; source_refs: ArtifactRef[]; readers: string[];
  operation: MemoryLifecycleOperation; policy_ref: ArtifactRef; retention_expires_at: string; review: MemoryReviewObservation | null;
  derived_copy_refs: ArtifactRef[]; propagation_entries: MemoryPropagationObservation[]; propagation_status: MemoryPropagationState;
}
/** Authenticated namespace/purpose context from the memory authority adapter and pinned policy. */
export interface MemoryLifecycleContext {
  tenant_id: string; owner_id: string; namespace: string; purpose_id: string; allowed_readers: string[];
  allowed_operations: MemoryLifecycleOperation[]; requires_review: MemoryLifecycleOperation[];
  maximum_retention_expires_at: string; retention_exception: "none" | "requires_escalation";
  trusted_observers: PrincipalRef[]; access_observation: MemoryAccessObservation;
  data_flow_request: DataFlowRequest; data_policy: DataFlowPolicySnapshot;
  known_derived_copy_refs: ArtifactRef[]; derived_inventory_status: "verified_complete" | "incomplete" | "external_unknown";
}
const memoryOperation = (value: unknown): value is MemoryLifecycleOperation => ["propose", "promote", "correct", "delete"].includes(value as string);
const propagationState = (value: unknown): value is MemoryPropagationState => ["pending", "confirmed", "failed", "external_unknown"].includes(value as string);
function memoryReview(value: unknown): value is MemoryReviewObservation {
  return hasExactKeys(value, [...OBSERVATION_KEYS, "record_digest", "decision"]) && observationFields(value)
    && typeof value.record_digest === "string" && /^sha256:[a-f0-9]{64}$/.test(value.record_digest)
    && (value.decision === "approved" || value.decision === "denied");
}
function propagationObservation(value: unknown): value is MemoryPropagationObservation {
  return hasExactKeys(value, [...OBSERVATION_KEYS, "artifact_ref", "status", "record_id", "operation_id", "record_digest"])
    && observationFields(value) && isArtifactRef(value.artifact_ref) && propagationState(value.status)
    && isContractIdentifier(value.record_id) && isContractIdentifier(value.operation_id)
    && typeof value.record_digest === "string" && /^sha256:[a-f0-9]{64}$/.test(value.record_digest);
}
function memoryAccess(value: unknown): value is MemoryAccessObservation {
  return hasExactKeys(value, [...OBSERVATION_KEYS, "tenant_id", "owner_id", "namespace", "purpose_id"])
    && observationFields(value) && [value.tenant_id, value.owner_id, value.namespace, value.purpose_id].every(isContractIdentifier);
}
function memoryRecord(value: unknown): value is MemoryLifecycleRecord {
  return hasExactKeys(value, ["record_id", "memory_ref", "contract_id", "run_id", "operation_id", "action_digest", "tenant_id", "owner_id",
    "namespace", "purpose_id", "source_refs", "readers", "operation", "policy_ref", "retention_expires_at", "review", "derived_copy_refs",
    "propagation_entries", "propagation_status"])
    && [value.record_id, value.contract_id, value.run_id, value.operation_id, value.tenant_id, value.owner_id,
      value.namespace, value.purpose_id].every(isContractIdentifier) && isArtifactRef(value.memory_ref)
    && typeof value.action_digest === "string" && /^sha256:[a-f0-9]{64}$/.test(value.action_digest)
    && artifactRefs(value.source_refs) && value.source_refs.length > 0 && strings(value.readers) && memoryOperation(value.operation)
    && isArtifactRef(value.policy_ref) && isContractTimestamp(value.retention_expires_at)
    && (value.review === null || memoryReview(value.review)) && artifactRefs(value.derived_copy_refs)
    && Array.isArray(value.propagation_entries) && value.propagation_entries.length <= 129
    && value.propagation_entries.every(propagationObservation) && propagationState(value.propagation_status);
}
function memoryContext(value: unknown): value is MemoryLifecycleContext {
  return hasExactKeys(value, ["tenant_id", "owner_id", "namespace", "purpose_id", "allowed_readers", "allowed_operations", "requires_review",
    "maximum_retention_expires_at", "retention_exception", "trusted_observers", "access_observation", "data_flow_request", "data_policy",
    "known_derived_copy_refs", "derived_inventory_status"])
    && [value.tenant_id, value.owner_id, value.namespace, value.purpose_id].every(isContractIdentifier) && strings(value.allowed_readers)
    && list(value.allowed_operations, memoryOperation) && list(value.requires_review, memoryOperation)
    && isContractTimestamp(value.maximum_retention_expires_at) && ["none", "requires_escalation"].includes(value.retention_exception as string)
    && list(value.trusted_observers, principal) && memoryAccess(value.access_observation)
    && flowRequest(value.data_flow_request) && flowPolicy(value.data_policy) && artifactRefs(value.known_derived_copy_refs)
    && ["verified_complete", "incomplete", "external_unknown"].includes(value.derived_inventory_status as string);
}

/** Record-level authority/truthfulness checks. Does not write, erase, scan copies or establish broker authenticity. */
export function validateMemoryLifecycle(record: MemoryLifecycleRecord, context: MemoryLifecycleContext, evaluationTime: string): DataFlowDecision {
  const invalid = (): DataFlowDecision => ({ allowed: false, reason_codes: ["memory_record_invalid"],
    evaluation_time: isContractTimestamp(evaluationTime) ? evaluationTime : "invalid", policy_ref: null, artifact_refs: [],
    classification: null, unsatisfied_obligations: ["memory_record_invalid"], contract_id: null, run_id: null,
    operation_id: null, action_digest: null, propagation_status: "pending", completion_verified: false });
  try { canonicalizeJson(record); canonicalizeJson(context); } catch { return invalid(); }
  if (!memoryRecord(record) || !memoryContext(context)) return invalid();
  const flow = evaluateDataFlow(context.data_flow_request, context.data_policy, evaluationTime);
  const reasons = new Set(flow.reason_codes), request = context.data_flow_request;
  if (["tenant_id", "owner_id", "namespace", "purpose_id"].some(key => record[key as keyof MemoryLifecycleRecord]
    !== context[key as keyof MemoryLifecycleContext])) reasons.add("memory_scope_mismatch");
  if (record.contract_id !== request.contract_id || record.run_id !== request.run_id || record.operation_id !== request.operation_id
    || record.action_digest !== request.action_digest || request.stage !== "memory" || request.destination_id !== `memory:${record.namespace}`
    || request.purpose_id !== record.purpose_id || request.destination_tenant_id !== record.tenant_id
    || request.tenant_id !== record.tenant_id || !identical(record.policy_ref, context.data_policy.policy_ref)
    || !sameArtifactRefs(record.source_refs, request.source_artifacts.map(source => source.artifact_ref))) reasons.add("memory_scope_mismatch");
  if (!context.allowed_operations.includes(record.operation) || record.readers.some(reader => !context.allowed_readers.includes(reader))) reasons.add("memory_scope_mismatch");
  const current = (observed: VerifiedDataObservation) => observed.verification_status === "verified"
    && observed.observer.tenant_id === context.tenant_id && context.trusted_observers.some(observer => identical(observer, observed.observer))
    && isWithinContractInterval(evaluationTime, observed.observed_at, observed.valid_until)
    && ageWithinLimit(evaluationTime, observed.observed_at, context.data_policy.maximum_observation_age_seconds);
  const access = context.access_observation;
  if (!current(access) || access.tenant_id !== record.tenant_id || access.owner_id !== record.owner_id
    || access.namespace !== record.namespace || access.purpose_id !== record.purpose_id) reasons.add("memory_access_unverified");
  if (context.retention_exception === "requires_escalation") reasons.add("retention_escalation_required");
  if (record.operation !== "delete" && (compareContractTimes(evaluationTime, record.retention_expires_at) !== -1
    || compareContractTimes(record.retention_expires_at, context.maximum_retention_expires_at) === 1)) reasons.add("memory_retention_invalid");
  const { review, propagation_entries: ignoredEntries, propagation_status: ignoredStatus, ...intent } = record;
  void ignoredEntries; void ignoredStatus;
  const intentDigest = sha256Canonical({ domain: "contextos.memory_lifecycle_intent.v1", intent });
  if ((context.requires_review.includes(record.operation) && !review) || (review && (!current(review) || review.decision !== "approved"
    || review.record_digest !== intentDigest))) reasons.add("memory_review_unverified");
  if (!sameArtifactRefs(record.derived_copy_refs, context.known_derived_copy_refs)) reasons.add("memory_copy_tracking_invalid");
  const targets = [record.memory_ref, ...record.derived_copy_refs], targetKeys = new Set(targets.map(ref => canonicalizeJson(ref)));
  if (targetKeys.size !== targets.length) reasons.add("memory_copy_tracking_invalid");
  const currentEntry = (entry: MemoryPropagationObservation) => current(entry) && entry.record_id === record.record_id
    && entry.operation_id === record.operation_id && entry.record_digest === intentDigest;
  const entries = new Map<string, MemoryPropagationObservation>();
  for (const entry of record.propagation_entries) {
    const key = canonicalizeJson(entry.artifact_ref);
    if (entries.has(key) || !targetKeys.has(key)) reasons.add("memory_copy_tracking_invalid");
    if (!currentEntry(entry)) reasons.add("memory_propagation_unverified");
    entries.set(key, entry);
  }
  let state: MemoryPropagationState = "pending";
  if (record.propagation_entries.some(entry => entry.status === "failed" && currentEntry(entry))) state = "failed";
  else if (context.derived_inventory_status === "external_unknown" || record.propagation_entries.some(entry => entry.status === "external_unknown" && currentEntry(entry))) state = "external_unknown";
  else if (context.derived_inventory_status === "verified_complete" && targets.every(target => {
    const entry = entries.get(canonicalizeJson(target)); return entry?.status === "confirmed" && currentEntry(entry);
  })) state = "confirmed";
  if (record.propagation_status !== state) reasons.add("memory_propagation_incomplete");
  return { ...flow, allowed: reasons.size === 0, reason_codes: [...reasons].sort(), policy_ref: { ...record.policy_ref },
    artifact_refs: targets.map(ref => ({ ...ref })), unsatisfied_obligations: [...reasons].sort(), propagation_status: state,
    completion_verified: reasons.size === 0 && state === "confirmed" };
}
