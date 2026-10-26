import { canonicalizeJson, sha256Canonical } from "./canonical-json";
import { compareContractTimes, hasExactKeys, isArtifactRef, isContractIdentifier, isContractTimestamp,
  isControlRef, isProfileSelection, isWithinContractInterval } from "./contract-validation";
import { negotiateExecutionContract } from "./execution-contract";
import type { ArtifactRef, ControlRef, ExecutionContractEnvelope, ProfileRegistrySnapshot, ProfileSelection,
  RuntimeSupportDeclaration, WorkflowFeatureSet } from "./execution-contract-types";
import type { PrincipalRef, VerificationStatus } from "./authorization";

export type ControlEvidenceStatus = "passed" | "failed" | "unsupported" | "not_evaluated";
export type ConformanceOutcome = "passed" | "failed" | "insufficient_evidence";
export interface ConformanceCaseResult {
  case_id: string; status: "passed" | "failed" | "not_evaluated"; evidence_refs: ArtifactRef[];
}
export interface ControlEvidenceResult {
  control: ControlRef; status: ControlEvidenceStatus; case_results: ConformanceCaseResult[];
  evidence_refs: ArtifactRef[]; reason_codes: string[]; limitations: string[];
}
export interface ConformanceReport {
  report_version: "contextos.conformance_report.v1"; report_id: string;
  implementation_id: string; implementation_version: string; workflow_id: string;
  profiles: ProfileSelection[]; effective_required_controls: ControlRef[]; registry_ref: ArtifactRef; suite_ref: ArtifactRef;
  release_refs: ArtifactRef[]; environment: { description: string; configuration_ref: ArtifactRef };
  evaluated_at: string; valid_until: string; evaluator: PrincipalRef;
  control_results: ControlEvidenceResult[]; utility_results: ConformanceCaseResult[]; outcome: ConformanceOutcome;
}
interface EvidenceVerification {
  report_digest: string; verification_status: VerificationStatus; observer: PrincipalRef; evidence_ref: ArtifactRef;
  observed_at: string; valid_until: string; evidence_kind: "runtime" | "synthetic";
}
export interface ConformanceEvidenceObservation extends EvidenceVerification { actual_sha256: string }
export interface ConformanceAssessmentInput {
  contract: ExecutionContractEnvelope; support: RuntimeSupportDeclaration; registry: ProfileRegistrySnapshot; features: WorkflowFeatureSet;
  report: ConformanceReport; evaluation_time: string;
  scope: { workflow_id: string; implementation_id: string; implementation_version: string; release_refs: ArtifactRef[];
    environment_ref: ArtifactRef; required_utility_case_ids: string[] };
  trusted_assessors: PrincipalRef[]; trusted_evidence_observers: PrincipalRef[];
  report_verification: EvidenceVerification; evidence_observations: ConformanceEvidenceObservation[];
}
export interface ConformanceAssessment {
  outcome: ConformanceOutcome; report_id: string | null; workflow_id: string | null; implementation_id: string | null;
  implementation_version: string | null; release_refs: ArtifactRef[]; registry_ref: ArtifactRef | null;
  missing_controls: ControlRef[]; unsupported_optional: ControlRef[]; reasons: string[]; limitations: string[];
}
/** Deterministic fixtures exercise reference logic; none of their statuses attest a production control. */
export interface ReferenceValidationReport {
  report_version: "contextos.reference_validation.v1"; report_id: string; implementation_id: string;
  implementation_version: string; workflow_id: string; suite_ref: ArtifactRef; release_refs: ArtifactRef[];
  fixture_refs: ArtifactRef[]; case_results: { case_id: string; status: "passed" | "failed" }[];
  runtime_controls: "not_evaluated"; outcome: "reference_checks_passed" | "reference_checks_failed";
}
const same = (a: unknown, b: unknown) => canonicalizeJson(a) === canonicalizeJson(b);
const hash = (v: unknown): v is string => typeof v === "string" && /^sha256:[a-f0-9]{64}$/.test(v);
const list = <T>(v: unknown, check: (v: unknown) => v is T): v is T[] => Array.isArray(v) && v.length <= 128 && v.every(check);
const refs = (v: unknown): v is ArtifactRef[] => list(v, isArtifactRef);
const strings = (v: unknown): v is string[] => list(v, isContractIdentifier);
const compare = (a: string, b: string) => a < b ? -1 : a > b ? 1 : 0;
const controlKey = (c: ControlRef) => `${c.control_id}@${c.control_version}`;
const exactSet = (a: unknown[], b: unknown[]) => same(a.map(canonicalizeJson).sort(compare), b.map(canonicalizeJson).sort(compare));
const unique = (values: unknown[]) => new Set(values.map(canonicalizeJson)).size === values.length;
function principal(v: unknown): v is PrincipalRef {
  return hasExactKeys(v, ["principal_id", "principal_type", "trust_domain", "tenant_id"])
    && [v.principal_id, v.trust_domain, v.tenant_id].every(isContractIdentifier) && ["person", "agent", "workload"].includes(v.principal_type as string);
}
function caseResult(v: unknown): v is ConformanceCaseResult {
  return hasExactKeys(v, ["case_id", "status", "evidence_refs"]) && isContractIdentifier(v.case_id)
    && ["passed", "failed", "not_evaluated"].includes(v.status as string) && refs(v.evidence_refs) && unique(v.evidence_refs);
}
function controlResult(v: unknown): v is ControlEvidenceResult {
  return hasExactKeys(v, ["control", "status", "case_results", "evidence_refs", "reason_codes", "limitations"])
    && isControlRef(v.control) && ["passed", "failed", "unsupported", "not_evaluated"].includes(v.status as string)
    && list(v.case_results, caseResult) && refs(v.evidence_refs) && unique(v.evidence_refs) && strings(v.reason_codes) && strings(v.limitations);
}
function report(v: unknown): v is ConformanceReport {
  return hasExactKeys(v, ["report_version", "report_id", "implementation_id", "implementation_version", "workflow_id", "profiles",
    "effective_required_controls", "registry_ref", "suite_ref", "release_refs", "environment", "evaluated_at", "valid_until", "evaluator",
    "control_results", "utility_results", "outcome"]) && v.report_version === "contextos.conformance_report.v1"
    && [v.report_id, v.implementation_id, v.implementation_version, v.workflow_id].every(isContractIdentifier)
    && list(v.profiles, isProfileSelection) && v.profiles.length > 0 && unique(v.profiles)
    && list(v.effective_required_controls, isControlRef) && unique(v.effective_required_controls)
    && isArtifactRef(v.registry_ref) && isArtifactRef(v.suite_ref) && refs(v.release_refs) && v.release_refs.length > 0 && unique(v.release_refs)
    && hasExactKeys(v.environment, ["description", "configuration_ref"]) && isContractIdentifier(v.environment.description) && isArtifactRef(v.environment.configuration_ref)
    && isContractTimestamp(v.evaluated_at) && isContractTimestamp(v.valid_until) && principal(v.evaluator)
    && list(v.control_results, controlResult) && list(v.utility_results, caseResult) && ["passed", "failed", "insufficient_evidence"].includes(v.outcome as string);
}
const PROOF_KEYS = ["report_digest", "verification_status", "observer", "evidence_ref", "observed_at", "valid_until", "evidence_kind"];
function proofFields(v: Record<string, unknown>): boolean {
  return hash(v.report_digest) && ["verified", "invalid", "unavailable"].includes(v.verification_status as string)
    && principal(v.observer) && isArtifactRef(v.evidence_ref) && isContractTimestamp(v.observed_at) && isContractTimestamp(v.valid_until)
    && ["runtime", "synthetic"].includes(v.evidence_kind as string);
}
function proof(v: unknown): v is EvidenceVerification { return hasExactKeys(v, PROOF_KEYS) && proofFields(v); }
function evidence(v: unknown): v is ConformanceEvidenceObservation {
  return hasExactKeys(v, [...PROOF_KEYS, "actual_sha256"]) && proofFields(v) && hash(v.actual_sha256);
}
function input(v: unknown): v is ConformanceAssessmentInput {
  return hasExactKeys(v, ["contract", "support", "registry", "features", "report", "evaluation_time", "scope", "trusted_assessors",
    "trusted_evidence_observers", "report_verification", "evidence_observations"]) && report(v.report) && isContractTimestamp(v.evaluation_time)
    && hasExactKeys(v.scope, ["workflow_id", "implementation_id", "implementation_version", "release_refs", "environment_ref", "required_utility_case_ids"])
    && [v.scope.workflow_id, v.scope.implementation_id, v.scope.implementation_version].every(isContractIdentifier)
    && refs(v.scope.release_refs) && v.scope.release_refs.length > 0 && unique(v.scope.release_refs) && isArtifactRef(v.scope.environment_ref)
    && strings(v.scope.required_utility_case_ids) && v.scope.required_utility_case_ids.length > 0 && unique(v.scope.required_utility_case_ids)
    && list(v.trusted_assessors, principal) && v.trusted_assessors.length > 0 && list(v.trusted_evidence_observers, principal)
    && v.trusted_evidence_observers.length > 0 && proof(v.report_verification) && list(v.evidence_observations, evidence);
}

/** Assesses trusted, already verified adapter observations; JSON fields cannot authenticate their own origin. */
export function assessConformanceReport(value: ConformanceAssessmentInput): ConformanceAssessment {
  const result: ConformanceAssessment = { outcome: "insufficient_evidence", report_id: null, workflow_id: null,
    implementation_id: null, implementation_version: null, release_refs: [], registry_ref: null,
    missing_controls: [], unsupported_optional: [], reasons: [], limitations: [] };
  const reasons = new Set<string>();
  const finish = () => { result.reasons = [...reasons].sort(compare); result.limitations = [...new Set(result.limitations)].sort(compare); return result; };
  try { canonicalizeJson(value); } catch { reasons.add("report_invalid"); return finish(); }
  if (!input(value)) { reasons.add("report_invalid"); return finish(); }
  const r = value.report, scope = value.scope;
  Object.assign(result, { report_id: r.report_id, workflow_id: r.workflow_id, implementation_id: r.implementation_id,
    implementation_version: r.implementation_version, release_refs: structuredClone(r.release_refs), registry_ref: structuredClone(r.registry_ref) });
  const negotiation = negotiateExecutionContract(value.contract, value.support, value.registry, value.features);
  result.unsupported_optional = negotiation.unsupported_optional;
  if (negotiation.status !== "accepted") { reasons.add("contract_not_supported"); return finish(); }
  if (r.implementation_id !== scope.implementation_id || r.implementation_version !== scope.implementation_version
    || r.implementation_id !== value.support.implementation_id || r.implementation_version !== value.support.implementation_version
    || r.workflow_id !== scope.workflow_id || !exactSet(r.release_refs, scope.release_refs) || !exactSet(r.release_refs, value.contract.release_refs)
    || !same(r.environment.configuration_ref, scope.environment_ref) || !same(r.registry_ref, value.registry.registry_ref)
    || !exactSet(r.profiles, value.contract.profiles) || !exactSet(r.effective_required_controls, negotiation.effective_required_controls)) {
    reasons.add("report_scope_mismatch"); return finish();
  }
  const digest = sha256Canonical({ domain: "contextos.conformance_report.v1", report: r });
  const verified = (p: EvidenceVerification) => p.verification_status === "verified" && p.evidence_kind === "runtime"
    && p.report_digest === digest && p.observer.tenant_id === value.contract.tenant_id
    && value.trusted_evidence_observers.some(observer => same(observer, p.observer))
    && isWithinContractInterval(value.evaluation_time, p.observed_at, p.valid_until)
    && compareContractTimes(r.evaluated_at, p.observed_at) !== 1;
  if (!verified(value.report_verification) || r.evaluator.tenant_id !== value.contract.tenant_id
    || !value.trusted_assessors.some(assessor => same(assessor, r.evaluator))
    || !isWithinContractInterval(value.evaluation_time, r.evaluated_at, r.valid_until)) {
    reasons.add("report_unverified_or_stale"); return finish();
  }
  if (new Set(r.control_results.map(row => controlKey(row.control))).size !== r.control_results.length
    || new Set(r.utility_results.map(row => row.case_id)).size !== r.utility_results.length
    || r.control_results.some(row => new Set(row.case_results.map(c => c.case_id)).size !== row.case_results.length)
    || !unique(value.evidence_observations.map(e => e.evidence_ref))) {
    reasons.add("conflicting_evidence_rows"); return finish();
  }
  const observed = new Map(value.evidence_observations.map(e => [canonicalizeJson(e.evidence_ref), e]));
  const hasEvidence = (refs: ArtifactRef[]) => refs.length > 0 && refs.every(ref => {
    const observation = observed.get(canonicalizeJson(ref));
    return observation !== undefined && verified(observation) && observation.actual_sha256 === ref.sha256;
  });
  let failed = false;
  const covered = (row: ConformanceCaseResult) => {
    if (!hasEvidence(row.evidence_refs)) { reasons.add("case_evidence_missing_or_stale"); return false; }
    if (row.status === "failed") { failed = true; reasons.add("observed_case_failed"); }
    return row.status === "passed";
  };
  for (const required of negotiation.effective_required_controls) {
    const row = r.control_results.find(row => same(row.control, required));
    const definition = value.registry.controls.find(c => same(c.control, required))!;
    let complete = row !== undefined && hasEvidence(row.evidence_refs);
    if (row) {
      result.limitations.push(...row.limitations);
      if (row.status === "failed" && hasEvidence(row.evidence_refs)) { failed = true; reasons.add("observed_control_failed"); }
      complete = complete && row.status === "passed";
      for (const caseRow of row.case_results) if (!covered(caseRow)) complete = false;
      for (const id of [...definition.positive_cases, ...definition.negative_cases]) {
        const caseRow = row.case_results.find(c => c.case_id === id);
        if (!caseRow) complete = false;
      }
    }
    if (!complete) { result.missing_controls.push(structuredClone(required)); reasons.add("required_control_evidence_missing"); }
  }
  const allowedControls = [...negotiation.effective_required_controls, ...value.contract.optional_controls];
  if (r.control_results.some(row => !allowedControls.some(c => same(c, row.control)))) reasons.add("unselected_control_result");
  for (const row of r.control_results.filter(row => !negotiation.effective_required_controls.some(c => same(c, row.control)))) {
    result.limitations.push(...row.limitations, `${controlKey(row.control)}:${row.status}`);
  }
  for (const id of scope.required_utility_case_ids) {
    const utility = r.utility_results.find(row => row.case_id === id);
    if (!utility || !covered(utility)) reasons.add("required_utility_not_passed");
  }
  for (const utility of r.utility_results) if (!covered(utility)) reasons.add("utility_evidence_not_passed");
  result.missing_controls.sort((a, b) => compare(controlKey(a), controlKey(b)));
  if (r.outcome === "failed") { failed = true; reasons.add("report_declared_failure"); }
  if (r.outcome === "insufficient_evidence") reasons.add("report_declared_insufficient");
  result.outcome = failed ? "failed" : reasons.size === 0 ? "passed" : "insufficient_evidence";
  return finish();
}
