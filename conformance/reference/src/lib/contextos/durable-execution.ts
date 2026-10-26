import { canonicalizeJson, sha256Canonical } from "./canonical-json";
import { hasExactKeys, isArtifactRef, isContractIdentifier, isContractTimestamp,
  isWithinContractInterval, compareContractTimes } from "./contract-validation";
import type { ArtifactRef } from "./execution-contract-types";
import type { PrincipalRef, VerificationStatus } from "./authorization";

export type RunStatus = "created" | "running" | "waiting_approval" | "waiting_external" | "suspended"
  | "cancel_requested" | "completed" | "failed" | "cancelled" | "expired";
export type RunEventKind = "start" | "resume" | "wait_approval" | "wait_external" | "suspend"
  | "request_cancel" | "acknowledge_cancel" | "complete" | "fail" | "expire";
export type RunEffectOutcome = "not_dispatched" | "confirmed" | "not_applied" | "partial" | "unknown";
export interface RunExecutionState {
  contract_id: string; run_id: string; tenant_id: string; status: RunStatus; revision: number;
  executor_generation: number; deadline: string; admission_ref: ArtifactRef; trusted_observer: PrincipalRef;
  /** Declared required effects; only confirmed effects satisfy successful completion. */
  outstanding_effects: { operation_id: string; outcome: RunEffectOutcome }[];
  /** Children whose execution has not yet been settled in the trusted run store. */
  child_run_ids: string[]; dispatch_stop_acknowledged: boolean; last_event_id: string | null;
}
interface RunObservation {
  run_id: string; tenant_id: string; executor_generation: number; observer: PrincipalRef;
  verification_status: VerificationStatus; evidence_ref: ArtifactRef; observed_at: string; valid_until: string;
}
export interface RunPreconditionObservation extends RunObservation {
  admission_ref: ArtifactRef;
  checks: { admission: "ready" | "blocked" | "unknown"; authority: "ready" | "blocked" | "unknown";
    boundary: "ready" | "blocked" | "unknown"; budget: "ready" | "blocked" | "unknown" };
}
export interface DispatchStopObservation extends RunObservation {
  child_run_ids: string[]; dispatch_stopped: boolean; children_stop_recorded: boolean;
}
/** Events originate in an authenticated controller; serialized identifiers do not establish that authority. */
export interface RunEvent {
  event_id: string; run_id: string; tenant_id: string; kind: RunEventKind; expected_revision: number;
  executor_generation: number; preconditions: RunPreconditionObservation | null; dispatch_stop_ack: DispatchStopObservation | null;
}
export type TransitionResult<T> = { status: "accepted"; state: T; obligations: string[] }
  | { status: "rejected"; state: T; reason_codes: string[] };

const TRANSITIONS: Record<RunStatus, Partial<Record<RunEventKind, RunStatus>>> = {
  created: { start: "running", request_cancel: "cancel_requested", expire: "expired", fail: "failed" },
  running: { wait_approval: "waiting_approval", wait_external: "waiting_external", suspend: "suspended",
    request_cancel: "cancel_requested", complete: "completed", fail: "failed", expire: "expired" },
  waiting_approval: { resume: "running", request_cancel: "cancel_requested", fail: "failed", expire: "expired" },
  waiting_external: { resume: "running", request_cancel: "cancel_requested", fail: "failed", expire: "expired" },
  suspended: { resume: "running", request_cancel: "cancel_requested", fail: "failed", expire: "expired" },
  cancel_requested: { acknowledge_cancel: "cancelled", fail: "failed", expire: "expired" },
  completed: {}, failed: {}, cancelled: {}, expired: {},
};
const terminalStates = new Set<RunStatus>(["completed", "failed", "cancelled", "expired"]);
const eventKinds: RunEventKind[] = ["start", "resume", "wait_approval", "wait_external", "suspend", "request_cancel", "acknowledge_cancel", "complete", "fail", "expire"];
const integer = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) >= 0;
const same = (a: unknown, b: unknown) => canonicalizeJson(a) === canonicalizeJson(b);
const ids = (value: unknown): value is string[] => Array.isArray(value) && value.length <= 128
  && value.every(isContractIdentifier) && new Set(value).size === value.length;
const OBSERVATION_KEYS = ["run_id", "tenant_id", "executor_generation", "observer", "verification_status", "evidence_ref", "observed_at", "valid_until"];
function principal(value: unknown): value is PrincipalRef {
  return hasExactKeys(value, ["principal_id", "principal_type", "trust_domain", "tenant_id"])
    && [value.principal_id, value.trust_domain, value.tenant_id].every(isContractIdentifier)
    && ["person", "agent", "workload"].includes(value.principal_type as string);
}
function observationFields(value: Record<string, unknown>): boolean {
  return isContractIdentifier(value.run_id) && isContractIdentifier(value.tenant_id) && integer(value.executor_generation)
    && principal(value.observer) && ["verified", "invalid", "unavailable"].includes(value.verification_status as string)
    && isArtifactRef(value.evidence_ref) && isContractTimestamp(value.observed_at) && isContractTimestamp(value.valid_until);
}
function preconditions(value: unknown): value is RunPreconditionObservation {
  return hasExactKeys(value, [...OBSERVATION_KEYS, "admission_ref", "checks"]) && observationFields(value)
    && isArtifactRef(value.admission_ref) && hasExactKeys(value.checks, ["admission", "authority", "boundary", "budget"])
    && Object.values(value.checks).every(check => ["ready", "blocked", "unknown"].includes(check as string));
}
function stopObservation(value: unknown): value is DispatchStopObservation {
  return hasExactKeys(value, [...OBSERVATION_KEYS, "child_run_ids", "dispatch_stopped", "children_stop_recorded"])
    && observationFields(value) && ids(value.child_run_ids) && typeof value.dispatch_stopped === "boolean"
    && typeof value.children_stop_recorded === "boolean";
}
function validState(value: unknown): value is RunExecutionState {
  return hasExactKeys(value, ["contract_id", "run_id", "tenant_id", "status", "revision", "executor_generation", "deadline",
    "admission_ref", "trusted_observer", "outstanding_effects", "child_run_ids", "dispatch_stop_acknowledged", "last_event_id"])
    && [value.contract_id, value.run_id, value.tenant_id].every(isContractIdentifier) && typeof value.status === "string"
    && Object.hasOwn(TRANSITIONS, value.status) && integer(value.revision) && integer(value.executor_generation)
    && isContractTimestamp(value.deadline) && isArtifactRef(value.admission_ref) && principal(value.trusted_observer)
    && Array.isArray(value.outstanding_effects) && value.outstanding_effects.length <= 128
    && value.outstanding_effects.every(effect => hasExactKeys(effect, ["operation_id", "outcome"])
      && isContractIdentifier(effect.operation_id) && ["not_dispatched", "confirmed", "not_applied", "partial", "unknown"].includes(effect.outcome as string))
    && new Set(value.outstanding_effects.map(effect => effect.operation_id)).size === value.outstanding_effects.length
    && ids(value.child_run_ids) && typeof value.dispatch_stop_acknowledged === "boolean"
    && (value.last_event_id === null || isContractIdentifier(value.last_event_id));
}
function validEvent(value: unknown): value is RunEvent {
  return hasExactKeys(value, ["event_id", "run_id", "tenant_id", "kind", "expected_revision", "executor_generation", "preconditions", "dispatch_stop_ack"])
    && [value.event_id, value.run_id, value.tenant_id].every(isContractIdentifier) && eventKinds.includes(value.kind as RunEventKind)
    && integer(value.expected_revision) && integer(value.executor_generation)
    && (value.preconditions === null || preconditions(value.preconditions)) && (value.dispatch_stop_ack === null || stopObservation(value.dispatch_stop_ack));
}
function rejectTransition<T>(state: T, reason: string): TransitionResult<T> {
  return { status: "rejected", state, reason_codes: [reason] };
}

/** Intended immutable lifecycle transition. The store/adapter must atomically enforce revision, fencing and stop obligations. */
export function transitionRun(state: RunExecutionState, event: RunEvent, evaluationTime: string): TransitionResult<RunExecutionState> {
  try { canonicalizeJson(state); canonicalizeJson(event); } catch { return rejectTransition(state, "transition_invalid"); }
  if (!validState(state) || !validEvent(event) || !isContractTimestamp(evaluationTime)) return rejectTransition(state, "transition_invalid");
  if (terminalStates.has(state.status)) return rejectTransition(state, "transition_invalid");
  if (event.expected_revision !== state.revision) return rejectTransition(state, "revision_conflict");
  if (event.executor_generation !== state.executor_generation) return rejectTransition(state, "executor_stale");
  if (event.run_id !== state.run_id || event.tenant_id !== state.tenant_id) return rejectTransition(state, "transition_invalid");
  const destination = TRANSITIONS[state.status][event.kind];
  if (!destination) return rejectTransition(state, "transition_invalid");
  const expired = compareContractTimes(evaluationTime, state.deadline) !== -1;
  if (event.kind === "expire" && !expired) return rejectTransition(state, "transition_invalid");
  if (expired && !["expire", "fail", "request_cancel", "acknowledge_cancel"].includes(event.kind)) return rejectTransition(state, "deadline_exceeded");
  const verified = (observed: RunObservation) => observed.verification_status === "verified"
    && observed.run_id === state.run_id && observed.tenant_id === state.tenant_id
    && observed.executor_generation === state.executor_generation && observed.observer.tenant_id === state.tenant_id
    && same(observed.observer, state.trusted_observer) && isWithinContractInterval(evaluationTime, observed.observed_at, observed.valid_until);
  if (event.kind === "start" || event.kind === "resume") {
    const observed = event.preconditions;
    if (!observed || !verified(observed)) return rejectTransition(state, "authority_stale");
    if (!same(observed.admission_ref, state.admission_ref)) return rejectTransition(state, "artifact_binding_mismatch");
    if (observed.checks.admission !== "ready") return rejectTransition(state, "transition_invalid");
    if (observed.checks.authority !== "ready") return rejectTransition(state, "authority_stale");
    if (observed.checks.boundary !== "ready") return rejectTransition(state, "boundary_not_ready");
    if (observed.checks.budget !== "ready") return rejectTransition(state, "budget_exhausted");
  }
  if (event.kind === "complete") {
    if (state.outstanding_effects.some(effect => effect.outcome !== "confirmed")) return rejectTransition(state, "required_effect_unsatisfied");
    if (state.child_run_ids.length) return rejectTransition(state, "children_unsettled");
  }
  if (event.kind === "acknowledge_cancel") {
    const observed = event.dispatch_stop_ack;
    if (!observed || !verified(observed) || !observed.dispatch_stopped || !observed.children_stop_recorded
      || !same([...observed.child_run_ids].sort(), [...state.child_run_ids].sort())) return rejectTransition(state, "dispatch_stop_unverified");
  }
  if (!integer(state.revision + 1) || !integer(state.executor_generation + 1)) return rejectTransition(state, "counter_exhausted");
  const next = structuredClone(state);
  next.status = destination; next.revision += 1;
  // Every accepted lifecycle event invalidates observations/ownership from the previous generation.
  next.executor_generation += 1; next.last_event_id = event.event_id;
  if (event.kind === "acknowledge_cancel") next.dispatch_stop_acknowledged = true;
  const obligations = new Set<string>(["persist_event", "apply_executor_fence"]);
  if (destination === "running") obligations.add("acquire_executor_generation");
  else { obligations.add("stop_new_dispatch"); obligations.add("fence_executor"); }
  if (["cancel_requested", "cancelled", "failed", "expired"].includes(destination)) {
    obligations.add("cancel_children");
    if (state.outstanding_effects.some(effect => effect.outcome === "unknown" || effect.outcome === "partial")) obligations.add("reconcile_outstanding_effects");
  }
  return { status: "accepted", state: next, obligations: [...obligations].sort() };
}

export { claimOperation, recordEffectObservation } from "./operation-ledger";
export type { OperationIntent, OperationAttempt, OperationClaim, ProviderIdempotencyObservation,
  EffectObservation, OperationRecord, OperationLedger, RecoveryStrategy } from "./operation-ledger";

export interface ResourceCounters { tokens: number; tool_calls: number; replans: number; cost_units: number }
export interface CostAccountingUnit { currency: string; units_per_cent: number }
export { convertLegacyCostToUnits, reserveBudget, settleBudget, reserveChildBudget, settleChildBudget } from "./budget-ledger";
export type { CostUnitConversion, BudgetReservationRecord, BudgetMutationReceipt, BudgetLedger,
  BudgetReservationRequest, BudgetSettlementRequest } from "./budget-ledger";
export interface CheckpointBudgetSnapshot {
  ledger_revision: number; cost_unit: CostAccountingUnit; ceiling: ResourceCounters;
  used: ResourceCounters; reserved: ResourceCounters; deadline: string;
}
export interface ExecutionCheckpoint {
  checkpoint_version: "contextos.execution_checkpoint.v1"; checkpoint_id: string; revision: number;
  contract_id: string; run_id: string; tenant_id: string; contract_ref: ArtifactRef; pack_ref: ArtifactRef;
  policy_refs: ArtifactRef[]; tool_registry_ref: ArtifactRef; profile_registry_ref: ArtifactRef; release_refs: ArtifactRef[];
  run_state: RunExecutionState; operation_ledger_ref: ArtifactRef; budget_ledger_ref: ArtifactRef; operation_ids: string[];
  budget_snapshot: CheckpointBudgetSnapshot; pending_approval_refs: ArtifactRef[]; pending_task_refs: ArtifactRef[];
  cancellation_state: "none" | "requested" | "acknowledged"; executor_generation: number; require_target_fencing: boolean; digest: string;
}
interface ResumeObservation {
  verification_status: VerificationStatus; observer: PrincipalRef; evidence_ref: ArtifactRef; observed_at: string; valid_until: string;
}
export type ResumeCheck = "contract_support" | "authority" | "approval" | "boundary" | "external_preconditions" | "budget";
export interface ResumeControlObservation extends ResumeObservation {
  check: ResumeCheck; status: "ready" | "blocked" | "unknown"; run_id: string; tenant_id: string;
  checkpoint_digest: string; executor_generation: number;
}
export interface ResumeArtifactObservation extends ResumeObservation { artifact_ref: ArtifactRef; actual_sha256: string }
export interface ResumeStoreObservation extends ResumeObservation {
  checkpoint_id: string; checkpoint_revision: number; checkpoint_digest: string; contract_id: string; run_id: string; tenant_id: string;
  executor_id: string; executor_generation: number; lease_ref: ArtifactRef; target_fencing: "enforced" | "unsupported" | "unknown";
  run_status: RunStatus; cancellation_state: "none" | "requested" | "acknowledged";
  operation_ledger_ref: ArtifactRef; budget_ledger_ref: ArtifactRef; operation_ids: string[]; budget_snapshot: CheckpointBudgetSnapshot;
}
export interface ResumeValidationInput {
  checkpoint: ExecutionCheckpoint; run_id: string; tenant_id: string; executor_id: string; executor_generation: number;
  expected_revision: number; evaluation_time: string; trusted_observers: PrincipalRef[]; required_policy_refs: ArtifactRef[];
  store_observation: ResumeStoreObservation; artifact_observations: ResumeArtifactObservation[]; current_observations: ResumeControlObservation[];
}
/** Subtype of the generic result; rejection obligations never authorize dispatch. */
export type ResumeValidationResult = TransitionResult<ExecutionCheckpoint> & { obligations: string[] };

const RESUME_CHECKS: readonly ResumeCheck[] = ["contract_support", "authority", "approval", "boundary", "external_preconditions", "budget"];
const RESUME_OBSERVATION_KEYS = ["verification_status", "observer", "evidence_ref", "observed_at", "valid_until"];
const refs = (value: unknown): value is ArtifactRef[] => Array.isArray(value) && value.length <= 128 && value.every(isArtifactRef);
const hash = (value: unknown): value is string => typeof value === "string" && /^sha256:[a-f0-9]{64}$/.test(value);
const list = <T>(value: unknown, check: (item: unknown) => item is T): value is T[] => Array.isArray(value) && value.length <= 128 && value.every(check);
function resourceCounters(value: unknown): value is ResourceCounters {
  return hasExactKeys(value, ["tokens", "tool_calls", "replans", "cost_units"]) && Object.values(value).every(integer);
}
function countersFit(ceiling: ResourceCounters, used: ResourceCounters, reserved: ResourceCounters): boolean {
  return (Object.keys(ceiling) as (keyof ResourceCounters)[]).every(key => used[key] <= ceiling[key]
    && reserved[key] <= ceiling[key] - used[key]);
}
function budgetSnapshot(value: unknown): value is CheckpointBudgetSnapshot {
  return hasExactKeys(value, ["ledger_revision", "cost_unit", "ceiling", "used", "reserved", "deadline"])
    && integer(value.ledger_revision) && hasExactKeys(value.cost_unit, ["currency", "units_per_cent"])
    && typeof value.cost_unit.currency === "string" && /^[A-Z]{3}$/.test(value.cost_unit.currency)
    && integer(value.cost_unit.units_per_cent) && /^10*$/.test(String(value.cost_unit.units_per_cent))
    && resourceCounters(value.ceiling) && resourceCounters(value.used) && resourceCounters(value.reserved)
    && countersFit(value.ceiling, value.used, value.reserved) && isContractTimestamp(value.deadline);
}
function checkpoint(value: unknown): value is ExecutionCheckpoint {
  return hasExactKeys(value, ["checkpoint_version", "checkpoint_id", "revision", "contract_id", "run_id", "tenant_id", "contract_ref", "pack_ref",
    "policy_refs", "tool_registry_ref", "profile_registry_ref", "release_refs", "run_state", "operation_ledger_ref", "budget_ledger_ref",
    "operation_ids", "budget_snapshot", "pending_approval_refs", "pending_task_refs", "cancellation_state", "executor_generation", "require_target_fencing", "digest"])
    && value.checkpoint_version === "contextos.execution_checkpoint.v1" && [value.checkpoint_id, value.contract_id, value.run_id, value.tenant_id].every(isContractIdentifier)
    && integer(value.revision) && [value.contract_ref, value.pack_ref, value.tool_registry_ref, value.profile_registry_ref,
      value.operation_ledger_ref, value.budget_ledger_ref].every(isArtifactRef)
    && refs(value.policy_refs) && value.policy_refs.length > 0 && refs(value.release_refs) && value.release_refs.length > 0
    && validState(value.run_state) && ids(value.operation_ids) && budgetSnapshot(value.budget_snapshot)
    && refs(value.pending_approval_refs) && refs(value.pending_task_refs) && ["none", "requested", "acknowledged"].includes(value.cancellation_state as string)
    && integer(value.executor_generation) && typeof value.require_target_fencing === "boolean" && hash(value.digest);
}
function resumeObservationFields(value: Record<string, unknown>): boolean {
  return ["verified", "invalid", "unavailable"].includes(value.verification_status as string) && principal(value.observer)
    && isArtifactRef(value.evidence_ref) && isContractTimestamp(value.observed_at) && isContractTimestamp(value.valid_until);
}
function storeObservation(value: unknown): value is ResumeStoreObservation {
  return hasExactKeys(value, [...RESUME_OBSERVATION_KEYS, "checkpoint_id", "checkpoint_revision", "checkpoint_digest", "contract_id", "run_id", "tenant_id",
    "executor_id", "executor_generation", "lease_ref", "target_fencing", "run_status", "cancellation_state", "operation_ledger_ref", "budget_ledger_ref", "operation_ids", "budget_snapshot"])
    && resumeObservationFields(value) && [value.checkpoint_id, value.contract_id, value.run_id, value.tenant_id, value.executor_id].every(isContractIdentifier)
    && integer(value.checkpoint_revision) && hash(value.checkpoint_digest) && integer(value.executor_generation)
    && [value.lease_ref, value.operation_ledger_ref, value.budget_ledger_ref].every(isArtifactRef)
    && ["enforced", "unsupported", "unknown"].includes(value.target_fencing as string) && typeof value.run_status === "string"
    && Object.hasOwn(TRANSITIONS, value.run_status) && ["none", "requested", "acknowledged"].includes(value.cancellation_state as string)
    && ids(value.operation_ids) && budgetSnapshot(value.budget_snapshot);
}
function artifactObservation(value: unknown): value is ResumeArtifactObservation {
  return hasExactKeys(value, [...RESUME_OBSERVATION_KEYS, "artifact_ref", "actual_sha256"]) && resumeObservationFields(value)
    && isArtifactRef(value.artifact_ref) && hash(value.actual_sha256);
}
function controlObservation(value: unknown): value is ResumeControlObservation {
  return hasExactKeys(value, [...RESUME_OBSERVATION_KEYS, "check", "status", "run_id", "tenant_id", "checkpoint_digest", "executor_generation"])
    && resumeObservationFields(value) && RESUME_CHECKS.includes(value.check as ResumeCheck)
    && ["ready", "blocked", "unknown"].includes(value.status as string) && isContractIdentifier(value.run_id) && isContractIdentifier(value.tenant_id)
    && hash(value.checkpoint_digest) && integer(value.executor_generation);
}
function sameRefSet(left: ArtifactRef[], right: ArtifactRef[]): boolean {
  const a = new Set(left.map(ref => canonicalizeJson(ref))), b = new Set(right.map(ref => canonicalizeJson(ref)));
  return a.size === left.length && b.size === right.length && a.size === b.size && [...a].every(key => b.has(key));
}
function pinnedRefs(saved: ExecutionCheckpoint): ArtifactRef[] {
  const all = [saved.contract_ref, saved.pack_ref, ...saved.policy_refs, saved.tool_registry_ref, saved.profile_registry_ref,
    ...saved.release_refs, saved.operation_ledger_ref, saved.budget_ledger_ref, ...saved.pending_approval_refs, ...saved.pending_task_refs];
  return [...new Map(all.map(ref => [canonicalizeJson(ref), ref])).values()];
}

/** Validates a restore intent; ownership/CAS and adapter fencing must still be enforced atomically at the deployment boundary. */
export function validateResume(input: ResumeValidationInput): ResumeValidationResult {
  // A missing snapshot cannot be replaced with a fabricated empty state.
  try { canonicalizeJson(input); } catch { throw new TypeError("Resume request must be plain JSON"); }
  if (!input || typeof input !== "object" || !Object.hasOwn(input, "checkpoint") || input.checkpoint === null) {
    throw new TypeError("Resume request must include its checkpoint");
  }
  const saved = input.checkpoint;
  const reject = (reason: string, obligations: string[] = []): ResumeValidationResult =>
    ({ status: "rejected", state: saved, reason_codes: [reason], obligations });
  if (saved && typeof saved === "object" && typeof saved.checkpoint_version === "string"
    && saved.checkpoint_version !== "contextos.execution_checkpoint.v1") return reject("checkpoint_version_unsupported");
  if (!hasExactKeys(input, ["checkpoint", "run_id", "tenant_id", "executor_id", "executor_generation", "expected_revision", "evaluation_time",
    "trusted_observers", "required_policy_refs", "store_observation", "artifact_observations", "current_observations"])
    || !checkpoint(saved) || ![input.run_id, input.tenant_id, input.executor_id].every(isContractIdentifier)
    || !integer(input.executor_generation) || !integer(input.expected_revision) || !isContractTimestamp(input.evaluation_time)
    || !list(input.trusted_observers, principal) || !refs(input.required_policy_refs) || !storeObservation(input.store_observation)
    || !list(input.artifact_observations, artifactObservation) || !list(input.current_observations, controlObservation)) return reject("checkpoint_invalid");
  const { digest: ignored, ...payload } = saved; void ignored;
  if (saved.digest !== sha256Canonical({ domain: "contextos.checkpoint.v1", payload })) return reject("artifact_binding_mismatch");
  const store = input.store_observation, state = saved.run_state;
  const verified = (observed: ResumeObservation) => observed.verification_status === "verified" && observed.observer.tenant_id === input.tenant_id
    && input.trusted_observers.some(observer => same(observer, observed.observer)) && isWithinContractInterval(input.evaluation_time, observed.observed_at, observed.valid_until);
  if (!verified(store) || store.checkpoint_id !== saved.checkpoint_id || store.checkpoint_digest !== saved.digest) return reject("checkpoint_invalid");
  if (input.expected_revision !== saved.revision || store.checkpoint_revision !== input.expected_revision) return reject("revision_conflict");
  if (store.executor_generation !== input.executor_generation || input.executor_generation < saved.executor_generation
    || store.executor_id !== input.executor_id) return reject("executor_stale");
  if (input.tenant_id !== saved.tenant_id || input.run_id !== saved.run_id || store.contract_id !== saved.contract_id
    || store.run_id !== saved.run_id || store.tenant_id !== saved.tenant_id || state.contract_id !== saved.contract_id
    || state.run_id !== saved.run_id || state.tenant_id !== saved.tenant_id || state.executor_generation !== saved.executor_generation) return reject("checkpoint_invalid");
  if (saved.cancellation_state !== "none" || store.cancellation_state !== "none" || terminalStates.has(state.status)
    || terminalStates.has(store.run_status) || state.status === "cancel_requested" || store.run_status !== state.status) return reject("transition_invalid");
  if (compareContractTimes(input.evaluation_time, state.deadline) !== -1 || compareContractTimes(input.evaluation_time, saved.budget_snapshot.deadline) !== -1
    || compareContractTimes(saved.budget_snapshot.deadline, state.deadline) === 1) return reject("deadline_exceeded");
  if (!sameRefSet(saved.policy_refs, input.required_policy_refs)) return reject("policy_migration_required", ["migrate_policy_and_reauthorize"]);
  if (!same(store.operation_ledger_ref, saved.operation_ledger_ref) || !same(store.budget_ledger_ref, saved.budget_ledger_ref)
    || !same([...store.operation_ids].sort(), [...saved.operation_ids].sort()) || !same(store.budget_snapshot, saved.budget_snapshot)) return reject("artifact_binding_mismatch");
  const pins = pinnedRefs(saved);
  if (pins.length > 128) return reject("checkpoint_invalid");
  for (const ref of pins) {
    const observations = input.artifact_observations.filter(observed => same(observed.artifact_ref, ref)), observed = observations[0];
    if (observations.length !== 1 || !observed || !verified(observed) || observed.actual_sha256 !== ref.sha256) return reject("artifact_binding_mismatch");
  }
  const failures: Record<ResumeCheck, string> = { contract_support: "checkpoint_version_unsupported", authority: "authority_stale",
    approval: "approval_expired", boundary: "boundary_not_ready", external_preconditions: "precondition_stale", budget: "budget_exhausted" };
  for (const check of RESUME_CHECKS) {
    const observations = input.current_observations.filter(observed => observed.check === check), observed = observations[0];
    if (observations.length !== 1 || !observed || !verified(observed) || observed.status !== "ready" || observed.checkpoint_digest !== saved.digest
      || observed.executor_generation !== input.executor_generation || observed.run_id !== saved.run_id || observed.tenant_id !== saved.tenant_id) return reject(failures[check]);
  }
  if (store.target_fencing === "unknown" || (saved.require_target_fencing && store.target_fencing !== "enforced")) return reject("executor_stale", ["establish_required_target_fencing"]);
  const obligations = ["atomically_claim_executor_under_verified_revision", "recheck_before_bound_dispatch", "restore_under_current_fence"];
  if (store.target_fencing === "unsupported") obligations.push("target_fencing_unavailable_use_idempotency_and_reconciliation");
  return { status: "accepted", state: saved, obligations: obligations.sort() };
}
