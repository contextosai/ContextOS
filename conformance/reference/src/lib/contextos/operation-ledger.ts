import { canonicalizeJson } from "./canonical-json";
import { addContractSeconds, compareContractTimes, hasExactKeys, isArtifactRef, isContractIdentifier,
  isContractTimestamp, isWithinContractInterval } from "./contract-validation";
import type { ArtifactRef } from "./execution-contract-types";
import type { PrincipalRef, VerificationStatus } from "./authorization";
import type { RunEffectOutcome, TransitionResult } from "./durable-execution";

export type RecoveryStrategy = "query" | "idempotent_retry" | "manual_reconcile" | "no_retry";
export interface OperationIntent {
  contract_id: string; run_id: string; tenant_id: string; operation_id: string; action_digest: string;
  adapter_ref: ArtifactRef; capability_ref: ArtifactRef; desired_effect: string; recovery_strategy: RecoveryStrategy;
  idempotency_key: string | null; idempotency_scope: string | null; provider_idempotency_ref: ArtifactRef | null;
  max_attempts: number; retry_delays_seconds: number[]; deadline: string; compensates_operation_id: string | null;
}
export interface OperationAttempt {
  attempt_id: string; operation_id: string; executor_generation: number; started_at: string;
  dispatch_state: "claimed" | "dispatched" | "settled"; last_observation_ref: ArtifactRef | null;
}
export interface ProviderIdempotencyObservation {
  provider_contract_ref: ArtifactRef; key: string; scope: string; operation_id: string; action_digest: string;
  same_payload_enforced: boolean; verification_status: VerificationStatus; observer: PrincipalRef; evidence_ref: ArtifactRef;
  observed_at: string; valid_until: string; not_before: string; retention_expires_at: string;
}
export interface OperationClaim extends OperationIntent {
  attempt: OperationAttempt; evaluation_time: string; provider_observation: ProviderIdempotencyObservation | null;
}
export interface EffectObservation {
  observation_id: string; contract_id: string; run_id: string; tenant_id: string; operation_id: string; attempt_id: string;
  action_digest: string; executor_generation: number; outcome: RunEffectOutcome; finality: "definitive" | "provisional";
  external_ref: string | null; evidence_ref: ArtifactRef; verification_status: VerificationStatus; observer: PrincipalRef;
  observed_at: string; valid_until: string; evaluation_time: string;
}
export interface OperationRecord {
  intent: OperationIntent; attempts: OperationAttempt[]; observations: EffectObservation[];
  outcome: RunEffectOutcome; next_eligible_at: string | null; conflict: boolean;
}
export interface OperationLedger {
  ledger_id: string; contract_id: string; run_id: string; tenant_id: string; revision: number;
  executor_generation: number; deadline: string; trusted_observers: PrincipalRef[]; operations: OperationRecord[];
}
const INTENT_KEYS = ["contract_id", "run_id", "tenant_id", "operation_id", "action_digest", "adapter_ref", "capability_ref",
  "desired_effect", "recovery_strategy", "idempotency_key", "idempotency_scope", "provider_idempotency_ref", "max_attempts",
  "retry_delays_seconds", "deadline", "compensates_operation_id"];
const integer = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 0;
const digest = (v: unknown): v is string => typeof v === "string" && /^sha256:[a-f0-9]{64}$/.test(v);
const same = (a: unknown, b: unknown) => canonicalizeJson(a) === canonicalizeJson(b);
const nullableId = (v: unknown) => v === null || isContractIdentifier(v);
const nullableRef = (v: unknown) => v === null || isArtifactRef(v);
const list = <T>(v: unknown, guard: (entry: unknown) => entry is T): v is T[] => Array.isArray(v) && v.length <= 128 && v.every(guard);
const effect = (v: unknown): v is RunEffectOutcome => ["not_dispatched", "confirmed", "not_applied", "partial", "unknown"].includes(v as string);
function principal(v: unknown): v is PrincipalRef {
  return hasExactKeys(v, ["principal_id", "principal_type", "trust_domain", "tenant_id"])
    && [v.principal_id, v.trust_domain, v.tenant_id].every(isContractIdentifier) && ["person", "workload", "agent"].includes(v.principal_type as string);
}
function intentFields(v: Record<string, unknown>): boolean {
  return [v.contract_id, v.run_id, v.tenant_id, v.operation_id, v.desired_effect].every(isContractIdentifier) && digest(v.action_digest)
    && isArtifactRef(v.adapter_ref) && isArtifactRef(v.capability_ref) && ["query", "idempotent_retry", "manual_reconcile", "no_retry"].includes(v.recovery_strategy as string)
    && nullableId(v.idempotency_key) && nullableId(v.idempotency_scope) && nullableRef(v.provider_idempotency_ref)
    && integer(v.max_attempts) && v.max_attempts > 0 && v.max_attempts <= 128 && list(v.retry_delays_seconds, integer)
    && v.retry_delays_seconds.length === v.max_attempts - 1 && isContractTimestamp(v.deadline) && nullableId(v.compensates_operation_id)
    && ((v.idempotency_key === null && v.idempotency_scope === null && v.provider_idempotency_ref === null)
      || (isContractIdentifier(v.idempotency_key) && isContractIdentifier(v.idempotency_scope) && isArtifactRef(v.provider_idempotency_ref)));
}
function validIntent(v: unknown): v is OperationIntent { return hasExactKeys(v, INTENT_KEYS) && intentFields(v); }
function attempt(v: unknown): v is OperationAttempt {
  return hasExactKeys(v, ["attempt_id", "operation_id", "executor_generation", "started_at", "dispatch_state", "last_observation_ref"])
    && isContractIdentifier(v.attempt_id) && isContractIdentifier(v.operation_id) && integer(v.executor_generation)
    && isContractTimestamp(v.started_at) && ["claimed", "dispatched", "settled"].includes(v.dispatch_state as string) && nullableRef(v.last_observation_ref);
}
function provider(v: unknown): v is ProviderIdempotencyObservation {
  return hasExactKeys(v, ["provider_contract_ref", "key", "scope", "operation_id", "action_digest", "same_payload_enforced",
    "verification_status", "observer", "evidence_ref", "observed_at", "valid_until", "not_before", "retention_expires_at"])
    && isArtifactRef(v.provider_contract_ref) && [v.key, v.scope, v.operation_id].every(isContractIdentifier) && digest(v.action_digest)
    && typeof v.same_payload_enforced === "boolean" && ["verified", "invalid", "unavailable"].includes(v.verification_status as string)
    && principal(v.observer) && isArtifactRef(v.evidence_ref)
    && [v.observed_at, v.valid_until, v.not_before, v.retention_expires_at].every(isContractTimestamp);
}
function claim(v: unknown): v is OperationClaim {
  return hasExactKeys(v, [...INTENT_KEYS, "attempt", "evaluation_time", "provider_observation"]) && intentFields(v)
    && attempt(v.attempt) && isContractTimestamp(v.evaluation_time) && (v.provider_observation === null || provider(v.provider_observation));
}
function observation(v: unknown): v is EffectObservation {
  return hasExactKeys(v, ["observation_id", "contract_id", "run_id", "tenant_id", "operation_id", "attempt_id", "action_digest",
    "executor_generation", "outcome", "finality", "external_ref", "evidence_ref", "verification_status", "observer", "observed_at", "valid_until", "evaluation_time"])
    && [v.observation_id, v.contract_id, v.run_id, v.tenant_id, v.operation_id, v.attempt_id].every(isContractIdentifier)
    && digest(v.action_digest) && integer(v.executor_generation) && effect(v.outcome) && ["definitive", "provisional"].includes(v.finality as string)
    && nullableId(v.external_ref) && isArtifactRef(v.evidence_ref) && ["verified", "invalid", "unavailable"].includes(v.verification_status as string)
    && principal(v.observer) && [v.observed_at, v.valid_until, v.evaluation_time].every(isContractTimestamp);
}
function record(v: unknown): v is OperationRecord {
  return hasExactKeys(v, ["intent", "attempts", "observations", "outcome", "next_eligible_at", "conflict"])
    && validIntent(v.intent) && list(v.attempts, attempt) && list(v.observations, observation) && effect(v.outcome)
    && (v.next_eligible_at === null || isContractTimestamp(v.next_eligible_at)) && typeof v.conflict === "boolean";
}
function validLedger(v: unknown): v is OperationLedger {
  if (!(hasExactKeys(v, ["ledger_id", "contract_id", "run_id", "tenant_id", "revision", "executor_generation", "deadline", "trusted_observers", "operations"])
    && [v.ledger_id, v.contract_id, v.run_id, v.tenant_id].every(isContractIdentifier) && integer(v.revision) && integer(v.executor_generation)
    && isContractTimestamp(v.deadline) && list(v.trusted_observers, principal) && list(v.operations, record)
    && new Set(v.operations.map(op => op.intent.operation_id)).size === v.operations.length)) return false;
  // The structural guards above establish this shape; now validate stored cross-record invariants.
  const ledger = v as unknown as OperationLedger;
  const attemptIds = ledger.operations.flatMap(op => op.attempts.map(a => a.attempt_id));
  const observationIds = ledger.operations.flatMap(op => op.observations.map(o => o.observation_id));
  if (new Set(attemptIds).size !== attemptIds.length || new Set(observationIds).size !== observationIds.length) return false;
  return ledger.operations.every(op => {
    const derived = deriveOutcome(op), due = retryEligibleAt(op);
    return correlation(ledger, op.intent) && derived.outcome === op.outcome && derived.conflict === op.conflict
      && (due === null ? op.next_eligible_at === null : op.next_eligible_at !== null && compareContractTimes(due, op.next_eligible_at) === 0)
      && op.attempts.length <= op.intent.max_attempts && op.attempts.every(a => a.operation_id === op.intent.operation_id && a.executor_generation <= ledger.executor_generation)
      && op.observations.every(o => o.operation_id === op.intent.operation_id && o.action_digest === op.intent.action_digest
        && o.contract_id === ledger.contract_id && o.run_id === ledger.run_id && o.tenant_id === ledger.tenant_id
        && op.attempts.some(a => a.attempt_id === o.attempt_id && a.executor_generation === o.executor_generation));
  });
}
function rejectOperation(ledger: OperationLedger, reason: string): TransitionResult<OperationLedger> {
  return { status: "rejected", state: ledger, reason_codes: [reason] };
}
function stableIntent(input: OperationClaim): OperationIntent {
  const { attempt: ignored, evaluation_time: ignoredTime, provider_observation: ignoredProvider, ...intent } = input;
  void ignored; void ignoredTime; void ignoredProvider;
  return intent;
}
function correlation(ledger: OperationLedger, intent: OperationIntent): boolean {
  return intent.contract_id === ledger.contract_id && intent.run_id === ledger.run_id && intent.tenant_id === ledger.tenant_id
    && compareContractTimes(intent.deadline, ledger.deadline) !== 1;
}
function trusted(ledger: OperationLedger, observed: { observer: PrincipalRef; verification_status: VerificationStatus;
  observed_at: string; valid_until: string }, time: string): boolean {
  return observed.verification_status === "verified" && observed.observer.tenant_id === ledger.tenant_id
    && ledger.trusted_observers.some(observer => same(observer, observed.observer))
    && isWithinContractInterval(time, observed.observed_at, observed.valid_until);
}
function deriveOutcome(op: OperationRecord): { outcome: RunEffectOutcome; conflict: boolean } {
  let confirmed = false, partial = false, uncertain = false, notApplied = false, conflict = op.conflict;
  for (const current of op.attempts) {
    const facts = op.observations.filter(o => o.attempt_id === current.attempt_id);
    const definitive = facts.filter(o => o.finality === "definitive" && o.outcome !== "unknown");
    const applied = definitive.some(o => o.outcome === "confirmed" || o.outcome === "partial");
    const absent = definitive.some(o => o.outcome === "not_applied" || o.outcome === "not_dispatched");
    if (applied && absent) conflict = true;
    confirmed ||= definitive.some(o => o.outcome === "confirmed");
    partial ||= definitive.some(o => o.outcome === "partial");
    notApplied ||= definitive.some(o => o.outcome === "not_applied");
    if (!definitive.length && facts.length > 0) uncertain = true;
  }
  return { conflict, outcome: conflict ? "unknown" : confirmed ? "confirmed" : partial ? "partial"
    : uncertain ? "unknown" : notApplied ? "not_applied" : "not_dispatched" };
}
function retryEligibleAt(op: OperationRecord): string | null {
  const last = op.attempts.at(-1), facts = op.observations.filter(o => o.attempt_id === last?.attempt_id);
  const latest = [...facts].sort((a, b) => compareContractTimes(b.observed_at, a.observed_at) ?? 0)[0];
  const delay = op.intent.retry_delays_seconds[op.attempts.length - 1];
  const eligible = latest && delay !== undefined ? addContractSeconds(latest.observed_at, delay) : undefined;
  return eligible && compareContractTimes(eligible, op.intent.deadline) === -1 ? eligible : null;
}

/** Persists a claim intent only; current authorization and target-side fencing remain mandatory before dispatch. */
export function claimOperation(ledger: OperationLedger, input: OperationClaim, expectedRevision: number, executorGeneration: number): TransitionResult<OperationLedger> {
  try { canonicalizeJson(ledger); canonicalizeJson(input); } catch { return rejectOperation(ledger, "operation_binding_mismatch"); }
  if (!validLedger(ledger) || !claim(input) || !integer(expectedRevision) || !integer(executorGeneration)) return rejectOperation(ledger, "operation_binding_mismatch");
  if (ledger.revision !== expectedRevision) return rejectOperation(ledger, "revision_conflict");
  if (ledger.executor_generation !== executorGeneration || input.attempt.executor_generation !== executorGeneration) return rejectOperation(ledger, "executor_stale");
  if (!correlation(ledger, input) || input.attempt.operation_id !== input.operation_id || input.attempt.dispatch_state !== "claimed"
    || input.attempt.last_observation_ref !== null || compareContractTimes(input.attempt.started_at, input.evaluation_time) !== 0) return rejectOperation(ledger, "operation_binding_mismatch");
  if (compareContractTimes(input.evaluation_time, input.deadline) !== -1) return rejectOperation(ledger, "deadline_exceeded");
  const intent = stableIntent(input), existing = ledger.operations.find(op => op.intent.operation_id === intent.operation_id);
  if (ledger.operations.some(op => op.intent.operation_id !== intent.operation_id
    && op.attempts.some(a => a.attempt_id === input.attempt.attempt_id))) return rejectOperation(ledger, "operation_binding_mismatch");
  if (existing && !same(existing.intent, intent)) return rejectOperation(ledger, "operation_binding_mismatch");
  if (ledger.operations.some(op => op.intent.operation_id !== intent.operation_id && intent.idempotency_key !== null
    && op.intent.idempotency_key === intent.idempotency_key && op.intent.idempotency_scope === intent.idempotency_scope
    && same(op.intent.provider_idempotency_ref, intent.provider_idempotency_ref))) return rejectOperation(ledger, "operation_binding_mismatch");
  if (intent.compensates_operation_id !== null) {
    const original = ledger.operations.find(op => op.intent.operation_id === intent.compensates_operation_id);
    if (!original || original.intent.operation_id === intent.operation_id || !["confirmed", "partial"].includes(deriveOutcome(original).outcome)
      || original.intent.action_digest === intent.action_digest) return rejectOperation(ledger, "operation_binding_mismatch");
  }
  if (intent.recovery_strategy === "idempotent_retry") {
    const proof = input.provider_observation;
    if (!proof || !trusted(ledger, proof, input.evaluation_time) || !proof.same_payload_enforced
      || !same(proof.provider_contract_ref, intent.provider_idempotency_ref) || proof.key !== intent.idempotency_key
      || proof.scope !== intent.idempotency_scope || proof.operation_id !== intent.operation_id || proof.action_digest !== intent.action_digest
      || !isWithinContractInterval(input.evaluation_time, proof.not_before, proof.retention_expires_at)) return rejectOperation(ledger, "retry_unsafe");
  }
  if (existing) {
    const derived = deriveOutcome(existing);
    if (derived.conflict || derived.outcome === "confirmed" || derived.outcome === "partial") return rejectOperation(ledger, "retry_unsafe");
    if (derived.outcome === "unknown" && intent.recovery_strategy !== "idempotent_retry") return rejectOperation(ledger, "retry_unsafe");
    const duplicate = existing.attempts.find(a => a.attempt_id === input.attempt.attempt_id);
    if (duplicate) {
      if (duplicate.dispatch_state !== "claimed" || duplicate.executor_generation !== executorGeneration
        || compareContractTimes(duplicate.started_at, input.attempt.started_at) !== 0) return rejectOperation(ledger, "operation_binding_mismatch");
      return { status: "accepted", state: ledger, obligations: ["obtain_current_authorization", "recover_existing_claim"] };
    }
    if (existing.attempts.length >= intent.max_attempts || intent.recovery_strategy === "no_retry") return rejectOperation(ledger, "retry_unsafe");
    if (existing.attempts.at(-1)?.dispatch_state === "claimed") return rejectOperation(ledger, "operation_in_flight");
    if (!existing.next_eligible_at || compareContractTimes(input.evaluation_time, existing.next_eligible_at) === -1) return rejectOperation(ledger, "retry_not_due");
  }
  if (!integer(ledger.revision + 1) || (!existing && ledger.operations.length >= 128)) return rejectOperation(ledger, "operation_ledger_limit");
  const next = structuredClone(ledger), index = next.operations.findIndex(op => op.intent.operation_id === intent.operation_id);
  const op = index < 0 ? { intent: structuredClone(intent), attempts: [], observations: [], outcome: "not_dispatched" as RunEffectOutcome,
    next_eligible_at: null, conflict: false } : next.operations[index];
  op.attempts.push(structuredClone(input.attempt)); op.next_eligible_at = null;
  if (index < 0) next.operations.push(op);
  next.revision += 1;
  return { status: "accepted", state: next, obligations: ["enforce_provider_fence", "obtain_current_authorization",
    "persist_operation_claim", ...(input.provider_observation ? ["record_provider_idempotency_evidence"] : [])].sort() };
}

/** Appends verified facts, including late facts; never transfers executor ownership or settles budgets. */
export function recordEffectObservation(ledger: OperationLedger, observed: EffectObservation, expectedRevision: number): TransitionResult<OperationLedger> {
  try { canonicalizeJson(ledger); canonicalizeJson(observed); } catch { return rejectOperation(ledger, "operation_binding_mismatch"); }
  if (!validLedger(ledger) || !observation(observed) || !integer(expectedRevision)) return rejectOperation(ledger, "operation_binding_mismatch");
  if (ledger.revision !== expectedRevision) return rejectOperation(ledger, "revision_conflict");
  const index = ledger.operations.findIndex(op => op.intent.operation_id === observed.operation_id), op = ledger.operations[index];
  const attempted = op?.attempts.find(a => a.attempt_id === observed.attempt_id);
  if (!op || !attempted || !correlation(ledger, op.intent) || observed.contract_id !== ledger.contract_id || observed.run_id !== ledger.run_id
    || observed.tenant_id !== ledger.tenant_id || observed.action_digest !== op.intent.action_digest
    || observed.executor_generation !== attempted.executor_generation || compareContractTimes(observed.observed_at, attempted.started_at) === -1
    || !trusted(ledger, observed, observed.evaluation_time)) return rejectOperation(ledger, "operation_binding_mismatch");
  const duplicate = ledger.operations.flatMap(operation => operation.observations).find(o => o.observation_id === observed.observation_id);
  if (duplicate) return same(duplicate, observed) ? { status: "accepted", state: ledger, obligations: ["observation_already_recorded"] }
    : rejectOperation(ledger, "observation_binding_mismatch");
  if (!integer(ledger.revision + 1) || op.observations.length >= 128) return rejectOperation(ledger, "operation_ledger_limit");
  const next = structuredClone(ledger), updated = next.operations[index];
  updated.observations.push(structuredClone(observed));
  const target = updated.attempts.find(a => a.attempt_id === observed.attempt_id)!;
  const facts = updated.observations.filter(o => o.attempt_id === target.attempt_id);
  const final = facts.filter(o => o.finality === "definitive" && o.outcome !== "unknown");
  const latest = [...(final.length ? final : facts)].sort((a, b) => compareContractTimes(b.observed_at, a.observed_at)
    || (a.observation_id < b.observation_id ? -1 : a.observation_id > b.observation_id ? 1 : 0))[0];
  target.last_observation_ref = { ...latest.evidence_ref };
  target.dispatch_state = final.length ? "settled" : "dispatched";
  const derived = deriveOutcome(updated); updated.outcome = derived.outcome; updated.conflict = derived.conflict;
  updated.next_eligible_at = retryEligibleAt(updated);
  next.revision += 1;
  const obligations = new Set<string>(["persist_effect_observation", "verify_usage_before_settlement"]);
  if (observed.executor_generation !== ledger.executor_generation) obligations.add("late_fact_no_dispatch");
  if (updated.conflict) obligations.add("escalate_conflicting_effect_evidence");
  else if (updated.outcome === "unknown" || updated.outcome === "partial") {
    obligations.add(updated.intent.recovery_strategy === "query" ? "query_external_outcome" : "manual_reconcile_effect");
  }
  return { status: "accepted", state: next, obligations: [...obligations].sort() };
}
