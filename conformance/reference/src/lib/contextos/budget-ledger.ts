import { canonicalizeJson, sha256Canonical } from "./canonical-json";
import { compareContractTimes, hasExactKeys, isArtifactRef, isContractIdentifier,
  isContractTimestamp, isWithinContractInterval } from "./contract-validation";
import type { ArtifactRef } from "./execution-contract-types";
import type { PrincipalRef, VerificationStatus } from "./authorization";
import type { CostAccountingUnit, ResourceCounters, TransitionResult } from "./durable-execution";

export type CostUnitConversion = { status: "converted"; units: number }
  | { status: "rejected"; reason_code: "cost_precision_unsupported" | "budget_accounting_invalid" };
export interface BudgetReservationRecord {
  reservation_id: string; run_id: string; scope: "run" | "child"; allocation: ResourceCounters;
  used: ResourceCounters; status: "reserved" | "usage_unknown" | "settled"; deadline: string; settlement_ref: ArtifactRef | null;
}
export interface BudgetMutationReceipt {
  mutation_id: string; kind: "reserve" | "settle"; request_digest: string; reservation_id: string;
  result_revision: number; allocated: ResourceCounters; charged: ResourceCounters; released: ResourceCounters;
}
export interface BudgetLedger {
  ledger_id: string; contract_id: string; parent_run_id: string; tenant_id: string; revision: number;
  executor_generation: number; deadline: string; cost_unit: CostAccountingUnit;
  original_limits: { tokens: number; tool_calls: number; replans: number; cost_cents: number };
  original_limits_ref: ArtifactRef; opening_usage: ResourceCounters; opening_usage_ref: ArtifactRef;
  ceiling: ResourceCounters; used: ResourceCounters; reserved: ResourceCounters;
  unknown_usage_policy: "retain_reservation"; mutations: BudgetMutationReceipt[];
  trusted_observers: PrincipalRef[]; reservations: BudgetReservationRecord[];
}
interface BudgetRequest {
  ledger_id: string; contract_id: string; parent_run_id: string; tenant_id: string; mutation_id: string;
  reservation_id: string; scope: "run" | "child"; run_id: string; cost_unit: CostAccountingUnit;
  expected_revision: number; executor_generation: number; evaluation_time: string;
}
export interface BudgetReservationRequest extends BudgetRequest { allocation: ResourceCounters; deadline: string }
export interface BudgetSettlementRequest extends BudgetRequest {
  usage: ResourceCounters; usage_status: "known" | "unknown"; execution_status: "running" | "completed" | "cancelled" | "unknown";
  usage_observation: { intent_digest: string; verification_status: VerificationStatus; observer: PrincipalRef;
    evidence_ref: ArtifactRef; observed_at: string; valid_until: string };
}
const KEYS = ["tokens", "tool_calls", "replans", "cost_units"] as const;
const BASE_KEYS = ["ledger_id", "contract_id", "parent_run_id", "tenant_id", "mutation_id", "reservation_id", "scope", "run_id",
  "cost_unit", "expected_revision", "executor_generation", "evaluation_time"];
const integer = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) >= 0;
const hash = (value: unknown): value is string => typeof value === "string" && /^sha256:[a-f0-9]{64}$/.test(value);
const zero = (): ResourceCounters => ({ tokens: 0, tool_calls: 0, replans: 0, cost_units: 0 });
const same = (a: unknown, b: unknown) => canonicalizeJson(a) === canonicalizeJson(b);
const bounded = <T>(v: unknown, check: (v: unknown) => v is T): v is T[] => Array.isArray(v) && v.length <= 128 && v.every(check);
function counters(value: unknown): value is ResourceCounters {
  return hasExactKeys(value, KEYS) && KEYS.every(key => integer(value[key]));
}
function unit(value: unknown): value is CostAccountingUnit {
  return hasExactKeys(value, ["currency", "units_per_cent"]) && typeof value.currency === "string"
    && /^[A-Z]{3}$/.test(value.currency) && integer(value.units_per_cent) && /^10*$/.test(String(value.units_per_cent));
}
function principal(value: unknown): value is PrincipalRef {
  return hasExactKeys(value, ["principal_id", "principal_type", "trust_domain", "tenant_id"])
    && [value.principal_id, value.trust_domain, value.tenant_id].every(isContractIdentifier)
    && ["person", "agent", "workload"].includes(value.principal_type as string);
}
/** Exact decimal conversion of the existing number field; never rounds a spending limit or charge. */
export function convertLegacyCostToUnits(value: number, costUnit: CostAccountingUnit): CostUnitConversion {
  const invalid: CostUnitConversion = { status: "rejected", reason_code: "budget_accounting_invalid" };
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || !unit(costUnit)) return invalid;
  const match = /^(\d+)(?:\.(\d+))?(?:e([+-]?\d+))?$/.exec(JSON.stringify(value));
  if (!match) return invalid;
  const coefficient = BigInt(match[1] + (match[2] ?? ""));
  const exponent = Number(match[3] ?? 0) - (match[2]?.length ?? 0) + String(costUnit.units_per_cent).length - 1;
  let units: bigint;
  if (exponent >= 0) units = coefficient * BigInt(10) ** BigInt(exponent);
  else {
    const divisor = BigInt(10) ** BigInt(-exponent);
    if (coefficient % divisor !== BigInt(0)) return { status: "rejected", reason_code: "cost_precision_unsupported" };
    units = coefficient / divisor;
  }
  return units > BigInt(Number.MAX_SAFE_INTEGER) ? invalid : { status: "converted", units: Number(units) };
}
function scope(value: Record<string, unknown>): boolean {
  return value.scope === "run" ? value.run_id === value.parent_run_id : value.scope === "child" && value.run_id !== value.parent_run_id;
}
function reservation(value: unknown): value is BudgetReservationRecord {
  if (!hasExactKeys(value, ["reservation_id", "run_id", "scope", "allocation", "used", "status", "deadline", "settlement_ref"])
    || !counters(value.allocation) || !counters(value.used)) return false;
  const allocation = value.allocation, used = value.used;
  return [value.reservation_id, value.run_id].every(isContractIdentifier) && ["run", "child"].includes(value.scope as string)
    && KEYS.every(key => used[key] <= allocation[key])
    && ["reserved", "usage_unknown", "settled"].includes(value.status as string) && isContractTimestamp(value.deadline)
    && (value.settlement_ref === null || isArtifactRef(value.settlement_ref))
    && (value.status !== "settled" || value.settlement_ref !== null);
}
function receipt(value: unknown): value is BudgetMutationReceipt {
  return hasExactKeys(value, ["mutation_id", "kind", "request_digest", "reservation_id", "result_revision", "allocated", "charged", "released"])
    && [value.mutation_id, value.reservation_id].every(isContractIdentifier) && ["reserve", "settle"].includes(value.kind as string)
    && hash(value.request_digest) && integer(value.result_revision) && counters(value.allocated) && counters(value.charged) && counters(value.released);
}
function identity(ledger: BudgetLedger) {
  return { ledger_id: ledger.ledger_id, contract_id: ledger.contract_id, parent_run_id: ledger.parent_run_id,
    tenant_id: ledger.tenant_id, cost_unit: ledger.cost_unit };
}
function validLedger(value: unknown): value is BudgetLedger {
  if (!hasExactKeys(value, ["ledger_id", "contract_id", "parent_run_id", "tenant_id", "revision", "executor_generation", "deadline", "cost_unit",
    "original_limits", "original_limits_ref", "opening_usage", "opening_usage_ref", "ceiling", "used", "reserved", "unknown_usage_policy",
    "mutations", "trusted_observers", "reservations"]) || ![value.ledger_id, value.contract_id, value.parent_run_id, value.tenant_id].every(isContractIdentifier)
    || !integer(value.revision) || !integer(value.executor_generation) || !isContractTimestamp(value.deadline) || !unit(value.cost_unit)
    || !hasExactKeys(value.original_limits, ["tokens", "tool_calls", "replans", "cost_cents"])
    || ![value.original_limits.tokens, value.original_limits.tool_calls, value.original_limits.replans].every(integer)
    || !isArtifactRef(value.original_limits_ref) || !isArtifactRef(value.opening_usage_ref)
    || !counters(value.opening_usage) || !counters(value.ceiling) || !counters(value.used) || !counters(value.reserved)
    || value.unknown_usage_policy !== "retain_reservation" || !bounded(value.reservations, reservation) || !bounded(value.mutations, receipt)
    || !bounded(value.trusted_observers, principal) || value.trusted_observers.length === 0) return false;
  const ledger = value as unknown as BudgetLedger;
  const cost = convertLegacyCostToUnits(ledger.original_limits.cost_cents, ledger.cost_unit);
  if (cost.status !== "converted" || cost.units !== ledger.ceiling.cost_units
    || ["tokens", "tool_calls", "replans"].some(key => ledger.original_limits[key as "tokens"] !== ledger.ceiling[key as "tokens"])) return false;
  if (ledger.original_limits_ref.sha256 !== sha256Canonical({ domain: "contextos.budget_limits.v1",
    payload: { ...identity(ledger), original_limits: ledger.original_limits, deadline: ledger.deadline } })
    || ledger.opening_usage_ref.sha256 !== sha256Canonical({ domain: "contextos.budget_opening.v1",
      payload: { ...identity(ledger), opening_usage: ledger.opening_usage } })) return false;
  if (new Set(ledger.reservations.map(r => r.reservation_id)).size !== ledger.reservations.length
    || new Set(ledger.mutations.map(r => r.mutation_id)).size !== ledger.mutations.length
    || ledger.trusted_observers.some(p => p.tenant_id !== ledger.tenant_id)) return false;
  if (ledger.reservations.some(r => !scope({ ...r, parent_run_id: ledger.parent_run_id })
    || compareContractTimes(r.deadline, ledger.deadline) === 1)) return false;
  if (ledger.mutations.some(r => r.result_revision > ledger.revision || !ledger.reservations.some(s => s.reservation_id === r.reservation_id))) return false;
  return KEYS.every(key => {
    const used = ledger.reservations.reduce((n, r) => n + BigInt(r.used[key]), BigInt(ledger.opening_usage[key]));
    const reserved = ledger.reservations.reduce((n, r) => n + (r.status === "settled" ? BigInt(0) : BigInt(r.allocation[key]) - BigInt(r.used[key])), BigInt(0));
    return used === BigInt(ledger.used[key]) && reserved === BigInt(ledger.reserved[key]) && used + reserved <= BigInt(ledger.ceiling[key]);
  });
}
function baseRequest(value: Record<string, unknown>): boolean {
  return [value.ledger_id, value.contract_id, value.parent_run_id, value.tenant_id, value.mutation_id, value.reservation_id, value.run_id].every(isContractIdentifier)
    && scope(value) && unit(value.cost_unit) && integer(value.expected_revision) && integer(value.executor_generation) && isContractTimestamp(value.evaluation_time);
}
function reserveRequest(value: unknown): value is BudgetReservationRequest {
  return hasExactKeys(value, [...BASE_KEYS, "allocation", "deadline"]) && baseRequest(value) && counters(value.allocation) && isContractTimestamp(value.deadline);
}
function settleRequest(value: unknown): value is BudgetSettlementRequest {
  return hasExactKeys(value, [...BASE_KEYS, "usage", "usage_status", "execution_status", "usage_observation"]) && baseRequest(value)
    && counters(value.usage) && ["known", "unknown"].includes(value.usage_status as string)
    && ["running", "completed", "cancelled", "unknown"].includes(value.execution_status as string)
    && hasExactKeys(value.usage_observation, ["intent_digest", "verification_status", "observer", "evidence_ref", "observed_at", "valid_until"])
    && hash(value.usage_observation.intent_digest) && ["verified", "invalid", "unavailable"].includes(value.usage_observation.verification_status as string)
    && principal(value.usage_observation.observer) && isArtifactRef(value.usage_observation.evidence_ref)
    && isContractTimestamp(value.usage_observation.observed_at) && isContractTimestamp(value.usage_observation.valid_until);
}
function semanticRequest(request: BudgetRequest) {
  const { expected_revision, executor_generation, evaluation_time, ...body } = request;
  void expected_revision; void executor_generation; void evaluation_time; return body;
}
function reject(state: BudgetLedger, reason: string): TransitionResult<BudgetLedger> { return { status: "rejected", state, reason_codes: [reason] }; }
function prepare(ledger: BudgetLedger, request: BudgetRequest, kind: "reserve" | "settle", terminal = false): TransitionResult<BudgetLedger> | undefined {
  if (["ledger_id", "contract_id", "parent_run_id", "tenant_id"].some(key => ledger[key as "ledger_id"] !== request[key as "ledger_id"])
    || !same(ledger.cost_unit, request.cost_unit)) return reject(ledger, "budget_accounting_invalid");
  const digest = sha256Canonical({ domain: "contextos.budget_mutation.v1", kind, body: semanticRequest(request) });
  const previous = ledger.mutations.find(m => m.mutation_id === request.mutation_id);
  // Read-only recovery returns the original receipt in the CURRENT ledger, even after later mutations.
  if (previous) return previous.kind === kind && previous.request_digest === digest
    ? { status: "accepted", state: ledger, obligations: ["use_original_mutation_receipt"] } : reject(ledger, "mutation_conflict");
  if (request.expected_revision !== ledger.revision) return reject(ledger, "revision_conflict");
  if (request.executor_generation !== ledger.executor_generation) return reject(ledger, "executor_stale");
  // Every open reservation retains room for one verified terminal settlement.
  const pendingAfter = ledger.reservations.filter(record => record.status !== "settled").length
    + (kind === "reserve" ? 1 : terminal ? -1 : 0);
  if (!integer(ledger.revision + 1 + pendingAfter) || ledger.mutations.length + 1 + pendingAfter > 128)
    return reject(ledger, "counter_exhausted");
}
function finish(ledger: BudgetLedger, request: BudgetRequest, kind: "reserve" | "settle", allocated: ResourceCounters,
  charged: ResourceCounters, released: ResourceCounters): TransitionResult<BudgetLedger> {
  ledger.revision += 1;
  ledger.mutations.push({ mutation_id: request.mutation_id, kind, request_digest: sha256Canonical({ domain: "contextos.budget_mutation.v1", kind,
    body: semanticRequest(request) }), reservation_id: request.reservation_id, result_revision: ledger.revision, allocated, charged, released });
  return { status: "accepted", state: ledger, obligations: ["persist_budget_with_revision_and_executor_fence", "obtain_current_authorization_before_spending"] };
}
/** Intended CAS reservation; its persisted capacity does not grant action authority. */
export function reserveBudget(ledger: BudgetLedger, request: BudgetReservationRequest): TransitionResult<BudgetLedger> {
  try { canonicalizeJson(ledger); canonicalizeJson(request); } catch { return reject(ledger, "budget_accounting_invalid"); }
  if (!validLedger(ledger) || !reserveRequest(request)) return reject(ledger, "budget_accounting_invalid");
  const prior = prepare(ledger, request, "reserve"); if (prior) return prior;
  if (compareContractTimes(request.deadline, ledger.deadline) === 1 || compareContractTimes(request.evaluation_time, request.deadline) !== -1
    || compareContractTimes(request.evaluation_time, ledger.deadline) !== -1) return reject(ledger, "deadline_exceeded");
  if (ledger.reservations.length >= 128 || ledger.reservations.some(r => r.reservation_id === request.reservation_id)) return reject(ledger, "reservation_conflict");
  if (KEYS.some(key => request.allocation[key] > ledger.ceiling[key] - ledger.used[key] - ledger.reserved[key])) return reject(ledger, "budget_exhausted");
  const next = structuredClone(ledger);
  next.reservations.push({ reservation_id: request.reservation_id, run_id: request.run_id, scope: request.scope,
    allocation: structuredClone(request.allocation), used: zero(), status: "reserved", deadline: request.deadline, settlement_ref: null });
  KEYS.forEach(key => { next.reserved[key] += request.allocation[key]; });
  return finish(next, request, "reserve", structuredClone(request.allocation), zero(), zero());
}
/** Cumulative, verified accounting. Unknown usage retains capacity; terminal known usage releases the remainder. */
export function settleBudget(ledger: BudgetLedger, request: BudgetSettlementRequest): TransitionResult<BudgetLedger> {
  try { canonicalizeJson(ledger); canonicalizeJson(request); } catch { return reject(ledger, "budget_accounting_invalid"); }
  if (!validLedger(ledger) || !settleRequest(request)) return reject(ledger, "budget_accounting_invalid");
  const terminal = request.usage_status === "known" && ["completed", "cancelled"].includes(request.execution_status);
  const prior = prepare(ledger, request, "settle", terminal); if (prior) return prior;
  const reserved = ledger.reservations.find(r => r.reservation_id === request.reservation_id);
  if (!reserved || reserved.status === "settled" || reserved.scope !== request.scope || reserved.run_id !== request.run_id) return reject(ledger, "reservation_conflict");
  const { usage_observation: observation, ...withTransport } = request;
  const intent = semanticRequest(withTransport);
  if (observation.verification_status !== "verified" || !ledger.trusted_observers.some(p => same(p, observation.observer))
    || !isWithinContractInterval(request.evaluation_time, observation.observed_at, observation.valid_until)
    || observation.intent_digest !== sha256Canonical({ domain: "contextos.budget_settlement_intent.v1", intent })) return reject(ledger, "usage_unverified");
  if (KEYS.some(key => request.usage[key] < reserved.used[key] || request.usage[key] > reserved.allocation[key])) return reject(ledger, "budget_accounting_invalid");
  const next = structuredClone(ledger), record = next.reservations.find(r => r.reservation_id === request.reservation_id)!;
  const charged = zero(), released = zero();
  KEYS.forEach(key => {
    charged[key] = request.usage[key] - record.used[key];
    released[key] = terminal ? record.allocation[key] - request.usage[key] : 0;
    next.used[key] += charged[key]; next.reserved[key] -= charged[key] + released[key];
  });
  record.used = structuredClone(request.usage); record.settlement_ref = structuredClone(observation.evidence_ref);
  record.status = terminal ? "settled" : request.usage_status === "unknown" ? "usage_unknown" : "reserved";
  return finish(next, request, "settle", zero(), charged, released);
}
export function reserveChildBudget(ledger: BudgetLedger, request: BudgetReservationRequest): TransitionResult<BudgetLedger> {
  return reserveRequest(request) && request.scope === "child" ? reserveBudget(ledger, request) : reject(ledger, "budget_scope_invalid");
}
export function settleChildBudget(ledger: BudgetLedger, request: BudgetSettlementRequest): TransitionResult<BudgetLedger> {
  return settleRequest(request) && request.scope === "child" ? settleBudget(ledger, request) : reject(ledger, "budget_scope_invalid");
}
