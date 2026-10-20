import { test } from "vitest";
import { writeFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import path from "node:path";
import { transitionRun, validateResume } from "@ref/durable-execution";
import { claimOperation, recordEffectObservation } from "@ref/operation-ledger";
import { convertLegacyCostToUnits, reserveBudget, settleBudget, reserveChildBudget, settleChildBudget } from "@ref/budget-ledger";
import { runFixture, operationFixture, checkpointFixture, addressCheckpoint, budgetFixture, childReservation,
  childSettlement, bindBudgetUsage, fixtureArtifact } from "@fixtures/execution-contract";
import { mutate, rng } from "./mutate";

const out = path.resolve(import.meta.dirname, "../vectors");
const json = <T>(v: T): T => JSON.parse(JSON.stringify(v));
function call(fn: () => unknown) { try { return fn(); } catch (e: any) { return { throws: String(e.message) }; } }

const STATUSES = ["created", "running", "waiting_approval", "waiting_external", "suspended", "cancel_requested", "completed", "failed", "cancelled", "expired"];
const KINDS = ["start", "resume", "wait_approval", "wait_external", "suspend", "request_cancel", "acknowledge_cancel", "complete", "fail", "expire"];

function event(state: any, kind: string, opts: { checks?: any; stop?: any } = {}) {
  const obs = { run_id: state.run_id, tenant_id: state.tenant_id, executor_generation: state.executor_generation,
    observer: state.trusted_observer, verification_status: "verified", evidence_ref: fixtureArtifact("run_observation", "obs"),
    observed_at: "2026-10-16T07:59:00Z", valid_until: "2026-10-16T09:30:00Z" };
  return { event_id: `event_${kind}`, run_id: state.run_id, tenant_id: state.tenant_id, kind, expected_revision: state.revision,
    executor_generation: state.executor_generation,
    preconditions: ["start", "resume"].includes(kind) ? { ...obs, admission_ref: state.admission_ref,
      checks: { admission: "ready", authority: "ready", boundary: "ready", budget: "ready", ...(opts.checks ?? {}) } } : null,
    dispatch_stop_ack: kind === "acknowledge_cancel" ? { ...obs, child_run_ids: [...state.child_run_ids], dispatch_stopped: true,
      children_stop_recorded: true, ...(opts.stop ?? {}) } : null };
}

test("durable execution vectors", () => {
  const rand = rng(31337);
  const runs: unknown[] = [], ops: unknown[] = [], resumes: unknown[] = [], budgets: unknown[] = [], costs: unknown[] = [];
  const run = (name: string, state: any, ev: any, time: string) => { const input = json({ state, event: ev, evaluation_time: time });
    runs.push({ name, input, expected: call(() => transitionRun(json(input.state), json(input.event), input.evaluation_time)) }); };
  for (const status of STATUSES) for (const kind of KINDS) for (const time of ["2026-10-16T08:00:00Z", "2026-10-16T09:00:00Z"]) {
    const s: any = runFixture(); s.status = status;
    run(`grid:${status}:${kind}:${time}`, s, event(s, kind), time);
  }
  const semantic: [string, (s: any) => void, (e: any) => void, string?][] = [
    ["complete_unconfirmed", (s) => { s.outstanding_effects = [{ operation_id: "op", outcome: "unknown" }]; }, () => {}],
    ["complete_confirmed", (s) => { s.outstanding_effects = [{ operation_id: "op", outcome: "confirmed" }]; }, () => {}],
    ["complete_children", (s) => { s.child_run_ids = ["child_1"]; }, () => {}],
    ["fail_with_partial", (s) => { s.outstanding_effects = [{ operation_id: "op", outcome: "partial" }]; }, (e) => { e.kind = "fail"; e.event_id = "e_fail"; }],
    ["stale_revision", () => {}, (e) => { e.expected_revision = 0; }],
    ["stale_generation", () => {}, (e) => { e.executor_generation = 2; }],
    ["wrong_tenant", () => {}, (e) => { e.tenant_id = "other"; }],
  ];
  for (const [n, es, ee] of semantic) { const s: any = runFixture(); es(s); const e: any = event(s, "complete"); ee(e); run(`semantic:${n}`, s, e, "2026-10-16T08:00:00Z"); }
  for (const [n, checks] of [["admission", { admission: "blocked" }], ["authority", { authority: "unknown" }], ["boundary", { boundary: "blocked" }], ["budget", { budget: "blocked" }]] as const) {
    const s: any = runFixture(); s.status = "suspended"; run(`resume_blocked:${n}`, s, event(s, "resume", { checks }), "2026-10-16T08:00:00Z");
  }
  { const s: any = runFixture(); s.status = "suspended"; const e: any = event(s, "resume"); e.preconditions.admission_ref = fixtureArtifact("run_admission", "other"); run("resume_admission_ref", s, e, "2026-10-16T08:00:00Z"); }
  { const s: any = runFixture(); s.status = "suspended"; const e: any = event(s, "resume"); e.preconditions.valid_until = "2026-10-16T07:59:30Z"; run("resume_stale_obs", s, e, "2026-10-16T08:00:00Z"); }
  for (const [n, stop] of [["not_stopped", { dispatch_stopped: false }], ["children_unrecorded", { children_stop_recorded: false }], ["child_mismatch", { child_run_ids: ["x"] }]] as const) {
    const s: any = runFixture(); s.status = "cancel_requested"; s.child_run_ids = ["child_a", "child_b"];
    run(`cancel_ack:${n}`, s, event(s, "acknowledge_cancel", { stop }), "2026-10-16T08:00:00Z");
  }
  { const s: any = runFixture(); s.status = "cancel_requested"; s.child_run_ids = ["child_b", "child_a"]; const e: any = event(s, "acknowledge_cancel"); e.dispatch_stop_ack.child_run_ids = ["child_a", "child_b"]; run("cancel_ack_sorted", s, e, "2026-10-16T08:00:00Z"); }
  { const s: any = runFixture(); s.revision = 9007199254740991; run("counter_exhausted", s, event(s, "suspend"), "2026-10-16T08:00:00Z"); }
  for (let i = 0; i < 500; i++) { const s: any = runFixture(); s.status = STATUSES[i % 6]; const kind = KINDS[i % KINDS.length];
    const m: any = mutate({ state: s, event: event(s, kind), evaluation_time: "2026-10-16T08:00:00Z" }, rand);
    run(`mutation:${i}`, m.state, m.event, m.evaluation_time); }

  // Operation ledger: claim → observe → retry chains.
  const claim = (name: string, ledger: any, intent: any, rev: number, gen: number) => { const input = json({ ledger, intent, expected_revision: rev, executor_generation: gen });
    const expected: any = call(() => claimOperation(json(input.ledger), json(input.intent), input.expected_revision, input.executor_generation));
    ops.push({ name, op: "claim", input, expected }); return expected; };
  const observe = (name: string, ledger: any, observation: any, rev: number) => { const input = json({ ledger, observation, expected_revision: rev });
    const expected: any = call(() => recordEffectObservation(json(input.ledger), json(input.observation), input.expected_revision));
    ops.push({ name, op: "observe", input, expected }); return expected; };
  const f: any = operationFixture();
  const empty = { ...json(f.ledger), operations: [] };
  const first = claim("fresh_claim", empty, f.intent, 1, 3);
  observe("timeout", f.ledger, f.observation, 1);
  const outcomes: [string, string, string][] = [["confirmed", "definitive", "c"], ["not_applied", "definitive", "n"], ["partial", "definitive", "p"], ["unknown", "provisional", "u"], ["not_dispatched", "definitive", "d"]];
  for (const [outcome, finality, tag] of outcomes) {
    const o = { ...json(f.observation), observation_id: `obs_${tag}`, outcome, finality };
    const r: any = observe(`observe:${outcome}`, f.ledger, o, 1);
    if (r.status !== "accepted") continue;
    const retry = { ...json(f.intent), attempt: { ...json(f.intent.attempt), attempt_id: `attempt_retry_${tag}`, started_at: "2026-10-16T08:00:06Z" }, evaluation_time: "2026-10-16T08:00:06Z" };
    claim(`retry_after:${outcome}`, r.state, retry, 2, 3);
    const early = { ...json(retry), attempt: { ...retry.attempt, started_at: "2026-10-16T08:00:03Z" }, evaluation_time: "2026-10-16T08:00:03Z" };
    claim(`retry_early:${outcome}`, r.state, early, 2, 3);
    const conflicting = { ...json(o), observation_id: `obs_conflict_${tag}`, outcome: outcome === "confirmed" ? "not_applied" : "confirmed", finality: "definitive", observed_at: "2026-10-16T08:00:02Z", evaluation_time: "2026-10-16T08:00:02Z" };
    const c: any = observe(`conflict_after:${outcome}`, r.state, conflicting, 2);
    observe(`duplicate:${outcome}`, r.state, o, 2);
    observe(`duplicate_changed:${outcome}`, r.state, { ...o, external_ref: "ext_1" }, 2);
    if (c.status === "accepted") claim(`retry_after_conflict:${outcome}`, c.state, retry, 3, 3);
    observe(`late_generation:${outcome}`, { ...json(r.state), executor_generation: 4 }, { ...json(o), observation_id: `obs_late_${tag}` }, 2);
  }
  { // idempotent retry with provider proof
    const g: any = operationFixture();
    const key = { idempotency_key: "idem_refund", idempotency_scope: "payments:tenant_acme_prod", provider_idempotency_ref: fixtureArtifact("provider_contract", "payments_idem") };
    Object.assign(g.intent, key, { recovery_strategy: "idempotent_retry", max_attempts: 3, retry_delays_seconds: [5, 10] });
    Object.assign(g.ledger.operations[0].intent, key, { recovery_strategy: "idempotent_retry", max_attempts: 3, retry_delays_seconds: [5, 10] });
    const proof = { provider_contract_ref: key.provider_idempotency_ref, key: key.idempotency_key, scope: key.idempotency_scope,
      operation_id: g.intent.operation_id, action_digest: g.intent.action_digest, same_payload_enforced: true, verification_status: "verified",
      observer: g.ledger.trusted_observers[0], evidence_ref: fixtureArtifact("provider_idempotency", "proof"),
      observed_at: "2026-10-16T07:00:00Z", valid_until: "2026-10-16T09:00:00Z", not_before: "2026-10-16T07:00:00Z", retention_expires_at: "2026-10-17T00:00:00Z" };
    const r: any = observe("idem:timeout", g.ledger, g.observation, 1);
    const retry = { ...json(g.intent), attempt: { ...json(g.intent.attempt), attempt_id: "attempt_idem_2", started_at: "2026-10-16T08:00:06Z" }, evaluation_time: "2026-10-16T08:00:06Z", provider_observation: proof };
    claim("idem:retry_with_proof", r.state, retry, 2, 3);
    claim("idem:retry_without_proof", r.state, { ...json(retry), provider_observation: null }, 2, 3);
    claim("idem:proof_payload_not_enforced", r.state, { ...json(retry), provider_observation: { ...proof, same_payload_enforced: false } }, 2, 3);
    claim("idem:proof_expired_retention", r.state, { ...json(retry), provider_observation: { ...proof, retention_expires_at: "2026-10-16T08:00:00Z" } }, 2, 3);
    claim("idem:recover_existing_claim", g.ledger, { ...json(g.intent), provider_observation: proof }, 1, 3);
    const dupKey = { ...json(g.intent), operation_id: "op_other", attempt: { ...json(g.intent.attempt), attempt_id: "attempt_other", operation_id: "op_other" }, provider_observation: { ...proof, operation_id: "op_other" } };
    claim("idem:key_reused_by_other_op", g.ledger, dupKey, 1, 3);
  }
  { // compensation
    const h: any = operationFixture();
    const done: any = observe("comp:confirmed", h.ledger, { ...json(h.observation), outcome: "confirmed", finality: "definitive" }, 1);
    const comp = { ...json(h.intent), operation_id: "op_refund_reversal", action_digest: "sha256:" + "c".repeat(64), compensates_operation_id: h.intent.operation_id,
      attempt: { ...json(h.intent.attempt), attempt_id: "attempt_reversal", operation_id: "op_refund_reversal" } };
    claim("comp:claim", done.state, comp, 2, 3);
    claim("comp:same_digest", done.state, { ...json(comp), action_digest: h.intent.action_digest }, 2, 3);
    claim("comp:before_effect", h.ledger, comp, 1, 3);
  }
  claim("stale_revision", f.ledger, f.intent, 0, 3);
  claim("stale_executor", f.ledger, f.intent, 1, 2);
  claim("past_deadline", empty, { ...json(f.intent), evaluation_time: "2026-10-16T09:00:00Z", attempt: { ...json(f.intent.attempt), started_at: "2026-10-16T09:00:00Z" } }, 1, 3);
  for (let i = 0; i < 400; i++) {
    const g: any = operationFixture();
    if (i % 2) { const m: any = mutate({ ledger: g.ledger, observation: g.observation, expected_revision: 1 }, rand); observe(`mutation_observe:${i}`, m.ledger, m.observation, m.expected_revision); }
    else { const m: any = mutate({ ledger: { ...g.ledger, operations: [] }, intent: g.intent, expected_revision: 1, executor_generation: 3 }, rand); claim(`mutation_claim:${i}`, m.ledger, m.intent, m.expected_revision, m.executor_generation); }
  }

  // Resume.
  const resume = (name: string, input: any) => { const x = json(input); resumes.push({ name, input: x, expected: call(() => validateResume(json(x))) }); };
  resume("base", checkpointFixture());
  const rSemantic: [string, (x: any) => void][] = [
    ["policy_migration", (x) => { x.required_policy_refs = [fixtureArtifact("policy_bundle", "refund_policy_v2")]; }],
    ["revision", (x) => { x.expected_revision = 1; }],
    ["executor_regressed", (x) => { x.executor_generation = 2; x.store_observation.executor_generation = 2; }],
    ["executor_id", (x) => { x.executor_id = "other_worker"; }],
    ["fencing_unsupported", (x) => { x.store_observation.target_fencing = "unsupported"; }],
    ["fencing_unsupported_optional", (x) => { x.store_observation.target_fencing = "unsupported"; x.checkpoint.require_target_fencing = false; addressCheckpoint(x.checkpoint);
      x.store_observation.checkpoint_digest = x.checkpoint.digest; x.current_observations.forEach((o: any) => { o.checkpoint_digest = x.checkpoint.digest; }); }],
    ["fencing_unknown", (x) => { x.store_observation.target_fencing = "unknown"; }],
    ["cancel_requested", (x) => { x.store_observation.cancellation_state = "requested"; }],
    ["deadline", (x) => { x.evaluation_time = "2026-10-16T09:00:00Z"; }],
    ["budget_snapshot_drift", (x) => { x.store_observation.budget_snapshot.used.tokens = 101; }],
    ["artifact_drift", (x) => { x.artifact_observations[0].actual_sha256 = "sha256:" + "d".repeat(64); }],
    ["artifact_missing", (x) => { x.artifact_observations.pop(); }],
    ["digest_tamper", (x) => { x.checkpoint.revision = 3; }],
    ["version", (x) => { x.checkpoint.checkpoint_version = "contextos.execution_checkpoint.v2"; }],
    ...(["contract_support", "authority", "approval", "boundary", "external_preconditions", "budget"].map((c, i) =>
      [`check_${c}`, (x: any) => { x.current_observations[i].status = i % 2 ? "unknown" : "blocked"; }] as [string, (x: any) => void])),
    ["observer_untrusted", (x) => { x.trusted_observers = [{ ...x.trusted_observers[0], principal_id: "other" }]; }],
    ["no_checkpoint", (x) => { delete x.checkpoint; }],
    ["null_checkpoint", (x) => { x.checkpoint = null; }],
  ];
  for (const [n, edit] of rSemantic) { const x: any = checkpointFixture(); edit(x); resume(`semantic:${n}`, x); }
  for (let i = 0; i < 400; i++) { const x: any = mutate(checkpointFixture(), rand); if (i % 3 === 0 && x?.checkpoint && typeof x.checkpoint === "object") call(() => addressCheckpoint(x.checkpoint)); resume(`mutation:${i}`, x); }

  // Budget.
  const budget = (name: string, op: string, ledger: any, request: any) => {
    const input = json({ ledger, request });
    const fn: any = { reserve: reserveBudget, settle: settleBudget, reserve_child: reserveChildBudget, settle_child: settleChildBudget }[op];
    const expected: any = call(() => fn(json(input.ledger), json(input.request)));
    budgets.push({ name, op, input, expected }); return expected;
  };
  const b0 = budgetFixture();
  const r1: any = budget("reserve_child", "reserve_child", b0, childReservation());
  budget("reserve_too_much", "reserve", b0, childReservation({ cost_units: 2501 }));
  budget("reserve_run_scope_as_child", "reserve_child", b0, { ...childReservation(), scope: "run", run_id: "run_contract" });
  budget("reserve_run", "reserve", b0, { ...childReservation(), scope: "run", run_id: "run_contract", mutation_id: "reserve_run_1", reservation_id: "reservation_run_1" });
  budget("reserve_past_deadline", "reserve", b0, { ...childReservation(), deadline: "2026-10-16T10:00:00Z" });
  budget("reserve_stale_revision", "reserve", b0, { ...childReservation(), expected_revision: 0 });
  budget("reserve_stale_executor", "reserve", b0, { ...childReservation(), executor_generation: 2 });
  budget("reserve_wrong_unit", "reserve", b0, { ...childReservation(), cost_unit: { currency: "USD", units_per_cent: 10 } });
  if (r1.status === "accepted") {
    const l1 = r1.state;
    budget("reserve_replay", "reserve", l1, childReservation());
    budget("reserve_replay_changed", "reserve", l1, childReservation({ tokens: 11 }));
    budget("reserve_duplicate_reservation", "reserve", l1, { ...childReservation(), mutation_id: "reserve_child_2", expected_revision: 2 });
    const settle = childSettlement(l1);
    const s1: any = budget("settle_known", "settle_child", l1, settle);
    budget("settle_unknown_usage", "settle", l1, (() => { const s: any = childSettlement(l1); s.usage_status = "unknown"; s.execution_status = "unknown"; bindBudgetUsage(s); return s; })());
    budget("settle_running", "settle", l1, (() => { const s: any = childSettlement(l1); s.execution_status = "running"; bindBudgetUsage(s); return s; })());
    budget("settle_over_allocation", "settle", l1, (() => { const s: any = childSettlement(l1, { tokens: 11 }); return s; })());
    budget("settle_unverified", "settle", l1, (() => { const s: any = childSettlement(l1); s.usage_observation.verification_status = "unavailable"; return s; })());
    budget("settle_digest_mismatch", "settle", l1, (() => { const s: any = childSettlement(l1); s.usage.tokens = 7; return s; })());
    if (s1.status === "accepted") {
      budget("settle_replay_after", "settle", s1.state, settle);
      budget("settle_again", "settle", s1.state, { ...childSettlement(l1), mutation_id: "settle_child_2", expected_revision: 3 });
      budget("reserve_after_settle", "reserve", s1.state, { ...childReservation(), mutation_id: "reserve_child_3", reservation_id: "reservation_child_3", expected_revision: 3 });
    }
  }
  budget("existing_reservation_exhausted", "reserve", budgetFixture({ cost_units: { reserved: 2450 } }), childReservation());
  for (let i = 0; i < 300; i++) {
    const l: any = budgetFixture();
    const m: any = mutate({ ledger: l, request: childReservation() }, rand);
    budget(`mutation_reserve:${i}`, "reserve", m.ledger, m.request);
  }
  for (const v of [0, 1, 25, 25.5, 0.01, 0.001, 0.125, 1e-7, 123456.78, 1e21, 9007199254740991, 90071992547409.91, -1, 2.5e-3, 1.005, 3.3]) {
    for (const u of [1, 10, 100, 1000, 3]) costs.push({ value: v, unit: { currency: "USD", units_per_cent: u }, expected: convertLegacyCostToUnits(v, { currency: "USD", units_per_cent: u }) });
  }
  writeFileSync(path.join(out, "durable.json.gz"), gzipSync(JSON.stringify({ runs, ops, resumes, budgets, costs }) + "\n", { level: 9 }));
});
