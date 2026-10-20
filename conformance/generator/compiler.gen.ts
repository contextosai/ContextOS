import { test } from "vitest";
import { writeFileSync } from "node:fs";
import path from "node:path";
import { ContextPackCompiler, evaluateActionRisk, type CompileDeps } from "@ref/compiler";
import { demoPack } from "@ref/scenario";
import type { ActionRisk, ActionRiskPolicy, ApprovalMode, ContextPack, InvokeRequest, RunContext } from "@ref/types";

const out = path.resolve(import.meta.dirname, "../vectors");
const clone = <T>(v: T): T => structuredClone(v);

type Knobs = { intent: string; identityVerified: boolean; refundAmount: number; userRole: string;
  safetyMode: ApprovalMode; evidenceTokens: number };

function message(k: Knobs): string {
  if (k.intent === "support.refund") return `Refund order ord_881 for INR ${k.refundAmount}.`;
  if (k.intent === "data.lookup") return "Look up the status of order ord_881.";
  return "What is the refund policy for damaged items?";
}
function request(k: Knobs): InvokeRequest {
  return {
    request_id: "req_9f3a12", session_id: "sess_42f1", tenant_id: "tenant_acme_prod",
    user: { user_id: "usr_771", role: k.userRole },
    agent: { agent_id: "agt_support", workload_identity: "spiffe://contextos/agents/support", role: "support_ops" },
    context_pack_refs: ["ctxpack.support@5.2.0"],
    input: { intent: k.intent, message: message(k), channel: "app_chat", locale: "en-IN",
      context: { identity_verified: k.identityVerified, refund_amount: k.refundAmount, order_id: "ord_881" } },
    mode: "stream", runtime: { plan_timeout_ms: 15000, max_tool_calls: 8, max_cost_cents: 25.0 },
    trace: { trace_id: "4bf92f3577b34da6a3ce929d0e0e4736", span_id: "00f067aa0ba902b7", trace_flags: "01" },
  };
}
function runContext(k: Knobs): RunContext {
  return {
    run_id: "run_a1b2c3d4e5f60718", trace_id: "4bf92f3577b34da6a3ce929d0e0e4736", session_id: "sess_42f1",
    tenant_id: "tenant_acme_prod", user: { user_id: "usr_771", role: k.userRole },
    agent: { agent_id: "agt_support", workload_identity: "spiffe://contextos/agents/support", role: "support_ops" },
    intent: k.intent, locale: "en-IN", safety_mode: k.safetyMode,
    run_budget: { total_tokens: 12000,
      bucket_tokens: { business: 1500, policy: 1800, tool: 1500, evidence: k.evidenceTokens, memory: 1500, session: 2200 },
      max_tool_calls: 8, max_replan_attempts: 2, wall_clock_ms: 30000, max_cost_cents: 25.0,
      tokens_used: 0, tool_calls_used: 0, latency_ms_used: 0, cost_cents_used: 0 },
  };
}
const EVIDENCE = [
  { evidence_ref: "kg:order:ord_881#snapshot_kg_2026_05_03_T0930", source_id: "kg.orders",
    content: "order ord_881 exists in snapshot_kg_2026_05_03_T0930", integrity: "verified", freshness: "current", satisfies: ["order_lookup"] },
  { evidence_ref: "kg:customer:cus_77#tier=gold,joined=2021", source_id: "kg.customers",
    content: "customer cus_77 has tier=gold and joined=2021", integrity: "verified", freshness: "current", satisfies: [] },
  { evidence_ref: "kg:policy:returns#clause_4.2_refund_window_30d", source_id: "policy.returns",
    content: "returns clause 4.2 sets refund_window_days=30", integrity: "verified", freshness: "current", satisfies: ["policy.eval"] },
  { evidence_ref: "kg:payment:txn_prior_5512#status=settled,amount=4200", source_id: "kg.payments",
    content: "payment txn_prior_5512 has status=settled and amount=4200", integrity: "verified", freshness: "current", satisfies: [] },
  { evidence_ref: "kg:fraud:cus_77#risk_score=0.04,signals=none", source_id: "kg.fraud",
    content: "customer cus_77 has risk_score=0.04 and signals=none", integrity: "verified", freshness: "current", satisfies: [] },
];
const MEMORY = [{ memory_ref: "memory:customer:cus_77:preferred_communication_channel",
  content: "customer:cus_77 prefers_communication_channel=email", source_refs: ["decision:dr_customer_preference_77"], freshness: "current" }];

const BASE: Knobs = { intent: "support.refund", identityVerified: true, refundAmount: 4200, userRole: "support_agent",
  safetyMode: "destructive", evidenceTokens: 400 };

type Case = { name: string; pack: ContextPack; request: InvokeRequest; run_context: RunContext; deps: CompileDeps };
const cases: Case[] = [];
const add = (name: string, k: Partial<Knobs>, deps: CompileDeps = { evidence: EVIDENCE as any, promoted_memory: MEMORY as any },
  mutate?: (c: Case) => void) => {
  const knobs = { ...BASE, ...k };
  const c: Case = { name, pack: clone(demoPack), request: request(knobs), run_context: runContext(knobs), deps: clone(deps) };
  mutate?.(c);
  cases.push(c);
};

for (const intent of ["support.refund", "data.lookup", "general.query"])
  for (const identityVerified of [true, false])
    for (const refundAmount of [1200, 4200])
      for (const userRole of ["support_agent", "support_lead"])
        add(`grid:${intent}:${identityVerified}:${refundAmount}:${userRole}`, { intent, identityVerified, refundAmount, userRole });
for (const safetyMode of ["read_only", "local_write", "network", "delegated", "destructive"] as ApprovalMode[])
  add(`safety:${safetyMode}`, { safetyMode });
for (const evidenceTokens of [0, 10, 25, 60, 100])
  add(`evidence_budget:${evidenceTokens}`, { evidenceTokens });
add("default_allocation", {}, undefined, (c) => { c.run_context.run_budget.bucket_tokens = {}; });
add("no_deps", {}, {});
add("legacy_strings", {}, { evidence: ["kg:order:ord_881", "plain text evidence"], promoted_memory: ["legacy memory"] });
add("labels_fail_closed", {}, { evidence: [
  { ...EVIDENCE[0], integrity: "authoritative" as any }, { ...EVIDENCE[2], freshness: "stale" },
  { evidence_ref: "", source_id: "", satisfies: ["order_lookup", 7, "order_lookup"] } as any,
  { ...EVIDENCE[0], evidence_ref: "dup", freshness: "bogus" as any }],
  promoted_memory: [{ memory_ref: "", content: "", source_refs: [], freshness: "later" } as any] });
add("conflict_unresolved", {}, { evidence: EVIDENCE as any, evidence_conflicts: [
  { conflict_id: "c2", evidence_refs: [EVIDENCE[0].evidence_ref, EVIDENCE[2].evidence_ref, EVIDENCE[0].evidence_ref],
    requirements: ["order_lookup"], status: "unresolved", subject: "ord_881", predicate: "exists", values: [true, false] }] });
add("conflict_resolved", {}, { evidence: [...EVIDENCE, { ...EVIDENCE[0], evidence_ref: "kg:order:alt", content: "alt" }] as any,
  evidence_conflicts: [
    { conflict_id: "c9", evidence_refs: [EVIDENCE[0].evidence_ref, "kg:order:alt"], requirements: ["order_lookup", "x"],
      status: "resolved", resolution: { resolution_ref: "review:1", selected_evidence_refs: ["kg:order:alt"] } },
    { conflict_id: "c1", evidence_refs: ["a", "b"], requirements: ["unrelated"], status: "unresolved" }] });
add("unicode_and_escapes", {}, { evidence: [{ ...EVIDENCE[0], content: "naïve \"quoted\" \\ tab\t 😀 \u0001" }] as any },
  (c) => { c.request.input.message = "Rëfund ✓ \"now\"\n"; });
add("no_risk_policy", {}, undefined, (c) => { delete (c.pack.policy_layer as any).action_risk_policy; });
add("tight_risk_policy", {}, undefined, (c) => { c.pack.policy_layer.action_risk_policy = {
  allowed_effects: ["none", "external_state"], allowed_authorities: ["agent", "service"], allowed_reversibility: ["read_only", "reversible"],
  allowed_interactions: ["api"], data_scope_ceiling: "INTERNAL", max_decision_ttl_seconds: 60 }; });

const errorCases: Case[] = [];
const addErr = (name: string, mutate: (c: Case) => void, deps?: CompileDeps) => {
  const c: Case = { name, pack: clone(demoPack), request: request(BASE), run_context: runContext(BASE),
    deps: clone(deps ?? { evidence: EVIDENCE as any }) };
  mutate(c); errorCases.push(c);
};
addErr("policy_eval_error", (c) => { c.pack.policy_layer.policy_bundles[0].policy_dsl.rules[0].if = { no_such_op: [1] }; });
addErr("evidence_hash_mismatch", () => {}, { evidence: [{ ...EVIDENCE[0], hash: "sha256:00" }] as any });
addErr("memory_hash_mismatch", () => {}, { promoted_memory: [{ ...MEMORY[0], hash: "sha256:00" }] as any });
addErr("conflict_one_ref", () => {}, { evidence_conflicts: [{ conflict_id: "c", evidence_refs: ["a"], requirements: ["r"], status: "unresolved" }] });
addErr("conflict_duplicate_id", () => {}, { evidence_conflicts: [
  { conflict_id: "c", evidence_refs: ["a", "b"], requirements: ["r"], status: "unresolved" },
  { conflict_id: "c", evidence_refs: ["a", "b"], requirements: ["r"], status: "unresolved" }] });
addErr("conflict_resolution_outside", () => {}, { evidence_conflicts: [{ conflict_id: "c", evidence_refs: ["a", "b"], requirements: ["r"],
  status: "resolved", resolution: { resolution_ref: "x", selected_evidence_refs: ["z"] } }] });
addErr("conflict_unresolved_with_resolution", () => {}, { evidence_conflicts: [{ conflict_id: "c", evidence_refs: ["a", "b"],
  requirements: ["r"], status: "unresolved", resolution: { resolution_ref: "x", selected_evidence_refs: ["a"] } }] });
addErr("unknown_decision_binding", (c) => { c.pack.decision_layer.decision_specs = []; });
addErr("undeclared_capability_risk", (c) => { const a = c.pack.tooling_layer.adapter_registry.find(a => a.capability_risks)!;
  a.capability_risks = { ...a.capability_risks, ghost: Object.values(a.capability_risks!)[0] }; });
addErr("nonconservative_projection", (c) => { const a = c.pack.tooling_layer.adapter_registry.find(a => a.capability_risks && a.approval_mode === "destructive")!;
  a.approval_mode = "read_only"; });

test("compiler vectors", async () => {
  const ok = [];
  for (const c of cases) {
    const compiled = await new ContextPackCompiler(c.pack).compile(c.request, c.run_context, c.deps);
    ok.push({ ...c, expected: compiled });
  }
  const errors = [];
  for (const c of errorCases) {
    try {
      await new ContextPackCompiler(c.pack).compile(c.request, c.run_context, c.deps);
      throw new Error(`expected failure for ${c.name}`);
    } catch (e: any) {
      if (e.message?.startsWith("expected failure")) throw e;
      errors.push({ ...c, expected_error: { message: e.message, detail: typeof e.toJSON === "function" ? e.toJSON() : null } });
    }
  }
  writeFileSync(path.join(out, "compiler.json"), JSON.stringify({ cases: ok, error_cases: errors }, null, 1) + "\n");
});

test("action risk vectors", () => {
  const effects = ["none", "local_state", "external_state", "physical_world"] as const;
  const authorities = ["agent", "service", "user_delegated", "human_approved"] as const;
  const revs = ["read_only", "reversible", "compensatable", "irreversible"] as const;
  const inters = ["api", "browser", "computer", "agent_to_agent", "human_handoff"] as const;
  const scopes = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"] as const;
  const policies: (ActionRiskPolicy | undefined)[] = [undefined,
    { allowed_effects: ["none", "local_state"], allowed_authorities: ["agent", "service", "user_delegated"],
      allowed_reversibility: ["read_only", "reversible", "compensatable"], allowed_interactions: ["api", "browser"],
      data_scope_ceiling: "CONFIDENTIAL" },
    { allowed_effects: [...effects], allowed_authorities: [...authorities], allowed_reversibility: [...revs],
      allowed_interactions: [...inters], data_scope_ceiling: "RESTRICTED", max_decision_ttl_seconds: 300 },
    { allowed_effects: ["teleport" as any], allowed_authorities: [], allowed_reversibility: [], allowed_interactions: [],
      data_scope_ceiling: "PUBLIC" }];
  const vectors = [];
  let i = 0;
  for (const effect of effects) for (const authority of authorities) for (const reversibility of revs)
    for (const interaction of inters) {
      const data_scope = scopes[i % 4];
      const risk: ActionRisk = { effect, authority, reversibility, interaction, data_scope };
      if (i % 3 === 0) risk.decision_ttl_seconds = (i * 37) % 600;
      const policy = policies[i % policies.length];
      vectors.push({ risk, policy: policy ?? null, expected: evaluateActionRisk(risk, policy) });
      i++;
    }
  vectors.push({ risk: { effect: "teleport", authority: "agent", reversibility: "read_only", interaction: "api", data_scope: "PUBLIC" },
    policy: policies[1], expected: evaluateActionRisk({ effect: "teleport" } as any, policies[1]) });
  writeFileSync(path.join(out, "action-risk.json"), JSON.stringify(vectors) + "\n");
});
