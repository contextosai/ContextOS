/**
 * Synthetic compiler and blocked-decision demonstration.
 *
 *   new ContextPackCompiler(pack).compile(request, RunContext, deps)
 *     → CompiledContext + proposed Plan
 *     → DEFERRED DecisionRecord while evidence/execution controls are unverified
 *
 * Run with: rtk npx tsx src/lib/contextos/test-harness.ts
 *
 * No provider, LLM, approval store, sandbox or effect gateway is called.
 * Fixed identity/evidence labels are fixtures, not authenticated observations.
 * Successful governed workflow fixtures live in tests/execution-workflows.test.ts;
 * those are also synthetic reference checks, not deployment conformance proof.
 */

import { ContextPackCompiler, type CompileDeps } from "./compiler";
import { demoPack } from "./scenario";
import type {
  ApprovalMode,
  CompiledContext,
  ContextPack,
  CriticReport,
  DecisionRecord,
  InvokeRequest,
  Plan,
  RunContext,
  ToolResult,
} from "./types";

// ─── Mock Context Pack ───────────────────────────────────────────────────
// Canonical fixture lives in scenario.ts so the test-harness and the live
// CompilerPlayground widget compile against one identical pack.

const mockPack: ContextPack = demoPack;

// ─── Mock Run Context ───────────────────────────────────────────────────────

const mockRunContext: RunContext = {
  run_id: "run_a1b2c3d4e5f60718",
  trace_id: "4bf92f3577b34da6a3ce929d0e0e4736",
  session_id: "sess_42f1",
  tenant_id: "tenant_acme_prod",
  user: {
    user_id: "usr_771",
    role: "support_agent",
    delegation: {
      auth_type: "oauth2",
      scopes: ["orders.read", "payments.refund"],
      subject: "u:user:771",
      token_ref: "tok_user_7a",
    },
  },
  agent: {
    agent_id: "agt_support",
    agent_urn: "agent:contextos/support-refund@1.2.0",
    workload_identity: "spiffe://contextos/agents/support",
    role: "support_ops",
    token_ref: "tok_agent_92",
    lifecycle: "active",
    identity_scopes: ["tools:read", "tools:write", "a2a:send"],
    principal_chain: [
      { kind: "user", id: "usr_771", tenant_id: "tenant_acme_prod" },
      {
        kind: "agent",
        id: "agent:contextos/support-refund@1.2.0",
        tenant_id: "tenant_acme_prod",
      },
    ],
    identity_claim: {
      version: "ctxid/1",
      iss: "contextos:identity",
      sub: "agent:contextos/support-refund@1.2.0",
      aud: "contextos:runtime",
      run_id: "run_a1b2c3d4e5f60718",
      session_id: "sess_42f1",
      tenant_id: "tenant_acme_prod",
      principal_chain: [{ kind: "user", id: "usr_771", tenant_id: "tenant_acme_prod" }],
      scopes: ["tools:read", "tools:write", "a2a:send"],
      nbf: "2026-05-17T10:00:00Z",
      exp: "2026-05-17T10:05:00Z",
      kid: "kid_ctxos_support_2026_05",
      claim_hash: "sha256:mock-identity-claim",
    },
  },
  intent: "support.refund",
  locale: "en-IN",
  safety_mode: "destructive",
  run_budget: {
    total_tokens: 12000,
    bucket_tokens: { policy: 1800, tool: 1500, evidence: 3500, memory: 1500, business: 1500, session: 2200 },
    max_tool_calls: 8,
    max_replan_attempts: 2,
    wall_clock_ms: 30000,
    max_cost_cents: 25.0,
    tokens_used: 0,
    tool_calls_used: 0,
    latency_ms_used: 0,
    cost_cents_used: 0,
  },
};

// ─── Mock invokeAgent request ───────────────────────────────────────────────

const mockRequest: InvokeRequest = {
  request_id: "req_9f3a12",
  session_id: "sess_42f1",
  tenant_id: "tenant_acme_prod",
  user: mockRunContext.user,
  agent: mockRunContext.agent,
  context_pack_refs: ["ctxpack.support@5.2.0"],
  input: {
    intent: "support.refund",
    message: "Refund order ord_881 for INR 4200.",
    channel: "app_chat",
    locale: "en-IN",
    context: {
      identity_verified: true,
      refund_amount: 4200,
      order_id: "ord_881",
    },
  },
  mode: "stream",
  runtime: {
    plan_timeout_ms: 15000,
    max_tool_calls: 8,
    max_payload_bytes: 1048576,
    max_cost_cents: 25.0,
  },
  trace: {
    trace_id: "4bf92f3577b34da6a3ce929d0e0e4736",
    span_id: "00f067aa0ba902b7",
    trace_flags: "01",
  },
};

// ─── Proposed Plan (never dispatched by this demo) ───────────────────────────────────────

function stubPlanner(): Plan {
  return {
    plan_id: "plan_refund_01",
    intent: "support.refund",
    steps: [
      { id: "s1", tool: "adp_orders.lookup", params: { order_id: "ord_881" } },
      { id: "s2", tool: "adp_policy.eval", depends_on: ["s1"] },
      {
        id: "s3",
        tool: "adp_payments.issue_refund",
        depends_on: ["s2"],
        approval_mode: "destructive" as ApprovalMode,
        requires: ["GATE_FINANCE_APPROVAL"],
      },
    ],
    decision_checkpoints: [
      { decision_id: "support.refund.execute", after_step: "s3" },
    ],
  };
}

function emitDeferredRecord(compiled: CompiledContext): DecisionRecord {
  const missingEvidence = compiled.runtime_controls.evidence_gates
    .filter((gate) => !gate.commit_allowed)
    .flatMap((gate) => gate.unresolved);
  return {
    record_id: "dr_2026_05_04_a17",
    decision_key: "support.refund.execute",
    decision_version: "1.0.0",
    timestamp: "2026-05-04T09:31:42Z",
    status: "DEFERRED",
    actor: { type: "AGENT", id: mockRequest.agent.agent_id },
    intent_ref: "support.refund",
    context_snapshot_hash: compiled.context_ledger.compiled_context_hash,
    subject_ids: ["customer:cus_77", "order:ord_881"],
    inputs_refs: { request: mockRequest.request_id, session: mockRequest.session_id ?? "" },
    outputs: {
      effects_dispatched: false,
      unresolved_evidence: missingEvidence,
      execution_controls: "not_evaluated",
      reason: "Required evidence and independent current execution checks must pass before dispatch.",
    },
    evidence_refs: compiled.context_ledger.evidence_refs,
    policy_decisions: [], // Compilation does not produce an effect-authorization receipt.
    approvals: [], // No approval was requested, authenticated or redeemed.
    controls_active: compiled.runtime_controls,
    tool_lineage: [],
    rationale: { strategy: "defer_until_evidence_and_current_execution_controls_are_verified" },
    budget_usage: {
      tokens: compiled.budget_report.tokens_used_at_compile,
      tool_calls: 0,
      cost_usd_cents: 0,
      wall_clock_ms: 0, // Fixed synthetic accounting; no elapsed-time measurement.
    },
    lineage: {
      pack_version: compiled.context_ledger.pack_ref,
      policy_versions: ["POLICY_RETURNS_V4@4.0.0"],
      decision_spec: "support.refund.execute@1.0.0",
    },
    replay: {
      compiled_context_hash: compiled.context_ledger.compiled_context_hash,
      last_status: "not_run",
    },
    trace_id: mockRunContext.trace_id,
  };
}

// ─── Synthetic blocked harness run ─────────────────────────────────────────────────

export async function runHarness(): Promise<void> {
  console.log("=== Run Context ===");
  console.log(JSON.stringify(mockRunContext, null, 2));

  console.log("\n=== invokeAgent request ===");
  console.log(JSON.stringify(mockRequest, null, 2));

  const compiler = new ContextPackCompiler(mockPack);
  const deps: CompileDeps = {
    evidence: [
      {
        evidence_ref: "kg:order:ord_881#snapshot_kg_2026_05_03_T0930",
        source_id: "kg.orders",
        content: "order ord_881 exists in snapshot_kg_2026_05_03_T0930",
        integrity: "verified",
        freshness: "current",
        satisfies: ["order_lookup"],
      },
    ],
    promoted_memory: [
      {
        memory_ref: "memory:customer:cus_77:preferred_communication_channel",
        content: "customer:cus_77 prefers_communication_channel=email",
        source_refs: ["decision:dr_customer_preference_77"],
        freshness: "current",
      },
    ],
  };
  const compiled = await compiler.compile(mockRequest, mockRunContext, deps);
  console.log("\n=== CompiledContext (manifests + runtime_controls + budget_report) ===");
  console.log(JSON.stringify(
    {
      manifests: compiled.manifests,
      runtime_controls: compiled.runtime_controls,
      budget_report: compiled.budget_report,
      block_count: compiled.compiled_prompt.context_blocks.length,
    },
    null,
    2
  ));

  const plan = stubPlanner();
  console.log("\n=== Plan (Planner output) ===");
  console.log(JSON.stringify(plan, null, 2));

  // No dispatch path exists here. A model plan or populated approval field cannot
  // substitute for current exact action/quorum, authority, active boundaries,
  // protected accounting/ownership and verified provider-recovery controls.
  const results: ToolResult[] = [];
  console.log("\n=== Tool transcripts (Executor → Tool Gateway) ===");
  console.log(JSON.stringify(results, null, 2));

  const critic: CriticReport = {
    verdict: "escalate",
    step_scores: [],
    loop_guard_trips: 0,
    replan_attempts: 0,
    reason: "Required evidence is unresolved; independent execution controls are not evaluated.",
  };
  console.log("\n=== Critic verdict ===");
  console.log(JSON.stringify(critic, null, 2));

  const decision = emitDeferredRecord(compiled);
  console.log("\n=== DecisionRecord ===");
  console.log(JSON.stringify(decision, null, 2));
}

// Auto-run when executed directly (e.g. via tsx).
const directlyExecuted =
  typeof process !== "undefined" &&
  Array.isArray(process.argv) &&
  process.argv[1]?.endsWith("test-harness.ts");

if (directlyExecuted) {
  runHarness().catch((err) => {
    console.error("harness failed:", err);
    process.exitCode = 1;
  });
}
