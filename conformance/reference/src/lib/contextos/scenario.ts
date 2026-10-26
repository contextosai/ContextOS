/**
 * Demo scenario fixtures + a thin driver that runs the *real*
 * {@link ContextPackCompiler} against knob-driven inputs.
 *
 * This is the single source of truth for the canonical support-refund pack:
 * `test-harness.ts` imports {@link demoPack} from here, and the interactive
 * CompilerPlayground widget calls {@link compileScenario} through a Server
 * Action. Because the compiler depends on `node:crypto` for the deterministic
 * `compiled_context_hash`, this module is server-only — never import it into a
 * client component (the widget uses `import type` for the DTOs and reaches the
 * runtime through the action).
 *
 * Synthetic compilation only: no identity authentication, approval redemption,
 * live retrieval, payment, protected store or runtime conformance is demonstrated.
 * User-controlled knobs and fixture labels cannot grant production authority.
 */

import { ContextPackCompiler, evaluateActionRisk, type CompileDeps } from "./compiler";
import type {
  ActionRisk,
  ActionRiskEvaluation,
  ApprovalMode,
  CompiledContext,
  ContextBucket,
  ContextPack,
  InvokeRequest,
  RunContext,
} from "./types";

// ─── Canonical demo Context Pack ─────────────────────────────────────────────

export const demoPack: ContextPack = {
  contract_meta: {
    contract_name: "ctxpack.support",
    contract_version: "2.0.0",
    issuer: "tenant_acme_prod",
    created_at: "2026-04-15T10:00:00Z",
    compatibility: { requires: { runtime: ">=2.0.0", ontology: ">=4.2.0" } },
  },
  pack_meta: {
    pack_id: "ctxpack.support",
    pack_version: "5.2.0",
    tenant: { tenant_id: "tenant_acme_prod", name: "Acme Support" },
    environment_defaults: {
      language: "en",
      timezone: "Asia/Kolkata",
      currency: "INR",
      region: "ap-south-1",
    },
    ttl_seconds: 86400,
    data_classification: "INTERNAL",
  },
  intelligence_refs: {
    ontology: {
      namespace: "ont.support",
      version: "4.2.0",
      entity_types: ["Customer", "Order"],
      relationship_types: ["order_belongs_to_customer"],
    },
    knowledge_graph: { snapshot_pin_rule: "alias:prod" },
    identity_layer: { ceid_namespaces: ["customer", "order"] },
  },
  business_context: {
    summary: {
      what_we_do: "Post-purchase customer support.",
      who_we_serve: ["consumers"],
      differentiators: ["fast resolution"],
    },
    non_negotiables: ["never charge a customer without consent"],
  },
  policy_layer: {
    policy_bundles: [
      {
        bundle_id: "POLICY_RETURNS_V4",
        priority: 10,
        policy_dsl: {
          language: "jsonlogic",
          rules: [
            {
              rule_id: "R_REFUND_REQUIRES_IDV",
              applies_to: { intent: "support.refund" },
              if: { "==": [{ var: "request.context.identity_verified" }, true] },
              then: { allow: true, requires: ["order_lookup"] },
              else: { allow: false, reason: "Identity not verified; refund path blocked." },
              rationale: "Refunds require verified identity.",
            },
            {
              rule_id: "R_HIGH_VALUE_REQUIRES_APPROVAL",
              applies_to: { intent: "support.refund" },
              if: {
                and: [
                  { "==": [{ var: "user.role" }, "support_agent"] },
                  { ">": [{ var: "request.context.refund_amount" }, 3000] },
                ],
              },
              then: {
                allow: true,
                approval_mode: "destructive",
                requires_approval_gate: "GATE_FINANCE_APPROVAL",
              },
              decision_binding: "support.refund.execute",
              rationale: "High-value refunds require finance approval.",
            },
          ],
        },
      },
    ],
    guardrails: {
      must_refuse: ["refund_without_identity"],
      must_escalate: ["fraud_signal_high"],
      redaction_rules: ["pan", "credit_card"],
    },
    approval_gates: [
      {
        gate_id: "GATE_FINANCE_APPROVAL",
        when: { ">": [{ var: "request.context.refund_amount" }, 3000] },
        required_approver_role: "finance_lead",
        ttl_seconds: 7200,
      },
    ],
    action_risk_policy: {
      allowed_effects: ["none", "local_state", "external_state"],
      allowed_authorities: ["agent", "service", "user_delegated", "human_approved"],
      allowed_reversibility: ["read_only", "reversible", "compensatable", "irreversible"],
      allowed_interactions: ["api", "browser", "computer", "agent_to_agent", "human_handoff"],
      data_scope_ceiling: "CONFIDENTIAL",
    },
  },
  tooling_layer: {
    adapter_registry: [
      {
        adapter_id: "adp_orders",
        type: "OPENAPI",
        endpoint_ref: "internal://orders",
        capabilities: ["lookup"],
        approval_mode: "read_only",
        capability_risks: {
          lookup: {
            effect: "none",
            authority: "service",
            reversibility: "read_only",
            interaction: "api",
            data_scope: "CONFIDENTIAL",
          },
        },
      },
      {
        adapter_id: "adp_policy",
        type: "INTERNAL",
        endpoint_ref: "internal://policy",
        capabilities: ["eval"],
        approval_mode: "read_only",
        capability_risks: {
          eval: {
            effect: "none",
            authority: "service",
            reversibility: "read_only",
            interaction: "api",
            data_scope: "INTERNAL",
          },
        },
      },
      {
        adapter_id: "adp_payments",
        type: "OPENAPI",
        endpoint_ref: "internal://payments",
        capabilities: ["issue_refund"],
        approval_mode: "destructive",
        capability_risks: {
          issue_refund: {
            effect: "external_state",
            authority: "human_approved",
            reversibility: "compensatable",
            interaction: "api",
            data_scope: "CONFIDENTIAL",
            decision_ttl_seconds: 300,
          },
        },
      },
    ],
    permissions: [
      { permission_id: "p1", adapter_id: "adp_orders", capability: "lookup", allow: true },
      { permission_id: "p2", adapter_id: "adp_policy", capability: "eval", allow: true },
      {
        permission_id: "p3",
        adapter_id: "adp_payments",
        capability: "issue_refund",
        allow: true,
        arg_constraints: { amount_inr: { min: 1, max: 50000 }, idempotency_key: { required: true } },
      },
    ],
  },
  decision_layer: {
    decision_specs: [
      {
        decision_key: "support.refund.execute",
        version: "1.0.0",
        owner_role: "support_ops",
        required_evidence: ["order_lookup", "policy.eval", "identity_verified"],
        allowed_outcomes: ["approved", "denied", "escalated"],
        approval_mode: "destructive",
        decision_right: "execute",
      },
    ],
  },
  memory_layer: {
    memory_policy: {
      tier_ttls: { working: "1h", episodic: "24h", semantic: "365d", durable: "1825d" },
      write_classes_allowed: ["preference", "decision_outcome", "correction"],
      consent_gating: { pii_write_back_allowed: false },
    },
    promotion_thresholds: { auto_promote_confidence: 0.95 },
  },
  evaluation_layer: {
    eval_targets: [
      {
        intent: "support.refund",
        policy: 1.0,
        utility: 0.9,
        latency_p99_ms: 3000,
        safety: 1.0,
        economics_cents_per_decision: 1.5,
      },
    ],
  },
  tone_and_comms: {
    voice_attributes: ["clear", "neutral"],
    do: ["cite policy"],
    dont: ["promise outcomes"],
  },
};

// ─── Knobs the playground exposes ────────────────────────────────────────────

export type ScenarioKnobs = {
  /** Declared intent; drives policy `applies_to` matching. */
  intent: string;
  /** request.context.identity_verified — flips R_REFUND_REQUIRES_IDV. */
  identityVerified: boolean;
  /** request.context.refund_amount — crosses the INR 3000 high-value threshold. */
  refundAmount: number;
  /** user.role — R_HIGH_VALUE_REQUIRES_APPROVAL only fires for support_agent. */
  userRole: string;
  /** Highest approval mode this run may produce; filters the tool surface. */
  safetyMode: ApprovalMode;
  /** evidence bucket token budget — shrink it to watch buckets truncate. */
  evidenceTokens: number;
};

export const DEFAULT_KNOBS: ScenarioKnobs = {
  intent: "support.refund",
  identityVerified: true,
  refundAmount: 4200,
  userRole: "support_agent",
  safetyMode: "destructive",
  evidenceTokens: 400,
};

export const INTENT_OPTIONS = ["support.refund", "data.lookup", "general.query"] as const;
export const ROLE_OPTIONS = ["support_agent", "support_lead"] as const;
export const SAFETY_OPTIONS: ApprovalMode[] = [
  "read_only",
  "local_write",
  "network",
  "delegated",
  "destructive",
];

/** Constructed evidence labels for this scenario; no graph or source is queried. */
const DEMO_EVIDENCE = [
  {
    evidence_ref: "kg:order:ord_881#snapshot_kg_2026_05_03_T0930",
    source_id: "kg.orders",
    content: "order ord_881 exists in snapshot_kg_2026_05_03_T0930",
    integrity: "verified",
    freshness: "current",
    satisfies: ["order_lookup"],
  },
  {
    evidence_ref: "kg:customer:cus_77#tier=gold,joined=2021",
    source_id: "kg.customers",
    content: "customer cus_77 has tier=gold and joined=2021",
    integrity: "verified",
    freshness: "current",
    satisfies: [],
  },
  {
    evidence_ref: "kg:policy:returns#clause_4.2_refund_window_30d",
    source_id: "policy.returns",
    content: "returns clause 4.2 sets refund_window_days=30",
    integrity: "verified",
    freshness: "current",
    satisfies: ["policy.eval"],
  },
  {
    evidence_ref: "kg:payment:txn_prior_5512#status=settled,amount=4200",
    source_id: "kg.payments",
    content: "payment txn_prior_5512 has status=settled and amount=4200",
    integrity: "verified",
    freshness: "current",
    satisfies: [],
  },
  {
    evidence_ref: "kg:fraud:cus_77#risk_score=0.04,signals=none",
    source_id: "kg.fraud",
    content: "customer cus_77 has risk_score=0.04 and signals=none",
    integrity: "verified",
    freshness: "current",
    satisfies: [],
  },
] satisfies NonNullable<CompileDeps["evidence"]>;

/** Constructed promoted-memory fixture; no review, consent or storage is performed. */
const DEMO_MEMORY = [
  {
    memory_ref: "memory:customer:cus_77:preferred_communication_channel",
    content: "customer:cus_77 prefers_communication_channel=email",
    source_refs: ["decision:dr_customer_preference_77"],
    freshness: "current",
  },
] satisfies NonNullable<CompileDeps["promoted_memory"]>;

const APPROVAL_RANK: Record<ApprovalMode, number> = {
  read_only: 0,
  local_write: 1,
  network: 2,
  delegated: 3,
  destructive: 4,
};

const MAX_REFUND_AMOUNT = 1_000_000_000;
const MAX_EVIDENCE_TOKENS = 100_000;

/**
 * Coerce untrusted knob input into a valid, bounded {@link ScenarioKnobs}.
 *
 * The playground reaches this through a public Server Action, so values arrive
 * unvalidated (TypeScript types are not a runtime guarantee). Unknown/oversized
 * values fall back to safe defaults, strings are constrained to known options
 * (so nothing unbounded is echoed or hashed), and an invalid `safety_mode`
 * fails *closed* to `read_only` — the most restrictive tier.
 */
export function normalizeKnobs(input: unknown): ScenarioKnobs {
  const raw = (input ?? {}) as Record<string, unknown>;
  const oneOf = (v: unknown, allowed: readonly string[], fallback: string): string =>
    typeof v === "string" && allowed.includes(v) ? v : fallback;
  const clampNum = (v: unknown, min: number, max: number, fallback: number): number =>
    typeof v === "number" && Number.isFinite(v) ? Math.min(max, Math.max(min, v)) : fallback;
  return {
    intent: oneOf(raw.intent, INTENT_OPTIONS, DEFAULT_KNOBS.intent),
    identityVerified: raw.identityVerified === true,
    refundAmount: clampNum(raw.refundAmount, 0, MAX_REFUND_AMOUNT, DEFAULT_KNOBS.refundAmount),
    userRole: oneOf(raw.userRole, ROLE_OPTIONS, DEFAULT_KNOBS.userRole),
    safetyMode: oneOf(raw.safetyMode, SAFETY_OPTIONS, "read_only") as ApprovalMode,
    evidenceTokens: clampNum(raw.evidenceTokens, 0, MAX_EVIDENCE_TOKENS, DEFAULT_KNOBS.evidenceTokens),
  };
}

// ─── Result DTO (serializable; crosses the action boundary to the client) ─────

export type FiredRule = { rule_id: string; bundle_id: string; rationale: string };
export type SurfacedTool = {
  adapter_id: string;
  capabilities: string[];
  approval_mode: ApprovalMode;
  action_risk?: ActionRisk;
  action_risk_evaluation?: ActionRiskEvaluation;
};
export type FilteredTool = {
  adapter_id: string;
  approval_mode: ApprovalMode;
  reason: string;
};

export type ScenarioResult = {
  intent: string;
  packRef: string;
  firedRules: FiredRule[];
  surfacedTools: SurfacedTool[];
  filteredTools: FilteredTool[];
  runtimeControls: CompiledContext["runtime_controls"];
  budget: {
    allocated: Partial<Record<ContextBucket, number>>;
    usedByBucket: Partial<Record<ContextBucket, number>>;
    totalUsed: number;
    truncatedBuckets: ContextBucket[];
    droppedBlockIds: string[];
    warnings: string[];
  };
  contextHash: string;
};

// ─── Input builders ──────────────────────────────────────────────────────────

function messageFor(knobs: ScenarioKnobs): string {
  if (knobs.intent === "support.refund")
    return `Refund order ord_881 for INR ${knobs.refundAmount}.`;
  if (knobs.intent === "data.lookup") return "Look up the status of order ord_881.";
  return "What is the refund policy for damaged items?";
}

function buildRequest(knobs: ScenarioKnobs): InvokeRequest {
  return {
    request_id: "req_9f3a12",
    session_id: "sess_42f1",
    tenant_id: "tenant_acme_prod",
    user: { user_id: "usr_771", role: knobs.userRole },
    agent: {
      agent_id: "agt_support",
      workload_identity: "spiffe://contextos/agents/support",
      role: "support_ops",
    },
    context_pack_refs: ["ctxpack.support@5.2.0"],
    input: {
      intent: knobs.intent,
      message: messageFor(knobs),
      channel: "app_chat",
      locale: "en-IN",
      context: {
        identity_verified: knobs.identityVerified,
        refund_amount: knobs.refundAmount,
        order_id: "ord_881",
      },
    },
    mode: "stream",
    runtime: { plan_timeout_ms: 15000, max_tool_calls: 8, max_cost_cents: 25.0 },
    trace: {
      trace_id: "4bf92f3577b34da6a3ce929d0e0e4736",
      span_id: "00f067aa0ba902b7",
      trace_flags: "01",
    },
  };
}

function buildRunContext(knobs: ScenarioKnobs): RunContext {
  // Generous per-bucket budgets so only the evidence knob drives truncation.
  return {
    run_id: "run_a1b2c3d4e5f60718",
    trace_id: "4bf92f3577b34da6a3ce929d0e0e4736",
    session_id: "sess_42f1",
    tenant_id: "tenant_acme_prod",
    user: { user_id: "usr_771", role: knobs.userRole },
    agent: {
      agent_id: "agt_support",
      workload_identity: "spiffe://contextos/agents/support",
      role: "support_ops",
    },
    intent: knobs.intent,
    locale: "en-IN",
    safety_mode: knobs.safetyMode,
    run_budget: {
      total_tokens: 12000,
      bucket_tokens: {
        business: 1500,
        policy: 1800,
        tool: 1500,
        evidence: Math.max(0, knobs.evidenceTokens),
        memory: 1500,
        session: 2200,
      },
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
}

// ─── Driver ──────────────────────────────────────────────────────────────────

/**
 * Runs the unmodified reference compiler and projects its `CompiledContext`
 * into a flat, serializable DTO for the playground. Adds one thing the raw
 * manifest does not carry: the *filtered* tools and why each was withheld —
 * which is what makes the approval-mode safety filter legible.
 */
export async function compileScenario(rawKnobs: ScenarioKnobs): Promise<ScenarioResult> {
  const knobs = normalizeKnobs(rawKnobs);
  const request = buildRequest(knobs);
  const runCtx = buildRunContext(knobs);
  const deps: CompileDeps = { evidence: DEMO_EVIDENCE, promoted_memory: DEMO_MEMORY };

  const compiled = await new ContextPackCompiler(demoPack).compile(request, runCtx, deps);

  // rule_id → base rationale, used as a fallback.
  const baseRationale = new Map<string, string>();
  for (const bundle of demoPack.policy_layer.policy_bundles)
    for (const rule of bundle.policy_dsl.rules)
      baseRationale.set(rule.rule_id, rule.rationale ?? "");

  // The compiler writes the *effective* rationale into each policy block as
  // `Rule <id> (bundle <id>): <rationale>` — and when a rule's else branch
  // fires it substitutes the else reason. Read it from there so a denied
  // verdict (e.g. identity not verified) reads differently from an allowed one,
  // rather than re-deriving the verdict and risking drift from the compiler.
  const policyBlocks = compiled.compiled_prompt.context_blocks.filter(
    (b) => b.bucket === "policy"
  );
  const effectiveRationale = (rule_id: string, bundle_id: string): string => {
    const prefix = `Rule ${rule_id} (bundle ${bundle_id}):`;
    const block = policyBlocks.find((b) => b.content.startsWith(prefix));
    const sep = block?.content.indexOf("): ");
    if (block && sep !== undefined && sep >= 0) return block.content.slice(sep + 3);
    return baseRationale.get(rule_id) ?? "";
  };

  const firedRules: FiredRule[] = compiled.manifests.policy_manifest.flatMap((entry) =>
    entry.rule_ids.map((rule_id) => ({
      rule_id,
      bundle_id: entry.bundle_id,
      rationale: effectiveRationale(rule_id, entry.bundle_id),
    }))
  );

  const surfacedTools: SurfacedTool[] = compiled.manifests.tool_manifest.map((tool) => ({
    adapter_id: tool.adapter_id,
    capabilities: tool.capabilities,
    approval_mode:
      tool.capability_metadata?.[tool.capabilities[0]]?.approval_mode ?? "read_only",
    action_risk: tool.capability_metadata?.[tool.capabilities[0]]?.action_risk,
    action_risk_evaluation:
      tool.capability_metadata?.[tool.capabilities[0]]?.action_risk_evaluation,
  }));
  const surfacedIds = new Set(surfacedTools.map((t) => t.adapter_id));

  const permitted = new Set(
    demoPack.tooling_layer.permissions
      .filter((p) => p.allow)
      .map((p) => `${p.adapter_id}.${p.capability}`)
  );

  const filteredTools: FilteredTool[] = demoPack.tooling_layer.adapter_registry
    .filter((adapter) => !surfacedIds.has(adapter.adapter_id))
    .map((adapter) => {
      let reason: string;
      if (APPROVAL_RANK[adapter.approval_mode] > APPROVAL_RANK[knobs.safetyMode]) {
        reason = `approval_mode "${adapter.approval_mode}" exceeds safety_mode "${knobs.safetyMode}"`;
      } else if (!adapter.capabilities.some((c) => permitted.has(`${adapter.adapter_id}.${c}`))) {
        reason = "no allow permission in pack";
      } else {
        const deniedRisk = adapter.capabilities
          .filter((capability) => permitted.has(`${adapter.adapter_id}.${capability}`))
          .map((capability) => adapter.capability_risks?.[capability])
          .filter((risk): risk is ActionRisk => risk !== undefined)
          .map((risk) => evaluateActionRisk(risk, demoPack.policy_layer.action_risk_policy))
          .find((evaluation) => evaluation.verdict === "deny");
        reason = deniedRisk
          ? `action_risk policy denied: ${deniedRisk.violations.join(", ")}`
          : "withheld by an active policy prohibition";
      }
      return { adapter_id: adapter.adapter_id, approval_mode: adapter.approval_mode, reason };
    });

  const report = compiled.budget_report;
  return {
    intent: compiled.context_ledger.intent,
    packRef: compiled.context_ledger.pack_ref,
    firedRules,
    surfacedTools,
    filteredTools,
    runtimeControls: compiled.runtime_controls,
    budget: {
      allocated: report.tokens_allocated,
      usedByBucket: report.tokens_used_by_bucket,
      totalUsed: report.tokens_used_at_compile,
      truncatedBuckets: compiled.context_ledger.budget.truncated_buckets,
      droppedBlockIds: compiled.context_ledger.dropped_block_ids,
      warnings: report.warnings,
    },
    contextHash: compiled.context_ledger.compiled_context_hash,
  };
}
