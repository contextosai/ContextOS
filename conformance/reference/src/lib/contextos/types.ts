/**
 * ContextOS reference types — Schema v2.
 *
 * This module is the typed reference for the canonical execution contract:
 *   invokeAgent(request, RunContext)
 *     → new ContextPackCompiler(pack).compile(request, RunContext, deps) → CompiledContext
 *     → loop { planner → critic.verify → executor → critic.score → consolidate }
 *     → DecisionRecord
 *
 * Authoritative narrative: src/content/docs/foundations/* and src/content/docs/implementation/*.
 * This module is a typed contract reference, not a production runtime.
 * Existing v1 shapes remain compatible. Additive execution attachments at the end
 * are externally bound to the base invocation; they are not implicit RunContext
 * fields. Type/schema validity and compiler output do not authorize an effect.
 */

// ─── Cross-cutting primitives ───────────────────────────────────────────────

export type ApprovalMode =
  | "read_only"
  | "local_write"
  | "network"
  | "delegated"
  | "destructive";

export type ActionEffect =
  | "none"
  | "local_state"
  | "external_state"
  | "physical_world";

export type ActionAuthority =
  | "agent"
  | "service"
  | "user_delegated"
  | "human_approved";

export type ActionReversibility =
  | "read_only"
  | "reversible"
  | "compensatable"
  | "irreversible";

export type ActionInteraction =
  | "api"
  | "browser"
  | "computer"
  | "agent_to_agent"
  | "human_handoff";

/**
 * Multidimensional action-risk description for 2026-era agents.
 * ApprovalMode remains the v1 compatibility projection.
 */
export interface ActionRisk {
  effect: ActionEffect;
  authority: ActionAuthority;
  reversibility: ActionReversibility;
  interaction: ActionInteraction;
  data_scope: DataClassification;
  decision_ttl_seconds?: number;
}

/**
 * Conjunctive policy for native action-risk dimensions. Every declared
 * dimension must be allowed; dimensions are never collapsed into a score.
 */
export interface ActionRiskPolicy {
  allowed_effects: ActionEffect[];
  allowed_authorities: ActionAuthority[];
  allowed_reversibility: ActionReversibility[];
  allowed_interactions: ActionInteraction[];
  data_scope_ceiling: DataClassification;
  /** When set, a classified capability must declare a TTL at or below it. */
  max_decision_ttl_seconds?: number;
}

export type ActionRiskViolation =
  | "unsupported_action_risk"
  | "unsupported_action_risk_policy"
  | "effect_not_allowed"
  | "authority_not_allowed"
  | "reversibility_not_allowed"
  | "interaction_not_allowed"
  | "data_scope_exceeds_ceiling"
  | "decision_ttl_required"
  | "decision_ttl_exceeds_maximum";

export interface ActionRiskEvaluation {
  verdict: "allow" | "deny";
  policy_applied: boolean;
  approval_mode_projection: ApprovalMode;
  violations: ActionRiskViolation[];
}

export type DataClassification =
  | "PUBLIC"
  | "INTERNAL"
  | "CONFIDENTIAL"
  | "RESTRICTED";

export type ContextBucket =
  | "business"
  | "policy"
  | "tool"
  | "evidence"
  | "memory"
  | "session";

/** SPIFFE-style URI for agent workload identity, e.g. spiffe://contextos/agents/support */
export type WorkloadIdentity = string;

/** Versioned agent subject for audit and authorization, e.g. agent:contextos/support@1.2.0 */
export type AgentURN = string;

export type PrincipalKind = "user" | "service" | "agent" | "automation";

export interface Principal {
  kind: PrincipalKind;
  id: string;
  tenant_id?: string;
  display?: string;
}

export interface UserDelegation {
  auth_type: "oauth2" | "saml" | "oidc" | "service";
  scopes: string[];
  subject: string;
  token_ref?: string;
}

export interface UserClaims {
  user_id: string;
  delegation?: UserDelegation;
  role?: string;
  tenure_days?: number;
}

export interface AgentIdentity {
  agent_id: string;
  agent_urn?: AgentURN;
  workload_identity: WorkloadIdentity;
  role: string;
  token_ref?: string;
  lifecycle?: "active" | "deprecated" | "revoked";
  identity_scopes?: string[];
  principal_chain?: Principal[];
  identity_claim?: IdentityClaim;
}

export interface IdentityClaim {
  version: "ctxid/1";
  iss: string;
  sub: AgentURN;
  aud?: string;
  run_id: string;
  session_id?: string;
  tenant_id: string;
  principal_chain: Principal[];
  scopes: string[];
  nbf: string;
  exp: string;
  kid: string;
  claim_hash: string;
  sig?: string;
}

export interface RunBudget {
  total_tokens: number;
  bucket_tokens: Partial<Record<ContextBucket, number>>;
  max_tool_calls: number;
  max_replan_attempts: number;
  wall_clock_ms: number;
  max_cost_cents: number;
  // Atomic accumulators (mutated under lock by the runtime).
  tokens_used: number;
  tool_calls_used: number;
  latency_ms_used: number;
  cost_cents_used: number;
}

export interface RunContext {
  run_id: string;
  trace_id: string;
  session_id?: string;
  tenant_id: string;
  user: UserClaims;
  agent: AgentIdentity;
  intent?: string;
  locale?: string;
  /** Highest approval mode this run may produce. Tools above this are filtered out. */
  safety_mode: ApprovalMode;
  run_budget: RunBudget;
  metadata?: Record<string, unknown>;
}

// ─── Context Pack ───────────────────────────────────────────────────────────

export interface ContractMeta {
  contract_name: string;
  contract_version: string;
  issuer: string;
  created_at: string;
  compatibility: { requires: Record<string, string> };
}

export interface PackMeta {
  pack_id: string;
  pack_version: string;
  tenant: { tenant_id: string; name: string };
  environment_defaults: {
    language: string;
    timezone: string;
    currency: string;
    region: string;
  };
  ttl_seconds: number;
  data_classification: DataClassification;
}

export type EntityType = string;
export type RelationshipType = string;

export interface IntelligenceRefs {
  ontology: {
    namespace: string;
    version: string;
    entity_types: EntityType[];
    relationship_types: RelationshipType[];
  };
  knowledge_graph: {
    /** Snapshot pinning rule: alias for reads, fixed version for replay. */
    snapshot_pin_rule: string;
  };
  identity_layer: {
    ceid_namespaces: string[];
  };
  embedding_keys?: string[];
}

export interface BusinessContext {
  summary: {
    what_we_do: string;
    who_we_serve: string[];
    differentiators: string[];
  };
  non_negotiables: string[];
}

/** JsonLogic expression — opaque object evaluated against the Run Context. */
export type JsonLogic = unknown;

export interface PolicyRule {
  rule_id: string;
  applies_to: { intent?: string; task?: string };
  if: JsonLogic;
  then: {
    allow: boolean;
    requires?: string[];
    prohibits?: string[];
    requires_approval_gate?: string | null;
    /** Effective approval mode if this rule fires. */
    approval_mode?: ApprovalMode;
    arg_constraints?: Record<string, unknown>;
  };
  else?: { allow: boolean; reason?: string };
  decision_binding?: string;
  rationale?: string;
  citations?: string[];
}

export interface PolicyBundle {
  bundle_id: string;
  priority: number;
  effective_from?: string;
  policy_dsl: { language: "jsonlogic"; rules: PolicyRule[] };
  prohibited_claims?: string[];
}

export interface Guardrails {
  must_refuse: string[];
  must_escalate: string[];
  redaction_rules: string[];
}

export interface ApprovalGate {
  gate_id: string;
  when: JsonLogic;
  required_approver_role: string;
  ttl_seconds?: number;
}

export interface PolicyLayer {
  policy_bundles: PolicyBundle[];
  guardrails: Guardrails;
  approval_gates: ApprovalGate[];
  /** Optional during v1 migration; classified capabilities are evaluated when present. */
  action_risk_policy?: ActionRiskPolicy;
}

export type AdapterType =
  | "MCP"
  | "A2A"
  | "OPENAPI"
  | "INTERNAL"
  | "DB"
  | "CUSTOM";

export interface AdapterDefinition {
  adapter_id: string;
  type: AdapterType;
  endpoint_ref: string;
  capabilities: string[];
  /** Highest approval mode any capability under this adapter can produce. */
  approval_mode: ApprovalMode;
  /** Native risk classification keyed by capability name. Additive in schema v2. */
  capability_risks?: Record<string, ActionRisk>;
}

export interface ToolPermission {
  permission_id: string;
  adapter_id: string;
  capability: string;
  allow: boolean;
  arg_constraints?: Record<string, unknown>;
  requires_approval_gate?: string | null;
}

export interface ToolingLayer {
  adapter_registry: AdapterDefinition[];
  permissions: ToolPermission[];
}

export interface DecisionSpec {
  decision_key: string;
  version: string;
  owner_role?: string;
  required_evidence: string[];
  allowed_outcomes: string[];
  approval_mode: ApprovalMode;
  inputs_schema_ref?: string;
  outputs_schema_ref?: string;
  eligibility_rules?: JsonLogic;
  decision_right?: "propose" | "recommend" | "execute" | "escalate";
  challenge_required?: boolean;
}

export interface DecisionLayer {
  decision_specs: DecisionSpec[];
}

export type WriteClass =
  | "evidence_link"
  | "preference"
  | "decision_outcome"
  | "correction";

export interface MemoryPolicy {
  tier_ttls: { working: string; episodic: string; semantic: string; durable: string };
  write_classes_allowed: WriteClass[];
  consent_gating: { pii_write_back_allowed: boolean };
}

export interface MemoryLayer {
  memory_policy: MemoryPolicy;
  promotion_thresholds: { auto_promote_confidence: number };
}

export interface EvalTarget {
  intent: string;
  policy: number;
  utility: number;
  latency_p99_ms: number;
  safety: number;
  economics_cents_per_decision: number;
}

export interface EvaluationLayer {
  eval_targets: EvalTarget[];
  release_gates?: Array<{ metric: string; max_delta: number }>;
}

export interface ToneAndComms {
  voice_attributes: string[];
  do: string[];
  dont: string[];
}

export interface ContextPack {
  contract_meta: ContractMeta;
  pack_meta: PackMeta;
  intelligence_refs: IntelligenceRefs;
  business_context: BusinessContext;
  policy_layer: PolicyLayer;
  tooling_layer: ToolingLayer;
  decision_layer: DecisionLayer;
  memory_layer: MemoryLayer;
  evaluation_layer: EvaluationLayer;
  tone_and_comms: ToneAndComms;
}

// ─── Invocation contract ────────────────────────────────────────────────────

export type InvokeMode = "stream" | "batch" | "long_running";

export interface InvokeAttachment {
  artifact_id: string;
  media_type: string;
  sha256: string;
  uri: string;
}

export interface InvokeTrace {
  trace_id: string;
  span_id: string;
  trace_flags?: string;
  tracestate?: string;
  baggage?: string;
}

export interface InvokeRequest {
  request_id: string;
  session_id?: string;
  tenant_id: string;
  user: UserClaims;
  agent: AgentIdentity;
  context_pack_refs: string[]; // pack_id@semver
  input: {
    intent: string;
    message: string;
    channel?: string;
    locale?: string;
    /** Optional structured context the caller already has (e.g., refund_amount, identity_verified). */
    context?: Record<string, unknown>;
  };
  mode: InvokeMode;
  runtime: {
    plan_timeout_ms?: number;
    max_session_duration_ms?: number;
    max_tool_calls?: number;
    max_payload_bytes?: number;
    max_cost_cents?: number;
  };
  attachments?: InvokeAttachment[];
  trace: InvokeTrace;
}

// ─── Agent delegation contract ─────────────────────────────────────────────

/** A parent-issued, strictly narrowing authority envelope for a child run. */
export interface AgentDelegationEnvelope {
  envelope_version: "contextos.agent_delegation.v1";
  delegation_id: string;
  parent_run_id: string;
  child_run_id: string;
  trace_id: string;
  tenant_id: string;
  issuer: AgentURN;
  subject: AgentURN;
  principal_chain: Principal[];
  scope: {
    allowed_intents: string[];
    allowed_capabilities: string[];
    data_classification_ceiling: DataClassification;
    output_schema_ref: string;
  };
  sub_budget: RunBudget;
  effect_policy: "isolate_until_accepted" | "read_only";
  issued_at: string;
  expires_at: string;
  cancellation_ref?: string;
  parent_claim_hash: string;
}

// ─── CompiledContext ────────────────────────────────────────────────────────

export type ContextOrigin =
  | "pack"
  | "policy"
  | "tool_registry"
  | "retrieval"
  | "memory"
  | "runtime";

/**
 * Integrity is about whether a block may justify a governed action. It is
 * intentionally separate from data classification (who may see the block).
 */
export type ContextIntegrity = "authoritative" | "verified" | "untrusted";

export type ContextFreshness = "current" | "stale" | "unknown" | "not_applicable";

/** Only control blocks may carry instructions; retrieved and recalled text is data. */
export type InstructionTreatment = "control" | "data_only";

export interface ContextProvenance {
  source_refs: string[];
  origin: ContextOrigin;
  integrity: ContextIntegrity;
  freshness: ContextFreshness;
  instruction_treatment: InstructionTreatment;
  inclusion_reason: string;
  content_hash: string;
  observed_at?: string;
  valid_until?: string;
}

export interface ContextBlock {
  block_id: string;
  bucket: ContextBucket;
  content: string;
  priority: number;
  provenance: ContextProvenance;
  /** @deprecated use provenance.source_refs */
  provenance_refs?: string[];
  /** True if this block was truncated to fit its bucket budget. */
  truncated?: boolean;
}

export interface CompiledPrompt {
  system: string;
  developer: string;
  task: string;
  context_blocks: ContextBlock[];
}

export interface PolicyManifestEntry {
  bundle_id: string;
  rule_ids: string[];
}

export interface ToolManifestEntry {
  adapter_id: string;
  capabilities: string[];
  constraints?: Record<string, unknown>;
  capability_metadata?: Record<string, CapabilityMetadata>;
}

export interface CapabilityMetadata {
  kind?: "read" | "write" | "network" | "delegated" | "destructive";
  risk_level?: string;
  approval_mode?: ApprovalMode;
  action_risk?: ActionRisk;
  action_risk_evaluation?: ActionRiskEvaluation;
  source?: string;
}

export interface EvidenceManifestEntry {
  evidence_ref: string;
  source_id: string;
  hash: string;
  integrity: Exclude<ContextIntegrity, "authoritative">;
  freshness: Exclude<ContextFreshness, "not_applicable">;
  instruction_treatment: "data_only";
  satisfies: string[];
  observed_at?: string;
  valid_until?: string;
}

export interface RetrievedEvidence {
  evidence_ref: string;
  source_id: string;
  content: string;
  integrity: Exclude<ContextIntegrity, "authoritative">;
  freshness: Exclude<ContextFreshness, "not_applicable">;
  satisfies: string[];
  hash?: string;
  observed_at?: string;
  valid_until?: string;
}

/**
 * A retrieval-layer conflict that must remain visible through compilation.
 * Resolved conflicts name the evidence selected by a deterministic rule or
 * accountable reviewer; unresolved conflicts cannot close a decision gate.
 */
export interface EvidenceConflictMarker {
  conflict_id: string;
  evidence_refs: string[];
  requirements: string[];
  status: "unresolved" | "resolved";
  subject?: string;
  predicate?: string;
  values?: unknown[];
  resolution?: {
    resolution_ref: string;
    selected_evidence_refs: string[];
  };
}

export interface PromotedMemory {
  memory_ref: string;
  content: string;
  source_refs: string[];
  freshness: Exclude<ContextFreshness, "not_applicable">;
  hash?: string;
  observed_at?: string;
  valid_until?: string;
}

export type EvidenceRejectionReason =
  | "untrusted"
  | "stale"
  | "freshness_unknown"
  | "budget_omitted"
  | "unresolved_conflict"
  | "superseded_by_resolution";

export interface RejectedEvidence {
  evidence_ref: string;
  requirements: string[];
  reasons: EvidenceRejectionReason[];
}

export interface EvidenceGate {
  decision_key: string;
  required: string[];
  satisfied: string[];
  unresolved: string[];
  rejected_evidence: RejectedEvidence[];
  /** Additive v1 field; older stored records may not carry conflict state. */
  conflicts?: EvidenceConflictMarker[];
  /** Additive v1 field derived from coverage, admission, and conflict state. */
  sufficiency?: "sufficient" | "insufficient";
  commit_allowed: boolean;
}

export interface ContextAdmissionControls {
  data_only_block_ids: string[];
  untrusted_block_ids: string[];
  privileged_sink_policy: "verified_or_user_intent";
}

export interface RuntimeControls {
  must_refuse: string[];
  must_escalate: string[];
  approval_gates_active: string[];
  redaction_rules_active: string[];
  context_admission: ContextAdmissionControls;
  evidence_gates: EvidenceGate[];
}

export interface ContextOmission {
  block_id: string;
  bucket: ContextBucket;
  reason: "budget_exceeded";
  estimated_tokens: number;
  priority: number;
  source_refs: string[];
}

export interface BudgetReport {
  tokens_allocated: Partial<Record<ContextBucket, number>>;
  tokens_used_at_compile: number;
  tokens_used_by_bucket: Partial<Record<ContextBucket, number>>;
  bucket_truncations: Partial<Record<ContextBucket, boolean>>;
  dropped_block_ids: Partial<Record<ContextBucket, string[]>>;
  omissions: ContextOmission[];
  warnings: string[];
}

export interface ContextLedger {
  pack_ref: string;
  intent: string;
  request_id: string;
  session_id?: string;
  policy_bundles: string[];
  policy_rule_ids: string[];
  tools: string[];
  evidence_refs: string[];
  memory_refs: string[];
  dropped_block_ids: string[];
  omissions: ContextOmission[];
  budget: {
    tokens_used_at_compile: number;
    tokens_used_by_bucket: Partial<Record<ContextBucket, number>>;
    truncated_buckets: ContextBucket[];
  };
  compiled_context_hash: string;
}

export interface CompiledContext {
  compiled_prompt: CompiledPrompt;
  manifests: {
    policy_manifest: PolicyManifestEntry[];
    tool_manifest: ToolManifestEntry[];
    evidence_manifest: EvidenceManifestEntry[];
  };
  runtime_controls: RuntimeControls;
  budget_report: BudgetReport;
  context_ledger: ContextLedger;
}

// ─── Tool envelopes ─────────────────────────────────────────────────────────

export interface ToolCallEnvelope {
  envelope_version: "contextos.tool_call.v1";
  tool_call_id: string;
  run_id: string;
  trace_id: string;
  session_id?: string;
  capability_id: string;
  args: Record<string, unknown>;
  principal_chain: Principal[];
  approval_mode_requested: ApprovalMode;
  approval_mode_effective: ApprovalMode;
  approval_mode_highest: ApprovalMode;
  /** Native risk vector. Optional in v1; required by the planned v2 envelope. */
  action_risk_requested?: ActionRisk;
  /** Policy-resolved vector after argument, identity, and evidence checks. */
  action_risk_effective?: ActionRisk;
  policy_decision_id?: string | null;
  evidence_refs: string[];
  idempotency_key?: string | null;
  auth_ref?: string | null;
  metadata?: Record<string, unknown>;
}

export type ToolStatus =
  | "ok"
  | "error"
  | "paused"
  | "completed"
  | "failed"
  | "rejected"
  | "blocked";

export interface ToolResultEnvelope {
  envelope_version: "contextos.tool_result.v1";
  tool_call_id: string;
  run_id: string;
  trace_id: string;
  session_id?: string;
  capability_id: string;
  status: ToolStatus;
  output: Record<string, unknown>;
  error?: string | null;
  artifacts: string[];
  citations: Array<Record<string, unknown>>;
  mutations: string[];
  risk_tags: string[];
  policy_decision_id?: string | null;
  latency_ms: number;
  metadata?: Record<string, unknown>;
}

/** @deprecated use ToolCallEnvelope */
export type ToolCall = ToolCallEnvelope;

/** @deprecated use ToolResultEnvelope */
export type ToolResult = ToolResultEnvelope;

// ─── Plan + Critic verdicts ─────────────────────────────────────────────────

export interface PlanStep {
  id: string;
  tool: string;
  params?: Record<string, unknown>;
  depends_on?: string[];
  approval_mode?: ApprovalMode;
  requires?: string[];
  /** JsonLogic predicate evaluated against running outputs to gate execution. */
  execute_when?: JsonLogic;
}

export interface DecisionCheckpoint {
  decision_id: string;
  after_step: string;
}

export interface Plan {
  plan_id: string;
  intent: string;
  steps: PlanStep[];
  decision_checkpoints: DecisionCheckpoint[];
}

export type CriticVerdict = "accept" | "retry" | "replan" | "escalate" | "reject" | "ok";

export interface RunScore {
  policy: number;
  utility: number;
  latency_ms?: number;
  safety: number;
  economics_cents?: number;
}

export interface StepScore {
  step_id: string;
  scores: RunScore;
  approval_gate?: string;
  approver?: string;
}

export interface CriticReport {
  verdict: CriticVerdict;
  step_scores: StepScore[];
  loop_guard_trips: number;
  replan_attempts: number;
  reason?: string;
}

// ─── Decision Record ────────────────────────────────────────────────────────

export type DecisionStatus =
  | "DECIDED"
  | "DEFERRED"
  | "REJECTED"
  | "ESCALATED"
  | "IN_FLIGHT"
  | "CLOSED";

export type DecisionActorType = "USER" | "AGENT" | "SYSTEM";

export interface DecisionApproval {
  gate_id: string;
  approver: string;
  approval_mode_effective: ApprovalMode;
  evidence_snapshot_hash: string;
  decided_at: string;
}

export interface DecisionPolicyDecision {
  policy_decision_id: string;
  bundle_id?: string;
  rule_ids: string[];
  verdict?: "allow" | "deny" | "require_approval" | "escalate";
}

export interface ToolLineageEntry {
  tool_call_id: string;
  tool_result_id?: string;
  capability_id?: string;
  approval_mode_effective?: ApprovalMode;
  policy_decision_id?: string | null;
  idempotency_key?: string | null;
  artifact_refs?: string[];
  mutation_refs?: string[];
  reversal_token?: string;
}

export interface DecisionScorecard {
  policy: number;
  utility: number;
  latency?: number;
  safety: number;
  cost?: number;
}

export interface DecisionLineage {
  pack_version: string;
  snapshot_version?: string;
  policy_versions?: string[];
  decision_spec?: string;
  kg_snapshot?: string;
  model_profile?: string;
  evaluator_suite?: string;
  routing_decision_id?: string;
}

export interface DecisionReplay {
  replay_packet_id?: string;
  replay_case_id?: string;
  compiled_context_hash?: string;
  tool_transcript_chain_hash?: string;
  last_status?: "not_run" | "replay_equal" | "replay_mismatch" | "not_replayable";
  diff_refs?: string[];
}

export interface DecisionAudit {
  prev_hash?: string;
  record_hash?: string;
  signed_by?: string;
  emitted_at?: string;
}

export interface DecisionRecord {
  record_id: string;
  decision_key: string;
  decision_version: string;
  timestamp: string;
  status: DecisionStatus;
  actor: { type: DecisionActorType; id: string };
  intent_ref?: string;
  context_snapshot_hash?: string;
  subject_ids?: string[];
  inputs_refs?: Record<string, string>;
  outputs?: Record<string, unknown>;
  evidence_refs: string[];
  policy_decisions: DecisionPolicyDecision[];
  approvals: DecisionApproval[];
  controls_active: RuntimeControls;
  tool_lineage?: ToolLineageEntry[];
  scorecard?: DecisionScorecard;
  confidence?: number;
  rationale?: { strategy: string; alternatives_considered?: unknown[] };
  budget_usage: {
    tokens: number;
    tool_calls: number;
    cost_usd_cents: number;
    wall_clock_ms: number;
  };
  lineage: DecisionLineage;
  replay?: DecisionReplay;
  audit?: DecisionAudit;
  trace_id: string;
}

// ─── Replay packet ──────────────────────────────────────────────────────────

/** What a replay packet was derived from. */
export type ReplaySourceKind =
  | "decision_record"
  | "quality_replay_case"
  | "environment_episode"
  | "operator_correction"
  | "golden_case";

/** How side effects are handled when a packet is replayed. */
export type SideEffectPolicy = "transcript_only" | "sandbox" | "live_disallowed";

/** Lifecycle status of the most recent replay of a packet. */
export type ReplayResultStatus =
  | "not_run"
  | "replay_equal"
  | "replay_mismatch"
  | "fixed"
  | "still_failing"
  | "invalid"
  | "superseded";

/**
 * Portable replay contract for audit replay, regression replay, environment
 * replay, and source-pressure closure. Published as
 * `/schemas/replay-packet.v1.schema.json`.
 */
export interface ReplayPacket {
  replay_packet_id: string;
  trace_id: string;
  session_id?: string;
  source_kind: ReplaySourceKind;
  source_ref: string;
  context_pack_ref: string;
  run_context_ref?: string;
  knowledge_snapshot_ref?: string;
  compiled_context_hash: string;
  tool_transcript_chain_hash?: string;
  side_effect_policy: SideEffectPolicy;
  expected: {
    status: string;
    decision_record_hash?: string;
    scorecard?: Record<string, unknown>;
    properties?: string[];
  };
  latest_result?: {
    status: ReplayResultStatus;
    eval_run_id?: string;
    score?: number;
    diff_refs?: string[];
    updated_at?: string;
  };
  metadata?: Record<string, unknown>;
}

// ─── Memory write proposals ─────────────────────────────────────────────────

export interface MemoryProposal {
  proposal_id: string;
  candidate: {
    entity_ceid: string;
    predicate: string;
    value: unknown;
    evidence_refs: string[];
    confidence: number;
  };
  class: WriteClass;
  tier_target: "working" | "episodic" | "semantic" | "durable";
  consent_check: "passed" | "failed" | "n/a";
  contradiction_check: { existing: unknown | null; verdict: "no_conflict" | "supersede" | "conflict" };
  auto_promote_eligible: boolean;
}

// ─── Evidence bundle (Knowledge Graph) ──────────────────────────────────────

export interface EvidenceHop {
  hop: number;
  edge: string;
  evidence_ref: string;
  to: { ceid?: string; entity_type?: string; value?: unknown };
  confidence: number;
  as_of?: string;
}

/** @deprecated emit EvidenceConflictMarker with stable refs and requirement impact. */
export interface LegacyEvidenceConflict {
  subject: string;
  predicate: string;
  values: unknown[];
}

export interface EvidenceBundle {
  snapshot_version: string;
  ontology_version: string;
  seed: { ceid?: string; entity_type?: string; query?: string };
  hops: EvidenceHop[];
  conflicts: Array<EvidenceConflictMarker | LegacyEvidenceConflict>;
  truncated: boolean;
}

// ─── Back-compat aliases (legacy v1 names) ──────────────────────────────────

/** @deprecated use InvokeRequest */
export type CompileRequest = InvokeRequest;
/** @deprecated use CompiledContext */
export type CompiledOutput = CompiledContext;

// Additive execution profiles; existing serialized envelopes remain unchanged.
export type ControlRef = import("./execution-contract-types").ControlRef;
export type ArtifactRef = import("./execution-contract-types").ArtifactRef;
export type ProfileSelection = import("./execution-contract-types").ProfileSelection;
export type WorkflowFeatureSet = import("./execution-contract-types").WorkflowFeatureSet;
export type ConditionalControlRequirement = import("./execution-contract-types").ConditionalControlRequirement;
export type ControlDefinition = import("./execution-contract-types").ControlDefinition;
export type ProfileDefinition = import("./execution-contract-types").ProfileDefinition;
export type ProfileRegistrySnapshot = import("./execution-contract-types").ProfileRegistrySnapshot;
export type ExecutionContractEnvelope = import("./execution-contract-types").ExecutionContractEnvelope;
export type RuntimeSupportDeclaration = import("./execution-contract-types").RuntimeSupportDeclaration;
export type ContractNegotiationReasonCode = import("./execution-contract-types").ContractNegotiationReasonCode;
export type ContractNegotiationReason = import("./execution-contract-types").ContractNegotiationReason;
export type ContractNegotiationResult = import("./execution-contract-types").ContractNegotiationResult;
export type PrincipalRef = import("./authorization").PrincipalRef;
export type MonetaryAmount = import("./authorization").MonetaryAmount;
export type ActionBinding = import("./authorization").ActionBinding;
export type ArgumentConstraint = import("./authorization").ArgumentConstraint;
export type AuthorityScope = import("./authorization").AuthorityScope;
export type GrantRef = import("./authorization").GrantRef;
export type AuthorityGrant = import("./authorization").AuthorityGrant;
export type VerificationStatus = import("./authorization").VerificationStatus;
export type GrantObservation = import("./authorization").GrantObservation;
export type AuthenticatedPrincipalContext = import("./authorization").AuthenticatedPrincipalContext;
export type VerifiedRunLink = import("./authorization").VerifiedRunLink;
export type AuthorityValidationInput = import("./authorization").AuthorityValidationInput;
export type AuthorityValidationResult = import("./authorization").AuthorityValidationResult;
export type AuthorityReasonCode = import("./authorization").AuthorityReasonCode;
export type AuthorizationVerdict = import("./authorization").AuthorizationVerdict;
export type NormalizedPolicyOutcome = import("./authorization").NormalizedPolicyOutcome;
export type ComposedPolicyOutcome = import("./authorization").ComposedPolicyOutcome;
export type StoredActionProposal = import("./authorization").StoredActionProposal;
export type ApprovalRequestRecord = import("./authorization").ApprovalRequestRecord;
export type ApprovalBinding = import("./authorization").ApprovalBinding;
export type ApprovalVerificationObservation = import("./authorization").ApprovalVerificationObservation;
export type ApproverEntitlementObservation = import("./authorization").ApproverEntitlementObservation;
export type ApprovalRedemptionState = import("./authorization").ApprovalRedemptionState;
export type ApprovalValidationInput = import("./authorization").ApprovalValidationInput;
export type ApprovalValidationResult = import("./authorization").ApprovalValidationResult;
export type ApprovalRedemptionInput = import("./authorization").ApprovalRedemptionInput;
export type ApprovalRedemptionResult = import("./authorization").ApprovalRedemptionResult;
export type ConstraintObservation = import("./authorization").ConstraintObservation;
export type AuthorizationInput = import("./authorization").AuthorizationInput;
export type AuthorizationDecision = import("./authorization").AuthorizationDecision;
export type AuthorizationOutcome = import("./authorization").AuthorizationOutcome;
export type ControlEvidenceStatus = import("./conformance").ControlEvidenceStatus;
export type ConformanceOutcome = import("./conformance").ConformanceOutcome;
export type ConformanceCaseResult = import("./conformance").ConformanceCaseResult;
export type ControlEvidenceResult = import("./conformance").ControlEvidenceResult;
export type ConformanceReport = import("./conformance").ConformanceReport;
export type ConformanceEvidenceObservation = import("./conformance").ConformanceEvidenceObservation;
export type ConformanceAssessmentInput = import("./conformance").ConformanceAssessmentInput;
export type ConformanceAssessment = import("./conformance").ConformanceAssessment;
export type ReferenceValidationReport = import("./conformance").ReferenceValidationReport;
export type IsolationMode = import("./execution-boundary").IsolationMode;
export type FilesystemGrant = import("./execution-boundary").FilesystemGrant;
export type NetworkGrant = import("./execution-boundary").NetworkGrant;
export type ProcessRestrictions = import("./execution-boundary").ProcessRestrictions;
export type BoundaryResourceCeilings = import("./execution-boundary").BoundaryResourceCeilings;
export type ExecutionBoundaryRequirement = import("./execution-boundary").ExecutionBoundaryRequirement;
export type ExecutionBoundaryObservation = import("./execution-boundary").ExecutionBoundaryObservation;
export type BoundaryReadinessResult = import("./execution-boundary").BoundaryReadinessResult;
export type DataFlowStage = import("./execution-boundary").DataFlowStage;
export type SourceClassificationObservation = import("./execution-boundary").SourceClassificationObservation;
export type ProcessorObservation = import("./execution-boundary").ProcessorObservation;
export type DataTransformationObservation = import("./execution-boundary").DataTransformationObservation;
export type DataFlowRequest = import("./execution-boundary").DataFlowRequest;
export type DataFlowRule = import("./execution-boundary").DataFlowRule;
export type DataFlowPolicySnapshot = import("./execution-boundary").DataFlowPolicySnapshot;
export type DataFlowDecision = import("./execution-boundary").DataFlowDecision;
export type MemoryLifecycleOperation = import("./execution-boundary").MemoryLifecycleOperation;
export type MemoryPropagationState = import("./execution-boundary").MemoryPropagationState;
export type MemoryReviewObservation = import("./execution-boundary").MemoryReviewObservation;
export type MemoryPropagationObservation = import("./execution-boundary").MemoryPropagationObservation;
export type MemoryAccessObservation = import("./execution-boundary").MemoryAccessObservation;
export type MemoryLifecycleRecord = import("./execution-boundary").MemoryLifecycleRecord;
export type MemoryLifecycleContext = import("./execution-boundary").MemoryLifecycleContext;
export type RunStatus = import("./durable-execution").RunStatus;
export type RunEventKind = import("./durable-execution").RunEventKind;
export type RunEffectOutcome = import("./durable-execution").RunEffectOutcome;
export type RunExecutionState = import("./durable-execution").RunExecutionState;
export type RunPreconditionObservation = import("./durable-execution").RunPreconditionObservation;
export type DispatchStopObservation = import("./durable-execution").DispatchStopObservation;
export type RunEvent = import("./durable-execution").RunEvent;
export type ResourceCounters = import("./durable-execution").ResourceCounters;
export type CostAccountingUnit = import("./durable-execution").CostAccountingUnit;
export type CheckpointBudgetSnapshot = import("./durable-execution").CheckpointBudgetSnapshot;
export type ExecutionCheckpoint = import("./durable-execution").ExecutionCheckpoint;
export type ResumeCheck = import("./durable-execution").ResumeCheck;
export type ResumeControlObservation = import("./durable-execution").ResumeControlObservation;
export type ResumeArtifactObservation = import("./durable-execution").ResumeArtifactObservation;
export type ResumeStoreObservation = import("./durable-execution").ResumeStoreObservation;
export type ResumeValidationInput = import("./durable-execution").ResumeValidationInput;
export type ResumeValidationResult = import("./durable-execution").ResumeValidationResult;
export type RecoveryStrategy = import("./operation-ledger").RecoveryStrategy;
export type OperationIntent = import("./operation-ledger").OperationIntent;
export type OperationAttempt = import("./operation-ledger").OperationAttempt;
export type ProviderIdempotencyObservation = import("./operation-ledger").ProviderIdempotencyObservation;
export type OperationClaim = import("./operation-ledger").OperationClaim;
export type EffectObservation = import("./operation-ledger").EffectObservation;
export type OperationRecord = import("./operation-ledger").OperationRecord;
export type OperationLedger = import("./operation-ledger").OperationLedger;
export type CostUnitConversion = import("./budget-ledger").CostUnitConversion;
export type BudgetReservationRecord = import("./budget-ledger").BudgetReservationRecord;
export type BudgetMutationReceipt = import("./budget-ledger").BudgetMutationReceipt;
export type BudgetLedger = import("./budget-ledger").BudgetLedger;
export type BudgetReservationRequest = import("./budget-ledger").BudgetReservationRequest;
export type BudgetSettlementRequest = import("./budget-ledger").BudgetSettlementRequest;
export type ContextCompileErrorDetail = import("./errors").ContextCompileErrorDetail;
export type TransitionResult<T> = import("./durable-execution").TransitionResult<T>;
