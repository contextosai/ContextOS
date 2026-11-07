// Shapes of towerd responses.

export type Severity = "critical" | "high" | "medium" | "low";

export interface Finding {
  id: string;
  rule: string;
  severity: Severity;
  agent: string | null;
  source: string | null;
  title: string;
  detail: string;
  remediation: string;
  evidence: unknown;
  waiver: Waiver | null;
}

export interface AgentRow {
  key: string;
  agent_id: string;
  agent_urn: string | null;
  owner: string | null;
  team: string | null;
  business_unit: string | null;
  lifecycle: string;
  purpose: string | null;
  reviewed: boolean;
  required_profile: string;
  capabilities: number;
  external: number;
  irreversible: number;
  models: string[];
  sources: string[];
  runs: number;
  last_seen: string;
  findings: Record<Severity, number>;
}

export interface Capability {
  id: string;
  adapter: string;
  effect: string;
  authority: string;
  reversibility: string;
  interaction: string;
  /** Every interaction kind its packs declare; controls derive from all of them. */
  interactions: string[];
  data_scope: string;
  approval_mode: string;
  packs: string[];
  surfaced: boolean;
  used: boolean;
}

export interface Requirement {
  profile: string;
  reasons: string[];
  features: string[];
  controls: string[];
}

export interface Anomaly {
  agent: string;
  metric: string;
  hour: number;
  value: number;
  baseline: number;
  title: string;
}

export interface RunSummary {
  source: string;
  run_id: string;
  agent: string;
  trace_id: string;
  pack_ref: string;
  intent: string | null;
  parent_run_id: string | null;
  status: string;
  admitted_at: string;
  last_at: string;
  effects: number;
  refused: number;
  unknown: number;
  decisions: number;
  capabilities: string[];
  refusal_reasons: string[];
}

export interface Facts {
  declared: boolean;
  declaration: Record<string, unknown> | null;
  reviewed: boolean;
  /** The review approved the agent, but its validity has passed. */
  review_expired: boolean;
  review: Record<string, unknown> | null;
  exposure: Record<string, unknown>;
  controls: { required_profile: string; required: string[]; missing: Record<string, string[]>; admitted_profiles: string[]; features: string[] };
  drift: string[];
  /** Reviewed capabilities whose risk differs from what was approved. */
  risk_changed: string[];
  activity: Record<string, unknown> & { refusals: Record<string, number> };
  agent: Record<string, unknown> & { models: string[]; evaluators: string[]; packs: string[]; sources: string[]; intents: string[] };
}

export interface AgentDetail {
  row: AgentRow;
  facts: Facts;
  requirement: Requirement;
  graph: Capability[];
  digest: string;
  findings: Finding[];
  anomalies: Anomaly[];
  series: { hour: number; runs: number; effects: number; applied: number; refused: number; unknown: number; approvals: number }[];
  runs: RunSummary[];
  can_revoke: boolean;
}

export interface Posture {
  now: string;
  agents: {
    total: number;
    declared: number;
    reviewed: number;
    external_effects: number;
    irreversible_external: number;
    by_required_profile: Record<string, number>;
    by_lifecycle: Record<string, number>;
  };
  findings: { by_severity: Partial<Record<Severity, number>>; by_rule: Record<string, number>; waived: number };
  anomalies: number;
  riskiest: AgentRow[];
  top_findings: Finding[];
  sources: { id: string; verified_to: number; head: number; broken: unknown; last_error: string | null; last_sync: string | null; revoked: number }[];
  unattributed: number;
  guardrails: number;
  intelligence: string | null;
}

export interface Guardrail {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  rule: unknown;
  remediation: string;
  origin: string;
  intent?: string | null;
  status: "draft" | "active" | "retired";
  created_by: string;
  created_at: string;
  activated_by?: string;
  impact?: { evaluated: number; violating: string[]; errors: unknown[] };
}

export interface Waiver {
  id: string;
  rule: string;
  agent: string;
  reason: string;
  days: number;
  status: "requested" | "approved" | "rejected" | "expired";
  requested_by: string;
  requested_at: string;
  decided_by?: string;
  expires_at?: string;
  decision_reason?: string;
}

export interface Change {
  source: string;
  sequence: number;
  at: string;
  kind: string;
  summary: string;
  by: string | null;
}

export const PROFILE_LABEL: Record<string, string> = {
  "contextos.core": "Core",
  "contextos.enterprise": "Enterprise",
  "contextos.durable-delegated": "Durable-delegated",
  "contextos.high-assurance": "High-assurance",
};

/** Model usage over a window (`cost_units` are hundredths of a cent). */
export interface SpendUsage {
  calls: number;
  verified_calls: number;
  tokens: number;
  cost_units: number;
  verified_tokens: number;
  verified_cost_units: number;
  self_reported_tokens: number;
  self_reported_cost_units: number;
  uncovered_tokens: number;
  uncovered_cost_units: number;
  refused: number;
  claimed: number;
  unsettled_claims: number;
}

export interface ModelUsage {
  calls: number;
  tokens: number;
  cost_units: number;
  verified_tokens: number;
}

export interface SpendPoint {
  hour: number;
  tokens: number;
  cost_units: number;
  verified_tokens: number;
  self_reported_tokens: number;
  uncovered_tokens: number;
  refused: number;
}

export type SpendGroup = "agent" | "team" | "model";

export interface SpendRow {
  key: string;
  usage: SpendUsage | ModelUsage;
  agent_id?: string | null;
  team?: string;
  owner?: string | null;
  models?: string[];
  agents?: number;
}

export interface SpendReport {
  from_hour: number;
  to_hour: number;
  bucket_hours: number;
  group: SpendGroup;
  totals: SpendUsage;
  rows: SpendRow[];
  total_rows: number;
  series: SpendPoint[];
  refusals: Record<string, number>;
}

export interface AgentSpendReport {
  key: string;
  from_hour: number;
  to_hour: number;
  bucket_hours: number;
  usage: SpendUsage;
  since_start: SpendUsage;
  models: { key: string; usage: ModelUsage }[];
  refusals: Record<string, number>;
  series: SpendPoint[];
}

export type Provenance = "verified" | "runtime_only" | "chain_only" | "chain";

export interface Revocation {
  source: string;
  kind: string;
  target: string;
  reason: string;
  /** The runtime principal that made the change. */
  by: string | null;
  /** The Tower user, when the change came through Tower. */
  via_tower: string | null;
  at: string | null;
  sequence: number | null;
  provenance: Provenance;
  mismatch: boolean;
  affected: string[];
  refusals: number;
}

export interface RevocationsView {
  revocations: Revocation[];
  mismatches: number;
  sources: { id: string; live: "read" | "no_control_key" | "paused" | "error"; error?: string }[];
  pending_requests: number;
  two_person_restore: boolean;
}

export interface RestoreRequest {
  id: string;
  kind: string;
  target: string;
  sources: string[] | null;
  reason: string;
  status: "requested" | "approved" | "restored" | "partially_restored" | "failed" | "cancelled" | "expired";
  requested_by: string;
  requested_at: string;
  expires_at: string;
  approved_by?: string;
  approved_at?: string;
  executed_at?: string;
  results?: { source: string | null; ok: boolean; error?: string }[];
}

/** One open escalation in the approvals inbox (`GET /api/inbox`). */
export interface InboxItem {
  source: string;
  escalation_id: string;
  /** `policy` (policy answered escalate) or `outcome_missed` (an effect's outcome never arrived). */
  kind: "policy" | "outcome_missed";
  run_id: string;
  trace_id?: string;
  operation_id?: string;
  capability_id?: string;
  reason_codes?: string[];
  action_digest?: string;
  policy_decision_id?: string;
  due_at?: string;
  opened_at: string;
  age_seconds: number | null;
  reopened: number;
  /** Null when the run left Tower's recent-run window. */
  agent: string | null;
  agent_id: string | null;
  owner: string | null;
  team: string | null;
  declared: boolean;
  can_resolve: boolean;
}

export interface InboxSource {
  source: string;
  ok: boolean;
  open?: number;
  truncated?: boolean;
  can_resolve: boolean;
  error?: string;
}

export interface Inbox {
  open: number;
  items: InboxItem[];
  sources: InboxSource[];
  at: string;
}
