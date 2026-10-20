//! Base contract types (schema v1 envelopes, Context Pack v2, CompiledContext v1).
//!
//! Field names and enum spellings follow the published schemas exactly. Optional
//! fields are omitted when absent (never serialized as `null`) so that hashes
//! computed over these types match records produced by other conforming runtimes.
//!
//! Ingress should validate raw JSON with [`crate::schema`] first; these types are the
//! typed view the kernel computes over.

// Nullable optional fields (`"x": null` vs absent) are distinct on the wire.
#![allow(clippy::option_option)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Distinguishes an explicit JSON `null` (`Some(None)`) from an absent field (`None`).
fn nullable<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

/// Arbitrary JSON object (`Record<string, unknown>`).
pub type JsonObject = Map<String, Value>;
/// JsonLogic expression evaluated against the Run Context.
pub type JsonLogic = Value;

// ─── Cross-cutting primitives ──────────────────────────────────────────────

/// v1 approval-mode ladder. Ordered from least to most risky; `Ord` is the rank.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMode {
    ReadOnly,
    LocalWrite,
    Network,
    Delegated,
    Destructive,
}

impl ApprovalMode {
    pub const LADDER: [ApprovalMode; 5] = [
        ApprovalMode::ReadOnly,
        ApprovalMode::LocalWrite,
        ApprovalMode::Network,
        ApprovalMode::Delegated,
        ApprovalMode::Destructive,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ApprovalMode::ReadOnly => "read_only",
            ApprovalMode::LocalWrite => "local_write",
            ApprovalMode::Network => "network",
            ApprovalMode::Delegated => "delegated",
            ApprovalMode::Destructive => "destructive",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::LADDER.into_iter().find(|mode| mode.as_str() == value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionEffect {
    None,
    LocalState,
    ExternalState,
    PhysicalWorld,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionAuthority {
    Agent,
    Service,
    UserDelegated,
    HumanApproved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionReversibility {
    ReadOnly,
    Reversible,
    Compensatable,
    Irreversible,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionInteraction {
    Api,
    Browser,
    Computer,
    AgentToAgent,
    HumanHandoff,
}

/// Data classification; `Ord` is the sensitivity rank.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DataClassification {
    Public,
    Internal,
    Confidential,
    Restricted,
}

/// Multidimensional native action risk. Dimensions are never collapsed into a score.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionRisk {
    pub effect: ActionEffect,
    pub authority: ActionAuthority,
    pub reversibility: ActionReversibility,
    pub interaction: ActionInteraction,
    pub data_scope: DataClassification,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_ttl_seconds: Option<u64>,
}

/// Conjunctive policy over native risk dimensions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionRiskPolicy {
    pub allowed_effects: Vec<ActionEffect>,
    pub allowed_authorities: Vec<ActionAuthority>,
    pub allowed_reversibility: Vec<ActionReversibility>,
    pub allowed_interactions: Vec<ActionInteraction>,
    pub data_scope_ceiling: DataClassification,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_decision_ttl_seconds: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionRiskViolation {
    UnsupportedActionRisk,
    UnsupportedActionRiskPolicy,
    EffectNotAllowed,
    AuthorityNotAllowed,
    ReversibilityNotAllowed,
    InteractionNotAllowed,
    DataScopeExceedsCeiling,
    DecisionTtlRequired,
    DecisionTtlExceedsMaximum,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllowDeny {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionRiskEvaluation {
    pub verdict: AllowDeny,
    pub policy_applied: bool,
    pub approval_mode_projection: ApprovalMode,
    pub violations: Vec<ActionRiskViolation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextBucket {
    Business,
    Policy,
    Tool,
    Evidence,
    Memory,
    Session,
}

impl ContextBucket {
    pub const ALL: [ContextBucket; 6] = [
        ContextBucket::Business,
        ContextBucket::Policy,
        ContextBucket::Tool,
        ContextBucket::Evidence,
        ContextBucket::Memory,
        ContextBucket::Session,
    ];
}

/// Per-bucket integer map (`Partial<Record<ContextBucket, number>>`).
pub type BucketMap<T> = BTreeMap<ContextBucket, T>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    User,
    Service,
    Agent,
    Automation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    pub kind: PrincipalKind,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationAuthType {
    Oauth2,
    Saml,
    Oidc,
    Service,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserDelegation {
    pub auth_type: DelegationAuthType,
    pub scopes: Vec<String>,
    pub subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserClaims {
    pub user_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation: Option<UserDelegation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenure_days: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentLifecycle {
    Active,
    Deprecated,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityClaim {
    pub version: String,
    pub iss: String,
    pub sub: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    pub run_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub tenant_id: String,
    pub principal_chain: Vec<Principal>,
    pub scopes: Vec<String>,
    pub nbf: String,
    pub exp: String,
    pub kid: String,
    pub claim_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentIdentity {
    pub agent_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_urn: Option<String>,
    pub workload_identity: String,
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<AgentLifecycle>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_scopes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_chain: Option<Vec<Principal>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_claim: Option<IdentityClaim>,
}

/// Run budget. Limits plus accumulators that the runtime mutates under its own
/// concurrency control (the exact shared ledger lives in the execution contract).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunBudget {
    pub total_tokens: u64,
    pub bucket_tokens: BucketMap<u64>,
    pub max_tool_calls: u64,
    pub max_replan_attempts: u64,
    pub wall_clock_ms: u64,
    pub max_cost_cents: f64,
    pub tokens_used: u64,
    pub tool_calls_used: u64,
    pub latency_ms_used: u64,
    pub cost_cents_used: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunContext {
    pub run_id: String,
    pub trace_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub tenant_id: String,
    pub user: UserClaims,
    pub agent: AgentIdentity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    /// Highest approval mode this run may produce; tools above it are filtered out.
    pub safety_mode: ApprovalMode,
    pub run_budget: RunBudget,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<JsonObject>,
}

// ─── Context Pack v2 ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Compatibility {
    pub requires: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContractMeta {
    pub contract_name: String,
    pub contract_version: String,
    pub issuer: String,
    pub created_at: String,
    pub compatibility: Compatibility,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Tenant {
    pub tenant_id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnvironmentDefaults {
    pub language: String,
    pub timezone: String,
    pub currency: String,
    pub region: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PackMeta {
    pub pack_id: String,
    pub pack_version: String,
    pub tenant: Tenant,
    pub environment_defaults: EnvironmentDefaults,
    pub ttl_seconds: u64,
    pub data_classification: DataClassification,
}

impl PackMeta {
    /// `pack_id@pack_version`.
    pub fn pack_ref(&self) -> String {
        format!("{}@{}", self.pack_id, self.pack_version)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OntologyRef {
    pub namespace: String,
    pub version: String,
    pub entity_types: Vec<String>,
    pub relationship_types: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KnowledgeGraphRef {
    pub snapshot_pin_rule: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdentityLayerRef {
    pub ceid_namespaces: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IntelligenceRefs {
    pub ontology: OntologyRef,
    pub knowledge_graph: KnowledgeGraphRef,
    pub identity_layer: IdentityLayerRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding_keys: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BusinessSummary {
    pub what_we_do: String,
    pub who_we_serve: Vec<String>,
    pub differentiators: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BusinessContext {
    pub summary: BusinessSummary,
    pub non_negotiables: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct AppliesTo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleThen {
    pub allow: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prohibits: Option<Vec<String>>,
    /// `null` and absent are distinct on the wire; both mean "no gate".
    #[serde(default, deserialize_with = "nullable", skip_serializing_if = "Option::is_none")]
    pub requires_approval_gate: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_mode: Option<ApprovalMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arg_constraints: Option<JsonObject>,
}

impl RuleThen {
    pub fn approval_gate(&self) -> Option<&str> {
        self.requires_approval_gate.as_ref().and_then(|gate| gate.as_deref())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleElse {
    pub allow: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyRule {
    pub rule_id: String,
    pub applies_to: AppliesTo,
    #[serde(rename = "if")]
    pub condition: JsonLogic,
    pub then: RuleThen,
    #[serde(rename = "else", default, skip_serializing_if = "Option::is_none")]
    pub otherwise: Option<RuleElse>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_binding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub citations: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyDsl {
    pub language: String,
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyBundle {
    pub bundle_id: String,
    pub priority: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_from: Option<String>,
    pub policy_dsl: PolicyDsl,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prohibited_claims: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Guardrails {
    pub must_refuse: Vec<String>,
    pub must_escalate: Vec<String>,
    pub redaction_rules: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalGate {
    pub gate_id: String,
    pub when: JsonLogic,
    pub required_approver_role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyLayer {
    pub policy_bundles: Vec<PolicyBundle>,
    pub guardrails: Guardrails,
    pub approval_gates: Vec<ApprovalGate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_risk_policy: Option<ActionRiskPolicy>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AdapterType {
    Mcp,
    A2a,
    Openapi,
    Internal,
    Db,
    Custom,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdapterDefinition {
    pub adapter_id: String,
    #[serde(rename = "type")]
    pub adapter_type: AdapterType,
    pub endpoint_ref: String,
    pub capabilities: Vec<String>,
    /// Highest approval mode any capability under this adapter can produce.
    pub approval_mode: ApprovalMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_risks: Option<BTreeMap<String, ActionRisk>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolPermission {
    pub permission_id: String,
    pub adapter_id: String,
    pub capability: String,
    pub allow: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arg_constraints: Option<JsonObject>,
    #[serde(default, deserialize_with = "nullable", skip_serializing_if = "Option::is_none")]
    pub requires_approval_gate: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolingLayer {
    pub adapter_registry: Vec<AdapterDefinition>,
    pub permissions: Vec<ToolPermission>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionRight {
    Propose,
    Recommend,
    Execute,
    Escalate,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionSpec {
    pub decision_key: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_role: Option<String>,
    pub required_evidence: Vec<String>,
    pub allowed_outcomes: Vec<String>,
    pub approval_mode: ApprovalMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inputs_schema_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outputs_schema_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eligibility_rules: Option<JsonLogic>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_right: Option<DecisionRight>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_required: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionLayer {
    pub decision_specs: Vec<DecisionSpec>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteClass {
    EvidenceLink,
    Preference,
    DecisionOutcome,
    Correction,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TierTtls {
    pub working: String,
    pub episodic: String,
    pub semantic: String,
    pub durable: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConsentGating {
    pub pii_write_back_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryPolicy {
    pub tier_ttls: TierTtls,
    pub write_classes_allowed: Vec<WriteClass>,
    pub consent_gating: ConsentGating,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PromotionThresholds {
    pub auto_promote_confidence: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryLayer {
    pub memory_policy: MemoryPolicy,
    pub promotion_thresholds: PromotionThresholds,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvalTarget {
    pub intent: String,
    pub policy: f64,
    pub utility: f64,
    pub latency_p99_ms: u64,
    pub safety: f64,
    pub economics_cents_per_decision: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReleaseGate {
    pub metric: String,
    pub max_delta: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvaluationLayer {
    pub eval_targets: Vec<EvalTarget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_gates: Option<Vec<ReleaseGate>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToneAndComms {
    pub voice_attributes: Vec<String>,
    #[serde(rename = "do")]
    pub do_: Vec<String>,
    pub dont: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextPack {
    pub contract_meta: ContractMeta,
    pub pack_meta: PackMeta,
    pub intelligence_refs: IntelligenceRefs,
    pub business_context: BusinessContext,
    pub policy_layer: PolicyLayer,
    pub tooling_layer: ToolingLayer,
    pub decision_layer: DecisionLayer,
    pub memory_layer: MemoryLayer,
    pub evaluation_layer: EvaluationLayer,
    pub tone_and_comms: ToneAndComms,
}

// ─── Invocation contract ───────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvokeMode {
    Stream,
    Batch,
    LongRunning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvokeAttachment {
    pub artifact_id: String,
    pub media_type: String,
    pub sha256: String,
    pub uri: String,
}

/// W3C trace context carried on every invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvokeTrace {
    pub trace_id: String,
    pub span_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_flags: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tracestate: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baggage: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvokeInput {
    pub intent: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<JsonObject>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct InvokeRuntime {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_timeout_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_session_duration_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tool_calls: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_payload_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cost_cents: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvokeRequest {
    pub request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub tenant_id: String,
    pub user: UserClaims,
    pub agent: AgentIdentity,
    /// `pack_id@semver` references.
    pub context_pack_refs: Vec<String>,
    pub input: InvokeInput,
    pub mode: InvokeMode,
    pub runtime: InvokeRuntime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachments: Option<Vec<InvokeAttachment>>,
    pub trace: InvokeTrace,
}

// ─── Agent delegation ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DelegationScope {
    pub allowed_intents: Vec<String>,
    pub allowed_capabilities: Vec<String>,
    pub data_classification_ceiling: DataClassification,
    pub output_schema_ref: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectPolicy {
    IsolateUntilAccepted,
    ReadOnly,
}

/// Parent-issued, strictly narrowing authority envelope for a child run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentDelegationEnvelope {
    pub envelope_version: String,
    pub delegation_id: String,
    pub parent_run_id: String,
    pub child_run_id: String,
    pub trace_id: String,
    pub tenant_id: String,
    pub issuer: String,
    pub subject: String,
    pub principal_chain: Vec<Principal>,
    pub scope: DelegationScope,
    pub sub_budget: RunBudget,
    pub effect_policy: EffectPolicy,
    pub issued_at: String,
    pub expires_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancellation_ref: Option<String>,
    pub parent_claim_hash: String,
}

// ─── CompiledContext ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextOrigin {
    Pack,
    Policy,
    ToolRegistry,
    Retrieval,
    Memory,
    Runtime,
}

/// Whether a block may justify a governed action (separate from classification).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextIntegrity {
    Authoritative,
    Verified,
    Untrusted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextFreshness {
    Current,
    Stale,
    Unknown,
    NotApplicable,
}

/// Only control blocks may carry instructions; retrieved and recalled text is data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstructionTreatment {
    Control,
    DataOnly,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextProvenance {
    pub source_refs: Vec<String>,
    pub origin: ContextOrigin,
    pub integrity: ContextIntegrity,
    pub freshness: ContextFreshness,
    pub instruction_treatment: InstructionTreatment,
    pub inclusion_reason: String,
    pub content_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextBlock {
    pub block_id: String,
    pub bucket: ContextBucket,
    pub content: String,
    pub priority: i64,
    pub provenance: ContextProvenance,
    /// Deprecated mirror of `provenance.source_refs`, still emitted for compatibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance_refs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompiledPrompt {
    pub system: String,
    pub developer: String,
    pub task: String,
    pub context_blocks: Vec<ContextBlock>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyManifestEntry {
    pub bundle_id: String,
    pub rule_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityKind {
    Read,
    Write,
    Network,
    Delegated,
    Destructive,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct CapabilityMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<CapabilityKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_mode: Option<ApprovalMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_risk: Option<ActionRisk>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_risk_evaluation: Option<ActionRiskEvaluation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolManifestEntry {
    pub adapter_id: String,
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraints: Option<JsonObject>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_metadata: Option<BTreeMap<String, CapabilityMetadata>>,
}

/// Integrity labels admissible for retrieved evidence (never `authoritative`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceIntegrity {
    Verified,
    Untrusted,
}

/// Freshness labels admissible for retrieved evidence and memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceFreshness {
    Current,
    Stale,
    Unknown,
}

impl From<EvidenceIntegrity> for ContextIntegrity {
    fn from(value: EvidenceIntegrity) -> Self {
        match value {
            EvidenceIntegrity::Verified => ContextIntegrity::Verified,
            EvidenceIntegrity::Untrusted => ContextIntegrity::Untrusted,
        }
    }
}

impl From<EvidenceFreshness> for ContextFreshness {
    fn from(value: EvidenceFreshness) -> Self {
        match value {
            EvidenceFreshness::Current => ContextFreshness::Current,
            EvidenceFreshness::Stale => ContextFreshness::Stale,
            EvidenceFreshness::Unknown => ContextFreshness::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceManifestEntry {
    pub evidence_ref: String,
    pub source_id: String,
    pub hash: String,
    pub integrity: EvidenceIntegrity,
    pub freshness: EvidenceFreshness,
    /// Always `data_only`.
    pub instruction_treatment: InstructionTreatment,
    pub satisfies: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictStatus {
    Unresolved,
    Resolved,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConflictResolution {
    pub resolution_ref: String,
    pub selected_evidence_refs: Vec<String>,
}

/// A retrieval-layer conflict that stays visible through compilation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceConflictMarker {
    pub conflict_id: String,
    pub evidence_refs: Vec<String>,
    pub requirements: Vec<String>,
    pub status: ConflictStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predicate: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution: Option<ConflictResolution>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceRejectionReason {
    Untrusted,
    Stale,
    FreshnessUnknown,
    BudgetOmitted,
    UnresolvedConflict,
    SupersededByResolution,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RejectedEvidence {
    pub evidence_ref: String,
    pub requirements: Vec<String>,
    pub reasons: Vec<EvidenceRejectionReason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sufficiency {
    Sufficient,
    Insufficient,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceGate {
    pub decision_key: String,
    pub required: Vec<String>,
    pub satisfied: Vec<String>,
    pub unresolved: Vec<String>,
    pub rejected_evidence: Vec<RejectedEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conflicts: Option<Vec<EvidenceConflictMarker>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sufficiency: Option<Sufficiency>,
    pub commit_allowed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegedSinkPolicy {
    VerifiedOrUserIntent,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextAdmissionControls {
    pub data_only_block_ids: Vec<String>,
    pub untrusted_block_ids: Vec<String>,
    pub privileged_sink_policy: PrivilegedSinkPolicy,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeControls {
    pub must_refuse: Vec<String>,
    pub must_escalate: Vec<String>,
    pub approval_gates_active: Vec<String>,
    pub redaction_rules_active: Vec<String>,
    pub context_admission: ContextAdmissionControls,
    pub evidence_gates: Vec<EvidenceGate>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OmissionReason {
    BudgetExceeded,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextOmission {
    pub block_id: String,
    pub bucket: ContextBucket,
    pub reason: OmissionReason,
    pub estimated_tokens: u64,
    pub priority: i64,
    pub source_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct BudgetReport {
    pub tokens_allocated: BucketMap<u64>,
    pub tokens_used_at_compile: u64,
    pub tokens_used_by_bucket: BucketMap<u64>,
    pub bucket_truncations: BucketMap<bool>,
    pub dropped_block_ids: BucketMap<Vec<String>>,
    pub omissions: Vec<ContextOmission>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LedgerBudget {
    pub tokens_used_at_compile: u64,
    pub tokens_used_by_bucket: BucketMap<u64>,
    pub truncated_buckets: Vec<ContextBucket>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextLedger {
    pub pack_ref: String,
    pub intent: String,
    pub request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub policy_bundles: Vec<String>,
    pub policy_rule_ids: Vec<String>,
    pub tools: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub memory_refs: Vec<String>,
    pub dropped_block_ids: Vec<String>,
    pub omissions: Vec<ContextOmission>,
    pub budget: LedgerBudget,
    pub compiled_context_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifests {
    pub policy_manifest: Vec<PolicyManifestEntry>,
    pub tool_manifest: Vec<ToolManifestEntry>,
    pub evidence_manifest: Vec<EvidenceManifestEntry>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompiledContext {
    pub compiled_prompt: CompiledPrompt,
    pub manifests: Manifests,
    pub runtime_controls: RuntimeControls,
    pub budget_report: BudgetReport,
    pub context_ledger: ContextLedger,
}

// ─── Tool envelopes ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolCallEnvelope {
    pub envelope_version: String,
    pub tool_call_id: String,
    pub run_id: String,
    pub trace_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub capability_id: String,
    pub args: JsonObject,
    pub principal_chain: Vec<Principal>,
    pub approval_mode_requested: ApprovalMode,
    pub approval_mode_effective: ApprovalMode,
    pub approval_mode_highest: ApprovalMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_risk_requested: Option<ActionRisk>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_risk_effective: Option<ActionRisk>,
    #[serde(default, deserialize_with = "nullable", skip_serializing_if = "Option::is_none")]
    pub policy_decision_id: Option<Option<String>>,
    pub evidence_refs: Vec<String>,
    #[serde(default, deserialize_with = "nullable", skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<Option<String>>,
    #[serde(default, deserialize_with = "nullable", skip_serializing_if = "Option::is_none")]
    pub auth_ref: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<JsonObject>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolStatus {
    Ok,
    Error,
    Paused,
    Completed,
    Failed,
    Rejected,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolResultEnvelope {
    pub envelope_version: String,
    pub tool_call_id: String,
    pub run_id: String,
    pub trace_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub capability_id: String,
    pub status: ToolStatus,
    pub output: JsonObject,
    #[serde(default, deserialize_with = "nullable", skip_serializing_if = "Option::is_none")]
    pub error: Option<Option<String>>,
    pub artifacts: Vec<String>,
    pub citations: Vec<JsonObject>,
    pub mutations: Vec<String>,
    pub risk_tags: Vec<String>,
    #[serde(default, deserialize_with = "nullable", skip_serializing_if = "Option::is_none")]
    pub policy_decision_id: Option<Option<String>>,
    pub latency_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<JsonObject>,
}

// ─── Decision Record ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionStatus {
    Decided,
    Deferred,
    Rejected,
    Escalated,
    InFlight,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DecisionActorType {
    User,
    Agent,
    System,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionActor {
    #[serde(rename = "type")]
    pub actor_type: DecisionActorType,
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionApproval {
    pub gate_id: String,
    pub approver: String,
    pub approval_mode_effective: ApprovalMode,
    pub evidence_snapshot_hash: String,
    pub decided_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyVerdict {
    Allow,
    Deny,
    RequireApproval,
    Escalate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionPolicyDecision {
    pub policy_decision_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_id: Option<String>,
    pub rule_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<PolicyVerdict>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolLineageEntry {
    pub tool_call_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_result_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_mode_effective: Option<ApprovalMode>,
    #[serde(default, deserialize_with = "nullable", skip_serializing_if = "Option::is_none")]
    pub policy_decision_id: Option<Option<String>>,
    #[serde(default, deserialize_with = "nullable", skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_refs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mutation_refs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reversal_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionScorecard {
    pub policy: f64,
    pub utility: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency: Option<f64>,
    pub safety: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DecisionLineage {
    pub pack_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_versions: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_spec: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kg_snapshot: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluator_suite: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing_decision_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionReplayStatus {
    NotRun,
    ReplayEqual,
    ReplayMismatch,
    NotReplayable,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DecisionReplay {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_packet_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_case_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compiled_context_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_transcript_chain_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_status: Option<DecisionReplayStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff_refs: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DecisionAudit {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emitted_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionRationale {
    pub strategy: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alternatives_considered: Option<Vec<Value>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BudgetUsage {
    pub tokens: u64,
    pub tool_calls: u64,
    pub cost_usd_cents: f64,
    pub wall_clock_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionRecord {
    pub record_id: String,
    pub decision_key: String,
    pub decision_version: String,
    pub timestamp: String,
    pub status: DecisionStatus,
    pub actor: DecisionActor,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_snapshot_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_ids: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inputs_refs: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outputs: Option<JsonObject>,
    pub evidence_refs: Vec<String>,
    pub policy_decisions: Vec<DecisionPolicyDecision>,
    pub approvals: Vec<DecisionApproval>,
    pub controls_active: RuntimeControls,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_lineage: Option<Vec<ToolLineageEntry>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scorecard: Option<DecisionScorecard>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<DecisionRationale>,
    pub budget_usage: BudgetUsage,
    pub lineage: DecisionLineage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay: Option<DecisionReplay>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<DecisionAudit>,
    pub trace_id: String,
}

// ─── Replay packet ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplaySourceKind {
    DecisionRecord,
    QualityReplayCase,
    EnvironmentEpisode,
    OperatorCorrection,
    GoldenCase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SideEffectPolicy {
    TranscriptOnly,
    Sandbox,
    LiveDisallowed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayResultStatus {
    NotRun,
    ReplayEqual,
    ReplayMismatch,
    Fixed,
    StillFailing,
    Invalid,
    Superseded,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplayExpected {
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_record_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scorecard: Option<JsonObject>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplayLatestResult {
    pub status: ReplayResultStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eval_run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff_refs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplayPacket {
    pub replay_packet_id: String,
    pub trace_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub source_kind: ReplaySourceKind,
    pub source_ref: String,
    pub context_pack_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_context_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub knowledge_snapshot_ref: Option<String>,
    pub compiled_context_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_transcript_chain_hash: Option<String>,
    pub side_effect_policy: SideEffectPolicy,
    pub expected: ReplayExpected,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_result: Option<ReplayLatestResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<JsonObject>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_mode_rank_follows_ladder() {
        assert!(ApprovalMode::ReadOnly < ApprovalMode::LocalWrite);
        assert!(ApprovalMode::Delegated < ApprovalMode::Destructive);
        assert_eq!(ApprovalMode::parse("network"), Some(ApprovalMode::Network));
        assert_eq!(ApprovalMode::parse("admin"), None);
    }

    #[test]
    fn enums_use_published_spellings() {
        let json = serde_json::to_string(&(
            DataClassification::Confidential,
            DecisionStatus::InFlight,
            AdapterType::Openapi,
            ActionInteraction::AgentToAgent,
            DecisionActorType::System,
        ))
        .unwrap();
        assert_eq!(
            json,
            r#"["CONFIDENTIAL","IN_FLIGHT","OPENAPI","agent_to_agent","SYSTEM"]"#
        );
    }

    #[test]
    fn nullable_gate_round_trips() {
        let then: RuleThen = serde_json::from_str(r#"{"allow":true,"requires_approval_gate":null}"#).unwrap();
        assert_eq!(then.requires_approval_gate, Some(None));
        assert_eq!(
            serde_json::to_string(&then).unwrap(),
            r#"{"allow":true,"requires_approval_gate":null}"#
        );
        let then: RuleThen = serde_json::from_str(r#"{"allow":true}"#).unwrap();
        assert_eq!(serde_json::to_string(&then).unwrap(), r#"{"allow":true}"#);
    }
}
