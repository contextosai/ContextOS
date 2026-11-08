//! Pinned capability manifests.
//!
//! Admission of a capability comes only from a reviewed, pinned manifest, never from
//! protocol discovery: tool descriptions, annotations and prompts are metadata, not
//! permission. The manifest fixes the native risk, how resource/destination/amount
//! bindings are extracted from arguments, the recovery strategy and the per-call
//! budget reservation.

use contextos_contract::types::{ActionRisk, ApprovalMode};
use contextos_kernel::action_risk::project_action_risk;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStrategy {
    /// Query the provider for the outcome of an unknown attempt.
    Query,
    /// Retry under a verified provider idempotency contract.
    IdempotentRetry,
    /// Escalate unknown outcomes to an operator.
    ManualReconcile,
    /// Never retry.
    NoRetry,
}

impl RecoveryStrategy {
    pub fn as_str(self) -> &'static str {
        match self {
            RecoveryStrategy::Query => "query",
            RecoveryStrategy::IdempotentRetry => "idempotent_retry",
            RecoveryStrategy::ManualReconcile => "manual_reconcile",
            RecoveryStrategy::NoRetry => "no_retry",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderIdempotency {
    /// Pinned artifact describing the provider's idempotency guarantee.
    pub provider_contract_ref: Value,
    /// Provider key scope, e.g. `payments:<tenant>`.
    pub scope: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recovery {
    pub strategy: RecoveryStrategy,
    pub max_attempts: u32,
    /// One delay per retry (`max_attempts - 1` entries).
    pub retry_delays_seconds: Vec<u64>,
    #[serde(default)]
    pub idempotency: Option<ProviderIdempotency>,
    /// The provider's reported-state contract. It decides a finished `2xx` (HTTP) or a
    /// finished tool result (MCP, read from `structuredContent`) from the state it
    /// reports, and for HTTP how to look up an accepted, unfinished effect. Required
    /// for every effectful capability on an HTTP adapter, and on MCP with `[guards]
    /// require_completion_contracts` (on in production).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion: Option<CompletionCheck>,
    /// HTTP client-error statuses the provider guarantees it returns only when it did
    /// not and will not apply the effect (for example, validation that runs before any
    /// write). A status code alone does not establish that, so for an effectful HTTP
    /// capability every other 4xx leaves the outcome unknown.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_applied_statuses: Vec<u16>,
    /// JSON Pointer to the provider's own reference for the applied effect (its
    /// transaction or receipt id, a string) in a finished result: MCP
    /// `structuredContent`, or the HTTP response body (unset: `/id`). Recorded with the
    /// attempt as `external_ref`; an outcome contract that binds the effect needs it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_pointer: Option<String>,
}

/// Statuses a manifest may declare as not applied, at most.
pub const MAX_NOT_APPLIED_STATUSES: usize = 16;

/// The provider's reviewed completion contract for an accepted job: the status
/// endpoint, where the job state is in its response and which states are final.
/// Only listed states settle the effect; any other state, a missing job or a failed
/// lookup leaves it unknown, since absence does not prove the effect was not applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompletionCheck {
    /// Path segment of the status endpoint, queried as `{status_tool}/{external_ref}`.
    /// Required for HTTP; MCP looks tasks up with `tasks/get` and leaves it empty.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub status_tool: String,
    /// JSON Pointer to the job state (a string) in the status response.
    pub state_pointer: String,
    /// States in which the declared effect holds.
    pub confirmed: Vec<String>,
    /// States in which the effect holds in part.
    #[serde(default)]
    pub partial: Vec<String>,
    /// Terminal states in which the provider guarantees the job did not and will not
    /// apply the effect.
    #[serde(default)]
    pub not_applied: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AmountBinding {
    /// JSON pointer to an integer amount in minor units inside the arguments.
    pub minor_units_pointer: String,
    /// ISO 4217 currency code.
    pub currency: String,
}

/// How a capability's applied effect is undone: the capability that compensates it and
/// where each of that capability's arguments comes from. Compensation is a new governed
/// operation (fresh authority, policy, approval and budget), never a rollback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Compensation {
    /// The compensating capability (pinned and surfaced like any other).
    pub capability_id: String,
    /// Compensating argument name → source: `/arguments/<pointer>` into the original
    /// call's arguments, or `/external_ref`, the provider's reference recorded with the
    /// original effect (the reversal token; it never reaches the agent).
    pub arguments: std::collections::BTreeMap<String, String>,
}

/// Compensating arguments a manifest may map at most.
pub const MAX_COMPENSATION_ARGUMENTS: usize = 32;

impl Compensation {
    fn validate(&self, capability_id: &str) -> Result<(), &'static str> {
        if self.capability_id.is_empty() || self.capability_id == capability_id {
            return Err("capability_id must name another capability");
        }
        if self.arguments.len() > MAX_COMPENSATION_ARGUMENTS {
            return Err("too many arguments");
        }
        for (name, source) in &self.arguments {
            if name.is_empty() {
                return Err("argument names must be non-empty");
            }
            let pointer_ok = source
                .strip_prefix("/arguments")
                .is_some_and(|rest| rest.starts_with('/'));
            if !(pointer_ok || source == "/external_ref") {
                return Err("sources must be /arguments/<pointer> or /external_ref");
            }
        }
        Ok(())
    }
}

/// Budget reserved for one attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallCost {
    pub tokens: u64,
    pub tool_calls: u64,
    pub replans: u64,
    pub cost_units: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityManifest {
    /// `<adapter_id>.<capability>`.
    pub capability_id: String,
    pub capability_version: String,
    pub adapter_id: String,
    /// Tool name at the protocol layer (MCP tool, OpenAPI operation id, …).
    pub protocol_tool: String,
    pub purpose_id: String,
    pub desired_effect: String,
    pub action_risk: ActionRisk,
    pub approval_mode: ApprovalMode,
    /// Pointers into arguments whose string values are the resources acted on.
    #[serde(default)]
    pub resource_pointers: Vec<String>,
    /// Pointers into arguments whose string values are effect recipients.
    #[serde(default)]
    pub destination_pointers: Vec<String>,
    /// The capability sends data to a fixed recipient (its adapter). With a data
    /// governance provider, data flow is evaluated for every call of a capability
    /// that sends data or names recipients.
    #[serde(default)]
    pub sends_data: bool,
    #[serde(default)]
    pub amount: Option<AmountBinding>,
    /// Identical calls under different operation keys are distinct effects (for example
    /// two equal top-ups). Off by default: a new operation repeating an effect the run
    /// already applied is refused with `effect_repeated`.
    #[serde(default)]
    pub repeatable: bool,
    pub recovery: Recovery,
    pub timeout_ms: u64,
    pub reservation: CallCost,
    /// Pinned digest refs of the adapter build and this capability definition.
    pub adapter_ref: Value,
    pub capability_ref: Value,
    /// Reviewed JSON Schema (draft 2020-12) for the arguments. When present, calls
    /// whose arguments do not conform are rejected before authorization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<Value>,
    /// Reviewed JSON Schema for the tool's output. When present, a confirmed effect
    /// whose output does not conform is still recorded, but its output is withheld
    /// from the agent and the violation is audited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>,
    /// Human-readable description shown to agents (for example as an MCP tool).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// How an applied effect of this capability is compensated. Only `reversible` or
    /// `compensatable` capabilities may declare it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compensation: Option<Compensation>,
    /// Reviewed digest of the upstream tool's definition (name, input and output
    /// schemas, annotations); until it is checked, and while it differs, the capability
    /// refuses calls (see [`crate::upstream_drift`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_tool_digest: Option<String>,
    /// Reviewed digest of the upstream tool's description; a change is reported, not
    /// refused, since agents see the manifest's own description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_description_digest: Option<String>,
    /// What must be observed, by whom and by when, before an applied effect counts as
    /// done (see [`crate::outcomes`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<OutcomeContract>,
    /// Information-flow labels of the tool's output and what it may send out (see
    /// [`crate::information_flow`]); absent, its output is untrusted `INTERNAL`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<crate::information_flow::FlowLabels>,
    /// Which arguments identify the business request, so the same request sent from
    /// another run is refused while its claim stands (see [`crate::intent_guard`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent: Option<crate::intent_guard::IntentKey>,
}

/// What happens when an outcome's witness has not reported by its deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnMissed {
    /// Open an escalation for a human (once).
    #[default]
    Escalate,
}

/// What a witness's observation establishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeBinds {
    /// This particular effect completed: the observation names the provider's
    /// reference for it (`receipt`), and one observation closes one effect.
    Effect,
    /// The action's resource is in the postcondition's state: one observation of that
    /// state may close every effect on the resource it was taken after.
    State,
}

/// A capability's outcome contract: after its effect is applied, the run cannot
/// complete until `witness` (an `[[evidence_issuers]]` issuer) attests
/// `postcondition` for the action's resource, within `within_seconds`. `binds` says
/// whether that establishes the effect itself or only the resource's state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeContract {
    pub witness: String,
    pub postcondition: String,
    pub within_seconds: u64,
    pub binds: OutcomeBinds,
    #[serde(default)]
    pub on_missed: OnMissed,
}

/// The longest an outcome may wait for its witness.
pub const MAX_OUTCOME_WITHIN_SECONDS: u64 = 30 * 86_400;

impl OutcomeContract {
    fn validate(&self) -> Result<(), &'static str> {
        if self.witness.is_empty() || self.witness.len() > 512 || self.witness.chars().any(char::is_control) {
            return Err("witness must name an evidence issuer");
        }
        if !contextos_contract::validation::is_contract_identifier(&self.postcondition) {
            return Err("postcondition must be an identifier");
        }
        if !(1..=MAX_OUTCOME_WITHIN_SECONDS).contains(&self.within_seconds) {
            return Err("within_seconds must be between 1 and 2592000");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    #[error("capability {0} approval_mode is less conservative than its ActionRisk projection")]
    NonConservativeApprovalMode(String),
    #[error("capability {0} has {1} retry delays for {2} attempts")]
    RetryDelays(String, usize, u32),
    #[error("capability {0} declares idempotent_retry without a provider idempotency contract")]
    MissingIdempotency(String),
    #[error("capability {0} must be named <adapter_id>.<capability>")]
    CapabilityId(String),
    #[error("capability {0} timeout must be between 1 ms and 10 minutes")]
    Timeout(String),
    #[error("capability {0} input_schema does not compile: {1}")]
    InputSchema(String, String),
    #[error("capability {0} output_schema does not compile: {1}")]
    OutputSchema(String, String),
    #[error("capability {0} completion check is invalid: {1}")]
    Completion(String, &'static str),
    #[error("capability {0} compensation is invalid: {1}")]
    Compensation(String, &'static str),
    #[error("capability {0} not_applied_statuses must list at most 16 distinct 4xx statuses")]
    NotAppliedStatuses(String),
    #[error("capability {0} repeats the capability_ref of a pinned or retired version")]
    DuplicateCapabilityRef(String),
    #[error("capability {0} outcome contract is invalid: {1}")]
    Outcome(String, &'static str),
    #[error("capability {0} intent key is invalid: {1}")]
    Intent(String, &'static str),
}

impl CompletionCheck {
    fn validate(&self) -> Result<(), &'static str> {
        if !self.status_tool.is_empty() && !is_path_segment(&self.status_tool) {
            return Err("status_tool must be a path segment of letters, digits, '.', '_' or '-'");
        }
        if !self.state_pointer.starts_with('/') {
            return Err("state_pointer must be a JSON Pointer");
        }
        if self.confirmed.is_empty() {
            return Err("confirmed must list at least one state");
        }
        let states = [&self.confirmed, &self.partial, &self.not_applied];
        let mut seen = std::collections::HashSet::new();
        if states
            .iter()
            .flat_map(|s| s.iter())
            .any(|s| s.is_empty() || !seen.insert(s))
        {
            return Err("states must be non-empty and listed once");
        }
        Ok(())
    }

    /// The outcome a provider-reported job state establishes, if any.
    pub fn outcome(&self, state: &str) -> Option<crate::EffectOutcome> {
        let listed = |states: &[String]| states.iter().any(|s| s == state);
        if listed(&self.confirmed) {
            Some(crate::EffectOutcome::Confirmed)
        } else if listed(&self.partial) {
            Some(crate::EffectOutcome::Partial)
        } else if listed(&self.not_applied) {
            Some(crate::EffectOutcome::NotApplied)
        } else {
            None
        }
    }
}

/// A tool or endpoint name usable as one URL path segment.
pub fn is_path_segment(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

impl CapabilityManifest {
    /// Structural review of a manifest before it can be pinned.
    pub fn validate(&self) -> Result<(), ManifestError> {
        let id = &self.capability_id;
        if !id.starts_with(&format!("{}.", self.adapter_id)) || id.len() <= self.adapter_id.len() + 1 {
            return Err(ManifestError::CapabilityId(id.clone()));
        }
        if self.approval_mode < project_action_risk(&self.action_risk) {
            return Err(ManifestError::NonConservativeApprovalMode(id.clone()));
        }
        let expected = self.recovery.max_attempts.saturating_sub(1) as usize;
        if self.recovery.max_attempts == 0 || self.recovery.retry_delays_seconds.len() != expected {
            return Err(ManifestError::RetryDelays(
                id.clone(),
                self.recovery.retry_delays_seconds.len(),
                self.recovery.max_attempts,
            ));
        }
        if self.recovery.strategy == RecoveryStrategy::IdempotentRetry && self.recovery.idempotency.is_none() {
            return Err(ManifestError::MissingIdempotency(id.clone()));
        }
        if let Some(completion) = &self.recovery.completion {
            completion
                .validate()
                .map_err(|reason| ManifestError::Completion(id.clone(), reason))?;
        }
        if self
            .recovery
            .reference_pointer
            .as_ref()
            .is_some_and(|p| !p.starts_with('/'))
        {
            return Err(ManifestError::Completion(
                id.clone(),
                "reference_pointer must be a JSON Pointer",
            ));
        }
        let statuses = &self.recovery.not_applied_statuses;
        if statuses.len() > MAX_NOT_APPLIED_STATUSES
            || statuses.iter().any(|s| !(400..500).contains(s))
            || statuses.iter().collect::<std::collections::BTreeSet<_>>().len() != statuses.len()
        {
            return Err(ManifestError::NotAppliedStatuses(id.clone()));
        }
        if self.timeout_ms == 0 || self.timeout_ms > 600_000 {
            return Err(ManifestError::Timeout(id.clone()));
        }
        if let Some(schema) = &self.input_schema {
            contextos_contract::schema::ArgumentSchema::compile(schema)
                .map_err(|e| ManifestError::InputSchema(id.clone(), e))?;
        }
        if let Some(schema) = &self.output_schema {
            contextos_contract::schema::ArgumentSchema::compile(schema)
                .map_err(|e| ManifestError::OutputSchema(id.clone(), e))?;
        }
        if let Some(compensation) = &self.compensation {
            use contextos_contract::types::ActionReversibility;
            if !matches!(
                self.action_risk.reversibility,
                ActionReversibility::Reversible | ActionReversibility::Compensatable
            ) {
                return Err(ManifestError::Compensation(
                    id.clone(),
                    "only a reversible or compensatable capability can declare compensation",
                ));
            }
            compensation
                .validate(id)
                .map_err(|reason| ManifestError::Compensation(id.clone(), reason))?;
        }
        if let Some(outcome) = &self.outcome {
            if self.action_risk.effect == contextos_contract::types::ActionEffect::None {
                return Err(ManifestError::Outcome(
                    id.clone(),
                    "only an effectful capability can declare one",
                ));
            }
            outcome
                .validate()
                .map_err(|reason| ManifestError::Outcome(id.clone(), reason))?;
            if outcome.binds == OutcomeBinds::Effect && self.recovery.reference_pointer.is_none() {
                return Err(ManifestError::Outcome(
                    id.clone(),
                    "binds = effect needs recovery.reference_pointer: the provider's reference the witness must name",
                ));
            }
        }
        if let Some(intent) = &self.intent {
            if self.action_risk.effect == contextos_contract::types::ActionEffect::None {
                return Err(ManifestError::Intent(
                    id.clone(),
                    "only an effectful capability can declare one",
                ));
            }
            if self.repeatable {
                return Err(ManifestError::Intent(
                    id.clone(),
                    "a repeatable capability has no single request to deduplicate",
                ));
            }
            intent
                .validate()
                .map_err(|reason| ManifestError::Intent(id.clone(), reason))?;
        }
        Ok(())
    }

    /// The adapter-local capability name.
    pub fn capability_name(&self) -> &str {
        &self.capability_id[self.adapter_id.len() + 1..]
    }
}

/// Words in a tool or capability name that usually mean the call destroys or replaces
/// something. A naming hint for reviewers, never a decision: `ctx init-tool` offers
/// it, and startup notes a capability so named that is declared reversible or
/// approved below `destructive`.
const DESTRUCTIVE_VERBS: &[&str] = &[
    "delete",
    "drop",
    "destroy",
    "terminate",
    "purge",
    "truncate",
    "wipe",
    "erase",
    "remove",
    "rm",
    "reset",
    "replace",
    "overwrite",
    "deprovision",
    "decommission",
    "kill",
    "shutdown",
    "format",
];

/// The destructive verb `name` contains as a word (split on `_`, `-`, `.`, `/` and
/// lower-to-upper case changes), if any.
#[must_use]
pub fn destructive_verb(name: &str) -> Option<&'static str> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut previous_lower = false;
    for c in name.chars() {
        if (!c.is_ascii_alphanumeric() || (c.is_ascii_uppercase() && previous_lower)) && !word.is_empty() {
            words.push(std::mem::take(&mut word));
        }
        if c.is_ascii_alphanumeric() {
            word.push(c.to_ascii_lowercase());
        }
        previous_lower = c.is_ascii_lowercase();
    }
    words.push(word);
    DESTRUCTIVE_VERBS
        .iter()
        .copied()
        .find(|verb| words.iter().any(|w| w == verb))
}

/// Marks a field of a drafted manifest (`ctx init-tool`) that a person must decide.
pub const REVIEW_MARKER: &str = "REVIEW:";

/// JSON pointers of every string in a manifest document that still starts with
/// [`REVIEW_MARKER`]. Loaders refuse a manifest while any remain, so a draft cannot
/// be pinned before review even where its placeholder would otherwise parse (a
/// description, a pointer).
#[must_use]
pub fn unreviewed(document: &Value) -> Vec<String> {
    fn walk(value: &Value, pointer: &mut String, found: &mut Vec<String>) {
        match value {
            Value::String(s) if s.trim_start().starts_with(REVIEW_MARKER) => found.push(pointer.clone()),
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    let len = pointer.len();
                    pointer.push('/');
                    pointer.push_str(&index.to_string());
                    walk(item, pointer, found);
                    pointer.truncate(len);
                }
            }
            Value::Object(fields) => {
                for (key, item) in fields {
                    let len = pointer.len();
                    pointer.push('/');
                    pointer.push_str(&key.replace('~', "~0").replace('/', "~1"));
                    walk(item, pointer, found);
                    pointer.truncate(len);
                }
            }
            _ => {}
        }
    }
    let mut found = Vec::new();
    walk(document, &mut String::new(), &mut found);
    found
}

#[cfg(test)]
mod review_tests {
    use super::unreviewed;
    use serde_json::json;

    #[test]
    fn finds_every_marked_string_by_pointer() {
        let draft = json!({
            "purpose_id": "REVIEW: a purpose",
            "description": "  REVIEW: upstream says hi",
            "resource_pointers": ["/order_id", "REVIEW: more?"],
            "action_risk": {"effect": "REVIEW: none|external_state", "authority": "service"},
            "a/b": "REVIEW: escaped",
            "note": "not a REVIEW: marker",
        });
        let mut found = unreviewed(&draft);
        found.sort();
        assert_eq!(
            found,
            [
                "/action_risk/effect",
                "/a~1b",
                "/description",
                "/purpose_id",
                "/resource_pointers/1"
            ]
        );
        assert_eq!(
            unreviewed(&json!({"purpose_id": "support.refund"})),
            Vec::<String>::new()
        );
    }
}
