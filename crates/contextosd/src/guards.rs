//! `[guards]`: limits on agent behaviour and what the deployment requires of runs
//! and capabilities. Several default on in production and off in development.

use serde::{Deserialize, Serialize};

/// Guards on agent behaviour.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct GuardsConfig {
    /// Identical tool calls (same capability and arguments, new operation) a run may
    /// make before the next is refused with `loop_detected`; 0 disables the guard.
    #[serde(default = "default_identical_calls")]
    pub identical_tool_calls: u64,
    /// Refuse a new operation whose effect is identical (same capability and
    /// arguments) to one the run already applied, unless the capability is
    /// `repeatable`: `effect_repeated`. On by default.
    #[serde(default = "default_true")]
    pub refuse_repeated_effects: bool,
    /// Tokens every model-call reservation covers at least, so an executor cannot
    /// reserve (and self-settle) a model call for nothing.
    #[serde(default = "default_model_call_tokens")]
    pub model_call_min_tokens: u64,
    /// Release artifact types every run's execution contract must pin in
    /// `release_refs` (e.g. `["model_profile", "evaluator_suite"]`), so each decision
    /// records which model and evaluators produced it. Unset: `model_profile` and
    /// `evaluator_suite` in production, none in development; `[]` opts out explicitly.
    #[serde(default)]
    pub required_release_refs: Option<Vec<String>>,
    /// Refuse runs whose user claims carry no `role`, so policy never evaluates a role
    /// nobody asserted (the reference compiler defaults it; see the threat model).
    /// Unset: on in production, off in development.
    #[serde(default)]
    pub require_user_role: Option<bool>,
    /// Admit recalled memory (`deps.promoted_memory`) that no memory-governance service
    /// can verify. Without `[providers.memory]`, production refuses such memory unless
    /// this is set; with it, every item is verified against promoted state regardless.
    #[serde(default)]
    pub trust_supplied_memory: bool,
    /// Refuse to start with a capability that lacks an `input_schema` or
    /// `output_schema`, so every call's arguments and results are checked against a
    /// reviewed shape (read-only tools too: their results carry most injected content).
    #[serde(default)]
    pub require_tool_schemas: bool,
    /// Online validation: a run may complete only when every decision that applied an
    /// effect holds an independent score whose `policy` and `safety` meet these floors.
    /// Unset: on in production (policy 1.0, safety 0.9), off in development; `true` uses
    /// those floors, `false` opts out explicitly, a table sets them.
    #[serde(default)]
    pub completion_requires_scores: Option<CompletionScores>,
    /// Refuse runs that can apply effects unless they state what their principal
    /// authorized (`task_authorization`), so no effect relies on the agent's own reading
    /// of the request.
    #[serde(default)]
    pub require_task_authorization: bool,
    /// Refuse to start with an effectful MCP capability that declares no
    /// `recovery.completion`, so a finished result is confirmed by the state the tool
    /// reports, not by the absence of `isError`. Unset: on in production, off in
    /// development. (Effectful HTTP capabilities always need one.)
    #[serde(default)]
    pub require_completion_contracts: Option<bool>,
}

/// `[guards] completion_requires_scores`: on or off, or explicit floors.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(untagged)]
pub enum CompletionScores {
    Enabled(bool),
    Floors(ScoreFloors),
}

/// The floors `completion_requires_scores = true` and production use.
pub const DEFAULT_SCORE_FLOORS: ScoreFloors = ScoreFloors {
    policy_floor: 1.0,
    safety_floor: 0.9,
};

/// Score floors for [`GuardsConfig::completion_requires_scores`], each in 0..=1.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScoreFloors {
    pub policy_floor: f64,
    pub safety_floor: f64,
}

fn default_model_call_tokens() -> u64 {
    1_000
}

fn default_true() -> bool {
    true
}

fn default_identical_calls() -> u64 {
    5
}

impl Default for GuardsConfig {
    fn default() -> Self {
        Self {
            identical_tool_calls: default_identical_calls(),
            refuse_repeated_effects: true,
            model_call_min_tokens: default_model_call_tokens(),
            required_release_refs: None,
            require_user_role: None,
            trust_supplied_memory: false,
            require_tool_schemas: false,
            completion_requires_scores: None,
            require_task_authorization: false,
            require_completion_contracts: None,
        }
    }
}
