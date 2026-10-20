//! Ports a deployment plugs into the gateway.
//!
//! The gateway never verifies a signature, looks up a live revocation list, asks an
//! approver or touches a provider itself. Trusted adapters do, and hand the gateway
//! *verified, normalized observations*; the kernel then decides whether those facts
//! are current, correctly bound and sufficient.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::admission::RunAdmission;
use crate::manifest::CapabilityManifest;

/// Port failure. Any failure to obtain a required fact blocks the effect.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{port} unavailable: {message}")]
pub struct PortError {
    pub port: &'static str,
    pub message: String,
}

impl PortError {
    pub fn new(port: &'static str, message: impl Into<String>) -> Self {
        Self {
            port,
            message: message.into(),
        }
    }
}

/// Trusted wall clock. Kernel decisions receive its readings as explicit inputs.
pub trait Clock: Send + Sync {
    /// Current time as a contract timestamp.
    fn now(&self) -> String;
}

/// Unique identifier source for attempts, mutations and records.
pub trait IdSource: Send + Sync {
    fn new_id(&self, prefix: &str) -> String;
}

/// Verified identity and mandate facts for one action binding: the parts of
/// `AuthorityValidationInput` other than the binding and evaluation time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthorityFacts {
    pub authenticated: Value,
    pub leaf_grant_ref: Value,
    pub grants: Vec<Value>,
    pub observations: Vec<Value>,
    pub run_links: Vec<Value>,
}

#[async_trait]
pub trait AuthorityProvider: Send + Sync {
    async fn authority(&self, admission: &RunAdmission, binding: &Value) -> Result<AuthorityFacts, PortError>;
}

/// Normalized applicable policy outcomes (`NormalizedPolicyOutcome`) for a binding.
#[async_trait]
pub trait PolicyProvider: Send + Sync {
    async fn outcomes(&self, admission: &RunAdmission, binding: &Value) -> Result<Vec<Value>, PortError>;
}

/// Verified observations (`ConstraintObservation`) for independent required controls.
#[async_trait]
pub trait ConstraintProvider: Send + Sync {
    async fn observations(
        &self,
        admission: &RunAdmission,
        required: &[Value],
        action_digest: &str,
    ) -> Result<Vec<Value>, PortError>;
}

/// Approval records bound to an action digest.
#[async_trait]
pub trait ApprovalProvider: Send + Sync {
    /// Stored, verified approval material (`ApprovalValidationInput` without
    /// `binding`, `redemption_state` and `evaluation_time`) if any exists.
    async fn approval(&self, admission: &RunAdmission, action_digest: &str) -> Result<Option<Value>, PortError>;

    /// Opens an approval request for the exact binding; returns its id.
    async fn request(
        &self,
        admission: &RunAdmission,
        binding: &Value,
        action_digest: &str,
    ) -> Result<String, PortError>;
}

/// The outcome an adapter observed for one attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectOutcome {
    Confirmed,
    NotApplied,
    NotDispatched,
    Partial,
    Unknown,
}

impl EffectOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            EffectOutcome::Confirmed => "confirmed",
            EffectOutcome::NotApplied => "not_applied",
            EffectOutcome::NotDispatched => "not_dispatched",
            EffectOutcome::Partial => "partial",
            EffectOutcome::Unknown => "unknown",
        }
    }
}

/// One governed call to a provider. The operation id and provider key are stable
/// across attempts; the attempt id is fresh for every attempt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdapterCall {
    pub tenant_id: String,
    pub run_id: String,
    pub trace_id: String,
    pub operation_id: String,
    pub attempt_id: String,
    pub action_digest: String,
    pub protocol_tool: String,
    pub arguments: Value,
    pub idempotency_key: Option<String>,
    pub deadline: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdapterResponse {
    pub outcome: EffectOutcome,
    /// `true` when the provider's answer is final for this attempt.
    pub definitive: bool,
    pub output: serde_json::Map<String, Value>,
    pub external_ref: Option<String>,
    /// Actual cost in ledger cost units, if the provider reports it.
    pub cost_units: Option<u64>,
}

impl AdapterResponse {
    /// What the gateway records when the provider never answered.
    pub fn unknown() -> Self {
        Self {
            outcome: EffectOutcome::Unknown,
            definitive: false,
            output: serde_json::Map::new(),
            external_ref: None,
            cost_units: None,
        }
    }
}

/// A protocol adapter (MCP, OpenAPI, A2A, internal). Credentials are injected by
/// the adapter from a broker; the model never sees them.
#[async_trait]
pub trait Adapter: Send + Sync {
    async fn invoke(&self, manifest: &CapabilityManifest, call: &AdapterCall) -> AdapterResponse;

    /// Asks the provider for the current outcome of an earlier attempt, identified by
    /// the external reference that attempt returned (for example an MCP task id).
    /// `call.attempt_id` is a fresh request id; operation identity and the provider
    /// key are the original ones. `None` when the provider cannot be queried, in
    /// which case only an authorized operator can reconcile.
    async fn query(
        &self,
        _manifest: &CapabilityManifest,
        _call: &AdapterCall,
        _external_ref: &str,
    ) -> Option<AdapterResponse> {
        None
    }
}
