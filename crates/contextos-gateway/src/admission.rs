//! Run admission: exact profile negotiation, pinned references and the protected
//! ledgers every governed effect of the run is accounted against.

use std::collections::{HashMap, HashSet};

use contextos_contract::execution::{NegotiationStatus, ProfileRegistrySnapshot, WorkflowFeatureSet};
use contextos_contract::types::CompiledContext;
use contextos_kernel::budget_ledger::{
    CostUnitConversion, budget_limits_digest, budget_opening_digest, convert_legacy_cost_to_units,
};
use contextos_kernel::negotiation::negotiate_execution_contract;
use contextos_store::{DocKey, DocKind, DocumentStore, StoreError};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Everything the gateway needs to govern effects for one admitted run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunAdmission {
    pub tenant_id: String,
    pub run_id: String,
    pub trace_id: String,
    pub contract: Value,
    pub contract_id: String,
    /// Effective required controls from negotiation (`ControlRef`s).
    pub required_controls: Vec<Value>,
    /// The authenticated workload acting for this run (`PrincipalRef`).
    pub actor: Value,
    pub policy_refs: Vec<Value>,
    pub profile_refs: Vec<Value>,
    pub release_refs: Vec<Value>,
    /// Capability ids that survived compilation for this run.
    pub surfaced_capabilities: HashSet<String>,
    /// Admitted evidence by `evidence_ref`, as artifact refs.
    pub evidence: HashMap<String, Value>,
    pub operation_ledger_id: String,
    pub budget_ledger_id: String,
    pub executor_generation: u64,
    pub deadline: String,
    /// The gateway's own principal; it observes adapter outcomes and usage.
    pub gateway_observer: Value,
}

/// Inputs to admission. `features` must be derived by trusted admission from the
/// workflow's actual capabilities, never from caller claims.
#[derive(Debug, Clone)]
pub struct AdmissionRequest<'a> {
    pub contract: &'a Value,
    pub support: &'a Value,
    pub registry: &'a ProfileRegistrySnapshot,
    pub features: WorkflowFeatureSet,
    pub compiled: &'a CompiledContext,
    pub actor: Value,
    pub policy_refs: Vec<Value>,
    pub gateway_observer: Value,
    pub deadline: String,
    pub executor_generation: u64,
    pub limits: BudgetLimits,
}

/// Original run limits. `cost_cents` keeps the legacy number semantics and must
/// convert exactly into cost units.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct BudgetLimits {
    pub tokens: u64,
    pub tool_calls: u64,
    pub replans: u64,
    pub cost_cents: f64,
}

#[derive(Debug, thiserror::Error)]
pub enum AdmissionError {
    #[error("execution contract rejected: {0:?}")]
    ContractRejected(Vec<String>),
    #[error("budget limits cannot be represented exactly: {0}")]
    Budget(String),
    #[error(transparent)]
    Store(#[from] StoreError),
}

const USD_UNITS_PER_CENT: u64 = 100;

fn artifact(kind: &str, id: &str, sha256: String) -> Value {
    json!({"artifact_type": kind, "artifact_id": id, "version": "1", "sha256": sha256})
}

/// Admits a run: negotiates the exact contract, then creates its operation and budget
/// ledgers. Unsupported required controls block admission.
pub async fn admit_run<S: DocumentStore>(
    store: &S,
    request: AdmissionRequest<'_>,
) -> Result<RunAdmission, AdmissionError> {
    let registry = serde_json::to_value(request.registry).unwrap_or(Value::Null);
    let features = serde_json::to_value(request.features).unwrap_or(Value::Null);
    let negotiation = negotiate_execution_contract(request.contract, request.support, &registry, &features);
    if negotiation.status != NegotiationStatus::Accepted {
        return Err(AdmissionError::ContractRejected(
            negotiation
                .reasons
                .iter()
                .map(|r| format!("{}:{}", r.code.as_str(), r.identifier))
                .collect(),
        ));
    }
    let contract = request.contract;
    let s = |key: &str| contract[key].as_str().unwrap_or_default().to_owned();
    let (tenant_id, run_id, contract_id) = (s("tenant_id"), s("run_id"), s("contract_id"));
    let operation_ledger_id = format!("operations:{run_id}");
    let budget_ledger_id = format!("budget:{run_id}");

    let operation_ledger = json!({
        "ledger_id": operation_ledger_id, "contract_id": contract_id, "run_id": run_id, "tenant_id": tenant_id,
        "revision": 0, "executor_generation": request.executor_generation, "deadline": request.deadline,
        "trusted_observers": [request.gateway_observer], "operations": [],
    });
    let unit = json!({"currency": "USD", "units_per_cent": USD_UNITS_PER_CENT});
    let cost_units = match convert_legacy_cost_to_units(&json!(request.limits.cost_cents), &unit) {
        CostUnitConversion::Converted { units } => units,
        CostUnitConversion::Rejected { reason_code } => return Err(AdmissionError::Budget(reason_code)),
    };
    let zero = json!({"tokens": 0, "tool_calls": 0, "replans": 0, "cost_units": 0});
    let mut budget_ledger = json!({
        "ledger_id": budget_ledger_id, "contract_id": contract_id, "parent_run_id": run_id, "tenant_id": tenant_id,
        "revision": 0, "executor_generation": request.executor_generation, "deadline": request.deadline,
        "cost_unit": unit,
        "original_limits": {"tokens": request.limits.tokens, "tool_calls": request.limits.tool_calls,
            "replans": request.limits.replans, "cost_cents": request.limits.cost_cents},
        "original_limits_ref": Value::Null, "opening_usage": zero, "opening_usage_ref": Value::Null,
        "ceiling": {"tokens": request.limits.tokens, "tool_calls": request.limits.tool_calls,
            "replans": request.limits.replans, "cost_units": cost_units},
        "used": zero, "reserved": zero, "unknown_usage_policy": "retain_reservation", "mutations": [],
        "trusted_observers": [request.gateway_observer], "reservations": [],
    });
    let limits_digest = budget_limits_digest(&budget_ledger).unwrap_or_default();
    let opening_digest = budget_opening_digest(&budget_ledger).unwrap_or_default();
    budget_ledger["original_limits_ref"] = artifact("budget_limits", &budget_ledger_id, limits_digest);
    budget_ledger["opening_usage_ref"] = artifact("budget_opening", &budget_ledger_id, opening_digest);

    store
        .create(
            &DocKey::new(&tenant_id, DocKind::OperationLedger, &operation_ledger_id),
            &operation_ledger,
        )
        .await?;
    store
        .create(
            &DocKey::new(&tenant_id, DocKind::BudgetLedger, &budget_ledger_id),
            &budget_ledger,
        )
        .await?;

    let surfaced = request
        .compiled
        .manifests
        .tool_manifest
        .iter()
        .flat_map(|t| t.capabilities.iter().map(move |c| format!("{}.{c}", t.adapter_id)))
        .collect();
    let evidence = request
        .compiled
        .manifests
        .evidence_manifest
        .iter()
        .map(|e| {
            (
                e.evidence_ref.clone(),
                artifact("evidence", &e.evidence_ref, e.hash.clone()),
            )
        })
        .collect();
    let refs = |key: &str| contract[key].as_array().cloned().unwrap_or_default();
    Ok(RunAdmission {
        trace_id: s("trace_id"),
        required_controls: negotiation
            .effective_required_controls
            .iter()
            .map(|c| serde_json::to_value(c).unwrap_or(Value::Null))
            .collect(),
        profile_refs: vec![serde_json::to_value(&request.registry.registry_ref).unwrap_or(Value::Null)],
        release_refs: refs("release_refs"),
        contract: contract.clone(),
        contract_id,
        actor: request.actor,
        policy_refs: request.policy_refs,
        surfaced_capabilities: surfaced,
        evidence,
        operation_ledger_id,
        budget_ledger_id,
        executor_generation: request.executor_generation,
        deadline: request.deadline,
        gateway_observer: request.gateway_observer,
        tenant_id,
        run_id,
    })
}
