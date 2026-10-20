//! Run admission: exact profile negotiation, pinned references and the protected
//! ledgers every governed effect of the run is accounted against.

use std::collections::{HashMap, HashSet};

use contextos_contract::canonical::sha256_canonical;
use contextos_contract::execution::{NegotiationStatus, ProfileRegistrySnapshot, WorkflowFeatureSet};
use contextos_contract::types::{CompiledContext, InvokeRequest, RunContext};
use contextos_kernel::budget_ledger::{
    CostUnitConversion, budget_limits_digest, budget_opening_digest, convert_legacy_cost_to_units,
};
use contextos_kernel::negotiation::negotiate_execution_contract;
use contextos_kernel::{CompileError, ContextPackCompiler};
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
    /// Normalized policy outcomes resolved at compile time for this run.
    pub policy_outcomes: Vec<Value>,
    pub profile_refs: Vec<Value>,
    pub release_refs: Vec<Value>,
    /// Capability ids that survived compilation for this run.
    pub surfaced_capabilities: HashSet<String>,
    /// Admitted evidence by `evidence_ref`, as artifact refs.
    pub evidence: HashMap<String, Value>,
    /// Namespace of this run's per-operation ledger documents.
    pub operation_ledger_id: String,
    pub budget_ledger_id: String,
    pub executor_generation: u64,
    pub deadline: String,
    /// The gateway's own principal; it observes adapter outcomes and usage.
    pub gateway_observer: Value,
    /// `compiled_context_hash` of the run's compiled context; delegations bind to it.
    #[serde(default)]
    pub compiled_context_hash: String,
    /// Present for delegated child runs.
    #[serde(default)]
    pub lineage: Option<crate::delegation::Lineage>,
    /// When the run was admitted, by the gateway's clock; the start of its wall clock.
    /// Empty for admissions recorded before it was kept (wall clock unknown).
    #[serde(default)]
    pub admitted_at: String,
    /// The authenticated principal that admitted the run (not the caller-named agent).
    #[serde(default)]
    pub admitted_by: String,
    /// The pinned Context Pack (release tuple) the run was compiled from.
    #[serde(default)]
    pub pack_ref: String,
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
    /// The pinned pack and the request it was compiled for; admission pins the
    /// policy outcomes resolved for this run.
    pub compiler: &'a ContextPackCompiler,
    pub request: &'a InvokeRequest,
    pub run_context: &'a RunContext,
    pub actor: Value,
    pub gateway_observer: Value,
    pub deadline: String,
    /// Admission time by the gateway's clock.
    pub admitted_at: String,
    /// The authenticated principal admitting the run.
    pub admitted_by: String,
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
    #[error("policy resolution failed: {0}")]
    Policy(#[from] CompileError),
    #[error("delegation rejected: {0:?}")]
    Delegation(Vec<String>),
    /// A store or audit dependency failed; the detail is for server logs only.
    #[error("a dependency is unavailable")]
    Unavailable(String),
}

/// Pins the compile-time policy resolution as normalized outcomes. Every applicable
/// rule is a business outcome of its bundle's priority: a disallowing rule denies, a
/// rule with an approval gate requires approval, otherwise it allows. A run with no
/// applicable rule has no business allowance, so its effects are denied.
fn policy_outcomes(request: &AdmissionRequest<'_>) -> Result<(Vec<Value>, Vec<Value>), AdmissionError> {
    let pack = request.compiler.pack();
    let pack_ref = pack.pack_meta.pack_ref();
    let rules = request
        .compiler
        .resolve_active_rules(request.request, request.run_context)?;
    let mut refs: Vec<(String, Value)> = Vec::new();
    let mut outcomes = Vec::new();
    for rule in rules {
        let bundle = pack
            .policy_layer
            .policy_bundles
            .iter()
            .find(|b| b.bundle_id == rule.bundle_id);
        let digest = bundle
            .and_then(|b| serde_json::to_value(b).ok())
            .and_then(|b| sha256_canonical(&b).ok())
            .unwrap_or_default();
        let bundle_ref = json!({"artifact_type": "policy_bundle", "artifact_id": rule.bundle_id, "version": pack_ref, "sha256": digest});
        if !refs.iter().any(|(id, _)| *id == rule.bundle_id) {
            refs.push((rule.bundle_id.clone(), bundle_ref.clone()));
        }
        let verdict = if !rule.allow {
            "deny"
        } else if rule.approval_gate.is_some() {
            "require_approval"
        } else {
            "allow"
        };
        outcomes.push(
            json!({"category": "business", "priority": rule.priority, "verdict": verdict,
            "rule_id": rule.rule_id, "bundle_ref": bundle_ref, "obligations": rule.requires}),
        );
    }
    Ok((refs.into_iter().map(|(_, r)| r).collect(), outcomes))
}

const USD_UNITS_PER_CENT: u64 = 100;

fn artifact(kind: &str, id: &str, sha256: String) -> Value {
    json!({"artifact_type": kind, "artifact_id": id, "version": "1", "sha256": sha256})
}

/// Admits a run: negotiates the exact contract, then creates its operation and budget
/// ledgers. Unsupported required controls block admission.
#[tracing::instrument(name = "contextos.admit", skip_all)]
pub async fn admit_run<S: DocumentStore>(
    store: &S,
    request: AdmissionRequest<'_>,
) -> Result<RunAdmission, AdmissionError> {
    let (policy_refs, policy_outcomes) = policy_outcomes(&request)?;
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
    // Document keys join run ids with `/` (run/decision, run/scores): a run id holding
    // one could alias another run's documents.
    if run_id.contains('/') {
        return Err(AdmissionError::ContractRejected(vec!["run_id_invalid:/".into()]));
    }
    let operation_ledger_id = format!("operations:{run_id}");
    let budget_ledger_id = format!("budget:{run_id}");

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
        policy_refs,
        policy_outcomes,
        surfaced_capabilities: surfaced,
        evidence,
        operation_ledger_id,
        budget_ledger_id,
        executor_generation: request.executor_generation,
        deadline: request.deadline,
        gateway_observer: request.gateway_observer,
        compiled_context_hash: request.compiled.context_ledger.compiled_context_hash.clone(),
        lineage: None,
        admitted_at: request.admitted_at,
        admitted_by: request.admitted_by,
        pack_ref: request.compiled.context_ledger.pack_ref.clone(),
        tenant_id,
        run_id,
    })
}
