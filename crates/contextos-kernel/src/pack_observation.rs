//! What a Context Pack decides for one case, read the way the runtime reads it at
//! admission. The release gate compares two packs on these observations; pack tests
//! check them against an author's expectations.

use std::collections::{BTreeMap, BTreeSet};

use contextos_contract::canonical::sha256_canonical;
use contextos_contract::types::{CompiledContext, ContextPack, InvokeRequest, RunContext};
use serde_json::{Value, json};

use crate::authorization::{ComposedPolicyOutcome, compose_policy_outcomes};
use crate::{CompileDeps, ContextPackCompiler, ResolvedRule};

/// Composed verdicts from most to least restrictive (`error` counts as `deny`).
pub(crate) const VERDICTS: [&str; 4] = ["deny", "escalate", "require_approval", "allow"];

#[derive(Debug, Clone)]
pub(crate) struct Observed {
    /// Surfaced capabilities as `adapter_id.capability`.
    pub capabilities: BTreeSet<String>,
    /// Index into [`VERDICTS`].
    pub verdict: usize,
    pub obligations: BTreeSet<String>,
    /// Ids of the rules that applied to the case.
    pub rules: BTreeSet<String>,
    /// Evidence gates by decision key: whether commit is allowed.
    pub gates: BTreeMap<String, bool>,
    pub hash: String,
}

/// The compile dependencies a case carries (`evidence`, `evidence_conflicts`,
/// `promoted_memory`), each defaulting to empty.
pub(crate) fn deps(value: &Value) -> CompileDeps {
    let list = |key: &str| value[key].as_array().cloned().unwrap_or_default();
    CompileDeps {
        evidence: list("evidence"),
        evidence_conflicts: list("evidence_conflicts"),
        promoted_memory: list("promoted_memory"),
    }
}

/// The business policy outcome admission records for `rule`.
fn business_outcome(pack: &ContextPack, rule: &ResolvedRule) -> Value {
    let digest = pack
        .policy_layer
        .policy_bundles
        .iter()
        .find(|b| b.bundle_id == rule.bundle_id)
        .and_then(|b| serde_json::to_value(b).ok())
        .and_then(|b| sha256_canonical(&b).ok())
        .unwrap_or_else(|| format!("sha256:{}", "0".repeat(64)));
    let verdict = if !rule.allow {
        "deny"
    } else if rule.approval_gate.is_some() {
        "require_approval"
    } else {
        "allow"
    };
    json!({"category": "business", "priority": rule.priority, "verdict": verdict, "rule_id": rule.rule_id,
        "bundle_ref": {"artifact_type": "policy_bundle", "artifact_id": rule.bundle_id, "version": "1", "sha256": digest},
        "obligations": rule.requires})
}

/// Composes the verdict of the rules that apply, exactly as admission does: the same
/// normalized business outcomes, highest-priority bundles deciding.
pub(crate) fn compose(pack: &ContextPack, rules: &[ResolvedRule]) -> ComposedPolicyOutcome {
    let outcomes: Vec<Value> = rules.iter().map(|rule| business_outcome(pack, rule)).collect();
    compose_policy_outcomes(&Value::Array(outcomes))
}

/// The index into [`VERDICTS`] of a composed verdict (`error` counts as `deny`).
pub(crate) fn verdict_index(composed: &ComposedPolicyOutcome) -> usize {
    VERDICTS.iter().position(|v| *v == composed.verdict).unwrap_or(0)
}

/// Compiles the case and composes its policy verdict (see [`compose`]).
pub(crate) fn observe(
    compiler: &ContextPackCompiler,
    request: &InvokeRequest,
    run_context: &RunContext,
    case_deps: &Value,
) -> Result<Observed, String> {
    let compiled: CompiledContext = compiler
        .compile(request, run_context, &deps(case_deps))
        .map_err(|e| e.to_string())?;
    let rules = compiler
        .resolve_active_rules(request, run_context)
        .map_err(|e| e.to_string())?;
    let composed = compose(compiler.pack(), &rules);
    let verdict = verdict_index(&composed);
    let capabilities = compiled
        .manifests
        .tool_manifest
        .iter()
        .flat_map(|t| t.capabilities.iter().map(move |c| format!("{}.{c}", t.adapter_id)))
        .collect();
    let gates = compiled
        .runtime_controls
        .evidence_gates
        .iter()
        .map(|g| (g.decision_key.clone(), g.commit_allowed))
        .collect();
    Ok(Observed {
        capabilities,
        verdict,
        obligations: composed.obligations.into_iter().collect(),
        rules: rules.into_iter().map(|r| r.rule_id).collect(),
        gates,
        hash: compiled.context_ledger.compiled_context_hash,
    })
}
