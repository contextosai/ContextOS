//! Release gate for Context Pack changes (runtime extension; see the spec's
//! improvement loop: a candidate cannot define its own release gate, and baseline and
//! candidate are compared on paired replay cases).
//!
//! Every captured case (request, run context, compile dependencies) is compiled under
//! the baseline and the candidate pack, and the governance-relevant results are
//! compared:
//!
//! - **surfaced capabilities**: a capability the candidate surfaces that the baseline
//!   did not *widens* authority; one it no longer surfaces narrows it;
//! - **policy**: the most restrictive applicable verdict (`deny` < `require_approval`
//!   < `allow`, composed exactly as the runtime does: highest-priority business
//!   bundles decide, and no applicable rule is `deny`) loosening, or required
//!   obligations dropping, *widens*;
//! - **evidence gates**: a decision whose commit the baseline blocked but the
//!   candidate allows, or whose blocking gate the candidate removes, *widens*;
//! - a case the baseline compiles and the candidate cannot is a *regression*; a case
//!   the baseline refused and the candidate compiles *widens*.
//!
//! The gate fails on any widening or regression that the operator did not
//! acknowledge. Acknowledgements are inputs to the gate, never part of the candidate.

use std::collections::{BTreeMap, BTreeSet};

use contextos_contract::types::{CompiledContext, ContextPack, InvokeRequest, RunContext};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use contextos_contract::canonical::sha256_canonical;
use serde_json::json;

use crate::authorization::compose_policy_outcomes;
use crate::{CompileDeps, ContextPackCompiler};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayCase {
    pub name: String,
    pub request: InvokeRequest,
    pub run_context: RunContext,
    #[serde(default)]
    pub deps: Value,
}

/// Widenings the operator accepts for this release.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acknowledgements {
    /// Capability ids the candidate may newly surface.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Replay cases (by name) whose policy may loosen: a looser verdict or dropped
    /// obligations. Named per case so one approval cannot cover unseen ones.
    #[serde(default)]
    pub policy_loosening: Vec<String>,
    /// Decision keys whose evidence gates may newly allow commit or be removed.
    #[serde(default)]
    pub evidence_gates: Vec<String>,
    /// Replay cases (by name) the candidate may compile although the baseline refused.
    #[serde(default)]
    pub compile_expansion: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Change {
    /// `capability`, `policy`, `evidence_gate`, `compile`, or `context`.
    pub kind: String,
    /// `widens`, `narrows`, `regression` or `neutral`.
    pub effect: String,
    pub detail: String,
    pub acknowledged: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaseReport {
    pub name: String,
    pub changes: Vec<Change>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GateReport {
    /// `pass` or `fail`.
    pub verdict: String,
    pub cases: Vec<CaseReport>,
    pub unacknowledged: usize,
}

#[derive(Debug, Clone)]
struct Observed {
    capabilities: BTreeSet<String>,
    verdict: usize,
    obligations: BTreeSet<String>,
    gates: BTreeMap<String, bool>,
    hash: String,
}

/// Composed verdicts from most to least restrictive (`error` counts as `deny`).
const VERDICTS: [&str; 4] = ["deny", "escalate", "require_approval", "allow"];

fn deps(value: &Value) -> CompileDeps {
    let list = |key: &str| value[key].as_array().cloned().unwrap_or_default();
    CompileDeps {
        evidence: list("evidence"),
        evidence_conflicts: list("evidence_conflicts"),
        promoted_memory: list("promoted_memory"),
    }
}

fn observe(compiler: &ContextPackCompiler, case: &ReplayCase) -> Result<Observed, String> {
    let compiled: CompiledContext = compiler
        .compile(&case.request, &case.run_context, &deps(&case.deps))
        .map_err(|e| e.to_string())?;
    let rules = compiler
        .resolve_active_rules(&case.request, &case.run_context)
        .map_err(|e| e.to_string())?;
    // The verdict the runtime would reach: the same normalized business outcomes
    // admission pins, composed by the kernel (highest-priority bundles decide).
    let pack = compiler.pack();
    let outcomes: Vec<Value> = rules
        .iter()
        .map(|rule| {
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
        })
        .collect();
    let composed = compose_policy_outcomes(&Value::Array(outcomes));
    let verdict = VERDICTS.iter().position(|v| *v == composed.verdict).unwrap_or(0);
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
        gates,
        hash: compiled.context_ledger.compiled_context_hash,
    })
}

fn change(kind: &str, effect: &str, detail: String, acknowledged: bool) -> Change {
    Change {
        kind: kind.into(),
        effect: effect.into(),
        detail,
        acknowledged,
    }
}

/// Compares `candidate` with `baseline` on `cases`.
pub fn evaluate_release_gate(
    baseline: &ContextPack,
    candidate: &ContextPack,
    cases: &[ReplayCase],
    acknowledged: &Acknowledgements,
) -> Result<GateReport, String> {
    if cases.is_empty() {
        return Err("the release gate needs at least one replay case".into());
    }
    let base = ContextPackCompiler::new(baseline.clone()).map_err(|e| format!("baseline: {e}"))?;
    let cand = ContextPackCompiler::new(candidate.clone()).map_err(|e| format!("candidate: {e}"))?;
    let mut reports = Vec::with_capacity(cases.len());
    let mut unacknowledged = 0;
    for case in cases {
        let mut changes = Vec::new();
        match (observe(&base, case), observe(&cand, case)) {
            (Err(_), Err(_)) => changes.push(change(
                "compile",
                "neutral",
                "neither pack compiles this case".into(),
                true,
            )),
            // A case the baseline refused but the candidate admits is new behaviour.
            (Err(_), Ok(_)) => changes.push(change(
                "compile",
                "widens",
                "candidate compiles a case the baseline refused".into(),
                acknowledged.compile_expansion.contains(&case.name),
            )),
            (Ok(_), Err(error)) => changes.push(change(
                "compile",
                "regression",
                format!("candidate fails: {error}"),
                false,
            )),
            (Ok(b), Ok(c)) => {
                for added in c.capabilities.difference(&b.capabilities) {
                    let ok = acknowledged.capabilities.contains(added);
                    changes.push(change("capability", "widens", format!("{added} newly surfaced"), ok));
                }
                for removed in b.capabilities.difference(&c.capabilities) {
                    changes.push(change(
                        "capability",
                        "narrows",
                        format!("{removed} no longer surfaced"),
                        true,
                    ));
                }
                if c.verdict != b.verdict {
                    let detail = format!("policy {} -> {}", VERDICTS[b.verdict], VERDICTS[c.verdict]);
                    if c.verdict > b.verdict {
                        changes.push(change(
                            "policy",
                            "widens",
                            detail,
                            acknowledged.policy_loosening.contains(&case.name),
                        ));
                    } else {
                        changes.push(change("policy", "narrows", detail, true));
                    }
                }
                let dropped: Vec<&String> = b.obligations.difference(&c.obligations).collect();
                if !dropped.is_empty() {
                    let detail = format!("obligations no longer required: {dropped:?}");
                    changes.push(change(
                        "policy",
                        "widens",
                        detail,
                        acknowledged.policy_loosening.contains(&case.name),
                    ));
                }
                for (key, allowed) in &b.gates {
                    if !*allowed && !c.gates.contains_key(key) {
                        let ok = acknowledged.evidence_gates.contains(key);
                        changes.push(change(
                            "evidence_gate",
                            "widens",
                            format!("{key} blocking gate removed"),
                            ok,
                        ));
                    }
                }
                for (key, allowed) in &c.gates {
                    let before = b.gates.get(key).copied();
                    if *allowed && before == Some(false) {
                        let ok = acknowledged.evidence_gates.contains(key);
                        changes.push(change(
                            "evidence_gate",
                            "widens",
                            format!("{key} commit newly allowed"),
                            ok,
                        ));
                    } else if !*allowed && before != Some(false) {
                        changes.push(change(
                            "evidence_gate",
                            "narrows",
                            format!("{key} commit newly blocked"),
                            true,
                        ));
                    }
                }
                if b.hash != c.hash && changes.is_empty() {
                    changes.push(change("context", "neutral", "compiled context changed".into(), true));
                }
            }
        }
        unacknowledged += changes.iter().filter(|c| !c.acknowledged).count();
        reports.push(CaseReport {
            name: case.name.clone(),
            changes,
        });
    }
    Ok(GateReport {
        verdict: if unacknowledged == 0 { "pass" } else { "fail" }.into(),
        cases: reports,
        unacknowledged,
    })
}
