//! Decision plans: what a Context Pack lets a principal do for an intent, before any
//! request exists (runtime extension, `ctx plan`).
//!
//! Admission decides one request. A plan answers the question asked before one: for
//! this user, agent and tenant, and this intent, which rules always apply, which never
//! do, and which depend on the request, and on exactly what. Each rule condition is
//! partially evaluated with everything but `request` known (see
//! [`contextos_policy::partial_apply`]); what remains is a residual JsonLogic
//! condition over `request.*`, exact for every request.
//!
//! The verdict is stated when no applying rule depends on the request. Otherwise the
//! plan lists the verdicts reachable by some assignment of the residual conditions,
//! composed as admission composes them. Conditions are treated as independent, so an
//! assignment no request can produce (`amount > 10` and `amount < 5`) is not excluded:
//! the list may include a verdict no request reaches, never omit one that one does.
//!
//! A plan describes policy rules only. Tool surfacing also depends on the run's safety
//! mode and the request's evidence; `prohibits` on each rule says which capabilities
//! the rule withholds when it applies.

use std::collections::BTreeSet;

use contextos_contract::canonical::canonicalize;
use contextos_contract::types::{ContextPack, RunContext};
use contextos_policy::{Partial, partial_apply};
use serde::Serialize;
use serde_json::Value;

use crate::ResolvedRule;
use crate::compiler::principal_eval_context;
use crate::pack_observation::{VERDICTS, compose, verdict_index};

/// The data a plan leaves unknown.
const UNKNOWN: [&str; 1] = ["request"];
/// Beyond this many distinct residual conditions, reachable verdicts are not listed.
pub const MAX_ENUMERATED_CONDITIONS: usize = 10;

#[derive(Debug, Clone, Serialize)]
pub struct PlannedRule {
    pub bundle_id: String,
    pub priority: i64,
    pub rule_id: String,
    /// `then`, or `else` for a rule's else branch.
    pub branch: &'static str,
    /// `allow`, `require_approval` or `deny`.
    pub effect: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_gate: Option<String>,
    pub obligations: Vec<String>,
    pub prohibits: Vec<String>,
    /// `always`, `when` (the condition holds) or `unless` (it does not).
    pub applies: &'static str,
    /// The residual condition over `request.*`, for `when` and `unless`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DecisionPlan {
    pub intent: String,
    /// The composed verdict when it does not depend on the request, else `conditional`.
    pub verdict: String,
    /// Verdicts some assignment of the conditions reaches, most restrictive first;
    /// `None` past [`MAX_ENUMERATED_CONDITIONS`] conditions.
    pub possible_verdicts: Option<Vec<String>>,
    /// The distinct residual conditions the plan depends on.
    pub conditions: Vec<Value>,
    /// Rules that apply for some request; rules that never apply are left out.
    pub rules: Vec<PlannedRule>,
}

struct Candidate {
    rule: ResolvedRule,
    planned: PlannedRule,
    /// Index into the plan's conditions and the truth value under which it applies.
    depends: Option<(usize, bool)>,
}

fn effect(rule: &ResolvedRule) -> &'static str {
    if !rule.allow {
        "deny"
    } else if rule.approval_gate.is_some() {
        "require_approval"
    } else {
        "allow"
    }
}

fn candidate(
    rule: ResolvedRule,
    branch: &'static str,
    prohibits: Vec<String>,
    depends: Option<(usize, bool)>,
    conditions: &[Value],
) -> Candidate {
    let applies = match depends {
        None => "always",
        Some((_, true)) => "when",
        Some((_, false)) => "unless",
    };
    let planned = PlannedRule {
        bundle_id: rule.bundle_id.clone(),
        priority: rule.priority,
        rule_id: rule.rule_id.clone(),
        branch,
        effect: effect(&rule),
        approval_gate: rule.approval_gate.clone(),
        obligations: rule.requires.clone(),
        prohibits,
        applies,
        condition: depends.map(|(index, _)| conditions[index].clone()),
    };
    Candidate { rule, planned, depends }
}

/// Plans `intent` for the principal in `run_context` under `pack`. Fails when a rule's
/// condition fails on the principal alone, as admission would for every request.
pub fn plan_decisions(pack: &ContextPack, run_context: &RunContext, intent: &str) -> Result<DecisionPlan, String> {
    let known = principal_eval_context(intent, run_context);
    let mut conditions: Vec<Value> = Vec::new();
    let mut keys: Vec<String> = Vec::new();
    let mut candidates = Vec::new();
    let mut bundles: Vec<_> = pack.policy_layer.policy_bundles.iter().collect();
    bundles.sort_by_key(|bundle| std::cmp::Reverse(bundle.priority));
    for bundle in bundles {
        for rule in &bundle.policy_dsl.rules {
            if let Some(applies) = rule.applies_to.intent.as_deref()
                && !applies.is_empty()
                && applies != intent
            {
                continue;
            }
            let partial = partial_apply(&rule.condition, &known, &UNKNOWN)
                .map_err(|e| format!("rule {} in {}: {e}", rule.rule_id, bundle.bundle_id))?;
            let (fires, depends) = match partial {
                Partial::Known(value) => (Some(value.js_truthy()), None),
                Partial::Residual(residual) => {
                    let key = canonicalize(&residual).map_err(|e| format!("rule {}: {e}", rule.rule_id))?;
                    let index = keys.iter().position(|k| *k == key).unwrap_or_else(|| {
                        keys.push(key);
                        conditions.push(residual);
                        conditions.len() - 1
                    });
                    (None, Some(index))
                }
            };
            let resolved = |allow, approval_gate, requires| ResolvedRule {
                bundle_id: bundle.bundle_id.clone(),
                priority: bundle.priority,
                rule_id: rule.rule_id.clone(),
                allow,
                approval_gate,
                requires,
            };
            if fires != Some(false) {
                let then = resolved(
                    rule.then.allow,
                    rule.then.approval_gate().filter(|g| !g.is_empty()).map(str::to_owned),
                    rule.then.requires.clone().unwrap_or_default(),
                );
                let prohibits = rule.then.prohibits.clone().unwrap_or_default();
                candidates.push(candidate(
                    then,
                    "then",
                    prohibits,
                    depends.map(|i| (i, true)),
                    &conditions,
                ));
            }
            if let Some(otherwise) = rule.otherwise.as_ref().filter(|_| fires != Some(true)) {
                let other = resolved(otherwise.allow, None, Vec::new());
                candidates.push(candidate(
                    other,
                    "else",
                    Vec::new(),
                    depends.map(|i| (i, false)),
                    &conditions,
                ));
            }
        }
    }
    let possible = (conditions.len() <= MAX_ENUMERATED_CONDITIONS).then(|| {
        let mut reached = BTreeSet::new();
        for assignment in 0u32..(1 << conditions.len()) {
            let active: Vec<ResolvedRule> = candidates
                .iter()
                .filter(|c| c.depends.is_none_or(|(i, when)| (assignment >> i & 1 == 1) == when))
                .map(|c| c.rule.clone())
                .collect();
            reached.insert(verdict_index(&compose(pack, &active)));
        }
        reached.into_iter().map(|i| VERDICTS[i].to_owned()).collect::<Vec<_>>()
    });
    let verdict = match possible.as_deref() {
        Some([only]) if conditions.is_empty() => only.clone(),
        _ => "conditional".to_owned(),
    };
    Ok(DecisionPlan {
        intent: intent.to_owned(),
        verdict,
        possible_verdicts: possible,
        conditions,
        rules: candidates.into_iter().map(|c| c.planned).collect(),
    })
}

#[cfg(test)]
mod tests {
    use contextos_contract::types::{ContextPack, InvokeRequest, RunContext};
    use serde_json::{Value, json};

    use super::{DecisionPlan, plan_decisions};
    use crate::ResolvedRule;
    use crate::pack_observation::{VERDICTS, compose, observe, verdict_index};

    fn load(path: &str) -> Value {
        let path = format!("{}/../../{path}", env!("CARGO_MANIFEST_DIR"));
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    /// The verdict the plan implies once the request is known.
    fn planned_verdict(pack: &ContextPack, plan: &DecisionPlan, data: &Value) -> &'static str {
        let active: Vec<ResolvedRule> = plan
            .rules
            .iter()
            .filter(|r| {
                let holds = || contextos_policy::predicate(r.condition.as_ref().unwrap(), data).unwrap();
                match r.applies {
                    "always" => true,
                    "when" => holds(),
                    _ => !holds(),
                }
            })
            .map(|r| ResolvedRule {
                bundle_id: r.bundle_id.clone(),
                priority: r.priority,
                rule_id: r.rule_id.clone(),
                allow: r.effect != "deny",
                approval_gate: r.approval_gate.clone(),
                requires: r.obligations.clone(),
            })
            .collect();
        VERDICTS[verdict_index(&compose(pack, &active))]
    }

    #[test]
    fn plans_agree_with_admission_for_every_request() {
        let pack: ContextPack = serde_json::from_value(load("examples/support-refund/pack.json")).unwrap();
        let compiler = crate::ContextPackCompiler::new(pack.clone()).unwrap();
        let run = load("examples/support-refund/requests/run.json");
        let mut checked = 0;
        for role in ["support_agent", "supervisor"] {
            let mut run_context = run["run_context"].clone();
            run_context["user"]["role"] = json!(role);
            let run_context: RunContext = serde_json::from_value(run_context).unwrap();
            let plan = plan_decisions(&pack, &run_context, "support.refund").unwrap();
            for verified in [json!(true), json!(false), Value::Null, json!("true")] {
                for amount in [json!(0), json!(3000), json!(3000.5), json!("4000"), Value::Null] {
                    let mut request = run["request"].clone();
                    request["input"]["context"]["identity_verified"] = verified.clone();
                    request["input"]["context"]["refund_amount"] = amount.clone();
                    let request: InvokeRequest = serde_json::from_value(request).unwrap();
                    let observed = observe(&compiler, &request, &run_context, &Value::Null).unwrap();
                    let data = json!({"request": {"context": request.input.context}});
                    assert_eq!(
                        planned_verdict(&pack, &plan, &data),
                        VERDICTS[observed.verdict],
                        "{role} verified={verified} amount={amount}"
                    );
                    assert!(
                        plan.possible_verdicts
                            .as_ref()
                            .unwrap()
                            .iter()
                            .any(|v| v == VERDICTS[observed.verdict])
                    );
                    checked += 1;
                }
            }
        }
        assert_eq!(checked, 40);
    }
}
