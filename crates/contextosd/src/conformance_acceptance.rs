//! Suite acceptance: whether this deployment accepts a conformance assessment as a
//! claim, under a suite policy it pins in configuration.
//!
//! The assessor checks a report against its contract, registry and evidence. It does
//! not know which suite the consumer accepts: a report that authenticates its
//! `suite_ref` only shows which suite it names. This module is the consumer's side. Per
//! tenant and workflow, `[[conformance.accepted_suites]]` pins the one suite it accepts,
//! the cases that suite must have passed, and what a failed optional control does
//! (`block` or `disclose`, stated, never defaulted). An assessment is `accepted` only
//! when it `passed`, names exactly the pinned suite, reports every listed case as
//! passed under a required control or as a utility result (where the assessor checked
//! its evidence), and no optional control failed under `block`. Without a policy the
//! answer is `no_policy`, never `accepted`.

use std::collections::HashSet;

use contextos_contract::shape::{is_artifact_ref, is_identifier};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// What a failed optional control does to acceptance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OptionalFailures {
    /// A failed optional control (or a failed case under one) prevents acceptance.
    Block,
    /// Failed optional controls are listed in the acceptance, which can still be
    /// `accepted`.
    Disclose,
}

/// The one suite a tenant accepts for a workflow, and what it must show.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AcceptedSuite {
    /// Tenant whose assessments this policy governs.
    pub tenant_id: String,
    /// Workflow the suite is accepted for.
    pub workflow_id: String,
    /// The accepted suite, exactly: `{artifact_type, artifact_id, version, sha256}`. A
    /// report naming any other suite, or another version or digest, is not accepted.
    pub suite: Value,
    /// Cases the report must show passed, under a required control or as utility
    /// results. Include the regressions the workflow depends on; a case reported only
    /// under an optional control does not count.
    pub required_case_ids: Vec<String>,
    /// What a failed optional control does: `block` or `disclose`. Required.
    pub optional_failures: OptionalFailures,
}

/// Configuration check: valid suite references and identifiers, one policy per tenant
/// and workflow.
pub fn check(config: &crate::Config) -> Result<(), String> {
    let mut seen = HashSet::new();
    for policy in &config.conformance.accepted_suites {
        let name = format!("{}/{}", policy.tenant_id, policy.workflow_id);
        if !is_identifier(&json!(policy.tenant_id)) || !is_identifier(&json!(policy.workflow_id)) {
            return Err(format!(
                "accepted suite {name}: tenant_id and workflow_id must be identifiers"
            ));
        }
        if !is_artifact_ref(&policy.suite) {
            return Err(format!(
                "accepted suite {name}: suite must be {{artifact_type, artifact_id, version, sha256}}"
            ));
        }
        if policy.required_case_ids.is_empty() {
            return Err(format!("accepted suite {name}: required_case_ids is empty"));
        }
        let mut cases = HashSet::new();
        for id in &policy.required_case_ids {
            if !is_identifier(&json!(id)) || !cases.insert(id) {
                return Err(format!("accepted suite {name}: case {id:?} is invalid or repeated"));
            }
        }
        if !seen.insert(name.clone()) {
            return Err(format!("accepted suite {name}: more than one policy"));
        }
    }
    Ok(())
}

fn rows(v: &Value) -> &[Value] {
    v.as_array().map_or(&[], Vec::as_slice)
}

fn control_key(c: &Value) -> String {
    format!(
        "{}@{}",
        c["control_id"].as_str().unwrap_or_default(),
        c["control_version"].as_str().unwrap_or_default()
    )
}

/// The acceptance of `report` given the assessor's `outcome`, for `tenant_id`.
pub fn accept(policies: &[AcceptedSuite], tenant_id: &str, report: &Value, outcome: &str) -> Value {
    let workflow = report["workflow_id"].as_str().unwrap_or_default();
    let Some(policy) = policies
        .iter()
        .find(|p| p.tenant_id == tenant_id && p.workflow_id == workflow)
    else {
        return json!({"status": "no_policy", "reasons": ["no_suite_policy"]});
    };
    let mut reasons = Vec::new();
    if outcome != "passed" {
        reasons.push("assessment_not_passed".to_owned());
    }
    if report["suite_ref"] != policy.suite {
        reasons.push("suite_not_accepted".to_owned());
    }
    let required: Vec<String> = rows(&report["effective_required_controls"])
        .iter()
        .map(control_key)
        .collect();
    let (mut checked, mut optional) = (Vec::new(), Vec::new());
    for row in rows(&report["control_results"]) {
        if required.contains(&control_key(&row["control"])) {
            checked.extend(rows(&row["case_results"]));
        } else {
            optional.push(row);
        }
    }
    checked.extend(rows(&report["utility_results"]));
    // A case reported in more than one place must pass in each.
    for id in &policy.required_case_ids {
        let found: Vec<&&Value> = checked.iter().filter(|c| c["case_id"] == id.as_str()).collect();
        if found.is_empty() {
            reasons.push(format!("required_case_missing:{id}"));
        } else if found.iter().any(|c| c["status"] != "passed") {
            reasons.push(format!("required_case_not_passed:{id}"));
        }
    }
    let optional_failed: Vec<String> = optional
        .iter()
        .filter(|row| row["status"] == "failed" || rows(&row["case_results"]).iter().any(|c| c["status"] == "failed"))
        .map(|row| control_key(&row["control"]))
        .collect();
    if policy.optional_failures == OptionalFailures::Block {
        reasons.extend(optional_failed.iter().map(|k| format!("optional_control_failed:{k}")));
    }
    json!({
        "status": if reasons.is_empty() { "accepted" } else { "not_accepted" },
        "suite": policy.suite,
        "optional_failures": policy.optional_failures,
        "optional_failed": optional_failed,
        "reasons": reasons,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn suite() -> Value {
        json!({"artifact_type": "conformance_suite", "artifact_id": "refund_suite", "version": "3",
            "sha256": format!("sha256:{}", "a".repeat(64))})
    }

    fn policy(optional_failures: OptionalFailures) -> Vec<AcceptedSuite> {
        vec![AcceptedSuite {
            tenant_id: "tenant_a".into(),
            workflow_id: "support.refund".into(),
            suite: suite(),
            required_case_ids: vec!["refund.useful".into(), "intent.retry_reclaims".into()],
            optional_failures,
        }]
    }

    fn control(id: &str, status: &str, cases: &[(&str, &str)]) -> Value {
        json!({"control": {"control_id": id, "control_version": "1"}, "status": status,
            "case_results": cases.iter().map(|(c, s)| json!({"case_id": c, "status": s})).collect::<Vec<_>>()})
    }

    fn report() -> Value {
        json!({"workflow_id": "support.refund", "suite_ref": suite(),
            "effective_required_controls": [{"control_id": "durable.effects", "control_version": "1"}],
            "control_results": [control("durable.effects", "passed", &[("intent.retry_reclaims", "passed")]),
                control("optional.monitor", "failed", &[("monitor.flags", "failed")])],
            "utility_results": [{"case_id": "refund.useful", "status": "passed"}]})
    }

    #[test]
    fn accepts_only_the_pinned_suite_with_every_required_case() {
        let disclose = policy(OptionalFailures::Disclose);
        let accepted = accept(&disclose, "tenant_a", &report(), "passed");
        assert_eq!(accepted["status"], "accepted", "{accepted}");
        // Disclosed, not hidden.
        assert_eq!(accepted["optional_failed"], json!(["optional.monitor@1"]));

        let mut other = report();
        other["suite_ref"]["version"] = json!("2");
        let refused = accept(&disclose, "tenant_a", &other, "passed");
        assert_eq!(refused["status"], "not_accepted");
        assert_eq!(refused["reasons"], json!(["suite_not_accepted"]));

        let refused = accept(&disclose, "tenant_a", &report(), "insufficient_evidence");
        assert_eq!(refused["reasons"], json!(["assessment_not_passed"]));
    }

    #[test]
    fn missing_failed_or_optional_only_cases_are_not_accepted() {
        let disclose = policy(OptionalFailures::Disclose);
        let mut missing = report();
        missing["control_results"][0]["case_results"] = json!([]);
        assert_eq!(
            accept(&disclose, "tenant_a", &missing, "passed")["reasons"],
            json!(["required_case_missing:intent.retry_reclaims"])
        );
        // Reported only under an optional control, where its evidence was not checked.
        let mut optional_only = missing.clone();
        optional_only["control_results"][1]["case_results"] =
            json!([{"case_id": "intent.retry_reclaims", "status": "passed"}]);
        assert_eq!(
            accept(&disclose, "tenant_a", &optional_only, "passed")["reasons"],
            json!(["required_case_missing:intent.retry_reclaims"])
        );
        // A case reported twice must pass in both places.
        let mut twice = report();
        twice["utility_results"]
            .as_array_mut()
            .unwrap()
            .push(json!({"case_id": "intent.retry_reclaims", "status": "failed"}));
        assert_eq!(
            accept(&disclose, "tenant_a", &twice, "passed")["reasons"],
            json!(["required_case_not_passed:intent.retry_reclaims"])
        );
    }

    #[test]
    fn a_blocking_policy_refuses_failed_optional_controls() {
        let refused = accept(&policy(OptionalFailures::Block), "tenant_a", &report(), "passed");
        assert_eq!(refused["status"], "not_accepted");
        assert_eq!(
            refused["reasons"],
            json!(["optional_control_failed:optional.monitor@1"])
        );
    }

    #[test]
    fn without_a_policy_nothing_is_accepted() {
        let blocking = policy(OptionalFailures::Block);
        for (tenant, workflow) in [("tenant_b", "support.refund"), ("tenant_a", "other.workflow")] {
            let mut r = report();
            r["workflow_id"] = json!(workflow);
            let none = accept(&blocking, tenant, &r, "passed");
            assert_eq!(none["status"], "no_policy");
            assert_eq!(none["reasons"], json!(["no_suite_policy"]));
        }
    }
}
