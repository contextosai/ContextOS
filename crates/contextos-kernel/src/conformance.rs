//! Evidence-scoped conformance assessment.
//!
//! Conformance applies to one exact workflow, implementation, release and
//! environment. A report passes only when every effective required control has
//! current, runtime (never synthetic) evidence verified by a trusted observer,
//! every positive and negative case defined for the control is covered, and every
//! required utility case passed. Missing, stale or synthetic evidence yields
//! `insufficient_evidence`; profile names are not certification.

use std::collections::{HashMap, HashSet};

use contextos_contract::canonical::{canonicalize, sha256_canonical, utf16_cmp};
use contextos_contract::shape::{
    exact_keys, is_artifact_ref, is_control_ref, is_digest, is_identifier, is_profile_selection, is_timestamp,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::authorization::valid_principal;
use crate::negotiation::negotiate_execution_contract;
use crate::support::{cmp_times, encoded, list, s, same, verification_status, within};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConformanceAssessment {
    pub outcome: String,
    pub report_id: Option<String>,
    pub workflow_id: Option<String>,
    pub implementation_id: Option<String>,
    pub implementation_version: Option<String>,
    pub release_refs: Vec<Value>,
    pub registry_ref: Option<Value>,
    pub missing_controls: Vec<Value>,
    pub unsupported_optional: Vec<Value>,
    pub reasons: Vec<String>,
    pub limitations: Vec<String>,
}

fn refs(v: &Value) -> bool {
    list(v, is_artifact_ref)
}

fn strings(v: &Value) -> bool {
    list(v, is_identifier)
}

fn unique(v: &Value) -> bool {
    v.as_array()
        .is_some_and(|a| a.iter().map(encoded).collect::<HashSet<_>>().len() == a.len())
}

fn non_empty(v: &Value) -> bool {
    v.as_array().is_some_and(|a| !a.is_empty())
}

fn control_key(c: &Value) -> String {
    format!("{}@{}", s(&c["control_id"]), s(&c["control_version"]))
}

fn exact_set(a: &Value, b: &Value) -> bool {
    let sorted = |v: &Value| {
        let mut items: Vec<String> = v
            .as_array()
            .map(|a| a.iter().map(encoded).collect())
            .unwrap_or_default();
        items.sort_by(|x, y| utf16_cmp(x, y));
        items
    };
    sorted(a) == sorted(b)
}

fn case_result(v: &Value) -> bool {
    exact_keys(v, &["case_id", "status", "evidence_refs"]).is_some_and(|o| {
        is_identifier(&o["case_id"])
            && matches!(o["status"].as_str(), Some("passed" | "failed" | "not_evaluated"))
            && refs(&o["evidence_refs"])
            && unique(&o["evidence_refs"])
    })
}

fn control_result(v: &Value) -> bool {
    exact_keys(
        v,
        &[
            "control",
            "status",
            "case_results",
            "evidence_refs",
            "reason_codes",
            "limitations",
        ],
    )
    .is_some_and(|o| {
        is_control_ref(&o["control"])
            && matches!(
                o["status"].as_str(),
                Some("passed" | "failed" | "unsupported" | "not_evaluated")
            )
            && list(&o["case_results"], case_result)
            && refs(&o["evidence_refs"])
            && unique(&o["evidence_refs"])
            && strings(&o["reason_codes"])
            && strings(&o["limitations"])
    })
}

fn report(v: &Value) -> bool {
    exact_keys(
        v,
        &[
            "report_version",
            "report_id",
            "implementation_id",
            "implementation_version",
            "workflow_id",
            "profiles",
            "effective_required_controls",
            "registry_ref",
            "suite_ref",
            "release_refs",
            "environment",
            "evaluated_at",
            "valid_until",
            "evaluator",
            "control_results",
            "utility_results",
            "outcome",
        ],
    )
    .is_some_and(|o| {
        o["report_version"] == "contextos.conformance_report.v1"
            && [
                "report_id",
                "implementation_id",
                "implementation_version",
                "workflow_id",
            ]
            .iter()
            .all(|k| is_identifier(&o[*k]))
            && list(&o["profiles"], is_profile_selection)
            && non_empty(&o["profiles"])
            && unique(&o["profiles"])
            && list(&o["effective_required_controls"], is_control_ref)
            && unique(&o["effective_required_controls"])
            && is_artifact_ref(&o["registry_ref"])
            && is_artifact_ref(&o["suite_ref"])
            && refs(&o["release_refs"])
            && non_empty(&o["release_refs"])
            && unique(&o["release_refs"])
            && exact_keys(&o["environment"], &["description", "configuration_ref"])
                .is_some_and(|e| is_identifier(&e["description"]) && is_artifact_ref(&e["configuration_ref"]))
            && is_timestamp(&o["evaluated_at"])
            && is_timestamp(&o["valid_until"])
            && valid_principal(&o["evaluator"])
            && list(&o["control_results"], control_result)
            && list(&o["utility_results"], case_result)
            && matches!(
                o["outcome"].as_str(),
                Some("passed" | "failed" | "insufficient_evidence")
            )
    })
}

const PROOF_KEYS: [&str; 7] = [
    "report_digest",
    "verification_status",
    "observer",
    "evidence_ref",
    "observed_at",
    "valid_until",
    "evidence_kind",
];

fn proof_fields(o: &Map<String, Value>) -> bool {
    is_digest(&o["report_digest"])
        && verification_status(&o["verification_status"])
        && valid_principal(&o["observer"])
        && is_artifact_ref(&o["evidence_ref"])
        && is_timestamp(&o["observed_at"])
        && is_timestamp(&o["valid_until"])
        && matches!(o["evidence_kind"].as_str(), Some("runtime" | "synthetic"))
}

fn proof(v: &Value) -> bool {
    exact_keys(v, &PROOF_KEYS).is_some_and(proof_fields)
}

fn evidence(v: &Value) -> bool {
    let keys: Vec<&str> = PROOF_KEYS.iter().copied().chain(["actual_sha256"]).collect();
    exact_keys(v, &keys).is_some_and(|o| proof_fields(o) && is_digest(&o["actual_sha256"]))
}

fn input_shape(v: &Value) -> bool {
    exact_keys(
        v,
        &[
            "contract",
            "support",
            "registry",
            "features",
            "report",
            "evaluation_time",
            "scope",
            "trusted_assessors",
            "trusted_evidence_observers",
            "report_verification",
            "evidence_observations",
        ],
    )
    .is_some_and(|o| {
        report(&o["report"])
            && is_timestamp(&o["evaluation_time"])
            && exact_keys(
                &o["scope"],
                &[
                    "workflow_id",
                    "implementation_id",
                    "implementation_version",
                    "release_refs",
                    "environment_ref",
                    "required_utility_case_ids",
                ],
            )
            .is_some_and(|sc| {
                ["workflow_id", "implementation_id", "implementation_version"]
                    .iter()
                    .all(|k| is_identifier(&sc[*k]))
                    && refs(&sc["release_refs"])
                    && non_empty(&sc["release_refs"])
                    && unique(&sc["release_refs"])
                    && is_artifact_ref(&sc["environment_ref"])
                    && strings(&sc["required_utility_case_ids"])
                    && non_empty(&sc["required_utility_case_ids"])
                    && unique(&sc["required_utility_case_ids"])
            })
            && list(&o["trusted_assessors"], valid_principal)
            && non_empty(&o["trusted_assessors"])
            && list(&o["trusted_evidence_observers"], valid_principal)
            && non_empty(&o["trusted_evidence_observers"])
            && proof(&o["report_verification"])
            && list(&o["evidence_observations"], evidence)
    })
}

fn arr(v: &Value) -> &[Value] {
    v.as_array().map_or(&[], Vec::as_slice)
}

/// Assesses an already-verified conformance report against its exact scope.
pub fn assess_conformance_report(value: &Value) -> ConformanceAssessment {
    let mut result = ConformanceAssessment {
        outcome: "insufficient_evidence".into(),
        report_id: None,
        workflow_id: None,
        implementation_id: None,
        implementation_version: None,
        release_refs: vec![],
        registry_ref: None,
        missing_controls: vec![],
        unsupported_optional: vec![],
        reasons: vec![],
        limitations: vec![],
    };
    let mut reasons: HashSet<String> = HashSet::new();
    let finish = |mut result: ConformanceAssessment, reasons: HashSet<String>| {
        let mut r: Vec<String> = reasons.into_iter().collect();
        r.sort_by(|a, b| utf16_cmp(a, b));
        result.reasons = r;
        let mut l: Vec<String> = result
            .limitations
            .iter()
            .cloned()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        l.sort_by(|a, b| utf16_cmp(a, b));
        result.limitations = l;
        result
    };
    if canonicalize(value).is_err() || !input_shape(value) {
        reasons.insert("report_invalid".into());
        return finish(result, reasons);
    }
    let r = &value["report"];
    let scope = &value["scope"];
    result.report_id = Some(s(&r["report_id"]).to_owned());
    result.workflow_id = Some(s(&r["workflow_id"]).to_owned());
    result.implementation_id = Some(s(&r["implementation_id"]).to_owned());
    result.implementation_version = Some(s(&r["implementation_version"]).to_owned());
    result.release_refs = arr(&r["release_refs"]).to_vec();
    result.registry_ref = Some(r["registry_ref"].clone());
    let negotiation = negotiate_execution_contract(
        &value["contract"],
        &value["support"],
        &value["registry"],
        &value["features"],
    );
    result.unsupported_optional = negotiation
        .unsupported_optional
        .iter()
        .map(|c| serde_json::to_value(c).unwrap_or(Value::Null))
        .collect();
    if negotiation.status != contextos_contract::execution::NegotiationStatus::Accepted {
        reasons.insert("contract_not_supported".into());
        return finish(result, reasons);
    }
    let effective: Vec<Value> = negotiation
        .effective_required_controls
        .iter()
        .map(|c| serde_json::to_value(c).unwrap_or(Value::Null))
        .collect();
    let support = &value["support"];
    let contract = &value["contract"];
    if r["implementation_id"] != scope["implementation_id"]
        || r["implementation_version"] != scope["implementation_version"]
        || r["implementation_id"] != support["implementation_id"]
        || r["implementation_version"] != support["implementation_version"]
        || r["workflow_id"] != scope["workflow_id"]
        || !exact_set(&r["release_refs"], &scope["release_refs"])
        || !exact_set(&r["release_refs"], &contract["release_refs"])
        || !same(&r["environment"]["configuration_ref"], &scope["environment_ref"])
        || !same(&r["registry_ref"], &value["registry"]["registry_ref"])
        || !exact_set(&r["profiles"], &contract["profiles"])
        || !exact_set(&r["effective_required_controls"], &Value::Array(effective.clone()))
    {
        reasons.insert("report_scope_mismatch".into());
        return finish(result, reasons);
    }
    let digest =
        sha256_canonical(&json!({"domain": "contextos.conformance_report.v1", "report": r})).unwrap_or_default();
    let time = &value["evaluation_time"];
    let observers = arr(&value["trusted_evidence_observers"]);
    let verified = |p: &Value| {
        p["verification_status"] == "verified"
            && p["evidence_kind"] == "runtime"
            && p["report_digest"] == digest.as_str()
            && p["observer"]["tenant_id"] == contract["tenant_id"]
            && observers.iter().any(|o| same(o, &p["observer"]))
            && within(time, &p["observed_at"], &p["valid_until"])
            && cmp_times(&r["evaluated_at"], &p["observed_at"]) != Some(std::cmp::Ordering::Greater)
    };
    if !verified(&value["report_verification"])
        || r["evaluator"]["tenant_id"] != contract["tenant_id"]
        || !arr(&value["trusted_assessors"])
            .iter()
            .any(|a| same(a, &r["evaluator"]))
        || !within(time, &r["evaluated_at"], &r["valid_until"])
    {
        reasons.insert("report_unverified_or_stale".into());
        return finish(result, reasons);
    }
    let control_rows = arr(&r["control_results"]);
    let utility_rows = arr(&r["utility_results"]);
    let distinct = |keys: Vec<String>| keys.iter().collect::<HashSet<_>>().len() == keys.len();
    if !distinct(control_rows.iter().map(|row| control_key(&row["control"])).collect())
        || !distinct(utility_rows.iter().map(|row| s(&row["case_id"]).to_owned()).collect())
        || control_rows.iter().any(|row| {
            !distinct(
                arr(&row["case_results"])
                    .iter()
                    .map(|c| s(&c["case_id"]).to_owned())
                    .collect(),
            )
        })
        || !unique(&Value::Array(
            arr(&value["evidence_observations"])
                .iter()
                .map(|e| e["evidence_ref"].clone())
                .collect(),
        ))
    {
        reasons.insert("conflicting_evidence_rows".into());
        return finish(result, reasons);
    }
    let observed: HashMap<String, &Value> = arr(&value["evidence_observations"])
        .iter()
        .map(|e| (encoded(&e["evidence_ref"]), e))
        .collect();
    let has_evidence = |refs: &Value| {
        non_empty(refs)
            && arr(refs).iter().all(|r| {
                observed
                    .get(&encoded(r))
                    .is_some_and(|o| verified(o) && o["actual_sha256"] == r["sha256"])
            })
    };
    let failed = std::cell::Cell::new(false);
    let covered = |row: &Value, reasons: &mut HashSet<String>| -> bool {
        if !has_evidence(&row["evidence_refs"]) {
            reasons.insert("case_evidence_missing_or_stale".into());
            return false;
        }
        if row["status"] == "failed" {
            failed.set(true);
            reasons.insert("observed_case_failed".into());
        }
        row["status"] == "passed"
    };
    let registry_controls = arr(&value["registry"]["controls"]);
    for required in &effective {
        let row = control_rows.iter().find(|row| same(&row["control"], required));
        let definition = registry_controls.iter().find(|c| same(&c["control"], required));
        let mut complete = row.is_some_and(|row| has_evidence(&row["evidence_refs"]));
        if let Some(row) = row {
            result
                .limitations
                .extend(arr(&row["limitations"]).iter().map(|l| s(l).to_owned()));
            if row["status"] == "failed" && has_evidence(&row["evidence_refs"]) {
                failed.set(true);
                reasons.insert("observed_control_failed".into());
            }
            complete = complete && row["status"] == "passed";
            for case_row in arr(&row["case_results"]) {
                if !covered(case_row, &mut reasons) {
                    complete = false;
                }
            }
            if let Some(definition) = definition {
                for id in arr(&definition["positive_cases"])
                    .iter()
                    .chain(arr(&definition["negative_cases"]))
                {
                    if !arr(&row["case_results"]).iter().any(|c| c["case_id"] == *id) {
                        complete = false;
                    }
                }
            }
        }
        if !complete {
            result.missing_controls.push(required.clone());
            reasons.insert("required_control_evidence_missing".into());
        }
    }
    let allowed: Vec<&Value> = effective.iter().chain(arr(&contract["optional_controls"])).collect();
    if control_rows
        .iter()
        .any(|row| !allowed.iter().any(|c| same(c, &row["control"])))
    {
        reasons.insert("unselected_control_result".into());
    }
    for row in control_rows
        .iter()
        .filter(|row| !effective.iter().any(|c| same(c, &row["control"])))
    {
        result
            .limitations
            .extend(arr(&row["limitations"]).iter().map(|l| s(l).to_owned()));
        result
            .limitations
            .push(format!("{}:{}", control_key(&row["control"]), s(&row["status"])));
    }
    for id in arr(&scope["required_utility_case_ids"]) {
        let utility = utility_rows.iter().find(|row| row["case_id"] == *id);
        if !utility.is_some_and(|u| covered(u, &mut reasons)) {
            reasons.insert("required_utility_not_passed".into());
        }
    }
    for utility in utility_rows {
        if !covered(utility, &mut reasons) {
            reasons.insert("utility_evidence_not_passed".into());
        }
    }
    result
        .missing_controls
        .sort_by(|a, b| utf16_cmp(&control_key(a), &control_key(b)));
    if r["outcome"] == "failed" {
        failed.set(true);
        reasons.insert("report_declared_failure".into());
    }
    if r["outcome"] == "insufficient_evidence" {
        reasons.insert("report_declared_insufficient".into());
    }
    result.outcome = if failed.get() {
        "failed".into()
    } else if reasons.is_empty() {
        "passed".into()
    } else {
        "insufficient_evidence".into()
    };
    finish(result, reasons)
}
