//! The release gate reports how a candidate pack changes governance on paired cases.

use contextos_contract::types::ContextPack;
use contextos_kernel::release_gate::{Acknowledgements, ReplayCase, evaluate_release_gate};
use serde_json::{Value, json};

fn vectors() -> Value {
    let path = format!("{}/../../conformance/vectors/compiler.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn setup() -> (Value, Vec<ReplayCase>) {
    let v = vectors();
    let pick = |name: &str| {
        v["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == name)
            .unwrap()
            .clone()
    };
    let high = pick("grid:support.refund:true:4200:support_agent");
    let low = pick("grid:support.refund:true:1200:support_agent");
    let case = |name: &str, c: &Value| -> ReplayCase {
        serde_json::from_value(
            json!({"name": name, "request": c["request"], "run_context": c["run_context"], "deps": c["deps"]}),
        )
        .unwrap()
    };
    (
        high["pack"].clone(),
        vec![case("high_value_refund", &high), case("low_value_refund", &low)],
    )
}

fn pack(value: &Value) -> ContextPack {
    serde_json::from_value(value.clone()).unwrap()
}

fn gate(
    baseline: &Value,
    candidate: &Value,
    cases: &[ReplayCase],
    ack: &Acknowledgements,
) -> contextos_kernel::release_gate::GateReport {
    evaluate_release_gate(&pack(baseline), &pack(candidate), cases, ack).unwrap()
}

#[test]
fn an_unchanged_pack_passes() {
    let (baseline, cases) = setup();
    let report = gate(&baseline, &baseline, &cases, &Acknowledgements::default());
    assert_eq!(report.verdict, "pass");
    assert!(report.cases.iter().all(|c| c.changes.is_empty()));
}

#[test]
fn removing_an_approval_gate_is_a_widening_that_needs_acknowledgement() {
    let (baseline, cases) = setup();
    let mut candidate = baseline.clone();
    let then = &mut candidate["policy_layer"]["policy_bundles"][0]["policy_dsl"]["rules"][1]["then"];
    then.as_object_mut().unwrap().retain(|k, _| k == "allow");
    let report = gate(&baseline, &candidate, &cases, &Acknowledgements::default());
    assert_eq!(report.verdict, "fail");
    let high = report.cases.iter().find(|c| c.name == "high_value_refund").unwrap();
    assert!(
        high.changes
            .iter()
            .any(|c| c.kind == "policy" && c.effect == "widens" && c.detail == "policy require_approval -> allow")
    );
    let low = report.cases.iter().find(|c| c.name == "low_value_refund").unwrap();
    assert!(
        low.changes.iter().all(|c| c.kind != "policy"),
        "the low-value path did not change"
    );
    let acknowledged = Acknowledgements {
        policy_loosening: vec!["high_value_refund".into()],
        ..Acknowledgements::default()
    };
    assert_eq!(gate(&baseline, &candidate, &cases, &acknowledged).verdict, "pass");
}

#[test]
fn a_newly_surfaced_capability_is_a_widening() {
    let (baseline, cases) = setup();
    let mut candidate = baseline.clone();
    let tooling = &mut candidate["tooling_layer"];
    tooling["adapter_registry"].as_array_mut().unwrap().push(json!({
        "adapter_id": "adp_crm", "type": "OPENAPI", "endpoint_ref": "internal://crm", "capabilities": ["delete_customer"],
        "approval_mode": "destructive", "capability_risks": {"delete_customer": {"effect": "external_state",
            "authority": "service", "reversibility": "irreversible", "interaction": "api", "data_scope": "CONFIDENTIAL"}}}));
    tooling["permissions"].as_array_mut().unwrap().push(
        json!({"permission_id": "p_crm", "adapter_id": "adp_crm", "capability": "delete_customer", "allow": true}),
    );
    let report = gate(&baseline, &candidate, &cases, &Acknowledgements::default());
    let widened: Vec<&str> = report.cases[0]
        .changes
        .iter()
        .filter(|c| c.effect == "widens")
        .map(|c| c.detail.as_str())
        .collect();
    assert_eq!(widened, ["adp_crm.delete_customer newly surfaced"]);
    assert_eq!(report.verdict, "fail", "{widened:?}");
    let acknowledged = Acknowledgements {
        capabilities: vec!["adp_crm.delete_customer".into()],
        ..Acknowledgements::default()
    };
    assert_eq!(gate(&baseline, &candidate, &cases, &acknowledged).verdict, "pass");
}

#[test]
fn a_candidate_that_cannot_compile_a_case_is_a_regression() {
    let (baseline, cases) = setup();
    let mut candidate = baseline.clone();
    candidate["policy_layer"]["policy_bundles"][0]["policy_dsl"]["rules"][0]["if"] = json!({"no_such_op": [1]});
    let report = gate(
        &baseline,
        &candidate,
        &cases,
        &Acknowledgements {
            policy_loosening: vec!["high_value_refund".into(), "low_value_refund".into()],
            ..Acknowledgements::default()
        },
    );
    assert_eq!(report.verdict, "fail");
    assert!(report.cases[0].changes.iter().any(|c| c.effect == "regression"));
}

#[test]
fn a_higher_priority_allow_bundle_is_caught_as_the_runtime_would_see_it() {
    let (baseline, cases) = setup();
    let mut candidate = baseline.clone();
    let priority = baseline["policy_layer"]["policy_bundles"][0]["priority"]
        .as_i64()
        .unwrap();
    let mut overriding = baseline["policy_layer"]["policy_bundles"][0].clone();
    overriding["bundle_id"] = json!("POLICY_FAST_REFUNDS");
    overriding["priority"] = json!(priority + 10);
    overriding["policy_dsl"]["rules"] = json!([{"rule_id": "R_ALWAYS_REFUND", "applies_to": {"intent": "support.refund"},
        "if": {"==": [1, 1]}, "then": {"allow": true}, "rationale": "fast path"}]);
    candidate["policy_layer"]["policy_bundles"]
        .as_array_mut()
        .unwrap()
        .push(overriding);
    let report = gate(&baseline, &candidate, &cases, &Acknowledgements::default());
    let high = report.cases.iter().find(|c| c.name == "high_value_refund").unwrap();
    assert!(
        high.changes.iter().any(|c| c.kind == "policy" && c.effect == "widens"),
        "the approval requirement is overridden: {:?}",
        high.changes
    );
    assert_eq!(report.verdict, "fail");
}

#[test]
fn removing_a_blocking_evidence_gate_is_a_widening() {
    let v = vectors();
    let blocked = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "grid:support.refund:false:4200:support_agent")
        .unwrap();
    let baseline = blocked["pack"].clone();
    let case: ReplayCase = serde_json::from_value(json!({"name": "unverified", "request": blocked["request"],
        "run_context": blocked["run_context"], "deps": blocked["deps"]}))
    .unwrap();
    let mut candidate = baseline.clone();
    for rule in candidate["policy_layer"]["policy_bundles"][0]["policy_dsl"]["rules"]
        .as_array_mut()
        .unwrap()
    {
        rule.as_object_mut().unwrap().remove("decision_binding");
    }
    candidate["decision_layer"]["decision_specs"] = json!([]);
    let baseline_report = gate(
        &baseline,
        &baseline,
        std::slice::from_ref(&case),
        &Acknowledgements::default(),
    );
    assert_eq!(baseline_report.verdict, "pass");
    let report = gate(&baseline, &candidate, &[case], &Acknowledgements::default());
    assert!(
        report.cases[0]
            .changes
            .iter()
            .any(|c| c.kind == "evidence_gate" && c.detail == "support.refund.execute blocking gate removed"),
        "{:?}",
        report.cases[0].changes
    );
    assert_eq!(report.verdict, "fail");
    let acknowledged = Acknowledgements {
        evidence_gates: vec!["support.refund.execute".into()],
        ..Acknowledgements::default()
    };
    let report = gate(&baseline, &candidate, &[report_case(&v)], &acknowledged);
    assert!(
        report.cases[0]
            .changes
            .iter()
            .filter(|c| c.kind == "evidence_gate")
            .all(|c| c.acknowledged)
    );
}

fn report_case(v: &Value) -> ReplayCase {
    let c = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "grid:support.refund:false:4200:support_agent")
        .unwrap();
    serde_json::from_value(
        json!({"name": "unverified", "request": c["request"], "run_context": c["run_context"], "deps": c["deps"]}),
    )
    .unwrap()
}

#[test]
fn empty_corpora_and_newly_admitted_cases_fail() {
    let (baseline, cases) = setup();
    assert!(evaluate_release_gate(&pack(&baseline), &pack(&baseline), &[], &Acknowledgements::default()).is_err());
    let mut refusing = baseline.clone();
    refusing["policy_layer"]["policy_bundles"][0]["policy_dsl"]["rules"][0]["if"] = json!({"no_such_op": [1]});
    let report = gate(&refusing, &baseline, &cases, &Acknowledgements::default());
    assert!(
        report.cases[0]
            .changes
            .iter()
            .any(|c| c.kind == "compile" && c.effect == "widens")
    );
    assert_eq!(report.verdict, "fail");
}

#[test]
fn a_policy_acknowledgement_covers_only_the_cases_it_names() {
    let (baseline, cases) = setup();
    let mut candidate = baseline.clone();
    // Drop the identity requirement: both cases loosen.
    candidate["policy_layer"]["policy_bundles"][0]["policy_dsl"]["rules"][0]["then"] = json!({"allow": true});
    let only_high = Acknowledgements {
        policy_loosening: vec!["high_value_refund".into()],
        ..Acknowledgements::default()
    };
    let report = gate(&baseline, &candidate, &cases, &only_high);
    let low = report.cases.iter().find(|c| c.name == "low_value_refund").unwrap();
    assert!(
        low.changes.iter().any(|c| c.kind == "policy" && !c.acknowledged),
        "{:?}",
        low.changes
    );
    assert_eq!(report.verdict, "fail");
}

#[test]
fn duplicate_case_names_are_refused() {
    let (baseline, cases) = setup();
    let mut twice = cases.clone();
    twice[1].name = twice[0].name.clone();
    assert!(evaluate_release_gate(&pack(&baseline), &pack(&baseline), &twice, &Acknowledgements::default()).is_err());
}
