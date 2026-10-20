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
        policy_loosening: true,
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
            policy_loosening: true,
            ..Acknowledgements::default()
        },
    );
    assert_eq!(report.verdict, "fail");
    assert!(report.cases[0].changes.iter().any(|c| c.effect == "regression"));
}
