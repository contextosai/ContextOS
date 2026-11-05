//! Pack tests check a pack's decisions against an author's expectations.

use contextos_contract::types::ContextPack;
use contextos_kernel::pack_test::{PackTestSuite, SuiteReport, run_pack_tests};
use serde_json::{Value, json};

fn low_value_case() -> Value {
    let path = format!("{}/../../conformance/vectors/compiler.json", env!("CARGO_MANIFEST_DIR"));
    let vectors: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "grid:support.refund:true:1200:support_agent")
        .unwrap()
        .clone()
}

fn run(tests: Value) -> SuiteReport {
    let case = low_value_case();
    let pack: ContextPack = serde_json::from_value(case["pack"].clone()).unwrap();
    let suite: PackTestSuite = serde_json::from_value(json!({
        "suite": "support refunds",
        "base": {"request": case["request"], "run_context": case["run_context"], "deps": case["deps"]},
        "tests": tests,
    }))
    .unwrap();
    run_pack_tests(&pack, &suite).unwrap()
}

fn amount(minor: u64) -> Value {
    json!({"request": {"input": {"context": {"refund_amount": minor}}}})
}

#[test]
fn expectations_that_hold_pass() {
    let report = run(json!([
        {"name": "low value refund is allowed", "expect": {
            "verdict": "allow",
            "rules": ["R_REFUND_REQUIRES_IDV"],
            "obligations": ["order_lookup"],
            "capabilities": {"include": ["adp_payments.issue_refund", "adp_orders.lookup"]}}},
        {"name": "high value refund needs approval", "with": amount(4200), "expect": {
            "verdict": "require_approval",
            "rules": ["R_REFUND_REQUIRES_IDV", "R_HIGH_VALUE_REQUIRES_APPROVAL"],
            "evidence_gates": {"support.refund.execute": true}}},
        {"name": "unverified identity is denied",
         "with": {"request": {"input": {"context": {"identity_verified": false}}}},
         "expect": {"verdict": "deny"}},
    ]));
    assert_eq!(report.verdict, "pass", "{report:#?}");
    assert_eq!((report.passed, report.failed), (3, 0));
}

#[test]
fn a_wrong_expectation_fails_and_names_what_was_observed() {
    let report = run(json!([
        {"name": "high value refund is wrongly expected to be allowed", "with": amount(4200),
         "expect": {"verdict": "allow", "rules": ["R_REFUND_REQUIRES_IDV"]}},
    ]));
    assert_eq!(report.verdict, "fail");
    let failures = &report.tests[0].failures;
    assert!(
        failures.contains(&"verdict: expected allow, got require_approval".to_owned()),
        "{failures:?}"
    );
    assert!(
        failures
            .iter()
            .any(|f| f.starts_with("rules:") && f.contains("R_HIGH_VALUE_REQUIRES_APPROVAL")),
        "{failures:?}"
    );
}

#[test]
fn capability_and_gate_expectations_fail_with_the_difference() {
    let report = run(json!([
        {"name": "surfacing and gates", "expect": {
            "capabilities": {"include": ["no_such_adapter.refund"], "exclude": ["adp_payments.issue_refund"]},
            "evidence_gates": {"support.refund.execute": false}}},
    ]));
    assert_eq!(report.tests[0].status, "fail");
    assert_eq!(
        report.tests[0].failures,
        vec![
            "capability no_such_adapter.refund is not surfaced",
            "capability adp_payments.issue_refund is surfaced",
            "evidence gate support.refund.execute is absent",
        ]
    );
}

#[test]
fn invalid_tests_are_errors_not_passes() {
    let report = run(json!([
        {"name": "checks nothing", "expect": {}},
        {"name": "patches an unknown key", "with": {"pack": {}}, "expect": {"verdict": "allow"}},
        {"name": "unknown verdict", "expect": {"verdict": "maybe"}},
        {"name": "refused with more", "expect": {"compile": "refused", "verdict": "deny"}},
        {"name": "breaks the request", "with": {"request": {"input": null}}, "expect": {"verdict": "allow"}},
    ]));
    assert_eq!(report.failed, 5);
    assert!(report.tests.iter().all(|t| t.status == "error"), "{report:#?}");
}

#[test]
fn compile_refusal_is_expected_or_reported() {
    // An evidence item that is neither a string nor an object makes the compiler refuse.
    let bad = json!({"deps": {"evidence": [42]}});
    let report = run(json!([
        {"name": "refused as expected", "with": bad, "expect": {"compile": "refused"}},
        {"name": "refused unexpectedly", "with": bad, "expect": {"verdict": "allow"}},
        {"name": "compiles but expected refused", "expect": {"compile": "refused"}},
    ]));
    let statuses: Vec<&str> = report.tests.iter().map(|t| t.status.as_str()).collect();
    assert_eq!(statuses, ["pass", "fail", "fail"]);
    assert!(report.tests[1].failures[0].starts_with("compile: expected the case to compile, got evidence[0]"));
}

#[test]
fn duplicate_names_and_empty_suites_are_refused() {
    let case = low_value_case();
    let pack: ContextPack = serde_json::from_value(case["pack"].clone()).unwrap();
    let suite = |tests: Value| -> PackTestSuite {
        serde_json::from_value(json!({"suite": "s", "base": {"request": case["request"],
            "run_context": case["run_context"]}, "tests": tests}))
        .unwrap()
    };
    assert!(run_pack_tests(&pack, &suite(json!([]))).is_err());
    let twice = json!([{"name": "a", "expect": {"verdict": "allow"}}, {"name": "a", "expect": {"verdict": "allow"}}]);
    assert!(
        run_pack_tests(&pack, &suite(twice))
            .unwrap_err()
            .contains("more than once")
    );
}
