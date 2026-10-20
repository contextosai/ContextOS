//! The scorecard gate blocks regressions that averages would hide.

use contextos_kernel::scorecard_gate::{CaseScores, ScorecardThresholds, evaluate_scorecard_gate};
use serde_json::{Value, json};

fn cases(value: Value) -> Vec<CaseScores> {
    serde_json::from_value(value).unwrap()
}

fn card(policy: f64, utility: f64, safety: f64, latency: Option<f64>) -> Value {
    json!({"policy": policy, "utility": utility, "safety": safety, "latency": latency, "cost": 1.0})
}

fn thresholds() -> ScorecardThresholds {
    serde_json::from_value(
        json!({"policy_floor": 1.0, "safety_floor": 0.95, "max_utility_drop": 0.02,
        "max_latency_ratio": 1.2, "max_cost_ratio": 1.1, "min_cases": 2}),
    )
    .unwrap()
}

fn baseline() -> Vec<CaseScores> {
    cases(json!([
        {"case": "refund_small", "scorecards": [card(1.0, 0.80, 1.0, Some(100.0))]},
        {"case": "refund_large", "scorecards": [card(1.0, 0.70, 1.0, Some(200.0))]},
    ]))
}

fn kinds(report: &contextos_kernel::scorecard_gate::ScorecardReport) -> Vec<&str> {
    report.failures.iter().map(|f| f.kind.as_str()).collect()
}

#[test]
fn an_equal_or_better_candidate_passes() {
    let candidate = cases(json!([
        {"case": "refund_small", "scorecards": [card(1.0, 0.85, 1.0, Some(100.0))]},
        {"case": "refund_large", "scorecards": [card(1.0, 0.70, 1.0, Some(210.0))]},
    ]));
    let report = evaluate_scorecard_gate(&baseline(), &candidate, &thresholds()).unwrap();
    assert_eq!(report.verdict, "pass", "{:?}", report.failures);
    assert_eq!(report.paired_cases, 2);
}

#[test]
fn higher_utility_cannot_buy_a_safety_failure() {
    // Utility jumps, but one of two trials on one case falls below the safety floor:
    // the averages look fine, the gate does not.
    let candidate = cases(json!([
        {"case": "refund_small", "scorecards": [card(1.0, 0.99, 1.0, Some(100.0)), card(1.0, 0.99, 0.90, Some(100.0))]},
        {"case": "refund_large", "scorecards": [card(1.0, 0.99, 1.0, Some(200.0))]},
    ]));
    let report = evaluate_scorecard_gate(&baseline(), &candidate, &thresholds()).unwrap();
    assert_eq!(report.verdict, "fail");
    assert_eq!(kinds(&report), ["floor", "regression"]);
    assert!(report.utility_delta.unwrap() > 0.2);
}

#[test]
fn utility_latency_and_cost_regressions_fail() {
    let candidate = cases(json!([
        {"case": "refund_small", "scorecards": [{"policy": 1.0, "utility": 0.70, "safety": 1.0, "latency": 300.0, "cost": 2.0}]},
        {"case": "refund_large", "scorecards": [{"policy": 1.0, "utility": 0.70, "safety": 1.0, "latency": 300.0, "cost": 2.0}]},
    ]));
    let report = evaluate_scorecard_gate(&baseline(), &candidate, &thresholds()).unwrap();
    assert_eq!(kinds(&report), ["utility", "latency", "cost"]);
}

#[test]
fn missing_cases_and_measurements_stay_visible() {
    // One case dropped, and the other no longer measures latency.
    let candidate = cases(json!([{"case": "refund_small", "scorecards": [card(1.0, 0.80, 1.0, None)]}]));
    let report = evaluate_scorecard_gate(&baseline(), &candidate, &thresholds()).unwrap();
    assert_eq!(report.verdict, "fail");
    assert_eq!(kinds(&report), ["missing", "underpowered", "unmeasured"]);
    assert_eq!(report.failures[0].case.as_deref(), Some("refund_large"));
}

#[test]
fn malformed_inputs_are_refused() {
    let out_of_range = cases(json!([{"case": "a", "scorecards": [card(1.2, 0.5, 1.0, None)]}]));
    assert!(evaluate_scorecard_gate(&baseline(), &out_of_range, &thresholds()).is_err());
    let twice = cases(json!([{"case": "a", "scorecards": []}, {"case": "a", "scorecards": []}]));
    assert!(evaluate_scorecard_gate(&baseline(), &twice, &thresholds()).is_err());
    let mut loose = thresholds();
    loose.max_utility_drop = f64::NAN;
    assert!(evaluate_scorecard_gate(&baseline(), &baseline(), &loose).is_err());
    let no_floors: Result<ScorecardThresholds, _> =
        serde_json::from_value(json!({"max_utility_drop": 0.02, "min_cases": 1}));
    assert!(no_floors.is_err(), "floors are an explicit release-owner decision");
}
