//! The reliability gate compares how consistently baseline and candidate succeed.

use contextos_kernel::reliability_gate::{
    CaseTrials, ReliabilityReport, ReliabilityThresholds, evaluate_reliability_gate, pass_at_k, pass_hat_k,
};
use serde_json::{Value, json};

/// `passes` of `n` trials, each taking `steps`.
fn case(name: &str, n: usize, passes: usize, steps: u64) -> Value {
    let trials: Vec<Value> = (0..n).map(|i| json!({"passed": i < passes, "steps": steps})).collect();
    json!({"case": name, "trials": trials})
}

fn cases(values: Vec<Value>) -> Vec<CaseTrials> {
    serde_json::from_value(Value::Array(values)).unwrap()
}

fn limits(extra: Value) -> ReliabilityThresholds {
    let mut base = json!({"k": 2, "max_pass_k_drop": 0.05, "min_cases": 3});
    for (key, value) in extra.as_object().unwrap() {
        base[key] = value.clone();
    }
    serde_json::from_value(base).unwrap()
}

fn kinds(report: &ReliabilityReport) -> Vec<&str> {
    report.failures.iter().map(|f| f.kind.as_str()).collect()
}

fn suite(passes: [usize; 4], steps: u64) -> Vec<CaseTrials> {
    cases(
        ["a", "b", "c", "d"]
            .iter()
            .zip(passes)
            .map(|(name, p)| case(name, 4, p, steps))
            .collect(),
    )
}

#[test]
fn estimators_match_their_definitions() {
    // 3 of 4 passed: pass^2 = C(3,2)/C(4,2) = 3/6; pass@2 = 1 - C(1,2)/C(4,2) = 1.
    assert!((pass_hat_k(4, 3, 2) - 0.5).abs() < 1e-12);
    assert!((pass_at_k(4, 3, 2) - 1.0).abs() < 1e-12);
    // 2 of 4: pass^2 = 1/6, pass@2 = 1 - 1/6.
    assert!((pass_hat_k(4, 2, 2) - 1.0 / 6.0).abs() < 1e-12);
    assert!((pass_at_k(4, 2, 2) - 5.0 / 6.0).abs() < 1e-12);
    assert!(pass_hat_k(4, 1, 2).abs() < 1e-12);
    assert!((pass_hat_k(8, 8, 8) - 1.0).abs() < 1e-12);
}

#[test]
fn an_equally_reliable_candidate_passes() {
    let report = evaluate_reliability_gate(&suite([4; 4], 3), &suite([4; 4], 3), &limits(json!({}))).unwrap();
    assert_eq!(report.verdict, "pass", "{:?}", report.failures);
    assert_eq!(report.paired_cases, 4);
    assert_eq!(report.candidate.pass_k, Some(1.0));
    assert_eq!(report.candidate.convergence, Some(1.0));
}

#[test]
fn a_consistent_drop_is_a_regression_and_pass_at_k_hides_it() {
    // Every case drops from 4/4 to 3/4: pass@2 stays 1, pass^2 halves.
    let report = evaluate_reliability_gate(&suite([4; 4], 3), &suite([3; 4], 3), &limits(json!({}))).unwrap();
    assert_eq!(report.candidate.pass_at_k, Some(1.0));
    assert_eq!(report.candidate.pass_k, Some(0.5));
    assert_eq!(kinds(&report), ["regression"]);
    assert_eq!(report.flaky_cases, Vec::<String>::new());
}

#[test]
fn a_noisy_suite_is_inconclusive_not_a_pass() {
    let base = suite([4, 4, 2, 2], 3);
    let cand = suite([2, 4, 4, 2], 3);
    let report = evaluate_reliability_gate(&base, &cand, &limits(json!({}))).unwrap();
    let delta = report.pass_k_delta.as_ref().unwrap();
    assert!(delta.mean.abs() < 1e-12);
    assert!(delta.lower < -0.05 && delta.upper > -0.05);
    assert_eq!(kinds(&report), ["inconclusive"]);
    assert!(delta.detectable_drop > 0.05);
    assert_eq!(report.flaky_cases, ["c", "d"]);
}

#[test]
fn too_few_cases_or_trials_cannot_pass() {
    let one = cases(vec![case("a", 4, 4, 1), case("b", 4, 4, 1)]);
    let report = evaluate_reliability_gate(&one, &one, &limits(json!({}))).unwrap();
    assert_eq!(kinds(&report), ["underpowered"]);

    let short = suite([1; 4], 1);
    let short: Vec<CaseTrials> = serde_json::from_value(json!(
        short
            .iter()
            .map(|c| json!({"case": c.case, "trials": [{"passed": true}]}))
            .collect::<Vec<_>>()
    ))
    .unwrap();
    let report = evaluate_reliability_gate(&suite([4; 4], 1), &short, &limits(json!({}))).unwrap();
    assert!(kinds(&report).contains(&"too_few_trials"));
    assert!(kinds(&report).contains(&"underpowered"));
}

#[test]
fn missing_cases_must_pass_cases_and_floors_fail() {
    let cand = cases(vec![case("a", 4, 4, 1), case("b", 4, 4, 1), case("c", 4, 3, 1)]);
    let report = evaluate_reliability_gate(
        &suite([4; 4], 1),
        &cand,
        &limits(json!({"must_pass": ["c", "e"], "pass_k_floor": 0.9, "min_cases": 2, "max_pass_k_drop": 1.0})),
    )
    .unwrap();
    let mut found = kinds(&report);
    found.sort_unstable();
    assert_eq!(found, ["floor", "missing", "must_pass", "must_pass"]);
}

#[test]
fn a_candidate_that_wanders_fails_convergence() {
    // Same successes, but the candidate takes twice the steps.
    let report = evaluate_reliability_gate(
        &suite([4; 4], 3),
        &suite([4; 4], 6),
        &limits(json!({"max_convergence_drop": 0.2})),
    )
    .unwrap();
    assert_eq!(report.baseline.convergence, Some(1.0));
    assert_eq!(report.candidate.convergence, Some(0.5));
    assert_eq!(kinds(&report), ["convergence"]);
}

#[test]
fn cases_that_never_pass_are_reported_as_broken() {
    let base = suite([0, 4, 4, 4], 1);
    let report = evaluate_reliability_gate(&base, &base, &limits(json!({}))).unwrap();
    assert_eq!(report.broken_cases, ["a"]);
    assert_eq!(report.verdict, "pass");
}

#[test]
fn bad_thresholds_and_duplicates_are_refused() {
    let s = suite([4; 4], 1);
    assert!(evaluate_reliability_gate(&s, &s, &limits(json!({"k": 0}))).is_err());
    assert!(evaluate_reliability_gate(&s, &s, &limits(json!({"min_cases": 1}))).is_err());
    assert!(evaluate_reliability_gate(&s, &s, &limits(json!({"max_pass_k_drop": 1.5}))).is_err());
    let twice = cases(vec![case("a", 2, 2, 1), case("a", 2, 2, 1)]);
    assert!(evaluate_reliability_gate(&twice, &s, &limits(json!({}))).is_err());
}
