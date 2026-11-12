//! `ctx trials` and `ctx reliability-gate`: per-trial pass/fail from run evidence,
//! and the kernel's reliability gate over them.
//!
//! A trial is one run of a case. It passes when the runtime's own record says the run
//! succeeded, not when the agent said so:
//!
//! - the run completed (`run_state.status`);
//! - every outcome its effects owed was witnessed (or retired as not applicable), so
//!   an effect the system of record never confirmed is a failure;
//! - with criteria, every independent score on its decisions meets them, and no
//!   tool-call evaluation carries a failing label or a score under the floor.

use std::path::PathBuf;

use contextos_kernel::reliability_gate::{CaseTrials, ReliabilityThresholds, evaluate_reliability_gate};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{Failure, read, typed};

/// What a trial's scores must meet. Unset dimensions are not checked.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Criteria {
    #[serde(default)]
    policy_floor: Option<f64>,
    #[serde(default)]
    safety_floor: Option<f64>,
    /// The utility a score must reach for the trial to count as a success.
    #[serde(default)]
    utility_pass: Option<f64>,
    /// A run with no independent score fails.
    #[serde(default)]
    require_scores: bool,
    /// Tool-call evaluations with any of these labels fail the run (e.g. `["fail"]`).
    #[serde(default)]
    failing_labels: Vec<String>,
    /// Tool-call evaluations scored below this fail the run.
    #[serde(default)]
    evaluation_floor: Option<f64>,
}

/// Why one run's evidence does not count as a pass (empty when it does).
fn reasons(bundle: &Value, criteria: &Criteria) -> Vec<String> {
    let mut reasons = Vec::new();
    match bundle["run_state"]["status"].as_str() {
        Some("completed") => {}
        status => reasons.push(format!("run {}", status.unwrap_or("has no state"))),
    }
    for outcome in bundle["outcomes"].as_array().into_iter().flatten() {
        let state = outcome["state"].as_str().unwrap_or("unknown");
        if !matches!(state, "witnessed" | "not_applicable") {
            let operation = outcome["operation_id"].as_str().unwrap_or("?");
            reasons.push(format!("outcome of {operation} {state}"));
        }
    }
    let scores: Vec<&Value> = bundle["decisions"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|d| d["scores"].as_array().into_iter().flatten())
        .map(|s| &s["score"])
        .collect();
    if criteria.require_scores && scores.is_empty() {
        reasons.push("no independent score".into());
    }
    let checks = [
        ("policy", criteria.policy_floor),
        ("safety", criteria.safety_floor),
        ("utility", criteria.utility_pass),
    ];
    for score in scores {
        for (dimension, limit) in checks {
            let value = score["scorecard"][dimension].as_f64();
            if let Some(limit) = limit
                && value.is_none_or(|v| v < limit)
            {
                let evaluator = score["evaluator_ref"].as_str().unwrap_or("?");
                reasons.push(format!("{evaluator}: {dimension} {} < {limit}", json!(value)));
            }
        }
    }
    for operation in bundle["operation_evaluations"].as_array().into_iter().flatten() {
        for kept in operation["evaluations"].as_array().into_iter().flatten() {
            let evaluation = &kept["evaluation"];
            let what = format!(
                "{} {} of {}",
                evaluation["evaluator_ref"].as_str().unwrap_or("?"),
                evaluation["name"].as_str().unwrap_or("?"),
                operation["operation_id"].as_str().unwrap_or("?")
            );
            if let Some(label) = evaluation["label"].as_str()
                && criteria.failing_labels.iter().any(|l| l == label)
            {
                reasons.push(format!("{what}: {label}"));
            }
            if let (Some(floor), Some(score)) = (criteria.evaluation_floor, evaluation["score"].as_f64())
                && score < floor
            {
                reasons.push(format!("{what}: {score} < {floor}"));
            }
        }
    }
    reasons
}

/// One `{case, trials: [{run_id, passed, steps, reasons}]}` per case, from evidence.
pub(crate) fn trials(
    evidence: &[PathBuf],
    case_map: Option<&PathBuf>,
    criteria: Option<&PathBuf>,
) -> Result<Value, Failure> {
    let map = match case_map {
        Some(path) => read(path)?,
        None => json!({}),
    };
    let criteria: Criteria = match criteria {
        Some(path) => typed(read(path)?, "criteria")?,
        None => Criteria::default(),
    };
    let unit = |v: Option<f64>| v.is_none_or(|v| v.is_finite() && (0.0..=1.0).contains(&v));
    if !(unit(criteria.policy_floor)
        && unit(criteria.safety_floor)
        && unit(criteria.utility_pass)
        && unit(criteria.evaluation_floor))
    {
        return Err(Failure::Usage("criteria must be numbers in [0, 1]".into()));
    }
    let mut cases: Vec<Value> = Vec::new();
    for path in evidence {
        let bundle = read(path)?;
        let Some(run_id) = bundle["run_id"].as_str() else {
            return Err(Failure::Rejected(
                json!({"error": format!("{}: not an evidence bundle", path.display())}),
            ));
        };
        let case = map[run_id].as_str().unwrap_or(run_id).to_owned();
        let why = reasons(&bundle, &criteria);
        let trial = json!({
            "run_id": run_id, "passed": why.is_empty(), "reasons": why,
            "steps": bundle["budget_ledger"]["used"]["tool_calls"].as_u64(),
        });
        match cases.iter_mut().find(|c| c["case"] == case.as_str()) {
            Some(existing) => existing["trials"]
                .as_array_mut()
                .into_iter()
                .for_each(|t| t.push(trial.clone())),
            None => cases.push(json!({"case": case, "trials": [trial]})),
        }
    }
    Ok(Value::Array(cases))
}

pub(crate) fn gate(baseline: &PathBuf, candidate: &PathBuf, thresholds: &PathBuf) -> Result<Value, Failure> {
    let baseline: Vec<CaseTrials> = typed(read(baseline)?, "baseline")?;
    let candidate: Vec<CaseTrials> = typed(read(candidate)?, "candidate")?;
    let thresholds: ReliabilityThresholds = typed(read(thresholds)?, "thresholds")?;
    let report = evaluate_reliability_gate(&baseline, &candidate, &thresholds)
        .map_err(|e| Failure::Rejected(json!({"error": e})))?;
    let value = serde_json::to_value(&report).unwrap_or(Value::Null);
    if report.verdict == "pass" {
        Ok(value)
    } else {
        Err(Failure::Rejected(value))
    }
}
