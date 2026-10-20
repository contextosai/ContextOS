//! Scorecard release gate (runtime extension; see the spec's evaluation plane: a
//! release is blocked when scorecard deltas exceed configured thresholds, utility,
//! cost and latency cannot trade away policy or safety, a high average cannot hide a
//! failure, and missing measurements stay visible).
//!
//! Baseline and candidate scorecards are paired by replay-case name; a case may carry
//! several scorecards (evaluators or trials). The gate fails when:
//!
//! - any candidate scorecard is below the policy or safety **floor** (each one, never
//!   an average);
//! - on any paired case, the candidate's lowest policy or safety score is below the
//!   baseline's (**no regression** on the dimensions that guard authority and harm);
//! - mean utility over paired cases drops by more than the allowed amount;
//! - mean latency or cost rises by more than the allowed ratio, when a limit is set;
//!   a case measured in the baseline but not in the candidate fails as unmeasured;
//! - a baseline case has no candidate scorecards (**missing** stays in the
//!   denominator), or fewer cases are paired than the minimum (**underpowered**).
//!
//! Thresholds are the release owner's input, never part of the candidate.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// One DecisionRecord-shaped scorecard.
#[derive(Debug, Clone, Deserialize)]
pub struct Scorecard {
    pub policy: f64,
    pub utility: f64,
    pub safety: f64,
    #[serde(default)]
    pub latency: Option<f64>,
    #[serde(default)]
    pub cost: Option<f64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseScores {
    pub case: String,
    pub scorecards: Vec<Scorecard>,
}

/// The release owner's limits. Floors have no defaults: they are a policy decision.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScorecardThresholds {
    pub policy_floor: f64,
    pub safety_floor: f64,
    /// Largest allowed drop in mean utility (absolute, e.g. `0.02`).
    pub max_utility_drop: f64,
    /// Largest allowed candidate/baseline ratio of mean latency (e.g. `1.10`).
    #[serde(default)]
    pub max_latency_ratio: Option<f64>,
    /// Largest allowed candidate/baseline ratio of mean cost.
    #[serde(default)]
    pub max_cost_ratio: Option<f64>,
    /// Fewest paired cases for a verdict.
    pub min_cases: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Failure {
    /// `floor`, `regression`, `utility`, `latency`, `cost`, `unmeasured`, `missing`
    /// or `underpowered`.
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub case: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScorecardReport {
    /// `pass` or `fail`.
    pub verdict: String,
    pub paired_cases: usize,
    pub utility_delta: Option<f64>,
    pub latency_ratio: Option<f64>,
    pub cost_ratio: Option<f64>,
    pub failures: Vec<Failure>,
}

/// A named scorecard dimension and how to read it.
type Dimension = (&'static str, fn(&Scorecard) -> f64);

fn failure(kind: &str, case: Option<&str>, detail: String) -> Failure {
    Failure {
        kind: kind.into(),
        case: case.map(str::to_owned),
        detail,
    }
}

fn mean(values: impl Iterator<Item = f64>) -> Option<f64> {
    let (sum, n) = values.fold((0.0, 0_u32), |(s, n), v| (s + v, n + 1));
    (n > 0).then(|| sum / f64::from(n))
}

fn min(values: impl Iterator<Item = f64>) -> Option<f64> {
    values.fold(None, |m: Option<f64>, v| Some(m.map_or(v, |m| m.min(v))))
}

fn valid(card: &Scorecard) -> bool {
    let unit = |v: f64| v.is_finite() && (0.0..=1.0).contains(&v);
    let measure = |v: Option<f64>| v.is_none_or(|v| v.is_finite() && v >= 0.0);
    unit(card.policy) && unit(card.utility) && unit(card.safety) && measure(card.latency) && measure(card.cost)
}

fn index(cases: &[CaseScores], side: &str) -> Result<BTreeMap<String, Vec<Scorecard>>, String> {
    let mut map = BTreeMap::new();
    for case in cases {
        if case.scorecards.iter().any(|c| !valid(c)) {
            return Err(format!(
                "{side} case {}: scores must be in [0, 1], measures finite and >= 0",
                case.case
            ));
        }
        if map.insert(case.case.clone(), case.scorecards.clone()).is_some() {
            return Err(format!("{side} case {} appears twice", case.case));
        }
    }
    Ok(map)
}

/// Mean over paired cases of each side's per-case mean of `pick`, and the cases the
/// baseline measured that the candidate did not.
fn measured_ratio(
    pairs: &[(&String, &Vec<Scorecard>, &Vec<Scorecard>)],
    pick: fn(&Scorecard) -> Option<f64>,
) -> (Option<f64>, Vec<String>) {
    let mut unmeasured = Vec::new();
    let (mut base, mut cand) = (Vec::new(), Vec::new());
    for (name, b, c) in pairs {
        let (bm, cm) = (mean(b.iter().filter_map(pick)), mean(c.iter().filter_map(pick)));
        // Every candidate scorecard must be measured where the baseline was.
        let incomplete = c.iter().any(|card| pick(card).is_none());
        match (bm, cm) {
            (Some(_), _) if incomplete => unmeasured.push((*name).clone()),
            (Some(bv), Some(cv)) => {
                base.push(bv);
                cand.push(cv);
            }
            _ => {}
        }
    }
    let ratio = match (mean(base.into_iter()), mean(cand.into_iter())) {
        (Some(b), Some(c)) if b > 0.0 => Some(c / b),
        (Some(_), Some(c)) => Some(if c > 0.0 { f64::INFINITY } else { 1.0 }),
        _ => None,
    };
    (ratio, unmeasured)
}

/// Compares candidate scorecards with the baseline's on paired replay cases.
pub fn evaluate_scorecard_gate(
    baseline: &[CaseScores],
    candidate: &[CaseScores],
    thresholds: &ScorecardThresholds,
) -> Result<ScorecardReport, String> {
    let limits = [
        thresholds.policy_floor,
        thresholds.safety_floor,
        thresholds.max_utility_drop,
    ];
    if limits.iter().any(|v| !v.is_finite() || *v < 0.0)
        || [thresholds.max_latency_ratio, thresholds.max_cost_ratio]
            .iter()
            .flatten()
            .any(|v| !v.is_finite() || *v <= 0.0)
    {
        return Err("thresholds must be finite and non-negative (ratios positive)".into());
    }
    let base = index(baseline, "baseline")?;
    let cand = index(candidate, "candidate")?;
    let mut failures = Vec::new();

    // Floors apply to every candidate scorecard, paired or not.
    for (name, cards) in &cand {
        for card in cards {
            if card.policy < thresholds.policy_floor {
                failures.push(failure(
                    "floor",
                    Some(name),
                    format!("policy {} < floor {}", card.policy, thresholds.policy_floor),
                ));
            }
            if card.safety < thresholds.safety_floor {
                failures.push(failure(
                    "floor",
                    Some(name),
                    format!("safety {} < floor {}", card.safety, thresholds.safety_floor),
                ));
            }
        }
    }

    let mut pairs = Vec::new();
    for (name, b) in &base {
        match cand.get(name).filter(|c| !c.is_empty()) {
            Some(c) => pairs.push((name, b, c)),
            None => failures.push(failure(
                "missing",
                Some(name),
                "no candidate scorecards for this case".into(),
            )),
        }
    }
    if pairs.len() < thresholds.min_cases.max(1) {
        failures.push(failure(
            "underpowered",
            None,
            format!(
                "{} paired case(s), {} required",
                pairs.len(),
                thresholds.min_cases.max(1)
            ),
        ));
    }

    for (name, b, c) in &pairs {
        let dimensions: [Dimension; 2] = [("policy", |s| s.policy), ("safety", |s| s.safety)];
        for (dimension, pick) in dimensions {
            if let (Some(bm), Some(cm)) = (min(b.iter().map(pick)), min(c.iter().map(pick)))
                && cm < bm
            {
                failures.push(failure("regression", Some(name), format!("{dimension} {bm} -> {cm}")));
            }
        }
    }

    let utility_delta = mean(
        pairs
            .iter()
            .filter_map(|(_, b, c)| Some(mean(c.iter().map(|s| s.utility))? - mean(b.iter().map(|s| s.utility))?)),
    );
    if let Some(delta) = utility_delta
        && -delta > thresholds.max_utility_drop
    {
        failures.push(failure("utility", None, format!("mean utility changed by {delta:.4}")));
    }

    let mut ratio_check = |kind: &str, limit: Option<f64>, pick: fn(&Scorecard) -> Option<f64>| {
        let (ratio, unmeasured) = measured_ratio(&pairs, pick);
        if limit.is_some() {
            for name in unmeasured {
                failures.push(failure(
                    "unmeasured",
                    Some(&name),
                    format!("{kind} measured in the baseline only"),
                ));
            }
        }
        if let (Some(r), Some(max)) = (ratio, limit)
            && r > max
        {
            failures.push(failure(kind, None, format!("mean {kind} ratio {r:.4} > {max}")));
        }
        ratio
    };
    let latency_ratio = ratio_check("latency", thresholds.max_latency_ratio, |s| s.latency);
    let cost_ratio = ratio_check("cost", thresholds.max_cost_ratio, |s| s.cost);

    Ok(ScorecardReport {
        verdict: if failures.is_empty() { "pass" } else { "fail" }.into(),
        paired_cases: pairs.len(),
        utility_delta,
        latency_ratio,
        cost_ratio,
        failures,
    })
}
