//! Reliability release gate: does a candidate succeed as *consistently* as the
//! baseline on the same replayed cases?
//!
//! Each case is run several times (trials) under the baseline and the candidate, and
//! each trial is a pass or a fail. Per case, with `n` trials and `c` passes:
//!
//! - **pass^k** = C(c, k) / C(n, k): the chance that `k` trials drawn without
//!   replacement all pass. It falls as `k` grows unless the agent is consistent,
//!   which is what an agent that moves money or changes records needs
//!   (<https://arxiv.org/abs/2406.12045>).
//! - **pass@k** = 1 − C(n − c, k) / C(n, k): the chance that at least one of `k`
//!   passes, the unbiased estimator of <https://arxiv.org/abs/2107.03374>. Reported,
//!   never gated: one success in `k` is not good enough for a consequential action.
//!
//! The case is the unit of analysis: each side's suite score is the mean of its
//! per-case pass^k, and the comparison is the mean of the paired per-case differences
//! with a normal interval `mean ± z·sd/√m` over the `m` paired cases (the clustered,
//! paired comparison of <https://arxiv.org/abs/2411.00640>). The gate is a
//! non-inferiority test with the release owner's margin `δ`:
//!
//! - the interval's lower bound is at least `−δ`: **pass**;
//! - its upper bound is below `−δ`: the candidate is worse (**regression**);
//! - otherwise the suite cannot tell (**inconclusive**), which also fails: run more
//!   cases or trials. The report names the drop the suite could detect
//!   (`(z + 0.84)·se`, 80% power) so a pass on a small suite is not over-read.
//!
//! Normal intervals are too narrow on small suites (<https://arxiv.org/abs/2503.01747>);
//! `min_cases` and `z` are the owner's guard against that.
//!
//! When trials carry their step counts (tool calls), the report adds **path
//! convergence** over passing trials: per case, `s_min` is the fewest steps of any
//! passing trial on either side, and each side's convergence is the mean of
//! `s_min / s_i` over its passing trials (1 is every pass taking the shortest path).
//! A limit on its drop catches a candidate that still succeeds but wanders.
//!
//! The gate also fails when a `must_pass` case has any failing candidate trial, the
//! candidate's suite pass^k is under its floor, a baseline case has no candidate
//! trials (**missing**), a case has fewer than `k` trials (**too_few_trials**), or
//! fewer cases pair than `min_cases` (**underpowered**). Thresholds are the release
//! owner's input, never the candidate's.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The one-sided 80% power quantile used for the detectable drop.
const Z_POWER_80: f64 = 0.8416;

/// One run of a case.
#[derive(Debug, Clone, Deserialize)]
pub struct Trial {
    pub passed: bool,
    /// Steps the run took (governed tool calls), for path convergence.
    #[serde(default)]
    pub steps: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CaseTrials {
    pub case: String,
    pub trials: Vec<Trial>,
}

fn default_z() -> f64 {
    1.96
}

/// The release owner's limits. The margin and `k` have no defaults: they are a
/// policy decision.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReliabilityThresholds {
    /// The pass^k order: how many runs in a row must succeed.
    pub k: usize,
    /// Non-inferiority margin: the largest mean pass^k drop a release may carry.
    pub max_pass_k_drop: f64,
    /// Fewest paired cases for a verdict (at least 2).
    pub min_cases: usize,
    /// The candidate's suite pass^k must be at least this.
    #[serde(default)]
    pub pass_k_floor: Option<f64>,
    /// Cases whose every candidate trial must pass.
    #[serde(default)]
    pub must_pass: Vec<String>,
    /// Largest allowed drop in mean path convergence (absolute).
    #[serde(default)]
    pub max_convergence_drop: Option<f64>,
    /// Interval quantile; 1.96 is a two-sided 95% interval.
    #[serde(default = "default_z")]
    pub z: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Failure {
    /// `regression`, `inconclusive`, `floor`, `must_pass`, `convergence`, `missing`,
    /// `too_few_trials` or `underpowered`.
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub case: Option<String>,
    pub detail: String,
}

/// One side's suite figures.
#[derive(Debug, Clone, Serialize)]
pub struct SideSummary {
    pub cases: usize,
    pub trials: usize,
    /// Mean per-case pass rate (pass^1).
    pub pass_1: Option<f64>,
    pub pass_k: Option<f64>,
    pub pass_at_k: Option<f64>,
    /// Mean path convergence over cases measured on both sides.
    pub convergence: Option<f64>,
}

/// The paired per-case difference in pass^k (candidate − baseline).
#[derive(Debug, Clone, Serialize)]
pub struct Delta {
    pub mean: f64,
    pub lower: f64,
    pub upper: f64,
    /// The smallest drop this suite detects at 80% power.
    pub detectable_drop: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReliabilityReport {
    /// `pass` or `fail`.
    pub verdict: String,
    pub k: usize,
    pub paired_cases: usize,
    pub baseline: SideSummary,
    pub candidate: SideSummary,
    pub pass_k_delta: Option<Delta>,
    /// Baseline cases that passed some trials and failed others.
    pub flaky_cases: Vec<String>,
    /// Paired cases no trial passed on either side: usually a broken case, not an
    /// incapable agent; they stay in the comparison.
    pub broken_cases: Vec<String>,
    pub failures: Vec<Failure>,
}

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

/// C(a, k) / C(n, k) for `a <= n`, as a product so large counts do not overflow.
#[allow(clippy::cast_precision_loss)]
fn choose_ratio(a: usize, n: usize, k: usize) -> f64 {
    if a < k {
        return 0.0;
    }
    (0..k).map(|i| (a - i) as f64 / (n - i) as f64).product()
}

/// pass^k of `c` passes in `n >= k` trials.
#[must_use]
pub fn pass_hat_k(n: usize, c: usize, k: usize) -> f64 {
    choose_ratio(c, n, k)
}

/// pass@k of `c` passes in `n >= k` trials.
#[must_use]
pub fn pass_at_k(n: usize, c: usize, k: usize) -> f64 {
    1.0 - choose_ratio(n - c, n, k)
}

fn index(cases: &[CaseTrials], side: &str) -> Result<BTreeMap<String, Vec<Trial>>, String> {
    let mut map = BTreeMap::new();
    for case in cases {
        if map.insert(case.case.clone(), case.trials.clone()).is_some() {
            return Err(format!("{side} case {} appears twice", case.case));
        }
    }
    Ok(map)
}

fn passes(trials: &[Trial]) -> usize {
    trials.iter().filter(|t| t.passed).count()
}

/// Steps of passing trials that recorded them.
fn passing_steps(trials: &[Trial]) -> impl Iterator<Item = u64> + '_ {
    trials.iter().filter(|t| t.passed).filter_map(|t| t.steps)
}

#[allow(clippy::cast_precision_loss)]
fn convergence(trials: &[Trial], shortest: u64) -> Option<f64> {
    mean(passing_steps(trials).map(|s| if s == 0 { 1.0 } else { shortest as f64 / s as f64 }))
}

fn validate(t: &ReliabilityThresholds) -> Result<(), String> {
    let unit = |v: f64| v.is_finite() && (0.0..=1.0).contains(&v);
    if t.k == 0 {
        return Err("k must be at least 1".into());
    }
    if t.min_cases < 2 {
        return Err("min_cases must be at least 2: one case has no variance".into());
    }
    let valid = unit(t.max_pass_k_drop)
        && t.pass_k_floor.is_none_or(unit)
        && t.max_convergence_drop.is_none_or(unit)
        && t.z.is_finite()
        && t.z > 0.0;
    if !valid {
        return Err("margins and floors must be in [0, 1] and z positive".into());
    }
    Ok(())
}

fn summary(cases: &BTreeMap<String, Vec<Trial>>, k: usize, convergence: Option<f64>) -> SideSummary {
    let scored: Vec<(usize, usize)> = cases
        .values()
        .filter(|t| t.len() >= k)
        .map(|t| (t.len(), passes(t)))
        .collect();
    #[allow(clippy::cast_precision_loss)]
    SideSummary {
        cases: cases.len(),
        trials: cases.values().map(Vec::len).sum(),
        pass_1: mean(scored.iter().map(|&(n, c)| c as f64 / n as f64)),
        pass_k: mean(scored.iter().map(|&(n, c)| pass_hat_k(n, c, k))),
        pass_at_k: mean(scored.iter().map(|&(n, c)| pass_at_k(n, c, k))),
        convergence,
    }
}

/// Compares the candidate's per-case reliability with the baseline's.
pub fn evaluate_reliability_gate(
    baseline: &[CaseTrials],
    candidate: &[CaseTrials],
    thresholds: &ReliabilityThresholds,
) -> Result<ReliabilityReport, String> {
    validate(thresholds)?;
    let k = thresholds.k;
    let base = index(baseline, "baseline")?;
    let cand = index(candidate, "candidate")?;
    let mut failures = Vec::new();

    for (side, cases) in [("baseline", &base), ("candidate", &cand)] {
        for (name, trials) in cases {
            if trials.len() < k {
                failures.push(failure(
                    "too_few_trials",
                    Some(name),
                    format!("{side} has {} trial(s), k = {k}", trials.len()),
                ));
            }
        }
    }
    for name in &thresholds.must_pass {
        match cand.get(name) {
            Some(trials) if !trials.is_empty() && passes(trials) == trials.len() => {}
            Some(trials) => failures.push(failure(
                "must_pass",
                Some(name),
                format!("{} of {} candidate trial(s) passed", passes(trials), trials.len()),
            )),
            None => failures.push(failure("must_pass", Some(name), "the candidate did not run it".into())),
        }
    }

    // Pairs with enough trials on both sides; missing cases stay visible.
    let mut diffs = Vec::new();
    let mut broken = Vec::new();
    let (mut base_conv, mut cand_conv) = (Vec::new(), Vec::new());
    let mut unconverged = Vec::new();
    for (name, b) in &base {
        let Some(c) = cand.get(name).filter(|c| !c.is_empty()) else {
            failures.push(failure(
                "missing",
                Some(name),
                "no candidate trials for this case".into(),
            ));
            continue;
        };
        if passes(b) == 0 && passes(c) == 0 {
            broken.push(name.clone());
        }
        if let Some(shortest) = passing_steps(b).chain(passing_steps(c)).min() {
            match (convergence(b, shortest), convergence(c, shortest)) {
                (Some(bc), Some(cc)) => {
                    base_conv.push(bc);
                    cand_conv.push(cc);
                }
                // The baseline converged here and the candidate never passed.
                (Some(bc), None) => {
                    base_conv.push(bc);
                    cand_conv.push(0.0);
                    unconverged.push(name.clone());
                }
                _ => {}
            }
        }
        if b.len() >= k && c.len() >= k {
            diffs.push(pass_hat_k(c.len(), passes(c), k) - pass_hat_k(b.len(), passes(b), k));
        }
    }
    let flaky = base
        .iter()
        .filter(|(_, t)| (1..t.len()).contains(&passes(t)))
        .map(|(n, _)| n.clone())
        .collect();

    if diffs.len() < thresholds.min_cases {
        failures.push(failure(
            "underpowered",
            None,
            format!("{} paired case(s), {} required", diffs.len(), thresholds.min_cases),
        ));
    }
    let pass_k_delta = interval(&diffs, thresholds.z);
    if let Some(delta) = &pass_k_delta
        && diffs.len() >= thresholds.min_cases
    {
        let margin = -thresholds.max_pass_k_drop;
        if delta.upper < margin {
            failures.push(failure(
                "regression",
                None,
                format!(
                    "pass^{k} changed by {:.4} [{:.4}, {:.4}], margin -{}",
                    delta.mean, delta.lower, delta.upper, thresholds.max_pass_k_drop
                ),
            ));
        } else if delta.lower < margin {
            failures.push(failure(
                "inconclusive",
                None,
                format!(
                    "pass^{k} changed by {:.4} [{:.4}, {:.4}]: cannot rule out a drop beyond {}; \
                     this suite detects drops of {:.4}",
                    delta.mean, delta.lower, delta.upper, thresholds.max_pass_k_drop, delta.detectable_drop
                ),
            ));
        }
    }

    let (base_c, cand_c) = (mean(base_conv.into_iter()), mean(cand_conv.into_iter()));
    if let (Some(limit), Some(b), Some(c)) = (thresholds.max_convergence_drop, base_c, cand_c)
        && b - c > limit
    {
        failures.push(failure(
            "convergence",
            None,
            format!(
                "mean path convergence {b:.4} -> {c:.4}{}",
                if unconverged.is_empty() {
                    String::new()
                } else {
                    format!(" (no candidate pass on {})", unconverged.join(", "))
                }
            ),
        ));
    }

    let candidate_summary = summary(&cand, k, cand_c);
    if let (Some(floor), Some(score)) = (thresholds.pass_k_floor, candidate_summary.pass_k)
        && score < floor
    {
        failures.push(failure(
            "floor",
            None,
            format!("candidate pass^{k} {score:.4} < floor {floor}"),
        ));
    }
    Ok(ReliabilityReport {
        verdict: if failures.is_empty() { "pass" } else { "fail" }.into(),
        k,
        paired_cases: diffs.len(),
        baseline: summary(&base, k, base_c),
        candidate: candidate_summary,
        pass_k_delta,
        flaky_cases: flaky,
        broken_cases: broken,
        failures,
    })
}

/// `mean ± z·sd/√m` over the paired differences.
#[allow(clippy::cast_precision_loss)]
fn interval(diffs: &[f64], z: f64) -> Option<Delta> {
    let m = diffs.len();
    let mean = mean(diffs.iter().copied())?;
    let se = if m < 2 {
        f64::INFINITY
    } else {
        let var = diffs.iter().map(|d| (d - mean).powi(2)).sum::<f64>() / (m - 1) as f64;
        (var / m as f64).sqrt()
    };
    Some(Delta {
        mean,
        lower: mean - z * se,
        upper: mean + z * se,
        detectable_drop: (z + Z_POWER_80) * se,
    })
}
