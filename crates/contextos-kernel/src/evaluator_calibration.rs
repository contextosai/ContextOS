//! Evaluator calibration: is a judge fit to count toward gates?
//!
//! A judge (an LLM rubric, a classifier, a scripted check) is validated as a classifier
//! against people. Each label pairs a human verdict with the judge's on the same item,
//! `pass` being the positive class:
//!
//! - **TPR** = TP / (TP + FN): the human passes the judge also passes;
//! - **TNR** = TN / (TN + FP): the human failures the judge also catches;
//! - **Youden's J** = TPR + TNR − 1: 0 is a coin, 1 is perfect agreement;
//! - **Cohen's κ**: agreement corrected for chance.
//!
//! TPR and TNR are reported separately because raw agreement hides a judge that
//! misses rare failures: when 5% fail, a judge that always says `pass` agrees 95% of
//! the time and has TNR 0 (<https://hamel.dev/blog/posts/llm-judge/>). Practitioners
//! aim for both above 0.9 with about 100 labels and never fewer than 60; the floors
//! here are the release owner's.
//!
//! The record binds the verdict to the evaluator release it was measured for and to
//! the digest of the labels, so a new judge version needs a new record, and a reader
//! recomputes every rate from the counts ([`check_record`]) rather than trusting the
//! rates it states.

use contextos_contract::canonical::sha256_canonical;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const CALIBRATION_VERSION: &str = "contextos-rs.evaluator_calibration.v1";

/// A verdict: `pass` or `fail`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Pass,
    Fail,
}

/// One item judged by a person and by the evaluator.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Label {
    pub id: String,
    pub human: Verdict,
    pub judge: Verdict,
}

/// What a fit evaluator must reach. No defaults: they are the release owner's.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CalibrationFloors {
    pub min_tpr: f64,
    pub min_tnr: f64,
    /// Fewest labels in each class (human `pass` and human `fail`).
    pub min_per_class: u64,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Counts {
    pub tp: u64,
    #[serde(rename = "fn")]
    pub fn_: u64,
    pub tn: u64,
    pub fp: u64,
}

/// Rates computed from counts.
#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
pub struct Rates {
    pub tpr: f64,
    pub tnr: f64,
    pub youden_j: f64,
    pub kappa: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationRecord {
    pub calibration_version: String,
    /// The evaluator release this record measured, e.g. `evaluator.refund_quality@3`.
    pub evaluator_ref: String,
    /// Digest of the canonical label set.
    pub labels_sha256: String,
    pub counts: Counts,
    pub floors: CalibrationFloors,
    /// Informational; [`check_record`] recomputes them from `counts`.
    #[serde(default)]
    pub rates: Option<Value>,
    /// `fit` or `unfit`, with what fell short.
    #[serde(default)]
    pub verdict: Option<String>,
    #[serde(default)]
    pub shortfalls: Vec<String>,
}

#[allow(clippy::cast_precision_loss)]
fn ratio(a: u64, b: u64) -> f64 {
    if b == 0 { 0.0 } else { a as f64 / b as f64 }
}

/// TPR, TNR, Youden's J and Cohen's κ from counts.
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn rates(c: Counts) -> Rates {
    let tpr = ratio(c.tp, c.tp + c.fn_);
    let tnr = ratio(c.tn, c.tn + c.fp);
    let n = (c.tp + c.fn_ + c.tn + c.fp) as f64;
    let kappa = if n == 0.0 {
        0.0
    } else {
        let observed = (c.tp + c.tn) as f64 / n;
        let human_pass = (c.tp + c.fn_) as f64 / n;
        let judge_pass = (c.tp + c.fp) as f64 / n;
        let expected = human_pass * judge_pass + (1.0 - human_pass) * (1.0 - judge_pass);
        if (1.0 - expected).abs() < f64::EPSILON {
            if observed >= 1.0 { 1.0 } else { 0.0 }
        } else {
            (observed - expected) / (1.0 - expected)
        }
    };
    Rates {
        tpr,
        tnr,
        youden_j: tpr + tnr - 1.0,
        kappa,
    }
}

fn shortfalls(c: Counts, floors: &CalibrationFloors) -> Vec<String> {
    let r = rates(c);
    let mut out = Vec::new();
    if c.tp + c.fn_ < floors.min_per_class {
        out.push(format!(
            "{} human pass label(s), {} required",
            c.tp + c.fn_,
            floors.min_per_class
        ));
    }
    if c.tn + c.fp < floors.min_per_class {
        out.push(format!(
            "{} human fail label(s), {} required",
            c.tn + c.fp,
            floors.min_per_class
        ));
    }
    if r.tpr < floors.min_tpr {
        out.push(format!("tpr {:.4} < {}", r.tpr, floors.min_tpr));
    }
    if r.tnr < floors.min_tnr {
        out.push(format!("tnr {:.4} < {}", r.tnr, floors.min_tnr));
    }
    out
}

fn check_floors(floors: &CalibrationFloors) -> Result<(), String> {
    let unit = |v: f64| v.is_finite() && (0.0..=1.0).contains(&v);
    if !(unit(floors.min_tpr) && unit(floors.min_tnr)) || floors.min_per_class == 0 {
        return Err("floors: min_tpr and min_tnr in [0, 1], min_per_class at least 1".into());
    }
    Ok(())
}

fn valid_ref(evaluator_ref: &str) -> bool {
    !evaluator_ref.trim().is_empty() && evaluator_ref.len() <= 256
}

/// Calibrates `evaluator_ref` against `labels` and returns its record.
pub fn calibrate(
    evaluator_ref: &str,
    labels: &[Label],
    floors: &CalibrationFloors,
) -> Result<CalibrationRecord, String> {
    check_floors(floors)?;
    if !valid_ref(evaluator_ref) {
        return Err("the evaluator ref is required (at most 256 bytes)".into());
    }
    let mut ids = std::collections::BTreeSet::new();
    let mut counts = Counts::default();
    for label in labels {
        if !ids.insert(label.id.as_str()) {
            return Err(format!("label {} appears twice", label.id));
        }
        match (label.human, label.judge) {
            (Verdict::Pass, Verdict::Pass) => counts.tp += 1,
            (Verdict::Pass, Verdict::Fail) => counts.fn_ += 1,
            (Verdict::Fail, Verdict::Fail) => counts.tn += 1,
            (Verdict::Fail, Verdict::Pass) => counts.fp += 1,
        }
    }
    let mut sorted: Vec<&Label> = labels.iter().collect();
    sorted.sort_by(|a, b| a.id.cmp(&b.id));
    let digest =
        sha256_canonical(&serde_json::to_value(&sorted).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    let short = shortfalls(counts, floors);
    Ok(CalibrationRecord {
        calibration_version: CALIBRATION_VERSION.into(),
        evaluator_ref: evaluator_ref.into(),
        labels_sha256: digest,
        counts,
        floors: *floors,
        rates: serde_json::to_value(rates(counts)).ok(),
        verdict: Some(if short.is_empty() { "fit" } else { "unfit" }.into()),
        shortfalls: short,
    })
}

/// Checks a record against `floors` (the deployment's, not the record's own),
/// recomputing every rate from its counts. `Ok(())` when the evaluator is fit.
pub fn check_record(record: &CalibrationRecord, floors: &CalibrationFloors) -> Result<(), Vec<String>> {
    check_floors(floors).map_err(|e| vec![e])?;
    if record.calibration_version != CALIBRATION_VERSION {
        return Err(vec![format!(
            "unknown calibration_version {}",
            record.calibration_version
        )]);
    }
    if !valid_ref(&record.evaluator_ref) || !record.labels_sha256.starts_with("sha256:") {
        return Err(vec!["a record names its evaluator and the digest of its labels".into()]);
    }
    let short = shortfalls(record.counts, floors);
    if short.is_empty() { Ok(()) } else { Err(short) }
}
