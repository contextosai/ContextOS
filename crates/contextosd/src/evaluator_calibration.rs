//! `[guards.evaluator_calibration]`: only evaluators shown to agree with people may
//! score decisions or evaluate tool calls.
//!
//! Each record (written by `ctx calibrate`) names one evaluator release and the counts
//! of its verdicts against human labels. At startup every listed record is read and
//! checked against this deployment's floors, rates recomputed from the counts; a
//! record that falls short, or that cannot be read, stops the server, since listing it
//! asserts the evaluator is fit. A score or evaluation from an `evaluator_ref` with no
//! record is refused (`evaluator_uncalibrated`), so an unvalidated judge can neither
//! hold nor release a run. A new judge version needs a new record.

use std::collections::BTreeSet;
use std::path::PathBuf;

use axum::http::StatusCode;
use contextos_kernel::evaluator_calibration::{CalibrationFloors, CalibrationRecord, check_record};
use serde::{Deserialize, Serialize};

use crate::app::ApiError;

/// `[guards.evaluator_calibration]`.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvaluatorCalibration {
    /// Calibration record files (`ctx calibrate` output), one per evaluator release.
    pub records: Vec<PathBuf>,
    /// Smallest share of human `pass` labels the evaluator must also pass.
    pub min_tpr: f64,
    /// Smallest share of human `fail` labels the evaluator must also fail.
    pub min_tnr: f64,
    /// Fewest labels in each class a record must hold.
    pub min_per_class: u64,
}

impl EvaluatorCalibration {
    fn floors(&self) -> CalibrationFloors {
        CalibrationFloors {
            min_tpr: self.min_tpr,
            min_tnr: self.min_tnr,
            min_per_class: self.min_per_class,
        }
    }
}

/// The evaluator releases whose records meet the floors; `None` without the guard.
pub fn load(guard: Option<&EvaluatorCalibration>) -> Result<Option<BTreeSet<String>>, String> {
    let Some(guard) = guard else {
        return Ok(None);
    };
    if guard.records.is_empty() {
        return Err("[guards.evaluator_calibration] lists no records".into());
    }
    let mut fit = BTreeSet::new();
    for path in &guard.records {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let record: CalibrationRecord =
            serde_json::from_str(&text).map_err(|e| format!("{}: not a calibration record: {e}", path.display()))?;
        check_record(&record, &guard.floors()).map_err(|short| {
            format!(
                "{}: {} is not fit to evaluate: {}",
                path.display(),
                record.evaluator_ref,
                short.join("; ")
            )
        })?;
        if !fit.insert(record.evaluator_ref.clone()) {
            return Err(format!("{}: {} has two records", path.display(), record.evaluator_ref));
        }
    }
    Ok(Some(fit))
}

/// Refuses an evaluator release without a fit record, when the guard is on.
pub(crate) fn require(fit: Option<&BTreeSet<String>>, evaluator_ref: &str) -> Result<(), ApiError> {
    match fit {
        Some(fit) if !fit.contains(evaluator_ref) => Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "evaluator_uncalibrated",
            format!("{evaluator_ref} has no calibration record meeting this deployment's floors."),
        )),
        _ => Ok(()),
    }
}
