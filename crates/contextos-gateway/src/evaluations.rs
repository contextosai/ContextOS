//! Tool-call evaluations: an independent evaluator's verdict on one governed tool call.
//!
//! A decision score judges what a run decided; a tool-call evaluation judges one call
//! the run made: whether the agent picked the right tool, filled its arguments
//! correctly, or should have asked instead. The record carries the fields of the
//! OpenTelemetry `gen_ai.evaluation.result` event (`name`, `score`, `label`) and adds
//! what that convention leaves out: the authenticated evaluator and the pinned
//! evaluator release that produced the verdict. Explanations are cited by reference
//! (`explanation_ref`, for example the evaluation platform's link), never carried as
//! text: signed records are not rewritten on erasure, so they hold no free text.
//!
//! Independence is as for decision scores: whoever admitted the run cannot evaluate
//! its calls. Each evaluator gives one verdict per evaluation name per call; a call
//! takes at most [`MAX_EVALUATIONS_PER_OPERATION`] and a run indexes at most
//! [`MAX_EVALUATED_OPERATIONS`] evaluated calls. Every evaluation is signed into the
//! audit chain (`operation_evaluation`) before it is kept, and the evidence bundle
//! lists them under `operation_evaluations`.

use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore, StoreError, Versioned};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::admission::RunAdmission;
use crate::{Gateway, GatewayError};

/// Verdicts one tool call takes at most.
pub const MAX_EVALUATIONS_PER_OPERATION: usize = 32;
/// Evaluated tool calls one run indexes at most.
pub const MAX_EVALUATED_OPERATIONS: usize = 4096;
/// Attempts to land a write against concurrent evaluators.
const MAX_ATTEMPTS: usize = 8;

/// What an evaluator reports about one tool call.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationReport {
    /// The pinned evaluator release, e.g. `evaluator.tool_selection@2`.
    pub evaluator_ref: String,
    /// What was evaluated (`gen_ai.evaluation.name`), e.g. `tool_selection`.
    pub name: String,
    /// `gen_ai.evaluation.score.value`, in `[0, 1]`.
    #[serde(default)]
    pub score: Option<f64>,
    /// `gen_ai.evaluation.score.label`, a short category such as `pass` or `fail`.
    #[serde(default)]
    pub label: Option<String>,
    /// Where the evaluator keeps its explanation (a URL or an id), at most 512 bytes.
    #[serde(default)]
    pub explanation_ref: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum EvaluationRefusal {
    #[error(
        "an evaluation names its evaluator and what it evaluated (short identifiers), and has a score in [0, 1] or a label"
    )]
    Invalid,
    #[error("no such tool call in this run")]
    UnknownOperation,
    #[error("this evaluator already gave this evaluation of the call")]
    AlreadyEvaluated,
    #[error("the call or the run has the maximum number of evaluations")]
    TooManyEvaluations,
    #[error("the principal that admitted the run cannot evaluate its calls")]
    SelfEvaluation,
    #[error(transparent)]
    Gateway(#[from] GatewayError),
}

/// A short identifier: letters, digits and `._-@:/`, 1 to `max` bytes.
fn identifier(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-@:/".contains(&b))
}

impl EvaluationReport {
    fn valid(&self) -> bool {
        identifier(&self.evaluator_ref, 256)
            && identifier(&self.name, 64)
            && self.label.as_deref().is_none_or(|l| identifier(l, 64))
            && self.score.is_none_or(|s| s.is_finite() && (0.0..=1.0).contains(&s))
            && (self.score.is_some() || self.label.is_some())
            && self
                .explanation_ref
                .as_deref()
                .is_none_or(|r| !r.trim().is_empty() && r.len() <= 512 && !r.chars().any(char::is_control))
    }
}

fn evaluations_key(admission: &RunAdmission, operation_id: &str) -> DocKey {
    DocKey::new(
        &admission.tenant_id,
        DocKind::RunScore,
        format!("{}/operation:{operation_id}", admission.run_id),
    )
}

fn index_key(admission: &RunAdmission) -> DocKey {
    DocKey::new(
        &admission.tenant_id,
        DocKind::RunScore,
        format!("{}/operations", admission.run_id),
    )
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// Records `evaluator`'s evaluation of the run's tool call `operation_id`.
    #[tracing::instrument(name = "contextos.evaluate_operation", skip_all, fields(tenant_id = %admission.tenant_id, run_id = %admission.run_id, trace_id = %admission.trace_id))]
    pub async fn evaluate_operation(
        &self,
        admission: &RunAdmission,
        operation_id: &str,
        evaluator: &str,
        report: &EvaluationReport,
    ) -> Result<Value, EvaluationRefusal> {
        if !report.valid() || evaluator.is_empty() {
            return Err(EvaluationRefusal::Invalid);
        }
        if evaluator == admission.admitted_by {
            return Err(EvaluationRefusal::SelfEvaluation);
        }
        // Only calls the run's ledger holds.
        let ledger = self
            .store
            .get(&crate::operation_ledger_key(admission, operation_id))
            .await
            .map_err(GatewayError::from)?;
        let capability = ledger
            .as_ref()
            .and_then(|l| {
                l.body["operations"]
                    .as_array()?
                    .iter()
                    .find(|op| op["intent"]["operation_id"] == operation_id)
                    .map(|op| op["intent"]["capability_ref"].clone())
            })
            .ok_or(EvaluationRefusal::UnknownOperation)?;

        let now = self.now();
        let mut evaluation = json!({
            "evaluation_version": "contextos-rs.operation_evaluation.v1",
            "run_id": admission.run_id, "trace_id": admission.trace_id, "operation_id": operation_id,
            "capability_ref": capability, "evaluator": evaluator, "evaluator_ref": report.evaluator_ref,
            "name": report.name, "evaluated_at": now,
        });
        for (field, value) in [
            ("score", report.score.map(|s| json!(s))),
            ("label", report.label.as_ref().map(|l| json!(l))),
            ("explanation_ref", report.explanation_ref.as_ref().map(|r| json!(r))),
        ] {
            if let Some(value) = value {
                evaluation[field] = value;
            }
        }
        let key = evaluations_key(admission, operation_id);
        let check = |current: &Value| -> Result<(), EvaluationRefusal> {
            let kept = current["evaluations"].as_array().map_or(&[][..], Vec::as_slice);
            if kept
                .iter()
                .any(|e| e["evaluation"]["evaluator"] == evaluator && e["evaluation"]["name"] == report.name.as_str())
            {
                return Err(EvaluationRefusal::AlreadyEvaluated);
            }
            if kept.len() >= MAX_EVALUATIONS_PER_OPERATION {
                return Err(EvaluationRefusal::TooManyEvaluations);
            }
            Ok(())
        };
        let current = self.store.get(&key).await.map_err(GatewayError::from)?;
        check(current.as_ref().map_or(&Value::Null, |c| &c.body))?;
        if current.is_none() {
            self.index_operation(admission, operation_id).await?;
        }
        // Signed before it is kept: the evidence never holds an unaudited verdict.
        let entry = self
            .audit
            .append(&admission.tenant_id, "operation_evaluation", evaluation.clone(), &now)
            .await
            .map_err(GatewayError::from)?;
        // The OpenTelemetry evaluation event, with the evaluator the convention lacks.
        tracing::info!(
            gen_ai.evaluation.name = %report.name,
            gen_ai.evaluation.score.value = report.score,
            gen_ai.evaluation.score.label = report.label.as_deref(),
            contextos.operation_id = %operation_id,
            contextos.evaluator_ref = %report.evaluator_ref,
            "gen_ai.evaluation.result"
        );
        let kept = self
            .keep_evaluation(&key, current, &evaluation, entry.sequence, &check)
            .await;
        if let Err(refusal) = &kept {
            let _ = self
                .audit
                .append(
                    &admission.tenant_id,
                    "operation_evaluation_not_applied",
                    json!({"run_id": admission.run_id, "operation_id": operation_id, "evaluator": evaluator,
                        "name": report.name, "reason": refusal.to_string()}),
                    &now,
                )
                .await;
        }
        kept
    }

    /// Adds the operation to the run's index of evaluated calls (idempotent).
    async fn index_operation(&self, admission: &RunAdmission, operation_id: &str) -> Result<(), EvaluationRefusal> {
        let key = index_key(admission);
        for _ in 0..MAX_ATTEMPTS {
            let current = self.store.get(&key).await.map_err(GatewayError::from)?;
            let mut ids = current
                .as_ref()
                .and_then(|c| c.body["operation_ids"].as_array().cloned())
                .unwrap_or_default();
            if ids.iter().any(|id| id == operation_id) {
                return Ok(());
            }
            if ids.len() >= MAX_EVALUATED_OPERATIONS {
                return Err(EvaluationRefusal::TooManyEvaluations);
            }
            ids.push(json!(operation_id));
            let state = json!({"operation_ids": ids});
            let written = match &current {
                None => self.store.create(&key, &state).await.map(|_| ()),
                Some(c) => self.store.compare_and_swap(&key, c.revision, &state).await.map(|_| ()),
            };
            match written {
                Ok(()) => return Ok(()),
                Err(e) if e.is_conflict() => {}
                Err(e) => return Err(GatewayError::from(e).into()),
            }
        }
        Err(conflict())
    }

    async fn keep_evaluation(
        &self,
        key: &DocKey,
        mut current: Option<Versioned>,
        evaluation: &Value,
        sequence: u64,
        check: &(dyn Fn(&Value) -> Result<(), EvaluationRefusal> + Sync),
    ) -> Result<Value, EvaluationRefusal> {
        let kept = json!({"evaluation": evaluation, "audit_sequence": sequence});
        for _ in 0..MAX_ATTEMPTS {
            let mut list = current
                .as_ref()
                .and_then(|c| c.body["evaluations"].as_array().cloned())
                .unwrap_or_default();
            check(&json!({"evaluations": list}))?;
            list.push(kept.clone());
            let state = json!({"evaluations": list});
            let written = match &current {
                None => self.store.create(key, &state).await.map(|_| ()),
                Some(c) => self.store.compare_and_swap(key, c.revision, &state).await.map(|_| ()),
            };
            match written {
                Ok(()) => return Ok(kept),
                Err(e) if e.is_conflict() => {
                    current = self.store.get(key).await.map_err(GatewayError::from)?;
                }
                Err(e) => return Err(GatewayError::from(e).into()),
            }
        }
        Err(conflict())
    }

    /// The run's evaluated tool calls, each with its evaluations oldest first.
    pub(crate) async fn operation_evaluations(&self, admission: &RunAdmission) -> Result<Vec<Value>, GatewayError> {
        let ids = self
            .store
            .get(&index_key(admission))
            .await?
            .and_then(|i| i.body["operation_ids"].as_array().cloned())
            .unwrap_or_default();
        let mut out = Vec::new();
        for id in ids.iter().filter_map(Value::as_str) {
            let evaluations = self
                .store
                .get(&evaluations_key(admission, id))
                .await?
                .and_then(|d| d.body["evaluations"].as_array().cloned())
                .unwrap_or_default();
            out.push(json!({"operation_id": id, "evaluations": evaluations}));
        }
        Ok(out)
    }
}

fn conflict() -> EvaluationRefusal {
    EvaluationRefusal::Gateway(GatewayError::from(StoreError::Conflict {
        expected: None,
        actual: None,
    }))
}
