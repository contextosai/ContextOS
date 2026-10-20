//! Run scores (the spec's `RunScore`, recorded as a DecisionRecord-shaped scorecard).
//!
//! The system under evaluation cannot score itself. An evaluator, a principal separate
//! from the run's executor, reports the judged dimensions (policy, utility, safety,
//! each in `[0, 1]`) for one recorded decision and names the pinned evaluator that
//! produced them. The gateway adds what it measured itself: the cost from the signed
//! decision's budget usage, and the latency in milliseconds from the run's admission
//! to the decision. Latency is left out for runs admitted before admission times were
//! kept: missing usage is unknown, never zero.
//!
//! Every score is signed into the audit chain bound to the run, trace and record, and
//! kept beside the decision for the evidence bundle. An evaluator scores a decision
//! once; a decision takes at most [`MAX_SCORES_PER_DECISION`] evaluators.

use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore, StoreError};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::admission::RunAdmission;
use crate::{Gateway, GatewayError};

/// Evaluators that may score one decision.
pub const MAX_SCORES_PER_DECISION: usize = 16;

/// What an evaluator reports.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScoreReport {
    /// The pinned evaluator (suite, rubric or judge) and its version, e.g.
    /// `evaluator.refund_quality@3`.
    pub evaluator_ref: String,
    pub policy: f64,
    pub utility: f64,
    pub safety: f64,
}

#[derive(Debug, thiserror::Error)]
pub enum ScoreRefusal {
    #[error("scores must be numbers in [0, 1] and the evaluator must be named")]
    Invalid,
    #[error("no such decision in this run")]
    UnknownDecision,
    #[error("this evaluator already scored the decision")]
    AlreadyScored,
    #[error("the decision has the maximum number of scores")]
    TooManyScores,
    #[error("the principal that admitted the run or recorded the decision cannot score it")]
    SelfScoring,
    #[error(transparent)]
    Gateway(#[from] GatewayError),
}

fn scores_key(admission: &RunAdmission, record_id: &str) -> DocKey {
    DocKey::new(
        &admission.tenant_id,
        DocKind::RunScore,
        format!("{}/{record_id}", admission.run_id),
    )
}

/// Attempts to land a score against concurrent evaluators of the same decision.
const MAX_ATTEMPTS: usize = 8;

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// Records `evaluator`'s score of decision `record_id` of the run.
    #[tracing::instrument(name = "contextos.score", skip_all, fields(tenant_id = %admission.tenant_id, run_id = %admission.run_id, trace_id = %admission.trace_id))]
    pub async fn score_decision(
        &self,
        admission: &RunAdmission,
        record_id: &str,
        evaluator: &str,
        report: &ScoreReport,
    ) -> Result<Value, ScoreRefusal> {
        let unit = |v: f64| v.is_finite() && (0.0..=1.0).contains(&v);
        let named = !report.evaluator_ref.trim().is_empty() && report.evaluator_ref.len() <= 256;
        if !(named && unit(report.policy) && unit(report.utility) && unit(report.safety)) || evaluator.is_empty() {
            return Err(ScoreRefusal::Invalid);
        }

        // Only the run's own decisions, by the ids the gateway issued.
        let issued = self
            .store
            .get(&crate::decisions::decisions_key(admission))
            .await
            .map_err(GatewayError::from)?
            .is_some_and(|d| {
                d.body["record_ids"]
                    .as_array()
                    .is_some_and(|ids| ids.iter().any(|id| id == record_id))
            });
        if !issued {
            return Err(ScoreRefusal::UnknownDecision);
        }
        let decision_key = DocKey::new(
            &admission.tenant_id,
            DocKind::DecisionLog,
            format!("{}/{record_id}", admission.run_id),
        );
        let decision = self
            .store
            .get(&decision_key)
            .await
            .map_err(GatewayError::from)?
            .ok_or(ScoreRefusal::UnknownDecision)?;
        // Independence is judged on authenticated principals: whoever admitted the run
        // or recorded the decision cannot score it, whatever token it presents. (The
        // agent id is named by the admitter, so it is neither trusted nor used.)
        if evaluator == admission.admitted_by || decision.body["recorded_by"] == evaluator {
            return Err(ScoreRefusal::SelfScoring);
        }
        let record = &decision.body["record"];
        let mut scorecard = json!({"policy": report.policy, "utility": report.utility, "safety": report.safety});
        if let Some(cost) = record["budget_usage"]["cost_usd_cents"].as_f64() {
            scorecard["cost"] = json!(cost);
        }
        // Latency (ms) from admission to the decision, when the admission time is known.
        let decided_at = record["timestamp"].as_str().unwrap_or_default();
        if let Some(latency) = contextos_contract::validation::elapsed_millis(&admission.admitted_at, decided_at) {
            scorecard["latency"] = json!(latency);
        }
        let now = self.now();
        let score = json!({
            "score_version": "contextos-rs.run_score.v1",
            "run_id": admission.run_id, "trace_id": admission.trace_id, "record_id": record_id,
            "decision_key": record["decision_key"], "evaluator": evaluator,
            "evaluator_ref": report.evaluator_ref, "scorecard": scorecard, "scored_at": now,
        });
        let key = scores_key(admission, record_id);
        let check = |current: &Value| -> Result<(), ScoreRefusal> {
            let scores = current["scores"].as_array().map_or(&[][..], Vec::as_slice);
            if scores.iter().any(|s| s["score"]["evaluator"] == evaluator) {
                return Err(ScoreRefusal::AlreadyScored);
            }
            if scores.len() >= MAX_SCORES_PER_DECISION {
                return Err(ScoreRefusal::TooManyScores);
            }
            Ok(())
        };
        let current = self.store.get(&key).await.map_err(GatewayError::from)?;
        check(current.as_ref().map_or(&Value::Null, |c| &c.body))?;
        // Signed before it is kept: the evidence never holds an unaudited score.
        let entry = self
            .audit
            .append(&admission.tenant_id, "run_score", score.clone(), &now)
            .await
            .map_err(GatewayError::from)?;
        let kept = self.keep_score(&key, current, &score, entry.sequence, &check).await;
        if let Err(refusal) = &kept {
            // Every exit after signing says the score was not kept; if even that
            // append fails, the caller sees the original error and the gap is the
            // audit writer's to report.
            let _ = self
                .score_not_applied(admission, record_id, evaluator, refusal, &now)
                .await;
        }
        kept
    }

    /// Adds the signed score to the decision's scores against concurrent evaluators.
    async fn keep_score(
        &self,
        key: &DocKey,
        mut current: Option<contextos_store::Versioned>,
        score: &Value,
        sequence: u64,
        check: &(dyn Fn(&Value) -> Result<(), ScoreRefusal> + Sync),
    ) -> Result<Value, ScoreRefusal> {
        let kept = json!({"score": score, "audit_sequence": sequence});
        for _ in 0..MAX_ATTEMPTS {
            let mut scores = current
                .as_ref()
                .and_then(|c| c.body["scores"].as_array().cloned())
                .unwrap_or_default();
            check(&json!({"scores": scores}))?;
            scores.push(kept.clone());
            let state = json!({"scores": scores});
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
        Err(ScoreRefusal::Gateway(GatewayError::from(StoreError::Conflict {
            expected: None,
            actual: None,
        })))
    }

    async fn score_not_applied(
        &self,
        admission: &RunAdmission,
        record_id: &str,
        evaluator: &str,
        refusal: &ScoreRefusal,
        now: &str,
    ) -> Result<(), GatewayError> {
        self.audit
            .append(
                &admission.tenant_id,
                "run_score_not_applied",
                json!({"run_id": admission.run_id, "record_id": record_id, "evaluator": evaluator,
                    "reason": refusal.to_string()}),
                now,
            )
            .await?;
        Ok(())
    }

    /// The scores of one decision, oldest first.
    pub(crate) async fn decision_scores(
        &self,
        admission: &RunAdmission,
        record_id: &str,
    ) -> Result<Vec<Value>, GatewayError> {
        Ok(self
            .store
            .get(&scores_key(admission, record_id))
            .await?
            .and_then(|r| r.body["scores"].as_array().cloned())
            .unwrap_or_default())
    }
}
