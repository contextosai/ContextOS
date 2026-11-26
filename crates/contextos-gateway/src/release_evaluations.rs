//! Evaluation-gated releases: an agent release runs only after the evaluation suites
//! the deployment requires have passed on it.
//!
//! An independent evaluator (the `evaluate` scope, which never admits or dispatches)
//! records each suite's result against one agent release, named by the run contract's
//! `agent_release` release ref (`artifact_id`, `version`, `sha256`):
//! `release_evaluation_recorded`, signed into the audit chain. With
//! `[guards.release_evaluations]`, admission of a run whose agent a rule covers needs
//! its `agent_release` ref, and the latest recorded result of each required suite on
//! exactly that release (same digest) to be `passed`; otherwise the run is refused
//! (`release_unevaluated`, or `agent_release_missing`) and the refusal audited
//! (`release_evaluation_refusal`). A failed result recorded later than a pass stops the
//! release again.

use contextos_contract::canonical::sha256_canonical;
use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{Gateway, GatewayError};

/// Results kept per release at most (the newest).
pub const MAX_RESULTS: usize = 256;
/// Rules at most.
pub const MAX_RULES: usize = 64;

/// One `[[guards.release_evaluations.rules]]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvaluationRule {
    /// Agent ids the rule covers, or `"*"` for every agent.
    pub agents: Vec<String>,
    /// Suite ids that must have passed on the release.
    pub suites: Vec<String>,
}

/// `[guards.release_evaluations]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReleaseEvaluationPolicy {
    pub rules: Vec<EvaluationRule>,
}

impl ReleaseEvaluationPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if self.rules.is_empty() || self.rules.len() > MAX_RULES {
            return Err(format!("[guards.release_evaluations] has 1 to {MAX_RULES} rules"));
        }
        if self.rules.iter().any(|r| r.agents.is_empty() || r.suites.is_empty()) {
            return Err("each release-evaluation rule names agents and suites".into());
        }
        Ok(())
    }

    /// The suites `agent_id`'s releases must have passed.
    #[must_use]
    pub fn suites_for(&self, agent_id: &str) -> Vec<String> {
        let mut out: Vec<String> = self
            .rules
            .iter()
            .filter(|r| r.agents.iter().any(|a| a == "*" || a == agent_id))
            .flat_map(|r| r.suites.iter().cloned())
            .collect();
        out.sort();
        out.dedup();
        out
    }
}

/// A result to record.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationResult {
    /// The agent release: `{artifact_type: "agent_release", artifact_id, version, sha256}`.
    pub release: Value,
    pub suite_id: String,
    pub suite_version: String,
    /// `passed` or `failed`.
    pub outcome: String,
    pub cases_passed: u64,
    pub cases_total: u64,
    /// Where the full report is kept (a URI or an artifact id).
    pub report_ref: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ReleaseEvaluationError {
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Gateway(#[from] GatewayError),
}

fn release_key(tenant: &str, release: &Value) -> Option<DocKey> {
    let digest = sha256_canonical(
        &json!({"artifact_id": release["artifact_id"], "version": release["version"],
        "sha256": release["sha256"]}),
    )
    .ok()?;
    Some(DocKey::new(tenant, DocKind::ReleaseEvaluations, &digest))
}

fn valid_release(r: &Value) -> bool {
    r["artifact_type"] == "agent_release" && contextos_contract::shape::is_artifact_ref(r)
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// Requires passed evaluations of agent releases under `policy`.
    pub fn set_release_evaluations(&mut self, policy: Option<ReleaseEvaluationPolicy>) {
        self.release_evaluations = policy;
    }

    /// Records one suite's result on one release (audited `release_evaluation_recorded`).
    pub async fn record_release_evaluation(
        &self,
        tenant: &str,
        result: &EvaluationResult,
        evaluator: &str,
    ) -> Result<Value, ReleaseEvaluationError> {
        let sized = |s: &str, max: usize| !s.trim().is_empty() && s.len() <= max;
        if !valid_release(&result.release) {
            return Err(ReleaseEvaluationError::Invalid(
                "release is an agent_release artifact ref (artifact_id, version, sha256)".into(),
            ));
        }
        if !sized(&result.suite_id, 256) || !sized(&result.suite_version, 64) || !sized(&result.report_ref, 2048) {
            return Err(ReleaseEvaluationError::Invalid(
                "suite_id, suite_version and report_ref are required".into(),
            ));
        }
        if !matches!(result.outcome.as_str(), "passed" | "failed") || result.cases_passed > result.cases_total {
            return Err(ReleaseEvaluationError::Invalid(
                "outcome is passed or failed, and cases_passed is at most cases_total".into(),
            ));
        }
        if result.outcome == "passed" && result.cases_passed != result.cases_total {
            return Err(ReleaseEvaluationError::Invalid(
                "a passed suite passed every case".into(),
            ));
        }
        let now = self.now();
        let record = json!({"release": result.release, "suite_id": result.suite_id, "suite_version": result.suite_version,
            "outcome": result.outcome, "cases_passed": result.cases_passed, "cases_total": result.cases_total,
            "report_ref": result.report_ref, "evaluator": evaluator, "recorded_at": now});
        let entry = self
            .audit
            .append(tenant, "release_evaluation_recorded", record.clone(), &now)
            .await
            .map_err(GatewayError::from)?;
        let key =
            release_key(tenant, &result.release).ok_or_else(|| ReleaseEvaluationError::Invalid("release".into()))?;
        for _ in 0..32 {
            let current = self.store.get(&key).await.map_err(GatewayError::from)?;
            let mut results = current
                .as_ref()
                .and_then(|c| c.body["results"].as_array().cloned())
                .unwrap_or_default();
            let mut stored = record.clone();
            stored["audit_sequence"] = json!(entry.sequence);
            results.push(stored);
            if results.len() > MAX_RESULTS {
                results.remove(0);
            }
            let body = json!({"results": results});
            let written = match &current {
                None => self.store.create(&key, &body).await.map(|_| ()),
                Some(c) => self.store.compare_and_swap(&key, c.revision, &body).await.map(|_| ()),
            };
            match written {
                Ok(()) => return Ok(record),
                Err(e) if e.is_conflict() => {}
                Err(e) => return Err(GatewayError::from(e).into()),
            }
        }
        Err(ReleaseEvaluationError::Gateway(GatewayError::from(
            contextos_store::StoreError::Conflict {
                expected: None,
                actual: None,
            },
        )))
    }

    /// The results recorded on `release`, oldest first.
    pub async fn release_evaluations(&self, tenant: &str, release: &Value) -> Result<Vec<Value>, GatewayError> {
        let Some(key) = release_key(tenant, release) else {
            return Ok(Vec::new());
        };
        Ok(self
            .store
            .get(&key)
            .await?
            .and_then(|d| d.body["results"].as_array().cloned())
            .unwrap_or_default())
    }

    /// Why a new run of `agent_id` with these release refs may not be admitted, if it
    /// may not: `(reason, missing suites)`. Audited as `release_evaluation_refusal`.
    pub async fn release_evaluation_refusal(
        &self,
        tenant: &str,
        agent_id: &str,
        release_refs: &[Value],
    ) -> Result<Option<(String, Vec<String>)>, GatewayError> {
        let Some(policy) = &self.release_evaluations else {
            return Ok(None);
        };
        let required = policy.suites_for(agent_id);
        if required.is_empty() {
            return Ok(None);
        }
        let release = release_refs.iter().find(|r| r["artifact_type"] == "agent_release");
        let refusal = match release {
            None => Some(("agent_release_missing".to_owned(), required.clone())),
            Some(release) => {
                let results = self.release_evaluations(tenant, release).await?;
                let missing: Vec<String> = required
                    .iter()
                    .filter(|suite| {
                        results
                            .iter()
                            .rev()
                            .find(|r| r["suite_id"] == suite.as_str())
                            .is_none_or(|latest| latest["outcome"] != "passed")
                    })
                    .cloned()
                    .collect();
                (!missing.is_empty()).then(|| ("release_unevaluated".to_owned(), missing))
            }
        };
        if let Some((reason, missing)) = &refusal {
            let body =
                json!({"agent_id": agent_id, "release": release, "reason_codes": [reason], "missing_suites": missing});
            self.audit
                .append(tenant, "release_evaluation_refusal", body, &self.now())
                .await?;
        }
        Ok(refusal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_combine_by_agent() {
        let p = ReleaseEvaluationPolicy {
            rules: vec![
                EvaluationRule {
                    agents: vec!["*".into()],
                    suites: vec!["safety".into()],
                },
                EvaluationRule {
                    agents: vec!["agt_support".into()],
                    suites: vec!["refund_regression".into(), "safety".into()],
                },
            ],
        };
        p.validate().unwrap();
        assert_eq!(p.suites_for("agt_support"), ["refund_regression", "safety"]);
        assert_eq!(p.suites_for("agt_other"), ["safety"]);
        assert!(ReleaseEvaluationPolicy { rules: vec![] }.validate().is_err());
    }
}
