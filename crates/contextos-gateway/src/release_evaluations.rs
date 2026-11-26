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
//!
//! A rule can set a floor on what counts: `min_cases` (a pass over fewer cases does
//! not satisfy it) and `suite_versions` (only results of that suite version count, so
//! an older or easier suite cannot stand in for the one reviewed).
//!
//! **Trust.** A recorded result is the evaluator's statement, signed into the chain;
//! the runtime does not rerun suites. The `agent_release` ref is asserted by whoever
//! admits the run; the runtime checks the evaluations of the release named, not that
//! the code running is that release. Have the deployment pipeline that ships the
//! artifact set the ref, and keep admission credentials with that pipeline.

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
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvaluationRule {
    /// Agent ids the rule covers, or `"*"` for every agent.
    pub agents: Vec<String>,
    /// Suite ids that must have passed on the release.
    pub suites: Vec<String>,
    /// A pass counts only with at least this many cases. 0: any.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub min_cases: u64,
    /// Suite versions that count, by suite id; a suite not listed counts at any version.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub suite_versions: std::collections::BTreeMap<String, String>,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// What a suite's result must meet to count, from every rule covering an agent.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SuiteRequirement {
    pub suite_id: String,
    pub min_cases: u64,
    pub version: Option<String>,
}

impl SuiteRequirement {
    /// Whether the latest result that counts for this requirement passed.
    fn met_by(&self, results: &[Value]) -> bool {
        results
            .iter()
            .rev()
            .filter(|r| r["suite_id"] == self.suite_id.as_str())
            .find(|r| self.version.as_deref().is_none_or(|v| r["suite_version"] == v))
            .is_some_and(|latest| {
                latest["outcome"] == "passed" && latest["cases_total"].as_u64().unwrap_or(0) >= self.min_cases
            })
    }
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
        let mut pins = std::collections::BTreeMap::new();
        for rule in &self.rules {
            if let Some(suite) = rule.suite_versions.keys().find(|s| !rule.suites.contains(s)) {
                return Err(format!("suite_versions names {suite}, which the rule does not require"));
            }
            for (suite, version) in &rule.suite_versions {
                if version.trim().is_empty() || version.len() > 64 {
                    return Err(format!("suite_versions.{suite}: a version of 1 to 64 bytes"));
                }
                if pins
                    .insert(suite.as_str(), version.as_str())
                    .is_some_and(|other| other != version)
                {
                    return Err(format!("suite {suite} is pinned to two versions"));
                }
            }
        }
        Ok(())
    }

    /// The suites `agent_id`'s releases must have passed.
    #[must_use]
    pub fn suites_for(&self, agent_id: &str) -> Vec<String> {
        self.requirements_for(agent_id)
            .into_iter()
            .map(|r| r.suite_id)
            .collect()
    }

    /// What each suite's result must meet for `agent_id`: the highest `min_cases` and
    /// the pinned version of every rule covering it.
    #[must_use]
    pub fn requirements_for(&self, agent_id: &str) -> Vec<SuiteRequirement> {
        let mut out: std::collections::BTreeMap<&str, SuiteRequirement> = std::collections::BTreeMap::new();
        for rule in self
            .rules
            .iter()
            .filter(|r| r.agents.iter().any(|a| a == "*" || a == agent_id))
        {
            for suite in &rule.suites {
                let req = out.entry(suite.as_str()).or_insert_with(|| SuiteRequirement {
                    suite_id: suite.clone(),
                    ..SuiteRequirement::default()
                });
                req.min_cases = req.min_cases.max(rule.min_cases);
                if let Some(v) = rule.suite_versions.get(suite) {
                    req.version = Some(v.clone());
                }
            }
        }
        out.into_values().collect()
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
        let required = policy.requirements_for(agent_id);
        if required.is_empty() {
            return Ok(None);
        }
        let release = release_refs.iter().find(|r| r["artifact_type"] == "agent_release");
        let refusal = match release {
            None => Some((
                "agent_release_missing".to_owned(),
                required.iter().map(|r| r.suite_id.clone()).collect(),
            )),
            Some(release) => {
                let results = self.release_evaluations(tenant, release).await?;
                let missing: Vec<String> = required
                    .iter()
                    .filter(|req| !req.met_by(&results))
                    .map(|req| req.suite_id.clone())
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
                    ..EvaluationRule::default()
                },
                EvaluationRule {
                    agents: vec!["agt_support".into()],
                    suites: vec!["refund_regression".into(), "safety".into()],
                    ..EvaluationRule::default()
                },
            ],
        };
        p.validate().unwrap();
        assert_eq!(p.suites_for("agt_support"), ["refund_regression", "safety"]);
        assert_eq!(p.suites_for("agt_other"), ["safety"]);
        assert!(ReleaseEvaluationPolicy { rules: vec![] }.validate().is_err());
    }

    fn policy(v: Value) -> ReleaseEvaluationPolicy {
        serde_json::from_value(v).unwrap()
    }

    fn result(version: &str, outcome: &str, total: u64) -> Value {
        json!({"suite_id": "safety", "suite_version": version, "outcome": outcome, "cases_total": total})
    }

    #[test]
    fn a_pass_counts_only_at_the_pinned_version_and_case_floor() {
        let p = policy(json!({"rules": [
            {"agents": ["*"], "suites": ["safety"], "min_cases": 20},
            {"agents": ["agt_support"], "suites": ["safety"], "min_cases": 50, "suite_versions": {"safety": "3"}}]}));
        p.validate().unwrap();
        let support = &p.requirements_for("agt_support")[0];
        assert_eq!((support.min_cases, support.version.as_deref()), (50, Some("3")));
        let other = &p.requirements_for("agt_other")[0];
        assert_eq!((other.min_cases, other.version.as_deref()), (20, None));

        // A one-case pass satisfies nothing with a floor.
        assert!(!other.met_by(&[result("3", "passed", 1)]));
        assert!(other.met_by(&[result("3", "passed", 20)]));
        // Only the pinned version counts: a later pass of another version does not
        // stand in, and a later failure of the pinned version stops it again.
        assert!(!support.met_by(&[result("2", "passed", 80)]));
        assert!(support.met_by(&[result("3", "passed", 80), result("2", "failed", 80)]));
        assert!(!support.met_by(&[result("3", "passed", 80), result("3", "failed", 80)]));
    }

    #[test]
    fn suite_pins_are_validated() {
        let two = policy(json!({"rules": [
            {"agents": ["a"], "suites": ["safety"], "suite_versions": {"safety": "3"}},
            {"agents": ["b"], "suites": ["safety"], "suite_versions": {"safety": "4"}}]}));
        assert!(two.validate().unwrap_err().contains("two versions"));
        let unlisted = policy(json!({"rules": [
            {"agents": ["a"], "suites": ["safety"], "suite_versions": {"other": "1"}}]}));
        assert!(unlisted.validate().is_err());
    }
}
