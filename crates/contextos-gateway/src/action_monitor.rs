//! Action monitor: a trusted monitor scores each consequential call before it is sent.
//!
//! The AI-control literature (trusted monitoring, defer-to-human protocols) gates an
//! agent's actions on a suspicion score from a separate, trusted monitor that sees the
//! proposed action and the trajectory so far. ContextOS ships the port and the
//! response, not a monitor model. For every effectful call, and every call that sends
//! data out, the provider receives the action binding (capability, arguments,
//! resources, recipients, amount) and the run's recent calls with their scores. It
//! answers:
//!
//! ```json
//! {"suspicion": 0.0..=1.0, "reason_codes": ["..."]}
//! ```
//!
//! The response is a guardrail outcome composed with the run's others:
//!
//! - `suspicion >= deny_at`: denied (`action_monitor_deny`);
//! - `suspicion >= ask_at`: needs an approval of the exact action (`action_monitor_ask`);
//! - with `run_budget`, once the run's summed suspicion reaches it, every further
//!   monitored call needs an approval (`action_monitor_run_budget`). A run can reach
//!   that through many mildly suspicious calls that no single threshold catches;
//! - an unreachable monitor, or a malformed answer, gets `on_unavailable` (`ask` by
//!   default; `deny` to fail hard; `allow` only to fail open deliberately).
//!
//! The monitor is called alongside the other authorization reads. Each score is added
//! to the run's trajectory (the last calls, bounded) whatever the final decision.
//! Calls that are not allowed outright are audited (`action_monitored`) with the score
//! and reason codes, never the arguments.

use std::sync::Arc;

use contextos_contract::types::ActionEffect;
use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore, StoreError, Versioned};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::admission::RunAdmission;
use crate::guard_policy::{FlowGate, gate};
use crate::information_flow::FlowVerdict;
use crate::manifest::CapabilityManifest;
use crate::{Gateway, GatewayError, Pipeline, PortError};

/// Calls kept in a run's trajectory.
const TRAJECTORY: usize = 16;
const MAX_REASONS: usize = 16;

/// Scores one proposed action.
#[async_trait::async_trait]
pub trait ActionMonitorProvider: Send + Sync {
    async fn assess(
        &self,
        admission: &RunAdmission,
        manifest: &CapabilityManifest,
        binding: &Value,
        trajectory: &Value,
    ) -> Result<Value, PortError>;
}

fn half() -> f64 {
    0.5
}

fn nine_tenths() -> f64 {
    0.9
}

fn ask() -> FlowVerdict {
    FlowVerdict::Ask
}

/// `[guards.action_monitor]`.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MonitorPolicy {
    /// Suspicion at which a call needs an approval.
    #[serde(default = "half")]
    pub ask_at: f64,
    /// Suspicion at which a call is denied.
    #[serde(default = "nine_tenths")]
    pub deny_at: f64,
    /// Summed suspicion of a run's calls past which every further call needs an
    /// approval. Unset: no run budget.
    #[serde(default)]
    pub run_budget: Option<f64>,
    /// What an unreachable monitor or malformed answer means.
    #[serde(default = "ask")]
    pub on_unavailable: FlowVerdict,
}

impl Default for MonitorPolicy {
    fn default() -> Self {
        Self {
            ask_at: half(),
            deny_at: nine_tenths(),
            run_budget: None,
            on_unavailable: FlowVerdict::Ask,
        }
    }
}

impl MonitorPolicy {
    pub fn validate(&self) -> Result<(), String> {
        let unit = |x: f64| (0.0..=1.0).contains(&x);
        if !unit(self.ask_at) || !unit(self.deny_at) || self.ask_at > self.deny_at {
            return Err("action_monitor: need 0 <= ask_at <= deny_at <= 1".into());
        }
        if self.run_budget.is_some_and(|b| !b.is_finite() || b <= 0.0) {
            return Err("action_monitor: run_budget must be positive".into());
        }
        Ok(())
    }

    /// The verdict and reason codes for `answer` given the run's summed suspicion
    /// before this call; `None` for the suspicion when the answer is unusable.
    pub fn judge(&self, answer: Option<&Value>, total: f64) -> (FlowVerdict, Vec<String>, Option<f64>) {
        let parsed = answer.and_then(|a| {
            let suspicion = a["suspicion"].as_f64().filter(|s| (0.0..=1.0).contains(s))?;
            let reasons = match &a["reason_codes"] {
                Value::Null => Vec::new(),
                Value::Array(items) if items.len() <= MAX_REASONS => items
                    .iter()
                    .map(|r| r.as_str().filter(|s| reason_code(s)).map(str::to_owned))
                    .collect::<Option<_>>()?,
                _ => return None,
            };
            Some((suspicion, reasons))
        });
        let Some((suspicion, mut reasons)) = parsed else {
            return (self.on_unavailable, vec!["action_monitor_unavailable".into()], None);
        };
        let mut verdict = FlowVerdict::Allow;
        if suspicion >= self.deny_at {
            verdict = FlowVerdict::Deny;
            reasons.insert(0, "action_monitor_deny".into());
        } else if suspicion >= self.ask_at {
            verdict = FlowVerdict::Ask;
            reasons.insert(0, "action_monitor_ask".into());
        }
        if verdict == FlowVerdict::Allow && self.run_budget.is_some_and(|b| total + suspicion >= b) {
            verdict = FlowVerdict::Ask;
            reasons.insert(0, "action_monitor_run_budget".into());
        }
        (verdict, reasons, Some(suspicion))
    }
}

fn reason_code(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'.')
}

/// Whether `manifest`'s calls are monitored: effects, and anything that sends data out.
pub fn monitored(manifest: &CapabilityManifest) -> bool {
    manifest.action_risk.effect != ActionEffect::None
        || manifest.sends_data
        || !manifest.destination_pointers.is_empty()
}

fn key(admission: &RunAdmission) -> DocKey {
    DocKey::new(&admission.tenant_id, DocKind::ActionMonitor, &admission.run_id)
}

/// The monitor's answer for one call, with the run's trajectory as read.
pub(crate) struct Assessment {
    state: Option<Versioned>,
    answer: Option<Value>,
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// Asks the monitor about this call, when one is configured and the call is
    /// monitored. Run alongside the other authorization reads.
    pub(crate) async fn assess_action(
        &self,
        admission: &RunAdmission,
        manifest: &CapabilityManifest,
        binding: &Value,
    ) -> Result<Option<Assessment>, StoreError> {
        let Some((provider, _)) = &self.action_monitor else {
            return Ok(None);
        };
        if !monitored(manifest) {
            return Ok(None);
        }
        let state = self.store.get(&key(admission)).await?;
        let trajectory = state
            .as_ref()
            .map_or_else(|| json!({"total": 0.0, "calls": []}), |s| s.body.clone());
        let answer = provider.assess(admission, manifest, binding, &trajectory).await.ok();
        Ok(Some(Assessment { state, answer }))
    }

    /// The monitor's part in this call's decision; records the score in the run's
    /// trajectory (not for checks) and audits calls not allowed outright.
    pub(crate) async fn monitor_guard(
        &self,
        p: &mut Pipeline<'_>,
        admission: &RunAdmission,
        manifest: &CapabilityManifest,
        operation_id: &str,
        assessment: Option<Assessment>,
        now: &str,
    ) -> Result<FlowGate, GatewayError> {
        let (Some((_, policy)), Some(assessment)) = (&self.action_monitor, assessment) else {
            return Ok(FlowGate::Pass);
        };
        let total = assessment
            .state
            .as_ref()
            .and_then(|s| s.body["total"].as_f64())
            .unwrap_or(0.0);
        let (verdict, reasons, suspicion) = policy.judge(assessment.answer.as_ref(), total);
        if let Some(suspicion) = suspicion
            && !p.check
        {
            let entry = json!({"capability_id": manifest.capability_id, "operation_id": operation_id,
                "suspicion": suspicion, "verdict": verdict, "at": now});
            self.record_trajectory(admission, assessment.state, entry, suspicion)
                .await?;
        }
        if verdict != FlowVerdict::Allow || suspicion.is_none() {
            let body = json!({"run_id": admission.run_id, "operation_id": operation_id,
                "capability_id": manifest.capability_id, "suspicion": suspicion, "run_total": total,
                "verdict": verdict, "reason_codes": reasons});
            self.record(p, "action_monitored", body, now).await?;
        }
        Ok(gate(
            admission,
            verdict,
            "action_monitor",
            "review_monitored_action",
            reasons,
            "monitor_policy_unpinned",
        ))
    }

    async fn record_trajectory(
        &self,
        admission: &RunAdmission,
        mut seen: Option<Versioned>,
        entry: Value,
        suspicion: f64,
    ) -> Result<(), StoreError> {
        let key = key(admission);
        for attempt in 0..32_u32 {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_micros(50 << attempt.min(8))).await;
                seen = self.store.get(&key).await?;
            }
            let mut calls = seen
                .as_ref()
                .and_then(|s| s.body["calls"].as_array().cloned())
                .unwrap_or_default();
            calls.push(entry.clone());
            if calls.len() > TRAJECTORY {
                calls.drain(..calls.len() - TRAJECTORY);
            }
            let total = seen.as_ref().and_then(|s| s.body["total"].as_f64()).unwrap_or(0.0) + suspicion;
            let body = json!({"total": total, "calls": calls});
            let written = match &seen {
                None => self.store.create(&key, &body).await.map(|_| ()),
                Some(c) => self.store.compare_and_swap(&key, c.revision, &body).await.map(|_| ()),
            };
            match written {
                Ok(()) => return Ok(()),
                Err(e) if e.is_conflict() => {}
                Err(e) => return Err(e),
            }
        }
        Err(StoreError::Conflict {
            expected: None,
            actual: None,
        })
    }

    /// Scores consequential calls with `provider` and responds by `policy` (see
    /// [`crate::action_monitor`]).
    pub fn set_action_monitor(&mut self, monitor: Option<(Arc<dyn ActionMonitorProvider>, MonitorPolicy)>) {
        self.action_monitor = monitor;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scores_map_to_graded_responses() {
        let policy = MonitorPolicy {
            run_budget: Some(1.0),
            ..MonitorPolicy::default()
        };
        let judge = |a: Value, total: f64| policy.judge(Some(&a), total);
        assert_eq!(judge(json!({"suspicion": 0.1}), 0.0).0, FlowVerdict::Allow);
        let (verdict, reasons, _) = judge(json!({"suspicion": 0.6, "reason_codes": ["exfiltration"]}), 0.0);
        assert_eq!(
            (verdict, reasons),
            (
                FlowVerdict::Ask,
                vec!["action_monitor_ask".into(), "exfiltration".into()]
            )
        );
        assert_eq!(judge(json!({"suspicion": 0.95}), 0.0).0, FlowVerdict::Deny);
        // Many mild calls exhaust the run budget.
        let (verdict, reasons, _) = judge(json!({"suspicion": 0.3}), 0.8);
        assert_eq!(
            (verdict, reasons[0].as_str()),
            (FlowVerdict::Ask, "action_monitor_run_budget")
        );
    }

    #[test]
    fn unusable_answers_fail_by_policy() {
        let policy = MonitorPolicy::default();
        for bad in [
            json!({"suspicion": 1.5}),
            json!({"suspicion": "high"}),
            json!({"suspicion": 0.2, "reason_codes": ["Not A Code"]}),
        ] {
            let (verdict, reasons, suspicion) = policy.judge(Some(&bad), 0.0);
            assert_eq!(verdict, FlowVerdict::Ask, "{bad}");
            assert_eq!(reasons, ["action_monitor_unavailable"]);
            assert!(suspicion.is_none());
        }
        let hard = MonitorPolicy {
            on_unavailable: FlowVerdict::Deny,
            ..MonitorPolicy::default()
        };
        assert_eq!(hard.judge(None, 0.0).0, FlowVerdict::Deny);
        assert!(
            MonitorPolicy {
                ask_at: 0.9,
                deny_at: 0.5,
                ..MonitorPolicy::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            MonitorPolicy {
                run_budget: Some(0.0),
                ..MonitorPolicy::default()
            }
            .validate()
            .is_err()
        );
    }
}
