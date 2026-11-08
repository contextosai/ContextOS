//! Review floor for approvals: a decision made faster than a person can read the
//! action does not count.
//!
//! Human oversight fails quietly when approvers click through prompts. The EU AI Act
//! asks that overseers stay aware of automation bias (Art. 14(4)(b)), and agentic
//! governance frameworks ask deployments to measure time-to-approve. This guard
//! enforces a floor. For the approvals it covers (named capabilities, amounts at or
//! above a threshold, or every approval when neither is set), each approved decision
//! must be made at least `min_review_seconds` after the approval was requested.
//!
//! The request time is the gateway's own: it is recorded when the gateway asks the
//! approval service for an approval (see [`crate::approval_events`]). For a request the gateway did not make, the
//! request's `not_before` is used. A decision that is too fast is not used: the call
//! needs an approval again (`approval_review_too_fast`, obligation `review_again`),
//! and the refusal is audited with the measured seconds. `decided_at` is the approval
//! service's claim, as everything about a decision is.

use contextos_contract::validation::elapsed_millis;
use contextos_store::{AppendLog, DocumentStore};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::admission::RunAdmission;
use crate::step_up::AmountThreshold;
use crate::{Gateway, GatewayError};

/// `[guards.approval_review]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReviewPolicy {
    /// Seconds between the request and an approved decision, at least.
    pub min_review_seconds: u64,
    /// Applies to every approval of these capabilities.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Applies to actions whose bound amount reaches the threshold for its currency
    /// (and to amounts in a currency without one).
    #[serde(default)]
    pub amount_at_least: Vec<AmountThreshold>,
}

impl ReviewPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=3600).contains(&self.min_review_seconds) {
            return Err("approval_review min_review_seconds must be 1..=3600".into());
        }
        Ok(())
    }

    /// Whether approvals of this action are covered.
    #[must_use]
    pub fn applies(&self, capability_id: &str, binding: &Value) -> bool {
        if self.capabilities.is_empty() && self.amount_at_least.is_empty() {
            return true;
        }
        let amount = &binding["amount"];
        self.capabilities.iter().any(|c| c == capability_id)
            || (!self.amount_at_least.is_empty()
                && amount["minor_units"].as_u64().is_some_and(|units| {
                    self.amount_at_least
                        .iter()
                        .find(|t| amount["currency"] == t.currency.as_str())
                        .is_none_or(|t| units >= t.minor_units)
                }))
    }

    /// The fastest approved decision's review time in seconds, when it is under the
    /// floor (`Some(0)` when a decision has no usable time).
    #[must_use]
    pub fn too_fast(&self, material: &Map<String, Value>, requested_at: &str) -> Option<u64> {
        let decisions = material.get("decisions").and_then(Value::as_array)?;
        decisions
            .iter()
            .filter(|d| d["decision"] == "approved")
            .map(|d| {
                d["decided_at"]
                    .as_str()
                    .and_then(|at| elapsed_millis(requested_at, at))
                    .map_or(0, |ms| ms / 1000)
            })
            .min()
            .filter(|seconds| *seconds < self.min_review_seconds)
    }
}

use crate::approval_events::requested_key as key;

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// `material` unless its approval was decided too fast; then `None`, with the
    /// request id and measured seconds.
    pub(crate) async fn review_approval(
        &self,
        admission: &RunAdmission,
        capability_id: &str,
        binding: &Value,
        material: Option<Value>,
    ) -> Result<(Option<Value>, Option<(Value, u64)>), GatewayError> {
        let Some(policy) = &self.approval_review else {
            return Ok((material, None));
        };
        let Some(Value::Object(fields)) = &material else {
            return Ok((material, None));
        };
        if !policy.applies(capability_id, binding) {
            return Ok((material, None));
        }
        let request = fields.get("request").cloned().unwrap_or(Value::Null);
        let request_id = request["approval_request_id"].as_str().unwrap_or_default();
        let recorded = if request_id.is_empty() {
            None
        } else {
            self.store.get(&key(&admission.tenant_id, request_id)).await?
        };
        let requested_at = recorded
            .as_ref()
            .and_then(|r| r.body["requested_at"].as_str().map(str::to_owned))
            .or_else(|| request["not_before"].as_str().map(str::to_owned))
            .unwrap_or_default();
        Ok(match policy.too_fast(fields, &requested_at) {
            Some(seconds) => (None, Some((request["approval_request_id"].clone(), seconds))),
            None => (material, None),
        })
    }

    /// Requires approvals `policy` covers to be reviewed for a minimum time (see
    /// [`crate::approval_review`]).
    pub fn set_approval_review(&mut self, policy: Option<ReviewPolicy>) {
        self.approval_review = policy;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn material(decided: &[&str]) -> Map<String, Value> {
        let decisions: Vec<Value> = decided
            .iter()
            .map(|at| json!({"decision": "approved", "decided_at": at}))
            .collect();
        json!({"decisions": decisions}).as_object().unwrap().clone()
    }

    #[test]
    fn a_decision_faster_than_the_floor_does_not_count() {
        let policy = ReviewPolicy {
            min_review_seconds: 30,
            capabilities: vec![],
            amount_at_least: vec![],
        };
        let at = "2026-11-07T10:00:00Z";
        assert_eq!(policy.too_fast(&material(&["2026-11-07T10:00:05Z"]), at), Some(5));
        assert_eq!(policy.too_fast(&material(&["2026-11-07T10:00:45Z"]), at), None);
        // Every approver must have reviewed: the fastest decides.
        assert_eq!(
            policy.too_fast(&material(&["2026-11-07T10:01:00Z", "2026-11-07T10:00:02Z"]), at),
            Some(2)
        );
        // A decision before the request, or without a time, is not a review.
        assert_eq!(policy.too_fast(&material(&["2026-11-07T09:59:00Z"]), at), Some(0));
        assert_eq!(policy.too_fast(&material(&["soon"]), at), Some(0));
        assert!(policy.applies("any.capability", &json!({})));
        assert!(policy.validate().is_ok());
        assert!(
            ReviewPolicy {
                min_review_seconds: 0,
                ..policy
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn scoped_policies_apply_by_capability_or_amount() {
        let policy = ReviewPolicy {
            min_review_seconds: 30,
            capabilities: vec!["adp_payments.issue_refund".into()],
            amount_at_least: vec![AmountThreshold {
                currency: "USD".into(),
                minor_units: 100_000,
            }],
        };
        assert!(policy.applies("adp_payments.issue_refund", &json!({})));
        assert!(!policy.applies(
            "adp_crm.note",
            &json!({"amount": {"currency": "USD", "minor_units": 5}})
        ));
        assert!(policy.applies(
            "adp_crm.note",
            &json!({"amount": {"currency": "USD", "minor_units": 100_000}})
        ));
    }
}
