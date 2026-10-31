//! Step-up for large approvals: above a configured amount, or for named capabilities,
//! an approval counts only if every approver authenticated strongly and recently.
//!
//! The kernel decides whether an approval binds the exact action (approver
//! eligibility, quorum, expiry, single redemption). It does not know how the approver
//! signed in, and its input shape is fixed by the spec. So the approval service
//! reports that separately, beside the decisions:
//!
//! ```json
//! "assurance": {"<approval_id>": {"acr": "…", "amr": ["mfa"], "auth_time": "<timestamp>"}}
//! ```
//!
//! The gateway removes `assurance` before the kernel sees the material. When step-up
//! applies, every approved decision needs an entry with an accepted `acr` or `amr`
//! value and an `auth_time` at most `max_age_seconds` before the decision. Otherwise
//! the approval is not used: the call needs an approval again (`require_approval`,
//! reason `approval_step_up_required`), and the refusal is audited. Assurance is a
//! claim the approval service makes. Its value is the service's honesty plus the
//! identity provider's `acr`/`amr`, so take them from the approver's ID token.

use contextos_contract::validation::{age_within_limit, compare_contract_times};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

fn default_max_age() -> u64 {
    300
}

/// An amount at or above which approvals need step-up, in one currency.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AmountThreshold {
    /// ISO 4217 code, as the action's bound `amount.currency`.
    pub currency: String,
    pub minor_units: u64,
}

/// `[guards.approval_step_up]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StepUpPolicy {
    /// Applies to actions whose bound amount reaches the threshold for its currency,
    /// and to any bound amount in a currency without one (or without a currency).
    #[serde(default)]
    pub amount_at_least: Vec<AmountThreshold>,
    /// Applies to every approval of these capabilities.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Accepted `acr` values (any one).
    #[serde(default)]
    pub acr_values: Vec<String>,
    /// Accepted `amr` methods (any one present), for example `mfa`, `hwk`, `otp`.
    #[serde(default)]
    pub amr_values: Vec<String>,
    /// How long before the decision the approver may have authenticated.
    #[serde(default = "default_max_age")]
    pub max_age_seconds: u64,
}

impl StepUpPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if self.amount_at_least.is_empty() && self.capabilities.is_empty() {
            return Err("approval_step_up needs amount_at_least or capabilities".into());
        }
        let mut currencies = std::collections::HashSet::new();
        for threshold in &self.amount_at_least {
            let code = &threshold.currency;
            if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_uppercase()) || !currencies.insert(code) {
                return Err(format!(
                    "approval_step_up amount_at_least: {code:?} must be a distinct ISO 4217 currency code"
                ));
            }
        }
        if self.acr_values.is_empty() && self.amr_values.is_empty() {
            return Err("approval_step_up needs acr_values or amr_values".into());
        }
        if !(1..=3600).contains(&self.max_age_seconds) {
            return Err("approval_step_up max_age_seconds must be 1..=3600".into());
        }
        Ok(())
    }

    /// Whether approvals of this action need step-up.
    #[must_use]
    pub fn applies(&self, capability_id: &str, binding: &Value) -> bool {
        let amount = &binding["amount"];
        self.capabilities.iter().any(|c| c == capability_id)
            || (!self.amount_at_least.is_empty()
                && amount["minor_units"].as_u64().is_some_and(|units| {
                    // A currency without a threshold cannot be compared: step up.
                    self.amount_at_least
                        .iter()
                        .find(|t| amount["currency"] == t.currency.as_str())
                        .is_none_or(|t| units >= t.minor_units)
                }))
    }

    fn strong(&self, entry: &Value, decided_at: &str) -> bool {
        let acr = entry["acr"]
            .as_str()
            .is_some_and(|acr| self.acr_values.iter().any(|v| v == acr));
        let amr = entry["amr"].as_array().is_some_and(|methods| {
            methods
                .iter()
                .any(|m| m.as_str().is_some_and(|m| self.amr_values.iter().any(|v| v == m)))
        });
        let Some(auth_time) = entry["auth_time"].as_str() else {
            return false;
        };
        (acr || amr)
            && compare_contract_times(auth_time, decided_at).is_some_and(std::cmp::Ordering::is_le)
            && age_within_limit(decided_at, auth_time, self.max_age_seconds)
    }

    /// Whether every approved decision in `material` was made after a step-up.
    #[must_use]
    pub fn satisfied(&self, material: &Map<String, Value>, assurance: Option<&Value>) -> bool {
        let Some(decisions) = material.get("decisions").and_then(Value::as_array) else {
            return false;
        };
        let approved: Vec<&Value> = decisions.iter().filter(|d| d["decision"] == "approved").collect();
        !approved.is_empty()
            && approved.iter().all(|decision| {
                let (Some(id), Some(decided_at)) = (decision["approval_id"].as_str(), decision["decided_at"].as_str())
                else {
                    return false;
                };
                assurance
                    .and_then(|a| a.get(id))
                    .is_some_and(|entry| self.strong(entry, decided_at))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn policy() -> StepUpPolicy {
        StepUpPolicy {
            amount_at_least: vec![AmountThreshold {
                currency: "USD".into(),
                minor_units: 100_000,
            }],
            capabilities: Vec::new(),
            acr_values: vec!["phr".into()],
            amr_values: vec!["mfa".into(), "hwk".into()],
            max_age_seconds: 300,
        }
    }

    fn material(decided_at: &str) -> Map<String, Value> {
        json!({"decisions": [{"approval_id": "apv_1", "decision": "approved", "decided_at": decided_at}]})
            .as_object()
            .unwrap()
            .clone()
    }

    #[test]
    fn step_up_applies_by_amount_or_capability() {
        let p = policy();
        let amount = |currency: &str, units: u64| json!({"amount": {"currency": currency, "minor_units": units}});
        assert!(p.applies("adp_payments.issue_refund", &amount("USD", 100_000)));
        assert!(!p.applies("adp_payments.issue_refund", &amount("USD", 99_999)));
        assert!(!p.applies("adp_payments.issue_refund", &json!({})));
        // No threshold for the currency, or none named: the amounts cannot be
        // compared, so step-up applies.
        assert!(p.applies("adp_payments.issue_refund", &amount("JPY", 5)));
        assert!(p.applies("adp_payments.issue_refund", &json!({"amount": {"minor_units": 5}})));
        for currency in ["usd", "US", "USD"] {
            let mut twice = p.clone();
            twice.amount_at_least.push(AmountThreshold {
                currency: currency.into(),
                minor_units: 1,
            });
            assert!(twice.validate().is_err(), "{currency}");
        }
        let named = StepUpPolicy {
            capabilities: vec!["adp_iam.grant_admin".into()],
            ..policy()
        };
        assert!(named.applies("adp_iam.grant_admin", &json!({})));
        assert!(
            StepUpPolicy {
                acr_values: vec![],
                amr_values: vec![],
                ..policy()
            }
            .validate()
            .is_err()
        );
        assert!(
            StepUpPolicy {
                amount_at_least: Vec::new(),
                ..policy()
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn every_approver_needs_a_strong_recent_sign_in() {
        let p = policy();
        let decided = "2026-10-30T10:10:00Z";
        let fresh_mfa = json!({"apv_1": {"amr": ["pwd", "mfa"], "auth_time": "2026-10-30T10:06:00Z"}});
        assert!(p.satisfied(&material(decided), Some(&fresh_mfa)));
        let phishing_resistant = json!({"apv_1": {"acr": "phr", "auth_time": "2026-10-30T10:09:59Z"}});
        assert!(p.satisfied(&material(decided), Some(&phishing_resistant)));
        for weak in [
            json!({"apv_1": {"amr": ["pwd"], "auth_time": "2026-10-30T10:09:00Z"}}),
            json!({"apv_1": {"amr": ["mfa"], "auth_time": "2026-10-30T10:04:59Z"}}),
            json!({"apv_1": {"amr": ["mfa"], "auth_time": "2026-10-30T10:10:01Z"}}),
            json!({"apv_1": {"amr": ["mfa"]}}),
            json!({"apv_2": {"amr": ["mfa"], "auth_time": "2026-10-30T10:09:00Z"}}),
        ] {
            assert!(!p.satisfied(&material(decided), Some(&weak)), "{weak}");
        }
        assert!(!p.satisfied(&material(decided), None));
    }
}
