//! What the principal authorized for this run.
//!
//! Broker grants say what an agent *may* do; a task authorization says what its
//! principal asked for in this run ("refund order ord_881 for INR 1200"). It is fixed
//! at admission, before the agent acts, as `AuthorityGrant` scopes, and every effect
//! must also fall inside one of them: the kernel's own grant-scope check decides, on
//! the actual action binding rather than on what the request stated. It only narrows
//! authority, so whoever supplies it cannot widen what the broker grants.
//!
//! Every decision of the run composes a guardrail policy outcome citing it: `allow`
//! inside, and outside `deny` (refuse) or, with `ask`, `require_approval` (an exact
//! approval of that action before it runs). The action binding's `policy_refs` name
//! it, so decisions and approvals are bound to the authorization they were checked
//! against. Agents that ask only after acting are the failure `ask` prevents.

use contextos_contract::canonical::sha256_canonical;
use contextos_contract::types::ActionEffect;
use contextos_kernel::authorization::{scope_mismatch, valid_authority_scope, valid_principal};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Most scopes one task authorization may list.
pub const MAX_SCOPES: usize = 32;

/// What happens to an action the principal did not authorize.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutOfScope {
    /// Refuse it.
    #[default]
    Deny,
    /// Pause it for an exact approval of that action.
    Ask,
}

/// Whether read-only capabilities must be listed too.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadOnly {
    /// Read-only capabilities (`effect: none`) need no scope.
    #[default]
    Allow,
    /// Every capability, reads included, must fall inside a scope.
    Scoped,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAuthorization {
    /// Who authorized the task (`PrincipalRef`), usually the run's user.
    pub issued_by: Value,
    /// `AuthorityGrant` scopes; an action must fall inside at least one.
    pub scopes: Vec<Value>,
    #[serde(default)]
    pub out_of_scope: OutOfScope,
    #[serde(default)]
    pub read_only: ReadOnly,
    /// Evidence of the principal's confirmation (an `ArtifactRef`), when recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmation_ref: Option<Value>,
}

/// The task authorization's verdict on one action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskCheck {
    /// The guardrail policy outcome to compose with the run's other outcomes.
    pub outcome: Value,
    /// Outside: `outside_task_authorization` and the first dimension that did not
    /// match. Empty inside.
    pub reason_codes: Vec<String>,
}

impl TaskAuthorization {
    /// Structural review at admission. `root_run_id` is the run's root: every scope
    /// must name it, so a scope cannot be replayed into another task.
    pub fn validate(&self, root_run_id: &str) -> Result<(), &'static str> {
        if !valid_principal(&self.issued_by) {
            return Err("issued_by must be a principal reference");
        }
        if self.scopes.is_empty() || self.scopes.len() > MAX_SCOPES {
            return Err("scopes must list between 1 and 32 grant scopes");
        }
        if !self.scopes.iter().all(valid_authority_scope) {
            return Err("every scope must be a valid AuthorityGrant scope");
        }
        if self.scopes.iter().any(|s| s["root_run_id"] != root_run_id) {
            return Err("every scope must name the run's root_run_id");
        }
        if self
            .confirmation_ref
            .as_ref()
            .is_some_and(|r| !contextos_contract::shape::is_artifact_ref(r))
        {
            return Err("confirmation_ref must be an artifact reference");
        }
        Ok(())
    }

    /// The pinned reference policy outcomes cite.
    pub fn bundle_ref(&self, run_id: &str) -> Value {
        let digest = serde_json::to_value(self)
            .ok()
            .and_then(|v| sha256_canonical(&v).ok())
            .unwrap_or_default();
        json!({"artifact_type": "task_authorization", "artifact_id": run_id, "version": "1", "sha256": digest})
    }

    pub fn check(&self, run_id: &str, binding: &Value, effect: ActionEffect) -> TaskCheck {
        let outcome = |verdict: &str, obligations: Value| {
            json!({"category": "guardrail", "priority": 0, "verdict": verdict,
                "rule_id": "task_authorization", "bundle_ref": self.bundle_ref(run_id), "obligations": obligations})
        };
        let inside = TaskCheck {
            outcome: outcome("allow", json!([])),
            reason_codes: vec![],
        };
        if effect == ActionEffect::None && self.read_only == ReadOnly::Allow {
            return inside;
        }
        let Some(mismatches) = self
            .scopes
            .iter()
            .map(|s| scope_mismatch(binding, s))
            .collect::<Option<Vec<&'static str>>>()
        else {
            return inside;
        };
        // Report the dimension of a scope that names this capability: it says what the
        // principal did authorize for it. Otherwise the capability itself is outside.
        let dimension = self
            .scopes
            .iter()
            .zip(&mismatches)
            .find(|(scope, _)| {
                scope["capability_ids"]
                    .as_array()
                    .is_some_and(|ids| ids.contains(&binding["capability_id"]))
            })
            .map_or("capability", |(_, m)| *m);
        let (verdict, obligations) = match self.out_of_scope {
            OutOfScope::Deny => ("deny", json!([])),
            OutOfScope::Ask => ("require_approval", json!(["confirm_with_principal"])),
        };
        TaskCheck {
            outcome: outcome(verdict, obligations),
            reason_codes: vec!["outside_task_authorization".into(), format!("task_scope_{dimension}")],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(capability: &str, resource: &str, ceiling: u64) -> Value {
        json!({"root_run_id": "run_1", "purpose_ids": ["support.refund"], "capability_ids": [capability],
            "resource_ids": [resource], "destination_ids": ["cus_77"], "classification_labels": ["CONFIDENTIAL"],
            "argument_constraints": [], "amount_ceiling": {"minor_units": ceiling, "currency": "INR"}})
    }

    fn task(scopes: Vec<Value>, out_of_scope: OutOfScope, read_only: ReadOnly) -> TaskAuthorization {
        TaskAuthorization {
            issued_by: json!({"principal_id": "usr_771", "principal_type": "person", "trust_domain": "t", "tenant_id": "acme"}),
            scopes,
            out_of_scope,
            read_only,
            confirmation_ref: None,
        }
    }

    fn binding(capability: &str, resource: &str, amount: u64) -> Value {
        json!({"purpose_id": "support.refund", "capability_id": capability, "resource_ids": [resource],
            "destination_ids": ["cus_77"], "action_risk": {"data_scope": "CONFIDENTIAL"}, "arguments": {},
            "amount": {"minor_units": amount, "currency": "INR"}})
    }

    fn verdict(check: &TaskCheck) -> &str {
        check.outcome["verdict"].as_str().unwrap()
    }

    #[test]
    fn any_scope_covering_the_action_admits_it() {
        let t = task(
            vec![scope("pay.refund", "ord_1", 100), scope("pay.refund", "ord_2", 500)],
            OutOfScope::Deny,
            ReadOnly::Allow,
        );
        let inside = t.check(
            "run_1",
            &binding("pay.refund", "ord_2", 400),
            ActionEffect::ExternalState,
        );
        assert_eq!((verdict(&inside), inside.reason_codes.len()), ("allow", 0));
        let outside = t.check(
            "run_1",
            &binding("pay.refund", "ord_1", 400),
            ActionEffect::ExternalState,
        );
        assert_eq!(verdict(&outside), "deny");
        assert_eq!(
            outside.reason_codes,
            ["outside_task_authorization", "task_scope_amount"]
        );
    }

    #[test]
    fn an_unlisted_capability_is_named_as_such() {
        let t = task(
            vec![scope("pay.refund", "ord_1", 100)],
            OutOfScope::Ask,
            ReadOnly::Allow,
        );
        let out = t.check("run_1", &binding("mail.send", "ord_1", 1), ActionEffect::ExternalState);
        assert_eq!(out.reason_codes[1], "task_scope_capability");
        assert_eq!(verdict(&out), "require_approval");
        assert_eq!(out.outcome["obligations"], json!(["confirm_with_principal"]));
    }

    #[test]
    fn reads_are_scoped_only_when_asked() {
        let read = binding("orders.lookup", "ord_9", 0);
        let allow = task(
            vec![scope("pay.refund", "ord_1", 100)],
            OutOfScope::Deny,
            ReadOnly::Allow,
        );
        assert_eq!(verdict(&allow.check("run_1", &read, ActionEffect::None)), "allow");
        let scoped = task(
            vec![scope("pay.refund", "ord_1", 100)],
            OutOfScope::Deny,
            ReadOnly::Scoped,
        );
        assert_eq!(verdict(&scoped.check("run_1", &read, ActionEffect::None)), "deny");
    }

    #[test]
    fn authorizations_are_reviewed_and_pinned() {
        let good = task(
            vec![scope("pay.refund", "ord_1", 100)],
            OutOfScope::Deny,
            ReadOnly::Allow,
        );
        assert!(good.validate("run_1").is_ok());
        assert!(good.validate("run_2").is_err(), "a scope for another task");
        assert!(
            task(vec![], OutOfScope::Deny, ReadOnly::Allow)
                .validate("run_1")
                .is_err()
        );
        let mut malformed = scope("pay.refund", "ord_1", 100);
        malformed["amount_ceiling"]["currency"] = json!("inr");
        assert!(
            task(vec![malformed], OutOfScope::Deny, ReadOnly::Allow)
                .validate("run_1")
                .is_err()
        );
        let mut other = good.clone();
        other.scopes[0]["resource_ids"] = json!(["ord_2"]);
        assert_ne!(
            good.bundle_ref("run_1"),
            other.bundle_ref("run_1"),
            "the reference pins the content"
        );
    }
}
