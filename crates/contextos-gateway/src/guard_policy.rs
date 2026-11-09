//! The runtime guards' policy reference.
//!
//! The information-flow guard and the action monitor decide by composing guardrail
//! policy outcomes with the run's others, so an `ask` is an approval of the exact
//! action. The kernel requires every outcome's `bundle_ref` to be one of the action
//! binding's `policy_refs`, and constraint services bind their observations to the
//! same set. So a run pins one reference to the runtime guards' configuration when it
//! is admitted (`guard_policy_ref`). Every decision of the run cites it, even after the
//! guards' configuration changes.
//!
//! The pin binds only the reference. Guards always decide under the live
//! configuration: after a mid-run change, a call is decided by the new configuration
//! while its composed outcome still cites the admission-time reference. The
//! information-flow guard's audit entry (`information_flow_decision`) carries the
//! `policy_ref` that decided.
//!
//! A run admitted while no guard was on has no reference to cite. A call a guard would
//! not allow is then refused outright (`<guard>_policy_unpinned`) rather than approved.

use contextos_contract::canonical::sha256_canonical;
use serde_json::{Value, json};

use crate::admission::RunAdmission;
use crate::information_flow::FlowVerdict;

/// The reference a run admitted under these guards pins; `None` when none is on.
pub fn guard_policy_ref(guards: &Value) -> Option<Value> {
    if guards.as_object().is_none_or(|g| g.values().all(Value::is_null)) {
        return None;
    }
    let digest = sha256_canonical(guards).ok()?;
    Some(json!({"artifact_type": "runtime_guard_policy", "artifact_id": "guards", "version": "1", "sha256": digest}))
}

/// The guardrail policy outcome `rule_id` composes, citing `bundle_ref`.
pub fn outcome(rule_id: &str, verdict: FlowVerdict, obligation: &str, bundle_ref: Value) -> Value {
    let (verdict, obligations) = match verdict {
        FlowVerdict::Allow => ("allow", json!([])),
        FlowVerdict::Ask => ("require_approval", json!([obligation])),
        FlowVerdict::Deny => ("deny", json!([])),
    };
    json!({"category": "guardrail", "priority": 0, "verdict": verdict,
        "rule_id": rule_id, "bundle_ref": bundle_ref, "obligations": obligations})
}

/// The outcome every decision of a pinned run composes, so its binding's reference is
/// always cited (an allow; the guards add their own verdicts beside it).
pub fn pinned_outcome(admission: &RunAdmission) -> Option<Value> {
    admission
        .guard_policy_ref
        .clone()
        .map(|r| outcome("runtime_guards", FlowVerdict::Allow, "", r))
}

/// What a guard does to one call.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum FlowGate {
    /// Nothing to add.
    Pass,
    /// A policy outcome to compose, with reason codes for the report.
    Outcome(Value, Vec<String>),
    /// Refuse the call with these reason codes.
    Refuse(Vec<String>),
}

/// A guard's `verdict` for a call of `admission`, as the gate the pipeline applies.
pub(crate) fn gate(
    admission: &RunAdmission,
    verdict: FlowVerdict,
    rule_id: &str,
    obligation: &str,
    reason_codes: Vec<String>,
    unpinned: &str,
) -> FlowGate {
    if verdict == FlowVerdict::Allow {
        return FlowGate::Pass;
    }
    if let Some(pinned) = &admission.guard_policy_ref {
        FlowGate::Outcome(outcome(rule_id, verdict, obligation, pinned.clone()), reason_codes)
    } else {
        let mut codes = reason_codes;
        codes.push(unpinned.to_owned());
        FlowGate::Refuse(codes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_guard_pins_nothing_and_a_change_changes_the_reference() {
        assert_eq!(
            guard_policy_ref(&json!({"information_flow": null, "action_monitor": null})),
            None
        );
        let a = guard_policy_ref(&json!({"information_flow": {"mode": "enforce"}})).unwrap();
        let b = guard_policy_ref(&json!({"information_flow": {"mode": "observe"}})).unwrap();
        assert_ne!(a, b);
        assert!(contextos_contract::shape::is_artifact_ref(&a));
        assert_eq!(
            outcome("x", FlowVerdict::Ask, "o", a.clone())["verdict"],
            "require_approval"
        );
        assert_eq!(outcome("x", FlowVerdict::Deny, "o", a)["obligations"], json!([]));
    }
}
