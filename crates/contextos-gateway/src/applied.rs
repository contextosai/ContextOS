//! What a retry of an operation that already took effect is told.
//!
//! Sending an applied operation again is refused (`retry_unsafe`): the effect is not
//! repeated. So that an agent can stop retrying instead of reconciling something that
//! is not in doubt, the answer says the operation was applied and names the recorded
//! result it rests on: `metadata.applied_operation` carries the operation id, its
//! outcome and the observation that established it (attempt, time and the evidence
//! ref, whose digest covers the provider's answer). The provider's own reference is
//! never included; it stays with the effect's record.

use serde_json::{Value, json};

/// The message of a refused retry of an applied operation.
pub(crate) const APPLIED_MESSAGE: &str =
    "The operation was already applied; it is not sent again. metadata.applied_operation names its recorded result.";

/// The applied operation's record, if `op` (an operation ledger entry) is confirmed or
/// partial without a conflict and an observation of that outcome is recorded.
pub(crate) fn applied_operation(op: &Value) -> Option<Value> {
    let outcome = op["outcome"]
        .as_str()
        .filter(|o| matches!(*o, "confirmed" | "partial"))?;
    if op["conflict"] == true {
        return None;
    }
    let observed = op["observations"]
        .as_array()?
        .iter()
        .rev()
        .find(|o| o["outcome"] == outcome && o["finality"] == "definitive")?;
    Some(json!({
        "operation_id": op["intent"]["operation_id"],
        "outcome": outcome,
        "attempt_id": observed["attempt_id"],
        "observation_id": observed["observation_id"],
        "observed_at": observed["observed_at"],
        "evidence_ref": observed["evidence_ref"],
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(outcome: &str, conflict: bool) -> Value {
        json!({"intent": {"operation_id": "op_1"}, "outcome": outcome, "conflict": conflict, "observations": [
            {"attempt_id": "att_1", "observation_id": "obs_1", "outcome": "unknown", "finality": "provisional"},
            {"attempt_id": "att_1", "observation_id": "obs_2", "outcome": outcome, "finality": "definitive",
             "observed_at": "2026-11-20T10:00:00Z", "external_ref": "rf_secret",
             "evidence_ref": {"artifact_type": "provider_ledger", "artifact_id": "export_1"}}]})
    }

    #[test]
    fn names_the_observation_that_applied_it_without_the_provider_reference() {
        let applied = applied_operation(&op("confirmed", false)).unwrap();
        assert_eq!(applied["operation_id"], "op_1");
        assert_eq!(applied["observation_id"], "obs_2");
        assert_eq!(applied["evidence_ref"]["artifact_id"], "export_1");
        assert!(!applied.to_string().contains("rf_secret"));
    }

    #[test]
    fn only_settled_effects_count_as_applied() {
        assert!(applied_operation(&op("partial", false)).is_some());
        assert!(
            applied_operation(&op("confirmed", true)).is_none(),
            "a conflict is not settled"
        );
        assert!(applied_operation(&op("unknown", false)).is_none());
        assert!(applied_operation(&op("not_applied", false)).is_none());
    }
}
