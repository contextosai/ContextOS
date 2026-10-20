//! Operation ledger: stable effect identity distinct from transport attempts.
//!
//! An operation is claimed before dispatch, observed afterwards, and retried only
//! when it is provably safe: never after a confirmed or partial effect, never while
//! an attempt is in flight, never before its scheduled delay, and after an unknown
//! outcome only under a verified provider idempotency contract that enforces the same
//! payload. Late facts from earlier executor generations are still recorded but never
//! authorize dispatch.

use std::cmp::Ordering;
use std::collections::HashSet;

use contextos_contract::canonical::{canonicalize, utf16_cmp};
use contextos_contract::shape::{
    exact_keys, is_artifact_ref, is_digest, is_identifier, is_safe_non_negative_integer, is_timestamp,
};
use contextos_contract::validation::add_contract_seconds;
use serde_json::{Map, Value, json};

use crate::authorization::valid_principal;
use crate::run_state::int;
use crate::support::{
    MAX_SAFE_INTEGER, TransitionResult, cmp_times, list, s, same, sorted_strings, verification_status, within,
};

const INTENT_KEYS: [&str; 16] = [
    "contract_id",
    "run_id",
    "tenant_id",
    "operation_id",
    "action_digest",
    "adapter_ref",
    "capability_ref",
    "desired_effect",
    "recovery_strategy",
    "idempotency_key",
    "idempotency_scope",
    "provider_idempotency_ref",
    "max_attempts",
    "retry_delays_seconds",
    "deadline",
    "compensates_operation_id",
];

const OUTCOMES: [&str; 5] = ["not_dispatched", "confirmed", "not_applied", "partial", "unknown"];

fn nullable_id(v: &Value) -> bool {
    v.is_null() || is_identifier(v)
}

fn nullable_ref(v: &Value) -> bool {
    v.is_null() || is_artifact_ref(v)
}

fn effect(v: &Value) -> bool {
    v.as_str().is_some_and(|o| OUTCOMES.contains(&o))
}

fn intent_fields(o: &Map<String, Value>) -> bool {
    ["contract_id", "run_id", "tenant_id", "operation_id", "desired_effect"]
        .iter()
        .all(|k| is_identifier(&o[*k]))
        && is_digest(&o["action_digest"])
        && is_artifact_ref(&o["adapter_ref"])
        && is_artifact_ref(&o["capability_ref"])
        && matches!(
            o["recovery_strategy"].as_str(),
            Some("query" | "idempotent_retry" | "manual_reconcile" | "no_retry")
        )
        && nullable_id(&o["idempotency_key"])
        && nullable_id(&o["idempotency_scope"])
        && nullable_ref(&o["provider_idempotency_ref"])
        && is_safe_non_negative_integer(&o["max_attempts"])
        && (1..=128).contains(&int(&o["max_attempts"]))
        && list(&o["retry_delays_seconds"], is_safe_non_negative_integer)
        && o["retry_delays_seconds"]
            .as_array()
            .is_some_and(|d| i64::try_from(d.len()).ok() == Some(int(&o["max_attempts"]) - 1))
        && is_timestamp(&o["deadline"])
        && nullable_id(&o["compensates_operation_id"])
        && ((o["idempotency_key"].is_null()
            && o["idempotency_scope"].is_null()
            && o["provider_idempotency_ref"].is_null())
            || (is_identifier(&o["idempotency_key"])
                && is_identifier(&o["idempotency_scope"])
                && is_artifact_ref(&o["provider_idempotency_ref"])))
}

fn valid_intent(v: &Value) -> bool {
    exact_keys(v, &INTENT_KEYS).is_some_and(intent_fields)
}

fn attempt(v: &Value) -> bool {
    exact_keys(
        v,
        &[
            "attempt_id",
            "operation_id",
            "executor_generation",
            "started_at",
            "dispatch_state",
            "last_observation_ref",
        ],
    )
    .is_some_and(|o| {
        is_identifier(&o["attempt_id"])
            && is_identifier(&o["operation_id"])
            && is_safe_non_negative_integer(&o["executor_generation"])
            && is_timestamp(&o["started_at"])
            && matches!(o["dispatch_state"].as_str(), Some("claimed" | "dispatched" | "settled"))
            && nullable_ref(&o["last_observation_ref"])
    })
}

fn provider(v: &Value) -> bool {
    exact_keys(
        v,
        &[
            "provider_contract_ref",
            "key",
            "scope",
            "operation_id",
            "action_digest",
            "same_payload_enforced",
            "verification_status",
            "observer",
            "evidence_ref",
            "observed_at",
            "valid_until",
            "not_before",
            "retention_expires_at",
        ],
    )
    .is_some_and(|o| {
        is_artifact_ref(&o["provider_contract_ref"])
            && ["key", "scope", "operation_id"].iter().all(|k| is_identifier(&o[*k]))
            && is_digest(&o["action_digest"])
            && o["same_payload_enforced"].is_boolean()
            && verification_status(&o["verification_status"])
            && valid_principal(&o["observer"])
            && is_artifact_ref(&o["evidence_ref"])
            && ["observed_at", "valid_until", "not_before", "retention_expires_at"]
                .iter()
                .all(|k| is_timestamp(&o[*k]))
    })
}

fn claim_shape(v: &Value) -> bool {
    let keys: Vec<&str> = INTENT_KEYS
        .iter()
        .copied()
        .chain(["attempt", "evaluation_time", "provider_observation"])
        .collect();
    exact_keys(v, &keys).is_some_and(|o| {
        intent_fields(o)
            && attempt(&o["attempt"])
            && is_timestamp(&o["evaluation_time"])
            && (o["provider_observation"].is_null() || provider(&o["provider_observation"]))
    })
}

fn observation(v: &Value) -> bool {
    exact_keys(
        v,
        &[
            "observation_id",
            "contract_id",
            "run_id",
            "tenant_id",
            "operation_id",
            "attempt_id",
            "action_digest",
            "executor_generation",
            "outcome",
            "finality",
            "external_ref",
            "evidence_ref",
            "verification_status",
            "observer",
            "observed_at",
            "valid_until",
            "evaluation_time",
        ],
    )
    .is_some_and(|o| {
        [
            "observation_id",
            "contract_id",
            "run_id",
            "tenant_id",
            "operation_id",
            "attempt_id",
        ]
        .iter()
        .all(|k| is_identifier(&o[*k]))
            && is_digest(&o["action_digest"])
            && is_safe_non_negative_integer(&o["executor_generation"])
            && effect(&o["outcome"])
            && matches!(o["finality"].as_str(), Some("definitive" | "provisional"))
            && nullable_id(&o["external_ref"])
            && is_artifact_ref(&o["evidence_ref"])
            && verification_status(&o["verification_status"])
            && valid_principal(&o["observer"])
            && ["observed_at", "valid_until", "evaluation_time"]
                .iter()
                .all(|k| is_timestamp(&o[*k]))
    })
}

fn record(v: &Value) -> bool {
    exact_keys(
        v,
        &[
            "intent",
            "attempts",
            "observations",
            "outcome",
            "next_eligible_at",
            "conflict",
        ],
    )
    .is_some_and(|o| {
        valid_intent(&o["intent"])
            && list(&o["attempts"], attempt)
            && list(&o["observations"], observation)
            && effect(&o["outcome"])
            && (o["next_eligible_at"].is_null() || is_timestamp(&o["next_eligible_at"]))
            && o["conflict"].is_boolean()
    })
}

fn arr(v: &Value) -> &[Value] {
    v.as_array().map_or(&[], Vec::as_slice)
}

/// Derived outcome across all attempts. Definitive applied and absent facts for the
/// same attempt are a conflict, which forces `unknown` until escalated.
fn derive_outcome(op: &Value) -> (&'static str, bool) {
    let (mut confirmed, mut partial, mut uncertain, mut not_applied) = (false, false, false, false);
    let mut conflict = op["conflict"] == true;
    for current in arr(&op["attempts"]) {
        let facts: Vec<&Value> = arr(&op["observations"])
            .iter()
            .filter(|o| o["attempt_id"] == current["attempt_id"])
            .collect();
        let definitive: Vec<&&Value> = facts
            .iter()
            .filter(|o| o["finality"] == "definitive" && o["outcome"] != "unknown")
            .collect();
        let has = |set: &[&&Value], outcomes: &[&str]| set.iter().any(|o| outcomes.contains(&s(&o["outcome"])));
        let applied = has(&definitive, &["confirmed", "partial"]);
        let absent = has(&definitive, &["not_applied", "not_dispatched"]);
        if applied && absent {
            conflict = true;
        }
        confirmed |= has(&definitive, &["confirmed"]);
        partial |= has(&definitive, &["partial"]);
        not_applied |= has(&definitive, &["not_applied"]);
        if definitive.is_empty() && !facts.is_empty() {
            uncertain = true;
        }
    }
    let outcome = if conflict {
        "unknown"
    } else if confirmed {
        "confirmed"
    } else if partial {
        "partial"
    } else if uncertain {
        "unknown"
    } else if not_applied {
        "not_applied"
    } else {
        "not_dispatched"
    };
    (outcome, conflict)
}

fn latest_by_time<'a>(facts: &[&'a Value]) -> Option<&'a Value> {
    let mut sorted: Vec<&Value> = facts.to_vec();
    sorted.sort_by(|a, b| cmp_times(&b["observed_at"], &a["observed_at"]).unwrap_or(Ordering::Equal));
    sorted.first().copied()
}

fn retry_eligible_at(op: &Value) -> Option<String> {
    let attempts = arr(&op["attempts"]);
    let last = attempts.last();
    let facts: Vec<&Value> = arr(&op["observations"])
        .iter()
        .filter(|o| last.is_some_and(|l| o["attempt_id"] == l["attempt_id"]))
        .collect();
    let latest = latest_by_time(&facts)?;
    let delay = arr(&op["intent"]["retry_delays_seconds"]).get(attempts.len().checked_sub(1)?)?;
    let eligible = add_contract_seconds(s(&latest["observed_at"]), u64::try_from(int(delay)).ok()?)?;
    (cmp_times(&json!(eligible), &op["intent"]["deadline"]) == Some(Ordering::Less)).then_some(eligible)
}

fn correlation(ledger: &Value, intent: &Value) -> bool {
    intent["contract_id"] == ledger["contract_id"]
        && intent["run_id"] == ledger["run_id"]
        && intent["tenant_id"] == ledger["tenant_id"]
        && cmp_times(&intent["deadline"], &ledger["deadline"]) != Some(Ordering::Greater)
}

fn trusted(ledger: &Value, observed: &Value, time: &Value) -> bool {
    observed["verification_status"] == "verified"
        && observed["observer"]["tenant_id"] == ledger["tenant_id"]
        && arr(&ledger["trusted_observers"])
            .iter()
            .any(|t| same(t, &observed["observer"]))
        && within(time, &observed["observed_at"], &observed["valid_until"])
}

fn valid_ledger(v: &Value) -> bool {
    let structural = exact_keys(
        v,
        &[
            "ledger_id",
            "contract_id",
            "run_id",
            "tenant_id",
            "revision",
            "executor_generation",
            "deadline",
            "trusted_observers",
            "operations",
        ],
    )
    .is_some_and(|o| {
        ["ledger_id", "contract_id", "run_id", "tenant_id"]
            .iter()
            .all(|k| is_identifier(&o[*k]))
            && is_safe_non_negative_integer(&o["revision"])
            && is_safe_non_negative_integer(&o["executor_generation"])
            && is_timestamp(&o["deadline"])
            && list(&o["trusted_observers"], valid_principal)
            && list(&o["operations"], record)
            && {
                let ids: HashSet<&str> = arr(&o["operations"])
                    .iter()
                    .map(|op| s(&op["intent"]["operation_id"]))
                    .collect();
                ids.len() == arr(&o["operations"]).len()
            }
    });
    if !structural {
        return false;
    }
    let operations = arr(&v["operations"]);
    let attempt_ids: Vec<&str> = operations
        .iter()
        .flat_map(|op| arr(&op["attempts"]))
        .map(|a| s(&a["attempt_id"]))
        .collect();
    let observation_ids: Vec<&str> = operations
        .iter()
        .flat_map(|op| arr(&op["observations"]))
        .map(|o| s(&o["observation_id"]))
        .collect();
    if attempt_ids.iter().collect::<HashSet<_>>().len() != attempt_ids.len()
        || observation_ids.iter().collect::<HashSet<_>>().len() != observation_ids.len()
    {
        return false;
    }
    operations.iter().all(|op| {
        let (outcome, conflict) = derive_outcome(op);
        let due = retry_eligible_at(op);
        let attempts = arr(&op["attempts"]);
        correlation(v, &op["intent"])
            && op["outcome"] == outcome
            && op["conflict"] == conflict
            && match due {
                None => op["next_eligible_at"].is_null(),
                Some(due) => {
                    !op["next_eligible_at"].is_null()
                        && cmp_times(&json!(due), &op["next_eligible_at"]) == Some(Ordering::Equal)
                }
            }
            && i64::try_from(attempts.len()).unwrap_or(i64::MAX) <= int(&op["intent"]["max_attempts"])
            && attempts.iter().all(|a| {
                a["operation_id"] == op["intent"]["operation_id"]
                    && int(&a["executor_generation"]) <= int(&v["executor_generation"])
            })
            && arr(&op["observations"]).iter().all(|o| {
                o["operation_id"] == op["intent"]["operation_id"]
                    && o["action_digest"] == op["intent"]["action_digest"]
                    && o["contract_id"] == v["contract_id"]
                    && o["run_id"] == v["run_id"]
                    && o["tenant_id"] == v["tenant_id"]
                    && attempts.iter().any(|a| {
                        a["attempt_id"] == o["attempt_id"]
                            && int(&a["executor_generation"]) == int(&o["executor_generation"])
                    })
            })
    })
}

fn stable_intent(claim: &Value) -> Value {
    let mut intent = claim.as_object().cloned().unwrap_or_default();
    for key in ["attempt", "evaluation_time", "provider_observation"] {
        intent.remove(key);
    }
    Value::Object(intent)
}

/// Persists a claim intent before dispatch. Current authorization and target-side
/// fencing remain mandatory before the effect is sent.
pub fn claim_operation(
    ledger: &Value,
    input: &Value,
    expected_revision: &Value,
    executor_generation: &Value,
) -> TransitionResult {
    let reject = |reason: &str| TransitionResult::rejected(ledger.clone(), reason);
    if canonicalize(ledger).is_err() || canonicalize(input).is_err() {
        return reject("operation_binding_mismatch");
    }
    if !valid_ledger(ledger)
        || !claim_shape(input)
        || !is_safe_non_negative_integer(expected_revision)
        || !is_safe_non_negative_integer(executor_generation)
    {
        return reject("operation_binding_mismatch");
    }
    let (expected_revision, generation) = (int(expected_revision), int(executor_generation));
    if int(&ledger["revision"]) != expected_revision {
        return reject("revision_conflict");
    }
    let attempt = &input["attempt"];
    if int(&ledger["executor_generation"]) != generation || int(&attempt["executor_generation"]) != generation {
        return reject("executor_stale");
    }
    let time = &input["evaluation_time"];
    if !correlation(ledger, input)
        || attempt["operation_id"] != input["operation_id"]
        || attempt["dispatch_state"] != "claimed"
        || !attempt["last_observation_ref"].is_null()
        || cmp_times(&attempt["started_at"], time) != Some(Ordering::Equal)
    {
        return reject("operation_binding_mismatch");
    }
    if cmp_times(time, &input["deadline"]) != Some(Ordering::Less) {
        return reject("deadline_exceeded");
    }
    let intent = stable_intent(input);
    let operations = arr(&ledger["operations"]);
    let existing = operations
        .iter()
        .find(|op| op["intent"]["operation_id"] == intent["operation_id"]);
    if operations.iter().any(|op| {
        op["intent"]["operation_id"] != intent["operation_id"]
            && arr(&op["attempts"])
                .iter()
                .any(|a| a["attempt_id"] == attempt["attempt_id"])
    }) {
        return reject("operation_binding_mismatch");
    }
    if existing.is_some_and(|op| !same(&op["intent"], &intent)) {
        return reject("operation_binding_mismatch");
    }
    if operations.iter().any(|op| {
        op["intent"]["operation_id"] != intent["operation_id"]
            && !intent["idempotency_key"].is_null()
            && op["intent"]["idempotency_key"] == intent["idempotency_key"]
            && op["intent"]["idempotency_scope"] == intent["idempotency_scope"]
            && same(
                &op["intent"]["provider_idempotency_ref"],
                &intent["provider_idempotency_ref"],
            )
    }) {
        return reject("operation_binding_mismatch");
    }
    if !intent["compensates_operation_id"].is_null() {
        let original = operations
            .iter()
            .find(|op| op["intent"]["operation_id"] == intent["compensates_operation_id"]);
        let valid = original.is_some_and(|o| {
            o["intent"]["operation_id"] != intent["operation_id"]
                && matches!(derive_outcome(o).0, "confirmed" | "partial")
                && o["intent"]["action_digest"] != intent["action_digest"]
        });
        if !valid {
            return reject("operation_binding_mismatch");
        }
    }
    let proof = &input["provider_observation"];
    if intent["recovery_strategy"] == "idempotent_retry" {
        let ok = !proof.is_null()
            && trusted(ledger, proof, time)
            && proof["same_payload_enforced"] == true
            && same(&proof["provider_contract_ref"], &intent["provider_idempotency_ref"])
            && proof["key"] == intent["idempotency_key"]
            && proof["scope"] == intent["idempotency_scope"]
            && proof["operation_id"] == intent["operation_id"]
            && proof["action_digest"] == intent["action_digest"]
            && within(time, &proof["not_before"], &proof["retention_expires_at"]);
        if !ok {
            return reject("retry_unsafe");
        }
    }
    if let Some(existing) = existing {
        let (outcome, conflict) = derive_outcome(existing);
        if conflict || outcome == "confirmed" || outcome == "partial" {
            return reject("retry_unsafe");
        }
        if outcome == "unknown" && intent["recovery_strategy"] != "idempotent_retry" {
            return reject("retry_unsafe");
        }
        let attempts = arr(&existing["attempts"]);
        if let Some(duplicate) = attempts.iter().find(|a| a["attempt_id"] == attempt["attempt_id"]) {
            if duplicate["dispatch_state"] != "claimed"
                || int(&duplicate["executor_generation"]) != generation
                || cmp_times(&duplicate["started_at"], &attempt["started_at"]) != Some(Ordering::Equal)
            {
                return reject("operation_binding_mismatch");
            }
            return TransitionResult::accepted(
                ledger.clone(),
                vec!["obtain_current_authorization".into(), "recover_existing_claim".into()],
            );
        }
        if i64::try_from(attempts.len()).unwrap_or(i64::MAX) >= int(&intent["max_attempts"])
            || intent["recovery_strategy"] == "no_retry"
        {
            return reject("retry_unsafe");
        }
        if attempts.last().is_some_and(|a| a["dispatch_state"] == "claimed") {
            return reject("operation_in_flight");
        }
        if existing["next_eligible_at"].is_null()
            || cmp_times(time, &existing["next_eligible_at"]) == Some(Ordering::Less)
        {
            return reject("retry_not_due");
        }
    }
    if int(&ledger["revision"]) + 1 > MAX_SAFE_INTEGER || (existing.is_none() && operations.len() >= 128) {
        return reject("operation_ledger_limit");
    }
    let mut next = ledger.clone();
    let ops = next["operations"].as_array_mut().expect("validated");
    match ops
        .iter_mut()
        .find(|op| op["intent"]["operation_id"] == intent["operation_id"])
    {
        Some(op) => {
            op["attempts"].as_array_mut().expect("validated").push(attempt.clone());
            op["next_eligible_at"] = Value::Null;
        }
        None => ops.push(json!({
            "intent": intent, "attempts": [attempt], "observations": [],
            "outcome": "not_dispatched", "next_eligible_at": null, "conflict": false,
        })),
    }
    next["revision"] = json!(int(&ledger["revision"]) + 1);
    let mut obligations = vec![
        "enforce_provider_fence".to_owned(),
        "obtain_current_authorization".into(),
        "persist_operation_claim".into(),
    ];
    if !proof.is_null() {
        obligations.push("record_provider_idempotency_evidence".into());
    }
    TransitionResult::accepted(next, sorted_strings(obligations))
}

/// Appends a verified effect fact (including late facts) and re-derives the outcome
/// and retry eligibility. Never transfers executor ownership or settles budgets.
pub fn record_effect_observation(ledger: &Value, observed: &Value, expected_revision: &Value) -> TransitionResult {
    let reject = |reason: &str| TransitionResult::rejected(ledger.clone(), reason);
    if canonicalize(ledger).is_err() || canonicalize(observed).is_err() {
        return reject("operation_binding_mismatch");
    }
    if !valid_ledger(ledger) || !observation(observed) || !is_safe_non_negative_integer(expected_revision) {
        return reject("operation_binding_mismatch");
    }
    if int(&ledger["revision"]) != int(expected_revision) {
        return reject("revision_conflict");
    }
    let operations = arr(&ledger["operations"]);
    let index = operations
        .iter()
        .position(|op| op["intent"]["operation_id"] == observed["operation_id"]);
    let op = index.map(|i| &operations[i]);
    let attempted = op.and_then(|op| {
        arr(&op["attempts"])
            .iter()
            .find(|a| a["attempt_id"] == observed["attempt_id"])
    });
    let (Some(index), Some(op), Some(attempted)) = (index, op, attempted) else {
        return reject("operation_binding_mismatch");
    };
    if !correlation(ledger, &op["intent"])
        || observed["contract_id"] != ledger["contract_id"]
        || observed["run_id"] != ledger["run_id"]
        || observed["tenant_id"] != ledger["tenant_id"]
        || observed["action_digest"] != op["intent"]["action_digest"]
        || int(&observed["executor_generation"]) != int(&attempted["executor_generation"])
        || cmp_times(&observed["observed_at"], &attempted["started_at"]) == Some(Ordering::Less)
        || !trusted(ledger, observed, &observed["evaluation_time"])
    {
        return reject("operation_binding_mismatch");
    }
    if let Some(duplicate) = operations
        .iter()
        .flat_map(|o| arr(&o["observations"]))
        .find(|o| o["observation_id"] == observed["observation_id"])
    {
        return if same(duplicate, observed) {
            TransitionResult::accepted(ledger.clone(), vec!["observation_already_recorded".into()])
        } else {
            reject("observation_binding_mismatch")
        };
    }
    if int(&ledger["revision"]) + 1 > MAX_SAFE_INTEGER || arr(&op["observations"]).len() >= 128 {
        return reject("operation_ledger_limit");
    }
    let mut next = ledger.clone();
    let updated = &mut next["operations"][index];
    updated["observations"]
        .as_array_mut()
        .expect("validated")
        .push(observed.clone());
    let facts: Vec<Value> = arr(&updated["observations"])
        .iter()
        .filter(|o| o["attempt_id"] == observed["attempt_id"])
        .cloned()
        .collect();
    let finals: Vec<&Value> = facts
        .iter()
        .filter(|o| o["finality"] == "definitive" && o["outcome"] != "unknown")
        .collect();
    let mut pool: Vec<&Value> = if finals.is_empty() {
        facts.iter().collect()
    } else {
        finals.clone()
    };
    pool.sort_by(|a, b| match cmp_times(&b["observed_at"], &a["observed_at"]) {
        Some(Ordering::Equal) | None => utf16_cmp(s(&a["observation_id"]), s(&b["observation_id"])),
        Some(order) => order,
    });
    let latest_ref = pool[0]["evidence_ref"].clone();
    let settled = !finals.is_empty();
    if let Some(target) = updated["attempts"]
        .as_array_mut()
        .expect("validated")
        .iter_mut()
        .find(|a| a["attempt_id"] == observed["attempt_id"])
    {
        target["last_observation_ref"] = latest_ref;
        target["dispatch_state"] = json!(if settled { "settled" } else { "dispatched" });
    }
    let (outcome, conflict) = derive_outcome(updated);
    updated["outcome"] = json!(outcome);
    updated["conflict"] = json!(conflict);
    updated["next_eligible_at"] = retry_eligible_at(updated).map_or(Value::Null, Value::String);
    let recovery = updated["intent"]["recovery_strategy"].clone();
    next["revision"] = json!(int(&ledger["revision"]) + 1);
    let mut obligations = vec![
        "persist_effect_observation".to_owned(),
        "verify_usage_before_settlement".into(),
    ];
    if int(&observed["executor_generation"]) != int(&ledger["executor_generation"]) {
        obligations.push("late_fact_no_dispatch".into());
    }
    if conflict {
        obligations.push("escalate_conflicting_effect_evidence".into());
    } else if outcome == "unknown" || outcome == "partial" {
        obligations.push(
            if recovery == "query" {
                "query_external_outcome"
            } else {
                "manual_reconcile_effect"
            }
            .into(),
        );
    }
    TransitionResult::accepted(next, sorted_strings(obligations))
}
