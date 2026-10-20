//! Durable run lifecycle and checkpoint resume.
//!
//! Every accepted lifecycle event advances both the revision and the executor
//! generation, invalidating observations and ownership from the previous generation.
//! Completion requires every declared effect to be confirmed and every child run
//! settled; cancellation completes only after a verified dispatch-stop that covers
//! all children. Resume re-checks current controls and never resets the original
//! budgets or held reservations.

use contextos_contract::canonical::{canonicalize, sha256_canonical};
use contextos_contract::shape::{
    bounded_array, exact_keys, is_artifact_ref, is_digest, is_identifier, is_safe_non_negative_integer, is_timestamp,
};
use contextos_contract::validation::is_contract_timestamp;
use serde_json::{Map, Value, json};

use crate::authorization::valid_principal;
use crate::support::{
    MAX_SAFE_INTEGER, TransitionResult, cmp_times, encoded, js_sorted, list, s, same, sorted_strings, unique_ids,
    verification_status, within,
};

const STATUSES: [&str; 10] = [
    "created",
    "running",
    "waiting_approval",
    "waiting_external",
    "suspended",
    "cancel_requested",
    "completed",
    "failed",
    "cancelled",
    "expired",
];
const TERMINAL: [&str; 4] = ["completed", "failed", "cancelled", "expired"];
const EVENT_KINDS: [&str; 10] = [
    "start",
    "resume",
    "wait_approval",
    "wait_external",
    "suspend",
    "request_cancel",
    "acknowledge_cancel",
    "complete",
    "fail",
    "expire",
];

/// The run lifecycle transition table.
pub fn next_status(status: &str, kind: &str) -> Option<&'static str> {
    Some(match (status, kind) {
        ("created", "start") => "running",
        ("created" | "running" | "waiting_approval" | "waiting_external" | "suspended", "request_cancel") => {
            "cancel_requested"
        }
        (
            "created" | "running" | "waiting_approval" | "waiting_external" | "suspended" | "cancel_requested",
            "expire",
        ) => "expired",
        (
            "created" | "running" | "waiting_approval" | "waiting_external" | "suspended" | "cancel_requested",
            "fail",
        ) => "failed",
        ("running", "wait_approval") => "waiting_approval",
        ("running", "wait_external") => "waiting_external",
        ("running", "suspend") => "suspended",
        ("running", "complete") => "completed",
        ("waiting_approval" | "waiting_external" | "suspended", "resume") => "running",
        ("cancel_requested", "acknowledge_cancel") => "cancelled",
        _ => return None,
    })
}

fn status_known(value: &Value) -> bool {
    value.as_str().is_some_and(|v| STATUSES.contains(&v))
}

const OBSERVATION_KEYS: [&str; 8] = [
    "run_id",
    "tenant_id",
    "executor_generation",
    "observer",
    "verification_status",
    "evidence_ref",
    "observed_at",
    "valid_until",
];

fn keys_with(base: &[&'static str], extra: &[&'static str]) -> Vec<&'static str> {
    base.iter().chain(extra.iter()).copied().collect()
}

fn run_observation_fields(o: &Map<String, Value>) -> bool {
    is_identifier(&o["run_id"])
        && is_identifier(&o["tenant_id"])
        && is_safe_non_negative_integer(&o["executor_generation"])
        && valid_principal(&o["observer"])
        && verification_status(&o["verification_status"])
        && is_artifact_ref(&o["evidence_ref"])
        && is_timestamp(&o["observed_at"])
        && is_timestamp(&o["valid_until"])
}

fn preconditions(value: &Value) -> bool {
    exact_keys(value, &keys_with(&OBSERVATION_KEYS, &["admission_ref", "checks"])).is_some_and(|o| {
        run_observation_fields(o)
            && is_artifact_ref(&o["admission_ref"])
            && exact_keys(&o["checks"], &["admission", "authority", "boundary", "budget"]).is_some_and(|c| {
                c.values()
                    .all(|v| matches!(v.as_str(), Some("ready" | "blocked" | "unknown")))
            })
    })
}

fn stop_observation(value: &Value) -> bool {
    exact_keys(
        value,
        &keys_with(
            &OBSERVATION_KEYS,
            &["child_run_ids", "dispatch_stopped", "children_stop_recorded"],
        ),
    )
    .is_some_and(|o| {
        run_observation_fields(o)
            && unique_ids(&o["child_run_ids"])
            && o["dispatch_stopped"].is_boolean()
            && o["children_stop_recorded"].is_boolean()
    })
}

pub(crate) fn valid_run_state(value: &Value) -> bool {
    exact_keys(
        value,
        &[
            "contract_id",
            "run_id",
            "tenant_id",
            "status",
            "revision",
            "executor_generation",
            "deadline",
            "admission_ref",
            "trusted_observer",
            "outstanding_effects",
            "child_run_ids",
            "dispatch_stop_acknowledged",
            "last_event_id",
        ],
    )
    .is_some_and(|o| {
        ["contract_id", "run_id", "tenant_id"]
            .iter()
            .all(|k| is_identifier(&o[*k]))
            && status_known(&o["status"])
            && is_safe_non_negative_integer(&o["revision"])
            && is_safe_non_negative_integer(&o["executor_generation"])
            && is_timestamp(&o["deadline"])
            && is_artifact_ref(&o["admission_ref"])
            && valid_principal(&o["trusted_observer"])
            && bounded_array(&o["outstanding_effects"], 0, 128, |e| {
                exact_keys(e, &["operation_id", "outcome"]).is_some_and(|e| {
                    is_identifier(&e["operation_id"])
                        && matches!(
                            e["outcome"].as_str(),
                            Some("not_dispatched" | "confirmed" | "not_applied" | "partial" | "unknown")
                        )
                })
            })
            && o["outstanding_effects"].as_array().is_some_and(|effects| {
                let ids: std::collections::HashSet<String> =
                    effects.iter().map(|e| encoded(&e["operation_id"])).collect();
                ids.len() == effects.len()
            })
            && unique_ids(&o["child_run_ids"])
            && o["dispatch_stop_acknowledged"].is_boolean()
            && (o["last_event_id"].is_null() || is_identifier(&o["last_event_id"]))
    })
}

fn valid_event(value: &Value) -> bool {
    exact_keys(
        value,
        &[
            "event_id",
            "run_id",
            "tenant_id",
            "kind",
            "expected_revision",
            "executor_generation",
            "preconditions",
            "dispatch_stop_ack",
        ],
    )
    .is_some_and(|o| {
        ["event_id", "run_id", "tenant_id"]
            .iter()
            .all(|k| is_identifier(&o[*k]))
            && o["kind"].as_str().is_some_and(|k| EVENT_KINDS.contains(&k))
            && is_safe_non_negative_integer(&o["expected_revision"])
            && is_safe_non_negative_integer(&o["executor_generation"])
            && (o["preconditions"].is_null() || preconditions(&o["preconditions"]))
            && (o["dispatch_stop_ack"].is_null() || stop_observation(&o["dispatch_stop_ack"]))
    })
}

/// Integer view of a value already validated as a safe integer.
pub(crate) fn int(value: &Value) -> i64 {
    contextos_contract::shape::as_safe_integer(value).unwrap_or(-1)
}

/// Intended immutable lifecycle transition for one authenticated controller event.
pub fn transition_run(state: &Value, event: &Value, evaluation_time: &Value) -> TransitionResult {
    let reject = |reason: &str| TransitionResult::rejected(state.clone(), reason);
    if canonicalize(state).is_err() || canonicalize(event).is_err() {
        return reject("transition_invalid");
    }
    if !valid_run_state(state) || !valid_event(event) || !evaluation_time.as_str().is_some_and(is_contract_timestamp) {
        return reject("transition_invalid");
    }
    let status = s(&state["status"]);
    let kind = s(&event["kind"]);
    if TERMINAL.contains(&status) {
        return reject("transition_invalid");
    }
    if int(&event["expected_revision"]) != int(&state["revision"]) {
        return reject("revision_conflict");
    }
    if int(&event["executor_generation"]) != int(&state["executor_generation"]) {
        return reject("executor_stale");
    }
    if event["run_id"] != state["run_id"] || event["tenant_id"] != state["tenant_id"] {
        return reject("transition_invalid");
    }
    let Some(destination) = next_status(status, kind) else {
        return reject("transition_invalid");
    };
    let expired = cmp_times(evaluation_time, &state["deadline"]) != Some(std::cmp::Ordering::Less);
    if kind == "expire" && !expired {
        return reject("transition_invalid");
    }
    if expired && !["expire", "fail", "request_cancel", "acknowledge_cancel"].contains(&kind) {
        return reject("deadline_exceeded");
    }
    let verified = |o: &Value| {
        o["verification_status"] == "verified"
            && o["run_id"] == state["run_id"]
            && o["tenant_id"] == state["tenant_id"]
            && int(&o["executor_generation"]) == int(&state["executor_generation"])
            && o["observer"]["tenant_id"] == state["tenant_id"]
            && same(&o["observer"], &state["trusted_observer"])
            && within(evaluation_time, &o["observed_at"], &o["valid_until"])
    };
    if kind == "start" || kind == "resume" {
        let observed = &event["preconditions"];
        if observed.is_null() || !verified(observed) {
            return reject("authority_stale");
        }
        if !same(&observed["admission_ref"], &state["admission_ref"]) {
            return reject("artifact_binding_mismatch");
        }
        let checks = &observed["checks"];
        if checks["admission"] != "ready" {
            return reject("transition_invalid");
        }
        if checks["authority"] != "ready" {
            return reject("authority_stale");
        }
        if checks["boundary"] != "ready" {
            return reject("boundary_not_ready");
        }
        if checks["budget"] != "ready" {
            return reject("budget_exhausted");
        }
    }
    let effects = state["outstanding_effects"].as_array().expect("validated");
    if kind == "complete" {
        if effects.iter().any(|e| e["outcome"] != "confirmed") {
            return reject("required_effect_unsatisfied");
        }
        if state["child_run_ids"].as_array().is_some_and(|c| !c.is_empty()) {
            return reject("children_unsettled");
        }
    }
    if kind == "acknowledge_cancel" {
        let observed = &event["dispatch_stop_ack"];
        if observed.is_null()
            || !verified(observed)
            || observed["dispatch_stopped"] != true
            || observed["children_stop_recorded"] != true
            || !same(
                &js_sorted(&observed["child_run_ids"]),
                &js_sorted(&state["child_run_ids"]),
            )
        {
            return reject("dispatch_stop_unverified");
        }
    }
    let (revision, generation) = (int(&state["revision"]), int(&state["executor_generation"]));
    if revision + 1 > MAX_SAFE_INTEGER || generation + 1 > MAX_SAFE_INTEGER {
        return reject("counter_exhausted");
    }
    let mut next = state.clone();
    next["status"] = json!(destination);
    next["revision"] = json!(revision + 1);
    next["executor_generation"] = json!(generation + 1);
    next["last_event_id"] = event["event_id"].clone();
    if kind == "acknowledge_cancel" {
        next["dispatch_stop_acknowledged"] = json!(true);
    }
    let mut obligations = vec!["persist_event".to_owned(), "apply_executor_fence".to_owned()];
    if destination == "running" {
        obligations.push("acquire_executor_generation".into());
    } else {
        obligations.push("stop_new_dispatch".into());
        obligations.push("fence_executor".into());
    }
    if ["cancel_requested", "cancelled", "failed", "expired"].contains(&destination) {
        obligations.push("cancel_children".into());
        if effects
            .iter()
            .any(|e| e["outcome"] == "unknown" || e["outcome"] == "partial")
        {
            obligations.push("reconcile_outstanding_effects".into());
        }
    }
    TransitionResult::accepted(next, sorted_strings(obligations))
}

// ─── Checkpoint resume ─────────────────────────────────────────────────────

const RESUME_CHECKS: [&str; 6] = [
    "contract_support",
    "authority",
    "approval",
    "boundary",
    "external_preconditions",
    "budget",
];
const RESUME_OBSERVATION_KEYS: [&str; 5] = [
    "verification_status",
    "observer",
    "evidence_ref",
    "observed_at",
    "valid_until",
];
const COUNTER_KEYS: [&str; 4] = ["tokens", "tool_calls", "replans", "cost_units"];

pub(crate) fn resource_counters(value: &Value) -> bool {
    exact_keys(value, &COUNTER_KEYS).is_some_and(|o| o.values().all(is_safe_non_negative_integer))
}

pub(crate) fn cost_unit(value: &Value) -> bool {
    exact_keys(value, &["currency", "units_per_cent"]).is_some_and(|o| {
        o["currency"]
            .as_str()
            .is_some_and(|c| c.len() == 3 && c.bytes().all(|b| b.is_ascii_uppercase()))
            && is_safe_non_negative_integer(&o["units_per_cent"])
            && {
                let digits = int(&o["units_per_cent"]).to_string();
                digits.starts_with('1') && digits[1..].bytes().all(|b| b == b'0')
            }
    })
}

fn counters_fit(ceiling: &Value, used: &Value, reserved: &Value) -> bool {
    COUNTER_KEYS.iter().all(|k| {
        let (c, u, r) = (int(&ceiling[*k]), int(&used[*k]), int(&reserved[*k]));
        u <= c && r <= c - u
    })
}

fn budget_snapshot(value: &Value) -> bool {
    exact_keys(
        value,
        &[
            "ledger_revision",
            "cost_unit",
            "ceiling",
            "used",
            "reserved",
            "deadline",
        ],
    )
    .is_some_and(|o| {
        is_safe_non_negative_integer(&o["ledger_revision"])
            && cost_unit(&o["cost_unit"])
            && resource_counters(&o["ceiling"])
            && resource_counters(&o["used"])
            && resource_counters(&o["reserved"])
            && counters_fit(&o["ceiling"], &o["used"], &o["reserved"])
            && is_timestamp(&o["deadline"])
    })
}

fn refs(value: &Value) -> bool {
    list(value, is_artifact_ref)
}

fn non_empty(value: &Value) -> bool {
    value.as_array().is_some_and(|a| !a.is_empty())
}

fn checkpoint(value: &Value) -> bool {
    exact_keys(
        value,
        &[
            "checkpoint_version",
            "checkpoint_id",
            "revision",
            "contract_id",
            "run_id",
            "tenant_id",
            "contract_ref",
            "pack_ref",
            "policy_refs",
            "tool_registry_ref",
            "profile_registry_ref",
            "release_refs",
            "run_state",
            "operation_ledger_ref",
            "budget_ledger_ref",
            "operation_ids",
            "budget_snapshot",
            "pending_approval_refs",
            "pending_task_refs",
            "cancellation_state",
            "executor_generation",
            "require_target_fencing",
            "digest",
        ],
    )
    .is_some_and(|o| {
        o["checkpoint_version"] == "contextos.execution_checkpoint.v1"
            && ["checkpoint_id", "contract_id", "run_id", "tenant_id"]
                .iter()
                .all(|k| is_identifier(&o[*k]))
            && is_safe_non_negative_integer(&o["revision"])
            && [
                "contract_ref",
                "pack_ref",
                "tool_registry_ref",
                "profile_registry_ref",
                "operation_ledger_ref",
                "budget_ledger_ref",
            ]
            .iter()
            .all(|k| is_artifact_ref(&o[*k]))
            && refs(&o["policy_refs"])
            && non_empty(&o["policy_refs"])
            && refs(&o["release_refs"])
            && non_empty(&o["release_refs"])
            && valid_run_state(&o["run_state"])
            && unique_ids(&o["operation_ids"])
            && budget_snapshot(&o["budget_snapshot"])
            && refs(&o["pending_approval_refs"])
            && refs(&o["pending_task_refs"])
            && matches!(
                o["cancellation_state"].as_str(),
                Some("none" | "requested" | "acknowledged")
            )
            && is_safe_non_negative_integer(&o["executor_generation"])
            && o["require_target_fencing"].is_boolean()
            && is_digest(&o["digest"])
    })
}

fn resume_observation_fields(o: &Map<String, Value>) -> bool {
    verification_status(&o["verification_status"])
        && valid_principal(&o["observer"])
        && is_artifact_ref(&o["evidence_ref"])
        && is_timestamp(&o["observed_at"])
        && is_timestamp(&o["valid_until"])
}

fn store_observation(value: &Value) -> bool {
    exact_keys(
        value,
        &keys_with(
            &RESUME_OBSERVATION_KEYS,
            &[
                "checkpoint_id",
                "checkpoint_revision",
                "checkpoint_digest",
                "contract_id",
                "run_id",
                "tenant_id",
                "executor_id",
                "executor_generation",
                "lease_ref",
                "target_fencing",
                "run_status",
                "cancellation_state",
                "operation_ledger_ref",
                "budget_ledger_ref",
                "operation_ids",
                "budget_snapshot",
            ],
        ),
    )
    .is_some_and(|o| {
        resume_observation_fields(o)
            && ["checkpoint_id", "contract_id", "run_id", "tenant_id", "executor_id"]
                .iter()
                .all(|k| is_identifier(&o[*k]))
            && is_safe_non_negative_integer(&o["checkpoint_revision"])
            && is_digest(&o["checkpoint_digest"])
            && is_safe_non_negative_integer(&o["executor_generation"])
            && ["lease_ref", "operation_ledger_ref", "budget_ledger_ref"]
                .iter()
                .all(|k| is_artifact_ref(&o[*k]))
            && matches!(
                o["target_fencing"].as_str(),
                Some("enforced" | "unsupported" | "unknown")
            )
            && status_known(&o["run_status"])
            && matches!(
                o["cancellation_state"].as_str(),
                Some("none" | "requested" | "acknowledged")
            )
            && unique_ids(&o["operation_ids"])
            && budget_snapshot(&o["budget_snapshot"])
    })
}

fn artifact_observation(value: &Value) -> bool {
    exact_keys(
        value,
        &keys_with(&RESUME_OBSERVATION_KEYS, &["artifact_ref", "actual_sha256"]),
    )
    .is_some_and(|o| {
        resume_observation_fields(o) && is_artifact_ref(&o["artifact_ref"]) && is_digest(&o["actual_sha256"])
    })
}

fn control_observation(value: &Value) -> bool {
    exact_keys(
        value,
        &keys_with(
            &RESUME_OBSERVATION_KEYS,
            &[
                "check",
                "status",
                "run_id",
                "tenant_id",
                "checkpoint_digest",
                "executor_generation",
            ],
        ),
    )
    .is_some_and(|o| {
        resume_observation_fields(o)
            && o["check"].as_str().is_some_and(|c| RESUME_CHECKS.contains(&c))
            && matches!(o["status"].as_str(), Some("ready" | "blocked" | "unknown"))
            && is_identifier(&o["run_id"])
            && is_identifier(&o["tenant_id"])
            && is_digest(&o["checkpoint_digest"])
            && is_safe_non_negative_integer(&o["executor_generation"])
    })
}

fn same_ref_set(left: &Value, right: &Value) -> bool {
    let (Some(l), Some(r)) = (left.as_array(), right.as_array()) else {
        return false;
    };
    let a: std::collections::HashSet<String> = l.iter().map(encoded).collect();
    let b: std::collections::HashSet<String> = r.iter().map(encoded).collect();
    a.len() == l.len() && b.len() == r.len() && a == b
}

fn pinned_refs(saved: &Value) -> Vec<Value> {
    let mut all: Vec<&Value> = vec![&saved["contract_ref"], &saved["pack_ref"]];
    all.extend(saved["policy_refs"].as_array().into_iter().flatten());
    all.push(&saved["tool_registry_ref"]);
    all.push(&saved["profile_registry_ref"]);
    all.extend(saved["release_refs"].as_array().into_iter().flatten());
    all.push(&saved["operation_ledger_ref"]);
    all.push(&saved["budget_ledger_ref"]);
    all.extend(saved["pending_approval_refs"].as_array().into_iter().flatten());
    all.extend(saved["pending_task_refs"].as_array().into_iter().flatten());
    let mut out: Vec<(String, Value)> = Vec::new();
    for r in all {
        let key = encoded(r);
        match out.iter_mut().find(|(k, _)| *k == key) {
            Some(slot) => slot.1 = r.clone(),
            None => out.push((key, r.clone())),
        }
    }
    out.into_iter().map(|(_, v)| v).collect()
}

/// A resume request that is not plain JSON or has no checkpoint cannot be answered
/// with a fabricated empty state.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResumeError {
    #[error("Resume request must be plain JSON")]
    NotPlainJson,
    #[error("Resume request must include its checkpoint")]
    MissingCheckpoint,
}

/// Digest that content-addresses a checkpoint: everything except `digest` itself.
pub fn checkpoint_digest(checkpoint: &Value) -> Option<String> {
    let mut payload = checkpoint.as_object()?.clone();
    payload.remove("digest");
    sha256_canonical(&json!({"domain": "contextos.checkpoint.v1", "payload": payload})).ok()
}

/// Validates a restore intent against current verified store, artifact and control
/// observations. Ownership CAS and target fencing must still be enforced atomically
/// by the deployment.
pub fn validate_resume(input: &Value) -> Result<TransitionResult, ResumeError> {
    if canonicalize(input).is_err() {
        return Err(ResumeError::NotPlainJson);
    }
    let Some(saved) = input
        .as_object()
        .and_then(|o| o.get("checkpoint"))
        .filter(|c| !c.is_null())
    else {
        return Err(ResumeError::MissingCheckpoint);
    };
    let reject = |reason: &str, obligations: Vec<String>| TransitionResult {
        status: "rejected".into(),
        state: saved.clone(),
        obligations: Some(obligations),
        reason_codes: Some(vec![reason.into()]),
    };
    if saved.is_object()
        && saved["checkpoint_version"].is_string()
        && saved["checkpoint_version"] != "contextos.execution_checkpoint.v1"
    {
        return Ok(reject("checkpoint_version_unsupported", vec![]));
    }
    let shape_ok = exact_keys(
        input,
        &[
            "checkpoint",
            "run_id",
            "tenant_id",
            "executor_id",
            "executor_generation",
            "expected_revision",
            "evaluation_time",
            "trusted_observers",
            "required_policy_refs",
            "store_observation",
            "artifact_observations",
            "current_observations",
        ],
    )
    .is_some_and(|o| {
        checkpoint(saved)
            && ["run_id", "tenant_id", "executor_id"]
                .iter()
                .all(|k| is_identifier(&o[*k]))
            && is_safe_non_negative_integer(&o["executor_generation"])
            && is_safe_non_negative_integer(&o["expected_revision"])
            && is_timestamp(&o["evaluation_time"])
            && list(&o["trusted_observers"], valid_principal)
            && refs(&o["required_policy_refs"])
            && store_observation(&o["store_observation"])
            && list(&o["artifact_observations"], artifact_observation)
            && list(&o["current_observations"], control_observation)
    });
    if !shape_ok {
        return Ok(reject("checkpoint_invalid", vec![]));
    }
    if saved["digest"].as_str() != checkpoint_digest(saved).as_deref() {
        return Ok(reject("artifact_binding_mismatch", vec![]));
    }
    let store = &input["store_observation"];
    let state = &saved["run_state"];
    let time = &input["evaluation_time"];
    let trusted = input["trusted_observers"].as_array().expect("validated");
    let verified = |o: &Value| {
        o["verification_status"] == "verified"
            && o["observer"]["tenant_id"] == input["tenant_id"]
            && trusted.iter().any(|t| same(t, &o["observer"]))
            && within(time, &o["observed_at"], &o["valid_until"])
    };
    if !verified(store)
        || store["checkpoint_id"] != saved["checkpoint_id"]
        || store["checkpoint_digest"] != saved["digest"]
    {
        return Ok(reject("checkpoint_invalid", vec![]));
    }
    if int(&input["expected_revision"]) != int(&saved["revision"])
        || int(&store["checkpoint_revision"]) != int(&input["expected_revision"])
    {
        return Ok(reject("revision_conflict", vec![]));
    }
    if int(&store["executor_generation"]) != int(&input["executor_generation"])
        || int(&input["executor_generation"]) < int(&saved["executor_generation"])
        || store["executor_id"] != input["executor_id"]
    {
        return Ok(reject("executor_stale", vec![]));
    }
    if input["tenant_id"] != saved["tenant_id"]
        || input["run_id"] != saved["run_id"]
        || store["contract_id"] != saved["contract_id"]
        || store["run_id"] != saved["run_id"]
        || store["tenant_id"] != saved["tenant_id"]
        || state["contract_id"] != saved["contract_id"]
        || state["run_id"] != saved["run_id"]
        || state["tenant_id"] != saved["tenant_id"]
        || int(&state["executor_generation"]) != int(&saved["executor_generation"])
    {
        return Ok(reject("checkpoint_invalid", vec![]));
    }
    let terminal = |v: &Value| TERMINAL.contains(&s(v));
    if saved["cancellation_state"] != "none"
        || store["cancellation_state"] != "none"
        || terminal(&state["status"])
        || terminal(&store["run_status"])
        || state["status"] == "cancel_requested"
        || store["run_status"] != state["status"]
    {
        return Ok(reject("transition_invalid", vec![]));
    }
    let less = Some(std::cmp::Ordering::Less);
    if cmp_times(time, &state["deadline"]) != less
        || cmp_times(time, &saved["budget_snapshot"]["deadline"]) != less
        || cmp_times(&saved["budget_snapshot"]["deadline"], &state["deadline"]) == Some(std::cmp::Ordering::Greater)
    {
        return Ok(reject("deadline_exceeded", vec![]));
    }
    if !same_ref_set(&saved["policy_refs"], &input["required_policy_refs"]) {
        return Ok(reject(
            "policy_migration_required",
            vec!["migrate_policy_and_reauthorize".into()],
        ));
    }
    if !same(&store["operation_ledger_ref"], &saved["operation_ledger_ref"])
        || !same(&store["budget_ledger_ref"], &saved["budget_ledger_ref"])
        || !same(&js_sorted(&store["operation_ids"]), &js_sorted(&saved["operation_ids"]))
        || !same(&store["budget_snapshot"], &saved["budget_snapshot"])
    {
        return Ok(reject("artifact_binding_mismatch", vec![]));
    }
    let pins = pinned_refs(saved);
    if pins.len() > 128 {
        return Ok(reject("checkpoint_invalid", vec![]));
    }
    let artifacts = input["artifact_observations"].as_array().expect("validated");
    for r in &pins {
        let matches: Vec<&Value> = artifacts.iter().filter(|o| same(&o["artifact_ref"], r)).collect();
        if matches.len() != 1 || !verified(matches[0]) || matches[0]["actual_sha256"] != r["sha256"] {
            return Ok(reject("artifact_binding_mismatch", vec![]));
        }
    }
    let failures = [
        ("contract_support", "checkpoint_version_unsupported"),
        ("authority", "authority_stale"),
        ("approval", "approval_expired"),
        ("boundary", "boundary_not_ready"),
        ("external_preconditions", "precondition_stale"),
        ("budget", "budget_exhausted"),
    ];
    let controls = input["current_observations"].as_array().expect("validated");
    for (check, failure) in failures {
        let matches: Vec<&Value> = controls.iter().filter(|o| o["check"] == check).collect();
        let ok = matches.len() == 1 && {
            let o = matches[0];
            verified(o)
                && o["status"] == "ready"
                && o["checkpoint_digest"] == saved["digest"]
                && int(&o["executor_generation"]) == int(&input["executor_generation"])
                && o["run_id"] == saved["run_id"]
                && o["tenant_id"] == saved["tenant_id"]
        };
        if !ok {
            return Ok(reject(failure, vec![]));
        }
    }
    let fencing = s(&store["target_fencing"]);
    if fencing == "unknown" || (saved["require_target_fencing"] == true && fencing != "enforced") {
        return Ok(reject(
            "executor_stale",
            vec!["establish_required_target_fencing".into()],
        ));
    }
    let mut obligations = vec![
        "atomically_claim_executor_under_verified_revision".to_owned(),
        "recheck_before_bound_dispatch".to_owned(),
        "restore_under_current_fence".to_owned(),
    ];
    if fencing == "unsupported" {
        obligations.push("target_fencing_unavailable_use_idempotency_and_reconciliation".into());
    }
    Ok(TransitionResult::accepted(saved.clone(), sorted_strings(obligations)))
}
