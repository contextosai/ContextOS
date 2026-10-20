//! Shared budget ledger: conserved accounting across root, child, retry and replan
//! work.
//!
//! Capacity is reserved before spending and settled only from verified usage.
//! Unknown usage keeps its reservation held; terminal known usage releases the
//! remainder. Every mutation carries a stable id: replaying it returns the original
//! receipt against the *current* ledger, so a retried request can neither double
//! charge nor mint capacity. Original limits and opening usage are content-addressed,
//! so resume can never silently reset them.

use contextos_contract::canonical::{js_number, sha256_canonical};
use contextos_contract::shape::{
    exact_keys, is_artifact_ref, is_digest, is_identifier, is_safe_non_negative_integer, is_timestamp,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::authorization::valid_principal;
use crate::run_state::{cost_unit, int, resource_counters};
use crate::support::{MAX_SAFE_INTEGER, TransitionResult, cmp_times, list, s, same, verification_status, within};

const KEYS: [&str; 4] = ["tokens", "tool_calls", "replans", "cost_units"];
const BASE_KEYS: [&str; 12] = [
    "ledger_id",
    "contract_id",
    "parent_run_id",
    "tenant_id",
    "mutation_id",
    "reservation_id",
    "scope",
    "run_id",
    "cost_unit",
    "expected_revision",
    "executor_generation",
    "evaluation_time",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CostUnitConversion {
    Converted { units: i64 },
    Rejected { reason_code: String },
}

/// Exact decimal conversion of a legacy `cost_cents` number into integer cost
/// units. Never rounds a spending limit or charge.
pub fn convert_legacy_cost_to_units(value: &Value, unit: &Value) -> CostUnitConversion {
    let invalid = || CostUnitConversion::Rejected {
        reason_code: "budget_accounting_invalid".into(),
    };
    let Some(number) = value.as_f64().filter(|n| n.is_finite() && *n >= 0.0) else {
        return invalid();
    };
    if !value.is_number() || !cost_unit(unit) {
        return invalid();
    }
    let Some(text) = js_number(number) else {
        return invalid();
    };
    // ^(\d+)(?:\.(\d+))?(?:e([+-]?\d+))?$
    let (mantissa, exponent) = match text.split_once('e') {
        Some((m, e)) => (m, e.parse::<i64>().ok()),
        None => (text.as_str(), Some(0)),
    };
    let Some(exponent) = exponent else { return invalid() };
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    if whole.is_empty() || !whole.bytes().all(|b| b.is_ascii_digit()) || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return invalid();
    }
    let digits = format!("{whole}{fraction}");
    let Ok(coefficient) = digits.parse::<u128>() else {
        return invalid();
    };
    let unit_digits = i64::try_from(int(&unit["units_per_cent"]).to_string().len()).unwrap_or(0);
    let shift = exponent - i64::try_from(fraction.len()).unwrap_or(0) + unit_digits - 1;
    let units: Option<u128> = if shift >= 0 {
        u32::try_from(shift)
            .ok()
            .and_then(|p| 10_u128.checked_pow(p))
            .and_then(|m| coefficient.checked_mul(m))
    } else {
        match u32::try_from(-shift).ok().and_then(|p| 10_u128.checked_pow(p)) {
            Some(divisor) if coefficient % divisor == 0 => Some(coefficient / divisor),
            Some(_) => {
                return CostUnitConversion::Rejected {
                    reason_code: "cost_precision_unsupported".into(),
                };
            }
            // Divisor beyond u128: a non-zero coefficient cannot divide exactly.
            None if coefficient == 0 => Some(0),
            None => {
                return CostUnitConversion::Rejected {
                    reason_code: "cost_precision_unsupported".into(),
                };
            }
        }
    };
    match units
        .and_then(|u| i64::try_from(u).ok())
        .filter(|u| *u <= MAX_SAFE_INTEGER)
    {
        Some(units) => CostUnitConversion::Converted { units },
        None => invalid(),
    }
}

fn scope_ok(o: &Value, parent_run_id: &Value) -> bool {
    match s(&o["scope"]) {
        "run" => o["run_id"] == *parent_run_id,
        "child" => o["run_id"] != *parent_run_id,
        _ => false,
    }
}

fn reservation(v: &Value) -> bool {
    exact_keys(
        v,
        &[
            "reservation_id",
            "run_id",
            "scope",
            "allocation",
            "used",
            "status",
            "deadline",
            "settlement_ref",
        ],
    )
    .is_some_and(|o| {
        resource_counters(&o["allocation"])
            && resource_counters(&o["used"])
            && is_identifier(&o["reservation_id"])
            && is_identifier(&o["run_id"])
            && matches!(o["scope"].as_str(), Some("run" | "child"))
            && KEYS.iter().all(|k| int(&o["used"][*k]) <= int(&o["allocation"][*k]))
            && matches!(o["status"].as_str(), Some("reserved" | "usage_unknown" | "settled"))
            && is_timestamp(&o["deadline"])
            && (o["settlement_ref"].is_null() || is_artifact_ref(&o["settlement_ref"]))
            && (o["status"] != "settled" || !o["settlement_ref"].is_null())
    })
}

fn receipt(v: &Value) -> bool {
    exact_keys(
        v,
        &[
            "mutation_id",
            "kind",
            "request_digest",
            "reservation_id",
            "result_revision",
            "allocated",
            "charged",
            "released",
        ],
    )
    .is_some_and(|o| {
        is_identifier(&o["mutation_id"])
            && is_identifier(&o["reservation_id"])
            && matches!(o["kind"].as_str(), Some("reserve" | "settle"))
            && is_digest(&o["request_digest"])
            && is_safe_non_negative_integer(&o["result_revision"])
            && ["allocated", "charged", "released"]
                .iter()
                .all(|k| resource_counters(&o[*k]))
    })
}

fn identity(ledger: &Value) -> Map<String, Value> {
    ["ledger_id", "contract_id", "parent_run_id", "tenant_id", "cost_unit"]
        .iter()
        .map(|k| ((*k).to_owned(), ledger[*k].clone()))
        .collect()
}

/// Content address of the original limits; resume compares against it.
pub fn budget_limits_digest(ledger: &Value) -> Option<String> {
    let mut payload = identity(ledger);
    payload.insert("original_limits".into(), ledger["original_limits"].clone());
    payload.insert("deadline".into(), ledger["deadline"].clone());
    sha256_canonical(&json!({"domain": "contextos.budget_limits.v1", "payload": payload})).ok()
}

/// Content address of the opening usage.
pub fn budget_opening_digest(ledger: &Value) -> Option<String> {
    let mut payload = identity(ledger);
    payload.insert("opening_usage".into(), ledger["opening_usage"].clone());
    sha256_canonical(&json!({"domain": "contextos.budget_opening.v1", "payload": payload})).ok()
}

fn arr(v: &Value) -> &[Value] {
    v.as_array().map_or(&[], Vec::as_slice)
}

fn valid_ledger(v: &Value) -> bool {
    let structural = exact_keys(
        v,
        &[
            "ledger_id",
            "contract_id",
            "parent_run_id",
            "tenant_id",
            "revision",
            "executor_generation",
            "deadline",
            "cost_unit",
            "original_limits",
            "original_limits_ref",
            "opening_usage",
            "opening_usage_ref",
            "ceiling",
            "used",
            "reserved",
            "unknown_usage_policy",
            "mutations",
            "trusted_observers",
            "reservations",
        ],
    )
    .is_some_and(|o| {
        ["ledger_id", "contract_id", "parent_run_id", "tenant_id"]
            .iter()
            .all(|k| is_identifier(&o[*k]))
            && is_safe_non_negative_integer(&o["revision"])
            && is_safe_non_negative_integer(&o["executor_generation"])
            && is_timestamp(&o["deadline"])
            && cost_unit(&o["cost_unit"])
            && exact_keys(
                &o["original_limits"],
                &["tokens", "tool_calls", "replans", "cost_cents"],
            )
            .is_some_and(|l| {
                ["tokens", "tool_calls", "replans"]
                    .iter()
                    .all(|k| is_safe_non_negative_integer(&l[*k]))
            })
            && is_artifact_ref(&o["original_limits_ref"])
            && is_artifact_ref(&o["opening_usage_ref"])
            && ["opening_usage", "ceiling", "used", "reserved"]
                .iter()
                .all(|k| resource_counters(&o[*k]))
            && o["unknown_usage_policy"] == "retain_reservation"
            && list(&o["reservations"], reservation)
            && list(&o["mutations"], receipt)
            && list(&o["trusted_observers"], valid_principal)
            && !arr(&o["trusted_observers"]).is_empty()
    });
    if !structural {
        return false;
    }
    let ceiling = &v["ceiling"];
    match convert_legacy_cost_to_units(&v["original_limits"]["cost_cents"], &v["cost_unit"]) {
        CostUnitConversion::Converted { units } if units == int(&ceiling["cost_units"]) => {}
        _ => return false,
    }
    if ["tokens", "tool_calls", "replans"]
        .iter()
        .any(|k| int(&v["original_limits"][*k]) != int(&ceiling[*k]))
    {
        return false;
    }
    if v["original_limits_ref"]["sha256"].as_str() != budget_limits_digest(v).as_deref()
        || v["opening_usage_ref"]["sha256"].as_str() != budget_opening_digest(v).as_deref()
    {
        return false;
    }
    let reservations = arr(&v["reservations"]);
    let mutations = arr(&v["mutations"]);
    let unique = |items: &[Value], key: &str| {
        items
            .iter()
            .map(|i| s(&i[key]))
            .collect::<std::collections::HashSet<_>>()
            .len()
            == items.len()
    };
    if !unique(reservations, "reservation_id")
        || !unique(mutations, "mutation_id")
        || arr(&v["trusted_observers"])
            .iter()
            .any(|p| p["tenant_id"] != v["tenant_id"])
    {
        return false;
    }
    if reservations.iter().any(|r| {
        !scope_ok(r, &v["parent_run_id"])
            || cmp_times(&r["deadline"], &v["deadline"]) == Some(std::cmp::Ordering::Greater)
    }) {
        return false;
    }
    if mutations.iter().any(|m| {
        int(&m["result_revision"]) > int(&v["revision"])
            || !reservations.iter().any(|r| r["reservation_id"] == m["reservation_id"])
    }) {
        return false;
    }
    KEYS.iter().all(|k| {
        let used: i128 = i128::from(int(&v["opening_usage"][*k]))
            + reservations
                .iter()
                .map(|r| i128::from(int(&r["used"][*k])))
                .sum::<i128>();
        let reserved: i128 = reservations
            .iter()
            .map(|r| {
                if r["status"] == "settled" {
                    0
                } else {
                    i128::from(int(&r["allocation"][*k])) - i128::from(int(&r["used"][*k]))
                }
            })
            .sum();
        used == i128::from(int(&v["used"][*k]))
            && reserved == i128::from(int(&v["reserved"][*k]))
            && used + reserved <= i128::from(int(&ceiling[*k]))
    })
}

fn base_request(o: &Map<String, Value>) -> bool {
    [
        "ledger_id",
        "contract_id",
        "parent_run_id",
        "tenant_id",
        "mutation_id",
        "reservation_id",
        "run_id",
    ]
    .iter()
    .all(|k| is_identifier(&o[*k]))
        && scope_ok(&Value::Object(o.clone()), &o["parent_run_id"])
        && cost_unit(&o["cost_unit"])
        && is_safe_non_negative_integer(&o["expected_revision"])
        && is_safe_non_negative_integer(&o["executor_generation"])
        && is_timestamp(&o["evaluation_time"])
}

fn keys_with(extra: &[&'static str]) -> Vec<&'static str> {
    BASE_KEYS.iter().chain(extra.iter()).copied().collect()
}

fn reserve_request(v: &Value) -> bool {
    exact_keys(v, &keys_with(&["allocation", "deadline"]))
        .is_some_and(|o| base_request(o) && resource_counters(&o["allocation"]) && is_timestamp(&o["deadline"]))
}

fn settle_request(v: &Value) -> bool {
    exact_keys(
        v,
        &keys_with(&["usage", "usage_status", "execution_status", "usage_observation"]),
    )
    .is_some_and(|o| {
        base_request(o)
            && resource_counters(&o["usage"])
            && matches!(o["usage_status"].as_str(), Some("known" | "unknown"))
            && matches!(
                o["execution_status"].as_str(),
                Some("running" | "completed" | "cancelled" | "unknown")
            )
            && exact_keys(
                &o["usage_observation"],
                &[
                    "intent_digest",
                    "verification_status",
                    "observer",
                    "evidence_ref",
                    "observed_at",
                    "valid_until",
                ],
            )
            .is_some_and(|u| {
                is_digest(&u["intent_digest"])
                    && verification_status(&u["verification_status"])
                    && valid_principal(&u["observer"])
                    && is_artifact_ref(&u["evidence_ref"])
                    && is_timestamp(&u["observed_at"])
                    && is_timestamp(&u["valid_until"])
            })
    })
}

fn without(v: &Value, keys: &[&str]) -> Value {
    let mut object = v.as_object().cloned().unwrap_or_default();
    for key in keys {
        object.remove(*key);
    }
    Value::Object(object)
}

fn semantic_request(request: &Value) -> Value {
    without(
        request,
        &["expected_revision", "executor_generation", "evaluation_time"],
    )
}

fn mutation_digest(kind: &str, request: &Value) -> String {
    sha256_canonical(
        &json!({"domain": "contextos.budget_mutation.v1", "kind": kind, "body": semantic_request(request)}),
    )
    .unwrap_or_default()
}

/// Digest a settlement's usage observation must carry: the request without its
/// transport fields and without the observation itself.
pub fn settlement_intent_digest(request: &Value) -> Option<String> {
    let intent = semantic_request(&without(request, &["usage_observation"]));
    sha256_canonical(&json!({"domain": "contextos.budget_settlement_intent.v1", "intent": intent})).ok()
}

fn zero() -> Value {
    json!({"tokens": 0, "tool_calls": 0, "replans": 0, "cost_units": 0})
}

fn prepare(ledger: &Value, request: &Value, kind: &str, terminal: bool) -> Option<TransitionResult> {
    if ["ledger_id", "contract_id", "parent_run_id", "tenant_id"]
        .iter()
        .any(|k| ledger[*k] != request[*k])
        || !same(&ledger["cost_unit"], &request["cost_unit"])
    {
        return Some(TransitionResult::rejected(ledger.clone(), "budget_accounting_invalid"));
    }
    let digest = mutation_digest(kind, request);
    if let Some(previous) = arr(&ledger["mutations"])
        .iter()
        .find(|m| m["mutation_id"] == request["mutation_id"])
    {
        return Some(
            if previous["kind"] == kind && previous["request_digest"] == digest.as_str() {
                TransitionResult::accepted(ledger.clone(), vec!["use_original_mutation_receipt".into()])
            } else {
                TransitionResult::rejected(ledger.clone(), "mutation_conflict")
            },
        );
    }
    if int(&request["expected_revision"]) != int(&ledger["revision"]) {
        return Some(TransitionResult::rejected(ledger.clone(), "revision_conflict"));
    }
    if int(&request["executor_generation"]) != int(&ledger["executor_generation"]) {
        return Some(TransitionResult::rejected(ledger.clone(), "executor_stale"));
    }
    let open = i64::try_from(
        arr(&ledger["reservations"])
            .iter()
            .filter(|r| r["status"] != "settled")
            .count(),
    )
    .unwrap_or(i64::MAX);
    let pending_after = open
        + if kind == "reserve" {
            1
        } else if terminal {
            -1
        } else {
            0
        };
    let next_revision = int(&ledger["revision"]) + 1 + pending_after;
    let mutations = i64::try_from(arr(&ledger["mutations"]).len()).unwrap_or(i64::MAX);
    if !(0..=MAX_SAFE_INTEGER).contains(&next_revision) || mutations + 1 + pending_after > 128 {
        return Some(TransitionResult::rejected(ledger.clone(), "counter_exhausted"));
    }
    None
}

#[allow(clippy::needless_pass_by_value)]
fn finish(
    mut ledger: Value,
    request: &Value,
    kind: &str,
    allocated: Value,
    charged: Value,
    released: Value,
) -> TransitionResult {
    let revision = int(&ledger["revision"]) + 1;
    ledger["revision"] = json!(revision);
    ledger["mutations"].as_array_mut().expect("validated").push(json!({
        "mutation_id": request["mutation_id"],
        "kind": kind,
        "request_digest": mutation_digest(kind, request),
        "reservation_id": request["reservation_id"],
        "result_revision": revision,
        "allocated": allocated,
        "charged": charged,
        "released": released,
    }));
    TransitionResult::accepted(
        ledger,
        vec![
            "persist_budget_with_revision_and_executor_fence".into(),
            "obtain_current_authorization_before_spending".into(),
        ],
    )
}

/// Intended compare-and-swap reservation. Persisted capacity does not grant action
/// authority.
pub fn reserve_budget(ledger: &Value, request: &Value) -> TransitionResult {
    let reject = |reason: &str| TransitionResult::rejected(ledger.clone(), reason);
    if contextos_contract::canonical::check_canonical(ledger).is_err()
        || contextos_contract::canonical::check_canonical(request).is_err()
        || !valid_ledger(ledger)
        || !reserve_request(request)
    {
        return reject("budget_accounting_invalid");
    }
    if let Some(result) = prepare(ledger, request, "reserve", false) {
        return result;
    }
    let less = Some(std::cmp::Ordering::Less);
    if cmp_times(&request["deadline"], &ledger["deadline"]) == Some(std::cmp::Ordering::Greater)
        || cmp_times(&request["evaluation_time"], &request["deadline"]) != less
        || cmp_times(&request["evaluation_time"], &ledger["deadline"]) != less
    {
        return reject("deadline_exceeded");
    }
    let reservations = arr(&ledger["reservations"]);
    if reservations.len() >= 128
        || reservations
            .iter()
            .any(|r| r["reservation_id"] == request["reservation_id"])
    {
        return reject("reservation_conflict");
    }
    let allocation = &request["allocation"];
    if KEYS.iter().any(|k| {
        int(&allocation[*k]) > int(&ledger["ceiling"][*k]) - int(&ledger["used"][*k]) - int(&ledger["reserved"][*k])
    }) {
        return reject("budget_exhausted");
    }
    let mut next = ledger.clone();
    next["reservations"].as_array_mut().expect("validated").push(json!({
        "reservation_id": request["reservation_id"], "run_id": request["run_id"], "scope": request["scope"],
        "allocation": allocation, "used": zero(), "status": "reserved", "deadline": request["deadline"],
        "settlement_ref": null,
    }));
    for k in KEYS {
        next["reserved"][k] = json!(int(&ledger["reserved"][k]) + int(&allocation[k]));
    }
    finish(next, request, "reserve", allocation.clone(), zero(), zero())
}

/// Cumulative, verified accounting. Unknown usage retains capacity; terminal known
/// usage releases the remainder.
pub fn settle_budget(ledger: &Value, request: &Value) -> TransitionResult {
    let reject = |reason: &str| TransitionResult::rejected(ledger.clone(), reason);
    if contextos_contract::canonical::check_canonical(ledger).is_err()
        || contextos_contract::canonical::check_canonical(request).is_err()
        || !valid_ledger(ledger)
        || !settle_request(request)
    {
        return reject("budget_accounting_invalid");
    }
    let terminal = request["usage_status"] == "known"
        && matches!(request["execution_status"].as_str(), Some("completed" | "cancelled"));
    if let Some(result) = prepare(ledger, request, "settle", terminal) {
        return result;
    }
    let Some(index) = arr(&ledger["reservations"])
        .iter()
        .position(|r| r["reservation_id"] == request["reservation_id"])
    else {
        return reject("reservation_conflict");
    };
    let reserved = &ledger["reservations"][index];
    if reserved["status"] == "settled"
        || reserved["scope"] != request["scope"]
        || reserved["run_id"] != request["run_id"]
    {
        return reject("reservation_conflict");
    }
    let observation = &request["usage_observation"];
    if observation["verification_status"] != "verified"
        || !arr(&ledger["trusted_observers"])
            .iter()
            .any(|p| same(p, &observation["observer"]))
        || !within(
            &request["evaluation_time"],
            &observation["observed_at"],
            &observation["valid_until"],
        )
        || observation["intent_digest"].as_str() != settlement_intent_digest(request).as_deref()
    {
        return reject("usage_unverified");
    }
    let usage = &request["usage"];
    if KEYS
        .iter()
        .any(|k| int(&usage[*k]) < int(&reserved["used"][*k]) || int(&usage[*k]) > int(&reserved["allocation"][*k]))
    {
        return reject("budget_accounting_invalid");
    }
    let mut next = ledger.clone();
    let (mut charged, mut released) = (zero(), zero());
    for k in KEYS {
        let charge = int(&usage[k]) - int(&reserved["used"][k]);
        let release = if terminal {
            int(&reserved["allocation"][k]) - int(&usage[k])
        } else {
            0
        };
        charged[k] = json!(charge);
        released[k] = json!(release);
        next["used"][k] = json!(int(&ledger["used"][k]) + charge);
        next["reserved"][k] = json!(int(&ledger["reserved"][k]) - charge - release);
    }
    let record = &mut next["reservations"][index];
    record["used"] = usage.clone();
    record["settlement_ref"] = observation["evidence_ref"].clone();
    record["status"] = json!(if terminal {
        "settled"
    } else if request["usage_status"] == "unknown" {
        "usage_unknown"
    } else {
        "reserved"
    });
    finish(next, request, "settle", zero(), charged, released)
}

pub fn reserve_child_budget(ledger: &Value, request: &Value) -> TransitionResult {
    if reserve_request(request) && request["scope"] == "child" {
        reserve_budget(ledger, request)
    } else {
        TransitionResult::rejected(ledger.clone(), "budget_scope_invalid")
    }
}

pub fn settle_child_budget(ledger: &Value, request: &Value) -> TransitionResult {
    if settle_request(request) && request["scope"] == "child" {
        settle_budget(ledger, request)
    } else {
        TransitionResult::rejected(ledger.clone(), "budget_scope_invalid")
    }
}
