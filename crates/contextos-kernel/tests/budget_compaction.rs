//! Compaction keeps accounting exact while letting a run go past 128 receipts.

use contextos_kernel::budget_compaction::{compact_budget_ledger, verify_compaction};
use contextos_kernel::budget_ledger::{
    budget_limits_digest, budget_opening_digest, reserve_budget, settle_budget, settlement_intent_digest,
};
use serde_json::{Value, json};

const NOW: &str = "2026-10-20T10:00:00Z";

fn observer() -> Value {
    json!({"principal_id": "gateway", "principal_type": "workload", "trust_domain": "contextos.test", "tenant_id": "t1"})
}

fn artifact(kind: &str, id: &str, sha: String) -> Value {
    json!({"artifact_type": kind, "artifact_id": id, "version": "1", "sha256": sha})
}

fn ledger(tool_calls: i64) -> Value {
    let zero = json!({"tokens": 0, "tool_calls": 0, "replans": 0, "cost_units": 0});
    let mut ledger = json!({
        "ledger_id": "budget:run_1", "contract_id": "contract_1", "parent_run_id": "run_1", "tenant_id": "t1",
        "revision": 0, "executor_generation": 1, "deadline": "2026-10-20T11:00:00Z",
        "cost_unit": {"currency": "USD", "units_per_cent": 100},
        "original_limits": {"tokens": 0, "tool_calls": tool_calls, "replans": 0, "cost_cents": 1000},
        "original_limits_ref": null, "opening_usage": zero, "opening_usage_ref": null,
        "ceiling": {"tokens": 0, "tool_calls": tool_calls, "replans": 0, "cost_units": 100_000},
        "used": zero, "reserved": zero, "unknown_usage_policy": "retain_reservation", "mutations": [],
        "trusted_observers": [observer()], "reservations": [],
    });
    ledger["original_limits_ref"] = artifact("budget_limits", "budget:run_1", budget_limits_digest(&ledger).unwrap());
    ledger["opening_usage_ref"] = artifact(
        "budget_opening",
        "budget:run_1",
        budget_opening_digest(&ledger).unwrap(),
    );
    ledger
}

fn base(ledger: &Value, mutation: &str, reservation: &str) -> Value {
    json!({"ledger_id": "budget:run_1", "contract_id": "contract_1", "parent_run_id": "run_1", "tenant_id": "t1",
        "mutation_id": mutation, "reservation_id": reservation, "scope": "run", "run_id": "run_1",
        "cost_unit": {"currency": "USD", "units_per_cent": 100}, "expected_revision": ledger["revision"],
        "executor_generation": 1, "evaluation_time": NOW})
}

fn reserve(ledger: &Value, n: usize) -> Value {
    let mut request = base(ledger, &format!("reserve:{n}"), &format!("reservation:{n}"));
    request["allocation"] = json!({"tokens": 0, "tool_calls": 1, "replans": 0, "cost_units": 100});
    request["deadline"] = json!("2026-10-20T11:00:00Z");
    let result = reserve_budget(ledger, &request);
    assert_eq!(result.status, "accepted", "{:?}", result.reason_codes);
    result.state
}

fn settle(ledger: &Value, n: usize, known: bool) -> Value {
    let mut request = base(ledger, &format!("settle:{n}:{known}"), &format!("reservation:{n}"));
    request["usage"] = json!({"tokens": 0, "tool_calls": 1, "replans": 0, "cost_units": 40});
    request["usage_status"] = json!(if known { "known" } else { "unknown" });
    request["execution_status"] = json!(if known { "completed" } else { "unknown" });
    request["usage_observation"] = json!({"intent_digest": "", "verification_status": "verified", "observer": observer(),
        "evidence_ref": artifact("usage", &format!("u{n}"), format!("sha256:{n:064x}")),
        "observed_at": NOW, "valid_until": "2026-10-20T10:05:00Z"});
    request["usage_observation"]["intent_digest"] = json!(settlement_intent_digest(&request).unwrap());
    let result = settle_budget(ledger, &request);
    assert_eq!(result.status, "accepted", "{:?}", result.reason_codes);
    result.state
}

fn compact(ledger: &Value, id: &str) -> (Value, Value) {
    let c = compact_budget_ledger(ledger, id, &ledger["revision"], &ledger["executor_generation"]).unwrap();
    (c.ledger, c.archive)
}

#[test]
fn compaction_preserves_accounting_and_lifts_the_receipt_ceiling() {
    let mut l = ledger(1_000);
    // Without compaction the ledger runs out of receipts after ~63 effects.
    let mut exhausted = ledger(1_000);
    let mut done = 0;
    loop {
        let mut request = base(&exhausted, &format!("reserve:{done}"), &format!("reservation:{done}"));
        request["allocation"] = json!({"tokens": 0, "tool_calls": 1, "replans": 0, "cost_units": 100});
        request["deadline"] = json!("2026-10-20T11:00:00Z");
        let result = reserve_budget(&exhausted, &request);
        if result.status != "accepted" {
            assert_eq!(result.reason_codes.unwrap(), vec!["counter_exhausted".to_owned()]);
            break;
        }
        exhausted = settle(&result.state, done, true);
        done += 1;
    }
    assert_eq!(done, 64, "the spec bound applies without compaction");

    // With compaction every 16 effects, 300 effects run; one reservation stays open
    // with unknown usage across compactions.
    l = reserve(&l, 9_999);
    l = settle(&l, 9_999, false);
    let mut archives = Vec::new();
    for n in 0..300 {
        l = reserve(&l, n);
        l = settle(&l, n, true);
        if l["mutations"].as_array().unwrap().len() >= 32 {
            let previous = l.clone();
            let (next, archive) = compact(&l, &format!("budget:run_1:archive:{}", archives.len()));
            assert!(verify_compaction(&previous, &next, &archive));
            for k in ["used", "reserved", "ceiling"] {
                assert_eq!(previous[k], next[k], "{k} is unchanged by compaction");
            }
            assert_eq!(
                archive["previous_ledger_digest"],
                json!(contextos_contract::canonical::sha256_canonical(&previous).unwrap())
            );
            archives.push(archive);
            l = next;
        }
    }
    assert!(l["mutations"].as_array().unwrap().len() < 40, "the ledger stays small");
    assert_eq!(l["used"]["tool_calls"], 301);
    assert_eq!(l["used"]["cost_units"], 300 * 40 + 40);
    assert_eq!(
        l["reserved"]["cost_units"], 60,
        "the unknown reservation keeps its remainder"
    );
    // The open reservation survived every compaction and still settles.
    assert!(
        l["reservations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["reservation_id"] == "reservation:9999")
    );
    let l = settle(&l, 9_999, true);
    assert_eq!(l["reserved"]["cost_units"], 0);
    // Every archived receipt plus the live ones account for all 602 mutations.
    let archived: usize = archives.iter().map(|a| a["mutations"].as_array().unwrap().len()).sum();
    assert_eq!(archived + l["mutations"].as_array().unwrap().len(), 2 * 301 + 1);
}

#[test]
fn compaction_is_fenced_and_refuses_empty_or_forged_work() {
    let l = ledger(10);
    assert_eq!(
        compact_budget_ledger(&l, "a", &l["revision"], &json!(1)).unwrap_err(),
        "nothing_to_compact"
    );
    let l = settle(&reserve(&l, 1), 1, true);
    assert_eq!(
        compact_budget_ledger(&l, "a", &json!(0), &json!(1)).unwrap_err(),
        "revision_conflict"
    );
    assert_eq!(
        compact_budget_ledger(&l, "a", &l["revision"], &json!(2)).unwrap_err(),
        "executor_stale"
    );
    let mut forged = l.clone();
    forged["used"]["cost_units"] = json!(0);
    assert_eq!(
        compact_budget_ledger(&forged, "a", &forged["revision"], &json!(1)).unwrap_err(),
        "budget_accounting_invalid"
    );
    let (next, archive) = compact(&l, "a");
    let mut tampered = archive.clone();
    tampered["mutations"] = json!([]);
    assert!(!verify_compaction(&l, &next, &tampered));
}
