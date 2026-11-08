//! Spend caps from shared guarantees: estimated amounts from a price table, limits per
//! agent or tenant, and limits per window.

mod support;

use std::sync::atomic::Ordering;

use contextos_gateway::*;
use contextos_store::AppendLog;
use serde_json::{Value, json};
use support::*;

/// Each agent may commit 500,000 a day; a call reserves the estimate its `amount_minor`
/// (standing in for an instance type or a model) is priced at, as text.
fn daily_cap() -> SharedGuarantee {
    serde_json::from_value(
        json!({"id": "agent_daily", "capability_ids": ["adp_payments.issue_refund"],
        "resource_from": "actor", "limit": 500_000, "unit": "INR_minor", "window_seconds": 86_400,
        "amount_table": {"key_pointer": "/amount_minor", "prices": {"1": 300_000, "3": 300_000}, "default": 100_000}}),
    )
    .unwrap()
}

fn spend(admission: &RunAdmission, operation: &str, amount: u64) -> Value {
    let mut v = call(operation, Some(operation));
    v["run_id"] = json!(admission.run_id);
    v["principal_chain"][0]["id"] = admission.actor["principal_id"].clone();
    v["args"]["amount_minor"] = json!(amount);
    v
}

async fn reserved_entries(h: &Harness) -> Vec<Value> {
    h.audit
        .log()
        .range(TENANT, 1, 1000)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.body["kind"] == "shared_guarantee_reserved")
        .map(|e| e.body["payload"].clone())
        .collect()
}

#[tokio::test]
async fn an_agents_estimated_spend_is_capped_per_window() {
    let mut h = harness("allow", Behavior::Confirm).await;
    h.gateway.set_shared_guarantees(vec![daily_cap()]).unwrap();

    let first = h
        .gateway
        .dispatch(&h.admission, &spend(&h.admission, "a", 1))
        .await
        .unwrap();
    assert_eq!(first.report.status, "completed", "{:?}", first.report.reason_codes);
    // An unpriced key reserves the default estimate: 300,000 + 100,000 fits.
    let second = h
        .gateway
        .dispatch(&h.admission, &spend(&h.admission, "b", 2))
        .await
        .unwrap();
    assert_eq!(second.report.status, "completed", "{:?}", second.report.reason_codes);
    // The next priced call would reach 700,000: refused before the provider is called.
    let third = h
        .gateway
        .dispatch(&h.admission, &spend(&h.admission, "c", 3))
        .await
        .unwrap();
    assert_eq!(third.report.reason_codes, ["shared_guarantee_exceeded"]);
    assert_eq!(h.adapter.calls.load(Ordering::SeqCst), 2);

    let reserved = reserved_entries(&h).await;
    assert_eq!(reserved.len(), 2);
    assert!(reserved.iter().all(|r| r["estimated"] == true), "{reserved:?}");
    assert_eq!(
        reserved
            .iter()
            .map(|r| r["amount"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        [300_000, 100_000]
    );
    let start = reserved[0]["window_start"].as_u64().unwrap();
    assert_eq!(start % 86_400, 0, "windows start on their boundary");

    // Another agent has its own cap.
    let other = independent_run(&h, "run_other_agent").await;
    assert_ne!(other.actor["principal_id"], h.admission.actor["principal_id"]);
    let theirs = h.gateway.dispatch(&other, &spend(&other, "d", 4)).await.unwrap();
    assert_eq!(theirs.report.status, "completed", "{:?}", theirs.report.reason_codes);
}

#[tokio::test]
async fn a_call_without_a_price_or_default_is_refused() {
    let mut h = harness("allow", Behavior::Confirm).await;
    let mut rule = daily_cap();
    rule.amount_table.as_mut().unwrap().default = None;
    h.gateway.set_shared_guarantees(vec![rule]).unwrap();
    let out = h
        .gateway
        .dispatch(&h.admission, &spend(&h.admission, "a", 2))
        .await
        .unwrap();
    assert_eq!(out.report.reason_codes, ["shared_guarantee_amount_invalid"]);
    assert_eq!(h.adapter.calls.load(Ordering::SeqCst), 0);
    assert_eq!(reserved_entries(&h).await, Vec::<Value>::new());
}

#[test]
fn a_guarantee_names_one_resource_source_and_one_amount_source() {
    assert!(daily_cap().validate().is_ok());
    let mut both = daily_cap();
    both.resource_pointer = "/order_id".into();
    assert!(both.validate().is_err(), "a pointer and resource_from");
    let mut neither = daily_cap();
    neither.amount_table = None;
    assert!(neither.validate().is_err(), "no amount source");
    let mut short = daily_cap();
    short.window_seconds = Some(10);
    assert!(short.validate().is_err(), "a window under a minute");
    let mut free = daily_cap();
    free.amount_table.as_mut().unwrap().prices.insert("cus_0".into(), 0);
    assert!(free.validate().is_err(), "a zero price");
    // An existing definition serializes as before: the new sources are omitted.
    let existing = shared_rule();
    let value = serde_json::to_value(&existing).unwrap();
    for absent in ["resource_from", "amount_table", "window_seconds"] {
        assert!(value.get(absent).is_none(), "{absent} in {value}");
    }
}
