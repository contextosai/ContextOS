//! Checking a tool call governs it exactly as dispatch would, and changes nothing but
//! one audit entry recording the check.

mod support;

use std::sync::atomic::Ordering;

use contextos_audit::verify_tenant_chain;
use contextos_gateway::operation_ledger_key;
use contextos_store::{DocKey, DocKind, DocumentStore};
use support::*;

async fn unclaimed(h: &Harness, operation_id: &str) {
    let key = operation_ledger_key(&h.admission, operation_id);
    assert!(
        h.store.get(&key).await.unwrap().is_none(),
        "a check claims no operation"
    );
    let budget = ledger(h, DocKind::BudgetLedger, &h.admission.budget_ledger_id).await;
    assert!(
        budget["reservations"].as_array().is_none_or(Vec::is_empty),
        "a check reserves no budget: {budget}"
    );
}

#[tokio::test]
async fn an_allowed_call_is_reported_without_effect_and_then_dispatches() {
    let h = harness("allow", Behavior::Confirm).await;
    let check = h
        .gateway
        .check_tool_call(&h.admission, &call("tc_1", Some("refund_1")), None)
        .await
        .unwrap();
    assert_eq!(check.status, "allowed", "{check:?}");
    assert_eq!(check.operation_id.as_deref(), Some("refund_1"));
    assert!(check.action_digest.is_some());
    assert!(!check.operation_exists);
    assert_eq!(check.not_evaluated, ["budget_reservation", "operation_claim"]);
    assert_eq!(h.adapter.calls.load(Ordering::SeqCst), 0);
    unclaimed(&h, "refund_1").await;
    // Only the check is on the audit chain.
    assert_eq!(verify_tenant_chain(h.audit.log(), TENANT, &keys()).await.unwrap(), 1);

    let done = h
        .gateway
        .dispatch(&h.admission, &call("tc_2", Some("refund_1")))
        .await
        .unwrap();
    assert_eq!(done.result["status"], "completed", "{:?}", done.report);
    assert_eq!(
        done.report.action_digest, check.action_digest,
        "the check bound the same action"
    );

    let again = h
        .gateway
        .check_tool_call(&h.admission, &call("tc_3", Some("refund_1")), None)
        .await
        .unwrap();
    assert!(again.operation_exists, "a check of an existing operation says so");
}

#[tokio::test]
async fn a_denied_call_is_blocked_with_the_dispatch_reasons() {
    let h = harness("deny", Behavior::Confirm).await;
    let check = h
        .gateway
        .check_tool_call(&h.admission, &call("tc_1", None), None)
        .await
        .unwrap();
    assert_eq!(check.status, "blocked");
    assert!(check.reason_codes.contains(&"business_policy_denied".to_owned()));
    assert_eq!(check.message.as_deref(), Some("Authorization denied."));
    assert_eq!(verify_tenant_chain(h.audit.log(), TENANT, &keys()).await.unwrap(), 1);
}

#[tokio::test]
async fn approval_is_reported_not_requested_and_a_granted_one_is_not_redeemed() {
    let h = harness("require_approval", Behavior::Confirm).await;
    let check = h
        .gateway
        .check_tool_call(&h.admission, &call("tc_1", Some("refund_big")), None)
        .await
        .unwrap();
    assert_eq!(check.status, "approval_required");
    assert!(check.obligations.contains(&"await_approval".to_owned()));
    assert_eq!(h.approvals.0.load(Ordering::SeqCst), 0, "a check requests no approval");

    // Dispatch requests the approval; once granted, a check sees it as redeemable.
    let paused = h
        .gateway
        .dispatch(&h.admission, &call("tc_2", Some("refund_big")))
        .await
        .unwrap();
    let digest = paused.report.action_digest.clone().unwrap();
    h.approvals.approve(&digest);
    let check = h
        .gateway
        .check_tool_call(&h.admission, &call("tc_3", Some("refund_big")), None)
        .await
        .unwrap();
    assert_eq!(check.status, "allowed", "{check:?}");
    let request_id = format!("approval_request:{}", &digest[7..19]);
    let redemption = DocKey::new(TENANT, DocKind::ApprovalRedemption, &request_id);
    assert!(
        h.store.get(&redemption).await.unwrap().is_none(),
        "a check redeems nothing"
    );

    // The approval still redeems once for the real call.
    let done = h
        .gateway
        .dispatch(&h.admission, &call("tc_4", Some("refund_big")))
        .await
        .unwrap();
    assert_eq!(done.result["status"], "completed", "{:?}", done.report);
    assert_eq!(h.adapter.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_malformed_or_stale_call_is_rejected_as_dispatch_would() {
    let h = harness("allow", Behavior::Confirm).await;
    let mut unsurfaced = call("tc_1", None);
    unsurfaced["capability_id"] = serde_json::json!("adp_payments.unknown");
    let check = h
        .gateway
        .check_tool_call(&h.admission, &unsurfaced, None)
        .await
        .unwrap();
    assert_eq!(
        (check.status.as_str(), check.reason_codes.as_slice()),
        ("rejected", &["capability_not_pinned".to_owned()][..])
    );

    // A fenced check of a run with no current executor is refused like a dispatch.
    let fenced = h
        .gateway
        .check_tool_call(&h.admission, &call("tc_2", None), Some(1))
        .await
        .unwrap();
    assert_eq!(fenced.status, "rejected", "{fenced:?}");
    assert_eq!(fenced.reason_codes, ["run_not_started"]);
}
