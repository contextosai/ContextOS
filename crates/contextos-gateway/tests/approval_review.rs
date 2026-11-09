//! An approval decided faster than the review floor does not count.

mod support;

use contextos_gateway::approval_review::ReviewPolicy;
use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore};
use serde_json::{Value, json};
use support::*;

async fn requested_at(h: &Harness, request_id: &str, at: &str) {
    let key = DocKey::new(&h.admission.tenant_id, DocKind::ApprovalRequested, request_id);
    let current = h
        .store
        .get(&key)
        .await
        .unwrap()
        .expect("the gateway recorded the request");
    h.store
        .compare_and_swap(&key, current.revision, &json!({"requested_at": at}))
        .await
        .unwrap();
}

async fn audited(h: &Harness, kind: &str) -> Vec<Value> {
    h.audit
        .log()
        .range(&h.admission.tenant_id, 1, 1000)
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.body["kind"] == kind)
        .map(|r| r.body["payload"].clone())
        .collect()
}

#[tokio::test]
async fn a_rubber_stamped_approval_is_refused_and_a_reviewed_one_counts() {
    let mut h = harness("require_approval", Behavior::Confirm).await;
    h.gateway.set_approval_review(Some(ReviewPolicy {
        min_review_seconds: 60,
        capabilities: vec![],
        amount_at_least: vec![],
    }));
    let call = call("tc_1", Some("refund_big"));
    let paused = h.gateway.dispatch(&h.admission, &call).await.unwrap();
    assert_eq!(paused.result["status"], "paused");
    let request_id = paused.report.approval_request_id.clone().unwrap();
    h.approvals.approve(paused.report.action_digest.as_deref().unwrap());

    // Decided at 09:30:00, ten seconds after it was requested.
    requested_at(&h, &request_id, "2026-10-20T09:29:50Z").await;
    let stamped = h.gateway.dispatch(&h.admission, &call).await.unwrap();
    assert_ne!(stamped.report.status, "completed", "{:?}", stamped.report);
    assert!(
        stamped
            .report
            .reason_codes
            .contains(&"approval_review_too_fast".to_owned())
    );
    assert!(stamped.report.obligations.contains(&"review_again".to_owned()));
    let refused = audited(&h, "approval_review_too_fast").await;
    assert_eq!(refused[0]["review_seconds"], 10);
    assert_eq!(h.adapter.calls.load(std::sync::atomic::Ordering::SeqCst), 0);

    // Requested half an hour before the decision: reviewed.
    requested_at(&h, &request_id, "2026-10-20T09:00:00Z").await;
    let reviewed = h.gateway.dispatch(&h.admission, &call).await.unwrap();
    assert_eq!(reviewed.report.status, "completed", "{:?}", reviewed.report);

    // The chain carries what approval quality is measured from: one request, one
    // redemption with its decision time (30 minutes), never the refused fast one.
    let requested = audited(&h, "approval_requested").await;
    assert_eq!(requested.len(), 1, "{requested:?}");
    assert_eq!(requested[0]["approval_request_id"], request_id.as_str());
    assert_eq!(requested[0]["capability_id"], "adp_payments.issue_refund");
    let redeemed = audited(&h, "approval_redeemed").await;
    assert_eq!(redeemed.len(), 1, "{redeemed:?}");
    assert_eq!(redeemed[0]["decision_seconds"], 1800);
    assert_eq!(redeemed[0]["approval_request_id"], request_id.as_str());
    assert!(
        redeemed[0]["approvers"].as_array().is_some_and(|a| !a.is_empty()),
        "{redeemed:?}"
    );

    // Re-sending the completed call redeems nothing again.
    h.gateway.dispatch(&h.admission, &call).await.unwrap();
    assert_eq!(audited(&h, "approval_redeemed").await.len(), 1);
}
