//! An approval request nobody decides in time is escalated, or refused.

mod support;

use std::sync::atomic::Ordering;

use contextos_gateway::{ApprovalNote, OnTimeout, TimeoutPolicy};
use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore};
use serde_json::{Value, json};
use support::*;

/// Moves the gateway's record of when it asked back to `at` (the harness clock is fixed
/// at 10:00:00).
async fn requested_at(h: &Harness, request_id: &str, at: &str) {
    let key = DocKey::new(&h.admission.tenant_id, DocKind::ApprovalRequested, request_id);
    let current = h
        .store
        .get(&key)
        .await
        .unwrap()
        .expect("the gateway recorded the request");
    let mut body = current.body.clone();
    body["requested_at"] = json!(at);
    h.store.compare_and_swap(&key, current.revision, &body).await.unwrap();
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

async fn paused_request(on_timeout: OnTimeout) -> (Harness, Value, String) {
    let mut h = harness("require_approval", Behavior::Confirm).await;
    h.gateway.set_approval_timeout(Some(TimeoutPolicy {
        timeout_seconds: 900,
        on_timeout,
        capabilities: vec![],
    }));
    // The daemon keeps each run's admission; the sweep reads it to escalate.
    h.store
        .create(
            &DocKey::new(&h.admission.tenant_id, DocKind::RunAdmission, &h.admission.run_id),
            &serde_json::to_value(&h.admission).unwrap(),
        )
        .await
        .unwrap();
    let call = call("tc_1", Some("refund_big"));
    let paused = h.gateway.dispatch(&h.admission, &call).await.unwrap();
    assert_eq!(paused.result["status"], "paused");
    assert_eq!(paused.report.approval, Some(ApprovalNote::Requested));
    let request_id = paused.report.approval_request_id.clone().unwrap();
    (h, call, request_id)
}

#[tokio::test]
async fn an_undecided_request_is_escalated_once_and_a_late_decision_still_counts() {
    let (h, call, request_id) = paused_request(OnTimeout::Escalate).await;
    let tenant = h.admission.tenant_id.clone();

    // Ten minutes in: still waiting.
    requested_at(&h, &request_id, "2026-10-20T09:50:00Z").await;
    assert_eq!(h.gateway.expire_approvals(&tenant, 100).await.unwrap(), 0);
    assert_eq!(h.gateway.open_escalation_count(&tenant).await.unwrap(), 0);

    // Twenty minutes in: timed out, audited and handed to a human, once.
    requested_at(&h, &request_id, "2026-10-20T09:40:00Z").await;
    assert_eq!(h.gateway.expire_approvals(&tenant, 100).await.unwrap(), 1);
    assert_eq!(h.gateway.expire_approvals(&tenant, 100).await.unwrap(), 0);
    let timed_out = audited(&h, "approval_timed_out").await;
    assert_eq!(timed_out.len(), 1, "{timed_out:?}");
    assert_eq!(timed_out[0]["waited_seconds"], 1200);
    assert_eq!(timed_out[0]["on_timeout"], "escalate");
    assert_eq!(timed_out[0]["approval_request_id"], request_id.as_str());
    assert_eq!(h.gateway.open_escalation_count(&tenant).await.unwrap(), 1);

    // The escalated human approves: the decision counts.
    h.approvals.approve(
        h.gateway
            .dispatch(&h.admission, &call)
            .await
            .unwrap()
            .report
            .action_digest
            .as_deref()
            .unwrap(),
    );
    let done = h.gateway.dispatch(&h.admission, &call).await.unwrap();
    assert_eq!(done.report.status, "completed", "{:?}", done.report);
    assert!(
        matches!(done.report.approval, Some(ApprovalNote::Redeemed { .. })),
        "{:?}",
        done.report.approval
    );
}

#[tokio::test]
async fn under_deny_a_decision_after_the_timeout_is_refused() {
    let (h, call, request_id) = paused_request(OnTimeout::Deny).await;
    let tenant = h.admission.tenant_id.clone();
    requested_at(&h, &request_id, "2026-10-20T09:00:00Z").await;
    assert_eq!(h.gateway.expire_approvals(&tenant, 100).await.unwrap(), 1);
    // Denied, not escalated.
    assert_eq!(h.gateway.open_escalation_count(&tenant).await.unwrap(), 0);

    let paused = h.gateway.dispatch(&h.admission, &call).await.unwrap();
    h.approvals.approve(paused.report.action_digest.as_deref().unwrap());
    let late = h.gateway.dispatch(&h.admission, &call).await.unwrap();
    assert_eq!(late.report.reason_codes, ["approval_timed_out"], "{:?}", late.report);
    assert_eq!(h.adapter.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_redeemed_request_leaves_the_watch_without_timing_out() {
    let (h, call, request_id) = paused_request(OnTimeout::Escalate).await;
    let tenant = h.admission.tenant_id.clone();
    let paused = h.gateway.dispatch(&h.admission, &call).await.unwrap();
    h.approvals.approve(paused.report.action_digest.as_deref().unwrap());
    requested_at(&h, &request_id, "2026-10-20T09:20:00Z").await;
    let done = h.gateway.dispatch(&h.admission, &call).await.unwrap();
    assert_eq!(done.report.status, "completed", "{:?}", done.report);

    requested_at(&h, &request_id, "2026-10-20T08:00:00Z").await;
    assert_eq!(h.gateway.expire_approvals(&tenant, 100).await.unwrap(), 0);
    assert_eq!(audited(&h, "approval_timed_out").await, Vec::<Value>::new());
    let watch = h
        .store
        .get(&DocKey::new(&tenant, DocKind::ApprovalTimeouts, "open"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(watch.body["ids"], json!([]));
}
