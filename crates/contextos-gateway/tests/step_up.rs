//! Approvals that need a step-up count only when the approval service reports a
//! strong, recent sign-in for every approver.

mod support;

use std::sync::atomic::Ordering;

use contextos_gateway::step_up::StepUpPolicy;
use contextos_store::AppendLog;
use serde_json::json;
use support::*;

#[tokio::test]
async fn an_approval_without_a_recent_strong_sign_in_is_not_used() {
    let mut h = harness("require_approval", Behavior::Confirm).await;
    h.gateway.set_approval_step_up(Some(StepUpPolicy {
        amount_at_least: Vec::new(),
        capabilities: vec!["adp_payments.issue_refund".into()],
        acr_values: Vec::new(),
        amr_values: vec!["mfa".into(), "hwk".into()],
        max_age_seconds: 300,
    }));
    let paused = h
        .gateway
        .dispatch(&h.admission, &call("tc_1", Some("refund_big")))
        .await
        .unwrap();
    let digest = paused.report.action_digest.clone().unwrap();
    h.approvals.approve(&digest);

    // Approved, but the service reports no step-up: the approval is not used.
    let refused = h
        .gateway
        .dispatch(&h.admission, &call("tc_2", Some("refund_big")))
        .await
        .unwrap();
    assert_eq!(refused.result["status"], "paused", "{:?}", refused.report);
    assert!(
        refused
            .report
            .reason_codes
            .contains(&"approval_step_up_required".to_owned())
    );
    assert!(refused.report.obligations.contains(&"approve_with_step_up".to_owned()));
    assert_eq!(h.adapter.calls.load(Ordering::SeqCst), 0);

    // A password sign-in an hour before the decision is not a step-up either.
    let set_assurance = |assurance: serde_json::Value| {
        let mut store = h.approvals.1.lock().unwrap();
        store.get_mut(&format!("approved:{digest}")).unwrap()["assurance"] = assurance;
    };
    set_assurance(json!({"approval_1": {"amr": ["pwd"], "auth_time": "2026-10-20T08:30:00Z"}}));
    let weak = h
        .gateway
        .dispatch(&h.admission, &call("tc_3", Some("refund_big")))
        .await
        .unwrap();
    assert_eq!(weak.result["status"], "paused");

    // MFA two minutes before approving: the approval counts and is redeemed.
    set_assurance(json!({"approval_1": {"amr": ["pwd", "mfa"], "auth_time": "2026-10-20T09:28:00Z"}}));
    let done = h
        .gateway
        .dispatch(&h.admission, &call("tc_4", Some("refund_big")))
        .await
        .unwrap();
    assert_eq!(done.result["status"], "completed", "{:?}", done.report);
    assert_eq!(h.adapter.calls.load(Ordering::SeqCst), 1);

    let refusals = h
        .audit
        .log()
        .range(TENANT, 1, 1000)
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.body["kind"] == "approval_step_up_refused")
        .count();
    assert_eq!(refusals, 2);
}
