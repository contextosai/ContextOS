//! What an agent is told, and what is recorded, when a call cites no evidence where a
//! capability requires it, an approval is denied, an applied operation is sent again,
//! or a run is refused because its agent is revoked.

mod support;

use std::sync::atomic::Ordering;

use contextos_gateway::AdmissionTargets;
use contextos_store::AppendLog;
use serde_json::{Value, json};
use support::*;

async fn audited(h: &Harness, kind: &str) -> Vec<Value> {
    h.audit
        .log()
        .range(TENANT, 1, 1000)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.body["kind"] == kind)
        .map(|e| e.body["payload"].clone())
        .collect()
}

fn refund(id: &str, order: &str) -> Value {
    let mut c = call(id, Some(id));
    c["args"]["order_id"] = json!(order);
    c
}

#[tokio::test]
async fn a_capability_can_require_admitted_evidence() {
    let mut h = harness("allow", Behavior::Confirm).await;
    // Off by default: a call citing nothing runs, as before.
    let mut bare = refund("tc_1", "ord_1");
    bare["evidence_refs"] = json!([]);
    let out = h.gateway.dispatch(&h.admission, &bare).await.unwrap();
    assert_eq!(out.report.status, "completed", "{:?}", out.report);

    let mut pinned = manifest();
    pinned.evidence_required = true;
    h.gateway.pin_capability(pinned).unwrap();
    let mut bare = refund("tc_2", "ord_2");
    bare["evidence_refs"] = json!([]);
    let out = h.gateway.dispatch(&h.admission, &bare).await.unwrap();
    assert_eq!(out.result["status"], "rejected");
    assert_eq!(out.report.reason_codes, ["evidence_required"]);
    assert_eq!(out.report.obligations, ["cite_admitted_evidence"]);
    // A made-up citation is still refused as not admitted.
    let mut forged = refund("tc_3", "ord_3");
    forged["evidence_refs"] = json!(["kg:forged"]);
    let out = h.gateway.dispatch(&h.admission, &forged).await.unwrap();
    assert_eq!(out.report.reason_codes, ["evidence_not_admitted"]);
    assert_eq!(
        h.adapter.calls.load(Ordering::SeqCst),
        1,
        "neither refused call was sent"
    );

    // Citing what the run admitted, it runs.
    let out = h
        .gateway
        .dispatch(&h.admission, &refund("tc_4", "ord_4"))
        .await
        .unwrap();
    assert_eq!(out.report.status, "completed", "{:?}", out.report);

    // The setting round-trips, and manifests without it serialize as before.
    assert!(
        !serde_json::to_value(manifest())
            .unwrap()
            .as_object()
            .unwrap()
            .contains_key("evidence_required")
    );
}

#[tokio::test]
async fn a_denied_approval_refuses_the_call() {
    let h = harness("require_approval", Behavior::Confirm).await;
    let paused = h
        .gateway
        .dispatch(&h.admission, &call("tc_1", Some("refund_big")))
        .await
        .unwrap();
    assert_eq!(paused.result["status"], "paused");
    h.approvals.deny(paused.report.action_digest.as_deref().unwrap());
    let refused = h
        .gateway
        .dispatch(&h.admission, &call("tc_2", Some("refund_big")))
        .await
        .unwrap();
    assert_eq!(refused.result["status"], "blocked", "{:?}", refused.report);
    assert!(
        refused.report.reason_codes.contains(&"approval_denied".to_owned()),
        "{:?}",
        refused.report
    );
    assert_eq!(h.adapter.calls.load(Ordering::SeqCst), 0, "nothing was sent");
    // The denial is evidence too, for approval analytics.
    let denied: Vec<serde_json::Value> = contextos_store::AppendLog::range(h.audit.log(), TENANT, 1, 1000)
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.body)
        .filter(|e| e["kind"] == "approval_denied")
        .collect();
    assert_eq!(denied.len(), 1);
    assert_eq!(denied[0]["payload"]["capability_id"], "adp_payments.issue_refund");
}

#[tokio::test]
async fn a_retry_of_an_applied_operation_points_to_its_result() {
    let mut h = harness("allow", Behavior::Confirm).await;
    h.gateway.set_shared_guarantees(vec![shared_rule()]).unwrap();
    let done = h
        .gateway
        .dispatch(&h.admission, &call("tc_1", Some("refund_1")))
        .await
        .unwrap();
    assert_eq!(done.report.status, "completed", "{:?}", done.report);
    let settled = audited(&h, "shared_guarantee_settled").await.len();
    assert_eq!(settled, 1);

    for id in ["tc_2", "tc_3"] {
        let again = h
            .gateway
            .dispatch(&h.admission, &call(id, Some("refund_1")))
            .await
            .unwrap();
        assert_eq!(again.result["status"], "paused");
        assert_eq!(again.report.reason_codes, ["retry_unsafe"]);
        let applied = &again.result["metadata"]["applied_operation"];
        assert_eq!(applied["operation_id"], "refund_1");
        assert_eq!(applied["outcome"], "confirmed");
        assert_eq!(applied["attempt_id"], done.report.attempt_id.as_deref().unwrap());
        assert_eq!(applied["evidence_ref"]["artifact_type"], "effect_observation");
        assert!(
            !applied.to_string().contains("rf_1"),
            "the provider's reference stays recorded"
        );
        assert!(again.result["error"].as_str().unwrap().contains("already applied"));
    }
    assert_eq!(h.adapter.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        audited(&h, "shared_guarantee_settled").await.len(),
        settled,
        "settled once"
    );
    assert_eq!(audited(&h, "shared_guarantee_settlement_requested").await.len(), 1);
}

#[tokio::test]
async fn a_run_refused_for_a_revoked_agent_is_audited_with_the_revoker() {
    let h = harness("allow", Behavior::Confirm).await;
    let targets = AdmissionTargets {
        tenant_id: TENANT,
        pack_ref: &h.admission.pack_ref,
        principal: &h.admission.admitted_by,
        agent_id: "agt_support",
        declared_user: None,
        chain: None,
        parent: None,
    };
    assert!(h.gateway.admission_revoked(&targets).await.unwrap().is_none());
    assert!(
        audited(&h, "revocation_refusal").await.is_empty(),
        "admission is not a refusal"
    );

    for (id, by, revoker) in [
        ("tc_1", "circuit_breaker:refund_rate", "circuit breaker refund_rate"),
        ("tc_2", "svc_oncall", "an operator"),
    ] {
        h.gateway
            .set_revocation(TENANT, "agent", "agt_support", "incident", by, true)
            .await
            .unwrap();
        let revoked = h.gateway.admission_revoked(&targets).await.unwrap().unwrap();
        assert_eq!(revoked.reason_code, "revoked_agent");
        assert_eq!(revoked.by, by);
        assert_eq!(revoked.message(), format!("The agent has been revoked by {revoker}."));
        let refusal = audited(&h, "revocation_refusal").await.pop().unwrap();
        assert_eq!(refusal["stage"], "admission");
        assert_eq!(refusal["agent_id"], "agt_support");
        assert_eq!(refusal["reason_codes"], json!(["revoked_agent"]));
        assert_eq!(refusal["revoked_by"], by);

        // A call of a running run says the same.
        let blocked = h.gateway.dispatch(&h.admission, &refund(id, "ord_9")).await.unwrap();
        assert_eq!(blocked.result["error"], json!(revoked.message()));
        h.gateway
            .set_revocation(TENANT, "agent", "agt_support", "fixed", "svc_oncall", false)
            .await
            .unwrap();
    }
}
