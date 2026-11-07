//! Information-flow labels: once a run's agent has read untrusted output, its effects
//! need an approval of the exact action; trusted output leaves the run as it was.

mod support;

use contextos_gateway::information_flow::{FlowMode, FlowPolicy};
use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore};
use serde_json::{Value, json};
use support::*;

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

async fn labels(h: &Harness) -> Option<Value> {
    let key = DocKey::new(&h.admission.tenant_id, DocKind::FlowLabels, &h.admission.run_id);
    h.store.get(&key).await.unwrap().map(|d| d.body)
}

#[tokio::test]
async fn after_reading_untrusted_output_an_effect_needs_an_exact_approval() {
    let mut h = harness("allow", Behavior::Confirm).await;
    h.gateway.set_information_flow(Some(FlowPolicy::default()));
    h.admission.guard_policy_ref = h.gateway.guard_policy_ref();

    let first = h
        .gateway
        .dispatch(&h.admission, &call("tc_1", Some("refund_1")))
        .await
        .unwrap();
    assert_eq!(first.result["status"], "completed", "{:?}", first.report);
    let state = labels(&h).await.unwrap();
    assert_eq!(
        state["integrity"], "untrusted",
        "the tool's output is untrusted by default"
    );
    assert_eq!(state["sources"][0]["capability_id"], "adp_payments.issue_refund");

    let mut second = call("tc_2", Some("refund_2"));
    second["args"]["order_id"] = json!("ord_2");
    let paused = h.gateway.dispatch(&h.admission, &second).await.unwrap();
    assert_eq!(paused.result["status"], "paused", "{:?}", paused.report);
    assert!(paused.report.reason_codes.contains(&"flow_untrusted_effect".to_owned()));
    let decisions = audited(&h, "information_flow_decision").await;
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0]["verdict"], "ask");
    assert_eq!(decisions[0]["enforced"], true);

    h.approvals.approve(paused.report.action_digest.as_deref().unwrap());
    let approved = h.gateway.dispatch(&h.admission, &second).await.unwrap();
    assert_eq!(approved.result["status"], "completed", "{:?}", approved.report);
}

#[tokio::test]
async fn trusted_output_leaves_the_run_trusted_and_observe_mode_only_audits() {
    let mut h = harness("allow", Behavior::Confirm).await;
    let mut trusted = manifest();
    trusted.flow = serde_json::from_value(json!({"output_integrity": "trusted"})).unwrap();
    h.gateway.pin_capability(trusted).unwrap();
    h.gateway.set_information_flow(Some(FlowPolicy::default()));
    h.admission.guard_policy_ref = h.gateway.guard_policy_ref();
    for (id, order) in [("tc_1", "ord_1"), ("tc_2", "ord_2")] {
        let mut c = call(id, Some(id));
        c["args"]["order_id"] = json!(order);
        let out = h.gateway.dispatch(&h.admission, &c).await.unwrap();
        assert_eq!(out.result["status"], "completed", "{:?}", out.report);
    }
    assert_eq!(labels(&h).await.unwrap()["integrity"], "trusted");

    let mut h = harness("allow", Behavior::Confirm).await;
    h.gateway.set_information_flow(Some(FlowPolicy {
        mode: FlowMode::Observe,
        ..FlowPolicy::default()
    }));
    h.admission.guard_policy_ref = h.gateway.guard_policy_ref();
    for (id, order) in [("tc_1", "ord_1"), ("tc_2", "ord_2")] {
        let mut c = call(id, Some(id));
        c["args"]["order_id"] = json!(order);
        let out = h.gateway.dispatch(&h.admission, &c).await.unwrap();
        assert_eq!(
            out.result["status"], "completed",
            "observe never blocks: {:?}",
            out.report
        );
    }
    let decisions = audited(&h, "information_flow_decision").await;
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0]["enforced"], false);
    assert_eq!(decisions[0]["reason_codes"], json!(["flow_untrusted_effect"]));
}

#[tokio::test]
async fn a_run_admitted_before_the_guard_was_on_is_refused_rather_than_approved() {
    let mut h = harness("allow", Behavior::Confirm).await;
    h.gateway.set_information_flow(Some(FlowPolicy::default()));
    let first = h
        .gateway
        .dispatch(&h.admission, &call("tc_1", Some("refund_1")))
        .await
        .unwrap();
    assert_eq!(first.result["status"], "completed", "{:?}", first.report);
    let mut second = call("tc_2", Some("refund_2"));
    second["args"]["order_id"] = json!("ord_2");
    let refused = h.gateway.dispatch(&h.admission, &second).await.unwrap();
    assert_eq!(refused.report.status, "blocked", "{:?}", refused.report);
    assert!(refused.report.reason_codes.contains(&"flow_policy_unpinned".to_owned()));
}
