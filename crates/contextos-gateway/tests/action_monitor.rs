//! The action monitor's score decides through the kernel: an `ask` is an approval of
//! the exact action, scores accumulate per run, and an unusable monitor fails by policy.

mod support;

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use contextos_gateway::action_monitor::{ActionMonitorProvider, MonitorPolicy};
use contextos_gateway::information_flow::FlowVerdict;
use contextos_gateway::*;
use contextos_store::AppendLog;
use serde_json::{Value, json};
use support::*;

/// Answers with the score the test sets (`None`: unreachable).
struct Monitor(Mutex<Option<Value>>);

#[async_trait]
impl ActionMonitorProvider for Monitor {
    async fn assess(
        &self,
        _: &RunAdmission,
        _: &CapabilityManifest,
        binding: &Value,
        _: &Value,
    ) -> Result<Value, PortError> {
        assert!(binding["arguments"].is_object(), "the monitor sees the action");
        self.0
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| PortError::new("action_monitor", "unreachable"))
    }
}

async fn monitored(policy: MonitorPolicy) -> (Harness, Arc<Monitor>) {
    let mut h = harness("allow", Behavior::Confirm).await;
    let monitor = Arc::new(Monitor(Mutex::new(Some(json!({"suspicion": 0.0})))));
    h.gateway.set_action_monitor(Some((monitor.clone(), policy)));
    h.admission.guard_policy_ref = h.gateway.guard_policy_ref();
    (h, monitor)
}

fn refund(id: &str, order: &str) -> Value {
    let mut c = call(id, Some(id));
    c["args"]["order_id"] = json!(order);
    c
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
async fn graded_responses_allow_ask_deny_and_fail_by_policy() {
    let (h, monitor) = monitored(MonitorPolicy::default()).await;
    let calm = h
        .gateway
        .dispatch(&h.admission, &refund("tc_1", "ord_1"))
        .await
        .unwrap();
    assert_eq!(calm.report.status, "completed", "{:?}", calm.report);

    *monitor.0.lock().unwrap() = Some(json!({"suspicion": 0.6, "reason_codes": ["unusual_recipient"]}));
    let paused = h
        .gateway
        .dispatch(&h.admission, &refund("tc_2", "ord_2"))
        .await
        .unwrap();
    assert_eq!(paused.result["status"], "paused", "{:?}", paused.report);
    assert!(paused.report.reason_codes.contains(&"action_monitor_ask".to_owned()));
    h.approvals.approve(paused.report.action_digest.as_deref().unwrap());
    let approved = h
        .gateway
        .dispatch(&h.admission, &refund("tc_2", "ord_2"))
        .await
        .unwrap();
    assert_eq!(
        approved.report.status, "completed",
        "an exact approval clears it: {:?}",
        approved.report
    );

    *monitor.0.lock().unwrap() = Some(json!({"suspicion": 0.95}));
    let denied = h
        .gateway
        .dispatch(&h.admission, &refund("tc_3", "ord_3"))
        .await
        .unwrap();
    assert_eq!(denied.report.status, "blocked");
    assert!(denied.report.reason_codes.contains(&"action_monitor_deny".to_owned()));

    *monitor.0.lock().unwrap() = None;
    let unavailable = h
        .gateway
        .dispatch(&h.admission, &refund("tc_4", "ord_4"))
        .await
        .unwrap();
    assert_eq!(
        unavailable.result["status"], "paused",
        "fails to ask: {:?}",
        unavailable.report
    );
    assert!(
        unavailable
            .report
            .reason_codes
            .contains(&"action_monitor_unavailable".to_owned())
    );

    let entries = audited(&h, "action_monitored").await;
    let verdicts: Vec<&str> = entries.iter().filter_map(|e| e["verdict"].as_str()).collect();
    assert_eq!(verdicts, ["ask", "ask", "deny", "ask"], "calm calls are not audited");
    assert!(
        !json!(entries).to_string().contains("amount_minor"),
        "no arguments in the chain"
    );
}

#[tokio::test]
async fn many_mild_scores_exhaust_the_run_budget() {
    let (h, monitor) = monitored(MonitorPolicy {
        run_budget: Some(0.5),
        ..MonitorPolicy::default()
    })
    .await;
    *monitor.0.lock().unwrap() = Some(json!({"suspicion": 0.3}));
    let first = h
        .gateway
        .dispatch(&h.admission, &refund("tc_1", "ord_1"))
        .await
        .unwrap();
    assert_eq!(first.report.status, "completed", "{:?}", first.report);
    let second = h
        .gateway
        .dispatch(&h.admission, &refund("tc_2", "ord_2"))
        .await
        .unwrap();
    assert_eq!(second.result["status"], "paused", "{:?}", second.report);
    assert!(
        second
            .report
            .reason_codes
            .contains(&"action_monitor_run_budget".to_owned())
    );
}

#[tokio::test]
async fn a_hard_failing_monitor_denies_and_an_unpinned_run_is_refused() {
    let (h, monitor) = monitored(MonitorPolicy {
        on_unavailable: FlowVerdict::Deny,
        ..MonitorPolicy::default()
    })
    .await;
    *monitor.0.lock().unwrap() = Some(json!({"suspicion": "high"}));
    let denied = h
        .gateway
        .dispatch(&h.admission, &refund("tc_1", "ord_1"))
        .await
        .unwrap();
    assert_eq!(denied.report.status, "blocked", "{:?}", denied.report);

    let (mut h, monitor) = monitored(MonitorPolicy::default()).await;
    h.admission.guard_policy_ref = None;
    *monitor.0.lock().unwrap() = Some(json!({"suspicion": 0.6}));
    let refused = h
        .gateway
        .dispatch(&h.admission, &refund("tc_1", "ord_1"))
        .await
        .unwrap();
    assert!(
        refused
            .report
            .reason_codes
            .contains(&"monitor_policy_unpinned".to_owned()),
        "{:?}",
        refused.report
    );
}
