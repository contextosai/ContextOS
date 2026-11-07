//! `[providers.action_monitor]`: a trusted monitor scores each effect before it is
//! sent, over HTTP, and its score decides through the kernel.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::routing::post;
use contextos_gateway::action_monitor::MonitorPolicy;
use serde_json::{Value, json};

use crate::harness::*;

#[tokio::test]
async fn a_suspicious_effect_is_denied_and_the_monitor_sees_the_trajectory() {
    let seen: Arc<Mutex<Vec<Value>>> = Arc::default();
    let log = seen.clone();
    let monitor = serve(Router::new().fallback(post(move |axum::Json(r): axum::Json<Value>| {
        let log = log.clone();
        async move {
            log.lock().unwrap().push(r.clone());
            // Large refunds to this customer look like exfiltration of funds.
            let suspicion = if r["binding"]["amount"]["minor_units"].as_u64() > Some(900) {
                0.97
            } else {
                0.1
            };
            axum::Json(json!({"suspicion": suspicion, "reason_codes": ["amount_outlier"]}))
        }
    })))
    .await;
    let w = world_with(&ALL_CONTROLS, 1, |c| {
        let mut provider = c.providers.as_ref().unwrap().authority.clone();
        provider.url = monitor;
        c.providers.as_mut().unwrap().action_monitor = Some(provider);
        c.guards.action_monitor = Some(MonitorPolicy::default());
    })
    .await;
    assert_eq!(admit(&w, &run_body("run_mon", 1200)).await.status(), 201);
    let calm = dispatch(&w, "run_mon", &refund("run_mon", "refund_a", "ord_881", "cus_77", 100)).await;
    assert_eq!(calm["report"]["status"], "completed", "{calm}");
    let suspicious = dispatch(&w, "run_mon", &refund("run_mon", "refund_b", "ord_881", "cus_77", 1000)).await;
    assert_eq!(suspicious["report"]["status"], "blocked", "{suspicious}");
    let reasons = suspicious["report"]["reason_codes"].to_string();
    assert!(reasons.contains("action_monitor_deny"), "{suspicious}");

    let requests = seen.lock().unwrap().clone();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0]["binding"]["capability_id"], "adp_payments.issue_refund");
    assert_eq!(
        requests[1]["trajectory"]["calls"][0]["operation_id"], "refund_a",
        "the monitor sees earlier calls"
    );
}
