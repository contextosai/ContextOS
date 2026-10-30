//! Escalation notifications are delivered from the signed audit chain, signed, at
//! least once, and never for anything the chain does not record.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use contextosd::notifications::{Dispatcher, Webhook, WebhookConfig};
use serde_json::{Value, json};

use crate::harness::*;

type Received = Arc<Mutex<Vec<(HeaderMap, Value)>>>;

const SECRET: &str = "notify-secret-0123456789abcdef0123456789";

async fn receiver(failing: Arc<AtomicBool>) -> (String, Received) {
    let received: Received = Arc::default();
    let seen = received.clone();
    let base = serve(Router::new().route(
        "/hook",
        post(move |headers: HeaderMap, body: String| {
            let seen = seen.clone();
            let failing = failing.clone();
            async move {
                if failing.load(Ordering::SeqCst) {
                    return StatusCode::SERVICE_UNAVAILABLE;
                }
                seen.lock()
                    .unwrap()
                    .push((headers, serde_json::from_str(&body).unwrap()));
                StatusCode::NO_CONTENT
            }
        }),
    ))
    .await;
    (format!("{base}/hook"), received)
}

#[tokio::test]
async fn escalations_in_the_chain_reach_the_webhook_signed_and_once() {
    let failing = Arc::new(AtomicBool::new(false));
    let (url, received) = receiver(failing.clone()).await;
    let hook = Webhook::new(
        WebhookConfig {
            id: "oncall".into(),
            url,
            secret_env: "CONTEXTOS_TEST_NOTIFY_SECRET".into(),
            link_template: Some("https://tower.example/escalations/{escalation_id}".into()),
            max_attempts: 3,
        },
        SECRET.as_bytes(),
    )
    .unwrap();
    let w = world(&ALL_CONTROLS).await;
    let metrics = w.state.metrics.clone();
    let mut dispatcher = Dispatcher::new(
        w.state.store.clone(),
        w.state.audit.clone(),
        metrics.clone(),
        vec![hook],
        vec![TENANT.into()],
        true,
    );
    let now = || w.state.gateway.as_ref().unwrap().now();
    w.state
        .audit
        .append(
            TENANT,
            "escalation_opened",
            json!({"escalation_id": "esc_before"}),
            &now(),
        )
        .await
        .unwrap();
    // A new webhook starts at the chain's head: history is not replayed.
    dispatcher.tick().await;
    assert!(received.lock().unwrap().is_empty());

    let opened = json!({"escalation_id": "esc_1", "run_id": "run_1", "operation_id": "op_1",
        "capability_id": "adp_payments.issue_refund", "action_digest": "sha256:ab",
        "policy_decision_id": "dec_1", "reason_codes": ["policy_escalation"]});
    let entry = w
        .state
        .audit
        .append(TENANT, "escalation_opened", opened, &now())
        .await
        .unwrap();
    w.state
        .audit
        .append(TENANT, "run_admitted", json!({"run_id": "run_2"}), &now())
        .await
        .unwrap();
    dispatcher.tick().await;
    dispatcher.tick().await;
    {
        let received = received.lock().unwrap();
        assert_eq!(received.len(), 1, "delivered once, other kinds skipped");
        let (headers, event) = &received[0];
        assert_eq!(event["id"], format!("{TENANT}:{}", entry.sequence));
        assert_eq!(event["type"], "io.contextos.escalation.opened");
        assert_eq!(event["data"]["link"], "https://tower.example/escalations/esc_1");
        let signature = headers["contextos-signature"].to_str().unwrap();
        let (t, v1) = signature.strip_prefix("t=").unwrap().split_once(",v1=").unwrap();
        let body = serde_json::to_vec(event).unwrap();
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, SECRET.as_bytes());
        let mut message = format!("{t}.").into_bytes();
        message.extend_from_slice(&body);
        ring::hmac::verify(&key, &message, &hex::decode(v1).unwrap()).expect("valid signature");
    }

    // A failing receiver is retried; the event is not skipped while attempts remain.
    failing.store(true, Ordering::SeqCst);
    w.state
        .audit
        .append(
            TENANT,
            "escalation_resolved",
            json!({"escalation_id": "esc_1", "run_id": "run_1",
            "outcome": "handled", "by": "svc_oncall", "reason": "refunded manually"}),
            &now(),
        )
        .await
        .unwrap();
    dispatcher.tick().await;
    let text = metrics.render();
    assert!(
        text.contains("contextos_notifications_total{webhook=\"oncall\",outcome=\"failed\"} 1\n"),
        "{text}"
    );
    failing.store(false, Ordering::SeqCst);
    dispatcher.tick().await; // still backing off
    assert_eq!(received.lock().unwrap().len(), 1);
}
