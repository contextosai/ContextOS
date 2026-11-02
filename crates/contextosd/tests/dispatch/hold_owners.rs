//! A hold that waits past its guarantee's threshold is reported once to the
//! guarantee's business owner, from the audit chain, and to no other webhook.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::routing::post;
use contextos_store::AppendLog;
use contextosd::governance_sweep::{Census, SweepConfig};
use contextosd::notifications::{Dispatcher, Webhook, WebhookConfig};
use serde_json::{Value, json};

use crate::harness::*;

const SECRET: &str = "owner-secret-0123456789abcdef0123456789";

async fn receiver() -> (String, Arc<Mutex<Vec<Value>>>) {
    let received: Arc<Mutex<Vec<Value>>> = Arc::default();
    let seen = received.clone();
    let base = serve(Router::new().route(
        "/hook",
        post(move |body: String| {
            let seen = seen.clone();
            async move {
                seen.lock().unwrap().push(serde_json::from_str(&body).unwrap());
                axum::http::StatusCode::NO_CONTENT
            }
        }),
    ))
    .await;
    (format!("{base}/hook"), received)
}

fn webhook(id: &str, url: String) -> WebhookConfig {
    WebhookConfig {
        id: id.into(),
        url,
        secret_env: "UNUSED".into(),
        link_template: None,
        max_attempts: 3,
    }
}

#[tokio::test]
async fn an_aged_hold_reaches_its_owner_once_and_no_one_else() {
    let (owner_url, to_owner) = receiver().await;
    let (oncall_url, to_oncall) = receiver().await;
    let hooks = [webhook("refund_leads", owner_url), webhook("oncall", oncall_url)];
    // The dispatcher holds the webhooks; the server only needs the route on the guarantee.
    let w = world_with(&ALL_CONTROLS, 1, |c| {
        c.guarantees = vec![
            serde_json::from_value(json!({"id":"refunds","capability_ids":["adp_payments.issue_refund"],
            "resource_pointer":"/order_id","amount_pointer":"/amount_minor","limit":1000,"unit":"INR_minor",
            "owner_route":"refund_leads","owner_after_seconds":1}))
            .unwrap(),
        ];
    })
    .await;
    let gateway = w.state.gateway.clone().unwrap();
    let mut dispatcher = Dispatcher::new(
        w.state.store.clone(),
        w.state.audit.clone(),
        w.state.metrics.clone(),
        hooks
            .into_iter()
            .map(|h| Webhook::new(h, SECRET.as_bytes()).unwrap())
            .collect(),
        vec![TENANT.into()],
        true,
    );
    dispatcher.tick().await; // cursors start at the head

    // An effect whose outcome is unknown holds 777 of the order's 1,000.
    let http = executor_client(2);
    let admitted = http
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_held", 7))
        .send()
        .await
        .unwrap();
    assert_eq!(admitted.status(), 201);
    let out: Value = http
        .post(format!("{}/v1/runs/run_held/tool-calls", w.base))
        .bearer_auth("acme-key")
        .json(&tool_call("run_held", "pending", 777))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(out["result"]["status"], "paused", "{out}");

    let config = SweepConfig::default();
    let mut census = Census::new(vec![TENANT.into()], gateway.shared_guarantee_ids());
    census.step(&gateway, &config).await.unwrap();
    let reported = |kind: &'static str| {
        let audit = w.state.audit.clone();
        async move {
            audit
                .log()
                .range(TENANT, 1, 1000)
                .await
                .unwrap()
                .into_iter()
                .filter(|e| e.body["kind"] == kind)
                .map(|e| e.body["payload"].clone())
                .collect::<Vec<_>>()
        }
    };
    assert!(
        reported("shared_hold_aged").await.is_empty(),
        "younger than its threshold"
    );

    tokio::time::sleep(Duration::from_millis(1100)).await;
    // A later pass, or a new leader's sweep, does not report it again.
    census.step(&gateway, &config).await.unwrap();
    let mut fresh = Census::new(vec![TENANT.into()], gateway.shared_guarantee_ids());
    fresh.step(&gateway, &config).await.unwrap();
    let aged = reported("shared_hold_aged").await;
    assert_eq!(aged.len(), 1, "{aged:?}");
    assert_eq!(aged[0]["amount"], 777);
    assert_eq!(aged[0]["state"], "unknown_provider_reference");
    assert_eq!(aged[0]["run_id"], "run_held");
    assert!(
        aged[0]["next_safe_step"]["reconcile"]
            .as_str()
            .unwrap()
            .ends_with("/reconcile")
    );

    dispatcher.tick().await;
    let owner = to_owner.lock().unwrap().clone();
    assert_eq!(owner.len(), 1);
    assert_eq!(owner[0]["type"], "io.contextos.hold.aged");
    assert_eq!(owner[0]["data"]["guarantee_id"], "refunds");
    assert_eq!(owner[0]["data"]["amount"], 777);
    assert!(
        !owner[0].to_string().contains("cus_77"),
        "no tool arguments: {}",
        owner[0]
    );
    assert!(to_oncall.lock().unwrap().is_empty(), "other webhooks are not told");

    // A hold no longer held is not reported.
    assert!(
        !gateway
            .report_aged_hold(
                TENANT,
                "refunds",
                aged[0]["resource_digest"].as_str().unwrap(),
                "sha256:none",
                99
            )
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn an_owner_route_must_name_a_webhook() {
    let (mut config, _) = world_setup(&ALL_CONTROLS).await;
    config.guarantees = vec![
        serde_json::from_value(json!({"id":"refunds","capability_ids":["adp_payments.issue_refund"],
        "resource_pointer":"/order_id","amount_pointer":"/amount_minor","limit":1000,"unit":"INR_minor",
        "owner_route":"refund_leads"}))
        .unwrap(),
    ];
    let error = contextosd::notifications::check(&config).unwrap_err();
    assert!(error.contains("owner_route refund_leads"), "{error}");
}
