//! Failover across a provider's endpoints never risks an effect twice.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::Router;
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::post;
use contextos_adapters::*;
use contextos_gateway::{Adapter, AdapterCall, CapabilityManifest, EffectOutcome};
use serde_json::{Value, json};

/// A server answering every request with `status` (and, for 200, the tool result),
/// counting requests.
async fn server(status: StatusCode) -> (String, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let router = Router::new().fallback(post(move |body: String| {
        let counter = counter.clone();
        async move {
            counter.fetch_add(1, Ordering::SeqCst);
            let request: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
            if status != StatusCode::OK {
                return status.into_response();
            }
            let result = json!({"jsonrpc": "2.0", "id": request["id"],
                "result": {"content": [], "structuredContent": {"refund_id": "rf_1"}}});
            ([(header::CONTENT_TYPE, "application/json")], result.to_string()).into_response()
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{addr}/mcp"), hits)
}

/// A server that accepts the connection and the request, then closes without answering.
async fn black_hole() -> (String, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            let mut buf = vec![0u8; 8192];
            let _ = tokio::io::AsyncReadExt::read(&mut socket, &mut buf).await;
            drop(socket);
        }
    });
    (format!("http://{addr}/mcp"), hits)
}

/// A server that accepts the connection, reads the request and then holds the
/// connection open without ever answering.
async fn hang() -> (String, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let _ = tokio::io::AsyncReadExt::read(&mut socket, &mut buf).await;
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                drop(socket);
            });
        }
    });
    (format!("http://{addr}/mcp"), hits)
}

/// Invokes as the gateway does: the whole call under the capability's timeout.
async fn invoke_under_timeout(primary: &str, fallbacks: &[String], effect: &str) -> contextos_gateway::AdapterResponse {
    let timeout = std::time::Duration::from_millis(manifest(effect).timeout_ms);
    tokio::time::timeout(timeout, invoke(primary, fallbacks, effect))
        .await
        .unwrap_or_else(|_| contextos_gateway::AdapterResponse::unknown())
}

fn closed_port() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/mcp", listener.local_addr().unwrap());
    drop(listener);
    url
}

fn manifest(effect: &str) -> CapabilityManifest {
    serde_json::from_value(json!({
        "capability_id": "adp_payments.issue_refund", "capability_version": "3", "adapter_id": "adp_payments",
        "protocol_tool": "issue_refund", "purpose_id": "support.refund", "desired_effect": "refund_created",
        "action_risk": {"effect": effect, "authority": "service", "reversibility": "compensatable", "interaction": "api", "data_scope": "CONFIDENTIAL"},
        "approval_mode": "destructive",
        "recovery": {"strategy": "manual_reconcile", "max_attempts": 1, "retry_delays_seconds": []},
        "timeout_ms": 2000, "reservation": {"tokens": 0, "tool_calls": 1, "replans": 0, "cost_units": 1},
        "adapter_ref": {}, "capability_ref": {},
    }))
    .unwrap()
}

fn call() -> AdapterCall {
    AdapterCall {
        tenant_id: "tenant_acme_prod".into(),
        run_id: "run_1".into(),
        trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".into(),
        operation_id: "op_refund".into(),
        attempt_id: "attempt_7".into(),
        action_digest: format!("sha256:{}", "a".repeat(64)),
        protocol_tool: "issue_refund".into(),
        arguments: json!({"order_id": "ord_881", "amount_minor": 420}),
        idempotency_key: Some("ctxos:op_refund".into()),
        deadline: "2026-10-20T10:00:05Z".into(),
        input: None,
        executor_generation: None,
    }
}

async fn invoke(primary: &str, fallbacks: &[String], effect: &str) -> contextos_gateway::AdapterResponse {
    let policy = TransportPolicy {
        allow_loopback_http: true,
        ..TransportPolicy::default()
    };
    McpAdapter::new(primary, policy, Arc::new(NoCredentials), "contextos-test")
        .unwrap()
        .with_fallback_endpoints(fallbacks)
        .unwrap()
        .invoke(&manifest(effect), &call())
        .await
}

#[tokio::test]
async fn an_unreachable_endpoint_hands_any_call_to_the_next() {
    let (replica, hits) = server(StatusCode::OK).await;
    let response = invoke(&closed_port(), &[replica], "external_state").await;
    assert_eq!(response.outcome, EffectOutcome::Confirmed, "{response:?}");
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_effect_that_may_have_been_delivered_is_never_sent_again() {
    // The primary read the request and dropped the connection: it may have refunded.
    let (lost, lost_hits) = black_hole().await;
    let (replica, replica_hits) = server(StatusCode::OK).await;
    let response = invoke(&lost, std::slice::from_ref(&replica), "external_state").await;
    assert_eq!(response.outcome, EffectOutcome::Unknown);
    assert_eq!(lost_hits.load(Ordering::SeqCst), 1);
    assert_eq!(replica_hits.load(Ordering::SeqCst), 0, "no second delivery");

    // An overloaded primary may also have applied it before failing.
    let (busy, _) = server(StatusCode::SERVICE_UNAVAILABLE).await;
    let response = invoke(&busy, &[replica], "external_state").await;
    assert_ne!(response.outcome, EffectOutcome::Confirmed);
    assert_eq!(replica_hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn read_only_calls_move_on_after_a_lost_response_or_overload() {
    let (lost, _) = black_hole().await;
    let (busy, busy_hits) = server(StatusCode::SERVICE_UNAVAILABLE).await;
    let (replica, replica_hits) = server(StatusCode::OK).await;
    let response = invoke(&lost, &[busy, replica], "none").await;
    assert_eq!(response.outcome, EffectOutcome::Confirmed, "{response:?}");
    assert_eq!(busy_hits.load(Ordering::SeqCst), 1);
    assert_eq!(replica_hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_failing_endpoint_is_ejected_and_tried_last() {
    let (busy, busy_hits) = server(StatusCode::SERVICE_UNAVAILABLE).await;
    let (replica, replica_hits) = server(StatusCode::OK).await;
    let policy = TransportPolicy {
        allow_loopback_http: true,
        ..TransportPolicy::default()
    };
    let adapter = McpAdapter::new(&busy, policy, Arc::new(NoCredentials), "contextos-test")
        .unwrap()
        .with_fallback_endpoints(&[replica])
        .unwrap();
    for _ in 0..5 {
        let response = adapter.invoke(&manifest("none"), &call()).await;
        assert_eq!(response.outcome, EffectOutcome::Confirmed);
    }
    // Three failures ejected the primary; later calls went straight to the replica.
    assert_eq!(busy_hits.load(Ordering::SeqCst), 3);
    assert_eq!(replica_hits.load(Ordering::SeqCst), 5);
}

#[tokio::test]
async fn a_hung_endpoint_hands_a_read_only_call_to_the_next_within_the_timeout() {
    let (hung, hung_hits) = hang().await;
    let (replica, replica_hits) = server(StatusCode::OK).await;
    let response = invoke_under_timeout(&hung, &[replica], "none").await;
    assert_eq!(response.outcome, EffectOutcome::Confirmed, "{response:?}");
    assert_eq!(hung_hits.load(Ordering::SeqCst), 1);
    assert_eq!(replica_hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_hung_endpoint_leaves_an_effect_unknown_and_never_resends_it() {
    let (hung, hung_hits) = hang().await;
    let (replica, replica_hits) = server(StatusCode::OK).await;
    let response = invoke_under_timeout(&hung, &[replica], "external_state").await;
    assert_eq!(response.outcome, EffectOutcome::Unknown, "{response:?}");
    assert_eq!(hung_hits.load(Ordering::SeqCst), 1);
    assert_eq!(replica_hits.load(Ordering::SeqCst), 0, "no second delivery");
}

#[tokio::test]
async fn a_500_counts_toward_ejection_without_moving_a_call_on() {
    let (broken, broken_hits) = server(StatusCode::INTERNAL_SERVER_ERROR).await;
    let (replica, replica_hits) = server(StatusCode::OK).await;
    let policy = TransportPolicy {
        allow_loopback_http: true,
        ..TransportPolicy::default()
    };
    let adapter = McpAdapter::new(&broken, policy, Arc::new(NoCredentials), "contextos-test")
        .unwrap()
        .with_fallback_endpoints(&[replica])
        .unwrap();
    for _ in 0..3 {
        let response = adapter.invoke(&manifest("none"), &call()).await;
        assert_ne!(response.outcome, EffectOutcome::Confirmed, "a 500 is not moved past");
    }
    assert_eq!(replica_hits.load(Ordering::SeqCst), 0);
    // Three 500s ejected the primary; the replica now answers first.
    let response = adapter.invoke(&manifest("none"), &call()).await;
    assert_eq!(response.outcome, EffectOutcome::Confirmed);
    assert_eq!(broken_hits.load(Ordering::SeqCst), 3);
    assert_eq!(replica_hits.load(Ordering::SeqCst), 1);
}
