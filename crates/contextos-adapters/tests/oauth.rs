//! The OAuth client-credentials broker against a local token endpoint.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use contextos_adapters::{CredentialBroker, OAuthClientCredentials, TransportPolicy};
use contextos_gateway::{AdapterCall, CapabilityManifest};
use serde_json::{Value, json};

type Requests = Arc<Mutex<Vec<(HeaderMap, String)>>>;

async fn token_server(answer: fn(usize) -> Response) -> (String, Requests) {
    let requests: Requests = Arc::default();
    let seen = requests.clone();
    let count = Arc::new(AtomicUsize::new(0));
    let router = Router::new().route(
        "/token",
        post(move |headers: HeaderMap, body: String| {
            let seen = seen.clone();
            let n = count.fetch_add(1, Ordering::SeqCst);
            async move {
                seen.lock().unwrap().push((headers, body));
                answer(n)
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{addr}/token"), requests)
}

fn token(value: Value) -> Response {
    ([(header::CONTENT_TYPE, "application/json")], value.to_string()).into_response()
}

fn broker(url: &str, refresh_before: Duration) -> OAuthClientCredentials {
    let policy = TransportPolicy {
        allow_loopback_http: true,
        ..TransportPolicy::default()
    };
    OAuthClientCredentials::new(
        url,
        "contextos-gateway",
        "client-secret",
        Some("payments.refund".into()),
        "https://payments-mcp.internal.example/mcp",
        refresh_before,
        &policy,
    )
    .unwrap()
}

fn manifest() -> CapabilityManifest {
    serde_json::from_value(json!({
        "capability_id": "adp_payments.issue_refund", "capability_version": "3", "adapter_id": "adp_payments",
        "protocol_tool": "issue_refund", "purpose_id": "support.refund", "desired_effect": "refund_created",
        "action_risk": {"effect": "external_state", "authority": "service", "reversibility": "compensatable", "interaction": "api", "data_scope": "CONFIDENTIAL"},
        "approval_mode": "destructive",
        "recovery": {"strategy": "manual_reconcile", "max_attempts": 1, "retry_delays_seconds": []},
        "timeout_ms": 2000, "reservation": {"tokens": 0, "tool_calls": 1, "replans": 0, "cost_units": 1},
        "adapter_ref": {}, "capability_ref": {},
    }))
    .unwrap()
}

fn call() -> AdapterCall {
    serde_json::from_value(
        json!({"tenant_id": "t", "run_id": "run_1", "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
        "operation_id": "op_1", "attempt_id": "att_1", "action_digest": format!("sha256:{}", "a".repeat(64)),
        "protocol_tool": "issue_refund", "arguments": {}, "idempotency_key": null, "deadline": "2026-10-20T10:00:05Z"}),
    )
    .unwrap()
}

fn debug(credential: &contextos_adapters::Credential) -> String {
    format!("{credential:?}")
}

#[tokio::test]
async fn tokens_are_fetched_with_client_credentials_and_reused_until_refresh() {
    let (url, requests) = token_server(|n| {
        token(json!({"access_token": format!("tok_{n}"), "token_type": "Bearer", "expires_in": 3600}))
    })
    .await;
    let broker = broker(&url, Duration::from_secs(60));
    let first = broker.credential(&manifest(), &call()).await.unwrap().unwrap();
    let second = broker.credential(&manifest(), &call()).await.unwrap().unwrap();
    assert_eq!(debug(&first), "Credential(<redacted>)");
    assert_eq!(debug(&second), debug(&first));
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1, "cached");
    let (headers, body) = &requests[0];
    // HTTP Basic with client id and secret; the provider is the RFC 8707 resource.
    assert_eq!(
        headers["authorization"],
        "Basic Y29udGV4dG9zLWdhdGV3YXk6Y2xpZW50LXNlY3JldA=="
    );
    assert!(body.contains("grant_type=client_credentials"), "{body}");
    assert!(
        body.contains("resource=https%3A%2F%2Fpayments-mcp.internal.example%2Fmcp"),
        "{body}"
    );
    assert!(body.contains("scope=payments.refund"), "{body}");
}

#[tokio::test]
async fn a_short_lived_token_is_replaced_halfway_through_its_life() {
    let (url, requests) =
        token_server(|n| token(json!({"access_token": format!("tok_{n}"), "token_type": "bearer", "expires_in": 1})))
            .await;
    let broker = broker(&url, Duration::from_secs(60));
    broker.credential(&manifest(), &call()).await.unwrap();
    broker.credential(&manifest(), &call()).await.unwrap();
    assert_eq!(requests.lock().unwrap().len(), 1);
    tokio::time::sleep(Duration::from_millis(600)).await;
    broker.credential(&manifest(), &call()).await.unwrap();
    assert_eq!(requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn an_unrepresentable_lifetime_is_capped_not_a_crash() {
    let (url, requests) = token_server(|n| {
        token(json!({"access_token": format!("tok_{n}"), "token_type": "Bearer", "expires_in": u64::MAX}))
    })
    .await;
    let broker = broker(&url, Duration::from_secs(60));
    broker.credential(&manifest(), &call()).await.unwrap();
    broker.credential(&manifest(), &call()).await.unwrap();
    assert_eq!(requests.lock().unwrap().len(), 1, "cached for the capped lifetime");
}

#[tokio::test]
async fn without_a_bearer_token_the_call_fails_before_anything_is_sent() {
    for answer in [
        (|_| StatusCode::UNAUTHORIZED.into_response()) as fn(usize) -> Response,
        |_| token(json!({"access_token": "sekrit_value", "token_type": "mac"})),
        |_| token(json!({"token_type": "Bearer"})),
    ] {
        let (url, _) = token_server(answer).await;
        let error = broker(&url, Duration::from_secs(60))
            .credential(&manifest(), &call())
            .await
            .unwrap_err();
        assert_eq!(error.port, "credentials");
        assert!(!error.message.contains("sekrit"), "{}", error.message);
    }
    let policy = TransportPolicy::default();
    assert!(
        OAuthClientCredentials::new("http://idp.example/token", "c", "s", None, "r", Duration::ZERO, &policy).is_err(),
        "token endpoints must use https"
    );
}
