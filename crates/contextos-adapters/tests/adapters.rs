//! Adapter outcome classification against real local HTTP servers.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::Router;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use contextos_adapters::*;
use contextos_gateway::{Adapter, AdapterCall, CapabilityManifest, EffectOutcome, PortError};
use serde_json::{Value, json};

type Seen = Arc<Mutex<Vec<(HeaderMap, Value)>>>;

async fn serve(router: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    format!("http://{addr}")
}

/// A server that records each request and answers with `respond(body)`.
async fn server(respond: fn(&Value) -> Response) -> (String, Seen) {
    let seen: Seen = Arc::default();
    let log = seen.clone();
    let router = Router::new().fallback(post(move |headers: HeaderMap, body: String| {
        let log = log.clone();
        async move {
            let parsed: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
            log.lock().unwrap().push((headers, parsed.clone()));
            respond(&parsed)
        }
    }));
    (serve(router).await, seen)
}

fn json_response(value: Value) -> Response {
    ([(header::CONTENT_TYPE, "application/json")], value.to_string()).into_response()
}

fn rpc_result(request: &Value, result: Value) -> Response {
    json_response(json!({"jsonrpc": "2.0", "id": request["id"], "result": result}))
}

struct Broker;
#[async_trait]
impl CredentialBroker for Broker {
    async fn credential(&self, _: &CapabilityManifest, call: &AdapterCall) -> Result<Option<Credential>, PortError> {
        Ok(Some(Credential::bearer(format!("scoped-{}", call.operation_id))))
    }
}

fn policy() -> TransportPolicy {
    TransportPolicy {
        allow_loopback_http: true,
        max_response_bytes: 64 * 1024,
        ..TransportPolicy::default()
    }
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
        arguments: json!({"order_id": "ord_881", "amount_minor": 420_000}),
        idempotency_key: Some("ctxos:op_refund".into()),
        deadline: "2026-10-20T10:00:05Z".into(),
        input: None,
    }
}

async fn mcp(url: &str, effect: &str) -> contextos_gateway::AdapterResponse {
    McpAdapter::new(url, policy(), Arc::new(Broker), "contextos-test")
        .unwrap()
        .invoke(&manifest(effect), &call())
        .await
}

#[tokio::test]
async fn mcp_success_carries_protocol_meta_and_scoped_credentials() {
    let (url, seen) = server(|r| {
        rpc_result(
            r,
            json!({"content": [{"type": "text", "text": "ok"}], "structuredContent": {"refund_id": "rf_1"}}),
        )
    })
    .await;
    let response = mcp(&url, "external_state").await;
    assert_eq!(
        (response.outcome, response.definitive),
        (EffectOutcome::Confirmed, true)
    );
    assert_eq!(response.output["refund_id"], "rf_1");
    let (headers, body) = seen.lock().unwrap()[0].clone();
    assert_eq!(headers["mcp-protocol-version"], "2026-07-28");
    assert_eq!(headers["authorization"], "Bearer scoped-op_refund");
    assert_eq!(headers["idempotency-key"], "ctxos:op_refund");
    assert!(
        headers["traceparent"]
            .to_str()
            .unwrap()
            .starts_with("00-4bf92f3577b34da6a3ce929d0e0e4736-")
    );
    assert!(headers.get("mcp-session-id").is_none());
    assert_eq!(body["method"], "tools/call");
    assert_eq!(body["id"], "attempt_7");
    assert_eq!(
        body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
        "2026-07-28"
    );
    assert_eq!(body["params"]["arguments"]["amount_minor"], 420_000);
}

#[tokio::test]
async fn mcp_tool_errors_depend_on_effect() {
    let (url, _) = server(|r| rpc_result(r, json!({"content": [], "isError": true}))).await;
    assert_eq!(mcp(&url, "external_state").await.outcome, EffectOutcome::Unknown);
    let read_only = mcp(&url, "none").await;
    assert_eq!(
        (read_only.outcome, read_only.definitive),
        (EffectOutcome::NotApplied, true)
    );
}

#[tokio::test]
async fn mcp_protocol_errors_are_pre_execution() {
    let (url, _) = server(|r| {
        json_response(json!({"jsonrpc": "2.0", "id": r["id"],
        "error": {"code": -32602, "message": "Unsupported protocol version", "data": {"supported": ["2025-11-25"]}}}))
    })
    .await;
    let response = mcp(&url, "external_state").await;
    assert_eq!(
        (response.outcome, response.definitive),
        (EffectOutcome::NotApplied, true)
    );
    let (url, _) = server(|r| {
        json_response(json!({"jsonrpc": "2.0", "id": r["id"], "error": {"code": -32603, "message": "boom"}}))
    })
    .await;
    assert_eq!(mcp(&url, "external_state").await.outcome, EffectOutcome::Unknown);
}

#[tokio::test]
async fn mcp_malformed_or_mismatched_responses_are_unknown() {
    let (url, _) = server(|_| json_response(json!({"jsonrpc": "2.0", "id": "someone_else", "result": {}}))).await;
    assert_eq!(mcp(&url, "external_state").await.outcome, EffectOutcome::Unknown);
    let (url, _) = server(|r| {
        (
            [(header::CONTENT_TYPE, "application/json")],
            format!(
                r#"{{"jsonrpc":"2.0","id":{},"result":{{"isError":false,"isError":true}}}}"#,
                r["id"]
            ),
        )
            .into_response()
    })
    .await;
    assert_eq!(
        mcp(&url, "external_state").await.outcome,
        EffectOutcome::Unknown,
        "duplicate keys are rejected"
    );
    let (url, _) = server(|r| rpc_result(r, json!({"padding": "x".repeat(128 * 1024)}))).await;
    assert_eq!(
        mcp(&url, "external_state").await.outcome,
        EffectOutcome::Unknown,
        "oversized"
    );
}

#[tokio::test]
async fn mcp_sse_input_required_and_tasks() {
    let (url, _) = server(|r| {
        (
            [(header::CONTENT_TYPE, "text/event-stream")],
            format!(
                "event: message\ndata: {}\n\n",
                json!({"jsonrpc": "2.0", "id": r["id"], "result": {"structuredContent": {"ok": true}}})
            ),
        )
            .into_response()
    })
    .await;
    assert_eq!(mcp(&url, "external_state").await.outcome, EffectOutcome::Confirmed);
    let (url, _) = server(|r| {
        rpc_result(
            r,
            json!({"resultType": "input_required", "inputRequests": [{"type": "confirmation"}]}),
        )
    })
    .await;
    let response = mcp(&url, "external_state").await;
    assert_eq!(
        (response.outcome, response.definitive),
        (EffectOutcome::NotApplied, true),
        "input_required means the tool has not run"
    );
    assert_eq!(response.output["result_type"], "input_required");

    // A task result stays unknown and keeps the task id for reconciliation.
    let (url, _) = server(|r| {
        rpc_result(
            r,
            json!({"resultType": "task", "task": {"taskId": "t_1", "status": "working"}}),
        )
    })
    .await;
    let response = mcp(&url, "external_state").await;
    assert_eq!(response.outcome, EffectOutcome::Unknown);
    assert_eq!(response.external_ref.as_deref(), Some("t_1"));
}

#[tokio::test]
async fn unreachable_provider_was_not_dispatched() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let response = mcp(&url, "external_state").await;
    assert_eq!(
        (response.outcome, response.definitive),
        (EffectOutcome::NotDispatched, true)
    );
}

#[tokio::test]
async fn redirects_are_never_followed() {
    let hits = Arc::new(Mutex::new(0));
    let counter = hits.clone();
    let target = serve(Router::new().fallback(post(move || {
        let counter = counter.clone();
        async move {
            *counter.lock().unwrap() += 1;
            StatusCode::OK
        }
    })))
    .await;
    let redirect = serve(Router::new().fallback(post(move || {
        let target = target.clone();
        async move { (StatusCode::TEMPORARY_REDIRECT, [(header::LOCATION, target)]).into_response() }
    })))
    .await;
    assert_eq!(mcp(&redirect, "external_state").await.outcome, EffectOutcome::Unknown);
    assert_eq!(*hits.lock().unwrap(), 0);
}

#[tokio::test]
async fn http_status_mapping_and_headers() {
    let (url, seen) = server(|_| (StatusCode::CREATED, json_response(json!({"id": "rf_9"}))).into_response()).await;
    let adapter = HttpAdapter::new(&url, policy(), Arc::new(Broker)).unwrap();
    let response = adapter.invoke(&manifest("external_state"), &call()).await;
    assert_eq!(
        (response.outcome, response.external_ref.as_deref()),
        (EffectOutcome::Confirmed, Some("rf_9"))
    );
    assert_eq!(seen.lock().unwrap()[0].0["idempotency-key"], "ctxos:op_refund");
    for (status, expected) in [
        (422, EffectOutcome::NotApplied),
        (503, EffectOutcome::Unknown),
        (409, EffectOutcome::Unknown),
    ] {
        let router = Router::new().fallback(post(move || async move { StatusCode::from_u16(status).unwrap() }));
        let url = serve(router).await;
        let adapter = HttpAdapter::new(&url, policy(), Arc::new(NoCredentials)).unwrap();
        assert_eq!(
            adapter.invoke(&manifest("external_state"), &call()).await.outcome,
            expected,
            "{status}"
        );
    }
    let mut traversal = manifest("external_state");
    traversal.protocol_tool = "../admin".into();
    assert_eq!(
        adapter.invoke(&traversal, &call()).await.outcome,
        EffectOutcome::NotDispatched
    );
}

#[test]
fn endpoints_are_pinned_and_secure() {
    let strict = TransportPolicy::default();
    assert!(McpAdapter::new("http://example.com/mcp", strict.clone(), Arc::new(NoCredentials), "t").is_err());
    assert!(McpAdapter::new("http://127.0.0.1:9/mcp", strict.clone(), Arc::new(NoCredentials), "t").is_err());
    assert!(
        McpAdapter::new(
            "https://user:pw@example.com/mcp",
            strict.clone(),
            Arc::new(NoCredentials),
            "t"
        )
        .is_err()
    );
    assert!(
        McpAdapter::new(
            "https://example.com/mcp?x=1",
            strict.clone(),
            Arc::new(NoCredentials),
            "t"
        )
        .is_err()
    );
    assert!(McpAdapter::new("https://example.com/mcp", strict, Arc::new(NoCredentials), "t").is_ok());
    assert!(McpAdapter::new("http://example.com/mcp", policy(), Arc::new(NoCredentials), "t").is_err());
}
