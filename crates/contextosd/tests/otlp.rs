//! Spans are exported over OTLP/HTTP and join the caller's W3C trace.
#![cfg(feature = "otlp")]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use contextos_audit::AuditSigner;
use contextos_store::{MemoryLog, MemoryStore};
use contextosd::auth::hash_api_key;
use contextosd::{Config, build_state, router};

async fn serve(app: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_spans_join_the_callers_trace() {
    let exports: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
    let sink = exports.clone();
    let collector = serve(axum::Router::new().route(
        "/v1/traces",
        axum::routing::post(move |body: axum::body::Bytes| {
            sink.lock().unwrap().push(body.to_vec());
            async { "" }
        }),
    ))
    .await;
    let telemetry = contextosd::telemetry::init_with(Some(&format!("{collector}/v1/traces"))).unwrap();

    let config = Config::parse(&format!(
        r#"
        [server]
        listen = "127.0.0.1:0"
        [store]
        kind = "memory"
        [audit]
        signing_seed_env = "UNUSED"
        key_id = "audit-test"
        [support]
        implementation_id = "contextos-rs"
        implementation_version = "0.1.0"
        profiles = ["contextos.core"]
        controls = []
        [[api_keys]]
        key_sha256 = "{key}"
        tenant_id = "tenant_acme_prod"
        principal_id = "svc"
        scopes = ["audit:read"]
        "#,
        key = hash_api_key("acme-key"),
    ))
    .unwrap();
    let state = build_state(
        &config,
        Arc::new(MemoryStore::new()),
        MemoryLog::new(),
        AuditSigner::from_seed("audit-test", [5; 32]),
        HashMap::new(),
        None,
    )
    .unwrap();
    let base = serve(router(state, Duration::from_secs(5))).await;
    let trace_id = "4bf92f3577b34da6a3ce929d0e0e4736";
    let response = reqwest::Client::new()
        .get(format!("{base}/v1/audit/verify"))
        .bearer_auth("acme-key")
        .header("traceparent", format!("00-{trace_id}-00f067aa0ba902b7-01"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    tokio::time::sleep(Duration::from_millis(100)).await;
    telemetry.shutdown().await;

    let exported = exports.lock().unwrap().concat();
    assert_ne!(exported, [] as [u8; 0], "no spans exported");
    let needle = hex::decode(trace_id).unwrap();
    assert!(
        exported.windows(needle.len()).any(|w| w == needle.as_slice()),
        "exported spans do not carry the caller's trace id"
    );
    assert!(exported.windows(12).any(|w| w == b"http.request"));
}
