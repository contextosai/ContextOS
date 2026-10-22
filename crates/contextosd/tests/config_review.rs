//! Configuration review over HTTP: the running configuration and dry runs.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use contextos_audit::AuditSigner;
use contextos_store::{MemoryLog, MemoryStore};
use contextosd::auth::hash_api_key;
use contextosd::{Config, build_state, router};
use serde_json::{Value, json};

fn text() -> String {
    format!(
        r#"[server]
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
key_sha256 = "{alice}"
tenant_id = "tenant_ops"
principal_id = "alice"
scopes = ["config", "audit:read"]

[[api_keys]]
key_sha256 = "{bob}"
tenant_id = "tenant_ops"
principal_id = "bob"
scopes = ["config"]

[[api_keys]]
key_sha256 = "{reader}"
tenant_id = "tenant_ops"
principal_id = "reader"
scopes = ["audit:read"]
"#,
        alice = hash_api_key("alice-key"),
        bob = hash_api_key("bob-key"),
        reader = hash_api_key("reader-key"),
    )
}

async fn start() -> String {
    let config = Config::parse(&text()).unwrap();
    let state = build_state(
        &config,
        Arc::new(MemoryStore::new()),
        MemoryLog::new(),
        AuditSigner::from_seed("audit-test", [5; 32]),
        HashMap::new(),
        None,
    )
    .unwrap();
    let app = router(state, Duration::from_secs(5));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

async fn call(http: &reqwest::Client, method: &str, url: String, key: &str, body: Option<Value>) -> (u16, Value) {
    let mut request = if method == "GET" { http.get(url) } else { http.post(url) };
    request = request.bearer_auth(key);
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await.unwrap();
    let status = response.status().as_u16();
    (status, response.json().await.unwrap_or(Value::Null))
}

#[tokio::test]
async fn the_running_configuration_needs_the_config_scope() {
    let base = start().await;
    let http = reqwest::Client::new();
    let (status, _) = call(&http, "GET", format!("{base}/v1/config"), "reader-key", None).await;
    assert_eq!(status, 403);
    let (status, running) = call(&http, "GET", format!("{base}/v1/config"), "bob-key", None).await;
    assert_eq!(status, 200);
    assert_eq!(running["source"], text());
    assert_eq!(running["digest"], contextos_contract::canonical::sha256_text(&text()));
    assert_eq!(
        running["effective"]["guards"]["require_user_role"], true,
        "mode defaults resolved"
    );
    assert!(
        running["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["severity"] == "critical")
    );
}

#[tokio::test]
async fn a_dry_run_reports_errors_and_classified_changes() {
    let base = start().await;
    let http = reqwest::Client::new();
    let url = format!("{base}/v1/config/validate");
    let (_, invalid) = call(
        &http,
        "POST",
        url.clone(),
        "bob-key",
        Some(json!({"toml": "[server]\nlisten = 7"})),
    )
    .await;
    assert_eq!(invalid["valid"], false);
    assert!(!invalid["errors"][0].as_str().unwrap().is_empty());

    let looser = text().replace(
        "controls = []",
        "controls = []\n\n[guards]\nrefuse_repeated_effects = false",
    );
    let (status, review) = call(&http, "POST", url, "bob-key", Some(json!({"toml": looser}))).await;
    assert_eq!(status, 200);
    assert_eq!(review["valid"], true);
    assert_eq!(review["loosening"], json!(["guards.refuse_repeated_effects"]));
    assert_eq!(review["changes"][0]["from"], true);
    assert_eq!(review["changes"][0]["to"], false);
}
