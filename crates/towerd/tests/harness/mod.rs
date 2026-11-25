//! A real `contextosd` runtime with a governed-dispatch configuration and a Tower over
//! it, for end-to-end tests of Tower's governance routes. Used as `mod harness;`.
//!
//! Keys: runtime `reader-key` (audit:read) and `control-key` (control). Tower:
//! `viewer` (ciso), `owner` (maya, team support-ai), `risk-a` and `risk-b` (risk),
//! `oncall-a` and `oncall-b` (operator).

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use contextos_audit::AuditSigner;
use contextos_store::{MemoryLog, MemoryStore};
use contextosd::auth::hash_api_key;
use serde_json::Value;
use towerd::source::Source;
use towerd::{Config, Tower, api, collector};

pub const TENANT: &str = "tenant_acme_prod";
pub const SOURCE: &str = "eu-support";

/// A runtime whose audit chain starts with `entries`, each `(kind, payload, at)`.
pub async fn runtime(entries: &[(&str, Value, &str)]) -> String {
    let config = contextosd::Config::parse(&format!(
        r#"
        [server]
        listen = "127.0.0.1:0"
        mode = "development"
        [store]
        kind = "memory"
        [audit]
        signing_seed_env = "UNUSED"
        key_id = "rt-audit"
        [support]
        implementation_id = "contextos-rs"
        implementation_version = "0.1.0"
        profiles = ["contextos.core"]
        controls = ["identity.authenticated", "authority.scoped", "policy.fail_visible", "context.integrity", "audit.correlated"]
        [identity]
        trust_domain = "contextos.test"
        gateway_principal_id = "contextosd"
        # The kill switch needs governed dispatch; these providers are never called.
        [providers.authority]
        url = "http://127.0.0.1:9/authority"
        [providers.constraints]
        url = "http://127.0.0.1:9/constraints"
        [providers.approvals]
        url = "http://127.0.0.1:9/approvals"
        [[api_keys]]
        key_sha256 = "{reader}"
        tenant_id = "{TENANT}"
        principal_id = "svc_tower"
        scopes = ["audit:read"]
        [[api_keys]]
        key_sha256 = "{control}"
        tenant_id = "{TENANT}"
        principal_id = "svc_tower_control"
        scopes = ["control"]
        "#,
        reader = hash_api_key("reader-key"),
        control = hash_api_key("control-key"),
    ))
    .unwrap();
    let pack = std::fs::read_to_string(format!(
        "{}/../../examples/support-refund/pack.json",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let (pack_ref, loaded) = contextosd::load_pack(&pack).unwrap();
    let state = contextosd::build_state(
        &config,
        Arc::new(MemoryStore::new()),
        MemoryLog::new(),
        AuditSigner::from_seed("rt-audit", [3; 32]),
        HashMap::from([(pack_ref, loaded)]),
        contextosd::runtime::dispatch_setup_from_config(&config).unwrap(),
    )
    .unwrap();
    for (kind, payload, at) in entries {
        state.audit.append(TENANT, kind, payload.clone(), at).await.unwrap();
    }
    let app = contextosd::router(state, Duration::from_secs(5));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

/// A Tower over `runtime` (environment `production`), synced once. `extra` is added to
/// its configuration before the sources.
pub async fn tower(runtime: &str, extra: &str) -> (String, Arc<Tower<MemoryStore, MemoryLog>>) {
    let config = Config::parse(&format!(
        r#"
        [server]
        listen = "127.0.0.1:0"
        development = true
        [journal]
        signing_seed_env = "UNUSED"
        key_id = "tower-journal"
        {extra}
        [[sources]]
        id = "{SOURCE}"
        url = "{runtime}"
        token_env = "UNUSED"
        control_token_env = "UNUSED"
        environment = "production"
        [[api_keys]]
        key_sha256 = "{viewer}"
        principal_id = "ciso"
        roles = ["viewer"]
        [[api_keys]]
        key_sha256 = "{owner}"
        principal_id = "maya"
        roles = ["owner"]
        teams = ["support-ai"]
        [[api_keys]]
        key_sha256 = "{risk_a}"
        principal_id = "risk-a"
        roles = ["risk"]
        [[api_keys]]
        key_sha256 = "{risk_b}"
        principal_id = "risk-b"
        roles = ["risk"]
        [[api_keys]]
        key_sha256 = "{a}"
        principal_id = "oncall-a"
        roles = ["operator"]
        [[api_keys]]
        key_sha256 = "{b}"
        principal_id = "oncall-b"
        roles = ["operator"]
        "#,
        viewer = hash_api_key("viewer"),
        owner = hash_api_key("owner"),
        risk_a = hash_api_key("risk-a"),
        risk_b = hash_api_key("risk-b"),
        a = hash_api_key("oncall-a"),
        b = hash_api_key("oncall-b"),
    ))
    .unwrap();
    let source = Source::with_tokens(
        config.sources[0].clone(),
        "reader-key".into(),
        Some("control-key".into()),
    );
    let tower = Arc::new(
        Tower::assemble(
            config,
            vec![Arc::new(source)],
            Arc::new(MemoryStore::new()),
            MemoryLog::new(),
            AuditSigner::from_seed("tower-journal", [4; 32]),
            None,
        )
        .unwrap(),
    );
    sync(&tower).await;
    let app = api::router(tower.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), tower)
}

/// One collector pass, continuing from what Tower already verified.
pub async fn sync(tower: &Tower<MemoryStore, MemoryLog>) {
    let mut anchor = tower
        .fleet
        .read()
        .await
        .sources
        .get(SOURCE)
        .and_then(|s| s.anchor.clone());
    let (mut keys, mut refreshed) = (None, None);
    let source = tower.sources.get(SOURCE).unwrap();
    assert!(collector::sync(&source, &tower.fleet, &mut keys, &mut anchor, &mut refreshed).await);
}

/// Calls Tower; the body is JSON, or a string when the response is not JSON.
pub async fn call(base: &str, method: &str, path: &str, key: &str, body: Option<Value>) -> (u16, Value) {
    let http = reqwest::Client::new();
    let url = format!("{base}{path}");
    let mut request = match method {
        "GET" => http.get(url),
        "PUT" => http.put(url),
        _ => http.post(url),
    }
    .bearer_auth(key);
    if let Some(b) = body {
        request = request.json(&b);
    }
    let response = request.send().await.unwrap();
    let status = response.status().as_u16();
    let text = response.text().await.unwrap_or_default();
    (status, serde_json::from_str(&text).unwrap_or(Value::String(text)))
}

/// What the runtime has revoked, as `GET /v1/revocations` lists it.
pub async fn runtime_revoked(runtime: &str) -> Vec<Value> {
    let response = reqwest::Client::new()
        .get(format!("{runtime}/v1/revocations"))
        .bearer_auth("control-key")
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    body["revoked"].as_array().cloned().unwrap_or_default()
}
