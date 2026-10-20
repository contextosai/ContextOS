//! Overload protection over HTTP.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use contextos_audit::AuditSigner;
use contextos_store::{MemoryLog, MemoryStore};
use contextosd::auth::hash_api_key;
use contextosd::{Config, build_state, router};

async fn start() -> String {
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
        [limits]
        requests_per_second = 0.01
        burst = 2
        [[limits.tenants]]
        tenant_id = "tenant_big"
        burst = 5
        [[api_keys]]
        key_sha256 = "{a}"
        tenant_id = "tenant_a"
        principal_id = "svc_a"
        scopes = ["audit:read"]
        [[api_keys]]
        key_sha256 = "{b}"
        tenant_id = "tenant_big"
        principal_id = "svc_b"
        scopes = ["audit:read"]
        "#,
        a = hash_api_key("a-key"),
        b = hash_api_key("big-key"),
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
    let app = router(state, Duration::from_secs(5));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

#[tokio::test]
async fn tenants_are_rate_limited_independently() {
    let base = start().await;
    let http = reqwest::Client::new();
    let get = |key: &'static str| {
        let http = http.clone();
        let url = format!("{base}/v1/audit/verify");
        async move { http.get(url).bearer_auth(key).send().await.unwrap() }
    };
    assert_eq!(get("a-key").await.status(), 200);
    assert_eq!(get("a-key").await.status(), 200);
    let limited = get("a-key").await;
    assert_eq!(limited.status(), 429);
    assert!(
        limited.headers()["retry-after"]
            .to_str()
            .unwrap()
            .parse::<u64>()
            .unwrap()
            >= 1
    );
    let body: serde_json::Value = limited.json().await.unwrap();
    assert_eq!(body["error"]["code"], "rate_limited");
    for _ in 0..5 {
        assert_eq!(
            get("big-key").await.status(),
            200,
            "another tenant, with its own override"
        );
    }
    assert_eq!(get("big-key").await.status(), 429);
    // Unauthenticated requests never spend a tenant's allowance, and probes are exempt.
    assert_eq!(get("wrong").await.status(), 401);
    assert_eq!(http.get(format!("{base}/healthz")).send().await.unwrap().status(), 200);
}

#[test]
fn invalid_limits_are_refused() {
    let base = "[server]\nlisten = \"127.0.0.1:0\"\n[store]\nkind = \"memory\"\n[audit]\nsigning_seed_env = \"X\"\nkey_id = \"k\"\n[support]\nimplementation_id = \"x\"\nimplementation_version = \"1\"\nprofiles = []\ncontrols = []\n";
    assert!(Config::parse(&format!("{base}[limits]\nrequests_per_second = 0\n")).is_err());
    assert!(Config::parse(&format!("{base}[limits]\nmax_in_flight = 0\n")).is_err());
    assert!(Config::parse(&format!("{base}[limits]\nburst = 0.5\n")).is_err());
    assert!(Config::parse(base).is_ok(), "defaults apply without a [limits] section");
}
