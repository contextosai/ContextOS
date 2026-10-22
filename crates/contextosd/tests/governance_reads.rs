//! Read-only routes a governance plane (towerd) relies on: `GET /v1/deployment`,
//! `GET /v1/packs` and the audit page's `head`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use contextos_audit::AuditSigner;
use contextos_store::{MemoryLog, MemoryStore};
use contextosd::auth::hash_api_key;
use contextosd::{Config, build_state, load_pack, router};
use serde_json::Value;

fn pack() -> String {
    let path = format!("{}/../../conformance/vectors/compiler.json", env!("CARGO_MANIFEST_DIR"));
    let vectors: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "grid:support.refund:true:4200:support_agent")
        .unwrap()["pack"]
        .to_string()
}

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
        controls = ["identity.authenticated"]
        [[adapters]]
        id = "adp_payments"
        kind = "mcp"
        endpoint = "https://payments.internal.example/mcp"
        token_env = "PAYMENTS_TOKEN"
        [[api_keys]]
        key_sha256 = "{reader}"
        tenant_id = "tenant_acme_prod"
        principal_id = "svc_reader"
        scopes = ["audit:read"]
        [[api_keys]]
        key_sha256 = "{ops}"
        tenant_id = "tenant_acme_prod"
        principal_id = "svc_oncall"
        scopes = ["control"]
        [[api_keys]]
        key_sha256 = "{other}"
        tenant_id = "tenant_other"
        principal_id = "svc_other"
        scopes = ["audit:read"]
        "#,
        reader = hash_api_key("reader-key"),
        ops = hash_api_key("ops-key"),
        other = hash_api_key("other-key"),
    ))
    .unwrap();
    let mut packs = HashMap::new();
    let (pack_ref, pack) = load_pack(&pack()).unwrap();
    packs.insert(pack_ref, pack);
    let state = build_state(
        &config,
        Arc::new(MemoryStore::new()),
        MemoryLog::new(),
        AuditSigner::from_seed("audit-test", [5; 32]),
        packs,
        None,
    )
    .unwrap();
    let app = router(state, Duration::from_secs(5));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

#[tokio::test]
async fn deployment_names_the_caller_and_what_is_enforced_without_secrets() {
    let base = start().await;
    let http = client();
    let url = format!("{base}/v1/deployment");
    assert_eq!(http.get(&url).send().await.unwrap().status(), 401);

    let body: Value = http
        .get(&url)
        .bearer_auth("ops-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["caller"]["principal_id"], "svc_oncall");
    assert_eq!(body["caller"]["scopes"], serde_json::json!(["control"]));
    assert_eq!(body["mode"], "production");
    assert_eq!(body["packs"], serde_json::json!(["ctxpack.support@5.2.0"]));
    assert_eq!(
        body["adapters"],
        serde_json::json!([{"id": "adp_payments", "kind": "mcp"}])
    );
    assert_eq!(body["guards"]["require_user_role"], true);
    assert_eq!(body["guards"]["completion_requires_scores"]["policy_floor"], 1.0);
    assert_eq!(body["dispatch"], false);
    let text = body.to_string();
    for secret in ["payments.internal", "PAYMENTS_TOKEN", "UNUSED", "sha256:"] {
        assert!(!text.contains(secret), "deployment leaks {secret}");
    }

    let other: Value = http
        .get(&url)
        .bearer_auth("other-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(other["packs"], serde_json::json!([]), "packs are per tenant");
}

#[tokio::test]
async fn packs_and_the_audit_head_are_tenant_scoped_reads() {
    let base = start().await;
    let http = client();
    let url = format!("{base}/v1/packs");
    assert_eq!(
        http.get(&url).bearer_auth("ops-key").send().await.unwrap().status(),
        403
    );
    let body: Value = http
        .get(&url)
        .bearer_auth("reader-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["packs"][0]["pack_ref"], "ctxpack.support@5.2.0");
    assert_eq!(body["packs"][0]["pack"]["pack_meta"]["pack_id"], "ctxpack.support");
    let other: Value = http
        .get(&url)
        .bearer_auth("other-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(other["packs"], serde_json::json!([]));

    let page: Value = http
        .get(format!("{base}/v1/audit/entries?from=1&limit=1"))
        .bearer_auth("reader-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(page["head"], 0);
    assert_eq!(page["entries"], serde_json::json!([]));
}
