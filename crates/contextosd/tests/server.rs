//! Black-box tests of the HTTP API.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use contextos_audit::AuditSigner;
use contextos_store::{MemoryLog, MemoryStore};
use contextosd::auth::hash_api_key;
use contextosd::{Config, build_state, load_pack, router};
use serde_json::{Value, json};

fn vectors() -> Value {
    let path = format!("{}/../../conformance/vectors/compiler.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn case(name: &str) -> Value {
    vectors()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap()
        .clone()
}

async fn start(max_body: usize) -> String {
    let config = Config::parse(&format!(
        r#"
        [server]
        listen = "127.0.0.1:0"
        max_body_bytes = {max_body}
        [store]
        kind = "memory"
        [audit]
        signing_seed_env = "UNUSED"
        key_id = "audit-test"
        [support]
        implementation_id = "contextos-rs"
        implementation_version = "0.1.0"
        profiles = ["contextos.core"]
        controls = ["identity.authenticated", "authority.scoped", "policy.fail_visible", "context.integrity", "audit.correlated"]
        [[api_keys]]
        key_sha256 = "{acme}"
        tenant_id = "tenant_acme_prod"
        principal_id = "svc_orchestrator"
        scopes = ["compile", "admit", "audit:read"]
        [[api_keys]]
        key_sha256 = "{reader}"
        tenant_id = "tenant_acme_prod"
        principal_id = "svc_reader"
        scopes = ["audit:read"]
        [[api_keys]]
        key_sha256 = "{other}"
        tenant_id = "tenant_other"
        principal_id = "svc_other"
        scopes = ["compile", "admit", "audit:read"]
        "#,
        acme = hash_api_key("acme-key"),
        reader = hash_api_key("reader-key"),
        other = hash_api_key("other-key"),
    ))
    .unwrap();
    let mut packs = HashMap::new();
    let (pack_ref, pack) = load_pack(&case("grid:support.refund:true:4200:support_agent")["pack"].to_string()).unwrap();
    packs.insert(pack_ref, pack);
    let mut broken = case("grid:support.refund:true:4200:support_agent")["pack"].clone();
    broken["pack_meta"]["pack_id"] = json!("ctxpack.broken");
    broken["policy_layer"]["policy_bundles"][0]["policy_dsl"]["rules"][0]["if"] = json!({"no_such_op": [1]});
    let (pack_ref, pack) = load_pack(&broken.to_string()).unwrap();
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

fn compile_body(name: &str) -> Value {
    let c = case(name);
    json!({"pack_ref": "ctxpack.support@5.2.0", "request": c["request"], "run_context": c["run_context"], "deps": c["deps"]})
}

#[tokio::test]
async fn compile_matches_reference_and_enforces_auth_and_tenancy() {
    let base = start(1 << 20).await;
    let http = reqwest::Client::new();
    assert_eq!(http.get(format!("{base}/healthz")).send().await.unwrap().status(), 200);
    assert_eq!(http.get(format!("{base}/readyz")).send().await.unwrap().status(), 200);

    let url = format!("{base}/v1/compile");
    let body = compile_body("grid:support.refund:true:4200:support_agent");
    let unauthenticated = http.post(&url).json(&body).send().await.unwrap();
    assert_eq!(unauthenticated.status(), 401);
    assert_eq!(unauthenticated.headers()["www-authenticate"], "Bearer");
    assert_eq!(
        http.post(&url)
            .bearer_auth("wrong")
            .json(&body)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        http.post(&url)
            .bearer_auth("reader-key")
            .json(&body)
            .send()
            .await
            .unwrap()
            .status(),
        403,
        "missing scope"
    );
    assert_eq!(
        http.post(&url)
            .bearer_auth("other-key")
            .json(&body)
            .send()
            .await
            .unwrap()
            .status(),
        403,
        "other tenant"
    );

    let response = http
        .post(&url)
        .bearer_auth("acme-key")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    assert_eq!(response.headers()["cache-control"], "no-store");
    let compiled: Value = response.json().await.unwrap();
    let expected =
        case("grid:support.refund:true:4200:support_agent")["expected"]["context_ledger"]["compiled_context_hash"]
            .clone();
    assert_eq!(compiled["context_ledger"]["compiled_context_hash"], expected);

    let mut bad = body.clone();
    bad["pack_ref"] = json!("ctxpack.unknown@1.0.0");
    assert_eq!(
        http.post(&url)
            .bearer_auth("acme-key")
            .json(&bad)
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    let mut invalid = body.clone();
    invalid["request"]["mode"] = json!("telepathy");
    let response = http
        .post(&url)
        .bearer_auth("acme-key")
        .json(&invalid)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 422);
    let error: Value = response.json().await.unwrap();
    assert_eq!(error["error"]["code"], "request_invalid");
}

#[tokio::test]
async fn policy_errors_are_structured_and_sanitized() {
    let base = start(1 << 20).await;
    let http = reqwest::Client::new();
    let mut body = compile_body("grid:support.refund:true:4200:support_agent");
    body["pack_ref"] = json!("ctxpack.broken@5.2.0");
    let response = http
        .post(format!("{base}/v1/compile"))
        .bearer_auth("acme-key")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 422);
    let error: Value = response.json().await.unwrap();
    assert_eq!(error["error"]["code"], "policy_eval_error");
    assert_eq!(error["error"]["detail"]["rule_id"], "R_REFUND_REQUIRES_IDV");
    assert!(
        !error.to_string().contains("no_such_op"),
        "the expression is never echoed"
    );
}

#[tokio::test]
async fn hostile_bodies_are_refused() {
    let base = start(4096).await;
    let http = reqwest::Client::new();
    let url = format!("{base}/v1/compile");
    let duplicate = r#"{"pack_ref":"a","pack_ref":"ctxpack.support@5.2.0"}"#;
    let response = http
        .post(&url)
        .bearer_auth("acme-key")
        .header("content-type", "application/json")
        .body(duplicate)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    let big = format!(r#"{{"x":"{}"}}"#, "a".repeat(8192));
    let response = http.post(&url).bearer_auth("acme-key").body(big).send().await.unwrap();
    assert_eq!(response.status(), 413);
}

#[tokio::test]
async fn negotiate_validate_metrics_and_audit() {
    let base = start(1 << 20).await;
    let http = reqwest::Client::new();
    let contract = json!({"envelope_version": "contextos.execution_contract.v1", "contract_id": "c1", "run_id": "r1",
        "trace_id": "t1", "tenant_id": "tenant_acme_prod", "profiles": [{"profile_id": "contextos.core", "profile_version": "1"}],
        "required_controls": [], "optional_controls": [], "release_refs": []});
    let features = json!({"arbitrary_code": false, "external_network": false, "persistent_memory": false, "external_effects": false,
        "delegation": false, "checkpoint_resume": false, "proactive_triggers": false, "sensitive_data": false});
    let result: Value = http
        .post(format!("{base}/v1/contracts/negotiate"))
        .bearer_auth("acme-key")
        .json(&json!({"contract": contract, "features": features}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(result["status"], "accepted");
    let mut effects = features.clone();
    effects["external_effects"] = json!(true);
    let result: Value = http
        .post(format!("{base}/v1/contracts/negotiate"))
        .bearer_auth("acme-key")
        .json(&json!({"contract": contract, "features": effects}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        result["status"], "rejected",
        "this deployment does not declare effects.reconciled"
    );

    let valid: Value = http
        .post(format!("{base}/v1/schemas/execution-contract/validate?def=ControlRef"))
        .bearer_auth("acme-key")
        .json(&json!({"control_id": "x", "control_version": "1", "extra": 1}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(valid["valid"], false);

    let audit: Value = http
        .get(format!("{base}/v1/audit/verify"))
        .bearer_auth("reader-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(audit, json!({"verified": true, "entries": 0}));

    let metrics = http
        .get(format!("{base}/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        metrics.contains(r#"contextos_http_requests_total{route="/v1/contracts/negotiate",status="200"} 2"#),
        "{metrics}"
    );
    assert!(
        metrics.contains("contextos_replicas 1\n"),
        "a lone replica owns the full limits: {metrics}"
    );
}
