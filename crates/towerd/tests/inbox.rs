//! The approvals inbox against a real `contextosd`: an open escalation in the runtime
//! reaches Tower's queue attributed to its agent and owner, resolution needs the right
//! role and someone other than the agent's declarer, is journalled in Tower, and closes
//! the escalation in the runtime itself.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use contextos_audit::AuditSigner;
use contextos_store::{DocKey, DocKind, DocumentStore, MemoryLog, MemoryStore};
use contextosd::auth::hash_api_key;
use serde_json::{Value, json};
use towerd::source::Source;
use towerd::{Config, Tower, api, collector};

const TENANT: &str = "tenant_acme_prod";
const AT: &str = "2026-10-21T10:00:00.000000Z";
const ESC: &str = "esc_0123456789abcdef01234567";

/// A runtime with one admitted run whose refund was escalated to a human.
async fn runtime() -> String {
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
        # Escalations live in the dispatch gateway; these providers are never called here.
        [providers.authority]
        url = "http://127.0.0.1:9"
        [providers.constraints]
        url = "http://127.0.0.1:9"
        [providers.approvals]
        url = "http://127.0.0.1:9"
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
    let store = Arc::new(MemoryStore::new());
    let state = contextosd::build_state(
        &config,
        store.clone(),
        MemoryLog::new(),
        AuditSigner::from_seed("rt-audit", [3; 32]),
        HashMap::from([(pack_ref, loaded)]),
        contextosd::runtime::dispatch_setup_from_config(&config).unwrap(),
    )
    .unwrap();
    let escalation = json!({"escalation_id": ESC, "tenant_id": TENANT, "run_id": "r1", "trace_id": "trace_r1",
        "operation_id": "refund:1", "capability_id": "adp_payments.issue_refund", "action_digest": "sha256:ab",
        "policy_decision_id": "dec_1", "reason_codes": ["fraud_signal_high"], "opened_at": AT, "status": "open"});
    let entries = [
        (
            "run_admitted",
            json!({"run_id": "r1", "trace_id": "trace_r1", "agent_id": "agt_support",
                "pack_ref": "ctxpack.support@5.2.0", "intent": "support.refund", "profiles": ["contextos.core"],
                "required_controls": [], "release_refs": [], "surfaced_capabilities": ["adp_payments.issue_refund"],
                "admitted_by": "svc_orchestrator"}),
        ),
        ("escalation_opened", escalation.clone()),
    ];
    for (kind, payload) in entries {
        state.audit.append(TENANT, kind, payload, AT).await.unwrap();
    }
    // The escalation as the gateway keeps it when policy answers `escalate`: its record
    // and the tenant's open index (listing and resolution below go through the API).
    store
        .create(
            &DocKey::new(TENANT, DocKind::Escalation, format!("record:{ESC}")),
            &escalation,
        )
        .await
        .unwrap();
    store
        .create(
            &DocKey::new(TENANT, DocKind::Escalation, "open"),
            &json!({"keys": [ESC]}),
        )
        .await
        .unwrap();
    let app = contextosd::router(state, Duration::from_secs(5));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

async fn tower(runtime: &str, control: bool) -> String {
    let config = Config::parse(&format!(
        r#"
        [server]
        listen = "127.0.0.1:0"
        development = true
        [journal]
        signing_seed_env = "UNUSED"
        key_id = "tower-journal"
        [[sources]]
        id = "eu-support"
        url = "{runtime}"
        token_env = "UNUSED"
        control_token_env = "UNUSED_CONTROL"
        [[api_keys]]
        key_sha256 = "{viewer}"
        principal_id = "ciso"
        roles = ["viewer"]
        [[api_keys]]
        key_sha256 = "{risk_a}"
        principal_id = "risk-a"
        roles = ["risk"]
        [[api_keys]]
        key_sha256 = "{risk_b}"
        principal_id = "risk-b"
        roles = ["risk"]
        "#,
        viewer = hash_api_key("viewer"),
        risk_a = hash_api_key("risk-a"),
        risk_b = hash_api_key("risk-b"),
    ))
    .unwrap();
    let source = Source::with_tokens(
        config.sources[0].clone(),
        "reader-key".into(),
        control.then(|| "control-key".into()),
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
    let (mut keys, mut anchor, mut refreshed) = (None, None, None);
    assert!(
        collector::sync(
            &tower.sources.active()[0],
            &tower.fleet,
            &mut keys,
            &mut anchor,
            &mut refreshed
        )
        .await
    );
    let app = api::router(tower);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

async fn call(base: &str, method: &str, path: &str, key: &str, body: Option<Value>) -> (u16, Value) {
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
    (status, response.json().await.unwrap_or(Value::Null))
}

const AGENT: &str = "tenant_acme_prod%2Fagt_support";

#[tokio::test]
async fn escalations_are_queued_attributed_and_resolved_by_someone_else() {
    let rt = runtime().await;
    let base = tower(&rt, true).await;
    let declaration = json!({"owner": "Support AI lead", "team": "support-ai", "purpose": "Refunds",
        "users_served": "customers", "lifecycle": "production"});
    let (status, _) = call(
        &base,
        "PUT",
        &format!("/api/agents/{AGENT}/declaration"),
        "risk-b",
        Some(declaration),
    )
    .await;
    assert_eq!(status, 200);

    let (status, inbox) = call(&base, "GET", "/api/inbox", "viewer", None).await;
    assert_eq!(status, 200, "{inbox}");
    assert_eq!(inbox["open"], 1);
    let item = &inbox["items"][0];
    assert_eq!(item["escalation_id"], ESC);
    assert_eq!(item["agent"], "tenant_acme_prod/agt_support");
    assert_eq!(item["team"], "support-ai");
    assert_eq!(item["capability_id"], "adp_payments.issue_refund");
    assert_eq!(item["kind"], "policy");
    assert_eq!(item["can_resolve"], true);
    assert!(item["age_seconds"].as_i64().unwrap() > 0);
    assert_eq!(inbox["sources"][0]["ok"], true);
    let (_, filtered) = call(&base, "GET", "/api/inbox?team=other", "viewer", None).await;
    assert_eq!(filtered["open"], 0);

    let path = format!("/api/inbox/eu-support/{ESC}/resolve");
    let resolution = json!({"resolution": "handled", "reason": "Fraud team cleared the customer"});
    let (status, _) = call(&base, "POST", &path, "viewer", Some(resolution.clone())).await;
    assert_eq!(status, 403, "viewers cannot resolve");
    let (status, refused) = call(&base, "POST", &path, "risk-b", Some(resolution.clone())).await;
    assert_eq!(status, 403, "the declarer cannot resolve: {refused}");
    let (status, _) = call(
        &base,
        "POST",
        &path,
        "risk-a",
        Some(json!({"resolution": "approved", "reason": "x"})),
    )
    .await;
    assert_eq!(status, 422);
    let (status, resolved) = call(&base, "POST", &path, "risk-a", Some(resolution.clone())).await;
    assert_eq!(status, 200, "{resolved}");
    assert_eq!(resolved["escalation"]["resolution"]["outcome"], "handled");
    assert_eq!(
        resolved["escalation"]["resolution"]["reason"],
        "Fraud team cleared the customer (via Tower, risk-a)"
    );
    let (status, _) = call(&base, "POST", &path, "risk-a", Some(resolution)).await;
    assert_eq!(status, 404, "no longer open");

    let (_, after) = call(&base, "GET", "/api/inbox", "viewer", None).await;
    assert_eq!(after["open"], 0);
    let (_, runtime) = call(&rt, "GET", "/v1/escalations", "reader-key", None).await;
    assert_eq!(runtime["open"], 0, "closed in the runtime itself");

    let (_, journal) = call(&base, "GET", "/api/journal", "viewer", None).await;
    let entries = journal["entries"].as_array().unwrap();
    let kinds: Vec<&str> = entries.iter().filter_map(|e| e["kind"].as_str()).collect();
    assert!(kinds.contains(&"escalation_resolution_requested"), "{kinds:?}");
    let result = entries
        .iter()
        .find(|e| e["kind"] == "escalation_resolution_result" && e["payload"]["ok"] == true)
        .expect("the runtime's answer is journalled");
    assert_eq!(result["payload"]["by"], "risk-a");
    assert_eq!(result["payload"]["agent"], "tenant_acme_prod/agt_support");
}

#[tokio::test]
async fn without_a_control_key_the_queue_is_read_only_and_failures_are_shown() {
    let rt = runtime().await;
    let base = tower(&rt, false).await;
    let (_, inbox) = call(&base, "GET", "/api/inbox", "viewer", None).await;
    assert_eq!(inbox["items"][0]["can_resolve"], false);
    let (status, refused) = call(
        &base,
        "POST",
        &format!("/api/inbox/eu-support/{ESC}/resolve"),
        "risk-a",
        Some(json!({"resolution": "dismissed", "reason": "duplicate"})),
    )
    .await;
    assert_eq!(status, 409);
    assert_eq!(refused["error"]["code"], "no_control_key");

    // A runtime that cannot be read is reported, not silently left out.
    let unreachable = tower("http://127.0.0.1:9", true).await;
    let (status, inbox) = call(&unreachable, "GET", "/api/inbox", "viewer", None).await;
    assert_eq!(status, 200);
    assert_eq!(inbox["open"], 0);
    assert_eq!(inbox["sources"][0]["ok"], false);
    assert!(inbox["sources"][0]["error"].as_str().is_some());
}
