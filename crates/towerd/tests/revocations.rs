//! The revocations view and the two-person restore against a real `contextosd`: Tower
//! revokes through the runtime's `control` key, lists what is in force with who did it
//! and what it stops, refuses a one-person restore, and restores only on a second
//! operator's approval, journalling each step.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use contextos_audit::AuditSigner;
use contextos_store::{MemoryLog, MemoryStore};
use contextosd::auth::hash_api_key;
use serde_json::{Value, json};
use towerd::source::Source;
use towerd::{Config, Tower, api, collector};

const AT: &str = "2026-11-07T10:00:00.000000Z";

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
        # The kill switch needs governed dispatch; these providers are never called.
        [providers.authority]
        url = "http://127.0.0.1:9/authority"
        [providers.constraints]
        url = "http://127.0.0.1:9/constraints"
        [providers.approvals]
        url = "http://127.0.0.1:9/approvals"
        [[api_keys]]
        key_sha256 = "{reader}"
        tenant_id = "tenant_acme_prod"
        principal_id = "svc_tower"
        scopes = ["audit:read"]
        [[api_keys]]
        key_sha256 = "{control}"
        tenant_id = "tenant_acme_prod"
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
    let admitted = json!({"run_id": "r1", "trace_id": "trace_r1", "agent_id": "agt_support",
        "pack_ref": "ctxpack.support@5.2.0", "intent": "support.refund", "profiles": ["contextos.core"],
        "required_controls": [], "release_refs": [], "admitted_by": "svc_orchestrator",
        "surfaced_capabilities": ["adp_payments.issue_refund", "adp_orders.lookup"]});
    state
        .audit
        .append("tenant_acme_prod", "run_admitted", admitted, AT)
        .await
        .unwrap();
    let refused = json!({"run_id": "r1", "operation_id": "op1", "reason_codes": ["revoked_capability"]});
    state
        .audit
        .append("tenant_acme_prod", "revocation_refusal", refused, AT)
        .await
        .unwrap();
    let app = contextosd::router(state, Duration::from_secs(5));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

async fn tower(runtime: &str, extra: &str) -> (String, Arc<Tower<MemoryStore, MemoryLog>>) {
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
        id = "eu-support"
        url = "{runtime}"
        token_env = "UNUSED"
        control_token_env = "UNUSED"
        [[api_keys]]
        key_sha256 = "{viewer}"
        principal_id = "ciso"
        roles = ["viewer"]
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
async fn sync(tower: &Tower<MemoryStore, MemoryLog>) {
    let mut anchor = tower
        .fleet
        .read()
        .await
        .sources
        .get("eu-support")
        .and_then(|s| s.anchor.clone());
    let (mut keys, mut refreshed) = (None, None);
    let source = tower.sources.get("eu-support").unwrap();
    assert!(collector::sync(&source, &tower.fleet, &mut keys, &mut anchor, &mut refreshed).await);
}

async fn call(base: &str, method: &str, path: &str, key: &str, body: Option<Value>) -> (u16, Value) {
    let http = reqwest::Client::new();
    let url = format!("{base}{path}");
    let mut request = if method == "GET" { http.get(url) } else { http.post(url) }.bearer_auth(key);
    if let Some(b) = body {
        request = request.json(&b);
    }
    let response = request.send().await.unwrap();
    let status = response.status().as_u16();
    (status, response.json().await.unwrap_or(Value::Null))
}

async fn runtime_revoked(runtime: &str) -> Vec<Value> {
    let response = reqwest::Client::new()
        .get(format!("{runtime}/v1/revocations"))
        .bearer_auth("control-key")
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    body["revoked"].as_array().cloned().unwrap_or_default()
}

const TARGET: &str = "adp_payments.issue_refund";

#[tokio::test]
async fn revocations_are_listed_and_restored_only_by_a_second_operator() {
    let rt = runtime().await;
    let (base, tower) = tower(&rt, "").await;
    let (_, me) = call(&base, "GET", "/api/me", "oncall-a", None).await;
    assert_eq!(me["two_person_restore"], true);

    // Revoking is one operator's action.
    let revoke = json!({"kind": "capability", "target": TARGET, "reason": "INC-42 duplicate refunds"});
    let (status, _) = call(&base, "POST", "/api/fleet/revoke", "viewer", Some(revoke.clone())).await;
    assert_eq!(status, 403);
    let (status, done) = call(&base, "POST", "/api/fleet/revoke", "oncall-a", Some(revoke)).await;
    assert_eq!(status, 200, "{done}");
    assert_eq!(done["results"][0]["ok"], true, "{done}");
    assert_eq!(runtime_revoked(&rt).await.len(), 1);

    // Before Tower has collected the change, the runtime lists what the chain does not.
    let (_, early) = call(&base, "GET", "/api/revocations", "viewer", None).await;
    assert_eq!(early["revocations"][0]["provenance"], "runtime_only");
    assert_eq!(early["mismatches"], 1);

    sync(&tower).await;
    let (status, view) = call(&base, "GET", "/api/revocations", "viewer", None).await;
    assert_eq!(status, 200, "{view}");
    assert_eq!(view["sources"][0]["live"], "read");
    assert_eq!(view["mismatches"], 0);
    let row = &view["revocations"][0];
    assert_eq!(row["provenance"], "verified");
    assert_eq!(
        (row["kind"].as_str(), row["target"].as_str()),
        (Some("capability"), Some(TARGET))
    );
    assert!(row["reason"].as_str().unwrap().starts_with("INC-42"));
    assert_eq!(row["by"], "svc_tower_control");
    assert_eq!(row["via_tower"], "oncall-a");
    assert!(row["at"].as_str().is_some() && row["sequence"].as_u64().is_some());
    assert_eq!(row["affected"], json!(["tenant_acme_prod/agt_support"]));
    assert_eq!(row["refusals"], 1);

    // Restoring takes a second operator.
    let restore = json!({"kind": "capability", "target": TARGET, "reason": "Fix deployed and verified"});
    let (status, refused) = call(&base, "POST", "/api/fleet/restore", "oncall-a", Some(restore.clone())).await;
    assert_eq!(status, 409);
    assert_eq!(refused["error"]["code"], "two_person_required");
    let (status, _) = call(
        &base,
        "POST",
        "/api/revocations/restore-requests",
        "oncall-a",
        Some(json!({"kind": "capability", "target": TARGET, "reason": "short"})),
    )
    .await;
    assert_eq!(status, 422, "a reason says why it is safe");
    let (status, request) = call(
        &base,
        "POST",
        "/api/revocations/restore-requests",
        "oncall-a",
        Some(restore.clone()),
    )
    .await;
    assert_eq!(status, 201, "{request}");
    let id = request["id"].as_str().unwrap().to_owned();
    let (status, _) = call(
        &base,
        "POST",
        "/api/revocations/restore-requests",
        "oncall-b",
        Some(restore),
    )
    .await;
    assert_eq!(status, 409, "one open request per target");
    let (_, view) = call(&base, "GET", "/api/revocations", "viewer", None).await;
    assert_eq!(view["pending_requests"], 1);

    let approve = format!("/api/revocations/restore-requests/{id}/approve");
    let (status, _) = call(&base, "POST", &approve, "oncall-a", None).await;
    assert_eq!(status, 403, "the requester cannot approve");
    let (status, _) = call(&base, "POST", &approve, "viewer", None).await;
    assert_eq!(status, 403);
    let (status, _) = call(
        &base,
        "POST",
        &format!("/api/revocations/restore-requests/{id}/cancel"),
        "oncall-b",
        None,
    )
    .await;
    assert_eq!(status, 403, "only the requester withdraws");
    assert_eq!(runtime_revoked(&rt).await.len(), 1, "nothing restored yet");

    let (status, executed) = call(&base, "POST", &approve, "oncall-b", None).await;
    assert_eq!(status, 200, "{executed}");
    assert_eq!(executed["status"], "restored");
    assert_eq!(executed["approved_by"], "oncall-b");
    assert_eq!(executed["results"][0]["ok"], true);
    assert_eq!(runtime_revoked(&rt).await, Vec::<Value>::new());
    let (status, _) = call(&base, "POST", &approve, "oncall-b", None).await;
    assert_eq!(status, 409, "approved once");

    sync(&tower).await;
    let (_, view) = call(&base, "GET", "/api/revocations", "viewer", None).await;
    assert_eq!(view["revocations"], json!([]));
    assert_eq!(view["pending_requests"], 0);
    let (_, list) = call(&base, "GET", "/api/revocations/restore-requests", "viewer", None).await;
    assert_eq!(list["requests"][0]["status"], "restored");

    let (_, journal) = call(&base, "GET", "/api/journal", "viewer", None).await;
    let kinds: Vec<&str> = journal["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["kind"].as_str())
        .collect();
    for kind in [
        "fleet_revoked",
        "restore_requested",
        "restore_approved",
        "restore_executed",
    ] {
        assert!(kinds.contains(&kind), "{kind} journalled: {kinds:?}");
    }
}

#[tokio::test]
async fn a_request_can_be_withdrawn_and_one_person_restore_can_be_configured() {
    let rt = runtime().await;
    let (base, _) = tower(&rt, "[governance]\n        two_person_restore = false").await;
    let restore = json!({"kind": "agent", "target": "agt_support", "reason": "Back in service after review"});
    let (status, done) = call(&base, "POST", "/api/fleet/revoke", "oncall-a", Some(restore.clone())).await;
    assert_eq!((status, &done["results"][0]["ok"]), (200, &json!(true)), "{done}");
    assert_eq!(runtime_revoked(&rt).await.len(), 1);
    let (status, request) = call(
        &base,
        "POST",
        "/api/revocations/restore-requests",
        "oncall-a",
        Some(restore.clone()),
    )
    .await;
    assert_eq!(status, 201);
    let cancel = format!(
        "/api/revocations/restore-requests/{}/cancel",
        request["id"].as_str().unwrap()
    );
    let (status, cancelled) = call(&base, "POST", &cancel, "oncall-a", None).await;
    assert_eq!((status, cancelled["status"].as_str()), (200, Some("cancelled")));
    let (status, _) = call(&base, "POST", &cancel, "oncall-a", None).await;
    assert_eq!(status, 409);
    let (status, done) = call(&base, "POST", "/api/fleet/restore", "oncall-a", Some(restore)).await;
    assert_eq!((status, &done["results"][0]["ok"]), (200, &json!(true)), "{done}");
    assert_eq!(runtime_revoked(&rt).await, Vec::<Value>::new());
}
