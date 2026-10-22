//! Tower against a real `contextosd`: signed entries written by the runtime's own audit
//! writer reach Tower only through the runtime's HTTP API, are verified, and become
//! inventory, findings and answers; governance actions enforce roles and separation of
//! duties and land in Tower's own verifiable journal.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use contextos_audit::AuditSigner;
use contextos_store::{MemoryLog, MemoryStore};
use contextosd::auth::hash_api_key;
use serde_json::{Value, json};
use towerd::intel::Scripted;
use towerd::source::Source;
use towerd::{Config, Tower, api, collector};

const AT: &str = "2026-10-21T10:00:00.000000Z";

/// A runtime holding the quickstart pack, with signed activity for two agents.
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
        [[api_keys]]
        key_sha256 = "{reader}"
        tenant_id = "tenant_acme_prod"
        principal_id = "svc_tower"
        scopes = ["audit:read"]
        "#,
        reader = hash_api_key("reader-key"),
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
        None,
    )
    .unwrap();
    let t = "tenant_acme_prod";
    let admit = |run: &str, agent: &str| {
        json!({"run_id": run, "trace_id": format!("trace_{run}"), "agent_id": agent, "pack_ref": "ctxpack.support@5.2.0",
            "intent": "support.refund", "profiles": ["contextos.core"], "required_controls": [],
            "release_refs": [], "surfaced_capabilities": ["adp_payments.issue_refund", "adp_orders.lookup"], "admitted_by": "svc_orchestrator"})
    };
    let entries = [
        ("run_admitted", admit("r1", "agt_support")),
        (
            "run_lifecycle",
            json!({"run_id": "r1", "event": "start", "status": "running", "executor_generation": 1}),
        ),
        (
            "authorization_decision",
            json!({"run_id": "r1", "operation_id": "refund:1", "verdict": "allow", "approval_refs": [], "reason_codes": []}),
        ),
        (
            "operation_claim",
            json!({"run_id": "r1", "operation_id": "refund:1", "attempt_id": "att_1", "capability_id": "adp_payments.issue_refund"}),
        ),
        (
            "effect_observation",
            json!({"run_id": "r1", "operation_id": "refund:1", "attempt_id": "att_1", "outcome": "unknown", "finality": "provisional"}),
        ),
        ("run_admitted", admit("r2", "agt_lookup")),
        (
            "revocation_refusal",
            json!({"run_id": "r2", "operation_id": "op2", "reason_codes": ["revoked_capability"]}),
        ),
    ];
    for (kind, payload) in entries {
        state.audit.append(t, kind, payload, AT).await.unwrap();
    }
    let app = contextosd::router(state, Duration::from_secs(5));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

async fn tower(
    runtime: &str,
    model: Option<Arc<dyn towerd::intel::Model>>,
) -> (String, Arc<Tower<MemoryStore, MemoryLog>>) {
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
        business_unit = "Customer Operations"
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
        "#,
        viewer = hash_api_key("viewer"),
        owner = hash_api_key("owner"),
        risk_a = hash_api_key("risk-a"),
        risk_b = hash_api_key("risk-b"),
    ))
    .unwrap();
    let source = Source::with_tokens(config.sources[0].clone(), "reader-key".into(), None);
    let tower = Arc::new(
        Tower::assemble(
            config,
            vec![Arc::new(source)],
            Arc::new(MemoryStore::new()),
            MemoryLog::new(),
            AuditSigner::from_seed("tower-journal", [4; 32]),
            model,
        )
        .unwrap(),
    );
    // One collector pass, synchronously.
    let (mut keys, mut anchor, mut refreshed) = (None, None, None);
    assert!(collector::sync(&tower.sources[0], &tower.fleet, &mut keys, &mut anchor, &mut refreshed).await);
    let app = api::router(tower.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), tower)
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

#[tokio::test]
async fn verified_activity_becomes_inventory_authority_and_findings() {
    let rt = runtime().await;
    let (base, tower) = tower(&rt, None).await;
    assert_eq!(tower.fleet.read().await.sources["eu-support"].verified_to, 7);

    let (status, _) = call(&base, "GET", "/api/posture", "nobody", None).await;
    assert_eq!(status, 401);
    let (_, posture) = call(&base, "GET", "/api/posture", "viewer", None).await;
    assert_eq!(posture["agents"]["total"], 2);
    assert_eq!(posture["agents"]["declared"], 0);
    assert!(posture["findings"]["by_severity"]["critical"].as_u64().unwrap() >= 2);

    let (_, agent) = call(
        &base,
        "GET",
        "/api/agents/tenant_acme_prod%2Fagt_support",
        "viewer",
        None,
    )
    .await;
    let rules: Vec<&str> = agent["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["rule"].as_str().unwrap())
        .collect();
    for rule in [
        "undeclared_agent",
        "unresolved_effects",
        "controls_missing",
        "profile_understated",
    ] {
        assert!(rules.contains(&rule), "{rule} missing from {rules:?}");
    }
    // The refund capability is external and compensatable: enterprise profile, with the
    // pack's approval gate counted.
    assert_eq!(agent["requirement"]["profile"], "contextos.enterprise");
    let refund = agent["graph"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "adp_payments.issue_refund")
        .unwrap();
    assert_eq!(
        (refund["effect"].as_str(), refund["used"].as_bool()),
        (Some("external_state"), Some(true))
    );
    assert_eq!(agent["facts"]["exposure"]["approval_gates"], 1);
    assert_eq!(agent["runs"][0]["unknown"], 1);
}

#[tokio::test]
async fn governance_actions_need_the_right_role_and_a_second_person() {
    let rt = runtime().await;
    let (base, tower) = tower(&rt, None).await;
    let key = "tenant_acme_prod%2Fagt_support";
    let declaration = json!({"owner": "maya", "team": "support-ai", "purpose": "Refunds for damaged deliveries",
        "users_served": "customers", "lifecycle": "production", "data_categories": ["order"], "regulatory_contexts": []});
    let (status, _) = call(
        &base,
        "PUT",
        &format!("/api/agents/{key}/declaration"),
        "viewer",
        Some(declaration.clone()),
    )
    .await;
    assert_eq!(status, 403);
    let mut other_team = declaration.clone();
    other_team["team"] = json!("payments");
    let (status, _) = call(
        &base,
        "PUT",
        &format!("/api/agents/{key}/declaration"),
        "owner",
        Some(other_team),
    )
    .await;
    assert_eq!(status, 403, "owners declare their own teams' agents");
    let (status, _) = call(
        &base,
        "PUT",
        &format!("/api/agents/{key}/declaration"),
        "owner",
        Some(declaration),
    )
    .await;
    assert_eq!(status, 200);
    // A risk reviewer may declare any team's agent (owners only their own).
    let (status, _) = call(
        &base,
        "PUT",
        "/api/agents/tenant_acme_prod%2Fagt_lookup/declaration",
        "risk-b",
        Some(json!({"owner": "sam", "team": "payments", "purpose": "Order lookups",
            "users_served": "internal", "lifecycle": "pilot"})),
    )
    .await;
    assert_eq!(status, 200);

    let (status, review) = call(
        &base,
        "POST",
        &format!("/api/agents/{key}/review"),
        "risk-a",
        Some(json!({"decision": "approved", "notes": "Refunds stay under the finance gate", "conditions": []})),
    )
    .await;
    assert_eq!(status, 200, "{review}");
    let (_, agent) = call(&base, "GET", &format!("/api/agents/{key}"), "viewer", None).await;
    let rules: Vec<&str> = agent["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["rule"].as_str().unwrap())
        .collect();
    assert!(
        !rules.contains(&"undeclared_agent") && !rules.contains(&"unreviewed"),
        "{rules:?}"
    );

    // Guardrail: drafted by one risk reviewer, activated only by another.
    let rule = json!({"title": "Customer-facing agents need a review", "severity": "high",
        "rule": {"and": [{"==": [{"var": "declaration.users_served"}, "customers"]}, {"!": {"var": "reviewed"}}]}});
    let (status, g) = call(&base, "POST", "/api/guardrails", "risk-a", Some(rule)).await;
    assert_eq!(status, 201, "{g}");
    let id = g["id"].as_str().unwrap();
    let (status, _) = call(&base, "POST", &format!("/api/guardrails/{id}/activate"), "risk-a", None).await;
    assert_eq!(status, 403);
    let (status, _) = call(&base, "POST", &format!("/api/guardrails/{id}/activate"), "risk-b", None).await;
    assert_eq!(status, 200);

    // Waiver: requested by the owner, decided by risk; expires on its own.
    let (_, w) = call(&base, "POST", "/api/waivers", "owner",
        Some(json!({"rule": "unresolved_effects", "agent": "tenant_acme_prod/agt_support", "reason": "provider outage INC-42, reconciling", "days": 7}))).await;
    let wid = w["id"].as_str().unwrap();
    let (status, _) = call(
        &base,
        "POST",
        &format!("/api/waivers/{wid}/decide"),
        "owner",
        Some(json!({"approve": true, "reason": "mine"})),
    )
    .await;
    assert_eq!(status, 403);
    let (status, decided) = call(
        &base,
        "POST",
        &format!("/api/waivers/{wid}/decide"),
        "risk-b",
        Some(json!({"approve": true, "reason": "tracked in INC-42"})),
    )
    .await;
    assert_eq!((status, decided["status"].as_str()), (200, Some("approved")));
    let (_, open) = call(
        &base,
        "GET",
        "/api/findings?agent=tenant_acme_prod/agt_support",
        "viewer",
        None,
    )
    .await;
    assert!(
        open["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["rule"] != "unresolved_effects")
    );

    // Every decision is in Tower's journal, which verifies like a runtime chain.
    let (_, journal) = call(&base, "GET", "/api/journal", "viewer", None).await;
    let kinds: Vec<&str> = journal["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap())
        .collect();
    assert_eq!(
        kinds,
        [
            "agent_declared",
            "agent_declared",
            "agent_reviewed",
            "guardrail_drafted",
            "guardrail_activated",
            "waiver_requested",
            "waiver_decided"
        ]
    );
    let entries: Vec<contextos_audit::AuditEntry> = serde_json::from_value(journal["entries"].clone()).unwrap();
    let ring = towerd::source::key_ring(&tower.journal_keys).unwrap();
    contextos_audit::verify_chain(&entries, None, &ring).unwrap();
}

#[tokio::test]
async fn the_analyst_answers_from_tools_and_its_use_is_journalled() {
    let rt = runtime().await;
    let model = Arc::new(Scripted::new(vec![
        Scripted::tool(
            "list_findings",
            json!({"severity": "critical", "agent": null, "rule": null}),
        ),
        Scripted::text(
            "[agent:tenant_acme_prod/agt_support] has an unknown refund outcome: [finding:unresolved_effects:tenant_acme_prod/agt_support].",
        ),
    ]));
    let (base, _) = tower(&rt, Some(model.clone())).await;
    let (status, out) = call(
        &base,
        "POST",
        "/api/ask",
        "viewer",
        Some(json!({"question": "What is critical right now?"})),
    )
    .await;
    assert_eq!(status, 200, "{out}");
    assert!(
        out["citations"].as_array().unwrap().iter().all(|c| c["exists"] == true),
        "{out}"
    );
    let tool_result = model.requests.lock().unwrap()[1]["messages"][2]["content"][0]["content"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(tool_result.contains("unresolved_effects"));
    let (_, journal) = call(&base, "GET", "/api/journal", "viewer", None).await;
    assert_eq!(journal["entries"][0]["kind"], "intelligence_used");
    assert_eq!(journal["entries"][0]["payload"]["by"], "ciso");
}

#[tokio::test]
async fn without_intelligence_the_ai_routes_say_so() {
    let rt = runtime().await;
    let (base, _) = tower(&rt, None).await;
    let (status, out) = call(
        &base,
        "POST",
        "/api/ask",
        "viewer",
        Some(json!({"question": "Anything?"})),
    )
    .await;
    assert_eq!(status, 501, "{out}");
}
