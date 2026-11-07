//! Model spend end to end: usage events signed into a real `contextosd` audit chain
//! reach Tower through the runtime's API, are verified and folded, and come out of
//! `/api/spend` by agent, team and model, with findings for uncovered and
//! self-reported spend.
//!
//! The events are appended with the runtime's own audit writer in the shapes the
//! runtime's usage settlement and claim emit, so this test does not depend on which
//! runtime route produced them.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use contextos_audit::AuditSigner;
use contextos_store::{MemoryLog, MemoryStore};
use contextosd::auth::hash_api_key;
use serde_json::{Value, json};
use towerd::source::Source;
use towerd::{Config, Tower, api, collector};

const ADMITTED_AT: &str = "2026-10-21T10:00:00.000000Z";

fn now() -> String {
    collector::wall_clock()
}

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
            "intent": "support.refund", "profiles": ["contextos.core"], "required_controls": [], "release_refs": [],
            "surfaced_capabilities": ["adp_orders.lookup"], "admitted_by": "svc_orchestrator"})
    };
    let settled = |run: &str, id: &str, verified: bool, model: Value, tokens: u64, cost_units: u64| {
        json!({"run_id": run, "reservation_id": id, "reporter": if verified { "svc_meter" } else { "svc_orchestrator" },
            "verified": verified, "model": model,
            "charged": {"tokens": tokens, "cost_units": cost_units, "tool_calls": 0, "replans": 0},
            "measured": if verified { json!({"tokens": tokens, "cost_units": cost_units}) } else { Value::Null }})
    };
    for (kind, payload) in [
        ("run_admitted", admit("r1", "agt_support")),
        ("run_admitted", admit("r2", "agt_lookup")),
    ] {
        state.audit.append(t, kind, payload, ADMITTED_AT).await.unwrap();
    }
    let usage = [
        (
            "usage_claimed",
            json!({"run_id": "r1", "reservation_id": "usage:a", "reporter": "svc_meter", "model": "gpt-5"}),
        ),
        (
            "usage_settled",
            settled("r1", "usage:a", true, json!("gpt-5"), 3_000, 9_000),
        ),
        (
            "usage_overage",
            json!({"run_id": "r1", "reservation_id": "usage:a", "reporter": "svc_meter", "reserved": {"tokens": 1_000},
                "measured": {"tokens": 3_500, "cost_units": 9_000}, "charged": {"tokens": 3_000, "cost_units": 9_000}}),
        ),
        ("usage_settled", settled("r2", "usage:b", false, Value::Null, 40_000, 0)),
        (
            "usage_refused",
            json!({"run_id": "r2", "kind": "model_call", "tokens": 4_000, "cost_cents": 0, "reason_codes": ["budget_tokens_exhausted"]}),
        ),
        // A run Tower never saw admitted: counted as unattributed, not guessed.
        ("usage_settled", settled("r9", "usage:c", true, json!("gpt-5"), 10, 10)),
    ];
    let at = now();
    for (kind, payload) in usage {
        state.audit.append(t, kind, payload, &at).await.unwrap();
    }
    let app = contextosd::router(state, Duration::from_secs(5));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

async fn tower(runtime: &str) -> String {
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
        [[api_keys]]
        key_sha256 = "{viewer}"
        principal_id = "ciso"
        roles = ["viewer"]
        [[api_keys]]
        key_sha256 = "{owner}"
        principal_id = "maya"
        roles = ["owner"]
        teams = ["support-ai"]
        "#,
        viewer = hash_api_key("viewer"),
        owner = hash_api_key("owner"),
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
            None,
        )
        .unwrap(),
    );
    let (mut keys, mut anchor, mut refreshed) = (None, None, None);
    let source = tower.sources.active()[0].clone();
    assert!(collector::sync(&source, &tower.fleet, &mut keys, &mut anchor, &mut refreshed).await);
    let app = api::router(tower);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

async fn call(base: &str, method: &str, path: &str, key: &str, body: Option<Value>) -> (u16, Value) {
    let http = reqwest::Client::new();
    let url = format!("{base}{path}");
    let mut request = if method == "PUT" { http.put(url) } else { http.get(url) }.bearer_auth(key);
    if let Some(b) = body {
        request = request.json(&b);
    }
    let response = request.send().await.unwrap();
    let status = response.status().as_u16();
    (status, response.json().await.unwrap_or(Value::Null))
}

#[tokio::test]
async fn verified_usage_becomes_spend_by_agent_team_and_model() {
    let base = tower(&runtime().await).await;
    let (status, _) = call(&base, "GET", "/api/spend", "nobody", None).await;
    assert_eq!(status, 401);
    let (status, _) = call(&base, "GET", "/api/spend?hours=5", "viewer", None).await;
    assert_eq!(status, 422);
    let (status, _) = call(&base, "GET", "/api/spend?group=planet", "viewer", None).await;
    assert_eq!(status, 422);

    let declaration = json!({"owner": "maya", "team": "support-ai", "purpose": "Refunds", "users_served": "customers",
        "lifecycle": "production"});
    let (status, _) = call(
        &base,
        "PUT",
        "/api/agents/tenant_acme_prod%2Fagt_support/declaration",
        "owner",
        Some(declaration),
    )
    .await;
    assert_eq!(status, 200);

    let (status, by_agent) = call(&base, "GET", "/api/spend?hours=24", "viewer", None).await;
    assert_eq!(status, 200, "{by_agent}");
    let totals = &by_agent["totals"];
    assert_eq!(totals["tokens"], 43_000);
    assert_eq!(totals["verified_tokens"], 3_000);
    assert_eq!(totals["self_reported_tokens"], 40_000);
    assert_eq!(totals["uncovered_tokens"], 500);
    assert_eq!(totals["refused"], 1);
    assert_eq!(totals["unsettled_claims"], 0);
    assert_eq!(by_agent["refusals"]["budget_tokens_exhausted"], 1);
    assert_eq!(by_agent["series"].as_array().unwrap().len(), 24);
    let rows = by_agent["rows"].as_array().unwrap();
    // Ranked by cost: the metered agent first.
    assert_eq!(rows[0]["key"], "tenant_acme_prod/agt_support");
    assert_eq!(rows[0]["team"], "support-ai");
    assert_eq!(rows[0]["models"], json!(["gpt-5"]));
    assert_eq!(rows[1]["team"], "(undeclared)");

    let (_, by_team) = call(&base, "GET", "/api/spend?hours=168&group=team", "viewer", None).await;
    let teams: Vec<&str> = by_team["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["key"].as_str().unwrap())
        .collect();
    assert_eq!(teams, ["support-ai", "(undeclared)"]);
    let (_, by_model) = call(&base, "GET", "/api/spend?hours=720&group=model", "viewer", None).await;
    assert_eq!(by_model["bucket_hours"], 24);
    assert_eq!(by_model["series"].as_array().unwrap().len(), 30);
    let models: Vec<&str> = by_model["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["key"].as_str().unwrap())
        .collect();
    assert_eq!(models, ["gpt-5", "(unreported)"]);

    let (_, one) = call(
        &base,
        "GET",
        "/api/agents/tenant_acme_prod%2Fagt_lookup/spend",
        "viewer",
        None,
    )
    .await;
    assert_eq!(one["usage"]["self_reported_tokens"], 40_000);
    assert_eq!(one["refusals"]["budget_tokens_exhausted"], 1);
    let (status, _) = call(
        &base,
        "GET",
        "/api/agents/tenant_acme_prod%2Fnobody/spend",
        "viewer",
        None,
    )
    .await;
    assert_eq!(status, 404);

    let (_, findings) = call(&base, "GET", "/api/findings", "viewer", None).await;
    let ids: Vec<&str> = findings["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap())
        .collect();
    assert!(
        ids.contains(&"uncovered_model_usage:tenant_acme_prod/agt_support"),
        "{ids:?}"
    );
    assert!(
        ids.contains(&"unmetered_model_spend:tenant_acme_prod/agt_lookup"),
        "{ids:?}"
    );
    assert!(!ids.contains(&"unmetered_model_spend:tenant_acme_prod/agt_support"));

    let (_, sources) = call(&base, "GET", "/api/sources", "viewer", None).await;
    assert_eq!(sources["sources"][0]["state"]["unattributed"], 1);
}
