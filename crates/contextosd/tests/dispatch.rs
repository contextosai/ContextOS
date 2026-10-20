//! End-to-end governed dispatch through `contextosd` with remote fact services and an
//! MCP provider, all over real HTTP.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::routing::post;
use contextos_audit::AuditSigner;
use contextos_contract::canonical::sha256_canonical;
use contextos_store::{MemoryLog, MemoryStore};
use contextosd::auth::hash_api_key;
use contextosd::runtime::dispatch_setup_from_config;
use contextosd::{Config, build_state, load_pack, router};
use serde_json::{Value, json};

const TENANT: &str = "tenant_acme_prod";

async fn serve(router: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    format!("http://{addr}")
}

fn principal(id: &str) -> Value {
    json!({"principal_id": id, "principal_type": "workload", "trust_domain": "contextos.test", "tenant_id": TENANT})
}

fn artifact(kind: &str, id: &str) -> Value {
    json!({"artifact_type": kind, "artifact_id": id, "version": "1",
        "sha256": sha256_canonical(&json!({"artifact_type": kind, "artifact_id": id})).unwrap()})
}

/// Identity broker: grants exactly the requested binding scope to the run's agent.
fn authority_facts(request: &Value) -> Value {
    let (run, binding) = (&request["run"], &request["binding"]);
    let grant = json!({
        "grant_id": "grant_refund", "grant_revision": "1", "issuer": principal("mandate_broker"), "subject": run["actor"],
        "audience": "contextosd", "not_before": "2026-01-01T00:00:00Z", "expires_at": "2099-01-01T00:00:00Z",
        "delegation_depth_remaining": 2, "verification_ref": artifact("authority_grant", "grant_refund"),
        "scope": {"root_run_id": run["run_id"], "purpose_ids": [binding["purpose_id"]], "capability_ids": [binding["capability_id"]],
            "resource_ids": binding["resource_ids"], "destination_ids": binding["destination_ids"],
            "classification_labels": ["CONFIDENTIAL"], "argument_constraints": [], "amount_ceiling": {"minor_units": 1_000_000, "currency": "INR"}},
    });
    let window = json!({"observed_at": "2026-01-01T00:00:00Z", "valid_until": "2099-01-01T00:00:00Z"});
    json!({
        "authenticated": {"principal": run["actor"], "audience": "contextosd", "root_run_id": run["run_id"], "run_id": run["run_id"],
            "mandate_kind": "workload", "trusted_issuers": [principal("mandate_broker")], "trusted_observers": [principal("control_plane")],
            "verification_status": "verified", "verification_ref": artifact("authentication", "agent"),
            "observed_at": window["observed_at"], "valid_until": window["valid_until"]},
        "leaf_grant_ref": {"grant_id": "grant_refund", "grant_revision": "1"},
        "grants": [grant],
        "observations": [{"grant_id": "grant_refund", "grant_revision": "1",
            "grant_digest": sha256_canonical(&json!({"domain": "contextos.authority_grant.v1", "grant": grant})).unwrap(),
            "verification_ref": grant["verification_ref"], "verification_status": "verified", "revocation_status": "active",
            "observer": principal("control_plane"), "observed_at": window["observed_at"], "valid_until": window["valid_until"]}],
        "run_links": [],
    })
}

fn constraint_facts(request: &Value) -> Value {
    let observations: Vec<Value> = request["required_controls"].as_array().unwrap().iter().map(|control| json!({
        "control": control, "action_digest": request["action_digest"], "policy_refs": [], "verdict": "allow",
        "verification_status": "verified", "verification_ref": artifact("control", control["control_id"].as_str().unwrap()),
        "observer": principal("control_plane"), "observed_at": "2026-01-01T00:00:00Z", "valid_until": "2099-01-01T00:00:00Z"})).collect();
    json!({"observations": observations})
}

struct World {
    base: String,
    provider_calls: Arc<AtomicUsize>,
    policy_refs: Arc<Mutex<Value>>,
}

async fn world(controls: &[&str]) -> World {
    let policy_refs: Arc<Mutex<Value>> = Arc::new(Mutex::new(json!([])));
    let refs = policy_refs.clone();
    let authority = serve(
        Router::new().fallback(post(|axum::Json(r): axum::Json<Value>| async move {
            axum::Json(authority_facts(&r))
        })),
    )
    .await;
    let constraints = serve(Router::new().fallback(post(move |axum::Json(r): axum::Json<Value>| {
        let refs = refs.clone();
        async move {
            // A real control plane attests against the pinned policy bundle refs.
            let mut facts = constraint_facts(&r);
            for o in facts["observations"].as_array_mut().unwrap() {
                o["policy_refs"] = refs.lock().unwrap().clone();
            }
            axum::Json(facts)
        }
    })))
    .await;
    let approvals = serve(
        Router::new().fallback(post(|axum::Json(r): axum::Json<Value>| async move {
            if r["op"] == "lookup" {
                axum::Json(json!({"approval": null}))
            } else {
                axum::Json(json!({"approval_request_id": "apr_1"}))
            }
        })),
    )
    .await;
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let counter = provider_calls.clone();
    let mcp = serve(Router::new().fallback(post(move |axum::Json(r): axum::Json<Value>| {
        let counter = counter.clone();
        async move {
            counter.fetch_add(1, Ordering::SeqCst);
            axum::Json(
                json!({"jsonrpc": "2.0", "id": r["id"], "result": {"structuredContent": {"refund_id": "rf_77"}}}),
            )
        }
    })))
    .await;

    let dir = std::env::temp_dir().join(format!("contextosd-dispatch-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let manifest_path = dir.join(format!("issue_refund-{}.json", controls.len()));
    std::fs::write(&manifest_path, json!({
        "capability_id": "adp_payments.issue_refund", "capability_version": "3", "adapter_id": "adp_payments",
        "protocol_tool": "issue_refund", "purpose_id": "support.refund", "desired_effect": "refund_created",
        "action_risk": {"effect": "external_state", "authority": "service", "reversibility": "compensatable", "interaction": "api", "data_scope": "CONFIDENTIAL"},
        "approval_mode": "destructive", "resource_pointers": ["/order_id"], "destination_pointers": ["/customer_id"],
        "amount": {"minor_units_pointer": "/amount_minor", "currency": "INR"},
        "recovery": {"strategy": "manual_reconcile", "max_attempts": 1, "retry_delays_seconds": []},
        "timeout_ms": 2000, "reservation": {"tokens": 0, "tool_calls": 1, "replans": 0, "cost_units": 100},
        "adapter_ref": artifact("adapter", "payments@3"), "capability_ref": artifact("capability", "issue_refund@3"),
    }).to_string()).unwrap();
    let controls = controls
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config = Config::parse(&format!(
        r#"
        capabilities = ["{manifest}"]
        [server]
        listen = "127.0.0.1:0"
        mode = "development"
        [store]
        kind = "memory"
        [audit]
        signing_seed_env = "UNUSED"
        key_id = "audit-test"
        [support]
        implementation_id = "contextos-rs"
        implementation_version = "0.1.0"
        profiles = ["contextos.core"]
        controls = [{controls}]
        [identity]
        trust_domain = "contextos.test"
        gateway_principal_id = "contextosd"
        [providers.authority]
        url = "{authority}"
        [providers.constraints]
        url = "{constraints}"
        [providers.approvals]
        url = "{approvals}"
        [[adapters]]
        id = "adp_payments"
        kind = "mcp"
        endpoint = "{mcp}"
        [[api_keys]]
        key_sha256 = "{key}"
        tenant_id = "{TENANT}"
        principal_id = "svc_orchestrator"
        scopes = ["admit", "dispatch", "audit:read"]
        "#,
        manifest = manifest_path.display(),
        key = hash_api_key("acme-key")
    ))
    .unwrap();
    let vectors: Value = serde_json::from_str(
        &std::fs::read_to_string(format!(
            "{}/../../conformance/vectors/compiler.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap();
    let pack = vectors["cases"][0]["pack"].to_string();
    let mut packs = HashMap::new();
    let (pack_ref, loaded) = load_pack(&pack).unwrap();
    packs.insert(pack_ref, loaded);
    let dispatch = dispatch_setup_from_config(&config).unwrap();
    let state = build_state(
        &config,
        Arc::new(MemoryStore::new()),
        MemoryLog::new(),
        AuditSigner::from_seed("audit-test", [5; 32]),
        packs,
        dispatch,
    )
    .unwrap();
    World {
        base: serve(router(state, Duration::from_secs(10))).await,
        provider_calls,
        policy_refs,
    }
}

const ALL_CONTROLS: [&str; 9] = [
    "identity.authenticated",
    "authority.scoped",
    "policy.fail_visible",
    "context.integrity",
    "audit.correlated",
    "effects.reconciled",
    "approval.bound",
    "network.mediated",
    "data.flow_policy",
];

fn run_body(run_id: &str, amount: u64) -> Value {
    let vectors: Value = serde_json::from_str(
        &std::fs::read_to_string(format!(
            "{}/../../conformance/vectors/compiler.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap();
    let case = vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "grid:support.refund:true:4200:support_agent")
        .unwrap();
    let mut request = case["request"].clone();
    request["input"]["context"]["refund_amount"] = json!(amount);
    let mut run_context = case["run_context"].clone();
    run_context["run_id"] = json!(run_id);
    json!({
        "pack_ref": "ctxpack.support@5.2.0", "request": request, "run_context": run_context, "deps": case["deps"],
        "contract": {"envelope_version": "contextos.execution_contract.v1", "contract_id": format!("contract_{run_id}"), "run_id": run_id,
            "trace_id": run_context["trace_id"], "tenant_id": TENANT, "profiles": [{"profile_id": "contextos.core", "profile_version": "1"}],
            "required_controls": [], "optional_controls": [], "release_refs": [artifact("release", "contextosd@0.1.0")]},
        "deadline": "2099-01-01T00:00:00Z",
        "limits": {"tokens": 10000, "tool_calls": 8, "replans": 2, "cost_cents": 25.0},
    })
}

fn tool_call(run_id: &str, id: &str, amount: u64) -> Value {
    json!({"envelope_version": "contextos.tool_call.v1", "tool_call_id": id, "run_id": run_id,
        "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736", "capability_id": "adp_payments.issue_refund",
        "args": {"order_id": "ord_881", "customer_id": "cus_77", "amount_minor": amount},
        "principal_chain": [{"kind": "agent", "id": "agt_support"}], "approval_mode_requested": "destructive",
        "approval_mode_effective": "destructive", "approval_mode_highest": "destructive",
        "evidence_refs": ["kg:order:ord_881#snapshot_kg_2026_05_03_T0930"], "idempotency_key": format!("refund:{run_id}")})
}

#[tokio::test]
async fn admitted_run_dispatches_governed_effects() {
    let w = world(&ALL_CONTROLS).await;
    let http = reqwest::Client::new();
    let admitted = http
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_small", 1200))
        .send()
        .await
        .unwrap();
    assert_eq!(admitted.status(), 201, "{}", admitted.text().await.unwrap());
    let admitted: Value = admitted.json().await.unwrap();
    assert_eq!(
        admitted["features"]["external_effects"], true,
        "derived from the pinned capability"
    );
    assert_eq!(admitted["features"]["sensitive_data"], true);
    *w.policy_refs.lock().unwrap() = admitted["policy_refs"].clone();

    let again = http
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_small", 1200))
        .send()
        .await
        .unwrap();
    assert_eq!(again.status(), 409);

    let out: Value = http
        .post(format!("{}/v1/runs/run_small/tool-calls", w.base))
        .bearer_auth("acme-key")
        .json(&tool_call("run_small", "tc_1", 120_000))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(out["result"]["status"], "completed", "{out}");
    assert_eq!(out["result"]["output"]["refund_id"], "rf_77");
    assert_eq!(w.provider_calls.load(Ordering::SeqCst), 1);

    let audit: Value = http
        .get(format!("{}/v1/audit/verify", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(audit, json!({"verified": true, "entries": 3}));
    let metrics = http
        .get(format!("{}/metrics", w.base))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(metrics.contains(r#"contextos_dispatch_outcomes_total{status="completed"} 1"#));

    let missing = http
        .post(format!("{}/v1/runs/run_nope/tool-calls", w.base))
        .bearer_auth("acme-key")
        .json(&tool_call("run_nope", "tc_9", 1))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 404);
}

#[tokio::test]
async fn high_value_refund_pauses_for_approval() {
    let w = world(&ALL_CONTROLS).await;
    let http = reqwest::Client::new();
    let admitted: Value = http
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_big", 4200))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    *w.policy_refs.lock().unwrap() = admitted["policy_refs"].clone();
    let out: Value = http
        .post(format!("{}/v1/runs/run_big/tool-calls", w.base))
        .bearer_auth("acme-key")
        .json(&tool_call("run_big", "tc_1", 420_000))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(out["result"]["status"], "paused", "{out}");
    assert_eq!(out["report"]["approval_request_id"], "apr_1");
    assert_eq!(w.provider_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn deployment_without_effect_controls_cannot_admit_effectful_runs() {
    let w = world(&ALL_CONTROLS[..5]).await;
    let response = reqwest::Client::new()
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_x", 1200))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 422);
    let error: Value = response.json().await.unwrap();
    assert_eq!(error["error"]["code"], "contract_rejected");
    assert!(error["error"]["detail"].to_string().contains("effects.reconciled"));
}
