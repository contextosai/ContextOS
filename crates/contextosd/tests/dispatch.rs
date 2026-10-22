//! End-to-end governed dispatch through `contextosd` with remote fact services and an
//! MCP provider, all over real HTTP.

#[tokio::test]
async fn shared_guarantee_unknown_exposure_can_be_reconciled_after_the_run_fails() {
    let w = world_with(&ALL_CONTROLS, 1, |c| {
        c.guarantees = vec![
            serde_json::from_value(json!({
        "id":"refunds","capability_ids":["adp_payments.issue_refund"],"resource_pointer":"/order_id",
        "amount_pointer":"/amount_minor","limit":1000,"unit":"INR_minor"}))
            .unwrap(),
        ];
    })
    .await;
    let http = executor_client(2);
    let admitted: Value = http
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_terminal_shared", 7))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(admitted["executor_generation"], 2);
    let out: Value = http
        .post(format!("{}/v1/runs/run_terminal_shared/tool-calls", w.base))
        .bearer_auth("acme-key")
        .json(&tool_call("run_terminal_shared", "pending", 777))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(out["result"]["status"], "paused");
    let failed: Value = http
        .post(format!("{}/v1/runs/run_terminal_shared/fail", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(failed["status"], "failed");
    let generation = failed["executor_generation"].as_u64().unwrap();
    let url = format!(
        "{}/v1/runs/run_terminal_shared/operations/refund:run_terminal_shared/reconcile",
        w.base
    );
    let stale = http
        .post(&url)
        .bearer_auth("acme-key")
        .json(&json!({"source":"provider"}))
        .send()
        .await
        .unwrap();
    assert_eq!(stale.status(), 409);
    let outcome: Value = executor_client(generation)
        .post(&url)
        .bearer_auth("acme-key")
        .json(&json!({"source":"provider"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(outcome["status"], "resolved", "{outcome}");
    assert_eq!(w.provider_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn shared_guarantees_coordinate_replicas_and_expose_only_tenant_scoped_read_views() {
    let w = world_with(&ALL_CONTROLS, 2, |c| {
        c.guarantees = vec![
            serde_json::from_value(json!({"id":"refunds","capability_ids":["adp_payments.issue_refund"],
            "resource_pointer":"/order_id","amount_pointer":"/amount_minor","limit":200_000,"unit":"INR_minor"}))
            .unwrap(),
        ];
        c.api_keys.push(contextosd::config::ApiKey {
            key_sha256: hash_api_key("other-reader"),
            tenant_id: "tenant_other".into(),
            principal_id: "other_reader".into(),
            scopes: vec!["audit:read".into()],
        });
    })
    .await;
    let http = executor_client(2);
    for id in ["run_shared_a", "run_shared_b"] {
        let out = http
            .post(format!("{}/v1/runs", w.base))
            .bearer_auth("acme-key")
            .json(&run_body(id, 1200))
            .send()
            .await
            .unwrap();
        assert_eq!(out.status(), 201, "{}", out.text().await.unwrap());
    }
    let a = http
        .post(format!("{}/v1/runs/run_shared_a/tool-calls", w.base))
        .bearer_auth("acme-key")
        .json(&tool_call("run_shared_a", "a", 120_000));
    let b = http
        .post(format!("{}/v1/runs/run_shared_b/tool-calls", w.bases[1]))
        .bearer_auth("acme-key")
        .json(&tool_call("run_shared_b", "b", 120_000));
    let (a, b) = tokio::join!(a.send(), b.send());
    let a: Value = a.unwrap().json().await.unwrap();
    let b: Value = b.unwrap().json().await.unwrap();
    assert_eq!(
        [&a, &b].iter().filter(|o| o["result"]["status"] == "completed").count(),
        1,
        "{a} {b}"
    );
    assert!(
        [&a, &b]
            .iter()
            .any(|o| o["report"]["reason_codes"] == json!(["shared_guarantee_exceeded"])),
        "{a} {b}"
    );
    assert_eq!(w.provider_calls.load(Ordering::SeqCst), 1);
    let list = format!("{}/v1/guarantees", w.base);
    assert_eq!(http.get(&list).send().await.unwrap().status(), 401);
    assert_eq!(
        http.get(&list).bearer_auth("ops-key").send().await.unwrap().status(),
        403
    );
    let rules: Value = http
        .get(&list)
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(rules["guarantees"][0]["id"], "refunds");
    let digest = sha256_canonical(&json!("ord_881")).unwrap();
    let url = format!("{}/v1/guarantees/refunds/resources/{digest}", w.base);
    let view: Value = http
        .get(&url)
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(view["committed"], 120_000);
    assert_eq!(view["available"], 80_000);
    assert!(!view.to_string().contains("ord_881"));
    assert_eq!(
        http.get(&url)
            .bearer_auth("other-reader")
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
}

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
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
    /// Every replica's address (they share one store and one audit log).
    bases: Vec<String>,
    state: Arc<contextosd::app::AppState<MemoryStore, Arc<MemoryLog>>>,
    provider_calls: Arc<AtomicUsize>,
}

async fn world(controls: &[&str]) -> World {
    world_n(controls, 1).await
}

/// `replicas` servers sharing one in-memory store and one audit log, as separate
/// processes sharing a database would.
async fn world_n(controls: &[&str], replicas: usize) -> World {
    world_with(controls, replicas, |_| {}).await
}

/// As [`world_n`], with the configuration adjusted first.
async fn world_with(controls: &[&str], replicas: usize, adjust: impl FnOnce(&mut Config)) -> World {
    let (mut config, provider_calls) = world_setup(controls).await;
    adjust(&mut config);
    let (store, log) = (Arc::new(MemoryStore::new()), Arc::new(MemoryLog::new()));
    let mut bases = Vec::new();
    let mut first = None;
    for _ in 0..replicas.max(1) {
        let state = replica_state(&config, store.clone(), log.clone());
        first.get_or_insert_with(|| state.clone());
        bases.push(serve(router(state, Duration::from_secs(10))).await);
    }
    World {
        base: bases[0].clone(),
        bases,
        state: first.unwrap(),
        provider_calls,
    }
}

/// One replica's server state over a shared store and log.
fn replica_state<S, L>(config: &Config, store: Arc<S>, log: L) -> Arc<contextosd::app::AppState<S, L>>
where
    S: contextos_store::DocumentStore + 'static,
    L: contextos_store::AppendLog + 'static,
{
    build_state(
        config,
        store,
        log,
        AuditSigner::from_seed("audit-test", [5; 32]),
        world_packs(),
        dispatch_setup_from_config(config).unwrap(),
    )
    .unwrap()
}

/// The pack and a candidate version that drops the high-value approval (for rollouts).
fn world_packs() -> HashMap<String, contextosd::app::LoadedPack> {
    let vectors = compiler_vectors();
    let mut packs = HashMap::new();
    let (pack_ref, loaded) = load_pack(&vectors["cases"][0]["pack"].to_string()).unwrap();
    packs.insert(pack_ref, loaded);
    let mut candidate = vectors["cases"][0]["pack"].clone();
    candidate["pack_meta"]["pack_version"] = json!("5.3.0");
    candidate["policy_layer"]["policy_bundles"][0]["policy_dsl"]["rules"][1]["then"] = json!({"allow": true});
    let (pack_ref, loaded) = load_pack(&candidate.to_string()).unwrap();
    packs.insert(pack_ref, loaded);
    packs
}

/// The fake fact services and MCP tool server, and the configuration pointing at them.
/// Numbers each setup's capability manifest file.
static SETUPS: AtomicUsize = AtomicUsize::new(0);

async fn world_setup(controls: &[&str]) -> (Config, Arc<AtomicUsize>) {
    let authority = serve(
        Router::new().fallback(post(|axum::Json(r): axum::Json<Value>| async move {
            axum::Json(authority_facts(&r))
        })),
    )
    .await;
    let constraints = serve(Router::new().fallback(post(move |axum::Json(r): axum::Json<Value>| {
        async move {
            // A real control plane attests against the pinned policy bundle refs.
            let mut facts = constraint_facts(&r);
            for o in facts["observations"].as_array_mut().unwrap() {
                o["policy_refs"] = r["run"]["policy_refs"].clone();
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
            if r["method"] == "tasks/get" {
                // The long-running refund has finished.
                return axum::Json(json!({"jsonrpc": "2.0", "id": r["id"], "result": {"task": {
                    "taskId": r["params"]["taskId"], "status": "completed",
                    "result": {"structuredContent": {"refund_id": "rf_task"}}}}}));
            }
            counter.fetch_add(1, Ordering::SeqCst);
            if r["params"]["arguments"]["amount_minor"] == 555 {
                // Asks why before refunding; runs once the answer arrives.
                let answered = &r["params"]["inputResponses"]["reason"];
                if answered["action"] == "accept" && r["params"]["requestState"] == "st_1" {
                    return axum::Json(json!({"jsonrpc": "2.0", "id": r["id"], "result": {
                        "structuredContent": {"refund_id": "rf_reasoned", "reason": answered["content"]["reason"]}}}));
                }
                return axum::Json(json!({"jsonrpc": "2.0", "id": r["id"], "result": {
                    "resultType": "input_required", "requestState": "st_1",
                    "inputRequests": {"reason": {"method": "elicitation/create", "params": {
                        "message": "Why is this refund being issued?",
                        "requestedSchema": {"type": "object", "required": ["reason"],
                            "properties": {"reason": {"type": "string", "enum": ["damaged", "late"]}}}}}}}}));
            }
            if r["params"]["arguments"]["amount_minor"] == 777 {
                return axum::Json(json!({"jsonrpc": "2.0", "id": r["id"], "result": {
                    "resultType": "task", "task": {"taskId": "task_e2e_1", "status": "working"}}}));
            }
            axum::Json(
                json!({"jsonrpc": "2.0", "id": r["id"], "result": {"structuredContent": {"refund_id": "rf_77"}}}),
            )
        }
    })))
    .await;

    let dir = std::env::temp_dir().join(format!("contextosd-dispatch-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // One file per setup: parallel tests must not rewrite a file another is reading.
    let manifest_path = dir.join(format!("issue_refund-{}.json", SETUPS.fetch_add(1, Ordering::SeqCst)));
    std::fs::write(&manifest_path, json!({
        "capability_id": "adp_payments.issue_refund", "capability_version": "3", "adapter_id": "adp_payments",
        "protocol_tool": "issue_refund", "purpose_id": "support.refund", "desired_effect": "refund_created",
        "action_risk": {"effect": "external_state", "authority": "service", "reversibility": "compensatable", "interaction": "api", "data_scope": "CONFIDENTIAL"},
        "approval_mode": "destructive", "resource_pointers": ["/order_id"], "destination_pointers": ["/customer_id"],
        "amount": {"minor_units_pointer": "/amount_minor", "currency": "INR"},
        "recovery": {"strategy": "manual_reconcile", "max_attempts": 2, "retry_delays_seconds": [0]},
        "timeout_ms": 2000, "reservation": {"tokens": 0, "tool_calls": 1, "replans": 0, "cost_units": 100},
        "adapter_ref": artifact("adapter", "payments@3"), "capability_ref": artifact("capability", "issue_refund@3"),
        "description": "Refund an order to the customer's original payment method.",
        "input_schema": {"type": "object", "additionalProperties": false, "required": ["order_id", "customer_id", "amount_minor"],
            "properties": {"order_id": {"type": "string"}, "customer_id": {"type": "string"},
                "amount_minor": {"type": "integer", "minimum": 1}}},
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
        [limits]
        requests_per_second = 1000000.0
        burst = 1000000.0
        max_concurrent_dispatch = 100000
        max_in_flight = 100000
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
        scopes = ["admit", "dispatch", "reconcile", "audit:read"]
        [[api_keys]]
        key_sha256 = "{evaluator}"
        tenant_id = "{TENANT}"
        principal_id = "svc_quality_judge"
        scopes = ["evaluate"]
        [[api_keys]]
        key_sha256 = "{agent_judge}"
        tenant_id = "{TENANT}"
        principal_id = "agt_support"
        scopes = ["evaluate"]
        [[api_keys]]
        key_sha256 = "{operator}"
        tenant_id = "{TENANT}"
        principal_id = "svc_oncall"
        scopes = ["control"]
        [[api_keys]]
        key_sha256 = "{meter}"
        tenant_id = "{TENANT}"
        principal_id = "svc_llm_gateway"
        scopes = ["meter"]
        "#,
        manifest = manifest_path.display(),
        key = hash_api_key("acme-key"),
        evaluator = hash_api_key("judge-key"),
        agent_judge = hash_api_key("agent-judge-key"),
        operator = hash_api_key("ops-key"),
        meter = hash_api_key("meter-key")
    ))
    .unwrap();
    (config, provider_calls)
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

/// The compiler vectors, parsed once (the load test builds thousands of bodies).
fn compiler_vectors() -> &'static Value {
    static VECTORS: std::sync::LazyLock<Value> = std::sync::LazyLock::new(|| {
        let path = format!("{}/../../conformance/vectors/compiler.json", env!("CARGO_MANIFEST_DIR"));
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    });
    &VECTORS
}

fn run_body(run_id: &str, amount: u64) -> Value {
    let vectors = compiler_vectors();
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
    let http = executor_client(2);
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
    // run admitted, run start, authorization decision, operation claim, effect observation
    assert_eq!(audit, json!({"verified": true, "entries": 5}));
    let page: Value = http
        .get(format!("{}/v1/audit/entries?from=1&limit=1", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let admitted = &page["entries"][0];
    assert_eq!(admitted["kind"], "run_admitted");
    assert_eq!(admitted["payload"]["profiles"], json!(["contextos.core"]));
    assert!(admitted["payload"]["agent_id"].is_string() && admitted["payload"]["pack_ref"].is_string());
    assert!(
        admitted["payload"]["surfaced_capabilities"]
            .as_array()
            .is_some_and(|c| !c.is_empty())
    );
    let metrics = http
        .get(format!("{}/metrics", w.base))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        metrics.contains(
            r#"contextos_dispatch_outcomes_total{capability="adp_payments.issue_refund",status="completed"} 1"#
        ),
        "{metrics}"
    );
    assert!(
        metrics.contains(r#"contextos_admissions_total{pack="ctxpack.support@5.2.0"}"#),
        "{metrics}"
    );

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
    let http = executor_client(2);
    let admitted = http
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_big", 4200))
        .send()
        .await
        .unwrap();
    assert_eq!(admitted.status(), 201);
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

#[tokio::test]
async fn long_running_mcp_tasks_are_reconciled() {
    let w = world(&ALL_CONTROLS).await;
    let http = executor_client(2);
    let admitted = http
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_task", 1200))
        .send()
        .await
        .unwrap();
    assert_eq!(admitted.status(), 201);
    let out: Value = http
        .post(format!("{}/v1/runs/run_task/tool-calls", w.base))
        .bearer_auth("acme-key")
        .json(&tool_call("run_task", "tc_1", 777))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(out["result"]["status"], "paused", "{out}");
    let operation_id = out["report"]["operation_id"].as_str().unwrap().to_owned();
    let url = format!("{}/v1/runs/run_task/operations/{operation_id}/reconcile", w.base);

    let invalid = http
        .post(&url)
        .bearer_auth("acme-key")
        .json(&json!({"source": "operator", "outcome": "maybe", "evidence_ref": {}}))
        .send()
        .await
        .unwrap();
    assert_eq!(invalid.status(), 422);

    let resolved: Value = http
        .post(&url)
        .bearer_auth("acme-key")
        .json(&json!({"source": "provider"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resolved["status"], "resolved", "{resolved}");
    assert_eq!(resolved["outcome"], "confirmed");
    assert_eq!(resolved["output"]["refund_id"], "rf_task");
    assert_eq!(
        w.provider_calls.load(Ordering::SeqCst),
        1,
        "querying never re-invokes the tool"
    );

    let unknown: Value = http
        .post(format!("{}/v1/runs/run_task/operations/op_missing/reconcile", w.base))
        .bearer_auth("acme-key")
        .json(&json!({"source": "provider"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(unknown["reason_codes"], json!(["operation_not_found"]));
}

#[tokio::test]
async fn tools_that_need_input_continue_the_same_operation() {
    let w = world(&ALL_CONTROLS).await;
    let http = executor_client(2);
    let admitted = http
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_input", 1200))
        .send()
        .await
        .unwrap();
    assert_eq!(admitted.status(), 201);
    let call = tool_call("run_input", "tc_1", 555);
    let out: Value = http
        .post(format!("{}/v1/runs/run_input/tool-calls", w.base))
        .bearer_auth("acme-key")
        .json(&call)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(out["result"]["status"], "paused", "{out}");
    assert_eq!(
        out["report"]["obligations"].as_array().unwrap().last().unwrap(),
        "provide_requested_input"
    );
    assert!(out["result"]["output"]["result"]["inputRequests"]["reason"].is_object());
    let operation_id = out["report"]["operation_id"].as_str().unwrap().to_owned();
    let url = format!("{}/v1/runs/run_input/operations/{operation_id}/input", w.base);
    let send = |body: Value| {
        let http = http.clone();
        let url = url.clone();
        async move {
            http.post(url)
                .bearer_auth("acme-key")
                .json(&body)
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap()
        }
    };

    // Answers cannot change the authorized action.
    let altered = tool_call("run_input", "tc_2", 999_999);
    let refused = send(json!({"tool_call": altered,
        "input_responses": {"reason": {"action": "accept", "content": {"reason": "late"}}}}))
    .await;
    assert_eq!(refused["result"]["status"], "rejected", "{refused}");
    // Answers must fit the request.
    let refused = send(json!({"tool_call": call,
        "input_responses": {"reason": {"action": "accept", "content": {"reason": "because"}}}}))
    .await;
    assert_eq!(refused["report"]["reason_codes"], json!(["input_response_invalid"]));
    assert_eq!(w.provider_calls.load(Ordering::SeqCst), 1);

    let done = send(json!({"tool_call": call,
        "input_responses": {"reason": {"action": "accept", "content": {"reason": "damaged"}}}}))
    .await;
    assert_eq!(done["result"]["status"], "completed", "{done}");
    assert_eq!(done["result"]["output"]["reason"], "damaged");
    assert_eq!(
        done["report"]["operation_id"],
        json!(operation_id),
        "same operation, new attempt"
    );

    // The request was single-use, and the confirmed effect cannot be repeated.
    let replay = send(json!({"tool_call": call,
        "input_responses": {"reason": {"action": "accept", "content": {"reason": "damaged"}}}}))
    .await;
    assert_eq!(replay["result"]["status"], "rejected");
    assert_eq!(replay["report"]["reason_codes"], json!(["input_not_requested"]));
    assert_eq!(w.provider_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn delegated_children_are_admitted_narrowed_and_closed() {
    let w = world(&ALL_CONTROLS).await;
    let http = executor_client(2);
    let parent: Value = http
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_parent", 1200))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let mut child = run_body("run_child", 1200);
    let agent = child["run_context"]["agent"]["agent_id"].clone();
    let delegation = |capabilities: Value, child_run: &str| {
        json!({
            "envelope_version": "contextos.agent_delegation.v1", "delegation_id": format!("dlg_{child_run}"),
            "parent_run_id": "run_parent", "child_run_id": child_run, "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
            "tenant_id": TENANT, "issuer": agent, "subject": agent,
            "principal_chain": [{"kind": "agent", "id": agent}],
            "scope": {"allowed_intents": [child["request"]["input"]["intent"]], "allowed_capabilities": capabilities,
                "data_classification_ceiling": "CONFIDENTIAL", "output_schema_ref": "schema://refund-evidence.v1"},
            "sub_budget": {"total_tokens": 100, "bucket_tokens": {}, "max_tool_calls": 2, "max_replan_attempts": 0,
                "wall_clock_ms": 60_000, "max_cost_cents": 5},
            "effect_policy": "read_only", "issued_at": "2020-01-01T00:00:00Z", "expires_at": "2098-01-01T00:00:00Z",
            "parent_claim_hash": parent["compiled_context_hash"],
        })
    };

    let mut widened = run_body("run_wide", 1200);
    widened["delegation"] = delegation(json!(["adp_payments.issue_refund", "adp_other.anything"]), "run_wide");
    let refused = http
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&widened)
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 422);
    let refused: Value = refused.json().await.unwrap();
    assert_eq!(refused["error"]["detail"], json!(["delegation_scope_expanded"]));

    child["delegation"] = delegation(json!(["adp_payments.issue_refund"]), "run_child");
    let admitted = http
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&child)
        .send()
        .await
        .unwrap();
    assert_eq!(admitted.status(), 201, "{}", admitted.text().await.unwrap());

    // read_only: the effectful refund is not in the child's lane.
    let out: Value = http
        .post(format!("{}/v1/runs/run_child/tool-calls", w.base))
        .bearer_auth("acme-key")
        .json(&tool_call("run_child", "tc_1", 120_000))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(out["report"]["reason_codes"], json!(["capability_not_surfaced"]));
    assert_eq!(w.provider_calls.load(Ordering::SeqCst), 0);

    let close = |run: &'static str| {
        let http = http.clone();
        let url = format!("{}/v1/runs/{run}/close", w.base);
        async move {
            http.post(url)
                .bearer_auth("acme-key")
                .json(&json!({"decision": "accept"}))
                .send()
                .await
                .unwrap()
        }
    };
    let closed = close("run_child").await;
    assert_eq!(closed.status(), 200);
    let closed: Value = closed.json().await.unwrap();
    assert_eq!(closed["usage"]["tool_calls"], 0);
    assert_eq!(close("run_parent").await.status(), 422, "only delegated runs close");
}

/// A client acting as the executor that holds `generation` (a freshly admitted run
/// starts at generation 2: created, then started).
fn executor_client(generation: u64) -> reqwest::Client {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert("contextos-executor-generation", generation.to_string().parse().unwrap());
    reqwest::Client::builder().default_headers(headers).build().unwrap()
}

#[tokio::test]
async fn a_new_executor_takes_over_and_the_old_one_is_fenced() {
    let w = world(&ALL_CONTROLS).await;
    let old = executor_client(2);
    let admitted: Value = old
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_failover", 1200))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(admitted["executor_generation"], 2);
    let status: Value = old
        .get(format!("{}/v1/runs/run_failover", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        (status["status"].as_str(), status["executor_generation"].as_u64()),
        (Some("running"), Some(2))
    );

    // A new executor takes over from what it observed.
    let takeover = |expected: u64| {
        let http = reqwest::Client::new();
        let url = format!("{}/v1/runs/run_failover/takeover", w.base);
        async move {
            http.post(url)
                .bearer_auth("acme-key")
                .json(&json!({"expected_generation": expected}))
                .send()
                .await
                .unwrap()
        }
    };
    let taken: Value = takeover(2).await.json().await.unwrap();
    assert_eq!(
        taken["executor_generation"], 4,
        "suspend and resume each advance the generation"
    );
    assert_eq!(
        takeover(2).await.status(),
        409,
        "a takeover from a stale view is refused"
    );

    // The old executor can no longer start work; the new one can.
    let stale: Value = old
        .post(format!("{}/v1/runs/run_failover/tool-calls", w.base))
        .bearer_auth("acme-key")
        .json(&tool_call("run_failover", "tc_1", 120_000))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(stale["report"]["reason_codes"], json!(["executor_stale"]));
    assert_eq!(w.provider_calls.load(Ordering::SeqCst), 0);
    let fresh: Value = executor_client(4)
        .post(format!("{}/v1/runs/run_failover/tool-calls", w.base))
        .bearer_auth("acme-key")
        .json(&tool_call("run_failover", "tc_1", 120_000))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(fresh["result"]["status"], "completed", "{fresh}");
    let missing = reqwest::Client::new()
        .post(format!("{}/v1/runs/run_failover/tool-calls", w.base))
        .bearer_auth("acme-key")
        .json(&tool_call("run_failover", "tc_2", 120_000))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 428, "effectful requests must carry a generation");
}

#[tokio::test]
async fn runs_complete_and_cancel_over_http() {
    let w = world(&ALL_CONTROLS).await;
    let http = executor_client(2);
    for run in ["run_done", "run_stop"] {
        let admitted = http
            .post(format!("{}/v1/runs", w.base))
            .bearer_auth("acme-key")
            .json(&run_body(run, 1200))
            .send()
            .await
            .unwrap();
        assert_eq!(admitted.status(), 201);
    }
    let out: Value = http
        .post(format!("{}/v1/runs/run_done/tool-calls", w.base))
        .bearer_auth("acme-key")
        .json(&tool_call("run_done", "tc_1", 120_000))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(out["result"]["status"], "completed");
    let done = http
        .post(format!("{}/v1/runs/run_done/complete", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap();
    assert_eq!(done.status(), 200);
    let done: Value = done.json().await.unwrap();
    assert_eq!(done["status"], "completed");

    let cancelled: Value = reqwest::Client::new()
        .post(format!("{}/v1/runs/run_stop/cancel", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(cancelled["status"], "cancelled", "{cancelled}");
    let after: Value = http
        .post(format!("{}/v1/runs/run_stop/tool-calls", w.base))
        .bearer_auth("acme-key")
        .json(&tool_call("run_stop", "tc_1", 120_000))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        after["result"]["status"], "rejected",
        "a cancelled run's executor is fenced: {after}"
    );
    assert_eq!(w.provider_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn decisions_are_verified_gated_signed_and_exported() {
    let w = world(&ALL_CONTROLS).await;
    let http = executor_client(2);
    let post = |url: String, body: Value| {
        let http = http.clone();
        async move { http.post(url).bearer_auth("acme-key").json(&body).send().await.unwrap() }
    };
    assert_eq!(
        post(format!("{}/v1/runs", w.base), run_body("run_decide", 1200))
            .await
            .status(),
        201
    );
    let out: Value = post(
        format!("{}/v1/runs/run_decide/tool-calls", w.base),
        tool_call("run_decide", "tc_1", 120_000),
    )
    .await
    .json()
    .await
    .unwrap();
    assert_eq!(out["result"]["status"], "completed", "{out}");
    let operation_id = out["report"]["operation_id"].clone();

    let decision = |tool_calls: Value| {
        json!({"decision_key": "support.refund.execute", "decision_version": "1", "status": "DECIDED",
            "outcome": "refund_issued", "tool_calls": tool_calls,
            "rationale": {"strategy": "policy_and_evidence"}})
    };
    let url = format!("{}/v1/runs/run_decide/decisions", w.base);
    let forged = post(
        url.clone(),
        decision(json!([{"tool_call_id": "tc_x", "operation_id": "op_never_ran"}])),
    )
    .await;
    assert_eq!(forged.status(), 422);
    assert_eq!(
        forged.json::<Value>().await.unwrap()["error"]["code"],
        "lineage_unverified"
    );

    let recorded = post(
        url,
        decision(json!([{"tool_call_id": "tc_1", "operation_id": operation_id}])),
    )
    .await;
    assert_eq!(recorded.status(), 201, "{}", recorded.text().await.unwrap());
    let recorded: Value = recorded.json().await.unwrap();
    let record = &recorded["record"];
    assert_eq!(record["tool_lineage"][0]["tool_call_id"], "tc_1");
    assert_eq!(
        record["budget_usage"]["tool_calls"], 1,
        "usage comes from the run's ledger"
    );
    assert!(
        record["audit"]["record_hash"].is_string(),
        "signed into the audit chain"
    );
    assert_eq!(
        recorded["replay_packet"]["compiled_context_hash"],
        record["context_snapshot_hash"]
    );
    assert!(recorded["replay_packet"]["tool_transcript_chain_hash"].is_string());

    // Without the evidence its gate requires, the decision cannot be committed.
    let mut ungated = run_body("run_ungated", 4200);
    ungated["deps"]["evidence"] = json!([]);
    assert_eq!(post(format!("{}/v1/runs", w.base), ungated).await.status(), 201);
    let gated = post(format!("{}/v1/runs/run_ungated/decisions", w.base), decision(json!([]))).await;
    assert_eq!(gated.status(), 409);
    assert_eq!(
        gated.json::<Value>().await.unwrap()["error"]["code"],
        "evidence_gate_open"
    );
    let mut deferred = decision(json!([]));
    deferred["status"] = json!("DEFERRED");
    deferred.as_object_mut().unwrap().remove("outcome");
    assert_eq!(
        post(format!("{}/v1/runs/run_ungated/decisions", w.base), deferred)
            .await
            .status(),
        201
    );

    let evidence: Value = http
        .get(format!("{}/v1/runs/run_decide/evidence", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(evidence["run_state"]["status"], "running");
    assert_eq!(evidence["decisions"][0]["record"]["record_id"], record["record_id"]);
    assert_eq!(evidence["budget_ledger"]["used"]["tool_calls"], 1);

    let page: Value = http
        .get(format!("{}/v1/audit/entries?from=1&limit=3", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(page["entries"].as_array().unwrap().len(), 3);
    assert_eq!(page["entries"][0]["sequence"], 1);
    assert_eq!(page["next"], 4);
}

#[tokio::test]
async fn agent_hosts_use_governed_tools_over_mcp() {
    let w = world(&ALL_CONTROLS).await;
    let http = executor_client(2);
    assert_eq!(
        http.post(format!("{}/v1/runs", w.base))
            .bearer_auth("acme-key")
            .json(&run_body("run_mcp", 1200))
            .send()
            .await
            .unwrap()
            .status(),
        201
    );
    let url = format!("{}/v1/runs/run_mcp/mcp", w.base);
    let rpc = |id: u64, method: &str, params: Value| {
        let http = http.clone();
        let url = url.clone();
        let body = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        async move {
            http.post(url)
                .bearer_auth("acme-key")
                .json(&body)
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap()
        }
    };
    let init = rpc(
        1,
        "initialize",
        json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "host", "version": "1"}}),
    )
    .await;
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    conforms("McpResponse", &init);

    let listed = rpc(2, "tools/list", json!({})).await;
    conforms("McpResponse", &listed);
    let tools = listed["result"]["tools"].as_array().unwrap();
    // Listed under a name model APIs accept; the capability id travels with it.
    let refund = tools
        .iter()
        .find(|t| t["name"] == "adp_payments_issue_refund")
        .expect("surfaced capability listed");
    assert_eq!(
        refund["_meta"]["io.contextos/capabilityId"],
        "adp_payments.issue_refund"
    );
    assert_eq!(refund["title"], "adp_payments.issue_refund");
    assert_eq!(refund["annotations"]["destructiveHint"], true);
    assert_eq!(
        refund["inputSchema"]["required"],
        json!(["order_id", "customer_id", "amount_minor"])
    );

    let evidence = json!({"io.contextos/evidenceRefs": ["kg:order:ord_881#snapshot_kg_2026_05_03_T0930"]});
    let call = |id: u64, arguments: Value| {
        rpc(
            id,
            "tools/call",
            json!({"name": "adp_payments.issue_refund", "arguments": arguments, "_meta": evidence}),
        )
    };
    let args = json!({"order_id": "ord_881", "customer_id": "cus_77", "amount_minor": 120_000});
    let cited = json!({"io.contextos/evidenceRefs": ["kg:order:ord_881#snapshot_kg_2026_05_03_T0930"],
        "io.contextos/toolCallId": "tc_host_1"});
    let done = rpc(
        3,
        "tools/call",
        json!({"name": "adp_payments.issue_refund", "arguments": args, "_meta": cited}),
    )
    .await;
    assert_eq!(done["result"]["isError"], false, "{done}");
    conforms("McpResponse", &done);
    assert_eq!(done["result"]["structuredContent"]["refund_id"], "rf_77");
    // The result names the call and operation, so a decision can cite them.
    assert_eq!(done["result"]["_meta"]["io.contextos/toolCallId"], "tc_host_1");
    let operation = done["result"]["_meta"]["io.contextos/operationId"].clone();
    assert!(operation.as_str().unwrap().starts_with("mcp:"), "{operation}");

    // A host retrying what it believes failed cannot refund twice.
    let retried = call(4, args.clone()).await;
    assert_eq!(retried["result"]["isError"], true);
    conforms("McpResponse", &retried);
    assert_eq!(
        retried["result"]["structuredContent"]["reason_codes"],
        json!(["retry_unsafe"])
    );
    assert_eq!(retried["result"]["_meta"]["io.contextos/operationId"], operation);
    assert_eq!(w.provider_calls.load(Ordering::SeqCst), 1);

    // The listed name and the capability id name the same tool: a retry by either is the
    // same operation.
    let by_listed_name = rpc(
        41,
        "tools/call",
        json!({"name": "adp_payments_issue_refund", "arguments": args, "_meta": evidence}),
    )
    .await;
    assert_eq!(
        by_listed_name["result"]["structuredContent"]["reason_codes"],
        json!(["retry_unsafe"]),
        "{by_listed_name}"
    );
    assert_eq!(w.provider_calls.load(Ordering::SeqCst), 1);

    // Arguments are checked against the reviewed schema before anything else.
    let invalid = call(
        5,
        json!({"order_id": "ord_9", "customer_id": "cus_77", "amount_minor": 5, "note": "x"}),
    )
    .await;
    assert_eq!(
        invalid["result"]["structuredContent"]["reason_codes"],
        json!(["arguments_invalid"])
    );

    // A tool that needs input: the host answers and the same operation continues.
    let ask = call(
        6,
        json!({"order_id": "ord_555", "customer_id": "cus_77", "amount_minor": 555}),
    )
    .await;
    assert_eq!(ask["result"]["resultType"], "input_required", "{ask}");
    let state = ask["result"]["requestState"].clone();
    let answered = rpc(
        7,
        "tools/call",
        json!({"name": "adp_payments.issue_refund", "_meta": evidence,
        "arguments": {"order_id": "ord_555", "customer_id": "cus_77", "amount_minor": 555},
        "inputResponses": {"reason": {"action": "accept", "content": {"reason": "late"}}}, "requestState": state}),
    )
    .await;
    assert_eq!(answered["result"]["isError"], false, "{answered}");
    assert_eq!(answered["result"]["structuredContent"]["reason"], "late");

    let unknown = rpc(
        8,
        "tools/call",
        json!({"name": "adp_crm.delete_customer", "arguments": {}}),
    )
    .await;
    assert_eq!(unknown["error"]["code"], -32602);
    let stale = reqwest::Client::new()
        .post(&url)
        .bearer_auth("acme-key")
        .header("contextos-executor-generation", "1")
        .json(&json!({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
            "params": {"name": "adp_payments.issue_refund", "arguments": args, "_meta": evidence}}))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(
        stale["result"]["structuredContent"]["reason_codes"],
        json!(["executor_stale"])
    );
    let missing = reqwest::Client::new()
        .post(&url)
        .bearer_auth("acme-key")
        .json(&json!({"jsonrpc": "2.0", "id": 10, "method": "tools/call", "params": {"name": "adp_payments.issue_refund", "arguments": args}}))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(missing["error"]["code"], -32602, "the executor generation is required");
}

#[tokio::test]
async fn only_the_parents_executor_can_delegate() {
    let w = world(&ALL_CONTROLS).await;
    let owner = executor_client(2);
    let parent: Value = owner
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_p", 1200))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let mut child = run_body("run_c", 1200);
    let agent = child["run_context"]["agent"]["agent_id"].clone();
    child["delegation"] = json!({
        "envelope_version": "contextos.agent_delegation.v1", "delegation_id": "dlg_c", "parent_run_id": "run_p",
        "child_run_id": "run_c", "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736", "tenant_id": TENANT,
        "issuer": agent, "subject": agent, "principal_chain": [{"kind": "agent", "id": agent}],
        "scope": {"allowed_intents": [child["request"]["input"]["intent"]], "allowed_capabilities": ["adp_payments.issue_refund"],
            "data_classification_ceiling": "CONFIDENTIAL", "output_schema_ref": "schema://x"},
        "sub_budget": {"total_tokens": 10, "bucket_tokens": {}, "max_tool_calls": 1, "max_replan_attempts": 0, "wall_clock_ms": 1000, "max_cost_cents": 1},
        "effect_policy": "read_only", "issued_at": "2020-01-01T00:00:00Z", "expires_at": "2098-01-01T00:00:00Z",
        "parent_claim_hash": parent["compiled_context_hash"],
    });
    let stale = executor_client(1)
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&child)
        .send()
        .await
        .unwrap();
    assert_eq!(stale.status(), 409, "a stale executor cannot spend the parent's budget");
    let missing = reqwest::Client::new()
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&child)
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 428);
    let ok = owner
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&child)
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 201);
    let replay = owner
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&child)
        .send()
        .await
        .unwrap();
    assert_eq!(
        replay.status(),
        422,
        "a replayed delegation is refused without touching the budget"
    );
}

#[tokio::test]
async fn oversized_decisions_are_refused_before_signing() {
    let w = world(&ALL_CONTROLS).await;
    let http = executor_client(2);
    assert_eq!(
        http.post(format!("{}/v1/runs", w.base))
            .bearer_auth("acme-key")
            .json(&run_body("run_big_dec", 1200))
            .send()
            .await
            .unwrap()
            .status(),
        201
    );
    let entries = |http: reqwest::Client| {
        let url = format!("{}/v1/audit/verify", w.base);
        async move {
            http.get(url)
                .bearer_auth("acme-key")
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap()["entries"]
                .clone()
        }
    };
    let before = entries(http.clone()).await;
    let calls: Vec<Value> = (0..300)
        .map(|i| json!({"tool_call_id": format!("tc_{i}"), "operation_id": format!("op_{i}")}))
        .collect();
    let refused = http
        .post(format!("{}/v1/runs/run_big_dec/decisions", w.base))
        .bearer_auth("acme-key")
        .json(&json!({"decision_key": "support.refund.execute", "decision_version": "1", "status": "DEFERRED", "tool_calls": calls}))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 413);
    assert_eq!(entries(http.clone()).await, before, "nothing was signed");
}

#[tokio::test]
async fn memory_operations_need_a_memory_policy_service() {
    let w = world(&ALL_CONTROLS).await;
    let http = executor_client(2);
    assert_eq!(
        http.post(format!("{}/v1/runs", w.base))
            .bearer_auth("acme-key")
            .json(&run_body("run_mem", 1200))
            .send()
            .await
            .unwrap()
            .status(),
        201
    );
    let refused = http
        .post(format!("{}/v1/runs/run_mem/memory", w.base))
        .bearer_auth("acme-key")
        .json(&json!({"record": {"record_id": "m1", "contract_id": "contract_run_mem", "run_id": "run_mem", "tenant_id": TENANT}}))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 422);
    let decision: Value = refused.json().await.unwrap();
    assert_eq!(decision["reason_codes"], json!(["memory_policy_unavailable"]));
    let missing = http
        .get(format!("{}/v1/memory/m1", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 404, "nothing was stored");
}

#[tokio::test]
async fn admitted_runs_export_replay_cases() {
    let w = world(&ALL_CONTROLS).await;
    let http = executor_client(2);
    let body = run_body("run_replay", 1200);
    assert_eq!(
        http.post(format!("{}/v1/runs", w.base))
            .bearer_auth("acme-key")
            .json(&body)
            .send()
            .await
            .unwrap()
            .status(),
        201
    );
    let case: Value = http
        .get(format!("{}/v1/runs/run_replay/replay-case", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(case["name"], "run_replay");
    assert_eq!(case["request"], body["request"]);
    assert_eq!(case["run_context"], body["run_context"]);
    // The case replays: the kernel compiles it to the same context the run was admitted with.
    let cases = vec![serde_json::from_value::<contextos_kernel::release_gate::ReplayCase>(case).unwrap()];
    let pack: contextos_contract::types::ContextPack = serde_json::from_value(
        serde_json::from_str::<Value>(
            &std::fs::read_to_string(format!(
                "{}/../../conformance/vectors/compiler.json",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap(),
        )
        .unwrap()["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "grid:support.refund:true:4200:support_agent")
            .unwrap()["pack"]
            .clone(),
    )
    .unwrap();
    let report = contextos_kernel::release_gate::evaluate_release_gate(
        &pack,
        &pack,
        &cases,
        &contextos_kernel::release_gate::Acknowledgements::default(),
    )
    .unwrap();
    assert_eq!(report.verdict, "pass");
}

#[tokio::test]
async fn the_api_description_is_served() {
    let w = world(&ALL_CONTROLS).await;
    let response = reqwest::get(format!("{}/v1/openapi.json", w.base)).await.unwrap();
    assert_eq!(response.status(), 200);
    let doc: Value = response.json().await.unwrap();
    assert_eq!(doc["openapi"], "3.1.0");
    assert!(doc["paths"]["/v1/runs/{run_id}/tool-calls"]["post"].is_object());
}

/// Validates `value` against a component schema of the published OpenAPI document,
/// resolving its references into the normative ContextOS schemas.
fn conforms(component: &str, value: &Value) {
    use contextos_contract::schema::SchemaDoc;
    use std::sync::LazyLock;
    const OPENAPI_ID: &str = "https://contextosai.com/openapi/contextosd.v1.json";
    static OPENAPI: LazyLock<Value> = LazyLock::new(|| serde_json::from_str(contextosd::app::OPENAPI).unwrap());
    static REGISTRY: LazyLock<jsonschema::Registry<'static>> = LazyLock::new(|| {
        let mut registry = jsonschema::Registry::new().add(OPENAPI_ID, &*OPENAPI).unwrap();
        for doc in SchemaDoc::ALL {
            registry = registry.add(doc.id(), doc.document()).unwrap();
        }
        registry.prepare().unwrap()
    });
    let root = json!({"$ref": format!("{OPENAPI_ID}#/components/schemas/{component}")});
    let validator = jsonschema::options()
        .offline()
        .with_registry(&REGISTRY)
        .build(&root)
        .unwrap();
    let errors: Vec<String> = validator
        .iter_errors(value)
        .map(|e| format!("{} {e}", e.instance_path()))
        .collect();
    assert!(errors.is_empty(), "{component} does not describe the body: {errors:#?}");
}

/// The document lists `status` among the operation's responses.
fn documented(method: &str, path: &str, status: u16) {
    let doc: Value = serde_json::from_str(contextosd::app::OPENAPI).unwrap();
    let responses = &doc["paths"][path][method]["responses"];
    assert!(
        responses.get(status.to_string()).is_some(),
        "{method} {path} returned undocumented {status}"
    );
}

#[tokio::test]
async fn bodies_match_the_api_description() {
    let w = world(&ALL_CONTROLS).await;
    let http = executor_client(1);
    let body = run_body("run_shapes", 1200);
    conforms("AdmissionRequest", &body);
    let admitted = http
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(admitted.status(), 201);
    let admitted: Value = admitted.json().await.unwrap();
    conforms("Admission", &admitted);
    let http = executor_client(admitted["executor_generation"].as_u64().unwrap());

    let status: Value = http
        .get(format!("{}/v1/runs/run_shapes", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    conforms("RunStatus", &status);

    let call = tool_call("run_shapes", "tc_1", 120_000);
    let out: Value = http
        .post(format!("{}/v1/runs/run_shapes/tool-calls", w.base))
        .bearer_auth("acme-key")
        .json(&call)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(out["result"]["status"], "completed", "{}", out["report"]);
    conforms("ToolCallOutcome", &out);
    let audit = executor_client(0)
        .get(format!("{}/v1/audit/entries?from=1&limit=2", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap();
    assert_eq!(audit.status(), 200);
    let page: Value = audit.json().await.unwrap();
    assert_eq!(page["entries"].as_array().unwrap().len(), 2);
    conforms("AuditPage", &page);

    let decision = json!({"decision_key": "support.refund.execute", "decision_version": "1", "status": "DECIDED",
        "outcome": "refund_issued", "rationale": {"strategy": "policy_and_evidence"},
        "tool_calls": [{"tool_call_id": "tc_1", "operation_id": out["report"]["operation_id"]}]});
    conforms("DecisionReport", &decision);
    let recorded = http
        .post(format!("{}/v1/runs/run_shapes/decisions", w.base))
        .bearer_auth("acme-key")
        .json(&decision)
        .send()
        .await
        .unwrap();
    documented("post", "/v1/runs/{run_id}/decisions", recorded.status().as_u16());
    conforms("RecordedDecision", &recorded.json().await.unwrap());
    let evidence = http
        .get(format!("{}/v1/runs/run_shapes/evidence", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap();
    documented("get", "/v1/runs/{run_id}/evidence", evidence.status().as_u16());
    conforms("EvidenceBundle", &evidence.json().await.unwrap());
    let verified = http
        .get(format!("{}/v1/audit/verify", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap();
    documented("get", "/v1/audit/verify", verified.status().as_u16());
    conforms("AuditVerification", &verified.json().await.unwrap());

    let case: Value = http
        .get(format!("{}/v1/runs/run_shapes/replay-case", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    conforms("ReplayCase", &case);

    let missing = http
        .get(format!("{}/v1/runs/run_absent", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 404);
    conforms("Error", &missing.json().await.unwrap());

    let taken: Value = http
        .post(format!("{}/v1/runs/run_shapes/takeover", w.base))
        .bearer_auth("acme-key")
        .json(&json!({"expected_generation": status["executor_generation"]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    conforms("Ownership", &taken);
}

#[tokio::test]
async fn independent_evaluators_score_decisions() {
    let w = world(&ALL_CONTROLS).await;
    let admitted: Value = reqwest::Client::new()
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_scored", 1200))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let http = executor_client(admitted["executor_generation"].as_u64().unwrap());
    let out: Value = http
        .post(format!("{}/v1/runs/run_scored/tool-calls", w.base))
        .bearer_auth("acme-key")
        .json(&tool_call("run_scored", "tc_1", 120_000))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(out["result"]["status"], "completed");
    let recorded: Value = http.post(format!("{}/v1/runs/run_scored/decisions", w.base)).bearer_auth("acme-key")
        .json(&json!({"decision_key": "support.refund.execute", "decision_version": "1", "status": "DECIDED",
            "outcome": "refund_issued", "tool_calls": [{"tool_call_id": "tc_1", "operation_id": out["report"]["operation_id"]}]}))
        .send().await.unwrap().json().await.unwrap();
    let record_id = recorded["record"]["record_id"].as_str().unwrap();
    let url = format!("{}/v1/runs/run_scored/decisions/{record_id}/scores", w.base);
    let score = json!({"evaluator_ref": "evaluator.refund_quality@3", "policy": 1.0, "utility": 0.8, "safety": 1.0});
    let post = |key: &'static str, body: Value| {
        let url = url.clone();
        async move {
            reqwest::Client::new()
                .post(url)
                .bearer_auth(key)
                .json(&body)
                .send()
                .await
                .unwrap()
        }
    };

    // The executor's key cannot score. (A principal holding `evaluate` on one key and
    // `admit`/`dispatch` on another is refused at startup; the gateway also refuses the
    // principal that admitted the run or recorded the decision, whatever its token.)
    assert_eq!(post("acme-key", score.clone()).await.status(), 403);
    // The agent id is named by the admitter, so it cannot be used to lock out a real
    // evaluator: an evaluator whose principal matches it still scores.
    assert_eq!(post("agent-judge-key", score.clone()).await.status(), 201);
    // Scores are bounded and the evaluator must be named.
    assert_eq!(
        post(
            "judge-key",
            json!({"evaluator_ref": "e@1", "policy": 1.5, "utility": 0.8, "safety": 1.0})
        )
        .await
        .status(),
        422
    );
    assert_eq!(
        post(
            "judge-key",
            json!({"evaluator_ref": " ", "policy": 1.0, "utility": 0.8, "safety": 1.0})
        )
        .await
        .status(),
        422
    );
    let unknown = reqwest::Client::new()
        .post(format!("{}/v1/runs/run_scored/decisions/decision_nope/scores", w.base))
        .bearer_auth("judge-key")
        .json(&score)
        .send()
        .await
        .unwrap();
    assert_eq!(unknown.status(), 404);

    let scored = post("judge-key", score.clone()).await;
    assert_eq!(scored.status(), 201);
    let scored: Value = scored.json().await.unwrap();
    conforms("RunScore", &scored);
    assert_eq!(scored["score"]["evaluator"], "svc_quality_judge");
    assert_eq!(scored["score"]["run_id"], "run_scored");
    assert_eq!(scored["score"]["record_id"], record_id);
    assert_eq!(
        scored["score"]["trace_id"],
        run_body("run_scored", 1200)["run_context"]["trace_id"]
    );
    // Cost is measured by the runtime from the signed decision, not reported.
    assert_eq!(
        scored["score"]["scorecard"]["cost"],
        recorded["record"]["budget_usage"]["cost_usd_cents"]
    );
    // Latency is measured from admission to the decision, as is the decision's wall clock.
    assert!(scored["score"]["scorecard"]["latency"].is_u64(), "{scored}");
    assert_eq!(
        scored["score"]["scorecard"]["latency"],
        recorded["record"]["budget_usage"]["wall_clock_ms"]
    );
    // One score per evaluator per decision.
    assert_eq!(post("judge-key", score).await.status(), 409);

    let evidence: Value = reqwest::Client::new()
        .get(format!("{}/v1/runs/run_scored/evidence", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    conforms("EvidenceBundle", &evidence);
    let scores = &evidence["decisions"][0]["scores"];
    let evaluators: Vec<&str> = scores
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["score"]["evaluator"].as_str().unwrap())
        .collect();
    assert_eq!(evaluators, ["agt_support", "svc_quality_judge"]);

    // A run id cannot hold `/`, so run and record ids cannot alias another run's keys.
    let mut aliasing = run_body("run_scored/decision_x", 1200);
    aliasing["contract"]["contract_id"] = json!("contract_aliasing");
    let refused = reqwest::Client::new()
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&aliasing)
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 422);
    assert_eq!(
        refused.json::<Value>().await.unwrap()["error"]["detail"],
        json!(["run_id_invalid:/"])
    );
    // And only decisions the gateway issued for this run can be scored.
    let forged = reqwest::Client::new()
        .post(format!(
            "{}/v1/runs/run_scored/decisions/x%2F{record_id}/scores",
            w.base
        ))
        .bearer_auth("judge-key")
        .json(&json!({"evaluator_ref": "e@1", "policy": 1.0, "utility": 1.0, "safety": 1.0}))
        .send()
        .await
        .unwrap();
    assert_eq!(forged.status(), 404);
    let verified: Value = reqwest::Client::new()
        .get(format!("{}/v1/audit/verify", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(verified["verified"], true, "the score is signed into the chain");
}

#[tokio::test]
async fn operators_revoke_and_restore_targets() {
    let w = world(&ALL_CONTROLS).await;
    let plain = reqwest::Client::new();
    let change = |path: &'static str, key: &'static str, kind: &'static str, target: &'static str| {
        let url = format!("{}/v1/revocations{path}", w.base);
        let plain = plain.clone();
        async move {
            plain
                .post(url)
                .bearer_auth(key)
                .json(&json!({"kind": kind, "target": target, "reason": "incident 4711"}))
                .send()
                .await
                .unwrap()
        }
    };
    // Only operators hold the kill switch.
    assert_eq!(
        change("", "acme-key", "capability", "adp_payments.issue_refund")
            .await
            .status(),
        403
    );
    assert_eq!(change("", "ops-key", "everything", "x").await.status(), 422);

    let admitted: Value = plain
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_killed", 1200))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let http = executor_client(admitted["executor_generation"].as_u64().unwrap());
    let calls_before = w.provider_calls.load(Ordering::SeqCst);

    // Revoke the capability: the effect stops before it is claimed or sent.
    assert_eq!(
        change("", "ops-key", "capability", "adp_payments.issue_refund")
            .await
            .status(),
        200
    );
    let blocked: Value = http
        .post(format!("{}/v1/runs/run_killed/tool-calls", w.base))
        .bearer_auth("acme-key")
        .json(&tool_call("run_killed", "tc_1", 120_000))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(blocked["result"]["status"], "blocked", "{blocked}");
    assert_eq!(blocked["report"]["reason_codes"], json!(["revoked_capability"]));
    assert_eq!(
        w.provider_calls.load(Ordering::SeqCst),
        calls_before,
        "nothing reached the provider"
    );
    let listed: Value = plain
        .get(format!("{}/v1/revocations", w.base))
        .bearer_auth("ops-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(listed["revoked"][0]["by"], "svc_oncall");

    // Restored, the same operation proceeds.
    assert_eq!(
        change("/restore", "ops-key", "capability", "adp_payments.issue_refund")
            .await
            .status(),
        200
    );
    let done: Value = http
        .post(format!("{}/v1/runs/run_killed/tool-calls", w.base))
        .bearer_auth("acme-key")
        .json(&tool_call("run_killed", "tc_1", 120_000))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(done["result"]["status"], "completed", "{done}");

    // A revoked agent cannot start new runs.
    assert_eq!(change("", "ops-key", "agent", "agt_support").await.status(), 200);
    let refused = plain
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_after_kill", 1200))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 403);
    assert_eq!(
        refused.json::<Value>().await.unwrap()["error"]["detail"],
        json!(["revoked_agent"])
    );

    let verified: Value = plain
        .get(format!("{}/v1/audit/verify", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(verified["verified"], true);
}

#[tokio::test]
async fn finished_runs_can_be_erased() {
    let w = world(&ALL_CONTROLS).await;
    let plain = reqwest::Client::new();
    let admitted: Value = plain
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_erase", 1200))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let http = executor_client(admitted["executor_generation"].as_u64().unwrap());
    let out: Value = http
        .post(format!("{}/v1/runs/run_erase/tool-calls", w.base))
        .bearer_auth("acme-key")
        .json(&tool_call("run_erase", "tc_1", 120_000))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(out["result"]["status"], "completed");
    let erase = |key: &'static str| {
        let url = format!("{}/v1/runs/run_erase/erase", w.base);
        let plain = plain.clone();
        async move {
            plain
                .post(url)
                .bearer_auth(key)
                .json(&json!({"reason": "subject request 88"}))
                .send()
                .await
                .unwrap()
        }
    };

    // A live run still decides against its context.
    assert_eq!(erase("ops-key").await.status(), 409);
    let done = http
        .post(format!("{}/v1/runs/run_erase/complete", w.base))
        .bearer_auth("acme-key")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(done.status(), 200, "{}", done.text().await.unwrap());
    // Only operators erase.
    assert_eq!(erase("acme-key").await.status(), 403);

    let erased: Value = erase("ops-key").await.json().await.unwrap();
    let documents: Vec<&str> = erased["erased"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["document"].as_str().unwrap())
        .collect();
    assert_eq!(documents, ["replay_case", "compiled_context"]);
    assert!(
        erased["erased"][0]["content_digest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    let case = plain
        .get(format!("{}/v1/runs/run_erase/replay-case", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap();
    assert_eq!(case.status(), 410);
    // Idempotent: nothing left to erase.
    let again: Value = erase("ops-key").await.json().await.unwrap();
    assert_eq!(again["erased"], json!([]));

    let verified: Value = plain
        .get(format!("{}/v1/audit/verify", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(verified["verified"], true);
}

#[tokio::test]
async fn retention_erases_finished_runs_and_waits_for_live_ones() {
    use contextosd::retention::{Swept, sweep_once};
    let w = world(&ALL_CONTROLS).await;
    let plain = reqwest::Client::new();
    let mut generations = HashMap::new();
    for run in ["run_old_done", "run_old_live"] {
        let admitted: Value = plain
            .post(format!("{}/v1/runs", w.base))
            .bearer_auth("acme-key")
            .json(&run_body(run, 1200))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        generations.insert(run, admitted["executor_generation"].as_u64().unwrap());
    }
    let finished = executor_client(generations["run_old_done"])
        .post(format!("{}/v1/runs/run_old_done/complete", w.base))
        .bearer_auth("acme-key")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(finished.status(), 200);

    let (store, gateway) = (w.state.store.as_ref(), w.state.gateway.as_ref().unwrap());
    let future = u64::MAX / 2;
    // Nothing is old enough yet.
    let (swept, _) = sweep_once(store, gateway, 30, 1, None, 100).await.unwrap();
    assert_eq!(swept, Swept::default());
    // Past the cutoff: the finished run is erased, the live one waits.
    let (swept, next) = sweep_once(store, gateway, 30, future, None, 100).await.unwrap();
    assert_eq!(
        swept,
        Swept {
            erased: 1,
            still_running: 1
        }
    );
    assert!(next.is_none(), "one page covered everything");
    let case = plain
        .get(format!("{}/v1/runs/run_old_done/replay-case", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap();
    assert_eq!(case.status(), 410);
    let live = plain
        .get(format!("{}/v1/runs/run_old_live/replay-case", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap();
    assert_eq!(live.status(), 200);
    // Erased runs are not scanned again; the live one is revisited.
    let (swept, _) = sweep_once(store, gateway, 30, future, None, 100).await.unwrap();
    assert_eq!(
        swept,
        Swept {
            erased: 0,
            still_running: 1
        }
    );

    let audit: Value = plain
        .get(format!("{}/v1/audit/entries?from=1&limit=500", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let erasure = audit["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["kind"] == "run_data_erased" || e["event"] == "run_data_erased");
    let erasure = erasure.unwrap_or_else(|| panic!("no erasure entry: {audit}"));
    assert!(erasure.to_string().contains("contextos.retention"), "{erasure}");
}

#[tokio::test]
async fn rollouts_route_runs_and_shadow_the_rest() {
    let w = world(&ALL_CONTROLS).await;
    let plain = reqwest::Client::new();
    let (baseline, candidate) = ("ctxpack.support@5.2.0", "ctxpack.support@5.3.0");
    let set_gated = |key: &'static str, percent: u8, shadow: bool, gate: Value| {
        let (plain, url) = (plain.clone(), format!("{}/v1/rollouts", w.base));
        async move {
            let mut body = json!({"baseline": baseline, "candidate": candidate, "percent": percent, "shadow": shadow, "reason": "v5.3 canary"});
            body.as_object_mut().unwrap().extend(gate.as_object().unwrap().clone());
            plain.post(url).bearer_auth(key).json(&body).send().await.unwrap()
        }
    };
    let set = |key: &'static str, percent: u8, shadow: bool| set_gated(key, percent, shadow, json!({}));
    let admit = |run: String| {
        let (plain, url) = (plain.clone(), format!("{}/v1/runs", w.base));
        async move {
            let response = plain
                .post(url)
                .bearer_auth("acme-key")
                .json(&run_body(&run, 4200))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 201, "{run}");
            response.json::<Value>().await.unwrap()
        }
    };
    assert_eq!(
        set("acme-key", 0, true).await.status(),
        403,
        "only operators steer traffic"
    );

    // Shadow: the run stays on the baseline; the candidate's difference is audited.
    assert_eq!(set("ops-key", 0, true).await.status(), 200);
    let shadowed = admit("run_shadow".into()).await;
    assert_eq!(shadowed["pack_ref"], baseline);
    assert_eq!(shadowed["rollout"]["on_candidate"], false);
    let mut diff = None;
    for _ in 0..50 {
        let audit: Value = plain
            .get(format!("{}/v1/audit/entries?from=1&limit=500", w.base))
            .bearer_auth("acme-key")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        diff = audit["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e.to_string().contains("shadow_diff"))
            .cloned();
        if diff.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let diff = diff.expect("the shadow diff is audited").to_string();
    assert!(
        diff.contains("policy require_approval -> allow") && diff.contains("run_shadow"),
        "{diff}"
    );

    // Live traffic only through the release gate on replayed cases: none named is
    // refused; the candidate's dropped approval fails it until acknowledged per case.
    assert_eq!(set("ops-key", 100, false).await.status(), 422);
    let failed = set_gated("ops-key", 100, false, json!({"gate_runs": ["run_shadow"]})).await;
    assert_eq!(failed.status(), 409);
    let failed: Value = failed.json().await.unwrap();
    assert_eq!(failed["error"]["code"], "release_gate_failed", "{failed}");
    let missing = set_gated("ops-key", 100, false, json!({"gate_runs": ["run_nope"]})).await;
    assert_eq!(missing.status(), 409);
    let acknowledged = json!({"gate_runs": ["run_shadow"], "acknowledge": {"policy_loosening": ["run_shadow"]}});

    // 100%: new runs are admitted on, and pinned to, the candidate.
    let live = set_gated("ops-key", 100, false, acknowledged.clone()).await;
    assert_eq!(live.status(), 200);
    let canary = admit("run_canary".into()).await;
    assert_eq!(canary["pack_ref"], candidate);
    assert_eq!(canary["rollout"]["on_candidate"], true);
    let evidence: Value = plain
        .get(format!("{}/v1/runs/run_canary/evidence", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(evidence["admission"]["pack_ref"], candidate);

    // 50%: routing follows the published, sticky bucket of each run.
    assert_eq!(
        set_gated("ops-key", 50, false, acknowledged.clone()).await.status(),
        200
    );
    let mut on_candidate = 0;
    for i in 0..8 {
        let run = format!("run_split_{i}");
        let expected = if contextosd::rollout::bucket(TENANT, &run) < 50 {
            candidate
        } else {
            baseline
        };
        on_candidate += usize::from(expected == candidate);
        assert_eq!(admit(run).await["pack_ref"], expected);
    }
    assert!((1..8).contains(&on_candidate), "the split exercised both packs");

    // Cleared: everything returns to the baseline.
    let cleared = plain
        .post(format!("{}/v1/rollouts/clear", w.base))
        .bearer_auth("ops-key")
        .json(&json!({"baseline": baseline, "reason": "rolled back"}))
        .send()
        .await
        .unwrap();
    assert_eq!(cleared.status(), 200);
    assert_eq!(admit("run_after_clear".into()).await["pack_ref"], baseline);

    // What was waived is in the audit chain, case by case.
    let audit: Value = plain
        .get(format!("{}/v1/audit/entries?from=1&limit=1000", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let set = audit["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["kind"] == "rollout_set" && e["payload"]["percent"] == 100)
        .unwrap()
        .clone();
    assert_eq!(set["payload"]["gate"]["waived"][0]["case"], "run_shadow", "{set}");

    // Once a correction is open on that run, its case cannot be waived.
    let filed = plain
        .post(format!("{}/v1/runs/run_shadow/feedback", w.base))
        .bearer_auth("judge-key")
        .json(
            &json!({"kind": "correction", "target_surface": "policy", "summary": "High-value refunds need approval."}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(filed.status(), 201);
    let refused = set_gated("ops-key", 100, false, acknowledged.clone()).await;
    assert_eq!(refused.status(), 422);
    assert_eq!(
        refused.json::<Value>().await.unwrap()["error"]["code"],
        "feedback_not_waivable"
    );
}

fn child_of(parent: &Value, parent_id: &str, child_id: &str, pack: &str) -> Value {
    let mut child = run_body(child_id, 1200);
    child["pack_ref"] = json!(pack);
    let agent = child["run_context"]["agent"]["agent_id"].clone();
    child["delegation"] = json!({
        "envelope_version": "contextos.agent_delegation.v1", "delegation_id": format!("dlg_{child_id}"), "parent_run_id": parent_id,
        "child_run_id": child_id, "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736", "tenant_id": TENANT,
        "issuer": agent, "subject": agent, "principal_chain": [{"kind": "agent", "id": agent}],
        "scope": {"allowed_intents": [child["request"]["input"]["intent"]], "allowed_capabilities": ["adp_payments.issue_refund"],
            "data_classification_ceiling": "CONFIDENTIAL", "output_schema_ref": "schema://x"},
        "sub_budget": {"total_tokens": 10, "bucket_tokens": {}, "max_tool_calls": 1, "max_replan_attempts": 0, "wall_clock_ms": 1000, "max_cost_cents": 1},
        "effect_policy": "read_only", "issued_at": "2020-01-01T00:00:00Z", "expires_at": "2098-01-01T00:00:00Z",
        "parent_claim_hash": parent["compiled_context_hash"],
    });
    child
}

#[tokio::test]
async fn revoked_runs_cannot_delegate_and_principals_can_be_revoked() {
    let w = world(&ALL_CONTROLS).await;
    let plain = reqwest::Client::new();
    let ops = |path: &'static str, kind: &'static str, target: &'static str| {
        let (plain, url) = (plain.clone(), format!("{}/v1/revocations{path}", w.base));
        async move {
            let r = plain
                .post(url)
                .bearer_auth("ops-key")
                .json(&json!({"kind": kind, "target": target, "reason": "incident"}))
                .send()
                .await
                .unwrap();
            assert_eq!(r.status(), 200);
        }
    };
    let parent: Value = plain
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_lane_parent", 1200))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let owner = executor_client(parent["executor_generation"].as_u64().unwrap());

    // A lane runs on its parent's pack.
    let moved = owner
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&child_of(
            &parent,
            "run_lane_parent",
            "run_lane_a",
            "ctxpack.support@5.3.0",
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(moved.status(), 422);
    assert_eq!(
        moved.json::<Value>().await.unwrap()["error"]["code"],
        "delegation_pack_mismatch"
    );

    // A run on a revoked pack cannot keep working through a child.
    ops("", "pack", "ctxpack.support@5.2.0").await;
    let child = owner
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&child_of(
            &parent,
            "run_lane_parent",
            "run_lane_b",
            "ctxpack.support@5.2.0",
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(child.status(), 403);
    assert_eq!(
        child.json::<Value>().await.unwrap()["error"]["detail"],
        json!(["revoked_pack"])
    );
    ops("/restore", "pack", "ctxpack.support@5.2.0").await;

    // Revoking the authenticated principal stops it, whatever agent id it declares:
    // its new runs and the runs it already admitted.
    ops("", "principal", "svc_orchestrator").await;
    let mut renamed = run_body("run_renamed_agent", 1200);
    renamed["run_context"]["agent"]["agent_id"] = json!("agt_other_name");
    let refused = plain
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&renamed)
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 403);
    assert_eq!(
        refused.json::<Value>().await.unwrap()["error"]["detail"],
        json!(["revoked_principal"])
    );
    let blocked: Value = owner
        .post(format!("{}/v1/runs/run_lane_parent/tool-calls", w.base))
        .bearer_auth("acme-key")
        .json(&tool_call("run_lane_parent", "tc_1", 120_000))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(blocked["report"]["reason_codes"], json!(["revoked_principal"]));
}

#[tokio::test]
async fn erasure_covers_pending_input_requests() {
    let w = world(&ALL_CONTROLS).await;
    let plain = reqwest::Client::new();
    let admitted: Value = plain
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_asked", 1200))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let http = executor_client(admitted["executor_generation"].as_u64().unwrap());
    let asked: Value = http
        .post(format!("{}/v1/runs/run_asked/tool-calls", w.base))
        .bearer_auth("acme-key")
        .json(&tool_call("run_asked", "tc_1", 555))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(asked["result"]["status"], "paused", "{asked}");
    let cancelled = plain
        .post(format!("{}/v1/runs/run_asked/cancel", w.base))
        .bearer_auth("acme-key")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(cancelled.status(), 200, "{}", cancelled.text().await.unwrap());
    let status: Value = http
        .get(format!("{}/v1/runs/run_asked", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let erased = plain
        .post(format!("{}/v1/runs/run_asked/erase", w.base))
        .bearer_auth("ops-key")
        .json(&json!({"reason": "subject request"}))
        .send()
        .await
        .unwrap();
    assert_eq!(erased.status(), 200, "run status {status}");
    let erased: Value = erased.json().await.unwrap();
    let documents: Vec<&str> = erased["erased"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["document"].as_str().unwrap())
        .collect();
    assert_eq!(
        documents,
        ["replay_case", "compiled_context", "pending_input"],
        "{erased}"
    );
}

/// Load across replicas sharing one store and audit log. Opt-in:
/// `cargo test --release -p contextosd --test dispatch load -- --ignored --nocapture`
/// (`CONTEXTOS_LOAD_REPLICAS`, `CONTEXTOS_LOAD_AGENTS`, `CONTEXTOS_LOAD_RUNS`).
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "load test; run explicitly"]
#[allow(clippy::cast_precision_loss)]
async fn load_across_replicas() {
    let env = |name: &str, default: usize| std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default);
    let (replicas, agents, runs) = (
        env("CONTEXTOS_LOAD_REPLICAS", 3),
        env("CONTEXTOS_LOAD_AGENTS", 64),
        env("CONTEXTOS_LOAD_RUNS", 20),
    );
    // PostgreSQL when CONTEXTOS_TEST_DATABASE_URL is set (replicas share the database),
    // otherwise one shared in-memory store.
    let (bases, provider_calls, backend) = if let Ok(url) = std::env::var("CONTEXTOS_TEST_DATABASE_URL") {
        {
            let (config, provider_calls) = world_setup(&ALL_CONTROLS).await;
            let store = Arc::new(
                contextos_store::postgres::PostgresStore::connect(&url, 64)
                    .await
                    .unwrap(),
            );
            store.migrate().await.unwrap();
            let mut bases = Vec::new();
            for _ in 0..replicas.max(1) {
                let state = replica_state(&config, store.clone(), (*store).clone());
                bases.push(serve(router(state, Duration::from_secs(10))).await);
            }
            (bases, provider_calls, "postgres")
        }
    } else {
        let w = world_n(&ALL_CONTROLS, replicas).await;
        (w.bases, w.provider_calls, "memory")
    };
    // Run ids unique to this execution (a database keeps earlier runs).
    let prefix = format!(
        "{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );
    let http = reqwest::Client::builder()
        .pool_max_idle_per_host(agents)
        .build()
        .unwrap();
    let started = std::time::Instant::now();
    let mut tasks = Vec::new();
    for agent in 0..agents {
        let (http, bases, prefix) = (http.clone(), bases.clone(), prefix.clone());
        tasks.push(tokio::spawn(async move {
            let mut latencies = Vec::with_capacity(runs * 2);
            let mut admissions = Vec::with_capacity(runs);
            for i in 0..runs {
                let run = format!("run_load_{prefix}_{agent}_{i}");
                // Admit on one replica, act on another: ownership and audit are shared.
                let (admit_at, act_at) = (&bases[(agent + i) % bases.len()], &bases[(agent + i + 1) % bases.len()]);
                let t = std::time::Instant::now();
                let admitted: Value = http
                    .post(format!("{admit_at}/v1/runs"))
                    .bearer_auth("acme-key")
                    .json(&run_body(&run, 1200))
                    .send()
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
                latencies.push(t.elapsed());
                admissions.push(t.elapsed());
                let generation = admitted["executor_generation"].as_u64().unwrap();
                let t = std::time::Instant::now();
                let out: Value = http
                    .post(format!("{act_at}/v1/runs/{run}/tool-calls"))
                    .bearer_auth("acme-key")
                    .header("contextos-executor-generation", generation.to_string())
                    .json(&tool_call(&run, "tc_1", 120_000))
                    .send()
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
                latencies.push(t.elapsed());
                assert_eq!(out["result"]["status"], "completed", "{out}");
            }
            (latencies, admissions)
        }));
    }
    let (mut latencies, mut admissions): (Vec<Duration>, Vec<Duration>) = (Vec::new(), Vec::new());
    for task in tasks {
        let (all, admitted) = task.await.unwrap();
        latencies.extend(all);
        admissions.extend(admitted);
    }
    admissions.sort();
    println!(
        "admission latency p50 {:.2?} p99 {:.2?}",
        admissions[admissions.len() / 2],
        admissions[admissions.len() * 99 / 100]
    );
    let elapsed = started.elapsed();
    latencies.sort();
    let pct = |per_mille: usize| latencies[(latencies.len() - 1) * per_mille / 1000];
    let effects = agents * runs;
    println!(
        "{backend}: {replicas} replicas, {agents} agents x {runs} runs: {effects} admitted runs + governed effects in {elapsed:.2?} \
         ({:.0} effects/s, {:.0} requests/s); request latency p50 {:.2?} p99 {:.2?} max {:.2?}",
        effects as f64 / elapsed.as_secs_f64(),
        (effects * 2) as f64 / elapsed.as_secs_f64(),
        pct(500),
        pct(990),
        latencies.last().unwrap()
    );
    // Every replica appended to one tenant chain. It must verify: here, this execution's
    // segment, continuing the entry before it (a shared database also holds entries other
    // suites signed with other keys), exactly as `ctx audit-verify --continues` does.
    let mut entries: Vec<contextos_audit::AuditEntry> = Vec::new();
    let mut cursor = Some(1_u64);
    while let Some(from) = cursor {
        let page: Value = http
            .get(format!("{}/v1/audit/entries?from={from}&limit=1000", bases[0]))
            .bearer_auth("acme-key")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        entries.extend(serde_json::from_value::<Vec<contextos_audit::AuditEntry>>(page["entries"].clone()).unwrap());
        cursor = page["next"].as_u64();
    }
    let marker = format!("run_load_{prefix}_");
    let start = entries
        .iter()
        .position(|e| e.payload.to_string().contains(&marker))
        .expect("this run's entries");
    let mut ring = contextos_audit::KeyRing::new();
    let signer = AuditSigner::from_seed("audit-test", [5; 32]);
    ring.insert(signer.kid(), signer.verifying_key());
    let anchor = start.checked_sub(1).map(|i| &entries[i]);
    contextos_audit::verify_chain(&entries[start..], anchor, &ring)
        .expect("every replica's entries verify as one chain");
    assert_eq!(
        provider_calls.load(Ordering::SeqCst),
        effects,
        "exactly one provider call per effect"
    );
}

#[tokio::test]
async fn model_calls_and_replans_spend_the_run_budget() {
    let w = world(&ALL_CONTROLS).await;
    let plain = reqwest::Client::new();
    let admitted: Value = plain
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_budgeted", 1200))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let http = executor_client(admitted["executor_generation"].as_u64().unwrap());
    let reserve = |body: Value| {
        let (http, url) = (http.clone(), format!("{}/v1/runs/run_budgeted/usage/reserve", w.base));
        async move { http.post(url).bearer_auth("acme-key").json(&body).send().await.unwrap() }
    };
    let settle = |key: &'static str, body: Value| {
        let (http, url) = (http.clone(), format!("{}/v1/runs/run_budgeted/usage/settle", w.base));
        async move { http.post(url).bearer_auth(key).json(&body).send().await.unwrap() }
    };
    let id = |r: Value| r["reservation_id"].as_str().unwrap().to_owned();

    // Self-reported usage is not evidence: the whole reservation is charged.
    let first = id(reserve(json!({"kind": "model_call", "tokens": 4000, "cost_cents": 1}))
        .await
        .json()
        .await
        .unwrap());
    let charged: Value = settle("acme-key", json!({"reservation_id": first, "tokens": 10}))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(
        (charged["charged"]["tokens"].as_u64(), charged["verified"].as_bool()),
        (Some(4000), Some(false)),
        "{charged}"
    );
    // Usage measured by a metering principal settles to what was measured.
    let second = id(reserve(json!({"kind": "model_call", "tokens": 4000, "cost_cents": 1}))
        .await
        .json()
        .await
        .unwrap());
    let metered: Value = settle("meter-key", json!({"reservation_id": second, "tokens": 500}))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(
        (metered["charged"]["tokens"].as_u64(), metered["verified"].as_bool()),
        (Some(500), Some(true)),
        "{metered}"
    );
    // 4,500 of 10,000 tokens are spent: 6,000 more does not fit.
    let over = reserve(json!({"kind": "model_call", "tokens": 6000})).await;
    assert_eq!(over.status(), 409);
    assert_eq!(over.json::<Value>().await.unwrap()["error"]["code"], "budget_exhausted");
    // Two replans are allowed; the third is refused.
    for _ in 0..2 {
        assert_eq!(reserve(json!({"kind": "replan"})).await.status(), 201);
    }
    assert_eq!(reserve(json!({"kind": "replan"})).await.status(), 409);
    // Only usage reservations settle here.
    assert_eq!(
        settle("meter-key", json!({"reservation_id": "reservation:attempt_1"}))
            .await
            .status(),
        404
    );

    let evidence: Value = plain
        .get(format!("{}/v1/runs/run_budgeted/evidence", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ledger = &evidence["budget_ledger"];
    assert_eq!(ledger["used"]["tokens"], 4500, "{ledger}");
    assert_eq!(
        ledger["reserved"]["replans"], 2,
        "open replan reservations stay reserved"
    );
}

#[tokio::test]
async fn many_model_calls_keep_the_budget_ledger_compact() {
    let w = world(&ALL_CONTROLS).await;
    let plain = reqwest::Client::new();
    let admitted: Value = plain
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_chatty", 1200))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let http = executor_client(admitted["executor_generation"].as_u64().unwrap());
    for _ in 0..20 {
        let reserved: Value = http
            .post(format!("{}/v1/runs/run_chatty/usage/reserve", w.base))
            .bearer_auth("acme-key")
            .json(&json!({"kind": "model_call", "tokens": 100}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let settled = plain
            .post(format!("{}/v1/runs/run_chatty/usage/settle", w.base))
            .bearer_auth("meter-key")
            .json(&json!({"reservation_id": reserved["reservation_id"], "tokens": 90}))
            .send()
            .await
            .unwrap();
        assert_eq!(settled.status(), 200);
    }
    let evidence: Value = plain
        .get(format!("{}/v1/runs/run_chatty/evidence", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        !evidence["budget_archives"].as_array().unwrap().is_empty(),
        "40 mutations were compacted"
    );
    assert!(evidence["budget_ledger"]["mutations"].as_array().unwrap().len() < 32);
    let opening = evidence["budget_ledger"]["opening_usage"]["tokens"].as_u64().unwrap();
    let used = evidence["budget_ledger"]["used"]["tokens"].as_u64().unwrap();
    assert_eq!(used, 1800, "20 metered calls of 90 tokens (opening {opening})");
}

#[tokio::test]
async fn repeated_identical_calls_trip_the_loop_guard() {
    // Identical effects under new keys are what the repeated-effect guard refuses; turn
    // it off to reach the loop guard (as for a capability marked `repeatable`).
    let w = world_with(&ALL_CONTROLS, 1, |c| c.guards.refuse_repeated_effects = false).await;
    let plain = reqwest::Client::new();
    let admitted: Value = plain
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_looping", 1200))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let http = executor_client(admitted["executor_generation"].as_u64().unwrap());
    let call = |key: &str, amount: u64| {
        let mut body = tool_call("run_looping", &format!("tc_{key}"), amount);
        body["idempotency_key"] = json!(key);
        let (http, url) = (http.clone(), format!("{}/v1/runs/run_looping/tool-calls", w.base));
        async move {
            http.post(url)
                .bearer_auth("acme-key")
                .json(&body)
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap()
        }
    };
    let before = w.provider_calls.load(Ordering::SeqCst);
    for i in 0..5 {
        assert_eq!(
            call(&format!("loop_{i}"), 120_000).await["result"]["status"],
            "completed"
        );
    }
    // The sixth identical call under a new key is refused before it is claimed or sent.
    let tripped = call("loop_5", 120_000).await;
    assert_eq!(tripped["result"]["status"], "blocked", "{tripped}");
    assert_eq!(tripped["report"]["reason_codes"], json!(["loop_detected"]));
    assert!(
        tripped["report"]["obligations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|o| o == "change_approach")
    );
    assert_eq!(w.provider_calls.load(Ordering::SeqCst), before + 5);
    // A retry of an existing operation is not a new call, and other arguments are not a loop.
    // (Re-sending a completed operation is answered from its ledger as before.)
    let retry = call("loop_4", 120_000).await;
    assert_eq!(retry["report"]["reason_codes"], json!(["retry_unsafe"]), "{retry}");
    let other = call("loop_other", 120_001).await;
    assert_eq!(other["result"]["status"], "completed", "{other}");
}

#[tokio::test]
async fn an_effect_is_not_applied_twice_under_a_new_key() {
    let w = world(&ALL_CONTROLS).await;
    let plain = reqwest::Client::new();
    let admitted: Value = plain
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_rekeyed", 1200))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let http = executor_client(admitted["executor_generation"].as_u64().unwrap());
    let call = |key: &str, amount: u64| {
        let mut body = tool_call("run_rekeyed", &format!("tc_{key}"), amount);
        body["idempotency_key"] = json!(key);
        let (http, url) = (http.clone(), format!("{}/v1/runs/run_rekeyed/tool-calls", w.base));
        async move {
            http.post(url)
                .bearer_auth("acme-key")
                .json(&body)
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap()
        }
    };
    let before = w.provider_calls.load(Ordering::SeqCst);
    assert_eq!(call("refund:a", 120_000).await["result"]["status"], "completed");
    // A host retrying under a fresh key (or the same effect sent through another route)
    // is refused before anything is claimed or sent, naming the operation that applied it.
    let again = call("refund:b", 120_000).await;
    assert_eq!(again["result"]["status"], "blocked", "{again}");
    assert_eq!(again["report"]["reason_codes"], json!(["effect_repeated"]));
    assert!(
        again["report"]["obligations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|o| o == "reconcile_existing_operation")
    );
    assert!(
        again["result"]["error"].as_str().unwrap().contains("refund:a"),
        "{again}"
    );
    assert_eq!(w.provider_calls.load(Ordering::SeqCst), before + 1);
    // The original operation's retry is answered from its ledger; a different effect runs.
    assert_eq!(
        call("refund:a", 120_000).await["report"]["reason_codes"],
        json!(["retry_unsafe"])
    );
    assert_eq!(call("refund:c", 119_999).await["result"]["status"], "completed");
    assert_eq!(w.provider_calls.load(Ordering::SeqCst), before + 2);
    let page: Value = plain
        .get(format!("{}/v1/audit/entries?from=1&limit=500", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        page["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["kind"] == "repeated_effect_refusal"),
        "the refusal is audited"
    );
}

#[tokio::test]
async fn checkpoints_survive_failover_and_fence_the_old_executor() {
    let w = world(&ALL_CONTROLS).await;
    let plain = reqwest::Client::new();
    let admitted: Value = plain
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_ckpt", 1200))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let first = executor_client(admitted["executor_generation"].as_u64().unwrap());
    let save = |http: reqwest::Client, expected: u64, state: Value| {
        let url = format!("{}/v1/runs/run_ckpt/checkpoint", w.base);
        async move {
            http.post(url)
                .bearer_auth("acme-key")
                .json(&json!({"expected_revision": expected, "state": state}))
                .send()
                .await
                .unwrap()
        }
    };
    let plan = json!({"plan": ["lookup", "refund", "decide"], "step": 1, "verdict": "accept"});
    let saved = save(first.clone(), 0, plan.clone()).await;
    assert_eq!(saved.status(), 201);
    assert_eq!(saved.json::<Value>().await.unwrap()["revision"], 1);
    // Optimistic: a writer that read an older revision does not overwrite.
    let stale = save(first.clone(), 0, json!({"step": 99})).await;
    assert_eq!(stale.status(), 409);
    assert_eq!(
        stale.json::<Value>().await.unwrap()["error"]["detail"]["current_revision"],
        1
    );
    let plan2 = json!({"plan": ["lookup", "refund", "decide"], "step": 2, "verdict": "accept"});
    assert_eq!(save(first.clone(), 1, plan2.clone()).await.status(), 201);
    // Oversized state is refused.
    assert_eq!(
        save(first.clone(), 2, json!({"blob": "x".repeat(300 * 1024)}))
            .await
            .status(),
        413
    );

    // A new executor takes over and resumes from the latest checkpoint; the old one is fenced.
    let status: Value = plain
        .get(format!("{}/v1/runs/run_ckpt", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let taken: Value = plain
        .post(format!("{}/v1/runs/run_ckpt/takeover", w.base))
        .bearer_auth("acme-key")
        .json(&json!({"expected_generation": status["executor_generation"]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let second = executor_client(taken["executor_generation"].as_u64().unwrap());
    assert_eq!(
        save(first.clone(), 2, json!({"step": 3})).await.status(),
        409,
        "the old executor is stale"
    );
    // Only the run's current executor reads its working state.
    let snooped = first
        .get(format!("{}/v1/runs/run_ckpt/checkpoint", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap();
    assert_eq!(snooped.status(), 409);
    let latest: Value = second
        .get(format!("{}/v1/runs/run_ckpt/checkpoint", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!((latest["revision"].as_u64(), &latest["state"]), (Some(2), &plan2));
    assert_eq!(latest["executor_generation"], admitted["executor_generation"]);

    // Checkpoints are audited by digest and erased with the run.
    assert_eq!(
        second
            .post(format!("{}/v1/runs/run_ckpt/complete", w.base))
            .bearer_auth("acme-key")
            .json(&json!({}))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let erased: Value = plain
        .post(format!("{}/v1/runs/run_ckpt/erase", w.base))
        .bearer_auth("ops-key")
        .json(&json!({"reason": "subject request"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        erased["erased"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["document"] == "checkpoint"),
        "{erased}"
    );
    // A finished run's working state is no longer readable by anyone.
    let closed = second
        .get(format!("{}/v1/runs/run_ckpt/checkpoint", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap();
    assert_eq!(closed.status(), 409);
}

#[tokio::test]
async fn model_call_budgets_cannot_be_dodged() {
    let w = world(&ALL_CONTROLS).await;
    let plain = reqwest::Client::new();
    let admitted: Value = plain
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_dodge", 1200))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let http = executor_client(admitted["executor_generation"].as_u64().unwrap());
    let reserve = |tokens: u64| {
        let (http, url) = (http.clone(), format!("{}/v1/runs/run_dodge/usage/reserve", w.base));
        async move {
            let r: Value = http
                .post(url)
                .bearer_auth("acme-key")
                .json(&json!({"kind": "model_call", "tokens": tokens}))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            r["reservation_id"].as_str().unwrap().to_owned()
        }
    };
    let settle = |key: &'static str, body: Value| {
        let (http, url) = (http.clone(), format!("{}/v1/runs/run_dodge/usage/settle", w.base));
        async move {
            http.post(url)
                .bearer_auth(key)
                .json(&body)
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap()
        }
    };
    // A zero reservation still covers the floor, so a self-settled call is never free.
    let free = reserve(0).await;
    assert_eq!(
        settle("acme-key", json!({"reservation_id": free})).await["charged"]["tokens"],
        1000
    );
    // A meter that measured more than was reserved charges the overage too.
    let under = reserve(1000).await;
    let metered = settle("meter-key", json!({"reservation_id": under, "tokens": 3000})).await;
    assert_eq!(metered["charged"]["tokens"], 3000, "{metered}");
    // Beyond the run's remaining capacity (10,000 - 4,000 used), the charge is capped and audited.
    let last = reserve(1000).await;
    let capped = settle("meter-key", json!({"reservation_id": last, "tokens": 50_000})).await;
    assert_eq!(capped["charged"]["tokens"], 6000, "{capped}");
    let audit: Value = plain
        .get(format!("{}/v1/audit/entries?from=1&limit=500", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let overages = audit["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e.to_string().contains("usage_overage"))
        .count();
    assert_eq!(overages, 2);
    // Absurd values are refused rather than wrapped.
    let huge = http
        .post(format!("{}/v1/runs/run_dodge/usage/reserve", w.base))
        .bearer_auth("acme-key")
        .json(&json!({"kind": "model_call", "cost_cents": u64::MAX}))
        .send()
        .await
        .unwrap();
    assert_eq!(huge.status(), 422);
}

#[tokio::test]
async fn exported_audit_verifies_against_published_keys() {
    use base64::Engine as _;
    let w = world(&ALL_CONTROLS).await;
    let plain = reqwest::Client::new();
    let admitted: Value = plain
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_audited", 1200))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let out: Value = executor_client(admitted["executor_generation"].as_u64().unwrap())
        .post(format!("{}/v1/runs/run_audited/tool-calls", w.base))
        .bearer_auth("acme-key")
        .json(&tool_call("run_audited", "tc_1", 120_000))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(out["result"]["status"], "completed");
    // The keys are public; the entries are the tenant's.
    let keys: Value = plain
        .get(format!("{}/v1/audit/keys", w.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let page: Value = plain
        .get(format!("{}/v1/audit/entries?from=1&limit=1000", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let entries: Vec<contextos_audit::AuditEntry> = serde_json::from_value(page["entries"].clone()).unwrap();
    let mut ring = contextos_audit::KeyRing::new();
    for key in keys["keys"].as_array().unwrap() {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(key["public_key"].as_str().unwrap())
            .unwrap();
        ring.insert(
            key["kid"].as_str().unwrap(),
            ed25519_dalek::VerifyingKey::from_bytes(&bytes.try_into().unwrap()).unwrap(),
        );
    }
    assert!(entries.len() >= 3);
    contextos_audit::verify_chain(&entries, None, &ring).expect("the exported chain verifies without the server");
}

#[tokio::test]
async fn operator_corrections_become_replay_obligations() {
    let w = world(&ALL_CONTROLS).await;
    let plain = reqwest::Client::new();
    let admitted: Value = plain
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_corrected", 1200))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let http = executor_client(admitted["executor_generation"].as_u64().unwrap());
    let out: Value = http
        .post(format!("{}/v1/runs/run_corrected/tool-calls", w.base))
        .bearer_auth("acme-key")
        .json(&tool_call("run_corrected", "tc_1", 120_000))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let recorded: Value = http.post(format!("{}/v1/runs/run_corrected/decisions", w.base)).bearer_auth("acme-key")
        .json(&json!({"decision_key": "support.refund.execute", "decision_version": "1", "status": "DECIDED", "outcome": "refund_issued",
            "tool_calls": [{"tool_call_id": "tc_1", "operation_id": out["report"]["operation_id"]}]}))
        .send().await.unwrap().json().await.unwrap();
    let record_id = recorded["record"]["record_id"].as_str().unwrap();
    let file = |key: &'static str, body: Value| {
        let (plain, url) = (plain.clone(), format!("{}/v1/runs/run_corrected/feedback", w.base));
        async move { plain.post(url).bearer_auth(key).json(&body).send().await.unwrap() }
    };
    let correction = json!({"kind": "correction", "target_surface": "policy", "decision_record_id": record_id,
        "summary": "Refund issued without checking the order was delivered damaged.", "expected_outcome": "escalate"});

    // Only an independent reviewer files feedback; references must exist.
    assert_eq!(file("acme-key", correction.clone()).await.status(), 403);
    let mut unknown = correction.clone();
    unknown["decision_record_id"] = json!("decision_nope");
    assert_eq!(file("judge-key", unknown).await.status(), 404);
    let mut invalid = correction.clone();
    invalid["kind"] = json!("praise");
    assert_eq!(file("judge-key", invalid).await.status(), 422);

    let filed = file("judge-key", correction).await;
    assert_eq!(filed.status(), 201);
    let filed: Value = filed.json().await.unwrap();
    assert_eq!(filed["status"], "open");
    assert_eq!(filed["replay_obligation"]["case"], "run_corrected");
    let id = filed["feedback_id"].as_str().unwrap().to_owned();

    // Open feedback is the replay corpus a candidate change must pass.
    let open: Value = plain
        .get(format!("{}/v1/feedback", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(open["open"], 1);
    assert_eq!(open["feedback"][0]["feedback_id"], id.as_str());

    // Closed only by an operator, only with evidence, and only once.
    let close = |body: Value| {
        let (plain, url) = (plain.clone(), format!("{}/v1/feedback/{id}/close", w.base));
        async move { plain.post(url).bearer_auth("ops-key").json(&body).send().await.unwrap() }
    };
    assert_eq!(
        close(json!({"status": "fixed", "evidence_ref": {}})).await.status(),
        422
    );
    let evidence = json!({"artifact_type": "gate_report", "artifact_id": "gate_2026_10_21", "sha256": format!("sha256:{}", "a".repeat(64))});
    let closed = close(json!({"status": "fixed", "evidence_ref": evidence.clone()})).await;
    assert_eq!(closed.status(), 200);
    assert_eq!(closed.json::<Value>().await.unwrap()["closed_by"], "svc_oncall");
    assert_eq!(
        close(json!({"status": "fixed", "evidence_ref": evidence}))
            .await
            .status(),
        409
    );
    let open: Value = plain
        .get(format!("{}/v1/feedback", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(open["open"], 0);
    let verified: Value = plain
        .get(format!("{}/v1/audit/verify", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(verified["verified"], true);
}

#[tokio::test]
async fn feedback_index_heals_and_closures_stay_bounded() {
    let w = world(&ALL_CONTROLS).await;
    let plain = reqwest::Client::new();
    plain
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_fb", 1200))
        .send()
        .await
        .unwrap();
    let body = json!({"kind": "override", "target_surface": "tool", "summary": "Wrong tool chosen."});
    let file = || {
        let (plain, url, body) = (
            plain.clone(),
            format!("{}/v1/runs/run_fb/feedback", w.base),
            body.clone(),
        );
        async move {
            plain
                .post(url)
                .bearer_auth("judge-key")
                .json(&body)
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap()
        }
    };
    // Concurrent identical filings never share an id.
    let (a, b) = tokio::join!(file(), file());
    assert_ne!(a["feedback_id"], b["feedback_id"]);
    let tenant = a["tenant_id"].as_str().unwrap().to_owned();
    let (a, b) = (
        a["feedback_id"].as_str().unwrap().to_owned(),
        b["feedback_id"].as_str().unwrap().to_owned(),
    );

    // An id left in the index without a record (an interrupted filing) is dropped,
    // not counted or listed forever.
    contextosd::feedback::index_open(w.state.store.as_ref(), &tenant, "fb_phantom")
        .await
        .unwrap();
    let open = || {
        let (plain, url) = (plain.clone(), format!("{}/v1/feedback", w.base));
        async move {
            plain
                .get(url)
                .bearer_auth("acme-key")
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap()
        }
    };
    assert_eq!(open().await["open"], 2);
    assert_eq!(
        contextosd::feedback::open_ids(w.state.store.as_ref(), &tenant)
            .await
            .unwrap()
            .len(),
        2
    );

    let close = |id: String, body: Value| {
        let (plain, url) = (plain.clone(), format!("{}/v1/feedback/{id}/close", w.base));
        async move { plain.post(url).bearer_auth("ops-key").json(&body).send().await.unwrap() }
    };
    let digest = format!("sha256:{}", "b".repeat(64));
    // Evidence is exactly three bounded fields: nothing else reaches the audit chain.
    let extra = json!({"status": "invalid", "evidence_ref": {"artifact_type": "note", "artifact_id": "x", "sha256": digest, "notes": "pii"}});
    assert_eq!(close(a.clone(), extra).await.status(), 422);
    let long = json!({"status": "invalid", "evidence_ref": {"artifact_type": "note", "artifact_id": "x".repeat(300), "sha256": digest}});
    assert_eq!(close(a.clone(), long).await.status(), 422);

    // A record closed while its index entry survived (an interrupted close) is not
    // listed as open, and a retried close clears the entry.
    let good =
        json!({"status": "invalid", "evidence_ref": {"artifact_type": "note", "artifact_id": "x", "sha256": digest}});
    assert_eq!(close(a.clone(), good.clone()).await.status(), 200);
    contextosd::feedback::index_open(w.state.store.as_ref(), &tenant, &a)
        .await
        .unwrap();
    let listed = open().await;
    assert_eq!(listed["open"], 1);
    assert_eq!(listed["feedback"][0]["feedback_id"], b.as_str());
    contextosd::feedback::index_open(w.state.store.as_ref(), &tenant, &a)
        .await
        .unwrap();
    assert_eq!(close(a.clone(), good.clone()).await.status(), 409);
    assert_eq!(
        contextosd::feedback::open_ids(w.state.store.as_ref(), &tenant)
            .await
            .unwrap(),
        vec![b.clone()]
    );

    // Racing closers: exactly one wins and exactly one closure is audited.
    let (x, y) = tokio::join!(close(b.clone(), good.clone()), close(b.clone(), good));
    let mut codes = [x.status().as_u16(), y.status().as_u16()];
    codes.sort_unstable();
    assert_eq!(codes, [200, 409]);
    let page: Value = plain
        .get(format!("{}/v1/audit/entries?from=1&limit=1000", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let entries = page["entries"].as_array().unwrap();
    let closures = entries
        .iter()
        .filter(|e| e["kind"] == "feedback_closed" && e["payload"]["feedback_id"] == b.as_str())
        .count();
    assert_eq!(closures, 1);
}

#[tokio::test]
async fn erasing_a_run_redacts_its_feedback_text() {
    let w = world(&ALL_CONTROLS).await;
    let plain = reqwest::Client::new();
    plain
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_forget", 1200))
        .send()
        .await
        .unwrap();
    let file = || {
        let (plain, url) = (plain.clone(), format!("{}/v1/runs/run_forget/feedback", w.base));
        async move {
            plain.post(url).bearer_auth("judge-key")
                .json(&json!({"kind": "correction", "target_surface": "memory", "summary": "Customer Jane Doe at 12 Elm St was misidentified.",
                    "expected_outcome": "ask for the order id"}))
                .send().await.unwrap().json::<Value>().await.unwrap()
        }
    };
    let before = file().await;
    let id = before["feedback_id"].as_str().unwrap().to_owned();
    let cancelled = plain
        .post(format!("{}/v1/runs/run_forget/cancel", w.base))
        .bearer_auth("acme-key")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(cancelled.status(), 200);
    let erased: Value = plain
        .post(format!("{}/v1/runs/run_forget/erase", w.base))
        .bearer_auth("ops-key")
        .json(&json!({"reason": "subject request"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        erased["erased"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["document"] == "feedback_text"),
        "{erased}"
    );

    // The record stays open with its obligation (an operator still closes it); its text is gone.
    let open: Value = plain
        .get(format!("{}/v1/feedback", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let record = open["feedback"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["feedback_id"] == id.as_str())
        .unwrap()
        .clone();
    assert_eq!(record["summary"], Value::Null);
    assert_eq!(record["expected_outcome"], Value::Null);
    assert_eq!(record["content_erased"]["erased_by"], "svc_oncall");
    assert_eq!(record["replay_obligation"]["case"], "run_forget");

    // Feedback filed after the erasure is redacted at once.
    let late = file().await;
    assert_eq!(late["summary"], Value::Null, "{late}");
    assert!(late["content_erased"].is_object());
    assert!(!open.to_string().contains("Jane Doe"));
    let verified: Value = plain
        .get(format!("{}/v1/audit/verify", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(verified["verified"], true);
}

#[tokio::test]
async fn decisions_record_the_pinned_model_and_evaluators() {
    let (mut config, _) = world_setup(&ALL_CONTROLS).await;
    config.guards.required_release_refs = Some(vec!["model_profile".into(), "evaluator_suite".into()]);
    let state = replica_state(&config, Arc::new(MemoryStore::new()), Arc::new(MemoryLog::new()));
    let base = serve(router(state, Duration::from_secs(10))).await;
    let plain = reqwest::Client::new();
    let admit = |body: Value| {
        let (plain, url) = (plain.clone(), format!("{base}/v1/runs"));
        async move {
            plain
                .post(url)
                .bearer_auth("acme-key")
                .json(&body)
                .send()
                .await
                .unwrap()
        }
    };

    // A contract that does not pin the model is refused, naming what is missing.
    let unpinned = admit(run_body("run_unpinned", 1200)).await;
    assert_eq!(unpinned.status(), 422);
    let unpinned: Value = unpinned.json().await.unwrap();
    assert_eq!(unpinned["error"]["code"], "release_ref_missing");

    let mut body = run_body("run_pinned", 1200);
    let refs = body["contract"]["release_refs"].as_array_mut().unwrap();
    refs.push(artifact("model_profile", "claude-opus-5-5.support"));
    refs.push(artifact("evaluator_suite", "support.refund.judges"));
    refs.push(artifact("model_profile", "claude-sonnet-5-5.support"));
    let admitted = admit(body).await;
    assert_eq!(admitted.status(), 201, "{}", admitted.text().await.unwrap());
    let admitted: Value = admitted.json().await.unwrap();
    let recorded: Value = executor_client(admitted["executor_generation"].as_u64().unwrap())
        .post(format!("{base}/v1/runs/run_pinned/decisions"))
        .bearer_auth("acme-key")
        .json(
            &json!({"decision_key": "support.refund.execute", "decision_version": "1", "status": "DECIDED",
            "outcome": "refund_denied", "tool_calls": [], "model_profile": "claude-opus-5-5.support@1"}),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let lineage = &recorded["record"]["lineage"];
    assert_eq!(lineage["model_profile"], "claude-opus-5-5.support@1", "{recorded}");
    assert_eq!(lineage["evaluator_suite"], "support.refund.judges@1");

    // A decision made by the pinned fallback names it; an unpinned model is refused.
    let decide = |model: &'static str, key: &'static str| {
        let (url, client) = (
            format!("{base}/v1/runs/run_pinned/decisions"),
            executor_client(admitted["executor_generation"].as_u64().unwrap()),
        );
        async move {
            client
                .post(url)
                .bearer_auth("acme-key")
                .json(
                    &json!({"decision_key": key, "decision_version": "1", "status": "DECIDED",
                    "outcome": "refund_denied", "tool_calls": [], "model_profile": model}),
                )
                .send()
                .await
                .unwrap()
        }
    };
    let fallback: Value = decide("claude-sonnet-5-5.support@1", "support.refund.execute")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(
        fallback["record"]["lineage"]["model_profile"], "claude-sonnet-5-5.support@1",
        "{fallback}"
    );
    let unpinned = decide("some-other-model@1", "support.refund.execute").await;
    assert_eq!(unpinned.status(), 422);
    assert_eq!(
        unpinned.json::<Value>().await.unwrap()["error"]["code"],
        "model_not_pinned"
    );
}

#[tokio::test]
async fn recalled_memory_must_be_promoted_current_and_unchanged() {
    use contextos_store::{DocKey, DocKind, DocumentStore as _};
    let (mut config, _) = world_setup(&ALL_CONTROLS).await;
    // A memory-governance service is configured; verification reads only stored state.
    config.providers.as_mut().unwrap().memory =
        Some(serde_json::from_value(json!({"url": "http://127.0.0.1:9"})).unwrap());
    let store = Arc::new(MemoryStore::new());
    let state = replica_state(&config, store.clone(), Arc::new(MemoryLog::new()));
    let base = serve(router(state, Duration::from_secs(10))).await;
    let content = "customer:cus_77 prefers_communication_channel=email";
    let promoted = |operation: &str, until: &str, text: &str| {
        json!({"record": {"operation": operation, "retention_expires_at": until, "readers": ["usr_771"],
            "memory_ref": {"artifact_id": format!("key:{text}"), "sha256": contextos_contract::canonical::sha256_text(text)}}})
    };
    for (id, record) in [
        ("mem_ok", promoted("promote", "2099-01-01T00:00:00Z", content)),
        ("mem_deleted", promoted("delete", "2099-01-01T00:00:00Z", content)),
        ("mem_expired", promoted("promote", "2000-01-01T00:00:00Z", content)),
        ("mem_proposed", promoted("propose", "2099-01-01T00:00:00Z", content)),
        ("mem_unreadable", {
            let mut r = promoted("promote", "2099-01-01T00:00:00Z", content);
            r["record"]["readers"] = json!(["usr_someone_else"]);
            r
        }),
    ] {
        store
            .create(&DocKey::new(TENANT, DocKind::MemoryRecord, id), &record)
            .await
            .unwrap();
    }
    let plain = reqwest::Client::new();
    let admit = |run: &'static str, memory_ref: &'static str, text: &'static str| {
        let (plain, url) = (plain.clone(), format!("{base}/v1/runs"));
        async move {
            let mut body = run_body(run, 1200);
            body["deps"]["promoted_memory"] =
                json!([{"memory_ref": memory_ref, "content": text, "freshness": "current", "source_refs": []}]);
            plain
                .post(url)
                .bearer_auth("acme-key")
                .json(&body)
                .send()
                .await
                .unwrap()
        }
    };
    let ok = admit("run_mem_ok", "mem_ok", content).await;
    assert_eq!(ok.status(), 201, "{}", ok.text().await.unwrap());
    for (run, memory_ref, text) in [
        (
            "run_mem_changed",
            "mem_ok",
            "customer:cus_77 prefers_communication_channel=sms",
        ),
        ("run_mem_deleted", "mem_deleted", content),
        ("run_mem_expired", "mem_expired", content),
        ("run_mem_proposed", "mem_proposed", content),
        ("run_mem_unknown", "mem_nope", content),
        ("run_mem_unreadable", "mem_unreadable", content),
    ] {
        let refused = admit(run, memory_ref, text).await;
        assert_eq!(refused.status(), 422, "{run}");
        assert_eq!(
            refused.json::<Value>().await.unwrap()["error"]["code"],
            "memory_unverified",
            "{run}"
        );
    }

    // Two promoted values for one memory key cannot be recalled together.
    let other = "customer:cus_77 prefers_communication_channel=sms";
    for (id, text) in [("mem_pref_email", content), ("mem_pref_sms", other)] {
        let mut record = promoted("promote", "2099-01-01T00:00:00Z", text);
        record["record"]["memory_ref"]["artifact_id"] = json!("pref:cus_77:channel");
        store
            .create(&DocKey::new(TENANT, DocKind::MemoryRecord, id), &record)
            .await
            .unwrap();
    }
    let mut body = run_body("run_mem_conflict", 1200);
    body["deps"]["promoted_memory"] = json!([
        {"memory_ref": "mem_pref_email", "content": content, "freshness": "current", "source_refs": []},
        {"memory_ref": "mem_pref_sms", "content": other, "freshness": "current", "source_refs": []}]);
    let conflict = plain
        .post(format!("{base}/v1/runs"))
        .bearer_auth("acme-key")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(conflict.status(), 422);
    assert_eq!(
        conflict.json::<Value>().await.unwrap()["error"]["code"],
        "memory_conflict"
    );

    // A memory whose key a newer promotion holds is superseded and cannot be recalled.
    store
        .create(
            &DocKey::new(
                TENANT,
                DocKind::MemoryKey,
                contextos_contract::canonical::sha256_text(&format!("\u{0}\u{0}key:{content}")),
            ),
            &json!({"record_id": "mem_newer"}),
        )
        .await
        .unwrap();
    let superseded = admit("run_mem_superseded", "mem_ok", content).await;
    assert_eq!(superseded.status(), 422);
    assert_eq!(
        superseded.json::<Value>().await.unwrap()["error"]["code"],
        "memory_superseded"
    );
}

#[tokio::test]
async fn startup_can_require_schemas_on_effectful_tools() {
    let (mut config, _) = world_setup(&ALL_CONTROLS).await;
    assert!(dispatch_setup_from_config(&config).is_ok(), "off by default");
    config.guards.require_tool_schemas = true;
    let refused = dispatch_setup_from_config(&config).err().unwrap();
    assert!(refused.contains("needs input_schema and output_schema"), "{refused}");

    // With an output schema next to the input schema, it starts.
    let path = &config.capabilities[0];
    let mut manifest: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    manifest["output_schema"] = json!({"type": "object", "properties": {"refund_id": {"type": "string"}}});
    std::fs::write(path, manifest.to_string()).unwrap();
    assert!(dispatch_setup_from_config(&config).is_ok());
}

#[tokio::test]
async fn production_requires_pins_and_a_stated_role() {
    let (mut config, _) = world_setup(&ALL_CONTROLS).await;
    // Development defaults: neither required.
    assert!(config.required_release_refs().is_empty());
    assert!(!config.require_user_role());
    // Production defaults: both, unless opted out explicitly.
    config.server.mode = contextosd::config::Mode::Production;
    assert_eq!(config.required_release_refs(), ["model_profile", "evaluator_suite"]);
    assert!(config.require_user_role());
    let floors = config
        .completion_score_floors()
        .expect("judged before completion in production");
    assert_eq!((floors.policy_floor, floors.safety_floor), (1.0, 0.9));
    config.guards.required_release_refs = Some(vec![]);
    config.guards.require_user_role = Some(false);
    config.guards.completion_requires_scores = Some(contextosd::config::CompletionScores::Enabled(false));
    assert!(config.required_release_refs().is_empty() && !config.require_user_role());
    assert!(config.completion_score_floors().is_none(), "opted out explicitly");

    // `true`, `false` and explicit floors all parse.
    let parsed = |guards: &str| {
        Config::parse(&format!(
            "[server]\nlisten = \"127.0.0.1:0\"\n[store]\nkind = \"memory\"\n[audit]\nsigning_seed_env = \"X\"\nkey_id = \"k\"\n\
             [support]\nimplementation_id = \"x\"\nimplementation_version = \"1\"\nprofiles = []\ncontrols = []\n[guards]\n{guards}\n"
        ))
        .unwrap()
        .completion_score_floors()
        .map(|f| (f.policy_floor, f.safety_floor))
    };
    assert_eq!(parsed("completion_requires_scores = true"), Some((1.0, 0.9)));
    assert_eq!(parsed("completion_requires_scores = false"), None);
    assert_eq!(
        parsed("completion_requires_scores = { policy_floor = 0.8, safety_floor = 0.7 }"),
        Some((0.8, 0.7))
    );

    // Admission refuses a run whose user claims state no role.
    let (mut config, _) = world_setup(&ALL_CONTROLS).await;
    config.guards.require_user_role = Some(true);
    let state = replica_state(&config, Arc::new(MemoryStore::new()), Arc::new(MemoryLog::new()));
    let base = serve(router(state, Duration::from_secs(10))).await;
    let plain = reqwest::Client::new();
    let mut roleless = run_body("run_roleless", 1200);
    roleless["run_context"]["user"].as_object_mut().unwrap().remove("role");
    let refused = plain
        .post(format!("{base}/v1/runs"))
        .bearer_auth("acme-key")
        .json(&roleless)
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 422);
    assert_eq!(
        refused.json::<Value>().await.unwrap()["error"]["code"],
        "user_role_missing"
    );
    let mut invisible = run_body("run_invisible_role", 1200);
    invisible["run_context"]["user"]["role"] = json!("\u{200B}");
    let refused = plain
        .post(format!("{base}/v1/runs"))
        .bearer_auth("acme-key")
        .json(&invisible)
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 422, "an invisible character is not a role");
    let admitted = plain
        .post(format!("{base}/v1/runs"))
        .bearer_auth("acme-key")
        .json(&run_body("run_with_role", 1200))
        .send()
        .await
        .unwrap();
    assert_eq!(admitted.status(), 201, "{}", admitted.text().await.unwrap());
}
