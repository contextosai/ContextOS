//! The world every dispatch test runs in: fake fact services and an MCP tool server
//! over HTTP, `contextosd` replicas configured against them, and request builders.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::Router;
use axum::routing::post;
use contextos_audit::AuditSigner;
use contextos_contract::canonical::sha256_canonical;
use contextos_store::{DocumentStore, MemoryLog, MemoryStore};
use contextosd::auth::hash_api_key;
use contextosd::runtime::dispatch_setup_from_config;
use contextosd::{Config, build_state, load_pack, router};
use serde_json::{Value, json};

pub(crate) const TENANT: &str = "tenant_acme_prod";

pub(crate) async fn serve(router: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    format!("http://{addr}")
}

pub(crate) fn principal(id: &str) -> Value {
    json!({"principal_id": id, "principal_type": "workload", "trust_domain": "contextos.test", "tenant_id": TENANT})
}

pub(crate) fn artifact(kind: &str, id: &str) -> Value {
    json!({"artifact_type": kind, "artifact_id": id, "version": "1",
        "sha256": sha256_canonical(&json!({"artifact_type": kind, "artifact_id": id})).unwrap()})
}

/// Identity broker: grants exactly the requested binding scope to the run's agent.
pub(crate) fn authority_facts(request: &Value) -> Value {
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

pub(crate) fn constraint_facts(request: &Value) -> Value {
    let observations: Vec<Value> = request["required_controls"].as_array().unwrap().iter().map(|control| json!({
        "control": control, "action_digest": request["action_digest"], "policy_refs": [], "verdict": "allow",
        "verification_status": "verified", "verification_ref": artifact("control", control["control_id"].as_str().unwrap()),
        "observer": principal("control_plane"), "observed_at": "2026-01-01T00:00:00Z", "valid_until": "2099-01-01T00:00:00Z"})).collect();
    json!({"observations": observations})
}

pub(crate) struct World {
    pub(crate) base: String,
    /// Every replica's address (they share one store and one audit log).
    pub(crate) bases: Vec<String>,
    pub(crate) state: Arc<contextosd::app::AppState<MemoryStore, Arc<MemoryLog>>>,
    pub(crate) provider_calls: Arc<AtomicUsize>,
}

pub(crate) async fn world(controls: &[&str]) -> World {
    world_n(controls, 1).await
}

/// `replicas` servers sharing one in-memory store and one audit log, as separate
/// processes sharing a database would.
pub(crate) async fn world_n(controls: &[&str], replicas: usize) -> World {
    world_with(controls, replicas, |_| {}).await
}

/// As [`world_n`], with the configuration adjusted first.
pub(crate) async fn world_with(controls: &[&str], replicas: usize, adjust: impl FnOnce(&mut Config)) -> World {
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
pub(crate) fn replica_state<S, L>(config: &Config, store: Arc<S>, log: L) -> Arc<contextosd::app::AppState<S, L>>
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
pub(crate) fn world_packs() -> HashMap<String, contextosd::app::LoadedPack> {
    let vectors = compiler_vectors();
    let mut packs = HashMap::new();
    let (pack_ref, loaded) = load_pack(&vectors["cases"][0]["pack"].to_string()).unwrap();
    packs.insert(pack_ref, loaded);
    let mut candidate = vectors["cases"][0]["pack"].clone();
    candidate["pack_meta"]["pack_version"] = json!("5.3.0");
    candidate["policy_layer"]["policy_bundles"][0]["policy_dsl"]["rules"][1]["then"] = json!({"allow": true});
    let (pack_ref, loaded) = load_pack(&candidate.to_string()).unwrap();
    packs.insert(pack_ref, loaded);
    // A version that also surfaces the refund's compensation.
    let mut reversible = vectors["cases"][0]["pack"].clone();
    reversible["pack_meta"]["pack_version"] = json!("5.4.0");
    let tooling = &mut reversible["tooling_layer"];
    for adapter in tooling["adapter_registry"].as_array_mut().unwrap() {
        if adapter["adapter_id"] == "adp_payments" {
            adapter["capabilities"]
                .as_array_mut()
                .unwrap()
                .push(json!("reverse_refund"));
            adapter["capability_risks"]["reverse_refund"] = json!({"effect": "external_state", "authority": "service",
                "reversibility": "irreversible", "interaction": "api", "data_scope": "CONFIDENTIAL"});
        }
    }
    tooling["permissions"].as_array_mut().unwrap().push(
        json!({"permission_id": "p_reverse", "adapter_id": "adp_payments", "capability": "reverse_refund", "allow": true}),
    );
    let (pack_ref, loaded) = load_pack(&reversible.to_string()).unwrap();
    packs.insert(pack_ref, loaded);
    packs
}

/// The fake fact services and MCP tool server, and the configuration pointing at them.
/// Numbers each setup's capability manifest file.
pub(crate) static SETUPS: AtomicUsize = AtomicUsize::new(0);

pub(crate) async fn world_setup(controls: &[&str]) -> (Config, Arc<AtomicUsize>) {
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
        key_sha256 = "{app}"
        tenant_id = "{TENANT}"
        principal_id = "svc_support_app"
        scopes = ["authorize"]
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
        meter = hash_api_key("meter-key"),
        app = hash_api_key("app-key")
    ))
    .unwrap();
    (config, provider_calls)
}

pub(crate) const ALL_CONTROLS: [&str; 9] = [
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
pub(crate) fn compiler_vectors() -> &'static Value {
    static VECTORS: std::sync::LazyLock<Value> = std::sync::LazyLock::new(|| {
        let path = format!("{}/../../conformance/vectors/compiler.json", env!("CARGO_MANIFEST_DIR"));
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    });
    &VECTORS
}

pub(crate) fn run_body(run_id: &str, amount: u64) -> Value {
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

pub(crate) fn tool_call(run_id: &str, id: &str, amount: u64) -> Value {
    json!({"envelope_version": "contextos.tool_call.v1", "tool_call_id": id, "run_id": run_id,
        "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736", "capability_id": "adp_payments.issue_refund",
        "args": {"order_id": "ord_881", "customer_id": "cus_77", "amount_minor": amount},
        "principal_chain": [{"kind": "agent", "id": "agt_support"}], "approval_mode_requested": "destructive",
        "approval_mode_effective": "destructive", "approval_mode_highest": "destructive",
        "evidence_refs": ["kg:order:ord_881#snapshot_kg_2026_05_03_T0930"], "idempotency_key": format!("refund:{run_id}")})
}

/// What the user asked for: refund order ord_881 to cus_77, at most `ceiling` minor units.
pub(crate) fn task_authorization(root_run_id: &str, out_of_scope: &str, ceiling: u64) -> Value {
    json!({"issued_by": {"principal_id": "usr_771", "principal_type": "person", "trust_domain": "contextos.test", "tenant_id": TENANT},
        "out_of_scope": out_of_scope,
        "scopes": [{"root_run_id": root_run_id, "purpose_ids": ["support.refund"], "capability_ids": ["adp_payments.issue_refund"],
            "resource_ids": ["ord_881"], "destination_ids": ["cus_77"], "classification_labels": ["CONFIDENTIAL"],
            "argument_constraints": [], "amount_ceiling": {"minor_units": ceiling, "currency": "INR"}}]})
}

pub(crate) fn refund(run_id: &str, key: &str, order: &str, customer: &str, amount: u64) -> Value {
    let mut call = tool_call(run_id, key, amount);
    call["args"]["order_id"] = json!(order);
    call["args"]["customer_id"] = json!(customer);
    call["evidence_refs"] = json!([]);
    call["idempotency_key"] = json!(key);
    call
}

pub(crate) async fn admit(w: &World, body: &Value) -> reqwest::Response {
    executor_client(2)
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(body)
        .send()
        .await
        .unwrap()
}

pub(crate) async fn dispatch(w: &World, run_id: &str, call: &Value) -> Value {
    executor_client(2)
        .post(format!("{}/v1/runs/{run_id}/tool-calls", w.base))
        .bearer_auth("acme-key")
        .json(call)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// How many policy references the run's actions bind.
pub(crate) async fn stored_policy_refs(w: &World, run_id: &str) -> usize {
    let stored = w
        .state
        .store
        .get(&contextos_store::DocKey::new(
            TENANT,
            contextos_store::DocKind::RunAdmission,
            run_id,
        ))
        .await
        .unwrap()
        .unwrap()
        .body;
    let admission: contextos_gateway::RunAdmission = serde_json::from_value(stored).unwrap();
    admission.binding_policy_refs().len()
}

pub(crate) async fn amend(w: &World, key: &str, run_id: &str, expected: u64, task: &Value) -> (u16, Value) {
    let response = reqwest::Client::new()
        .put(format!("{}/v1/runs/{run_id}/task-authorization", w.base))
        .bearer_auth(key)
        .json(&json!({"expected_revision": expected, "task_authorization": task}))
        .send()
        .await
        .unwrap();
    (response.status().as_u16(), response.json().await.unwrap())
}

/// A client acting as the executor that holds `generation` (a freshly admitted run
/// starts at generation 2: created, then started).
pub(crate) fn executor_client(generation: u64) -> reqwest::Client {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert("contextos-executor-generation", generation.to_string().parse().unwrap());
    reqwest::Client::builder().default_headers(headers).build().unwrap()
}

/// Validates `value` against a component schema of the published OpenAPI document,
/// resolving its references into the normative ContextOS schemas.
pub(crate) fn conforms(component: &str, value: &Value) {
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

pub(crate) fn child_of(parent: &Value, parent_id: &str, child_id: &str, pack: &str) -> Value {
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
