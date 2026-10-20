//! End-to-end governed dispatch through `contextosd` with remote fact services and an
//! MCP provider, all over real HTTP.

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
    provider_calls: Arc<AtomicUsize>,
}

async fn world(controls: &[&str]) -> World {
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
    let manifest_path = dir.join(format!("issue_refund-{}.json", controls.len()));
    std::fs::write(&manifest_path, json!({
        "capability_id": "adp_payments.issue_refund", "capability_version": "3", "adapter_id": "adp_payments",
        "protocol_tool": "issue_refund", "purpose_id": "support.refund", "desired_effect": "refund_created",
        "action_risk": {"effect": "external_state", "authority": "service", "reversibility": "compensatable", "interaction": "api", "data_scope": "CONFIDENTIAL"},
        "approval_mode": "destructive", "resource_pointers": ["/order_id"], "destination_pointers": ["/customer_id"],
        "amount": {"minor_units_pointer": "/amount_minor", "currency": "INR"},
        "recovery": {"strategy": "manual_reconcile", "max_attempts": 2, "retry_delays_seconds": [0]},
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
        scopes = ["admit", "dispatch", "reconcile", "audit:read"]
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
    // run start, authorization decision, operation claim, effect observation
    assert_eq!(audit, json!({"verified": true, "entries": 4}));
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
