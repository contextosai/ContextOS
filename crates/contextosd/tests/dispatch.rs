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
        "#,
        manifest = manifest_path.display(),
        key = hash_api_key("acme-key"),
        evaluator = hash_api_key("judge-key"),
        agent_judge = hash_api_key("agent-judge-key"),
        operator = hash_api_key("ops-key")
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

    let tools = rpc(2, "tools/list", json!({})).await;
    let tools = tools["result"]["tools"].as_array().unwrap();
    let refund = tools
        .iter()
        .find(|t| t["name"] == "adp_payments.issue_refund")
        .expect("surfaced capability listed");
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
    let done = call(3, args.clone()).await;
    assert_eq!(done["result"]["isError"], false, "{done}");
    assert_eq!(done["result"]["structuredContent"]["refund_id"], "rf_77");

    // A host retrying what it believes failed cannot refund twice.
    let retried = call(4, args.clone()).await;
    assert_eq!(retried["result"]["isError"], true);
    assert_eq!(
        retried["result"]["structuredContent"]["reason_codes"],
        json!(["retry_unsafe"])
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
