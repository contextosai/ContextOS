//! Delegated child runs: admission, narrowing, closure and revocation.

use std::sync::atomic::Ordering;

use contextos_store::DocumentStore;
use serde_json::{Value, json};

use crate::harness::*;

#[tokio::test]
async fn delegated_children_are_admitted_narrowed_and_closed() {
    let w = world(&ALL_CONTROLS).await;
    let http = executor_client(2);
    let mut parent_body = run_body("run_parent", 1200);
    parent_body["task_authorization"] = task_authorization("run_parent", "deny", 120_000);
    let parent: Value = http
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&parent_body)
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
    // The child keeps what the parent's principal authorized.
    let stored = w
        .state
        .store
        .get(&contextos_store::DocKey::new(
            TENANT,
            contextos_store::DocKind::RunAdmission,
            "run_child",
        ))
        .await
        .unwrap()
        .unwrap()
        .body;
    assert_eq!(
        stored["task_authorizations"][0]["scopes"][0]["root_run_id"],
        "run_parent"
    );
    // Its effects count toward the limits of the run that issued the authorization.
    assert_eq!(stored["task_authorization_origins"], json!(["run_parent"]));
    // The child may restrict itself; what it inherited stays.
    let mut own = task_authorization("run_parent", "deny", 1_000);
    own["issued_by"]["principal_id"] = json!("usr_other");
    let (status, amended) = amend(&w, "acme-key", "run_child", 0, &own).await;
    assert_eq!(
        (status, amended["change"].as_str()),
        (200, Some("narrowed")),
        "{amended}"
    );
    assert_eq!(
        amended["policy_refs"].as_array().unwrap().len(),
        stored_policy_refs(&w, "run_parent").await + 1
    );

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
