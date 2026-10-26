//! Governed effects: approval, long-running and accepted jobs, input requests, idempotency.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::Router;
use axum::routing::post;
use serde_json::{Value, json};

use crate::harness::*;

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
async fn accepted_http_jobs_are_reconciled_through_the_declared_completion_check() {
    // The provider accepts the refund (202) and reports the job's state on a status
    // endpoint: processing on the first lookup, succeeded afterwards.
    let calls = Arc::new(AtomicUsize::new(0));
    let lookups = Arc::new(AtomicUsize::new(0));
    let (invoked, looked_up) = (calls.clone(), lookups.clone());
    let provider = serve(
        Router::new()
            .route(
                "/issue_refund",
                post(move || {
                    let invoked = invoked.clone();
                    async move {
                        invoked.fetch_add(1, Ordering::SeqCst);
                        (axum::http::StatusCode::ACCEPTED, axum::Json(json!({"id": "job_e2e"})))
                    }
                }),
            )
            .route(
                "/refund_status/{job}",
                axum::routing::get(move |axum::extract::Path(job): axum::extract::Path<String>| {
                    let looked_up = looked_up.clone();
                    async move {
                        let state = if looked_up.fetch_add(1, Ordering::SeqCst) == 0 {
                            "processing"
                        } else {
                            "succeeded"
                        };
                        axum::Json(json!({"id": job, "state": state, "refund_id": "rf_async"}))
                    }
                }),
            ),
    )
    .await;
    let w = world_with(&ALL_CONTROLS, 1, |config| {
        let path = &config.capabilities[0];
        let mut manifest: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        manifest["recovery"] = json!({"strategy": "query", "max_attempts": 1, "retry_delays_seconds": [],
            "completion": {"status_tool": "refund_status", "state_pointer": "/state",
                "confirmed": ["succeeded"], "not_applied": ["canceled"]}});
        let async_path = path.with_extension("async.json");
        std::fs::write(&async_path, manifest.to_string()).unwrap();
        config.capabilities[0] = async_path;
        config.adapters[0].kind = contextosd::config::AdapterKind::Http;
        config.adapters[0].endpoint.clone_from(&provider);
    })
    .await;
    let http = executor_client(2);
    let admitted = http
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_async", 1200))
        .send()
        .await
        .unwrap();
    assert_eq!(admitted.status(), 201);
    let out: Value = http
        .post(format!("{}/v1/runs/run_async/tool-calls", w.base))
        .bearer_auth("acme-key")
        .json(&tool_call("run_async", "tc_1", 300))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // Accepted is not applied: the effect stays unknown until the provider says so.
    assert_eq!(out["result"]["status"], "paused", "{out}");
    let operation_id = out["report"]["operation_id"].as_str().unwrap().to_owned();
    let url = format!("{}/v1/runs/run_async/operations/{operation_id}/reconcile", w.base);
    let reconcile = || async {
        http.post(&url)
            .bearer_auth("acme-key")
            .json(&json!({"source": "provider"}))
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap()
    };
    let pending = reconcile().await;
    assert_eq!(pending["status"], "pending", "{pending}");
    let resolved = reconcile().await;
    assert_eq!(resolved["status"], "resolved", "{resolved}");
    assert_eq!(resolved["outcome"], "confirmed");
    assert_eq!(resolved["output"]["refund_id"], "rf_async");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "looking up the job never re-invokes the tool"
    );
    assert_eq!(lookups.load(Ordering::SeqCst), 2);
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
