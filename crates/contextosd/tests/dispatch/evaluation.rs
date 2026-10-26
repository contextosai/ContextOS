//! Independent evaluators, replay cases, operator corrections and the feedback index.

use serde_json::{Value, json};

use crate::harness::*;

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
