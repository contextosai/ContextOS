//! Decision records: verification, signing, size limits, pinned models and audit export.

use std::sync::Arc;
use std::time::Duration;

use contextos_store::{MemoryLog, MemoryStore};
use contextosd::router;
use serde_json::{Value, json};

use crate::harness::*;

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
