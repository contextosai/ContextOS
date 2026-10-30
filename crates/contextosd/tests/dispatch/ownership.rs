//! Runs are driven only by the principal that admitted them.

use contextosd::auth::hash_api_key;
use serde_json::{Value, json};

use crate::harness::*;

#[tokio::test]
async fn another_principal_in_the_tenant_cannot_drive_or_see_a_run() {
    let w = world_with(&ALL_CONTROLS, 1, |c| {
        c.api_keys.push(contextosd::config::ApiKey {
            key_sha256: hash_api_key("other-agent"),
            tenant_id: TENANT.into(),
            principal_id: "svc_other_agent".into(),
            scopes: vec!["admit".into(), "dispatch".into()],
        });
    })
    .await;
    let http = executor_client(1);
    let admitted = http
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_owned", 7))
        .send()
        .await
        .unwrap();
    assert_eq!(admitted.status(), 201);
    let run = format!("{}/v1/runs/run_owned", w.base);
    let attempts = [
        http.get(&run),
        http.post(format!("{run}/tool-calls"))
            .json(&tool_call("run_owned", "pending", 100)),
        http.post(format!("{run}/takeover"))
            .json(&json!({"expected_generation": 1})),
        http.post(format!("{run}/complete")),
        http.post(format!("{run}/cancel")),
        http.get(format!("{run}/checkpoint")),
        http.get(format!("{run}/compensations")),
        http.get(format!("{run}/notices")),
    ];
    for request in attempts {
        let response = request.bearer_auth("other-agent").send().await.unwrap();
        assert_eq!(response.status(), 404, "{:?}", response.url().path());
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["error"]["code"], "run_not_found");
    }
    // Nor can it delegate from the run.
    let parent = json!({"run_id": "run_owned", "executor_generation": 1});
    let child = http
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("other-agent")
        .json(&child_of(&parent, "run_owned", "run_child", "ctxpack.support@5.2.0"))
        .send()
        .await
        .unwrap();
    assert_eq!(child.status(), 404);
    // The run is untouched: its owner still drives it.
    let status: Value = http
        .get(&run)
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["status"], "running", "{status}");
}

#[tokio::test]
async fn only_an_independent_principal_asserts_that_an_effect_did_not_apply() {
    let w = world_with(&ALL_CONTROLS, 1, |c| {
        c.api_keys.push(contextosd::config::ApiKey {
            key_sha256: hash_api_key("reconciler"),
            tenant_id: TENANT.into(),
            principal_id: "svc_reconciler".into(),
            scopes: vec!["reconcile".into()],
        });
    })
    .await;
    let http = executor_client(2);
    let admitted = http
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_held", 7))
        .send()
        .await
        .unwrap();
    assert_eq!(admitted.status(), 201);
    let out: Value = http
        .post(format!("{}/v1/runs/run_held/tool-calls", w.base))
        .bearer_auth("acme-key")
        .json(&tool_call("run_held", "pending", 777))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(out["result"]["status"], "paused", "{out}");
    let operation_id = out["report"]["operation_id"].as_str().unwrap();
    let url = format!("{}/v1/runs/run_held/operations/{operation_id}/reconcile", w.base);
    let evidence = json!({"artifact_type": "provider_ledger_extract", "artifact_id": "payments-2026-10-30",
        "version": "1", "sha256": format!("sha256:{}", "a".repeat(64))});
    let assertion = |outcome: &str| json!({"source": "operator", "outcome": outcome, "evidence_ref": evidence});

    // The run's own principal cannot release its hold on its own word.
    for outcome in ["not_applied", "partial"] {
        let refused = http
            .post(&url)
            .bearer_auth("acme-key")
            .json(&assertion(outcome))
            .send()
            .await
            .unwrap();
        assert_eq!(refused.status(), 403);
        let body: Value = refused.json().await.unwrap();
        assert_eq!(body["error"]["code"], "reconcile_not_independent");
    }
    // Another principal can, without an executor generation: it is not the executor.
    let resolved: Value = reqwest::Client::new()
        .post(&url)
        .bearer_auth("reconciler")
        .json(&assertion("not_applied"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resolved["status"], "resolved", "{resolved}");
    assert_eq!(resolved["outcome"], "not_applied");
}
