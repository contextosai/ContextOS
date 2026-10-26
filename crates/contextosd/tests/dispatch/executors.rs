//! Executor generations: takeover, fencing, checkpoints, completion and cancellation.

use std::sync::atomic::Ordering;

use serde_json::{Value, json};

use crate::harness::*;

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
