//! Erasure and retention of finished runs.

use std::collections::HashMap;

use serde_json::{Value, json};

use crate::harness::*;

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
