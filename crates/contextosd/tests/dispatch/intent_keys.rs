//! Intent keys: one business request is applied once across runs.

use std::sync::atomic::Ordering;

use serde_json::{Value, json};

use crate::harness::*;

/// A world whose refund capability names its request by order and amount.
async fn intent_world(pointers: Value) -> World {
    world_with(&ALL_CONTROLS, 2, |c| {
        let path = c.capabilities[0].clone();
        let mut manifest: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        manifest["intent"] = json!({"key_pointers": pointers, "window_seconds": 3600});
        std::fs::write(&path, manifest.to_string()).unwrap();
    })
    .await
}

async fn started(w: &World, run_id: &str) {
    let response = admit(w, &run_body(run_id, 1200)).await;
    assert_eq!(response.status(), 201, "{}", response.text().await.unwrap());
}

#[tokio::test]
async fn the_same_request_from_another_run_is_refused() {
    let w = intent_world(json!(["/order_id", "/amount_minor"])).await;
    for run in ["run_intent_a", "run_intent_b"] {
        started(&w, run).await;
    }
    let before = w.provider_calls.load(Ordering::SeqCst);
    let first = dispatch(&w, "run_intent_a", &tool_call("run_intent_a", "tc_a", 120_000)).await;
    assert_eq!(first["result"]["status"], "completed", "{first}");

    // A redelivery of the request into a new run, under its own operation key.
    let again = dispatch(&w, "run_intent_b", &tool_call("run_intent_b", "tc_b", 120_000)).await;
    assert_eq!(again["result"]["status"], "blocked", "{again}");
    assert_eq!(again["report"]["reason_codes"], json!(["effect_repeated_across_runs"]));
    assert!(
        again["report"]["obligations"]
            .as_array()
            .unwrap()
            .contains(&json!("reconcile_existing_operation")),
        "{again}"
    );
    assert_eq!(w.provider_calls.load(Ordering::SeqCst), before + 1, "sent once");

    // A different request (another amount) is not the same intent.
    let mut smaller = tool_call("run_intent_b", "tc_c", 60_000);
    smaller["idempotency_key"] = json!("refund:run_intent_b:smaller");
    let other = dispatch(&w, "run_intent_b", &smaller).await;
    assert_eq!(other["result"]["status"], "completed", "{other}");

    // The refusal is audited with the operation that holds the intent.
    let entries: Value = reqwest::Client::new()
        .get(format!("{}/v1/audit/entries?from=1&limit=1000", w.bases[1]))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let refusal = entries["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["kind"] == "repeated_effect_refusal")
        .expect("refusal audited");
    assert_eq!(refusal["payload"]["applied"]["run_id"], "run_intent_a", "{refusal}");
    assert_eq!(
        refusal["payload"]["reason_codes"],
        json!(["effect_repeated_across_runs"])
    );
}

#[tokio::test]
async fn racing_runs_send_one_request() {
    let w = intent_world(json!(["/order_id", "/amount_minor"])).await;
    let runs: Vec<String> = (0..6).map(|i| format!("run_race_{i}")).collect();
    for run in &runs {
        started(&w, run).await;
    }
    let before = w.provider_calls.load(Ordering::SeqCst);
    let mut calls = tokio::task::JoinSet::new();
    for (i, run) in runs.iter().enumerate() {
        let (base, call) = (w.bases[i % 2].clone(), tool_call(run, &format!("tc_{i}"), 120_000));
        let url = format!("{base}/v1/runs/{run}/tool-calls");
        calls.spawn(async move {
            executor_client(2)
                .post(url)
                .bearer_auth("acme-key")
                .json(&call)
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap()
        });
    }
    let results = calls.join_all().await;
    let completed = results.iter().filter(|r| r["result"]["status"] == "completed").count();
    assert_eq!(completed, 1, "{results:?}");
    assert_eq!(w.provider_calls.load(Ordering::SeqCst), before + 1);
}

#[tokio::test]
async fn a_call_without_its_intent_arguments_is_rejected() {
    let w = intent_world(json!(["/order_id", "/reason"])).await;
    started(&w, "run_intent_missing").await;
    let before = w.provider_calls.load(Ordering::SeqCst);
    let call = dispatch(
        &w,
        "run_intent_missing",
        &tool_call("run_intent_missing", "tc_m", 120_000),
    )
    .await;
    assert_eq!(call["result"]["status"], "rejected", "{call}");
    assert_eq!(call["report"]["reason_codes"], json!(["intent_key_missing"]));
    assert_eq!(w.provider_calls.load(Ordering::SeqCst), before);
}
