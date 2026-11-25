//! Legal holds and deletion requests: a hold keeps runs from erasure, a subject's
//! finished runs are erased together, and the audit chain still verifies.

use serde_json::{Value, json};

use crate::harness::*;

const SUBJECT: &str = "cus_77";

async fn post(w: &World, path: &str, key: &str, body: Value) -> (u16, Value) {
    let response = reqwest::Client::new()
        .post(format!("{}{path}", w.base))
        .bearer_auth(key)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    (status, response.json().await.unwrap_or(Value::Null))
}

async fn get(w: &World, path: &str) -> (u16, Value) {
    let response = reqwest::Client::new()
        .get(format!("{}{path}", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    (status, response.json().await.unwrap_or(Value::Null))
}

/// Admits a run about `subject` and finishes it.
async fn finished_run(w: &World, run_id: &str, subject: &str) {
    let mut body = run_body(run_id, 1200);
    body["request"]["input"]["context"]["customer_id"] = json!(subject);
    let admitted = admit(w, &body).await;
    assert_eq!(admitted.status(), 201);
    let admitted: Value = admitted.json().await.unwrap();
    let done = executor_client(admitted["executor_generation"].as_u64().unwrap())
        .post(format!("{}/v1/runs/{run_id}/complete", w.base))
        .bearer_auth("acme-key")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(done.status(), 200, "{}", done.text().await.unwrap());
}

#[tokio::test]
async fn a_hold_keeps_a_subjects_runs_until_released_and_the_chain_still_verifies() {
    let w = world_with(&ALL_CONTROLS, 1, |c| {
        c.privacy.subject_pointers = vec!["/input/context/customer_id".into()];
    })
    .await;
    finished_run(&w, "run_dsar_a", SUBJECT).await;
    finished_run(&w, "run_dsar_b", SUBJECT).await;
    finished_run(&w, "run_other", "cus_88").await;

    // The subject's runs, found by its identifier; only operators may ask.
    let (status, _) = post(&w, "/v1/subjects/runs", "acme-key", json!({"subject": SUBJECT})).await;
    assert_eq!(status, 403);
    let (status, found) = post(&w, "/v1/subjects/runs", "ops-key", json!({"subject": SUBJECT})).await;
    assert_eq!(status, 200, "{found}");
    assert_eq!(found["runs"], json!(["run_dsar_a", "run_dsar_b"]));

    // A hold on the subject keeps both runs: neither one erasure nor the request erases.
    let hold = json!({"hold_id": "case-2026-114", "reason": "litigation hold for case 114", "subjects": [SUBJECT]});
    let (status, placed) = post(&w, "/v1/legal-holds", "ops-key", hold.clone()).await;
    assert_eq!(status, 201, "{placed}");
    assert!(
        !placed.to_string().contains(SUBJECT),
        "only the digest is kept: {placed}"
    );
    let (status, _) = post(&w, "/v1/legal-holds", "ops-key", hold).await;
    assert_eq!(status, 409, "hold ids are unique");
    let (status, refused) = post(
        &w,
        "/v1/runs/run_dsar_a/erase",
        "ops-key",
        json!({"reason": "subject request 88"}),
    )
    .await;
    assert_eq!(status, 409, "{refused}");
    assert_eq!(refused["error"]["code"], "legal_hold");
    let request = json!({"subject": SUBJECT, "reason": "deletion request DSR-88"});
    let (status, summary) = post(&w, "/v1/subjects/erase", "ops-key", request.clone()).await;
    assert_eq!(status, 200, "{summary}");
    assert_eq!(summary["erased"], json!([]));
    assert_eq!(summary["held"].as_array().unwrap().len(), 2);
    assert_eq!(get(&w, "/v1/runs/run_dsar_a/replay-case").await.0, 200);

    // Released, the request erases both runs and leaves the other subject's alone.
    let (status, released) = post(
        &w,
        "/v1/legal-holds/case-2026-114/release",
        "ops-key",
        json!({"reason": "case 114 closed by counsel"}),
    )
    .await;
    assert_eq!(status, 200, "{released}");
    let (status, summary) = post(&w, "/v1/subjects/erase", "ops-key", request).await;
    assert_eq!(status, 200, "{summary}");
    assert_eq!(summary["erased"], json!(["run_dsar_a", "run_dsar_b"]));
    assert_eq!(get(&w, "/v1/runs/run_dsar_a/replay-case").await.0, 410);
    assert_eq!(get(&w, "/v1/runs/run_other/replay-case").await.0, 200);

    // A tenant-wide hold keeps everything.
    let (status, _) = post(
        &w,
        "/v1/legal-holds",
        "ops-key",
        json!({"hold_id": "regulator-audit", "reason": "regulator audit in progress", "tenant_wide": true}),
    )
    .await;
    assert_eq!(status, 201);
    let (status, _) = post(
        &w,
        "/v1/runs/run_other/erase",
        "ops-key",
        json!({"reason": "subject request 89"}),
    )
    .await;
    assert_eq!(status, 409);
    let (_, holds) = get_as(&w, "/v1/legal-holds", "ops-key").await;
    assert_eq!(holds["holds"].as_array().unwrap().len(), 2);

    // The chain verifies after every erasure; it names the subject by digest only.
    let (status, verify) = get(&w, "/v1/audit/verify").await;
    assert_eq!(status, 200);
    assert_eq!(verify["verified"], true, "{verify}");
    let (_, entries) = get(&w, "/v1/audit/entries?from=1&limit=1000").await;
    let kinds: Vec<&str> = entries["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["kind"].as_str())
        .collect();
    for kind in [
        "legal_hold_placed",
        "legal_hold_released",
        "subject_erasure",
        "run_data_erased",
    ] {
        assert!(kinds.contains(&kind), "{kind} missing");
    }
    let erasure_entries: Vec<&Value> = entries["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["kind"] == "subject_erasure" || e["kind"].as_str().is_some_and(|k| k.starts_with("legal_hold")))
        .collect();
    assert!(!json!(erasure_entries).to_string().contains(SUBJECT));
}

async fn get_as(w: &World, path: &str, key: &str) -> (u16, Value) {
    let response = reqwest::Client::new()
        .get(format!("{}{path}", w.base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    (status, response.json().await.unwrap_or(Value::Null))
}

#[tokio::test]
async fn invalid_holds_and_pointers_are_refused() {
    let w = world_with(&ALL_CONTROLS, 1, |_| {}).await;
    let (status, _) = post(
        &w,
        "/v1/legal-holds",
        "ops-key",
        json!({"hold_id": "h1", "reason": "short"}),
    )
    .await;
    assert_eq!(status, 422);
    let (status, _) = post(
        &w,
        "/v1/legal-holds",
        "ops-key",
        json!({"hold_id": "h1", "reason": "nothing named at all"}),
    )
    .await;
    assert_eq!(status, 422);
    let (status, _) = post(
        &w,
        "/v1/legal-holds/none/release",
        "ops-key",
        json!({"reason": "no such hold here"}),
    )
    .await;
    assert_eq!(status, 404);
    let (config, _) = world_setup(&ALL_CONTROLS).await;
    let bad = contextosd::config::Config::parse(&format!(
        "{}\n[privacy]\nsubject_pointers = [\"customer_id\"]",
        config.source
    ));
    assert!(bad.is_err());
}
