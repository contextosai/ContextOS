//! Read-only inspection of shared-guarantee holds over HTTP.

use std::sync::atomic::Ordering;

use contextos_contract::canonical::sha256_canonical;
use contextos_store::DocumentStore;
use contextosd::auth::hash_api_key;
use serde_json::{Value, json};

use crate::harness::*;

#[tokio::test]
async fn holds_are_listed_and_explained_without_arguments_until_reconciled() {
    let w = world_with(&ALL_CONTROLS, 1, |c| {
        c.guarantees = vec![
            serde_json::from_value(json!({"id":"refunds","capability_ids":["adp_payments.issue_refund"],
            "resource_pointer":"/order_id","amount_pointer":"/amount_minor","limit":1000,"unit":"INR_minor"}))
            .unwrap(),
        ];
        c.api_keys.push(contextosd::config::ApiKey {
            key_sha256: hash_api_key("other-reader"),
            tenant_id: "tenant_other".into(),
            principal_id: "other_reader".into(),
            scopes: vec!["audit:read".into()],
        });
    })
    .await;
    let http = executor_client(2);
    let get = |url: String, key: &'static str| {
        let http = http.clone();
        async move { http.get(url).bearer_auth(key).send().await.unwrap() }
    };
    let list = format!("{}/v1/guarantees/refunds/holds", w.base);
    let empty: Value = get(list.clone(), "acme-key").await.json().await.unwrap();
    assert_eq!(empty, json!({"guarantee_id": "refunds", "resources": [], "next": null}));

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

    let page: Value = get(list.clone(), "acme-key").await.json().await.unwrap();
    let digest = sha256_canonical(&json!("ord_881")).unwrap();
    assert_eq!(page["next"], Value::Null);
    assert_eq!(page["resources"].as_array().unwrap().len(), 1, "{page}");
    let resource = &page["resources"][0];
    assert_eq!(resource["resource_digest"], digest);
    assert_eq!(
        (resource["held"].as_u64(), resource["open_holds"].as_u64()),
        (Some(777), Some(1))
    );

    let detail_url = format!("{}/v1/guarantees/refunds/resources/{digest}/holds", w.base);
    let detail: Value = get(detail_url.clone(), "acme-key").await.json().await.unwrap();
    let text = detail.to_string();
    assert!(!text.contains("ord_881") && !text.contains("cus_77"), "{detail}");
    assert_eq!(
        (detail["held"].as_u64(), detail["available"].as_u64()),
        (Some(777), Some(223))
    );
    let hold = &detail["holds"][0];
    assert_eq!(hold["run_id"], "run_held");
    assert_eq!(hold["operation_id"], "refund:run_held");
    assert_eq!(hold["amount"], 777);
    assert_eq!(hold["dispatch_started"], true);
    assert_eq!(hold["state"], "unknown_provider_reference", "{hold}");
    assert_eq!(hold["last_observation"]["external_ref"], "task_e2e_1");
    assert!(hold["attempt_started_at"].is_string());
    assert_eq!(hold["next_safe_step"]["action"], "provider_query");
    let reconcile = hold["next_safe_step"]["reconcile"].as_str().unwrap();
    assert_eq!(reconcile, "/v1/runs/run_held/operations/refund:run_held/reconcile");

    // Other tenants, unknown guarantees and readers without the scope see nothing.
    assert_eq!(get(detail_url.clone(), "other-reader").await.status(), 404);
    let other: Value = get(list.clone(), "other-reader").await.json().await.unwrap();
    assert_eq!(other["resources"], json!([]));
    assert_eq!(
        get(format!("{}/v1/guarantees/nope/holds", w.base), "acme-key")
            .await
            .status(),
        404
    );
    assert_eq!(get(list.clone(), "ops-key").await.status(), 403);
    assert_eq!(get(format!("{list}?scan=1&bogus=1"), "acme-key").await.status(), 400);

    // Following the next safe step resolves the hold; inspection never sent anything.
    let outcome: Value = http
        .post(format!("{}{reconcile}", w.base))
        .bearer_auth("acme-key")
        .json(&json!({"source":"provider"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(outcome["status"], "resolved", "{outcome}");
    assert_eq!(w.provider_calls.load(Ordering::SeqCst), 1);
    let after: Value = get(list, "acme-key").await.json().await.unwrap();
    assert_eq!(after["resources"], json!([]));
    let detail: Value = get(detail_url, "acme-key").await.json().await.unwrap();
    assert_eq!(
        (detail["committed"].as_u64(), detail["held"].as_u64()),
        (Some(777), Some(0))
    );
    assert_eq!(detail["holds"], json!([]));
}

#[tokio::test]
async fn an_unreadable_ledger_is_listed_without_hiding_the_rest() {
    let w = world_with(&ALL_CONTROLS, 1, |c| {
        c.guarantees = vec![
            serde_json::from_value(json!({"id":"refunds","capability_ids":["adp_payments.issue_refund"],
            "resource_pointer":"/order_id","amount_pointer":"/amount_minor","limit":1000,"unit":"INR_minor"}))
            .unwrap(),
        ];
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
    let corrupt = "0".repeat(64);
    w.state
        .store
        .create(
            &contextos_store::DocKey::new(TENANT, contextos_store::DocKind::SharedExposure, &corrupt),
            &json!({"binding": {"guarantee_id": "refunds"}, "receipts": "torn"}),
        )
        .await
        .unwrap();

    let page = http
        .get(format!("{}/v1/guarantees/refunds/holds", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), 200);
    let page: Value = page.json().await.unwrap();
    let resources = page["resources"].as_array().unwrap();
    assert_eq!(resources.len(), 2, "{page}");
    assert_eq!(resources[0], json!({"resource_digest": corrupt, "unreadable": true}));
    assert_eq!(resources[1]["held"], 777);
}

#[tokio::test]
async fn attesting_absence_needs_its_own_scope_and_a_started_attempt_without_a_fact() {
    let w = world_with(&ALL_CONTROLS, 1, |c| {
        c.guarantees = vec![
            serde_json::from_value(json!({"id":"refunds","capability_ids":["adp_payments.issue_refund"],
            "resource_pointer":"/order_id","amount_pointer":"/amount_minor","limit":1000,"unit":"INR_minor"}))
            .unwrap(),
        ];
        c.api_keys.push(contextosd::config::ApiKey {
            key_sha256: hash_api_key("attester-key"),
            tenant_id: TENANT.into(),
            principal_id: "svc_ledger_check".into(),
            scopes: vec!["attest".into()],
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
    let url = format!("{}/v1/runs/run_held/operations/refund:run_held/attest-absence", w.base);
    let body = json!({"evidence_ref": {"artifact_type": "provider_ledger", "artifact_id": "export_1", "version": "1",
        "sha256": format!("sha256:{}", "a".repeat(64))}, "checked_through": "2026-10-20T10:06:00.000000Z"});
    let attest = |key: &'static str, body: Value| {
        let (http, url) = (http.clone(), url.clone());
        async move { http.post(url).bearer_auth(key).json(&body).send().await.unwrap() }
    };
    // The orchestrator that ran the effect cannot vouch that it did not apply.
    assert_eq!(attest("acme-key", body.clone()).await.status(), 403);
    assert_eq!(
        attest("attester-key", json!({"checked_through": "x"})).await.status(),
        422
    );
    // The provider answered (the task is pending): ordinary reconciliation applies.
    let refused: Value = attest("attester-key", body).await.json().await.unwrap();
    assert_eq!(refused["status"], "rejected", "{refused}");
    assert_eq!(refused["reason_codes"], json!(["attestation_not_applicable"]));
}
