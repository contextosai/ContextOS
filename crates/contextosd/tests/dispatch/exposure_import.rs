//! Prior exposure imported over HTTP, one way, under its own scope.

use contextos_contract::canonical::sha256_canonical;
use contextosd::auth::hash_api_key;
use serde_json::{Value, json};

use crate::harness::*;

fn rows(rows: Value) -> Value {
    json!({"rows": rows})
}

#[tokio::test]
async fn imports_need_their_scope_answer_each_row_and_raise_over_limit() {
    let w = world_with(&ALL_CONTROLS, 1, |c| {
        c.guarantees = vec![
            serde_json::from_value(json!({"id":"refunds","capability_ids":["adp_payments.issue_refund"],
            "resource_pointer":"/order_id","amount_pointer":"/amount_minor","limit":1000,"unit":"INR_minor"}))
            .unwrap(),
        ];
        c.api_keys.push(contextosd::config::ApiKey {
            key_sha256: hash_api_key("finance-key"),
            tenant_id: TENANT.into(),
            principal_id: "svc_finance".into(),
            scopes: vec!["exposure:import".into()],
            agent_ids: None,
        });
    })
    .await;
    let http = reqwest::Client::new();
    let url = format!("{}/v1/guarantees/refunds/imports", w.base);
    let post = |key: &'static str, body: Value| {
        let (http, url) = (http.clone(), url.clone());
        async move { http.post(url).bearer_auth(key).json(&body).send().await.unwrap() }
    };
    let row = |id: &str, resource: &str, amount: u64| {
        json!({"import_id": id, "resource": resource, "amount": amount, "source": "legacy_backoffice",
            "as_of": "2026-10-01T00:00:00Z", "evidence_ref": format!("backoffice:{id}")})
    };

    // The executor's key cannot import.
    assert_eq!(
        post("acme-key", rows(json!([row("legacy_1", "ord_881", 600)])))
            .await
            .status(),
        403
    );
    assert_eq!(post("finance-key", rows(json!([]))).await.status(), 422);
    let missing = format!("{}/v1/guarantees/nope/imports", w.base);
    let response = http
        .post(missing)
        .bearer_auth("finance-key")
        .json(&rows(json!([row("legacy_1", "ord_881", 600)])))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);

    let response = post(
        "finance-key",
        rows(json!([
            row("legacy_1", "ord_881", 600),
            row("legacy_1", "ord_881", 600),
            row("legacy_2", "ord_881", 700),
            {"import_id": "legacy_3", "resource": "ord_882"},
        ])),
    )
    .await;
    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.unwrap();
    let results = body["results"].as_array().unwrap();
    let statuses: Vec<&str> = results.iter().map(|r| r["status"].as_str().unwrap()).collect();
    assert_eq!(statuses, ["imported", "duplicate", "imported", "refused"]);
    assert_eq!(results[0]["over_limit"], false);
    assert_eq!(results[2]["over_limit"], true, "1,300 of a 1,000 limit");
    assert_eq!(results[3]["reason"], "shared_guarantee_import_invalid");

    let digest = sha256_canonical(&json!("ord_881")).unwrap();
    let view: Value = http
        .get(format!("{}/v1/guarantees/refunds/resources/{digest}", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        (view["committed"].as_u64(), view["imported"].as_u64()),
        (Some(1300), Some(1300))
    );
    assert_eq!(view["over_limit"], true);
    let metrics = reqwest::get(format!("{}/metrics", w.base))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        metrics.contains("contextos_shared_guarantee_over_limit_imports_total{guarantee=\"refunds\"} 1\n"),
        "{metrics}"
    );
}
