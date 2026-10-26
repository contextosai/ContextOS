//! Peer work shared through trusted lineage, and shared guarantees across replicas.

use std::sync::atomic::Ordering;

use contextos_contract::canonical::sha256_canonical;
use contextosd::auth::hash_api_key;
use serde_json::{Value, json};

use crate::harness::*;

#[tokio::test]
async fn peer_work_is_shared_through_trusted_lineage_and_claimed_atomically_over_http() {
    let w = world_with(&ALL_CONTROLS, 2, |c| {
        c.api_keys.push(contextosd::config::ApiKey {
            key_sha256: hash_api_key("impostor"),
            tenant_id: TENANT.into(),
            principal_id: "different-principal".into(),
            scopes: vec!["dispatch".into()],
        });
    })
    .await;
    let http = executor_client(2);
    let parent: Value = http
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("work_root", 1200))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(parent["executor_generation"], 2);
    for id in ["work_a", "work_b"] {
        let response = http
            .post(format!("{}/v1/runs", w.base))
            .bearer_auth("acme-key")
            .json(&child_of(&parent, "work_root", id, "ctxpack.support@5.2.0"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 201, "{}", response.text().await.unwrap());
    }
    let url = |base: &str, run: &str, suffix: &str| format!("{base}/v1/runs/{run}/work{suffix}");
    let board = url(&w.base, "work_root", "");
    assert_eq!(http.get(&board).send().await.unwrap().status(), 401);
    assert_eq!(
        http.get(&board).bearer_auth("ops-key").send().await.unwrap().status(),
        403
    );
    let impersonated = http.get(&board).bearer_auth("impostor").send().await.unwrap();
    assert_eq!(impersonated.status(), 403);
    assert_eq!(
        impersonated.json::<Value>().await.unwrap()["error"]["code"],
        "work_forbidden"
    );
    let definition =
        json!({"task_id":"parser","title":"Implement parser","acceptance_criteria":"Checks pass","dependencies":[]});
    let published = http
        .post(&board)
        .bearer_auth("acme-key")
        .json(&definition)
        .send()
        .await
        .unwrap();
    assert_eq!(published.status(), 201, "{}", published.text().await.unwrap());
    let input = json!({"action":"claim","expected_revision":1,"lease_seconds":60});
    let a = http
        .post(url(&w.base, "work_a", "/parser"))
        .bearer_auth("acme-key")
        .json(&input);
    let b = http
        .post(url(&w.bases[1], "work_b", "/parser"))
        .bearer_auth("acme-key")
        .json(&input);
    let (a, b) = tokio::join!(a.send(), b.send());
    let a = a.unwrap();
    let b = b.unwrap();
    assert_eq!(usize::from(a.status() == 200) + usize::from(b.status() == 200), 1);
    let (winner, loser) = if a.status() == 200 { (a, b) } else { (b, a) };
    assert_eq!(loser.status(), 409);
    let winner: Value = winner.json().await.unwrap();
    conforms("WorkResult", &winner);
    assert_eq!(winner["data_only"], true);
    let owner = winner["task"]["claim"]["run_id"].as_str().unwrap();
    let completed=http.post(url(&w.base,owner,"/parser")).bearer_auth("acme-key")
        .json(&json!({"action":"complete","expected_revision":2,"lease_epoch":1,
            "evidence_refs":[{"artifact_type":"test","artifact_id":"report","sha256":format!("sha256:{}","b".repeat(64))}]}))
        .send().await.unwrap();
    assert_eq!(completed.status(), 200, "{}", completed.text().await.unwrap());
    let listed: Value = http
        .get(&board)
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    conforms("WorkPage", &listed);
    assert_eq!(listed["tasks"][0]["status"], "completed");
    assert_eq!(listed["evidence_verified"], false);
    assert_eq!(
        w.provider_calls.load(Ordering::SeqCst),
        0,
        "coordination never invokes a business tool"
    );
    let mut forged = definition.clone();
    forged["root_run_id"] = json!("some-other-root");
    assert_eq!(
        http.post(&board)
            .bearer_auth("acme-key")
            .json(&forged)
            .send()
            .await
            .unwrap()
            .status(),
        422
    );
    assert_eq!(
        http.post(&board)
            .bearer_auth("acme-key")
            .header("Content-Type", "application/json")
            .body(r#"{"task_id":"a","task_id":"b"}"#)
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    assert_eq!(
        http.get(format!("{board}?limit=101"))
            .bearer_auth("acme-key")
            .send()
            .await
            .unwrap()
            .status(),
        422
    );
    assert_eq!(
        executor_client(1)
            .get(&board)
            .bearer_auth("acme-key")
            .send()
            .await
            .unwrap()
            .status(),
        409
    );
}

#[tokio::test]
async fn shared_guarantee_unknown_exposure_can_be_reconciled_after_the_run_fails() {
    let w = world_with(&ALL_CONTROLS, 1, |c| {
        c.guarantees = vec![
            serde_json::from_value(json!({
        "id":"refunds","capability_ids":["adp_payments.issue_refund"],"resource_pointer":"/order_id",
        "amount_pointer":"/amount_minor","limit":1000,"unit":"INR_minor"}))
            .unwrap(),
        ];
    })
    .await;
    let http = executor_client(2);
    let admitted: Value = http
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_terminal_shared", 7))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(admitted["executor_generation"], 2);
    let out: Value = http
        .post(format!("{}/v1/runs/run_terminal_shared/tool-calls", w.base))
        .bearer_auth("acme-key")
        .json(&tool_call("run_terminal_shared", "pending", 777))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(out["result"]["status"], "paused");
    let failed: Value = http
        .post(format!("{}/v1/runs/run_terminal_shared/fail", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(failed["status"], "failed");
    let generation = failed["executor_generation"].as_u64().unwrap();
    let url = format!(
        "{}/v1/runs/run_terminal_shared/operations/refund:run_terminal_shared/reconcile",
        w.base
    );
    let stale = http
        .post(&url)
        .bearer_auth("acme-key")
        .json(&json!({"source":"provider"}))
        .send()
        .await
        .unwrap();
    assert_eq!(stale.status(), 409);
    let outcome: Value = executor_client(generation)
        .post(&url)
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
}

#[tokio::test]
async fn shared_guarantees_coordinate_replicas_and_expose_only_tenant_scoped_read_views() {
    let w = world_with(&ALL_CONTROLS, 2, |c| {
        c.guarantees = vec![
            serde_json::from_value(json!({"id":"refunds","capability_ids":["adp_payments.issue_refund"],
            "resource_pointer":"/order_id","amount_pointer":"/amount_minor","limit":200_000,"unit":"INR_minor"}))
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
    for id in ["run_shared_a", "run_shared_b"] {
        let out = http
            .post(format!("{}/v1/runs", w.base))
            .bearer_auth("acme-key")
            .json(&run_body(id, 1200))
            .send()
            .await
            .unwrap();
        assert_eq!(out.status(), 201, "{}", out.text().await.unwrap());
    }
    let a = http
        .post(format!("{}/v1/runs/run_shared_a/tool-calls", w.base))
        .bearer_auth("acme-key")
        .json(&tool_call("run_shared_a", "a", 120_000));
    let b = http
        .post(format!("{}/v1/runs/run_shared_b/tool-calls", w.bases[1]))
        .bearer_auth("acme-key")
        .json(&tool_call("run_shared_b", "b", 120_000));
    let (a, b) = tokio::join!(a.send(), b.send());
    let a: Value = a.unwrap().json().await.unwrap();
    let b: Value = b.unwrap().json().await.unwrap();
    assert_eq!(
        [&a, &b].iter().filter(|o| o["result"]["status"] == "completed").count(),
        1,
        "{a} {b}"
    );
    assert!(
        [&a, &b]
            .iter()
            .any(|o| o["report"]["reason_codes"] == json!(["shared_guarantee_exceeded"])),
        "{a} {b}"
    );
    assert_eq!(w.provider_calls.load(Ordering::SeqCst), 1);
    let list = format!("{}/v1/guarantees", w.base);
    assert_eq!(http.get(&list).send().await.unwrap().status(), 401);
    assert_eq!(
        http.get(&list).bearer_auth("ops-key").send().await.unwrap().status(),
        403
    );
    let rules: Value = http
        .get(&list)
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(rules["guarantees"][0]["id"], "refunds");
    let digest = sha256_canonical(&json!("ord_881")).unwrap();
    let url = format!("{}/v1/guarantees/refunds/resources/{digest}", w.base);
    let view: Value = http
        .get(&url)
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(view["committed"], 120_000);
    assert_eq!(view["available"], 80_000);
    assert!(!view.to_string().contains("ord_881"));
    assert_eq!(
        http.get(&url)
            .bearer_auth("other-reader")
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
}
