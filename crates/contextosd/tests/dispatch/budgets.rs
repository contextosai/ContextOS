//! Run budgets: model calls, replans, ledger compaction and the loop guard.

use std::sync::atomic::Ordering;

use serde_json::{Value, json};

use crate::harness::*;

#[tokio::test]
async fn model_calls_and_replans_spend_the_run_budget() {
    let w = world(&ALL_CONTROLS).await;
    let plain = reqwest::Client::new();
    let admitted: Value = plain
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_budgeted", 1200))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let http = executor_client(admitted["executor_generation"].as_u64().unwrap());
    let reserve = |body: Value| {
        let (http, url) = (http.clone(), format!("{}/v1/runs/run_budgeted/usage/reserve", w.base));
        async move { http.post(url).bearer_auth("acme-key").json(&body).send().await.unwrap() }
    };
    let settle = |key: &'static str, body: Value| {
        let (http, url) = (http.clone(), format!("{}/v1/runs/run_budgeted/usage/settle", w.base));
        async move { http.post(url).bearer_auth(key).json(&body).send().await.unwrap() }
    };
    let id = |r: Value| r["reservation_id"].as_str().unwrap().to_owned();

    // Self-reported usage is not evidence: the whole reservation is charged.
    let first = id(reserve(json!({"kind": "model_call", "tokens": 4000, "cost_cents": 1}))
        .await
        .json()
        .await
        .unwrap());
    let charged: Value = settle("acme-key", json!({"reservation_id": first, "tokens": 10}))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(
        (charged["charged"]["tokens"].as_u64(), charged["verified"].as_bool()),
        (Some(4000), Some(false)),
        "{charged}"
    );
    // Usage measured by a metering principal settles to what was measured.
    let second = id(reserve(json!({"kind": "model_call", "tokens": 4000, "cost_cents": 1}))
        .await
        .json()
        .await
        .unwrap());
    let metered: Value = settle("meter-key", json!({"reservation_id": second, "tokens": 500}))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(
        (metered["charged"]["tokens"].as_u64(), metered["verified"].as_bool()),
        (Some(500), Some(true)),
        "{metered}"
    );
    // 4,500 of 10,000 tokens are spent: 6,000 more does not fit.
    let over = reserve(json!({"kind": "model_call", "tokens": 6000})).await;
    assert_eq!(over.status(), 409);
    assert_eq!(over.json::<Value>().await.unwrap()["error"]["code"], "budget_exhausted");
    // Two replans are allowed; the third is refused.
    for _ in 0..2 {
        assert_eq!(reserve(json!({"kind": "replan"})).await.status(), 201);
    }
    assert_eq!(reserve(json!({"kind": "replan"})).await.status(), 409);
    // Only usage reservations settle here.
    assert_eq!(
        settle("meter-key", json!({"reservation_id": "reservation:attempt_1"}))
            .await
            .status(),
        404
    );

    let evidence: Value = plain
        .get(format!("{}/v1/runs/run_budgeted/evidence", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ledger = &evidence["budget_ledger"];
    assert_eq!(ledger["used"]["tokens"], 4500, "{ledger}");
    assert_eq!(
        ledger["reserved"]["replans"], 2,
        "open replan reservations stay reserved"
    );
}

#[tokio::test]
async fn many_model_calls_keep_the_budget_ledger_compact() {
    let w = world(&ALL_CONTROLS).await;
    let plain = reqwest::Client::new();
    let admitted: Value = plain
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_chatty", 1200))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let http = executor_client(admitted["executor_generation"].as_u64().unwrap());
    for _ in 0..20 {
        let reserved: Value = http
            .post(format!("{}/v1/runs/run_chatty/usage/reserve", w.base))
            .bearer_auth("acme-key")
            .json(&json!({"kind": "model_call", "tokens": 100}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let settled = plain
            .post(format!("{}/v1/runs/run_chatty/usage/settle", w.base))
            .bearer_auth("meter-key")
            .json(&json!({"reservation_id": reserved["reservation_id"], "tokens": 90}))
            .send()
            .await
            .unwrap();
        assert_eq!(settled.status(), 200);
    }
    let evidence: Value = plain
        .get(format!("{}/v1/runs/run_chatty/evidence", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        !evidence["budget_archives"].as_array().unwrap().is_empty(),
        "40 mutations were compacted"
    );
    assert!(evidence["budget_ledger"]["mutations"].as_array().unwrap().len() < 32);
    let opening = evidence["budget_ledger"]["opening_usage"]["tokens"].as_u64().unwrap();
    let used = evidence["budget_ledger"]["used"]["tokens"].as_u64().unwrap();
    assert_eq!(used, 1800, "20 metered calls of 90 tokens (opening {opening})");
}

#[tokio::test]
async fn repeated_identical_calls_trip_the_loop_guard() {
    // Identical effects under new keys are what the repeated-effect guard refuses; turn
    // it off to reach the loop guard (as for a capability marked `repeatable`).
    let w = world_with(&ALL_CONTROLS, 1, |c| c.guards.refuse_repeated_effects = false).await;
    let plain = reqwest::Client::new();
    let admitted: Value = plain
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_looping", 1200))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let http = executor_client(admitted["executor_generation"].as_u64().unwrap());
    let call = |key: &str, amount: u64| {
        let mut body = tool_call("run_looping", &format!("tc_{key}"), amount);
        body["idempotency_key"] = json!(key);
        let (http, url) = (http.clone(), format!("{}/v1/runs/run_looping/tool-calls", w.base));
        async move {
            http.post(url)
                .bearer_auth("acme-key")
                .json(&body)
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap()
        }
    };
    let before = w.provider_calls.load(Ordering::SeqCst);
    for i in 0..5 {
        assert_eq!(
            call(&format!("loop_{i}"), 120_000).await["result"]["status"],
            "completed"
        );
    }
    // The sixth identical call under a new key is refused before it is claimed or sent.
    let tripped = call("loop_5", 120_000).await;
    assert_eq!(tripped["result"]["status"], "blocked", "{tripped}");
    assert_eq!(tripped["report"]["reason_codes"], json!(["loop_detected"]));
    assert!(
        tripped["report"]["obligations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|o| o == "change_approach")
    );
    assert_eq!(w.provider_calls.load(Ordering::SeqCst), before + 5);
    // A retry of an existing operation is not a new call, and other arguments are not a loop.
    // (Re-sending a completed operation is answered from its ledger as before.)
    let retry = call("loop_4", 120_000).await;
    assert_eq!(retry["report"]["reason_codes"], json!(["retry_unsafe"]), "{retry}");
    let other = call("loop_other", 120_001).await;
    assert_eq!(other["result"]["status"], "completed", "{other}");
}

#[tokio::test]
async fn model_call_budgets_cannot_be_dodged() {
    let w = world(&ALL_CONTROLS).await;
    let plain = reqwest::Client::new();
    let admitted: Value = plain
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_dodge", 1200))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let http = executor_client(admitted["executor_generation"].as_u64().unwrap());
    let reserve = |tokens: u64| {
        let (http, url) = (http.clone(), format!("{}/v1/runs/run_dodge/usage/reserve", w.base));
        async move {
            let r: Value = http
                .post(url)
                .bearer_auth("acme-key")
                .json(&json!({"kind": "model_call", "tokens": tokens}))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            r["reservation_id"].as_str().unwrap().to_owned()
        }
    };
    let settle = |key: &'static str, body: Value| {
        let (http, url) = (http.clone(), format!("{}/v1/runs/run_dodge/usage/settle", w.base));
        async move {
            http.post(url)
                .bearer_auth(key)
                .json(&body)
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap()
        }
    };
    // A zero reservation still covers the floor, so a self-settled call is never free.
    let free = reserve(0).await;
    assert_eq!(
        settle("acme-key", json!({"reservation_id": free})).await["charged"]["tokens"],
        1000
    );
    // A meter that measured more than was reserved charges the overage too.
    let under = reserve(1000).await;
    let metered = settle("meter-key", json!({"reservation_id": under, "tokens": 3000})).await;
    assert_eq!(metered["charged"]["tokens"], 3000, "{metered}");
    // Beyond the run's remaining capacity (10,000 - 4,000 used), the charge is capped and audited.
    let last = reserve(1000).await;
    let capped = settle("meter-key", json!({"reservation_id": last, "tokens": 50_000})).await;
    assert_eq!(capped["charged"]["tokens"], 6000, "{capped}");
    let audit: Value = plain
        .get(format!("{}/v1/audit/entries?from=1&limit=500", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let overages = audit["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e.to_string().contains("usage_overage"))
        .count();
    assert_eq!(overages, 2);
    // Absurd values are refused rather than wrapped.
    let huge = http
        .post(format!("{}/v1/runs/run_dodge/usage/reserve", w.base))
        .bearer_auth("acme-key")
        .json(&json!({"kind": "model_call", "cost_cents": u64::MAX}))
        .send()
        .await
        .unwrap();
    assert_eq!(huge.status(), 422);
}
