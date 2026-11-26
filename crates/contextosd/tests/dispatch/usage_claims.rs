//! Metering gateways claim model-call reservations before forwarding a call, and every
//! refused reservation, claim and settlement is audited for the governance plane.

use serde_json::{Value, json};

use crate::harness::*;

struct Calls {
    base: String,
    run: &'static str,
    executor: reqwest::Client,
    plain: reqwest::Client,
}

impl Calls {
    async fn post(&self, key: &str, action: &str, body: Value) -> (u16, Value) {
        let client = if key == "acme-key" { &self.executor } else { &self.plain };
        let response = client
            .post(format!("{}/v1/runs/{}/usage/{action}", self.base, self.run))
            .bearer_auth(key)
            .json(&body)
            .send()
            .await
            .unwrap();
        let status = response.status().as_u16();
        (status, response.json().await.unwrap_or(Value::Null))
    }

    async fn reserve(&self, body: Value) -> String {
        let (status, reply) = self.post("acme-key", "reserve", body).await;
        assert_eq!(status, 201, "{reply}");
        reply["reservation_id"].as_str().unwrap().to_owned()
    }

    async fn audit(&self, kind: &str) -> Vec<Value> {
        let audit: Value = self
            .plain
            .get(format!("{}/v1/audit/entries?from=1&limit=1000", self.base))
            .bearer_auth("acme-key")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        audit["entries"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["kind"] == kind)
            .map(|e| e["payload"].clone())
            .collect()
    }
}

async fn admitted(w: &World, run: &'static str) -> Calls {
    let plain = reqwest::Client::new();
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
    Calls {
        base: w.base.clone(),
        run,
        executor: executor_client(admitted["executor_generation"].as_u64().unwrap()),
        plain,
    }
}

#[tokio::test]
async fn a_reservation_covers_one_metered_call() {
    let w = world(&ALL_CONTROLS).await;
    let calls = admitted(&w, "run_claimed").await;
    let reservation = calls
        .reserve(json!({"kind": "model_call", "tokens": 2000, "cost_cents": 3}))
        .await;

    // Only an independent meter claims; the executor cannot.
    let (status, _) = calls
        .post("acme-key", "claim", json!({"reservation_id": reservation}))
        .await;
    assert_eq!(status, 403);
    // The claim returns what the reservation covers.
    let (status, claimed) = calls
        .post(
            "meter-key",
            "claim",
            json!({"reservation_id": reservation, "model": "gpt-test"}),
        )
        .await;
    assert_eq!(status, 200, "{claimed}");
    assert_eq!(
        claimed,
        json!({"reservation_id": reservation, "tokens": 2000, "cost_cents": 3})
    );
    // A second call on the same reservation is refused, by any meter.
    for key in ["meter-key", "meter-b-key"] {
        let (status, refused) = calls.post(key, "claim", json!({"reservation_id": reservation})).await;
        assert_eq!(
            (status, &refused["error"]["code"]),
            (409, &json!("reservation_claimed"))
        );
    }
    // Forged ids, replans and malformed models are refused before any model call.
    let (status, _) = calls
        .post("meter-key", "claim", json!({"reservation_id": "usage:forged"}))
        .await;
    assert_eq!(status, 404);
    let replan = calls.reserve(json!({"kind": "replan"})).await;
    let (status, _) = calls
        .post("meter-key", "claim", json!({"reservation_id": replan}))
        .await;
    assert_eq!(status, 404);
    let (status, _) = calls
        .post(
            "meter-key",
            "claim",
            json!({"reservation_id": replan, "model": " padded"}),
        )
        .await;
    assert_eq!(status, 422);

    // Only the claiming meter settles it as measured.
    let (status, _) = calls
        .post(
            "meter-b-key",
            "settle",
            json!({"reservation_id": reservation, "tokens": 10}),
        )
        .await;
    assert_eq!(status, 409);
    let (status, settled) = calls
        .post(
            "meter-key",
            "settle",
            json!({"reservation_id": reservation, "tokens": 700, "cost_cents": 2, "model": "gpt-test"}),
        )
        .await;
    assert_eq!(status, 200, "{settled}");
    assert_eq!(settled["charged"]["tokens"], 700);
    // Settled reservations cannot be claimed again.
    let (status, _) = calls
        .post("meter-key", "claim", json!({"reservation_id": reservation}))
        .await;
    assert_eq!(status, 404);
    // An unclaimed reservation still settles as measured (claiming is how gateways
    // refuse reuse up front, not a precondition of settlement).
    let unclaimed = calls.reserve(json!({"kind": "model_call", "tokens": 1500})).await;
    let (status, _) = calls
        .post(
            "meter-b-key",
            "settle",
            json!({"reservation_id": unclaimed, "tokens": 100}),
        )
        .await;
    assert_eq!(status, 200);
    // The executor settles its replan in full.
    let (status, _) = calls
        .post("acme-key", "settle", json!({"reservation_id": replan}))
        .await;
    assert_eq!(status, 200);

    assert_eq!(
        calls.audit("usage_claimed").await,
        vec![
            json!({"run_id": "run_claimed", "reservation_id": reservation, "reporter": "svc_llm_gateway",
            "model": "gpt-test"})
        ]
    );
    let settled = calls.audit("usage_settled").await;
    assert_eq!(settled.len(), 3, "{settled:?}");
    assert_eq!(
        settled[0],
        json!({"run_id": "run_claimed", "reservation_id": reservation, "reporter": "svc_llm_gateway",
            "verified": true, "model": "gpt-test",
            "charged": {"tokens": 700, "tool_calls": 0, "replans": 0, "cost_units": 200},
            "measured": {"tokens": 700, "cost_units": 200}})
    );
    assert_eq!(settled[1]["reporter"], "svc_llm_gateway_b");
    assert_eq!(settled[1]["model"], Value::Null);
    assert_eq!(
        (
            &settled[2]["verified"],
            &settled[2]["measured"],
            &settled[2]["charged"]["replans"]
        ),
        (&json!(false), &Value::Null, &json!(1))
    );
}

#[tokio::test]
async fn refused_reservations_are_audited() {
    let w = world(&ALL_CONTROLS).await;
    let calls = admitted(&w, "run_refused").await;
    // The run's budget is 10,000 tokens.
    let (status, _) = calls
        .post(
            "acme-key",
            "reserve",
            json!({"kind": "model_call", "tokens": 20_000, "cost_cents": 1}),
        )
        .await;
    assert_eq!(status, 409);
    let open = calls.reserve(json!({"kind": "model_call", "tokens": 1000})).await;
    let operator = reqwest::Client::new();
    let revoked = operator
        .post(format!("{}/v1/revocations", w.base))
        .bearer_auth("ops-key")
        .json(&json!({"kind": "tenant", "target": TENANT, "reason": "incident 4711"}))
        .send()
        .await
        .unwrap();
    assert_eq!(revoked.status(), 200);
    // A revoked run reserves nothing and its open reservations cannot be claimed.
    let (status, _) = calls.post("acme-key", "reserve", json!({"kind": "replan"})).await;
    assert_eq!(status, 403);
    let (status, refused) = calls.post("meter-key", "claim", json!({"reservation_id": open})).await;
    assert_eq!((status, &refused["error"]["code"]), (403, &json!("revoked")));

    let refusals = calls.audit("usage_refused").await;
    assert_eq!(refusals.len(), 2, "{refusals:?}");
    assert_eq!(
        (
            &refusals[0]["run_id"],
            &refusals[0]["kind"],
            &refusals[0]["tokens"],
            &refusals[0]["cost_cents"]
        ),
        (&json!("run_refused"), &json!("model_call"), &json!(20_000), &json!(1))
    );
    assert_ne!(refusals[0]["reason_codes"], json!([]));
    assert_eq!(
        refusals[1],
        json!({"run_id": "run_refused", "kind": "replan", "tokens": 0, "cost_cents": 0,
            "reason_codes": ["revoked"]})
    );
}

#[tokio::test]
async fn only_allowed_models_are_pinned_or_called() {
    let w = world_with(&ALL_CONTROLS, 1, |c| {
        c.guards.models = Some(
            serde_json::from_value(json!({"allowed": ["gpt-test", "claude-sonnet-5-5"],
            "agents": {"agt_support": ["gpt-test"]}}))
            .unwrap(),
        );
    })
    .await;
    // A run pinning a model its agent may not use is refused at admission.
    let mut pinned = run_body("run_pinned", 1200);
    pinned["contract"]["release_refs"].as_array_mut().unwrap().push(
        json!({"artifact_type": "model_profile", "artifact_id": "claude-sonnet-5-5", "version": "1",
            "sha256": format!("sha256:{}", "cd".repeat(32))}),
    );
    let refused = admit(&w, &pinned).await;
    assert_eq!(refused.status(), 403);
    let refused: Value = refused.json().await.unwrap();
    assert_eq!(refused["error"]["code"], "model_not_allowed");

    let calls = admitted(&w, "run_models").await;
    let reservation = calls
        .reserve(json!({"kind": "model_call", "tokens": 2000, "cost_cents": 3}))
        .await;
    for model in [json!("claude-sonnet-5-5"), Value::Null] {
        let (status, body) = calls
            .post(
                "meter-key",
                "claim",
                json!({"reservation_id": reservation, "model": model}),
            )
            .await;
        assert_eq!(
            (status, body["error"]["code"].as_str()),
            (403, Some("model_not_allowed")),
            "{model}: {body}"
        );
    }
    let refusals = calls.audit("usage_refused").await;
    assert_eq!(refusals.len(), 2);
    assert_eq!(refusals[0]["reason_codes"], json!(["model_not_allowed"]));
    let (status, body) = calls
        .post(
            "meter-key",
            "claim",
            json!({"reservation_id": reservation, "model": "gpt-test@2026-11"}),
        )
        .await;
    assert_eq!(status, 200, "{body}");
}

#[tokio::test]
async fn a_usage_ceiling_is_shared_by_every_run_of_an_agent() {
    let w = world_with(&ALL_CONTROLS, 1, |c| {
        c.guards.usage_ceilings = serde_json::from_value(json!([{"id": "agent-tokens", "resource": "tokens",
            "per": "agent", "limit": 5000, "window_seconds": 3600}]))
        .unwrap();
    })
    .await;
    let first = admitted(&w, "run_ceiling_a").await;
    let second = admitted(&w, "run_ceiling_b").await;
    let call = json!({"kind": "model_call", "tokens": 2000, "cost_cents": 1});
    let a = first.reserve(call.clone()).await;
    second.reserve(call.clone()).await;
    // Each run's own budget has room; the agent's shared ceiling does not.
    let (status, body) = second.post("acme-key", "reserve", call.clone()).await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (409, Some("budget_exhausted")),
        "{body}"
    );
    assert_eq!(body["error"]["detail"], json!(["usage_ceiling_reached:agent-tokens"]));
    let refusals = second.audit("usage_refused").await;
    assert_eq!(
        refusals[0]["reason_codes"],
        json!(["usage_ceiling_reached:agent-tokens"])
    );
    // Settling commits the held amount: it still counts against the ceiling.
    let (status, body) = first.post("acme-key", "settle", json!({"reservation_id": a})).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(first.post("acme-key", "reserve", call.clone()).await.0, 409);
    // Replans are not model usage.
    assert_eq!(
        first.post("acme-key", "reserve", json!({"kind": "replan"})).await.0,
        201
    );
}

#[tokio::test]
async fn concurrent_runs_never_pass_a_usage_ceiling_together() {
    let w = world_with(&ALL_CONTROLS, 1, |c| {
        c.guards.usage_ceilings = serde_json::from_value(json!([{"id": "tenant-spend", "resource": "cost_cents",
            "per": "tenant", "limit": 50, "window_seconds": 86400}]))
        .unwrap();
    })
    .await;
    let ids = [
        "run_c0", "run_c1", "run_c2", "run_c3", "run_c4", "run_c5", "run_c6", "run_c7", "run_c8", "run_c9",
    ];
    let mut runs = Vec::new();
    for run in ids {
        runs.push(admitted(&w, run).await);
    }
    let mut tasks = tokio::task::JoinSet::new();
    for calls in runs {
        tasks.spawn(async move {
            calls
                .post(
                    "acme-key",
                    "reserve",
                    json!({"kind": "model_call", "tokens": 100, "cost_cents": 10}),
                )
                .await
        });
    }
    let statuses = tasks.join_all().await;
    let admitted = statuses.iter().filter(|(s, _)| *s == 201).count();
    assert_eq!(admitted, 5, "{statuses:?}");
    assert!(statuses.iter().all(|(s, _)| *s == 201 || *s == 409), "{statuses:?}");
}
