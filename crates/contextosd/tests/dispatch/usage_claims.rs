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
