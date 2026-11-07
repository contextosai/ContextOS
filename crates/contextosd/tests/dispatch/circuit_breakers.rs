//! `[[guards.circuit_breakers]]` over HTTP: a breaker stops an agent across runs,
//! revokes it in the kill switch, and shows in metrics.

use contextos_gateway::circuit_breakers::{BreakerCount, BreakerRule, BreakerScope, BreakerTrip};
use contextosd::config::Config;

use crate::harness::*;

#[tokio::test]
async fn a_breaker_stops_the_agent_across_runs_and_revokes_it() {
    let w = world_with(&ALL_CONTROLS, 1, |c| {
        c.guards.circuit_breakers = vec![BreakerRule {
            id: "refund_rate".into(),
            scope: BreakerScope::Agent,
            count: BreakerCount::Effects,
            capabilities: vec!["adp_payments.issue_refund".into()],
            threshold: 1,
            window_seconds: 3600,
            trip: BreakerTrip::Revoke,
        }];
    })
    .await;
    assert_eq!(admit(&w, &run_body("run_a", 1200)).await.status(), 201);
    assert_eq!(admit(&w, &run_body("run_b", 1200)).await.status(), 201);
    let first = dispatch(&w, "run_a", &refund("run_a", "refund_a", "ord_881", "cus_77", 100)).await;
    assert_eq!(first["report"]["status"], "completed", "{first}");
    // Another run of the same agent: the breaker counts across runs.
    let second = dispatch(&w, "run_b", &refund("run_b", "refund_b", "ord_881", "cus_77", 100)).await;
    assert_eq!(
        second["report"]["reason_codes"],
        serde_json::json!(["circuit_open"]),
        "{second}"
    );
    let revocations: serde_json::Value = reqwest::Client::new()
        .get(format!("{}/v1/revocations", w.base))
        .bearer_auth("ops-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        revocations["revoked"][0]["by"], "circuit_breaker:refund_rate",
        "{revocations}"
    );
    let metrics = reqwest::get(format!("{}/metrics", w.base))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(metrics.contains("reason=\"circuit_open\""), "{metrics}");
}

#[tokio::test]
async fn breakers_are_validated_at_startup() {
    let (config, _) = world_setup(&ALL_CONTROLS).await;
    let with = |table: &str| Config::parse(&format!("{}\n{table}", config.source));
    let parsed = with(
        "[[guards.circuit_breakers]]\nid = \"refunds\"\nscope = \"agent\"\ncount = \"effects\"\nthreshold = 50\ntrip = \"revoke\"",
    )
    .unwrap();
    assert_eq!(parsed.guards.circuit_breakers[0].window_seconds, 60);
    let zero =
        with("[[guards.circuit_breakers]]\nid = \"refunds\"\nscope = \"agent\"\ncount = \"effects\"\nthreshold = 0")
            .unwrap_err();
    assert!(zero.to_string().contains("threshold"), "{zero}");
}
