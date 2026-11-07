//! `[guards.information_flow]`: what a run's agent has read gates its later effects,
//! with every decision citing the flow policy the run was admitted under.

use contextos_gateway::information_flow::{FlowPolicy, FlowVerdict};
use contextosd::config::Config;

use crate::harness::*;

#[tokio::test]
async fn after_untrusted_output_an_effect_is_refused_and_its_decision_cites_the_policy() {
    let w = world_with(&ALL_CONTROLS, 1, |c| {
        c.guards.information_flow = Some(FlowPolicy {
            untrusted_effects: FlowVerdict::Deny,
            ..FlowPolicy::default()
        });
    })
    .await;
    assert_eq!(admit(&w, &run_body("run_flow", 1200)).await.status(), 201);
    // The first effect: the run has read nothing yet, and the remote constraint
    // service's observations bind the same policy references as the action.
    let first = dispatch(
        &w,
        "run_flow",
        &refund("run_flow", "refund_a", "ord_881", "cus_77", 100),
    )
    .await;
    assert_eq!(first["report"]["status"], "completed", "{first}");
    // Its output was untrusted: the next effect is refused.
    let second = dispatch(
        &w,
        "run_flow",
        &refund("run_flow", "refund_b", "ord_881", "cus_77", 200),
    )
    .await;
    assert_ne!(second["report"]["status"], "completed", "{second}");
    let reasons = second["report"]["reason_codes"].to_string();
    assert!(reasons.contains("flow_untrusted_effect"), "{second}");
    let entries: serde_json::Value = reqwest::Client::new()
        .get(format!("{}/v1/audit/entries?from=1&limit=1000", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let kinds = |kind: &str| {
        entries["entries"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["kind"] == kind)
            .map(|e| e["payload"].to_string())
            .collect::<Vec<_>>()
    };
    let decisions = kinds("authorization_decision");
    assert_eq!(decisions.len(), 2);
    assert!(
        decisions.iter().all(|d| d.contains("runtime_guard_policy")),
        "{decisions:?}"
    );
    assert_eq!(kinds("information_flow_decision").len(), 1);
}

#[tokio::test]
async fn the_policy_is_parsed_from_the_guards_table() {
    let (config, _) = world_setup(&ALL_CONTROLS).await;
    let with = |table: &str| Config::parse(&format!("{}\n{table}", config.source));
    let parsed = with(
        "[guards.information_flow]\nuntrusted_effects = \"deny\"\nclassified_egress = \"ask\"\nrule_of_two = false",
    )
    .unwrap();
    let policy = parsed.guards.information_flow.unwrap();
    assert_eq!(policy.untrusted_effects, FlowVerdict::Deny);
    assert_eq!(policy.classified_egress, FlowVerdict::Ask);
    assert!(!policy.rule_of_two);
    assert!(with("[guards.information_flow]\nuntrusted_effects = \"maybe\"").is_err());
}
