//! The environment guard: a gateway serving staging refuses effects aimed at production.

use std::sync::atomic::Ordering;

use contextos_gateway::environment_guard::{EnvironmentMode, EnvironmentPolicy, TargetRule, Unmatched};
use serde_json::{Value, json};

use crate::harness::*;

fn policy(mode: EnvironmentMode) -> EnvironmentPolicy {
    EnvironmentPolicy {
        current: "staging".into(),
        mode,
        targets: vec![TargetRule {
            capabilities: vec!["adp_payments.issue_refund".into()],
            environment: None,
            pointer: Some("/order_id".into()),
            prefixes: [
                ("ord_".to_owned(), "production".to_owned()),
                ("stg_".to_owned(), "staging".to_owned()),
            ]
            .into_iter()
            .collect(),
            unmatched: Unmatched::Refuse,
        }],
    }
}

async fn admitted(w: &World, run_id: &str) {
    assert_eq!(admit(w, &run_body(run_id, 1200)).await.status(), 201);
}

async fn audited(w: &World, kind: &str) -> Vec<Value> {
    let entries: Value = reqwest::Client::new()
        .get(format!("{}/v1/audit/entries?from=1&limit=1000", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    entries["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["kind"] == kind)
        .map(|e| e["payload"].clone())
        .collect()
}

#[tokio::test]
async fn an_effect_aimed_at_another_environment_is_refused() {
    let w = world_with(&ALL_CONTROLS, 1, |c| {
        c.guards.environments = Some(policy(EnvironmentMode::Required));
    })
    .await;
    admitted(&w, "run_env").await;
    let before = w.provider_calls.load(Ordering::SeqCst);
    let call = dispatch(&w, "run_env", &tool_call("run_env", "tc_env", 120_000)).await;
    assert_eq!(call["result"]["status"], "blocked", "{call}");
    assert_eq!(call["report"]["reason_codes"], json!(["environment_mismatch"]));
    assert_eq!(w.provider_calls.load(Ordering::SeqCst), before, "nothing sent");
    let refusals = audited(&w, "environment_refusal").await;
    assert_eq!(refusals.len(), 1);
    assert_eq!(refusals[0]["target_environment"], "production");
    assert_eq!(refusals[0]["gateway_environment"], "staging");
    assert_eq!(refusals[0]["enforced"], true);
}

#[tokio::test]
async fn observing_audits_and_lets_the_call_through() {
    let w = world_with(&ALL_CONTROLS, 1, |c| {
        c.guards.environments = Some(policy(EnvironmentMode::Observe));
    })
    .await;
    admitted(&w, "run_env_observe").await;
    let call = dispatch(&w, "run_env_observe", &tool_call("run_env_observe", "tc_env", 120_000)).await;
    assert_eq!(call["result"]["status"], "completed", "{call}");
    let refusals = audited(&w, "environment_refusal").await;
    assert_eq!(refusals.len(), 1);
    assert_eq!(refusals[0]["enforced"], false);
}

#[tokio::test]
async fn a_rule_naming_an_unknown_capability_is_refused_at_startup() {
    let (mut config, _) = world_setup(&ALL_CONTROLS).await;
    let mut unknown = policy(EnvironmentMode::Required);
    unknown.targets[0].capabilities = vec!["adp_infra.delete_volume".into()];
    config.guards.environments = Some(unknown);
    let error = contextosd::runtime::dispatch_setup_from_config(&config).err().unwrap();
    assert!(error.contains("adp_infra.delete_volume"), "{error}");
}
