//! `[guards.risk_tiers]`: a capability's tier decides whether a call goes through,
//! needs an approval of the exact action, or is refused; unclassified counts as high.

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;

use contextos_gateway::risk_tiers::{RiskTier, TierMode, TierPolicy};
use contextosd::config::Config;
use serde_json::Value;

use crate::harness::*;

const REFUND: &str = "adp_payments.issue_refund";

fn policy(tier: Option<RiskTier>, mode: TierMode) -> TierPolicy {
    let mut p: TierPolicy = serde_json::from_value(serde_json::json!({})).unwrap();
    p.mode = mode;
    p.capabilities = tier
        .map(|t| BTreeMap::from([(REFUND.to_owned(), t)]))
        .unwrap_or_default();
    p
}

async fn tier_decisions(w: &World) -> Vec<Value> {
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
        .filter(|e| e["kind"] == "risk_tier_decision")
        .map(|e| e["payload"].clone())
        .collect()
}

async fn call(tier: Option<RiskTier>, mode: TierMode, run: &str) -> (World, Value, usize) {
    let w = world_with(&ALL_CONTROLS, 1, |c| c.guards.risk_tiers = Some(policy(tier, mode))).await;
    assert_eq!(admit(&w, &run_body(run, 1200)).await.status(), 201);
    let before = w.provider_calls.load(Ordering::SeqCst);
    let result = dispatch(&w, run, &refund(run, "refund_a", "ord_881", "cus_77", 100)).await;
    let sent = w.provider_calls.load(Ordering::SeqCst) - before;
    (w, result, sent)
}

#[tokio::test]
async fn a_low_tier_call_goes_through_unaudited() {
    let (w, result, sent) = call(Some(RiskTier::Low), TierMode::Enforce, "run_tier_low").await;
    assert_eq!(result["report"]["status"], "completed", "{result}");
    assert_eq!(sent, 1);
    assert_eq!(tier_decisions(&w).await, Vec::<Value>::new());
}

#[tokio::test]
async fn a_prohibited_capability_is_never_sent() {
    let (w, result, sent) = call(Some(RiskTier::Prohibited), TierMode::Enforce, "run_tier_prohibited").await;
    assert_eq!(result["result"]["status"], "blocked", "{result}");
    assert!(
        result["report"]["reason_codes"]
            .to_string()
            .contains("risk_tier_prohibited"),
        "{result}"
    );
    assert_eq!(sent, 0, "nothing sent");
    let d = tier_decisions(&w).await;
    assert_eq!(d.len(), 1);
    assert_eq!(d[0]["tier"], "prohibited");
    assert_eq!(d[0]["tier_source"], "configuration");
    assert_eq!(d[0]["enforced"], true);
}

#[tokio::test]
async fn an_unclassified_capability_needs_an_approval_of_the_exact_action() {
    let (w, result, sent) = call(None, TierMode::Enforce, "run_tier_unclassified").await;
    assert_ne!(result["report"]["status"], "completed", "{result}");
    assert!(
        result["report"]["reason_codes"]
            .to_string()
            .contains("risk_tier_approval_required"),
        "{result}"
    );
    assert_eq!(sent, 0, "not sent before approval");
    let d = tier_decisions(&w).await;
    assert_eq!(d[0]["tier"], "high");
    assert_eq!(d[0]["tier_source"], "unclassified");
}

#[tokio::test]
async fn observing_audits_and_lets_a_prohibited_call_through() {
    let (w, result, sent) = call(Some(RiskTier::Prohibited), TierMode::Observe, "run_tier_observe").await;
    assert_eq!(result["report"]["status"], "completed", "{result}");
    assert_eq!(sent, 1);
    let d = tier_decisions(&w).await;
    assert_eq!(d.len(), 1);
    assert_eq!(d[0]["enforced"], false);
}

#[tokio::test]
async fn tiers_are_parsed_and_unknown_capabilities_refused_at_startup() {
    let (config, _) = world_setup(&ALL_CONTROLS).await;
    let with = |table: &str| Config::parse(&format!("{}\n{table}", config.source));
    let parsed = with("[guards.risk_tiers]\nhigh = \"refuse\"\n[guards.risk_tiers.capabilities]\n\"adp_payments.issue_refund\" = \"limited\"").unwrap();
    let tiers = parsed.guards.risk_tiers.clone().unwrap();
    assert_eq!(tiers.capabilities[REFUND], RiskTier::Limited);
    assert!(
        with("[guards.risk_tiers]\nprohibited = \"allow\"").is_err(),
        "prohibited is not configurable"
    );
    assert!(with("[guards.risk_tiers.capabilities]\n\"x.y\" = \"extreme\"").is_err());
    let mut unknown = config.clone();
    unknown.guards.risk_tiers = Some(policy(None, TierMode::Enforce));
    unknown
        .guards
        .risk_tiers
        .as_mut()
        .unwrap()
        .capabilities
        .insert("adp_infra.delete_volume".into(), RiskTier::High);
    let error = contextosd::runtime::dispatch_setup_from_config(&unknown).err().unwrap();
    assert!(error.contains("adp_infra.delete_volume"), "{error}");
}
