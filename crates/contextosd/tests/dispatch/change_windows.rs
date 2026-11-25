//! `[[guards.change_windows]]`: inside a freeze a capability's calls are refused (or
//! need an approval of the exact action), decided on the server clock and audited.

use std::sync::atomic::Ordering;

use contextos_gateway::change_windows::ChangeWindow;
use contextosd::config::Config;
use serde_json::{Value, json};

use crate::harness::*;

fn window(v: Value) -> ChangeWindow {
    serde_json::from_value(v).unwrap()
}

/// A freeze that contains every plausible test run.
fn now_frozen(extra: Value) -> ChangeWindow {
    let mut v = json!({"name": "freeze", "capabilities": ["adp_payments.issue_refund"],
        "from": "2000-01-01T00:00:00Z", "until": "2999-01-01T00:00:00Z"});
    v.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
    window(v)
}

async fn decisions(w: &World) -> Vec<Value> {
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
        .filter(|e| e["kind"] == "change_window_decision")
        .map(|e| e["payload"].clone())
        .collect()
}

async fn call(windows: Vec<ChangeWindow>, run: &str) -> (World, Value, usize) {
    let w = world_with(&ALL_CONTROLS, 1, |c| c.guards.change_windows = windows).await;
    assert_eq!(admit(&w, &run_body(run, 1200)).await.status(), 201);
    let before = w.provider_calls.load(Ordering::SeqCst);
    let result = dispatch(&w, run, &refund(run, "refund_a", "ord_881", "cus_77", 100)).await;
    let sent = w.provider_calls.load(Ordering::SeqCst) - before;
    (w, result, sent)
}

#[tokio::test]
async fn a_call_inside_a_freeze_is_refused_and_the_decision_time_recorded() {
    let (w, result, sent) = call(vec![now_frozen(json!({}))], "run_freeze").await;
    assert_eq!(result["result"]["status"], "blocked", "{result}");
    assert!(
        result["report"]["reason_codes"]
            .to_string()
            .contains("change_window_closed"),
        "{result}"
    );
    assert_eq!(sent, 0, "nothing sent");
    let d = decisions(&w).await;
    assert_eq!(d.len(), 1);
    assert_eq!(d[0]["windows"][0]["name"], "freeze");
    assert_eq!(d[0]["windows"][0]["enforced"], true);
    assert!(
        d[0]["decided_at"].as_str().is_some_and(|t| t.starts_with("20")),
        "{}",
        d[0]
    );
}

#[tokio::test]
async fn an_approval_window_holds_the_call_for_an_approval() {
    let (_, result, sent) = call(vec![now_frozen(json!({"action": "approval"}))], "run_window_ask").await;
    assert_ne!(result["report"]["status"], "completed", "{result}");
    assert!(
        result["report"]["reason_codes"]
            .to_string()
            .contains("change_window_approval_required"),
        "{result}"
    );
    assert_eq!(sent, 0);
}

#[tokio::test]
async fn outside_every_window_and_while_observing_the_call_goes_through() {
    let past = window(json!({"name": "last year", "capabilities": ["*"],
        "from": "2001-01-01T00:00:00Z", "until": "2001-01-02T00:00:00Z"}));
    let (w, result, sent) = call(vec![past], "run_window_past").await;
    assert_eq!(result["report"]["status"], "completed", "{result}");
    assert_eq!(sent, 1);
    assert_eq!(decisions(&w).await, Vec::<Value>::new());

    let (w, result, sent) = call(vec![now_frozen(json!({"observe": true}))], "run_window_observe").await;
    assert_eq!(result["report"]["status"], "completed", "{result}");
    assert_eq!(sent, 1);
    assert_eq!(decisions(&w).await[0]["windows"][0]["enforced"], false);
}

#[tokio::test]
async fn invalid_or_unknown_windows_refuse_startup() {
    let (config, _) = world_setup(&ALL_CONTROLS).await;
    let with = |table: &str| Config::parse(&format!("{}\n{table}", config.source));
    assert!(with("[[guards.change_windows]]\nname = \"n\"\ncapabilities = [\"*\"]\nstart = \"18:00\"\nend = \"08:00\"\nutc_offset = \"+05:30\"").is_ok());
    assert!(
        with("[[guards.change_windows]]\nname = \"n\"\ncapabilities = [\"*\"]\nfrom = \"2026-12-20T00:00:00Z\"")
            .is_err()
    );
    let mut unknown = config.clone();
    unknown.guards.change_windows = vec![window(json!({"name": "infra", "capabilities": ["adp_infra.deploy"],
        "start": "18:00", "end": "08:00"}))];
    let error = contextosd::runtime::dispatch_setup_from_config(&unknown).err().unwrap();
    assert!(error.contains("adp_infra.deploy"), "{error}");
}
