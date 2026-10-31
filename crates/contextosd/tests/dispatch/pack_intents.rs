//! A run must declare an intent its Context Pack's rules govern, so intent-scoped
//! restrictions cannot be stepped around by declaring another intent.

use contextosd::pack_intents::{self, PackIntents};
use serde_json::{Value, json};

use crate::harness::*;

async fn admit(w: &World, run_id: &str, intent: &str) -> reqwest::Response {
    let mut body = run_body(run_id, 1200);
    body["request"]["input"]["intent"] = json!(intent);
    reqwest::Client::new()
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&body)
        .send()
        .await
        .unwrap()
}

async fn admitted_intent(w: &World, run_id: &str) -> Value {
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
        .find(|e| e["kind"] == "run_admitted" && e["payload"]["run_id"] == run_id)
        .map(|e| e["payload"]["pack_intent"].clone())
        .unwrap()
}

async fn metrics(w: &World) -> String {
    reqwest::get(format!("{}/metrics", w.base))
        .await
        .unwrap()
        .text()
        .await
        .unwrap()
}

#[tokio::test]
async fn required_pack_intents_refuse_an_intent_the_pack_does_not_govern() {
    // The support pack scopes its identity and approval rules to support.refund.
    let w = world_with(&ALL_CONTROLS, 1, |c| {
        c.guards.pack_intents = Some(PackIntents::Required);
    })
    .await;
    let refused = admit(&w, "run_elsewhere", "general.query").await;
    assert_eq!(refused.status(), 422);
    let error: Value = refused.json().await.unwrap();
    assert_eq!(error["error"]["code"], "intent_not_governed");
    assert!(
        metrics(&w)
            .await
            .contains("contextos_pack_intent_mismatches_total{mode=\"required\"} 1\n")
    );

    assert_eq!(admit(&w, "run_refund", "support.refund").await.status(), 201);
    assert_eq!(
        admitted_intent(&w, "run_refund").await,
        json!({"mode": "required", "governed": true})
    );
}

#[tokio::test]
async fn observed_pack_intents_admit_and_count_an_ungoverned_intent() {
    let w = world(&ALL_CONTROLS).await;
    assert_eq!(
        w.state.pack_intents,
        PackIntents::Observe,
        "the default without the enterprise profile"
    );
    assert_eq!(admit(&w, "run_observed", "general.query").await.status(), 201);
    assert_eq!(
        admitted_intent(&w, "run_observed").await,
        json!({"mode": "observe", "governed": false})
    );
    assert!(
        metrics(&w)
            .await
            .contains("contextos_pack_intent_mismatches_total{mode=\"observe\"} 1\n")
    );
}

#[tokio::test]
async fn the_enterprise_profile_requires_governed_intents_unless_set_explicitly() {
    let (mut config, _) = world_setup(&ALL_CONTROLS).await;
    assert_eq!(pack_intents::mode(&config), PackIntents::Observe);
    config.support.profiles.push("contextos.enterprise".into());
    assert_eq!(pack_intents::mode(&config), PackIntents::Required);
    config.guards.pack_intents = Some(PackIntents::Off);
    assert_eq!(pack_intents::mode(&config), PackIntents::Off);
}
