//! A run's declared agent must be one its caller's credential is issued for.

use contextosd::agent_binding::{self, AgentBinding};
use contextosd::auth::hash_api_key;
use serde_json::Value;

use crate::harness::*;

async fn admit(w: &World, key: &str, run_id: &str) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth(key)
        .json(&run_body(run_id, 1200))
        .send()
        .await
        .unwrap()
}

async fn admitted_binding(w: &World, run_id: &str) -> Value {
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
        .map(|e| e["payload"]["agent_binding"].clone())
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
async fn required_binding_admits_only_the_agents_a_credential_is_issued_for() {
    let w = world_with(&ALL_CONTROLS, 1, |c| {
        c.guards.agent_binding = Some(AgentBinding::Required);
        // The orchestrator's key is issued for another agent; a second key for agt_support.
        c.api_keys[0].agent_ids = Some(vec!["agt_billing".into()]);
        let mut support = c.api_keys[0].clone();
        support.key_sha256 = hash_api_key("support-key");
        support.agent_ids = Some(vec!["agt_support".into()]);
        c.api_keys.push(support);
    })
    .await;
    let refused = admit(&w, "acme-key", "run_unbound").await;
    assert_eq!(refused.status(), 403);
    let error: Value = refused.json().await.unwrap();
    assert_eq!(error["error"]["code"], "agent_not_bound");
    assert!(
        metrics(&w)
            .await
            .contains("contextos_agent_binding_mismatches_total{mode=\"required\"} 1\n")
    );

    assert_eq!(admit(&w, "support-key", "run_bound").await.status(), 201);
    let binding = admitted_binding(&w, "run_bound").await;
    assert_eq!(binding["mode"], "required");
    assert_eq!(binding["bound"], true);
    assert_eq!(binding["source"], "api_key");
}

#[tokio::test]
async fn observed_binding_admits_and_counts_an_unbound_agent() {
    let w = world(&ALL_CONTROLS).await;
    assert_eq!(
        w.state.agent_binding,
        AgentBinding::Observe,
        "the default without the enterprise profile"
    );
    assert_eq!(admit(&w, "acme-key", "run_observed").await.status(), 201);
    let binding = admitted_binding(&w, "run_observed").await;
    assert_eq!(binding["mode"], "observe");
    assert_eq!(binding["bound"], false);
    assert!(
        metrics(&w)
            .await
            .contains("contextos_agent_binding_mismatches_total{mode=\"observe\"} 1\n")
    );
}

#[tokio::test]
async fn the_enterprise_profile_requires_every_admitting_credential_to_name_its_agents() {
    let (mut config, _) = world_setup(&ALL_CONTROLS).await;
    assert!(agent_binding::check(&config).is_ok());
    config.support.profiles.push("contextos.enterprise".into());
    assert_eq!(agent_binding::mode(&config), AgentBinding::Required);
    let refused = agent_binding::check(&config).unwrap_err();
    assert!(
        refused.contains("svc_orchestrator") && refused.contains("agent_ids"),
        "{refused}"
    );
    for key in &mut config.api_keys {
        key.agent_ids = Some(vec!["agt_support".into()]);
    }
    assert!(agent_binding::check(&config).is_ok());
    // An explicit setting wins over the profile's default.
    config.guards.agent_binding = Some(AgentBinding::Observe);
    config.api_keys[0].agent_ids = None;
    assert!(agent_binding::check(&config).is_ok());
}
