//! Deployment and startup requirements.

use std::sync::Arc;
use std::time::Duration;

use contextos_store::{MemoryLog, MemoryStore};
use contextosd::runtime::dispatch_setup_from_config;
use contextosd::{Config, router};
use serde_json::{Value, json};

use crate::harness::*;

#[tokio::test]
async fn deployment_without_effect_controls_cannot_admit_effectful_runs() {
    let w = world(&ALL_CONTROLS[..5]).await;
    let response = reqwest::Client::new()
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_x", 1200))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 422);
    let error: Value = response.json().await.unwrap();
    assert_eq!(error["error"]["code"], "contract_rejected");
    assert!(error["error"]["detail"].to_string().contains("effects.reconciled"));
}

#[tokio::test]
async fn startup_can_require_schemas_on_effectful_tools() {
    let (mut config, _) = world_setup(&ALL_CONTROLS).await;
    assert!(dispatch_setup_from_config(&config).is_ok(), "off by default");
    config.guards.require_tool_schemas = true;
    let refused = dispatch_setup_from_config(&config).err().unwrap();
    assert!(refused.contains("needs input_schema and output_schema"), "{refused}");

    // With an output schema next to the input schema, it starts.
    let path = &config.capabilities[0];
    let mut manifest: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    manifest["output_schema"] = json!({"type": "object", "properties": {"refund_id": {"type": "string"}}});
    std::fs::write(path, manifest.to_string()).unwrap();
    assert!(dispatch_setup_from_config(&config).is_ok());
}

#[tokio::test]
async fn production_requires_pins_and_a_stated_role() {
    let (mut config, _) = world_setup(&ALL_CONTROLS).await;
    // Development defaults: neither required.
    assert_eq!(config.required_release_refs(), [] as [String; 0]);
    assert!(!config.require_user_role());
    // Production defaults: both, unless opted out explicitly.
    config.server.mode = contextosd::config::Mode::Production;
    assert_eq!(config.required_release_refs(), ["model_profile", "evaluator_suite"]);
    assert!(config.require_user_role());
    let floors = config
        .completion_score_floors()
        .expect("judged before completion in production");
    assert_eq!((floors.policy_floor, floors.safety_floor), (1.0, 0.9));
    config.guards.required_release_refs = Some(vec![]);
    config.guards.require_user_role = Some(false);
    config.guards.completion_requires_scores = Some(contextosd::config::CompletionScores::Enabled(false));
    assert!(config.required_release_refs().is_empty() && !config.require_user_role());
    assert!(config.completion_score_floors().is_none(), "opted out explicitly");

    // `true`, `false` and explicit floors all parse.
    let parsed = |guards: &str| {
        Config::parse(&format!(
            "[server]\nlisten = \"127.0.0.1:0\"\n[store]\nkind = \"memory\"\n[audit]\nsigning_seed_env = \"X\"\nkey_id = \"k\"\n\
             [support]\nimplementation_id = \"x\"\nimplementation_version = \"1\"\nprofiles = []\ncontrols = []\n[guards]\n{guards}\n"
        ))
        .unwrap()
        .completion_score_floors()
        .map(|f| (f.policy_floor, f.safety_floor))
    };
    assert_eq!(parsed("completion_requires_scores = true"), Some((1.0, 0.9)));
    assert_eq!(parsed("completion_requires_scores = false"), None);
    assert_eq!(
        parsed("completion_requires_scores = { policy_floor = 0.8, safety_floor = 0.7 }"),
        Some((0.8, 0.7))
    );

    // Admission refuses a run whose user claims state no role.
    let (mut config, _) = world_setup(&ALL_CONTROLS).await;
    config.guards.require_user_role = Some(true);
    let state = replica_state(&config, Arc::new(MemoryStore::new()), Arc::new(MemoryLog::new()));
    let base = serve(router(state, Duration::from_secs(10))).await;
    let plain = reqwest::Client::new();
    let mut roleless = run_body("run_roleless", 1200);
    roleless["run_context"]["user"].as_object_mut().unwrap().remove("role");
    let refused = plain
        .post(format!("{base}/v1/runs"))
        .bearer_auth("acme-key")
        .json(&roleless)
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 422);
    assert_eq!(
        refused.json::<Value>().await.unwrap()["error"]["code"],
        "user_role_missing"
    );
    let mut invisible = run_body("run_invisible_role", 1200);
    invisible["run_context"]["user"]["role"] = json!("\u{200B}");
    let refused = plain
        .post(format!("{base}/v1/runs"))
        .bearer_auth("acme-key")
        .json(&invisible)
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 422, "an invisible character is not a role");
    let admitted = plain
        .post(format!("{base}/v1/runs"))
        .bearer_auth("acme-key")
        .json(&run_body("run_with_role", 1200))
        .send()
        .await
        .unwrap();
    assert_eq!(admitted.status(), 201, "{}", admitted.text().await.unwrap());
}

#[tokio::test]
async fn effectful_http_capabilities_need_a_reported_state_contract() {
    let (mut config, _) = world_setup(&ALL_CONTROLS).await;
    let path = config.capabilities[0].clone();
    let mut manifest: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let adapter_id = manifest["adapter_id"].as_str().unwrap().to_owned();
    let adapter = config.adapters.iter_mut().find(|a| a.id == adapter_id).unwrap();
    adapter.kind = contextosd::config::AdapterKind::Http;
    // An HTTP success status cannot confirm the refund on its own.
    let refused = dispatch_setup_from_config(&config).err().unwrap();
    assert!(refused.contains("needs recovery.completion"), "{refused}");

    manifest["recovery"]["completion"] = json!({"status_tool": "refund_status", "state_pointer": "/status",
        "confirmed": ["succeeded"], "not_applied": ["canceled"]});
    std::fs::write(&path, manifest.to_string()).unwrap();
    assert!(dispatch_setup_from_config(&config).is_ok());
}
