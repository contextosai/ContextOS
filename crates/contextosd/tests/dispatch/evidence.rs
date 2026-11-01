//! Strict evidence: a decision's gate is not satisfied from the request context.

use contextosd::Config;
use contextosd::evidence_admission::{self, EvidenceMode};
use serde_json::{Value, json};

use crate::harness::*;

async fn admit(w: &World, body: &Value) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(body)
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn strict_evidence_refuses_a_gate_satisfied_from_request_context() {
    let w = world_with(&ALL_CONTROLS, 1, |c| {
        c.guards.evidence = Some(EvidenceMode::Strict);
    })
    .await;
    // The refund decision requires identity_verified, which this request asserts.
    let mut body = run_body("run_asserted", 1200);
    assert_eq!(body["request"]["input"]["context"]["identity_verified"], true);
    let refused = admit(&w, &body).await;
    assert_eq!(refused.status(), 422);
    let error: Value = refused.json().await.unwrap();
    assert_eq!(error["error"]["code"], "evidence_in_request_context");
    assert_eq!(error["error"]["detail"]["requirements"], json!(["identity_verified"]));

    // The same fact as an evidence entry is admitted.
    body["request"]["input"]["context"]
        .as_object_mut()
        .unwrap()
        .remove("identity_verified");
    body["deps"]["evidence"].as_array_mut().unwrap().push(json!({
        "evidence_ref": "idp:session:cus_77", "source_id": "idp", "content": "customer cus_77 verified",
        "integrity": "verified", "freshness": "current", "satisfies": ["identity_verified"],
    }));
    body["run_context"]["run_id"] = json!("run_evidenced");
    body["contract"]["run_id"] = json!("run_evidenced");
    assert_eq!(admit(&w, &body).await.status(), 201);
}

#[tokio::test]
async fn caller_evidence_is_the_default_without_the_enterprise_profile() {
    let w = world(&ALL_CONTROLS).await;
    assert_eq!(w.state.evidence, EvidenceMode::Caller);
    assert_eq!(admit(&w, &run_body("run_caller", 1200)).await.status(), 201);
}

#[tokio::test]
async fn the_enterprise_profile_requires_strict_evidence() {
    let (mut config, _) = world_setup(&ALL_CONTROLS).await;
    config.support.profiles.push("contextos.enterprise".into());
    assert_eq!(evidence_admission::mode(&config), EvidenceMode::Strict);
    assert!(evidence_admission::check(&config).is_ok());
    config.guards.evidence = Some(EvidenceMode::Caller);
    let refused = evidence_admission::check(&config).unwrap_err();
    assert!(refused.contains("requires \"strict\""), "{refused}");

    let text = "[server]\nlisten = \"127.0.0.1:0\"\n[store]\nkind = \"memory\"\n[audit]\nsigning_seed_env = \"S\"\nkey_id = \"k\"\n\
                [support]\nimplementation_id = \"x\"\nimplementation_version = \"0\"\nprofiles = [\"contextos.enterprise\"]\ncontrols = []\n\
                [guards]\nevidence = \"caller\"\n";
    let error = Config::parse(text).unwrap_err().to_string();
    assert!(error.contains("requires \"strict\""), "{error}");
}
