//! Conformance assessment over HTTP: the caller supplies the report and evidence; the
//! deployment supplies its identity, support, registry, clock and trust anchors.

use std::collections::HashMap;
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use contextos_audit::AuditSigner;
use contextos_contract::canonical::sha256_canonical;
use contextos_contract::validation::format_unix_micros;
use contextos_store::{MemoryLog, MemoryStore};
use contextosd::auth::hash_api_key;
use contextosd::{Config, build_state, router};
use serde_json::{Value, json};

fn base_case() -> Value {
    let path = format!(
        "{}/../../conformance/vectors/conformance.json.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut text = String::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_string(&mut text)
        .unwrap();
    let vectors: Value = serde_json::from_str(&text).unwrap();
    vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "base")
        .unwrap()["input"]
        .clone()
}

/// The vector moved to the present: its evidence window spans now, and digests of the
/// report are recomputed.
fn current_case() -> Value {
    let mut input = base_case();
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap();
    let old_digest = input["report_verification"]["report_digest"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut text = input.to_string();
    for (from, offset) in [
        ("2026-10-16T08:00:00Z", -60),
        ("2026-10-16T08:01:00Z", 0),
        ("2026-10-16T09:00:00Z", 3_540),
    ] {
        text = text.replace(from, &format_unix_micros(now + offset * 1_000_000));
    }
    input = serde_json::from_str(&text).unwrap();
    let new_digest =
        sha256_canonical(&json!({"domain": "contextos.conformance_report.v1", "report": input["report"]})).unwrap();
    serde_json::from_str(&input.to_string().replace(&old_digest, &new_digest)).unwrap()
}

async fn start() -> (String, Value) {
    let case = base_case();
    let support = &case["support"];
    let names = |list: &Value, key: &str| -> Vec<String> {
        list.as_array()
            .unwrap()
            .iter()
            .map(|v| v[key].as_str().unwrap().to_owned())
            .collect()
    };
    let mut config = Config::parse(&format!(
        r#"
        [server]
        listen = "127.0.0.1:0"
        [store]
        kind = "memory"
        [audit]
        signing_seed_env = "UNUSED"
        key_id = "audit-test"
        [support]
        implementation_id = "{id}"
        implementation_version = "{version}"
        profiles = []
        controls = []
        [[api_keys]]
        key_sha256 = "{acme}"
        tenant_id = "tenant_acme_prod"
        principal_id = "svc_auditor"
        scopes = ["audit:read"]
        [[api_keys]]
        key_sha256 = "{other}"
        tenant_id = "tenant_other"
        principal_id = "svc_other"
        scopes = ["audit:read"]
        "#,
        id = support["implementation_id"].as_str().unwrap(),
        version = support["implementation_version"].as_str().unwrap(),
        acme = hash_api_key("acme-key"),
        other = hash_api_key("other-key"),
    ))
    .unwrap();
    config.support.profiles = names(&support["supported_profiles"], "profile_id");
    config.support.controls = names(&support["supported_controls"], "control_id");
    config.conformance.trusted_assessors = case["trusted_assessors"].as_array().unwrap().clone();
    config.conformance.trusted_evidence_observers = case["trusted_evidence_observers"].as_array().unwrap().clone();
    let state = build_state(
        &config,
        Arc::new(MemoryStore::new()),
        MemoryLog::new(),
        AuditSigner::from_seed("audit-test", [5; 32]),
        HashMap::new(),
        None,
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, router(state, Duration::from_secs(10)))
            .await
            .unwrap();
    });
    (base, case)
}

fn caller_part(input: &Value) -> Value {
    let scope = &input["scope"];
    json!({"contract": input["contract"], "features": input["features"], "report": input["report"],
        "report_verification": input["report_verification"], "evidence_observations": input["evidence_observations"],
        "scope": {"workflow_id": scope["workflow_id"], "release_refs": scope["release_refs"],
            "environment_ref": scope["environment_ref"], "required_utility_case_ids": scope["required_utility_case_ids"]}})
}

#[tokio::test]
async fn reports_are_assessed_against_the_deployments_trust_anchors() {
    let (base, _) = start().await;
    let http = reqwest::Client::new();
    let assess = |key: &'static str, body: Value| {
        let (http, url) = (http.clone(), format!("{base}/v1/conformance/assess"));
        async move { http.post(url).bearer_auth(key).json(&body).send().await.unwrap() }
    };
    let input = current_case();

    let passed = assess("acme-key", caller_part(&input)).await;
    assert_eq!(passed.status(), 200);
    let passed: Value = passed.json().await.unwrap();
    assert_eq!(passed["outcome"], "passed", "{passed}");

    // The caller cannot bring its own trust anchors or evaluation time.
    let mut forged = caller_part(&input);
    forged["trusted_assessors"] = input["trusted_assessors"].clone();
    assert_eq!(assess("acme-key", forged).await.status(), 422);
    // A report changed after verification no longer matches its verified digest.
    let mut tampered = caller_part(&input);
    tampered["report"]["limitations"] = json!(["added later"]);
    let tampered: Value = assess("acme-key", tampered).await.json().await.unwrap();
    assert_ne!(tampered["outcome"], "passed", "{tampered}");
    // Another tenant has no trust anchors here.
    let other = assess("other-key", caller_part(&input)).await;
    assert_eq!(other.status(), 409);

    let audit: Value = http
        .get(format!("{base}/v1/audit/entries"))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let outcomes: Vec<String> = audit["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e.to_string().contains("conformance_assessed"))
        .map(ToString::to_string)
        .collect();
    assert_eq!(outcomes.len(), 2, "both assessments are audited: {audit}");
    assert!(outcomes[0].contains("\"passed\""), "{}", outcomes[0]);
}
