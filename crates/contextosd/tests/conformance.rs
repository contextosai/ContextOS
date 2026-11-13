//! Conformance assessment over HTTP: the caller supplies the report and evidence; the
//! deployment supplies its identity, support, registry, clock and trust anchors.

use std::collections::HashMap;
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
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
    let signers = |principals: &Value| -> Vec<contextosd::attest::TrustedSigner> {
        principals
            .as_array()
            .unwrap()
            .iter()
            .map(|p| contextosd::attest::TrustedSigner {
                principal: p.clone(),
                public_key: base64::engine::general_purpose::STANDARD.encode(signing_key().verifying_key().as_bytes()),
            })
            .collect()
    };
    config.conformance.trusted_assessors = signers(&case["trusted_assessors"]);
    config.conformance.trusted_evidence_observers = signers(&case["trusted_evidence_observers"]);
    // The suite this deployment accepts for the vector's workflow, pinned independently
    // of the report, with the cases it must show passed.
    config.conformance.accepted_suites = vec![
        serde_json::from_value(json!({
        "tenant_id": "tenant_acme_prod", "workflow_id": case["report"]["workflow_id"],
        "suite": case["report"]["suite_ref"],
        "required_case_ids": ["identity.authenticated.denied", "owner_scheduling.useful"],
        "optional_failures": "block"}))
        .unwrap(),
    ];
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

/// The vector's assessor and observer (one principal) hold this key.
fn signing_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[9; 32])
}

fn sign(domain: &str, attested: &Value) -> Value {
    use ed25519_dalek::Signer as _;
    let signature = signing_key().sign(contextosd::attest::message(domain, attested).as_bytes());
    json!(base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()))
}

/// The caller's part of an assessment, with every attestation signed.
fn caller_part(input: &Value) -> Value {
    use contextosd::attest::{OBSERVATION_DOMAIN, REPORT_DOMAIN, VERIFICATION_DOMAIN};
    let scope = &input["scope"];
    let attested_report =
        json!({"report": input["report"], "contract": input["contract"], "features": input["features"]});
    json!({"contract": input["contract"], "features": input["features"], "report": input["report"],
        "report_verification": input["report_verification"], "evidence_observations": input["evidence_observations"],
        "scope": {"workflow_id": scope["workflow_id"], "release_refs": scope["release_refs"],
            "environment_ref": scope["environment_ref"], "required_utility_case_ids": scope["required_utility_case_ids"]},
        "report_signature": sign(REPORT_DOMAIN, &attested_report),
        "verification_signature": sign(VERIFICATION_DOMAIN, &input["report_verification"]),
        "evidence_signatures": input["evidence_observations"].as_array().unwrap().iter()
            .map(|o| sign(OBSERVATION_DOMAIN, o)).collect::<Vec<_>>()})
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
    assert_eq!(passed["acceptance"]["status"], "accepted", "{passed}");
    assert_eq!(passed["acceptance"]["reasons"], json!([]));

    // The caller cannot bring its own trust anchors or evaluation time.
    let mut forged = caller_part(&input);
    forged["trusted_assessors"] = input["trusted_assessors"].clone();
    assert_eq!(assess("acme-key", forged).await.status(), 422);
    // Caller-asserted verification is not accepted: attestations must be signed.
    let mut unsigned = caller_part(&input);
    unsigned["verification_signature"] = json!("AAAA");
    let refused = assess("acme-key", unsigned).await;
    assert_eq!(refused.status(), 422);
    assert_eq!(
        refused.json::<Value>().await.unwrap()["error"]["detail"],
        json!(["report_verification"])
    );
    // The report's signature binds the contract: a weaker contract cannot be swapped in.
    let mut swapped = caller_part(&input);
    swapped["contract"]["profiles"] = json!([]);
    let refused = assess("acme-key", swapped).await;
    let status = refused.status();
    let refused: Value = refused.json().await.unwrap();
    assert_eq!(status, 422, "{refused}");
    assert_eq!(refused["error"]["detail"], json!(["report"]));
    // A report changed after verification (re-signed by the assessor, but no longer the
    // verified digest) does not pass.
    let mut tampered_input = input.clone();
    tampered_input["report"]["limitations"] = json!(["added later"]);
    let tampered: Value = assess("acme-key", caller_part(&tampered_input))
        .await
        .json()
        .await
        .unwrap();
    assert_ne!(tampered["outcome"], "passed", "{tampered}");
    assert_eq!(tampered["acceptance"]["status"], "not_accepted", "{tampered}");
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
    assert!(outcomes[0].contains("\"accepted\""), "{}", outcomes[0]);
}

#[test]
fn suite_policies_state_their_optional_failure_rule_and_cases() {
    let base = r#"
        [server]
        listen = "127.0.0.1:0"
        [store]
        kind = "memory"
        [audit]
        signing_seed_env = "UNUSED"
        key_id = "audit-test"
        [support]
        implementation_id = "impl"
        implementation_version = "1"
        profiles = []
        controls = []
        [[conformance.accepted_suites]]
        tenant_id = "tenant_a"
        workflow_id = "support.refund"
        suite = { artifact_type = "conformance_suite", artifact_id = "refunds", version = "3", sha256 = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
        "#;
    let parse = |extra: &str| {
        Config::parse(&format!("{base}{extra}"))
            .map(|_| ())
            .map_err(|e| e.to_string())
    };
    assert!(parse("required_case_ids = [\"refund.useful\"]\noptional_failures = \"disclose\"\n").is_ok());
    // The optional-failure rule is stated, never defaulted.
    assert!(parse("required_case_ids = [\"refund.useful\"]\n").is_err());
    let empty = parse("required_case_ids = []\noptional_failures = \"block\"\n").unwrap_err();
    assert!(empty.contains("required_case_ids is empty"), "{empty}");
    let repeated = parse("required_case_ids = [\"a\", \"a\"]\noptional_failures = \"block\"\n").unwrap_err();
    assert!(repeated.contains("repeated"), "{repeated}");
    let unpinned = Config::parse(&format!(
        "{}required_case_ids = [\"a\"]\noptional_failures = \"block\"\n",
        base.replace(
            ", sha256 = \"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
            ""
        )
    ))
    .map(|_| ())
    .unwrap_err()
    .to_string();
    assert!(unpinned.contains("suite must be"), "{unpinned}");
}
