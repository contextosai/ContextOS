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

mod issuers {
    use std::time::{SystemTime, UNIX_EPOCH};

    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use contextos_contract::canonical::sha256_text;
    use contextos_contract::validation::format_unix_micros;
    use contextosd::evidence_admission::EvidenceMode;
    use contextosd::evidence_issuers::EvidenceIssuerConfig;
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use serde_json::{Value, json};

    use super::admit;
    use crate::harness::*;

    const ISS: &str = "https://kyc.example.test";
    const CONTENT: &str = "customer cus_77 verified";

    fn at(offset_seconds: i64) -> String {
        let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros()).unwrap();
        format_unix_micros(now + offset_seconds * 1_000_000)
    }

    /// The identity gate of the refund decision, as compiled at admission.
    fn identity_gate(admitted: &Value) -> Value {
        admitted["compiled"]["runtime_controls"]["evidence_gates"]
            .as_array()
            .unwrap()
            .iter()
            .find(|g| g["required"].as_array().unwrap().contains(&json!("identity_verified")))
            .cloned()
            .unwrap_or_else(|| panic!("{}", admitted["compiled"]))
    }

    fn body(run_id: &str, entry: Value) -> Value {
        // Above 3000 the refund decision is bound, and its evidence gate compiled.
        let mut body = run_body(run_id, 4200);
        body["request"]["input"]["context"]
            .as_object_mut()
            .unwrap()
            .remove("identity_verified");
        body["deps"]["evidence"].as_array_mut().unwrap().push(entry);
        body
    }

    #[tokio::test]
    async fn only_an_issuer_attested_entry_satisfies_a_strict_gate_and_replay_keeps_its_labels() {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
        let public = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
            .unwrap()
            .public_key()
            .as_ref()
            .to_vec();
        let jwks =
            json!({"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "k1", "x": URL_SAFE_NO_PAD.encode(&public)}]});
        let w = world_with(&ALL_CONTROLS, 1, |c| {
            c.guards.evidence = Some(EvidenceMode::Strict);
            c.evidence_issuers.push(EvidenceIssuerConfig {
                issuer: ISS.into(),
                tenants: vec![TENANT.into()],
                satisfies: vec!["identity_verified".into()],
                max_validity_seconds: 3600,
                algorithm: "EdDSA".into(),
                jwks: jwks.to_string(),
            });
        })
        .await;
        let entry = json!({"evidence_ref": "kyc:cus_77", "source_id": "kyc", "content": CONTENT,
            "integrity": "verified", "freshness": "current", "satisfies": ["identity_verified"]});

        // The caller's labels alone no longer satisfy the gate.
        let labelled = admit(&w, &body("run_labelled", entry.clone())).await;
        assert_eq!(labelled.status(), 201);
        let gate = identity_gate(&labelled.json().await.unwrap());
        assert!(
            gate["unresolved"]
                .as_array()
                .unwrap()
                .contains(&json!("identity_verified")),
            "{gate}"
        );

        // The issuer's attestation does.
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some("k1".into());
        let claims = json!({"iss": ISS, "sub": "customer:cus_77", "satisfies": ["identity_verified"],
            "content_hash": sha256_text(CONTENT), "observed_at": at(-60), "valid_until": at(600)});
        let mut attested = entry;
        attested["attestation"] =
            json!(jsonwebtoken::encode(&header, &claims, &EncodingKey::from_ed_der(pkcs8.as_ref())).unwrap());
        let admitted = admit(&w, &body("run_attested", attested)).await;
        assert_eq!(admitted.status(), 201);
        let gate = identity_gate(&admitted.json().await.unwrap());
        assert!(
            gate["satisfied"]
                .as_array()
                .unwrap()
                .contains(&json!("identity_verified")),
            "{gate}"
        );

        // The replay case holds the server's labels and the verification, not the clock.
        let case: Value = reqwest::Client::new()
            .get(format!("{}/v1/runs/run_attested/replay-case", w.base))
            .bearer_auth("acme-key")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let replayed = case["deps"]["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["evidence_ref"] == "kyc:cus_77")
            .cloned()
            .unwrap_or_else(|| panic!("{case}"));
        assert_eq!(replayed["integrity"], "verified");
        assert_eq!(replayed["freshness"], "current");
        assert_eq!(replayed["verification"]["issuer"], ISS);
        assert!(replayed["verification"]["evaluated_at"].is_string());
    }
}
