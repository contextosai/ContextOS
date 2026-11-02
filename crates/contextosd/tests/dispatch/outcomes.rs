//! Outcome contracts: a confirmed refund is done when the refund ledger says it posted,
//! for that order and amount.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use contextos_contract::validation::format_unix_micros;
use contextos_store::AppendLog;
use contextosd::config::ApiKey;
use contextosd::evidence_issuers::EvidenceIssuerConfig;
use contextosd::governance_sweep::{Census, SweepConfig};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{Value, json};

use crate::harness::*;

const LEDGER: &str = "https://ledger.example.test";

struct Witness(Vec<u8>, Vec<u8>);

impl Witness {
    fn new() -> Self {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
        let public = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
            .unwrap()
            .public_key()
            .as_ref()
            .to_vec();
        Self(pkcs8.as_ref().to_vec(), public)
    }

    fn issuer(&self, iss: &str) -> EvidenceIssuerConfig {
        EvidenceIssuerConfig {
            issuer: iss.into(),
            tenants: vec![TENANT.into()],
            satisfies: vec!["refund_posted".into()],
            max_validity_seconds: 86_400,
            algorithm: "EdDSA".into(),
            jwks:
                json!({"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "k1", "x": URL_SAFE_NO_PAD.encode(&self.1)}]})
                    .to_string(),
        }
    }

    fn sign(&self, claims: &Value) -> String {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some("k1".into());
        jsonwebtoken::encode(&header, claims, &EncodingKey::from_ed_der(&self.0)).unwrap()
    }
}

fn at(offset_seconds: i64) -> String {
    let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros()).unwrap();
    format_unix_micros(now + offset_seconds * 1_000_000)
}

/// What the ledger saw: refund of `amount` on `order`, observed `observed` seconds from now.
fn posted(order: &str, amount: u64, observed: i64, until: i64) -> Value {
    json!({"iss": LEDGER, "sub": order, "satisfies": ["refund_posted"], "observed_at": at(observed),
        "valid_until": at(until), "amount": {"minor_units": amount, "currency": "INR"}})
}

/// A world whose refund capability declares an outcome witnessed by the ledger.
async fn outcome_world(witness: &Witness, within_seconds: u64) -> World {
    world_with(&ALL_CONTROLS, 1, |c| {
        let path = c.capabilities[0].clone();
        let mut manifest: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        manifest["outcome"] =
            json!({"witness": LEDGER, "postcondition": "refund_posted", "within_seconds": within_seconds});
        std::fs::write(&path, manifest.to_string()).unwrap();
        c.evidence_issuers.push(witness.issuer(LEDGER));
        c.api_keys.push(ApiKey {
            key_sha256: contextosd::auth::hash_api_key("witness-key"),
            tenant_id: TENANT.into(),
            principal_id: "svc_refund_ledger".into(),
            scopes: vec!["outcome:report".into()],
            agent_ids: None,
        });
    })
    .await
}

/// Admits `run_id` and refunds 120,000 on ord_881; returns the executor client.
async fn refund(w: &World, run_id: &str) -> reqwest::Client {
    let admitted: Value = reqwest::Client::new()
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body(run_id, 1200))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let http = executor_client(admitted["executor_generation"].as_u64().unwrap());
    let out: Value = http
        .post(format!("{}/v1/runs/{run_id}/tool-calls", w.base))
        .bearer_auth("acme-key")
        .json(&tool_call(run_id, "tc_1", 120_000))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(out["result"]["status"], "completed", "{out}");
    http
}

async fn report(w: &World, run_id: &str, token: &str) -> (u16, Value) {
    let response = reqwest::Client::new()
        .post(format!(
            "{}/v1/runs/{run_id}/operations/refund:{run_id}/outcome",
            w.base
        ))
        .bearer_auth("witness-key")
        .json(&json!({"attestation": token}))
        .send()
        .await
        .unwrap();
    (response.status().as_u16(), response.json().await.unwrap())
}

async fn complete(w: &World, http: &reqwest::Client, run_id: &str) -> Value {
    http.post(format!("{}/v1/runs/{run_id}/complete", w.base))
        .bearer_auth("acme-key")
        .json(&json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

async fn audited(w: &World, kind: &str) -> Vec<Value> {
    w.state
        .audit
        .log()
        .range(TENANT, 1, 10_000)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.body["kind"] == kind)
        .map(|e| e.body["payload"].clone())
        .collect()
}

async fn decide(w: &World, http: &reqwest::Client, run_id: &str) -> (u16, Value) {
    let response = http
        .post(format!("{}/v1/runs/{run_id}/decisions", w.base))
        .bearer_auth("acme-key")
        .json(
            &json!({"decision_key": "support.refund.execute", "decision_version": "1", "status": "DECIDED",
            "outcome": "refund_issued", "rationale": {"strategy": "policy_and_evidence"},
            "tool_calls": [{"tool_call_id": "tc_1", "operation_id": format!("refund:{run_id}")}]}),
        )
        .send()
        .await
        .unwrap();
    (response.status().as_u16(), response.json().await.unwrap())
}

fn code(body: &Value) -> &str {
    body["error"]["code"].as_str().unwrap_or_default()
}

#[tokio::test]
async fn a_confirmed_refund_completes_only_once_the_ledger_witnesses_it() {
    let ledger = Witness::new();
    let w = outcome_world(&ledger, 900).await;
    let http = refund(&w, "run_witnessed").await;

    let refused = complete(&w, &http, "run_witnessed").await;
    assert!(refused.to_string().contains("outcome_pending"), "{refused}");
    let pending = audited(&w, "outcome_pending").await;
    assert_eq!(pending.len(), 1, "{pending:?}");
    assert_eq!(pending[0]["postcondition"], "refund_posted");
    // Nor can a decision commit to the refund.
    let decided = decide(&w, &http, "run_witnessed").await;
    assert_eq!(decided.0, 409, "{}", decided.1);
    assert_eq!(code(&decided.1), "outcome_pending");

    tokio::time::sleep(Duration::from_millis(1100)).await;
    // Another order, another amount, an expired reading, an earlier reading, a service
    // that is not the witness: each is refused.
    let cases = [
        (
            ledger.sign(&posted("ord_999", 120_000, 0, 600)),
            "outcome_resource_mismatch",
        ),
        (
            ledger.sign(&posted("ord_881", 90_000, 0, 600)),
            "outcome_amount_mismatch",
        ),
        (ledger.sign(&posted("ord_881", 120_000, -600, -60)), "expired"),
        (
            ledger.sign(&posted("ord_881", 120_000, -300, 600)),
            "outcome_before_effect",
        ),
        (
            Witness::new().sign(&posted("ord_881", 120_000, 0, 600)),
            "signature_invalid",
        ),
    ];
    for (token, expected) in &cases {
        let (status, body) = report(&w, "run_witnessed", token).await;
        assert_eq!((status, code(&body)), (422, *expected), "{body}");
    }
    let mut stranger = posted("ord_881", 120_000, 0, 600);
    stranger["iss"] = json!("https://stranger.example.test");
    let (status, body) = report(&w, "run_witnessed", &ledger.sign(&stranger)).await;
    assert_eq!((status, code(&body)), (422, "issuer_unknown"), "{body}");
    assert!(
        complete(&w, &http, "run_witnessed")
            .await
            .to_string()
            .contains("outcome_pending")
    );

    // The ledger's own reading closes it, once.
    let token = ledger.sign(&posted("ord_881", 120_000, 0, 600));
    let (status, body) = report(&w, "run_witnessed", &token).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["state"], "witnessed");
    assert_eq!(body["late"], false);
    assert_eq!(report(&w, "run_witnessed", &token).await.0, 200);
    let witnessed = audited(&w, "outcome_witnessed").await;
    assert_eq!(witnessed.len(), 1, "{witnessed:?}");
    assert_eq!(witnessed[0]["observation"]["issuer"], LEDGER);
    assert!(
        !witnessed[0].to_string().contains(&token),
        "the token is recorded by digest"
    );

    // The decision cites the reading; the evidence bundle carries the outcome.
    let (status, recorded) = decide(&w, &http, "run_witnessed").await;
    assert_eq!(status, 201, "{recorded}");
    let digest = witnessed[0]["observation"]["attestation_digest"].as_str().unwrap();
    assert_eq!(
        recorded["record"]["tool_lineage"][0]["artifact_refs"],
        json!([format!("outcome:{digest}")])
    );
    let evidence: Value = http
        .get(format!("{}/v1/runs/run_witnessed/evidence", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(evidence["outcomes"][0]["state"], "witnessed", "{evidence}");
    conforms("EvidenceBundle", &evidence);

    let done = complete(&w, &http, "run_witnessed").await;
    assert_eq!(done["status"], "completed", "{done}");
}

#[tokio::test]
async fn a_missed_outcome_escalates_once_and_a_late_witness_still_closes_it() {
    let ledger = Witness::new();
    let w = outcome_world(&ledger, 1).await;
    let http = refund(&w, "run_late").await;
    let gateway = w.state.gateway.clone().unwrap();
    let config = SweepConfig::default();
    let mut census = Census::new(vec![TENANT.into()], gateway.shared_guarantee_ids());

    tokio::time::sleep(Duration::from_millis(1100)).await;
    census.step(&gateway, &config).await.unwrap();
    // Another pass, or a new leader's sweep, opens nothing new.
    census.step(&gateway, &config).await.unwrap();
    Census::new(vec![TENANT.into()], gateway.shared_guarantee_ids())
        .step(&gateway, &config)
        .await
        .unwrap();
    let opened = audited(&w, "escalation_opened").await;
    assert_eq!(opened.len(), 1, "{opened:?}");
    assert_eq!(opened[0]["reason_codes"], json!(["outcome_missed"]));
    assert_eq!(opened[0]["capability_id"], "adp_payments.issue_refund");
    assert!(
        complete(&w, &http, "run_late")
            .await
            .to_string()
            .contains("outcome_pending")
    );

    let (status, body) = report(&w, "run_late", &ledger.sign(&posted("ord_881", 120_000, 0, 600))).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["late"], true);
    assert_eq!(complete(&w, &http, "run_late").await["status"], "completed");
}

#[tokio::test]
async fn an_operation_without_a_contract_has_no_outcome_to_report() {
    let ledger = Witness::new();
    let w = world(&ALL_CONTROLS).await;
    refund(&w, "run_plain").await;
    let response = reqwest::Client::new()
        .post(format!(
            "{}/v1/runs/run_plain/operations/refund:run_plain/outcome",
            w.base
        ))
        .bearer_auth("acme-key")
        .json(&json!({"attestation": ledger.sign(&posted("ord_881", 120_000, 0, 600))}))
        .send()
        .await
        .unwrap();
    // The executor's key lacks the scope.
    assert_eq!(response.status(), 403);
}

#[tokio::test]
async fn a_witness_must_be_an_issuer_that_may_attest_the_postcondition() {
    let contract: contextos_gateway::manifest::OutcomeContract =
        serde_json::from_value(json!({"witness": LEDGER, "postcondition": "refund_posted", "within_seconds": 900}))
            .unwrap();
    let contracts = [("adp_payments.issue_refund".to_owned(), contract)];
    let unlisted = contextosd::outcome_witness::check(&contracts, &[]).unwrap_err();
    assert!(unlisted.contains("is not an [[evidence_issuers]] issuer"), "{unlisted}");
    let mut issuer = Witness::new().issuer(LEDGER);
    issuer.satisfies = vec!["identity_verified".into()];
    let unable = contextosd::outcome_witness::check(&contracts, &[issuer]).unwrap_err();
    assert!(
        unable.contains("may not satisfy postcondition refund_posted"),
        "{unable}"
    );
}
