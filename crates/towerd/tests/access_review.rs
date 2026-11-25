//! Access reviews end to end: grants held but unused are listed from verified evidence,
//! and a risk reviewer attests to the exact report they read.

mod harness;

use harness::{call, runtime, tower};
use serde_json::{Value, json};

fn now_minus(hours: i64) -> String {
    let micros = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap()
        - hours * 3_600_000_000;
    contextos_contract::validation::format_unix_micros(micros)
}

#[tokio::test]
async fn unused_grants_are_reported_and_the_review_is_attested_by_digest() {
    let recent = now_minus(2);
    let old = now_minus(24 * 200);
    let rt = runtime(&[
        (
            "run_admitted",
            json!({"run_id": "r_old", "trace_id": "t_old", "agent_id": "agt_support", "pack_ref": "ctxpack.support@5.2.0",
                "intent": "support.refund", "profiles": ["contextos.core"], "required_controls": [], "release_refs": [],
                "admitted_by": "svc", "surfaced_capabilities": ["adp_orders.lookup", "adp_payments.issue_refund"]}),
            old.as_str(),
        ),
        (
            "operation_claim",
            json!({"run_id": "r_old", "operation_id": "op0", "attempt_id": "a0", "capability_id": "adp_orders.lookup"}),
            old.as_str(),
        ),
        (
            "run_admitted",
            json!({"run_id": "r1", "trace_id": "t1", "agent_id": "agt_support", "pack_ref": "ctxpack.support@5.2.0",
                "intent": "support.refund", "profiles": ["contextos.core"], "required_controls": [], "release_refs": [],
                "admitted_by": "svc", "surfaced_capabilities": ["adp_orders.lookup", "adp_payments.issue_refund"]}),
            recent.as_str(),
        ),
        (
            "operation_claim",
            json!({"run_id": "r1", "operation_id": "op1", "attempt_id": "a1", "capability_id": "adp_payments.issue_refund"}),
            recent.as_str(),
        ),
    ])
    .await;
    let (base, _) = tower(&rt, "").await;
    let (status, _) = call(&base, "GET", "/api/access-review?days=3", "viewer", None).await;
    assert_eq!(status, 422);
    let (status, review) = call(&base, "GET", "/api/access-review?days=90", "viewer", None).await;
    assert_eq!(status, 200, "{review}");
    let status_of = |cap: &str| -> Value {
        review["grants"]
            .as_array()
            .unwrap()
            .iter()
            .find(|g| g["capability"] == cap)
            .map_or(Value::Null, |g| g["status"].clone())
    };
    assert_eq!(status_of("adp_payments.issue_refund"), "used");
    assert_eq!(status_of("adp_orders.lookup"), "unused", "last used 200 days ago");
    // Every grant but the refund is unused: the lookup, and whatever else the pack pins.
    let grants = review["summary"]["grants"].as_u64().unwrap();
    assert!(grants >= 2, "{review}");
    assert_eq!(
        review["summary"]["unused_grants"].as_u64().unwrap(),
        grants - 1,
        "{review}"
    );
    let digest = review["digest"].as_str().unwrap().to_owned();

    let (status, csv) = call(&base, "GET", "/api/access-review?days=90&format=csv", "viewer", None).await;
    assert_eq!(status, 200);
    assert!(csv.as_str().unwrap().contains("adp_orders.lookup,"), "{csv}");

    let attest = |digest: &str| json!({"days": 90, "digest": digest, "notes": "Quarterly review Q4: lookup grant to be removed"});
    let (status, _) = call(
        &base,
        "POST",
        "/api/access-review/attest",
        "viewer",
        Some(attest(&digest)),
    )
    .await;
    assert_eq!(status, 403);
    let (status, _) = call(
        &base,
        "POST",
        "/api/access-review/attest",
        "risk-a",
        Some(attest("sha256:stale")),
    )
    .await;
    assert_eq!(status, 409, "an attestation names the findings it covers");
    let (status, record) = call(
        &base,
        "POST",
        "/api/access-review/attest",
        "risk-a",
        Some(attest(&digest)),
    )
    .await;
    assert_eq!(status, 200, "{record}");
    let (_, journal) = call(&base, "GET", "/api/journal?limit=500", "viewer", None).await;
    let attested: Vec<&Value> = journal["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["kind"] == "access_review_attested")
        .collect();
    assert_eq!(attested.len(), 1);
    assert_eq!(attested[0]["payload"]["digest"], digest.as_str());
    assert_eq!(attested[0]["payload"]["attested_by"], "risk-a");
}
