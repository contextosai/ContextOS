//! Incident cases end to end: open from a finding, add evidence and notes, move through
//! statuses, export a report whose digest the signed journal records.

mod harness;

use harness::{call, runtime, tower};
use serde_json::{Value, json};

#[tokio::test]
async fn a_case_carries_evidence_a_timeline_and_a_journalled_report() {
    let rt = runtime(&[]).await;
    let (base, _) = tower(&rt, "").await;
    let open = json!({"title": "Refunds held after payout outage", "severity": "high", "summary": "INC-311",
        "links": [{"kind": "finding", "ref": "unresolved_effects:tenant_acme_prod/agt_support"}]});
    let (status, _) = call(&base, "POST", "/api/cases", "viewer", Some(open.clone())).await;
    assert_eq!(status, 403);
    let (status, _) = call(
        &base,
        "POST",
        "/api/cases",
        "oncall-a",
        Some(json!({"title": "x", "severity": "huge"})),
    )
    .await;
    assert_eq!(status, 422);
    let (status, case) = call(&base, "POST", "/api/cases", "oncall-a", Some(open)).await;
    assert_eq!(status, 201, "{case}");
    let id = case["id"].as_str().unwrap().to_owned();

    let path = |p: &str| format!("/api/cases/{id}{p}");
    let (status, _) = call(
        &base,
        "POST",
        &path("/links"),
        "risk-a",
        Some(json!({"kind": "audit_entry", "ref": "42", "source": "eu-support"})),
    )
    .await;
    assert_eq!(status, 200);
    let (status, _) = call(
        &base,
        "POST",
        &path("/links"),
        "risk-a",
        Some(json!({"kind": "run", "ref": "r1", "payload": {"pan": "4111"}})),
    )
    .await;
    assert_eq!(status, 422, "links carry references, never payloads");
    let (status, _) = call(
        &base,
        "POST",
        &path("/notes"),
        "oncall-a",
        Some(json!({"text": "Provider confirmed both refunds applied; reconciling."})),
    )
    .await;
    assert_eq!(status, 200);
    let (status, moved) = call(
        &base,
        "POST",
        &path("/status"),
        "oncall-a",
        Some(json!({"status": "contained", "owner": "oncall-b", "reason": "held effects reconciled"})),
    )
    .await;
    assert_eq!(status, 200, "{moved}");
    assert_eq!(moved["owner"], "oncall-b");
    assert_eq!(moved["timeline"].as_array().unwrap().len(), 4);

    let (_, listed) = call(&base, "GET", "/api/cases?status=contained", "viewer", None).await;
    assert_eq!(listed["cases"].as_array().unwrap().len(), 1);
    assert!(listed["cases"][0].get("timeline").is_none());

    let (status, report) = call(&base, "GET", &path("/report"), "viewer", None).await;
    assert_eq!(status, 200);
    let digest = report["report_digest"].as_str().unwrap().to_owned();
    let (_, md) = call(&base, "GET", &path("/report?format=md"), "viewer", None).await;
    assert!(md.as_str().unwrap().contains(&digest));
    let (_, journal) = call(&base, "GET", "/api/journal?limit=500", "viewer", None).await;
    let exported: Vec<&Value> = journal["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["kind"] == "case_exported")
        .collect();
    assert_eq!(exported.len(), 2);
    assert_eq!(exported[0]["payload"]["report_digest"], digest.as_str());

    let (status, _) = call(
        &base,
        "POST",
        &path("/status"),
        "risk-a",
        Some(json!({"status": "closed", "reason": "post-incident review done"})),
    )
    .await;
    assert_eq!(status, 200);
    let (status, _) = call(
        &base,
        "POST",
        &path("/notes"),
        "oncall-a",
        Some(json!({"text": "late"})),
    )
    .await;
    assert_eq!(status, 409, "a closed case is final");
}
