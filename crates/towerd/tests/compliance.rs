//! Compliance readiness: the live view is read with `GET`, and the auditor export is a
//! `POST` that journals the exact report digest.

mod harness;

use harness::{call, runtime, tower};
use serde_json::{Value, json};

#[tokio::test]
async fn the_compliance_export_is_a_journalled_post_and_never_a_certification() {
    let rt = runtime(&[(
        "run_admitted",
        json!({"run_id": "r1", "trace_id": "t1", "agent_id": "agt_support", "pack_ref": "ctxpack.support@5.2.0",
            "intent": "support.refund", "profiles": ["contextos.core"], "required_controls": [], "release_refs": [],
            "admitted_by": "svc", "surfaced_capabilities": ["adp_orders.lookup"]}),
        "2026-11-27T10:00:00Z",
    )])
    .await;
    let (base, _) = tower(&rt, "").await;

    let (status, view) = call(&base, "GET", "/api/compliance?framework=soc2", "viewer", None).await;
    assert_eq!(status, 200, "{view}");

    // A GET never exports (nor journals) a report.
    let (status, _) = call(&base, "GET", "/api/compliance/report?format=json", "viewer", None).await;
    assert_eq!(status, 405);

    let (status, report) = call(
        &base,
        "POST",
        "/api/compliance/report",
        "viewer",
        Some(json!({"framework": "soc2", "format": "json"})),
    )
    .await;
    assert_eq!(status, 200, "{report}");
    assert_eq!(report["certification"], false);
    let digest = report["digest"].as_str().unwrap().to_owned();

    let (status, _) = call(
        &base,
        "POST",
        "/api/compliance/report",
        "viewer",
        Some(json!({"format": "pdf"})),
    )
    .await;
    assert_eq!(status, 422);

    let (_, journal) = call(&base, "GET", "/api/journal?limit=500", "viewer", None).await;
    let exported: Vec<&Value> = journal["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["kind"] == "compliance_report_exported")
        .collect();
    assert_eq!(exported.len(), 1);
    assert_eq!(exported[0]["payload"]["report_digest"], digest.as_str());
    assert_eq!(exported[0]["payload"]["format"], "json");
}
