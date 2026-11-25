//! The governance dashboard end to end: a runtime's verified chain becomes held,
//! refused and evidence numbers, and its ceilings are read live.

mod harness;

use harness::{call, runtime, tower};
use serde_json::json;

const AT: &str = "2026-10-21T10:00:00.000000Z";

#[tokio::test]
async fn the_dashboard_counts_what_is_held_refused_and_verified() {
    let rt = runtime(&[
        (
            "run_admitted",
            json!({"run_id": "r1", "trace_id": "t1", "agent_id": "agt_support", "pack_ref": "ctxpack.support@5.2.0",
                "intent": "support.refund", "profiles": ["contextos.core"], "required_controls": [], "release_refs": [],
                "admitted_by": "svc", "surfaced_capabilities": ["adp_payments.issue_refund"]}),
            AT,
        ),
        ("operation_claim", json!({"run_id": "r1", "operation_id": "op1", "attempt_id": "a1", "capability_id": "adp_payments.issue_refund"}), AT),
        ("effect_observation", json!({"run_id": "r1", "attempt_id": "a1", "outcome": "unknown", "finality": "provisional"}), AT),
        ("revocation_refusal", json!({"run_id": "r1", "operation_id": "op2", "reason_codes": ["revoked_capability"]}), AT),
    ])
    .await;
    let (base, _) = tower(&rt, "").await;
    let (status, _) = call(&base, "GET", "/api/dashboard", "nobody", None).await;
    assert_eq!(status, 401);
    let (status, d) = call(&base, "GET", "/api/dashboard", "viewer", None).await;
    assert_eq!(status, 200, "{d}");
    assert_eq!(d["held_effects"]["total"], 1, "{d}");
    assert_eq!(d["denials"]["by_reason"][0]["reason"], "revoked_capability");
    assert_eq!(d["evidence"]["sources"], 1);
    assert_eq!(d["evidence"]["broken"], 0);
    assert_eq!(d["evidence"]["chains"][0]["behind"], 0);
    // The runtime configures no shared guarantee: read live, nothing to show.
    assert_eq!(d["ceilings"], json!([]), "{d}");
}
