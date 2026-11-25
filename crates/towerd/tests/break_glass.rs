//! Every break-glass grant a runtime's chain shows stays a finding until a risk
//! reviewer other than its opener records a review.

mod harness;

use harness::{call, runtime, tower};
use serde_json::{Value, json};

const AT: &str = "2026-10-21T10:00:00.000000Z";

#[tokio::test]
async fn a_grant_is_a_finding_until_someone_else_reviews_it() {
    let rt = runtime(&[
        (
            "break_glass_opened",
            json!({"grant_id": "bg_1", "capabilities": ["adp_payments.issue_refund"], "lifts": ["change_windows"],
                "justification": "INC-311: refunds for the failed payout run", "incident_ref": "INC-311",
                "opened_by": "risk-b", "opened_at": AT, "expires_at": "2026-10-21T10:10:00.000000Z", "closed_at": null}),
            AT,
        ),
        (
            "break_glass_used",
            json!({"run_id": "r1", "operation_id": "op1", "capability_id": "adp_payments.issue_refund", "grant_id": "bg_1",
                "lifted": "change_windows", "window": "freeze"}),
            AT,
        ),
    ])
    .await;
    let (base, _) = tower(&rt, "").await;
    let open = |findings: &Value| {
        findings["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| f["rule"] == "break_glass_unreviewed")
            .count()
    };
    let (_, findings) = call(&base, "GET", "/api/findings", "viewer", None).await;
    assert_eq!(open(&findings), 1, "{findings}");
    let (_, grants) = call(&base, "GET", "/api/break-glass", "viewer", None).await;
    assert_eq!(grants["grants"][0]["calls"], 1);
    assert!(grants["grants"][0]["review"].is_null());

    let review = json!({"source": "eu-support", "grant_id": "bg_1",
        "notes": "One refund went out under the grant; it matches INC-311's payout list."});
    let (status, _) = call(&base, "POST", "/api/break-glass/review", "risk-b", Some(review.clone())).await;
    assert_eq!(status, 403, "the opener does not review their own grant");
    let (status, _) = call(&base, "POST", "/api/break-glass/review", "viewer", Some(review.clone())).await;
    assert_eq!(status, 403);
    let (status, body) = call(&base, "POST", "/api/break-glass/review", "risk-a", Some(review.clone())).await;
    assert_eq!(status, 200, "{body}");
    let (status, _) = call(&base, "POST", "/api/break-glass/review", "risk-a", Some(review)).await;
    assert_eq!(status, 409);
    let (_, findings) = call(&base, "GET", "/api/findings", "viewer", None).await;
    assert_eq!(open(&findings), 0, "{findings}");
    let (_, journal) = call(&base, "GET", "/api/journal?limit=500", "viewer", None).await;
    assert!(
        journal["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["kind"] == "break_glass_reviewed")
    );
}
