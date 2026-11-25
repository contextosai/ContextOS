//! Agent lifecycle end to end: every change is requested and approved by a second
//! person, journalled, and a suspended or retired agent is revoked on the runtime.

mod harness;

use harness::{call, runtime, runtime_revoked, sync, tower};
use serde_json::{Value, json};

const AT: &str = "2026-10-21T10:00:00.000000Z";
const AGENT: &str = "tenant_acme_prod%2Fagt_support";

fn admitted() -> Vec<(&'static str, Value, &'static str)> {
    vec![(
        "run_admitted",
        json!({"run_id": "r1", "trace_id": "trace_r1", "agent_id": "agt_support", "pack_ref": "ctxpack.support@5.2.0",
            "intent": "support.refund", "profiles": ["contextos.core"], "required_controls": [], "release_refs": [],
            "admitted_by": "svc", "surfaced_capabilities": ["adp_orders.lookup"]}),
        AT,
    )]
}

fn declaration(lifecycle: &str) -> Value {
    json!({"owner": "maya", "team": "support-ai", "purpose": "Refunds damaged deliveries", "users_served": "customers",
        "lifecycle": lifecycle})
}

/// Requests a change as `requester` and approves it as `approver`; returns both responses.
async fn change(base: &str, to: &str, requester: &str, approver: &str) -> ((u16, Value), (u16, Value)) {
    let asked = call(
        base,
        "POST",
        &format!("/api/agents/{AGENT}/lifecycle"),
        requester,
        Some(json!({"to": to, "reason": format!("move to {to} for the test")})),
    )
    .await;
    let id = asked.1["id"].as_str().unwrap_or_default().to_owned();
    let decided = call(
        base,
        "POST",
        &format!("/api/lifecycle-requests/{id}/approve"),
        approver,
        None,
    )
    .await;
    (asked, decided)
}

fn agent_revoked(list: &[Value]) -> Option<&Value> {
    list.iter()
        .find(|r| r["kind"] == "agent" && r["target"] == "agt_support")
}

#[tokio::test]
async fn lifecycle_changes_need_a_second_person_and_stop_the_agent_on_the_runtime() {
    let rt = runtime(&admitted()).await;
    let (base, tower) = tower(&rt, "").await;
    let path = format!("/api/agents/{AGENT}/declaration");

    // A new agent starts as proposed; the stage then changes only by request.
    let (status, body) = call(&base, "PUT", &path, "owner", Some(declaration("production"))).await;
    assert_eq!(status, 422, "{body}");
    let (status, _) = call(&base, "PUT", &path, "owner", Some(declaration("proposed"))).await;
    assert_eq!(status, 200);
    let (status, body) = call(&base, "PUT", &path, "owner", Some(declaration("production"))).await;
    assert_eq!(status, 409, "{body}");

    // Approval needs a current risk review.
    let ((status, _), (decided, body)) = change(&base, "approved", "owner", "risk-a").await;
    assert_eq!(status, 201);
    assert_eq!(decided, 422, "{body}");
    let (_, list) = call(&base, "GET", "/api/lifecycle-requests", "viewer", None).await;
    let waiting = list["requests"][0]["id"].as_str().unwrap().to_owned();
    let (status, _) = call(
        &base,
        "POST",
        &format!("/api/agents/{AGENT}/review"),
        "risk-b",
        Some(json!({"decision": "approved", "notes": "reviewed for the test"})),
    )
    .await;
    assert_eq!(status, 200);
    // Not the requester, not an owner, not a viewer.
    for (key, expected) in [("owner", 403), ("viewer", 403)] {
        let (status, _) = call(
            &base,
            "POST",
            &format!("/api/lifecycle-requests/{waiting}/approve"),
            key,
            None,
        )
        .await;
        assert_eq!(status, expected, "{key}");
    }
    let (status, body) = call(
        &base,
        "POST",
        &format!("/api/lifecycle-requests/{waiting}/approve"),
        "risk-a",
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "applied");

    // A requester never approves their own change.
    let ((status, asked), (decided, _)) = change(&base, "production", "risk-a", "risk-a").await;
    assert_eq!(status, 201, "{asked}");
    assert_eq!(decided, 403);
    let id = asked["id"].as_str().unwrap();
    // One waiting change per agent.
    let (status, _) = call(
        &base,
        "POST",
        &format!("/api/agents/{AGENT}/lifecycle"),
        "owner",
        Some(json!({"to": "pilot", "reason": "a second request at once"})),
    )
    .await;
    assert_eq!(status, 409);
    let (status, _) = call(
        &base,
        "POST",
        &format!("/api/lifecycle-requests/{id}/approve"),
        "risk-b",
        None,
    )
    .await;
    assert_eq!(status, 200);
    // Stages that do not follow are refused.
    let (status, _) = call(
        &base,
        "POST",
        &format!("/api/agents/{AGENT}/lifecycle"),
        "owner",
        Some(json!({"to": "approved", "reason": "back to approved"})),
    )
    .await;
    assert_eq!(status, 422);

    // Suspending revokes the agent on the runtime, marked as the suspension's.
    let (_, (status, body)) = change(&base, "suspended", "owner", "risk-a").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["results"][0]["ok"], true, "{body}");
    let revoked = runtime_revoked(&rt).await;
    let r = agent_revoked(&revoked).expect("the runtime revokes the suspended agent");
    assert!(r["reason"].as_str().unwrap().contains("[lifecycle suspension]"), "{r}");
    sync(&tower).await;
    let (_, findings) = call(
        &base,
        "GET",
        "/api/findings?rule=lifecycle_not_enforced",
        "viewer",
        None,
    )
    .await;
    assert_eq!(findings["findings"].as_array().unwrap().len(), 0, "{findings}");

    // Resuming restores it.
    let (_, (status, body)) = change(&base, "production", "owner", "risk-b").await;
    assert_eq!(status, 200, "{body}");
    assert!(agent_revoked(&runtime_revoked(&rt).await).is_none());

    // Retiring revokes it for good; nothing follows retired.
    let (_, (status, _)) = change(&base, "retired", "owner", "risk-a").await;
    assert_eq!(status, 200);
    assert!(agent_revoked(&runtime_revoked(&rt).await).is_some());
    let (status, _) = call(
        &base,
        "POST",
        &format!("/api/agents/{AGENT}/lifecycle"),
        "owner",
        Some(json!({"to": "production", "reason": "bring it back"})),
    )
    .await;
    assert_eq!(status, 422);

    // Every step is in the signed journal.
    let (_, journal) = call(&base, "GET", "/api/journal?limit=500", "viewer", None).await;
    let kinds: Vec<&str> = journal["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["kind"].as_str())
        .collect();
    for kind in [
        "lifecycle_requested",
        "lifecycle_approved",
        "agent_lifecycle_changed",
        "lifecycle_enforced",
    ] {
        assert!(kinds.contains(&kind), "{kind} missing from {kinds:?}");
    }
}

#[tokio::test]
async fn a_resume_leaves_an_operators_own_revocation_in_force() {
    let rt = runtime(&admitted()).await;
    let (base, tower) = tower(&rt, "[governance]\nlifecycle_approval = false").await;
    let path = format!("/api/agents/{AGENT}/declaration");
    let (status, _) = call(&base, "PUT", &path, "owner", Some(declaration("production"))).await;
    assert_eq!(status, 200, "without lifecycle_approval a declaration sets the stage");
    // An operator revokes the agent for an incident.
    let (status, _) = call(
        &base,
        "POST",
        "/api/fleet/revoke",
        "oncall-a",
        Some(json!({"kind": "agent", "target": "agt_support", "reason": "incident 42: refunds to one account"})),
    )
    .await;
    assert_eq!(status, 200);
    let (_, (status, _)) = change(&base, "suspended", "owner", "risk-a").await;
    assert_eq!(status, 200);
    sync(&tower).await;
    let (_, (status, body)) = change(&base, "production", "owner", "risk-a").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["results"][0]["skipped"], true, "{body}");
    let still = runtime_revoked(&rt).await;
    let r = agent_revoked(&still).expect("the operator's revocation stays");
    assert!(r["reason"].as_str().unwrap().contains("incident 42"), "{r}");
}
