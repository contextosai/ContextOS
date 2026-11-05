//! `POST /v1/runs/{run_id}/tool-calls/check` answers what dispatch would do, without effect.

use serde_json::Value;

use crate::harness::*;

async fn check(client: &reqwest::Client, w: &World, run_id: &str, call: &Value) -> (u16, Value) {
    let response = client
        .post(format!("{}/v1/runs/{run_id}/tool-calls/check", w.base))
        .bearer_auth("acme-key")
        .json(call)
        .send()
        .await
        .unwrap();
    (response.status().as_u16(), response.json().await.unwrap())
}

#[tokio::test]
async fn a_check_reports_what_dispatch_would_do_without_effect() {
    let w = world(&ALL_CONTROLS).await;
    let admitted = admit(&w, &run_body("run_check", 1200)).await;
    assert_eq!(admitted.status(), 201);
    let call = tool_call("run_check", "tc_1", 120_000);

    // Without a generation header: a check has no effect to fence.
    let (status, body) = check(&reqwest::Client::new(), &w, "run_check", &call).await;
    assert_eq!(status, 200, "{body}");
    conforms("ToolCallCheck", &body);
    assert_eq!(body["check"]["status"], "allowed", "{body}");
    assert_eq!(body["check"]["operation_exists"], false);

    // A stale executor's check is refused as its dispatch would be.
    let (_, stale) = check(&executor_client(1), &w, "run_check", &call).await;
    assert_eq!(stale["check"]["status"], "rejected", "{stale}");

    // The check reserved and claimed nothing: the same call dispatches once.
    let out = dispatch(&w, "run_check", &call).await;
    assert_eq!(out["result"]["status"], "completed", "{}", out["report"]);
    assert_eq!(out["report"]["action_digest"], body["check"]["action_digest"]);
    let (_, after) = check(&executor_client(2), &w, "run_check", &call).await;
    assert_eq!(after["check"]["operation_exists"], true, "{after}");
}

#[tokio::test]
async fn a_check_names_the_approval_a_call_needs_without_requesting_it() {
    let w = world(&ALL_CONTROLS).await;
    assert_eq!(admit(&w, &run_body("run_check_big", 4200)).await.status(), 201);
    let (status, body) = check(
        &executor_client(2),
        &w,
        "run_check_big",
        &tool_call("run_check_big", "tc_1", 420_000),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["check"]["status"], "approval_required", "{body}");
    assert!(
        body["check"]["obligations"]
            .as_array()
            .unwrap()
            .contains(&"await_approval".into())
    );
}

#[tokio::test]
async fn a_check_needs_the_dispatch_scope_and_the_admitting_principal() {
    let w = world(&ALL_CONTROLS).await;
    assert_eq!(admit(&w, &run_body("run_check_auth", 1200)).await.status(), 201);
    let call = tool_call("run_check_auth", "tc_1", 120_000);
    let anonymous = reqwest::Client::new()
        .post(format!("{}/v1/runs/run_check_auth/tool-calls/check", w.base))
        .json(&call)
        .send()
        .await
        .unwrap();
    assert_eq!(anonymous.status(), 401);
    let (status, _) = check(&reqwest::Client::new(), &w, "no_such_run", &call).await;
    assert_eq!(status, 404);
}
