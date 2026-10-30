//! Runs are driven only by the principal that admitted them.

use contextosd::auth::hash_api_key;
use serde_json::{Value, json};

use crate::harness::*;

#[tokio::test]
async fn another_principal_in_the_tenant_cannot_drive_or_see_a_run() {
    let w = world_with(&ALL_CONTROLS, 1, |c| {
        c.api_keys.push(contextosd::config::ApiKey {
            key_sha256: hash_api_key("other-agent"),
            tenant_id: TENANT.into(),
            principal_id: "svc_other_agent".into(),
            scopes: vec!["admit".into(), "dispatch".into()],
        });
    })
    .await;
    let http = executor_client(1);
    let admitted = http
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_owned", 7))
        .send()
        .await
        .unwrap();
    assert_eq!(admitted.status(), 201);
    let run = format!("{}/v1/runs/run_owned", w.base);
    let attempts = [
        http.get(&run),
        http.post(format!("{run}/tool-calls"))
            .json(&tool_call("run_owned", "pending", 100)),
        http.post(format!("{run}/takeover"))
            .json(&json!({"expected_generation": 1})),
        http.post(format!("{run}/complete")),
        http.post(format!("{run}/cancel")),
        http.get(format!("{run}/checkpoint")),
        http.get(format!("{run}/compensations")),
        http.get(format!("{run}/notices")),
    ];
    for request in attempts {
        let response = request.bearer_auth("other-agent").send().await.unwrap();
        assert_eq!(response.status(), 404, "{:?}", response.url().path());
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["error"]["code"], "run_not_found");
    }
    // Nor can it delegate from the run.
    let parent = json!({"run_id": "run_owned", "executor_generation": 1});
    let child = http
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("other-agent")
        .json(&child_of(&parent, "run_owned", "run_child", "ctxpack.support@5.2.0"))
        .send()
        .await
        .unwrap();
    assert_eq!(child.status(), 404);
    // The run is untouched: its owner still drives it.
    let status: Value = http
        .get(&run)
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["status"], "running", "{status}");
}
