//! `[guards.release_evaluations]`: an agent release is admitted only after the suites
//! the deployment requires passed on it, recorded by an independent evaluator.

use contextos_gateway::release_evaluations::{EvaluationRule, ReleaseEvaluationPolicy};
use serde_json::{Value, json};

use crate::harness::*;

fn release() -> Value {
    json!({"artifact_type": "agent_release", "artifact_id": "agt_support", "version": "2026.11.2",
        "sha256": format!("sha256:{}", "ab".repeat(32))})
}

async fn post(w: &World, path: &str, key: &str, body: Value) -> (u16, Value) {
    let response = reqwest::Client::new()
        .post(format!("{}{path}", w.base))
        .bearer_auth(key)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    (status, response.json().await.unwrap_or(Value::Null))
}

fn result(outcome: &str, passed: u64) -> Value {
    json!({"release": release(), "suite_id": "refund_regression", "suite_version": "3", "outcome": outcome,
        "cases_passed": passed, "cases_total": 40, "report_ref": "evals://refund_regression/3/run-881"})
}

async fn try_admit(w: &World, run: &str, with_release: bool) -> (u16, Value) {
    let mut body = run_body(run, 1200);
    if with_release {
        body["contract"]["release_refs"].as_array_mut().unwrap().push(release());
    }
    let response = admit(w, &body).await;
    let status = response.status().as_u16();
    (status, response.json().await.unwrap_or(Value::Null))
}

#[tokio::test]
async fn a_release_runs_only_after_its_required_suites_pass() {
    let w = world_with(&ALL_CONTROLS, 1, |c| {
        c.guards.release_evaluations = Some(ReleaseEvaluationPolicy {
            rules: vec![EvaluationRule {
                agents: vec!["agt_support".into()],
                suites: vec!["refund_regression".into()],
            }],
        });
    })
    .await;
    let (status, body) = try_admit(&w, "run_rel_1", false).await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (403, Some("agent_release_missing")),
        "{body}"
    );
    let (status, body) = try_admit(&w, "run_rel_2", true).await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (403, Some("release_unevaluated")),
        "{body}"
    );
    assert_eq!(body["error"]["detail"]["missing_suites"], json!(["refund_regression"]));

    // Only an evaluator records results, and a pass is a pass of every case.
    assert_eq!(
        post(&w, "/v1/agent-releases/evaluations", "acme-key", result("passed", 40))
            .await
            .0,
        403
    );
    assert_eq!(
        post(&w, "/v1/agent-releases/evaluations", "judge-key", result("passed", 39))
            .await
            .0,
        422
    );
    assert_eq!(
        post(&w, "/v1/agent-releases/evaluations", "judge-key", result("failed", 31))
            .await
            .0,
        201
    );
    assert_eq!(
        try_admit(&w, "run_rel_3", true).await.0,
        403,
        "a failed suite does not count"
    );
    assert_eq!(
        post(&w, "/v1/agent-releases/evaluations", "judge-key", result("passed", 40))
            .await
            .0,
        201
    );
    let (status, body) = try_admit(&w, "run_rel_4", true).await;
    assert_eq!(status, 201, "{body}");
    // A later failure stops the release again.
    assert_eq!(
        post(&w, "/v1/agent-releases/evaluations", "judge-key", result("failed", 12))
            .await
            .0,
        201
    );
    assert_eq!(try_admit(&w, "run_rel_5", true).await.0, 403);

    let (status, listed) = post(
        &w,
        "/v1/agent-releases/evaluations/query",
        "acme-key",
        json!({"release": release()}),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(listed["results"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn other_agents_and_unconfigured_deployments_are_not_gated() {
    let w = world_with(&ALL_CONTROLS, 1, |c| {
        c.guards.release_evaluations = Some(ReleaseEvaluationPolicy {
            rules: vec![EvaluationRule {
                agents: vec!["agt_other".into()],
                suites: vec!["safety".into()],
            }],
        });
    })
    .await;
    assert_eq!(try_admit(&w, "run_free", false).await.0, 201);
}
