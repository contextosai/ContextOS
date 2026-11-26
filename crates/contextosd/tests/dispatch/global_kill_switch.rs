//! The kill switch at runtime scope: a `global` revocation, by a named principal, stops
//! every tenant's new runs and effects until restored.

use contextosd::auth::hash_api_key;
use contextosd::config::ApiKey;
use serde_json::{Value, json};

use crate::harness::*;

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

async fn listed(w: &World, key: &str) -> Value {
    reqwest::Client::new()
        .get(format!("{}/v1/revocations", w.base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test]
async fn a_global_revocation_stops_every_tenant_until_restored() {
    let w = world_with(&ALL_CONTROLS, 1, |c| {
        c.kill_switch.global_principals = vec!["svc_oncall".into()];
        for (key, tenant, principal) in [
            ("oncall-b-key", TENANT, "svc_oncall_b"),
            ("other-tenant-key", "tenant_other", "svc_other_ops"),
        ] {
            c.api_keys.push(ApiKey {
                key_sha256: hash_api_key(key),
                tenant_id: tenant.into(),
                principal_id: principal.into(),
                scopes: vec!["control".into()],
                agent_ids: None,
            });
        }
    })
    .await;
    assert_eq!(admit(&w, &run_body("run_before", 1200)).await.status(), 201);
    let stop = json!({"kind": "global", "target": "*", "reason": "INC-400: suspected credential leak"});
    let (status, body) = post(&w, "/v1/revocations", "oncall-b-key", stop.clone()).await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (403, Some("global_kill_switch_forbidden"))
    );
    let (status, _) = post(
        &w,
        "/v1/revocations",
        "ops-key",
        json!({"kind": "global", "target": "acme", "reason": "x"}),
    )
    .await;
    assert_eq!(status, 422, "the global target is *");
    let (status, body) = post(&w, "/v1/revocations", "ops-key", stop).await;
    assert_eq!(status, 200, "{body}");

    // Every tenant sees it; no tenant can hold the global scope's key.
    for key in ["ops-key", "other-tenant-key"] {
        let list = listed(&w, key).await;
        assert_eq!(list["revoked"][0]["kind"], "global", "{key}: {list}");
    }
    // New runs and effects of running ones stop.
    let refused = admit(&w, &run_body("run_after", 1200)).await;
    assert_eq!(refused.status(), 403);
    let call = dispatch(&w, "run_before", &refund("run_before", "r1", "ord_881", "cus_77", 100)).await;
    assert_eq!(call["report"]["reason_codes"], json!(["revoked_global"]), "{call}");

    let (status, _) = post(
        &w,
        "/v1/revocations/restore",
        "ops-key",
        json!({"kind": "global", "target": "*", "reason": "INC-400 contained, keys rotated"}),
    )
    .await;
    assert_eq!(status, 200);
    let call = dispatch(&w, "run_before", &refund("run_before", "r2", "ord_882", "cus_77", 100)).await;
    assert_eq!(call["report"]["status"], "completed", "{call}");
}

#[tokio::test]
async fn only_named_releasers_may_lift_a_quarantine() {
    let w = world_with(&ALL_CONTROLS, 1, |c| {
        c.guards.quarantine_releasers = vec!["svc_oncall".into()];
        c.api_keys.push(ApiKey {
            key_sha256: hash_api_key("other-tenant-key"),
            tenant_id: "tenant_other".into(),
            principal_id: "svc_other_ops".into(),
            scopes: vec!["control".into()],
            agent_ids: None,
        });
    })
    .await;
    let release = json!({"capability_id": "adp_payments.issue_refund", "reason": "reviewed: benign rollback"});
    // Another tenant's operator holds `control` but is not named: the quarantine
    // protects every tenant, so it is not theirs to lift.
    let (status, body) = post(
        &w,
        "/v1/upstream/quarantine/release",
        "other-tenant-key",
        release.clone(),
    )
    .await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (403, Some("quarantine_release_forbidden")),
        "{body}"
    );
    // A named releaser gets through to the quarantine check itself.
    let (status, body) = post(&w, "/v1/upstream/quarantine/release", "ops-key", release).await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (404, Some("not_quarantined")),
        "{body}"
    );
}
