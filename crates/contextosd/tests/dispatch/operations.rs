//! Operator controls: revocation and rollouts.

use std::sync::atomic::Ordering;
use std::time::Duration;

use serde_json::{Value, json};

use crate::harness::*;

#[tokio::test]
async fn operators_revoke_and_restore_targets() {
    let w = world(&ALL_CONTROLS).await;
    let plain = reqwest::Client::new();
    let change = |path: &'static str, key: &'static str, kind: &'static str, target: &'static str| {
        let url = format!("{}/v1/revocations{path}", w.base);
        let plain = plain.clone();
        async move {
            plain
                .post(url)
                .bearer_auth(key)
                .json(&json!({"kind": kind, "target": target, "reason": "incident 4711"}))
                .send()
                .await
                .unwrap()
        }
    };
    // Only operators hold the kill switch.
    assert_eq!(
        change("", "acme-key", "capability", "adp_payments.issue_refund")
            .await
            .status(),
        403
    );
    assert_eq!(change("", "ops-key", "everything", "x").await.status(), 422);

    let admitted: Value = plain
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_killed", 1200))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let http = executor_client(admitted["executor_generation"].as_u64().unwrap());
    let calls_before = w.provider_calls.load(Ordering::SeqCst);

    // Revoke the capability: the effect stops before it is claimed or sent.
    assert_eq!(
        change("", "ops-key", "capability", "adp_payments.issue_refund")
            .await
            .status(),
        200
    );
    let blocked: Value = http
        .post(format!("{}/v1/runs/run_killed/tool-calls", w.base))
        .bearer_auth("acme-key")
        .json(&tool_call("run_killed", "tc_1", 120_000))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(blocked["result"]["status"], "blocked", "{blocked}");
    assert_eq!(blocked["report"]["reason_codes"], json!(["revoked_capability"]));
    assert_eq!(
        w.provider_calls.load(Ordering::SeqCst),
        calls_before,
        "nothing reached the provider"
    );
    let listed: Value = plain
        .get(format!("{}/v1/revocations", w.base))
        .bearer_auth("ops-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(listed["revoked"][0]["by"], "svc_oncall");

    // Restored, the same operation proceeds.
    assert_eq!(
        change("/restore", "ops-key", "capability", "adp_payments.issue_refund")
            .await
            .status(),
        200
    );
    let done: Value = http
        .post(format!("{}/v1/runs/run_killed/tool-calls", w.base))
        .bearer_auth("acme-key")
        .json(&tool_call("run_killed", "tc_1", 120_000))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(done["result"]["status"], "completed", "{done}");

    // A revoked agent cannot start new runs.
    assert_eq!(change("", "ops-key", "agent", "agt_support").await.status(), 200);
    let refused = plain
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_after_kill", 1200))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 403);
    assert_eq!(
        refused.json::<Value>().await.unwrap()["error"]["detail"],
        json!(["revoked_agent"])
    );

    let verified: Value = plain
        .get(format!("{}/v1/audit/verify", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(verified["verified"], true);
}

#[tokio::test]
async fn rollouts_route_runs_and_shadow_the_rest() {
    let w = world(&ALL_CONTROLS).await;
    let plain = reqwest::Client::new();
    let (baseline, candidate) = ("ctxpack.support@5.2.0", "ctxpack.support@5.3.0");
    let set_gated = |key: &'static str, percent: u8, shadow: bool, gate: Value| {
        let (plain, url) = (plain.clone(), format!("{}/v1/rollouts", w.base));
        async move {
            let mut body = json!({"baseline": baseline, "candidate": candidate, "percent": percent, "shadow": shadow, "reason": "v5.3 canary"});
            body.as_object_mut().unwrap().extend(gate.as_object().unwrap().clone());
            plain.post(url).bearer_auth(key).json(&body).send().await.unwrap()
        }
    };
    let set = |key: &'static str, percent: u8, shadow: bool| set_gated(key, percent, shadow, json!({}));
    let admit = |run: String| {
        let (plain, url) = (plain.clone(), format!("{}/v1/runs", w.base));
        async move {
            let response = plain
                .post(url)
                .bearer_auth("acme-key")
                .json(&run_body(&run, 4200))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 201, "{run}");
            response.json::<Value>().await.unwrap()
        }
    };
    assert_eq!(
        set("acme-key", 0, true).await.status(),
        403,
        "only operators steer traffic"
    );

    // Shadow: the run stays on the baseline; the candidate's difference is audited.
    assert_eq!(set("ops-key", 0, true).await.status(), 200);
    let shadowed = admit("run_shadow".into()).await;
    assert_eq!(shadowed["pack_ref"], baseline);
    assert_eq!(shadowed["rollout"]["on_candidate"], false);
    let mut diff = None;
    for _ in 0..50 {
        let audit: Value = plain
            .get(format!("{}/v1/audit/entries?from=1&limit=500", w.base))
            .bearer_auth("acme-key")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        diff = audit["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e.to_string().contains("shadow_diff"))
            .cloned();
        if diff.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let diff = diff.expect("the shadow diff is audited").to_string();
    assert!(
        diff.contains("policy require_approval -> allow") && diff.contains("run_shadow"),
        "{diff}"
    );

    // Live traffic only through the release gate on replayed cases: none named is
    // refused; the candidate's dropped approval fails it until acknowledged per case.
    assert_eq!(set("ops-key", 100, false).await.status(), 422);
    let failed = set_gated("ops-key", 100, false, json!({"gate_runs": ["run_shadow"]})).await;
    assert_eq!(failed.status(), 409);
    let failed: Value = failed.json().await.unwrap();
    assert_eq!(failed["error"]["code"], "release_gate_failed", "{failed}");
    let missing = set_gated("ops-key", 100, false, json!({"gate_runs": ["run_nope"]})).await;
    assert_eq!(missing.status(), 409);
    let acknowledged = json!({"gate_runs": ["run_shadow"], "acknowledge": {"policy_loosening": ["run_shadow"]}});

    // 100%: new runs are admitted on, and pinned to, the candidate.
    let live = set_gated("ops-key", 100, false, acknowledged.clone()).await;
    assert_eq!(live.status(), 200);
    let canary = admit("run_canary".into()).await;
    assert_eq!(canary["pack_ref"], candidate);
    assert_eq!(canary["rollout"]["on_candidate"], true);
    let evidence: Value = plain
        .get(format!("{}/v1/runs/run_canary/evidence", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(evidence["admission"]["pack_ref"], candidate);

    // 50%: routing follows the published, sticky bucket of each run.
    assert_eq!(
        set_gated("ops-key", 50, false, acknowledged.clone()).await.status(),
        200
    );
    let mut on_candidate = 0;
    for i in 0..8 {
        let run = format!("run_split_{i}");
        let expected = if contextosd::rollout::bucket(TENANT, &run) < 50 {
            candidate
        } else {
            baseline
        };
        on_candidate += usize::from(expected == candidate);
        assert_eq!(admit(run).await["pack_ref"], expected);
    }
    assert!((1..8).contains(&on_candidate), "the split exercised both packs");

    // Cleared: everything returns to the baseline.
    let cleared = plain
        .post(format!("{}/v1/rollouts/clear", w.base))
        .bearer_auth("ops-key")
        .json(&json!({"baseline": baseline, "reason": "rolled back"}))
        .send()
        .await
        .unwrap();
    assert_eq!(cleared.status(), 200);
    assert_eq!(admit("run_after_clear".into()).await["pack_ref"], baseline);

    // What was waived is in the audit chain, case by case.
    let audit: Value = plain
        .get(format!("{}/v1/audit/entries?from=1&limit=1000", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let set = audit["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["kind"] == "rollout_set" && e["payload"]["percent"] == 100)
        .unwrap()
        .clone();
    assert_eq!(set["payload"]["gate"]["waived"][0]["case"], "run_shadow", "{set}");

    // Once a correction is open on that run, its case cannot be waived.
    let filed = plain
        .post(format!("{}/v1/runs/run_shadow/feedback", w.base))
        .bearer_auth("judge-key")
        .json(
            &json!({"kind": "correction", "target_surface": "policy", "summary": "High-value refunds need approval."}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(filed.status(), 201);
    let refused = set_gated("ops-key", 100, false, acknowledged.clone()).await;
    assert_eq!(refused.status(), 422);
    assert_eq!(
        refused.json::<Value>().await.unwrap()["error"]["code"],
        "feedback_not_waivable"
    );
}
