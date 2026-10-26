//! Task authorizations: what the principal allowed, amendments mid-run, review at admission.

use std::sync::atomic::Ordering;

use contextos_store::DocumentStore;
use serde_json::{Value, json};

use crate::harness::*;

#[tokio::test]
async fn effects_outside_what_the_principal_authorized_are_refused() {
    let w = world(&ALL_CONTROLS).await;
    let mut body = run_body("run_scoped", 1200);
    body["task_authorization"] = task_authorization("run_scoped", "deny", 120_000);
    let admitted = admit(&w, &body).await;
    assert_eq!(admitted.status(), 201, "{}", admitted.text().await.unwrap());

    // The request said INR 1200 for ord_881; the agent's actual calls decide.
    for (key, order, customer, amount, dimension) in [
        ("op_4x", "ord_881", "cus_77", 480_000, "task_scope_amount"),
        ("op_other_order", "ord_999", "cus_77", 120_000, "task_scope_resource"),
        (
            "op_other_customer",
            "ord_881",
            "cus_attacker",
            1_000,
            "task_scope_destination",
        ),
    ] {
        let out = dispatch(&w, "run_scoped", &refund("run_scoped", key, order, customer, amount)).await;
        assert_eq!(out["result"]["status"], "blocked", "{key}: {out}");
        let reasons = out["report"]["reason_codes"].as_array().unwrap();
        for code in ["guardrail_denied", "outside_task_authorization", dimension] {
            assert!(reasons.contains(&json!(code)), "{key}: {out}");
        }
        // A clean policy denial, not an evaluation error.
        assert!(!reasons.contains(&json!("policy_binding_mismatch")), "{key}: {out}");
    }
    assert_eq!(
        w.provider_calls.load(Ordering::SeqCst),
        0,
        "nothing outside the task reached the provider"
    );

    // What was asked for runs.
    let out = dispatch(
        &w,
        "run_scoped",
        &refund("run_scoped", "op_asked", "ord_881", "cus_77", 120_000),
    )
    .await;
    assert_eq!(out["result"]["status"], "completed", "{out}");
    assert_eq!(w.provider_calls.load(Ordering::SeqCst), 1);

    // The refusal is in the signed decision, citing the pinned task authorization.
    let entries: Value = reqwest::Client::new()
        .get(format!("{}/v1/audit/entries?from=1&limit=1000", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let entries = entries["entries"].as_array().unwrap();
    let admitted = entries.iter().find(|e| e["kind"] == "run_admitted").unwrap();
    let task_ref = &admitted["payload"]["task_authorization_refs"][0];
    assert_eq!(task_ref["artifact_type"], "task_authorization");
    assert!(entries.iter().any(|e| {
        e["kind"] == "authorization_decision"
            && e["payload"]["policy_refs"]
                .as_array()
                .is_some_and(|r| r.contains(task_ref))
    }));
}

#[tokio::test]
async fn the_task_as_a_whole_stays_within_its_limits() {
    let w = world(&ALL_CONTROLS).await;
    let mut body = run_body("run_total", 1200);
    let mut task = task_authorization("run_total", "deny", 120_000);
    task["limits"] = json!({"max_effects": 3, "amount_total": {"minor_units": 120_000, "currency": "INR"}});
    body["task_authorization"] = task.clone();
    assert_eq!(admit(&w, &body).await.status(), 201);

    // Each refund is under the per-action ceiling; together they may not exceed the
    // total the principal asked for.
    let first = refund("run_total", "op_part_1", "ord_881", "cus_77", 70_000);
    let out = dispatch(&w, "run_total", &first).await;
    assert_eq!(out["result"]["status"], "completed", "{out}");
    let out = dispatch(
        &w,
        "run_total",
        &refund("run_total", "op_part_2", "ord_881", "cus_77", 60_000),
    )
    .await;
    assert_eq!(out["result"]["status"], "blocked", "{out}");
    let reasons = out["report"]["reason_codes"].as_array().unwrap();
    for code in ["guardrail_denied", "outside_task_authorization", "task_scope_extent"] {
        assert!(reasons.contains(&json!(code)), "{out}");
    }
    assert!(!reasons.contains(&json!("policy_binding_mismatch")), "{out}");
    assert_eq!(w.provider_calls.load(Ordering::SeqCst), 1);

    // A retry of an applied refund is not charged again; what is left still fits.
    let retried = dispatch(&w, "run_total", &first).await;
    assert_ne!(retried["result"]["status"], "blocked", "{retried}");
    let out = dispatch(
        &w,
        "run_total",
        &refund("run_total", "op_part_3", "ord_881", "cus_77", 50_000),
    )
    .await;
    assert_eq!(out["result"]["status"], "completed", "{out}");
    let used = w
        .state
        .store
        .get(&contextos_store::DocKey::new(
            TENANT,
            contextos_store::DocKind::TaskExposure,
            "run_total",
        ))
        .await
        .unwrap()
        .unwrap()
        .body;
    assert_eq!(
        (used["effects"].clone(), used["amounts"]["INR"].clone()),
        (json!(2), json!(120_000))
    );

    // Raising a total is a widening: the agent's executor cannot make it.
    task["limits"]["amount_total"]["minor_units"] = json!(240_000);
    let (status, _) = amend(&w, "acme-key", "run_total", 0, &task).await;
    assert_eq!(status, 403);
    // Lowering the count is a narrowing it may make, and the count already used stays.
    task["limits"] = json!({"max_effects": 2, "amount_total": {"minor_units": 120_000, "currency": "INR"}});
    let (status, amended) = amend(&w, "acme-key", "run_total", 0, &task).await;
    assert_eq!(
        (status, amended["change"].as_str()),
        (200, Some("narrowed")),
        "{amended}"
    );
    let out = dispatch(
        &w,
        "run_total",
        &refund("run_total", "op_part_4", "ord_881", "cus_77", 1),
    )
    .await;
    assert_eq!(out["result"]["status"], "blocked", "{out}");
    assert!(
        out["report"]["reason_codes"]
            .as_array()
            .unwrap()
            .contains(&json!("task_scope_extent"))
    );
}

#[tokio::test]
async fn an_executor_cannot_allow_itself_amounts() {
    let w = world(&ALL_CONTROLS).await;
    // The principal asked for a refund without naming an amount: no amount is authorized.
    let mut task = task_authorization("run_no_amount", "deny", 0);
    task["scopes"][0].as_object_mut().unwrap().remove("amount_ceiling");
    let mut body = run_body("run_no_amount", 1200);
    body["task_authorization"] = task.clone();
    assert_eq!(admit(&w, &body).await.status(), 201);
    let call = refund("run_no_amount", "op_any", "ord_881", "cus_77", 120_000);
    let out = dispatch(&w, "run_no_amount", &call).await;
    assert!(
        out["report"]["reason_codes"]
            .as_array()
            .unwrap()
            .contains(&json!("task_scope_amount")),
        "{out}"
    );
    // Adding a ceiling looks like a restriction to the delegation rule, but permits
    // refunds the scope refused: it is a widening, which the executor cannot make.
    task["scopes"][0]["amount_ceiling"] = json!({"minor_units": 120_000, "currency": "INR"});
    let (status, refused) = amend(&w, "acme-key", "run_no_amount", 0, &task).await;
    assert_eq!(status, 403, "{refused}");
    assert_eq!(w.provider_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn effects_outside_the_task_can_wait_for_the_principal() {
    let w = world(&ALL_CONTROLS).await;
    let mut body = run_body("run_ask", 1200);
    body["task_authorization"] = task_authorization("run_ask", "ask", 120_000);
    assert_eq!(admit(&w, &body).await.status(), 201);
    let out = dispatch(
        &w,
        "run_ask",
        &refund("run_ask", "op_more", "ord_881", "cus_77", 480_000),
    )
    .await;
    // Asked before acting, about this exact action.
    assert_eq!(out["result"]["status"], "paused", "{out}");
    let obligations = out["report"]["obligations"].as_array().unwrap();
    assert!(obligations.contains(&json!("await_approval")) && obligations.contains(&json!("confirm_with_principal")));
    assert!(out["report"]["approval_request_id"].is_string());
    assert!(
        !out["report"]["reason_codes"]
            .as_array()
            .unwrap()
            .contains(&json!("policy_binding_mismatch"))
    );
    assert_eq!(w.provider_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn principals_correct_the_task_mid_run() {
    let w = world(&ALL_CONTROLS).await;
    let mut body = run_body("run_amend", 1200);
    body["task_authorization"] = task_authorization("run_amend", "deny", 120_000);
    assert_eq!(admit(&w, &body).await.status(), 201);

    // The user meant another account: the agent cannot just send it there.
    let revised = refund("run_amend", "op_revised", "ord_881", "cus_88", 120_000);
    let before = dispatch(&w, "run_amend", &revised).await;
    assert_eq!(before["result"]["status"], "blocked", "{before}");
    assert!(
        before["report"]["reason_codes"]
            .as_array()
            .unwrap()
            .contains(&json!("task_scope_destination"))
    );

    let mut corrected = task_authorization("run_amend", "deny", 120_000);
    corrected["scopes"][0]["destination_ids"] = json!(["cus_88"]);
    // Whoever runs the task cannot widen it, even with the right shape.
    let (status, refused) = amend(&w, "acme-key", "run_amend", 0, &corrected).await;
    assert_eq!(
        (status, refused["error"]["code"].as_str()),
        (403, Some("task_widening_forbidden"))
    );
    // Widening needs the principal's confirmation.
    let (status, refused) = amend(&w, "app-key", "run_amend", 0, &corrected).await;
    assert_eq!(
        (status, refused["error"]["code"].as_str()),
        (422, Some("task_authorization_invalid"))
    );
    corrected["confirmation_ref"] = artifact("principal_confirmation", "chat_msg_42");
    let (status, amended) = amend(&w, "app-key", "run_amend", 0, &corrected).await;
    assert_eq!(
        (status, amended["change"].as_str(), amended["revision"].as_u64()),
        (200, Some("widened"), Some(1)),
        "{amended}"
    );
    // Concurrent corrections are fenced.
    let (status, stale) = amend(&w, "app-key", "run_amend", 0, &corrected).await;
    assert_eq!(
        (status, stale["error"]["code"].as_str()),
        (409, Some("task_authorization_conflict"))
    );

    // The corrected action runs, under a new digest: nothing approved or claimed under
    // the old authorization carries over.
    let after = dispatch(&w, "run_amend", &revised).await;
    assert_eq!(after["result"]["status"], "completed", "{after}");
    assert_ne!(after["report"]["action_digest"], before["report"]["action_digest"]);
    assert_eq!(w.provider_calls.load(Ordering::SeqCst), 1);

    // The executor may always restrict its own task.
    let mut lower = corrected.clone();
    lower["scopes"][0]["amount_ceiling"]["minor_units"] = json!(50_000);
    let (status, narrowed) = amend(&w, "acme-key", "run_amend", 1, &lower).await;
    assert_eq!(
        (status, narrowed["change"].as_str()),
        (200, Some("narrowed")),
        "{narrowed}"
    );
    let more = dispatch(
        &w,
        "run_amend",
        &refund("run_amend", "op_more", "ord_881", "cus_88", 60_000),
    )
    .await;
    assert!(
        more["report"]["reason_codes"]
            .as_array()
            .unwrap()
            .contains(&json!("task_scope_amount")),
        "{more}"
    );

    let entries: Value = reqwest::Client::new()
        .get(format!("{}/v1/audit/entries?from=1&limit=1000", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let changes: Vec<&Value> = entries["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["kind"] == "task_authorization_amended")
        .map(|e| &e["payload"]["change"])
        .collect();
    assert_eq!(changes, [&json!("widened"), &json!("narrowed")]);
}

#[tokio::test]
async fn task_authorizations_are_reviewed_at_admission() {
    let w = world_with(&ALL_CONTROLS, 1, |c| c.guards.require_task_authorization = true).await;
    let refused = admit(&w, &run_body("run_unscoped", 1200)).await;
    assert_eq!(refused.status(), 422);
    let refused: Value = refused.json().await.unwrap();
    assert_eq!(refused["error"]["code"], "task_authorization_required");

    for (mutate, why) in [
        (json!({"scopes": []}), "no scope"),
        (json!({"out_of_scope": "maybe"}), "unknown mode"),
        (json!({"issued_by": "usr_771"}), "not a principal"),
    ] {
        let mut body = run_body("run_bad", 1200);
        let mut task = task_authorization("run_bad", "deny", 1);
        for (k, v) in mutate.as_object().unwrap() {
            task[k] = v.clone();
        }
        body["task_authorization"] = task;
        let refused = admit(&w, &body).await;
        assert_eq!(refused.status(), 422, "{why}");
        let refused: Value = refused.json().await.unwrap();
        assert_eq!(refused["error"]["code"], "task_authorization_invalid", "{why}");
    }
    // A scope written for another task cannot be replayed into this one.
    let mut body = run_body("run_replayed", 1200);
    body["task_authorization"] = task_authorization("run_elsewhere", "deny", 120_000);
    assert_eq!(admit(&w, &body).await.status(), 422);

    let mut body = run_body("run_ok", 1200);
    body["task_authorization"] = task_authorization("run_ok", "deny", 120_000);
    assert_eq!(admit(&w, &body).await.status(), 201);
}
