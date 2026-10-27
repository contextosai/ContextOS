//! Compensation over HTTP: an applied refund is reversed by a new governed operation.

use std::sync::atomic::Ordering;

use serde_json::{Value, json};

use crate::harness::*;

/// The refund declares its reversal; both manifests are pinned.
fn reversible(config: &mut contextosd::config::Config) {
    let refund = &config.capabilities[0];
    let mut manifest: Value = serde_json::from_str(&std::fs::read_to_string(refund).unwrap()).unwrap();
    manifest["compensation"] = json!({"capability_id": "adp_payments.reverse_refund",
        "arguments": {"order_id": "/arguments/order_id", "amount_minor": "/arguments/amount_minor"}});
    let mut reverse = manifest.clone();
    reverse.as_object_mut().unwrap().remove("compensation");
    for (key, value) in [
        ("capability_id", json!("adp_payments.reverse_refund")),
        ("protocol_tool", json!("reverse_refund")),
        ("desired_effect", json!("refund_reversed")),
        ("destination_pointers", json!([])),
        ("description", json!("Reverse a refund.")),
        (
            "input_schema",
            json!({"type": "object", "additionalProperties": false, "required": ["order_id", "amount_minor"],
            "properties": {"order_id": {"type": "string"}, "amount_minor": {"type": "integer", "minimum": 1}}}),
        ),
    ] {
        reverse[key] = value;
    }
    reverse["action_risk"]["reversibility"] = json!("irreversible");
    let refund_path = refund.with_extension("compensable.json");
    let reverse_path = refund.with_extension("reverse.json");
    std::fs::write(&refund_path, manifest.to_string()).unwrap();
    std::fs::write(&reverse_path, reverse.to_string()).unwrap();
    config.capabilities = vec![refund_path, reverse_path];
}

#[tokio::test]
async fn an_applied_refund_is_compensated_over_http() {
    let w = world_with(&ALL_CONTROLS, 1, reversible).await;
    let http = executor_client(2);
    let mut body = run_body("run_saga", 1200);
    body["pack_ref"] = json!("ctxpack.support@5.4.0");
    let admitted = admit(&w, &body).await;
    assert_eq!(admitted.status(), 201, "{}", admitted.text().await.unwrap());
    let out = dispatch(&w, "run_saga", &tool_call("run_saga", "tc_1", 120_000)).await;
    assert_eq!(out["result"]["status"], "completed", "{out}");

    let list = |path: &'static str| {
        let url = format!("{}/v1/runs/run_saga/{path}", w.base);
        async move {
            reqwest::Client::new()
                .get(url)
                .bearer_auth("acme-key")
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap()
        }
    };
    let listed = list("compensations").await;
    assert_eq!(listed["effects"][0]["operation_id"], "refund:run_saga", "{listed}");
    assert_eq!(listed["effects"][0]["state"], "compensable");

    // The executor generation is required; the request names the effect only.
    let url = format!("{}/v1/runs/run_saga/operations/refund:run_saga/compensate", w.base);
    let fenced = reqwest::Client::new()
        .post(&url)
        .bearer_auth("acme-key")
        .json(&json!({"tool_call_id": "tc_undo"}))
        .send()
        .await
        .unwrap();
    assert_eq!(fenced.status(), 428);
    let invalid = http
        .post(&url)
        .bearer_auth("acme-key")
        .json(&json!({"tool_call_id": "tc_undo", "args": {"amount_minor": 1}}))
        .send()
        .await
        .unwrap();
    assert_eq!(invalid.status(), 422);

    let undone: Value = http
        .post(&url)
        .bearer_auth("acme-key")
        .json(&json!({"tool_call_id": "tc_undo"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(undone["result"]["status"], "completed", "{undone}");
    assert_eq!(undone["result"]["capability_id"], "adp_payments.reverse_refund");
    assert_eq!(
        undone["result"]["metadata"]["compensates_operation_id"],
        "refund:run_saga"
    );
    conforms("ToolCallOutcome", &undone);
    assert_eq!(w.provider_calls.load(Ordering::SeqCst), 2);
    assert_eq!(list("compensations").await["effects"][0]["state"], "compensated");

    // Nothing is left for the saga to undo, and nothing is sent twice.
    let saga: Value = http
        .post(format!("{}/v1/runs/run_saga/compensate", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        saga,
        json!({"run_id": "run_saga", "status": "compensated", "steps": [], "stopped_at": null})
    );
    assert_eq!(w.provider_calls.load(Ordering::SeqCst), 2);
    let audit: Value = http
        .get(format!("{}/v1/audit/verify", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(audit["verified"], true, "{audit}");
}
