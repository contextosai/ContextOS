//! Envoy / agentgateway HTTP `ext_authz` backend (`POST /v1/ext-authz`).

use serde_json::{Value, json};

use crate::harness::*;

#[tokio::test]
async fn ext_authz_allows_and_forbids_envelopes_mcp_and_raw_arguments() {
    let w = world(&ALL_CONTROLS).await;
    assert_eq!(admit(&w, &run_body("run_ext_ok", 1200)).await.status(), 201);
    assert_eq!(admit(&w, &run_body("run_ext_big", 4200)).await.status(), 201);

    let client = reqwest::Client::new();

    // 1. Native tool-call envelope allowed -> 200 OK with check-only headers.
    let call = tool_call("run_ext_ok", "tc_ext_1", 120_000);
    let resp = client
        .post(format!("{}/v1/ext-authz", w.base))
        .bearer_auth("acme-key")
        .header("ContextOS-Run-Id", "run_ext_ok")
        .json(&call)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("x-contextos-verdict").unwrap(), "allow");
    assert_eq!(resp.headers().get("x-contextos-check-only").unwrap(), "true");
    assert!(resp.headers().contains_key("x-contextos-action-digest"));
    assert!(resp.headers().contains_key("x-contextos-not-evaluated"));
    assert!(resp.headers().contains_key("x-contextos-audit-sequence"));
    let body: Value = resp.json().await.unwrap();
    conforms("ToolCallCheck", &body);
    assert_eq!(body["check"]["status"], "allowed");

    // 2. MCP JSON-RPC `tools/call` allowed -> 200 OK.
    let mcp_call = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "adp_payments_issue_refund",
            "arguments": {"order_id": "ord_881", "customer_id": "cus_77", "amount_minor": 120_000},
            "_meta": {
                "io.contextos/idempotencyKey": "mcp_ext_1",
                "io.contextos/evidenceRefs": ["kg:order:ord_881#snapshot_kg_2026_05_03_T0930"]
            }
        }
    });
    let resp = client
        .post(format!("{}/v1/ext-authz", w.base))
        .bearer_auth("acme-key")
        .header("ContextOS-Run-Id", "run_ext_ok")
        .json(&mcp_call)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("x-contextos-verdict").unwrap(), "allow");

    // 3. Approval-requiring call -> 403 Forbidden with approval_required verdict header.
    let big_call = tool_call("run_ext_big", "tc_ext_big", 420_000);
    let resp = client
        .post(format!("{}/v1/ext-authz", w.base))
        .bearer_auth("acme-key")
        .header("ContextOS-Run-Id", "run_ext_big")
        .json(&big_call)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    assert_eq!(resp.headers().get("x-contextos-verdict").unwrap(), "approval_required");
    assert_eq!(resp.headers().get("x-contextos-check-only").unwrap(), "true");
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["check"]["status"], "approval_required");

    // 4. Plain JSON arguments with ContextOS-Capability header.
    let resp = client
        .post(format!("{}/v1/ext-authz", w.base))
        .bearer_auth("acme-key")
        .header("ContextOS-Run-Id", "run_ext_ok")
        .header("ContextOS-Capability", "adp_payments.issue_refund")
        .json(&json!({"order_id": "ord_881", "customer_id": "cus_77", "amount_minor": 120_000}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("x-contextos-verdict").unwrap(), "allow");
}

#[tokio::test]
async fn ext_authz_fails_closed_on_mismatched_capability_missing_run_or_unsupported_mcp() {
    let w = world(&ALL_CONTROLS).await;
    assert_eq!(admit(&w, &run_body("run_ext_fail", 1200)).await.status(), 201);
    let client = reqwest::Client::new();

    // Missing ContextOS-Run-Id header -> 400.
    let resp = client
        .post(format!("{}/v1/ext-authz", w.base))
        .bearer_auth("acme-key")
        .json(&tool_call("run_ext_fail", "tc_1", 10_000))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Header capability disagrees with body capability -> 422 capability_mismatch.
    let resp = client
        .post(format!("{}/v1/ext-authz", w.base))
        .bearer_auth("acme-key")
        .header("ContextOS-Run-Id", "run_ext_fail")
        .header("ContextOS-Capability", "other.capability")
        .json(&tool_call("run_ext_fail", "tc_1", 10_000))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 422);

    // Non-tools/call MCP JSON-RPC method -> 422 unsupported_mcp_method (never fails open).
    let resp = client
        .post(format!("{}/v1/ext-authz", w.base))
        .bearer_auth("acme-key")
        .header("ContextOS-Run-Id", "run_ext_fail")
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 422);

    // Stale executor generation -> 403 Forbidden.
    let resp = client
        .post(format!("{}/v1/ext-authz", w.base))
        .bearer_auth("acme-key")
        .header("ContextOS-Run-Id", "run_ext_fail")
        .header("ContextOS-Executor-Generation", "1")
        .json(&tool_call("run_ext_fail", "tc_1", 10_000))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    assert_eq!(resp.headers().get("x-contextos-verdict").unwrap(), "rejected");
}
