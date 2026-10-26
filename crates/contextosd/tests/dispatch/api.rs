//! The published API description, and agent hosts over MCP.

use std::sync::atomic::Ordering;

use serde_json::{Value, json};

use crate::harness::*;

#[tokio::test]
async fn agent_hosts_use_governed_tools_over_mcp() {
    let w = world(&ALL_CONTROLS).await;
    let http = executor_client(2);
    assert_eq!(
        http.post(format!("{}/v1/runs", w.base))
            .bearer_auth("acme-key")
            .json(&run_body("run_mcp", 1200))
            .send()
            .await
            .unwrap()
            .status(),
        201
    );
    let url = format!("{}/v1/runs/run_mcp/mcp", w.base);
    let rpc = |id: u64, method: &str, params: Value| {
        let http = http.clone();
        let url = url.clone();
        let body = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        async move {
            http.post(url)
                .bearer_auth("acme-key")
                .json(&body)
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap()
        }
    };
    let init = rpc(
        1,
        "initialize",
        json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "host", "version": "1"}}),
    )
    .await;
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    conforms("McpResponse", &init);

    let listed = rpc(2, "tools/list", json!({})).await;
    conforms("McpResponse", &listed);
    let tools = listed["result"]["tools"].as_array().unwrap();
    // Listed under a name model APIs accept; the capability id travels with it.
    let refund = tools
        .iter()
        .find(|t| t["name"] == "adp_payments_issue_refund")
        .expect("surfaced capability listed");
    assert_eq!(
        refund["_meta"]["io.contextos/capabilityId"],
        "adp_payments.issue_refund"
    );
    assert_eq!(refund["title"], "adp_payments.issue_refund");
    assert_eq!(refund["annotations"]["destructiveHint"], true);
    assert_eq!(
        refund["inputSchema"]["required"],
        json!(["order_id", "customer_id", "amount_minor"])
    );

    let evidence = json!({"io.contextos/evidenceRefs": ["kg:order:ord_881#snapshot_kg_2026_05_03_T0930"]});
    let call = |id: u64, arguments: Value| {
        rpc(
            id,
            "tools/call",
            json!({"name": "adp_payments.issue_refund", "arguments": arguments, "_meta": evidence}),
        )
    };
    let args = json!({"order_id": "ord_881", "customer_id": "cus_77", "amount_minor": 120_000});
    let cited = json!({"io.contextos/evidenceRefs": ["kg:order:ord_881#snapshot_kg_2026_05_03_T0930"],
        "io.contextos/toolCallId": "tc_host_1"});
    let done = rpc(
        3,
        "tools/call",
        json!({"name": "adp_payments.issue_refund", "arguments": args, "_meta": cited}),
    )
    .await;
    assert_eq!(done["result"]["isError"], false, "{done}");
    conforms("McpResponse", &done);
    assert_eq!(done["result"]["structuredContent"]["refund_id"], "rf_77");
    // The result names the call and operation, so a decision can cite them.
    assert_eq!(done["result"]["_meta"]["io.contextos/toolCallId"], "tc_host_1");
    let operation = done["result"]["_meta"]["io.contextos/operationId"].clone();
    assert!(operation.as_str().unwrap().starts_with("mcp:"), "{operation}");

    // A host retrying what it believes failed cannot refund twice.
    let retried = call(4, args.clone()).await;
    assert_eq!(retried["result"]["isError"], true);
    conforms("McpResponse", &retried);
    assert_eq!(
        retried["result"]["structuredContent"]["reason_codes"],
        json!(["retry_unsafe"])
    );
    assert_eq!(retried["result"]["_meta"]["io.contextos/operationId"], operation);
    assert_eq!(w.provider_calls.load(Ordering::SeqCst), 1);

    // The listed name and the capability id name the same tool: a retry by either is the
    // same operation.
    let by_listed_name = rpc(
        41,
        "tools/call",
        json!({"name": "adp_payments_issue_refund", "arguments": args, "_meta": evidence}),
    )
    .await;
    assert_eq!(
        by_listed_name["result"]["structuredContent"]["reason_codes"],
        json!(["retry_unsafe"]),
        "{by_listed_name}"
    );
    assert_eq!(w.provider_calls.load(Ordering::SeqCst), 1);

    // Arguments are checked against the reviewed schema before anything else.
    let invalid = call(
        5,
        json!({"order_id": "ord_9", "customer_id": "cus_77", "amount_minor": 5, "note": "x"}),
    )
    .await;
    assert_eq!(
        invalid["result"]["structuredContent"]["reason_codes"],
        json!(["arguments_invalid"])
    );

    // A tool that needs input: the host answers and the same operation continues.
    let ask = call(
        6,
        json!({"order_id": "ord_555", "customer_id": "cus_77", "amount_minor": 555}),
    )
    .await;
    assert_eq!(ask["result"]["resultType"], "input_required", "{ask}");
    let state = ask["result"]["requestState"].clone();
    let answered = rpc(
        7,
        "tools/call",
        json!({"name": "adp_payments.issue_refund", "_meta": evidence,
        "arguments": {"order_id": "ord_555", "customer_id": "cus_77", "amount_minor": 555},
        "inputResponses": {"reason": {"action": "accept", "content": {"reason": "late"}}}, "requestState": state}),
    )
    .await;
    assert_eq!(answered["result"]["isError"], false, "{answered}");
    assert_eq!(answered["result"]["structuredContent"]["reason"], "late");

    let unknown = rpc(
        8,
        "tools/call",
        json!({"name": "adp_crm.delete_customer", "arguments": {}}),
    )
    .await;
    assert_eq!(unknown["error"]["code"], -32602);
    let stale = reqwest::Client::new()
        .post(&url)
        .bearer_auth("acme-key")
        .header("contextos-executor-generation", "1")
        .json(&json!({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
            "params": {"name": "adp_payments.issue_refund", "arguments": args, "_meta": evidence}}))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(
        stale["result"]["structuredContent"]["reason_codes"],
        json!(["executor_stale"])
    );
    let missing = reqwest::Client::new()
        .post(&url)
        .bearer_auth("acme-key")
        .json(&json!({"jsonrpc": "2.0", "id": 10, "method": "tools/call", "params": {"name": "adp_payments.issue_refund", "arguments": args}}))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(missing["error"]["code"], -32602, "the executor generation is required");
}

#[tokio::test]
async fn the_api_description_is_served() {
    let w = world(&ALL_CONTROLS).await;
    let response = reqwest::get(format!("{}/v1/openapi.json", w.base)).await.unwrap();
    assert_eq!(response.status(), 200);
    let doc: Value = response.json().await.unwrap();
    assert_eq!(doc["openapi"], "3.1.0");
    assert!(doc["paths"]["/v1/runs/{run_id}/tool-calls"]["post"].is_object());
}

/// The document lists `status` among the operation's responses.
fn documented(method: &str, path: &str, status: u16) {
    let doc: Value = serde_json::from_str(contextosd::app::OPENAPI).unwrap();
    let responses = &doc["paths"][path][method]["responses"];
    assert!(
        responses.get(status.to_string()).is_some(),
        "{method} {path} returned undocumented {status}"
    );
}

#[tokio::test]
async fn bodies_match_the_api_description() {
    let w = world(&ALL_CONTROLS).await;
    let http = executor_client(1);
    let body = run_body("run_shapes", 1200);
    conforms("AdmissionRequest", &body);
    let admitted = http
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(admitted.status(), 201);
    let admitted: Value = admitted.json().await.unwrap();
    conforms("Admission", &admitted);
    let http = executor_client(admitted["executor_generation"].as_u64().unwrap());

    let status: Value = http
        .get(format!("{}/v1/runs/run_shapes", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    conforms("RunStatus", &status);

    let call = tool_call("run_shapes", "tc_1", 120_000);
    let out: Value = http
        .post(format!("{}/v1/runs/run_shapes/tool-calls", w.base))
        .bearer_auth("acme-key")
        .json(&call)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(out["result"]["status"], "completed", "{}", out["report"]);
    conforms("ToolCallOutcome", &out);
    let audit = executor_client(0)
        .get(format!("{}/v1/audit/entries?from=1&limit=2", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap();
    assert_eq!(audit.status(), 200);
    let page: Value = audit.json().await.unwrap();
    assert_eq!(page["entries"].as_array().unwrap().len(), 2);
    conforms("AuditPage", &page);

    let decision = json!({"decision_key": "support.refund.execute", "decision_version": "1", "status": "DECIDED",
        "outcome": "refund_issued", "rationale": {"strategy": "policy_and_evidence"},
        "tool_calls": [{"tool_call_id": "tc_1", "operation_id": out["report"]["operation_id"]}]});
    conforms("DecisionReport", &decision);
    let recorded = http
        .post(format!("{}/v1/runs/run_shapes/decisions", w.base))
        .bearer_auth("acme-key")
        .json(&decision)
        .send()
        .await
        .unwrap();
    documented("post", "/v1/runs/{run_id}/decisions", recorded.status().as_u16());
    conforms("RecordedDecision", &recorded.json().await.unwrap());
    let evidence = http
        .get(format!("{}/v1/runs/run_shapes/evidence", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap();
    documented("get", "/v1/runs/{run_id}/evidence", evidence.status().as_u16());
    conforms("EvidenceBundle", &evidence.json().await.unwrap());
    let verified = http
        .get(format!("{}/v1/audit/verify", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap();
    documented("get", "/v1/audit/verify", verified.status().as_u16());
    conforms("AuditVerification", &verified.json().await.unwrap());

    let case: Value = http
        .get(format!("{}/v1/runs/run_shapes/replay-case", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    conforms("ReplayCase", &case);

    let missing = http
        .get(format!("{}/v1/runs/run_absent", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 404);
    conforms("Error", &missing.json().await.unwrap());

    let taken: Value = http
        .post(format!("{}/v1/runs/run_shapes/takeover", w.base))
        .bearer_auth("acme-key")
        .json(&json!({"expected_generation": status["executor_generation"]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    conforms("Ownership", &taken);
}
