//! Every governed call, however it arrives, leaves one access line and one
//! `contextos.dispatch` span with the GenAI tool attributes and the stage it ended in.
//!
//! Its own test binary: tracing caches which callsites are enabled process-wide, so a
//! capturing subscriber shares a process with other tests unreliably.

use std::io::Write;
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

#[allow(dead_code)]
#[path = "dispatch/harness.rs"]
mod harness;

use harness::*;

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Captured {
    fn access_lines(&self) -> Vec<Value> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter(|l| l["target"] == "contextos::access")
            .collect()
    }
}

#[tokio::test]
async fn governed_calls_leave_an_access_line_and_a_tool_span() {
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_current_span(true)
        .with_env_filter("warn,contextos_gateway=info,contextos::access=info")
        .with_writer(move || writer.clone())
        .finish();
    // The test runtime is single-threaded, so the server's tasks log here too.
    let _guard = tracing::subscriber::set_default(subscriber);

    let w = world(&ALL_CONTROLS).await;
    assert_eq!(admit(&w, &run_body("run_obs", 1200)).await.status(), 201);
    // Over the REST API: completes.
    let done = dispatch(&w, "run_obs", &tool_call("run_obs", "tc_rest", 1200)).await;
    assert_eq!(done["report"]["status"], "completed", "{done}");
    // Over MCP: an unknown argument is refused at the argument check.
    let refused = executor_client(2)
        .post(format!("{}/v1/runs/run_obs/mcp", w.base))
        .bearer_auth("acme-key")
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name": "adp_payments_issue_refund",
            "arguments": {"order_id": "ord_881", "customer_id": "cus_77", "amount_minor": 5, "note": "x"},
            "_meta": {"io.contextos/toolCallId": "tc_mcp"}}}))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(refused["result"]["isError"], true, "{refused}");

    let lines = captured.access_lines();
    assert_eq!(lines.len(), 2, "{lines:#?}");
    let rest = lines.iter().find(|l| l["fields"]["tool_call_id"] == "tc_rest").unwrap();
    assert_eq!(rest["fields"]["status"], "completed");
    assert_eq!(rest["fields"]["stage"], "result");
    assert_eq!(rest["fields"]["capability_id"], "adp_payments.issue_refund");
    assert_eq!(rest["fields"]["run_id"], "run_obs");
    let stages: Vec<&str> = rest["fields"]["stages"]
        .as_str()
        .unwrap()
        .split(' ')
        .map(|s| s.split('=').next().unwrap())
        .collect();
    assert_eq!(
        stages,
        [
            "fence",
            "surface",
            "bind",
            "authorize",
            "reserve",
            "claim",
            "dispatch",
            "settle",
            "result"
        ]
    );
    let span = &rest["span"];
    assert_eq!(span["name"], "contextos.dispatch");
    assert_eq!(span["gen_ai.operation.name"], "execute_tool");
    assert_eq!(span["gen_ai.tool.name"], "adp_payments.issue_refund");
    assert_eq!(span["gen_ai.tool.call.id"], "tc_rest");
    assert_eq!(span["contextos.status"], "completed");

    let mcp = lines.iter().find(|l| l["fields"]["tool_call_id"] == "tc_mcp").unwrap();
    assert_ne!(mcp["fields"]["status"], "completed");
    assert_eq!(mcp["fields"]["reason_codes"], "arguments_invalid");
    assert_ne!(
        mcp["fields"]["stage"], "result",
        "a refusal names the stage that refused"
    );
    assert_eq!(mcp["span"]["error.type"], "arguments_invalid");
}
