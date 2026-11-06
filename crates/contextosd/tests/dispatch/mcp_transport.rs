//! The MCP endpoint's transport checks, and stdio hosts through `contextosd --mcp-stdio`.

use std::process::Stdio;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::harness::*;

#[tokio::test]
async fn browser_origins_and_protocol_versions_are_checked() {
    let w = world_with(&ALL_CONTROLS, 1, |c| {
        c.server.allowed_origins = vec!["https://console.example".into()];
    })
    .await;
    assert_eq!(admit(&w, &run_body("run_tx", 100)).await.status(), 201);
    let url = format!("{}/v1/runs/run_tx/mcp", w.base);
    let http = executor_client(2);
    let post = |body: Value, headers: &[(&'static str, &'static str)]| {
        let mut request = http.post(&url).bearer_auth("acme-key").json(&body);
        for (k, v) in headers {
            request = request.header(*k, *v);
        }
        request.send()
    };
    let list = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});

    // A page on another origin cannot drive the run's tools, even with a token.
    let rebound = post(list.clone(), &[("origin", "http://evil.example")]).await.unwrap();
    assert_eq!(rebound.status(), 403);
    let listed = post(list.clone(), &[("origin", "https://console.example")])
        .await
        .unwrap();
    assert_eq!(listed.status(), 200);

    // The response names the version the request used; an unknown one is refused.
    let versioned = post(list.clone(), &[("mcp-protocol-version", "2025-06-18")])
        .await
        .unwrap();
    assert_eq!(versioned.headers()["mcp-protocol-version"], "2025-06-18");
    let unknown = post(list.clone(), &[("mcp-protocol-version", "2000-01-01")])
        .await
        .unwrap();
    assert_eq!(unknown.status(), 400);
    let initialized = post(
        json!({"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}}),
        &[],
    )
    .await
    .unwrap();
    assert_eq!(initialized.headers()["mcp-protocol-version"], "2025-03-26");

    // Notifications are accepted; a call without an id is refused, not dropped.
    let note = post(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}), &[])
        .await
        .unwrap();
    assert_eq!(note.status(), 202);
    let idless = post(
        json!({"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "adp_payments.issue_refund"}}),
        &[],
    )
    .await
    .unwrap();
    assert_eq!(idless.status(), 400);
}

#[tokio::test]
async fn stdio_hosts_reach_the_run_through_the_bridge() {
    let w = world(&ALL_CONTROLS).await;
    assert_eq!(admit(&w, &run_body("run_stdio", 100)).await.status(), 201);
    let mut bridge = tokio::process::Command::new(env!("CARGO_BIN_EXE_contextosd"))
        .args(["--mcp-stdio", &format!("{}/v1/runs/run_stdio/mcp", w.base)])
        .env("CONTEXTOS_TOKEN", "acme-key")
        .env("CONTEXTOS_EXECUTOR_GENERATION", "2")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stdin = bridge.stdin.take().unwrap();
    let mut stdout = BufReader::new(bridge.stdout.take().unwrap()).lines();
    let messages = [
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}}),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    ];
    for message in &messages {
        stdin.write_all(format!("{message}\n").as_bytes()).await.unwrap();
    }
    stdin.write_all(b"not json\n").await.unwrap();
    drop(stdin);

    let mut replies = Vec::new();
    while let Some(line) = stdout.next_line().await.unwrap() {
        replies.push(serde_json::from_str::<Value>(&line).unwrap());
    }
    assert!(bridge.wait().await.unwrap().success());
    // One reply per request (none for the notification), in any order after initialize.
    assert_eq!(replies.len(), 3, "{replies:?}");
    assert_eq!(replies[0]["result"]["protocolVersion"], "2025-06-18");
    let listed = replies.iter().find(|r| r["id"] == 2).expect("tools/list answered");
    assert!(
        listed["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == "adp_payments_issue_refund"),
        "{listed}"
    );
    let parse = replies.iter().find(|r| r["id"].is_null()).unwrap();
    assert_eq!(parse["error"]["code"], -32700);
}
