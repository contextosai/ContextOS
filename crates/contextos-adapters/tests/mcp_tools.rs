//! Listing an MCP server's tools for upstream drift checks.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::Router;
use axum::http::{HeaderMap, header};
use axum::response::IntoResponse;
use axum::routing::post;
use contextos_adapters::*;
use contextos_gateway::{AdapterCall, CapabilityManifest, PortError};
use serde_json::{Value, json};

struct Discovery;
#[async_trait]
impl CredentialBroker for Discovery {
    async fn credential(&self, _: &CapabilityManifest, _: &AdapterCall) -> Result<Option<Credential>, PortError> {
        Ok(Some(Credential::bearer("call-token")))
    }

    async fn discovery_credential(&self) -> Result<Option<Credential>, PortError> {
        Ok(Some(Credential::bearer("list-token")))
    }
}

#[tokio::test]
async fn tools_are_listed_across_pages_with_the_discovery_credential() {
    let seen: Arc<Mutex<Vec<(HeaderMap, Value)>>> = Arc::default();
    let log = seen.clone();
    let router = Router::new().fallback(post(move |headers: HeaderMap, body: String| {
        let log = log.clone();
        async move {
            let request: Value = serde_json::from_str(&body).unwrap();
            log.lock().unwrap().push((headers, request.clone()));
            let result = if request["params"]["cursor"] == "page2" {
                json!({"tools": [{"name": "refunds.status"}]})
            } else {
                json!({"tools": [{"name": "refunds.create"}], "nextCursor": "page2"})
            };
            (
                [(header::CONTENT_TYPE, "application/json")],
                json!({"jsonrpc": "2.0", "id": request["id"], "result": result}).to_string(),
            )
                .into_response()
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let policy = TransportPolicy {
        allow_loopback_http: true,
        ..TransportPolicy::default()
    };
    let adapter = McpAdapter::new(
        &format!("http://{addr}/mcp"),
        policy,
        Arc::new(Discovery),
        "contextos-test",
    )
    .unwrap();
    let tools = adapter.list_tools().await.unwrap();
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    assert_eq!(names, ["refunds.create", "refunds.status"]);
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    assert!(
        seen.iter().all(|(_, r)| r["method"] == "tools/list"),
        "listing never calls a tool"
    );
    assert_eq!(seen[0].0["authorization"], "Bearer list-token");
}
