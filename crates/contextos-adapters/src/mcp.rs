//! MCP adapter for the stateless `2026-07-28` protocol over Streamable HTTP.
//!
//! Stateless means: no `initialize`, no `Mcp-Session-Id`, no GET event stream and no
//! resumption. Every `tools/call` request carries the protocol version and client
//! capabilities in `_meta`; the response must be a JSON-RPC 2.0 response with the
//! same id, delivered as `application/json` or as the first matching event of a
//! `text/event-stream`. Protocol requests ids are *attempt* ids; operation identity
//! and the provider key stay stable across attempts.
//!
//! Discovery is untrusted: the gateway admits only pinned manifests, so this adapter
//! never lists tools and never trusts annotations.
//!
//! | Response | Outcome |
//! |---|---|
//! | result, `isError` false | confirmed (definitive) |
//! | result, `isError` true, read-only capability | not applied (definitive) |
//! | result, `isError` true, effectful capability | unknown (the tool may have partially acted) |
//! | `input_required` / task result | unknown, with the request or task handle in `output` |
//! | JSON-RPC error -32700/-32600/-32601/-32602, incl. unsupported protocol version | not applied (definitive) |
//! | other errors, id mismatch, malformed or lost response | unknown |
//! | connection never established | not dispatched (definitive) |

use std::time::Duration;

use async_trait::async_trait;
use contextos_contract::ingress::parse_strict;
use contextos_contract::types::ActionEffect;
use contextos_gateway::{Adapter, AdapterCall, AdapterResponse, CapabilityManifest, EffectOutcome};
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderValue};
use serde_json::{Map, Value, json};
use url::Url;

use crate::http::{not_dispatched, object};
use crate::transport::{
    CredentialBroker, EndpointError, Exchange, TransportPolicy, client, governance_headers, pinned_endpoint, send,
    traceparent,
};

pub const PROTOCOL_VERSION: &str = "2026-07-28";
const PRE_EXECUTION_ERRORS: [i64; 4] = [-32700, -32600, -32601, -32602];

pub struct McpAdapter {
    endpoint: Url,
    policy: TransportPolicy,
    client: reqwest::Client,
    credentials: std::sync::Arc<dyn CredentialBroker>,
    client_name: String,
}

impl std::fmt::Debug for McpAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpAdapter")
            .field("endpoint", &self.endpoint.as_str())
            .finish_non_exhaustive()
    }
}

impl McpAdapter {
    pub fn new(
        endpoint: &str,
        policy: TransportPolicy,
        credentials: std::sync::Arc<dyn CredentialBroker>,
        client_name: impl Into<String>,
    ) -> Result<Self, EndpointError> {
        Ok(Self {
            endpoint: pinned_endpoint(endpoint, &policy)?,
            client: client(&policy),
            policy,
            credentials,
            client_name: client_name.into(),
        })
    }

    fn request_body(&self, manifest: &CapabilityManifest, call: &AdapterCall) -> Value {
        let mut meta = json!({
            "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": {"name": self.client_name, "version": env!("CARGO_PKG_VERSION")},
            "io.contextos/operationId": call.operation_id,
            "io.contextos/actionDigest": call.action_digest,
        });
        if let Some(tp) = traceparent(call) {
            meta["traceparent"] = json!(tp);
        }
        if let Some(key) = &call.idempotency_key {
            meta["io.contextos/idempotencyKey"] = json!(key);
        }
        json!({
            "jsonrpc": "2.0",
            "id": call.attempt_id,
            "method": "tools/call",
            "params": {"name": manifest.protocol_tool, "arguments": call.arguments, "_meta": meta},
        })
    }
}

/// Extracts the JSON-RPC response with `id` from a JSON or SSE body.
fn rpc_response(content_type: &str, body: &[u8], id: &str, max: usize) -> Option<Value> {
    let matches =
        |v: &Value| v["jsonrpc"] == "2.0" && v["id"] == id && (v.get("result").is_some() ^ v.get("error").is_some());
    if content_type.starts_with("application/json") {
        return parse_strict(body, max).ok().filter(matches);
    }
    if content_type.starts_with("text/event-stream") {
        let text = std::str::from_utf8(body).ok()?;
        let mut data = String::new();
        for line in text.lines().chain(std::iter::once("")) {
            if let Some(rest) = line.strip_prefix("data:") {
                data.push_str(rest.strip_prefix(' ').unwrap_or(rest));
                data.push('\n');
            } else if line.is_empty() && !data.is_empty() {
                if let Ok(value) = parse_strict(data.trim_end().as_bytes(), max)
                    && matches(&value)
                {
                    return Some(value);
                }
                data.clear();
            }
        }
    }
    None
}

#[async_trait]
impl Adapter for McpAdapter {
    async fn invoke(&self, manifest: &CapabilityManifest, call: &AdapterCall) -> AdapterResponse {
        let Ok(credential) = self.credentials.credential(manifest, call).await else {
            return not_dispatched();
        };
        let mut headers = governance_headers(call, credential.as_ref());
        headers.insert(ACCEPT, HeaderValue::from_static("application/json, text/event-stream"));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert("mcp-protocol-version", HeaderValue::from_static(PROTOCOL_VERSION));
        let request = self
            .client
            .post(self.endpoint.clone())
            .headers(headers)
            .json(&self.request_body(manifest, call));
        let (content_type, body) = match send(
            request,
            Duration::from_millis(manifest.timeout_ms),
            self.policy.max_response_bytes,
        )
        .await
        {
            Exchange::NotSent => return not_dispatched(),
            Exchange::Lost => return AdapterResponse::unknown(),
            Exchange::Response {
                status,
                content_type,
                body,
            } => {
                if matches!(status, 400 | 401 | 403 | 404 | 405 | 415) {
                    return AdapterResponse {
                        outcome: EffectOutcome::NotApplied,
                        definitive: true,
                        ..AdapterResponse::unknown()
                    };
                }
                (content_type, body)
            }
        };
        let Some(response) = rpc_response(&content_type, &body, &call.attempt_id, self.policy.max_response_bytes)
        else {
            return AdapterResponse::unknown();
        };
        if let Some(error) = response.get("error") {
            let code = error["code"].as_i64().unwrap_or(0);
            let mut output = Map::new();
            output.insert("error".into(), error.clone());
            if PRE_EXECUTION_ERRORS.contains(&code) {
                return AdapterResponse {
                    outcome: EffectOutcome::NotApplied,
                    definitive: true,
                    output,
                    external_ref: None,
                    cost_units: None,
                };
            }
            return AdapterResponse {
                output,
                ..AdapterResponse::unknown()
            };
        }
        let result = &response["result"];
        let result_type = result["resultType"].as_str().unwrap_or("complete");
        if result_type != "complete" {
            // input_required or task: the effect is not finished; keep the handle.
            let mut output = Map::new();
            output.insert("result_type".into(), json!(result_type));
            output.insert("result".into(), result.clone());
            return AdapterResponse {
                output,
                ..AdapterResponse::unknown()
            };
        }
        let mut output = object(result.get("structuredContent").cloned().unwrap_or_else(|| json!({})));
        if let Some(content) = result.get("content") {
            output.insert("content".into(), content.clone());
        }
        if result["isError"] == true {
            if manifest.action_risk.effect == ActionEffect::None {
                return AdapterResponse {
                    outcome: EffectOutcome::NotApplied,
                    definitive: true,
                    output,
                    external_ref: None,
                    cost_units: None,
                };
            }
            return AdapterResponse {
                output,
                ..AdapterResponse::unknown()
            };
        }
        AdapterResponse {
            outcome: EffectOutcome::Confirmed,
            definitive: true,
            output,
            external_ref: None,
            cost_units: None,
        }
    }
}
