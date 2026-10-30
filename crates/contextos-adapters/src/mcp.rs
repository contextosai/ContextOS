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
//! | result, `isError` false, no `recovery.completion` | confirmed (definitive) |
//! | result, `isError` false, `recovery.completion` | the state at its `state_pointer` in `structuredContent`: a listed state decides (definitive); a missing or unlisted one is unknown |
//! | result, `isError` true, read-only capability | not applied (definitive) |
//! | result, `isError` true, effectful capability | unknown (the tool may have partially acted) |
//! | `input_required` result | not applied (definitive): the tool has not run; requests in `output` |
//! | task result | unknown; the task id becomes the attempt's external reference |
//! | `tasks/get`: completed | mapped like a finished call |
//! | `tasks/get`: failed / cancelled | like an error result (unknown for effectful tools) |
//! | `tasks/get`: working / input_required | still unknown |
//! | JSON-RPC error -32700/-32600/-32601/-32602, incl. unsupported protocol version | not applied (definitive) |
//! | HTTP 4xx listed in the manifest's `recovery.not_applied_statuses` | not applied (definitive) |
//! | HTTP 400, 401, 403, 404, 405, 413, 415, 422, read-only capability | not applied (definitive) |
//! | HTTP 400, 401, 403, 404, 405, 415, effectful capability, not listed | unknown |
//! | other errors, id mismatch, malformed or lost response | unknown |
//! | connection never established | not dispatched (definitive) |
//!
//! An HTTP client error is not proof that an effectful tool did nothing: a proxy or
//! server can answer one after the tool acted, and "not applied" releases shared
//! exposure and permits a retry. As for the HTTP adapter, only statuses the reviewed
//! manifest declares settle an effectful call as not applied.
//!
//! A finished result maps into the object-only tool output through a selected
//! [`ResultProjection`]. `Flat` is the original mapping and stays the default so
//! existing output schemas keep validating; `McpResultV1` preserves the result
//! losslessly and is what new capabilities should select.

use std::time::Duration;

use async_trait::async_trait;
use contextos_contract::ingress::parse_strict;
use contextos_contract::types::ActionEffect;
use contextos_gateway::{Adapter, AdapterCall, AdapterResponse, CapabilityManifest, EffectOutcome, PortError};
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderValue};
use serde_json::{Map, Value, json};
use url::Url;

use crate::http::{not_dispatched, object, rejected_before_execution};
use crate::transport::{
    Credential, CredentialBroker, EndpointError, Exchange, TransportPolicy, client, governance_headers,
    pinned_endpoint, send, traceparent,
};

pub const PROTOCOL_VERSION: &str = "2026-07-28";
const PRE_EXECUTION_ERRORS: [i64; 4] = [-32700, -32600, -32601, -32602];
/// `tools/list` pages read at most when checking for upstream drift.
const MAX_TOOL_PAGES: usize = 20;

/// How a finished `CallToolResult` becomes the tool output object.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ResultProjection {
    /// The original mapping: `structuredContent` members at the top level (a non-object
    /// value under `value`) and presentation under `content`. Lossy: a structured
    /// member named `content` is overwritten, and absent and `null` structured content
    /// are indistinguishable.
    #[default]
    Flat,
    /// `{"mcp_result": {...}}`: structured content kept whole (any JSON value) beside
    /// its presence flag, presentation content and the tool's error flag, so provider
    /// data and adapter fields never share a namespace.
    McpResultV1,
}

pub struct McpAdapter {
    endpoint: Url,
    policy: TransportPolicy,
    client: reqwest::Client,
    credentials: std::sync::Arc<dyn CredentialBroker>,
    client_name: String,
    projection: ResultProjection,
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
            projection: ResultProjection::Flat,
        })
    }

    /// Selects the result projection. Changing it changes the output shape consumers
    /// and capability output schemas see, so it is a mapping revision, not a default.
    #[must_use]
    pub fn with_projection(mut self, projection: ResultProjection) -> Self {
        self.projection = projection;
        self
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

impl McpAdapter {
    fn meta(&self, call: &AdapterCall) -> Value {
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
        meta
    }

    /// Sends one JSON-RPC request (id = `call.attempt_id`) and returns the matching
    /// response, or the outcome to record when there is none.
    async fn exchange(
        &self,
        manifest: &CapabilityManifest,
        call: &AdapterCall,
        body: &Value,
    ) -> Result<Value, AdapterResponse> {
        let Ok(credential) = self.credentials.credential(manifest, call).await else {
            return Err(not_dispatched());
        };
        let mut headers = governance_headers(call, credential.as_ref());
        headers.insert(ACCEPT, HeaderValue::from_static("application/json, text/event-stream"));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert("mcp-protocol-version", HeaderValue::from_static(PROTOCOL_VERSION));
        let request = self.client.post(self.endpoint.clone()).headers(headers).json(body);
        let (content_type, body) = match send(
            request,
            Duration::from_millis(manifest.timeout_ms),
            self.policy.max_response_bytes,
        )
        .await
        {
            Exchange::NotSent => return Err(not_dispatched()),
            Exchange::Lost => return Err(AdapterResponse::unknown()),
            Exchange::Response {
                status,
                content_type,
                body,
            } => {
                if (400..500).contains(&status) && rejected_before_execution(manifest, status) {
                    return Err(AdapterResponse {
                        outcome: EffectOutcome::NotApplied,
                        definitive: true,
                        ..AdapterResponse::unknown()
                    });
                }
                if matches!(status, 400 | 401 | 403 | 404 | 405 | 415) {
                    return Err(AdapterResponse::unknown());
                }
                (content_type, body)
            }
        };
        let Some(response) = rpc_response(&content_type, &body, &call.attempt_id, self.policy.max_response_bytes)
        else {
            return Err(AdapterResponse::unknown());
        };
        if let Some(error) = response.get("error") {
            let code = error["code"].as_i64().unwrap_or(0);
            let mut output = Map::new();
            output.insert("error".into(), error.clone());
            let definitive = PRE_EXECUTION_ERRORS.contains(&code);
            return Err(AdapterResponse {
                outcome: if definitive {
                    EffectOutcome::NotApplied
                } else {
                    EffectOutcome::Unknown
                },
                definitive,
                output,
                external_ref: None,
                cost_units: None,
            });
        }
        Ok(response)
    }
}

impl McpAdapter {
    /// The server's tool definitions (`tools/list`, following `nextCursor`).
    pub async fn list_tools(&self) -> Result<Vec<Value>, PortError> {
        let failed = |why: &str| PortError::new("upstream_tools", why);
        let credential = self.credentials.discovery_credential().await?;
        let mut tools = Vec::new();
        let mut cursor: Option<String> = None;
        for page in 0..MAX_TOOL_PAGES {
            let id = format!("contextos-tools-{page}");
            let mut params = json!({"_meta": {
                "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": {"name": self.client_name, "version": env!("CARGO_PKG_VERSION")},
            }});
            if let Some(cursor) = &cursor {
                params["cursor"] = json!(cursor);
            }
            let mut request = self
                .client
                .post(self.endpoint.clone())
                .header(ACCEPT, "application/json, text/event-stream")
                .header("mcp-protocol-version", PROTOCOL_VERSION)
                .json(&json!({"jsonrpc": "2.0", "id": id, "method": "tools/list", "params": params}));
            if let Some(value) = credential.as_ref().and_then(Credential::header) {
                request = request.header(reqwest::header::AUTHORIZATION, value);
            }
            let Exchange::Response {
                status,
                content_type,
                body,
            } = send(request, Duration::from_secs(10), self.policy.max_response_bytes).await
            else {
                return Err(failed("tools/list unreachable"));
            };
            if !(200..300).contains(&status) {
                return Err(failed(&format!("tools/list answered {status}")));
            }
            let response = rpc_response(&content_type, &body, &id, self.policy.max_response_bytes)
                .ok_or_else(|| failed("tools/list returned no matching response"))?;
            let result = &response["result"];
            let page_tools = result["tools"]
                .as_array()
                .ok_or_else(|| failed("tools/list returned no tools"))?;
            tools.extend(page_tools.iter().cloned());
            match result["nextCursor"].as_str() {
                Some(next) if !next.is_empty() => cursor = Some(next.to_owned()),
                _ => return Ok(tools),
            }
        }
        Err(failed("tools/list has too many pages"))
    }
}

/// Maps a finished `CallToolResult`.
fn tool_result(projection: ResultProjection, manifest: &CapabilityManifest, result: &Value) -> AdapterResponse {
    let is_error = result["isError"] == true;
    let output = match projection {
        ResultProjection::Flat => {
            let mut output = object(result.get("structuredContent").cloned().unwrap_or_else(|| json!({})));
            if let Some(content) = result.get("content") {
                output.insert("content".into(), content.clone());
            }
            output
        }
        ResultProjection::McpResultV1 => {
            let structured = result.get("structuredContent");
            let mut output = Map::new();
            output.insert(
                "mcp_result".into(),
                json!({
                    "structured_content_present": structured.is_some(),
                    "structured_content": structured.cloned().unwrap_or(Value::Null),
                    "content": result.get("content").cloned().unwrap_or(Value::Null),
                    "is_error": is_error,
                }),
            );
            output
        }
    };
    if is_error {
        // An effectful tool that reports an error may still have partially acted.
        let read_only = manifest.action_risk.effect == ActionEffect::None;
        return AdapterResponse {
            outcome: if read_only {
                EffectOutcome::NotApplied
            } else {
                EffectOutcome::Unknown
            },
            definitive: read_only,
            output,
            external_ref: None,
            cost_units: None,
        };
    }
    // A finished call is not proof of the effect when the tool reports a state: under
    // the reviewed contract that state decides, as it does for HTTP.
    let outcome = match &manifest.recovery.completion {
        None => Some(EffectOutcome::Confirmed),
        Some(check) => result
            .get("structuredContent")
            .and_then(|s| s.pointer(&check.state_pointer))
            .and_then(Value::as_str)
            .and_then(|state| check.outcome(state)),
    };
    match outcome {
        Some(outcome) => AdapterResponse {
            outcome,
            definitive: true,
            output,
            external_ref: None,
            cost_units: None,
        },
        None => AdapterResponse {
            output,
            ..AdapterResponse::unknown()
        },
    }
}

/// The task id in a `resultType: "task"` result.
fn task_id(result: &Value) -> Option<String> {
    result["task"]["taskId"]
        .as_str()
        .or_else(|| result["taskId"].as_str())
        .map(str::to_owned)
}

#[async_trait]
impl Adapter for McpAdapter {
    async fn upstream_tools(&self) -> Option<Result<Vec<Value>, PortError>> {
        Some(self.list_tools().await)
    }

    async fn invoke(&self, manifest: &CapabilityManifest, call: &AdapterCall) -> AdapterResponse {
        let mut body = json!({
            "jsonrpc": "2.0", "id": call.attempt_id, "method": "tools/call",
            "params": {"name": manifest.protocol_tool, "arguments": call.arguments, "_meta": self.meta(call)},
        });
        // A continuation retries the original request, with a new id, plus the
        // validated answers and the tool's opaque request state.
        if let Some(input) = call.input.as_ref().and_then(Value::as_object) {
            for (key, value) in input {
                body["params"][key] = value.clone();
            }
        }
        let response = match self.exchange(manifest, call, &body).await {
            Ok(response) => response,
            Err(outcome) => return outcome,
        };
        let result = &response["result"];
        let result_type = result["resultType"].as_str().unwrap_or("complete");
        if result_type != "complete" {
            let mut output = Map::new();
            output.insert("result_type".into(), json!(result_type));
            output.insert("result".into(), result.clone());
            if result_type == "input_required" {
                // The request completed without running the tool: it needs answers
                // first. The continuation is a new attempt of the same operation.
                return AdapterResponse {
                    outcome: EffectOutcome::NotApplied,
                    definitive: true,
                    output,
                    external_ref: None,
                    cost_units: None,
                };
            }
            // A task is still running; its id becomes the attempt's external reference
            // so reconciliation can query it. Anything else is unknown.
            return AdapterResponse {
                output,
                external_ref: if result_type == "task" { task_id(result) } else { None },
                ..AdapterResponse::unknown()
            };
        }
        tool_result(self.projection, manifest, result)
    }

    /// `tasks/get` for a task handle. Unfinished tasks stay unknown; `failed` and
    /// `cancelled` prove nothing about an effectful tool's side effects.
    async fn query(
        &self,
        manifest: &CapabilityManifest,
        call: &AdapterCall,
        external_ref: &str,
    ) -> Option<AdapterResponse> {
        let body = json!({
            "jsonrpc": "2.0", "id": call.attempt_id, "method": "tasks/get",
            "params": {"taskId": external_ref, "_meta": self.meta(call)},
        });
        // A failed query says nothing about the original effect.
        let Ok(response) = self.exchange(manifest, call, &body).await else {
            return Some(AdapterResponse::unknown());
        };
        let result = &response["result"];
        let task = if result["task"].is_object() {
            &result["task"]
        } else {
            result
        };
        let status = task["status"].as_str().unwrap_or_default();
        let mut mapped = match status {
            "completed" => tool_result(
                self.projection,
                manifest,
                task.get("result")
                    .or_else(|| result.get("result"))
                    .unwrap_or(&Value::Null),
            ),
            "failed" | "cancelled" => tool_result(
                self.projection,
                manifest,
                &json!({"isError": true, "content": task["statusMessage"]}),
            ),
            _ => AdapterResponse::unknown(),
        };
        mapped.output.insert("task_status".into(), json!(status));
        mapped.external_ref = Some(external_ref.to_owned());
        Some(mapped)
    }
}
