//! MCP gateway mode: each admitted run is an MCP server at `POST /v1/runs/{run_id}/mcp`.
//!
//! Agent hosts that speak MCP (Streamable HTTP, JSON responses) connect with the
//! caller's bearer token and the executor generation (`ContextOS-Executor-Generation`
//! header, or `_meta["io.contextos/executorGeneration"]`). They see the run's surfaced
//! capabilities as tools, and every `tools/call` runs the full governed pipeline:
//! surface, argument schema, binding, authorization, budget, claim, dispatch, audit.
//!
//! - `tools/list` lists only what this run surfaced, with reviewed input schemas and
//!   risk annotations. Discovery grants nothing; the gateway re-checks every call.
//! - `tools/call` returns the tool's output on success. Anything else is a tool error
//!   (`isError: true`) whose `structuredContent` carries the status, reason codes and
//!   obligations, so the model sees that it may not proceed.
//! - A downstream `input_required` is passed through with `requestState` set to the
//!   operation id; the host's retry with `inputResponses` continues the same operation.
//! - Operation identity: `_meta["io.contextos/idempotencyKey"]` if given. Otherwise
//!   effectful calls derive a key from the capability and canonical arguments, so a
//!   host retrying a call it believes failed cannot apply the effect twice; read-only
//!   calls get a fresh key per request. Evidence the call cites goes in
//!   `_meta["io.contextos/evidenceRefs"]`.
//!
//! The stateless `2026-07-28` profile needs no handshake; `initialize` and
//! `notifications/initialized` are answered for older hosts without creating a session.

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use contextos_contract::canonical::sha256_canonical;
use contextos_contract::types::ActionEffect;
use contextos_gateway::{CapabilityManifest, Continuation, DispatchOutcome, Gateway, RunAdmission};
use contextos_store::{AppendLog, DocumentStore};
use serde_json::{Value, json};

pub const PROTOCOL_VERSION: &str = "2026-07-28";
const SUPPORTED_VERSIONS: [&str; 4] = ["2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"];

const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;
const INTERNAL_ERROR: i64 = -32603;

fn rpc_result(id: &Value, result: Value) -> Response {
    axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": result})).into_response()
}

pub(crate) fn rpc_error(id: &Value, code: i64, message: &str) -> Response {
    axum::Json(json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})).into_response()
}

/// The executor generation from the header or the request's `_meta`.
fn generation(headers: &HeaderMap, request: &Value) -> Option<u64> {
    headers
        .get(crate::app::EXECUTOR_GENERATION_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .or_else(|| request["params"]["_meta"]["io.contextos/executorGeneration"].as_u64())
}

fn tool(manifest: &CapabilityManifest) -> Value {
    let read_only = manifest.action_risk.effect == ActionEffect::None;
    let description = manifest.description.clone().unwrap_or_else(|| {
        format!(
            "{} (governed by ContextOS: {}, effect {:?}).",
            manifest.capability_id, manifest.desired_effect, manifest.action_risk.effect
        )
    });
    json!({
        "name": manifest.capability_id,
        "description": description,
        "inputSchema": manifest.input_schema.clone().unwrap_or_else(|| json!({"type": "object"})),
        "annotations": {
            "readOnlyHint": read_only,
            "destructiveHint": !read_only && manifest.approval_mode == contextos_contract::types::ApprovalMode::Destructive,
            "idempotentHint": read_only,
            "openWorldHint": true,
        },
    })
}

fn operation_key(manifest: &CapabilityManifest, arguments: &Value, meta: &Value, request_id: &Value) -> String {
    if let Some(key) = meta["io.contextos/idempotencyKey"].as_str().filter(|k| !k.is_empty()) {
        return key.to_owned();
    }
    if manifest.action_risk.effect == ActionEffect::None {
        let fresh = sha256_canonical(&json!([request_id, uuid::Uuid::now_v7().to_string()])).unwrap_or_default();
        return format!("mcp:{}", &fresh[7..39]);
    }
    let digest =
        sha256_canonical(&json!({"capability": manifest.capability_id, "arguments": arguments})).unwrap_or_default();
    format!("mcp:{}", &digest[7..39])
}

fn call_result(outcome: &DispatchOutcome) -> Value {
    let result = &outcome.result;
    let report = &outcome.report;
    let status = result["status"].as_str().unwrap_or_default();
    if status == "ok" || status == "completed" {
        let output = result["output"].clone();
        return json!({
            "content": [{"type": "text", "text": output.to_string()}],
            "structuredContent": output,
            "isError": false,
        });
    }
    if report.obligations.iter().any(|o| o == "provide_requested_input") {
        return json!({
            "resultType": "input_required",
            "inputRequests": result["output"]["result"]["inputRequests"],
            "requestState": report.operation_id,
        });
    }
    let summary = json!({
        "status": status, "reason_codes": report.reason_codes, "obligations": report.obligations,
        "operation_id": report.operation_id, "approval_request_id": report.approval_request_id,
    });
    let text = format!(
        "ContextOS {status}: {}. {}",
        if report.reason_codes.is_empty() {
            "no reason codes".to_owned()
        } else {
            report.reason_codes.join(", ")
        },
        result["error"].as_str().unwrap_or_default()
    );
    json!({"content": [{"type": "text", "text": text}], "structuredContent": summary, "isError": true})
}

/// Handles one JSON-RPC message for a run. Authentication, tenancy and the admission
/// lookup are the caller's (the HTTP handler's).
pub async fn handle<S, L>(
    gateway: &Gateway<S, L>,
    admission: &RunAdmission,
    principal_id: &str,
    headers: &HeaderMap,
    request: &Value,
) -> Response
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    if request.is_array() {
        return rpc_error(&Value::Null, INVALID_REQUEST, "batches are not supported");
    }
    if request["jsonrpc"] != "2.0" || !request["method"].is_string() {
        return rpc_error(&request["id"], INVALID_REQUEST, "not a JSON-RPC 2.0 request");
    }
    let id = &request["id"];
    let method = request["method"].as_str().unwrap_or_default();
    if id.is_null() {
        // Notifications (e.g. notifications/initialized) need no response.
        return StatusCode::ACCEPTED.into_response();
    }
    let params = &request["params"];
    match method {
        "initialize" => {
            let asked = params["protocolVersion"].as_str().unwrap_or(PROTOCOL_VERSION);
            let version = if SUPPORTED_VERSIONS.contains(&asked) {
                asked
            } else {
                PROTOCOL_VERSION
            };
            rpc_result(
                id,
                json!({"protocolVersion": version, "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": {"name": "contextosd", "version": env!("CARGO_PKG_VERSION")},
                    "instructions": "Tools are governed by ContextOS. A tool error with reason codes means the action was not performed; do not retry it unchanged."}),
            )
        }
        "ping" => rpc_result(id, json!({})),
        "tools/list" => {
            let mut names: Vec<&String> = admission.surfaced_capabilities.iter().collect();
            names.sort();
            let tools: Vec<Value> = names
                .into_iter()
                .filter_map(|n| gateway.manifest(n))
                .map(tool)
                .collect();
            rpc_result(id, json!({"tools": tools}))
        }
        "tools/call" => {
            let Some(name) = params["name"].as_str() else {
                return rpc_error(id, INVALID_PARAMS, "params.name is required");
            };
            let Some(manifest) = gateway
                .manifest(name)
                .filter(|_| admission.surfaced_capabilities.contains(name))
            else {
                return rpc_error(id, INVALID_PARAMS, "unknown tool");
            };
            let Some(executor_generation) = generation(headers, request) else {
                return rpc_error(id, INVALID_PARAMS, "the executor generation is required");
            };
            let arguments = if params["arguments"].is_null() {
                json!({})
            } else {
                params["arguments"].clone()
            };
            let meta = &params["_meta"];
            // A continuation names its operation in requestState; it must be the same one.
            let continuing = params["inputResponses"].is_object();
            let key = match params["requestState"].as_str() {
                Some(state) if continuing => state.to_owned(),
                _ => operation_key(manifest, &arguments, meta, id),
            };
            let envelope = json!({
                "envelope_version": "contextos.tool_call.v1",
                "tool_call_id": format!("mcp_{}", uuid::Uuid::now_v7().simple()),
                "run_id": admission.run_id, "trace_id": admission.trace_id, "capability_id": name, "args": arguments,
                "principal_chain": [{"kind": "agent", "id": admission.actor["principal_id"]}],
                "approval_mode_requested": manifest.approval_mode, "approval_mode_effective": manifest.approval_mode,
                "approval_mode_highest": manifest.approval_mode,
                "evidence_refs": meta["io.contextos/evidenceRefs"].as_array().cloned().unwrap_or_default(),
                "idempotency_key": key,
            });
            let outcome = if continuing {
                let continuation = Continuation {
                    operation_id: key.clone(),
                    input_responses: params["inputResponses"].clone(),
                    responder_id: principal_id.to_owned(),
                    executor_generation: Some(executor_generation),
                };
                gateway.continue_with_input(admission, &envelope, &continuation).await
            } else {
                gateway.dispatch_as(admission, &envelope, executor_generation).await
            };
            match outcome {
                Ok(outcome) => rpc_result(id, call_result(&outcome)),
                Err(_) => rpc_error(id, INTERNAL_ERROR, "governed dispatch is temporarily unavailable"),
            }
        }
        _ => rpc_error(id, METHOD_NOT_FOUND, "method not found"),
    }
}

/// For malformed bodies.
pub fn parse_error() -> Response {
    rpc_error(&Value::Null, PARSE_ERROR, "invalid JSON")
}
