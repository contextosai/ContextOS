//! Envoy and `agentgateway` HTTP `ext_authz` check backend (`POST /v1/ext-authz`).
//!
//! "agentgateway governs the wire; ContextOS governs the effect."
//!
//! This route adapts Envoy-compatible HTTP `ext_authz` requests to ContextOS's
//! [`Gateway::check_tool_call`] pipeline:
//!
//! - Requires the `dispatch` scope and ownership of the run named by `ContextOS-Run-Id`.
//! - Accepts a ContextOS tool-call envelope, an MCP JSON-RPC `tools/call` body, or a
//!   plain JSON arguments object paired with the `ContextOS-Capability` header.
//! - Answers `200 OK` when the check allows the call, or `403 Forbidden` when it is
//!   blocked, rejected, or requires an approval or escalation.
//! - Always sets `X-ContextOS-Check-Only: true` and `X-ContextOS-Not-Evaluated` so a
//!   proxy never mistakes an advisory check for an atomic dispatch, budget reservation,
//!   or shared-guarantee claim (see threat T73). Every check is audited as
//!   `tool_call_check`.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use contextos_contract::canonical::sha256_canonical;
use contextos_gateway::{Gateway, RunAdmission};
use contextos_store::{AppendLog, DocumentStore};
use serde_json::{Value, json};

use crate::app::{
    ApiError, ApiResult, AppState, EXECUTOR_GENERATION_HEADER, authorize, dispatch_gateway, executor_generation,
    load_owned_admission, parse_body,
};

pub const RUN_ID_HEADER: &str = "contextos-run-id";
pub const CAPABILITY_HEADER: &str = "contextos-capability";
pub const OPERATION_ID_HEADER: &str = "contextos-operation-id";
pub const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";

const VERDICT_HEADER: HeaderName = HeaderName::from_static("x-contextos-verdict");
const CHECK_ONLY_HEADER: HeaderName = HeaderName::from_static("x-contextos-check-only");
const ACTION_DIGEST_HEADER: HeaderName = HeaderName::from_static("x-contextos-action-digest");
const REASON_HEADER: HeaderName = HeaderName::from_static("x-contextos-reason");
const NOT_EVALUATED_HEADER: HeaderName = HeaderName::from_static("x-contextos-not-evaluated");
const AUDIT_SEQ_HEADER: HeaderName = HeaderName::from_static("x-contextos-audit-sequence");

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, ApiError> {
    let Some(value) = headers.get(name) else {
        return Ok(None);
    };
    let text = value.to_str().map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "header_invalid",
            format!("Header `{name}` must be valid ASCII."),
        )
    })?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    Ok(Some(trimmed))
}

fn resolve_capability(admission: &RunAdmission, requested: &str) -> String {
    let names = crate::mcp::tool_names(&admission.surfaced_capabilities);
    names.get(requested).map_or_else(|| requested.to_owned(), Clone::clone)
}

fn synthetic_envelope<S: DocumentStore + 'static, L: AppendLog + 'static>(
    gateway: &Gateway<S, L>,
    admission: &RunAdmission,
    capability_id: &str,
    arguments: Value,
    explicit_key: Option<String>,
    tool_call_id: Option<String>,
    evidence_refs: Vec<Value>,
) -> Value {
    let approval_mode = gateway
        .manifest(capability_id)
        .map_or(contextos_contract::types::ApprovalMode::Destructive, |m| {
            m.approval_mode
        });
    let key = explicit_key.unwrap_or_else(|| {
        let digest =
            sha256_canonical(&json!({"capability": capability_id, "arguments": &arguments})).unwrap_or_default();
        format!("ext_authz:{}", digest.get(7..39).unwrap_or("check"))
    });
    let tool_call_id = tool_call_id.unwrap_or_else(|| format!("ext_{}", uuid::Uuid::now_v7().simple()));
    json!({
        "envelope_version": "contextos.tool_call.v1",
        "tool_call_id": tool_call_id,
        "run_id": admission.run_id,
        "trace_id": admission.trace_id,
        "capability_id": capability_id,
        "args": arguments,
        "principal_chain": [{"kind": "agent", "id": admission.actor["principal_id"]}],
        "approval_mode_requested": approval_mode,
        "approval_mode_effective": approval_mode,
        "approval_mode_highest": approval_mode,
        "evidence_refs": evidence_refs,
        "idempotency_key": key,
    })
}

fn build_envelope<S: DocumentStore + 'static, L: AppendLog + 'static>(
    gateway: &Gateway<S, L>,
    admission: &RunAdmission,
    headers: &HeaderMap,
    body: Value,
) -> Result<Value, ApiError> {
    let header_cap = header_str(headers, CAPABILITY_HEADER)?;
    let header_key = header_str(headers, OPERATION_ID_HEADER)?
        .or(header_str(headers, IDEMPOTENCY_KEY_HEADER)?)
        .map(str::to_owned);

    // 1. Native ContextOS tool-call envelope.
    if body.get("envelope_version").is_some() || body.get("capability_id").is_some() {
        let body_cap = body["capability_id"].as_str().ok_or_else(|| {
            ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "request_invalid",
                "Tool-call envelope requires a string `capability_id`.",
            )
        })?;
        if let Some(hcap) = header_cap {
            let resolved = resolve_capability(admission, hcap);
            if resolved != body_cap && hcap != body_cap {
                return Err(ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "capability_mismatch",
                    "ContextOS-Capability header does not match body capability_id.",
                ));
            }
        }
        return Ok(body);
    }

    // 2. MCP JSON-RPC 2.0 `tools/call` payload (used by agentgateway / Envoy MCP proxies).
    if body.get("jsonrpc").is_some() {
        if body["jsonrpc"] != "2.0" || body["method"] != "tools/call" {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "unsupported_mcp_method",
                "ext_authz only checks MCP JSON-RPC 2.0 `tools/call` requests.",
            ));
        }
        let params = &body["params"];
        let name = params["name"].as_str().ok_or_else(|| {
            ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "request_invalid",
                "MCP `tools/call` requires string `params.name`.",
            )
        })?;
        let capability = resolve_capability(admission, name);
        if let Some(hcap) = header_cap {
            let resolved = resolve_capability(admission, hcap);
            if resolved != capability {
                return Err(ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "capability_mismatch",
                    "ContextOS-Capability header does not match MCP params.name.",
                ));
            }
        }
        let args = if params["arguments"].is_null() {
            json!({})
        } else {
            params["arguments"].clone()
        };
        let meta = &params["_meta"];
        let key = meta["io.contextos/idempotencyKey"]
            .as_str()
            .filter(|k| !k.is_empty())
            .map(str::to_owned)
            .or(header_key);
        let tool_call_id = meta["io.contextos/toolCallId"]
            .as_str()
            .filter(|id| !id.is_empty())
            .map(str::to_owned);
        let evidence_refs = meta["io.contextos/evidenceRefs"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        return Ok(synthetic_envelope(
            gateway,
            admission,
            &capability,
            args,
            key,
            tool_call_id,
            evidence_refs,
        ));
    }

    // 3. Plain JSON arguments object with explicit ContextOS-Capability header.
    let Some(hcap) = header_cap else {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "capability_required",
            "Provide a tool-call envelope, an MCP `tools/call` body, or the ContextOS-Capability header.",
        ));
    };
    if !body.is_object() {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "request_invalid",
            "Arguments body must be a JSON object.",
        ));
    }
    let capability = resolve_capability(admission, hcap);
    Ok(synthetic_envelope(
        gateway,
        admission,
        &capability,
        body,
        header_key,
        None,
        vec![],
    ))
}

fn safe_header(value: &str) -> Option<HeaderValue> {
    HeaderValue::from_str(value).ok()
}

/// `POST /v1/ext-authz/{*path}`: Envoy's HTTP `ext_authz` service appends the original
/// request path to its configured `path_prefix`, so a prefix of `/v1/ext-authz` reaches
/// this route. The appended path is ignored: the check is decided by the run, the
/// capability and the arguments, never by the upstream URL.
pub async fn check_prefixed<S, L>(state: State<Arc<AppState<S, L>>>, headers: HeaderMap, body: Bytes) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    check(state, headers, body).await
}

pub async fn check<S, L>(State(state): State<Arc<AppState<S, L>>>, headers: HeaderMap, body: Bytes) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("dispatch"))?;
    let gateway = dispatch_gateway(&state)?;
    let run_id = header_str(&headers, RUN_ID_HEADER)?.ok_or_else(|| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "run_id_required",
            "The ContextOS-Run-Id header is required for ext_authz checks.",
        )
    })?;
    let parsed = parse_body(&state, &body)?;
    let admission = load_owned_admission(&state, &caller, run_id).await?;
    let generation = if headers.contains_key(EXECUTOR_GENERATION_HEADER) {
        Some(executor_generation(&headers)?)
    } else {
        None
    };
    let envelope = build_envelope(gateway, &admission, &headers, parsed)?;
    let outcome = gateway
        .check_tool_call(&admission, &envelope, generation)
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "dispatch_unavailable",
                "Governed dispatch is temporarily unavailable.",
            )
        })?;

    let allowed = outcome.status == "allowed";
    let status_code = if allowed { StatusCode::OK } else { StatusCode::FORBIDDEN };
    let verdict = if allowed { "allow" } else { outcome.status.as_str() };
    let payload = if allowed {
        json!({"check": outcome})
    } else {
        let code = outcome
            .reason_codes
            .first()
            .cloned()
            .unwrap_or_else(|| outcome.status.clone());
        let message = outcome
            .message
            .clone()
            .unwrap_or_else(|| format!("Tool call check returned `{}`.", outcome.status));
        json!({"error": {"code": code, "message": message}, "check": outcome})
    };

    let mut response: Response = (status_code, axum::Json(payload)).into_response();
    let resp_headers = response.headers_mut();
    resp_headers.insert(CHECK_ONLY_HEADER, HeaderValue::from_static("true"));
    if let Some(v) = safe_header(verdict) {
        resp_headers.insert(VERDICT_HEADER, v);
    }
    if let Some(digest) = outcome.action_digest.as_deref().and_then(safe_header) {
        resp_headers.insert(ACTION_DIGEST_HEADER, digest);
    }
    if let Some(reason) = outcome.reason_codes.first().and_then(|r| safe_header(r)) {
        resp_headers.insert(REASON_HEADER, reason);
    }
    let not_evaluated = outcome.not_evaluated.join(",");
    if let Some(v) = safe_header(&not_evaluated) {
        resp_headers.insert(NOT_EVALUATED_HEADER, v);
    }
    if let Some(v) = safe_header(&outcome.audit_sequence.to_string()) {
        resp_headers.insert(AUDIT_SEQ_HEADER, v);
    }
    Ok(response)
}
