//! `POST /v1/runs/{run_id}/tool-calls/check`: govern a tool call as dispatch would,
//! without effect (see `contextos_gateway::tool_call_check`). The body is the same
//! tool call envelope; the answer says whether dispatch would proceed, and why not.
//! One audit entry records each check.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use contextos_store::{AppendLog, DocumentStore};
use serde_json::json;

use crate::app::{
    ApiError, ApiResult, AppState, EXECUTOR_GENERATION_HEADER, authorize, dispatch_gateway, executor_generation,
    load_owned_admission, parse_body,
};

pub async fn check<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    Path(run_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("dispatch"))?;
    let gateway = dispatch_gateway(&state)?;
    let envelope = parse_body(&state, &body)?;
    let admission = load_owned_admission(&state, &caller, &run_id).await?;
    // A check has no effect, so the executor generation is optional; when given, a
    // stale executor is refused as its dispatch would be.
    let generation = if headers.contains_key(EXECUTOR_GENERATION_HEADER) {
        Some(executor_generation(&headers)?)
    } else {
        None
    };
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
    Ok(axum::Json(json!({"check": outcome})).into_response())
}
