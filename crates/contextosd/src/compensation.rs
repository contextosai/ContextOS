//! Compensation routes: list a run's compensable effects, compensate one, or compensate
//! the run's effects newest first. Each compensation is a new governed operation (see
//! `contextos_gateway`'s compensation module); the caller names the effect, never the
//! provider's reversal reference.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use contextos_store::{AppendLog, DocumentStore};
use serde_json::{Value, json};

use crate::app::{
    ApiError, ApiResult, AppState, authorize, dispatch_gateway, executor_generation, load_admission, parse_body,
};

fn unavailable() -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "dispatch_unavailable",
        "Governed dispatch is temporarily unavailable.",
    )
}

fn limited() -> ApiError {
    ApiError::new(
        StatusCode::TOO_MANY_REQUESTS,
        "dispatch_concurrency_limited",
        "The tenant has the maximum number of governed effects in progress.",
    )
    .retry_after(std::time::Duration::from_secs(1))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CompensateBody {
    /// Identifies this request in the tool result, like a tool call's id.
    tool_call_id: String,
}

/// `GET /v1/runs/{run_id}/compensations`
pub async fn list<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    Path(run_id): Path<String>,
    headers: HeaderMap,
) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("dispatch"))?;
    let gateway = dispatch_gateway(&state)?;
    let admission = load_admission(&state, &caller, &run_id).await?;
    let listed = gateway.compensations(&admission).await.map_err(|_| unavailable())?;
    Ok(axum::Json(listed).into_response())
}

/// `POST /v1/runs/{run_id}/operations/{operation_id}/compensate`
pub async fn compensate<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    Path((run_id, operation_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("dispatch"))?;
    let _dispatch_slot = state.limits.dispatch_permit(&caller.tenant_id).ok_or_else(limited)?;
    let gateway = dispatch_gateway(&state)?;
    let request: CompensateBody = serde_json::from_value(parse_body(&state, &body)?)
        .ok()
        .filter(|b: &CompensateBody| !b.tool_call_id.is_empty() && b.tool_call_id.len() <= 256)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "request_invalid",
                "The compensate request needs a tool_call_id.",
            )
        })?;
    let admission = load_admission(&state, &caller, &run_id).await?;
    let generation = executor_generation(&headers)?;
    let outcome = gateway
        .compensate(&admission, &operation_id, &request.tool_call_id, Some(generation))
        .await
        .map_err(|_| unavailable())?;
    record(&state, &outcome.result, &outcome.report);
    Ok(axum::Json(json!({"result": outcome.result, "report": outcome.report})).into_response())
}

/// `POST /v1/runs/{run_id}/compensate`
pub async fn compensate_run<S, L>(
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
    let _dispatch_slot = state.limits.dispatch_permit(&caller.tenant_id).ok_or_else(limited)?;
    let gateway = dispatch_gateway(&state)?;
    if !body.is_empty() && parse_body(&state, &body)? != json!({}) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "request_invalid",
            "The compensate request takes no fields.",
        ));
    }
    let admission = load_admission(&state, &caller, &run_id).await?;
    let generation = executor_generation(&headers)?;
    let report = gateway
        .compensate_run(&admission, Some(generation))
        .await
        .map_err(|_| unavailable())?;
    for step in report["steps"].as_array().into_iter().flatten() {
        if let Ok(governed) = serde_json::from_value(step["report"].clone()) {
            record(&state, &step["result"], &governed);
        }
    }
    Ok(axum::Json(report).into_response())
}

fn record<S: DocumentStore + 'static, L: AppendLog + 'static>(
    state: &AppState<S, L>,
    result: &Value,
    report: &contextos_gateway::DispatchReport,
) {
    let capability = result["capability_id"].as_str().unwrap_or_default();
    let capability = match &state.gateway {
        Some(gateway) if gateway.manifest(capability).is_some() => capability,
        _ => "unpinned",
    };
    state
        .metrics
        .dispatch_outcome(capability, &report.status, &report.reason_codes);
}
