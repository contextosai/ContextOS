//! Shared findings and peer notices routes. Access is the work board's: `dispatch`,
//! the run's admitting principal and its current executor generation. Everything
//! returned is peer data (`data_only`), never instructions.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use contextos_gateway::{FindingInput, WorkError};
use contextos_store::{AppendLog, DocumentStore};

use crate::app::{
    ApiError, ApiResult, AppState, authorize, dispatch_gateway, executor_generation, load_owned_admission, parse_body,
};

fn findings_error(error: WorkError) -> ApiError {
    let code = match error.code() {
        "work_unavailable" => "findings_unavailable",
        code => code,
    };
    let status = match code {
        "work_forbidden" | "basis_outside_team" => StatusCode::FORBIDDEN,
        "work_not_found" | "findings_not_found" | "basis_not_found" => StatusCode::NOT_FOUND,
        "work_closed" | "findings_erased" => StatusCode::GONE,
        "findings_invalid" => StatusCode::UNPROCESSABLE_ENTITY,
        "findings_unavailable" => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::CONFLICT,
    };
    if matches!(error, WorkError::Store(_) | WorkError::Audit(_)) {
        tracing::warn!(%error, "findings unavailable");
    }
    ApiError::new(
        status,
        code,
        "The findings request could not be accepted; list the findings before retrying.",
    )
}

fn invalid() -> ApiError {
    findings_error(WorkError::Refused("findings_invalid"))
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageQuery {
    after: Option<String>,
    limit: Option<usize>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct InvalidateBody {
    reason: String,
    #[serde(default)]
    refuted_by: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AckBody {
    through: u64,
}

/// `GET /v1/runs/{run_id}/findings`
pub async fn list<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    Path(run_id): Path<String>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("dispatch"))?;
    let gateway = dispatch_gateway(&state)?;
    let admission = load_owned_admission(&state, &caller, &run_id).await?;
    let body = gateway
        .findings(
            &admission,
            &caller.principal_id,
            executor_generation(&headers)?,
            query.after.as_deref(),
            query.limit.unwrap_or(100),
        )
        .await
        .map_err(findings_error)?;
    Ok(axum::Json(body).into_response())
}

/// `POST /v1/runs/{run_id}/findings`
pub async fn publish<S, L>(
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
    let input: FindingInput = serde_json::from_value(parse_body(&state, &body)?).map_err(|_| invalid())?;
    let admission = load_owned_admission(&state, &caller, &run_id).await?;
    let body = gateway
        .publish_finding(&admission, &caller.principal_id, executor_generation(&headers)?, input)
        .await
        .map_err(findings_error)?;
    Ok((StatusCode::CREATED, axum::Json(body)).into_response())
}

/// `POST /v1/runs/{run_id}/findings/{finding_id}/invalidate`
pub async fn invalidate<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    Path((run_id, finding_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("dispatch"))?;
    let gateway = dispatch_gateway(&state)?;
    let request: InvalidateBody = serde_json::from_value(parse_body(&state, &body)?).map_err(|_| invalid())?;
    let admission = load_owned_admission(&state, &caller, &run_id).await?;
    let body = gateway
        .invalidate_finding(
            &admission,
            &caller.principal_id,
            executor_generation(&headers)?,
            &finding_id,
            &request.reason,
            request.refuted_by.as_deref(),
        )
        .await
        .map_err(findings_error)?;
    Ok(axum::Json(body).into_response())
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoticeQuery {
    limit: Option<usize>,
}

/// `GET /v1/runs/{run_id}/notices`
pub async fn notices<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    Path(run_id): Path<String>,
    headers: HeaderMap,
    Query(query): Query<NoticeQuery>,
) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("dispatch"))?;
    let gateway = dispatch_gateway(&state)?;
    let admission = load_owned_admission(&state, &caller, &run_id).await?;
    let body = gateway
        .notices(
            &admission,
            &caller.principal_id,
            executor_generation(&headers)?,
            query.limit.unwrap_or(20),
        )
        .await
        .map_err(findings_error)?;
    Ok(axum::Json(body).into_response())
}

/// `POST /v1/runs/{run_id}/notices/ack`
pub async fn acknowledge<S, L>(
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
    let request: AckBody = serde_json::from_value(parse_body(&state, &body)?).map_err(|_| invalid())?;
    let admission = load_owned_admission(&state, &caller, &run_id).await?;
    let body = gateway
        .acknowledge_notices(
            &admission,
            &caller.principal_id,
            executor_generation(&headers)?,
            request.through,
        )
        .await
        .map_err(findings_error)?;
    Ok(axum::Json(body).into_response())
}
