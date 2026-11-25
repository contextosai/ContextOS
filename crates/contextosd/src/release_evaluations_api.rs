//! Evaluation results on agent releases (see
//! [`contextos_gateway::release_evaluations`]).
//!
//! | Route | Scope |
//! |---|---|
//! | `POST /v1/agent-releases/evaluations` | `evaluate` (an independent evaluator) |
//! | `POST /v1/agent-releases/evaluations/query` | `audit:read` (`{"release": …}`: its results) |

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use contextos_gateway::release_evaluations::{EvaluationResult, ReleaseEvaluationError};
use contextos_store::{AppendLog, DocumentStore};
use serde_json::{Value, json};

use crate::app::{ApiError, ApiResult, AppState, authorize, dispatch_gateway, parse_body};

fn invalid(e: impl std::fmt::Display) -> ApiError {
    ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "request_invalid", e.to_string())
}

fn unavailable() -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "store_unavailable",
        "The store or audit log is unavailable.",
    )
}

pub(crate) async fn record<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    headers: HeaderMap,
    bytes: Bytes,
) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("evaluate"))?;
    let gateway = dispatch_gateway(&state)?;
    let result: EvaluationResult = serde_json::from_value(parse_body(&state, &bytes)?).map_err(invalid)?;
    match gateway
        .record_release_evaluation(&caller.tenant_id, &result, &caller.principal_id)
        .await
    {
        Ok(record) => Ok((StatusCode::CREATED, axum::Json(record)).into_response()),
        Err(ReleaseEvaluationError::Invalid(m)) => Err(invalid(m)),
        Err(ReleaseEvaluationError::Gateway(_)) => Err(unavailable()),
    }
}

pub(crate) async fn query<S, L>(State(state): State<Arc<AppState<S, L>>>, headers: HeaderMap, bytes: Bytes) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("audit:read"))?;
    let gateway = dispatch_gateway(&state)?;
    let body: Value = parse_body(&state, &bytes)?;
    let release = body
        .get("release")
        .cloned()
        .ok_or_else(|| invalid("a release ref is required"))?;
    let results = gateway
        .release_evaluations(&caller.tenant_id, &release)
        .await
        .map_err(|_| unavailable())?;
    Ok(axum::Json(json!({"release": release, "results": results})).into_response())
}
