//! `POST /v1/runs/{run_id}/operations/{operation_id}/evaluations`: an independent
//! evaluator's verdict on one governed tool call (see the gateway's `evaluations`).

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use contextos_gateway::{EvaluationRefusal, EvaluationReport};
use contextos_store::{AppendLog, DocumentStore};

use crate::app::{ApiError, ApiResult, AppState, authorize, dispatch_gateway, load_admission, parse_body};

pub async fn evaluate_operation<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    Path((run_id, operation_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("evaluate"))?;
    if caller.has("dispatch") || caller.has("admit") {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "evaluator_not_independent",
            "An evaluator cannot also run or admit agents.",
        ));
    }
    let gateway = dispatch_gateway(&state)?;
    let report: EvaluationReport = serde_json::from_value(parse_body(&state, &body)?).map_err(|e| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "request_invalid",
            format!("Invalid evaluation: {e}"),
        )
    })?;
    let admission = load_admission(&state, &caller, &run_id).await?;
    match gateway
        .evaluate_operation(&admission, &operation_id, &caller.principal_id, &report)
        .await
    {
        Ok(kept) => Ok((StatusCode::CREATED, axum::Json(kept)).into_response()),
        Err(refusal) => Err(match refusal {
            EvaluationRefusal::Invalid => ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "evaluation_invalid",
                refusal.to_string(),
            ),
            EvaluationRefusal::UnknownOperation => {
                ApiError::new(StatusCode::NOT_FOUND, "operation_not_found", refusal.to_string())
            }
            EvaluationRefusal::SelfEvaluation => {
                ApiError::new(StatusCode::FORBIDDEN, "evaluator_not_independent", refusal.to_string())
            }
            EvaluationRefusal::AlreadyEvaluated | EvaluationRefusal::TooManyEvaluations => {
                ApiError::new(StatusCode::CONFLICT, "evaluation_exists", refusal.to_string())
            }
            EvaluationRefusal::Gateway(_) => ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "store_unavailable",
                "The store is unavailable.",
            ),
        }),
    }
}
