//! Read-only shared-guarantee hold inspection (`audit:read`, caller's tenant only):
//! which resources have capacity held, and for one resource, who owns each hold and
//! the next safe step. Resolution stays with the reconcile route and its own scope.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use contextos_store::{AppendLog, DocumentStore};
use serde::Deserialize;

use crate::app::{ApiError, ApiResult, AppState, authorize, dispatch_gateway};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HoldsQuery {
    after: Option<String>,
    scan: Option<usize>,
}

fn unavailable(error: &contextos_gateway::GatewayError) -> ApiError {
    tracing::warn!(%error, "shared exposure inspection unavailable");
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "shared_guarantee_unavailable",
        "The shared exposure is unavailable.",
    )
}

/// `GET /v1/guarantees/{id}/holds`: resources with capacity held, one bounded page.
pub async fn resources_with_holds<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    Path(id): Path<String>,
    Query(query): Query<HoldsQuery>,
    headers: HeaderMap,
) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("audit:read"))?;
    let gateway = dispatch_gateway(&state)?;
    let scan = query.scan.unwrap_or(contextos_gateway::MAX_INSPECTION_SCAN);
    let page = gateway
        .resources_with_holds(&caller.tenant_id, &id, query.after.as_deref(), scan)
        .await
        .map_err(|e| unavailable(&e))?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "shared_guarantee_not_found",
                "No shared guarantee with this id.",
            )
        })?;
    Ok(axum::Json(page).into_response())
}

/// `GET /v1/guarantees/{id}/resources/{resource_digest}/holds`: the balance and each
/// open hold with its owner, last observation and next safe step.
pub async fn exposure_holds<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    Path((id, resource_digest)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("audit:read"))?;
    let gateway = dispatch_gateway(&state)?;
    let view = gateway
        .exposure_holds(&caller.tenant_id, &id, &resource_digest)
        .await
        .map_err(|e| unavailable(&e))?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "shared_exposure_not_found",
                "No shared exposure for this resource.",
            )
        })?;
    Ok(axum::Json(view).into_response())
}
