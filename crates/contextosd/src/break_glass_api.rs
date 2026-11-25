//! Break-glass over HTTP (see [`contextos_gateway::break_glass`]).
//!
//! | Route | Scope |
//! |---|---|
//! | `GET /v1/break-glass` | `control` (the tenant's grants, newest first) |
//! | `POST /v1/break-glass` | `break_glass`, held by a credential that neither admits nor dispatches |
//! | `POST /v1/break-glass/{grant_id}/close` | `break_glass` |

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use contextos_gateway::break_glass::{BreakGlassError, GrantRequest};
use contextos_store::{AppendLog, DocumentStore};
use serde_json::json;

use crate::app::{ApiError, ApiResult, AppState, authorize, dispatch_gateway, parse_body};

fn error(e: BreakGlassError) -> ApiError {
    match e {
        BreakGlassError::Off => ApiError::new(
            StatusCode::NOT_IMPLEMENTED,
            "break_glass_off",
            "Break-glass is not configured ([guards.break_glass]).",
        ),
        BreakGlassError::Invalid(m) => ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "request_invalid", m),
        BreakGlassError::NotFound => ApiError::new(StatusCode::NOT_FOUND, "break_glass_not_found", "No such grant."),
        BreakGlassError::Conflict(m) => ApiError::new(StatusCode::CONFLICT, "break_glass_conflict", m),
        BreakGlassError::Gateway(_) => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            "The store or audit log is unavailable.",
        ),
    }
}

pub(crate) async fn list<S, L>(State(state): State<Arc<AppState<S, L>>>, headers: HeaderMap) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("control"))?;
    let gateway = dispatch_gateway(&state)?;
    let grants = gateway
        .break_glass_grants(&caller.tenant_id)
        .await
        .map_err(|e| error(e.into()))?;
    Ok(axum::Json(json!({"grants": grants})).into_response())
}

pub(crate) async fn open<S, L>(State(state): State<Arc<AppState<S, L>>>, headers: HeaderMap, bytes: Bytes) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("break_glass"))?;
    // Whoever lifts the guards is not the one acting under them.
    if caller.has("admit") || caller.has("dispatch") {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "break_glass_not_independent",
            "A credential that admits or dispatches runs cannot open break-glass.",
        ));
    }
    let gateway = dispatch_gateway(&state)?;
    let request: GrantRequest = serde_json::from_value(parse_body(&state, &bytes)?)
        .map_err(|e| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "request_invalid", e.to_string()))?;
    let grant = gateway
        .open_break_glass(&caller.tenant_id, &request, &caller.principal_id)
        .await
        .map_err(error)?;
    Ok((StatusCode::CREATED, axum::Json(grant)).into_response())
}

pub(crate) async fn close<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    Path(grant_id): Path<String>,
    headers: HeaderMap,
) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("break_glass"))?;
    let gateway = dispatch_gateway(&state)?;
    let grant = gateway
        .close_break_glass(&caller.tenant_id, &grant_id, &caller.principal_id)
        .await
        .map_err(error)?;
    Ok(axum::Json(grant).into_response())
}
