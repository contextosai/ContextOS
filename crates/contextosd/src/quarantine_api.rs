//! Releasing a quarantined upstream tool (see
//! [`contextos_gateway::upstream_quarantine`]).
//!
//! | Route | Scope |
//! |---|---|
//! | `POST /v1/upstream/quarantine/release` | `control` (`{"capability_id", "reason"}`), and listed in `[guards] quarantine_releasers` when that is set |
//!
//! A quarantine is deployment-wide: it protects every tenant the runtime serves, so a
//! multi-tenant deployment names the principals that may lift it.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use contextos_gateway::upstream_quarantine::QuarantineError;
use contextos_store::{AppendLog, DocumentStore};

use crate::app::{ApiError, ApiResult, AppState, authorize, dispatch_gateway, parse_body};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Release {
    capability_id: String,
    reason: String,
}

pub(crate) async fn release<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    headers: HeaderMap,
    bytes: Bytes,
) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("control"))?;
    if !may_release(&state.quarantine_releasers, &caller.principal_id) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "quarantine_release_forbidden",
            "Only principals in [guards] quarantine_releasers may release a quarantine.",
        ));
    }
    let gateway = dispatch_gateway(&state)?;
    let request: Release = serde_json::from_value(parse_body(&state, &bytes)?)
        .map_err(|e| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "request_invalid", e.to_string()))?;
    match gateway
        .release_quarantine(
            &caller.tenant_id,
            &request.capability_id,
            &request.reason,
            &caller.principal_id,
        )
        .await
    {
        Ok(record) => Ok(axum::Json(record).into_response()),
        Err(QuarantineError::NotQuarantined) => Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "not_quarantined",
            "No quarantine applies to this capability's current pin.",
        )),
        Err(QuarantineError::StillDrifted) => Err(ApiError::new(
            StatusCode::CONFLICT,
            "upstream_tool_still_drifted",
            "The upstream tool still differs from its pin: re-pin it after review instead.",
        )),
        Err(QuarantineError::Invalid) => Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "request_invalid",
            "A reason of 1 to 1024 bytes is required.",
        )),
        Err(QuarantineError::Gateway(_)) => Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            "The store or audit log is unavailable.",
        )),
    }
}

/// Whether `principal` may release a quarantine: anyone with `control` when no
/// releasers are named, otherwise only those named.
fn may_release(releasers: &[String], principal: &str) -> bool {
    releasers.is_empty() || releasers.iter().any(|p| p == principal)
}
