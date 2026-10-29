//! `POST /v1/runs/{run_id}/operations/{operation_id}/attest-absence`: an attester
//! (`attest`, never with `admit` or `dispatch`) releases what a started attempt with
//! no fact holds, citing the provider's records. The rules are the gateway's
//! (`Gateway::attest_absence`); this route authenticates and separates duties. It
//! takes no executor generation: the executor that sent the call is usually gone.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use contextos_store::{AppendLog, DocumentStore};
use serde_json::Value;

use crate::app::{ApiError, ApiResult, AppState, authorize, dispatch_gateway, load_admission, parse_body};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AttestBody {
    /// `ArtifactRef` for the provider records the attester checked.
    evidence_ref: Value,
    /// The time the provider's records were checked through (a contract timestamp).
    checked_through: String,
}

pub async fn attest_absence<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    Path((run_id, operation_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("attest"))?;
    // Configuration refuses such keys; a token can still carry both scopes.
    if caller.has("admit") || caller.has("dispatch") {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "attestation_forbidden",
            "Whoever runs agents cannot attest that their effects did not apply.",
        ));
    }
    let gateway = dispatch_gateway(&state)?;
    let request: AttestBody = serde_json::from_value(parse_body(&state, &body)?).map_err(|_| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "request_invalid",
            "The attestation needs evidence_ref and checked_through.",
        )
    })?;
    let admission = load_admission(&state, &caller, &run_id).await?;
    let outcome = gateway
        .attest_absence(
            &admission,
            &operation_id,
            request.evidence_ref,
            &request.checked_through,
            &caller.principal_id,
        )
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "reconcile_unavailable",
                "Reconciliation is temporarily unavailable.",
            )
        })?;
    Ok(axum::Json(outcome).into_response())
}
