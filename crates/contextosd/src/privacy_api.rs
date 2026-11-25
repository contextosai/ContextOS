//! Legal holds and deletion requests over HTTP (see
//! [`contextos_gateway::privacy`]). Subject identifiers travel only in request bodies,
//! never in paths, so they stay out of access logs; the runtime stores and audits their
//! digests.
//!
//! | Route | Scope |
//! |---|---|
//! | `GET /v1/legal-holds` | `control` |
//! | `POST /v1/legal-holds` | `control` |
//! | `POST /v1/legal-holds/{hold_id}/release` | `control` |
//! | `POST /v1/subjects/runs` | `control` (the runs indexed under a subject) |
//! | `POST /v1/subjects/erase` | `control` (erase every finished, unheld run of a subject) |

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use contextos_gateway::privacy::{HoldRequest, PrivacyError, subject_digest};
use contextos_store::{AppendLog, DocumentStore};
use serde_json::json;

use crate::app::{ApiError, ApiResult, AppState, authorize, dispatch_gateway, parse_body};

/// `[privacy]`: where run requests name their data subjects.
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivacyConfig {
    /// JSON pointers into a run's request to the identifiers of the people it is about
    /// (for example `/input/context/customer_id`). Runs are indexed under a digest of
    /// each, for deletion requests and legal holds by subject. Empty: no subject index.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subject_pointers: Vec<String>,
}

fn invalid(e: impl std::fmt::Display) -> ApiError {
    ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "request_invalid", e.to_string())
}

fn privacy_error(e: PrivacyError) -> ApiError {
    match e {
        PrivacyError::Invalid(m) => invalid(m),
        PrivacyError::NotFound => ApiError::new(StatusCode::NOT_FOUND, "legal_hold_not_found", "No such legal hold."),
        PrivacyError::Conflict(m) => ApiError::new(StatusCode::CONFLICT, "legal_hold_conflict", m),
        PrivacyError::Gateway(_) => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            "The store or audit log is unavailable.",
        ),
    }
}

fn body<T: serde::de::DeserializeOwned, S, L>(state: &AppState<S, L>, bytes: &Bytes) -> Result<T, ApiError> {
    serde_json::from_value(parse_body(state, bytes)?).map_err(invalid)
}

pub(crate) async fn list_holds<S, L>(State(state): State<Arc<AppState<S, L>>>, headers: HeaderMap) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("control"))?;
    let gateway = dispatch_gateway(&state)?;
    let holds = gateway
        .legal_holds(&caller.tenant_id)
        .await
        .map_err(|e| privacy_error(e.into()))?;
    Ok(axum::Json(json!({"holds": holds})).into_response())
}

pub(crate) async fn place_hold<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    headers: HeaderMap,
    bytes: Bytes,
) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("control"))?;
    let gateway = dispatch_gateway(&state)?;
    let request: HoldRequest = body(&state, &bytes)?;
    let hold = gateway
        .place_hold(&caller.tenant_id, &request, &caller.principal_id)
        .await
        .map_err(privacy_error)?;
    Ok((StatusCode::CREATED, axum::Json(hold)).into_response())
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Reason {
    reason: String,
}

pub(crate) async fn release_hold<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    Path(hold_id): Path<String>,
    headers: HeaderMap,
    bytes: Bytes,
) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("control"))?;
    let gateway = dispatch_gateway(&state)?;
    let Reason { reason } = body(&state, &bytes)?;
    let hold = gateway
        .release_hold(&caller.tenant_id, &hold_id, &reason, &caller.principal_id)
        .await
        .map_err(privacy_error)?;
    Ok(axum::Json(hold).into_response())
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Subject {
    subject: String,
}

pub(crate) async fn subject_runs<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    headers: HeaderMap,
    bytes: Bytes,
) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("control"))?;
    let gateway = dispatch_gateway(&state)?;
    let Subject { subject } = body(&state, &bytes)?;
    if subject.is_empty() || subject.len() > 512 {
        return Err(invalid("a subject of 1 to 512 bytes is required"));
    }
    let (runs, truncated) = gateway
        .subject_runs(&caller.tenant_id, &subject)
        .await
        .map_err(|e| privacy_error(e.into()))?;
    Ok(
        axum::Json(json!({"subject_digest": subject_digest(&subject), "runs": runs, "index_truncated": truncated}))
            .into_response(),
    )
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SubjectErasure {
    subject: String,
    reason: String,
}

pub(crate) async fn erase_subject<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    headers: HeaderMap,
    bytes: Bytes,
) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("control"))?;
    let gateway = dispatch_gateway(&state)?;
    let SubjectErasure { subject, reason } = body(&state, &bytes)?;
    let summary = gateway
        .erase_subject(&caller.tenant_id, &subject, &caller.principal_id, &reason)
        .await
        .map_err(privacy_error)?;
    Ok(axum::Json(summary).into_response())
}
