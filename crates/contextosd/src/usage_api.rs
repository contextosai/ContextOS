//! Budgeted model calls and replans over HTTP: the executor reserves, a metering LLM
//! gateway claims and settles (see [`contextos_gateway::Gateway::reserve_usage`]).
//!
//! | Route | Scope |
//! |---|---|
//! | `POST /v1/runs/{run_id}/usage/reserve` | `dispatch` (the run's current executor) |
//! | `POST /v1/runs/{run_id}/usage/claim` | `meter` (independent of the run) |
//! | `POST /v1/runs/{run_id}/usage/settle` | `meter`, or `dispatch` (charges the whole reservation) |

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use contextos_gateway::{RunAdmission, UsageKind, UsageRefusal};
use contextos_store::{AppendLog, DocumentStore};
use serde_json::json;

use crate::app::{
    ApiError, ApiResult, AppState, authorize, dispatch_gateway, load_admission, load_owned_admission, parse_body,
    require_owner,
};
use crate::auth::Caller;

/// Longest model name a meter may report.
const MAX_MODEL_LEN: usize = 256;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum UsageKindBody {
    ModelCall,
    Replan,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ReserveUsage {
    kind: UsageKindBody,
    #[serde(default)]
    tokens: u64,
    #[serde(default)]
    cost_cents: u64,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimUsage {
    reservation_id: String,
    #[serde(default)]
    model: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SettleUsage {
    reservation_id: String,
    #[serde(default)]
    tokens: u64,
    #[serde(default)]
    cost_cents: u64,
    #[serde(default)]
    model: Option<String>,
}

fn usage_error(refusal: UsageRefusal) -> ApiError {
    match refusal {
        UsageRefusal::Budget(reasons) => ApiError::new(
            StatusCode::CONFLICT,
            "budget_exhausted",
            "The run's budget cannot fit this.",
        )
        .with_detail(json!(reasons)),
        UsageRefusal::Revoked(reason) => ApiError::new(
            StatusCode::FORBIDDEN,
            "revoked",
            "This run has been revoked by an operator.",
        )
        .with_detail(json!([reason])),
        UsageRefusal::Invalid => ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "usage_invalid",
            "The usage values are out of range.",
        ),
        UsageRefusal::UnknownReservation => ApiError::new(
            StatusCode::NOT_FOUND,
            "reservation_not_found",
            "No open usage reservation with this id in this run.",
        ),
        UsageRefusal::Claimed => ApiError::new(
            StatusCode::CONFLICT,
            "reservation_claimed",
            "This reservation already covers another model call.",
        ),
        UsageRefusal::Gateway(_) => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            "The store is unavailable.",
        ),
    }
}

fn invalid(what: &str, error: impl std::fmt::Display) -> ApiError {
    ApiError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "request_invalid",
        format!("Invalid {what}: {error}"),
    )
}

/// A model name as reported: bounded, printable, no surrounding space.
fn model_name(model: Option<String>) -> Result<Option<String>, ApiError> {
    match model {
        None => Ok(None),
        Some(m) if m.is_empty() || m.len() > MAX_MODEL_LEN || m.trim() != m || m.chars().any(char::is_control) => {
            Err(invalid("model", "a model name is 1 to 256 printable characters"))
        }
        Some(m) => Ok(Some(m)),
    }
}

/// True for a metering principal: `meter` without the scopes that run agents.
fn is_meter(caller: &Caller) -> bool {
    caller.has("meter") && !caller.has("dispatch") && !caller.has("admit")
}

/// A meter loads any run of its tenant, but never meters a run it admitted.
async fn metered_admission<S: DocumentStore, L>(
    state: &AppState<S, L>,
    caller: &Caller,
    run_id: &str,
) -> Result<RunAdmission, ApiError> {
    let admission = load_admission(state, caller, run_id).await?;
    if caller.principal_id == admission.admitted_by {
        // The run's own admitter cannot verify its usage, whatever token it presents.
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "meter_not_independent",
            "The principal that admitted the run cannot meter it.",
        ));
    }
    Ok(admission)
}

/// Reserves budget for a model call or a replan (the run's current executor).
pub async fn reserve_usage<S, L>(
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
    let request: ReserveUsage =
        serde_json::from_value(parse_body(&state, &body)?).map_err(|e| invalid("reservation", e))?;
    let admission = load_owned_admission(&state, &caller, &run_id).await?;
    require_owner(gateway, &admission, &headers).await?;
    let kind = match request.kind {
        UsageKindBody::ModelCall => UsageKind::ModelCall,
        UsageKindBody::Replan => UsageKind::Replan,
    };
    let reservation_id = gateway
        .reserve_usage(&admission, kind, request.tokens, request.cost_cents)
        .await
        .map_err(usage_error)?;
    Ok((
        StatusCode::CREATED,
        axum::Json(json!({"reservation_id": reservation_id})),
    )
        .into_response())
}

/// Claims a model-call reservation for the one call a metering gateway is about to
/// forward, and returns what it covers (so the gateway can cap the call's output).
pub async fn claim_usage<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    Path(run_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("meter"))?;
    if !is_meter(&caller) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "meter_not_independent",
            "A metering principal cannot also hold the dispatch or admit scope.",
        ));
    }
    let gateway = dispatch_gateway(&state)?;
    let request: ClaimUsage = serde_json::from_value(parse_body(&state, &body)?).map_err(|e| invalid("claim", e))?;
    let model = model_name(request.model)?;
    let admission = metered_admission(&state, &caller, &run_id).await?;
    let claimed = gateway
        .claim_usage(
            &admission,
            &request.reservation_id,
            &caller.principal_id,
            model.as_deref(),
        )
        .await
        .map_err(usage_error)?;
    Ok(axum::Json(
        json!({"reservation_id": request.reservation_id, "tokens": claimed.tokens,
        "cost_cents": claimed.cost_cents}),
    )
    .into_response())
}

/// Settles a usage reservation: verified when reported by a metering principal,
/// otherwise the whole reservation is charged.
pub async fn settle_usage<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    Path(run_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, None)?;
    let metered = is_meter(&caller);
    if !metered && !caller.has("dispatch") {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "scope_missing",
            "This requires the meter or dispatch scope.",
        ));
    }
    let gateway = dispatch_gateway(&state)?;
    let request: SettleUsage =
        serde_json::from_value(parse_body(&state, &body)?).map_err(|e| invalid("settlement", e))?;
    let model = model_name(request.model)?;
    let admission = if metered {
        metered_admission(&state, &caller, &run_id).await?
    } else {
        let admission = load_admission(&state, &caller, &run_id).await?;
        require_owner(gateway, &admission, &headers).await?;
        admission
    };
    let measured = metered.then_some((request.tokens, request.cost_cents));
    let settled = gateway
        .settle_usage(
            &admission,
            &request.reservation_id,
            measured,
            &caller.principal_id,
            model.as_deref(),
        )
        .await
        .map_err(usage_error)?;
    Ok(axum::Json(settled).into_response())
}
