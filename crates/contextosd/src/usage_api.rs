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
use contextos_gateway::{RunAdmission, TokenBreakdown, UsageKind, UsageRefusal};
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
    input_tokens: Option<u64>,
    #[serde(default)]
    output_tokens: Option<u64>,
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
        UsageRefusal::Revoked(revoked) => {
            ApiError::new(StatusCode::FORBIDDEN, "revoked", revoked.message()).with_detail(json!([revoked.reason_code]))
        }
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
    // The call goes out only to a model the deployment allows this agent.
    if let Some(models) = &state.models {
        let agent_id = admission.actor["principal_id"].as_str().unwrap_or_default();
        let allowed = model.as_deref().is_some_and(|m| models.allows(agent_id, m));
        if !allowed {
            let body = json!({"run_id": admission.run_id, "reservation_id": request.reservation_id, "kind": "model_call",
                "model": model, "reporter": caller.principal_id, "reason_codes": ["model_not_allowed"]});
            let _ = state
                .audit
                .append(&admission.tenant_id, "usage_refused", body, &gateway.now())
                .await;
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "model_not_allowed",
                "This model is not allowed for the run's agent ([guards.models]); a claim must name an allowed model.",
            ));
        }
    }
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
    let (effective_tokens, breakdown) = resolve_token_breakdown(&request)?;
    let model = model_name(request.model)?;
    let admission = if metered {
        metered_admission(&state, &caller, &run_id).await?
    } else {
        let admission = load_admission(&state, &caller, &run_id).await?;
        require_owner(gateway, &admission, &headers).await?;
        admission
    };
    let measured = metered.then_some((effective_tokens, request.cost_cents));
    let settled = gateway
        .settle_usage_with_breakdown(
            &admission,
            &request.reservation_id,
            measured,
            if metered { breakdown } else { TokenBreakdown::default() },
            &caller.principal_id,
            model.as_deref(),
        )
        .await
        .map_err(usage_error)?;
    if metered {
        let model_label = model
            .as_deref()
            .and_then(|m| state.models.as_ref().and_then(|p| p.matched_label(m)))
            .unwrap_or("unpinned");
        state
            .metrics
            .token_usage(model_label, breakdown.input_tokens, breakdown.output_tokens);
    }
    Ok(axum::Json(settled).into_response())
}

fn resolve_token_breakdown(request: &SettleUsage) -> Result<(u64, TokenBreakdown), ApiError> {
    let breakdown = TokenBreakdown {
        input_tokens: request.input_tokens,
        output_tokens: request.output_tokens,
    };
    if breakdown.input_tokens.is_none() && breakdown.output_tokens.is_none() {
        return Ok((request.tokens, breakdown));
    }
    let split_sum = breakdown
        .input_tokens
        .unwrap_or(0)
        .checked_add(breakdown.output_tokens.unwrap_or(0))
        .ok_or_else(|| usage_error(UsageRefusal::Invalid))?;
    if request.tokens == 0 {
        return Ok((split_sum, breakdown));
    }
    if split_sum > request.tokens {
        return Err(usage_error(UsageRefusal::Invalid));
    }
    Ok((request.tokens, breakdown))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_breakdown_derives_total_or_validates_split() {
        let derived = SettleUsage {
            reservation_id: "usage:1".into(),
            tokens: 0,
            input_tokens: Some(400),
            output_tokens: Some(120),
            cost_cents: 5,
            model: Some("claude-sonnet-5-5".into()),
        };
        let (total, breakdown) = resolve_token_breakdown(&derived).unwrap();
        assert_eq!(total, 520);
        assert_eq!(breakdown.input_tokens, Some(400));
        assert_eq!(breakdown.output_tokens, Some(120));

        let mismatched = SettleUsage {
            reservation_id: "usage:2".into(),
            tokens: 100,
            input_tokens: Some(80),
            output_tokens: Some(50),
            cost_cents: 0,
            model: None,
        };
        assert!(resolve_token_breakdown(&mismatched).is_err());
    }
}
