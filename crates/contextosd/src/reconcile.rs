//! `POST /v1/runs/{run_id}/operations/{operation_id}/reconcile`: resolve an unknown
//! effect by asking the provider, or by an operator asserting its outcome with evidence.
//!
//! An assertion that returns what the effect holds (`not_applied`, `partial`) must come
//! from a principal other than the one that admitted the run: whoever ran the agent
//! cannot release its own holds on its own word (`reconcile_not_independent`). It may
//! still ask the provider or confirm its own effect, which releases nothing. The run's
//! own executor reconciles at the current executor generation; an independent operator
//! is not an executor and sends none.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use contextos_gateway::{EffectOutcome, Resolution};
use contextos_store::{AppendLog, DocumentStore};
use serde_json::Value;

use crate::app::{
    ApiError, ApiResult, AppState, authorize, dispatch_gateway, executor_generation, load_admission, parse_body,
};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields, tag = "source", rename_all = "snake_case")]
enum ReconcileBody {
    /// Ask the provider about the attempt (for example an MCP task).
    Provider,
    /// Assert a definitive outcome with evidence; the caller is recorded as the source.
    Operator { outcome: String, evidence_ref: Value },
}

pub async fn reconcile<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    Path((run_id, operation_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("reconcile"))?;
    let _dispatch_slot = state.limits.dispatch_permit(&caller.tenant_id).ok_or_else(|| {
        ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "dispatch_concurrency_limited",
            "The tenant has the maximum number of governed effects in progress.",
        )
        .retry_after(std::time::Duration::from_secs(1))
    })?;
    let gateway = dispatch_gateway(&state)?;
    let request: ReconcileBody = serde_json::from_value(parse_body(&state, &body)?).map_err(|_| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "request_invalid",
            "The reconcile request is invalid.",
        )
    })?;
    let resolution = match request {
        ReconcileBody::Provider => Resolution::Query,
        ReconcileBody::Operator { outcome, evidence_ref } => Resolution::Assert {
            outcome: match outcome.as_str() {
                "confirmed" => EffectOutcome::Confirmed,
                "not_applied" => EffectOutcome::NotApplied,
                "partial" => EffectOutcome::Partial,
                _ => {
                    return Err(ApiError::new(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "request_invalid",
                        "outcome must be confirmed, not_applied or partial.",
                    ));
                }
            },
            evidence_ref,
            principal_id: caller.principal_id.clone(),
        },
    };
    let admission = load_admission(&state, &caller, &run_id).await?;
    let own = !admission.admitted_by.is_empty() && admission.admitted_by == caller.principal_id;
    if own
        && let Resolution::Assert { outcome, .. } = &resolution
        && *outcome != EffectOutcome::Confirmed
    {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "reconcile_not_independent",
            "The principal that admitted the run cannot assert that its effect did not (fully) apply.",
        ));
    }
    if own {
        // Reconciliation creates no new effect. Terminal runs still need to resolve
        // retained exposure; fence against their current generation without requiring
        // a running lifecycle status.
        let generation = executor_generation(&headers)?;
        let current = gateway.run_state(&admission).await.map_err(|_| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "store_unavailable",
                "The store is unavailable.",
            )
        })?;
        if current.as_ref().and_then(|s| s["executor_generation"].as_u64()) != Some(generation) {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "executor_stale",
                "Use the run's current executor generation.",
            ));
        }
    }
    let outcome = gateway
        .reconcile(&admission, &operation_id, resolution)
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
