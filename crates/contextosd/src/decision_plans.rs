//! `POST /v1/plan` (`compile`): a decision plan for one of the caller's packs (see
//! `contextos_kernel::decision_plan`). Before any request exists it says which of the
//! pack's rules always apply for the principal in `run_context`, which never do, and
//! which depend on the request and on exactly what. Pure: nothing is stored or audited.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use contextos_contract::schema::{SchemaDoc, SchemaTarget};
use contextos_contract::types::RunContext;
use contextos_kernel::decision_plan::plan_decisions;
use contextos_store::{AppendLog, DocumentStore};
use serde_json::json;

use crate::app::{ApiError, ApiResult, AppState, authorize, parse_body, same_tenant, schema_check};

pub async fn plan<S, L>(State(state): State<Arc<AppState<S, L>>>, headers: HeaderMap, body: Bytes) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("compile"))?;
    let input = parse_body(&state, &body)?;
    schema_check(
        &SchemaTarget::document(SchemaDoc::RunContext),
        &input["run_context"],
        "run_context_invalid",
    )?;
    same_tenant(&caller, &input["run_context"]["tenant_id"])?;
    let pack = state
        .packs
        .get(input["pack_ref"].as_str().unwrap_or_default())
        .filter(|p| p.tenant_id == caller.tenant_id)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "pack_not_found",
                "No such Context Pack for this tenant.",
            )
        })?;
    let invalid = |message: &str| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "plan_invalid", message);
    let run_context: RunContext =
        serde_json::from_value(input["run_context"].clone()).map_err(|_| invalid("The run context is invalid."))?;
    let intent = input["intent"]
        .as_str()
        .map(str::to_owned)
        .or_else(|| run_context.intent.clone())
        .filter(|i| !i.is_empty() && i.len() <= 256)
        .ok_or_else(|| invalid("Name an intent, in the body or the run context."))?;
    let plan = plan_decisions(pack.compiler.pack(), &run_context, &intent).map_err(|e| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "policy_eval_failed",
            "A rule cannot be evaluated for this principal.",
        )
        .with_detail(json!({"error": e}))
    })?;
    Ok(axum::Json(json!({"pack_ref": input["pack_ref"], "plan": plan})).into_response())
}
