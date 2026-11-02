//! `POST /v1/guarantees/{id}/imports` (`exposure:import`): exposure created outside the
//! runtime, before onboarding or later through another system, imported one way into
//! a shared guarantee's ledgers (see [`contextos_gateway::ImportRow`]).
//!
//! The body is `{"rows": [...]}` with at most 1,000 rows, each `{import_id, resource,
//! amount, source, as_of, evidence_ref}` naming the canonical resource. Rows are
//! applied in order and answered one by one: `imported`, `duplicate` (the same row was
//! imported before, so re-sending a file is safe) or `refused` with a reason. A row
//! that leaves its resource over its limit is counted in
//! `contextos_shared_guarantee_over_limit_imports_total`, which raises
//! `ContextOSResourceOverLimit`.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use contextos_gateway::ImportRow;
use contextos_store::{AppendLog, DocumentStore};
use serde_json::{Value, json};

use crate::app::{ApiError, ApiResult, AppState, authorize, dispatch_gateway, parse_body};

/// Rows one request may carry.
pub const MAX_IMPORT_ROWS: usize = 1000;

pub async fn import_exposure<S, L>(
    State(state): State<Arc<AppState<S, L>>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("exposure:import"))?;
    let gateway = dispatch_gateway(&state)?;
    let input = parse_body(&state, &body)?;
    let invalid = || {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "imports_invalid",
            "Send {\"rows\": [...]} with 1 to 1000 rows of import_id, resource, amount, source, as_of and evidence_ref.",
        )
    };
    let rows: Vec<Value> = input["rows"].as_array().cloned().ok_or_else(invalid)?;
    if rows.is_empty() || rows.len() > MAX_IMPORT_ROWS {
        return Err(invalid());
    }
    if !gateway.shared_guarantees().iter().any(|r| r.id == id) {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "shared_guarantee_not_found",
            "No shared guarantee with this id.",
        ));
    }
    let mut results = Vec::with_capacity(rows.len());
    for (index, raw) in rows.into_iter().enumerate() {
        let import_id = raw["import_id"].clone();
        let Ok(row) = serde_json::from_value::<ImportRow>(raw) else {
            results.push(json!({"index": index, "import_id": import_id, "status": "refused",
                "reason": "shared_guarantee_import_invalid"}));
            continue;
        };
        let outcome = gateway
            .import_shared_exposure(&caller.tenant_id, &id, &row, &caller.principal_id)
            .await
            .map_err(|error| {
                tracing::warn!(%error, "exposure import unavailable");
                ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "store_unavailable",
                    "The store is unavailable; rows before this one were applied, so send the request again.",
                )
                .with_detail(json!({"applied_through_index": index.checked_sub(1)}))
            })?;
        results.push(match outcome {
            Ok(mut result) => {
                if result["status"] == "imported" && result["over_limit"] == true {
                    state.metrics.over_limit_import(&id);
                }
                result["index"] = json!(index);
                result
            }
            Err(reason) => json!({"index": index, "import_id": row.import_id, "status": "refused", "reason": reason}),
        });
    }
    Ok(axum::Json(json!({"guarantee_id": id, "results": results})).into_response())
}
