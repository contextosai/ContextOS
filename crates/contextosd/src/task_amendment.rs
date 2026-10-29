//! Amending a run's task authorization: the principal corrects what the run may do.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use contextos_gateway::{Change, RunAdmission, TaskAuthorization, is_erased};
use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore};
use serde_json::{Value, json};

use crate::app::{ApiError, ApiResult, AppState, authorize, dispatch_gateway, parse_body};

/// The admission is looked up under the caller's tenant, so another tenant's run is
/// indistinguishable from a missing one.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AmendTaskBody {
    /// The run's `task_authorization_revision` the amendment was made against.
    expected_revision: u64,
    task_authorization: Value,
}

/// `PUT /v1/runs/{run_id}/task-authorization`: the principal corrects what the run may
/// do. Narrowing is open to whoever runs the task (`dispatch`) or authorizes it;
/// widening needs `authorize` held without `admit`/`dispatch`, the principal's
/// confirmation and the same issuing principal. Inherited authorizations never change.
/// Because the task reference is part of every action digest, approvals and claims
/// made under the previous authorization no longer match.
pub async fn amend_task_authorization<S, L>(
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
    if !caller.has("authorize") && !caller.has("dispatch") {
        return Err(ApiError::forbidden());
    }
    let gateway = dispatch_gateway(&state)?;
    let invalid = |reason: &str| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "task_authorization_invalid",
            "The task authorization is invalid.",
        )
        .with_detail(json!(reason))
    };
    let request: AmendTaskBody = serde_json::from_value(parse_body(&state, &body)?).map_err(|_| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "request_invalid",
            "The amendment needs expected_revision and task_authorization.",
        )
    })?;
    let task: TaskAuthorization =
        serde_json::from_value(request.task_authorization).map_err(|e| invalid(&e.to_string()))?;
    let unavailable = || {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            "The store is unavailable.",
        )
    };
    let key = DocKey::new(&caller.tenant_id, DocKind::RunAdmission, &run_id);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|_| unavailable())?
        .filter(|r| !is_erased(&r.body))
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "run_not_found", "No such run."))?;
    let mut admission: RunAdmission = serde_json::from_value(stored.body).map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "admission_corrupt",
            "The stored admission is unreadable.",
        )
    })?;
    let conflict = |current: u64| {
        ApiError::new(
            StatusCode::CONFLICT,
            "task_authorization_conflict",
            "The task authorization changed since expected_revision.",
        )
        .with_detail(json!({"revision": current}))
    };
    if admission.task_authorization_revision != request.expected_revision {
        return Err(conflict(admission.task_authorization_revision));
    }
    let status = gateway.run_state(&admission).await.map_err(|_| unavailable())?;
    if status
        .as_ref()
        .and_then(|s| s["status"].as_str())
        .is_some_and(|s| matches!(s, "completed" | "failed" | "cancelled" | "expired"))
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "run_not_active",
            "A finished run's task authorization cannot change.",
        ));
    }
    let root_run_id = admission
        .lineage
        .as_ref()
        .map_or_else(|| admission.run_id.clone(), |l| l.root_run_id.clone());
    task.validate(&root_run_id).map_err(invalid)?;
    let inherited = admission
        .inherited_task_authorizations
        .min(admission.task_authorizations.len());
    let current = admission.task_authorizations.get(inherited).cloned();
    let change = task.change_from(current.as_ref());
    if change == Change::Widened {
        if !caller.has("authorize") || caller.has("dispatch") || caller.has("admit") {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "task_widening_forbidden",
                "Only a principal that authorizes tasks, and does not run them, may widen one.",
            ));
        }
        if task.confirmation_ref.is_none() {
            return Err(invalid("widening needs the principal's confirmation_ref"));
        }
        if current.as_ref().is_some_and(|c| c.issued_by != task.issued_by) {
            return Err(invalid("widening must be issued by the same principal"));
        }
    }
    let from_ref = current.as_ref().map(|c| c.bundle_ref(&admission.run_id));
    admission.task_authorization_origins = (0..inherited)
        .map(|i| admission.task_authorization_origin(i).to_owned())
        .chain([admission.run_id.clone()])
        .collect();
    admission.task_authorizations.truncate(inherited);
    admission.task_authorizations.push(task.clone());
    admission.task_authorization_revision += 1;
    let body = serde_json::to_value(&admission).map_err(|_| unavailable())?;
    let to_ref = task.bundle_ref(&admission.run_id);
    let change_label = match change {
        Change::Narrowed => "narrowed",
        Change::Widened => "widened",
    };
    // Signed before it takes effect: an amendment (a widening above all) never goes
    // live without its record. If the commit then fails, a best-effort abort record
    // says so; a verifier holds the admission's revision and digest as the truth.
    state
        .audit
        .append(
            &caller.tenant_id,
            "task_authorization_amended",
            json!({"run_id": admission.run_id, "revision": admission.task_authorization_revision,
                "change": change_label, "from_ref": from_ref, "to_ref": to_ref, "amended_by": caller.principal_id,
                "issued_by": task.issued_by, "confirmation_ref": task.confirmation_ref}),
            &gateway.now(),
        )
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "audit_unavailable",
                "The audit log is unavailable.",
            )
        })?;
    let committed = state.store.compare_and_swap(&key, stored.revision, &body).await;
    if let Err(e) = committed {
        let _ = state
            .audit
            .append(
                &caller.tenant_id,
                "task_authorization_amendment_aborted",
                json!({"run_id": admission.run_id, "revision": admission.task_authorization_revision,
                    "to_ref": to_ref, "reason": if e.is_conflict() { "conflict" } else { "store_unavailable" }}),
                &gateway.now(),
            )
            .await;
        return Err(if e.is_conflict() {
            conflict(admission.task_authorization_revision - 1)
        } else {
            unavailable()
        });
    }
    state.metrics.task_amendment(change_label);
    Ok(axum::Json(
        json!({"run_id": admission.run_id, "revision": admission.task_authorization_revision,
        "change": change_label, "task_authorization_ref": to_ref, "policy_refs": admission.binding_policy_refs()}),
    )
    .into_response())
}
