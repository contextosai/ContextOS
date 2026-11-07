//! The revocations view and the two-person restore.
//!
//! | Route | Role | Purpose |
//! |---|---|---|
//! | `GET /api/revocations` | viewer | revocations in force on every source, reconciled, with the agents they stop |
//! | `GET /api/revocations/restore-requests` | viewer | restore requests, newest first |
//! | `POST /api/revocations/restore-requests` | operator | ask for a target to be restored |
//! | `POST /api/revocations/restore-requests/{id}/approve` | operator, not the requester | restore it on the runtimes |
//! | `POST /api/revocations/restore-requests/{id}/cancel` | the requester | withdraw the request |
//!
//! Revoking is one operator's action (`POST /api/fleet/revoke`): containment is never
//! slowed down. Restoring re-grants authority, so with `[governance] two_person_restore`
//! (the default) it takes a second operator. The approval is recorded before any
//! runtime is touched, and its per-source results after, both in Tower's journal; each
//! runtime also records the restore in its own audit chain.

use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use contextos_store::{AppendLog, DocumentStore};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::{
    ApiError, ApiResult, Shared, add_days, apply_revocation, body, caller, ok, revocation_targets, snapshot,
};
use crate::collector::wall_clock;
use crate::records::{RecordError, array, new_id, push_new};
use crate::revocations::{attribute, reconcile};

const COLLECTION: &str = "restore_requests";
/// How long a restore request waits for its approval.
const REQUEST_DAYS: u32 = 1;
/// How long Tower waits for a runtime's live list before showing its chain alone.
const LIVE_TIMEOUT: Duration = Duration::from_secs(5);
/// Requests listed, newest first.
const LISTED: usize = 200;

pub fn routes<S, L>() -> Router<Shared<S, L>>
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    Router::new()
        .route("/api/revocations", get(list::<S, L>))
        .route(
            "/api/revocations/restore-requests",
            get(requests::<S, L>).post(request::<S, L>),
        )
        .route("/api/revocations/restore-requests/{id}/approve", post(approve::<S, L>))
        .route("/api/revocations/restore-requests/{id}/cancel", post(cancel::<S, L>))
}

async fn list<S: DocumentStore, L: AppendLog>(State(t): State<Shared<S, L>>, headers: HeaderMap) -> ApiResult {
    caller(&t, &headers, "viewer")?;
    let listed = t.sources.listed();
    // Every live list at once, each bounded, so one slow runtime cannot stall the page.
    let live = futures_join(listed.iter().map(|l| {
        let source = l.source.clone();
        let paused = l.paused;
        async move {
            if paused {
                return (None, json!({"id": source.id(), "live": "paused"}));
            }
            match tokio::time::timeout(LIVE_TIMEOUT, source.live_revocations()).await {
                Ok(None) => (None, json!({"id": source.id(), "live": "no_control_key"})),
                Ok(Some(Ok(list))) => (Some(list), json!({"id": source.id(), "live": "read"})),
                Ok(Some(Err(e))) => (
                    None,
                    json!({"id": source.id(), "live": "error", "error": e.to_string()}),
                ),
                Err(_) => (None, json!({"id": source.id(), "live": "error", "error": "timed out"})),
            }
        }
    }))
    .await;
    let snap = snapshot(&t).await?;
    let mut active = Vec::new();
    {
        let fleet = t.fleet.read().await;
        for (l, (list, _)) in listed.iter().zip(&live) {
            let chain = fleet
                .sources
                .get(l.source.id())
                .map(|s| s.revocations.clone())
                .unwrap_or_default();
            active.extend(reconcile(l.source.id(), &chain, list.as_ref()));
        }
    }
    attribute(&mut active, &snap.views);
    let rows: Vec<Value> = active
        .iter()
        .map(|a| {
            let mut row = serde_json::to_value(a).unwrap_or_default();
            row["mismatch"] = json!(a.mismatch());
            row
        })
        .collect();
    let pending = load(&t)
        .await?
        .iter()
        .filter(|r| status(r, &snap.now) == "requested")
        .count();
    ok(json!({
        "revocations": rows,
        "mismatches": active.iter().filter(|a| a.mismatch()).count(),
        "sources": live.into_iter().map(|(_, s)| s).collect::<Vec<_>>(),
        "pending_requests": pending,
        "two_person_restore": t.config.governance.two_person_restore,
    }))
}

/// Runs futures concurrently, keeping their order.
async fn futures_join<F>(futures: impl Iterator<Item = F>) -> Vec<F::Output>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    let handles: Vec<_> = futures.map(tokio::spawn).collect();
    let mut out = Vec::with_capacity(handles.len());
    for h in handles {
        match h.await {
            Ok(v) => out.push(v),
            Err(e) => std::panic::resume_unwind(e.into_panic()),
        }
    }
    out
}

async fn load<S: DocumentStore, L: AppendLog>(t: &crate::Tower<S, L>) -> Result<Vec<Value>, ApiError> {
    Ok(t.records
        .load(COLLECTION)
        .await?
        .as_array()
        .cloned()
        .unwrap_or_default())
}

/// A request's status at `now`: an unapproved request lapses at its expiry.
fn status<'a>(r: &'a Value, now: &str) -> &'a str {
    let s = r["status"].as_str().unwrap_or("requested");
    if s == "requested" && r["expires_at"].as_str().is_some_and(|e| e <= now) {
        "expired"
    } else {
        s
    }
}

async fn requests<S: DocumentStore, L: AppendLog>(State(t): State<Shared<S, L>>, headers: HeaderMap) -> ApiResult {
    caller(&t, &headers, "viewer")?;
    let now = wall_clock();
    let list: Vec<Value> = load(&t)
        .await?
        .into_iter()
        .rev()
        .take(LISTED)
        .map(|mut r| {
            r["status"] = json!(status(&r, &now));
            r
        })
        .collect();
    ok(json!({"requests": list}))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestBody {
    kind: String,
    target: String,
    reason: String,
    /// Sources to restore on; every source holding a control key when omitted.
    #[serde(default)]
    sources: Option<Vec<String>>,
}

async fn request<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    bytes: Bytes,
) -> ApiResult {
    let c = caller(&t, &headers, "operator")?;
    let r: RequestBody = body(&bytes)?;
    if r.reason.trim().len() < 10 {
        return Err(ApiError::bad(
            "a reason (at least 10 characters) is required: say why it is safe to restore",
        ));
    }
    revocation_targets(&t, &r.kind, &r.target, &r.reason, r.sources.as_deref())?;
    let now = wall_clock();
    let record = json!({"id": new_id(), "kind": r.kind, "target": r.target, "sources": r.sources,
        "reason": r.reason, "status": "requested", "requested_by": c.principal_id, "requested_at": now,
        "expires_at": add_days(&now, REQUEST_DAYS)});
    let stored = record.clone();
    t.records
        .change(
            COLLECTION,
            "restore_requested",
            json!({"request": record}),
            &now,
            |items| {
                let open = array(items).iter().any(|i| {
                    status(i, &now) == "requested" && i["kind"] == stored["kind"] && i["target"] == stored["target"]
                });
                if open {
                    return Err(RecordError::Conflict(
                        "a restore of this target is already waiting for approval",
                    ));
                }
                push_new(items, &stored)
            },
        )
        .await?;
    Ok((StatusCode::CREATED, axum::Json(record)).into_response())
}

async fn approve<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    let c = caller(&t, &headers, "operator")?;
    let now = wall_clock();
    let by = c.principal_id.clone();
    // Approved first, atomically: two operators approving at once cannot both act.
    let approved = t
        .records
        .change(
            COLLECTION,
            "restore_approved",
            json!({"id": id, "by": by}),
            &now,
            |items| {
                let r = array(items)
                    .iter_mut()
                    .find(|r| r["id"] == id.as_str())
                    .ok_or(RecordError::NotFound)?;
                match status(r, &now) {
                    "requested" => {}
                    "expired" => return Err(RecordError::Conflict("the request expired; request the restore again")),
                    _ => return Err(RecordError::Conflict("the request was already decided")),
                }
                if r["requested_by"] == by.as_str() {
                    return Err(RecordError::Forbidden(
                        "A restore is approved by an operator other than its requester.",
                    ));
                }
                r["status"] = json!("approved");
                r["approved_by"] = json!(by);
                r["approved_at"] = json!(now);
                Ok(r.clone())
            },
        )
        .await?;
    let field = |k: &str| approved[k].as_str().unwrap_or_default().to_owned();
    let (kind, target, reason) = (field("kind"), field("target"), field("reason"));
    let only: Option<Vec<String>> = serde_json::from_value(approved["sources"].clone()).unwrap_or(None);
    let results = match revocation_targets(&t, &kind, &target, &reason, only.as_deref()) {
        Ok(targets) => {
            let note = format!(
                "{reason} (via Tower, requested by {}, approved by {by})",
                field("requested_by")
            );
            apply_revocation(&targets, false, &kind, &target, &note).await
        }
        Err(_) => vec![json!({"source": null, "ok": false, "error": "no selected source holds a control key"})],
    };
    let succeeded = results.iter().filter(|r| r["ok"] == true).count();
    let outcome = match succeeded {
        0 => "failed",
        n if n == results.len() => "restored",
        _ => "partially_restored",
    };
    let done = wall_clock();
    let record = t
        .records
        .change(
            COLLECTION,
            "restore_executed",
            json!({"id": id, "outcome": outcome, "results": results}),
            &done,
            |items| {
                let r = array(items)
                    .iter_mut()
                    .find(|r| r["id"] == id.as_str())
                    .ok_or(RecordError::NotFound)?;
                r["status"] = json!(outcome);
                r["results"] = json!(results);
                r["executed_at"] = json!(done);
                Ok(r.clone())
            },
        )
        .await?;
    ok(record)
}

async fn cancel<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    let c = caller(&t, &headers, "operator")?;
    let now = wall_clock();
    let by = c.principal_id.clone();
    let record = t
        .records
        .change(
            COLLECTION,
            "restore_cancelled",
            json!({"id": id, "by": by}),
            &now,
            |items| {
                let r = array(items)
                    .iter_mut()
                    .find(|r| r["id"] == id.as_str())
                    .ok_or(RecordError::NotFound)?;
                if r["requested_by"] != by.as_str() {
                    return Err(RecordError::Forbidden(
                        "Only the requester withdraws a restore request.",
                    ));
                }
                if status(r, &now) != "requested" {
                    return Err(RecordError::Conflict("the request is no longer waiting"));
                }
                r["status"] = json!("cancelled");
                r["cancelled_at"] = json!(now);
                Ok(r.clone())
            },
        )
        .await?;
    ok(record)
}
