//! Agent lifecycle changes: requested by an owner or risk reviewer, approved by a risk
//! reviewer who is neither the requester nor the agent's owner or declarer, journalled
//! at every step, and enforced on the runtimes.
//!
//! | Route | Role | Purpose |
//! |---|---|---|
//! | `GET /api/lifecycle-requests?agent=` | viewer | requests, newest first |
//! | `POST /api/agents/{key}/lifecycle` | owner (team) or risk | ask to move the agent to another stage |
//! | `POST /api/lifecycle-requests/{id}/approve` | risk, not the requester, owner or declarer | apply the change |
//! | `POST /api/lifecycle-requests/{id}/reject` | risk, not the requester | refuse it |
//! | `POST /api/lifecycle-requests/{id}/cancel` | the requester | withdraw it |
//!
//! States: `proposed` → `approved` → active (`pilot`, `production`, `deprecated`) ⇄
//! `suspended`, and `retired` from any state, for good. Moving to `approved` needs a
//! current approved risk review of the agent. Approving a move to `suspended` or
//! `retired` revokes the agent (`kind = agent`) on every runtime Tower holds a control
//! key for, so the runtimes refuse its runs and effects; resuming a suspended agent
//! restores only the revocations its suspension placed. Each runtime records the
//! revocation or restore in its own audit chain, and `lifecycle_not_enforced` reports a
//! suspended or retired agent some runtime does not revoke.
//!
//! Containment is not slowed down by this: an operator can still revoke an agent at
//! once with the fleet kill switch.

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use contextos_store::{AppendLog, DocumentStore};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::{ApiError, ApiResult, Shared, add_days, apply_revocation, body, caller, caller_any, ok, snapshot};
use crate::collector::wall_clock;
use crate::records::{RecordError, array, new_id, object, push_new};

const COLLECTION: &str = "lifecycle_requests";
/// How long a request waits for its decision.
const REQUEST_DAYS: u32 = 7;
/// Requests listed, newest first.
const LISTED: usize = 200;
/// Marks a revocation placed by a suspension, so a resume restores only its own.
pub const SUSPENSION_MARK: &str = "[lifecycle suspension]";

pub fn routes<S, L>() -> Router<Shared<S, L>>
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    Router::new()
        .route("/api/lifecycle-requests", get(list::<S, L>))
        .route("/api/agents/{key}/lifecycle", post(request::<S, L>))
        .route("/api/lifecycle-requests/{id}/approve", post(approve::<S, L>))
        .route("/api/lifecycle-requests/{id}/reject", post(reject::<S, L>))
        .route("/api/lifecycle-requests/{id}/cancel", post(cancel::<S, L>))
}

/// The stages an agent at `from` may move to.
#[must_use]
pub fn next(from: &str) -> &'static [&'static str] {
    match from {
        "proposed" => &["approved", "retired"],
        "approved" => &["pilot", "production", "retired"],
        "pilot" => &["production", "deprecated", "suspended", "retired"],
        "production" => &["deprecated", "suspended", "retired"],
        "deprecated" => &["production", "suspended", "retired"],
        "suspended" => &["pilot", "production", "deprecated", "retired"],
        _ => &[],
    }
}

/// Whether a stage stops the agent on the runtimes.
#[must_use]
pub fn stopped(stage: &str) -> bool {
    matches!(stage, "suspended" | "retired")
}

async fn load<S: DocumentStore, L: AppendLog>(t: &crate::Tower<S, L>) -> Result<Vec<Value>, ApiError> {
    Ok(t.records
        .load(COLLECTION)
        .await?
        .as_array()
        .cloned()
        .unwrap_or_default())
}

/// A request's status at `now`: an undecided request lapses at its expiry.
fn status<'a>(r: &'a Value, now: &str) -> &'a str {
    let s = r["status"].as_str().unwrap_or("requested");
    if s == "requested" && r["expires_at"].as_str().is_some_and(|e| e <= now) {
        "expired"
    } else {
        s
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListQuery {
    #[serde(default)]
    agent: Option<String>,
}

async fn list<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    Query(q): Query<ListQuery>,
) -> ApiResult {
    caller(&t, &headers, "viewer")?;
    let now = wall_clock();
    let requests: Vec<Value> = load(&t)
        .await?
        .into_iter()
        .rev()
        .filter(|r| q.agent.as_deref().is_none_or(|a| r["agent"] == a))
        .take(LISTED)
        .map(|mut r| {
            r["status"] = json!(status(&r, &now));
            r
        })
        .collect();
    ok(json!({"requests": requests}))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestBody {
    to: String,
    reason: String,
}

async fn request<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    Path(key): Path<String>,
    bytes: Bytes,
) -> ApiResult {
    let c = caller_any(&t, &headers, &["owner", "risk"])?;
    let r: RequestBody = body(&bytes)?;
    if r.reason.trim().len() < 10 || r.reason.len() > 2048 {
        return Err(ApiError::bad("a reason of 10 to 2048 characters is required"));
    }
    let declarations = t.records.load("declarations").await?;
    let declaration = declarations
        .get(&key)
        .ok_or_else(|| ApiError::bad("Declare the agent before changing its lifecycle."))?;
    let team = declaration["team"].as_str().unwrap_or_default();
    if !c.has("risk") && !c.teams.iter().any(|t| t == team) {
        return Err(ApiError::forbidden(
            "Owners change the lifecycle of their own teams' agents.",
        ));
    }
    let from = declaration["lifecycle"].as_str().unwrap_or_default().to_owned();
    if !next(&from).contains(&r.to.as_str()) {
        return Err(ApiError::bad(format!(
            "An agent in {from} can move to {:?}.",
            next(&from)
        )));
    }
    let now = wall_clock();
    let record = json!({"id": new_id(), "agent": key, "from": from, "to": r.to, "reason": r.reason,
        "status": "requested", "requested_by": c.principal_id, "requested_at": now,
        "expires_at": add_days(&now, REQUEST_DAYS)});
    let stored = record.clone();
    t.records
        .change(
            COLLECTION,
            "lifecycle_requested",
            json!({"request": record}),
            &now,
            |items| {
                if array(items)
                    .iter()
                    .any(|i| i["agent"] == stored["agent"] && status(i, &now) == "requested")
                {
                    return Err(RecordError::Conflict(
                        "a lifecycle change of this agent is already waiting",
                    ));
                }
                push_new(items, &stored)
            },
        )
        .await?;
    Ok((StatusCode::CREATED, axum::Json(record)).into_response())
}

/// Marks a waiting request decided (`approved` or `rejected`) by `by`, atomically, and
/// returns it. The decider is never the requester.
async fn decide<S: DocumentStore, L: AppendLog>(
    t: &crate::Tower<S, L>,
    id: &str,
    by: &str,
    decision: &str,
    now: &str,
) -> Result<Value, ApiError> {
    Ok(t.records
        .change(
            COLLECTION,
            if decision == "approved" {
                "lifecycle_approved"
            } else {
                "lifecycle_rejected"
            },
            json!({"id": id, "by": by}),
            now,
            |items| {
                let r = array(items)
                    .iter_mut()
                    .find(|r| r["id"] == id)
                    .ok_or(RecordError::NotFound)?;
                match status(r, now) {
                    "requested" => {}
                    "expired" => return Err(RecordError::Conflict("the request expired; request the change again")),
                    _ => return Err(RecordError::Conflict("the request was already decided")),
                }
                if r["requested_by"] == by {
                    return Err(RecordError::Forbidden(
                        "A lifecycle change is decided by someone other than its requester.",
                    ));
                }
                r["status"] = json!(decision);
                r["decided_by"] = json!(by);
                r["decided_at"] = json!(now);
                Ok(r.clone())
            },
        )
        .await?)
}

async fn approve<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    let c = caller(&t, &headers, "risk")?;
    let by = c.principal_id.clone();
    let pending = load(&t)
        .await?
        .into_iter()
        .find(|r| r["id"] == id.as_str())
        .ok_or_else(|| ApiError::not_found("lifecycle request"))?;
    let key = pending["agent"].as_str().unwrap_or_default().to_owned();
    let (from, to) = (
        pending["from"].as_str().unwrap_or_default().to_owned(),
        pending["to"].as_str().unwrap_or_default().to_owned(),
    );
    let snap = snapshot(&t).await?;
    let view = snap.views.iter().find(|v| v.key == key);
    let declaration = view.and_then(|v| v.declaration.as_ref());
    if declaration.is_some_and(|d| d["declared_by"] == by.as_str() || d["owner"] == by.as_str()) {
        return Err(ApiError::forbidden(
            "An agent's owner or declarer cannot approve its lifecycle change.",
        ));
    }
    if to == "approved" && !view.is_some_and(|v| v.approved) {
        return Err(ApiError::bad(
            "Approving an agent needs a current approved risk review of its authority.",
        ));
    }
    let agent_id = view.map_or_else(
        || key.rsplit('/').next().unwrap_or(&key).to_owned(),
        |v| v.activity.agent_id.clone(),
    );
    let now = wall_clock();
    let decided = decide(&t, &id, &by, "approved", &now).await?;
    // The stage changes only from the stage the request was made in, so two approved
    // requests cannot both apply.
    let changed = t
        .records
        .change(
            "declarations",
            "agent_lifecycle_changed",
            json!({"agent": key, "from": from, "to": to, "request": id, "requested_by": decided["requested_by"],
                "approved_by": by}),
            &now,
            |items| {
                let d = object(items).get_mut(&key).ok_or(RecordError::NotFound)?;
                if d["lifecycle"] != from.as_str() {
                    return Err(RecordError::Conflict("the agent's lifecycle changed since the request"));
                }
                d["lifecycle"] = json!(to);
                d["lifecycle_changed_at"] = json!(now);
                d["lifecycle_request"] = json!(id);
                Ok(d.clone())
            },
        )
        .await;
    if let Err(e) = changed {
        let reason = e.to_string();
        let _ = t
            .records
            .change(
                COLLECTION,
                "lifecycle_failed",
                json!({"id": id, "error": reason}),
                &now,
                |items| {
                    if let Some(r) = array(items).iter_mut().find(|r| r["id"] == id.as_str()) {
                        r["status"] = json!("failed");
                        r["error"] = json!(reason);
                    }
                    Ok(())
                },
            )
            .await;
        return Err(e.into());
    }
    let results = enforce(&t, &agent_id, &key, &from, &to, &id).await;
    let done = wall_clock();
    let record = t
        .records
        .change(
            COLLECTION,
            "lifecycle_enforced",
            json!({"id": id, "results": results}),
            &done,
            |items| {
                let r = array(items)
                    .iter_mut()
                    .find(|r| r["id"] == id.as_str())
                    .ok_or(RecordError::NotFound)?;
                r["status"] = json!("applied");
                r["results"] = json!(results);
                r["applied_at"] = json!(done);
                Ok(r.clone())
            },
        )
        .await?;
    ok(record)
}

/// Revokes the agent on every controllable runtime when it stops, and restores the
/// suspension's own revocations when a suspended agent resumes. One result per source.
async fn enforce<S: DocumentStore, L: AppendLog>(
    t: &crate::Tower<S, L>,
    agent_id: &str,
    key: &str,
    from: &str,
    to: &str,
    request: &str,
) -> Vec<Value> {
    let targets: Vec<_> = t.sources.active().into_iter().filter(|s| s.can_control()).collect();
    if stopped(to) && !stopped(from) {
        let reason = format!("{SUSPENSION_MARK} {key} moved to {to} (lifecycle request {request})");
        return apply_revocation(&targets, true, "agent", agent_id, &reason).await;
    }
    if from == "suspended" && !stopped(to) {
        // Only where the agent's revocation is the suspension's own: a revocation an
        // operator placed for another reason stays until restored on its own terms.
        let fleet = t.fleet.read().await;
        let (own, other): (Vec<_>, Vec<_>) = targets.into_iter().partition(|s| {
            fleet
                .sources
                .get(s.id())
                .and_then(|state| state.revocations.get(&format!("agent:{agent_id}")))
                .is_some_and(|r| r.reason.contains(SUSPENSION_MARK))
        });
        drop(fleet);
        let reason = format!("{key} resumed as {to} (lifecycle request {request})");
        let mut results = apply_revocation(&own, false, "agent", agent_id, &reason).await;
        results.extend(other.iter().map(|s| {
            json!({"source": s.id(), "ok": false, "skipped": true,
                "error": "not revoked by this suspension; restore it with a restore request if intended"})
        }));
        return results;
    }
    Vec::new()
}

async fn reject<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    let c = caller(&t, &headers, "risk")?;
    ok(decide(&t, &id, &c.principal_id, "rejected", &wall_clock()).await?)
}

async fn cancel<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    let c = caller_any(&t, &headers, &["owner", "risk"])?;
    let now = wall_clock();
    let by = c.principal_id.clone();
    let record = t
        .records
        .change(
            COLLECTION,
            "lifecycle_cancelled",
            json!({"id": id, "by": by}),
            &now,
            |items| {
                let r = array(items)
                    .iter_mut()
                    .find(|r| r["id"] == id.as_str())
                    .ok_or(RecordError::NotFound)?;
                if r["requested_by"] != by.as_str() {
                    return Err(RecordError::Forbidden(
                        "Only the requester withdraws a lifecycle request.",
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
