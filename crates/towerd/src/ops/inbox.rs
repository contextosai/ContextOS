//! `GET /api/inbox` and `POST /api/inbox/{source}/{escalation_id}/resolve`: the open
//! escalations of every runtime in one queue, and their resolution from Tower.
//!
//! Each source is read concurrently with its own deadline; a source that cannot be
//! read is reported next to the items, never silently left out. Resolving records
//! what a person did with the hand-off on the runtime (it grants nothing there), with
//! separation of duties: whoever declared or owns the agent cannot close its
//! escalations. Tower journals the request before it touches the runtime, and the
//! runtime's answer after.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use contextos_store::{AppendLog, DocumentStore};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::{ApiError, ApiResult, Shared, body, caller, caller_any, ok};
use crate::collector::wall_clock;
use crate::inbox::{self, Filter};
use crate::source::{Source, SourceError};

/// How long one runtime may take to list its escalations.
const PER_SOURCE: Duration = Duration::from_secs(10);
/// Escalations read per runtime (the runtime's own maximum page).
const LIMIT: usize = 1000;
/// The runtime keeps reasons up to 1024 bytes, Tower's attribution included.
const MAX_REASON: usize = 900;

pub fn routes<S, L>() -> Router<Shared<S, L>>
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    Router::new()
        .route("/api/inbox", get(list::<S, L>))
        .route("/api/inbox/{source}/{escalation_id}/resolve", post(resolve::<S, L>))
}

/// One source's open escalations, or why they could not be read.
async fn read(source: &Source) -> Result<Vec<Value>, String> {
    match tokio::time::timeout(PER_SOURCE, source.escalations(LIMIT)).await {
        Err(_) => Err(format!("no answer within {}s", PER_SOURCE.as_secs())),
        Ok(Err(e)) => Err(e.to_string()),
        Ok(Ok(body)) => body["escalations"]
            .as_array()
            .cloned()
            .ok_or_else(|| "unexpected response: no escalations".to_owned()),
    }
}

async fn list<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    Query(filter): Query<Filter>,
) -> ApiResult {
    caller(&t, &headers, "viewer")?;
    let sources: Vec<_> = t
        .sources
        .active()
        .into_iter()
        .filter(|s| filter.source.as_deref().is_none_or(|id| id == s.id()))
        .collect();
    let listings = read_all(&sources).await;
    let declarations = t.records.load("declarations").await?;
    let now = wall_clock();
    let fleet = t.fleet.read().await;
    let mut items = Vec::new();
    let mut states = Vec::new();
    for (source, listing) in sources.iter().zip(listings) {
        let can_resolve = source.can_control();
        let state = match listing {
            Ok(raw) => {
                let truncated = raw.len() >= LIMIT;
                let mut open = 0;
                for r in &raw {
                    let mut item = inbox::item(source.id(), r, &fleet, &declarations, &now);
                    item["can_resolve"] = json!(can_resolve);
                    if filter.keeps(&item) {
                        open += 1;
                        items.push(item);
                    }
                }
                json!({"source": source.id(), "ok": true, "open": open, "truncated": truncated,
                    "can_resolve": can_resolve})
            }
            Err(error) => json!({"source": source.id(), "ok": false, "error": error, "can_resolve": can_resolve}),
        };
        states.push(state);
    }
    drop(fleet);
    inbox::sort(&mut items);
    ok(json!({"open": items.len(), "items": items, "sources": states, "at": now}))
}

/// Reads every source concurrently, results in the sources' order.
async fn read_all(sources: &[Arc<Source>]) -> Vec<Result<Vec<Value>, String>> {
    let mut set = tokio::task::JoinSet::new();
    for (i, s) in sources.iter().enumerate() {
        let s = s.clone();
        set.spawn(async move { (i, read(&s).await) });
    }
    let mut out: Vec<Result<Vec<Value>, String>> = sources.iter().map(|_| Err("not read".to_owned())).collect();
    while let Some(joined) = set.join_next().await {
        if let Ok((i, result)) = joined {
            out[i] = result;
        }
    }
    out
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveBody {
    /// `handled` or `dismissed`.
    resolution: String,
    reason: String,
}

fn runtime_error(e: &SourceError) -> ApiError {
    match e {
        SourceError::Refused { status: 404, .. } => ApiError::not_found("open escalation"),
        SourceError::Refused { status: 409, .. } => ApiError::new(
            StatusCode::CONFLICT,
            "conflict",
            "The escalation was resolved meanwhile.",
        ),
        _ => ApiError::new(StatusCode::BAD_GATEWAY, "runtime", e.to_string()),
    }
}

async fn resolve<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    Path((source_id, escalation_id)): Path<(String, String)>,
    bytes: Bytes,
) -> ApiResult {
    let c = caller_any(&t, &headers, &["risk", "operator"])?;
    let r: ResolveBody = body(&bytes)?;
    if !matches!(r.resolution.as_str(), "handled" | "dismissed")
        || r.reason.trim().is_empty()
        || r.reason.len() > MAX_REASON
    {
        return Err(ApiError::bad(format!(
            "resolution (handled|dismissed) and a reason of up to {MAX_REASON} bytes are required"
        )));
    }
    let source = t.sources.get(&source_id).ok_or_else(|| ApiError::not_found("source"))?;
    if !source.can_control() {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "no_control_key",
            "Tower holds no control key for this runtime, so its escalations are read-only here.",
        ));
    }
    // The item is taken from the runtime, never from the request, so attribution and
    // separation of duties rest on the runtime's record of the run.
    let open = read(&source)
        .await
        .map_err(|e| ApiError::new(StatusCode::BAD_GATEWAY, "runtime", e))?;
    let raw = open
        .iter()
        .find(|e| e["escalation_id"] == escalation_id.as_str())
        .ok_or_else(|| ApiError::not_found("open escalation"))?;
    let declarations = t.records.load("declarations").await?;
    let now = wall_clock();
    let item = inbox::item(&source_id, raw, &*t.fleet.read().await, &declarations, &now);
    if let Some(agent) = item["agent"].as_str()
        && inbox::accountable(&declarations[agent]).contains(&c.principal_id)
    {
        return Err(ApiError::forbidden(
            "Whoever declared or owns the agent cannot resolve its escalations.",
        ));
    }
    let journal = json!({"source": source_id, "escalation_id": escalation_id, "run_id": item["run_id"],
        "agent": item["agent"], "capability_id": item["capability_id"], "resolution": r.resolution,
        "reason": r.reason, "by": c.principal_id});
    // Journalled before the runtime is touched, so an interrupted action is on record.
    t.records
        .note("escalation_resolution_requested", journal.clone(), &now)
        .await?;
    let reason = format!("{} (via Tower, {})", r.reason.trim(), c.principal_id);
    let outcome = source.resolve_escalation(&escalation_id, &r.resolution, &reason).await;
    let mut result = journal;
    match &outcome {
        Ok(_) => result["ok"] = json!(true),
        Err(e) => {
            result["ok"] = json!(false);
            result["error"] = json!(e.to_string());
        }
    }
    t.records
        .note("escalation_resolution_result", result, &wall_clock())
        .await?;
    let resolved = outcome.map_err(|e| runtime_error(&e))?;
    ok(json!({"source": source_id, "escalation": resolved}))
}
