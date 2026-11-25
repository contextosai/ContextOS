//! Break-glass grants and their post-incident reviews.
//!
//! | Route | Role | Purpose |
//! |---|---|---|
//! | `GET /api/break-glass` | viewer | every grant the runtimes' chains show, with its calls and review |
//! | `POST /api/break-glass/review` | risk, not the grant's opener | record the review (journal `break_glass_reviewed`) |

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::{get, post};
use contextos_store::{AppendLog, DocumentStore};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::{ApiError, ApiResult, Shared, body, caller, ok};
use crate::collector::wall_clock;
use crate::governance::break_glass::review_key;
use crate::records::{RecordError, object};

pub fn routes<S, L>() -> Router<Shared<S, L>>
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    Router::new()
        .route("/api/break-glass", get(list::<S, L>))
        .route("/api/break-glass/review", post(review::<S, L>))
}

async fn list<S: DocumentStore, L: AppendLog>(State(t): State<Shared<S, L>>, headers: HeaderMap) -> ApiResult {
    caller(&t, &headers, "viewer")?;
    let reviews = t.records.load("break_glass_reviews").await?;
    let fleet = t.fleet.read().await;
    let mut grants: Vec<Value> = Vec::new();
    for state in fleet.sources.values() {
        for g in state.break_glass.iter().rev() {
            let mut row = g.clone();
            row["source"] = json!(state.id);
            row["review"] = reviews
                .get(review_key(&state.id, g["grant_id"].as_str().unwrap_or_default()))
                .cloned()
                .unwrap_or(Value::Null);
            grants.push(row);
        }
    }
    ok(json!({"grants": grants}))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewBody {
    source: String,
    grant_id: String,
    notes: String,
}

async fn review<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    bytes: Bytes,
) -> ApiResult {
    let c = caller(&t, &headers, "risk")?;
    let r: ReviewBody = body(&bytes)?;
    if r.notes.trim().len() < 20 || r.notes.len() > 4096 {
        return Err(ApiError::bad("notes of 20 to 4096 characters are required"));
    }
    let opener = {
        let fleet = t.fleet.read().await;
        fleet
            .sources
            .get(&r.source)
            .and_then(|s| s.break_glass.iter().find(|g| g["grant_id"] == r.grant_id.as_str()))
            .map(|g| g["opened_by"].as_str().unwrap_or_default().to_owned())
            .ok_or_else(|| ApiError::not_found("break-glass grant"))?
    };
    if opener == c.principal_id {
        return Err(ApiError::forbidden(
            "Whoever opened a break-glass grant does not review it.",
        ));
    }
    let now = wall_clock();
    let key = review_key(&r.source, &r.grant_id);
    let record = json!({"source": r.source, "grant_id": r.grant_id, "notes": r.notes,
        "reviewed_by": c.principal_id, "reviewed_at": now});
    let stored = record.clone();
    t.records
        .change(
            "break_glass_reviews",
            "break_glass_reviewed",
            json!({"review": record}),
            &now,
            |items| {
                let items = object(items);
                if items.contains_key(&key) {
                    return Err(RecordError::Conflict("this grant was already reviewed"));
                }
                items.insert(key.clone(), stored.clone());
                Ok(())
            },
        )
        .await?;
    ok(record)
}
