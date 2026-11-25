//! Access reviews ([`crate::access_review`]).
//!
//! | Route | Role | Purpose |
//! |---|---|---|
//! | `GET /api/access-review?days=90&format=csv` | viewer | grants held vs used, stale delegations, dormant agents, expiring waivers and reviews |
//! | `POST /api/access-review/attest` | risk | record that the review was done, citing the report's digest (journal `access_review_attested`) |
//!
//! Acting on the report uses the existing routes: revoke an agent or capability on
//! every runtime (`POST /api/fleet/revoke`), suspend an agent through its lifecycle
//! (`POST /api/agents/{key}/lifecycle`), or let a waiver lapse.

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, header};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use contextos_store::{AppendLog, DocumentStore};
use serde::Deserialize;
use serde_json::json;

use crate::access_review::{AccessReview, access_review};
use crate::api::{ApiError, ApiResult, Shared, body, caller, ok, snapshot};

pub fn routes<S, L>() -> Router<Shared<S, L>>
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    Router::new()
        .route("/api/access-review", get(report::<S, L>))
        .route("/api/access-review/attest", post(attest::<S, L>))
}

fn days(d: Option<i64>) -> Result<i64, ApiError> {
    let d = d.unwrap_or(90);
    if !(7..=365).contains(&d) {
        return Err(ApiError::bad("days must be 7 to 365"));
    }
    Ok(d)
}

async fn build<S: DocumentStore, L: AppendLog>(t: &crate::Tower<S, L>, d: i64) -> Result<AccessReview, ApiError> {
    let snap = snapshot(t).await?;
    let waivers = t.records.load("waivers").await?;
    Ok(access_review(&snap.views, &waivers, &snap.now, d))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportQuery {
    #[serde(default)]
    days: Option<i64>,
    #[serde(default)]
    format: Option<String>,
}

fn csv(review: &AccessReview) -> String {
    let cell = |s: &str| {
        let s = if s.starts_with(['=', '+', '-', '@']) {
            format!("'{s}")
        } else {
            s.to_owned()
        };
        if s.contains([',', '"', '\n', '\r']) {
            format!("\"{}\"", s.replace('"', "\"\""))
        } else {
            s
        }
    };
    let mut out = String::from("agent,owner_team,capability,adapter,packs,status,last_used\n");
    for g in &review.grants {
        let row = [
            g.agent.clone(),
            g.owner_team.clone().unwrap_or_default(),
            g.capability.clone(),
            g.adapter.clone(),
            g.packs.join(";"),
            g.status.to_owned(),
            g.last_used.clone().unwrap_or_default(),
        ];
        out.push_str(&row.iter().map(|c| cell(c)).collect::<Vec<_>>().join(","));
        out.push('\n');
    }
    out
}

async fn report<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    Query(q): Query<ReportQuery>,
) -> ApiResult {
    caller(&t, &headers, "viewer")?;
    let review = build(&t, days(q.days)?).await?;
    match q.format.as_deref() {
        None | Some("json") => ok(serde_json::to_value(&review).unwrap_or_default()),
        Some("csv") => Ok((
            [
                (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"access-review.csv\"",
                ),
            ],
            csv(&review),
        )
            .into_response()),
        Some(_) => Err(ApiError::bad("format must be json or csv")),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Attestation {
    days: i64,
    /// The digest of the report the reviewer read.
    digest: String,
    notes: String,
}

async fn attest<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    bytes: Bytes,
) -> ApiResult {
    let c = caller(&t, &headers, "risk")?;
    let a: Attestation = body(&bytes)?;
    if a.notes.trim().len() < 10 || a.notes.len() > 4096 {
        return Err(ApiError::bad("notes of 10 to 4096 characters are required"));
    }
    let review = build(&t, days(Some(a.days))?).await?;
    if review.digest != a.digest {
        return Err(ApiError::new(
            axum::http::StatusCode::CONFLICT,
            "conflict",
            "The findings changed since that report was read; read the review again before attesting.",
        ));
    }
    let record = json!({"digest": review.digest, "window_days": review.window_days, "summary": review.summary,
        "notes": a.notes, "attested_by": c.principal_id, "attested_at": review.generated_at});
    t.records
        .note("access_review_attested", record.clone(), &review.generated_at)
        .await?;
    ok(record)
}
