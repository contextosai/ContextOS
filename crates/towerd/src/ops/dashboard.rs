//! The governance dashboard ([`crate::dashboard`]).
//!
//! | Route | Role | Purpose |
//! |---|---|---|
//! | `GET /api/dashboard` | viewer | held effects, denials, approvals waiting, waivers, policy drift, unreviewed break-glass, ceilings in use, evidence-chain health |

use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::get;
use contextos_store::{AppendLog, DocumentStore};
use serde_json::{Value, json};

use crate::api::{ApiResult, Shared, caller, ok, snapshot};
use crate::dashboard::{dashboard, utilisation};

/// How long a runtime may take to list its ceilings before the dashboard shows it as
/// unavailable.
const LIVE_TIMEOUT: Duration = Duration::from_secs(5);
/// Guarantees read per source at most.
const MAX_GUARANTEES: usize = 32;

pub fn routes<S, L>() -> Router<Shared<S, L>>
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    Router::new().route("/api/dashboard", get(view::<S, L>))
}

/// Each source's shared ceilings and how full they are, read live.
async fn ceilings(source: std::sync::Arc<crate::source::Source>) -> Vec<Value> {
    let id = source.id().to_owned();
    let read = async {
        let listed = source.get("/v1/guarantees").await?;
        let mut rows = Vec::new();
        for g in listed["guarantees"]
            .as_array()
            .into_iter()
            .flatten()
            .take(MAX_GUARANTEES)
        {
            let gid = g["id"].as_str().unwrap_or_default();
            let holds = source.get(&format!("/v1/guarantees/{gid}/holds")).await?;
            rows.push(utilisation(&id, g, &holds));
        }
        Ok::<_, crate::source::SourceError>(rows)
    };
    match tokio::time::timeout(LIVE_TIMEOUT, read).await {
        Ok(Ok(rows)) => rows,
        Ok(Err(e)) => vec![json!({"source": id, "unavailable": e.to_string()})],
        Err(_) => vec![json!({"source": id, "unavailable": "timed out"})],
    }
}

async fn view<S: DocumentStore, L: AppendLog>(State(t): State<Shared<S, L>>, headers: HeaderMap) -> ApiResult {
    caller(&t, &headers, "viewer")?;
    let snap = snapshot(&t).await?;
    let waivers = t.records.load("waivers").await?;
    let mut body = {
        let fleet = t.fleet.read().await;
        dashboard(&fleet, &snap.findings, &waivers, &snap.now)
    };
    let mut rows = Vec::new();
    for source in t.sources.active() {
        rows.extend(ceilings(source).await);
    }
    rows.sort_by(|a, b| {
        b["fullest_share"]
            .as_f64()
            .unwrap_or(-1.0)
            .total_cmp(&a["fullest_share"].as_f64().unwrap_or(-1.0))
    });
    body["ceilings"] = json!(rows);
    ok(body)
}
