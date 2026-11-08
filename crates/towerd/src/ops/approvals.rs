//! Approval quality (viewer): per capability and per approver, how many approvals were
//! requested and redeemed, how long decisions took and how many were refused as too
//! fast or without step-up. Folded by [`crate::approvals`] from the runtimes'
//! verified audit chains.
//!
//! | Route | Role | Purpose |
//! |---|---|---|
//! | `GET /api/approvals` | viewer | decision-time buckets, then rows by capability and by approver |

use axum::Router;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::get;
use contextos_store::{AppendLog, DocumentStore};
use serde_json::{Value, json};

use crate::api::{ApiResult, Shared, caller, ok};
use crate::approvals::{BUCKETS, Stats};

pub fn routes<S, L>() -> Router<Shared<S, L>>
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    Router::new().route("/api/approvals", get(approvals::<S, L>))
}

fn rows<'a>(field: &str, stats: impl Iterator<Item = (&'a String, &'a Stats)>) -> Vec<Value> {
    let mut rows: Vec<Value> = stats
        .map(|(name, s)| {
            let mut row = serde_json::to_value(s).unwrap_or_default();
            row[field] = json!(name);
            row["within_ten_seconds"] = json!(s.within_first_bucket());
            row
        })
        .collect();
    rows.sort_by_key(|r| std::cmp::Reverse(r["redeemed"].as_u64().unwrap_or(0) + r["requested"].as_u64().unwrap_or(0)));
    rows
}

async fn approvals<S: DocumentStore, L: AppendLog>(State(t): State<Shared<S, L>>, headers: HeaderMap) -> ApiResult {
    caller(&t, &headers, "viewer")?;
    let fleet = t.fleet.read().await;
    ok(json!({
        "buckets_seconds": BUCKETS,
        "capabilities": rows("capability_id", fleet.approvals.capabilities.iter()),
        "approvers": rows("approver", fleet.approvals.approvers.iter()),
    }))
}
