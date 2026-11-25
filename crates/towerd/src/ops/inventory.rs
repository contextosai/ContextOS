//! The inventory (viewer): every agent, capability, adapter, model and owning team,
//! with first and last seen, environments, risk tier and whether it is declared
//! ([`crate::inventory`]).
//!
//! | Route | Role | Purpose |
//! |---|---|---|
//! | `GET /api/inventory?kind=&shadow=true&format=csv` | viewer | inventory rows, as JSON or CSV |

use std::collections::BTreeMap;

use axum::Router;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, header};
use axum::response::IntoResponse;
use axum::routing::get;
use contextos_store::{AppendLog, DocumentStore};
use serde::Deserialize;
use serde_json::json;

use crate::api::{ApiError, ApiResult, Shared, caller, ok, snapshot};
use crate::inventory::{KINDS, csv, inventory};

pub fn routes<S, L>() -> Router<Shared<S, L>>
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    Router::new().route("/api/inventory", get(list::<S, L>))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryQuery {
    #[serde(default)]
    kind: Option<String>,
    /// Only rows seen in traffic and not declared.
    #[serde(default)]
    shadow: Option<bool>,
    /// `json` (the default) or `csv`.
    #[serde(default)]
    format: Option<String>,
}

async fn list<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    Query(q): Query<InventoryQuery>,
) -> ApiResult {
    caller(&t, &headers, "viewer")?;
    if q.kind.as_deref().is_some_and(|k| !KINDS.contains(&k)) {
        return Err(ApiError::bad(format!("kind must be one of {KINDS:?}")));
    }
    let csv_out = match q.format.as_deref() {
        None | Some("json") => false,
        Some("csv") => true,
        Some(_) => return Err(ApiError::bad("format must be json or csv")),
    };
    let environments: BTreeMap<String, String> = t
        .sources
        .listed()
        .iter()
        .filter_map(|l| {
            l.source
                .config
                .environment
                .clone()
                .map(|e| (l.source.id().to_owned(), e))
        })
        .collect();
    let snap = snapshot(&t).await?;
    let items: Vec<_> = inventory(&snap.views, &environments)
        .into_iter()
        .filter(|i| q.kind.as_deref().is_none_or(|k| i.kind == k))
        .filter(|i| !q.shadow.unwrap_or(false) || (!i.declared && i.last_seen.is_some()))
        .collect();
    if csv_out {
        return Ok((
            [
                (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
                (header::CONTENT_DISPOSITION, "attachment; filename=\"inventory.csv\""),
            ],
            csv(&items),
        )
            .into_response());
    }
    let shadow = items.iter().filter(|i| !i.declared && i.last_seen.is_some()).count();
    ok(json!({"items": items, "shadow": shadow, "generated_at": snap.now}))
}
