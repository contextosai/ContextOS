//! Live compliance readiness console and journalled auditor report export
//! ([`crate::compliance`]).
//!
//! | Route | Role | Purpose |
//! |---|---|---|
//! | `GET /api/compliance` | viewer | live control coverage and verified event counts per framework |
//! | `POST /api/compliance/report` | viewer | exportable Markdown or JSON report whose digest is journalled |
//!
//! The export is a `POST` because it appends to Tower's journal; a `GET` stays free of
//! side effects (prefetchers, link scanners and retries never journal an export).

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use contextos_store::{AppendLog, DocumentStore};
use serde::Deserialize;
use serde_json::json;

use crate::api::{ApiError, ApiResult, Shared, body, caller, ok, snapshot};
use crate::collector::wall_clock;
use crate::compliance::{FRAMEWORKS, evaluate, markdown};

pub fn routes<S, L>() -> Router<Shared<S, L>>
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    Router::new()
        .route("/api/compliance", get(view::<S, L>))
        .route("/api/compliance/report", post(report::<S, L>))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ComplianceQuery {
    #[serde(default)]
    framework: Option<String>,
    #[serde(default)]
    source: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportQuery {
    #[serde(default)]
    framework: Option<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    format: Option<String>,
}

fn select_frameworks(framework: Option<&str>) -> Result<Vec<&'static str>, ApiError> {
    let Some(name) = framework.filter(|s| !s.is_empty()) else {
        return Ok(FRAMEWORKS.to_vec());
    };
    FRAMEWORKS
        .iter()
        .copied()
        .find(|f| *f == name)
        .map(|f| vec![f])
        .ok_or_else(|| {
            ApiError::bad(format!(
                "unknown framework `{name}`; expected one of: {}",
                FRAMEWORKS.join(", ")
            ))
        })
}

async fn view<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    Query(q): Query<ComplianceQuery>,
) -> ApiResult {
    caller(&t, &headers, "viewer")?;
    let selected = select_frameworks(q.framework.as_deref())?;
    let snap = snapshot(&t).await?;
    let fleet = t.fleet.read().await;
    ok(evaluate(
        &fleet,
        &snap.findings,
        &selected,
        q.source.as_deref(),
        &snap.now,
    ))
}

async fn report<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    bytes: Bytes,
) -> ApiResult {
    let c = caller(&t, &headers, "viewer")?;
    let q: ReportQuery = if bytes.is_empty() {
        ReportQuery::default()
    } else {
        body(&bytes)?
    };
    let selected = select_frameworks(q.framework.as_deref())?;
    let snap = snapshot(&t).await?;
    let report = {
        let fleet = t.fleet.read().await;
        evaluate(&fleet, &snap.findings, &selected, q.source.as_deref(), &snap.now)
    };
    let digest = report["digest"].as_str().unwrap_or_default().to_owned();
    let format = q.format.as_deref().unwrap_or("markdown");
    if !matches!(format, "markdown" | "json") {
        return Err(ApiError::bad("format must be `markdown` or `json`"));
    }
    let now = wall_clock();
    t.records
        .note(
            "compliance_report_exported",
            json!({
                "frameworks": selected,
                "source": q.source,
                "format": format,
                "report_digest": digest,
                "by": c.principal_id,
            }),
            &now,
        )
        .await?;
    if format == "json" {
        return Ok((
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/json; charset=utf-8"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"contextos-compliance-report.json\"",
                ),
            ],
            serde_json::to_string_pretty(&report).unwrap_or_default(),
        )
            .into_response());
    }
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/markdown; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"contextos-compliance-report.md\"",
            ),
        ],
        markdown(&report),
    )
        .into_response())
}
