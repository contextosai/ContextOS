//! Incident cases: from a finding, a refusal, a held effect or an anomaly to a case with
//! an owner, a status, linked evidence and a timeline, and an exportable report.
//!
//! | Route | Role | Purpose |
//! |---|---|---|
//! | `GET /api/cases?status=` | viewer | cases, newest first |
//! | `POST /api/cases` | operator or risk | open a case (title, severity, links) |
//! | `GET /api/cases/{id}` | viewer | one case |
//! | `POST /api/cases/{id}/notes` | operator or risk | add a note to the timeline |
//! | `POST /api/cases/{id}/links` | operator or risk | link evidence: a finding, run, audit entry or agent |
//! | `POST /api/cases/{id}/status` | operator or risk | move it: open, investigating, contained, resolved, closed (with an owner) |
//! | `GET /api/cases/{id}/report?format=json\|md` | viewer | the incident report |
//!
//! Every change is in Tower's signed journal. Exporting a report journals its digest
//! (`case_exported`), so a report someone edits afterwards no longer matches what was
//! exported. Links name evidence by reference (source and run, audit sequence, finding
//! id); the report says where to verify each one (`ctx audit-verify`, the runtime's
//! evidence bundle), and copies no payloads.

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use contextos_contract::canonical::sha256_canonical;
use contextos_store::{AppendLog, DocumentStore};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::{ApiError, ApiResult, Shared, body, caller, caller_any, ok};
use crate::collector::wall_clock;
use crate::records::{RecordError, array, new_id, push_new};

const COLLECTION: &str = "cases";
pub const STATUSES: [&str; 5] = ["open", "investigating", "contained", "resolved", "closed"];
const SEVERITIES: [&str; 4] = ["critical", "high", "medium", "low"];
const LINK_KINDS: [&str; 5] = ["finding", "run", "audit_entry", "agent", "anomaly"];
/// Timeline entries and links per case at most.
const MAX_ITEMS: usize = 500;
const LISTED: usize = 200;

pub fn routes<S, L>() -> Router<Shared<S, L>>
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    Router::new()
        .route("/api/cases", get(list::<S, L>).post(open::<S, L>))
        .route("/api/cases/{id}", get(one::<S, L>))
        .route("/api/cases/{id}/notes", post(note::<S, L>))
        .route("/api/cases/{id}/links", post(link::<S, L>))
        .route("/api/cases/{id}/status", post(status::<S, L>))
        .route("/api/cases/{id}/report", get(report::<S, L>))
}

async fn load<S: DocumentStore, L: AppendLog>(t: &crate::Tower<S, L>) -> Result<Vec<Value>, ApiError> {
    Ok(t.records
        .load(COLLECTION)
        .await?
        .as_array()
        .cloned()
        .unwrap_or_default())
}

fn valid_link(link: &Value) -> Result<(), ApiError> {
    let kind = link["kind"].as_str().unwrap_or_default();
    let reference = link["ref"].as_str().unwrap_or_default();
    if !LINK_KINDS.contains(&kind) || reference.is_empty() || reference.len() > 512 {
        return Err(ApiError::bad(format!(
            "a link is {{kind: one of {LINK_KINDS:?}, ref, source?}}"
        )));
    }
    if link.as_object().is_some_and(|o| {
        o.keys()
            .any(|k| !["kind", "ref", "source", "note"].contains(&k.as_str()))
    }) {
        return Err(ApiError::bad("a link has kind, ref, and optionally source and note"));
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListQuery {
    #[serde(default)]
    status: Option<String>,
}

async fn list<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    Query(q): Query<ListQuery>,
) -> ApiResult {
    caller(&t, &headers, "viewer")?;
    let cases: Vec<Value> = load(&t)
        .await?
        .into_iter()
        .rev()
        .filter(|c| q.status.as_deref().is_none_or(|s| c["status"] == s))
        .take(LISTED)
        .map(|mut c| {
            // The list carries summaries; the timeline is on the case.
            c["timeline_entries"] = json!(c["timeline"].as_array().map_or(0, Vec::len));
            c.as_object_mut().map(|o| o.remove("timeline"));
            c
        })
        .collect();
    ok(json!({"cases": cases}))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenBody {
    title: String,
    severity: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    links: Vec<Value>,
}

async fn open<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    bytes: Bytes,
) -> ApiResult {
    let c = caller_any(&t, &headers, &["operator", "risk"])?;
    let b: OpenBody = body(&bytes)?;
    if b.title.trim().is_empty() || b.title.len() > 256 || b.summary.len() > 8192 {
        return Err(ApiError::bad(
            "a title of 1 to 256 characters, and a summary up to 8192",
        ));
    }
    if !SEVERITIES.contains(&b.severity.as_str()) {
        return Err(ApiError::bad(format!("severity is one of {SEVERITIES:?}")));
    }
    if b.links.len() > MAX_ITEMS {
        return Err(ApiError::bad("too many links"));
    }
    b.links.iter().try_for_each(valid_link)?;
    let now = wall_clock();
    let record = json!({"id": new_id(), "title": b.title, "severity": b.severity, "summary": b.summary,
        "status": "open", "owner": c.principal_id, "opened_by": c.principal_id, "opened_at": now,
        "links": b.links, "timeline": [{"at": now, "by": c.principal_id, "kind": "opened", "text": b.title}]});
    let stored = record.clone();
    t.records
        .change(COLLECTION, "case_opened", json!({"case": record}), &now, |items| {
            push_new(items, &stored)
        })
        .await?;
    Ok((StatusCode::CREATED, axum::Json(record)).into_response())
}

async fn one<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    caller(&t, &headers, "viewer")?;
    let case = load(&t)
        .await?
        .into_iter()
        .find(|c| c["id"] == id.as_str())
        .ok_or_else(|| ApiError::not_found("case"))?;
    ok(case)
}

/// Applies `edit` to case `id` and journals `kind` with `payload`.
async fn change<S: DocumentStore, L: AppendLog>(
    t: &crate::Tower<S, L>,
    id: &str,
    kind: &str,
    payload: Value,
    now: &str,
    edit: impl Fn(&mut Value) -> Result<(), RecordError>,
) -> ApiResult {
    let mut payload = payload;
    payload["case_id"] = json!(id);
    let updated = t
        .records
        .change(COLLECTION, kind, payload, now, |items| {
            let case = array(items)
                .iter_mut()
                .find(|c| c["id"] == id)
                .ok_or(RecordError::NotFound)?;
            if case["status"] == "closed" {
                return Err(RecordError::Conflict("the case is closed"));
            }
            if case["timeline"].as_array().map_or(0, Vec::len) >= MAX_ITEMS {
                return Err(RecordError::Conflict("the case's timeline is full"));
            }
            edit(case)?;
            Ok(case.clone())
        })
        .await?;
    ok(updated)
}

fn push(case: &mut Value, field: &str, item: Value) {
    if let Some(list) = case[field].as_array_mut() {
        list.push(item);
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoteBody {
    text: String,
}

async fn note<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    bytes: Bytes,
) -> ApiResult {
    let c = caller_any(&t, &headers, &["operator", "risk"])?;
    let b: NoteBody = body(&bytes)?;
    if b.text.trim().is_empty() || b.text.len() > 8192 {
        return Err(ApiError::bad("a note of 1 to 8192 characters"));
    }
    let now = wall_clock();
    let entry = json!({"at": now, "by": c.principal_id, "kind": "note", "text": b.text});
    change(&t, &id, "case_noted", json!({"entry": entry}), &now, |case| {
        push(case, "timeline", entry.clone());
        Ok(())
    })
    .await
}

async fn link<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    bytes: Bytes,
) -> ApiResult {
    let c = caller_any(&t, &headers, &["operator", "risk"])?;
    let l: Value = body(&bytes)?;
    valid_link(&l)?;
    let now = wall_clock();
    let entry = json!({"at": now, "by": c.principal_id, "kind": "link", "text": format!("{} {}", l["kind"].as_str().unwrap_or(""), l["ref"].as_str().unwrap_or(""))});
    change(&t, &id, "case_linked", json!({"link": l}), &now, |case| {
        if case["links"].as_array().map_or(0, Vec::len) >= MAX_ITEMS {
            return Err(RecordError::Conflict("the case has too many links"));
        }
        push(case, "links", l.clone());
        push(case, "timeline", entry.clone());
        Ok(())
    })
    .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusBody {
    status: String,
    #[serde(default)]
    owner: Option<String>,
    reason: String,
}

async fn status<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    bytes: Bytes,
) -> ApiResult {
    let c = caller_any(&t, &headers, &["operator", "risk"])?;
    let b: StatusBody = body(&bytes)?;
    if !STATUSES.contains(&b.status.as_str()) || b.reason.trim().is_empty() || b.reason.len() > 4096 {
        return Err(ApiError::bad(format!("status is one of {STATUSES:?}, with a reason")));
    }
    if b.owner.as_ref().is_some_and(|o| o.trim().is_empty() || o.len() > 256) {
        return Err(ApiError::bad("an owner is a principal id"));
    }
    let now = wall_clock();
    let entry =
        json!({"at": now, "by": c.principal_id, "kind": "status", "text": format!("{}: {}", b.status, b.reason)});
    change(
        &t,
        &id,
        "case_status_changed",
        json!({"status": b.status, "owner": b.owner, "reason": b.reason}),
        &now,
        |case| {
            case["status"] = json!(b.status);
            if let Some(owner) = &b.owner {
                case["owner"] = json!(owner);
            }
            if b.status == "closed" {
                case["closed_at"] = json!(now);
            }
            push(case, "timeline", entry.clone());
            Ok(())
        },
    )
    .await
}

/// The case as Markdown for a reader without Tower.
#[must_use]
pub fn markdown(case: &Value, digest: &str) -> String {
    use std::fmt::Write as _;
    let s = |v: &Value| v.as_str().unwrap_or("").replace('|', "/");
    let mut out = format!(
        "# Incident: {}\n\nSeverity {} · status {} · owner {} · opened {} by {}\n\n{}\n\n## Evidence\n\n",
        s(&case["title"]),
        s(&case["severity"]),
        s(&case["status"]),
        s(&case["owner"]),
        s(&case["opened_at"]),
        s(&case["opened_by"]),
        s(&case["summary"])
    );
    let links = case["links"].as_array().cloned().unwrap_or_default();
    if links.is_empty() {
        out.push_str("No evidence linked.\n");
    } else {
        out.push_str("| Kind | Reference | Source | Verify with |\n|---|---|---|---|\n");
        for l in &links {
            let verify = match l["kind"].as_str() {
                Some("audit_entry") => "`ctx audit-verify` on the source's export",
                Some("run") => "`GET /v1/runs/{run_id}/evidence` on the source",
                Some("finding") => "Tower `GET /api/findings`",
                _ => "Tower",
            };
            let _ = writeln!(
                out,
                "| {} | `{}` | {} | {verify} |",
                s(&l["kind"]),
                s(&l["ref"]),
                s(&l["source"])
            );
        }
    }
    out.push_str("\n## Timeline\n\n");
    for e in case["timeline"].as_array().into_iter().flatten() {
        let _ = writeln!(
            out,
            "- {} {} ({}): {}",
            s(&e["at"]),
            s(&e["kind"]),
            s(&e["by"]),
            s(&e["text"])
        );
    }
    let _ = write!(
        out,
        "\nReport digest `{digest}`, recorded in Tower's signed journal (`case_exported`); verify the journal with `ctx audit-verify` against `GET /api/journal/keys`.\n"
    );
    out
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportQuery {
    #[serde(default)]
    format: Option<String>,
}

async fn report<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<ReportQuery>,
) -> ApiResult {
    let c = caller(&t, &headers, "viewer")?;
    let case = load(&t)
        .await?
        .into_iter()
        .find(|c| c["id"] == id.as_str())
        .ok_or_else(|| ApiError::not_found("case"))?;
    let digest = sha256_canonical(&case).map_err(|e| ApiError::bad(e.to_string()))?;
    let now = wall_clock();
    t.records
        .note(
            "case_exported",
            json!({"case_id": id, "report_digest": digest, "by": c.principal_id, "status": case["status"]}),
            &now,
        )
        .await?;
    match q.format.as_deref() {
        None | Some("json") => ok(json!({"case": case, "report_digest": digest, "exported_at": now})),
        Some("md") => Ok((
            [(header::CONTENT_TYPE, "text/markdown; charset=utf-8")],
            markdown(&case, &digest),
        )
            .into_response()),
        Some(_) => Err(ApiError::bad("format is json or md")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_report_lists_evidence_with_how_to_verify_it() {
        let case = json!({"title": "Refunds | stuck", "severity": "high", "status": "contained", "owner": "oncall-a",
            "opened_at": "2026-11-26T10:00:00Z", "opened_by": "oncall-a", "summary": "INC-311",
            "links": [{"kind": "audit_entry", "ref": "42", "source": "eu"}, {"kind": "run", "ref": "r1", "source": "eu"}],
            "timeline": [{"at": "2026-11-26T10:00:00Z", "by": "oncall-a", "kind": "opened", "text": "Refunds"}]});
        let md = markdown(&case, "sha256:abc");
        assert!(md.starts_with("# Incident: Refunds / stuck"), "{md}");
        assert!(
            md.contains("| audit_entry | `42` | eu | `ctx audit-verify` on the source's export |"),
            "{md}"
        );
        assert!(md.contains("sha256:abc"));
    }

    #[test]
    fn links_name_evidence_by_reference_only() {
        assert!(valid_link(&json!({"kind": "run", "ref": "r1", "source": "eu"})).is_ok());
        assert!(valid_link(&json!({"kind": "payload", "ref": "x"})).is_err());
        assert!(valid_link(&json!({"kind": "run", "ref": ""})).is_err());
        assert!(valid_link(&json!({"kind": "run", "ref": "r1", "body": {"pan": "4111"}})).is_err());
    }
}
