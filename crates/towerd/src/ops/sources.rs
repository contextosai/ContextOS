//! Runtime sources from the console: their health, and adding, pausing, resuming,
//! re-verifying, re-keying and removing them (admin), each journalled with who and why.
//!
//! | Route | Role | Purpose |
//! |---|---|---|
//! | `GET /api/sources/health` | viewer (key references: admin) | every source's collector state, lag and errors |
//! | `POST /api/sources/probe` | admin | check a proposed source: keys, scopes, tenant, conflicts; changes nothing |
//! | `POST /api/sources` | admin | add a source (probed again first) |
//! | `POST /api/sources/{id}/{action}` | admin | `pause`, `resume`, `retry`, `reload` or `remove` (console sources), with a reason |
//!
//! Keys are referenced (environment variable or secret file), never accepted, stored,
//! returned or journalled. Every change goes through the `sources` record collection,
//! so it is journalled and every replica converges on it (see
//! [`crate::sources_admin`]).

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use contextos_store::{AppendLog, DocumentStore};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::Tower;
use crate::api::{ApiError, ApiResult, Caller, Shared, body, caller, ok};
use crate::collector::wall_clock;
use crate::config::SourceConfig;
use crate::fleet::SourceState;
use crate::records::{RecordError, object};
use crate::registry::Origin;
use crate::source::{Source, SourceError};
use crate::sources_admin::{COLLECTION, ConsoleSource, Control, Stored, reconcile};

pub fn routes<S, L>() -> Router<Shared<S, L>>
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    Router::new()
        .route("/api/sources", post(add::<S, L>))
        .route("/api/sources/health", get(health::<S, L>))
        .route("/api/sources/probe", post(probe::<S, L>))
        .route("/api/sources/{id}/{action}", post(act::<S, L>))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AddBody {
    source: SourceConfig,
    reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReasonBody {
    reason: String,
}

fn reason(text: &str) -> Result<&str, ApiError> {
    let text = text.trim();
    if text.is_empty() || text.len() > 2048 {
        return Err(ApiError::bad("A reason (up to 2048 bytes) is required."));
    }
    Ok(text)
}

/// The key references of a definition: names and paths only.
fn references(c: &SourceConfig) -> Value {
    json!({"token_env": c.token_env, "token_file": c.token_file,
        "control_token_env": c.control_token_env, "control_token_file": c.control_token_file})
}

/// A sub-map of the collection's items, created when missing.
fn submap<'a>(items: &'a mut Value, name: &str) -> &'a mut Map<String, Value> {
    let entry = object(items).entry(name.to_owned()).or_insert_with(|| json!({}));
    if !entry.is_object() {
        *entry = json!({});
    }
    entry.as_object_mut().expect("just set")
}

fn runtime_error(what: &str, e: &SourceError) -> ApiError {
    match e {
        SourceError::Refused { status: 401 | 403, .. } => ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "source_key_refused",
            format!("The runtime refused the {what}: {e}"),
        ),
        _ => ApiError::new(
            StatusCode::BAD_GATEWAY,
            "runtime",
            format!("The runtime could not be reached with the {what}: {e}"),
        ),
    }
}

fn scopes(deployment: &Value) -> Vec<String> {
    deployment["caller"]["scopes"]
        .as_array()
        .map(|a| a.iter().filter_map(|s| s.as_str().map(str::to_owned)).collect())
        .unwrap_or_default()
}

/// The tenant each existing source governs, from its verified chain or its deployment.
async fn governed<S: DocumentStore, L: AppendLog>(t: &Tower<S, L>, stored: &Stored) -> Vec<(String, String)> {
    let fleet = t.fleet.read().await;
    let mut out: Vec<(String, String)> = stored
        .console
        .iter()
        .map(|(id, s)| (id.clone(), s.tenant_id.clone()))
        .collect();
    for listed in t.sources.listed() {
        let id = listed.source.id();
        let tenant = fleet.sources.get(id).and_then(|s| {
            s.tenant_id
                .clone()
                .or_else(|| s.deployment["caller"]["tenant_id"].as_str().map(str::to_owned))
        });
        if let Some(tenant) = tenant {
            out.push((id.to_owned(), tenant));
        }
    }
    out
}

/// Checks a proposed source against the runtime without changing anything.
async fn check<S: DocumentStore, L: AppendLog>(t: &Tower<S, L>, config: &SourceConfig) -> Result<Value, ApiError> {
    config.check(t.config.server.development).map_err(ApiError::bad)?;
    let stored = Stored::parse(&t.records.load(COLLECTION).await?);
    if t.sources.get(&config.id).is_some() || stored.console.contains_key(&config.id) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "source_exists",
            format!("A source with id {:?} exists.", config.id),
        ));
    }
    let source = Source::new(config.clone()).map_err(|e| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "source_key_unavailable",
            format!("The read key cannot be loaded on this Tower: {e}"),
        )
    })?;
    let has_control_ref = config.control_token_env.is_some() || config.control_token_file.is_some();
    if has_control_ref && !source.can_control() {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "source_key_unavailable",
            "The control key cannot be loaded on this Tower: set the variable or mount the file, or leave it out.",
        ));
    }
    let deployment = source.deployment().await.map_err(|e| runtime_error("read key", &e))?;
    let tenant = deployment["caller"]["tenant_id"]
        .as_str()
        .filter(|t| !t.is_empty())
        .ok_or_else(|| ApiError::new(StatusCode::BAD_GATEWAY, "runtime", "The runtime did not name a tenant."))?
        .to_owned();
    let read_scopes = scopes(&deployment);
    if !read_scopes.iter().any(|s| s == "audit:read") {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "source_scope_missing",
            "The read key lacks the audit:read scope.",
        ));
    }
    source
        .keys()
        .await
        .map_err(|e| runtime_error("audit signing keys", &e))?;
    let mut warnings = Vec::new();
    let extra: Vec<&String> = read_scopes.iter().filter(|s| *s != "audit:read").collect();
    if !extra.is_empty() {
        warnings.push(format!(
            "The read key also holds {extra:?}; Tower needs only audit:read. Issue a narrower key."
        ));
    }
    if let Some(control) = source
        .deployment_as_control()
        .await
        .map_err(|e| runtime_error("control key", &e))?
    {
        if control["caller"]["tenant_id"].as_str() != Some(tenant.as_str()) {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "source_tenant_mismatch",
                "The control key belongs to a different tenant than the read key.",
            ));
        }
        if !scopes(&control).iter().any(|s| s == "control") {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "source_scope_missing",
                "The control key lacks the control scope.",
            ));
        }
    } else {
        warnings.push("No control key: the fleet kill switch will skip this source.".into());
    }
    if let Some((other, _)) = governed(t, &stored).await.into_iter().find(|(_, g)| *g == tenant) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "tenant_governed",
            format!("Tenant {tenant} is already governed by source {other}."),
        ));
    }
    let supported = deployment["support"]["supported_controls"]
        .as_array()
        .map_or(0, Vec::len);
    Ok(json!({
        "id": config.id, "url": config.url, "tenant_id": tenant,
        "principal_id": deployment["caller"]["principal_id"], "scopes": read_scopes,
        "mode": deployment["mode"], "packs": deployment["packs"].as_array().map_or(0, Vec::len),
        "supported_controls": supported, "can_revoke": source.can_control(), "warnings": warnings,
    }))
}

async fn probe<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    bytes: Bytes,
) -> ApiResult {
    caller(&t, &headers, "admin")?;
    let config: SourceConfig = body(&bytes)?;
    ok(check(&t, &config).await?)
}

async fn add<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    bytes: Bytes,
) -> ApiResult {
    let c = caller(&t, &headers, "admin")?;
    let request: AddBody = body(&bytes)?;
    let why = reason(&request.reason)?.to_owned();
    let probed = check(&t, &request.source).await?;
    let tenant = probed["tenant_id"].as_str().unwrap_or_default().to_owned();
    let now = wall_clock();
    let record = ConsoleSource {
        config: request.source.clone(),
        tenant_id: tenant.clone(),
        added_by: c.principal_id.clone(),
        added_at: now.clone(),
        reason: why.clone(),
    };
    let id = request.source.id.clone();
    let payload = json!({"source": id, "url": request.source.url, "tenant_id": tenant,
        "keys": references(&request.source), "by": c.principal_id, "reason": why});
    let value = serde_json::to_value(&record).map_err(|e| ApiError::bad(e.to_string()))?;
    t.records
        .change(COLLECTION, "source_added", payload, &now, |items| {
            let console = submap(items, "console");
            if console.contains_key(&id) {
                return Err(RecordError::Conflict("a source with this id exists"));
            }
            console.insert(id.clone(), value.clone());
            Ok(())
        })
        .await?;
    reconcile(&t).await?;
    let row = rows(&t, true).await?.into_iter().find(|r| r["id"] == id.as_str());
    Ok((StatusCode::CREATED, axum::Json(json!({"source": row, "probe": probed}))).into_response())
}

async fn act<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    Path((id, action)): Path<(String, String)>,
    bytes: Bytes,
) -> ApiResult {
    let c = caller(&t, &headers, "admin")?;
    let request: ReasonBody = body(&bytes)?;
    let why = reason(&request.reason)?.to_owned();
    let kind = match action.as_str() {
        "pause" => "source_paused",
        "resume" => "source_resumed",
        "retry" => "source_retried",
        "reload" => "source_keys_reloaded",
        "remove" => "source_removed",
        _ => return Err(ApiError::not_found("source action")),
    };
    let origin = t.sources.origin(&id);
    let unavailable = t.source_admin.unavailable().contains_key(&id);
    if origin.is_none() && !unavailable {
        return Err(ApiError::not_found("source"));
    }
    if action == "remove" && origin == Some(Origin::Config) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "source_in_config",
            "This source is defined in towerd.toml: remove it there and restart towerd.",
        ));
    }
    let now = wall_clock();
    let payload = json!({"source": id, "by": c.principal_id, "reason": why});
    t.records
        .change(COLLECTION, kind, payload, &now, |items| {
            if action == "remove" {
                if submap(items, "console").remove(&id).is_none() {
                    return Err(RecordError::NotFound);
                }
                submap(items, "controls").remove(&id);
                return Ok(());
            }
            let controls = submap(items, "controls");
            let mut control: Control = controls
                .get(&id)
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();
            match action.as_str() {
                "pause" if control.paused => return Err(RecordError::Conflict("the source is already paused")),
                "resume" if !control.paused => return Err(RecordError::Conflict("the source is not paused")),
                "pause" | "resume" => control.paused = action == "pause",
                "retry" => control.retry += 1,
                _ => control.reload += 1,
            }
            control.by = Some(c.principal_id.clone());
            control.at = Some(now.clone());
            control.reason = Some(why.clone());
            controls.insert(id.clone(), serde_json::to_value(&control).unwrap_or_default());
            Ok(())
        })
        .await?;
    reconcile(&t).await?;
    let row = rows(&t, true).await?.into_iter().find(|r| r["id"] == id.as_str());
    ok(json!({"source": row}))
}

async fn health<S: DocumentStore, L: AppendLog>(State(t): State<Shared<S, L>>, headers: HeaderMap) -> ApiResult {
    let c: Caller = caller(&t, &headers, "viewer")?;
    let (reconciled_at, reconcile_error) = t.source_admin.status();
    ok(
        json!({"sources": rows(&t, c.has("admin")).await?, "reconciled_at": reconciled_at,
        "reconcile_error": reconcile_error, "stale_after_seconds": stale_after(&t)}),
    )
}

fn stale_after<S, L>(t: &Tower<S, L>) -> u64 {
    (t.config.collector.poll_ms.saturating_mul(5) / 1000).max(60)
}

/// What a source's collector is doing, most urgent first.
pub fn status(
    paused: bool,
    collecting: bool,
    state: Option<&SourceState>,
    age: Option<u64>,
    stale: u64,
) -> &'static str {
    let broken = state.is_some_and(|s| s.broken.is_some());
    let error = state.is_some_and(|s| s.last_error.is_some());
    match () {
        () if paused => "paused",
        () if broken => "broken",
        () if !collecting => "stopped",
        () if error => "error",
        () if age.is_none() => "starting",
        () if age.is_some_and(|a| a > stale) => "stale",
        () => "current",
    }
}

async fn rows<S: DocumentStore, L: AppendLog>(t: &Tower<S, L>, admin: bool) -> Result<Vec<Value>, ApiError> {
    let stored = Stored::parse(&t.records.load(COLLECTION).await?);
    let unavailable = t.source_admin.unavailable();
    let now = wall_clock();
    let stale = stale_after(t);
    let fleet = t.fleet.read().await;
    let row = |config: &SourceConfig, origin: Origin, paused: bool, collecting: bool, can_revoke: bool| {
        let state = fleet.sources.get(&config.id);
        let age = state
            .and_then(|s| s.last_sync.as_deref())
            .and_then(|at| contextos_contract::validation::elapsed_millis(at, &now))
            .map(|ms| ms / 1000);
        let console = stored.console.get(&config.id);
        let control = stored.controls.get(&config.id);
        let mut row = json!({
            "id": config.id, "url": config.url, "origin": origin,
            "state": status(paused, collecting, state, age, stale), "paused": paused, "collecting": collecting,
            "tenant_id": state.and_then(|s| s.tenant_id.clone()).or_else(|| console.map(|c| c.tenant_id.clone())),
            "verified_to": state.map_or(0, |s| s.verified_to), "head": state.map_or(0, |s| s.head),
            "lag": state.map_or(0, |s| s.head.saturating_sub(s.verified_to)),
            "last_sync": state.and_then(|s| s.last_sync.clone()), "last_sync_age_seconds": age,
            "last_error": state.and_then(|s| s.last_error.clone()), "broken": state.and_then(|s| s.broken.clone()),
            "unattributed": state.map_or(0, |s| s.unattributed), "can_revoke": can_revoke,
            "business_unit": config.business_unit, "region": config.region, "environment": config.environment,
            "added_by": console.map(|c| c.added_by.clone()), "added_at": console.map(|c| c.added_at.clone()),
            "last_change": control.map(|c| json!({"by": c.by, "at": c.at, "reason": c.reason})),
        });
        if admin {
            row["keys"] = references(config);
        }
        row
    };
    let mut out: Vec<Value> = t
        .sources
        .listed()
        .iter()
        .map(|l| {
            row(
                &l.source.config,
                l.origin,
                l.paused,
                l.collecting,
                l.source.can_control(),
            )
        })
        .collect();
    for (id, u) in &unavailable {
        if t.sources.get(id).is_some() {
            continue;
        }
        let paused = stored.controls.get(id).is_some_and(|c| c.paused);
        let mut r = row(&u.config, Origin::Console, paused, false, false);
        r["state"] = json!("unavailable");
        r["last_error"] = json!(u.error);
        out.push(r);
    }
    out.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    Ok(out)
}
