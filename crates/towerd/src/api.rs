//! Tower's HTTP API (`/api/*`), role-checked, with separation of duties enforced here:
//! nobody approves their own review, waiver or guardrail, and the model approves nothing.
//!
//! | Route | Role | Purpose |
//! |---|---|---|
//! | `GET /api/me` | any | the caller's principal, roles and teams |
//! | `GET /api/posture` | viewer | the organisation's governance posture |
//! | `GET /api/agents` | viewer | the inventory |
//! | `GET /api/agents/{key}` | viewer | one agent: facts, authority, findings, activity |
//! | `PUT /api/agents/{key}/declaration` | owner (team) or risk | declare owner, purpose, lifecycle |
//! | `POST /api/agents/{key}/review` | risk (not the declarer) | record a risk review of the current authority |
//! | `GET /api/findings` | viewer | findings, most severe first |
//! | `GET /api/anomalies` | viewer | behaviour against each agent's own baseline |
//! | `GET /api/runs` | viewer | recent runs across the fleet |
//! | `GET /api/runs/{source}/{run}/evidence` | viewer | a run's evidence, fetched from its runtime (journalled) |
//! | `GET /api/changes` | viewer | governance changes across the fleet |
//! | `GET /api/sources` | viewer | runtimes and their verification state |
//! | `GET/POST /api/guardrails`, `POST …/{id}/activate`, `…/retire` | risk (activate: not the author) | organisation guardrails |
//! | `POST /api/guardrails/preview` | risk | a rule's impact on the current inventory |
//! | `GET/POST /api/waivers`, `POST …/{id}/decide` | owner/risk (decide: risk, not the requester) | time-boxed exceptions |
//! | `POST /api/fleet/revoke`, `POST /api/fleet/restore` | operator | kill switch on every runtime |
//! | `POST /api/ask` | viewer | ask the analyst |
//! | `POST /api/guardrails/draft` | risk | draft a guardrail from an intent |
//! | `POST /api/agents/{key}/assess` | risk or owner | draft an intake review |
//! | `POST /api/anomalies/brief` | operator or risk | brief an anomaly |
//! | `POST /api/runs/{source}/{run}/explain` | viewer | explain a run |
//! | `GET /api/journal`, `GET /api/journal/keys` | viewer / public | Tower's signed journal |

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use contextos_store::{AppendLog, DocumentStore};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::Tower;
use crate::collector::wall_clock;
use crate::config::ApiKey;
use crate::governance::{self, AgentView, Anomaly, Finding};
use crate::intel::{self, IntelError, jobs};
use crate::records::{Declaration, RecordError, array, object};

type Shared<S, L> = Arc<Tower<S, L>>;

// ---- callers ----

#[derive(Debug, Clone)]
pub struct Caller {
    pub principal_id: String,
    pub roles: Vec<String>,
    pub teams: Vec<String>,
}

impl Caller {
    pub fn has(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role || r == "admin") || (role == "viewer" && !self.roles.is_empty())
    }
}

#[derive(Debug, Clone, Default)]
pub struct Callers {
    keys: Vec<([u8; 32], Caller)>,
}

impl Callers {
    pub fn new(keys: &[ApiKey]) -> Self {
        let keys = keys
            .iter()
            .filter_map(|k| {
                let digest: [u8; 32] = hex::decode(k.key_sha256.strip_prefix("sha256:")?)
                    .ok()?
                    .try_into()
                    .ok()?;
                Some((
                    digest,
                    Caller {
                        principal_id: k.principal_id.clone(),
                        roles: k.roles.clone(),
                        teams: k.teams.clone(),
                    },
                ))
            })
            .collect();
        Self { keys }
    }

    fn authenticate(&self, header: Option<&str>) -> Option<Caller> {
        let token = header?.strip_prefix("Bearer ")?.trim();
        if token.is_empty() || token.len() > 512 {
            return None;
        }
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let mut found = None;
        for (candidate, caller) in &self.keys {
            // Every key is compared, so timing does not reveal which matched.
            if candidate
                .iter()
                .zip(digest.iter())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0
            {
                found = Some(caller.clone());
            }
        }
        found
    }
}

// ---- errors ----

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }
    fn bad(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, "invalid", message)
    }
    fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", message)
    }
    fn not_found(what: &str) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", format!("No such {what}."))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            axum::Json(json!({"error": {"code": self.code, "message": self.message}})),
        )
            .into_response();
        if self.status == StatusCode::UNAUTHORIZED {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, "Bearer".parse().expect("static"));
        }
        response
    }
}

impl From<RecordError> for ApiError {
    fn from(e: RecordError) -> Self {
        match e {
            RecordError::Invalid(m) => Self::bad(m),
            RecordError::NotFound => Self::not_found("record"),
            RecordError::Forbidden(m) => Self::forbidden(m),
            RecordError::Conflict(m) => Self::new(StatusCode::CONFLICT, "conflict", m),
            RecordError::Store(_) | RecordError::Journal => Self::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "Tower's store or journal is unavailable.",
            ),
        }
    }
}

impl From<IntelError> for ApiError {
    fn from(e: IntelError) -> Self {
        let status = match e {
            IntelError::Off => StatusCode::NOT_IMPLEMENTED,
            IntelError::Refusal(_) | IntelError::Truncated | IntelError::Malformed(_) => {
                StatusCode::UNPROCESSABLE_ENTITY
            }
            IntelError::Http(_) | IntelError::Api { .. } => StatusCode::BAD_GATEWAY,
        };
        Self::new(status, "intelligence", e.to_string())
    }
}

type ApiResult = Result<Response, ApiError>;

#[allow(clippy::unnecessary_wraps)] // handlers return ApiResult throughout
fn ok(value: Value) -> ApiResult {
    Ok(axum::Json(value).into_response())
}

fn caller<S, L>(t: &Tower<S, L>, headers: &HeaderMap, role: &str) -> Result<Caller, ApiError> {
    let header = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok());
    let caller = t
        .callers
        .authenticate(header)
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "unauthorized", "Authentication required."))?;
    if !caller.has(role) {
        return Err(ApiError::forbidden(format!("This needs the {role} role.")));
    }
    Ok(caller)
}

/// A caller holding any of `roles`.
fn caller_any<S, L>(t: &Tower<S, L>, headers: &HeaderMap, roles: &[&str]) -> Result<Caller, ApiError> {
    let c = caller(t, headers, "viewer")?;
    if roles.iter().any(|r| c.has(r)) {
        Ok(c)
    } else {
        Err(ApiError::forbidden(format!(
            "This needs one of the roles: {}.",
            roles.join(", ")
        )))
    }
}

fn body<T: serde::de::DeserializeOwned>(bytes: &Bytes) -> Result<T, ApiError> {
    if bytes.len() > 512 * 1024 {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "too_large",
            "The body is too large.",
        ));
    }
    let value =
        contextos_contract::ingress::parse_strict(bytes, 512 * 1024).map_err(|e| ApiError::bad(e.to_string()))?;
    serde_json::from_value(value).map_err(|e| ApiError::bad(e.to_string()))
}

// ---- snapshot ----

struct Snapshot {
    views: Vec<AgentView>,
    findings: Vec<Finding>,
    anomalies: Vec<Anomaly>,
    guardrails: Value,
    now: String,
}

async fn snapshot<S: DocumentStore, L: AppendLog>(t: &Tower<S, L>) -> Result<Snapshot, ApiError> {
    let declarations = t.records.load("declarations").await?;
    let reviews = t.records.load("reviews").await?;
    let guardrails = t.records.load("guardrails").await?;
    let waivers = t.records.load("waivers").await?;
    let now = wall_clock();
    let fleet = t.fleet.read().await;
    let views = governance::views(&fleet, &declarations, &reviews);
    let findings = governance::findings(&fleet, &views, &guardrails, &waivers, &now);
    let anomalies = governance::anomalies(&fleet);
    Ok(Snapshot {
        views,
        findings,
        anomalies,
        guardrails,
        now,
    })
}

fn open(findings: &[Finding]) -> impl Iterator<Item = &Finding> {
    findings.iter().filter(|f| f.waiver.is_none())
}

fn agent_row(view: &AgentView, findings: &[Finding]) -> Value {
    let mine: Vec<&Finding> = open(findings)
        .filter(|f| f.agent.as_deref() == Some(&view.key))
        .collect();
    let count = |s: &str| mine.iter().filter(|f| f.severity == s).count();
    let d = view.declaration.as_ref();
    json!({
        "key": view.key, "agent_id": view.activity.agent_id, "agent_urn": view.activity.agent_urn,
        "owner": d.map(|d| d["owner"].clone()), "team": d.map(|d| d["team"].clone()),
        "business_unit": d.map(|d| d["business_unit"].clone()),
        "lifecycle": d.map_or(json!("undeclared"), |d| d["lifecycle"].clone()),
        "purpose": d.map(|d| d["purpose"].clone()),
        "reviewed": view.review.as_ref().is_some_and(|r| r["decision"] == "approved"),
        "required_profile": view.requirement.profile,
        "capabilities": view.graph.len(),
        "external": view.graph.iter().filter(|c| c.external()).count(),
        "irreversible": view.graph.iter().filter(|c| c.external() && c.irreversible()).count(),
        "models": view.activity.models, "sources": view.activity.sources,
        "runs": view.activity.runs, "last_seen": view.activity.last_seen,
        "findings": {"critical": count("critical"), "high": count("high"), "medium": count("medium"), "low": count("low")},
    })
}

// ---- read routes ----

async fn me<S, L>(State(t): State<Shared<S, L>>, headers: HeaderMap) -> ApiResult {
    let c = caller(&t, &headers, "viewer")?;
    ok(
        json!({"principal_id": c.principal_id, "roles": c.roles, "teams": c.teams,
        "intelligence": t.model.as_ref().map(|m| m.name().to_owned())}),
    )
}

async fn posture<S: DocumentStore, L: AppendLog>(State(t): State<Shared<S, L>>, headers: HeaderMap) -> ApiResult {
    caller(&t, &headers, "viewer")?;
    let snap = snapshot(&t).await?;
    let fleet = t.fleet.read().await;
    let n = snap.views.len();
    let count = |pred: &dyn Fn(&AgentView) -> bool| snap.views.iter().filter(|v| pred(v)).count();
    let mut by_profile: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_lifecycle: BTreeMap<String, usize> = BTreeMap::new();
    for v in &snap.views {
        *by_profile.entry(v.requirement.profile.clone()).or_default() += 1;
        let l = v
            .declaration
            .as_ref()
            .and_then(|d| d["lifecycle"].as_str())
            .unwrap_or("undeclared");
        *by_lifecycle.entry(l.to_owned()).or_default() += 1;
    }
    let mut severities = BTreeMap::new();
    let mut rules: BTreeMap<String, usize> = BTreeMap::new();
    for f in open(&snap.findings) {
        *severities.entry(f.severity).or_insert(0usize) += 1;
        *rules.entry(f.rule.clone()).or_default() += 1;
    }
    let sources: Vec<Value> = fleet
        .sources
        .values()
        .map(|s| {
            json!({"id": s.id, "verified_to": s.verified_to, "head": s.head,
        "broken": s.broken, "last_error": s.last_error, "last_sync": s.last_sync, "revoked": s.revoked.len()})
        })
        .collect();
    let mut riskiest: Vec<Value> = snap.views.iter().map(|v| agent_row(v, &snap.findings)).collect();
    riskiest.sort_by_key(|r| {
        std::cmp::Reverse((
            r["findings"]["critical"].as_u64().unwrap_or(0),
            r["findings"]["high"].as_u64().unwrap_or(0),
            r["irreversible"].as_u64().unwrap_or(0),
        ))
    });
    riskiest.truncate(8);
    let external = count(&|v| v.graph.iter().any(crate::authority::Capability::external));
    ok(json!({
        "now": snap.now,
        "agents": {"total": n, "declared": count(&|v| v.declaration.is_some()),
            "reviewed": count(&|v| v.review.as_ref().is_some_and(|r| r["decision"] == "approved")),
            "external_effects": external,
            "irreversible_external": count(&|v| v.graph.iter().any(|c| c.external() && c.irreversible())),
            "by_required_profile": by_profile, "by_lifecycle": by_lifecycle},
        "findings": {"by_severity": severities, "by_rule": rules, "waived": snap.findings.iter().filter(|f| f.waiver.is_some()).count()},
        "anomalies": snap.anomalies.len(),
        "riskiest": riskiest,
        "top_findings": open(&snap.findings).take(8).collect::<Vec<_>>(),
        "sources": sources,
        "unattributed": fleet.sources.values().map(|s| s.unattributed).sum::<u64>(),
        "guardrails": snap.guardrails.as_array().map_or(0, |g| g.iter().filter(|g| g["status"] == "active").count()),
        "intelligence": t.model.as_ref().map(|m| m.name().to_owned()),
    }))
}

#[derive(Deserialize)]
struct AgentQuery {
    #[serde(default)]
    query: Option<String>,
    #[serde(default)]
    profile: Option<String>,
    #[serde(default)]
    lifecycle: Option<String>,
}

fn matches_agent(row: &Value, q: &AgentQuery) -> bool {
    let text = q.query.as_deref().map(str::to_lowercase);
    text.is_none_or(|t| {
        ["key", "owner", "team", "purpose", "business_unit"]
            .iter()
            .any(|k| row[*k].as_str().is_some_and(|v| v.to_lowercase().contains(&t)))
    }) && q.profile.as_deref().is_none_or(|p| row["required_profile"] == p)
        && q.lifecycle.as_deref().is_none_or(|l| row["lifecycle"] == l)
}

async fn agents<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    Query(q): Query<AgentQuery>,
) -> ApiResult {
    caller(&t, &headers, "viewer")?;
    let snap = snapshot(&t).await?;
    let rows: Vec<Value> = snap
        .views
        .iter()
        .map(|v| agent_row(v, &snap.findings))
        .filter(|r| matches_agent(r, &q))
        .collect();
    ok(json!({"agents": rows}))
}

async fn agent<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> ApiResult {
    caller(&t, &headers, "viewer")?;
    let snap = snapshot(&t).await?;
    let view = snap
        .views
        .iter()
        .find(|v| v.key == key)
        .ok_or_else(|| ApiError::not_found("agent"))?;
    let fleet = t.fleet.read().await;
    let now = governance::fleet_hour(&fleet).max(crate::fleet::hour_index(&snap.now));
    let series: Vec<Value> = view
        .activity
        .series(now - 24 * 7 + 1, now + 1)
        .into_iter()
        .map(|(h, b)| json!({"hour": h, "runs": b.runs, "effects": b.effects, "applied": b.applied, "refused": b.refused, "unknown": b.unknown, "approvals": b.approvals}))
        .collect();
    let runs: Vec<Value> = fleet
        .recent_runs(|r| r.agent == key)
        .take(25)
        .map(|r| json!(r))
        .collect();
    ok(json!({
        "row": agent_row(view, &snap.findings),
        "facts": governance::facts(view),
        "requirement": view.requirement,
        "graph": view.graph,
        "digest": view.digest,
        "findings": snap.findings.iter().filter(|f| f.agent.as_deref() == Some(&key)).collect::<Vec<_>>(),
        "anomalies": snap.anomalies.iter().filter(|a| a.agent == key).collect::<Vec<_>>(),
        "series": series,
        "runs": runs,
        "can_revoke": t.sources.iter().any(|s| s.can_control()),
    }))
}

#[derive(Deserialize)]
struct FindingQuery {
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    agent: Option<String>,
    #[serde(default)]
    rule: Option<String>,
    #[serde(default)]
    include_waived: Option<bool>,
}

fn filter_findings<'a>(findings: &'a [Finding], q: &'a FindingQuery) -> impl Iterator<Item = &'a Finding> + 'a {
    findings.iter().filter(move |f| {
        (q.include_waived.unwrap_or(false) || f.waiver.is_none())
            && q.severity.as_deref().is_none_or(|s| f.severity == s)
            && q.agent.as_deref().is_none_or(|a| f.agent.as_deref() == Some(a))
            && q.rule.as_deref().is_none_or(|r| f.rule == r)
    })
}

async fn findings<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    Query(q): Query<FindingQuery>,
) -> ApiResult {
    caller(&t, &headers, "viewer")?;
    let snap = snapshot(&t).await?;
    ok(json!({"findings": filter_findings(&snap.findings, &q).collect::<Vec<_>>()}))
}

async fn anomalies<S: DocumentStore, L: AppendLog>(State(t): State<Shared<S, L>>, headers: HeaderMap) -> ApiResult {
    caller(&t, &headers, "viewer")?;
    let fleet = t.fleet.read().await;
    ok(json!({"anomalies": governance::anomalies(&fleet)}))
}

#[derive(Deserialize)]
struct RunQuery {
    #[serde(default)]
    agent: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    capability: Option<String>,
    #[serde(default)]
    refused: Option<bool>,
    #[serde(default)]
    limit: Option<usize>,
}

fn run_rows(fleet: &crate::fleet::Fleet, q: &RunQuery) -> Vec<Value> {
    fleet
        .recent_runs(|r| {
            q.agent.as_deref().is_none_or(|a| r.agent == a)
                && q.status.as_deref().is_none_or(|s| r.status == s)
                && q.capability.as_deref().is_none_or(|c| r.capabilities.contains(c))
                && (!q.refused.unwrap_or(false) || r.refused > 0)
        })
        .take(q.limit.unwrap_or(100).min(500))
        .map(|r| json!(r))
        .collect()
}

async fn runs<S, L>(State(t): State<Shared<S, L>>, headers: HeaderMap, Query(q): Query<RunQuery>) -> ApiResult {
    caller(&t, &headers, "viewer")?;
    let fleet = t.fleet.read().await;
    ok(json!({"runs": run_rows(&fleet, &q)}))
}

async fn fetch_evidence<S: DocumentStore, L: AppendLog>(
    t: &Tower<S, L>,
    c: &Caller,
    source: &str,
    run: &str,
) -> Result<Value, ApiError> {
    let src = t
        .sources
        .iter()
        .find(|s| s.id() == source)
        .ok_or_else(|| ApiError::not_found("source"))?;
    // Evidence leaves the runtime only on request, and every request is journalled.
    t.records
        .note(
            "evidence_accessed",
            json!({"source": source, "run_id": run, "by": c.principal_id}),
            &wall_clock(),
        )
        .await?;
    src.evidence(run)
        .await
        .map_err(|e| ApiError::new(StatusCode::BAD_GATEWAY, "runtime", e.to_string()))
}

async fn evidence<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    Path((source, run)): Path<(String, String)>,
) -> ApiResult {
    let c = caller(&t, &headers, "viewer")?;
    ok(fetch_evidence(&t, &c, &source, &run).await?)
}

async fn changes<S, L>(State(t): State<Shared<S, L>>, headers: HeaderMap) -> ApiResult {
    caller(&t, &headers, "viewer")?;
    let fleet = t.fleet.read().await;
    ok(json!({"changes": fleet.changes.iter().rev().take(200).collect::<Vec<_>>()}))
}

async fn sources<S, L>(State(t): State<Shared<S, L>>, headers: HeaderMap) -> ApiResult {
    caller(&t, &headers, "viewer")?;
    let fleet = t.fleet.read().await;
    let list: Vec<Value> = t
        .sources
        .iter()
        .map(|s| {
            let state = fleet.sources.get(s.id());
            let d = state.map(|s| &s.deployment);
            json!({"id": s.id(), "url": s.config.url, "business_unit": s.config.business_unit, "region": s.config.region,
                "environment": s.config.environment, "can_revoke": s.can_control(),
                "state": state, "mode": d.map(|d| d["mode"].clone()), "tenant": d.map(|d| d["caller"]["tenant_id"].clone()),
                "packs": d.map(|d| d["packs"].clone()), "guards": d.map(|d| d["guards"].clone()),
                "controls": d.map(|d| d["support"]["supported_controls"].clone())})
        })
        .collect();
    ok(json!({"sources": list}))
}

// ---- declarations, reviews ----

async fn declare<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    Path(key): Path<String>,
    bytes: Bytes,
) -> ApiResult {
    let c = caller_any(&t, &headers, &["owner", "risk"])?;
    let declaration: Declaration = body(&bytes)?;
    declaration.check().map_err(ApiError::bad)?;
    let existing = t.records.load("declarations").await?;
    let team_ok = |team: &str| c.teams.iter().any(|t| t == team);
    if !c.has("risk") {
        let current_team = existing[&key]["team"].as_str();
        if !team_ok(&declaration.team) || current_team.is_some_and(|ct| !team_ok(ct)) {
            return Err(ApiError::forbidden("Owners declare agents of their own teams."));
        }
    }
    let now = wall_clock();
    let mut record = serde_json::to_value(&declaration).unwrap_or(Value::Null);
    record["declared_by"] = json!(c.principal_id);
    record["declared_at"] = json!(now);
    let stored = record.clone();
    t.records
        .change(
            "declarations",
            "agent_declared",
            json!({"agent": key, "declaration": record, "by": c.principal_id}),
            &now,
            |items| {
                object(items).insert(key.clone(), stored.clone());
                Ok(())
            },
        )
        .await?;
    ok(record)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewBody {
    decision: String,
    notes: String,
    #[serde(default)]
    conditions: Vec<String>,
    #[serde(default)]
    valid_days: Option<u32>,
}

async fn review<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    Path(key): Path<String>,
    bytes: Bytes,
) -> ApiResult {
    let c = caller(&t, &headers, "risk")?;
    let request: ReviewBody = body(&bytes)?;
    if !matches!(request.decision.as_str(), "approved" | "rejected" | "changes_requested")
        || request.notes.trim().is_empty()
    {
        return Err(ApiError::bad(
            "decision must be approved, rejected or changes_requested, with notes",
        ));
    }
    let snap = snapshot(&t).await?;
    let view = snap
        .views
        .iter()
        .find(|v| v.key == key)
        .ok_or_else(|| ApiError::not_found("agent"))?;
    if view
        .declaration
        .as_ref()
        .is_some_and(|d| d["declared_by"] == c.principal_id.as_str() || d["owner"] == c.principal_id.as_str())
    {
        return Err(ApiError::forbidden("An agent's owner or declarer cannot review it."));
    }
    if request.decision == "approved" && view.declaration.is_none() {
        return Err(ApiError::bad("Declare an owner before approving the agent."));
    }
    let now = wall_clock();
    let days = request.valid_days.unwrap_or(365).clamp(1, 730);
    let expires = add_days(&now, days);
    let record = json!({"decision": request.decision, "notes": request.notes, "conditions": request.conditions,
        "capabilities": view.graph.iter().map(|c| c.id.clone()).collect::<Vec<_>>(), "graph_digest": view.digest,
        "required_profile": view.requirement.profile, "reviewed_by": c.principal_id, "reviewed_at": now, "expires_at": expires});
    let stored = record.clone();
    t.records
        .change(
            "reviews",
            "agent_reviewed",
            json!({"agent": key, "review": record}),
            &now,
            |items| {
                object(items).insert(key.clone(), stored.clone());
                Ok(())
            },
        )
        .await?;
    ok(record)
}

fn add_days(now: &str, days: u32) -> String {
    let micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_micros()).unwrap_or(0))
        + i64::from(days) * 86_400_000_000;
    let _ = now;
    contextos_contract::validation::format_unix_micros(micros)
}

// ---- guardrails ----

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GuardrailBody {
    title: String,
    #[serde(default)]
    description: String,
    severity: String,
    rule: Value,
    #[serde(default)]
    remediation: String,
    /// `manual` or `ai_draft`.
    #[serde(default)]
    origin: Option<String>,
    #[serde(default)]
    intent: Option<String>,
}

async fn all_facts<S: DocumentStore, L: AppendLog>(t: &Tower<S, L>) -> Result<Vec<(String, Value)>, ApiError> {
    let snap = snapshot(t).await?;
    Ok(snap
        .views
        .iter()
        .map(|v| (v.key.clone(), governance::facts(v)))
        .collect())
}

fn impact(rule: &Value, facts: &[(String, Value)]) -> Value {
    let mut violating = Vec::new();
    let mut errors = Vec::new();
    for (key, f) in facts {
        match contextos_policy::jsonlogic::apply(rule, f) {
            Ok(v) if v.truthy() => violating.push(key.clone()),
            Ok(_) => {}
            Err(e) => errors.push(json!({"agent": key, "error": e.to_string()})),
        }
    }
    json!({"evaluated": facts.len(), "violating": violating, "errors": errors})
}

async fn guardrails<S: DocumentStore, L: AppendLog>(State(t): State<Shared<S, L>>, headers: HeaderMap) -> ApiResult {
    caller(&t, &headers, "viewer")?;
    let list = t.records.load("guardrails").await?;
    let facts = all_facts(&t).await?;
    let annotated: Vec<Value> = list
        .as_array()
        .into_iter()
        .flatten()
        .map(|g| {
            let mut g = g.clone();
            g["impact"] = impact(&g["rule"], &facts);
            g
        })
        .collect();
    ok(json!({"guardrails": annotated}))
}

async fn preview<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    bytes: Bytes,
) -> ApiResult {
    caller(&t, &headers, "risk")?;
    let request: Value = body(&bytes)?;
    let facts = all_facts(&t).await?;
    ok(impact(&request["rule"], &facts))
}

async fn create_guardrail<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    bytes: Bytes,
) -> ApiResult {
    let c = caller(&t, &headers, "risk")?;
    let g: GuardrailBody = body(&bytes)?;
    if g.title.trim().is_empty() || !governance::SEVERITIES.contains(&g.severity.as_str()) || !g.rule.is_object() {
        return Err(ApiError::bad(
            "title, severity (critical|high|medium|low) and a JsonLogic rule object are required",
        ));
    }
    let facts = all_facts(&t).await?;
    let errors = impact(&g.rule, &facts)["errors"].clone();
    if errors.as_array().is_some_and(|e| !e.is_empty()) {
        return Err(ApiError::bad(format!("The rule fails to evaluate: {errors}")));
    }
    let now = wall_clock();
    let id = uuid::Uuid::now_v7().simple().to_string()[..12].to_owned();
    let record = json!({"id": id, "title": g.title, "description": g.description, "severity": g.severity, "rule": g.rule,
        "remediation": g.remediation, "origin": g.origin.unwrap_or_else(|| "manual".into()), "intent": g.intent,
        "status": "draft", "created_by": c.principal_id, "created_at": now});
    let stored = record.clone();
    t.records
        .change(
            "guardrails",
            "guardrail_drafted",
            json!({"guardrail": record}),
            &now,
            |items| {
                array(items).push(stored.clone());
                Ok(())
            },
        )
        .await?;
    Ok((StatusCode::CREATED, axum::Json(record)).into_response())
}

async fn guardrail_status<S: DocumentStore, L: AppendLog>(
    t: &Tower<S, L>,
    c: &Caller,
    id: &str,
    to: &'static str,
) -> ApiResult {
    let now = wall_clock();
    let by = c.principal_id.clone();
    let result = t
        .records
        .change(
            "guardrails",
            if to == "active" {
                "guardrail_activated"
            } else {
                "guardrail_retired"
            },
            json!({"id": id, "by": by}),
            &now,
            |items| {
                let g = array(items)
                    .iter_mut()
                    .find(|g| g["id"] == id)
                    .ok_or(RecordError::NotFound)?;
                if to == "active" {
                    if g["status"] != "draft" {
                        return Err(RecordError::Conflict("only a draft can be activated"));
                    }
                    if g["created_by"] == by.as_str() {
                        return Err(RecordError::Forbidden(
                            "A guardrail is activated by someone other than its author.",
                        ));
                    }
                    g["activated_by"] = json!(by);
                    g["activated_at"] = json!(now);
                } else {
                    g["retired_by"] = json!(by);
                    g["retired_at"] = json!(now);
                }
                g["status"] = json!(to);
                Ok(g.clone())
            },
        )
        .await?;
    ok(result)
}

async fn activate<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    let c = caller(&t, &headers, "risk")?;
    guardrail_status(&t, &c, &id, "active").await
}

async fn retire<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    let c = caller(&t, &headers, "risk")?;
    guardrail_status(&t, &c, &id, "retired").await
}

// ---- waivers ----

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WaiverBody {
    rule: String,
    agent: String,
    reason: String,
    days: u32,
}

async fn waivers<S: DocumentStore, L: AppendLog>(State(t): State<Shared<S, L>>, headers: HeaderMap) -> ApiResult {
    caller(&t, &headers, "viewer")?;
    let now = wall_clock();
    let list: Vec<Value> = t
        .records
        .load("waivers")
        .await?
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|mut w| {
            if w["status"] == "approved" && w["expires_at"].as_str().is_some_and(|e| e <= now.as_str()) {
                w["status"] = json!("expired");
            }
            w
        })
        .collect();
    ok(json!({"waivers": list}))
}

async fn request_waiver<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    bytes: Bytes,
) -> ApiResult {
    let c = caller_any(&t, &headers, &["owner", "risk"])?;
    let w: WaiverBody = body(&bytes)?;
    if w.reason.trim().len() < 10 || !(1..=180).contains(&w.days) {
        return Err(ApiError::bad(
            "a reason (at least 10 characters) and 1 to 180 days are required",
        ));
    }
    let now = wall_clock();
    let id = uuid::Uuid::now_v7().simple().to_string()[..12].to_owned();
    let record = json!({"id": id, "rule": w.rule, "agent": w.agent, "reason": w.reason, "days": w.days, "status": "requested",
        "requested_by": c.principal_id, "requested_at": now});
    let stored = record.clone();
    t.records
        .change(
            "waivers",
            "waiver_requested",
            json!({"waiver": record}),
            &now,
            |items| {
                array(items).push(stored.clone());
                Ok(())
            },
        )
        .await?;
    Ok((StatusCode::CREATED, axum::Json(record)).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecideBody {
    approve: bool,
    reason: String,
}

async fn decide_waiver<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    bytes: Bytes,
) -> ApiResult {
    let c = caller(&t, &headers, "risk")?;
    let d: DecideBody = body(&bytes)?;
    if d.reason.trim().is_empty() {
        return Err(ApiError::bad("a reason is required"));
    }
    let now = wall_clock();
    let by = c.principal_id.clone();
    let result = t
        .records
        .change(
            "waivers",
            "waiver_decided",
            json!({"id": id, "approve": d.approve, "reason": d.reason, "by": by}),
            &now,
            |items| {
                let w = array(items)
                    .iter_mut()
                    .find(|w| w["id"] == id.as_str())
                    .ok_or(RecordError::NotFound)?;
                if w["status"] != "requested" {
                    return Err(RecordError::Conflict("the waiver was already decided"));
                }
                if w["requested_by"] == by.as_str() {
                    return Err(RecordError::Forbidden(
                        "A waiver is decided by someone other than its requester.",
                    ));
                }
                w["status"] = json!(if d.approve { "approved" } else { "rejected" });
                w["decided_by"] = json!(by);
                w["decided_at"] = json!(now);
                w["decision_reason"] = json!(d.reason);
                if d.approve {
                    w["expires_at"] = json!(add_days(
                        &now,
                        u32::try_from(w["days"].as_u64().unwrap_or(30)).unwrap_or(30)
                    ));
                }
                Ok(w.clone())
            },
        )
        .await?;
    ok(result)
}

// ---- fleet kill switch ----

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FleetRevocation {
    /// `agent`, `capability`, `pack`, `adapter` or `principal`.
    kind: String,
    target: String,
    reason: String,
    /// Sources to act on; all that hold a control key when omitted.
    #[serde(default)]
    sources: Option<Vec<String>>,
}

async fn fleet_revocation<S: DocumentStore, L: AppendLog>(
    t: &Tower<S, L>,
    c: &Caller,
    bytes: &Bytes,
    revoke: bool,
) -> ApiResult {
    let r: FleetRevocation = body(bytes)?;
    if !matches!(
        r.kind.as_str(),
        "agent" | "capability" | "pack" | "adapter" | "principal"
    ) || r.target.is_empty()
        || r.reason.trim().is_empty()
    {
        return Err(ApiError::bad(
            "kind (agent|capability|pack|adapter|principal), target and reason are required",
        ));
    }
    let targets: Vec<&Arc<crate::source::Source>> = t
        .sources
        .iter()
        .filter(|s| s.can_control() && r.sources.as_ref().is_none_or(|ids| ids.iter().any(|i| i == s.id())))
        .collect();
    if targets.is_empty() {
        return Err(ApiError::bad("No selected source holds a control key."));
    }
    let now = wall_clock();
    let reason = format!("{} (via Tower, {})", r.reason, c.principal_id);
    // Journalled before any runtime is touched, so an interrupted action is still on record.
    t.records
        .note(
            if revoke { "fleet_revoked" } else { "fleet_restored" },
            json!({"kind": r.kind, "target": r.target, "reason": r.reason, "by": c.principal_id,
                "sources": targets.iter().map(|s| s.id()).collect::<Vec<_>>()}),
            &now,
        )
        .await?;
    let mut results = Vec::new();
    for s in targets {
        let outcome = s.revocation(revoke, &r.kind, &r.target, &reason).await;
        results.push(match outcome {
            Ok(_) => json!({"source": s.id(), "ok": true}),
            Err(e) => json!({"source": s.id(), "ok": false, "error": e.to_string()}),
        });
    }
    ok(json!({"results": results}))
}

async fn revoke<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    bytes: Bytes,
) -> ApiResult {
    let c = caller(&t, &headers, "operator")?;
    fleet_revocation(&t, &c, &bytes, true).await
}

async fn restore<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    bytes: Bytes,
) -> ApiResult {
    let c = caller(&t, &headers, "operator")?;
    fleet_revocation(&t, &c, &bytes, false).await
}

// ---- intelligence ----

fn model<S, L>(t: &Tower<S, L>) -> Result<&dyn intel::Model, ApiError> {
    t.model.as_deref().ok_or_else(|| ApiError::from(IntelError::Off))
}

async fn journal_use<S: DocumentStore, L: AppendLog>(
    t: &Tower<S, L>,
    c: &Caller,
    job: &str,
    input: &str,
    output: &Value,
) -> Result<(), ApiError> {
    let digest = |s: &str| contextos_contract::canonical::sha256_text(s);
    t.records
        .note(
            "intelligence_used",
            json!({"job": job, "by": c.principal_id, "model": output["model"],
            "input_digest": digest(input), "output_digest": digest(&output.to_string()), "usage": output["usage"]}),
            &wall_clock(),
        )
        .await
        .map_err(ApiError::from)
}

/// The analyst's read-only tools, answered from one snapshot.
struct Host<'a, S, L> {
    tower: &'a Tower<S, L>,
    snap: Snapshot,
    runs: Vec<Value>,
}

#[async_trait::async_trait]
impl<S: DocumentStore + 'static, L: AppendLog + 'static> jobs::Tools for Host<'_, S, L> {
    async fn call(&self, name: &str, input: &Value) -> Value {
        let s = |k: &str| input[k].as_str().map(str::to_owned);
        match name {
            "fleet_summary" => {
                let fleet = self.tower.fleet.read().await;
                let mut sev = BTreeMap::new();
                for f in open(&self.snap.findings) {
                    *sev.entry(f.severity).or_insert(0usize) += 1;
                }
                json!({"agents": self.snap.views.len(), "findings": sev, "anomalies": self.snap.anomalies,
                    "sources": fleet.sources.values().map(|s| json!({"id": s.id, "verified_to": s.verified_to, "broken": s.broken})).collect::<Vec<_>>()})
            }
            "list_agents" => {
                let q = AgentQuery {
                    query: s("query"),
                    profile: s("required_profile"),
                    lifecycle: s("lifecycle"),
                };
                json!(
                    self.snap
                        .views
                        .iter()
                        .map(|v| agent_row(v, &self.snap.findings))
                        .filter(|r| matches_agent(r, &q))
                        .take(100)
                        .collect::<Vec<_>>()
                )
            }
            "get_agent" => match self.snap.views.iter().find(|v| Some(&v.key) == s("agent").as_ref()) {
                Some(v) => json!({"facts": governance::facts(v), "requirement": v.requirement,
                    "findings": self.snap.findings.iter().filter(|f| f.agent.as_deref() == Some(&v.key)).collect::<Vec<_>>(),
                    "anomalies": self.snap.anomalies.iter().filter(|a| a.agent == v.key).collect::<Vec<_>>()}),
                None => json!({"error": "no such agent"}),
            },
            "list_findings" => {
                let q = FindingQuery {
                    severity: s("severity"),
                    agent: s("agent"),
                    rule: s("rule"),
                    include_waived: Some(false),
                };
                json!(filter_findings(&self.snap.findings, &q).take(100).collect::<Vec<_>>())
            }
            "search_runs" => {
                let q = RunQuery {
                    agent: s("agent"),
                    status: s("status"),
                    capability: s("capability"),
                    refused: input["refused_only"].as_bool(),
                    limit: input["limit"]
                        .as_u64()
                        .map(|n| usize::try_from(n.min(50)).unwrap_or(50)),
                };
                let fleet = self.tower.fleet.read().await;
                json!(run_rows(&fleet, &q))
            }
            "recent_changes" => {
                let fleet = self.tower.fleet.read().await;
                let n = usize::try_from(input["limit"].as_u64().unwrap_or(30).min(100)).unwrap_or(30);
                json!(fleet.changes.iter().rev().take(n).collect::<Vec<_>>())
            }
            "list_guardrails" => self.snap.guardrails.clone(),
            _ => json!({"error": "unknown tool"}),
        }
    }

    fn exists(&self, kind: &str, id: &str) -> bool {
        match kind {
            "agent" => self.snap.views.iter().any(|v| v.key == id),
            "finding" => self.snap.findings.iter().any(|f| f.id == id),
            "run" => self.runs.iter().any(|r| {
                format!(
                    "{}/{}",
                    r["source"].as_str().unwrap_or(""),
                    r["run_id"].as_str().unwrap_or("")
                ) == id
            }),
            _ => false,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AskBody {
    question: String,
}

async fn ask<S: DocumentStore + 'static, L: AppendLog + 'static>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    bytes: Bytes,
) -> ApiResult {
    let c = caller(&t, &headers, "viewer")?;
    let request: AskBody = body(&bytes)?;
    if request.question.trim().is_empty() || request.question.len() > 4000 {
        return Err(ApiError::bad("a question of up to 4000 characters is required"));
    }
    let m = model(&t)?;
    let snap = snapshot(&t).await?;
    let runs = run_rows(
        &*t.fleet.read().await,
        &RunQuery {
            agent: None,
            status: None,
            capability: None,
            refused: None,
            limit: Some(500),
        },
    );
    let host = Host { tower: &t, snap, runs };
    let out = jobs::ask(m, &host, &request.question, t.config.intelligence.max_turns).await?;
    journal_use(&t, &c, "ask", &request.question, &out).await?;
    ok(out)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftBody {
    intent: String,
}

async fn draft_guardrail<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    bytes: Bytes,
) -> ApiResult {
    let c = caller(&t, &headers, "risk")?;
    let request: DraftBody = body(&bytes)?;
    if request.intent.trim().len() < 10 || request.intent.len() > 2000 {
        return Err(ApiError::bad("describe the intent in 10 to 2000 characters"));
    }
    let m = model(&t)?;
    let facts = all_facts(&t).await?;
    let example = facts
        .iter()
        .max_by_key(|(_, f)| f["capabilities"].as_array().map_or(0, Vec::len))
        .map_or_else(|| json!({}), |(_, f)| f.clone());
    let out = jobs::draft_guardrail(m, &request.intent, &facts, &example).await?;
    journal_use(&t, &c, "draft_guardrail", &request.intent, &out).await?;
    ok(out)
}

async fn assess<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> ApiResult {
    let c = caller_any(&t, &headers, &["owner", "risk"])?;
    let m = model(&t)?;
    let snap = snapshot(&t).await?;
    let view = snap
        .views
        .iter()
        .find(|v| v.key == key)
        .ok_or_else(|| ApiError::not_found("agent"))?;
    let findings: Vec<&Finding> = snap
        .findings
        .iter()
        .filter(|f| f.agent.as_deref() == Some(&key))
        .collect();
    let out = jobs::assess_agent(m, &governance::facts(view), &json!(findings)).await?;
    journal_use(&t, &c, "assess_agent", &key, &out).await?;
    ok(out)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BriefBody {
    agent: String,
    metric: String,
}

async fn brief<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    bytes: Bytes,
) -> ApiResult {
    let c = caller_any(&t, &headers, &["operator", "risk"])?;
    let request: BriefBody = body(&bytes)?;
    let m = model(&t)?;
    let snap = snapshot(&t).await?;
    let anomaly = snap
        .anomalies
        .iter()
        .find(|a| a.agent == request.agent && a.metric == request.metric)
        .ok_or_else(|| ApiError::not_found("anomaly"))?;
    let view = snap
        .views
        .iter()
        .find(|v| v.key == request.agent)
        .ok_or_else(|| ApiError::not_found("agent"))?;
    let runs = run_rows(
        &*t.fleet.read().await,
        &RunQuery {
            agent: Some(request.agent.clone()),
            status: None,
            capability: None,
            refused: None,
            limit: Some(20),
        },
    );
    let out = jobs::brief_anomaly(m, &json!(anomaly), &governance::facts(view), &json!(runs)).await?;
    journal_use(
        &t,
        &c,
        "brief_anomaly",
        &format!("{}:{}", request.agent, request.metric),
        &out,
    )
    .await?;
    ok(out)
}

async fn explain<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    Path((source, run)): Path<(String, String)>,
) -> ApiResult {
    let c = caller(&t, &headers, "viewer")?;
    let m = model(&t)?;
    let summary = t
        .fleet
        .read()
        .await
        .run(&source, &run)
        .map_or(Value::Null, |r| json!(r));
    let evidence = fetch_evidence(&t, &c, &source, &run).await?;
    let out = jobs::explain_run(m, &summary, &evidence).await?;
    journal_use(&t, &c, "explain_run", &format!("{source}/{run}"), &out).await?;
    ok(out)
}

// ---- journal ----

#[derive(Deserialize)]
struct JournalQuery {
    #[serde(default)]
    from: Option<u64>,
    #[serde(default)]
    limit: Option<usize>,
}

async fn journal<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    Query(q): Query<JournalQuery>,
) -> ApiResult {
    caller(&t, &headers, "viewer")?;
    let log = t.records.journal().log();
    let head = log
        .head(crate::records::NAMESPACE)
        .await
        .ok()
        .flatten()
        .map_or(0, |r| r.sequence);
    let limit = q.limit.unwrap_or(100).clamp(1, 500);
    let from = q.from.unwrap_or_else(|| head.saturating_sub(limit as u64 - 1).max(1));
    let rows = log.range(crate::records::NAMESPACE, from, limit).await.map_err(|_| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "The journal is unavailable.",
        )
    })?;
    ok(json!({"entries": rows.into_iter().map(|r| r.body).collect::<Vec<_>>(), "head": head}))
}

async fn journal_keys<S, L>(State(t): State<Shared<S, L>>) -> ApiResult {
    ok(t.journal_keys.clone())
}

pub fn router<S, L>(tower: Arc<Tower<S, L>>) -> Router
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let console = tower.console.clone().map_or_else(Router::new, crate::console::routes);
    Router::new()
        .merge(console)
        .route("/healthz", get(|| async { "ok" }))
        .route("/api/me", get(me::<S, L>))
        .route("/api/posture", get(posture::<S, L>))
        .route("/api/agents", get(agents::<S, L>))
        .route("/api/agents/{key}", get(agent::<S, L>))
        .route("/api/agents/{key}/declaration", put(declare::<S, L>))
        .route("/api/agents/{key}/review", post(review::<S, L>))
        .route("/api/agents/{key}/assess", post(assess::<S, L>))
        .route("/api/findings", get(findings::<S, L>))
        .route("/api/anomalies", get(anomalies::<S, L>))
        .route("/api/anomalies/brief", post(brief::<S, L>))
        .route("/api/runs", get(runs::<S, L>))
        .route("/api/runs/{source}/{run}/evidence", get(evidence::<S, L>))
        .route("/api/runs/{source}/{run}/explain", post(explain::<S, L>))
        .route("/api/changes", get(changes::<S, L>))
        .route("/api/sources", get(sources::<S, L>))
        .route(
            "/api/guardrails",
            get(guardrails::<S, L>).post(create_guardrail::<S, L>),
        )
        .route("/api/guardrails/preview", post(preview::<S, L>))
        .route("/api/guardrails/draft", post(draft_guardrail::<S, L>))
        .route("/api/guardrails/{id}/activate", post(activate::<S, L>))
        .route("/api/guardrails/{id}/retire", post(retire::<S, L>))
        .route("/api/waivers", get(waivers::<S, L>).post(request_waiver::<S, L>))
        .route("/api/waivers/{id}/decide", post(decide_waiver::<S, L>))
        .route("/api/fleet/revoke", post(revoke::<S, L>))
        .route("/api/fleet/restore", post(restore::<S, L>))
        .route("/api/ask", post(ask::<S, L>))
        .route("/api/journal", get(journal::<S, L>))
        .route("/api/journal/keys", get(journal_keys::<S, L>))
        .layer(tower_http::set_header::SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("no-store"),
        ))
        .layer(tower_http::set_header::SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            header::HeaderValue::from_static("nosniff"),
        ))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(1024 * 1024))
        .layer(tower_http::catch_panic::CatchPanicLayer::new())
        .with_state(tower)
}
