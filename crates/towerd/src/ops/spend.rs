//! Model spend (viewer): what each agent, team and model spends on model calls, how
//! much of it a metering gateway measured, and what the budget could not cover or
//! refused. Folded by [`crate::spend`] from the runtimes' verified audit chains.
//!
//! | Route | Role | Purpose |
//! |---|---|---|
//! | `GET /api/spend?hours=24\|168\|720&group=agent\|team\|model` | viewer | totals, ranked rows, series and refusals over a window |
//! | `GET /api/agents/{key}/spend?hours=…` | viewer | one agent's spend: window, models, refusals, series |

use std::collections::BTreeMap;

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::get;
use contextos_store::{AppendLog, DocumentStore};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::{ApiError, ApiResult, Shared, caller, ok};
use crate::collector::wall_clock;
use crate::fleet::hour_index;
use crate::spend::{AgentSpend, ModelUsage, Usage};

/// Rows returned at most; the rest are summarised in the totals.
const MAX_ROWS: usize = 500;
const UNDECLARED_TEAM: &str = "(undeclared)";

pub fn routes<S, L>() -> Router<Shared<S, L>>
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    Router::new()
        .route("/api/spend", get(spend::<S, L>))
        .route("/api/agents/{key}/spend", get(agent_spend::<S, L>))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SpendQuery {
    #[serde(default)]
    hours: Option<i64>,
    #[serde(default)]
    group: Option<String>,
}

/// The window's hours `[from, to)` ending with the current hour, and its bucket size.
fn window(hours: Option<i64>) -> Result<(i64, i64, i64), ApiError> {
    let hours = hours.unwrap_or(24);
    if ![24, 168, 720].contains(&hours) {
        return Err(ApiError::bad("hours must be 24, 168 or 720"));
    }
    let to = hour_index(&wall_clock()) + 1;
    Ok((to - hours, to, if hours > 168 { 24 } else { 1 }))
}

fn usage_json(u: &Usage) -> Value {
    let mut v = serde_json::to_value(u).unwrap_or_default();
    v["unsettled_claims"] = json!(u.unsettled_claims());
    v
}

/// Hourly (or daily) totals over the window, zeros filled in.
fn series<'a>(spends: impl Iterator<Item = &'a AgentSpend>, from: i64, to: i64, bucket: i64) -> Vec<Value> {
    let mut sums: BTreeMap<i64, Usage> = (from..to)
        .step_by(usize::try_from(bucket).unwrap_or(1))
        .map(|h| (h, Usage::default()))
        .collect();
    for s in spends {
        for (h, u) in s.hours.range(from..to) {
            let start = from + (h - from) / bucket * bucket;
            sums.entry(start).or_default().add(u);
        }
    }
    sums.into_iter()
        .map(|(hour, u)| {
            json!({"hour": hour, "tokens": u.tokens, "cost_units": u.cost_units, "verified_tokens": u.verified_tokens,
                "self_reported_tokens": u.self_reported_tokens, "uncovered_tokens": u.uncovered_tokens,
                "refused": u.refused})
        })
        .collect()
}

fn rank(rows: &mut [Value]) {
    rows.sort_by(|a, b| {
        let key = |v: &Value| {
            (
                v["usage"]["cost_units"].as_u64().unwrap_or(0),
                v["usage"]["tokens"].as_u64().unwrap_or(0),
            )
        };
        key(b)
            .cmp(&key(a))
            .then_with(|| a["key"].as_str().cmp(&b["key"].as_str()))
    });
}

async fn spend<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    Query(q): Query<SpendQuery>,
) -> ApiResult {
    caller(&t, &headers, "viewer")?;
    let (from, to, bucket) = window(q.hours)?;
    let group = q.group.as_deref().unwrap_or("agent");
    if !matches!(group, "agent" | "team" | "model") {
        return Err(ApiError::bad("group must be agent, team or model"));
    }
    let declarations = t.records.load("declarations").await?;
    let fleet = t.fleet.read().await;
    let team = |key: &str| {
        declarations[key]["team"]
            .as_str()
            .filter(|s| !s.is_empty())
            .unwrap_or(UNDECLARED_TEAM)
            .to_owned()
    };

    let mut totals = Usage::default();
    let mut refusals: BTreeMap<String, u64> = BTreeMap::new();
    let mut by_agent: Vec<(&String, &AgentSpend, Usage)> = Vec::new();
    for (key, s) in &fleet.spend {
        let u = s.window(from, to);
        if u == Usage::default() {
            continue;
        }
        totals.add(&u);
        for (r, n) in s.refusals_in(from, to) {
            *refusals.entry(r).or_default() += n;
        }
        by_agent.push((key, s, u));
    }

    let mut rows: Vec<Value> = match group {
        "agent" => by_agent
            .iter()
            .map(|(key, s, u)| {
                let a = fleet.agents.get(*key);
                json!({"key": key, "agent_id": a.map(|a| a.agent_id.clone()), "team": team(key),
                    "owner": declarations[key.as_str()]["owner"], "usage": usage_json(u),
                    "models": s.models_in(from, to).into_keys().collect::<Vec<_>>()})
            })
            .collect(),
        "team" => {
            let mut teams: BTreeMap<String, (Usage, u64)> = BTreeMap::new();
            for (key, _, u) in &by_agent {
                let entry = teams.entry(team(key)).or_default();
                entry.0.add(u);
                entry.1 += 1;
            }
            teams
                .into_iter()
                .map(|(key, (u, agents))| json!({"key": key, "agents": agents, "usage": usage_json(&u)}))
                .collect()
        }
        _ => {
            let mut models: BTreeMap<String, (ModelUsage, u64)> = BTreeMap::new();
            for (_, s, _) in &by_agent {
                for (model, m) in s.models_in(from, to) {
                    let entry = models.entry(model).or_default();
                    entry.0.add(&m);
                    entry.1 += 1;
                }
            }
            models
                .into_iter()
                .map(|(key, (m, agents))| json!({"key": key, "agents": agents, "usage": m}))
                .collect()
        }
    };
    rank(&mut rows);
    let total_rows = rows.len();
    rows.truncate(MAX_ROWS);
    let series = series(by_agent.iter().map(|(_, s, _)| *s), from, to, bucket);
    ok(
        json!({"from_hour": from, "to_hour": to, "bucket_hours": bucket, "group": group,
        "totals": usage_json(&totals), "rows": rows, "total_rows": total_rows, "series": series,
        "refusals": refusals}),
    )
}

async fn agent_spend<S: DocumentStore, L: AppendLog>(
    State(t): State<Shared<S, L>>,
    headers: HeaderMap,
    Path(key): Path<String>,
    Query(q): Query<SpendQuery>,
) -> ApiResult {
    caller(&t, &headers, "viewer")?;
    if q.group.is_some() {
        return Err(ApiError::bad("group does not apply to one agent"));
    }
    let (from, to, bucket) = window(q.hours)?;
    let fleet = t.fleet.read().await;
    if !fleet.agents.contains_key(&key) {
        return Err(ApiError::not_found("agent"));
    }
    let empty = AgentSpend::default();
    let s = fleet.spend.get(&key).unwrap_or(&empty);
    let mut models: Vec<Value> = s
        .models_in(from, to)
        .into_iter()
        .map(|(model, m)| json!({"key": model, "usage": m}))
        .collect();
    rank(&mut models);
    ok(
        json!({"key": key, "from_hour": from, "to_hour": to, "bucket_hours": bucket,
        "usage": usage_json(&s.window(from, to)), "since_start": usage_json(&s.total),
        "models": models, "refusals": s.refusals_in(from, to),
        "series": series(std::iter::once(s), from, to, bucket)}),
    )
}
