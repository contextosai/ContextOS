//! Chargeback: model spend grouped for whoever pays, from the fleet model's spend.
//!
//! Tower's `GET /api/spend` and `ctx chargeback` (offline, from a verified audit export)
//! both build their rows here, so the same entries give the same rows. A row's `usage`
//! keeps verified (measured by a metering gateway), self-reported and uncovered usage
//! apart: a bill built on self-reported usage is a bill built on the agent's word.
//!
//! Groups: `agent`, `team`, `business_unit` and `owner` (from Tower's declarations;
//! `(undeclared)` when missing), `tenant` (an agent seen in several tenants is counted
//! under `(several tenants)` rather than split by guess), and `model`.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde_json::{Value, json};

use crate::fleet::Fleet;
use crate::spend::{AgentSpend, ModelUsage, Usage, dollars};

pub const GROUPS: [&str; 6] = ["agent", "team", "business_unit", "owner", "tenant", "model"];
pub const UNDECLARED: &str = "(undeclared)";
pub const SEVERAL_TENANTS: &str = "(several tenants)";

pub fn usage_json(u: &Usage) -> Value {
    let mut v = serde_json::to_value(u).unwrap_or_default();
    v["unsettled_claims"] = json!(u.unsettled_claims());
    v
}

/// Rows ranked by spend, then tokens, then key.
pub fn rank(rows: &mut [Value]) {
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

/// Each agent with spend in `[from, to)`: key, spend, window usage.
pub fn active(fleet: &Fleet, from: i64, to: i64) -> Vec<(&String, &AgentSpend, Usage)> {
    fleet
        .spend
        .iter()
        .map(|(key, s)| (key, s, s.window(from, to)))
        .filter(|(_, _, u)| *u != Usage::default())
        .collect()
}

fn declared(declarations: &Value, key: &str, field: &str) -> String {
    declarations[key][field]
        .as_str()
        .filter(|s| !s.is_empty())
        .unwrap_or(UNDECLARED)
        .to_owned()
}

/// The ranked rows for `group` (one of [`GROUPS`]) over `[from, to)`.
pub fn rows(fleet: &Fleet, declarations: &Value, from: i64, to: i64, group: &str) -> Result<Vec<Value>, String> {
    if !GROUPS.contains(&group) {
        return Err(format!("group must be one of {}", GROUPS.join(", ")));
    }
    let agents = active(fleet, from, to);
    let mut rows: Vec<Value> = match group {
        "agent" => agents
            .iter()
            .map(|(key, s, u)| {
                let a = fleet.agents.get(*key);
                json!({"key": key, "agent_id": a.map(|a| a.agent_id.clone()), "team": declared(declarations, key, "team"),
                    "owner": declarations[key.as_str()]["owner"], "usage": usage_json(u),
                    "models": s.models_in(from, to).into_keys().collect::<Vec<_>>()})
            })
            .collect(),
        "model" => {
            let mut models: BTreeMap<String, (ModelUsage, u64)> = BTreeMap::new();
            for (_, s, _) in &agents {
                for (model, m) in s.models_in(from, to) {
                    let entry = models.entry(model).or_default();
                    entry.0.add(&m);
                    entry.1 += 1;
                }
            }
            models
                .into_iter()
                .map(|(key, (m, n))| {
                    // Per model only tokens are split by who measured them.
                    let self_reported = m.tokens.saturating_sub(m.verified_tokens);
                    let mut usage = serde_json::to_value(m).unwrap_or_default();
                    usage["self_reported_tokens"] = json!(self_reported);
                    json!({"key": key, "agents": n, "usage": usage})
                })
                .collect()
        }
        _ => {
            let mut groups: BTreeMap<String, (Usage, u64)> = BTreeMap::new();
            for (key, _, u) in &agents {
                let name = if group == "tenant" {
                    let tenants = fleet.agents.get(*key).map(|a| a.tenants.clone()).unwrap_or_default();
                    match tenants.len() {
                        1 => tenants.into_iter().next().unwrap_or_default(),
                        0 => UNDECLARED.to_owned(),
                        _ => SEVERAL_TENANTS.to_owned(),
                    }
                } else {
                    declared(declarations, key, group)
                };
                let entry = groups.entry(name).or_default();
                entry.0.add(u);
                entry.1 += 1;
            }
            groups
                .into_iter()
                .map(|(key, (u, n))| json!({"key": key, "agents": n, "usage": usage_json(&u)}))
                .collect()
        }
    };
    rank(&mut rows);
    Ok(rows)
}

fn field(s: &str) -> String {
    // Quote every field, and keep spreadsheet formulas from running.
    let s = if s.starts_with(['=', '+', '-', '@']) {
        format!("'{s}")
    } else {
        s.to_owned()
    };
    format!("\"{}\"", s.replace('"', "\"\""))
}

/// The rows as CSV: one line per row, cost in dollars and in hundredths of a cent.
#[must_use]
pub fn csv(group: &str, rows: &[Value]) -> String {
    let n = |v: &Value| v.as_u64().unwrap_or(0);
    let mut out = format!(
        "{group},agents,calls,tokens,cost,cost_units,verified_tokens,verified_cost_units,self_reported_tokens,self_reported_cost_units,uncovered_tokens,uncovered_cost_units,refused\n"
    );
    for r in rows {
        let u = &r["usage"];
        let agents = if group == "agent" { 1 } else { n(&r["agents"]) };
        let _ = writeln!(
            out,
            "{},{agents},{},{},{},{},{},{},{},{},{},{},{}",
            field(r["key"].as_str().unwrap_or_default()),
            n(&u["calls"]),
            n(&u["tokens"]),
            field(&dollars(n(&u["cost_units"]))),
            n(&u["cost_units"]),
            n(&u["verified_tokens"]),
            n(&u["verified_cost_units"]),
            n(&u["self_reported_tokens"]),
            n(&u["self_reported_cost_units"]),
            n(&u["uncovered_tokens"]),
            n(&u["uncovered_cost_units"]),
            n(&u["refused"]),
        );
    }
    out
}
