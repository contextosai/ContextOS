//! Model spend: each agent's model-call usage, folded from the runtime's budget events.
//!
//! The runtime reserves budget before every model call and settles it afterwards. A
//! settlement reported by a metering gateway (for example the LiteLLM plugin) is
//! *verified*: it charges what the provider measured. A settlement by the run's own
//! executor is *self-reported* and charges the whole reservation, because an agent's
//! own account of its usage is not evidence. Tower keeps the two apart, together with
//! usage the run's budget could not cover and reservations the budget refused, so a
//! risk lead can see not just what agents spend but how much of it is measured.
//!
//! Events folded (payload fields; anything missing counts as zero):
//!
//! | Event | Fields used |
//! |---|---|
//! | `usage_settled` | `verified`, `model`, `charged.{tokens, cost_units, replans}` |
//! | `usage_overage` | `measured.{tokens, cost_units}` − `charged.{tokens, cost_units}` = uncovered |
//! | `usage_refused` | `kind`, `reason_codes` |
//! | `usage_claimed` | (a metering gateway took a reservation for one call) |
//!
//! `cost_units` are hundredths of a cent. Memory is bounded like the rest of the fleet
//! model: spend exists only for known agents, hourly buckets follow the fleet's window,
//! and each agent keeps at most [`MAX_MODELS`] model names (the rest share
//! [`OTHER_MODELS`]).

use std::collections::BTreeMap;

use contextos_audit::AuditEntry;
use serde::Serialize;
use serde_json::{Value, json};

use crate::fleet::hour_index;
use crate::governance::{Anomaly, Finding};

/// Distinct model names kept per agent.
pub const MAX_MODELS: usize = 16;
/// Where an agent's models past [`MAX_MODELS`] are counted.
pub const OTHER_MODELS: &str = "(other models)";
/// A settlement that named no model.
pub const UNREPORTED_MODEL: &str = "(unreported)";
/// Hours a finding looks back over.
pub const FINDING_HOURS: i64 = 24 * 7;
/// Charged tokens below which an agent's metering is not judged.
pub const UNMETERED_FLOOR_TOKENS: u64 = 10_000;

/// Usage in one hour (or summed over a window).
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub struct Usage {
    /// Model calls settled (replans are not model calls).
    pub calls: u64,
    /// Of those, settled by a metering gateway.
    pub verified_calls: u64,
    pub tokens: u64,
    pub cost_units: u64,
    /// Charged from a metering gateway's measurement.
    pub verified_tokens: u64,
    pub verified_cost_units: u64,
    /// Charged in full from the executor's own settlement.
    pub self_reported_tokens: u64,
    pub self_reported_cost_units: u64,
    /// Measured beyond what the run's budget could still cover.
    pub uncovered_tokens: u64,
    pub uncovered_cost_units: u64,
    /// Reservations the budget (or a revocation) refused.
    pub refused: u64,
    /// Reservations a metering gateway claimed for a call.
    pub claimed: u64,
}

impl Usage {
    pub fn add(&mut self, o: &Self) {
        self.calls += o.calls;
        self.verified_calls += o.verified_calls;
        self.tokens += o.tokens;
        self.cost_units += o.cost_units;
        self.verified_tokens += o.verified_tokens;
        self.verified_cost_units += o.verified_cost_units;
        self.self_reported_tokens += o.self_reported_tokens;
        self.self_reported_cost_units += o.self_reported_cost_units;
        self.uncovered_tokens += o.uncovered_tokens;
        self.uncovered_cost_units += o.uncovered_cost_units;
        self.refused += o.refused;
        self.claimed += o.claimed;
    }

    /// Metered calls claimed but not (yet) settled by the gateway: their usage is
    /// still reserved, never assumed zero.
    #[must_use]
    pub fn unsettled_claims(&self) -> u64 {
        self.claimed.saturating_sub(self.verified_calls)
    }
}

/// One model's usage in one hour.
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub struct ModelUsage {
    pub calls: u64,
    pub tokens: u64,
    pub cost_units: u64,
    pub verified_tokens: u64,
}

impl ModelUsage {
    pub fn add(&mut self, o: &Self) {
        self.calls += o.calls;
        self.tokens += o.tokens;
        self.cost_units += o.cost_units;
        self.verified_tokens += o.verified_tokens;
    }
}

/// One agent's model spend.
#[derive(Debug, Clone, Default)]
pub struct AgentSpend {
    /// Since Tower started reading (not bounded by the window).
    pub total: Usage,
    pub hours: BTreeMap<i64, Usage>,
    /// Model → hour → usage.
    pub models: BTreeMap<String, BTreeMap<i64, ModelUsage>>,
    /// Refusal reason → hour → count.
    pub refusals: BTreeMap<String, BTreeMap<i64, u64>>,
}

impl AgentSpend {
    /// Usage summed over hours `[from, to)`.
    #[must_use]
    pub fn window(&self, from: i64, to: i64) -> Usage {
        let mut out = Usage::default();
        for u in self.hours.range(from..to).map(|(_, u)| u) {
            out.add(u);
        }
        out
    }

    /// Each model's usage over hours `[from, to)`, models without any omitted.
    #[must_use]
    pub fn models_in(&self, from: i64, to: i64) -> BTreeMap<String, ModelUsage> {
        let mut out = BTreeMap::new();
        for (model, hours) in &self.models {
            let mut sum = ModelUsage::default();
            for u in hours.range(from..to).map(|(_, u)| u) {
                sum.add(u);
            }
            if sum != ModelUsage::default() {
                out.insert(model.clone(), sum);
            }
        }
        out
    }

    /// Refusals by reason over hours `[from, to)`.
    #[must_use]
    pub fn refusals_in(&self, from: i64, to: i64) -> BTreeMap<String, u64> {
        self.refusals
            .iter()
            .filter_map(|(reason, hours)| {
                let n: u64 = hours.range(from..to).map(|(_, n)| n).sum();
                (n > 0).then(|| (reason.clone(), n))
            })
            .collect()
    }

    fn model(&mut self, name: &str) -> &mut BTreeMap<i64, ModelUsage> {
        let key = if self.models.contains_key(name) || self.models.len() < MAX_MODELS {
            name
        } else {
            OTHER_MODELS
        };
        self.models.entry(key.to_owned()).or_default()
    }

    /// Drops hours before `oldest`.
    pub fn prune(&mut self, oldest: i64) {
        self.hours = self.hours.split_off(&oldest);
        for hours in self.models.values_mut() {
            *hours = hours.split_off(&oldest);
        }
        self.models.retain(|_, h| !h.is_empty());
        for hours in self.refusals.values_mut() {
            *hours = hours.split_off(&oldest);
        }
        self.refusals.retain(|_, h| !h.is_empty());
    }

    /// Folds one usage event, already attributed to this agent.
    pub fn apply(&mut self, entry: &AuditEntry) {
        let p = &entry.payload;
        let hour = hour_index(&entry.emitted_at);
        let n = |v: &Value| v.as_u64().unwrap_or(0);
        let mut u = Usage::default();
        match entry.kind.as_str() {
            "usage_settled" => {
                let charged = &p["charged"];
                let (tokens, cost) = (n(&charged["tokens"]), n(&charged["cost_units"]));
                let model_call = n(&charged["replans"]) == 0;
                u.calls = u64::from(model_call);
                u.tokens = tokens;
                u.cost_units = cost;
                if p["verified"] == true {
                    u.verified_calls = u.calls;
                    u.verified_tokens = tokens;
                    u.verified_cost_units = cost;
                } else {
                    u.self_reported_tokens = tokens;
                    u.self_reported_cost_units = cost;
                }
                if model_call {
                    let name = p["model"]
                        .as_str()
                        .filter(|m| !m.is_empty())
                        .unwrap_or(UNREPORTED_MODEL);
                    let m = self.model(&truncate(name, 200)).entry(hour).or_default();
                    m.add(&ModelUsage {
                        calls: 1,
                        tokens,
                        cost_units: cost,
                        verified_tokens: if p["verified"] == true { tokens } else { 0 },
                    });
                }
            }
            "usage_overage" => {
                let (measured, charged) = (&p["measured"], &p["charged"]);
                u.uncovered_tokens = n(&measured["tokens"]).saturating_sub(n(&charged["tokens"]));
                u.uncovered_cost_units = n(&measured["cost_units"]).saturating_sub(n(&charged["cost_units"]));
            }
            "usage_refused" => {
                u.refused = 1;
                let reasons: Vec<String> = p["reason_codes"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|r| r.as_str().map(|r| truncate(r, 120))).collect())
                    .unwrap_or_default();
                let reasons = if reasons.is_empty() {
                    vec!["budget_exhausted".to_owned()]
                } else {
                    reasons
                };
                for r in reasons.into_iter().take(8) {
                    *self.refusals.entry(r).or_default().entry(hour).or_default() += 1;
                }
            }
            "usage_claimed" => u.claimed = 1,
            _ => return,
        }
        self.total.add(&u);
        self.hours.entry(hour).or_default().add(&u);
    }
}

fn truncate(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// Whether an entry kind carries model usage.
#[must_use]
pub fn is_usage(kind: &str) -> bool {
    matches!(
        kind,
        "usage_settled" | "usage_overage" | "usage_refused" | "usage_claimed"
    )
}

/// A metric read from one hour of usage, with the absolute floor a spike must clear.
type Metric = (&'static str, fn(&Usage) -> u64, u64);

/// Spend spikes: each agent's latest hour against its own previous week, as for the
/// fleet's other anomalies (mean + 4σ, above an absolute floor).
#[must_use]
pub fn anomalies(spend: &BTreeMap<String, AgentSpend>, now: i64) -> Vec<Anomaly> {
    let metrics: [Metric; 3] = [
        ("model_tokens", |u| u.tokens, 200_000),
        // $10 an hour, in hundredths of a cent.
        ("model_cost", |u| u.cost_units, 100_000),
        ("model_budget_refused", |u| u.refused, 5),
    ];
    let mut out = Vec::new();
    for (key, s) in spend {
        let current = s.hours.get(&now).copied().unwrap_or_default();
        let past: Vec<Usage> = (now - FINDING_HOURS..now)
            .map(|h| s.hours.get(&h).copied().unwrap_or_default())
            .collect();
        for (metric, read, floor) in metrics {
            let value = read(&current);
            if value < floor {
                continue;
            }
            let values: Vec<f64> = past.iter().map(|u| float(read(u))).collect();
            let n = float(values.len().max(1) as u64);
            let mean = values.iter().sum::<f64>() / n;
            let std = (values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n).sqrt();
            if float(value) >= mean + 4.0 * std {
                out.push(Anomaly {
                    agent: key.clone(),
                    metric,
                    hour: now,
                    value,
                    baseline: (mean * 100.0).round() / 100.0,
                    title: format!(
                        "{key}: {value} {} in the last hour (usual {mean:.1})",
                        metric.replace('_', " ")
                    ),
                });
            }
        }
    }
    out
}

/// Spend findings over the last [`FINDING_HOURS`] up to `now` (inclusive):
///
/// - `uncovered_model_usage` (high): measured model usage exceeded what the run's
///   budget could cover, so the budget did not bound the spend.
/// - `unmetered_model_spend` (medium): more than half the agent's charged model tokens
///   were self-reported (at least [`UNMETERED_FLOOR_TOKENS`]), so its spend is the
///   reservation, not a measurement.
#[must_use]
pub fn findings(spend: &BTreeMap<String, AgentSpend>, now: i64) -> Vec<Finding> {
    let from = now - FINDING_HOURS + 1;
    let mut out = Vec::new();
    for (key, s) in spend {
        let w = s.window(from, now + 1);
        if w.uncovered_tokens > 0 || w.uncovered_cost_units > 0 {
            out.push(finding(
                "uncovered_model_usage",
                "high",
                key,
                format!("{key} used more model budget than its runs could cover"),
                format!(
                    "In the last 7 days, {} tokens and {} of measured model usage exceeded the remaining run budget. \
                     The budget recorded it but did not stop it.",
                    w.uncovered_tokens,
                    dollars(w.uncovered_cost_units)
                ),
                "Reserve each model call's expected size (the gateway caps output to the reservation), and review the \
                 run budget ceilings in the agent's contract.",
                json!({"window_hours": FINDING_HOURS, "uncovered_tokens": w.uncovered_tokens,
                    "uncovered_cost_units": w.uncovered_cost_units}),
            ));
        }
        if w.tokens >= UNMETERED_FLOOR_TOKENS && w.self_reported_tokens * 2 > w.tokens {
            out.push(finding(
                "unmetered_model_spend",
                "medium",
                key,
                format!("{key}'s model spend is mostly self-reported"),
                format!(
                    "In the last 7 days, {} of {} charged model tokens were settled by the agent itself, so they are \
                     charged as reserved rather than as measured.",
                    w.self_reported_tokens, w.tokens
                ),
                "Route the agent's model calls through a metering gateway (the ContextOS LiteLLM plugin) and reserve \
                 with metered=True, so usage is settled from what the provider measured.",
                json!({"window_hours": FINDING_HOURS, "tokens": w.tokens,
                    "self_reported_tokens": w.self_reported_tokens, "verified_tokens": w.verified_tokens}),
            ));
        }
    }
    out
}

fn finding(
    rule: &str,
    severity: &'static str,
    key: &str,
    title: String,
    detail: String,
    fix: &str,
    evidence: Value,
) -> Finding {
    Finding {
        id: format!("{rule}:{key}"),
        rule: rule.to_owned(),
        severity,
        agent: Some(key.to_owned()),
        source: None,
        title,
        detail,
        remediation: fix.to_owned(),
        evidence,
        waiver: None,
    }
}

/// `$1.23` from hundredths of a cent, rounded up to the cent.
#[must_use]
pub fn dollars(cost_units: u64) -> String {
    let cents = cost_units.div_ceil(100);
    format!("${}.{:02}", cents / 100, cents % 100)
}

/// Counts here are far below 2^52, so the conversion is exact.
#[allow(clippy::cast_precision_loss)]
fn float(v: u64) -> f64 {
    v as f64
}

#[cfg(test)]
#[path = "spend_tests.rs"]
mod tests;
