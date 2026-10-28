//! Findings: what is wrong, for which agent, why, and how to fix it.
//!
//! Every agent is assessed from four inputs: its observed activity (from verified
//! chains), its authority graph and required profile ([`crate::authority`]), its
//! owner's declaration, and its last review. Built-in checks encode the governance
//! model in docs/design/tower-governance-plane.md; organisation guardrails are
//! JsonLogic rules over the same facts, evaluated by the kernel's bounded evaluator, so
//! an error is a visible finding and never a silent pass. Waivers suppress a finding
//! for one agent until they expire, and are shown, never hidden.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::{Value, json};

use crate::authority::{self, Capability, Requirement};
use crate::fleet::{AgentActivity, Fleet, Hour, hour_index};

mod builtin;
pub use builtin::builtin;
use builtin::finding;

pub const SEVERITIES: [&str; 4] = ["critical", "high", "medium", "low"];

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: String,
    pub rule: String,
    pub severity: &'static str,
    pub agent: Option<String>,
    pub source: Option<String>,
    pub title: String,
    pub detail: String,
    pub remediation: String,
    pub evidence: Value,
    pub waiver: Option<Value>,
}

/// Everything known about one agent.
#[derive(Debug, Clone, Serialize)]
pub struct AgentView {
    pub key: String,
    pub activity: AgentActivity,
    pub declaration: Option<Value>,
    pub review: Option<Value>,
    /// A current review approves the agent's whole authority graph, risk included.
    pub approved: bool,
    /// The review approved the agent, but its validity has passed.
    pub review_expired: bool,
    pub graph: Vec<Capability>,
    pub digest: String,
    pub requirement: Requirement,
    /// Required controls each source where the agent runs does not declare.
    pub missing_controls: BTreeMap<String, BTreeSet<String>>,
    /// Capabilities in the graph since the last approved review.
    pub drift: Vec<String>,
    /// Reviewed capabilities whose risk (any dimension, approval mode included) is no
    /// longer the risk that was approved.
    pub risk_changed: Vec<String>,
    pub approval_gates: Vec<Value>,
}

/// Whether a stored review approves its agent at `now`: an approval counts only until
/// it expires, and one without an expiry never counts.
pub fn approval(review: Option<&Value>, now: &str) -> (bool, bool) {
    let Some(r) = review.filter(|r| r["decision"] == "approved") else {
        return (false, false);
    };
    let current = r["expires_at"].as_str().is_some_and(|e| e > now);
    (current, !current)
}

pub fn views(fleet: &Fleet, declarations: &Value, reviews: &Value, now: &str) -> Vec<AgentView> {
    let packs = authority::packs(fleet);
    let mut keys: BTreeSet<String> = fleet.agents.keys().cloned().collect();
    // Declared agents Tower has never seen run are part of the inventory too.
    if let Some(d) = declarations.as_object() {
        keys.extend(d.keys().cloned());
    }
    keys.into_iter()
        .map(|key| {
            let activity = fleet.agents.get(&key).cloned().unwrap_or_else(|| AgentActivity {
                key: key.clone(),
                agent_id: key.rsplit('/').next().unwrap_or(&key).to_owned(),
                ..AgentActivity::default()
            });
            view(
                fleet,
                &packs,
                activity,
                declarations.get(&key).cloned(),
                reviews.get(&key).cloned(),
                now,
            )
        })
        .collect()
}

fn view(
    fleet: &Fleet,
    packs: &BTreeMap<(String, String), Value>,
    activity: AgentActivity,
    declaration: Option<Value>,
    review: Option<Value>,
    now: &str,
) -> AgentView {
    let (current, review_expired) = approval(review.as_ref(), now);
    let graph = authority::graph(&activity, packs);
    let contexts: Vec<String> = declaration
        .as_ref()
        .and_then(|d| d["regulatory_contexts"].as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();
    let requirement = authority::requirement(&activity, &graph, &contexts);
    let missing_controls = authority::supported(fleet, &activity)
        .into_iter()
        .map(|(source, supported)| {
            (
                source,
                requirement
                    .controls
                    .difference(&supported)
                    .cloned()
                    .collect::<BTreeSet<_>>(),
            )
        })
        .filter(|(_, m)| !m.is_empty())
        .collect();
    let digest = authority::graph_digest(&graph);
    let reviewed: BTreeSet<String> = review
        .as_ref()
        .filter(|_| current)
        .and_then(|r| r["capabilities"].as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();
    // A review approves each capability at the risk it had then. A review that recorded
    // no risk (made before risk was recorded) cannot vouch for any.
    let reviewed_risk = review.as_ref().and_then(|r| r["capability_risks"].as_object());
    let (mut drift, mut risk_changed) = (Vec::new(), Vec::new());
    if current {
        for c in &graph {
            if !reviewed.contains(&c.id) {
                drift.push(c.id.clone());
            } else if reviewed_risk.and_then(|r| r.get(&c.id)) != Some(&c.risk()) {
                risk_changed.push(c.id.clone());
            }
        }
    }
    let approved = current && drift.is_empty() && risk_changed.is_empty();
    let approval_gates = activity
        .source_packs
        .iter()
        .filter_map(|p| packs.get(p))
        .flat_map(|p| {
            p["policy_layer"]["approval_gates"]
                .as_array()
                .cloned()
                .unwrap_or_default()
        })
        .collect();
    AgentView {
        key: activity.key.clone(),
        activity,
        declaration,
        review,
        approved,
        review_expired,
        graph,
        digest,
        requirement,
        missing_controls,
        drift,
        risk_changed,
        approval_gates,
    }
}

/// The facts guardrails are written against (documented in the Tower guide).
pub fn facts(view: &AgentView) -> Value {
    let a = &view.activity;
    let g = &view.graph;
    let external: Vec<&Capability> = g.iter().filter(|c| c.external()).collect();
    let decl = view.declaration.clone().unwrap_or(Value::Null);
    let scopes: BTreeSet<&str> = g.iter().map(|c| c.data_scope.as_str()).collect();
    json!({
        "agent": {"key": view.key, "agent_id": a.agent_id, "agent_urn": a.agent_urn, "sources": a.sources,
            "tenants": a.tenants, "packs": a.packs, "intents": a.intents, "models": a.models, "evaluators": a.evaluators},
        "declared": !decl.is_null(),
        "declaration": decl,
        "reviewed": view.approved,
        "review_expired": view.review_expired,
        "review": view.review,
        "capabilities": g,
        "exposure": {
            "external_effects": !external.is_empty(),
            "irreversible_external": external.iter().any(|c| c.irreversible()),
            "physical": g.iter().any(|c| c.effect == "physical_world"),
            "human_approved_authority": g.iter().any(Capability::human_approved),
            "data_scopes": scopes,
            "restricted_data": scopes.contains("RESTRICTED"),
            "confidential_data": scopes.contains("CONFIDENTIAL"),
            "approval_gates": view.approval_gates.len(),
            "browser": g.iter().any(|c| c.interacts("browser")),
            "computer": g.iter().any(|c| c.interacts("computer")),
        },
        "controls": {"required_profile": view.requirement.profile, "required": view.requirement.controls,
            "features": view.requirement.features, "missing": view.missing_controls,
            "admitted_profiles": a.admitted_profiles, "admitted_controls": a.admitted_controls},
        "drift": view.drift,
        "risk_changed": view.risk_changed,
        "activity": {"runs": a.runs, "runs_by_status": a.runs_by_status, "child_runs": a.child_runs,
            "approvals_required": a.approvals_required, "approvals_redeemed": a.approvals_redeemed,
            "escalations": a.escalations, "decisions": a.decisions, "scores": a.scores, "low_scores": a.low_scores,
            "loops": a.loops, "repeated_effects": a.repeated_effects, "unresolved_effects": a.unresolved.len(),
            "refusals": a.refusals, "output_schema_violations": a.output_schema_violations,
            "first_seen": a.first_seen, "last_seen": a.last_seen},
    })
}

/// An organisation guardrail: a JsonLogic rule over agent facts; true means a violation.
pub fn guardrail(rule: &Value, view: &AgentView, facts: &Value) -> Option<Finding> {
    let id = rule["id"].as_str().unwrap_or("guardrail");
    let title = rule["title"].as_str().unwrap_or(id);
    let severity = SEVERITIES
        .into_iter()
        .find(|s| rule["severity"] == *s)
        .unwrap_or("medium");
    match contextos_policy::jsonlogic::apply(&rule["rule"], facts) {
        Ok(v) if v.truthy() => Some(finding(
            &format!("guardrail:{id}"),
            severity,
            view,
            format!("{}: {title}", view.key),
            rule["description"].as_str().unwrap_or_default().to_owned(),
            rule["remediation"]
                .as_str()
                .unwrap_or("Bring the agent within the guardrail or request a waiver."),
            json!({"guardrail": id}),
        )),
        Ok(_) => None,
        Err(e) => Some(finding(
            &format!("guardrail:{id}"),
            "high",
            view,
            format!("Guardrail {title} could not be evaluated for {}", view.key),
            format!("Evaluation failed ({e}); the agent is treated as not compliant."),
            "Fix the guardrail rule.",
            json!({"guardrail": id, "error": e.to_string()}),
        )),
    }
}

/// Built-in findings, active guardrails and source health, with waivers applied.
pub fn findings(fleet: &Fleet, views: &[AgentView], guardrails: &Value, waivers: &Value, now: &str) -> Vec<Finding> {
    let now_hour = fleet_hour(fleet).max(hour_index(now));
    let mut out = Vec::new();
    for view in views {
        out.extend(builtin(view, now_hour));
        let facts = facts(view);
        for rule in guardrails
            .as_array()
            .into_iter()
            .flatten()
            .filter(|g| g["status"] == "active")
        {
            out.extend(guardrail(rule, view, &facts));
        }
    }
    for (pack_ref, sources) in authority::pack_conflicts(&authority::packs(fleet)) {
        out.push(Finding {
            id: format!("pack_version_conflict:{pack_ref}"),
            rule: "pack_version_conflict".into(),
            severity: "high",
            agent: None,
            source: None,
            title: format!("{pack_ref} has different content in {}", sources.join(", ")),
            detail: "One pack version names different packs. Each agent's authority is read from the source \
                     that admitted its runs, but reviews and reports that cite the version are ambiguous."
                .into(),
            remediation: "Publish changed content under a new version, and pin that version in every source.".into(),
            evidence: json!({"pack_ref": pack_ref, "sources": sources}),
            waiver: None,
        });
    }
    for state in fleet.sources.values() {
        if let Some(broken) = &state.broken {
            out.push(Finding {
                id: format!("chain_broken:{}", state.id),
                rule: "chain_broken".into(),
                severity: "critical",
                agent: None,
                source: Some(state.id.clone()),
                title: format!("Audit chain of {} failed verification", state.id),
                detail: format!("{broken}. Tower stopped reading this source; nothing after the entry is trusted."),
                remediation:
                    "Treat as a security incident: follow docs/INCIDENT.md and verify the chain with ctx audit-verify."
                        .into(),
                evidence: broken.clone(),
                waiver: None,
            });
        }
    }
    for f in &mut out {
        f.waiver = waivers
            .as_array()
            .into_iter()
            .flatten()
            .find(|w| {
                w["status"] == "approved"
                    && w["rule"] == f.rule.as_str()
                    && f.agent.as_deref().is_some_and(|a| w["agent"] == a)
                    && w["expires_at"].as_str().is_some_and(|e| e > now)
            })
            .cloned();
    }
    out.sort_by_key(|f| (SEVERITIES.iter().position(|s| *s == f.severity), f.waiver.is_some()));
    out
}

/// The latest hour any agent was active in (chain time).
pub fn fleet_hour(fleet: &Fleet) -> i64 {
    fleet
        .agents
        .values()
        .map(|a| hour_index(&a.last_seen))
        .max()
        .unwrap_or(0)
}

/// Counts here are far below 2^52, so the conversion is exact.
#[allow(clippy::cast_precision_loss)]
fn float(n: u64) -> f64 {
    n as f64
}

/// A detector: name, reading from an hour, absolute floor.
type Metric = (&'static str, fn(&Hour) -> u64, u64);

#[derive(Debug, Clone, Serialize)]
pub struct Anomaly {
    pub agent: String,
    pub metric: &'static str,
    pub hour: i64,
    pub value: u64,
    pub baseline: f64,
    pub title: String,
}

/// Each agent's latest hour against its own trailing baseline (the previous week of
/// hours). Deterministic; spikes must clear an absolute floor so quiet agents are not noisy.
pub fn anomalies(fleet: &Fleet) -> Vec<Anomaly> {
    let now = fleet_hour(fleet);
    let mut out = Vec::new();
    let metrics: [Metric; 5] = [
        ("refused", |h| h.refused, 5),
        ("unknown", |h| h.unknown, 1),
        ("failed_runs", |h| h.failed_runs, 3),
        ("guard_hits", |h| h.guard_hits, 3),
        ("effects", |h| h.effects, 50),
    ];
    for agent in fleet.agents.values() {
        let current = agent.hours.get(&now).cloned().unwrap_or_default();
        let past = agent.series(now - 24 * 7, now);
        for (metric, read, floor) in metrics {
            let value = read(&current);
            let values: Vec<f64> = past.iter().map(|(_, h)| float(read(h))).collect();
            let n = float(values.len().max(1) as u64);
            let mean = values.iter().sum::<f64>() / n;
            let std = (values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n).sqrt();
            let threshold = (mean + 4.0 * std).max(float(floor));
            if float(value) >= threshold && value >= floor {
                out.push(Anomaly {
                    agent: agent.key.clone(),
                    metric,
                    hour: now,
                    value,
                    baseline: (mean * 100.0).round() / 100.0,
                    title: format!("{}: {value} {metric} in the last hour (usual {:.1})", agent.key, mean),
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fleet::Counts;

    fn agent_with(caps: &[(&str, &str, &str)]) -> (Fleet, AgentView) {
        let mut fleet = Fleet::new(10, 48);
        let mut a = AgentActivity {
            key: "acme/bot".into(),
            agent_id: "bot".into(),
            runs: 3,
            first_seen: "2026-10-21T10:00:00Z".into(),
            last_seen: "2026-10-21T10:00:00Z".into(),
            ..AgentActivity::default()
        };
        a.packs.insert("p@1".into());
        a.source_packs.insert(("eu".into(), "p@1".into()));
        a.sources.insert("eu".into());
        a.admitted_profiles.insert("contextos.core".into());
        a.capabilities.insert(
            "x.refund".into(),
            Counts {
                attempted: 1,
                ..Counts::default()
            },
        );
        let adapters: Vec<Value> = caps
            .iter()
            .map(|(cap, effect, rev)| json!({"adapter_id": "x", "capabilities": [cap], "approval_mode": "network",
                "capability_risks": {*cap: {"effect": effect, "authority": "service", "reversibility": rev, "interaction": "api", "data_scope": "INTERNAL"}}}))
            .collect();
        let src = fleet.source("eu");
        src.packs = json!({"packs": [{"pack_ref": "p@1", "pack": {"tooling_layer": {"adapter_registry": adapters}, "policy_layer": {"approval_gates": []}}}]});
        src.deployment = json!({"support": {"supported_controls": [{"control_id": "identity.authenticated"}]}});
        fleet.agents.insert(a.key.clone(), a);
        let view = views(&fleet, &Value::Null, &Value::Null, "2026-01-01T00:00:00Z")
            .pop()
            .unwrap();
        (fleet, view)
    }

    #[test]
    fn an_undeclared_agent_with_irreversible_power_is_critical_on_several_counts() {
        let (fleet, view) = agent_with(&[("refund", "external_state", "irreversible")]);
        let rules: Vec<(String, &str)> = findings(
            &fleet,
            std::slice::from_ref(&view),
            &Value::Null,
            &Value::Null,
            "2026-10-21T10:00:00Z",
        )
        .into_iter()
        .map(|f| (f.rule, f.severity))
        .collect();
        assert!(rules.contains(&("undeclared_agent".into(), "critical")), "{rules:?}");
        assert!(rules.contains(&("irreversible_without_approval".into(), "critical")));
        assert!(rules.contains(&("controls_missing".into(), "critical")));
        assert!(rules.contains(&("profile_understated".into(), "high")));
        assert_eq!(view.requirement.profile, "contextos.high-assurance");
    }

    #[test]
    fn guardrails_are_jsonlogic_over_facts_and_errors_are_visible() {
        let (fleet, view) = agent_with(&[("lookup", "none", "read_only")]);
        let rule = json!({"id": "owner", "title": "Agents need an owner", "severity": "high", "status": "active",
            "rule": {"!": {"var": "declared"}}});
        let f = findings(
            &fleet,
            std::slice::from_ref(&view),
            &json!([rule]),
            &Value::Null,
            "2026-10-21T10:00:00Z",
        );
        assert!(f.iter().any(|f| f.rule == "guardrail:owner" && f.severity == "high"));
        let broken = json!({"id": "bad", "status": "active", "rule": {"no_such_operator": []}});
        let f = findings(
            &fleet,
            std::slice::from_ref(&view),
            &json!([broken]),
            &Value::Null,
            "2026-10-21T10:00:00Z",
        );
        assert!(
            f.iter()
                .any(|f| f.rule == "guardrail:bad" && f.title.contains("could not be evaluated"))
        );
    }

    #[test]
    fn waivers_apply_to_one_agent_until_they_expire() {
        let (fleet, view) = agent_with(&[("refund", "external_state", "irreversible")]);
        let waiver = |expires: &str| json!([{"rule": "irreversible_without_approval", "agent": "acme/bot", "status": "approved", "expires_at": expires}]);
        let waived = |w: Value| {
            findings(
                &fleet,
                std::slice::from_ref(&view),
                &Value::Null,
                &w,
                "2026-10-21T10:00:00Z",
            )
            .into_iter()
            .find(|f| f.rule == "irreversible_without_approval")
            .unwrap()
            .waiver
            .is_some()
        };
        assert!(waived(waiver("2026-12-01T00:00:00Z")));
        assert!(!waived(waiver("2026-10-01T00:00:00Z")));
    }

    #[test]
    fn a_spike_against_an_agents_own_baseline_is_an_anomaly() {
        let mut fleet = Fleet::new(10, 400);
        let mut a = AgentActivity {
            key: "bot".into(),
            last_seen: "2026-10-21T10:00:00Z".into(),
            ..AgentActivity::default()
        };
        let now = hour_index("2026-10-21T10:00:00Z");
        for h in now - 100..now {
            a.hours.insert(
                h,
                Hour {
                    refused: 1,
                    effects: 10,
                    ..Hour::default()
                },
            );
        }
        a.hours.insert(
            now,
            Hour {
                refused: 30,
                effects: 12,
                ..Hour::default()
            },
        );
        fleet.agents.insert("bot".into(), a);
        let found = anomalies(&fleet);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!((found[0].metric, found[0].value), ("refused", 30));
    }
}
