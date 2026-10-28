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
    /// The review approves the agent and has not expired.
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
    let (approved, review_expired) = approval(review.as_ref(), now);
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
        .filter(|_| approved)
        .and_then(|r| r["capabilities"].as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();
    let drift = if approved {
        graph
            .iter()
            .filter(|c| !reviewed.contains(&c.id))
            .map(|c| c.id.clone())
            .collect()
    } else {
        Vec::new()
    };
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
            "browser": g.iter().any(|c| c.interaction == "browser"),
            "computer": g.iter().any(|c| c.interaction == "computer"),
        },
        "controls": {"required_profile": view.requirement.profile, "required": view.requirement.controls,
            "features": view.requirement.features, "missing": view.missing_controls,
            "admitted_profiles": a.admitted_profiles, "admitted_controls": a.admitted_controls},
        "drift": view.drift,
        "activity": {"runs": a.runs, "runs_by_status": a.runs_by_status, "child_runs": a.child_runs,
            "approvals_required": a.approvals_required, "approvals_redeemed": a.approvals_redeemed,
            "escalations": a.escalations, "decisions": a.decisions, "scores": a.scores, "low_scores": a.low_scores,
            "loops": a.loops, "repeated_effects": a.repeated_effects, "unresolved_effects": a.unresolved.len(),
            "refusals": a.refusals, "output_schema_violations": a.output_schema_violations,
            "first_seen": a.first_seen, "last_seen": a.last_seen},
    })
}

fn finding(
    rule: &str,
    severity: &'static str,
    view: &AgentView,
    title: String,
    detail: String,
    remediation: &str,
    evidence: Value,
) -> Finding {
    Finding {
        id: format!("{rule}:{}", view.key),
        rule: rule.to_owned(),
        severity,
        agent: Some(view.key.clone()),
        source: None,
        title,
        detail,
        remediation: remediation.to_owned(),
        evidence,
        waiver: None,
    }
}

/// The governance model's built-in checks for one agent.
pub fn builtin(view: &AgentView, now_hour: i64) -> Vec<Finding> {
    let a = &view.activity;
    let mut out = Vec::new();
    let external: Vec<&Capability> = view.graph.iter().filter(|c| c.external()).collect();
    let name = view.key.as_str();
    let lifecycle = view
        .declaration
        .as_ref()
        .and_then(|d| d["lifecycle"].as_str())
        .unwrap_or("undeclared");

    if view.declaration.is_none() && a.runs > 0 {
        out.push(finding(
            "undeclared_agent",
            if external.is_empty() { "high" } else { "critical" },
            view,
            format!("{name} runs without a declared owner"),
            format!(
                "{} governed run(s) since {}. Nobody is accountable for it{}.",
                a.runs,
                a.first_seen,
                if external.is_empty() {
                    String::new()
                } else {
                    format!(", and it can take external actions ({})", external.len())
                }
            ),
            "Declare the agent: owner, team, purpose, users served and lifecycle stage.",
            json!({"runs": a.runs, "first_seen": a.first_seen, "admitted_by": a.admitted_by}),
        ));
    }
    if !view.approved && (lifecycle == "production" || (a.runs > 0 && !external.is_empty())) {
        let expired = view.review.as_ref().filter(|_| view.review_expired);
        out.push(finding(
            "unreviewed",
            if external.is_empty() { "medium" } else { "high" },
            view,
            match expired {
                Some(r) => format!(
                    "{name}'s risk review expired at {}",
                    r["expires_at"].as_str().unwrap_or("?")
                ),
                None => format!("{name} has not passed a risk review"),
            },
            format!(
                "Required profile {} ({}).",
                view.requirement.profile,
                view.requirement.reasons.join("; ")
            ),
            "Run an intake review: confirm its authority, required controls and owner, then record the decision.",
            json!({"required_profile": view.requirement.profile, "reasons": view.requirement.reasons}),
        ));
    }
    if !view.drift.is_empty() {
        out.push(finding(
            "authority_drift",
            "high",
            view,
            format!("{name} gained capabilities since its review"),
            format!("Not in the approved review: {}.", view.drift.join(", ")),
            "Review the new capabilities and re-approve the agent, or remove them from its packs.",
            json!({"new": view.drift, "reviewed_at": view.review.as_ref().map(|r| r["reviewed_at"].clone())}),
        ));
    }
    for (source, missing) in &view.missing_controls {
        let critical = view.requirement.profile == "contextos.high-assurance";
        out.push(Finding {
            id: format!("controls_missing:{}:{source}", view.key),
            source: Some(source.clone()),
            ..finding(
                "controls_missing",
                if critical { "critical" } else { "high" },
                view,
                format!("{name} runs where required controls are not supported"),
                format!(
                    "Its authority requires {}; runtime {source} does not declare: {}.",
                    view.requirement.profile,
                    missing.iter().cloned().collect::<Vec<_>>().join(", ")
                ),
                "Enable the controls on that runtime (and record conformance evidence), or narrow the agent's capabilities.",
                json!({"source": source, "missing": missing, "required_profile": view.requirement.profile}),
            )
        });
    }
    if a.runs > 0
        && !a.admitted_profiles.is_empty()
        && !authority::satisfies(&a.admitted_profiles, &view.requirement.profiles)
    {
        out.push(finding(
            "profile_understated",
            "high",
            view,
            format!("{name}'s runs are admitted under a weaker profile than its authority needs"),
            format!(
                "Admitted under {}; its capabilities require {}.",
                a.admitted_profiles.iter().cloned().collect::<Vec<_>>().join(", "),
                view.requirement.profile
            ),
            "Have the orchestrator request the required profile in the execution contract, so admission negotiates its controls.",
            json!({"admitted": a.admitted_profiles, "required": view.requirement.profile}),
        ));
    }
    if view.approval_gates.is_empty() {
        let unguarded: Vec<&str> = external
            .iter()
            .filter(|c| c.irreversible() && !c.human_approved())
            .map(|c| c.id.as_str())
            .collect();
        if !unguarded.is_empty() {
            out.push(finding(
                "irreversible_without_approval",
                "critical",
                view,
                format!("{name} can take irreversible external actions with no human approval"),
                format!("{} — no approval gate in its packs, and the capability's authority is not human_approved.", unguarded.join(", ")),
                "Add an approval gate for these capabilities, or mark their authority human_approved so every call needs an exact approval.",
                json!({"capabilities": unguarded}),
            ));
        }
    }
    if !a.unresolved.is_empty() {
        out.push(finding(
            "unresolved_effects",
            "critical",
            view,
            format!("{name} has {} effect(s) with unknown outcome", a.unresolved.len()),
            "The runtime cannot tell whether these actions happened. Nothing may retry them until they are reconciled."
                .into(),
            "Reconcile each operation (provider query, or an operator assertion with evidence) on its runtime.",
            json!({"operations": a.unresolved.iter().take(20).collect::<Vec<_>>()}),
        ));
    }
    if !external.is_empty() && a.runs > 0 && a.models.is_empty() {
        out.push(finding(
            "model_unpinned",
            "medium",
            view,
            format!("{name}'s runs do not record which model made their decisions"),
            "No model_profile release reference was pinned at admission.".into(),
            "Pin model_profile (and evaluator_suite) in the execution contract's release_refs; production runtimes can require it.",
            json!({}),
        ));
    }
    if a.decisions > a.scores && !external.is_empty() {
        out.push(finding(
            "unscored_decisions",
            "medium",
            view,
            format!("{name} has decisions no independent evaluator scored"),
            format!("{} decision(s), {} score(s).", a.decisions, a.scores),
            "Route its decisions to an evaluator (scope `evaluate`), or require scores before completion.",
            json!({"decisions": a.decisions, "scores": a.scores}),
        ));
    }
    if a.low_scores > 0 {
        out.push(finding(
            "low_scores",
            "high",
            view,
            format!("{name} has decisions scored below the policy or safety floor"),
            format!("{} low score(s).", a.low_scores),
            "Inspect the decisions, file feedback, and gate the next pack release on these cases.",
            json!({"low_scores": a.low_scores}),
        ));
    }
    if a.approvals_redeemed >= 20
        && a.approvals_required > 0
        && a.escalations == 0
        && !a.refusals.contains_key("approval_self_denied")
    {
        let rate = float(a.approvals_redeemed) / float(a.approvals_required.max(a.approvals_redeemed));
        if rate >= 0.99 {
            out.push(finding(
                "oversight_possibly_vacuous",
                "low",
                view,
                format!("Every approval {name} asked for was granted"),
                format!("{} approvals requested, {} redeemed, none escalated. Review that never says no may not be review.", a.approvals_required, a.approvals_redeemed),
                "Sample these approvals: if they are routine, encode the rule as policy; if they matter, check reviewers see enough to refuse.",
                json!({"required": a.approvals_required, "redeemed": a.approvals_redeemed}),
            ));
        }
    }
    if a.loops + a.repeated_effects > 0 {
        out.push(finding(
            "agent_looping",
            "medium",
            view,
            format!("{name} repeats itself"),
            format!(
                "Loop guard fired {} time(s); repeated effects withheld {} time(s).",
                a.loops, a.repeated_effects
            ),
            "Inspect the runs: the agent is retrying identical calls instead of changing approach.",
            json!({"loops": a.loops, "repeated_effects": a.repeated_effects}),
        ));
    }
    if lifecycle == "production" && (a.runs == 0 || hour_index(&a.last_seen) < now_hour - 24 * 30) {
        out.push(finding(
            "ungoverned_or_dormant",
            "high",
            view,
            format!("{name} is declared in production but Tower has seen no governed run in 30 days"),
            "Either its actions bypass the runtime (ungoverned), or it is no longer used.".into(),
            "Route the agent's tools through a ContextOS runtime, or move it to deprecated and revoke it.",
            json!({"last_seen": a.last_seen}),
        ));
    }
    if matches!(lifecycle, "retired" | "deprecated") && a.runs > 0 && hour_index(&a.last_seen) >= now_hour - 24 {
        out.push(finding(
            "retired_but_running",
            "high",
            view,
            format!("{name} is declared {lifecycle} but is still running"),
            format!("Last run at {}.", a.last_seen),
            "Revoke the agent fleet-wide with the kill switch, or correct its lifecycle.",
            json!({"last_seen": a.last_seen}),
        ));
    }
    out
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
