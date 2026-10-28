//! The governance model's built-in checks for one agent (docs/tower/04-governance-model.md, §4.5).

use serde_json::{Value, json};

use super::{AgentView, Finding, float};
use crate::authority::{self, Capability};
use crate::fleet::hour_index;

pub(super) fn finding(
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
    // A current review that no longer covers the graph is reported as drift below.
    let drifted = !view.drift.is_empty() || !view.risk_changed.is_empty();
    if !view.approved && !drifted && (lifecycle == "production" || (a.runs > 0 && !external.is_empty())) {
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
    if drifted {
        let reviewed_risk = view
            .review
            .as_ref()
            .map_or(Value::Null, |r| r["capability_risks"].clone());
        let changed: Vec<Value> = view
            .graph
            .iter()
            .filter(|c| view.risk_changed.contains(&c.id))
            .map(|c| json!({"capability": c.id, "reviewed": reviewed_risk[&c.id], "current": c.risk()}))
            .collect();
        let mut parts = Vec::new();
        if !view.drift.is_empty() {
            parts.push(format!("Not in the approved review: {}.", view.drift.join(", ")));
        }
        if !view.risk_changed.is_empty() {
            parts.push(format!(
                "Risk changed since the review: {}.",
                view.risk_changed.join(", ")
            ));
        }
        out.push(finding(
            "authority_drift",
            "high",
            view,
            format!("{name}'s authority changed since its review; the approval no longer covers it"),
            parts.join(" "),
            "Review the new or changed capabilities and re-approve the agent, or restore what was reviewed.",
            json!({"new": view.drift, "risk_changed": changed,
                "reviewed_at": view.review.as_ref().map(|r| r["reviewed_at"].clone())}),
        ));
    }
    let conflicting: Vec<&str> = view
        .graph
        .iter()
        .filter(|c| c.risk_conflict)
        .map(|c| c.id.as_str())
        .collect();
    if !conflicting.is_empty() {
        out.push(finding(
            "capability_risk_conflict",
            "medium",
            view,
            format!("{name}'s packs declare different risk for the same capability"),
            format!(
                "{}: the most consequential value of each risk dimension is used.",
                conflicting.join(", ")
            ),
            "Make the packs agree on each capability's risk, or give the capabilities distinct ids.",
            json!({"capabilities": conflicting}),
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
