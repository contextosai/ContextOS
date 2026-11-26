//! Behaviour flags: an agent doing something it has not done before. Each flag is a
//! finding for a person to review (resolve, or waive with a reason); none blocks a
//! call. Blocking stays with the runtime's guards, breakers and monitor.
//!
//! - `new_tool_used`: a capability first called in the last day by an agent with at
//!   least a week of history.
//! - `new_model_used`: a model release first seen in the last day for such an agent.
//! - `unusual_hour`: runs in the last day in an hour of the day (UTC) when the agent
//!   ran nothing in the previous two weeks, for an agent with at least a week of runs.
//!
//! First sightings come from the inventory's per-agent record (`AgentActivity::seen`);
//! hours from the fleet model's hourly buckets, so the look-back is bounded by the
//! collector's `hours` window.

use std::collections::BTreeSet;

use serde_json::json;

use super::builtin::finding as builtin_finding;
use super::{AgentView, Finding};
use crate::fleet::hour_index;

/// History an agent needs before anything it does counts as new.
pub const MIN_HISTORY_HOURS: i64 = 24 * 7;
/// How far back an hour of the day must be unused to be unusual.
pub const LOOKBACK_HOURS: i64 = 24 * 14;

fn recent(at: &str, now_hour: i64) -> bool {
    !at.is_empty() && hour_index(at) >= now_hour - 24
}

/// The flags for one agent at `now_hour`.
pub fn flags(view: &AgentView, now_hour: i64) -> Vec<Finding> {
    let a = &view.activity;
    if a.first_seen.is_empty() || hour_index(&a.first_seen) > now_hour - MIN_HISTORY_HOURS {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (kind, rule, ids) in [
        (
            "capability",
            "new_tool_used",
            a.capabilities.keys().cloned().collect::<Vec<_>>(),
        ),
        ("model", "new_model_used", a.models.iter().cloned().collect::<Vec<_>>()),
    ] {
        let new: Vec<String> = ids
            .into_iter()
            .filter(|id| a.seen.get(kind, id).is_some_and(|s| recent(&s.first, now_hour)))
            .collect();
        if !new.is_empty() {
            out.push(builtin_finding(
                rule,
                "medium",
                view,
                format!("{} used {} {kind}(s) for the first time", view.key, new.len()),
                format!("First seen in the last day: {}.", new.join(", ")),
                "Check the change was intended (a pack or model release) and review the agent; waive with a reason if it was.",
                json!({"new": new}),
            ));
        }
    }
    let usual: BTreeSet<i64> = a
        .hours
        .iter()
        .filter(|(h, hour)| **h < now_hour - 24 && **h >= now_hour - LOOKBACK_HOURS && hour.runs > 0)
        .map(|(h, _)| h.rem_euclid(24))
        .collect();
    let unusual: BTreeSet<i64> = a
        .hours
        .iter()
        .filter(|(h, hour)| **h >= now_hour - 24 && hour.runs > 0 && !usual.contains(&h.rem_euclid(24)))
        .map(|(h, _)| h.rem_euclid(24))
        .collect();
    if !usual.is_empty() && !unusual.is_empty() {
        out.push(builtin_finding(
            "unusual_hour",
            "low",
            view,
            format!("{} ran at an hour of the day it has not used before", view.key),
            format!(
                "Runs in the last day at {} UTC; the previous two weeks only at {}.",
                unusual
                    .iter()
                    .map(|h| format!("{h:02}:00"))
                    .collect::<Vec<_>>()
                    .join(", "),
                usual
                    .iter()
                    .map(|h| format!("{h:02}:00"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            "Check who or what started these runs; waive with a reason if the schedule changed.",
            json!({"hours_utc": unusual, "usual_hours_utc": usual}),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::fleet::Fleet;
    use crate::fleet::tests::entry;
    use crate::governance::views;

    fn at(seq: u64, kind: &str, payload: Value, when: &str) -> contextos_audit::AuditEntry {
        let mut e = entry(seq, kind, payload);
        e.emitted_at = when.into();
        e
    }

    fn fleet_with_history() -> Fleet {
        let mut fleet = Fleet::new(100, 24 * 30);
        // Ten days of runs at 09:00 UTC, calling the lookup tool.
        for day in 1..=10u64 {
            let when = format!("2026-11-{day:02}T09:00:00Z");
            let run = format!("r{day}");
            fleet.apply(
                "eu",
                &at(
                    day * 2,
                    "run_admitted",
                    json!({"run_id": run, "agent_id": "agt", "trace_id": run,
                "release_refs": [{"artifact_type": "model_profile", "artifact_id": "m", "version": "1"}]}),
                    &when,
                ),
            );
            fleet.apply(
                "eu",
                &at(
                    day * 2 + 1,
                    "operation_claim",
                    json!({"run_id": run, "operation_id": "o", "attempt_id": format!("a{day}"),
                "capability_id": "crm.lookup"}),
                    &when,
                ),
            );
        }
        fleet
    }

    fn rules(fleet: &Fleet, now: &str) -> Vec<String> {
        let v = views(fleet, &json!({}), &json!({}), now);
        flags(&v[0], hour_index(now)).into_iter().map(|f| f.rule).collect()
    }

    #[test]
    fn steady_behaviour_raises_nothing() {
        let mut fleet = fleet_with_history();
        fleet.apply(
            "eu",
            &at(
                30,
                "run_admitted",
                json!({"run_id": "r11", "agent_id": "agt", "trace_id": "t",
            "release_refs": [{"artifact_type": "model_profile", "artifact_id": "m", "version": "1"}]}),
                "2026-11-11T09:00:00Z",
            ),
        );
        assert_eq!(rules(&fleet, "2026-11-11T10:00:00Z"), Vec::<String>::new());
    }

    #[test]
    fn a_new_tool_a_new_model_and_a_new_hour_are_flagged_for_review() {
        let mut fleet = fleet_with_history();
        let when = "2026-11-11T03:00:00Z";
        fleet.apply(
            "eu",
            &at(
                30,
                "run_admitted",
                json!({"run_id": "r11", "agent_id": "agt", "trace_id": "t",
            "release_refs": [{"artifact_type": "model_profile", "artifact_id": "m", "version": "2"}]}),
                when,
            ),
        );
        fleet.apply(
            "eu",
            &at(
                31,
                "operation_claim",
                json!({"run_id": "r11", "operation_id": "o", "attempt_id": "a11",
            "capability_id": "crm.export_all"}),
                when,
            ),
        );
        let found = rules(&fleet, "2026-11-11T04:00:00Z");
        assert_eq!(found, ["new_tool_used", "new_model_used", "unusual_hour"]);
    }

    #[test]
    fn a_young_agent_is_never_flagged() {
        let mut fleet = Fleet::new(100, 24 * 30);
        fleet.apply(
            "eu",
            &at(
                1,
                "run_admitted",
                json!({"run_id": "r1", "agent_id": "agt", "trace_id": "t"}),
                "2026-11-10T03:00:00Z",
            ),
        );
        fleet.apply(
            "eu",
            &at(
                2,
                "operation_claim",
                json!({"run_id": "r1", "operation_id": "o", "attempt_id": "a",
            "capability_id": "crm.export_all"}),
                "2026-11-10T03:00:00Z",
            ),
        );
        assert_eq!(rules(&fleet, "2026-11-10T04:00:00Z"), Vec::<String>::new());
    }
}
