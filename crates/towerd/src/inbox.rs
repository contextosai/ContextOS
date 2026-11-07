//! The approvals inbox: every runtime's open escalations (hand-offs to a human) as one
//! queue, attributed to the agent whose run raised it and to that agent's declared
//! owner. Pure: the HTTP layer ([`crate::ops::inbox`]) fetches each source's listing and
//! the declarations, and this module shapes, filters and orders the items.
//!
//! An item whose run has left Tower's recent-run window is still listed, unattributed,
//! rather than dropped: the escalation is the runtime's fact, not Tower's.

use serde::Deserialize;
use serde_json::{Value, json};

use crate::fleet::{Fleet, hour_index};

/// What an escalation hands to a human, from its reason codes.
fn kind(raw: &Value) -> &'static str {
    let reasons = raw["reason_codes"].as_array();
    if reasons.is_some_and(|r| r.iter().any(|c| c == "outcome_missed")) {
        "outcome_missed"
    } else {
        "policy"
    }
}

/// Seconds since the epoch of a contract timestamp (`YYYY-MM-DDTHH:MM:SS…Z`).
pub fn epoch_seconds(at: &str) -> Option<i64> {
    let n = |r: std::ops::Range<usize>| at.get(r).and_then(|v| v.parse::<i64>().ok());
    let hour = hour_index(at);
    match (hour, n(14..16), n(17..19)) {
        (h, Some(m), Some(s)) if h != 0 => Some(h * 3_600 + m * 60 + s),
        _ => None,
    }
}

/// Who a declaration names as accountable: its declarer and its owner. Neither may
/// resolve the agent's escalations.
pub fn accountable(declaration: &Value) -> Vec<String> {
    ["declared_by", "owner"]
        .iter()
        .filter_map(|k| declaration[*k].as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// One runtime escalation as an inbox item.
pub fn item(source: &str, raw: &Value, fleet: &Fleet, declarations: &Value, now: &str) -> Value {
    let run_id = raw["run_id"].as_str().unwrap_or_default();
    let agent = fleet.run(source, run_id).map(|r| r.agent.clone());
    let declaration = agent.as_deref().map_or(&Value::Null, |a| &declarations[a]);
    let agent_id = agent
        .as_deref()
        .and_then(|a| fleet.agents.get(a))
        .map(|a| a.agent_id.clone());
    let opened = raw["opened_at"].as_str().unwrap_or_default();
    let age = match (epoch_seconds(opened), epoch_seconds(now)) {
        (Some(o), Some(n)) => Some((n - o).max(0)),
        _ => None,
    };
    json!({
        "source": source,
        "escalation_id": raw["escalation_id"],
        "kind": kind(raw),
        "run_id": raw["run_id"],
        "trace_id": raw["trace_id"],
        "operation_id": raw["operation_id"],
        "capability_id": raw["capability_id"],
        "reason_codes": raw["reason_codes"],
        "action_digest": raw["action_digest"],
        "policy_decision_id": raw["policy_decision_id"],
        "due_at": raw["due_at"],
        "opened_at": raw["opened_at"],
        "age_seconds": age,
        "reopened": raw["history"].as_array().map_or(0, Vec::len),
        "agent": agent,
        "agent_id": agent_id,
        "owner": declaration["owner"],
        "team": declaration["team"],
        "declared": declaration.is_object(),
    })
}

/// Filters of the inbox listing.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Filter {
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub agent: Option<String>,
    #[serde(default)]
    pub team: Option<String>,
}

impl Filter {
    pub fn keeps(&self, item: &Value) -> bool {
        let is = |field: &str, want: &Option<String>| want.as_deref().is_none_or(|w| item[field].as_str() == Some(w));
        is("source", &self.source) && is("agent", &self.agent) && is("team", &self.team)
    }
}

/// Oldest first; items with an unreadable time last, then by source and id so the
/// order is stable.
pub fn sort(items: &mut [Value]) {
    items.sort_by(|a, b| {
        let at = |v: &Value| epoch_seconds(v["opened_at"].as_str().unwrap_or_default()).unwrap_or(i64::MAX);
        at(a)
            .cmp(&at(b))
            .then_with(|| a["source"].as_str().cmp(&b["source"].as_str()))
            .then_with(|| a["escalation_id"].as_str().cmp(&b["escalation_id"].as_str()))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_seconds_reads_contract_times() {
        let a = epoch_seconds("2026-10-21T10:00:00.000000Z").unwrap();
        let b = epoch_seconds("2026-10-21T11:01:05Z").unwrap();
        assert_eq!(b - a, 3_665);
        assert_eq!(epoch_seconds("not a time"), None);
    }

    #[test]
    fn items_are_attributed_filtered_and_ordered() {
        let fleet = Fleet::new(10, 24);
        let declarations = json!({});
        let raw = |id: &str, at: &str| {
            json!({"escalation_id": id, "run_id": "gone", "opened_at": at, "capability_id": "c",
                "reason_codes": ["outcome_missed"], "history": [{}]})
        };
        let now = "2026-10-21T12:00:00Z";
        let mut items = vec![
            item("b", &raw("esc_2", "2026-10-21T11:00:00Z"), &fleet, &declarations, now),
            item("a", &raw("esc_1", "2026-10-21T10:00:00Z"), &fleet, &declarations, now),
            item("a", &raw("esc_3", "bad"), &fleet, &declarations, now),
        ];
        sort(&mut items);
        let ids: Vec<_> = items.iter().map(|i| i["escalation_id"].as_str().unwrap()).collect();
        assert_eq!(ids, ["esc_1", "esc_2", "esc_3"]);
        assert_eq!(items[0]["age_seconds"], 7_200);
        assert_eq!(items[0]["kind"], "outcome_missed");
        assert_eq!(items[0]["reopened"], 1);
        assert!(
            items[0]["agent"].is_null(),
            "a run outside the window stays unattributed"
        );
        let only_b = Filter {
            source: Some("b".into()),
            ..Filter::default()
        };
        assert_eq!(items.iter().filter(|i| only_b.keeps(i)).count(), 1);
    }

    #[test]
    fn the_declarer_and_owner_are_accountable() {
        let d = json!({"declared_by": "maya", "owner": "sam", "team": "t"});
        assert_eq!(accountable(&d), ["maya", "sam"]);
        assert_eq!(accountable(&Value::Null), Vec::<String>::new());
    }
}
