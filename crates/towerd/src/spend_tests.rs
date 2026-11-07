//! Tests for model spend.

use serde_json::json;

use super::*;
use crate::fleet::Fleet;
use crate::fleet::tests::entry;

fn at(mut e: AuditEntry, when: &str) -> AuditEntry {
    when.clone_into(&mut e.emitted_at);
    e
}

fn admitted(fleet: &mut Fleet, run: &str, agent: &str) {
    fleet.apply(
        "eu",
        &entry(
            1,
            "run_admitted",
            json!({"run_id": run, "agent_id": agent, "trace_id": run}),
        ),
    );
}

fn settled(seq: u64, run: &str, verified: bool, model: Option<&str>, tokens: u64, cost_units: u64) -> AuditEntry {
    entry(
        seq,
        "usage_settled",
        json!({"run_id": run, "reservation_id": format!("usage:{seq}"), "reporter": "meter", "verified": verified,
            "model": model, "charged": {"tokens": tokens, "cost_units": cost_units, "tool_calls": 0, "replans": 0},
            "measured": if verified { json!({"tokens": tokens, "cost_units": cost_units}) } else { Value::Null }}),
    )
}

#[test]
fn settlements_split_measured_from_self_reported_usage() {
    let mut fleet = Fleet::new(10, 48);
    admitted(&mut fleet, "r1", "bot");
    fleet.apply(
        "eu",
        &entry(
            2,
            "usage_claimed",
            json!({"run_id": "r1", "reservation_id": "usage:3", "reporter": "meter", "model": "gpt-x"}),
        ),
    );
    fleet.apply("eu", &settled(3, "r1", true, Some("gpt-x"), 1_200, 3_600));
    fleet.apply("eu", &settled(4, "r1", false, None, 4_000, 0));
    // A replan settles budget but is not a model call.
    fleet.apply(
        "eu",
        &entry(
            5,
            "usage_settled",
            json!({"run_id": "r1", "verified": false, "model": null,
            "charged": {"tokens": 0, "cost_units": 0, "tool_calls": 0, "replans": 1}}),
        ),
    );
    fleet.apply(
        "eu",
        &entry(6, "usage_claimed", json!({"run_id": "r1", "reservation_id": "usage:7"})),
    );
    let s = &fleet.spend["acme/bot"];
    assert_eq!(s.total.calls, 2);
    assert_eq!(s.total.verified_calls, 1);
    assert_eq!(s.total.tokens, 5_200);
    assert_eq!((s.total.verified_tokens, s.total.verified_cost_units), (1_200, 3_600));
    assert_eq!(s.total.self_reported_tokens, 4_000);
    assert_eq!(s.total.claimed, 2);
    assert_eq!(s.total.unsettled_claims(), 1, "one metered call is still reserved");
    let h = hour_index("2026-10-21T10:00:00Z");
    let models = s.models_in(h, h + 1);
    assert_eq!(models["gpt-x"].verified_tokens, 1_200);
    assert_eq!(models[UNREPORTED_MODEL].tokens, 4_000);
    assert_eq!(models.len(), 2);
}

#[test]
fn overage_beyond_the_budget_is_uncovered_and_refusals_count_by_reason() {
    let mut fleet = Fleet::new(10, 48);
    admitted(&mut fleet, "r1", "bot");
    fleet.apply(
        "eu",
        &entry(
            2,
            "usage_overage",
            json!({"run_id": "r1", "reservation_id": "usage:1", "reporter": "meter",
            "reserved": {"tokens": 100}, "measured": {"tokens": 900, "cost_units": 500},
            "charged": {"tokens": 600, "cost_units": 500}}),
        ),
    );
    fleet.apply("eu", &entry(3, "usage_refused", json!({"run_id": "r1", "kind": "model_call", "tokens": 50, "cost_cents": 0, "reason_codes": ["budget_tokens_exhausted"]})));
    fleet.apply(
        "eu",
        &entry(4, "usage_refused", json!({"run_id": "r1", "kind": "model_call"})),
    );
    let s = &fleet.spend["acme/bot"];
    assert_eq!((s.total.uncovered_tokens, s.total.uncovered_cost_units), (300, 0));
    assert_eq!(s.total.refused, 2);
    let h = hour_index("2026-10-21T10:00:00Z");
    let reasons = s.refusals_in(h, h + 1);
    assert_eq!(reasons["budget_tokens_exhausted"], 1);
    assert_eq!(reasons["budget_exhausted"], 1);
}

#[test]
fn usage_of_unknown_runs_is_unattributed_not_guessed() {
    let mut fleet = Fleet::new(10, 48);
    fleet.apply("eu", &settled(1, "ghost", true, Some("m"), 10, 10));
    assert!(fleet.spend.is_empty());
    assert_eq!(fleet.sources["eu"].unattributed, 1);
}

#[test]
fn model_names_are_bounded_per_agent() {
    let mut fleet = Fleet::new(10, 48);
    admitted(&mut fleet, "r1", "bot");
    for i in 0..(MAX_MODELS as u64 + 5) {
        fleet.apply("eu", &settled(2 + i, "r1", true, Some(&format!("m{i}")), 1, 0));
    }
    let s = &fleet.spend["acme/bot"];
    assert_eq!(s.models.len(), MAX_MODELS + 1);
    let h = hour_index("2026-10-21T10:00:00Z");
    assert_eq!(s.models_in(h, h + 1)[OTHER_MODELS].calls, 5);
}

#[test]
fn hours_outside_the_window_are_pruned() {
    let mut s = AgentSpend::default();
    s.apply(&at(settled(1, "r", true, Some("m"), 10, 1), "2026-10-01T00:00:00Z"));
    s.apply(&at(settled(2, "r", true, Some("m"), 20, 1), "2026-10-21T00:00:00Z"));
    s.prune(hour_index("2026-10-10T00:00:00Z"));
    assert_eq!(s.hours.len(), 1);
    assert_eq!(s.window(0, i64::MAX).tokens, 20);
    assert_eq!(s.total.tokens, 30, "totals since start are kept");
}

#[test]
fn a_spend_spike_against_the_agents_own_week_is_an_anomaly() {
    let mut spend = BTreeMap::new();
    let mut s = AgentSpend::default();
    let now = hour_index("2026-10-21T10:00:00Z");
    for h in 1..=48 {
        s.hours.insert(
            now - h,
            Usage {
                tokens: 10_000,
                cost_units: 1_000,
                ..Usage::default()
            },
        );
    }
    s.hours.insert(
        now,
        Usage {
            tokens: 400_000,
            cost_units: 500,
            refused: 6,
            ..Usage::default()
        },
    );
    spend.insert("acme/bot".to_owned(), s);
    let found = anomalies(&spend, now);
    let metrics: Vec<&str> = found.iter().map(|a| a.metric).collect();
    assert_eq!(metrics, ["model_tokens", "model_budget_refused"]);
    // Below the absolute floor nothing is reported, however unusual.
    spend.get_mut("acme/bot").unwrap().hours.insert(
        now,
        Usage {
            tokens: 150_000,
            ..Usage::default()
        },
    );
    assert!(anomalies(&spend, now).is_empty());
}

#[test]
fn findings_name_uncovered_and_unmetered_spend() {
    let now = hour_index("2026-10-21T10:00:00Z");
    let mut spend = BTreeMap::new();
    spend.insert(
        "acme/selfie".to_owned(),
        AgentSpend {
            hours: BTreeMap::from([(
                now - 2,
                Usage {
                    tokens: 20_000,
                    self_reported_tokens: 15_000,
                    ..Usage::default()
                },
            )]),
            ..AgentSpend::default()
        },
    );
    spend.insert(
        "acme/over".to_owned(),
        AgentSpend {
            hours: BTreeMap::from([(
                now,
                Usage {
                    tokens: 5_000,
                    verified_tokens: 5_000,
                    uncovered_tokens: 10,
                    ..Usage::default()
                },
            )]),
            ..AgentSpend::default()
        },
    );
    spend.insert(
        "acme/old".to_owned(),
        AgentSpend {
            hours: BTreeMap::from([(
                now - FINDING_HOURS,
                Usage {
                    tokens: 90_000,
                    self_reported_tokens: 90_000,
                    ..Usage::default()
                },
            )]),
            ..AgentSpend::default()
        },
    );
    let ids: Vec<String> = findings(&spend, now).into_iter().map(|f| f.id).collect();
    assert_eq!(
        ids,
        ["uncovered_model_usage:acme/over", "unmetered_model_spend:acme/selfie"]
    );
}

#[test]
fn dollars_round_up_to_the_cent() {
    assert_eq!(dollars(0), "$0.00");
    assert_eq!(dollars(1), "$0.01");
    assert_eq!(dollars(12_345), "$1.24");
}
