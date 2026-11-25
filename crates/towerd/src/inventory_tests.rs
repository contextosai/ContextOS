//! Tests for the inventory view.

use serde_json::json;

use super::*;
use crate::fleet::Fleet;
use crate::fleet::tests::entry;
use crate::governance::views;

fn fleet() -> Fleet {
    let mut fleet = Fleet::new(10, 48);
    fleet.apply(
        "eu",
        &entry(
            1,
            "run_admitted",
            json!({"run_id": "r1", "agent_id": "agt_support", "trace_id": "t1",
                "pack_ref": "ctxpack.support@5.2.0", "intent": "support.refund",
                "release_refs": [{"artifact_type": "model_profile", "artifact_id": "claude-opus-5-5", "version": "1"}],
                "surfaced_capabilities": ["adp_payments.issue_refund"], "admitted_by": "svc"}),
        ),
    );
    fleet.apply(
        "eu",
        &entry(
            3,
            "operation_claim",
            json!({"run_id": "r1", "operation_id": "op", "attempt_id": "a1", "capability_id": "adp_payments.issue_refund"}),
        ),
    );
    fleet.apply(
        "eu",
        &entry(
            7,
            "operation_claim",
            json!({"run_id": "r1", "operation_id": "op2", "attempt_id": "a2", "capability_id": "adp_payments.issue_refund"}),
        ),
    );
    fleet.apply(
        "eu",
        &entry(
            9,
            "revocation_refusal",
            json!({"run_id": "r1", "capability_id": "crm.delete_customer", "reason_codes": ["capability_not_pinned"]}),
        ),
    );
    fleet
}

fn find<'a>(items: &'a [Item], kind: &str, id: &str) -> &'a Item {
    items
        .iter()
        .find(|i| i.kind == kind && i.id == id)
        .unwrap_or_else(|| panic!("no {kind} {id}"))
}

#[test]
fn traffic_without_declarations_is_all_shadow() {
    let fleet = fleet();
    let v = views(&fleet, &json!({}), &json!({}), "2026-10-21T11:00:00Z");
    let envs = BTreeMap::from([("eu".to_owned(), "production".to_owned())]);
    let items = inventory(&v, &envs);
    let agent = find(&items, "agent", "acme/agt_support");
    assert!(!agent.declared);
    assert_eq!(agent.lifecycle.as_deref(), Some("undeclared"));
    assert_eq!(agent.environments, BTreeSet::from(["production".to_owned()]));
    let cap = find(&items, "capability", "adp_payments.issue_refund");
    assert!(cap.declared, "surfaced at admission, so pinned by the runtime");
    let shadow = find(&items, "capability", "crm.delete_customer");
    assert!(!shadow.declared, "attempted, never surfaced, in no known pack");
    assert_eq!(shadow.first_seen.as_deref(), Some("2026-10-21T10:09:00Z"));
    assert!(!find(&items, "adapter", "crm").declared);
    assert!(find(&items, "adapter", "adp_payments").declared);
    assert_eq!(cap.first_seen.as_deref(), Some("2026-10-21T10:03:00Z"));
    assert_eq!(cap.last_seen.as_deref(), Some("2026-10-21T10:07:00Z"));
    assert_eq!(cap.agents, BTreeSet::from(["acme/agt_support".to_owned()]));
    let model = find(&items, "model", "claude-opus-5-5@1");
    assert!(!model.declared);
    assert_eq!(model.first_seen.as_deref(), Some("2026-10-21T10:01:00Z"));
    assert!(items.iter().all(|i| i.kind != "owner"));
}

#[test]
fn declarations_account_for_agents_models_and_owners() {
    let fleet = fleet();
    let declarations = json!({"acme/agt_support": {"owner": "ana", "team": "payments", "purpose": "refunds",
        "users_served": "customers", "lifecycle": "production", "risk_tier": "high", "models": ["claude-opus-5-5"]}});
    let v = views(&fleet, &declarations, &json!({}), "2026-10-21T11:00:00Z");
    let items = inventory(&v, &BTreeMap::new());
    let agent = find(&items, "agent", "acme/agt_support");
    assert!(agent.declared);
    assert_eq!(agent.risk_tier.as_deref(), Some("high"));
    assert_eq!(agent.lifecycle.as_deref(), Some("production"));
    assert!(
        find(&items, "model", "claude-opus-5-5@1").declared,
        "an id without a version matches every version"
    );
    let owner = find(&items, "owner", "payments");
    assert_eq!(owner.agents, BTreeSet::from(["acme/agt_support".to_owned()]));
    let cap = find(&items, "capability", "adp_payments.issue_refund");
    assert_eq!(
        cap.risk_tier.as_deref(),
        Some("high"),
        "a capability carries its riskiest user's tier"
    );
    assert_eq!(cap.owner_teams, BTreeSet::from(["payments".to_owned()]));
}

#[test]
fn a_declared_agent_never_seen_is_listed_without_sightings() {
    let declarations = json!({"acme/agt_new": {"owner": "ana", "team": "payments", "purpose": "p",
        "users_served": "internal", "lifecycle": "proposed"}});
    let v = views(&Fleet::new(10, 48), &declarations, &json!({}), "2026-10-21T11:00:00Z");
    let items = inventory(&v, &BTreeMap::new());
    let agent = find(&items, "agent", "acme/agt_new");
    assert!(agent.declared);
    assert!(agent.first_seen.is_none() && agent.last_seen.is_none());
}

#[test]
fn model_matching_needs_the_whole_id() {
    assert!(model_declared(&["gpt".into()], "gpt@4"));
    assert!(model_declared(&["gpt@4".into()], "gpt@4"));
    assert!(!model_declared(&["gpt@5".into()], "gpt@4"));
    assert!(!model_declared(&["gp".into()], "gpt@4"));
}

#[test]
fn sightings_per_agent_are_bounded() {
    let mut seen = SeenMap::default();
    for i in 0..=MAX_SEEN {
        seen.saw("capability", &format!("c{i}"), "2026-10-21T10:00:00Z");
    }
    assert!(seen.get("capability", "c0").is_some());
    assert!(seen.get("capability", &format!("c{MAX_SEEN}")).is_none());
}

#[test]
fn csv_quotes_and_neutralises_formulas() {
    let mut item = Item::new("agent", "=cmd|' /C calc'!A0");
    item.owner_teams.insert("a,b".into());
    let out = csv(&[item]);
    let line = out.lines().nth(1).unwrap();
    assert!(line.starts_with("agent,'=cmd|' /C calc'!A0,false,"), "{line}");
    assert!(line.contains("\"a,b\""), "{line}");
}

#[test]
fn shadow_tools_and_undeclared_models_are_findings() {
    let fleet = fleet();
    let declarations = json!({"acme/agt_support": {"owner": "ana", "team": "payments", "purpose": "refunds",
        "users_served": "customers", "lifecycle": "production", "models": ["gpt-5"]}});
    let v = views(&fleet, &declarations, &json!({}), "2026-10-21T11:00:00Z");
    let found = crate::governance::builtin(&v[0], crate::fleet::hour_index("2026-10-21T11:00:00Z"));
    let rule = |r: &str| {
        found
            .iter()
            .find(|f| f.rule == r)
            .unwrap_or_else(|| panic!("no {r}: {found:?}"))
    };
    assert_eq!(
        rule("shadow_tool").evidence["capabilities"],
        json!(["crm.delete_customer"])
    );
    assert_eq!(
        rule("undeclared_model").evidence["models"],
        json!(["claude-opus-5-5@1"])
    );

    // Without declared models there is nothing to compare: no finding.
    let declarations = json!({"acme/agt_support": {"owner": "ana", "team": "payments", "purpose": "refunds",
        "users_served": "customers", "lifecycle": "production"}});
    let v = views(&fleet, &declarations, &json!({}), "2026-10-21T11:00:00Z");
    let found = crate::governance::builtin(&v[0], crate::fleet::hour_index("2026-10-21T11:00:00Z"));
    assert!(found.iter().all(|f| f.rule != "undeclared_model"));
    assert!(found.iter().any(|f| f.rule == "shadow_tool"));
}
