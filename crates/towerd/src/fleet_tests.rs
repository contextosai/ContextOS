//! Tests for the fleet model.

use super::*;

pub(crate) fn entry(sequence: u64, kind: &str, payload: Value) -> AuditEntry {
    AuditEntry {
        entry_version: "contextos.audit_entry.v1".into(),
        tenant_id: "acme".into(),
        sequence,
        prev_hash: None,
        kind: kind.into(),
        emitted_at: format!("2026-10-21T10:{:02}:00Z", sequence % 60),
        payload_digest: String::new(),
        payload,
        record_hash: String::new(),
        signature: contextos_audit::chain::EntrySignature {
            alg: "ed25519".into(),
            kid: "k".into(),
            sig: String::new(),
        },
    }
}

#[test]
fn hours_count_from_the_epoch() {
    assert_eq!(hour_index("1970-01-01T00:00:00Z"), 0);
    assert_eq!(hour_index("1970-01-02T03:00:00.123Z"), 27);
    assert_eq!(hour_index("2026-10-21T10:00:00Z") % 24, 10);
    assert_eq!(hour_index("garbage"), 0);
}

#[test]
fn runs_are_attributed_to_agents_and_effects_to_capabilities() {
    let mut fleet = Fleet::new(10, 48);
    fleet.apply(
        "eu",
        &entry(
            1,
            "run_admitted",
            json!({"run_id": "r1", "agent_id": "agt_support", "trace_id": "t1",
        "pack_ref": "ctxpack.support@5.2.0", "intent": "support.refund", "profiles": ["contextos.core"],
        "release_refs": [{"artifact_type": "model_profile", "artifact_id": "claude-opus-5-5", "version": "1"}],
        "surfaced_capabilities": ["adp_payments.issue_refund"], "admitted_by": "svc"}),
        ),
    );
    fleet.apply("eu", &entry(2, "authorization_decision", json!({"run_id": "r1", "operation_id": "op", "verdict": "allow", "approval_refs": [{"artifact_id": "apr"}]})));
    fleet.apply("eu", &entry(3, "operation_claim", json!({"run_id": "r1", "operation_id": "op", "attempt_id": "a1", "capability_id": "adp_payments.issue_refund"})));
    fleet.apply(
        "eu",
        &entry(
            4,
            "effect_observation",
            json!({"run_id": "r1", "attempt_id": "a1", "outcome": "unknown", "finality": "provisional"}),
        ),
    );
    let agent = &fleet.agents["acme/agt_support"];
    assert_eq!(agent.runs, 1);
    assert_eq!(agent.approvals_redeemed, 1);
    assert_eq!(agent.models, BTreeSet::from(["claude-opus-5-5@1".to_owned()]));
    assert_eq!(agent.capabilities["adp_payments.issue_refund"].unknown, 1);
    assert_eq!(agent.unresolved.len(), 1);
    fleet.apply(
        "eu",
        &entry(
            5,
            "effect_reconciliation",
            json!({"attempt_id": "a1", "outcome": "not_applied"}),
        ),
    );
    assert!(fleet.agents["acme/agt_support"].unresolved.is_empty());
    assert_eq!(fleet.run("eu", "r1").unwrap().unknown, 1);
}

#[test]
fn the_run_window_is_bounded_and_late_effects_are_unattributed() {
    let mut fleet = Fleet::new(2, 48);
    for (i, run) in ["r1", "r2", "r3"].iter().enumerate() {
        fleet.apply(
            "eu",
            &entry(
                i as u64 + 1,
                "run_admitted",
                json!({"run_id": run, "agent_id": "a", "trace_id": run}),
            ),
        );
    }
    assert!(fleet.run("eu", "r1").is_none());
    assert_eq!(fleet.recent_runs(|_| true).count(), 2);
    fleet.apply(
        "eu",
        &entry(
            9,
            "operation_claim",
            json!({"run_id": "r1", "attempt_id": "x", "capability_id": "c"}),
        ),
    );
    assert_eq!(fleet.sources["eu"].unattributed, 1);
    assert_eq!(fleet.agents["acme/a"].runs, 3, "counters survive the window");
}

#[test]
fn decisions_belong_to_the_parent_run_of_a_shared_trace() {
    let mut fleet = Fleet::new(10, 48);
    for (i, run) in ["parent", "child"].iter().enumerate() {
        fleet.apply(
            "eu",
            &entry(
                i as u64 + 1,
                "run_admitted",
                json!({"run_id": run, "agent_id": "a", "trace_id": "t"}),
            ),
        );
    }
    fleet.apply(
        "eu",
        &entry(3, "decision_record", json!({"trace_id": "t", "record_id": "d1"})),
    );
    assert_eq!(fleet.run("eu", "parent").unwrap().decisions, 1);
    assert_eq!(fleet.run("eu", "child").unwrap().decisions, 0);
}

#[test]
fn kill_switch_state_and_changes_come_from_the_chain() {
    let mut fleet = Fleet::new(10, 48);
    fleet.apply(
        "eu",
        &entry(
            1,
            "revocation",
            json!({"kind": "capability", "target": "pay.send", "reason": "INC-1", "operator": "oncall"}),
        ),
    );
    assert_eq!(fleet.sources["eu"].revoked["capability:pay.send"], "INC-1");
    fleet.apply(
        "eu",
        &entry(
            2,
            "revocation_restored",
            json!({"kind": "capability", "target": "pay.send", "reason": "fixed"}),
        ),
    );
    assert!(fleet.sources["eu"].revoked.is_empty());
    assert_eq!(fleet.changes.len(), 2);
    assert_eq!(fleet.changes[0].by.as_deref(), Some("oncall"));
}

#[test]
fn attempts_unresolved_effects_and_agents_stay_bounded() {
    let mut fleet = Fleet::new(10, 48);
    (fleet.max_attempts, fleet.max_unresolved, fleet.max_agents) = (2, 1, 2);
    fleet.apply(
        "eu",
        &entry(
            1,
            "run_admitted",
            json!({"run_id": "r1", "agent_id": "a", "trace_id": "t1"}),
        ),
    );
    for (i, attempt) in ["x1", "x2", "x3"].iter().enumerate() {
        let claim = json!({"run_id": "r1", "operation_id": attempt, "attempt_id": attempt, "capability_id": "c"});
        fleet.apply("eu", &entry(2 + i as u64, "operation_claim", claim));
    }
    // The oldest attempt left; the newer ones still attribute their outcomes.
    for (i, attempt) in ["x1", "x2", "x3"].iter().enumerate() {
        let unknown = json!({"attempt_id": attempt, "outcome": "unknown", "finality": "provisional"});
        fleet.apply("eu", &entry(10 + i as u64, "effect_observation", unknown));
    }
    let agent = &fleet.agents["acme/a"];
    assert_eq!(agent.capabilities["c"].unknown, 2);
    assert_eq!((agent.unresolved.len(), agent.unresolved_untracked), (1, 1));
    assert_eq!(agent.unresolved_effects(), 2);
    for (i, attempt) in ["x2", "x3"].iter().enumerate() {
        let settled = json!({"attempt_id": attempt, "outcome": "not_applied"});
        fleet.apply("eu", &entry(20 + i as u64, "effect_reconciliation", settled));
    }
    assert_eq!(fleet.agents["acme/a"].unresolved_effects(), 0);

    // Past the agent bound, new agents are counted together per tenant.
    for (i, agent) in ["b", "c", "d"].iter().enumerate() {
        let run = format!("r_{agent}");
        let admitted = json!({"run_id": run, "agent_id": agent, "trace_id": run, "agent_urn": format!("urn:{agent}")});
        fleet.apply("eu", &entry(30 + i as u64, "run_admitted", admitted));
    }
    assert_eq!(fleet.agents.len(), 3);
    let other = &fleet.agents[&format!("acme/{OVERFLOW_AGENT}")];
    assert_eq!((other.runs, other.agent_urn.as_deref()), (2, None));
}

#[test]
fn one_tenant_past_its_agent_bound_does_not_crowd_out_another() {
    let mut fleet = Fleet::new(10, 48);
    fleet.max_agents = 1;
    let admit = |fleet: &mut Fleet, seq: u64, tenant: &str, agent: &str| {
        let mut e = entry(
            seq,
            "run_admitted",
            json!({"run_id": format!("r{seq}"), "agent_id": agent, "trace_id": format!("t{seq}")}),
        );
        e.tenant_id = tenant.into();
        fleet.apply("eu", &e);
    };
    admit(&mut fleet, 1, "noisy", "a1");
    admit(&mut fleet, 2, "noisy", "a2");
    admit(&mut fleet, 3, "quiet", "b1");
    assert!(fleet.agents.contains_key(&format!("noisy/{OVERFLOW_AGENT}")));
    assert!(
        fleet.agents.contains_key("quiet/b1"),
        "the other tenant keeps its own agents"
    );
}

#[test]
fn the_fleet_has_a_ceiling_beyond_the_per_tenant_bound() {
    let mut fleet = Fleet::new(10, 48);
    (fleet.max_agents, fleet.max_fleet_agents) = (10, 2);
    for (seq, tenant, agent) in [(1, "t1", "a"), (2, "t2", "b"), (3, "t3", "c"), (4, "t3", "d")] {
        let mut e = entry(
            seq,
            "run_admitted",
            json!({"run_id": format!("r{seq}"), "agent_id": agent, "trace_id": format!("t{seq}")}),
        );
        e.tenant_id = tenant.into();
        fleet.apply("eu", &e);
    }
    // Two real agents, then t3's new agents share its overflow agent.
    assert!(fleet.agents.contains_key("t1/a") && fleet.agents.contains_key("t2/b"));
    assert_eq!(fleet.agents[&format!("t3/{OVERFLOW_AGENT}")].runs, 2);
    assert_eq!(fleet.agents.len(), 3);
}
