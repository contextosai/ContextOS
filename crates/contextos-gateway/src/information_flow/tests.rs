use serde_json::json;

use super::*;

fn manifest(effect: &str, sends_data: bool, flow: Option<Value>) -> CapabilityManifest {
    let mut m = json!({
        "capability_id": "adp.tool", "capability_version": "1", "adapter_id": "adp",
        "protocol_tool": "tool", "purpose_id": "p", "desired_effect": "e",
        "action_risk": {"effect": effect, "authority": "service", "reversibility": "compensatable",
            "interaction": "api", "data_scope": "INTERNAL"},
        "approval_mode": "destructive", "sends_data": sends_data,
        "recovery": {"strategy": "manual_reconcile", "max_attempts": 1, "retry_delays_seconds": []},
        "timeout_ms": 200, "reservation": {"tokens": 0, "tool_calls": 1, "replans": 0, "cost_units": 1},
        "adapter_ref": {"artifact_type": "adapter", "artifact_id": "a", "version": "1", "sha256": format!("sha256:{}", "0".repeat(64))},
        "capability_ref": {"artifact_type": "capability", "artifact_id": "c", "version": "1", "sha256": format!("sha256:{}", "0".repeat(64))},
    });
    if let Some(flow) = flow {
        m["flow"] = flow;
    }
    serde_json::from_value(m).unwrap()
}

fn labels(integrity: Integrity, classification: Classification) -> RunLabels {
    RunLabels {
        integrity,
        classification,
    }
}

#[test]
fn a_trusted_public_run_may_do_anything_it_is_otherwise_allowed() {
    let policy = FlowPolicy::default();
    let start = policy.labels(None);
    assert_eq!(start, labels(Integrity::Trusted, Classification::Public));
    for m in [manifest("external_state", true, None), manifest("none", true, None)] {
        assert_eq!(policy.check(start, &m).verdict, FlowVerdict::Allow);
    }
}

#[test]
fn untrusted_input_puts_effects_behind_an_approval_but_not_reads() {
    let policy = FlowPolicy::default();
    let run = labels(Integrity::Untrusted, Classification::Internal);
    let effect = policy.check(run, &manifest("external_state", false, None));
    assert_eq!(effect.verdict, FlowVerdict::Ask);
    assert_eq!(effect.reason_codes, ["flow_untrusted_effect"]);
    assert_eq!(
        policy.check(run, &manifest("none", false, None)).verdict,
        FlowVerdict::Allow
    );
    let strict = FlowPolicy {
        untrusted_effects: FlowVerdict::Deny,
        ..FlowPolicy::default()
    };
    assert_eq!(
        strict.check(run, &manifest("local_state", false, None)).verdict,
        FlowVerdict::Deny
    );
}

#[test]
fn classified_data_cannot_leave_through_a_sink_not_cleared_for_it() {
    let policy = FlowPolicy::default();
    let run = labels(Integrity::Trusted, Classification::Confidential);
    // A read-only search that sends its query out is still egress.
    let search = policy.check(run, &manifest("none", true, None));
    assert_eq!(search.verdict, FlowVerdict::Deny);
    assert_eq!(search.reason_codes, ["flow_classified_egress"]);
    let cleared = manifest("none", true, Some(json!({"egress_ceiling": "CONFIDENTIAL"})));
    assert_eq!(policy.check(run, &cleared).verdict, FlowVerdict::Allow);
    // Not egress: nothing leaves.
    assert_eq!(
        policy.check(run, &manifest("local_state", false, None)).verdict,
        FlowVerdict::Allow
    );
}

#[test]
fn the_rule_of_two_asks_even_where_the_other_rules_allow() {
    let policy = FlowPolicy {
        untrusted_effects: FlowVerdict::Allow,
        ..FlowPolicy::default()
    };
    let run = labels(Integrity::Untrusted, Classification::Confidential);
    let cleared = manifest("external_state", true, Some(json!({"egress_ceiling": "RESTRICTED"})));
    let check = policy.check(run, &cleared);
    assert_eq!(check.verdict, FlowVerdict::Ask);
    assert_eq!(check.reason_codes, ["flow_rule_of_two"]);
    let off = FlowPolicy {
        rule_of_two: false,
        ..policy
    };
    assert_eq!(off.check(run, &cleared).verdict, FlowVerdict::Allow);
}

#[test]
fn verdicts_compose_to_the_strictest_and_unreadable_state_is_the_worst_case() {
    let policy = FlowPolicy::default();
    let run = labels(Integrity::Untrusted, Classification::Restricted);
    let check = policy.check(run, &manifest("external_state", true, None));
    assert_eq!(check.verdict, FlowVerdict::Deny);
    assert_eq!(
        check.reason_codes,
        ["flow_untrusted_effect", "flow_classified_egress", "flow_rule_of_two"]
    );
    assert_eq!(
        policy.labels(Some(&json!({"integrity": "bogus"}))),
        labels(Integrity::Untrusted, Classification::Restricted)
    );
    assert_eq!(outcome(check.verdict, policy.bundle_ref())["verdict"], "deny");
    assert!(contextos_contract::shape::is_artifact_ref(&policy.bundle_ref()));
}

#[test]
fn undeclared_output_is_untrusted_internal() {
    let flow: FlowLabels = serde_json::from_value(json!({})).unwrap();
    assert_eq!(flow, FlowLabels::default());
    assert_eq!(flow.output_integrity, Integrity::Untrusted);
    assert!(serde_json::from_value::<FlowLabels>(json!({"output_integrity": "maybe"})).is_err());
}
