use contextos_kernel::shared_exposure::{
    ExposureBinding, ExposureClaim, compact_exposure, empty_exposure, exposure_summary, reserve_exposure,
    settle_exposure,
};
use serde_json::{Value, json};

fn binding() -> ExposureBinding {
    ExposureBinding {
        guarantee_id: "refunds".into(),
        definition_digest: format!("sha256:{}", "a".repeat(64)),
        resource_digest: format!("sha256:{}", "b".repeat(64)),
        limit: 10_000,
        unit: "USD_minor".into(),
    }
}

fn claim(id: &str, amount: u64) -> ExposureClaim {
    ExposureClaim {
        reservation_id: id.into(),
        action_digest: format!("sha256:{}", "c".repeat(64)),
        attempt_id: "attempt_1".into(),
        amount,
    }
}

fn accepted(result: contextos_kernel::TransitionResult) -> Value {
    assert!(result.is_accepted(), "{:?}", result.reason_codes);
    result.state
}

#[test]
fn independent_operations_share_committed_and_pending_capacity() {
    let b = binding();
    let first = claim("operation_a", 8_000);
    let state = accepted(reserve_exposure(&empty_exposure(&b), &b, &first));
    assert_eq!(state["held"], 8_000);
    let refused = reserve_exposure(&state, &b, &claim("operation_b", 8_000));
    assert!(!refused.is_accepted());
    assert_eq!(refused.state, state);
    assert_eq!(refused.reason_codes.unwrap(), ["shared_guarantee_exceeded"]);
    let state = accepted(settle_exposure(&state, &b, &first, "committed"));
    assert_eq!(state["committed"], 8_000);
    assert_eq!(state["held"], 0);
    assert!(!reserve_exposure(&state, &b, &claim("operation_b", 2_001)).is_accepted());
    assert!(reserve_exposure(&state, &b, &claim("operation_b", 2_000)).is_accepted());
}

#[test]
fn uncertainty_keeps_capacity_and_definitive_non_application_releases_once() {
    let b = binding();
    let c = claim("operation_a", 8_000);
    let state = accepted(reserve_exposure(&empty_exposure(&b), &b, &c));
    assert_eq!(accepted(settle_exposure(&state, &b, &c, "held")), state);
    let released = accepted(settle_exposure(&state, &b, &c, "released"));
    assert_eq!(released["held"], 0);
    assert_eq!(accepted(settle_exposure(&released, &b, &c, "released")), released);
    assert!(!settle_exposure(&released, &b, &c, "committed").is_accepted());
    assert!(!reserve_exposure(&released, &b, &c).is_accepted());
    let retry = ExposureClaim {
        attempt_id: "attempt_2".into(),
        ..c
    };
    assert_eq!(accepted(reserve_exposure(&released, &b, &retry))["held"], 8_000);
}

#[test]
fn unresolved_attempt_blocks_retry_and_stale_attempt_cannot_release_a_new_hold() {
    let b = binding();
    let c = claim("operation_a", 8_000);
    let state = accepted(reserve_exposure(&empty_exposure(&b), &b, &c));
    assert_eq!(accepted(reserve_exposure(&state, &b, &c)), state);
    let retry = ExposureClaim {
        attempt_id: "attempt_2".into(),
        ..c.clone()
    };
    assert!(!reserve_exposure(&state, &b, &retry).is_accepted());
    let state = accepted(settle_exposure(&state, &b, &c, "released"));
    let state = accepted(reserve_exposure(&state, &b, &retry));
    assert_eq!(state["held"], 8_000);
    assert!(!settle_exposure(&state, &b, &c, "released").is_accepted());
    let done = accepted(settle_exposure(&state, &b, &retry, "committed"));
    assert_eq!(accepted(settle_exposure(&done, &b, &retry, "committed")), done);
    assert!(!settle_exposure(&done, &b, &retry, "released").is_accepted());
    assert!(!reserve_exposure(&done, &b, &retry).is_accepted());
}

#[test]
fn changed_rule_or_action_and_corrupt_or_unsafe_state_refuse_without_mutation() {
    let b = binding();
    let c = claim("operation_a", 8_000);
    let state = accepted(reserve_exposure(&empty_exposure(&b), &b, &c));
    let mut changed = b.clone();
    changed.limit = 20_000;
    assert!(!reserve_exposure(&state, &changed, &claim("other", 1)).is_accepted());
    let mut changed_claim = c.clone();
    changed_claim.amount = 1;
    assert!(!reserve_exposure(&state, &b, &changed_claim).is_accepted());
    for corrupt in [Value::Null, json!({}), {
        let mut v = state.clone();
        v["held"] = json!(0);
        v
    }] {
        let result = reserve_exposure(&corrupt, &b, &c);
        assert!(!result.is_accepted());
        assert_eq!(result.state, corrupt);
    }
    for amount in [0, 9_007_199_254_740_992, u64::MAX] {
        assert!(!reserve_exposure(&empty_exposure(&b), &b, &claim("bad", amount)).is_accepted());
    }
}

#[test]
fn receipt_saturation_keeps_replay_protection() {
    let b = binding();
    let mut state = empty_exposure(&b);
    for i in 0..1024 {
        let c = claim(&format!("op_{i}"), 1);
        state = accepted(reserve_exposure(&state, &b, &c));
        state = accepted(settle_exposure(&state, &b, &c, "released"));
    }
    let refused = reserve_exposure(&state, &b, &claim("new", 1));
    assert!(!refused.is_accepted());
    assert_eq!(refused.reason_codes.unwrap(), ["shared_guarantee_saturated"]);
    assert_eq!(refused.state, state);
}

#[test]
fn dispatch_activation_and_abort_are_mutually_exclusive_even_before_reservation() {
    use contextos_kernel::shared_exposure::transition_exposure_dispatch as phase;
    let b = binding();
    let c = claim("operation_a", 8_000);
    let empty = empty_exposure(&b);
    let aborted = accepted(phase(&empty, &b, &c, "abort"));
    assert!(!reserve_exposure(&aborted, &b, &c).is_accepted());
    assert!(!phase(&aborted, &b, &c, "start").is_accepted());
    let held = accepted(reserve_exposure(&empty, &b, &c));
    let aborted = accepted(phase(&held, &b, &c, "abort"));
    assert!(!phase(&aborted, &b, &c, "start").is_accepted());
    let started = accepted(phase(&held, &b, &c, "start"));
    assert!(!phase(&started, &b, &c, "start").is_accepted());
    assert!(!phase(&started, &b, &c, "abort").is_accepted());
    assert!(!settle_exposure(&started, &b, &c, "released").is_accepted());
    let observed = accepted(phase(&started, &b, &c, "observe"));
    assert!(settle_exposure(&observed, &b, &c, "released").is_accepted());
}

const T0: &str = "2026-10-30T10:00:00Z";
const T1: &str = "2026-10-30T10:59:59Z";
const T2: &str = "2026-10-30T11:00:00Z";

#[test]
fn settled_receipts_are_archived_after_their_retention_and_totals_are_kept() {
    let b = binding();
    let (done, gone, open) = (
        claim("op_done", 3_000),
        claim("op_gone", 2_000),
        claim("op_open", 1_000),
    );
    let mut state = empty_exposure(&b);
    for c in [&done, &gone, &open] {
        state = accepted(reserve_exposure(&state, &b, c));
    }
    state = accepted(settle_exposure(&state, &b, &done, "committed"));
    state = accepted(settle_exposure(&state, &b, &gone, "released"));

    // First seen settled: stamped, nothing archived; a second pass changes nothing.
    let stamped = accepted(compact_exposure(&state, &b, T0, 3600));
    assert_eq!(stamped["receipts"]["op_done"]["settled_seen_at"], T0);
    assert!(
        stamped["receipts"]["op_open"].get("settled_seen_at").is_none(),
        "held is never stamped"
    );
    assert_eq!(accepted(compact_exposure(&stamped, &b, T1, 3600)), stamped);
    // Within retention the fence still holds: the released attempt cannot reserve again.
    assert!(!reserve_exposure(&stamped, &b, &gone).is_accepted());

    let archived = accepted(compact_exposure(&stamped, &b, T2, 3600));
    let receipts = archived["receipts"].as_object().unwrap();
    assert_eq!(receipts.keys().collect::<Vec<_>>(), ["op_open"], "held stays");
    let summary = exposure_summary(&archived).unwrap();
    assert_eq!(
        (&summary["committed"], &summary["held"], &summary["available"]),
        (&json!(3_000), &json!(1_000), &json!(6_000))
    );
    assert_eq!(
        (&summary["receipt_count"], &summary["archived_receipts"]),
        (&json!(1), &json!(2))
    );
    assert_eq!(archived["archived_committed"], 3_000);
    // The archived commitment still counts against the limit.
    assert!(!reserve_exposure(&archived, &b, &claim("op_new", 6_001)).is_accepted());
    assert!(reserve_exposure(&archived, &b, &claim("op_new", 6_000)).is_accepted());
}

#[test]
fn a_resource_outlives_its_receipt_cap_when_settled_receipts_are_archived() {
    let b = binding();
    let mut state = empty_exposure(&b);
    for i in 0..1024 {
        let c = claim(&format!("op_{i}"), 1);
        state = accepted(reserve_exposure(&state, &b, &c));
        state = accepted(settle_exposure(
            &state,
            &b,
            &c,
            if i % 2 == 0 { "committed" } else { "released" },
        ));
    }
    assert!(!reserve_exposure(&state, &b, &claim("new", 1)).is_accepted());
    state = accepted(compact_exposure(&state, &b, T0, 3600));
    state = accepted(compact_exposure(&state, &b, T2, 3600));
    state = accepted(reserve_exposure(&state, &b, &claim("new", 1)));
    let summary = exposure_summary(&state).unwrap();
    assert_eq!((&summary["committed"], &summary["held"]), (&json!(512), &json!(1)));
    assert_eq!(
        (&summary["receipt_count"], &summary["archived_receipts"]),
        (&json!(1), &json!(1024))
    );
}

#[test]
fn archival_state_is_validated() {
    let b = binding();
    let c = claim("op_a", 1_000);
    let held = accepted(reserve_exposure(&empty_exposure(&b), &b, &c));
    let mut forged = held.clone();
    forged["receipts"]["op_a"]["settled_seen_at"] = json!(T0);
    assert!(
        !compact_exposure(&forged, &b, T2, 3600).is_accepted(),
        "a held receipt is never stamped"
    );
    let mut forged = held.clone();
    forged["archived_committed"] = json!(500);
    assert!(
        !reserve_exposure(&forged, &b, &claim("op_b", 1)).is_accepted(),
        "totals must add up"
    );
    assert!(!compact_exposure(&held, &b, "not a time", 3600).is_accepted());
}
