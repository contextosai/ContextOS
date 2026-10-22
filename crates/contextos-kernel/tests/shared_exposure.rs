use contextos_kernel::shared_exposure::{
    ExposureBinding, ExposureClaim, empty_exposure, reserve_exposure, settle_exposure,
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
