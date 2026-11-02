//! Exposure imported from outside the runtime: one-way, idempotent, never archived.

use contextos_kernel::shared_exposure::{
    ExposureBinding, ExposureClaim, ExposureImport, MAX_EXPOSURE_IMPORTS, compact_exposure, empty_exposure,
    exposure_summary, import_exposure, reserve_exposure, settle_exposure,
};
use serde_json::Value;

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

fn row(id: &str, amount: u64, content: char) -> ExposureImport {
    ExposureImport {
        import_id: id.into(),
        amount,
        row_digest: format!("sha256:{}", content.to_string().repeat(64)),
    }
}

fn accepted(result: contextos_kernel::TransitionResult) -> Value {
    assert!(result.is_accepted(), "{:?}", result.reason_codes);
    result.state
}

#[test]
fn an_import_commits_capacity_and_is_idempotent_per_id() {
    let b = binding();
    let state = accepted(import_exposure(&empty_exposure(&b), &b, &row("legacy_1", 6_000, 'd')));
    let summary = exposure_summary(&state).unwrap();
    assert_eq!(
        (summary["committed"].as_u64(), summary["imported"].as_u64()),
        (Some(6_000), Some(6_000))
    );
    assert_eq!(summary["available"], 4_000);
    // The same row again changes nothing; other content under the same id is refused.
    assert_eq!(
        accepted(import_exposure(&state, &b, &row("legacy_1", 6_000, 'd'))),
        state
    );
    let reused = import_exposure(&state, &b, &row("legacy_1", 6_000, 'e'));
    assert_eq!(reused.reason_codes.unwrap(), ["shared_guarantee_import_mismatch"]);
    // Reservations see imported exposure.
    assert!(!reserve_exposure(&state, &b, &claim("operation_a", 4_001)).is_accepted());
    assert!(reserve_exposure(&state, &b, &claim("operation_a", 4_000)).is_accepted());
}

#[test]
fn an_import_past_the_limit_is_kept_and_refuses_every_new_reservation() {
    let b = binding();
    let state = accepted(reserve_exposure(&empty_exposure(&b), &b, &claim("operation_a", 8_000)));
    let state = accepted(import_exposure(&state, &b, &row("legacy_1", 5_000, 'd')));
    let summary = exposure_summary(&state).unwrap();
    assert_eq!(summary["over_limit"], true);
    assert_eq!(summary["available"], 0);
    assert_eq!(
        (summary["committed"].as_u64(), summary["held"].as_u64()),
        (Some(5_000), Some(8_000))
    );
    let refused = reserve_exposure(&state, &b, &claim("operation_b", 1));
    assert_eq!(refused.reason_codes.unwrap(), ["shared_guarantee_exceeded"]);
    // Imports never touch held receipts: the hold still settles normally.
    let state = accepted(settle_exposure(&state, &b, &claim("operation_a", 8_000), "committed"));
    assert_eq!(exposure_summary(&state).unwrap()["committed"], 13_000);
}

#[test]
fn imports_survive_compaction_and_are_never_released() {
    let b = binding();
    let c = claim("operation_a", 1_000);
    let state = accepted(reserve_exposure(&empty_exposure(&b), &b, &c));
    let state = accepted(settle_exposure(&state, &b, &c, "released"));
    let state = accepted(import_exposure(&state, &b, &row("legacy_1", 2_000, 'd')));
    let state = accepted(compact_exposure(&state, &b, "2026-11-02T10:00:00Z", 60));
    let state = accepted(compact_exposure(&state, &b, "2026-11-02T11:00:00Z", 60));
    assert_eq!(
        state["receipts"].as_object().unwrap().len(),
        0,
        "the released receipt is archived"
    );
    let summary = exposure_summary(&state).unwrap();
    assert_eq!(
        (summary["committed"].as_u64(), summary["imported"].as_u64()),
        (Some(2_000), Some(2_000))
    );
    // Still idempotent after compaction.
    assert_eq!(
        accepted(import_exposure(&state, &b, &row("legacy_1", 2_000, 'd'))),
        state
    );
}

#[test]
fn import_rows_and_import_state_are_validated() {
    let b = binding();
    let empty = empty_exposure(&b);
    for bad in [
        row("", 1, 'd'),
        row("legacy_1", 0, 'd'),
        row("bad id", 1, 'd'),
        row("legacy_1", 1, 'X'),
    ] {
        let refused = import_exposure(&empty, &b, &bad);
        assert_eq!(
            refused.reason_codes.unwrap(),
            ["shared_guarantee_import_invalid"],
            "{bad:?}"
        );
    }
    let state = accepted(import_exposure(&empty, &b, &row("legacy_1", 2_000, 'd')));
    // A ledger whose imports and totals disagree is refused.
    let mut corrupt = state.clone();
    corrupt["imported"] = 1_000.into();
    assert!(!import_exposure(&corrupt, &b, &row("legacy_2", 1, 'd')).is_accepted());
    let mut inflated = state;
    inflated["imports"]["legacy_1"]["amount"] = 3_000.into();
    assert!(exposure_summary(&inflated).is_none());
}

#[test]
fn imports_per_resource_are_bounded() {
    let b = ExposureBinding {
        limit: 9_000_000,
        ..binding()
    };
    let mut state = empty_exposure(&b);
    for n in 0..MAX_EXPOSURE_IMPORTS {
        state = accepted(import_exposure(&state, &b, &row(&format!("legacy_{n}"), 1, 'd')));
    }
    let refused = import_exposure(&state, &b, &row("legacy_more", 1, 'd'));
    assert_eq!(refused.reason_codes.unwrap(), ["shared_guarantee_import_saturated"]);
    assert_eq!(exposure_summary(&state).unwrap()["import_count"], MAX_EXPOSURE_IMPORTS);
}

mod properties {
    use proptest::prelude::*;

    use super::*;

    #[derive(Debug, Clone)]
    enum Step {
        Import(u8, u64),
        Reserve(u8, u64),
        Settle(u8, bool),
        Compact(u32),
    }

    fn step() -> impl Strategy<Value = Step> {
        prop_oneof![
            (0..6_u8, 1..4_000_u64).prop_map(|(id, n)| Step::Import(id, n)),
            (0..6_u8, 1..4_000_u64).prop_map(|(id, n)| Step::Reserve(id, n)),
            (0..6_u8, any::<bool>()).prop_map(|(id, commit)| Step::Settle(id, commit)),
            (0..7_200_u32).prop_map(Step::Compact),
        ]
    }

    proptest! {
        #[test]
        fn imports_only_add_committed_and_only_imports_exceed_the_limit(steps in prop::collection::vec(step(), 1..60)) {
            let b = binding();
            let mut state = empty_exposure(&b);
            let mut amounts: std::collections::HashMap<u8, u64> = std::collections::HashMap::new();
            let mut imported = std::collections::BTreeMap::new();
            let mut clock = 0_u32;
            for step in steps {
                let before = exposure_summary(&state).unwrap();
                let result = match &step {
                    Step::Import(id, n) => import_exposure(&state, &b, &row(&format!("legacy_{id}"), *n, 'd')),
                    Step::Reserve(id, n) => {
                        amounts.entry(*id).or_insert(*n);
                        reserve_exposure(&state, &b, &claim(&format!("op_{id}"), amounts[id]))
                    }
                    Step::Settle(id, commit) => match amounts.get(id) {
                        Some(n) => settle_exposure(&state, &b, &claim(&format!("op_{id}"), *n),
                            if *commit { "committed" } else { "released" }),
                        None => continue,
                    },
                    Step::Compact(seconds) => {
                        clock += seconds;
                        let now = contextos_contract::validation::format_unix_micros(
                            1_800_000_000_000_000 + i64::from(clock) * 1_000_000);
                        compact_exposure(&state, &b, &now, 3_600)
                    }
                };
                if !result.is_accepted() {
                    prop_assert_eq!(&result.state, &state);
                    continue;
                }
                let changed = result.state != state;
                state = result.state;
                if let Step::Import(id, n) = step {
                    imported.entry(id).or_insert(n);
                }
                let after = exposure_summary(&state).unwrap();
                let committed = |s: &Value| s["committed"].as_u64().unwrap();
                prop_assert!(committed(&after) >= committed(&before), "committed never decreases");
                let total_imported: u64 = imported.values().sum();
                prop_assert_eq!(after["imported"].as_u64().unwrap(), total_imported, "imports are never lost");
                let used = committed(&after) + after["held"].as_u64().unwrap();
                prop_assert!(used <= b.limit + total_imported);
                if let Step::Reserve(..) = step && changed {
                    prop_assert!(used <= b.limit, "a new reservation never exceeds the limit");
                }
            }
        }
    }
}
