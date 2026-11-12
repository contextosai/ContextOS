//! A judge is fit only when it agrees with people on both passes and failures.

use contextos_kernel::evaluator_calibration::{
    CalibrationFloors, Counts, Label, Verdict, calibrate, check_record, rates,
};

fn labels(tp: usize, fn_: usize, tn: usize, fp: usize) -> Vec<Label> {
    let mut out = Vec::new();
    let mut push = |n: usize, human, judge| {
        for _ in 0..n {
            out.push(Label {
                id: format!("item_{}", out.len()),
                human,
                judge,
            });
        }
    };
    push(tp, Verdict::Pass, Verdict::Pass);
    push(fn_, Verdict::Pass, Verdict::Fail);
    push(tn, Verdict::Fail, Verdict::Fail);
    push(fp, Verdict::Fail, Verdict::Pass);
    out
}

const FLOORS: CalibrationFloors = CalibrationFloors {
    min_tpr: 0.9,
    min_tnr: 0.9,
    min_per_class: 30,
};

#[test]
fn rates_match_their_definitions() {
    let r = rates(Counts {
        tp: 45,
        fn_: 5,
        tn: 40,
        fp: 10,
    });
    assert!((r.tpr - 0.9).abs() < 1e-12);
    assert!((r.tnr - 0.8).abs() < 1e-12);
    assert!((r.youden_j - 0.7).abs() < 1e-12);
    // Observed 0.85; expected 0.5·0.55 + 0.5·0.45 = 0.5; kappa = 0.35/0.5.
    assert!((r.kappa - 0.7).abs() < 1e-12);
}

#[test]
fn a_judge_that_agrees_on_both_classes_is_fit() {
    let record = calibrate("judge@3", &labels(48, 2, 47, 3), &FLOORS).unwrap();
    assert_eq!(record.verdict.as_deref(), Some("fit"));
    assert!(record.labels_sha256.starts_with("sha256:"));
    assert!(check_record(&record, &FLOORS).is_ok());
}

#[test]
fn high_agreement_cannot_hide_missed_failures() {
    // 95 passes all agreed, 5 failures all missed: 95% agreement, TNR 0.
    let record = calibrate("lenient@1", &labels(95, 0, 0, 5), &FLOORS).unwrap();
    assert_eq!(record.verdict.as_deref(), Some("unfit"));
    assert_eq!(
        record.shortfalls,
        ["5 human fail label(s), 30 required", "tnr 0.0000 < 0.9"]
    );
}

#[test]
fn the_reader_recomputes_rates_and_applies_its_own_floors() {
    let mut record = calibrate("judge@3", &labels(48, 2, 47, 3), &FLOORS).unwrap();
    let stricter = CalibrationFloors {
        min_tnr: 0.99,
        ..FLOORS
    };
    assert!(check_record(&record, &stricter).is_err());
    // Stated rates are not trusted: the counts decide.
    record.rates = Some(serde_json::json!({"tpr": 1.0, "tnr": 1.0}));
    record.counts.fp = 30;
    assert!(check_record(&record, &FLOORS).is_err());
}

#[test]
fn duplicate_labels_and_bad_floors_are_refused() {
    let mut twice = labels(1, 0, 1, 0);
    twice[1].id = twice[0].id.clone();
    assert!(calibrate("judge@1", &twice, &FLOORS).is_err());
    let bad = CalibrationFloors { min_tpr: 1.5, ..FLOORS };
    assert!(calibrate("judge@1", &labels(1, 0, 1, 0), &bad).is_err());
    assert!(calibrate(" ", &labels(1, 0, 1, 0), &FLOORS).is_err());
}

#[test]
fn the_label_digest_ignores_order() {
    let a = labels(3, 1, 3, 1);
    let mut b = a.clone();
    b.reverse();
    let floors = CalibrationFloors {
        min_per_class: 1,
        ..FLOORS
    };
    assert_eq!(
        calibrate("j@1", &a, &floors).unwrap().labels_sha256,
        calibrate("j@1", &b, &floors).unwrap().labels_sha256
    );
}
