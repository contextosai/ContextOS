//! `[guards.evaluator_calibration]`: only calibrated evaluator releases may judge.

use contextos_kernel::evaluator_calibration::{CalibrationFloors, Label, Verdict, calibrate};
use contextosd::evaluator_calibration::{EvaluatorCalibration, load};
use serde_json::{Value, json};

use crate::harness::*;

/// A record for `evaluator_ref` from `agree` agreeing labels per class and `miss`
/// missed failures.
fn record_file(name: &str, evaluator_ref: &str, agree: usize, miss: usize) -> std::path::PathBuf {
    let mut labels = Vec::new();
    for i in 0..agree {
        labels.push(Label {
            id: format!("p{i}"),
            human: Verdict::Pass,
            judge: Verdict::Pass,
        });
        labels.push(Label {
            id: format!("f{i}"),
            human: Verdict::Fail,
            judge: Verdict::Fail,
        });
    }
    for i in 0..miss {
        labels.push(Label {
            id: format!("m{i}"),
            human: Verdict::Fail,
            judge: Verdict::Pass,
        });
    }
    let floors = CalibrationFloors {
        min_tpr: 0.0,
        min_tnr: 0.0,
        min_per_class: 1,
    };
    let record = calibrate(evaluator_ref, &labels, &floors).unwrap();
    let dir = std::env::temp_dir().join(format!("contextosd-calibration-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, serde_json::to_string(&record).unwrap()).unwrap();
    path
}

fn guard(records: Vec<std::path::PathBuf>) -> EvaluatorCalibration {
    EvaluatorCalibration {
        records,
        min_tpr: 0.9,
        min_tnr: 0.9,
        min_per_class: 30,
    }
}

#[test]
fn listed_records_must_meet_the_deployment_floors() {
    let fit = record_file("fit.json", "judge@2", 40, 0);
    assert_eq!(load(Some(&guard(vec![fit.clone()]))).unwrap().unwrap().len(), 1);
    // A judge that misses a third of the failures stops the server.
    let lenient = record_file("lenient.json", "lenient@1", 40, 20);
    let refused = load(Some(&guard(vec![fit.clone(), lenient]))).unwrap_err();
    assert!(refused.contains("lenient@1 is not fit to evaluate: tnr"), "{refused}");
    // Too few labels, two records for one release, no records, a missing file.
    assert!(load(Some(&guard(vec![record_file("small.json", "small@1", 10, 0)]))).is_err());
    assert!(
        load(Some(&guard(vec![fit.clone(), fit])))
            .unwrap_err()
            .contains("two records")
    );
    assert!(load(Some(&guard(Vec::new()))).is_err());
    assert!(load(Some(&guard(vec!["/nonexistent/record.json".into()]))).is_err());
    assert!(load(None).unwrap().is_none());
}

#[tokio::test]
async fn uncalibrated_evaluators_cannot_score_or_evaluate() {
    let fit = record_file("http_fit.json", "evaluator.tool_selection@2", 40, 0);
    let w = world_with(&ALL_CONTROLS, 1, |c| {
        c.guards.evaluator_calibration = Some(guard(vec![fit]));
    })
    .await;
    let admitted: Value = reqwest::Client::new()
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_calibrated", 1200))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let http = executor_client(admitted["executor_generation"].as_u64().unwrap());
    let out: Value = http
        .post(format!("{}/v1/runs/run_calibrated/tool-calls", w.base))
        .bearer_auth("acme-key")
        .json(&tool_call("run_calibrated", "tc_1", 120_000))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let operation = out["report"]["operation_id"].as_str().unwrap();
    let url = format!("{}/v1/runs/run_calibrated/operations/{operation}/evaluations", w.base);
    let evaluate = |evaluator_ref: &str| {
        reqwest::Client::new()
            .post(&url)
            .bearer_auth("judge-key")
            .json(&json!({"evaluator_ref": evaluator_ref, "name": "tool_selection", "label": "pass"}))
            .send()
    };
    let refused = evaluate("evaluator.tool_selection@3").await.unwrap();
    assert_eq!(refused.status(), 403);
    assert_eq!(
        refused.json::<Value>().await.unwrap()["error"]["code"],
        "evaluator_uncalibrated"
    );
    assert_eq!(evaluate("evaluator.tool_selection@2").await.unwrap().status(), 201);

    let recorded: Value = http
        .post(format!("{}/v1/runs/run_calibrated/decisions", w.base))
        .bearer_auth("acme-key")
        .json(
            &json!({"decision_key": "support.refund.execute", "decision_version": "1", "status": "DECIDED",
            "outcome": "refund_issued", "tool_calls": [{"tool_call_id": "tc_1", "operation_id": operation}]}),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let record_id = recorded["record"]["record_id"].as_str().unwrap();
    let scored = reqwest::Client::new()
        .post(format!(
            "{}/v1/runs/run_calibrated/decisions/{record_id}/scores",
            w.base
        ))
        .bearer_auth("judge-key")
        .json(&json!({"evaluator_ref": "evaluator.refund_quality@3", "policy": 1.0, "utility": 0.8, "safety": 1.0}))
        .send()
        .await
        .unwrap();
    assert_eq!(scored.status(), 403);
}
