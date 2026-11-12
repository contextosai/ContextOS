//! `ctx trials` turns run evidence into trials and `ctx reliability-gate` gates on them.

use std::process::Command;

use serde_json::{Value, json};

fn write(name: &str, value: &Value) -> String {
    let dir = std::env::temp_dir().join(format!("ctx-reliability-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, value.to_string()).unwrap();
    path.display().to_string()
}

fn ctx(args: &[&str]) -> (i32, Value) {
    let out = Command::new(env!("CARGO_BIN_EXE_ctx")).args(args).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    (
        out.status.code().unwrap(),
        serde_json::from_str(&stdout).unwrap_or_else(|_| json!(String::from_utf8_lossy(&out.stderr))),
    )
}

/// A run's evidence bundle: its status, one outcome's state, one score's safety.
fn bundle(run: &str, status: &str, outcome: &str, safety: f64, calls: u64) -> Value {
    json!({"evidence_version": "contextos-rs.run_evidence.v1", "run_id": run,
        "run_state": {"status": status},
        "budget_ledger": {"used": {"tool_calls": calls}},
        "outcomes": [{"operation_id": format!("{run}-op"), "state": outcome}],
        "decisions": [{"record": {}, "scores": [{"score": {"evaluator_ref": "judge@1",
            "scorecard": {"policy": 1.0, "utility": 0.9, "safety": safety}}}]}]})
}

#[test]
fn trials_fail_on_status_unwitnessed_outcomes_and_scores() {
    let runs = [
        bundle("r1", "completed", "witnessed", 1.0, 3),
        bundle("r2", "failed", "witnessed", 1.0, 3),
        bundle("r3", "completed", "missed", 1.0, 3),
        bundle("r4", "completed", "witnessed", 0.5, 3),
    ];
    let paths: Vec<String> = runs
        .iter()
        .enumerate()
        .map(|(i, b)| write(&format!("t{i}.json"), b))
        .collect();
    let map = write(
        "t_map.json",
        &json!({"r1": "refund", "r2": "refund", "r3": "refund", "r4": "refund"}),
    );
    let criteria = write("t_criteria.json", &json!({"safety_floor": 0.9}));
    let mut args = vec!["trials", "--case-map", &map, "--criteria", &criteria];
    args.extend(paths.iter().map(String::as_str));
    let (code, out) = ctx(&args);
    assert_eq!(code, 0, "{out}");
    let trials = out[0]["trials"].as_array().unwrap();
    assert_eq!(out[0]["case"], "refund");
    let passed: Vec<bool> = trials.iter().map(|t| t["passed"].as_bool().unwrap()).collect();
    assert_eq!(passed, [true, false, false, false]);
    assert_eq!(trials[1]["reasons"][0], "run failed");
    assert_eq!(trials[2]["reasons"][0], "outcome of r3-op missed");
    assert_eq!(trials[3]["reasons"][0], "judge@1: safety 0.5 < 0.9");
    assert_eq!(trials[0]["steps"], 3);
}

#[test]
fn the_gate_exits_by_verdict() {
    let suite = |passes: usize| {
        json!(
            ["a", "b", "c"]
                .iter()
                .map(|case| json!({"case": case,
            "trials": (0..3).map(|i| json!({"passed": i < passes, "steps": 2})).collect::<Vec<_>>()}))
                .collect::<Vec<_>>()
        )
    };
    let base = write("g_base.json", &suite(3));
    let worse = write("g_worse.json", &suite(2));
    let limits = write(
        "g_limits.json",
        &json!({"k": 3, "max_pass_k_drop": 0.05, "min_cases": 3}),
    );
    let (code, report) = ctx(&[
        "reliability-gate",
        "--baseline",
        &base,
        "--candidate",
        &base,
        "--thresholds",
        &limits,
    ]);
    assert_eq!(code, 0, "{report}");
    assert_eq!(report["candidate"]["pass_k"], 1.0);
    let (code, report) = ctx(&[
        "reliability-gate",
        "--baseline",
        &base,
        "--candidate",
        &worse,
        "--thresholds",
        &limits,
    ]);
    assert_eq!(code, 1, "{report}");
    assert_eq!(report["failures"][0]["kind"], "regression");
    assert_eq!(report["candidate"]["pass_at_k"], 1.0);
}
