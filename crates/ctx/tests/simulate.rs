//! `ctx simulate` reads recorded cases under two packs and reports what would change.

use std::path::PathBuf;
use std::process::Command;

use serde_json::{Value, json};

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ctx-simulate-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write(path: &PathBuf, value: &Value) -> String {
    std::fs::write(path, value.to_string()).unwrap();
    path.display().to_string()
}

fn ctx(args: &[&str]) -> (i32, Value) {
    let out = Command::new(env!("CARGO_BIN_EXE_ctx")).args(args).output().unwrap();
    (
        out.status.code().unwrap(),
        serde_json::from_slice(&out.stdout).unwrap_or(Value::Null),
    )
}

/// The compiler vectors' high-value refund case: its pack and a recorded case.
fn fixture() -> (Value, Value) {
    let v: Value = serde_json::from_str(
        &std::fs::read_to_string(format!(
            "{}/../../conformance/vectors/compiler.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap();
    let case = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "grid:support.refund:true:4200:support_agent")
        .unwrap()
        .clone();
    let recorded = json!({"name": "run_high_value", "request": case["request"], "run_context": case["run_context"], "deps": case["deps"]});
    (case["pack"].clone(), recorded)
}

#[test]
fn a_loosened_rule_is_reported_as_a_widening_with_its_verdict_change() {
    let work = dir("loosen");
    let (baseline, recorded) = fixture();
    let mut candidate = baseline.clone();
    candidate["policy_layer"]["policy_bundles"][0]["policy_dsl"]["rules"][1]["then"] = json!({"allow": true});
    let b = write(&work.join("baseline.json"), &baseline);
    let c = write(&work.join("candidate.json"), &candidate);
    // A directory of recorded cases, one file per run.
    let cases = work.join("cases");
    std::fs::create_dir_all(&cases).unwrap();
    write(&cases.join("run_high_value.json"), &recorded);
    let mut other = recorded.clone();
    other["name"] = json!("run_other");
    write(&cases.join("run_other.json"), &json!({"cases": [other]}));
    let md = work.join("report.md");
    let (code, report) = ctx(&[
        "simulate",
        "--baseline",
        &b,
        "--candidate",
        &c,
        "--cases",
        &cases.display().to_string(),
        "--report",
        &md.display().to_string(),
    ]);
    assert_eq!(code, 0, "informational by default: {report}");
    let s = &report["summary"];
    assert_eq!(s["cases"], 2);
    assert_eq!(s["changed"], 2, "{report}");
    assert_eq!(s["widens"], 2, "{report}");
    let transitions = s["verdict_transitions"].as_object().unwrap();
    assert_eq!(transitions.len(), 1, "{report}");
    let (change, n) = transitions.iter().next().unwrap();
    assert!(change.ends_with("-> allow"), "{change}");
    assert_eq!(n, 2);
    assert_eq!(report["cases"][0]["effect"], "widens");
    let text = std::fs::read_to_string(&md).unwrap();
    assert!(text.contains("2 recorded cases, 2 would change: 2 widen"), "{text}");
    assert!(text.contains("| `run_high_value` | widens |"), "{text}");

    let (code, failed) = ctx(&[
        "simulate",
        "--baseline",
        &b,
        "--candidate",
        &c,
        "--cases",
        &cases.display().to_string(),
        "--fail-on-widening",
    ]);
    assert_eq!(code, 1, "{failed}");
    // The same pack changes nothing; narrowing passes the CI switch.
    let (code, same) = ctx(&[
        "simulate",
        "--baseline",
        &b,
        "--candidate",
        &b,
        "--cases",
        &cases.display().to_string(),
        "--fail-on-widening",
    ]);
    assert_eq!(code, 0, "{same}");
    assert_eq!(same["summary"]["changed"], 0);
    let (code, narrowed) = ctx(&[
        "simulate",
        "--baseline",
        &c,
        "--candidate",
        &b,
        "--cases",
        &cases.display().to_string(),
        "--fail-on-widening",
    ]);
    assert_eq!(code, 0, "{narrowed}");
    assert_eq!(narrowed["summary"]["narrows"], 2);
}

#[test]
fn duplicate_or_missing_cases_are_usage_errors() {
    let work = dir("usage");
    let (baseline, recorded) = fixture();
    let b = write(&work.join("baseline.json"), &baseline);
    let twice = write(&work.join("twice.json"), &json!([recorded, recorded]));
    let (code, _) = ctx(&["simulate", "--baseline", &b, "--candidate", &b, "--cases", &twice]);
    assert_eq!(code, 2);
    let empty = write(&work.join("empty.json"), &json!([]));
    let (code, _) = ctx(&["simulate", "--baseline", &b, "--candidate", &b, "--cases", &empty]);
    assert_eq!(code, 2);
}
