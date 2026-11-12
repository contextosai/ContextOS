//! `ctx calibrate` writes a calibration record and exits by fitness.

use std::process::Command;

use serde_json::{Value, json};

fn write(name: &str, value: &Value) -> String {
    let dir = std::env::temp_dir().join(format!("ctx-calibration-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, value.to_string()).unwrap();
    path.display().to_string()
}

fn ctx(args: &[&str]) -> (i32, Value) {
    let out = Command::new(env!("CARGO_BIN_EXE_ctx")).args(args).output().unwrap();
    (
        out.status.code().unwrap(),
        serde_json::from_slice(&out.stdout).unwrap_or(Value::Null),
    )
}

/// `pass` human labels the judge agrees with, and `fail` ones it `misses`.
fn labels(pass: usize, fail: usize, misses: usize) -> Value {
    let mut out = Vec::new();
    for i in 0..pass {
        out.push(json!({"id": format!("p{i}"), "human": "pass", "judge": "pass"}));
    }
    for i in 0..fail {
        let judge = if i < misses { "pass" } else { "fail" };
        out.push(json!({"id": format!("f{i}"), "human": "fail", "judge": judge}));
    }
    Value::Array(out)
}

#[test]
fn calibrate_exits_by_fitness() {
    let floors = write(
        "floors.json",
        &json!({"min_tpr": 0.9, "min_tnr": 0.9, "min_per_class": 30}),
    );
    let good = write("good.json", &labels(50, 50, 2));
    let (code, record) = ctx(&[
        "calibrate",
        "--evaluator-ref",
        "judge@3",
        "--labels",
        &good,
        "--floors",
        &floors,
    ]);
    assert_eq!(code, 0, "{record}");
    assert_eq!(record["verdict"], "fit");
    assert_eq!(record["counts"], json!({"tp": 50, "fn": 0, "tn": 48, "fp": 2}));
    assert_eq!(record["evaluator_ref"], "judge@3");

    let lenient = write("lenient.json", &labels(50, 50, 20));
    let (code, record) = ctx(&[
        "calibrate",
        "--evaluator-ref",
        "judge@4",
        "--labels",
        &lenient,
        "--floors",
        &floors,
    ]);
    assert_eq!(code, 1, "{record}");
    assert_eq!(record["verdict"], "unfit");
    assert_eq!(record["shortfalls"], json!(["tnr 0.6000 < 0.9"]));
}
