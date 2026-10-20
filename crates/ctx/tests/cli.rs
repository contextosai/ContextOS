//! `ctx` behaves as documented, including exit codes.

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

fn vectors() -> Value {
    serde_json::from_str(
        &std::fs::read_to_string(format!(
            "{}/../../conformance/vectors/compiler.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap()
}

fn write(name: &str, value: &Value) -> String {
    let dir = std::env::temp_dir().join(format!("ctx-cli-{}", std::process::id()));
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

#[test]
fn compile_matches_reference_hash() {
    let v = vectors();
    let case = &v["cases"][0];
    let pack = write("pack.json", &case["pack"]);
    let request = write("request.json", &case["request"]);
    let run = write("run.json", &case["run_context"]);
    let deps = write("deps.json", &case["deps"]);
    let (code, compiled) = ctx(&[
        "compile",
        "--pack",
        &pack,
        "--request",
        &request,
        "--run-context",
        &run,
        "--deps",
        &deps,
    ]);
    assert_eq!(code, 0);
    assert_eq!(
        compiled["context_ledger"]["compiled_context_hash"],
        case["expected"]["context_ledger"]["compiled_context_hash"]
    );
    assert_eq!(ctx(&["validate", "context-pack", &pack]).0, 0);
}

#[test]
fn validation_and_negotiation_failures_exit_1() {
    let bad = write(
        "bad_ref.json",
        &json!({"control_id": "x", "control_version": "1", "extra": true}),
    );
    let (code, out) = ctx(&["validate", "execution-contract", "--def", "ControlRef", &bad]);
    assert_eq!((code, out["valid"].clone()), (1, json!(false)));
    let contract = write(
        "contract.json",
        &json!({"envelope_version": "contextos.execution_contract.v1", "contract_id": "c", "run_id": "r",
        "trace_id": "t", "tenant_id": "x", "profiles": [{"profile_id": "contextos.core", "profile_version": "1"}],
        "required_controls": [], "optional_controls": [], "release_refs": []}),
    );
    let support = write(
        "support.json",
        &json!({"implementation_id": "i", "implementation_version": "1",
        "supported_profiles": [{"profile_id": "contextos.core", "profile_version": "1"}], "supported_controls": []}),
    );
    let features = write(
        "features.json",
        &json!({"arbitrary_code": false, "external_network": false, "persistent_memory": false,
        "external_effects": false, "delegation": false, "checkpoint_resume": false, "proactive_triggers": false, "sensitive_data": false}),
    );
    let (code, out) = ctx(&[
        "negotiate",
        "--contract",
        &contract,
        "--support",
        &support,
        "--features",
        &features,
    ]);
    assert_eq!(code, 1);
    assert_eq!(out["status"], "rejected");
}

#[test]
fn usage_errors_exit_2_and_duplicate_keys_are_refused() {
    let dup = std::env::temp_dir().join(format!("ctx-dup-{}.json", std::process::id()));
    std::fs::write(&dup, r#"{"a":1,"a":2}"#).unwrap();
    assert_eq!(ctx(&["validate", "context-pack", dup.to_str().unwrap()]).0, 2);
    assert_eq!(ctx(&["validate", "no-such-schema", dup.to_str().unwrap()]).0, 2);
}

#[test]
fn hash_key_reads_stdin() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ctx"))
        .arg("hash-key")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"0123456789abcdef0123456789abcdef\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let value: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        value["key_sha256"],
        "sha256:3eb1bd439947eb762998e566ccc2e099c791118b2f40579cc4f7da2b5061b7f9"
    );
}
