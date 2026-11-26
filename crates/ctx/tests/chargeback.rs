//! `ctx chargeback` bills from a verified audit export, keeping measured and
//! self-reported usage apart, and from nothing that does not verify.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ctx-chargeback-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write(dir: &Path, name: &str, value: &Value) -> String {
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

/// A signed chain of `(kind, payload)` entries, and the keys that verify it.
fn signed_chain(entries: &[(&str, Value)]) -> (Vec<Value>, Value) {
    use base64::Engine as _;
    use contextos_store::AppendLog as _;
    let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
    runtime.block_on(async {
        let signer = contextos_audit::AuditSigner::from_seed("audit-test", [7; 32]);
        let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signer.verifying_key().as_bytes());
        let log = std::sync::Arc::new(contextos_store::MemoryLog::new());
        let writer = contextos_audit::AuditWriter::new(log.clone(), signer);
        for (i, (kind, payload)) in entries.iter().enumerate() {
            writer
                .append("acme", kind, payload.clone(), &format!("2026-10-20T10:00:{i:02}Z"))
                .await
                .unwrap();
        }
        let rows = log.range("acme", 1, 100).await.unwrap();
        (
            rows.into_iter().map(|r| r.body).collect(),
            json!({"keys": [{"kid": "audit-test", "alg": "ed25519", "public_key": key}]}),
        )
    })
}

fn settled(run: &str, verified: bool, tokens: u64, cost_units: u64) -> (&'static str, Value) {
    (
        "usage_settled",
        json!({"run_id": run, "reservation_id": format!("usage:{run}:{tokens}"), "reporter": "meter",
            "verified": verified, "model": "claude-sonnet-5-5",
            "charged": {"tokens": tokens, "cost_units": cost_units, "tool_calls": 0, "replans": 0}}),
    )
}

fn traffic() -> Vec<(&'static str, Value)> {
    vec![
        (
            "run_admitted",
            json!({"run_id": "r1", "agent_id": "agt_support", "trace_id": "t1"}),
        ),
        (
            "run_admitted",
            json!({"run_id": "r2", "agent_id": "agt_triage", "trace_id": "t2"}),
        ),
        settled("r1", true, 1_000, 30_000),
        settled("r1", false, 500, 10_000),
        settled("r2", true, 2_000, 5_000),
    ]
}

#[test]
fn a_verified_export_bills_by_team_with_measured_usage_apart() {
    let work = dir("verified");
    let (chain, keys) = signed_chain(&traffic());
    let entries = write(&work, "export.json", &json!({"entries": chain}));
    let keys = write(&work, "keys.json", &keys);
    let declarations = write(
        &work,
        "declarations.json",
        &json!({"acme/agt_support": {"owner": "ana", "team": "payments", "business_unit": "=cmd()"},
            "acme/agt_triage": {"owner": "raj", "team": "support"}}),
    );
    let csv = work.join("chargeback.csv");
    let csv_arg = csv.display().to_string();
    let (code, report) = ctx(&[
        "chargeback",
        "--entries",
        &entries,
        "--keys",
        &keys,
        "--declarations",
        &declarations,
        "--csv",
        &csv_arg,
    ]);
    assert_eq!(code, 0, "{report}");
    assert_eq!(report["verified_to"], 5);
    assert_eq!(report["totals"]["cost_units"], 45_000);
    let rows = report["rows"].as_array().unwrap();
    assert_eq!(rows[0]["key"], "payments", "ranked by spend: {report}");
    assert_eq!(rows[0]["usage"]["verified_cost_units"], 30_000);
    assert_eq!(rows[0]["usage"]["self_reported_cost_units"], 10_000);
    assert_eq!(rows[1]["key"], "support");
    let text = std::fs::read_to_string(&csv).unwrap();
    assert!(text.starts_with("team,agents,calls,tokens,cost,"), "{text}");
    assert!(
        text.contains("\"payments\",1,2,1500,\"$4.00\",40000,1000,30000,500,10000,"),
        "{text}"
    );

    let (code, by_unit) = ctx(&[
        "chargeback",
        "--entries",
        &entries,
        "--keys",
        &keys,
        "--declarations",
        &declarations,
        "--group",
        "business_unit",
        "--csv",
        &csv_arg,
    ]);
    assert_eq!(code, 0, "{by_unit}");
    assert_eq!(by_unit["rows"][1]["key"], "(undeclared)");
    let text = std::fs::read_to_string(&csv).unwrap();
    assert!(text.contains("\"'=cmd()\""), "a formula is never written live: {text}");
    let (code, _) = ctx(&[
        "chargeback",
        "--entries",
        &entries,
        "--keys",
        &keys,
        "--group",
        "planet",
    ]);
    assert_ne!(code, 0);
}

#[test]
fn an_export_that_does_not_verify_bills_nothing() {
    let work = dir("tampered");
    let (mut chain, keys) = signed_chain(&traffic());
    chain[2]["payload"]["charged"]["cost_units"] = json!(1);
    let entries = write(&work, "export.json", &json!({"entries": chain}));
    let keys = write(&work, "keys.json", &keys);
    let csv = work.join("chargeback.csv");
    let (code, report) = ctx(&[
        "chargeback",
        "--entries",
        &entries,
        "--keys",
        &keys,
        "--csv",
        &csv.display().to_string(),
    ]);
    assert_eq!(code, 1, "{report}");
    assert_eq!(report["verified"], false);
    assert!(report.get("rows").is_none());
    assert!(!csv.exists());
}
