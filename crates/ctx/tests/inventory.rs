//! `ctx inventory` lists what a verified audit export shows, and nothing from one that
//! does not verify.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ctx-inventory-{}-{name}", std::process::id()));
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

fn traffic() -> Vec<(&'static str, Value)> {
    vec![
        (
            "run_admitted",
            json!({"run_id": "r1", "agent_id": "agt_support", "trace_id": "t1", "pack_ref": "ctxpack.support@5.2.0",
                "release_refs": [{"artifact_type": "model_profile", "artifact_id": "claude-opus-5-5", "version": "1"}],
                "surfaced_capabilities": ["adp_payments.issue_refund"]}),
        ),
        (
            "operation_claim",
            json!({"run_id": "r1", "operation_id": "op", "attempt_id": "a1", "capability_id": "adp_payments.issue_refund"}),
        ),
        (
            "revocation_refusal",
            json!({"run_id": "r1", "capability_id": "crm.delete_customer", "reason_codes": ["capability_not_pinned"]}),
        ),
    ]
}

fn row<'a>(report: &'a Value, kind: &str, id: &str) -> &'a Value {
    report["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["kind"] == kind && i["id"] == id)
        .unwrap_or_else(|| panic!("no {kind} {id} in {report}"))
}

#[test]
fn a_verified_export_lists_what_ran_and_marks_the_shadow_rows() {
    let work = dir("verified");
    let (chain, keys) = signed_chain(&traffic());
    let entries = write(&work, "export.json", &json!({"entries": chain}));
    let keys = write(&work, "keys.json", &keys);
    let declarations = write(
        &work,
        "declarations.json",
        &json!({"acme/agt_support": {"owner": "ana", "team": "payments", "purpose": "refunds",
            "users_served": "customers", "lifecycle": "production", "risk_tier": "high"}}),
    );
    let csv = work.join("inventory.csv");
    let (code, report) = ctx(&[
        "inventory",
        "--entries",
        &entries,
        "--keys",
        &keys,
        "--environment",
        "production",
        "--declarations",
        &declarations,
        "--csv",
        &csv.display().to_string(),
    ]);
    assert_eq!(code, 0, "{report}");
    assert_eq!(report["verified_to"], 3);
    let agent = row(&report, "agent", "acme/agt_support");
    assert_eq!(agent["declared"], true);
    assert_eq!(agent["risk_tier"], "high");
    assert_eq!(agent["environments"], json!(["production"]));
    assert_eq!(
        row(&report, "capability", "adp_payments.issue_refund")["declared"],
        true
    );
    let shadow = row(&report, "capability", "crm.delete_customer");
    assert_eq!(shadow["declared"], false);
    assert_eq!(shadow["first_seen"], "2026-10-20T10:00:02Z");
    assert_eq!(row(&report, "model", "claude-opus-5-5@1")["declared"], false);
    // The undeclared model, the unpinned capability and its adapter.
    assert_eq!(report["shadow"], 3, "{report}");
    let text = std::fs::read_to_string(&csv).unwrap();
    assert!(text.starts_with("kind,id,declared,"), "{text}");
    assert!(text.contains("capability,crm.delete_customer,false,"), "{text}");
}

#[test]
fn an_export_that_does_not_verify_lists_nothing() {
    let work = dir("tampered");
    let (mut chain, keys) = signed_chain(&traffic());
    chain[1]["payload"]["capability_id"] = json!("adp_payments.transfer");
    let entries = write(&work, "export.json", &json!({"entries": chain}));
    let keys = write(&work, "keys.json", &keys);
    let csv = work.join("inventory.csv");
    let (code, report) = ctx(&[
        "inventory",
        "--entries",
        &entries,
        "--keys",
        &keys,
        "--csv",
        &csv.display().to_string(),
    ]);
    assert_eq!(code, 1, "{report}");
    assert_eq!(report["verified"], false);
    assert!(report.get("items").is_none());
    assert!(!csv.exists());
}
