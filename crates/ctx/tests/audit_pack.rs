//! `ctx audit-pack` builds one signed folder from a verified export, and its own
//! `verify.py` (standard-library Python) checks the signature and every file.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

const SEED: &str = "2727272727272727272727272727272727272727272727272727272727272727";

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ctx-audit-pack-{}-{name}", std::process::id()));
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
    let out = Command::new(env!("CARGO_BIN_EXE_ctx"))
        .args(args)
        .env("CONTEXTOS_AUDIT_PACK_SEED", SEED)
        .output()
        .unwrap();
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

fn pack() -> Value {
    let path = format!("{}/../../conformance/vectors/compiler.json", env!("CARGO_MANIFEST_DIR"));
    let vectors: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "grid:support.refund:true:4200:support_agent")
        .unwrap()["pack"]
        .clone()
}

fn verify(pack: &Path, key: &str) -> (i32, String) {
    let out = Command::new("python3")
        .arg(pack.join("verify.py"))
        .args(["--public-key", key])
        .output()
        .unwrap();
    (
        out.status.code().unwrap(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
fn an_audit_pack_is_signed_and_verifies_itself() {
    let work = dir("signed");
    let (chain, keys) = signed_chain(&[
        (
            "run_admitted",
            json!({"run_id": "r1", "agent_id": "agt_support", "trace_id": "t1"}),
        ),
        (
            "approval_requested",
            json!({"run_id": "r1", "approval_id": "ap1", "capability_id": "adp_payments.issue_refund"}),
        ),
        (
            "approval_redeemed",
            json!({"run_id": "r1", "approval_id": "ap1", "approver": "maya"}),
        ),
    ]);
    let entries = write(&work, "export.json", &json!({"entries": chain}));
    let keys = write(&work, "keys.json", &keys);
    let pack_file = write(&work, "support.json", &pack());
    std::fs::write(work.join("contextosd.toml"), "[server]\nlisten = \"127.0.0.1:8080\"\n").unwrap();
    let config = work.join("contextosd.toml").display().to_string();
    let out = work.join("audit-pack");
    let (code, report) = ctx(&[
        "audit-pack",
        "--entries",
        &entries,
        "--keys",
        &keys,
        "--framework",
        "soc2",
        "--pack",
        &pack_file,
        "--config",
        &config,
        "--kid",
        "audit-2026",
        "--out",
        &out.display().to_string(),
    ]);
    assert_eq!(code, 0, "{report}");
    let key = report["public_key"].as_str().unwrap().to_owned();
    for file in [
        "evidence/entries.json",
        "evidence/coverage.md",
        "inventory.json",
        "inventory.csv",
        "approvals.json",
        "packs/support.json",
        "packs.json",
        "config.json",
        "verify.py",
        "manifest.json",
        "manifest.sig",
    ] {
        assert!(out.join(file).is_file(), "{file}");
    }
    let approvals: Value = serde_json::from_slice(&std::fs::read(out.join("approvals.json")).unwrap()).unwrap();
    assert_eq!(approvals["approvals"].as_array().unwrap().len(), 2);
    let config_digest = std::fs::read_to_string(out.join("config.json")).unwrap();
    assert!(!config_digest.contains("127.0.0.1"), "only the digest: {config_digest}");

    let (code, said) = verify(&out, &key);
    assert_eq!(code, 0, "{said}");
    assert!(said.starts_with("VERIFIED"), "{said}");
    // Another key, even the one written in manifest.sig by someone else, is not trusted.
    let (code, said) = verify(&out, "7Td1UHAz8eQ1ycw94aNaBMR8-l8vg9MskJ4BkSc1h0k");
    assert_eq!(code, 1, "{said}");
    // Any changed file is found.
    std::fs::write(out.join("approvals.json"), "{}").unwrap();
    let (code, said) = verify(&out, &key);
    assert_eq!(code, 1, "{said}");
    assert!(said.contains("approvals.json: changed"), "{said}");
    std::fs::remove_dir_all(work).ok();
}

#[test]
fn an_audit_pack_needs_a_verified_export_and_a_seed() {
    let work = dir("refused");
    let (mut chain, keys) = signed_chain(&[(
        "run_admitted",
        json!({"run_id": "r1", "agent_id": "a", "trace_id": "t"}),
    )]);
    chain[0]["payload"]["agent_id"] = json!("b");
    let entries = write(&work, "export.json", &json!({"entries": chain}));
    let keys = write(&work, "keys.json", &keys);
    let out = work.join("pack").display().to_string();
    let (code, report) = ctx(&[
        "audit-pack",
        "--entries",
        &entries,
        "--keys",
        &keys,
        "--framework",
        "soc2",
        "--kid",
        "k",
        "--out",
        &out,
    ]);
    assert_eq!(code, 1, "{report}");
    assert_eq!(report["verified"], false);
    let unset = Command::new(env!("CARGO_BIN_EXE_ctx"))
        .args([
            "audit-pack",
            "--entries",
            &entries,
            "--keys",
            &keys,
            "--framework",
            "soc2",
            "--kid",
            "k",
            "--out",
            &out,
        ])
        .env_remove("CONTEXTOS_AUDIT_PACK_SEED")
        .output()
        .unwrap();
    assert_ne!(unset.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&unset.stderr).contains("CONTEXTOS_AUDIT_PACK_SEED"));
    std::fs::remove_dir_all(work).ok();
}
