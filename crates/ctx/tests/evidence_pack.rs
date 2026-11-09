//! `ctx evidence-pack` builds a self-checking review folder only from a chain that
//! verifies, and its control map names only events the runtime emits.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ctx-evidence-{}-{name}", std::process::id()));
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

/// A signed chain with one entry per kind, and the keys that verify it.
fn signed_chain(kinds: &[&str]) -> (Vec<Value>, Value) {
    use base64::Engine as _;
    use contextos_store::AppendLog as _;
    let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
    runtime.block_on(async {
        let signer = contextos_audit::AuditSigner::from_seed("audit-test", [7; 32]);
        let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signer.verifying_key().as_bytes());
        let log = std::sync::Arc::new(contextos_store::MemoryLog::new());
        let writer = contextos_audit::AuditWriter::new(log.clone(), signer);
        for (i, kind) in kinds.iter().enumerate() {
            writer
                .append(
                    "tenant_a",
                    kind,
                    json!({"step": i}),
                    &format!("2026-10-20T10:00:{i:02}Z"),
                )
                .await
                .unwrap();
        }
        let rows = log.range("tenant_a", 1, 100).await.unwrap();
        (
            rows.into_iter().map(|r| r.body).collect(),
            json!({"keys": [{"kid": "audit-test", "alg": "ed25519", "public_key": key}]}),
        )
    })
}

#[test]
fn a_verified_export_becomes_a_pack_that_checks_itself() {
    let work = dir("ok");
    let (chain, keys) = signed_chain(&[
        "run_admitted",
        "authorization_decision",
        "approval_requested",
        "approval_redeemed",
        "approval_timed_out",
        "effect_observation",
    ]);
    let entries = write(&work, "export.json", &json!({"entries": chain}));
    let keys = write(&work, "keys.json", &keys);
    let report = write(&work, "check.json", &json!({"ok": true}));
    let out = work.join("pack");
    let out_text = out.display().to_string();
    let args = [
        "evidence-pack",
        "--entries",
        &entries,
        "--keys",
        &keys,
        "--framework",
        "eu-ai-act",
        "--framework",
        "soc2",
        "--config-report",
        &report,
        "--out",
        &out_text,
    ];
    let (code, summary) = ctx(&args);
    assert_eq!(code, 0, "{summary}");
    assert_eq!(summary["period"]["entries"], 6);

    let read = |name: &str| std::fs::read(out.join(name)).unwrap();
    let manifest: Value = serde_json::from_slice(&read("manifest.json")).unwrap();
    assert_eq!(manifest["pack_version"], "contextos.evidence_pack.v1");
    assert_eq!(manifest["verification"]["verified"], true);
    // Every file the manifest lists is in the pack with that digest.
    for (name, digest) in manifest["files"].as_object().unwrap() {
        use sha2::Digest as _;
        let actual = format!("sha256:{}", hex::encode(sha2::Sha256::digest(read(name))));
        assert_eq!(digest.as_str().unwrap(), actual, "{name}");
    }
    // The export in the pack re-verifies as it is.
    let (code, again) = ctx(&[
        "audit-verify",
        "--entries",
        &out.join("entries.json").display().to_string(),
        "--keys",
        &out.join("keys.json").display().to_string(),
    ]);
    assert_eq!(code, 0, "{again}");

    let controls: Value = serde_json::from_slice(&read("controls.json")).unwrap();
    let find = |framework: &str, id: &str| -> Value {
        controls["frameworks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["framework"] == framework)
            .unwrap()["controls"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == id)
            .unwrap()
            .clone()
    };
    let oversight = find("eu-ai-act", "Art. 14(4)(b)");
    assert_eq!(oversight["status"], "evidenced");
    assert_eq!(oversight["observed"]["approval_timed_out"], 1);
    assert_eq!(oversight["observed"]["approval_review_too_fast"], 0);
    assert_eq!(find("eu-ai-act", "Art. 14(4)(e)")["status"], "no_events_in_period");
    assert_eq!(find("soc2", "CC1-CC5")["status"], "outside_audit");

    let coverage = String::from_utf8(read("coverage.md")).unwrap();
    assert!(coverage.contains("## What it does not cover"), "{coverage}");
    assert!(coverage.contains("bypasses the gateway"), "{coverage}");
    assert!(coverage.contains("config-report.json"), "{coverage}");

    // Deterministic: the same export gives the same pack.
    let again = work.join("pack2");
    let mut args2 = args;
    let again_text = again.display().to_string();
    args2[12] = &again_text;
    assert_eq!(ctx(&args2).0, 0);
    for name in ["manifest.json", "controls.json", "coverage.md"] {
        assert_eq!(read(name), std::fs::read(again.join(name)).unwrap(), "{name}");
    }
    // A pack is never written over another.
    assert_eq!(ctx(&args).0, 2);
}

#[test]
fn a_chain_that_does_not_verify_builds_no_pack() {
    let work = dir("tampered");
    let (mut chain, keys) = signed_chain(&["run_admitted", "authorization_decision"]);
    chain[1]["payload"]["step"] = json!(99);
    let entries = write(&work, "export.json", &json!({"entries": chain}));
    let keys = write(&work, "keys.json", &keys);
    let out = work.join("pack");
    let (code, report) = ctx(&[
        "evidence-pack",
        "--entries",
        &entries,
        "--keys",
        &keys,
        "--framework",
        "iso42001",
        "--out",
        &out.display().to_string(),
    ]);
    assert_eq!(code, 1, "{report}");
    assert_eq!(report["verified"], false);
    assert!(!out.exists());
    let (code, _) = ctx(&[
        "evidence-pack",
        "--entries",
        &entries,
        "--keys",
        &keys,
        "--framework",
        "hipaa",
        "--out",
        &out.display().to_string(),
    ]);
    assert_eq!(code, 2);
}

/// Every event kind the control map cites is one the runtime writes: named as a string
/// literal in the gateway's or the daemon's source.
#[test]
fn the_control_map_cites_only_events_the_runtime_emits() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut source = String::new();
    for crate_dir in ["crates/contextos-gateway/src", "crates/contextosd/src"] {
        let mut stack = vec![root.join(crate_dir)];
        while let Some(path) = stack.pop() {
            for entry in std::fs::read_dir(&path).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    source.push_str(&std::fs::read_to_string(&path).unwrap());
                }
            }
        }
    }
    let map: Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("crates/ctx/src/evidence_controls.json")).unwrap())
            .unwrap();
    let frameworks = map["frameworks"].as_object().unwrap();
    assert_eq!(frameworks.len(), 4);
    for (name, framework) in frameworks {
        for control in framework["controls"].as_array().unwrap() {
            for kind in control["events"].as_array().unwrap() {
                let kind = kind.as_str().unwrap();
                assert!(
                    source.contains(&format!("\"{kind}\"")),
                    "{name} {}: {kind} is not an event the runtime writes",
                    control["id"]
                );
            }
            if control["events"].as_array().unwrap().is_empty() {
                assert!(control["note"].is_string(), "{name} {}: say why", control["id"]);
            }
        }
    }
}
