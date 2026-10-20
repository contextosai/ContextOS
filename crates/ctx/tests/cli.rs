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

#[test]
fn release_gate_fails_unacknowledged_widenings() {
    let v = vectors();
    let case = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "grid:support.refund:true:4200:support_agent")
        .unwrap();
    let baseline = case["pack"].clone();
    let mut candidate = baseline.clone();
    candidate["policy_layer"]["policy_bundles"][0]["policy_dsl"]["rules"][1]["then"] =
        serde_json::json!({"allow": true});
    let cases = serde_json::json!([{"name": "high_value", "request": case["request"], "run_context": case["run_context"], "deps": case["deps"]}]);
    let (b, c, k) = (
        write("gate_baseline.json", &baseline),
        write("gate_candidate.json", &candidate),
        write("gate_cases.json", &cases),
    );
    let (code, report) = ctx(&["gate", "--baseline", &b, "--candidate", &c, "--cases", &k]);
    assert_eq!(code, 1, "{report}");
    assert_eq!(report["verdict"], "fail");
    let ack = write(
        "gate_ack.json",
        &serde_json::json!({"policy_loosening": ["high_value"]}),
    );
    let (code, report) = ctx(&[
        "gate",
        "--baseline",
        &b,
        "--candidate",
        &c,
        "--cases",
        &k,
        "--acknowledge",
        &ack,
    ]);
    assert_eq!(code, 0, "{report}");
    let (code, _) = ctx(&["gate", "--baseline", &b, "--candidate", &b, "--cases", &k]);
    assert_eq!(code, 0, "an unchanged pack passes");
}

#[test]
fn scorecard_gate_exits_by_verdict() {
    let card = |safety: f64| serde_json::json!({"policy": 1.0, "utility": 0.8, "safety": safety, "cost": 1.0});
    let baseline = write(
        "sc_baseline.json",
        &serde_json::json!([{"case": "a", "scorecards": [card(1.0)]}]),
    );
    let worse = write(
        "sc_worse.json",
        &serde_json::json!([{"case": "a", "scorecards": [card(0.5)]}]),
    );
    let limits = write(
        "sc_limits.json",
        &serde_json::json!({"policy_floor": 1.0, "safety_floor": 0.9, "max_utility_drop": 0.0, "min_cases": 1}),
    );
    let (code, report) = ctx(&[
        "scorecard-gate",
        "--baseline",
        &baseline,
        "--candidate",
        &baseline,
        "--thresholds",
        &limits,
    ]);
    assert_eq!(code, 0, "{report}");
    let (code, report) = ctx(&[
        "scorecard-gate",
        "--baseline",
        &baseline,
        "--candidate",
        &worse,
        "--thresholds",
        &limits,
    ]);
    assert_eq!(code, 1, "{report}");
    assert_eq!(report["failures"][0]["kind"], "floor");
}

#[test]
fn scorecards_are_collected_from_evidence_and_feed_the_gate() {
    let bundle = |run: &str, safety: f64| {
        serde_json::json!({"evidence_version": "contextos-rs.run_evidence.v1", "run_id": run, "decisions": [
            {"record": {}, "replay_packet": {}, "scores": [{"score": {"scorecard":
                {"policy": 1.0, "utility": 0.8, "safety": safety, "cost": 1.0, "latency": 120}}, "audit_sequence": 9}]}]})
    };
    let base = write("ev_base.json", &bundle("run_base_1", 1.0));
    let cand = write("ev_cand.json", &bundle("run_cand_1", 0.5));
    let map = write(
        "ev_map.json",
        &serde_json::json!({"run_base_1": "refund_small", "run_cand_1": "refund_small"}),
    );
    let (code, baseline) = ctx(&["scorecards", &base, "--case-map", &map]);
    assert_eq!(code, 0, "{baseline}");
    assert_eq!(baseline[0]["case"], "refund_small");
    assert_eq!(baseline[0]["scorecards"][0]["safety"], 1.0);
    let (_, candidate) = ctx(&["scorecards", &cand, "--case-map", &map]);
    let (b, c) = (
        write("sc_from_ev_b.json", &baseline),
        write("sc_from_ev_c.json", &candidate),
    );
    let limits = write(
        "sc_from_ev_limits.json",
        &serde_json::json!({"policy_floor": 1.0, "safety_floor": 0.9, "max_utility_drop": 0.0, "min_cases": 1}),
    );
    let (code, report) = ctx(&[
        "scorecard-gate",
        "--baseline",
        &b,
        "--candidate",
        &c,
        "--thresholds",
        &limits,
    ]);
    assert_eq!(code, 1, "{report}");
    assert_eq!(report["failures"][0]["kind"], "floor");
}

/// A real signed chain of `n` entries and the keys file `GET /v1/audit/keys` would serve.
fn signed_chain(n: u64) -> (Vec<serde_json::Value>, serde_json::Value) {
    use base64::Engine as _;
    use contextos_store::AppendLog as _;
    let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
    runtime.block_on(async {
        let signer = contextos_audit::AuditSigner::from_seed("audit-test", [7; 32]);
        let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signer.verifying_key().as_bytes());
        let log = std::sync::Arc::new(contextos_store::MemoryLog::new());
        let writer = contextos_audit::AuditWriter::new(log.clone(), signer);
        for i in 0..n {
            writer
                .append(
                    "tenant_a",
                    "tool_call",
                    serde_json::json!({"step": i}),
                    &format!("2026-10-20T10:00:0{i}Z"),
                )
                .await
                .unwrap();
        }
        let rows = log.range("tenant_a", 1, 100).await.unwrap();
        (
            rows.into_iter().map(|r| r.body).collect(),
            serde_json::json!({"keys": [{"kid": "audit-test", "alg": "ed25519", "public_key": key}]}),
        )
    })
}

#[test]
fn exported_audit_chains_verify_offline_and_tampering_is_caught() {
    let (chain, keys) = signed_chain(5);
    let k = write("audit_keys.json", &keys);
    let verify = |name: &str, entries: serde_json::Value| {
        ctx(&["audit-verify", "--entries", &write(name, &entries), "--keys", &k])
    };
    let (code, report) = verify("audit_ok.json", serde_json::json!({"entries": chain}));
    assert_eq!(code, 0, "{report}");
    assert_eq!(
        (report["entries"].as_u64(), report["last_sequence"].as_u64()),
        (Some(5), Some(5))
    );

    let mut edited = chain.clone();
    edited[2]["payload"]["step"] = serde_json::json!(99);
    let (code, report) = verify("audit_edited.json", serde_json::json!(edited));
    assert_eq!(code, 1);
    assert!(report["error"].as_str().unwrap().contains("payload digest"), "{report}");

    let mut deleted = chain.clone();
    deleted.remove(2);
    let (code, report) = verify("audit_deleted.json", serde_json::json!(deleted));
    assert_eq!(code, 1, "{report}");

    let mut reordered = chain.clone();
    reordered.swap(1, 3);
    assert_eq!(verify("audit_reordered.json", serde_json::json!(reordered)).0, 1);

    let mut other_keys = keys.clone();
    other_keys["keys"][0]["public_key"] = serde_json::json!("A".repeat(43));
    let untrusted = ctx(&[
        "audit-verify",
        "--entries",
        &write("audit_ok2.json", &serde_json::json!(chain)),
        "--keys",
        &write("audit_wrong_keys.json", &other_keys),
    ]);
    assert_ne!(untrusted.0, 0, "a chain signed by an untrusted key does not verify");
}

#[test]
fn audit_exports_verify_incrementally_from_a_trusted_head() {
    let (chain, keys) = signed_chain(6);
    let k = write("inc_keys.json", &keys);
    let (first, rest) = chain.split_at(3);
    let run = |entries: &[serde_json::Value], anchor: Option<&serde_json::Value>, name: &str| {
        let e = write(&format!("inc_{name}_entries.json"), &serde_json::json!(entries));
        let mut args = vec![
            "audit-verify".to_owned(),
            "--entries".into(),
            e,
            "--keys".into(),
            k.clone(),
        ];
        if let Some(anchor) = anchor {
            args.extend(["--continues".into(), write(&format!("inc_{name}_anchor.json"), anchor)]);
        }
        ctx(&args.iter().map(String::as_str).collect::<Vec<_>>())
    };
    assert_eq!(run(first, None, "first").0, 0);
    // Only the new entries are checked, continuing the head verified before.
    let (code, report) = run(rest, Some(&first[2]), "next");
    assert_eq!(code, 0, "{report}");
    assert_eq!(report["last_sequence"], 6);
    // A segment that does not continue that head exactly is refused.
    assert_eq!(run(rest, Some(&first[1]), "gap").0, 1, "a skipped entry");
    assert_eq!(run(rest, None, "headless").0, 1, "not genesis and no trusted head");
}

#[test]
fn audit_verify_refuses_empty_chains_and_malformed_keys() {
    let (chain, keys) = signed_chain(2);
    let k = write("strict_keys.json", &keys);
    let (code, report) = ctx(&[
        "audit-verify",
        "--entries",
        &write("strict_empty.json", &serde_json::json!([])),
        "--keys",
        &k,
    ]);
    assert_eq!(code, 1, "an empty export proves nothing: {report}");
    let e = write("strict_entries.json", &serde_json::json!(chain));
    for (name, bad) in [
        ("null_retired", {
            let mut k = keys.clone();
            k["keys"][0]["retired_at"] = serde_json::Value::Null;
            k
        }),
        ("bad_retired", {
            let mut k = keys.clone();
            k["keys"][0]["retired_at"] = serde_json::json!("yesterday");
            k
        }),
        ("wrong_alg", {
            let mut k = keys.clone();
            k["keys"][0]["alg"] = serde_json::json!("rsa");
            k
        }),
        ("duplicate", {
            let mut k = keys.clone();
            let first = k["keys"][0].clone();
            k["keys"].as_array_mut().unwrap().push(first);
            k
        }),
        ("none", serde_json::json!({"keys": []})),
    ] {
        let (code, _) = ctx(&[
            "audit-verify",
            "--entries",
            &e,
            "--keys",
            &write(&format!("strict_{name}.json"), &bad),
        ]);
        assert_eq!(
            code, 2,
            "{name}: a malformed keys file is refused, never trusted loosely"
        );
    }
    let (_, report) = ctx(&[
        "audit-verify",
        "--entries",
        &write("strict_tail.json", &serde_json::json!(&chain[1..])),
        "--keys",
        &k,
        "--continues",
        &write("strict_anchor.json", &chain[0]),
    ]);
    assert_eq!(report["anchor_sequence"], 1, "the assumed anchor is reported");
}
