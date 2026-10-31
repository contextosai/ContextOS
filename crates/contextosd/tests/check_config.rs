//! `contextosd --check-config`: passes on a startable configuration and reports the
//! first problem otherwise (every missing environment variable at once), without
//! serving.

use std::path::PathBuf;
use std::process::Command;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The support-refund quickstart with its API key placeholder filled and the given
/// listen address, written under the target directory.
fn config(name: &str, listen: &str) -> PathBuf {
    let text = std::fs::read_to_string(root().join("examples/support-refund/contextosd.toml"))
        .unwrap()
        .replace("sha256:REPLACED_BY_RUN_SH", &format!("sha256:{}", "ab".repeat(32)))
        .replace("127.0.0.1:8080", listen);
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::write(&path, text).unwrap();
    path
}

fn check(path: &PathBuf, seed: Option<&str>) -> (bool, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_contextosd"));
    command.arg("--check-config").arg(path).current_dir(root());
    command.env_remove("CONTEXTOS_AUDIT_SEED");
    if let Some(seed) = seed {
        command.env("CONTEXTOS_AUDIT_SEED", seed);
    }
    let output = command.output().unwrap();
    let text = String::from_utf8_lossy(&output.stdout).into_owned() + &String::from_utf8_lossy(&output.stderr);
    (output.status.success(), text)
}

#[test]
fn passes_on_a_startable_configuration() {
    let (ok, text) = check(&config("check-ok.toml", "127.0.0.1:0"), Some(&"11".repeat(32)));
    assert!(ok, "{text}");
    assert!(text.contains("ok: 1 context pack(s) valid"), "{text}");
    assert!(text.contains("ok: dispatch gateway and manifests valid"), "{text}");
    assert!(text.contains("ok: 127.0.0.1:0 is free"), "{text}");
}

#[test]
fn reports_a_missing_signing_seed() {
    let (ok, text) = check(&config("check-seed.toml", "127.0.0.1:0"), None);
    assert!(!ok);
    assert!(
        text.contains("CONTEXTOS_AUDIT_SEED (the audit signing seed: 64 hex characters)"),
        "{text}"
    );
}

#[test]
fn reports_every_missing_environment_variable_at_once() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_contextosd"));
    command
        .arg("--check-config")
        .arg("deploy/contextosd.example.toml")
        .current_dir(root());
    for var in [
        "CONTEXTOS_AUDIT_SEED",
        "CONTEXTOS_DATABASE_URL",
        "CONTEXTOS_AUTHORITY_TOKEN",
        "CONTEXTOS_CONTROLS_TOKEN",
        "CONTEXTOS_APPROVALS_TOKEN",
        "CONTEXTOS_PAYMENTS_TOKEN",
    ] {
        command.env_remove(var);
    }
    let output = command.output().unwrap();
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    for expected in [
        "CONTEXTOS_AUTHORITY_TOKEN (the authority service token)",
        "CONTEXTOS_PAYMENTS_TOKEN (adapter adp_payments's provider token)",
        "CONTEXTOS_AUDIT_SEED (the audit signing seed",
        "CONTEXTOS_DATABASE_URL (the PostgreSQL URL)",
    ] {
        assert!(text.contains(expected), "{text}");
    }
}

#[test]
fn reports_a_listen_address_in_use() {
    let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let listen = busy.local_addr().unwrap().to_string();
    let (ok, text) = check(&config("check-busy.toml", &listen), Some(&"11".repeat(32)));
    assert!(!ok);
    assert!(text.contains(&format!("cannot listen on {listen}")), "{text}");
}

#[test]
fn reports_an_unreadable_pack() {
    let path = config("check-pack.toml", "127.0.0.1:0");
    let text = std::fs::read_to_string(&path).unwrap().replace(
        "examples/support-refund/pack.json",
        "examples/support-refund/missing.json",
    );
    std::fs::write(&path, text).unwrap();
    let (ok, text) = check(&path, Some(&"11".repeat(32)));
    assert!(!ok);
    assert!(text.contains("missing.json"), "{text}");
}

#[test]
fn warns_about_an_effectful_capability_limits_cannot_bound() {
    let (ok, text) = check(&config("check-bounded.toml", "127.0.0.1:0"), Some(&"11".repeat(32)));
    // The example's MCP capability is not pinned to an upstream definition (its local
    // provider is a fixture); that is the only caveat.
    let caveats: Vec<&str> = text
        .lines()
        .filter(|l| l.starts_with("warning:") && !l.contains("pins no upstream_tool_digest"))
        .collect();
    assert!(ok && caveats.is_empty(), "{text}");
    assert!(
        text.contains("adp_payments.issue_refund is effectful on an MCP adapter and pins no upstream_tool_digest"),
        "{text}"
    );

    // The same refund without its amount pointer: a task's amount ceiling passes it.
    let mut manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root().join("examples/support-refund/capabilities/issue_refund.json")).unwrap(),
    )
    .unwrap();
    manifest.as_object_mut().unwrap().remove("amount");
    let refund = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("issue_refund_unbounded.json");
    std::fs::write(&refund, manifest.to_string()).unwrap();
    let path = config("check-unbounded.toml", "127.0.0.1:0");
    let text = std::fs::read_to_string(&path).unwrap().replace(
        "examples/support-refund/capabilities/issue_refund.json",
        refund.to_str().unwrap(),
    );
    std::fs::write(&path, text).unwrap();
    let (ok, text) = check(&path, Some(&"11".repeat(32)));
    assert!(ok, "{text}");
    assert!(
        text.contains("warning: adp_payments.issue_refund is effectful and declares no amount:"),
        "{text}"
    );
}

#[test]
fn a_private_ca_bundle_is_checked() {
    let path = config("check-ca.toml", "127.0.0.1:0");
    let run = |bundle: &std::path::Path| {
        let output = Command::new(env!("CARGO_BIN_EXE_contextosd"))
            .arg("--check-config")
            .arg(&path)
            .current_dir(root())
            .env("CONTEXTOS_AUDIT_SEED", "11".repeat(32))
            .env("CONTEXTOS_CA_BUNDLE", bundle)
            .output()
            .unwrap();
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).into_owned() + &String::from_utf8_lossy(&output.stderr),
        )
    };
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let empty = dir.join("no-certificates.pem");
    std::fs::write(&empty, "not a certificate\n").unwrap();
    let (ok, text) = run(&empty);
    assert!(!ok && text.contains("CONTEXTOS_CA_BUNDLE"), "{text}");
    // Any PEM certificate counts; the repository's test vectors have none, so reuse a
    // public root from the platform when there is one.
    let system = ["/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt"]
        .into_iter()
        .map(std::path::Path::new)
        .find(|p| p.exists());
    if let Some(bundle) = system {
        let (ok, text) = run(bundle);
        assert!(ok, "{text}");
        assert!(
            text.contains("private CA certificate(s) trusted from CONTEXTOS_CA_BUNDLE"),
            "{text}"
        );
    }
}
