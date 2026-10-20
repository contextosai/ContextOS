//! After an audit signing key rotation, entries signed with the retired key still
//! verify, and the retired key is published.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use contextos_audit::AuditSigner;
use contextos_store::{MemoryLog, MemoryStore};
use contextosd::auth::hash_api_key;
use contextosd::{Config, build_state, router};
use serde_json::{Value, json};

fn config(key_id: &str, retired: &str) -> Config {
    Config::parse(&format!(
        r#"
        [server]
        listen = "127.0.0.1:0"
        [store]
        kind = "memory"
        [audit]
        signing_seed_env = "UNUSED"
        key_id = "{key_id}"
        {retired}
        [support]
        implementation_id = "contextos-rs"
        implementation_version = "0.1.0"
        profiles = ["contextos.core"]
        controls = []
        [[api_keys]]
        key_sha256 = "{key}"
        tenant_id = "tenant_acme_prod"
        principal_id = "svc_auditor"
        scopes = ["audit:read"]
        "#,
        key = hash_api_key("acme-key"),
    ))
    .unwrap()
}

#[tokio::test]
async fn entries_signed_before_a_rotation_still_verify() {
    let (store, log) = (Arc::new(MemoryStore::new()), Arc::new(MemoryLog::new()));
    let old = AuditSigner::from_seed("audit-a", [1; 32]);
    let old_public = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(old.verifying_key().as_bytes());
    let before = build_state(
        &config("audit-a", ""),
        store.clone(),
        log.clone(),
        old,
        HashMap::new(),
        None,
    )
    .unwrap();
    for i in 0..2 {
        before
            .audit
            .append("tenant_acme_prod", "note", json!({"i": i}), "2026-10-20T10:00:00Z")
            .await
            .unwrap();
    }

    // Rotated: a new signing key, the old one kept as retired.
    let retired = format!(
        r#"retired_keys = [{{ kid = "audit-a", public_key = "{old_public}", retired_at = "2026-10-20T10:00:30Z" }}]"#
    );
    let after = build_state(
        &config("audit-b", &retired),
        store.clone(),
        log.clone(),
        AuditSigner::from_seed("audit-b", [2; 32]),
        HashMap::new(),
        None,
    )
    .unwrap();
    for i in 2..4 {
        after
            .audit
            .append("tenant_acme_prod", "note", json!({"i": i}), "2026-10-20T10:01:00Z")
            .await
            .unwrap();
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, router(after, Duration::from_secs(10)))
            .await
            .unwrap();
    });
    let http = reqwest::Client::new();
    let verified: Value = http
        .get(format!("{base}/v1/audit/verify"))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // Two entries by the old key, the rotation itself (signed by the new key), two more.
    assert_eq!(verified, json!({"verified": true, "entries": 5}));
    let page: Value = http
        .get(format!("{base}/v1/audit/entries"))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rotation = &page["entries"][2];
    assert_eq!(rotation["kind"], "signing_key_rotated");
    assert_eq!(rotation["payload"], json!({"from_kid": "audit-a", "to_kid": "audit-b"}));
    assert_eq!(rotation["signature"]["kid"], "audit-b");
    assert_eq!(page["entries"][3]["signature"]["kid"], "audit-b");
    let keys: Value = http
        .get(format!("{base}/v1/audit/keys"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let kids: Vec<&str> = keys["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["kid"].as_str().unwrap())
        .collect();
    assert_eq!(kids, ["audit-a", "audit-b"]);
    assert_eq!(keys["keys"][0]["retired_at"], "2026-10-20T10:00:30Z");

    // A retired key that leaks cannot sign new history: an entry it signs after its
    // retirement does not verify.
    let forged_log = Arc::new(MemoryLog::new());
    let forger = contextos_audit::AuditWriter::new(forged_log.clone(), AuditSigner::from_seed("audit-a", [1; 32]));
    forger
        .append(
            "tenant_acme_prod",
            "note",
            json!({"forged": true}),
            "2026-10-20T11:00:00Z",
        )
        .await
        .unwrap();
    let mut ring = contextos_audit::KeyRing::new();
    ring.insert_retired(
        "audit-a",
        AuditSigner::from_seed("audit-a", [1; 32]).verifying_key(),
        "2026-10-20T10:00:30Z",
    );
    assert!(
        contextos_audit::verify_tenant_chain(forged_log.as_ref(), "tenant_acme_prod", &ring)
            .await
            .is_err()
    );
    // (The same chain verifies when the key is trusted without a window: the window is what refuses it.)
    let mut unbounded = contextos_audit::KeyRing::new();
    unbounded.insert("audit-a", AuditSigner::from_seed("audit-a", [1; 32]).verifying_key());
    assert!(
        contextos_audit::verify_tenant_chain(forged_log.as_ref(), "tenant_acme_prod", &unbounded)
            .await
            .is_ok()
    );

    // Without the retired key, the history before the rotation does not verify.
    let forgetful = build_state(
        &config("audit-b", ""),
        store,
        log,
        AuditSigner::from_seed("audit-b", [2; 32]),
        HashMap::new(),
        None,
    )
    .unwrap();
    assert!(
        contextos_audit::verify_tenant_chain(forgetful.audit.log(), "tenant_acme_prod", &forgetful.audit_keys)
            .await
            .is_err()
    );

    // A retired key must be distinct from the signing key and valid.
    assert!(Config::parse(&toml_with_retired("audit-b", "audit-b", &old_public)).is_err());
    assert!(Config::parse(&toml_with_retired("audit-b", "audit-a", "not-a-key")).is_err());
    assert!(Config::parse(&toml_with_retired("audit-b", "audit-a", &old_public)).is_ok());
}

fn toml_with_retired(key_id: &str, kid: &str, public_key: &str) -> String {
    format!(
        "[server]\nlisten = \"127.0.0.1:0\"\n[store]\nkind = \"memory\"\n[audit]\nsigning_seed_env = \"UNUSED\"\nkey_id = \"{key_id}\"\nretired_keys = [{{ kid = \"{kid}\", public_key = \"{public_key}\", retired_at = \"2026-10-20T10:00:30Z\" }}]\n[support]\nimplementation_id = \"x\"\nimplementation_version = \"1\"\nprofiles = []\ncontrols = []\n"
    )
}
