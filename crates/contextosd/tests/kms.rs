//! Audit signing through a KMS (Vault Transit protocol): the runtime never holds the key.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::Router;
use axum::routing::{get, post};
use base64::Engine as _;
use contextos_audit::{AuditWriter, KeyRing, verify_tenant_chain};
use contextos_store::{AppendLog as _, MemoryLog};
use contextosd::kms::{KmsConfig, vault_transit_signer};
use ed25519_dalek::Signer as _;
use serde_json::{Value, json};

const STD: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// A Vault Transit stand-in holding `key` (and, when `wrong` is set, signing with another).
async fn fake_vault(key: ed25519_dalek::SigningKey, wrong: bool, calls: Arc<AtomicUsize>) -> String {
    let public = STD.encode(key.verifying_key().as_bytes());
    let signer = if wrong {
        ed25519_dalek::SigningKey::from_bytes(&[3; 32])
    } else {
        key
    };
    let app = Router::new()
        .route(
            "/v1/transit/keys/{name}",
            get(move || {
                let public = public.clone();
                async move { axum::Json(json!({"data": {"type": "ed25519", "latest_version": 1, "keys": {"1": {"public_key": public}}}})) }
            }),
        )
        .route(
            "/v1/transit/sign/{name}",
            post(move |headers: axum::http::HeaderMap, axum::Json(body): axum::Json<Value>| {
                let signer = signer.clone();
                let calls = calls.clone();
                async move {
                    // The token is the value of the variable the config names.
                    assert_eq!(headers["x-vault-token"].to_str().unwrap(), std::env::var("PATH").unwrap());
                    calls.fetch_add(1, Ordering::SeqCst);
                    let results: Vec<Value> = body["batch_input"].as_array().unwrap().iter().map(|item| {
                        let input = STD.decode(item["input"].as_str().unwrap()).unwrap();
                        json!({"signature": format!("vault:v1:{}", STD.encode(signer.sign(&input).to_bytes()))})
                    }).collect();
                    axum::Json(json!({"data": {"batch_results": results}}))
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    base
}

fn config(url: &str) -> KmsConfig {
    // Any variable that is set serves as the token here (the workspace forbids the
    // `unsafe` that setting one would need).
    serde_json::from_value(
        json!({"kind": "vault_transit", "url": url, "key_name": "contextos-audit", "token_env": "PATH"}),
    )
    .unwrap()
}

#[tokio::test]
async fn entries_are_signed_by_the_kms_in_one_call_per_batch() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
    let calls = Arc::new(AtomicUsize::new(0));
    let base = fake_vault(key.clone(), false, calls.clone()).await;
    let signer = vault_transit_signer(&config(&base), "audit-kms").await.unwrap();
    assert_eq!(
        signer.verifying_key(),
        key.verifying_key(),
        "the public key comes from the KMS"
    );

    let log = Arc::new(MemoryLog::new());
    let writer = AuditWriter::new(log.clone(), signer);
    let items = (0..20)
        .map(|i| ("note".to_owned(), json!({"i": i}), "2026-10-21T10:00:00Z".to_owned()))
        .collect();
    writer.append_all("t", items).await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1, "20 entries, one signing round trip");
    let mut keys = KeyRing::new();
    keys.insert("audit-kms", key.verifying_key());
    assert_eq!(verify_tenant_chain(log.as_ref(), "t", &keys).await.unwrap(), 20);

    // A KMS answering with signatures from another key fails the append; nothing lands.
    let bad = fake_vault(key.clone(), true, Arc::new(AtomicUsize::new(0))).await;
    let rogue = vault_transit_signer(&config(&bad), "audit-kms").await.unwrap();
    let rogue_log = Arc::new(MemoryLog::new());
    let refused = AuditWriter::new(rogue_log.clone(), rogue)
        .append("t", "note", json!({}), "2026-10-21T10:00:00Z")
        .await;
    assert!(
        matches!(refused, Err(contextos_audit::AuditError::Signing(_))),
        "{refused:?}"
    );
    assert!(
        rogue_log.head("t").await.unwrap().is_none(),
        "nothing is written unsigned or mis-signed"
    );

    // Exactly one of a seed or a KMS.
    let both = "[server]\nlisten = \"127.0.0.1:0\"\n[store]\nkind = \"memory\"\n[audit]\nsigning_seed_env = \"X\"\nkey_id = \"k\"\n[audit.kms]\nkind = \"vault_transit\"\nurl = \"http://v\"\nkey_name = \"a\"\ntoken_env = \"T\"\n[support]\nimplementation_id = \"x\"\nimplementation_version = \"1\"\nprofiles = []\ncontrols = []\n";
    assert!(contextosd::Config::parse(both).is_err());
}
