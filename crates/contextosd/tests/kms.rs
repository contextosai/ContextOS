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

/// How the stand-in misbehaves, if at all.
#[derive(Clone, Copy)]
enum Vault {
    Honest,
    /// Advertises the right public key but signs with another.
    SignsWithAnotherKey,
    /// Advertises another public key (a hijacked endpoint).
    AdvertisesAnotherKey,
    /// Signs with key version 2 although version 1 is pinned.
    WrongVersion,
}

async fn fake_vault(key: ed25519_dalek::SigningKey, mode: Vault, calls: Arc<AtomicUsize>) -> String {
    let other = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
    let advertised = match mode {
        Vault::AdvertisesAnotherKey => other.verifying_key(),
        _ => key.verifying_key(),
    };
    let public = STD.encode(advertised.as_bytes());
    let signer = if matches!(mode, Vault::SignsWithAnotherKey) {
        other
    } else {
        key
    };
    let version = if matches!(mode, Vault::WrongVersion) { 2 } else { 1 };
    let app = Router::new()
        .route(
            "/v1/transit/keys/{name}",
            get(move || {
                let public = public.clone();
                async move { axum::Json(json!({"data": {"type": "ed25519", "latest_version": 2, "keys": {"1": {"public_key": public}}}})) }
            }),
        )
        .route(
            "/v1/transit/sign/{name}",
            post(move |headers: axum::http::HeaderMap, axum::Json(body): axum::Json<Value>| {
                let (signer, calls) = (signer.clone(), calls.clone());
                async move {
                    assert_eq!(headers["x-vault-token"].to_str().unwrap(), std::env::var("PATH").unwrap());
                    assert_eq!(body["key_version"], 1, "the pinned version is requested");
                    calls.fetch_add(1, Ordering::SeqCst);
                    let results: Vec<Value> = body["batch_input"].as_array().unwrap().iter().map(|item| {
                        let input = STD.decode(item["input"].as_str().unwrap()).unwrap();
                        json!({"signature": format!("vault:v{version}:{}", STD.encode(signer.sign(&input).to_bytes()))})
                    }).collect();
                    axum::Json(json!({"data": {"batch_results": results}}))
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    base
}

fn config(url: &str, key: &ed25519_dalek::SigningKey) -> KmsConfig {
    // Any variable that is set serves as the token here (the workspace forbids the
    // `unsafe` that setting one would need).
    serde_json::from_value(json!({"kind": "vault_transit", "url": url, "key_name": "contextos-audit", "token_env": "PATH",
        "key_version": 1, "public_key": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes())}))
    .unwrap()
}

async fn append_with(mode: Vault) -> Result<(), contextos_audit::AuditError> {
    let key = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
    let base = fake_vault(key.clone(), mode, Arc::new(AtomicUsize::new(0))).await;
    let signer = vault_transit_signer(&config(&base, &key), "audit-kms", true)
        .await
        .unwrap();
    let log = Arc::new(MemoryLog::new());
    let result = AuditWriter::new(log.clone(), signer)
        .append("t", "note", json!({}), "2026-10-21T10:00:00Z")
        .await;
    if result.is_err() {
        assert!(
            log.head("t").await.unwrap().is_none(),
            "nothing is written unsigned or mis-signed"
        );
    }
    result.map(|_| ())
}

#[tokio::test]
async fn entries_are_signed_by_the_kms_in_one_call_per_batch() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
    let calls = Arc::new(AtomicUsize::new(0));
    let base = fake_vault(key.clone(), Vault::Honest, calls.clone()).await;
    let signer = vault_transit_signer(&config(&base, &key), "audit-kms", true)
        .await
        .unwrap();
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
}

#[tokio::test]
async fn a_misbehaving_or_substituted_kms_is_refused() {
    assert!(matches!(
        append_with(Vault::SignsWithAnotherKey).await,
        Err(contextos_audit::AuditError::Signing(_))
    ));
    assert!(matches!(
        append_with(Vault::WrongVersion).await,
        Err(contextos_audit::AuditError::Signing(_))
    ));
    // An endpoint advertising another public key than the pinned one is refused at startup.
    let key = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
    let hijacked = fake_vault(key.clone(), Vault::AdvertisesAnotherKey, Arc::new(AtomicUsize::new(0))).await;
    let refused = vault_transit_signer(&config(&hijacked, &key), "audit-kms", true)
        .await
        .err()
        .unwrap();
    assert!(refused.contains("does not match"), "{refused}");
    // Outside development the KMS must be reached over HTTPS.
    let plain = vault_transit_signer(&config("http://vault.internal:8200", &key), "audit-kms", false)
        .await
        .err()
        .unwrap();
    assert!(plain.contains("https"), "{plain}");
    // Exactly one of a seed or a KMS.
    let both = "[server]\nlisten = \"127.0.0.1:0\"\n[store]\nkind = \"memory\"\n[audit]\nsigning_seed_env = \"X\"\nkey_id = \"k\"\n[audit.kms]\nkind = \"vault_transit\"\nurl = \"http://v\"\nkey_name = \"a\"\ntoken_env = \"T\"\nkey_version = 1\npublic_key = \"x\"\n[support]\nimplementation_id = \"x\"\nimplementation_version = \"1\"\nprofiles = []\ncontrols = []\n";
    assert!(contextosd::Config::parse(both).is_err());
}
