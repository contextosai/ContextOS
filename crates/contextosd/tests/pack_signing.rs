//! `[pack_signing]`: only packs with a valid detached signature by a trusted key load,
//! at startup and on reload, and `pack_loaded` records who signed each.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use contextos_audit::AuditSigner;
use contextos_audit::pack_signature::{public_key, sign};
use contextos_store::{MemoryLog, MemoryStore};
use contextosd::auth::hash_api_key;
use contextosd::config::{PackSigning, TrustedPackKey};
use contextosd::{Config, build_state, load_pack, load_packs, router};
use serde_json::{Value, json};

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

fn version(version: &str) -> Value {
    let mut pack = pack();
    pack["pack_meta"]["pack_version"] = json!(version);
    pack
}

fn put(dir: &std::path::Path, name: &str, value: &Value) {
    let path = dir.join(name);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, value.to_string()).unwrap();
}

fn scratch() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("contextosd-signed-packs-{}", uuid_like()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Unique per test: tests run in parallel, and the clock alone can repeat (macOS
/// reports microseconds), which would hand two tests one directory.
fn uuid_like() -> String {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{}-{nanos}-{n}", std::process::id())
}

fn config(dir: &std::path::Path, reload_secs: u64) -> Config {
    Config::parse(&format!(
        r#"
        pack_dirs = ["{dir}"]
        pack_reload_secs = {reload_secs}
        [server]
        listen = "127.0.0.1:0"
        [store]
        kind = "memory"
        [audit]
        signing_seed_env = "UNUSED"
        key_id = "audit-test"
        [support]
        implementation_id = "contextos-rs"
        implementation_version = "0.1.0"
        profiles = ["contextos.core"]
        controls = ["identity.authenticated"]
        [[api_keys]]
        key_sha256 = "{reader}"
        tenant_id = "tenant_acme_prod"
        principal_id = "svc_reader"
        scopes = ["audit:read"]
        [[api_keys]]
        key_sha256 = "{ops}"
        tenant_id = "tenant_acme_prod"
        principal_id = "svc_oncall"
        scopes = ["control"]
        "#,
        dir = dir.display(),
        reader = hash_api_key("reader-key"),
        ops = hash_api_key("ops-key"),
    ))
    .unwrap()
}

async fn reload(base: &str, key: &str) -> (u16, Value) {
    let response = reqwest::Client::new()
        .post(format!("{base}/v1/packs/reload"))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    (response.status().as_u16(), response.json().await.unwrap_or(Value::Null))
}

const RELEASE: [u8; 32] = [21; 32];

fn signing(mut c: Config) -> Config {
    c.pack_signing = Some(PackSigning {
        trusted_keys: vec![TrustedPackKey {
            kid: "release".into(),
            public_key: public_key(&RELEASE),
        }],
    });
    c
}

/// Writes the pack and, when given a seed, its signature.
fn put_signed(dir: &std::path::Path, name: &str, value: &Value, seed: Option<[u8; 32]>) {
    put(dir, name, value);
    if let Some(seed) = seed {
        let (_, loaded) = load_pack(&value.to_string()).unwrap();
        put(dir, &format!("{name}.sig"), &sign(&seed, "release", &loaded.sha256));
    }
}

#[test]
fn startup_loads_signed_packs_and_refuses_unsigned_or_forged_ones() {
    let dir = scratch();
    put_signed(&dir, "a.json", &version("5.2.0"), Some(RELEASE));
    assert_eq!(load_packs(&signing(config(&dir, 0))).unwrap().len(), 1);
    // Without signing configured, signatures are not needed (and not read).
    put(&dir, "b.json", &version("5.3.0"));
    assert_eq!(load_packs(&config(&dir, 0)).unwrap().len(), 2);
    let error = load_packs(&signing(config(&dir, 0))).unwrap_err();
    assert!(error.contains("pack_signature_missing"), "{error}");
    // Signed by an untrusted key.
    put_signed(&dir, "b.json", &version("5.3.0"), Some([9; 32]));
    let error = load_packs(&signing(config(&dir, 0))).unwrap_err();
    assert!(error.contains("pack_signature_invalid"), "{error}");
    // A valid signature moved onto changed content.
    let sig = std::fs::read_to_string(dir.join("a.json.sig")).unwrap();
    let mut changed = version("5.3.0");
    changed["pack_meta"]["owner"] = json!("someone-else");
    put(&dir, "b.json", &changed);
    std::fs::write(dir.join("b.json.sig"), sig).unwrap();
    let error = load_packs(&signing(config(&dir, 0))).unwrap_err();
    assert!(error.contains("pack_signature_other_content"), "{error}");
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn reload_refuses_an_unsigned_pack_and_records_the_signer() {
    let dir = scratch();
    put_signed(&dir, "support/5.2.0.json", &version("5.2.0"), Some(RELEASE));
    let config = signing(config(&dir, 0));
    let packs = load_packs(&config).unwrap();
    let state = build_state(
        &config,
        Arc::new(MemoryStore::new()),
        MemoryLog::new(),
        AuditSigner::from_seed("audit-test", [5; 32]),
        packs,
        None,
    )
    .unwrap();
    let app = router(state, Duration::from_secs(5));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    put(&dir, "support/5.3.0.json", &version("5.3.0"));
    put_signed(&dir, "support/5.4.0.json", &version("5.4.0"), Some(RELEASE));
    let (status, report) = reload(&base, "ops-key").await;
    assert_eq!(status, 200, "{report}");
    assert_eq!(report["refused"][0]["reason"], "signature_refused", "{report}");
    assert!(report["refused"][0]["path"].as_str().unwrap().ends_with("5.3.0.json"));
    assert_eq!(report["added"].as_array().unwrap().len(), 1);
    let audit: Value = reqwest::Client::new()
        .get(format!("{base}/v1/audit/entries?from=1&limit=100"))
        .bearer_auth("reader-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let loaded: Vec<&Value> = audit["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["kind"] == "pack_loaded")
        .collect();
    // The reloaded pack (startup packs are bound by `bind_startup`, not run here).
    assert_eq!(loaded.len(), 1, "{loaded:?}");
    assert_eq!(loaded[0]["payload"]["pack_ref"], "ctxpack.support@5.4.0");
    assert_eq!(loaded[0]["payload"]["signed_by"], "release");
    std::fs::remove_dir_all(dir).ok();
}
