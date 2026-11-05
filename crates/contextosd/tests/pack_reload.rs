//! Pack sources read while the server runs: `pack_dirs` and `POST /v1/packs/reload`
//! only add new versions, never change or unload one.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use contextos_audit::AuditSigner;
use contextos_store::{MemoryLog, MemoryStore};
use contextosd::auth::hash_api_key;
use contextosd::{Config, build_state, load_packs, router};
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
    let dir = std::env::temp_dir().join(format!("contextosd-packs-{}", uuid_like()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn uuid_like() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{}-{nanos}", std::process::id())
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

async fn start(config: &Config) -> String {
    let packs = load_packs(config).unwrap();
    let state = build_state(
        config,
        Arc::new(MemoryStore::new()),
        MemoryLog::new(),
        AuditSigner::from_seed("audit-test", [5; 32]),
        packs,
        None,
    )
    .unwrap();
    let app = router(state, Duration::from_secs(5));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

async fn refs(base: &str) -> Vec<String> {
    let body: Value = reqwest::Client::new()
        .get(format!("{base}/v1/packs"))
        .bearer_auth("reader-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    body["packs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["pack_ref"].as_str().unwrap().to_owned())
        .collect()
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

#[tokio::test]
async fn reload_adds_new_versions_and_refuses_changes() {
    let dir = scratch();
    put(&dir, "support/5.2.0.json", &version("5.2.0"));
    // Hidden entries (a git checkout's metadata) are never read.
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::write(dir.join(".git/HEAD.json"), "not a pack").unwrap();
    let base = start(&config(&dir, 0)).await;
    assert_eq!(refs(&base).await, ["ctxpack.support@5.2.0"]);
    assert_eq!(reload(&base, "reader-key").await.0, 403);

    // Nothing changed.
    let (status, body) = reload(&base, "ops-key").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["added"], json!([]));
    assert_eq!(body["unchanged"], 1);

    // A new version is added; a changed existing version, a pack for an unknown
    // tenant and a file that is not a pack are refused.
    put(&dir, "support/5.3.0.json", &version("5.3.0"));
    let mut changed = version("5.2.0");
    changed["pack_meta"]["owner"] = json!("someone-else");
    put(&dir, "support/5.2.0-edited.json", &changed);
    let mut stranger = version("1.0.0");
    stranger["pack_meta"]["tenant"]["tenant_id"] = json!("tenant_other");
    put(&dir, "other/1.0.0.json", &stranger);
    std::fs::write(dir.join("notes.json"), "{").unwrap();
    let (status, body) = reload(&base, "ops-key").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["added"][0]["pack_ref"], "ctxpack.support@5.3.0");
    assert!(body["added"][0]["sha256"].as_str().unwrap().starts_with("sha256:"));
    let refused = body["refused"].as_array().unwrap();
    assert_eq!(refused.len(), 1, "{body}");
    assert_eq!(refused[0]["reason"], "pack_ref_immutable");
    assert_eq!(refused[0]["pack_ref"], "ctxpack.support@5.2.0");
    // The other tenant's pack and the unreadable file are only counted.
    assert_eq!(body["other"], json!({"added": 0, "refused": 2}));
    assert_eq!(refs(&base).await, ["ctxpack.support@5.2.0", "ctxpack.support@5.3.0"]);

    // A removed file does not unload its version.
    std::fs::remove_file(dir.join("support/5.3.0.json")).unwrap();
    reload(&base, "ops-key").await;
    assert_eq!(refs(&base).await, ["ctxpack.support@5.2.0", "ctxpack.support@5.3.0"]);

    // The addition is in the tenant's audit chain.
    let page: Value = reqwest::Client::new()
        .get(format!("{base}/v1/audit/entries?from=1&limit=10"))
        .bearer_auth("reader-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let loaded: Vec<&Value> = page["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["kind"] == "pack_loaded")
        .collect();
    assert_eq!(loaded.len(), 1, "{page}");
    assert_eq!(
        loaded[0]["payload"]["pack_ref"], "ctxpack.support@5.3.0",
        "{}",
        loaded[0]
    );
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn sources_are_reread_on_an_interval() {
    let dir = scratch();
    put(&dir, "5.2.0.json", &version("5.2.0"));
    let base = start(&config(&dir, 1)).await;
    put(&dir, "5.4.0.json", &version("5.4.0"));
    for _ in 0..50 {
        if refs(&base).await.len() == 2 {
            std::fs::remove_dir_all(dir).ok();
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("5.4.0 was not loaded within 5 s");
}

#[test]
fn startup_refuses_one_reference_with_two_contents() {
    let dir = scratch();
    put(&dir, "a.json", &version("5.2.0"));
    let mut changed = version("5.2.0");
    changed["pack_meta"]["owner"] = json!("someone-else");
    put(&dir, "b.json", &changed);
    let error = load_packs(&config(&dir, 0)).unwrap_err();
    assert!(error.contains("also loaded with other content"), "{error}");
    std::fs::remove_dir_all(dir).ok();
}
